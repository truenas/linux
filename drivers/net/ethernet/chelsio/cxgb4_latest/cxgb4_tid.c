/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "common.h"
#include "t4_regs.h"
#include "t4_msg.h"
#include "t4fw_interface.h"

#include "cxgb4_ofld.h"
#include "cxgb4_filter.h"

static void *cxgb4_tid_xarray_lookup(struct cxgb4_tid_info_xarray *ti_xarr,
				     u32 tid)
{
	return xa_load(&ti_xarr->tid_tab, tid);
}

static int cxgb4_tid_get_any_free_bits(struct cxgb4_tid_info_xarray *ti_xarr,
				       u8 n)
{
	return bitmap_find_free_region(ti_xarr->bitmap, ti_xarr->size,
				       get_count_order(n));
}

static int cxgb4_tid_set_bits(struct cxgb4_tid_info_xarray *ti_xarr, u32 tid,
			      u8 n)
{
	return bitmap_allocate_region(ti_xarr->bitmap, tid, get_count_order(n));
}

static void cxgb4_tid_clear_bits(struct cxgb4_tid_info_xarray *ti_xarr, u32 tid,
				 u8 n)
{
	bitmap_release_region(ti_xarr->bitmap, tid, get_count_order(n));
}

/* Must be called with xa_lock held */
static int cxgb4_tid_xarray_alloc_any(struct cxgb4_tid_info_xarray *ti_xarr,
				      void *data, bool range)
{
	int ret, tid;
	u8 n = range ? ti_xarr->max_range : 1;

	ret = cxgb4_tid_get_any_free_bits(ti_xarr, n);
	if (ret < 0)
		return ret;

	tid = ret;
	ret = __xa_insert(&ti_xarr->tid_tab, ti_xarr->start + tid, data,
			  GFP_KERNEL);
	if (ret) {
		cxgb4_tid_clear_bits(ti_xarr, tid, n);
		return ret;
	}

	if (range)
		ti_xarr->range_in_use += n;
	else
		ti_xarr->in_use++;

	return tid + ti_xarr->start;
}

/* Must be called with xa_lock held */
static int cxgb4_tid_xarray_alloc(struct cxgb4_tid_info_xarray *ti_xarr,
				  void *data, u32 tid, bool range)
{
	int ret;
	u8 n = range ? ti_xarr->max_range : 1;

	ret = cxgb4_tid_set_bits(ti_xarr, tid - ti_xarr->start, n);
	if (ret < 0)
		return ret;

	ret = __xa_insert(&ti_xarr->tid_tab, tid, data, GFP_KERNEL);
	if (ret) {
		cxgb4_tid_clear_bits(ti_xarr, tid - ti_xarr->start, n);
		return ret;
	}

	if (range)
		ti_xarr->range_in_use += n;
	else
		ti_xarr->in_use++;

	return 0;
}

/* Must be called with xa_lock held */
static void cxgb4_tid_xarray_free(struct cxgb4_tid_info_xarray *ti_xarr,
				  u32 tid, bool range)
{
	u8 n = range ? ti_xarr->max_range : 1;

	if (__xa_erase(&ti_xarr->tid_tab, tid)) {
		cxgb4_tid_clear_bits(ti_xarr, tid - ti_xarr->start, n);
		if (range)
			ti_xarr->range_in_use -= n;
		else
			ti_xarr->in_use--;
	}
}

/* TID APIs to lookup, insert, and free various TIDs in hardware.
 */
static bool cxgb4_tid_oor(struct cxgb4_tid_info_xarray *ti_xarr, u32 tid)
{
	return tid < ti_xarr->start || tid >= (ti_xarr->start + ti_xarr->size);
}

unsigned int cxgb4_atid_in_use(struct adapter *adap)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	xa_lock_bh(&t->atids.tid_tab);
	ret = t->atids.in_use;
	xa_unlock_bh(&t->atids.tid_tab);
	return ret;
}

static bool cxgb4_atid_out_of_range(struct adapter *adap, u32 atid)
{
	return cxgb4_tid_oor(&adap->tidinfo.atids, atid);
}

void *cxgb4_atid_lookup(struct adapter *adap, u32 atid)
{
	if (cxgb4_atid_out_of_range(adap, atid))
		return NULL;

	return cxgb4_tid_xarray_lookup(&adap->tidinfo.atids, atid);
}

int cxgb4_atid_alloc(struct adapter *adap, void *data)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!t->atids.size)
		return -EOPNOTSUPP;

	xa_lock_bh(&t->atids.tid_tab);
	ret = cxgb4_tid_xarray_alloc_any(&t->atids, data, 1);
	xa_unlock_bh(&t->atids.tid_tab);
	return ret;
}

void cxgb4_atid_free(struct adapter *adap, u32 atid)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (cxgb4_atid_out_of_range(adap, atid))
		return;

	xa_lock_bh(&t->atids.tid_tab);
	cxgb4_tid_xarray_free(&t->atids, atid, 1);
	xa_unlock_bh(&t->atids.tid_tab);
}

unsigned int cxgb4_tid_in_use(struct adapter *adap)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	xa_lock_bh(&t->tids.tid_tab);
	ret = t->tids.in_use + t->tids.range_in_use / t->tids.max_range;
	xa_unlock_bh(&t->tids.tid_tab);
	return ret;
}

bool cxgb4_tid_out_of_range(struct adapter *adap, u32 tid)
{
	return cxgb4_tid_oor(&adap->tidinfo.tids, tid);
}

void *cxgb4_tid_lookup(struct adapter *adap, u32 tid)
{
	if (cxgb4_tid_out_of_range(adap, tid))
		return NULL;

	return cxgb4_tid_xarray_lookup(&adap->tidinfo.tids, tid);
}

int cxgb4_tid_insert(struct adapter *adap, u32 tid, void *data, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (cxgb4_tid_out_of_range(adap, tid))
		return -EOPNOTSUPP;

	if (range)
		tid &= ~(t->tids.max_range - 1);

	xa_lock_irq(&t->tids.tid_tab);
	ret = cxgb4_tid_xarray_alloc(&t->tids, data, tid, range);
	xa_unlock_irq(&t->tids.tid_tab);
	return ret;
}

/* Populate a TID_RELEASE WR.  Caller must properly size the skb.
 */
static void cxgb4_tid_release_write(struct sk_buff *skb, u8 chan, u32 tid)
{
	struct cpl_tid_release *req;

	set_wr_txq(skb, CPL_PRIORITY_SETUP, chan);
	req = (struct cpl_tid_release *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_TID_RELEASE, tid);
}

/* Queue a TID release request and if necessary schedule a work queue to
 * process it.
 */
static void cxgb4_tid_release_list_add(struct adapter *adap, u8 chan, u32 tid)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	u64 head;

	spin_lock_bh(&t->tid_release_lock);
	head = t->tid_release_head;
	/* Low 2 bits encode the Tx channel number */
	t->tid_release_head = (tid << 2) | chan;
	if (!head)
		cxgb4_work_queue(adap->workq, &t->tid_release_task);
	spin_unlock_bh(&t->tid_release_lock);
}

/* Process the list of pending TID release requests.
 */
static void cxgb4_tid_process_release_list(struct work_struct *work)
{
	struct cxgb4_tid_info *t;
	struct adapter *adap;
	struct sk_buff *skb;

	t = container_of(work, struct cxgb4_tid_info, tid_release_task);
	adap = container_of(t, struct adapter, tidinfo);

	spin_lock_bh(&t->tid_release_lock);
	while (t->tid_release_head) {
		u64 head = t->tid_release_head;
		unsigned int chan = head & 3;
		unsigned int tid = head >> 2;

		t->tid_release_head = 0;
		spin_unlock_bh(&t->tid_release_lock);

		while (!(skb = alloc_skb(sizeof(struct cpl_tid_release),
					 GFP_KERNEL)))
			schedule();

		cxgb4_tid_release_write(skb, chan, tid);
		cxgb4_sge_xmit_ctrl(adap->port[chan], skb);
		spin_lock_bh(&t->tid_release_lock);
	}
	spin_unlock_bh(&t->tid_release_lock);
}

static void cxgb4_tid_remove_send(struct adapter *adap, u8 chan, u32 tid)
{
	struct cpl_tid_release sreq, *req = &sreq;

	INIT_TP_WR_MIT_CPL(req, CPL_TID_RELEASE, tid);
	req->rsvd = 0;
	if (cxgb4_sge_xmit_ctrl_direct(adap->port[chan], chan, req, sizeof(*req)))
		cxgb4_tid_release_list_add(adap, chan, tid);
}

/* Release a TID and inform HW.  If we are unable to allocate the release
 * message we defer to a work queue.
 */
void cxgb4_tid_remove(struct adapter *adap, u8 chan, u32 tid, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (cxgb4_tid_out_of_range(adap, tid))
		return;

	xa_lock_bh(&t->tids.tid_tab);
	cxgb4_tid_xarray_free(&t->tids, tid, range);
	xa_unlock_bh(&t->tids.tid_tab);

	cxgb4_tid_remove_send(adap, chan, tid);
}

static bool cxgb4_hashcoll_tid_out_of_range(struct adapter *adap,
					    u32 hashcoll_tid)
{
	return cxgb4_tid_oor(&adap->tidinfo.hashcoll_tids, hashcoll_tid);
}

static void *cxgb4_hashcoll_tid_lookup(struct adapter *adap, u32 hashcoll_tid)
{
	return cxgb4_tid_xarray_lookup(&adap->tidinfo.hashcoll_tids,
				       hashcoll_tid);
}

static int cxgb4_hashcoll_tid_insert(struct adapter *adap, u32 hashcoll_tid,
				     void *data, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (range)
		hashcoll_tid &= ~(t->hashcoll_tids.max_range - 1);

	xa_lock_irq(&t->hashcoll_tids.tid_tab);
	ret = cxgb4_tid_xarray_alloc(&t->hashcoll_tids, data,
				     hashcoll_tid, range);
	xa_unlock_irq(&t->hashcoll_tids.tid_tab);
	return ret;
}

static void cxgb4_hashcoll_tid_remove(struct adapter *adap, u8 chan,
				      u32 hashcoll_tid, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	xa_lock_bh(&t->hashcoll_tids.tid_tab);
	cxgb4_tid_xarray_free(&t->hashcoll_tids, hashcoll_tid, range);
	xa_unlock_bh(&t->hashcoll_tids.tid_tab);

	cxgb4_tid_remove_send(adap, chan, hashcoll_tid);
}

static bool cxgb4_hash_tid_out_of_range(struct adapter *adap, u32 hashtid)
{
	return cxgb4_tid_oor(&adap->tidinfo.hashtids, hashtid);
}

bool cxgb4_hashtid_out_of_range(struct adapter *adap, u32 hashtid)
{
	if (!cxgb4_hashcoll_tid_out_of_range(adap, hashtid))
		return false;

	return cxgb4_hash_tid_out_of_range(adap, hashtid);
}

void *cxgb4_hashtid_lookup(struct adapter *adap, u32 hashtid)
{
	if (!cxgb4_hashcoll_tid_out_of_range(adap, hashtid))
		return cxgb4_hashcoll_tid_lookup(adap, hashtid);

	if (cxgb4_hash_tid_out_of_range(adap, hashtid))
		return NULL;

	return cxgb4_tid_xarray_lookup(&adap->tidinfo.hashtids, hashtid);
}

int cxgb4_hashtid_insert(struct adapter *adap, u32 hashtid, void *data,
			 bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!cxgb4_hashcoll_tid_out_of_range(adap, hashtid))
		return cxgb4_hashcoll_tid_insert(adap, hashtid, data, range);

	if (cxgb4_hash_tid_out_of_range(adap, hashtid))
		return -EOPNOTSUPP;

	if (range)
		hashtid &= ~(t->hashtids.max_range - 1);

	xa_lock_irq(&t->hashtids.tid_tab);
	ret = cxgb4_tid_xarray_alloc(&t->hashtids, data, hashtid, range);
	xa_unlock_irq(&t->hashtids.tid_tab);
	return ret;
}

void cxgb4_hashtid_remove(struct adapter *adap, u8 chan, u32 hashtid,
			  bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (!cxgb4_hashcoll_tid_out_of_range(adap, hashtid)) {
		cxgb4_hashcoll_tid_remove(adap, chan, hashtid, range);
		return;
	}

	if (cxgb4_hash_tid_out_of_range(adap, hashtid))
		return;

	xa_lock_bh(&t->hashtids.tid_tab);
	cxgb4_tid_xarray_free(&t->hashtids, hashtid, range);
	xa_unlock_bh(&t->hashtids.tid_tab);

	cxgb4_tid_remove_send(adap, chan, hashtid);
}

bool cxgb4_hpftid_out_of_range(struct adapter *adap, u32 hpftid)
{
	return cxgb4_tid_oor(&adap->tidinfo.hpftids, hpftid);
}

static void *cxgb4_hpftid_lookup(struct adapter *adap, u32 hpftid)
{
	return cxgb4_tid_xarray_lookup(&adap->tidinfo.hpftids, hpftid);
}

static int cxgb4_hpftid_insert(struct adapter *adap, void *data, u32 hpftid,
			       bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (range)
		hpftid &= ~(t->hpftids.max_range - 1);

	xa_lock_bh(&t->hpftids.tid_tab);
	ret = cxgb4_tid_xarray_alloc(&t->hpftids, data, hpftid, range);
	xa_unlock_bh(&t->hpftids.tid_tab);
	return ret;
}

int cxgb4_hpftid_alloc(struct adapter *adap, void *data, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!t->hpftids.size)
		return -EOPNOTSUPP;

	xa_lock_bh(&t->hpftids.tid_tab);
	ret = cxgb4_tid_xarray_alloc_any(&t->hpftids, data, range);
	xa_unlock_bh(&t->hpftids.tid_tab);
	return ret;
}

static void cxgb4_hpftid_free(struct adapter *adap, u32 hpftid, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	xa_lock_bh(&t->hpftids.tid_tab);
	cxgb4_tid_xarray_free(&t->hpftids, hpftid, range);
	xa_unlock_bh(&t->hpftids.tid_tab);
}

bool cxgb4_ftid_out_of_range(struct adapter *adap, u32 ftid)
{
	return cxgb4_tid_oor(&adap->tidinfo.ftids, ftid);
}

void *cxgb4_ftid_lookup(struct adapter *adap, u32 ftid)
{
	if (!cxgb4_hpftid_out_of_range(adap, ftid))
		return cxgb4_hpftid_lookup(adap, ftid);

	if (cxgb4_ftid_out_of_range(adap, ftid))
		return NULL;

	return cxgb4_tid_xarray_lookup(&adap->tidinfo.ftids, ftid);
}

int cxgb4_ftid_insert(struct adapter *adap, void *data, u32 ftid, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!cxgb4_hpftid_out_of_range(adap, ftid))
		return cxgb4_hpftid_insert(adap, data, ftid, range);

	if (cxgb4_ftid_out_of_range(adap, ftid))
		return -EOPNOTSUPP;

	if (range)
		ftid &= ~(t->ftids.max_range - 1);

	xa_lock_bh(&t->ftids.tid_tab);
	ret = cxgb4_tid_xarray_alloc(&t->ftids, data, ftid, range);
	xa_unlock_bh(&t->ftids.tid_tab);
	return ret;
}

int cxgb4_ftid_alloc(struct adapter *adap, void *data, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!t->ftids.size)
		return -EOPNOTSUPP;

	xa_lock_bh(&t->ftids.tid_tab);
	ret = cxgb4_tid_xarray_alloc_any(&t->ftids, data, range);
	xa_unlock_bh(&t->ftids.tid_tab);
	return ret;
}

void cxgb4_ftid_free(struct adapter *adap, u32 ftid, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (!cxgb4_hpftid_out_of_range(adap, ftid)) {
		cxgb4_hpftid_free(adap, ftid, range);
		return;
	}

	if (cxgb4_ftid_out_of_range(adap, ftid))
		return;

	xa_lock_bh(&t->ftids.tid_tab);
	cxgb4_tid_xarray_free(&t->ftids, ftid, range);
	xa_unlock_bh(&t->ftids.tid_tab);
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
bool cxgb4_sftid_out_of_range(struct adapter *adap, u32 sftid)
{
	return cxgb4_tid_oor(&adap->tidinfo.sftids, sftid);
}

static void *cxgb4_sftid_lookup(struct adapter *adap, u32 sftid)
{
	return cxgb4_tid_xarray_lookup(&adap->tidinfo.sftids, sftid);
}

int cxgb4_sftid_alloc(struct adapter *adap, void *data, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!t->sftids.size || range)
		return -EOPNOTSUPP;

	xa_lock_bh(&t->sftids.tid_tab);
	ret = cxgb4_tid_xarray_alloc_any(&t->sftids, data, 1);
	xa_unlock_bh(&t->sftids.tid_tab);
	return ret;
}

static void cxgb4_sftid_free(struct adapter *adap, u32 sftid)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	xa_lock_bh(&t->sftids.tid_tab);
	cxgb4_tid_xarray_free(&t->sftids, sftid, 1);
	xa_unlock_bh(&t->sftids.tid_tab);
}

static bool cxgb4_stid_out_of_range(struct adapter *adap, u32 stid)
{
	if (!cxgb4_sftid_out_of_range(adap, stid))
		return false;

	return cxgb4_tid_oor(&adap->tidinfo.stids, stid);
}

void *cxgb4_stid_lookup(struct adapter *adap, u32 stid)
{
	if (!cxgb4_sftid_out_of_range(adap, stid))
		return cxgb4_sftid_lookup(adap, stid);

	if (cxgb4_stid_out_of_range(adap, stid))
		return NULL;

	return cxgb4_tid_xarray_lookup(&adap->tidinfo.stids, stid);
}

int cxgb4_stid_alloc(struct adapter *adap, void *data, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!t->stids.size)
		return -EOPNOTSUPP;

	xa_lock_bh(&t->stids.tid_tab);
	ret = cxgb4_tid_xarray_alloc_any(&t->stids, data, range);
	xa_unlock_bh(&t->stids.tid_tab);
	return ret;
}

void cxgb4_stid_free(struct adapter *adap, u32 stid, bool range)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (!cxgb4_sftid_out_of_range(adap, stid)) {
		cxgb4_sftid_free(adap, stid);
		return;
	}

	if (cxgb4_stid_out_of_range(adap, stid))
		return;

	xa_lock_bh(&t->stids.tid_tab);
	cxgb4_tid_xarray_free(&t->stids, stid, range);
	xa_unlock_bh(&t->stids.tid_tab);
}

static bool cxgb4_uotid_out_of_range(struct adapter *adap, u32 uotid)
{
	return cxgb4_tid_oor(&adap->tidinfo.uotids, uotid);
}

void *cxgb4_uotid_lookup(struct adapter *adap, u32 uotid)
{
	if (cxgb4_uotid_out_of_range(adap, uotid))
		return NULL;

	return cxgb4_tid_xarray_lookup(&adap->tidinfo.uotids, uotid);
}

int cxgb4_uotid_alloc(struct adapter *adap, void *data)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	if (!t->uotids.size)
		return -EOPNOTSUPP;

	xa_lock_bh(&t->uotids.tid_tab);
	ret = cxgb4_tid_xarray_alloc_any(&t->uotids, data, 0);
	xa_unlock_bh(&t->uotids.tid_tab);
	return ret;
}

void cxgb4_uotid_free(struct adapter *adap, u32 uotid)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;

	if (cxgb4_uotid_out_of_range(adap, uotid))
		return;

	xa_lock_bh(&t->uotids.tid_tab);
	cxgb4_tid_xarray_free(&t->uotids, uotid, 0);
	xa_unlock_bh(&t->uotids.tid_tab);
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/* Max # of ATIDs.  The absolute HW max is 16K but we keep it lower.
 */
#define CXGB4_MAX_ATIDS 8192U

static int cxgb4_tid_query_params(struct adapter *adap,
				  const struct fw_caps_config_cmd *caps_cmd)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	u32 tid_size, stid_start;
	u32 params[7], val[7];
	unsigned int chip_ver;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	u32 stid_size;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	int ret;

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	/* T6 TCAM can contain about 4 regions (Hi-Priority filter,
	 * Active, Server and Normal priority filter regions).
	 */
	if (chip_ver > CHELSIO_T5) {
		params[0] = FW_PARAM_PFVF(HPFILTER_START);
		params[1] = FW_PARAM_PFVF(HPFILTER_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (ret < 0)
			return ret;
		t->hpftids.start = val[0];
		t->hpftids.size = val[1] - val[0] + 1;
	}

	params[0] = FW_PARAM_DEV(NTID);
	params[1] = FW_PARAM_PFVF(FILTER_START);
	params[2] = FW_PARAM_PFVF(FILTER_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 3, params, val);
	if (ret < 0)
		return ret;
	tid_size = val[0];
	t->ftids.start = val[1];
	t->ftids.size = val[2] - val[1] + 1;

	params[0] = FW_PARAM_PFVF(SERVER_START);
	params[1] = FW_PARAM_PFVF(SERVER_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (ret < 0)
		return ret;
	stid_start = val[0];
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	stid_size = val[1] - val[0] + 1;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	if ((caps_cmd->niccaps & htons(FW_CAPS_CONFIG_NIC_HASHFILTER)) &&
	    use_ddr_filters && chip_ver > CHELSIO_T4) {
		u32 lconfig, hbase, hconfig;

		if (cxgb4_hash_filter_config_verify(adap, !!caps_cmd->toecaps))
			goto hashtids_done;

		lconfig = t4_read_reg(adap, A_LE_DB_CONFIG);
		if (lconfig & F_HASHEN) {
			hconfig = t4_read_reg(adap, A_LE_DB_HASH_CONFIG);
			if (chip_ver > CHELSIO_T5) {
				hbase = t4_read_reg(adap,
						    A_T6_LE_DB_HASH_TID_BASE);
				t->hashtids.start = hbase;
				t->hashtids.size = hconfig & 0xfffffU;
			} else {
				hbase = t4_read_reg(adap,
						    A_LE_DB_TID_HASHBASE);
				t->hashtids.start = hbase;
				t->hashtids.size =
					(1 << G_HASHTIDSIZE(hconfig));
			}

			t->hashcoll_tids.start = t->hpftids.start +
						 t->hpftids.size;
			t->hashcoll_tids.size = stid_start -
						t->hashcoll_tids.start;
		}
	}

hashtids_done:
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (!caps_cmd->toecaps)
		goto offload_tids_done;

	if (stid_size) {
		t->stids.start = stid_start;
		t->stids.size = stid_size;
	}

	params[0] = FW_PARAM_PFVF(ETHOFLD_START);
	params[1] = FW_PARAM_PFVF(ETHOFLD_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (val[0] != val[1] && ret >= 0) {
		t->uotids.start = val[0];
		t->uotids.size = val[1] - val[0] + 1;
	}

	/* query params related to active filter region */
	params[0] = FW_PARAM_PFVF(ACTIVE_FILTER_START);
	params[1] = FW_PARAM_PFVF(ACTIVE_FILTER_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	/* If Active filter size is set we enable establishing
	 * offload connection through firmware work request
	 */
	if (val[0] != val[1] && ret >= 0) {
		adap->flags |= FW_OFLD_CONN;
		if (t->hashcoll_tids.size) {
			t->hashcoll_tids.start = val[0];
			t->hashcoll_tids.size = val[1] - val[0] + 1;
		}
	}

	/* Setup server filter region. Divide the available filter
	 * region into two parts. Regular filters get 1/3rd and server
	 * filters get 2/3rd part. This is only enabled if workarond
	 * path is enabled.
	 * 1. For regular filters.
	 * 2. Server filter: This are special filters which are used
	 * to redirect SYN packets to offload queue.
	 */
	if ((adap->flags & FW_OFLD_CONN) && !is_bypass(adap)) {
		u32 n_user_filters;

		if (user_filter_perc >= 0 && user_filter_perc <= 100) {
			n_user_filters = mult_frac(t->ftids.size,
						   user_filter_perc, 100);
		} else {
			/* If we have invalid value in module-param then,
			 * use default value of 33% for user-filters.
			 */
			n_user_filters = mult_frac(t->ftids.size, 33, 100);
		}
		t->sftids.start = t->ftids.start + n_user_filters;
		t->sftids.size = t->ftids.size - n_user_filters;
		/* Reserve last sftid for default-rule filter */
		t->sftids.size--;
	}

offload_tids_done:
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	if (tid_size) {
		t->tids.start = t->hpftids.start + t->hpftids.size;
		t->tids.size = tid_size;
		t->atids.start = 0;
		/*
 		 * ATID field in CPL_ACT_OPEN_REQ is 24 bit wide of which atid
 		 * is 14 bit wide. So the CXGB4_MAX_ATIDS can be a most 2^14 - 1.
 		 * remaining 10 bits are used for rss_qid.
		 */
		t->atids.size = min(t->tids.size, CXGB4_MAX_ATIDS);
	}

	t->tids.max_range = chip_ver > CHELSIO_T6 ? 1 : 2;
	t->atids.max_range = 1;
	t->hpftids.max_range = 2;
	t->ftids.max_range = chip_ver > CHELSIO_T5 ? 2 : 4;
	t->hashtids.max_range = chip_ver > CHELSIO_T6 ? 1 : 2;
	t->hashcoll_tids.max_range = chip_ver > CHELSIO_T6 ? 1 : 2;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	t->stids.max_range = 2;
	t->uotids.max_range = 1;
	t->sftids.max_range = 1;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	return 0;
}

static void cxgb4_tid_info_xarray_cleanup(struct cxgb4_tid_info_xarray *ti_xarr)
{
	if (!ti_xarr->size || !ti_xarr->bitmap)
		return;

	xa_destroy(&ti_xarr->tid_tab);
	kfree(ti_xarr->bitmap);
	ti_xarr->bitmap = NULL;
}

static int cxgb4_tid_info_xarray_init(struct cxgb4_tid_info_xarray *ti_xarr)
{
	unsigned long *bitmap;

	if (!ti_xarr->size)
		return 0;

	bitmap = kcalloc(BITS_TO_LONGS(ti_xarr->size), sizeof(*bitmap),
			 GFP_KERNEL);
	if (!bitmap)
		return -ENOMEM;

	xa_init_flags(&ti_xarr->tid_tab, XA_FLAGS_LOCK_IRQ);
	ti_xarr->bitmap = bitmap;
	bitmap_zero(ti_xarr->bitmap, ti_xarr->size);
	return 0;
}

void cxgb4_tid_info_cleanup(struct adapter *adap)
{
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.tids);
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.atids);
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.ftids);
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.hpftids);
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.hashtids);
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.hashcoll_tids);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.stids);
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.uotids);
	cxgb4_tid_info_xarray_cleanup(&adap->tidinfo.sftids);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	cxgb4_work_cancel(adap->workq, &adap->tidinfo.tid_release_task);
	memset(&adap->tidinfo, 0, sizeof(adap->tidinfo));
}

/* Allocate and initialize the TID tables.  Returns 0 on success.
 */
int cxgb4_tid_info_init(struct adapter *adap,
			const struct fw_caps_config_cmd *caps_cmd)
{
	struct cxgb4_tid_info *t = &adap->tidinfo;
	int ret;

	spin_lock_init(&t->tid_release_lock);
	INIT_WORK(&t->tid_release_task, cxgb4_tid_process_release_list);

	ret = cxgb4_tid_query_params(adap, caps_cmd);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->tids);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->atids);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->ftids);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->hpftids);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->hashtids);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->hashcoll_tids);
	if (ret)
		goto out_free;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	ret = cxgb4_tid_info_xarray_init(&t->stids);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->uotids);
	if (ret)
		goto out_free;

	ret = cxgb4_tid_info_xarray_init(&t->sftids);
	if (ret)
		goto out_free;

	/* Reserve stid 0 for T4/T5 adapters */
	if (t->stids.size && !t->stids.start &&
	    (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5))
		set_bit(0, t->stids.bitmap);

#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	return 0;

out_free:
	cxgb4_tid_info_cleanup(adap);
	return ret;
}
