/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_TID_H__
#define __CXGB4_TID_H__

struct cxgb4_tid_info_xarray {
	struct xarray tid_tab;
	unsigned long *bitmap;
	u32 start;
	u32 size;
	u32 in_use;
	u32 range_in_use;
	u8 max_range;
};

/* Holds the size, base address, data, etc. of the various TIDs in
 * hardware.
 */
struct cxgb4_tid_info {
	struct cxgb4_tid_info_xarray tids;
	struct cxgb4_tid_info_xarray atids;
	struct cxgb4_tid_info_xarray hpftids;
	struct cxgb4_tid_info_xarray ftids;
	struct cxgb4_tid_info_xarray hashtids;
	struct cxgb4_tid_info_xarray hashcoll_tids;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	struct cxgb4_tid_info_xarray stids;
	struct cxgb4_tid_info_xarray uotids;
	struct cxgb4_tid_info_xarray sftids;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	u64 tid_release_head;
	spinlock_t tid_release_lock; /* Lock to access TID release list */
	struct work_struct tid_release_task;
};

unsigned int cxgb4_atid_in_use(struct adapter *adap);
void *cxgb4_atid_lookup(struct adapter *adap, u32 atid);
int cxgb4_atid_alloc(struct adapter *adap, void *data);
void cxgb4_atid_free(struct adapter *adap, u32 atid);

unsigned int cxgb4_tid_in_use(struct adapter *adap);
bool cxgb4_tid_out_of_range(struct adapter *adap, u32 tid);
void *cxgb4_tid_lookup(struct adapter *adap, u32 tid);
int cxgb4_tid_insert(struct adapter *adap, u32 tid, void *data, bool range);
void cxgb4_tid_remove(struct adapter *adap, u8 chan, u32 tid, bool range);

bool cxgb4_hashtid_out_of_range(struct adapter *adap, u32 hashtid);
void *cxgb4_hashtid_lookup(struct adapter *adap, u32 hashtid);
int cxgb4_hashtid_insert(struct adapter *adap, u32 hashtid, void *data,
			 bool range);
void cxgb4_hashtid_remove(struct adapter *adap, u8 chan, u32 hashtid,
			  bool range);

bool cxgb4_hpftid_out_of_range(struct adapter *adap, u32 hpftid);
int cxgb4_hpftid_alloc(struct adapter *adap, void *data, bool range);

bool cxgb4_ftid_out_of_range(struct adapter *adap, u32 ftid);
void *cxgb4_ftid_lookup(struct adapter *adap, u32 ftid);
int cxgb4_ftid_insert(struct adapter *adap, void *data, u32 ftid, bool range);
int cxgb4_ftid_alloc(struct adapter *adap, void *data, bool range);
void cxgb4_ftid_free(struct adapter *adap, u32 ftid, bool range);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
bool cxgb4_sftid_out_of_range(struct adapter *adap, u32 sftid);
int cxgb4_sftid_alloc(struct adapter *adap, void *data, bool range);

void *cxgb4_stid_lookup(struct adapter *adap, u32 stid);
int cxgb4_stid_alloc(struct adapter *adap, void *data, bool range);
void cxgb4_stid_free(struct adapter *adap, u32 stid, bool range);

void *cxgb4_uotid_lookup(struct adapter *adap, u32 uotid);
int cxgb4_uotid_alloc(struct adapter *adap, void *data);
void cxgb4_uotid_free(struct adapter *adap, u32 uotid);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

void cxgb4_tid_info_cleanup(struct adapter *adap);
int cxgb4_tid_info_init(struct adapter *adap,
			const struct fw_caps_config_cmd *caps_cmd);
#endif /* __CXGB4_TID_H__ */
