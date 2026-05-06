// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lio_ha_fwd.c -- STANDBY-side I/O forwarding
 *
 * DATA FLOW
 * ---------
 *
 * READ (initiator -> STANDBY -> ACTIVE -> STANDBY -> initiator):
 *   1. STANDBY: ha_ops.forward_cmd() -> lio_ha_forward_cmd()
 *   2. STANDBY sends CMD_FORWARD (CTL channel).
 *   3. ACTIVE submits command to local storage backend.
 *   4. ACTIVE backend completes; queue_data_in() sends:
 *        a. DATA message (lio_ha_data_hdr + raw SCSI read data)
 *        b. CMD_RESPONSE CTL message
 *   5. STANDBY rx thread: DATA -> ha_fwd_data_handler() stores in
 *      ha_fwd_data_ht.  Then CMD_RESPONSE -> ha_fwd_cmd_response_handler()
 *      picks up buffered data, copies to se_cmd->t_data_sg, completes cmd.
 *
 * WRITE (initiator -> STANDBY -> ACTIVE -> STANDBY -> initiator):
 *   1. STANDBY: ha_ops.forward_cmd() -> lio_ha_forward_cmd()
 *   2. STANDBY sends DATA (write data) then CMD_FORWARD (CTL channel).
 *   3. ACTIVE: DATA -> lio_ha_recv_data_rx() buffers by cookie.
 *      CMD_FORWARD -> lio_ha_recv_submit_cmd() -> target_submit_cmd() ->
 *      write_pending() picks up buffered data -> target_execute_cmd().
 *   4. ACTIVE backend completes; queue_status() sends CMD_RESPONSE.
 *   5. STANDBY: CMD_RESPONSE -> target_complete_cmd() GOOD status.
 *
 * ha_fwd_entry LIFETIME
 * ---------------------
 * Each in-flight command is tracked by an ha_fwd_entry with kref-based
 * reference counting.  The entry starts with kref = 2:
 *
 *   ref 1 -- "hash ref": held while the entry is in ha_fwd_ht; dropped
 *            by whoever calls hash_del() (CMD_RESPONSE handler, disconnect
 *            handler, or forward_cmd send-failure path).
 *
 *   ref 2 -- "caller ref": held by forward_cmd() until sends complete
 *            (success or failure); ensures the entry is not freed while
 *            forward_cmd still has a pointer to it.
 *
 * The entry is freed (kfree'd) when both refs are dropped.
 * target_complete_cmd() is called exactly once per entry: either by the
 * CMD_RESPONSE handler (success path) or by the disconnect/failure paths.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/unaligned.h>
#include <scsi/scsi_cmnd.h>    /* SCSI_SENSE_BUFFERSIZE */

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/target_core_ha.h>

#include "lio_ha.h"
#include "lio_ha_wire.h"
#include "lio_ha_tcp.h"
#include "lio_ha_recv.h"
#include "lio_ha_fwd.h"

/* ------------------------------------------------------------------ */
/* In-flight command table                                             */
/* ------------------------------------------------------------------ */

struct ha_fwd_entry {
	u64             cookie;   /* (u64)se_cmd -- unique per-command */
	struct se_cmd  *cmd;
	struct hlist_node node;
	struct kref     kref;     /* 2 on creation: hash ref + caller ref */
};

/*
 * Pending READ data (ACTIVE -> STANDBY): buffered in ha_fwd_data_ht
 * between the DATA channel message and the CMD_RESPONSE message.
 */
struct ha_fwd_data_entry {
	u64             cookie;
	void           *data;     /* kvmalloc'd buffer */
	u32             len;
	struct hlist_node node;
};

#define HA_FWD_HT_BITS  8

static DEFINE_HASHTABLE(ha_fwd_ht, HA_FWD_HT_BITS);
static DEFINE_SPINLOCK(ha_fwd_lock);

static DEFINE_HASHTABLE(ha_fwd_data_ht, HA_FWD_HT_BITS);
static DEFINE_SPINLOCK(ha_fwd_data_lock);

/* ------------------------------------------------------------------ */
/* ha_fwd_entry lifetime helpers                                       */
/* ------------------------------------------------------------------ */

static void ha_fwd_entry_kref_release(struct kref *k)
{
	kfree(container_of(k, struct ha_fwd_entry, kref));
}

static void ha_fwd_entry_put(struct ha_fwd_entry *e)
{
	kref_put(&e->kref, ha_fwd_entry_kref_release);
}

/*
 * Allocate an entry with kref = 2.
 * Ref 1 is for the hash table (dropped when removed from ha_fwd_ht).
 * Ref 2 is for the forward_cmd caller (dropped when sends complete).
 */
static struct ha_fwd_entry *ha_fwd_entry_alloc(u64 cookie, struct se_cmd *cmd)
{
	struct ha_fwd_entry *e = kzalloc(sizeof(*e), GFP_KERNEL);

	if (!e)
		return NULL;
	e->cookie = cookie;
	e->cmd    = cmd;
	kref_init(&e->kref);   /* count = 1 */
	kref_get(&e->kref);    /* count = 2 */
	return e;
}

/* ------------------------------------------------------------------ */
/* TCP send helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Send WRITE data (DMA_TO_DEVICE) on the DATA channel before CMD_FORWARD.
 * ACTIVE buffers this by cookie; ha_recv_write_pending() picks it up.
 */
static int ha_fwd_send_write_data(struct se_cmd *cmd, u64 cookie)
{
	size_t data_len = cmd->data_length;
	size_t buf_len  = sizeof(struct lio_ha_data_hdr) + data_len;
	struct lio_ha_data_hdr *dhdr;
	u8 *buf;
	int ret;

	buf = kvmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	dhdr = (struct lio_ha_data_hdr *)buf;
	dhdr->cmd_cookie = cpu_to_be64(cookie);

	sg_copy_to_buffer(cmd->t_data_sg, cmd->t_data_nents,
			  buf + sizeof(*dhdr), data_len);

	lio_ha_dbg(3, "fwd write data: cookie=%016llx len=%zu\n",
		   (unsigned long long)cookie, data_len);
	ret = lio_ha_tcp_send(LIO_HA_CHAN_DATA, buf, (u32)buf_len);
	kvfree(buf);
	return ret;
}

/* Build and send CMD_FORWARD on the CTL channel. */
static int ha_fwd_send_cmd_forward(struct se_cmd *cmd, u64 cookie)
{
	struct lio_ha_msg_cmd_forward fwd = {};

	fwd.hdr.type    = cpu_to_be32(LIO_HA_MSG_CMD_FORWARD);
	fwd.session_id  = cpu_to_be64(cmd->se_sess ? (u64)cmd->se_sess : 0);
	fwd.cmd_cookie  = cpu_to_be64(cookie);
	fwd.data_length = cpu_to_be64(cmd->data_length);
	fwd.lun         = cpu_to_be32((u32)cmd->orig_fe_lun);
	fwd.data_dir    = cpu_to_be32((u32)cmd->data_direction);
	/*
	 * t_task_cdb points to __t_task_cdb[TCM_MAX_COMMAND_SIZE] (32 bytes)
	 * for standard CDBs.  LIO_HA_CDB_LEN == TCM_MAX_COMMAND_SIZE == 32.
	 */
	memcpy(fwd.cdb, cmd->t_task_cdb, LIO_HA_CDB_LEN);

	return lio_ha_tcp_send(LIO_HA_CHAN_CTL, &fwd, sizeof(fwd));
}

/* ------------------------------------------------------------------ */
/* Main forward entry point                                            */
/* ------------------------------------------------------------------ */

void lio_ha_forward_cmd(struct se_cmd *cmd)
{
	u64 cookie = (u64)cmd;
	struct ha_fwd_entry *e;
	bool still_in_hash;
	int ret;

	e = ha_fwd_entry_alloc(cookie, cmd);
	if (!e) {
		pr_warn_ratelimited("ha_fwd: OOM for in-flight entry\n");
		target_complete_cmd(cmd, SAM_STAT_BUSY);
		return;
	}

	/* Add to in-flight table (hash holds ref 1; caller holds ref 2). */
	spin_lock(&ha_fwd_lock);
	hash_add(ha_fwd_ht, &e->node, cookie);
	spin_unlock(&ha_fwd_lock);

	lio_ha_dbg(2, "forward cmd: cookie=%016llx opcode=0x%02x len=%u\n",
		   (unsigned long long)cookie,
		   cmd->t_task_cdb[0],
		   (unsigned int)cmd->data_length);

	/*
	 * For WRITE: send DATA channel first.  TCP ordering guarantees
	 * ACTIVE sees the data before CMD_FORWARD on the same connection.
	 */
	if (cmd->data_direction == DMA_TO_DEVICE && cmd->data_length > 0) {
		ret = ha_fwd_send_write_data(cmd, cookie);
		if (ret)
			goto send_fail;
	}

	ret = ha_fwd_send_cmd_forward(cmd, cookie);
	if (ret)
		goto send_fail;

	/* Success: drop caller ref (ref 2->1); entry now lives until CMD_RESPONSE. */
	ha_fwd_entry_put(e);
	return;

send_fail:
	/*
	 * Atomically check whether the entry is still in the hash.  If the
	 * disconnect handler ran concurrently it will have already removed
	 * the entry, dropped the hash ref, and called target_complete_cmd().
	 * We must not complete cmd a second time.
	 *
	 * While we hold ha_fwd_lock, e cannot be freed: kref >= 1 because
	 * we still hold ref 2 (caller ref), so kref_put inside the lock
	 * would only reach 1, not 0.  We are safe to call hlist_unhashed().
	 */
	spin_lock(&ha_fwd_lock);
	still_in_hash = !hlist_unhashed(&e->node);
	if (still_in_hash)
		hash_del(&e->node);
	spin_unlock(&ha_fwd_lock);

	if (still_in_hash) {
		ha_fwd_entry_put(e);   /* drop hash ref:   kref 2->1 */
		ha_fwd_entry_put(e);   /* drop caller ref: kref 1->0 -> kfree */
		target_complete_cmd(cmd, SAM_STAT_BUSY);
	} else {
		/*
		 * Disconnect handler already owns the entry: it dropped the
		 * hash ref and called target_complete_cmd().  We only need to
		 * drop our caller ref, which frees the entry.
		 */
		ha_fwd_entry_put(e);   /* drop caller ref: kref 1->0 -> kfree */
	}
}

/* ------------------------------------------------------------------ */
/* TMR in-flight table and helpers                                     */
/* ------------------------------------------------------------------ */

struct ha_fwd_tmr_entry {
	u64             cookie;   /* (u64)se_cmd */
	struct se_cmd  *cmd;
	struct hlist_node node;
	struct kref     kref;     /* 2 on creation: hash ref + caller ref */
};

static DEFINE_HASHTABLE(ha_fwd_tmr_ht, HA_FWD_HT_BITS);
static DEFINE_SPINLOCK(ha_fwd_tmr_lock);

static void ha_fwd_tmr_entry_kref_release(struct kref *k)
{
	kfree(container_of(k, struct ha_fwd_tmr_entry, kref));
}

static void ha_fwd_tmr_entry_put(struct ha_fwd_tmr_entry *e)
{
	kref_put(&e->kref, ha_fwd_tmr_entry_kref_release);
}

static struct ha_fwd_tmr_entry *ha_fwd_tmr_entry_alloc(u64 cookie,
						       struct se_cmd *cmd)
{
	struct ha_fwd_tmr_entry *e = kzalloc(sizeof(*e), GFP_KERNEL);

	if (!e)
		return NULL;
	e->cookie = cookie;
	e->cmd    = cmd;
	kref_init(&e->kref);   /* count = 1 */
	kref_get(&e->kref);    /* count = 2 */
	return e;
}

/* ------------------------------------------------------------------ */
/* TMR forward entry point                                             */
/* ------------------------------------------------------------------ */

void lio_ha_forward_tmr(struct se_cmd *cmd)
{
	u64 cookie = (u64)cmd;
	struct se_tmr_req *tmr = cmd->se_tmr_req;
	struct lio_ha_msg_tmr_forward fwd = {};
	struct ha_fwd_tmr_entry *e;
	bool still_in_hash;
	int ret;

	e = ha_fwd_tmr_entry_alloc(cookie, cmd);
	if (!e) {
		pr_warn_ratelimited("ha_fwd: OOM for TMR in-flight entry\n");
		cmd->se_tmr_req->response = TMR_FUNCTION_REJECTED;
		target_complete_tmr(cmd);
		return;
	}

	spin_lock(&ha_fwd_tmr_lock);
	hash_add(ha_fwd_tmr_ht, &e->node, cookie);
	spin_unlock(&ha_fwd_tmr_lock);

	fwd.hdr.type   = cpu_to_be32(LIO_HA_MSG_TMR_FORWARD);
	fwd.session_id = cpu_to_be64(cmd->se_sess ? (u64)cmd->se_sess : 0);
	fwd.cmd_cookie = cpu_to_be64(cookie);
	fwd.ref_cookie = cpu_to_be64(tmr->ref_task_tag);
	fwd.function   = cpu_to_be32((u32)tmr->function);
	fwd.lun        = cpu_to_be32((u32)cmd->orig_fe_lun);

	lio_ha_dbg(2, "forward tmr: cookie=%016llx function=%u lun=%u\n",
		   (unsigned long long)cookie, tmr->function,
		   (unsigned int)cmd->orig_fe_lun);

	ret = lio_ha_tcp_send(LIO_HA_CHAN_CTL, &fwd, sizeof(fwd));
	if (ret)
		goto send_fail;

	/* Success: drop caller ref; entry lives until TMR_RESPONSE. */
	ha_fwd_tmr_entry_put(e);
	return;

send_fail:
	spin_lock(&ha_fwd_tmr_lock);
	still_in_hash = !hlist_unhashed(&e->node);
	if (still_in_hash)
		hash_del(&e->node);
	spin_unlock(&ha_fwd_tmr_lock);

	if (still_in_hash) {
		ha_fwd_tmr_entry_put(e);   /* drop hash ref:   kref 2->1 */
		ha_fwd_tmr_entry_put(e);   /* drop caller ref: kref 1->0 -> kfree */
		cmd->se_tmr_req->response = TMR_FUNCTION_REJECTED;
		target_complete_tmr(cmd);
	} else {
		ha_fwd_tmr_entry_put(e);   /* drop caller ref: kref 1->0 -> kfree */
	}
}

/* ------------------------------------------------------------------ */
/* CMD_RESPONSE CTL handler (ACTIVE -> STANDBY)                     */
/* ------------------------------------------------------------------ */

/*
 * lio_ha_replace_port_info - fix port-specific VPD 0x83 designators.
 *
 * When VPD page 0x83 (Device Identification) is forwarded to ACTIVE and
 * the response returned, the Relative Target Port Identifier and Target
 * Port Group designators reflect ACTIVE's port.  Patch them with the local
 * (STANDBY) values so the initiator sees the port it is actually connected to.
 *
 * The iSCSI SCSI name string designator (UTF-8, type 3) also encodes the TPG
 * tag in the form "iqn...,t,0x<tag>".  The tag suffix is patched in-place to
 * reflect STANDBY's tpg_rtpi (same fixed-width %04x format LIO uses).
 *
 * All other designators (NAA, T10 serial, etc.) are device-wide and correct
 * as received from ACTIVE.
 *
 * TPG tag assignment table (see middlewared/utils/iscsi/constants.py):
 *
 *   Fabric              Node A tag                Node B tag
 *   ------------------  ------------------------  ------------------
 *   iSCSI               rel_tgt_id                rel_tgt_id + 32000
 *   FC HBA M, target R  R + 5000 + M*1000         same + 32000
 */
static void lio_ha_replace_port_info(struct se_cmd *cmd, u8 *buf, size_t len)
{
	struct se_lun *lun = cmd->se_lun;
	struct t10_alua_tg_pt_gp *tg_pt_gp;
	u8 *p, *end;
	u16 page_length, tg_pt_gp_id;

	if (!lun || !lun->lun_tpg)
		return;

	/* Only VPD page 0x83 (Device Identification): EVPD=1, page_code=0x83 */
	if (!(cmd->t_task_cdb[1] & 0x01) || cmd->t_task_cdb[2] != 0x83)
		return;
	if (len < 4)
		return;

	page_length = get_unaligned_be16(buf + 2);
	end = buf + min_t(size_t, len, 4 + (size_t)page_length);

	rcu_read_lock();
	tg_pt_gp = rcu_dereference(lun->lun_tg_pt_gp);
	tg_pt_gp_id = tg_pt_gp ? tg_pt_gp->tg_pt_gp_id : 0;
	rcu_read_unlock();

	for (p = buf + 4; p + 4 <= end; p += 4 + p[3]) {
		u8 code_set        = p[0] & 0x0f;
		u8 association     = (p[1] & 0x30) >> 4;
		u8 designator_type = p[1] & 0x0f;

		if (association != 1)
			continue;

		if (code_set == 1 && p[3] == 4) {
			/* Binary 4-byte target-port designators */
			switch (designator_type) {
			case 4: /* Relative Target Port Identifier */
				put_unaligned_be16(lun->lun_tpg->tpg_rtpi, p + 6);
				break;
			case 5: /* Target Port Group */
				put_unaligned_be16(tg_pt_gp_id, p + 6);
				break;
			}
		} else if (code_set == 3 && designator_type == 8) {
			/*
			 * SCSI name string (code_set=3 UTF-8, type=8, iSCSI):
			 * "iqn...,t,0x<tag>" where <tag> is %04x.
			 * Patch the 4-hex-digit tag to match our tpg_rtpi.
			 */
			static const char marker[] = ",t,0x";
			char *pos;
			char hex[5];

			if (p + 4 + p[3] > end)
				continue;
			pos = strnstr((char *)(p + 4), marker, p[3]);
			if (!pos)
				continue;
			/* Ensure 4 hex digits fit after the marker */
			if ((u8 *)(pos + sizeof(marker) - 1 + 4) > p + 4 + p[3])
				continue;
			snprintf(hex, sizeof(hex), "%04x",
				 lun->lun_tpg->tpg_rtpi);
			memcpy(pos + sizeof(marker) - 1, hex, 4);
		}
	}
}

static void ha_fwd_cmd_response_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_cmd_response *resp = buf;
	struct ha_fwd_entry *e = NULL;
	struct ha_fwd_data_entry *de = NULL;
	struct se_cmd *cmd = NULL;
	u64 cookie;
	u8 scsi_status, sense_len;

	if (len < sizeof(*resp)) {
		pr_warn("ha_fwd: CMD_RESPONSE too short (%zu bytes)\n", len);
		return;
	}

	cookie      = be64_to_cpu(resp->cmd_cookie);
	scsi_status = resp->scsi_status;
	sense_len   = resp->sense_len;

	lio_ha_dbg(2, "cmd response: cookie=%016llx status=0x%02x sense_len=%u\n",
		   (unsigned long long)cookie, scsi_status, sense_len);

	if (sense_len > 0 && len < sizeof(*resp) + sense_len) {
		pr_warn("ha_fwd: CMD_RESPONSE truncated sense_len=%u total=%zu\n", sense_len, len);
		return;
	}

	/* Remove entry from in-flight table (drops hash ref). */
	spin_lock(&ha_fwd_lock);
	hash_for_each_possible(ha_fwd_ht, e, node, cookie) {
		if (e->cookie == cookie) {
			cmd = e->cmd;
			hash_del(&e->node);
			break;
		}
		e = NULL;
	}
	spin_unlock(&ha_fwd_lock);

	if (!cmd) {
		pr_debug("ha_fwd: CMD_RESPONSE for unknown cookie %llu\n",
			 (unsigned long long)cookie);
		return;
	}

	/* Pick up buffered READ data (sent by ACTIVE before CMD_RESPONSE). */
	spin_lock(&ha_fwd_data_lock);
	hash_for_each_possible(ha_fwd_data_ht, de, node, cookie) {
		if (de->cookie == cookie) {
			hash_del(&de->node);
			break;
		}
		de = NULL;
	}
	spin_unlock(&ha_fwd_data_lock);

	if (de) {
		if (cmd->t_data_sg && cmd->t_data_nents) {
			if (scsi_status == SAM_STAT_GOOD)
				lio_ha_replace_port_info(cmd, de->data, de->len);
			sg_copy_from_buffer(cmd->t_data_sg, cmd->t_data_nents,
					    de->data, de->len);
		}
		kvfree(de->data);
		kfree(de);
	}

	/* Populate sense buffer for CHECK_CONDITION. */
	if (scsi_status == SAM_STAT_CHECK_CONDITION && sense_len > 0) {
		u8 actual = min_t(u8, sense_len, SCSI_SENSE_BUFFERSIZE);

		memcpy(cmd->sense_buffer,
		       (const u8 *)buf + sizeof(*resp), actual);
		cmd->scsi_sense_length = actual;
		/*
		 * SCF_TRANSPORT_TASK_SENSE tells target_complete_cmd_with_sense
		 * that cmd->sense_buffer already contains the real sense data
		 * (success=1 path -> transport_send_check_condition_and_sense
		 * with from_transport=1).  Without this flag, success=0 ->
		 * target_complete_failure_work -> transport_generic_request_failure
		 * overwrites the sense with a generic HARDWARE ERROR.
		 */
		cmd->se_cmd_flags |= SCF_TRANSPORT_TASK_SENSE;
	}

	/*
	 * Drop the hash ref.  At this point the caller ref was already
	 * dropped by forward_cmd() (success path), so kref reaches 0 here.
	 */
	ha_fwd_entry_put(e);   /* kref 1->0 -> kfree */

	target_complete_cmd(cmd, scsi_status);
}

/* ------------------------------------------------------------------ */
/* TMR_RESPONSE CTL handler (ACTIVE -> STANDBY)                     */
/* ------------------------------------------------------------------ */

static void ha_fwd_tmr_response_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_tmr_response *resp = buf;
	struct ha_fwd_tmr_entry *e = NULL;
	struct se_cmd *cmd = NULL;
	u64 cookie;
	u32 response;

	if (len < sizeof(*resp)) {
		pr_warn("ha_fwd: TMR_RESPONSE too short (%zu bytes)\n", len);
		return;
	}

	cookie   = be64_to_cpu(resp->cmd_cookie);
	response = be32_to_cpu(resp->response);

	lio_ha_dbg(2, "tmr response: cookie=%016llx response=%u\n",
		   (unsigned long long)cookie, response);

	spin_lock(&ha_fwd_tmr_lock);
	hash_for_each_possible(ha_fwd_tmr_ht, e, node, cookie) {
		if (e->cookie == cookie) {
			cmd = e->cmd;
			hash_del(&e->node);
			break;
		}
		e = NULL;
	}
	spin_unlock(&ha_fwd_tmr_lock);

	if (!cmd) {
		pr_debug("ha_fwd: TMR_RESPONSE for unknown cookie %llu\n",
			 (unsigned long long)cookie);
		return;
	}

	cmd->se_tmr_req->response = (u8)response;
	ha_fwd_tmr_entry_put(e);   /* drop hash ref: kref 1->0 -> kfree */
	target_complete_tmr(cmd);
}

/* ------------------------------------------------------------------ */
/* DATA-channel handler                                                */
/* ------------------------------------------------------------------ */

/*
 * Called by the TCP rx kthread for each DATA-channel message.
 *
 * READ response (A->S): cookie matches an entry in ha_fwd_ht -> buffer the
 * data until the CMD_RESPONSE arrives.
 *
 * WRITE data (S->A): cookie not in ha_fwd_ht -> forward to lio_ha_recv_data_rx()
 * on the ACTIVE side (both roles run in the same module).
 */
static void ha_fwd_data_handler(u64 cookie, const void *data, u32 data_len)
{
	struct ha_fwd_entry *e = NULL;

	/* Is this READ response data for a STANDBY in-flight command? */
	spin_lock(&ha_fwd_lock);
	hash_for_each_possible(ha_fwd_ht, e, node, cookie) {
		if (e->cookie == cookie)
			break;
		e = NULL;
	}
	spin_unlock(&ha_fwd_lock);

	if (e) {
		lio_ha_dbg(3, "data rx: READ response cookie=%016llx len=%u\n",
			   (unsigned long long)cookie, data_len);
		/* READ data from ACTIVE -- buffer for CMD_RESPONSE handler. */
		struct ha_fwd_data_entry *de = kzalloc(sizeof(*de), GFP_KERNEL);

		if (!de)
			return;
		de->cookie = cookie;
		de->data   = kvmalloc(data_len, GFP_KERNEL);
		if (!de->data) {
			kfree(de);
			return;
		}
		memcpy(de->data, data, data_len);
		de->len = data_len;

		spin_lock(&ha_fwd_data_lock);
		hash_add(ha_fwd_data_ht, &de->node, cookie);
		spin_unlock(&ha_fwd_data_lock);
	} else {
		lio_ha_dbg(3, "data rx: WRITE data cookie=%016llx len=%u\n",
			   (unsigned long long)cookie, data_len);
		/*
		 * WRITE data destined for ACTIVE's ha_recv layer.  On a
		 * STANDBY node ha_recv is initialised but only acts as a
		 * data store here; on an ACTIVE node this is the normal path.
		 */
		lio_ha_recv_data_rx(cookie, data, data_len);
	}
}

/* ------------------------------------------------------------------ */
/* Disconnect handler                                                  */
/* ------------------------------------------------------------------ */

/*
 * Called by the TCP layer on link drop (not during module exit).
 * Completes all in-flight commands with SAM_STAT_BUSY so initiators retry.
 */
static void ha_fwd_disconnect_handler(void)
{
	struct ha_fwd_entry *e;
	struct ha_fwd_data_entry *de;
	struct ha_fwd_tmr_entry *te;
	struct hlist_node *tmp, *tmp_tmr;
	int bkt;

	lio_ha_dbg(1, "link dropped: draining in-flight command tables\n");

	/*
	 * Drain the in-flight table.  We drop the hash ref here; the caller
	 * ref (ref 2) is still held by forward_cmd() if it is concurrently
	 * in the send path.  kfree happens when both refs reach 0.
	 *
	 * We save cmd before ha_fwd_entry_put because the put might free the
	 * entry immediately (if the caller ref was already dropped), after
	 * which e->cmd is no longer safe to dereference.
	 */
	spin_lock(&ha_fwd_lock);
	hash_for_each_safe(ha_fwd_ht, bkt, tmp, e, node) {
		struct se_cmd *cmd = e->cmd;

		hash_del(&e->node);
		spin_unlock(&ha_fwd_lock);

		ha_fwd_entry_put(e);            /* drop hash ref */
		target_complete_cmd(cmd, SAM_STAT_BUSY);

		spin_lock(&ha_fwd_lock);
	}
	spin_unlock(&ha_fwd_lock);

	/* Flush any pending READ data -- no CMD_RESPONSE will arrive now. */
	spin_lock(&ha_fwd_data_lock);
	hash_for_each_safe(ha_fwd_data_ht, bkt, tmp, de, node) {
		hash_del(&de->node);
		spin_unlock(&ha_fwd_data_lock);
		kvfree(de->data);
		kfree(de);
		spin_lock(&ha_fwd_data_lock);
	}
	spin_unlock(&ha_fwd_data_lock);

	/* Drain in-flight TMR table -- no TMR_RESPONSE will arrive now. */
	spin_lock(&ha_fwd_tmr_lock);
	hash_for_each_safe(ha_fwd_tmr_ht, bkt, tmp_tmr, te, node) {
		struct se_cmd *tcmd = te->cmd;

		hash_del(&te->node);
		spin_unlock(&ha_fwd_tmr_lock);

		ha_fwd_tmr_entry_put(te);   /* drop hash ref */
		tcmd->se_tmr_req->response = TMR_FUNCTION_REJECTED;
		target_complete_tmr(tcmd);

		spin_lock(&ha_fwd_tmr_lock);
	}
	spin_unlock(&ha_fwd_tmr_lock);
}

/* ------------------------------------------------------------------ */
/* PERS_ACTION CTL handler (ACTIVE -> STANDBY)                        */
/* ------------------------------------------------------------------ */

/*
 * Called by the TCP rx kthread on STANDBY when a PERS_ACTION message
 * arrives from ACTIVE.  Applies the incremental PR mutation to the
 * in-memory replicated PR table.
 */
static void ha_fwd_pers_action_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_pers_action *msg = buf;
	char dev_name[LIO_HA_DEV_NAME_LEN];
	char initiator_name[LIO_HA_INITIATOR_NAME_LEN];
	char fabric_name[LIO_HA_FABRIC_NAME_LEN];
	u8   action;
	u64  res_key, sa_res_key;
	u8   res_type;

	if (len < sizeof(*msg)) {
		pr_warn("ha_fwd: PERS_ACTION too short (%zu bytes)\n", len);
		return;
	}
	action     = (u8)be32_to_cpu(msg->action);
	res_key    = be64_to_cpu(msg->res_key);
	sa_res_key = be64_to_cpu(msg->sa_res_key);
	res_type   = msg->res_type;
	strscpy(dev_name, msg->dev_name, LIO_HA_DEV_NAME_LEN);
	strscpy(initiator_name, msg->initiator_name, LIO_HA_INITIATOR_NAME_LEN);
	strscpy(fabric_name, msg->fabric_name, LIO_HA_FABRIC_NAME_LEN);

	lio_ha_dbg(2, "PERS_ACTION: dev=%s initiator=%s action=%u\n",
		   dev_name, initiator_name, action);
	lio_ha_pr_apply(action, dev_name, initiator_name, fabric_name,
			res_key, sa_res_key, res_type);
}

/* ------------------------------------------------------------------ */
/* LUN_SYNC / LUN_SYNC_DONE CTL handlers (ACTIVE -> STANDBY)          */
/* ------------------------------------------------------------------ */

/*
 * ha_fwd_lun_sync_handler - receive bulk PR state for one device
 *
 * Called on STANDBY from the TCP rx kthread when a LUN_SYNC message
 * arrives from ACTIVE.  Replaces all PR entries for the named device in
 * the in-memory replicated PR table:
 *
 *   1. CLEAR all existing entries for this device.
 *   2. REGISTER each initiator entry found in the APTPL text.
 *   3. After all registrations are in the table, RESERVE for the holder
 *      (if any) -- lio_ha_pr_apply(RESERVE) iterates all entries for
 *      the device and sets/clears res_holder, so applying it last
 *      ensures it operates on the complete, final set of registrations.
 *
 * A LUN_SYNC with aptpl_buf_len == 0 is valid: it signals that the device
 * has no registrations (CLEAR only).
 */
static void ha_fwd_lun_sync_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_lun_sync *msg = buf;
	char dev_name[LIO_HA_DEV_NAME_LEN];
	const char *aptpl;
	const char *aptpl_end;
	const char *line;
	u32 aptpl_len;
	/* Holder info: collected across all lines, applied last. */
	char holder_name[LIO_HA_INITIATOR_NAME_LEN] = {};
	char holder_fabric[LIO_HA_FABRIC_NAME_LEN] = {};
	u8   holder_type = 0;
	bool have_holder = false;

	if (len < sizeof(*msg)) {
		pr_warn("ha_fwd: LUN_SYNC too short (%zu bytes)\n", len);
		return;
	}
	aptpl_len = be32_to_cpu(msg->aptpl_buf_len);
	if (sizeof(*msg) + (size_t)aptpl_len > len) {
		pr_warn("ha_fwd: LUN_SYNC aptpl_buf_len overflows message\n");
		return;
	}
	strscpy(dev_name, msg->dev_name, LIO_HA_DEV_NAME_LEN);

	/* Clear all existing PR entries for this device. */
	lio_ha_pr_apply(LIO_HA_PR_CLEAR, dev_name, "", "", 0, 0, 0);

	if (!aptpl_len)
		return;

	aptpl     = (const char *)buf + sizeof(*msg);
	aptpl_end = aptpl + aptpl_len;

	/* Parse each line; register each entry and collect the holder. */
	line = aptpl;
	while (line < aptpl_end) {
		char linebuf[512];
		char initiator_name[LIO_HA_INITIATOR_NAME_LEN] = {};
		char fabric_name[LIO_HA_FABRIC_NAME_LEN] = {};
		const char *end;
		char *tok, *rest;
		size_t line_len;
		u64 res_key = 0;
		u8  res_holder = 0, res_type = 0;
		bool have_init = false;

		end = memchr(line, '\n', aptpl_end - line);
		line_len = end ? (size_t)(end - line) : (size_t)(aptpl_end - line);

		if (!line_len) {
			line = end ? end + 1 : aptpl_end;
			continue;
		}
		if (line_len >= sizeof(linebuf)) {
			pr_warn_ratelimited("ha_fwd: LUN_SYNC line too long (%zu), skipping\n",
					    line_len);
			line = end ? end + 1 : aptpl_end;
			continue;
		}
		memcpy(linebuf, line, line_len);
		linebuf[line_len] = '\0';

		rest = linebuf;
		while ((tok = strsep(&rest, ",")) != NULL) {
			unsigned long v;
			u64 u;

			if (!strncmp(tok, "initiator_fabric=", 17)) {
				strscpy(fabric_name, tok + 17,
					LIO_HA_FABRIC_NAME_LEN);
			} else if (!strncmp(tok, "initiator_node=", 15)) {
				strscpy(initiator_name, tok + 15,
					LIO_HA_INITIATOR_NAME_LEN);
				have_init = true;
			} else if (!strncmp(tok, "sa_res_key=", 11)) {
				if (!kstrtoull(tok + 11, 10, &u))
					res_key = u;
			} else if (!strncmp(tok, "res_holder=", 11)) {
				if (!kstrtoul(tok + 11, 10, &v))
					res_holder = (u8)v;
			} else if (!strncmp(tok, "res_type=", 9)) {
				if (!kstrtoul(tok + 9, 10, &v))
					res_type = (u8)v;
			}
		}

		if (have_init && initiator_name[0] && res_key != 0) {
			lio_ha_pr_apply(LIO_HA_PR_REGISTER, dev_name,
					initiator_name, fabric_name,
					0, res_key, 0);
			if (res_holder) {
				strscpy(holder_name, initiator_name,
					LIO_HA_INITIATOR_NAME_LEN);
				strscpy(holder_fabric, fabric_name,
					LIO_HA_FABRIC_NAME_LEN);
				holder_type  = res_type;
				have_holder  = true;
			}
		}

		line = end ? end + 1 : aptpl_end;
	}

	/*
	 * RESERVE for the holder after all registrations are in.
	 *
	 * We track a single holder_name/holder_fabric pair.  LIO only sets
	 * pr_res_holder=1 on the one registration that actually holds the
	 * reservation; ALL_TG_PT replication creates additional registrations
	 * for other ports but does not set pr_res_holder on them.  So
	 * target_ha_pr_export() will emit at most one res_holder=1 line per
	 * device, and the scalar holder_* variables are sufficient.
	 */
	if (have_holder)
		lio_ha_pr_apply(LIO_HA_PR_RESERVE, dev_name, holder_name,
				holder_fabric, 0, 0, holder_type);
}

/*
 * ha_fwd_lun_sync_done_handler - all LUN_SYNCs for this cycle are done
 *
 * Advances ha_state from CONNECTED to SYNCED.  Middleware polls ha_state
 * and writes ALUA NONOPTIMIZED only after seeing "synced".
 */
static void ha_fwd_lun_sync_done_handler(const void *buf, size_t len)
{
	spin_lock(&lio_ha_cfg.lock);
	lio_ha_cfg.ha_state = LIO_HA_SYNCED;
	spin_unlock(&lio_ha_cfg.lock);
	pr_info("lio_ha: LUN_SYNC complete -- ha_state = synced\n");
}

/* ------------------------------------------------------------------ */
/* Init / exit                                                         */
/* ------------------------------------------------------------------ */

int lio_ha_fwd_init(void)
{
	hash_init(ha_fwd_ht);
	hash_init(ha_fwd_data_ht);
	hash_init(ha_fwd_tmr_ht);

	/* STANDBY-only: messages received from ACTIVE. */
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_CMD_RESPONSE,
					ha_fwd_cmd_response_handler);
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_TMR_RESPONSE,
					ha_fwd_tmr_response_handler);
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_PERS_ACTION,
					ha_fwd_pers_action_handler);
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_LUN_SYNC,
					ha_fwd_lun_sync_handler);
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_LUN_SYNC_DONE,
					ha_fwd_lun_sync_done_handler);
	/* Both roles: DATA and disconnect are handled on ACTIVE and STANDBY. */
	lio_ha_tcp_register_data_handler(ha_fwd_data_handler);
	lio_ha_tcp_register_disconnect_handler(ha_fwd_disconnect_handler);

	pr_debug("ha_fwd: initialized\n");
	return 0;
}

void lio_ha_fwd_exit(void)
{
	struct ha_fwd_entry *e;
	struct ha_fwd_data_entry *de;
	struct ha_fwd_tmr_entry *te;
	struct hlist_node *tmp;
	int bkt;

	/*
	 * Defensive flush.  By the time we reach here, lio_ha_tcp_exit()
	 * has already stopped the TCP channel and the disconnect handler
	 * should have drained all tables.  These loops catch anything left
	 * over (e.g., entries added after the disconnect handler ran).
	 */
	spin_lock(&ha_fwd_lock);
	hash_for_each_safe(ha_fwd_ht, bkt, tmp, e, node) {
		struct se_cmd *cmd = e->cmd;

		hash_del(&e->node);
		spin_unlock(&ha_fwd_lock);
		ha_fwd_entry_put(e);
		target_complete_cmd(cmd, SAM_STAT_BUSY);
		spin_lock(&ha_fwd_lock);
	}
	spin_unlock(&ha_fwd_lock);

	spin_lock(&ha_fwd_data_lock);
	hash_for_each_safe(ha_fwd_data_ht, bkt, tmp, de, node) {
		hash_del(&de->node);
		spin_unlock(&ha_fwd_data_lock);
		kvfree(de->data);
		kfree(de);
		spin_lock(&ha_fwd_data_lock);
	}
	spin_unlock(&ha_fwd_data_lock);

	spin_lock(&ha_fwd_tmr_lock);
	hash_for_each_safe(ha_fwd_tmr_ht, bkt, tmp, te, node) {
		struct se_cmd *cmd = te->cmd;

		hash_del(&te->node);
		spin_unlock(&ha_fwd_tmr_lock);
		ha_fwd_tmr_entry_put(te);
		cmd->se_tmr_req->response = TMR_FUNCTION_REJECTED;
		target_complete_tmr(cmd);
		spin_lock(&ha_fwd_tmr_lock);
	}
	spin_unlock(&ha_fwd_tmr_lock);

	pr_debug("ha_fwd: exited\n");
}
