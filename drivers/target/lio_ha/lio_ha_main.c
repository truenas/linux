// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lio_ha.ko -- TrueNAS LIO HA forwarding module
 *
 * Loaded on both ACTIVE and STANDBY nodes.  Provides:
 *   - lio_ha_ops registration so LIO core can forward I/O and TMRs to ACTIVE
 *   - PR change notification for incremental PR replication (PERS_ACTION)
 *   - Configfs subsystem at /sys/kernel/config/lio_ha/ for middleware to
 *     configure local_addr, peer_addr, port, and forward_active
 *
 * This file: module init/exit, configfs attributes, replicated PR table,
 * lio_ha_pr_apply(), ha_main_failover_device(), and the forward_active handler.
 *
 * See drivers/target/lio_ha/README for the full design.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/configfs.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/target_core_ha.h>

#include "lio_ha.h"
#include "lio_ha_recv.h"
#include "lio_ha_tcp.h"
#include "lio_ha_fwd.h"

/* ------------------------------------------------------------------ */
/* Module parameters                                                   */
/* ------------------------------------------------------------------ */

static int default_forward_active;
module_param(default_forward_active, int, 0444);
MODULE_PARM_DESC(default_forward_active, "Initial value of forward_active on load (default 0)");

#ifdef CONFIG_DEBUG_KERNEL
int lio_ha_debug;
module_param(lio_ha_debug, int, 0644);
MODULE_PARM_DESC(lio_ha_debug, "Trace level: 0=off 1=state 2=cmd 3=verbose");
#endif

static char default_local_addr[LIO_HA_ADDR_LEN];
module_param_string(default_local_addr, default_local_addr, LIO_HA_ADDR_LEN, 0444);
MODULE_PARM_DESC(default_local_addr, "Local HA IP address (overridden by configfs local_addr)");

static char default_peer_addr[LIO_HA_ADDR_LEN];
module_param_string(default_peer_addr, default_peer_addr, LIO_HA_ADDR_LEN, 0444);
MODULE_PARM_DESC(default_peer_addr, "Peer HA IP address (overridden by configfs peer_addr)");

/* ------------------------------------------------------------------ */
/* Module-level state                                                   */
/* ------------------------------------------------------------------ */

struct lio_ha_cfg lio_ha_cfg;

static const char * const ha_state_names[] = {
	[LIO_HA_DISCONNECTED] = "disconnected",
	[LIO_HA_CONNECTED]    = "connected",
	[LIO_HA_SYNCED]       = "synced",
};

/* ------------------------------------------------------------------ */
/* Replicated PR table (STANDBY side)                                */
/*                                                                     */
/* Maintained by lio_ha_pr_apply(), called from the PERS_ACTION TCP   */
/* handler when ACTIVE pushes incremental PR mutations.  At failover  */
/* ha_main_failover_device() snapshots this table and calls             */
/* target_ha_pr_add_reg() to inject registrations directly.           */
/* ------------------------------------------------------------------ */

struct lio_ha_pr_entry {
	char             dev_name[LIO_HA_DEV_NAME_LEN];
	char             initiator_name[LIO_HA_INITIATOR_NAME_LEN];
	char             fabric_name[LIO_HA_FABRIC_NAME_LEN];
	u64              res_key;
	u8               res_holder;  /* 1 if this entry holds the reservation */
	u8               res_type;    /* reservation type (valid when res_holder) */
	struct list_head list;
};

static LIST_HEAD(lio_ha_pr_table);
static DEFINE_SPINLOCK(lio_ha_pr_lock);

/* Work item queued by ha_main_pr_change() to send PERS_ACTION via TCP. */
struct lio_ha_pr_work {
	struct work_struct work;
	char               dev_name[LIO_HA_DEV_NAME_LEN];
	char               initiator_name[LIO_HA_INITIATOR_NAME_LEN];
	char               fabric_name[LIO_HA_FABRIC_NAME_LEN];
	u64                res_key;
	u64                sa_res_key;
	u8                 action;
	u8                 res_type;
};

static struct workqueue_struct *lio_ha_pr_wq;

/* ------------------------------------------------------------------ */
/* Shadow session table (STANDBY side)                                  */
/*                                                                     */
/* Tracks every live initiator session so SESSION_CONNECT can be       */
/* replayed on TCP link recovery.  Only entries with forward_active=1  */
/* are added.  The spinlock protects the list; lio_ha_tcp_send() must  */
/* NOT be called while it is held (lio_ha_tcp_send acquires mutexes).  */
/* ------------------------------------------------------------------ */

struct ha_main_sess_entry {
	u64  session_id;
	u16  tpg_tag;
	char initiator_name[LIO_HA_INITIATOR_NAME_LEN];
	char target_name[LIO_HA_INITIATOR_NAME_LEN];
	char fabric_name[LIO_HA_FABRIC_NAME_LEN];
	struct list_head list;
};

static LIST_HEAD(ha_main_sess_list);
static DEFINE_SPINLOCK(ha_main_sess_lock);

static void ha_main_sess_list_flush(void)
{
	struct ha_main_sess_entry *se, *tmp;
	LIST_HEAD(free_list);

	spin_lock(&ha_main_sess_lock);
	list_splice_init(&ha_main_sess_list, &free_list);
	spin_unlock(&ha_main_sess_lock);

	list_for_each_entry_safe(se, tmp, &free_list, list) {
		list_del(&se->list);
		kfree(se);
	}
}

/* Free all entries in lio_ha_pr_table. Called at module exit. */
static void ha_main_pr_table_flush(void)
{
	struct lio_ha_pr_entry *e, *tmp;
	LIST_HEAD(free_list);

	spin_lock(&lio_ha_pr_lock);
	list_splice_init(&lio_ha_pr_table, &free_list);
	spin_unlock(&lio_ha_pr_lock);

	list_for_each_entry_safe(e, tmp, &free_list, list) {
		list_del(&e->list);
		kfree(e);
	}
}

/*
 * lio_ha_pr_apply - update the replicated PR table
 *
 * Called on STANDBY from ha_fwd_pers_action_handler() when a
 * PERS_ACTION message arrives from ACTIVE, and from ha_fwd_lun_sync_handler()
 * when bulk PR state arrives.  Process context (workqueue or kthread) --
 * GFP_KERNEL is fine.
 */
void lio_ha_pr_apply(u8 action, const char *dev_name,
		     const char *initiator_name, const char *fabric_name,
		     u64 res_key, u64 sa_res_key, u8 res_type)
{
	struct lio_ha_pr_entry *e, *tmp, *new_e = NULL;
	LIST_HEAD(free_list);

	/*
	 * REGISTER_AND_MOVE (0x07) is never sent as a raw action: the ACTIVE
	 * node decomposes it inside core_scsi3_emulate_pro_register_and_move()
	 * into individual REGISTER / RESERVE / REGISTER(key=0) messages before
	 * the destination nacl reference is released.  So it can never arrive
	 * here and needs no special handling.
	 *
	 * REGISTER_AND_IGNORE (0x06) has the same effect on the replicated
	 * table as a plain REGISTER: update or create the entry with the new
	 * key, or remove it if the new key is zero.  The distinction (skip
	 * the existing-key check) only matters on ACTIVE during CDB execution.
	 * Both actions use the REGISTER case in the switch below.
	 *
	 * Pre-allocate a new entry before taking the spinlock so we can use
	 * GFP_KERNEL rather than GFP_ATOMIC.
	 */
	if ((action == LIO_HA_PR_REGISTER ||
	     action == LIO_HA_PR_REGISTER_AND_IGNORE) && sa_res_key != 0) {
		new_e = kzalloc(sizeof(*new_e), GFP_KERNEL);
		if (!new_e)
			return;
	}

	spin_lock(&lio_ha_pr_lock);

	switch ((enum lio_ha_pr_action)action) {
	case LIO_HA_PR_REGISTER_AND_IGNORE:
		/* REGISTER_AND_IGNORE: same table update as REGISTER. */
		fallthrough;
	case LIO_HA_PR_REGISTER: {
		bool found = false;

		list_for_each_entry(e, &lio_ha_pr_table, list) {
			if (strncmp(e->dev_name, dev_name,
				    LIO_HA_DEV_NAME_LEN) == 0 &&
			    strncmp(e->initiator_name, initiator_name,
				    LIO_HA_INITIATOR_NAME_LEN) == 0) {
				found = true;
				if (sa_res_key == 0)
					list_move(&e->list, &free_list);
				else
					e->res_key = sa_res_key;
				break;
			}
		}
		if (!found && sa_res_key != 0 && new_e) {
			strscpy(new_e->dev_name, dev_name, LIO_HA_DEV_NAME_LEN);
			strscpy(new_e->initiator_name, initiator_name,
				LIO_HA_INITIATOR_NAME_LEN);
			strscpy(new_e->fabric_name, fabric_name,
				LIO_HA_FABRIC_NAME_LEN);
			new_e->res_key = sa_res_key;
			list_add_tail(&new_e->list, &lio_ha_pr_table);
			new_e = NULL;
		}
		break;
	}
	case LIO_HA_PR_RESERVE:
		list_for_each_entry(e, &lio_ha_pr_table, list) {
			if (strncmp(e->dev_name, dev_name,
				    LIO_HA_DEV_NAME_LEN) != 0)
				continue;
			if (strncmp(e->initiator_name, initiator_name,
				    LIO_HA_INITIATOR_NAME_LEN) == 0) {
				e->res_holder = 1;
				e->res_type   = res_type;
			} else {
				e->res_holder = 0;
			}
		}
		break;

	case LIO_HA_PR_RELEASE:
		list_for_each_entry(e, &lio_ha_pr_table, list) {
			if (strncmp(e->dev_name, dev_name,
				    LIO_HA_DEV_NAME_LEN) == 0 &&
			    strncmp(e->initiator_name, initiator_name,
				    LIO_HA_INITIATOR_NAME_LEN) == 0) {
				e->res_holder = 0;
				e->res_type   = 0;
				break;
			}
		}
		break;

	case LIO_HA_PR_CLEAR:
		list_for_each_entry_safe(e, tmp, &lio_ha_pr_table, list) {
			if (strncmp(e->dev_name, dev_name,
				    LIO_HA_DEV_NAME_LEN) == 0)
				list_move(&e->list, &free_list);
		}
		break;

	case LIO_HA_PR_PREEMPT:
	case LIO_HA_PR_PREEMPT_AND_ABORT:
		/*
		 * Remove all registrations with sa_res_key (the preempted key)
		 * for this device, then set the preempting initiator as holder.
		 */
		list_for_each_entry_safe(e, tmp, &lio_ha_pr_table, list) {
			if (strncmp(e->dev_name, dev_name,
				    LIO_HA_DEV_NAME_LEN) == 0 &&
			    e->res_key == sa_res_key)
				list_move(&e->list, &free_list);
		}
		list_for_each_entry(e, &lio_ha_pr_table, list) {
			if (strncmp(e->dev_name, dev_name,
				    LIO_HA_DEV_NAME_LEN) != 0)
				continue;
			if (strncmp(e->initiator_name, initiator_name,
				    LIO_HA_INITIATOR_NAME_LEN) == 0) {
				e->res_holder = 1;
				e->res_type   = res_type;
			} else {
				e->res_holder = 0;
			}
		}
		break;
	}

	spin_unlock(&lio_ha_pr_lock);

	list_for_each_entry_safe(e, tmp, &free_list, list) {
		list_del(&e->list);
		kfree(e);
	}
	kfree(new_e);
}

/* Worker: builds and sends a PERS_ACTION wire message, then frees pw. */
static void ha_main_pr_work_fn(struct work_struct *work)
{
	struct lio_ha_pr_work *pw =
		container_of(work, struct lio_ha_pr_work, work);
	struct lio_ha_msg_pers_action msg = {};

	msg.hdr.type   = cpu_to_be32(LIO_HA_MSG_PERS_ACTION);
	msg.action     = cpu_to_be32(pw->action);
	msg.res_type   = pw->res_type;
	msg.res_key    = cpu_to_be64(pw->res_key);
	msg.sa_res_key = cpu_to_be64(pw->sa_res_key);
	strscpy(msg.initiator_name, pw->initiator_name, LIO_HA_INITIATOR_NAME_LEN);
	strscpy(msg.dev_name, pw->dev_name, LIO_HA_DEV_NAME_LEN);
	strscpy(msg.fabric_name, pw->fabric_name, LIO_HA_FABRIC_NAME_LEN);

	if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, &msg, sizeof(msg)))
		pr_warn_ratelimited("lio_ha: PERS_ACTION send failed for %s\n",
				    pw->dev_name);
	kfree(pw);
}

/* ------------------------------------------------------------------ */
/* Session lifecycle hooks (STANDBY side)                           */
/*                                                                     */
/* Called from target_setup_session() / target_remove_session() for   */
/* every real initiator session on this node.  When forward_active=1  */
/* (STANDBY mode), send SESSION_CONNECT / SESSION_DISCONNECT to     */
/* ACTIVE so ACTIVE creates / destroys the matching synthetic        */
/* se_session with correct LUN mappings.                              */
/*                                                                     */
/* SESSION_CONNECT carries ACTIVE's real TPG tag, not STANDBY's.     */
/* Node A tags are < LIO_HA_NODE_B_TPG_OFFSET; Node B tags are >=.  */
/* STANDBY translates: peer_tag = local_tag +/- LIO_HA_NODE_B_TPG_OFFSET. */
/* This lets ACTIVE's target_ha_lookup_tpg() find the real TPG       */
/* (with the initiator's node_acl) rather than the phantom TPG.      */
/*                                                                     */
/* Skips internal TPGs (se_tpg_wwn=NULL, e.g. ha_recv itself) and    */
/* skips when forward_active=0 (ACTIVE mode or idle).                */
/* ------------------------------------------------------------------ */

static void ha_main_session_create(struct se_session *sess)
{
	struct se_portal_group *tpg = sess->se_tpg;
	struct ha_main_sess_entry *se;
	struct lio_ha_msg_session_connect msg = {};
	const char *wwn;
	u16 local_tag, peer_tag;

	if (!atomic_read(&lio_ha_forward_active))
		return;
	/* Skip internal TPGs (ha_recv, iSCSI discovery) that have no WWN. */
	if (!tpg->se_tpg_wwn)
		return;
	if (!sess->se_node_acl)
		return;

	wwn = tpg->se_tpg_tfo->tpg_get_wwn(tpg);
	if (!wwn)
		return;

	/*
	 * Translate STANDBY's local TPG tag to ACTIVE's real TPG tag.
	 * Node A tags are < LIO_HA_NODE_B_TPG_OFFSET; Node B tags are >=.
	 * Sending ACTIVE's tag lets target_ha_lookup_tpg() on ACTIVE find
	 * the real TPG (with the initiator's node_acl) instead of the
	 * portal-less phantom TPG which carries no real ACLs.
	 */
	local_tag = tpg->se_tpg_tfo->tpg_get_tag(tpg);
	if (local_tag >= LIO_HA_NODE_B_TPG_OFFSET)
		peer_tag = local_tag - LIO_HA_NODE_B_TPG_OFFSET;
	else
		peer_tag = local_tag + LIO_HA_NODE_B_TPG_OFFSET;

	/*
	 * Track this session so SESSION_CONNECT can be replayed on TCP link
	 * recovery.  Added before the send so that if the send fails (TCP
	 * not yet connected), ha_main_on_connect() will replay it when the
	 * link comes up.  GFP_ATOMIC: called from session setup which may
	 * not sleep.
	 */
	se = kzalloc(sizeof(*se), GFP_ATOMIC);
	if (se) {
		se->session_id = (u64)(uintptr_t)sess;
		se->tpg_tag    = peer_tag;
		strscpy(se->initiator_name, sess->se_node_acl->initiatorname,
			LIO_HA_INITIATOR_NAME_LEN);
		strscpy(se->target_name, wwn, LIO_HA_INITIATOR_NAME_LEN);
		strscpy(se->fabric_name, tpg->se_tpg_tfo->fabric_name,
			LIO_HA_FABRIC_NAME_LEN);
		spin_lock(&ha_main_sess_lock);
		list_add_tail(&se->list, &ha_main_sess_list);
		spin_unlock(&ha_main_sess_lock);
	} else {
		pr_warn_ratelimited("lio_ha: session shadow alloc failed for %s; won't replay on link recovery\n",
				    sess->se_node_acl->initiatorname);
	}

	msg.hdr.type   = cpu_to_be32(LIO_HA_MSG_SESSION_CONNECT);
	msg.session_id = cpu_to_be64((u64)(uintptr_t)sess);
	msg.tpg_tag    = cpu_to_be16(peer_tag);
	/* pad[6] is zero from the initialiser */
	strscpy(msg.initiator_name, sess->se_node_acl->initiatorname,
		LIO_HA_INITIATOR_NAME_LEN);
	strscpy(msg.target_name, wwn, LIO_HA_INITIATOR_NAME_LEN);
	strscpy(msg.fabric_name, tpg->se_tpg_tfo->fabric_name,
		LIO_HA_FABRIC_NAME_LEN);

	lio_ha_dbg(1, "session create: initiator=%s target=%s fabric=%s\n",
		   sess->se_node_acl->initiatorname, wwn,
		   tpg->se_tpg_tfo->fabric_name);
	if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, &msg, sizeof(msg)))
		pr_debug("lio_ha: SESSION_CONNECT send failed for %s\n",
			 sess->se_node_acl->initiatorname);
}

static void ha_main_session_destroy(struct se_session *sess)
{
	u64 session_id = (u64)(uintptr_t)sess;
	struct ha_main_sess_entry *se, *tmp;
	struct lio_ha_msg_session_disconnect msg = {};

	if (!atomic_read(&lio_ha_forward_active))
		return;

	/* Remove from replay list regardless of TCP or TPG state. */
	spin_lock(&ha_main_sess_lock);
	list_for_each_entry_safe(se, tmp, &ha_main_sess_list, list) {
		if (se->session_id == session_id) {
			list_del(&se->list);
			kfree(se);
			break;
		}
	}
	spin_unlock(&ha_main_sess_lock);

	/* se_tpg may already be NULL if called after partial teardown. */
	if (!sess->se_tpg || !sess->se_tpg->se_tpg_wwn)
		return;

	msg.hdr.type   = cpu_to_be32(LIO_HA_MSG_SESSION_DISCONNECT);
	msg.session_id = cpu_to_be64(session_id);

	lio_ha_dbg(1, "session destroy: initiator=%s\n",
		   sess->se_node_acl ? sess->se_node_acl->initiatorname : "(null)");
	if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, &msg, sizeof(msg)))
		pr_debug("lio_ha: SESSION_DISCONNECT send failed\n");
}

static const struct lio_ha_ops ha_ops = {
	.forward_cmd     = lio_ha_forward_cmd,
	.forward_tmr     = lio_ha_forward_tmr,
	.session_create  = ha_main_session_create,
	.session_destroy = ha_main_session_destroy,
};

/* ------------------------------------------------------------------ */
/* PR notifier -- ACTIVE pushes PERS_ACTION to STANDBY              */
/*                                                                     */
/* Called from target_core_pr.c after each successful PR OUT on       */
/* ACTIVE, under RCU read lock.  Must not sleep.  Queues a work item */
/* that builds and sends the PERS_ACTION wire message via TCP.        */
/* ------------------------------------------------------------------ */

static void ha_main_pr_change(struct se_device *dev, u8 action,
			      u64 res_key, u64 sa_res_key, u8 type,
			      const char *initiator_name,
			      const char *fabric_name)
{
	struct lio_ha_pr_work *pw;

	/*
	 * On ACTIVE, forward_active == 0 (we execute locally).
	 * On STANDBY, forward_active == 1 (PR OUT should not run locally;
	 * guard here defensively).
	 */
	if (atomic_read(&lio_ha_forward_active))
		return;
	if (!lio_ha_pr_wq)
		return;

	pw = kmalloc(sizeof(*pw), GFP_ATOMIC);
	if (!pw)
		return;
	snprintf(pw->dev_name, LIO_HA_DEV_NAME_LEN, "%s/%s",
		 config_item_name(&dev->se_hba->hba_group.cg_item),
		 config_item_name(&dev->dev_group.cg_item));
	strscpy(pw->initiator_name, initiator_name, LIO_HA_INITIATOR_NAME_LEN);
	strscpy(pw->fabric_name, fabric_name, LIO_HA_FABRIC_NAME_LEN);
	pw->res_key    = res_key;
	pw->sa_res_key = sa_res_key;
	pw->action     = action;
	pw->res_type   = type;
	INIT_WORK(&pw->work, ha_main_pr_work_fn);
	lio_ha_dbg(2, "PR change: dev=%s initiator=%s action=%u key=%016llx sa=%016llx\n",
		   pw->dev_name, pw->initiator_name, pw->action,
		   (unsigned long long)pw->res_key,
		   (unsigned long long)pw->sa_res_key);
	queue_work(lio_ha_pr_wq, &pw->work);
}

static const struct lio_ha_pr_notifier pr_notifier = {
	.pr_change = ha_main_pr_change,
};

/* ------------------------------------------------------------------ */
/* LUN_SYNC -- bulk PR state export to STANDBY on TCP link up         */
/*                                                                      */
/* Called only on ACTIVE (forward_active == 0) from ha_main_on_connect */
/* when the HA TCP connection is established.  Iterates all configured  */
/* se_devices, sends one LIO_HA_MSG_LUN_SYNC per device (even those    */
/* with no registrations -- STANDBY clears stale state on receipt),   */
/* then sends LIO_HA_MSG_LUN_SYNC_DONE.  On successful send, ACTIVE   */
/* advances its own ha_state to SYNCED; STANDBY advances on receipt.  */
/* ------------------------------------------------------------------ */

/*
 * Per-device callback for target_for_each_device().
 * Exports the device's live PR state as APTPL text and sends it as a
 * LUN_SYNC CTL message.
 *
 * Starts with a 4 KiB allocation (sufficient for ~15 registrations).
 * If target_ha_pr_export() returns -ENOSPC the buffer is grown to
 * LIO_HA_MAX_CTL_PAYLOAD (64 KiB) and the export is retried once.
 * Uses kvmalloc/kvfree to avoid requiring physically contiguous pages.
 */
static int ha_main_send_lun_sync_for_device(struct se_device *dev, void *data)
{
	const size_t hdr_size = sizeof(struct lio_ha_msg_lun_sync);
	size_t buf_size = 4096;
	struct lio_ha_msg_lun_sync *msg;
	void *full_buf;
	int aptpl_len;

	/* We are ACTIVE: skip if forward_active has been set since we started. */
	if (atomic_read(&lio_ha_forward_active))
		return 0;

	full_buf = kvmalloc(buf_size, GFP_KERNEL);
	if (!full_buf)
		return 0;

	aptpl_len = target_ha_pr_export(dev, (char *)(full_buf + hdr_size),
					buf_size - hdr_size);
	if (aptpl_len == -ENOSPC) {
		kvfree(full_buf);
		buf_size = LIO_HA_MAX_CTL_PAYLOAD;
		full_buf = kvmalloc(buf_size, GFP_KERNEL);
		if (!full_buf)
			return 0;
		aptpl_len = target_ha_pr_export(dev,
						(char *)(full_buf + hdr_size),
						buf_size - hdr_size);
	}
	if (aptpl_len < 0) {
		kvfree(full_buf);
		return 0;
	}

	msg = full_buf;
	msg->hdr.type      = cpu_to_be32(LIO_HA_MSG_LUN_SYNC);
	msg->hdr.reserved  = 0;
	msg->aptpl_buf_len = cpu_to_be32((u32)aptpl_len);
	msg->reserved      = 0;
	snprintf(msg->dev_name, LIO_HA_DEV_NAME_LEN, "%s/%s",
		 config_item_name(&dev->se_hba->hba_group.cg_item),
		 config_item_name(&dev->dev_group.cg_item));

	lio_ha_dbg(3, "LUN_SYNC: %s (%d bytes APTPL)\n", msg->dev_name, aptpl_len);
	if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, full_buf,
			    (u32)(hdr_size + (size_t)aptpl_len)))
		pr_debug("lio_ha: LUN_SYNC send failed for %s\n", msg->dev_name);

	kvfree(full_buf);
	return 0;
}

/*
 * ACTIVE-side bulk LUN_SYNC: send LUN_SYNC for every device, then a
 * LUN_SYNC_DONE; on successful send, advance our own ha_state to SYNCED.
 *
 * Two callers fire this:
 *   1. ha_main_on_connect() -- wire just came up while we are PRIMARY.
 *   2. lio_ha_forward_active_store(0) -- we just became PRIMARY while
 *      the wire was already up (delayed failover).
 *
 * Self-gated on ha_state so both callers can invoke unconditionally:
 *   DISCONNECTED -> no-op (the connect handler will fire when wire returns).
 *   CONNECTED    -> send LUN_SYNC + LUN_SYNC_DONE; flip to SYNCED on success.
 *   SYNCED       -> no-op (already done; idempotent).
 */
static void ha_main_send_lun_sync_all(void)
{
	struct lio_ha_msg_lun_sync_done done = {};
	enum lio_ha_state state;

	spin_lock(&lio_ha_cfg.lock);
	state = lio_ha_cfg.ha_state;
	spin_unlock(&lio_ha_cfg.lock);

	if (state != LIO_HA_CONNECTED)
		return;

	lio_ha_dbg(1, "ACTIVE: sending LUN_SYNC for all devices\n");
	target_for_each_device(ha_main_send_lun_sync_for_device, NULL);

	done.hdr.type     = cpu_to_be32(LIO_HA_MSG_LUN_SYNC_DONE);
	done.hdr.reserved = 0;
	if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, &done, sizeof(done))) {
		pr_debug("lio_ha: LUN_SYNC_DONE send failed\n");
		return;
	}
	spin_lock(&lio_ha_cfg.lock);
	lio_ha_cfg.ha_state = LIO_HA_SYNCED;
	spin_unlock(&lio_ha_cfg.lock);
	pr_info("lio_ha: LUN_SYNC complete -- ha_state = synced\n");
}

/*
 * TCP connect handler -- registered with lio_ha_tcp_register_connect_handler().
 * Called on both ACTIVE and STANDBY whenever the HA TCP link comes up.
 *
 * ACTIVE (forward_active == 0): sends bulk PR state (LUN_SYNC per device,
 * then LUN_SYNC_DONE).  On successful send, ACTIVE advances ha_state to
 * SYNCED; STANDBY advances to SYNCED on receipt of LUN_SYNC_DONE.
 *
 * STANDBY (forward_active == 1): replays SESSION_CONNECT for every live
 * initiator session tracked in ha_main_sess_list.  Sessions added after
 * the snapshot miss this round but will be handled by the next call (or
 * will have already succeeded if the link was up when they were created).
 * ACTIVE's lio_ha_recv_session_create() is idempotent: duplicate session
 * IDs on reconnect are silently ignored.
 */
static void ha_main_on_connect(void)
{
	if (atomic_read(&lio_ha_forward_active)) {
		struct ha_main_sess_entry *se;
		struct lio_ha_msg_session_connect *snap;
		int count = 0, filled, j;

		/*
		 * Count entries first so we can allocate the right-sized
		 * snapshot array.  Snapshot under the spinlock, then send
		 * outside it: lio_ha_tcp_send acquires ha_send_lock (mutex,
		 * may sleep) which must not be called with a spinlock held.
		 */
		spin_lock(&ha_main_sess_lock);
		list_for_each_entry(se, &ha_main_sess_list, list)
			count++;
		spin_unlock(&ha_main_sess_lock);

		if (!count)
			return;

		snap = kcalloc(count, sizeof(*snap), GFP_KERNEL);
		if (!snap)
			return;

		spin_lock(&ha_main_sess_lock);
		filled = 0;
		list_for_each_entry(se, &ha_main_sess_list, list) {
			if (filled >= count)
				break;
			snap[filled].hdr.type   = cpu_to_be32(LIO_HA_MSG_SESSION_CONNECT);
			snap[filled].session_id = cpu_to_be64(se->session_id);
			snap[filled].tpg_tag    = cpu_to_be16(se->tpg_tag);
			strscpy(snap[filled].initiator_name, se->initiator_name,
				LIO_HA_INITIATOR_NAME_LEN);
			strscpy(snap[filled].target_name, se->target_name,
				LIO_HA_INITIATOR_NAME_LEN);
			strscpy(snap[filled].fabric_name, se->fabric_name,
				LIO_HA_FABRIC_NAME_LEN);
			filled++;
		}
		spin_unlock(&ha_main_sess_lock);

		lio_ha_dbg(1, "TCP connected (STANDBY): replaying %d SESSION_CONNECT(s)\n", filled);
		for (j = 0; j < filled; j++) {
			if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, &snap[j],
					    sizeof(snap[j])))
				pr_warn_ratelimited("lio_ha: SESSION_CONNECT replay failed for %s\n",
						    snap[j].initiator_name);
		}
		kfree(snap);
		return;
	}

	/* ACTIVE: send bulk PR state. */
	ha_main_send_lun_sync_all();
}

/* ------------------------------------------------------------------ */
/* Failover: restore PR state and open backends                        */
/*                                                                     */
/* Called from lio_ha_forward_active_store(val=0) when middleware      */
/* signals that the pool has been imported and local I/O can begin.   */
/*                                                                     */
/* Sequence per device:                                                */
/*   1. Iterate lio_ha_pr_table for entries matching this device.     */
/*   2. For each entry, use target_ha_foreach_nacl_dev() to find the */
/*      live nacl+lun context on this node's TPGs.                    */
/*   3. Call target_ha_pr_add_reg() to inject the registration.       */
/*   4. Clear lio_ha_forward_active (done by the caller once).        */
/*   5. Call target_ha_reopen_backend() to open the backing store.    */
/* ------------------------------------------------------------------ */

/*
 * Context passed to the target_ha_foreach_nacl_dev() callback.
 * One callback invocation per (nacl, lun, mapped_lun) found.
 */
struct failover_reg_ctx {
	struct se_device *dev;
	u64               sa_res_key;
	int               res_holder;
	u8                res_type;
	int               errors;
};

static void ha_main_failover_add_reg_cb(struct se_node_acl *nacl,
					struct se_lun *lun,
					u64 mapped_lun,
					void *data)
{
	struct failover_reg_ctx *ctx = data;
	int ret;

	ret = target_ha_pr_add_reg(ctx->dev, nacl, lun, mapped_lun,
				   ctx->sa_res_key,
				   ctx->res_holder,
				   ctx->res_type);
	lio_ha_dbg(3, "failover PR reg: initiator=%s key=%016llx holder=%d type=%u ret=%d\n",
		   nacl->initiatorname, (unsigned long long)ctx->sa_res_key,
		   ctx->res_holder, ctx->res_type, ret);
	if (ret) {
		pr_warn_ratelimited("lio_ha: failed to restore PR reg for %s: %d\n",
				    nacl->initiatorname, ret);
		ctx->errors++;
	}
}

/* Snapshot of a single PR table entry, used for lock-free processing. */
struct pr_snap_entry {
	char initiator_name[LIO_HA_INITIATOR_NAME_LEN];
	char fabric_name[LIO_HA_FABRIC_NAME_LEN];
	u64  sa_res_key;
	u8   res_holder;
	u8   res_type;
};

#define FAILOVER_PR_SNAP_MAX  128

/*
 * Per-device callback for target_for_each_device() during failover.
 * Restores PR registrations from the replicated table, then reopens
 * the backend.
 */
static int ha_main_failover_device(struct se_device *dev, void *data)
{
	char dev_name[LIO_HA_DEV_NAME_LEN];
	struct pr_snap_entry *snap;
	struct lio_ha_pr_entry *e;
	int nsnap = 0, i;

	snprintf(dev_name, LIO_HA_DEV_NAME_LEN, "%s/%s",
		 config_item_name(&dev->se_hba->hba_group.cg_item),
		 config_item_name(&dev->dev_group.cg_item));

	snap = kcalloc(FAILOVER_PR_SNAP_MAX, sizeof(*snap), GFP_KERNEL);
	if (!snap)
		goto open_backend;

	/*
	 * Phase 1: snapshot all PR entries for this device under the spinlock.
	 * The table is not modified during failover (STANDBY is still in
	 * forwarding mode -- no PR OUTs run locally).
	 */
	spin_lock(&lio_ha_pr_lock);
	list_for_each_entry(e, &lio_ha_pr_table, list) {
		if (strncmp(e->dev_name, dev_name, LIO_HA_DEV_NAME_LEN) != 0)
			continue;
		if (nsnap >= FAILOVER_PR_SNAP_MAX) {
			pr_warn_ratelimited("lio_ha: PR snapshot full for %s (max %d)\n",
					    dev_name, FAILOVER_PR_SNAP_MAX);
			break;
		}
		strscpy(snap[nsnap].initiator_name, e->initiator_name,
			LIO_HA_INITIATOR_NAME_LEN);
		strscpy(snap[nsnap].fabric_name, e->fabric_name,
			LIO_HA_FABRIC_NAME_LEN);
		snap[nsnap].sa_res_key = e->res_key;
		snap[nsnap].res_holder = e->res_holder;
		snap[nsnap].res_type   = e->res_type;
		nsnap++;
	}
	spin_unlock(&lio_ha_pr_lock);

	/*
	 * Phase 2a: inject non-holder registrations first.
	 *
	 * target_ha_pr_add_reg() with res_holder=1 sets dev->dev_pr_res_holder,
	 * making the reservation immediately visible to LIO's conflict-checking
	 * code.  For registrants-only reservation types (WR_EX_RO, EX_AC_RO),
	 * only initiators already in registration_list are permitted access;
	 * others get RESERVATION_CONFLICT.  Injecting all non-holders first
	 * ensures registration_list is complete before the reservation goes
	 * live, so no legitimate initiator is incorrectly rejected.
	 */
	for (i = 0; i < nsnap; i++) {
		struct failover_reg_ctx ctx;

		if (snap[i].res_holder)
			continue;

		ctx.dev        = dev;
		ctx.sa_res_key = snap[i].sa_res_key;
		ctx.res_holder = 0;
		ctx.res_type   = snap[i].res_type;
		ctx.errors     = 0;

		target_ha_foreach_nacl_dev(snap[i].fabric_name,
					   snap[i].initiator_name,
					   dev,
					   ha_main_failover_add_reg_cb,
					   &ctx);
	}

	/* Phase 2b: inject the reservation holder (if any). */
	for (i = 0; i < nsnap; i++) {
		struct failover_reg_ctx ctx;

		if (!snap[i].res_holder)
			continue;

		ctx.dev        = dev;
		ctx.sa_res_key = snap[i].sa_res_key;
		ctx.res_holder = 1;
		ctx.res_type   = snap[i].res_type;
		ctx.errors     = 0;

		target_ha_foreach_nacl_dev(snap[i].fabric_name,
					   snap[i].initiator_name,
					   dev,
					   ha_main_failover_add_reg_cb,
					   &ctx);
	}

	kfree(snap);

open_backend:
	/*
	 * Open the backend now that lio_ha_forward_active has been cleared
	 * by the caller.  Best-effort: log and continue on error.
	 */
	lio_ha_dbg(1, "failover: %s: opening backend (%d registrant(s) restored)\n",
		   dev_name, nsnap);
	if (target_ha_reopen_backend(dev))
		pr_warn("lio_ha: failed to open backend for %s\n", dev_name);
	else
		lio_ha_dbg(1, "failover: %s: backend opened ok\n", dev_name);

	return 0;   /* always continue to next device */
}

/* ------------------------------------------------------------------ */
/* Module-level configfs attributes                                     */
/*                                                                      */
/* Exposed at /sys/kernel/config/lio_ha/.  Middleware writes these     */
/* attributes once at STANDBY startup and reads ha_state to gate the   */
/* NONOPTIMIZED ALUA write.                                            */
/* ------------------------------------------------------------------ */

/* local_addr */
static ssize_t lio_ha_local_addr_show(struct config_item *item, char *page)
{
	ssize_t ret;

	spin_lock(&lio_ha_cfg.lock);
	ret = sysfs_emit(page, "%s\n", lio_ha_cfg.local_addr);
	spin_unlock(&lio_ha_cfg.lock);
	return ret;
}

static ssize_t lio_ha_local_addr_store(struct config_item *item,
				       const char *page, size_t count)
{
	if (count >= LIO_HA_ADDR_LEN)
		return -EINVAL;
	spin_lock(&lio_ha_cfg.lock);
	strscpy(lio_ha_cfg.local_addr, page, LIO_HA_ADDR_LEN);
	strim(lio_ha_cfg.local_addr);
	spin_unlock(&lio_ha_cfg.lock);
	return count;
}
CONFIGFS_ATTR(lio_ha_, local_addr);

/* peer_addr */
static ssize_t lio_ha_peer_addr_show(struct config_item *item, char *page)
{
	ssize_t ret;

	spin_lock(&lio_ha_cfg.lock);
	ret = sysfs_emit(page, "%s\n", lio_ha_cfg.peer_addr);
	spin_unlock(&lio_ha_cfg.lock);
	return ret;
}

static ssize_t lio_ha_peer_addr_store(struct config_item *item,
				      const char *page, size_t count)
{
	if (count >= LIO_HA_ADDR_LEN)
		return -EINVAL;
	spin_lock(&lio_ha_cfg.lock);
	strscpy(lio_ha_cfg.peer_addr, page, LIO_HA_ADDR_LEN);
	strim(lio_ha_cfg.peer_addr);
	spin_unlock(&lio_ha_cfg.lock);
	return count;
}
CONFIGFS_ATTR(lio_ha_, peer_addr);

/* port */
static ssize_t lio_ha_port_show(struct config_item *item, char *page)
{
	return sysfs_emit(page, "%u\n", lio_ha_cfg.port);
}

static ssize_t lio_ha_port_store(struct config_item *item,
				 const char *page, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(page, 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val > 65535)
		return -EINVAL;
	lio_ha_cfg.port = (u16)val;
	return count;
}
CONFIGFS_ATTR(lio_ha_, port);

/* ha_state (read-only) -- middleware polls until "synced" on both nodes
 * before writing ALUA states; "disconnected" on either node triggers an
 * alert.  Both ACTIVE and STANDBY reach "synced" when LUN_SYNC_DONE is
 * sent/received respectively.
 */
static ssize_t lio_ha_ha_state_show(struct config_item *item, char *page)
{
	enum lio_ha_state state;

	spin_lock(&lio_ha_cfg.lock);
	state = lio_ha_cfg.ha_state;
	spin_unlock(&lio_ha_cfg.lock);
	return sysfs_emit(page, "%s\n", ha_state_names[state]);
}
CONFIGFS_ATTR_RO(lio_ha_, ha_state);

/*
 * forward_active -- the primary control knob written by middleware.
 *
 * Write "1" (STANDBY startup, before storage objects are configured):
 *   Sets lio_ha_forward_active in LIO core so that iblock/fileio backends
 *   defer their open() and all commands are forwarded to ACTIVE.  Takes a
 *   module self-reference preventing unload while forwarding is active.
 *
 * Write "0" (failover -- pool has been imported and is ready):
 *   Clears lio_ha_forward_active in LIO core; BUSY stops; all LUNs execute
 *   locally.  Also responsible for restoring replicated PR state to each
 *   iblock/fileio backend before opening it.  Calls
 *   ha_main_failover_device() for each se_device -- see that function for
 *   the per-device sequence.
 *
 * Both writes are idempotent.
 */
static ssize_t lio_ha_forward_active_show(struct config_item *item, char *page)
{
	return sysfs_emit(page, "%d\n", atomic_read(&lio_ha_forward_active));
}

static ssize_t lio_ha_forward_active_store(struct config_item *item,
					   const char *page, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(page, 0, &val);
	if (ret)
		return ret;
	if (val > 1)
		return -EINVAL;

	if (val == 1) {
		if (atomic_read(&lio_ha_forward_active))
			return count;   /* already set -- idempotent */
		__module_get(THIS_MODULE);
		atomic_set(&lio_ha_forward_active, 1);
		lio_ha_dbg(1, "forward_active set: STANDBY forwarding mode active\n");
	} else {
		if (!atomic_read(&lio_ha_forward_active))
			return count;   /* already clear -- idempotent */
		/*
		 * Failover: the pool has been imported.  Restore replicated PR
		 * state to each device's registration_list, then clear
		 * lio_ha_forward_active so I/O executes locally again, then
		 * open each iblock/fileio backend.
		 *
		 * target_for_each_device() calls ha_main_failover_device() for
		 * every configured se_device.  That function:
		 *   1. Snapshots PR entries for the device from lio_ha_pr_table.
		 *   2. Calls target_ha_foreach_nacl_dev() + target_ha_pr_add_reg()
		 *      for each registrant (non-holders first, holder last).
		 *   3. Calls target_ha_reopen_backend() to open the backing store.
		 *
		 * The flag is cleared BEFORE ha_main_failover_device() calls
		 * target_ha_reopen_backend() because iblock/fileio check
		 * lio_ha_forward_active inside configure_device().
		 */
		atomic_set(&lio_ha_forward_active, 0);
		lio_ha_dbg(1, "forward_active cleared: starting failover\n");
		/*
		 * Shadow list is no longer needed: forward_active=0 means we
		 * are becoming ACTIVE and will never replay SESSION_CONNECTs.
		 * Both session_create and session_destroy check forward_active
		 * first, so no new entries will be added after this point.
		 */
		ha_main_sess_list_flush();
		target_for_each_device(ha_main_failover_device, NULL);
		lio_ha_dbg(1, "forward_active cleared: failover complete\n");

		/*
		 * If the wire reconnected before this 1->0 transition (e.g.
		 * delayed failover -- the new SECONDARY came back online
		 * before middleware wrote forward_active=0 here), the
		 * connect-handler trigger already fired with us still in
		 * STANDBY mode and did NOT send LUN_SYNC.  Fire it now.
		 * Idempotent with the connect-handler path: the helper
		 * self-gates on ha_state and only sends when CONNECTED.
		 */
		ha_main_send_lun_sync_all();

		module_put(THIS_MODULE);
	}
	return count;
}
CONFIGFS_ATTR(lio_ha_, forward_active);

static struct configfs_attribute *lio_ha_attrs[] = {
	&lio_ha_attr_local_addr,
	&lio_ha_attr_peer_addr,
	&lio_ha_attr_port,
	&lio_ha_attr_ha_state,
	&lio_ha_attr_forward_active,
	NULL,
};

static const struct config_item_type lio_ha_root_type = {
	.ct_attrs = lio_ha_attrs,
	.ct_owner = THIS_MODULE,
};

static struct configfs_subsystem lio_ha_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "lio_ha",
			.ci_type    = &lio_ha_root_type,
		},
	},
};

/* ------------------------------------------------------------------ */
/* Module init / exit                                                   */
/* ------------------------------------------------------------------ */

static int __init lio_ha_init(void)
{
	int ret;

	spin_lock_init(&lio_ha_cfg.lock);
	lio_ha_cfg.port = LIO_HA_DEFAULT_PORT;
	lio_ha_cfg.ha_state = LIO_HA_DISCONNECTED;
	if (default_local_addr[0])
		strscpy(lio_ha_cfg.local_addr, default_local_addr,
			LIO_HA_ADDR_LEN);
	if (default_peer_addr[0])
		strscpy(lio_ha_cfg.peer_addr, default_peer_addr,
			LIO_HA_ADDR_LEN);

	config_group_init(&lio_ha_subsys.su_group);
	mutex_init(&lio_ha_subsys.su_mutex);

	ret = configfs_register_subsystem(&lio_ha_subsys);
	if (ret) {
		pr_err("lio_ha: configfs_register_subsystem failed: %d\n", ret);
		return ret;
	}

	lio_ha_pr_wq = alloc_workqueue("lio_ha_pr", WQ_UNBOUND, 0);
	if (!lio_ha_pr_wq) {
		pr_err("lio_ha: failed to create PR workqueue\n");
		configfs_unregister_subsystem(&lio_ha_subsys);
		return -ENOMEM;
	}

	lio_ha_register_ops(&ha_ops);
	lio_ha_register_pr_notifier(&pr_notifier);
	lio_ha_tcp_register_connect_handler(ha_main_on_connect);

	ret = lio_ha_recv_init();
	if (ret) {
		lio_ha_unregister_pr_notifier();
		destroy_workqueue(lio_ha_pr_wq);
		lio_ha_pr_wq = NULL;
		lio_ha_unregister_ops();
		configfs_unregister_subsystem(&lio_ha_subsys);
		return ret;
	}

	/*
	 * lio_ha_fwd_init() registers the TCP CTL and DATA channel handlers
	 * (CMD_RESPONSE, DATA dispatch, disconnect).  Must run before
	 * lio_ha_tcp_init() starts the TCP threads so that no messages are
	 * dispatched before the handlers are installed.
	 */
	ret = lio_ha_fwd_init();
	if (ret) {
		lio_ha_recv_exit();
		lio_ha_unregister_pr_notifier();
		destroy_workqueue(lio_ha_pr_wq);
		lio_ha_pr_wq = NULL;
		lio_ha_unregister_ops();
		configfs_unregister_subsystem(&lio_ha_subsys);
		return ret;
	}

	ret = lio_ha_tcp_init();
	if (ret) {
		lio_ha_fwd_exit();
		lio_ha_recv_exit();
		lio_ha_unregister_pr_notifier();
		destroy_workqueue(lio_ha_pr_wq);
		lio_ha_pr_wq = NULL;
		lio_ha_unregister_ops();
		configfs_unregister_subsystem(&lio_ha_subsys);
		return ret;
	}

	if (default_forward_active) {
		__module_get(THIS_MODULE);
		atomic_set(&lio_ha_forward_active, 1);
	}

	pr_info("lio_ha: loaded (port=%u forward_active=%d)\n",
		lio_ha_cfg.port, atomic_read(&lio_ha_forward_active));
	return 0;
}

static void __exit lio_ha_exit(void)
{
	/*
	 * Unregister the PR notifier first: lio_ha_unregister_pr_notifier()
	 * calls synchronize_rcu(), guaranteeing that no pr_change() call is
	 * in progress and no new ones will start.  Flush and destroy the
	 * workqueue next so all PERS_ACTION sends complete before TCP exits.
	 *
	 * lio_ha_forward_active is 0 by the time __exit runs (the module
	 * self-reference taken when forward_active is set to 1 prevents
	 * rmmod from succeeding while forwarding is active).
	 */
	lio_ha_unregister_pr_notifier();
	flush_workqueue(lio_ha_pr_wq);
	destroy_workqueue(lio_ha_pr_wq);
	lio_ha_pr_wq = NULL;
	lio_ha_tcp_exit();
	lio_ha_fwd_exit();
	lio_ha_recv_exit();
	lio_ha_unregister_ops();
	configfs_unregister_subsystem(&lio_ha_subsys);
	ha_main_sess_list_flush();
	ha_main_pr_table_flush();
	pr_info("lio_ha: unloaded\n");
}

module_init(lio_ha_init);
module_exit(lio_ha_exit);

MODULE_AUTHOR("iXsystems, Inc.");
MODULE_DESCRIPTION("TrueNAS LIO HA forwarding module");
MODULE_LICENSE("GPL");
