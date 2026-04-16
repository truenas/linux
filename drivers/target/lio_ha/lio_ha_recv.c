// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lio_ha_recv.c -- ha_recv fabric driver (ACTIVE side)
 *
 * ha_recv is a private LIO fabric driver used only by lio_ha.ko.  It is
 * never exposed via configfs; everything is created programmatically.
 *
 * A fabric driver approach was chosen for three reasons:
 *
 *   1. target_submit_cmd() -- the LIO entry point for command submission --
 *      requires an se_session backed by a TPG with fabric ops.  Using this
 *      path gives forwarded commands full LIO core processing: PR conflict
 *      checking, ALUA gating, task management, queue ordering.  Calling a
 *      backend execute_cmd() directly would bypass all of that.
 *
 *   2. LIO delivers command completions by calling back into the fabric via
 *      queue_data_in() / queue_status().  These callbacks are where ha_recv
 *      sends CMD_RESPONSE (and READ data) back to STANDBY over TCP.
 *
 *   3. PR is per-I_T nexus.  Each synthetic session must carry the real
 *      se_node_acl from the actual target TPG so that lun_entry_hlist
 *      resolves correctly and PR registrations are attributed to the right
 *      initiator.  Sessions are registered on ha_recv_tpg (so se_cmd->se_tfo
 *      routes callbacks through ha_recv_ops), but se_sess->se_node_acl
 *      points to the real nacl.  See lio_ha_recv_session_create().
 *
 * A single system-wide TPG is created at lio_ha_recv_init() following the
 * same pattern as the iSCSI discovery TPG (iscsit_load_discovery_tpg):
 *   1. Set se_tpg.se_tpg_tfo = &ha_recv_ops directly.
 *   2. Call core_tpg_register(NULL, &ha_recv_tpg.se_tpg, -1).
 *
 * No target_register_template() is called: ha_recv is a purely internal
 * fabric with no configfs presence under /sys/kernel/config/target/.
 *
 * Sessions are tracked in a spinlock-protected hash table keyed by
 * u64 session_id (the STANDBY's se_sess pointer, which is unique for
 * the lifetime of the session).
 *
 * This file: session management, WRITE-data buffering, command submission,
 * and response send callbacks.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <scsi/scsi_cmnd.h>   /* SCSI_SENSE_BUFFERSIZE */

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/target_core_ha.h>

#include "lio_ha.h"
#include "lio_ha_wire.h"
#include "lio_ha_tcp.h"
#include "lio_ha_recv.h"

/* ------------------------------------------------------------------ */
/* TPG and session table                                               */
/* ------------------------------------------------------------------ */

/*
 * Single static TPG for all ha_recv sessions.  All synthetic sessions
 * live here.  demo mode (tpg_check_demo_mode = 1) lets LIO create
 * node_acl entries automatically for any initiator name.
 */
struct ha_recv_tpg {
	struct se_portal_group se_tpg;
};

static struct ha_recv_tpg ha_recv_tpg;

/*
 * Session hash table: session_id (u64) -> ha_recv_sess_entry.
 * One entry per initiator session reported by STANDBY.
 * 256 buckets (8 bits); hash chaining handles any overflow.
 */
#define HA_RECV_SESS_HT_BITS	8

static DEFINE_HASHTABLE(ha_recv_sess_ht, HA_RECV_SESS_HT_BITS);
static DEFINE_SPINLOCK(ha_recv_sess_lock);

struct ha_recv_sess_entry {
	u64			session_id;
	struct se_session      *se_sess;
	struct hlist_node	node;
};

/* ------------------------------------------------------------------ */
/* WRITE-data buffer table (ACTIVE side)                             */
/*                                                                     */
/* When STANDBY sends DATA (WRITE data) before CMD_FORWARD, ACTIVE */
/* buffers it here keyed by cmd_cookie.  ha_recv_write_pending() picks */
/* it up and copies into the LIO-allocated se_cmd->t_data_sg.         */
/* ------------------------------------------------------------------ */

struct ha_recv_data_entry {
	u64             cmd_cookie;
	void           *data;    /* kvmalloc'd; freed by write_pending or release_cmd */
	u32             len;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(ha_recv_data_ht, HA_RECV_SESS_HT_BITS);
static DEFINE_SPINLOCK(ha_recv_data_lock);

/* ------------------------------------------------------------------ */
/* Fabric ops callbacks                                                */
/*                                                                     */
/* Minimum set required by LIO core for target_setup_session() and    */
/* target_submit_cmd() to work.  No configfs make/drop callbacks are  */
/* needed because ha_recv is created programmatically.                */
/* ------------------------------------------------------------------ */

static char *ha_recv_tpg_get_wwn(struct se_portal_group *tpg)
{
	return "ha_recv";
}

static u16 ha_recv_tpg_get_tag(struct se_portal_group *tpg)
{
	return 1;
}

/*
 * Demo mode is disabled.  ha_recv requires a real node_acl from the
 * actual target TPG for correct LUN lookup and PR I_T nexus attribution.
 * Sessions with no matching real nacl are refused in lio_ha_recv_session_create.
 */
static int ha_recv_tpg_check_demo_mode(struct se_portal_group *tpg)
{
	return 0;
}

static int ha_recv_tpg_check_demo_mode_cache(struct se_portal_group *tpg)
{
	return 0;
}

/*
 * check_stop_free: release an ha_recv command.
 *
 * LIO core calls this via transport_cmd_check_stop_to_fabric() after
 * queue_data_in() / queue_status() / queue_tm_rsp() returns, and also
 * during session teardown when CMD_T_STOP is set.  This is the only
 * place ha_recv commands are freed; the queue_* and aborted_task
 * callbacks must return without freeing the command.
 */
static int ha_recv_check_stop_free(struct se_cmd *cmd)
{
	return transport_generic_free_cmd(cmd, 0);
}

/* ------------------------------------------------------------------ */
/* TCP send helpers (ACTIVE -> STANDBY)                             */
/* ------------------------------------------------------------------ */

/* Build and send CMD_RESPONSE on the CTL channel (no inline data). */
static void ha_recv_send_cmd_response(struct se_cmd *cmd, u64 cookie)
{
	struct lio_ha_msg_cmd_response *resp;
	u8 sense_len = 0;
	size_t total;
	u8 *buf;

	if (cmd->scsi_status == SAM_STAT_CHECK_CONDITION)
		sense_len = (u8)min_t(u16, cmd->scsi_sense_length,
				      SCSI_SENSE_BUFFERSIZE);

	total = sizeof(*resp) + sense_len;
	buf   = kmalloc(total, GFP_KERNEL);
	if (!buf)
		return;

	resp = (struct lio_ha_msg_cmd_response *)buf;
	resp->hdr.type     = cpu_to_be32(LIO_HA_MSG_CMD_RESPONSE);
	resp->hdr.reserved = 0;
	resp->cmd_cookie   = cpu_to_be64(cookie);
	resp->scsi_status  = cmd->scsi_status;
	resp->sense_len    = sense_len;
	memset(resp->pad, 0, sizeof(resp->pad));
	if (sense_len > 0)
		memcpy(buf + sizeof(*resp), cmd->sense_buffer, sense_len);

	if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, buf, (u32)total))
		pr_debug("ha_recv: CMD_RESPONSE send failed cookie=%llu\n",
			 (unsigned long long)cookie);
	kfree(buf);
}

/* Send DATA (READ response), then CMD_RESPONSE. */
static void ha_recv_send_cmd_response_with_data(struct se_cmd *cmd, u64 cookie)
{
	size_t data_len = cmd->data_length;
	size_t buf_len  = sizeof(struct lio_ha_data_hdr) + data_len;
	struct lio_ha_data_hdr *dhdr;
	u8 *buf;

	buf = kvmalloc(buf_len, GFP_KERNEL);
	if (buf) {
		dhdr = (struct lio_ha_data_hdr *)buf;
		dhdr->cmd_cookie = cpu_to_be64(cookie);
		sg_copy_to_buffer(cmd->t_data_sg, cmd->t_data_nents,
				  buf + sizeof(*dhdr), data_len);
		if (lio_ha_tcp_send(LIO_HA_CHAN_DATA, buf, (u32)buf_len))
			pr_debug("ha_recv: DATA send failed cookie=%llu\n",
				 (unsigned long long)cookie);
		kvfree(buf);
	}

	ha_recv_send_cmd_response(cmd, cookie);
}

/* ------------------------------------------------------------------ */
/* Helper: consume and free any buffered write data for @cookie.      */
/* ------------------------------------------------------------------ */

static void ha_recv_flush_data(u64 cookie)
{
	struct ha_recv_data_entry *de;

	spin_lock(&ha_recv_data_lock);
	hash_for_each_possible(ha_recv_data_ht, de, node, cookie) {
		if (de->cmd_cookie == cookie) {
			hash_del(&de->node);
			spin_unlock(&ha_recv_data_lock);
			kvfree(de->data);
			kfree(de);
			return;
		}
	}
	spin_unlock(&ha_recv_data_lock);
}

/* ------------------------------------------------------------------ */
/* Fabric callbacks                                                    */
/* ------------------------------------------------------------------ */

static void ha_recv_release_cmd(struct se_cmd *cmd)
{
	struct ha_recv_cmd *hcmd = container_of(cmd, struct ha_recv_cmd, se_cmd);

	/*
	 * se_cmd is embedded in ha_recv_cmd (lio_ha_recv.h).  If
	 * write_pending() was never called (e.g., LUN lookup failed),
	 * discard any buffered write data for this cookie.
	 */
	ha_recv_flush_data(hcmd->cookie);
	kfree(hcmd);
}

/*
 * write_pending: called by LIO core when a WRITE command is ready to
 * receive data -- LIO has allocated t_data_sg and needs it filled before
 * target_execute_cmd() can be called.
 *
 * For ha_recv the write data was already received from STANDBY over the
 * DATA channel and buffered in ha_recv_data_ht, so we copy it in and
 * call target_execute_cmd() directly without waiting for any network I/O.
 */
static int ha_recv_write_pending(struct se_cmd *cmd)
{
	struct ha_recv_cmd *hcmd = container_of(cmd, struct ha_recv_cmd, se_cmd);
	struct ha_recv_data_entry *de = NULL;

	/*
	 * STANDBY always sends the DATA channel message before CMD_FORWARD
	 * on the same ordered TCP connection, so the write data must already
	 * be in ha_recv_data_ht by the time write_pending() is called.
	 */
	spin_lock(&ha_recv_data_lock);
	hash_for_each_possible(ha_recv_data_ht, de, node, hcmd->cookie) {
		if (de->cmd_cookie == hcmd->cookie) {
			hash_del(&de->node);
			break;
		}
		de = NULL;
	}
	spin_unlock(&ha_recv_data_lock);

	if (de) {
		lio_ha_dbg(3, "write_pending: cookie=%016llx len=%u\n",
			   (unsigned long long)hcmd->cookie, de->len);
		sg_copy_from_buffer(cmd->t_data_sg, cmd->t_data_nents,
				    de->data, de->len);
		kvfree(de->data);
		kfree(de);
		target_execute_cmd(cmd);
		return 0;
	}

	/* Shouldn't happen on an ordered TCP stream; fail gracefully. */
	WARN_ONCE(1, "ha_recv: write_pending: no data for cookie %llu\n",
		  (unsigned long long)hcmd->cookie);
	target_complete_cmd(cmd, SAM_STAT_BUSY);
	return 0;
}

/*
 * queue_data_in / queue_status: called by LIO core after a command
 * completes to deliver the response to the fabric.
 *
 * For ha_recv the response is sent to STANDBY over TCP, carrying
 * ha_recv_cmd.cookie so STANDBY can call target_complete_cmd() on
 * the original initiator command.
 */
static int ha_recv_queue_data_in(struct se_cmd *cmd)
{
	struct ha_recv_cmd *hcmd = container_of(cmd, struct ha_recv_cmd, se_cmd);

	/* Send DATA channel (read data) then CMD_RESPONSE. */
	ha_recv_send_cmd_response_with_data(cmd, hcmd->cookie);
	return 0;
}

static int ha_recv_queue_status(struct se_cmd *cmd)
{
	struct ha_recv_cmd *hcmd = container_of(cmd, struct ha_recv_cmd, se_cmd);

	/* No data: send CMD_RESPONSE only. */
	ha_recv_send_cmd_response(cmd, hcmd->cookie);
	return 0;
}

/*
 * queue_tm_rsp: called by LIO core when a TMR completes.
 * Send TMR_RESPONSE to STANDBY with the result, then free the cmd.
 */
static void ha_recv_queue_tm_rsp(struct se_cmd *cmd)
{
	struct ha_recv_cmd *hcmd = container_of(cmd, struct ha_recv_cmd, se_cmd);
	struct lio_ha_msg_tmr_response resp = {};

	resp.hdr.type   = cpu_to_be32(LIO_HA_MSG_TMR_RESPONSE);
	resp.cmd_cookie = cpu_to_be64(hcmd->cookie);
	resp.response   = cpu_to_be32((u32)cmd->se_tmr_req->response);

	if (lio_ha_tcp_send(LIO_HA_CHAN_CTL, &resp, sizeof(resp)))
		pr_debug("ha_recv: TMR_RESPONSE send failed cookie=%llu\n",
			 (unsigned long long)hcmd->cookie);
}

/*
 * aborted_task: called by LIO core when a command has been successfully
 * aborted by a TMR.  LIO will not call queue_data_in or queue_status for
 * this command, so we must send CMD_RESPONSE with SAM_STAT_TASK_ABORTED
 * ourselves; otherwise STANDBY's ha_fwd_ht entry for the command would
 * leak until the TCP link drops.  Do not free the command here -- LIO
 * core calls check_stop_free after aborted_task returns.
 */
static void ha_recv_aborted_task(struct se_cmd *cmd)
{
	struct ha_recv_cmd *hcmd = container_of(cmd, struct ha_recv_cmd, se_cmd);

	cmd->scsi_status = SAM_STAT_TASK_ABORTED;
	ha_recv_send_cmd_response(cmd, hcmd->cookie);
}

static const struct target_core_fabric_ops ha_recv_ops = {
	.module				= THIS_MODULE,
	.fabric_name			= "ha_recv",
	.tpg_get_wwn			= ha_recv_tpg_get_wwn,
	.tpg_get_tag			= ha_recv_tpg_get_tag,
	.tpg_check_demo_mode		= ha_recv_tpg_check_demo_mode,
	.tpg_check_demo_mode_cache	= ha_recv_tpg_check_demo_mode_cache,
	.check_stop_free		= ha_recv_check_stop_free,
	.release_cmd			= ha_recv_release_cmd,
	/*
	 * write_pending_must_be_called = 1: we rely on write_pending() being
	 * invoked for every WRITE command so we can copy the buffered TCP
	 * data into LIO's allocated t_data_sg before target_execute_cmd().
	 */
	.write_pending_must_be_called	= 1,
	.write_pending			= ha_recv_write_pending,
	.queue_data_in			= ha_recv_queue_data_in,
	.queue_status			= ha_recv_queue_status,
	.queue_tm_rsp			= ha_recv_queue_tm_rsp,
	.aborted_task			= ha_recv_aborted_task,
	.default_submit_type		= TARGET_QUEUE_SUBMIT,
	.direct_submit_supp		= 0,
};

/* ------------------------------------------------------------------ */
/* TCP CTL-channel handlers (ACTIVE side)                            */
/* ------------------------------------------------------------------ */

/*
 * Decode CMD_FORWARD and dispatch to lio_ha_recv_submit_cmd().
 * Registered with the TCP layer in lio_ha_recv_init().
 */
static void ha_recv_cmd_forward_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_cmd_forward *fwd = buf;

	if (len < sizeof(*fwd)) {
		pr_warn("ha_recv: CMD_FORWARD too short (%zu bytes)\n", len);
		return;
	}

	lio_ha_recv_submit_cmd(be64_to_cpu(fwd->session_id),
			       fwd->cdb, LIO_HA_CDB_LEN,
			       be64_to_cpu(fwd->cmd_cookie),
			       be32_to_cpu(fwd->lun),
			       (u32)be64_to_cpu(fwd->data_length),
			       (u8)be32_to_cpu(fwd->data_dir));
}

/*
 * Submit a TMR to LIO core on ACTIVE.
 * On completion, ha_recv_queue_tm_rsp() sends TMR_RESPONSE to STANDBY.
 */
static void ha_recv_submit_tmr(u64 session_id, u64 cmd_cookie,
			       u64 ref_cookie, u32 function, u32 lun)
{
	struct ha_recv_sess_entry *e;
	struct se_session *se_sess = NULL;
	struct ha_recv_cmd *hcmd;

	spin_lock(&ha_recv_sess_lock);
	hash_for_each_possible(ha_recv_sess_ht, e, node, session_id) {
		if (e->session_id == session_id) {
			se_sess = e->se_sess;
			break;
		}
	}
	spin_unlock(&ha_recv_sess_lock);

	if (!se_sess) {
		struct lio_ha_msg_tmr_response resp = {
			.hdr.type   = cpu_to_be32(LIO_HA_MSG_TMR_RESPONSE),
			.cmd_cookie = cpu_to_be64(cmd_cookie),
			.response   = cpu_to_be32(TMR_FUNCTION_REJECTED),
		};
		pr_warn_ratelimited("ha_recv: TMR: unknown session %llu\n",
				    (unsigned long long)session_id);
		lio_ha_tcp_send(LIO_HA_CHAN_CTL, &resp, sizeof(resp));
		return;
	}

	hcmd = kzalloc(sizeof(*hcmd), GFP_KERNEL);
	if (!hcmd) {
		struct lio_ha_msg_tmr_response resp = {
			.hdr.type   = cpu_to_be32(LIO_HA_MSG_TMR_RESPONSE),
			.cmd_cookie = cpu_to_be64(cmd_cookie),
			.response   = cpu_to_be32(TMR_FUNCTION_REJECTED),
		};
		lio_ha_tcp_send(LIO_HA_CHAN_CTL, &resp, sizeof(resp));
		return;
	}
	hcmd->cookie = cmd_cookie;

	/*
	 * target_submit_tmr() allocates se_tmr_req and submits the TMR to
	 * LIO core.  On completion, queue_tm_rsp() is called; ha_recv
	 * sends TMR_RESPONSE back to STANDBY.
	 *
	 * For ABORT_TASK: ref_cookie is STANDBY's cookie of the target
	 * command; passed as ref_task_tag so LIO can look it up.  Since
	 * ha_recv commands are submitted with tag=0 (no explicit task tag),
	 * ABORT_TASK may return TMR_FUNCTION_FAILED; LUN_RESET/TARGET_RESET
	 * work normally.
	 */
	target_submit_tmr(&hcmd->se_cmd, se_sess, hcmd->sense_buf,
			  (u64)lun, NULL, (unsigned char)function,
			  GFP_KERNEL, ref_cookie, 0);
}

/*
 * Decode TMR_FORWARD and dispatch to ha_recv_submit_tmr().
 */
static void ha_recv_tmr_forward_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_tmr_forward *fwd = buf;

	if (len < sizeof(*fwd)) {
		pr_warn("ha_recv: TMR_FORWARD too short (%zu bytes)\n", len);
		return;
	}

	ha_recv_submit_tmr(be64_to_cpu(fwd->session_id),
			   be64_to_cpu(fwd->cmd_cookie),
			   be64_to_cpu(fwd->ref_cookie),
			   be32_to_cpu(fwd->function),
			   be32_to_cpu(fwd->lun));
}

/* ------------------------------------------------------------------ */
/* Session management                                                  */
/* ------------------------------------------------------------------ */

int lio_ha_recv_session_create(const char *initiator_name, u64 session_id,
			       const char *target_name, u16 tpg_tag,
			       const char *fabric_name)
{
	struct ha_recv_sess_entry *e, *existing;
	struct se_portal_group *real_tpg;
	struct se_node_acl *real_nacl;
	struct target_cmd_counter *cmd_cnt;
	struct se_session *se_sess;

	/*
	 * Idempotent: if a session with this id already exists (e.g. STANDBY
	 * replayed SESSION_CONNECT after a TCP link bounce), keep the existing
	 * synthetic session -- it is still valid.
	 */
	spin_lock(&ha_recv_sess_lock);
	hash_for_each_possible(ha_recv_sess_ht, existing, node, session_id) {
		if (existing->session_id == session_id) {
			spin_unlock(&ha_recv_sess_lock);
			lio_ha_dbg(1, "session already exists: id=%llu, ignoring replay\n",
				   (unsigned long long)session_id);
			return 0;
		}
	}
	spin_unlock(&ha_recv_sess_lock);

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	/*
	 * Look up the real target TPG by fabric identity so the synthetic
	 * session gets se_node_acl from the real TPG.  This makes LUN
	 * lookups (transport_lookup_cmd_lun -> lun_entry_hlist) resolve
	 * correctly, fixing the CHECK_CONDITION LUN-not-found failure that
	 * occurs when sessions live on ha_recv_tpg which has no LUN mappings.
	 *
	 * The session itself is still registered on ha_recv_tpg so that
	 * se_cmd->se_tfo = ha_recv_ops and all fabric callbacks (queue_data_in,
	 * queue_status, queue_tm_rsp) route back through ha_recv.
	 */
	real_tpg  = target_ha_lookup_tpg(fabric_name, target_name, tpg_tag);
	real_nacl = real_tpg
		? core_tpg_get_initiator_node_acl(real_tpg,
					(unsigned char *)initiator_name)
		: NULL;

	if (real_nacl) {
		cmd_cnt = target_alloc_cmd_counter();
		if (!cmd_cnt) {
			target_put_nacl(real_nacl);
			kfree(e);
			return -ENOMEM;
		}
		se_sess = transport_alloc_session(TARGET_PROT_NORMAL);
		if (IS_ERR(se_sess)) {
			int rc = PTR_ERR(se_sess);

			target_free_cmd_counter(cmd_cnt);
			target_put_nacl(real_nacl);
			kfree(e);
			return rc;
		}
		se_sess->cmd_cnt     = cmd_cnt;
		/*
		 * Transfer the nacl kref obtained from
		 * core_tpg_get_initiator_node_acl() to the session.
		 * transport_free_session() will drop it via target_put_nacl().
		 */
		se_sess->se_node_acl = real_nacl;
		transport_register_session(&ha_recv_tpg.se_tpg, real_nacl,
					   se_sess, e);
	} else {
		/*
		 * No real nacl found -- refuse the session.  Creating a
		 * demo-mode nacl on ha_recv_tpg would produce a session with
		 * no LUN mappings (every forwarded command gets CHECK_CONDITION
		 * at LUN lookup) and PR operations attributed to the wrong
		 * I_T nexus.  Returning an error causes STANDBY to receive
		 * SAM_STAT_BUSY for commands forwarded on this session, which
		 * triggers retries and surfaces the misconfiguration clearly.
		 */
		if (real_tpg)
			pr_warn_ratelimited("ha_recv: no ACL for %s on %s/%s tpg%u -- session refused\n",
					    initiator_name, fabric_name,
					    target_name, tpg_tag);
		else
			pr_warn_ratelimited("ha_recv: TPG %s/%s tpg%u not found -- session refused\n",
					    fabric_name, target_name, tpg_tag);
		kfree(e);
		return -ENOENT;
	}

	e->session_id = session_id;
	e->se_sess    = se_sess;

	spin_lock(&ha_recv_sess_lock);
	hash_add(ha_recv_sess_ht, &e->node, session_id);
	spin_unlock(&ha_recv_sess_lock);

	pr_debug("ha_recv: session created: initiator=%s id=%llu nacl=%s\n",
		 initiator_name, (unsigned long long)session_id,
		 real_nacl ? "real" : "demo");
	lio_ha_dbg(1, "session created: initiator=%s target=%s tpg%u id=%llu\n",
		   initiator_name, target_name, tpg_tag,
		   (unsigned long long)session_id);
	return 0;
}

/*
 * Decode SESSION_CONNECT and call lio_ha_recv_session_create().
 * Registered with the TCP layer in lio_ha_recv_init().
 */
static void ha_recv_session_connect_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_session_connect *msg = buf;
	char initiator_name[LIO_HA_INITIATOR_NAME_LEN];
	char target_name[LIO_HA_INITIATOR_NAME_LEN];
	char fabric_name[LIO_HA_FABRIC_NAME_LEN];
	u64 session_id;
	u16 tpg_tag;

	if (len < sizeof(*msg)) {
		pr_warn("ha_recv: SESSION_CONNECT too short (%zu bytes)\n",
			len);
		return;
	}

	session_id = be64_to_cpu(msg->session_id);
	tpg_tag    = be16_to_cpu(msg->tpg_tag);

	/* Copy with defensive NUL-termination. */
	memcpy(initiator_name, msg->initiator_name, LIO_HA_INITIATOR_NAME_LEN);
	initiator_name[LIO_HA_INITIATOR_NAME_LEN - 1] = '\0';

	memcpy(target_name, msg->target_name, LIO_HA_INITIATOR_NAME_LEN);
	target_name[LIO_HA_INITIATOR_NAME_LEN - 1] = '\0';

	memcpy(fabric_name, msg->fabric_name, LIO_HA_FABRIC_NAME_LEN);
	fabric_name[LIO_HA_FABRIC_NAME_LEN - 1] = '\0';

	lio_ha_recv_session_create(initiator_name, session_id,
				   target_name, tpg_tag, fabric_name);
}

/*
 * Decode SESSION_DISCONNECT and call lio_ha_recv_session_destroy().
 * Registered with the TCP layer in lio_ha_recv_init().
 */
static void ha_recv_session_disconnect_handler(const void *buf, size_t len)
{
	const struct lio_ha_msg_session_disconnect *msg = buf;

	if (len < sizeof(*msg)) {
		pr_warn("ha_recv: SESSION_DISCONNECT too short (%zu bytes)\n",
			len);
		return;
	}

	lio_ha_recv_session_destroy(be64_to_cpu(msg->session_id));
}

void lio_ha_recv_session_destroy(u64 session_id)
{
	struct ha_recv_sess_entry *e;

	spin_lock(&ha_recv_sess_lock);
	hash_for_each_possible(ha_recv_sess_ht, e, node, session_id) {
		if (e->session_id != session_id)
			continue;
		hash_del(&e->node);
		spin_unlock(&ha_recv_sess_lock);

		pr_debug("ha_recv: session destroyed: id=%llu\n",
			 (unsigned long long)session_id);
		lio_ha_dbg(1, "session destroyed: id=%llu\n",
			   (unsigned long long)session_id);
		target_remove_session(e->se_sess);
		kfree(e);
		return;
	}
	spin_unlock(&ha_recv_sess_lock);

	pr_warn("ha_recv: session_destroy: unknown session_id %llu\n",
		(unsigned long long)session_id);
}

void lio_ha_recv_data_rx(u64 cookie, const void *data, u32 len)
{
	struct ha_recv_data_entry *de;

	de = kzalloc(sizeof(*de), GFP_KERNEL);
	if (!de)
		return;
	de->cmd_cookie = cookie;
	de->data = kvmalloc(len, GFP_KERNEL);
	if (!de->data) {
		kfree(de);
		return;
	}
	memcpy(de->data, data, len);
	de->len = len;

	spin_lock(&ha_recv_data_lock);
	hash_add(ha_recv_data_ht, &de->node, cookie);
	spin_unlock(&ha_recv_data_lock);

	lio_ha_dbg(3, "write data buffered: cookie=%016llx len=%u\n",
		   (unsigned long long)cookie, (unsigned int)len);
}

void lio_ha_recv_submit_cmd(u64 session_id, const void *cdb, size_t cdb_len,
			    u64 cookie, u32 lun, u32 data_length, u8 data_dir)
{
	struct ha_recv_sess_entry *e;
	struct se_session *se_sess = NULL;
	struct ha_recv_cmd *hcmd;

	/* Look up synthetic se_session by session_id. */
	spin_lock(&ha_recv_sess_lock);
	hash_for_each_possible(ha_recv_sess_ht, e, node, session_id) {
		if (e->session_id == session_id) {
			se_sess = e->se_sess;
			break;
		}
	}
	spin_unlock(&ha_recv_sess_lock);

	if (!se_sess) {
		pr_warn_ratelimited("ha_recv: submit_cmd: unknown session %llu\n",
				    (unsigned long long)session_id);
		/*
		 * Send a BUSY response so STANDBY retries after
		 * SESSION_CONNECT re-establishes the session.
		 */
		struct lio_ha_msg_cmd_response resp = {
			.hdr.type    = cpu_to_be32(LIO_HA_MSG_CMD_RESPONSE),
			.cmd_cookie  = cpu_to_be64(cookie),
			.scsi_status = SAM_STAT_BUSY,
		};
		lio_ha_tcp_send(LIO_HA_CHAN_CTL, &resp, sizeof(resp));
		return;
	}

	hcmd = kzalloc(sizeof(*hcmd), GFP_KERNEL);
	if (!hcmd) {
		struct lio_ha_msg_cmd_response resp = {
			.hdr.type    = cpu_to_be32(LIO_HA_MSG_CMD_RESPONSE),
			.cmd_cookie  = cpu_to_be64(cookie),
			.scsi_status = SAM_STAT_BUSY,
		};
		lio_ha_tcp_send(LIO_HA_CHAN_CTL, &resp, sizeof(resp));
		return;
	}
	hcmd->cookie = cookie;

	lio_ha_dbg(2, "submit cmd: session=%llu cookie=%016llx opcode=0x%02x lun=%u len=%u\n",
		   (unsigned long long)session_id,
		   (unsigned long long)cookie,
		   ((const u8 *)cdb)[0],
		   (unsigned int)lun,
		   (unsigned int)data_length);

	/*
	 * target_submit_cmd() routes the command through LIO core.
	 * LUN routing: the session's se_node_acl is the real nacl from the
	 * target TPG (set by lio_ha_recv_session_create), so lun_entry_hlist
	 * contains the correct LUN mappings.
	 *
	 * Use TCM_SIMPLE_TAG; we do not forward the task attribute.
	 */
	target_submit_cmd(&hcmd->se_cmd, se_sess, (unsigned char *)cdb,
			  hcmd->sense_buf, (u64)lun, data_length,
			  TCM_SIMPLE_TAG, (int)data_dir, 0);
}

/* ------------------------------------------------------------------ */
/* Init / exit                                                         */
/* ------------------------------------------------------------------ */

int lio_ha_recv_init(void)
{
	int ret;

	hash_init(ha_recv_sess_ht);
	hash_init(ha_recv_data_ht);

	/*
	 * Register the ha_recv TPG programmatically -- no configfs WWN parent
	 * (NULL), protocol id -1 (internal).  Follows the iSCSI discovery TPG
	 * pattern (iscsit_load_discovery_tpg): set se_tpg_tfo directly, then
	 * call core_tpg_register with NULL wwn.
	 */
	ha_recv_tpg.se_tpg.se_tpg_tfo = &ha_recv_ops;
	ret = core_tpg_register(NULL, &ha_recv_tpg.se_tpg, -1);
	if (ret) {
		pr_err("ha_recv: core_tpg_register failed: %d\n", ret);
		return ret;
	}

	/*
	 * Register handlers for messages that ACTIVE must process.
	 */
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_SESSION_CONNECT,
					ha_recv_session_connect_handler);
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_SESSION_DISCONNECT,
					ha_recv_session_disconnect_handler);
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_CMD_FORWARD,
					ha_recv_cmd_forward_handler);
	lio_ha_tcp_register_ctl_handler(LIO_HA_MSG_TMR_FORWARD,
					ha_recv_tmr_forward_handler);

	pr_debug("ha_recv: initialized\n");
	return 0;
}

void lio_ha_recv_exit(void)
{
	struct ha_recv_sess_entry *e;
	struct ha_recv_data_entry *de;
	struct hlist_node *tmp;
	int bkt;

	/*
	 * Destroy any sessions that were not cleaned up by SESSION_DISCONNECT
	 * messages (e.g. TCP link dropped without clean disconnect).
	 *
	 * target_stop_session() + target_wait_for_sess_cmds() drain commands
	 * that are already in the LIO core pipeline (target_submit_cmd() was
	 * called, backend is executing).  These commands run against LOCAL
	 * storage, so they will complete; this wait is bounded.  It is safe
	 * because lio_ha_tcp_exit() has already run and closed the TCP socket,
	 * so no new CMD_FORWARD messages can arrive.
	 *
	 * lio_ha.ko is loaded on both nodes.  On whichever node is currently
	 * acting as STANDBY, ha_recv_sess_ht is always empty: SESSION_CONNECT
	 * is S->A only, so the STANDBY node never populates its own session
	 * table.  This loop is therefore a no-op on the STANDBY node.
	 */
	spin_lock(&ha_recv_sess_lock);
	hash_for_each_safe(ha_recv_sess_ht, bkt, tmp, e, node) {
		hash_del(&e->node);
		spin_unlock(&ha_recv_sess_lock);
		target_stop_session(e->se_sess);
		target_wait_for_sess_cmds(e->se_sess);
		target_remove_session(e->se_sess);
		kfree(e);
		spin_lock(&ha_recv_sess_lock);
	}
	spin_unlock(&ha_recv_sess_lock);

	/* Discard any buffered WRITE data whose CMD_FORWARD never arrived. */
	spin_lock(&ha_recv_data_lock);
	hash_for_each_safe(ha_recv_data_ht, bkt, tmp, de, node) {
		hash_del(&de->node);
		spin_unlock(&ha_recv_data_lock);
		kvfree(de->data);
		kfree(de);
		spin_lock(&ha_recv_data_lock);
	}
	spin_unlock(&ha_recv_data_lock);

	core_tpg_deregister(&ha_recv_tpg.se_tpg);
	pr_debug("ha_recv: exited\n");
}
