// SPDX-License-Identifier: GPL-2.0-or-later
/*******************************************************************************
 * Filename: target_core_ua.c
 *
 * This file contains logic for SPC-3 Unit Attention emulation
 *
 * (c) Copyright 2009-2013 Datera, Inc.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 ******************************************************************************/

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/rculist.h>
#include <scsi/scsi_proto.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>

#include "target_core_internal.h"
#include "target_core_alua.h"
#include "target_core_pr.h"
#include "target_core_ua.h"

/*
 * ============================================================================
 * Per-I_T-Nexus Session/Device-Entry Join Lifecycle (se_session_deve)
 *
 * struct se_session_deve is a join object binding one active session to
 * one of its mapped LUNs, holding that nexus's own independent Unit
 * Attention queue (see the struct definition in target_core_base.h).
 *
 * This block adds the struct and its setup/teardown lifecycle only; the
 * producer/consumer functions below still read/write the legacy
 * deve->ua_lock/ua_list directly until a following patch migrates them
 * onto se_session_deve and removes those two fields from se_dev_entry.
 * ============================================================================
 */

/*
 * Drain and free every UA queued on sess_deve, optionally returning the
 * head (highest-priority) entry's ASC/ASCQ in *asc and *ascq before
 * freeing it. Caller must hold sess_deve->ua_lock.
 */
static void __target_ua_drain_queue(struct se_session_deve *sess_deve,
				    u8 *asc, u8 *ascq)
{
	struct se_ua *ua, *ua_tmp;
	int head = 1;

	list_for_each_entry_safe(ua, ua_tmp, &sess_deve->ua_list, ua_nacl_list) {
		if (head && asc && ascq) {
			*asc = ua->ua_asc;
			*ascq = ua->ua_ascq;
			head = 0;
		}
		list_del(&ua->ua_nacl_list);
		kmem_cache_free(se_ua_cache, ua);
	}
}

/*
 * Assumes sess->se_node_acl is already assigned and that no fabric
 * command can yet arrive on this session (the session isn't registered
 * with its fabric until after this returns). Allocates one struct
 * se_session_deve per LUN currently mapped to sess->se_node_acl and
 * links it into both deve->sess_list and sess->deve_list. LUNs mapped
 * to the node ACL after this point are not retroactively picked up.
 *
 * On failure partway through, entries already linked are unwound via
 * target_free_session_deve_entries() before returning.
 */
int target_setup_session_deve_entries(struct se_session *sess)
{
	struct se_node_acl *nacl = sess->se_node_acl;
	struct se_dev_entry *deve;
	struct se_session_deve *sess_deve;
	int rc = 0;

	if (!nacl)
		return 0;

	mutex_lock(&nacl->lun_entry_mutex);
	hlist_for_each_entry_rcu(deve, &nacl->lun_entry_hlist, link,
				 lockdep_is_held(&nacl->lun_entry_mutex)) {
		sess_deve = kzalloc(sizeof(*sess_deve), GFP_KERNEL);
		if (!sess_deve) {
			rc = -ENOMEM;
			break;
		}

		sess_deve->se_sess = sess;
		sess_deve->se_deve = deve;
		sess_deve->mapped_lun = deve->mapped_lun;
		spin_lock_init(&sess_deve->ua_lock);
		INIT_LIST_HEAD(&sess_deve->ua_list);
		INIT_LIST_HEAD(&sess_deve->deve_link);
		INIT_LIST_HEAD(&sess_deve->sess_link);
		INIT_LIST_HEAD(&sess_deve->teardown_link);

		/* Link into parent deve's RCU-protected session list */
		spin_lock(&deve->sess_list_lock);
		list_add_tail_rcu(&sess_deve->deve_link, &deve->sess_list);
		spin_unlock(&deve->sess_list_lock);

		/* Link into parent session's spinlock-protected deve list */
		spin_lock(&sess->deve_list_lock);
		list_add_tail(&sess_deve->sess_link, &sess->deve_list);
		spin_unlock(&sess->deve_list_lock);
	}
	mutex_unlock(&nacl->lun_entry_mutex);

	if (rc < 0)
		target_free_session_deve_entries(sess);

	return rc;
}

/*
 * Unlinks and frees every struct se_session_deve owned by @sess. Safe
 * to call even when one of @sess's mapped LUNs is concurrently being
 * unmapped -- core_scsi3_ua_release_all() runs the mirror-image
 * teardown from the se_dev_entry side, and the two paths arbitrate
 * ownership of any shared se_session_deve via SE_SESS_DEVE_CLAIMED so
 * exactly one of them frees a given object.
 */
void target_free_session_deve_entries(struct se_session *sess)
{
	struct se_session_deve *sess_deve, *tmp;
	LIST_HEAD(local_claimed_list);

	if (!sess)
		return;

	/* STAGE 1: Unlink from sess->deve_list and atomically claim ownership */
	spin_lock(&sess->deve_list_lock);
	list_for_each_entry_safe(sess_deve, tmp, &sess->deve_list, sess_link) {
		list_del_init(&sess_deve->sess_link);
		set_bit(SE_SESS_DEVE_SESS_UNLINKED, &sess_deve->flags);

		if (!test_and_set_bit(SE_SESS_DEVE_CLAIMED, &sess_deve->flags))
			list_add_tail(&sess_deve->teardown_link, &local_claimed_list);
	}
	spin_unlock(&sess->deve_list_lock);

	/* STAGE 2: Ensure unlinked from deve->sess_list for claimed entries */
	list_for_each_entry(sess_deve, &local_claimed_list, teardown_link) {
		struct se_dev_entry *deve = sess_deve->se_deve;

		if (deve) {
			spin_lock(&deve->sess_list_lock);
			if (!test_and_set_bit(SE_SESS_DEVE_DEVE_UNLINKED, &sess_deve->flags))
				list_del_rcu(&sess_deve->deve_link);
			spin_unlock(&deve->sess_list_lock);
		}
	}

	/* STAGE 3: single-pass RCU synchronization */
	synchronize_rcu();

	/* STAGE 4: batch drain UAs and free claimed objects */
	list_for_each_entry_safe(sess_deve, tmp, &local_claimed_list, teardown_link) {
		list_del(&sess_deve->teardown_link);

		spin_lock(&sess_deve->ua_lock);
		__target_ua_drain_queue(sess_deve, NULL, NULL);
		spin_unlock(&sess_deve->ua_lock);

		kfree(sess_deve);
	}
}

sense_reason_t
target_scsi3_ua_check(struct se_cmd *cmd)
{
	struct se_dev_entry *deve;
	struct se_session *sess = cmd->se_sess;
	struct se_node_acl *nacl;

	if (!sess)
		return 0;

	nacl = sess->se_node_acl;
	if (!nacl)
		return 0;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, cmd->orig_fe_lun);
	if (!deve) {
		rcu_read_unlock();
		return 0;
	}
	if (list_empty_careful(&deve->ua_list)) {
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	/*
	 * From sam4r14, section 5.14 Unit attention condition:
	 *
	 * a) if an INQUIRY command enters the enabled command state, the
	 *    device server shall process the INQUIRY command and shall neither
	 *    report nor clear any unit attention condition;
	 * b) if a REPORT LUNS command enters the enabled command state, the
	 *    device server shall process the REPORT LUNS command and shall not
	 *    report any unit attention condition;
	 * e) if a REQUEST SENSE command enters the enabled command state while
	 *    a unit attention condition exists for the SCSI initiator port
	 *    associated with the I_T nexus on which the REQUEST SENSE command
	 *    was received, then the device server shall process the command
	 *    and either:
	 */
	switch (cmd->t_task_cdb[0]) {
	case INQUIRY:
	case REPORT_LUNS:
	case REQUEST_SENSE:
		return 0;
	default:
		return TCM_CHECK_CONDITION_UNIT_ATTENTION;
	}
}

int core_scsi3_ua_allocate(
	struct se_dev_entry *deve,
	u8 asc,
	u8 ascq)
{
	struct se_ua *ua, *ua_p, *ua_tmp;

	ua = kmem_cache_zalloc(se_ua_cache, GFP_ATOMIC);
	if (!ua) {
		pr_err("Unable to allocate struct se_ua\n");
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&ua->ua_nacl_list);

	ua->ua_asc = asc;
	ua->ua_ascq = ascq;

	spin_lock(&deve->ua_lock);
	list_for_each_entry_safe(ua_p, ua_tmp, &deve->ua_list, ua_nacl_list) {
		/*
		 * Do not report the same UNIT ATTENTION twice..
		 */
		if ((ua_p->ua_asc == asc) && (ua_p->ua_ascq == ascq)) {
			spin_unlock(&deve->ua_lock);
			kmem_cache_free(se_ua_cache, ua);
			return 0;
		}
		/*
		 * Attach the highest priority Unit Attention to
		 * the head of the list following sam4r14,
		 * Section 5.14 Unit Attention Condition:
		 *
		 * POWER ON, RESET, OR BUS DEVICE RESET OCCURRED highest
		 * POWER ON OCCURRED or
		 * DEVICE INTERNAL RESET
		 * SCSI BUS RESET OCCURRED or
		 * MICROCODE HAS BEEN CHANGED or
		 * protocol specific
		 * BUS DEVICE RESET FUNCTION OCCURRED
		 * I_T NEXUS LOSS OCCURRED
		 * COMMANDS CLEARED BY POWER LOSS NOTIFICATION
		 * all others                                    Lowest
		 *
		 * Each of the ASCQ codes listed above are defined in
		 * the 29h ASC family, see spc4r17 Table D.1
		 */
		if (ua_p->ua_asc == 0x29) {
			if ((asc == 0x29) && (ascq > ua_p->ua_ascq))
				list_add(&ua->ua_nacl_list,
						&deve->ua_list);
			else
				list_add_tail(&ua->ua_nacl_list,
						&deve->ua_list);
		} else if (ua_p->ua_asc == 0x2a) {
			/*
			 * Incoming Family 29h ASCQ codes will override
			 * Family 2AHh ASCQ codes for Unit Attention condition.
			 */
			if ((asc == 0x29) || (ascq > ua_p->ua_asc))
				list_add(&ua->ua_nacl_list,
					&deve->ua_list);
			else
				list_add_tail(&ua->ua_nacl_list,
						&deve->ua_list);
		} else
			list_add_tail(&ua->ua_nacl_list,
				&deve->ua_list);
		spin_unlock(&deve->ua_lock);

		return 0;
	}
	list_add_tail(&ua->ua_nacl_list, &deve->ua_list);
	spin_unlock(&deve->ua_lock);

	pr_debug("Allocated UNIT ATTENTION, mapped LUN: %llu, ASC:"
		" 0x%02x, ASCQ: 0x%02x\n", deve->mapped_lun,
		asc, ascq);

	return 0;
}

void target_ua_allocate_lun(struct se_node_acl *nacl,
			    u32 unpacked_lun, u8 asc, u8 ascq)
{
	struct se_dev_entry *deve;

	if (!nacl)
		return;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, unpacked_lun);
	if (!deve) {
		rcu_read_unlock();
		return;
	}

	core_scsi3_ua_allocate(deve, asc, ascq);
	rcu_read_unlock();
}

/*
 * Releases every form of UA state associated with @deve before it is
 * unmapped/freed: the legacy per-identity queue, and every struct
 * se_session_deve still pointing at @deve (freed via call_rcu()
 * immediately after this function returns to its caller -- see the
 * comment below for why the latter must happen synchronously here).
 */
void core_scsi3_ua_release_all(
	struct se_dev_entry *deve)
{
	struct se_session_deve *sess_deve, *sess_deve_tmp;
	LIST_HEAD(local_claimed_list);
	struct se_ua *ua, *ua_p;

	if (!deve)
		return;

	/*
	 * Legacy drain: deve->ua_lock/ua_list remain the live UA queue for
	 * every producer/consumer not yet converted onto struct
	 * se_session_deve. This half is deleted once a following patch
	 * finishes that conversion and removes deve->ua_lock/ua_list.
	 */
	spin_lock(&deve->ua_lock);
	list_for_each_entry_safe(ua, ua_p, &deve->ua_list, ua_nacl_list) {
		list_del(&ua->ua_nacl_list);
		kmem_cache_free(se_ua_cache, ua);
	}
	spin_unlock(&deve->ua_lock);

	/*
	 * This deve is being unmapped; the caller frees it shortly after
	 * we return (via call_rcu()). Any se_session_deve still pointing
	 * at it -- one per session that had this LUN mapped at login --
	 * must be unlinked from both lists and freed now, or a session
	 * logging out afterward would dereference this, by then freed,
	 * deve through sess_deve->se_deve.
	 *
	 * target_free_session_deve_entries() can be tearing down the same
	 * se_session_deve concurrently from a session logging out right
	 * now. SE_SESS_DEVE_CLAIMED arbitrates exactly-once ownership
	 * between the two paths so only one of them frees a given object;
	 * SESS_UNLINKED/DEVE_UNLINKED guard against either path double
	 * list_del()'ing a link the other side already removed. Neither
	 * path ever holds more than one of {sess->deve_list_lock,
	 * deve->sess_list_lock, ua_lock} at a time, so no lock-ordering
	 * cycle is possible between them.
	 */

	/* STAGE 1: Unlink from deve->sess_list via RCU and atomically claim ownership */
	spin_lock(&deve->sess_list_lock);
	list_for_each_entry_safe(sess_deve, sess_deve_tmp, &deve->sess_list, deve_link) {
		if (!test_and_set_bit(SE_SESS_DEVE_DEVE_UNLINKED, &sess_deve->flags))
			list_del_rcu(&sess_deve->deve_link);

		if (!test_and_set_bit(SE_SESS_DEVE_CLAIMED, &sess_deve->flags))
			list_add_tail(&sess_deve->teardown_link, &local_claimed_list);
	}
	spin_unlock(&deve->sess_list_lock);

	/* STAGE 2: Ensure unlinked from sess->deve_list for claimed entries */
	list_for_each_entry(sess_deve, &local_claimed_list, teardown_link) {
		struct se_session *sess = sess_deve->se_sess;

		if (sess) {
			spin_lock(&sess->deve_list_lock);
			if (!test_and_set_bit(SE_SESS_DEVE_SESS_UNLINKED, &sess_deve->flags))
				list_del_init(&sess_deve->sess_link);
			spin_unlock(&sess->deve_list_lock);
		}
	}

	/* STAGE 3: single-pass RCU synchronization */
	synchronize_rcu();

	/* STAGE 4: batch drain UAs and free claimed objects */
	list_for_each_entry_safe(sess_deve, sess_deve_tmp, &local_claimed_list, teardown_link) {
		list_del(&sess_deve->teardown_link);

		spin_lock(&sess_deve->ua_lock);
		__target_ua_drain_queue(sess_deve, NULL, NULL);
		spin_unlock(&sess_deve->ua_lock);

		kfree(sess_deve);
	}
}

/*
 * Dequeue a unit attention from the unit attention list. This function
 * returns true if the dequeuing succeeded and if *@key, *@asc and *@ascq have
 * been set.
 */
bool core_scsi3_ua_for_check_condition(struct se_cmd *cmd, u8 *key, u8 *asc,
				       u8 *ascq)
{
	struct se_device *dev = cmd->se_dev;
	struct se_dev_entry *deve;
	struct se_session *sess = cmd->se_sess;
	struct se_node_acl *nacl;
	struct se_ua *ua = NULL, *ua_p;
	int head = 1;
	bool dev_ua_intlck_clear = (dev->dev_attrib.emulate_ua_intlck_ctrl
						== TARGET_UA_INTLCK_CTRL_CLEAR);

	if (WARN_ON_ONCE(!sess))
		return false;

	nacl = sess->se_node_acl;
	if (WARN_ON_ONCE(!nacl))
		return false;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, cmd->orig_fe_lun);
	if (!deve) {
		rcu_read_unlock();
		*key = ILLEGAL_REQUEST;
		*asc = 0x25; /* LOGICAL UNIT NOT SUPPORTED */
		*ascq = 0;
		return true;
	}
	*key = UNIT_ATTENTION;
	/*
	 * The highest priority Unit Attentions are placed at the head of the
	 * struct se_dev_entry->ua_list, and will be returned in CHECK_CONDITION +
	 * sense data for the received CDB.
	 */
	spin_lock(&deve->ua_lock);
	list_for_each_entry_safe(ua, ua_p, &deve->ua_list, ua_nacl_list) {
		/*
		 * For ua_intlck_ctrl code not equal to 00b, only report the
		 * highest priority UNIT_ATTENTION and ASC/ASCQ without
		 * clearing it.
		 */
		if (!dev_ua_intlck_clear) {
			*asc = ua->ua_asc;
			*ascq = ua->ua_ascq;
			break;
		}
		/*
		 * Otherwise for the default 00b, release the UNIT ATTENTION
		 * condition.  Return the ASC/ASCQ of the highest priority UA
		 * (head of the list) in the outgoing CHECK_CONDITION + sense.
		 */
		if (head) {
			*asc = ua->ua_asc;
			*ascq = ua->ua_ascq;
			head = 0;
		}
		list_del(&ua->ua_nacl_list);
		kmem_cache_free(se_ua_cache, ua);
	}
	spin_unlock(&deve->ua_lock);
	rcu_read_unlock();

	pr_debug("[%s]: %s UNIT ATTENTION condition with"
		" INTLCK_CTRL: %d, mapped LUN: %llu, got CDB: 0x%02x"
		" reported ASC: 0x%02x, ASCQ: 0x%02x\n",
		nacl->se_tpg->se_tpg_tfo->fabric_name,
		dev_ua_intlck_clear ? "Releasing" : "Reporting",
		dev->dev_attrib.emulate_ua_intlck_ctrl,
		cmd->orig_fe_lun, cmd->t_task_cdb[0], *asc, *ascq);

	return head == 0;
}

int core_scsi3_ua_clear_for_request_sense(
	struct se_cmd *cmd,
	u8 *asc,
	u8 *ascq)
{
	struct se_dev_entry *deve;
	struct se_session *sess = cmd->se_sess;
	struct se_node_acl *nacl;
	struct se_ua *ua = NULL, *ua_p;
	int head = 1;

	if (!sess)
		return -EINVAL;

	nacl = sess->se_node_acl;
	if (!nacl)
		return -EINVAL;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, cmd->orig_fe_lun);
	if (!deve) {
		rcu_read_unlock();
		return -EINVAL;
	}
	if (list_empty_careful(&deve->ua_list)) {
		rcu_read_unlock();
		return -EPERM;
	}
	/*
	 * The highest priority Unit Attentions are placed at the head of the
	 * struct se_dev_entry->ua_list.  The First (and hence highest priority)
	 * ASC/ASCQ will be returned in REQUEST_SENSE payload data for the
	 * matching struct se_lun.
	 *
	 * Once the returning ASC/ASCQ values are set, we go ahead and
	 * release all of the Unit Attention conditions for the associated
	 * struct se_lun.
	 */
	spin_lock(&deve->ua_lock);
	list_for_each_entry_safe(ua, ua_p, &deve->ua_list, ua_nacl_list) {
		if (head) {
			*asc = ua->ua_asc;
			*ascq = ua->ua_ascq;
			head = 0;
		}
		list_del(&ua->ua_nacl_list);
		kmem_cache_free(se_ua_cache, ua);
	}
	spin_unlock(&deve->ua_lock);
	rcu_read_unlock();

	pr_debug("[%s]: Released UNIT ATTENTION condition, mapped"
		" LUN: %llu, got REQUEST_SENSE reported ASC: 0x%02x,"
		" ASCQ: 0x%02x\n", nacl->se_tpg->se_tpg_tfo->fabric_name,
		cmd->orig_fe_lun, *asc, *ascq);

	return (head) ? -EPERM : 0;
}
