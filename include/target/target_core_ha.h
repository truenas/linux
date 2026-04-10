/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * target_core_ha.h -- TrueNAS HA forwarding interface for LIO core
 *
 * Declares the hooks added to LIO core under CONFIG_TRUENAS to
 * support active/standby HA between two TrueNAS nodes.  All code
 * additions are isolated in #ifdef CONFIG_TRUENAS / #endif blocks in
 * the core files.  Upstream behaviour is unchanged when the option is
 * not set.
 *
 * For a full design description see drivers/target/lio_ha/README.
 *
 *
 * ARCHITECTURE OVERVIEW
 * =====================
 *
 * ACTIVE owns the storage pool and executes SCSI commands against
 * real iblock or fileio backends.  STANDBY re-exports the same
 * LUNs to initiators over iSCSI or FC and forwards every command to
 * ACTIVE during normal operation.
 *
 * Both nodes load lio_ha.ko.  A single persistent TCP connection
 * (default port 999) carries all HA traffic between them.
 *
 * On STANDBY, iblock/fileio backends are configured but not opened
 * until failover.  While lio_ha_forward_active == 1, every command
 * reaching __target_execute_cmd() or target_tmr_work() is handed to
 * lio_ha.ko for forwarding instead of being executed locally.
 *
 * On ACTIVE, the ha_recv fabric driver (part of lio_ha.ko) creates
 * a synthetic se_session for each initiator session reported by
 * STANDBY.  Forwarded commands execute against the real backends
 * under the correct I_T nexus and PR context.
 *
 *
 * THE THREE HOOKS
 * ===============
 *
 * lio_ha_forward_active  (target_core_transport.c)
 *
 *   Global atomic_t.  Set to 1 on STANDBY startup so that backends
 *   defer open() and all commands are forwarded.  Cleared to 0 at
 *   failover to switch all LUNs to local execution atomically.
 *   Checked in __target_execute_cmd() and target_tmr_work().
 *
 * lio_ha_ops  (target_core_transport.c)
 *
 *   Pointer to struct lio_ha_ops registered by lio_ha.ko.  Provides:
 *
 *     forward_cmd    -- serialise a se_cmd to CMD_FORWARD + optional
 *                       DATA, send to ACTIVE, await CMD_RESPONSE,
 *                       then call target_complete_cmd().  Takes full
 *                       ownership of se_cmd; caller must not touch it
 *                       after this call returns.
 *     forward_tmr    -- same ownership contract for TMR_FORWARD.
 *     session_create -- called from target_setup_session(); sends
 *                       SESSION_CONNECT so ACTIVE creates a matching
 *                       synthetic se_session with the correct LUN
 *                       mappings and node_acl.
 *     session_destroy -- called from target_remove_session(); sends
 *                        SESSION_DISCONNECT.
 *
 * lio_ha_pr_notifier  (target_core_pr.c)
 *
 *   Pointer to struct lio_ha_pr_notifier registered by lio_ha.ko.
 *   Its pr_change() callback fires after each successful PR OUT on
 *   ACTIVE, before target_complete_cmd().  lio_ha.ko uses it to
 *   enqueue a PERS_ACTION message to STANDBY (fire-and-forget)
 *   so STANDBY's replicated in-memory PR table stays current.
 *
 *
 * TPG REGISTRY (target_core_tpg.c)
 * ==================================
 *
 * Normally LIO has no central directory of all Target Portal Groups —
 * each fabric driver knows about its own TPGs but there is no single
 * place to look one up by name.  Two additions to target_core_tpg.c
 * provide that directory under CONFIG_TRUENAS.
 *
 * A linked list (ha_tpg_reg_list) is maintained automatically: every
 * real TPG (one registered with a non-NULL se_wwn) is added when
 * core_tpg_register() is called and removed when core_tpg_deregister()
 * is called.  Internal TPGs such as the iSCSI discovery TPG and
 * ha_recv's own private TPG are excluded.  The list is maintained on
 * both nodes (because core_tpg_register runs on both), but is only
 * consumed on ACTIVE.
 *
 * target_ha_lookup_tpg() -- used during SESSION_CONNECT processing
 *
 *   When STANDBY reports an initiator connection it identifies the TPG
 *   by three strings: fabric_name, target_name (IQN or WWPN), and
 *   tpg_tag.  ACTIVE calls target_ha_lookup_tpg() to resolve those
 *   identifiers to a live se_portal_group *, then looks up the
 *   node_acl for the initiator within that TPG.  The synthetic
 *   se_session is given that real node_acl so that LUN lookups and
 *   PR per-I_T nexus tracking are correct.
 *
 * target_ha_foreach_nacl_dev() -- used during failover
 *
 *   To restore a PR registration onto a device, the caller needs the
 *   concrete (nacl, se_lun, mapped_lun) objects — not just names.
 *   target_ha_foreach_nacl_dev() walks every TPG for a given fabric,
 *   finds the nacl for the initiator in each, and invokes a callback
 *   for every LUN mapping that points at the target device.  This
 *   bridges the replicated PR table (which stores names) and the
 *   target_ha_pr_add_reg() call (which requires live kernel pointers).
 *
 *
 * FAILOVER SEQUENCE
 * =================
 *
 * The storage pool imports on STANDBY (which becomes the new ACTIVE
 * node).  The middleware-driven sequence is:
 *
 *   1. Middleware sets all ALUA target port groups to TRANSITIONING
 *      so that initiators receive the correct UA and pause I/O while
 *      the failover completes.
 *
 *   2. Middleware writes "0" to the forward_active configfs attribute.
 *      lio_ha.ko processes the write as follows:
 *
 *      a. lio_ha_forward_active is cleared to 0 first.  iblock and
 *         fileio check this flag inside configure_device(), so it must
 *         be clear before any backend is opened.
 *
 *      b. target_for_each_device() calls lio_ha_failover_device() for
 *         every configured se_device.  Per device:
 *
 *         i.  The replicated PR table is scanned for entries matching
 *             this device and collected into a snapshot.
 *         ii. For each registrant, target_ha_foreach_nacl_dev()
 *             resolves the (nacl, lun, mapped_lun) tuple and
 *             target_ha_pr_add_reg() installs the PR registration in
 *             LIO core (non-holders first, holder last so the
 *             reservation is set after all registrants exist).
 *         iii.target_ha_reopen_backend() opens the backing store.
 *
 *   3. Middleware sets all ALUA target port groups to ACTIVE-OPTIMIZED.
 *      Initiators resume I/O against the new ACTIVE node.
 *
 * Writing "0" to forward_active is idempotent.  Devices whose backend
 * fails to open return NOT READY; the operator retries by writing "0"
 * again.
 */
#ifndef _TARGET_CORE_HA_H
#define _TARGET_CORE_HA_H

#ifdef CONFIG_TRUENAS

#include <linux/atomic.h>

struct se_cmd;
struct se_device;
struct se_lun;
struct se_node_acl;
struct se_portal_group;
struct se_session;

/**
 * struct lio_ha_ops - operations provided by lio_ha.ko to LIO core
 * @forward_cmd: forward a data/PR command to ACTIVE; takes ownership of @cmd.
 *               Always completes @cmd (via target_complete_cmd()) before
 *               returning -- either with the ACTIVE's response on success, or
 *               with SAM_STAT_BUSY if the HA link is down or the send fails.
 *               Never returns an error; the caller does not touch @cmd after
 *               this call.
 * @forward_tmr: same ownership and completion contract as @forward_cmd.
 * @session_create: called from target_setup_session() after the session is
 *                  registered.  On STANDBY, sends SESSION_CONNECT to ACTIVE
 *                  so ACTIVE creates a synthetic se_session with the correct
 *                  LUN mappings.  Skips ha_recv's own sessions (tpg_wwn=NULL)
 *                  and sessions created when forward_active=0.  Must not sleep.
 * @session_destroy: called from target_remove_session() before the session is
 *                   deregistered.  On STANDBY, sends SESSION_DISCONNECT so
 *                   ACTIVE tears down the synthetic se_session.  Same filters
 *                   as @session_create.  Must not sleep.
 *
 * @forward_cmd and @forward_tmr are guaranteed non-NULL whenever
 * lio_ha_forward_active == 1.  @session_create and @session_destroy are
 * always checked for NULL before calling.
 */
struct lio_ha_ops {
	void (*forward_cmd)(struct se_cmd *cmd);
	void (*forward_tmr)(struct se_cmd *cmd);
	void (*session_create)(struct se_session *sess);
	void (*session_destroy)(struct se_session *sess);
};

/**
 * struct lio_ha_pr_notifier - PR change notification hook registered by lio_ha.ko
 * @pr_change: called after each successful PR OUT on ACTIVE
 *             @dev:            the se_device whose PR state changed
 *             @action:         SERVICE ACTION field from the PR OUT CDB
 *             @res_key:        RESERVATION KEY field from the PR OUT parameter list
 *             @sa_res_key:     SERVICE ACTION RESERVATION KEY (new key for REGISTER)
 *             @type:           reservation type from the CDB (0 if not applicable)
 *             @initiator_name: IQN or WWPN of the initiator that issued PR OUT
 *             @fabric_name:    fabric driver name (e.g. "iscsi", "qla2xxx")
 *
 * lio_ha.ko registers this hook to receive incremental PR mutations and
 * push PERS_ACTION messages to STANDBY.  The hook is fired under RCU read
 * lock; implementations must not sleep.
 */
struct lio_ha_pr_notifier {
	void (*pr_change)(struct se_device *dev, u8 action,
			  u64 res_key, u64 sa_res_key, u8 type,
			  const char *initiator_name,
			  const char *fabric_name);
};

/* Defined in target_core_transport.c */
extern atomic_t lio_ha_forward_active;
void lio_ha_register_ops(const struct lio_ha_ops *ops);
void lio_ha_unregister_ops(void);

/* Defined in target_core_pr.c */
void lio_ha_register_pr_notifier(const struct lio_ha_pr_notifier *notifier);
void lio_ha_unregister_pr_notifier(void);
int target_ha_pr_export(struct se_device *dev, char *buf, size_t buf_len);

/**
 * target_ha_pr_add_reg - directly add one PR registration at failover
 * @dev:        the se_device
 * @nacl:       the initiator's se_node_acl (obtained from target_ha_foreach_nacl_dev)
 * @lun:        the target se_lun the nacl is mapped through
 * @mapped_lun: the initiator-side LUN number
 * @sa_res_key: the registration key
 * @res_holder: 1 if this registration also holds the reservation
 * @res_type:   reservation type (valid when res_holder == 1)
 *
 * Called by lio_ha.ko at failover to restore replicated PR state.
 * Must not be called concurrently for the same device.
 * Returns 0 on success, -ENOMEM on allocation failure.
 */
int target_ha_pr_add_reg(struct se_device *dev,
			 struct se_node_acl *nacl,
			 struct se_lun *lun,
			 u64 mapped_lun,
			 u64 sa_res_key,
			 int res_holder,
			 u8 res_type);

/* Defined in target_core_device.c */
int target_for_each_device(int (*fn)(struct se_device *dev, void *data),
			   void *data);

/**
 * target_ha_reopen_backend - reopen a deferred-open backend at HA failover
 * @dev: the se_device whose backend was opened with lio_ha_forward_active=1
 *
 * Retries dev->transport->configure_device() after lio_ha_forward_active is
 * cleared, then refreshes block_size/queue_depth from the hw_ attributes that
 * are now populated by the backend.  Idempotent: iblock/fileio skip if already
 * open (ibd_bdev_file != NULL / fd_file != NULL).
 *
 * Returns 0 on success, negative errno if the backend fails to open.
 */
int target_ha_reopen_backend(struct se_device *dev);

/* Defined in target_core_transport.c */
void target_complete_tmr(struct se_cmd *cmd);

/* Defined in target_core_tpg.c -- find a real fabric TPG by identity */
struct se_portal_group *target_ha_lookup_tpg(const char *fabric_name,
					     const char *target_name,
					     u16 tpg_tag);

/* Callback type for target_ha_foreach_nacl_dev(). */
typedef void (*target_ha_nacl_fn_t)(struct se_node_acl *nacl, struct se_lun *lun,
				    u64 mapped_lun, void *data);

/**
 * target_ha_foreach_nacl_dev - find all nacl+lun mappings for an initiator/device
 * @fabric_name:     fabric driver name (e.g. "iscsi", "qla2xxx")
 * @initiator_name:  IQN or WWPN of the initiator
 * @dev:             the se_device to match LUN mappings against
 * @fn:              callback invoked for each (nacl, lun, mapped_lun) match
 * @data:            opaque pointer passed to @fn
 *
 * Iterates all registered TPGs for @fabric_name, locates the nacl for
 * @initiator_name in each, and walks the nacl's lun_entry_hlist to find
 * entries mapped to @dev.  Calls @fn for each match.
 *
 * Called by lio_ha.ko at failover to resolve nacl+lun context needed by
 * target_ha_pr_add_reg().  Called from process context; @fn must not sleep
 * for long and must not call target_ha_foreach_nacl_dev() recursively.
 */
void target_ha_foreach_nacl_dev(const char *fabric_name, const char *initiator_name,
				struct se_device *dev, target_ha_nacl_fn_t fn, void *data);

/*
 * target_ha_session_create / target_ha_session_destroy
 *
 * Fire the lio_ha.ko session_create / session_destroy hooks for a fabric
 * that registers sessions without going through target_setup_session() or
 * target_remove_session() (e.g. iSCSI, which calls __transport_register_session
 * and transport_deregister_session directly).  These wrappers hide the static
 * ha_ops pointer from code outside target_core_transport.c.
 *
 * Must be called from process context (may sleep via lio_ha_tcp_send).
 * session_create: call after the session is fully registered and any
 *   per-fabric spinlocks protecting the session list are released.
 * session_destroy: call before transport_deregister_session() while
 *   se_tpg and se_node_acl are still valid.
 */
void target_ha_session_create(struct se_session *sess);
void target_ha_session_destroy(struct se_session *sess);

#endif /* CONFIG_TRUENAS */
#endif /* _TARGET_CORE_HA_H */
