/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * lio_ha.ko -- TrueNAS LIO HA forwarding module (internal header)
 */
#ifndef _LIO_HA_H
#define _LIO_HA_H

#include <linux/atomic.h>
#include <linux/spinlock.h>

#define LIO_HA_DEFAULT_PORT  999
#define LIO_HA_ADDR_LEN      64

enum lio_ha_state {
	LIO_HA_DISCONNECTED = 0,
	LIO_HA_CONNECTED,
	LIO_HA_SYNCED,
};

/**
 * struct lio_ha_cfg - module-level configuration and runtime state
 *
 * A single global instance; attributes are exposed via the configfs
 * subsystem at /sys/kernel/config/lio_ha/.  Middleware writes local_addr,
 * peer_addr, port, and forward_active once at STANDBY startup.
 *
 * @local_addr:        IP address on which ha_recv listens (node's own HA IP)
 * @peer_addr:         IP address of the peer node's HA interface
 * @port:              TCP port shared by both sides (default 999)
 * @ha_state:          current HA channel state (read by middleware to gate
 *                     NONOPTIMIZED write on STANDBY)
 * @lock:              protects local_addr, peer_addr, ha_state
 */
struct lio_ha_cfg {
	char             local_addr[LIO_HA_ADDR_LEN];
	char             peer_addr[LIO_HA_ADDR_LEN];
	u16              port;
	enum lio_ha_state ha_state;
	spinlock_t       lock;  /* protects local_addr, peer_addr, ha_state */
};

extern struct lio_ha_cfg lio_ha_cfg;

/**
 * lio_ha_pr_apply - update the replicated PR table on STANDBY
 * @action:         enum lio_ha_pr_action value
 * @dev_name:       storage object name (e.g. "iblock_0/disk0")
 * @initiator_name: IQN or WWPN of the initiator whose key changed
 * @fabric_name:    fabric driver name (e.g. "iscsi", "qla2xxx")
 * @res_key:        RESERVATION KEY from the PR OUT parameter list
 * @sa_res_key:     SERVICE ACTION RESERVATION KEY
 * @res_type:       reservation type (0 if not applicable)
 *
 * Called from ha_fwd_pers_action_handler() when a PERS_ACTION message
 * arrives from ACTIVE, and from ha_fwd_lun_sync_handler() when bulk PR
 * state arrives.  Updates the in-memory replicated PR table (defined in
 * lio_ha_main.c) according to @action.
 */
void lio_ha_pr_apply(u8 action, const char *dev_name,
		     const char *initiator_name, const char *fabric_name,
		     u64 res_key, u64 sa_res_key, u8 res_type);

#endif /* _LIO_HA_H */
