/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * lio_ha.ko -- TrueNAS LIO HA forwarding module (internal header)
 */
#ifndef _LIO_HA_H
#define _LIO_HA_H

#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/spinlock.h>

/* ------------------------------------------------------------------ */
/* Debug tracing (compiled in only for CONFIG_DEBUG_KERNEL builds)     */
/* ------------------------------------------------------------------ */

#ifdef CONFIG_DEBUG_KERNEL
extern int lio_ha_debug;

#define lio_ha_dbg(level, fmt, ...)					\
	do {								\
		if (lio_ha_debug >= (level))				\
			pr_info("lio_ha[%s:%d]: " fmt,			\
				__func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)
#else
#define lio_ha_dbg(level, fmt, ...) \
	do { (void)(level); no_printk(fmt, ##__VA_ARGS__); } while (0)
#endif /* CONFIG_DEBUG_KERNEL */

#define LIO_HA_DEFAULT_PORT     999
#define LIO_HA_ADDR_LEN         64

/*
 * TPG tag offset between Node A and Node B (must match
 * REL_TGT_ID_NODEB_OFFSET in middlewared/utils/iscsi/constants.py).
 * Node A tags are always < this value; Node B tags are always >= it.
 *
 * A tag names one physical target port and is unique across the pair, so a
 * message carries it as the sender holds it and the receiver stores it
 * unchanged.  lio_ha_peer_tpg_tag() maps a port's tag to the tag of the same
 * target's TPG on the other node.  It is used only to find this node's own
 * real TPG, the one with the static node_acl and the LUN mappings, rather than
 * the portal-less phantom TPG that carries the peer's port.
 */
#define LIO_HA_NODE_B_TPG_OFFSET  32000

static inline u16 lio_ha_peer_tpg_tag(u16 tag)
{
	return tag >= LIO_HA_NODE_B_TPG_OFFSET ?
		tag - LIO_HA_NODE_B_TPG_OFFSET :
		tag + LIO_HA_NODE_B_TPG_OFFSET;
}

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
 * lio_ha_pr_replace_device - replace a device's entries in the PR table
 * @dev_name: storage object name (e.g. "iblock_0/disk0")
 * @text:     the device's registrations, in target_ha_pr_export()'s format
 * @len:      length of @text
 *
 * Called on STANDBY from ha_fwd_lun_sync_handler() when a LUN_SYNC message
 * arrives from ACTIVE.  Defined in lio_ha_main.c.
 */
void lio_ha_pr_replace_device(const char *dev_name, const char *text,
			      size_t len);

#endif /* _LIO_HA_H */
