/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * lio_ha_tcp.h -- TCP channel API for lio_ha.ko
 *
 * A single full-duplex TCP connection multiplexed across two logical
 * channels (CTL and DATA) via the lio_ha_wire_hdr.  Both sides run a
 * listen socket and a connect loop simultaneously; the first connection
 * to be established wins.
 *
 * lio_ha_tcp_init() / lio_ha_tcp_exit() are called from lio_ha_init /
 * lio_ha_exit.  The threads they start wait until local_addr, peer_addr,
 * and port are all written before attempting to bind / connect.
 *
 * Message handlers for CTL-channel messages are registered per message
 * type via lio_ha_tcp_register_ctl_handler().  Unregistered types are
 * dropped with a debug log.  Handlers are registered by:
 *
 *   lio_ha_recv.c  SESSION_CONNECT / SESSION_DISCONNECT
 *   lio_ha_fwd.c   CMD_FORWARD / CMD_RESPONSE / TMR_FORWARD / TMR_RESPONSE
 *   lio_ha_main.c  PERS_ACTION / LUN_SYNC / LUN_SYNC_DONE
 */
#ifndef _LIO_HA_TCP_H
#define _LIO_HA_TCP_H

#include <linux/types.h>
#include "lio_ha_wire.h"

/*
 * Maximum CTL-channel payload size (enforced by the rx loop).
 * DATA-channel payloads are raw SCSI data and are handled without
 * this limit (see ha_rx_task's DATA channel path).
 */
#define LIO_HA_MAX_CTL_PAYLOAD    (64 * 1024)   /* 64 KiB */

/* Initialise / shut down the TCP channel (call from module init/exit). */
int  lio_ha_tcp_init(void);
void lio_ha_tcp_exit(void);

/**
 * lio_ha_tcp_send - send a CTL-channel message
 * @chan:    LIO_HA_CHAN_CTL or LIO_HA_CHAN_DATA
 * @payload: message payload (without wire header)
 * @len:     payload length in bytes
 *
 * Prepends the 8-byte wire header and sends the complete message.
 * Returns 0 on success, -ENOTCONN if no connection is up, or a
 * negative errno from the send path.
 *
 * Concurrent calls are serialised by an internal send mutex so that
 * header and payload are always written as a unit.
 */
int lio_ha_tcp_send(enum lio_ha_channel chan, const void *payload, u32 len);

/**
 * lio_ha_tcp_register_data_handler - register the DATA-channel handler
 *
 * Called once at init time; not safe to call concurrently with
 * lio_ha_tcp_exit().
 *
 * @handler: called from the rx kthread for each DATA-channel message.
 *   @cookie:    cmd_cookie from lio_ha_data_hdr
 *   @data:      raw SCSI data (within the rx payload buffer, valid only
 *               for the duration of the call -- copy if needed)
 *   @data_len:  length of raw SCSI data (excludes lio_ha_data_hdr)
 *
 * The handler must not sleep for long.
 */
void lio_ha_tcp_register_data_handler(void (*handler)(u64 cookie, const void *data, u32 data_len));

/**
 * lio_ha_tcp_register_connect_handler - register a TCP connect callback
 *
 * Called once at init time; not safe to call concurrently with
 * lio_ha_tcp_exit().
 *
 * @handler: called when a new TCP connection is established (from the
 *   connect or listen thread, after the rx kthread is started).  On
 *   ACTIVE (forward_active == 0), used to trigger LUN_SYNC.  May sleep.
 *   NOT called during module exit.
 */
void lio_ha_tcp_register_connect_handler(void (*handler)(void));

/**
 * lio_ha_tcp_register_disconnect_handler - register a TCP disconnect callback
 *
 * Called once at init time; not safe to call concurrently with
 * lio_ha_tcp_exit().
 *
 * @handler: called when the TCP connection drops (from the rx kthread,
 *   before sock_release()).  May sleep briefly to flush in-flight tables.
 *   NOT called during module exit (lio_ha_tcp_exit handles that path).
 */
void lio_ha_tcp_register_disconnect_handler(void (*handler)(void));

/**
 * lio_ha_tcp_register_ctl_handler - register a CTL-channel message handler
 * @msg_type:  message type from enum lio_ha_msg_type
 * @handler:   function called with (payload_ptr, payload_len) when a
 *             message of that type arrives.  Called from the rx kthread;
 *             must not sleep for long.  payload includes the
 *             lio_ha_msg_hdr prefix.
 *
 * Not safe to call concurrently with lio_ha_tcp_exit().
 */
void lio_ha_tcp_register_ctl_handler(u32 msg_type,
				     void (*handler)(const void *buf,
						     size_t len));

#endif /* _LIO_HA_TCP_H */
