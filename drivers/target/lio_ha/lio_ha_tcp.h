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
 *   lio_ha_main.c  LUN_SYNC / LUN_SYNC_DONE
 */
#ifndef _LIO_HA_TCP_H
#define _LIO_HA_TCP_H

#include <linux/types.h>
#include "lio_ha_wire.h"

struct scatterlist;

/*
 * Maximum CTL-channel payload size (enforced by the rx loop).  The largest
 * CTL message is a LUN_SYNC, which carries all of one device's PR
 * registrations: 4 MiB holds several thousand even with the longest names.
 * DATA-channel messages carry at most LIO_HA_MAX_DATA_CHUNK of data.
 */
#define LIO_HA_MAX_CTL_PAYLOAD    (4 * 1024 * 1024)   /* 4 MiB */

/* Initialise / shut down the TCP channel (call from module init/exit). */
int  lio_ha_tcp_init(void);
void lio_ha_tcp_exit(void);

/**
 * lio_ha_tcp_send - send a CTL-channel message
 * @chan:    LIO_HA_CHAN_CTL or LIO_HA_CHAN_DATA
 * @payload: message payload (without wire header)
 * @len:     payload length in bytes
 *
 * Prepends the 12-byte wire header and sends the complete message.
 * Returns 0 on success, -ENOTCONN if no connection is up, or a
 * negative errno from the send path.
 *
 * Concurrent calls are serialised by an internal send mutex so that
 * header and payload are always written as a unit.
 */
int lio_ha_tcp_send(enum lio_ha_channel chan, const void *payload, u32 len);

/**
 * lio_ha_tcp_generation - the current connection generation
 *
 * Names the connection that is up, or the last one if none is.  It
 * changes when a new connection is installed, never otherwise.
 */
u64 lio_ha_tcp_generation(void);

/**
 * lio_ha_tcp_send_gen - send only on the connection of generation @gen
 * @gen: from lio_ha_tcp_generation(), or 0 for whichever is up
 *
 * As lio_ha_tcp_send(), but returns -ENOTCONN, sending nothing, if a
 * connection after @gen has been installed.  A sender whose message
 * belongs to an in-flight entry captures @gen before it adds the entry,
 * so that once the link has dropped (and the disconnect handler has
 * completed the entry), nothing for it reaches the next connection.
 */
int lio_ha_tcp_send_gen(enum lio_ha_channel chan, const void *payload,
			u32 len, u64 gen);

/**
 * lio_ha_tcp_send_data - send a command's data on the DATA channel
 * @cookie: the command's cmd_cookie
 * @sg:     the data
 * @nents:  entries in @sg
 * @total:  bytes to send from the start of @sg; 0 sends nothing
 * @gen:    as for lio_ha_tcp_send_gen()
 *
 * Sends the data in chunks of LIO_HA_DATA_CHUNK, each a DATA message of
 * its own, so other messages can go out between them.  Returns 0, or the
 * first error; after a send error the connection is already shut down.
 */
int lio_ha_tcp_send_data(u64 cookie, struct scatterlist *sg,
			 unsigned int nents, u32 total, u64 gen);

/**
 * lio_ha_tcp_register_data_handler - register the DATA-channel handler
 *
 * Called once at init time; not safe to call concurrently with
 * lio_ha_tcp_exit().
 *
 * @handler: called from the rx kthread once all of a transfer's chunks
 *   have arrived.
 *   @cookie:    cmd_cookie from lio_ha_data_hdr
 *   @data:      the whole transfer, kvmalloc'd; the handler takes it and
 *               must kvfree() it or keep it
 *   @data_len:  its length
 *
 * The handler must not sleep for long.
 */
void lio_ha_tcp_register_data_handler(void (*handler)(u64 cookie, void *data, u32 data_len));

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
 *   before sock_release()).  May sleep to flush in-flight tables and wait
 *   for commands.  No new connection is accepted until every handler has
 *   returned.  NOT called during module exit (lio_ha_tcp_exit handles that
 *   path).  Up to two handlers can be registered; they run in the order
 *   they were registered.
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
