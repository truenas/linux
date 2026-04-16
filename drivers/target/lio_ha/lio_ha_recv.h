/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * lio_ha_recv -- ha_recv fabric driver (ACTIVE-side) internal header
 *
 * ha_recv is the ACTIVE-side fabric driver.  It creates synthetic
 * se_sessions for each real initiator session on STANDBY, routes
 * forwarded commands through LIO core (target_submit_cmd()), and
 * completes responses back over the TCP channel.
 *
 * lio_ha_recv_init() / lio_ha_recv_exit() are called from lio_ha_main.c.
 *
 * lio_ha_recv_session_create() and lio_ha_recv_session_destroy() are called
 * by the TCP channel layer when SESSION_CONNECT and SESSION_DISCONNECT
 * messages arrive.
 *
 * lio_ha_recv_submit_cmd() is called by the TCP channel layer when a
 * forwarded command arrives from STANDBY.
 *
 * LUN routing note: forwarded commands are routed to the storage
 * objects on ACTIVE.  transport_lookup_cmd_lun() uses
 * se_sess->se_node_acl->lun_entry_hlist.  SESSION_CONNECT carries
 * target_name and tpg_tag so ha_recv can map each synthetic session
 * to the real target TPG with the correct LUN mappings.
 */
#ifndef _LIO_HA_RECV_H
#define _LIO_HA_RECV_H

#include <linux/types.h>
#include <scsi/scsi_cmnd.h>   /* SCSI_SENSE_BUFFERSIZE */

/**
 * struct ha_recv_cmd - per-command wrapper used by ha_recv
 * @cookie:    STANDBY's se_cmd pointer, echoed in the response so
 *             STANDBY can call target_complete_cmd() on the correct cmd
 * @se_cmd:    embedded LIO command; passed to target_submit_cmd()
 * @sense_buf: sense data buffer; passed to target_submit_cmd() and
 *             populated by LIO core on CHECK_CONDITION
 *
 * Allocated by lio_ha_recv_submit_cmd(); freed in ha_recv_release_cmd()
 * (which is called by LIO core via se_tpg_tfo->release_cmd).
 */
struct ha_recv_cmd {
	u64             cookie;
	struct se_cmd   se_cmd;
	unsigned char   sense_buf[SCSI_SENSE_BUFFERSIZE];
};

int  lio_ha_recv_init(void);
void lio_ha_recv_exit(void);

/**
 * lio_ha_recv_session_create - create a synthetic se_session for a STANDBY session
 * @initiator_name: IQN or WWPN string from SESSION_CONNECT
 * @session_id:     opaque u64 (STANDBY's se_sess pointer) for routing
 * @target_name:    IQN or WWPN of the target TPG from SESSION_CONNECT
 * @tpg_tag:        portal group tag from SESSION_CONNECT
 * @fabric_name:    fabric driver name (e.g. "iscsi", "qla2xxx")
 *
 * Looks up the real target TPG and node_acl so the synthetic session gets
 * correct LUN mappings and PR I_T nexus attribution.  If no matching TPG
 * or ACL is found, session creation is refused (-ENOENT) and subsequent
 * CMD_FORWARD messages for this session_id will receive SAM_STAT_BUSY.
 *
 * Called by the TCP channel when SESSION_CONNECT arrives.
 * Returns 0 on success, negative errno on failure.
 */
int  lio_ha_recv_session_create(const char *initiator_name, u64 session_id,
				const char *target_name, u16 tpg_tag,
				const char *fabric_name);

/**
 * lio_ha_recv_session_destroy - tear down the synthetic se_session
 * @session_id: same opaque u64 passed to lio_ha_recv_session_create()
 *
 * Called by the TCP channel when SESSION_DISCONNECT arrives or the
 * TCP link drops.
 */
void lio_ha_recv_session_destroy(u64 session_id);

/**
 * lio_ha_recv_data_rx - receive WRITE data from STANDBY on ACTIVE
 * @cookie:   cmd_cookie from the DATA channel header (= STANDBY se_cmd ptr)
 * @data:     raw SCSI write data
 * @len:      data length in bytes
 *
 * Buffers the data in the primary-side write-data table keyed by cookie.
 * ha_recv_write_pending() consumes it when the corresponding CMD_FORWARD
 * arrives and LIO core asks for write data.
 *
 * Called by ha_fwd_data_handler() when the DATA channel message cookie
 * is not found in the STANDBY in-flight table.
 */
void lio_ha_recv_data_rx(u64 cookie, const void *data, u32 len);

/**
 * lio_ha_recv_submit_cmd - submit a forwarded command to LIO core on ACTIVE
 * @session_id: identifies the synthetic se_session
 * @cdb:        SCSI CDB bytes
 * @cdb_len:    length of @cdb (typically 10 or 16)
 * @cookie:     STANDBY's se_cmd pointer; echoed in queue_data_in /
 *              queue_status so STANDBY can complete the original cmd
 * @lun:        target LUN
 * @data_length: expected transfer length
 * @data_dir:   DMA_FROM_DEVICE / DMA_TO_DEVICE / DMA_NONE
 *
 * Allocates ha_recv_cmd, populates se_cmd, and calls target_submit_cmd().
 * queue_data_in / queue_status send the response back to STANDBY via
 * TCP, echoing @cookie so STANDBY can complete the original initiator cmd.
 */
void lio_ha_recv_submit_cmd(u64 session_id, const void *cdb, size_t cdb_len,
			    u64 cookie, u32 lun, u32 data_length, u8 data_dir);

#endif /* _LIO_HA_RECV_H */
