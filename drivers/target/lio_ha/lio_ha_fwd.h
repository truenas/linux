/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * lio_ha_fwd.h -- STANDBY-side I/O and TMR forwarding
 *
 * lio_ha_fwd_init() / lio_ha_fwd_exit() are called from lio_ha_main.c.
 *
 * lio_ha_forward_cmd() implements ha_ops.forward_cmd(): it packages each
 * SCSI command and sends it to ACTIVE over the HA TCP channel, then
 * completes the command when the response arrives.
 *
 * lio_ha_forward_tmr() implements ha_ops.forward_tmr(): it sends
 * TMR_FORWARD to ACTIVE and completes via target_complete_tmr() when
 * the TMR_RESPONSE arrives.
 */
#ifndef _LIO_HA_FWD_H
#define _LIO_HA_FWD_H

#include <linux/types.h>

struct se_cmd;

int  lio_ha_fwd_init(void);
void lio_ha_fwd_exit(void);

/**
 * lio_ha_forward_cmd - ha_ops.forward_cmd implementation
 * @cmd: the se_cmd to forward
 *
 * Packages the command and sends it to ACTIVE over the TCP channel.
 * Always completes @cmd asynchronously -- with the ACTIVE's actual status
 * on success, or SAM_STAT_BUSY if the HA link is down or send fails.
 */
void lio_ha_forward_cmd(struct se_cmd *cmd);

/**
 * lio_ha_forward_tmr - ha_ops.forward_tmr implementation
 * @cmd: the se_cmd carrying the TMR request (se_tmr_req populated)
 *
 * Sends TMR_FORWARD to ACTIVE and eventually calls target_complete_tmr()
 * with the result.  On send failure or link down, completes immediately
 * with TMR_FUNCTION_REJECTED.
 */
void lio_ha_forward_tmr(struct se_cmd *cmd);

#endif /* _LIO_HA_FWD_H */
