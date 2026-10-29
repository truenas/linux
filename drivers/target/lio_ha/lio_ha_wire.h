/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * lio_ha_wire.h -- wire protocol types for the lio_ha HA channel
 *
 * A single multiplexed TCP connection carries all lio_ha traffic.
 * Every message on the wire is prefixed by an 8-byte lio_ha_wire_hdr
 * (channel + payload length), followed by the payload.
 *
 * CTL-channel (channel 0) payloads start with lio_ha_msg_hdr (type +
 * reserved), followed by a message-specific struct.
 *
 * DATA-channel (channel 1) payloads carry raw SCSI data for WRITE
 * commands; they are correlated to a CMD_FORWARD message by the
 * cmd_cookie carried in that message.
 *
 * All integer fields are in network byte order (__be*).
 * String fields (IQN, WWPN, device names) are NUL-terminated ASCII;
 * no byte-order conversion needed.
 *
 * Directionality legend:
 *   S->A = STANDBY to ACTIVE
 *   A->S = ACTIVE to STANDBY
 */
#ifndef _LIO_HA_WIRE_H
#define _LIO_HA_WIRE_H

#include <linux/types.h>

/*
 * Every TPG tag carried in a message is the global tag of a physical target
 * port.  The receiver stores it as sent.
 */

/* ------------------------------------------------------------------ */
/* Wire header (8 bytes, present on every message)                    */
/* ------------------------------------------------------------------ */

struct lio_ha_wire_hdr {
	__be32 channel;  /* enum lio_ha_channel */
	__be32 length;   /* payload length; does NOT include this header */
};

enum lio_ha_channel {
	LIO_HA_CHAN_CTL  = 0,  /* control: session, I/O, TMR, PR, LUN sync */
	LIO_HA_CHAN_DATA = 1,  /* raw SCSI data for forwarded WRITE commands */
};

/* ------------------------------------------------------------------ */
/* CTL-channel message types                                           */
/* ------------------------------------------------------------------ */

enum lio_ha_msg_type {
	/* Session lifecycle */
	LIO_HA_MSG_SESSION_CONNECT    = 1,  /* S->A */
	LIO_HA_MSG_SESSION_DISCONNECT = 2,  /* S->A */

	/* I/O forwarding */
	LIO_HA_MSG_CMD_FORWARD        = 3,  /* S->A */
	LIO_HA_MSG_CMD_RESPONSE       = 4,  /* A->S */

	/* TMR forwarding */
	LIO_HA_MSG_TMR_FORWARD        = 5,  /* S->A */
	LIO_HA_MSG_TMR_RESPONSE       = 6,  /* A->S */

	/* 7 was PERS_ACTION, an incremental PR change; no longer sent. */

	/* PR replication: on link up, and after PR OUT changes a device */
	LIO_HA_MSG_LUN_SYNC           = 8,  /* A->S; one per storage object */
	LIO_HA_MSG_LUN_SYNC_DONE      = 9,  /* A->S; all LUN_SYNCs complete */

	_LIO_HA_MSG_MAX
};

/* ------------------------------------------------------------------ */
/* Common CTL-channel message header (8 bytes)                        */
/* Every CTL payload begins with this struct.                         */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_hdr {
	__be32 type;      /* enum lio_ha_msg_type */
	__be32 reserved;  /* must be zero */
};

/* ------------------------------------------------------------------ */
/* String field sizes                                                  */
/* ------------------------------------------------------------------ */

/*
 * IQN maximum length: RFC 3720 s3.2.6.3 says <= 223 characters.
 * We carry IQN/WWPN in the same field; WWPN is much shorter.
 * 224 bytes gives IQN max + NUL.
 */
#define LIO_HA_INITIATOR_NAME_LEN  224

/*
 * Storage object names as they appear in LIO configfs: "<hba>/<soname>",
 * e.g. "iblock_0/my-long-extent-name".
 *
 * Components:
 *   HBA group name:  "iblock_0" or "fileio_0" (8 chars)
 *   separator:       "/"                       (1 char)
 *   SO name:         sanitized TrueNAS extent name, API max 64 chars
 *
 * Worst case: 8 + 1 + 64 = 73 chars + NUL = 74 bytes.
 * 80 bytes gives 79 usable chars with 6 chars of headroom.
 */
#define LIO_HA_DEV_NAME_LEN  80

/*
 * Fabric driver name (target_core_fabric_ops.fabric_name): "iscsi",
 * "qla2xxx", etc.  31 chars + NUL is plenty.
 */
#define LIO_HA_FABRIC_NAME_LEN  32

/* Matches PR_REG_ISID_LEN in target_core_base.h. */
#define LIO_HA_ISID_LEN  16

/* Maximum CDB length (SPC-4 table 1: 32 bytes for variable-length CDBs) */
#define LIO_HA_CDB_LEN  32

/* Maximum DATA-channel payload (raw SCSI data, one forwarded command).   */
#define LIO_HA_MAX_DATA_PAYLOAD   (4 * 1024 * 1024)   /* 4 MiB           */

/*
 * DATA-channel payload header (8 bytes, immediately before raw SCSI data).
 * Wire format: lio_ha_wire_hdr + lio_ha_data_hdr + <raw SCSI data>.
 * Used for both WRITE data (S->A) and READ response data (A->S).
 */
struct lio_ha_data_hdr {
	__be64 cmd_cookie;   /* identifies the CMD_FORWARD / CMD_RESPONSE */
};

/* ------------------------------------------------------------------ */
/* SESSION_CONNECT (S->A)                                              */
/*                                                                     */
/* Sent by STANDBY when a real initiator connects to one of its     */
/* iSCSI/FC targets.  ACTIVE's ha_recv looks up the real TPG via     */
/* fabric_name + target_name + tpg_tag, finds the node_acl for        */
/* initiator_name, and creates a synthetic se_session on ha_recv_tpg  */
/* with se_node_acl pointing to the real nacl so that LUN lookups     */
/* resolve correctly.                                                  */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_session_connect {
	struct lio_ha_msg_hdr hdr;          /* type = LIO_HA_MSG_SESSION_CONNECT */
	__be64                session_id;   /* STANDBY's se_sess pointer; opaque */
	__be16                tpg_tag;      /* sender's tpg_get_tag(): the physical port */
	u8                    pad[6];       /* reserved, must be zero */
	char initiator_name[LIO_HA_INITIATOR_NAME_LEN]; /* IQN or WWPN, NUL-terminated */
	char target_name[LIO_HA_INITIATOR_NAME_LEN];    /* IQN or WWPN of target */
	/* Fabric-provided nexus discriminator (iSCSI/iSER ISID); empty if none */
	char initiator_sid[LIO_HA_ISID_LEN];
	char fabric_name[LIO_HA_FABRIC_NAME_LEN];       /* e.g. "iscsi", "qla2xxx" */
};

/* ------------------------------------------------------------------ */
/* SESSION_DISCONNECT (S->A)                                           */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_session_disconnect {
	struct lio_ha_msg_hdr hdr;         /* type = LIO_HA_MSG_SESSION_DISCONNECT */
	__be64                session_id;  /* same id as SESSION_CONNECT */
};

/* ------------------------------------------------------------------ */
/* CMD_FORWARD (S->A)                                                  */
/*                                                                     */
/* For WRITE commands: raw data is sent on the DATA channel before     */
/* CMD_FORWARD, correlated by cmd_cookie.                              */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_cmd_forward {
	struct lio_ha_msg_hdr hdr;           /* type = LIO_HA_MSG_CMD_FORWARD */
	__be64 session_id;                   /* identifies synthetic se_sess on ACTIVE */
	__be64 cmd_cookie;                   /* STANDBY's se_cmd ptr; echoed back */
	__be64 data_length;                  /* expected transfer length */
	__be32 lun;                          /* target LUN number */
	__be32 data_dir;    /* enum dma_data_direction: TO_DEVICE=1 FROM_DEVICE=2 NONE=3 */
	u8     cdb[LIO_HA_CDB_LEN];          /* SCSI CDB, zero-padded */
};

/* ------------------------------------------------------------------ */
/* CMD_RESPONSE (A->S)                                                 */
/*                                                                     */
/* For READ commands: data is sent on the DATA channel before          */
/* CMD_RESPONSE (both on CTL channel), correlated by cmd_cookie.      */
/* Variable tail: sense_len bytes of sense data follow the fixed part */
/* if sense_len > 0.                                                   */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_cmd_response {
	struct lio_ha_msg_hdr hdr;    /* type = LIO_HA_MSG_CMD_RESPONSE */
	__be64 cmd_cookie;            /* echoed from CMD_FORWARD */
	u8     scsi_status;           /* SAM_STAT_GOOD / SAM_STAT_CHECK_CONDITION */
	u8     sense_len;             /* 0 = no sense data */
	u8     pad[6];
	/* If sense_len > 0: sense_len bytes of sense data follow */
};

/* ------------------------------------------------------------------ */
/* TMR_FORWARD (S->A)                                                  */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_tmr_forward {
	struct lio_ha_msg_hdr hdr;    /* type = LIO_HA_MSG_TMR_FORWARD */
	__be64 session_id;
	__be64 cmd_cookie;            /* STANDBY's se_cmd ptr for this TMR */
	__be64 ref_cookie;            /* for ABORT TASK: cookie of cmd to abort */
	__be32 function;              /* LIO TMR function code (TMR_ABORT_TASK etc.) */
	__be32 lun;                   /* target LUN for the TMR */
};

/* ------------------------------------------------------------------ */
/* TMR_RESPONSE (A->S)                                                 */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_tmr_response {
	struct lio_ha_msg_hdr hdr;    /* type = LIO_HA_MSG_TMR_RESPONSE */
	__be64 cmd_cookie;            /* echoed from TMR_FORWARD */
	__be32 response;              /* TMR_FUNCTION_COMPLETE / TMR_FUNCTION_REJECTED */
	__be32 reserved;
};

/* ------------------------------------------------------------------ */
/* LUN_SYNC (A->S)                                                     */
/*                                                                     */
/* Full PR state for one storage object, sent on TCP link up and     */
/* after PR OUT commands change it.  STANDBY replaces the object's    */
/* entries with these.                                                 */
/* Payload: this fixed header immediately followed by aptpl_buf_len   */
/* bytes of APTPL-format text (same format as LIO's res_aptpl_metadata */
/* configfs attribute).                                                */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_lun_sync {
	struct lio_ha_msg_hdr hdr;    /* type = LIO_HA_MSG_LUN_SYNC */
	__be32 aptpl_buf_len;         /* length of APTPL text following */
	__be32 reserved;
	char   dev_name[LIO_HA_DEV_NAME_LEN]; /* storage object name */
	/* APTPL text immediately follows */
};

/* ------------------------------------------------------------------ */
/* LUN_SYNC_DONE (A->S)                                                */
/*                                                                     */
/* Sent after all LUN_SYNC messages for the current sync cycle.       */
/* On receipt, STANDBY advances ha_state from CONNECTED to SYNCED.  */
/* ------------------------------------------------------------------ */

struct lio_ha_msg_lun_sync_done {
	struct lio_ha_msg_hdr hdr;    /* type = LIO_HA_MSG_LUN_SYNC_DONE */
};

#endif /* _LIO_HA_WIRE_H */
