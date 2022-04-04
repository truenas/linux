/*-
 * SPDX-License-Indentifier: BSD-2-Clause-FreeBSD
 *
 * Copyright 2022 iXsystems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_proto.h>
#include <target/target_core_base.h>
#include <linux/libata.h>
#include "ahci.h"

#define DRV_NAME	"ahciem"
#define DRV_VERSION	"0.1"

/* FreeBSD XREF sys/cam/ata/ata_all.h
struct ata_cmd {
	u_int8_t	flags;

	u_int8_t	command;		// cmnd[2]
	u_int8_t	features;		// cmnd[3]
	u_int8_t	lba_low;		// cmnd[4]
	u_int8_t	lba_mid;		// cmnd[5]
	u_int8_t	lba_high;		// cmnd[6]
	u_int8_t	device;			// cmnd[7]
	u_int8_t	lba_low_exp;		// cmnd[8]
	u_int8_t	lba_mid_exp;		// cmnd[9]
	u_int8_t	lba_high_exp;		// cmnd[10]
	u_int8_t	features_exp;		// cmnd[11]
	u_int8_t	sector_count;		// cmnd[12]
	u_int8_t	sector_count_exp;	// cmnd[13]

	u_int8_t	control;		// cmnd[15]
};

struct ata_res {
	u_int8_t	flags;

	u_int8_t	status;			// res[2]
	u_int8_t	error;			// res[3]
	u_int8_t	lba_low;		// res[4]
	u_int8_t	lba_mid;		// res[5]
	u_int8_t	lba_high;		// res[6]
	u_int8_t	device;			// res[7]
	u_int8_t	lba_low_exp;		// res[8]
	u_int8_t	lba_mid_exp;		// res[9]
	u_int8_t	lba_high_exp;		// res[10]

	u_int8_t	sector_count;		// res[12]
	u_int8_t	sector_count_exp;	// res[13]
};
*/

#define AHCIEM_RBUF_SIZE	576	/* size from libata-scsi.c */

static DEFINE_SPINLOCK(ahciem_rbuf_lock);
static u8 ahciem_rbuf[AHCIEM_RBUF_SIZE];

struct ahciem_args {
	struct scsi_cmnd *cmd;
	struct ata_device *dev;
};

static void ahciem_rbuf_fill(struct ahciem_args *args,
		unsigned int (*actor)(struct ahciem_args *args, u8 *rbuf))
{
	unsigned int rc;
	struct scsi_cmnd *cmd = args->cmd;
	unsigned long flags;

	spin_lock_irqsave(&ahciem_rbuf_lock, flags);

	memset(ahciem_rbuf, 0, AHCIEM_RBUF_SIZE);
	rc = actor(args, ahciem_rbuf);
	if (rc == 0)
		sg_copy_from_buffer(scsi_sglist(cmd), scsi_sg_count(cmd),
				    ahciem_rbuf, AHCIEM_RBUF_SIZE);

	spin_unlock_irqrestore(&ahciem_rbuf_lock, flags);

	if (rc == 0)
		cmd->result = SAM_STAT_GOOD;
}

/*
 * Generic SCSI operations
 */

static unsigned int ahciem_scsiop_inq_std(struct ahciem_args *args, u8 *rbuf)
{
	static const u8 hdr[] = {
		TYPE_ENCLOSURE,
		0,
		0x7,	/* claim SPC-5 version compatibility */
		0x2,	/* response data format compatible with SPC-5 */
		95 - 4,	/* additional length */
		0,
		0x40,	/* enclosure services provided (XXX: is this correct?) */
		0x2,	/* claim SAM-5 command management compatibility */
	};
	static const u8 versions[] = {
		/* XXX: Copied from ata_scsiop_inq_std, might need tweaking? */
		0x00, 0xA0,	/* SAM-5 (no version claimed) */
		0x06, 0x00,	/* SBC-4 (no version claimed) */
		0x05, 0xC0,	/* SPC-5 (no version claimed) */
	};
	struct scsi_device *sdev = args->dev->sdev;

	memcpy(rbuf, hdr, sizeof(hdr));
	memcpy(rbuf + 8, "AHCI    ", INQUIRY_VENDOR_LEN);
	memcpy(rbuf + 16, "SGPIO Enclosure ", INQUIRY_MODEL_LEN);
	memcpy(rbuf + 32, "2.00", INQUIRY_REVISION_LEN);
	memcpy(rbuf + 36, "0001", 4);
	memcpy(rbuf + 40, "S-E-S ", 6);
	memcpy(rbuf + 46, "2.00", 4);
	memcpy(rbuf + 58, versions, sizeof(versions));
	return 0;
}

static unsigned int ahciem_scsiop_inq_00(struct ahciem_args *args, u8 *rbuf)
{
	static const u8 pages[] = {
		0x00,	/* this page */
		0x83,	/* device ident page */
	};

	rbuf[3] = sizeof(pages);
	memcpy(rbuf + 4, pages, sizeof(pages));
	return 0;
}

/* XXX: Mostly copied from ata_scsiop_inq_std, might need more tweaking */
static unsigned int ahciem_scsiop_inq_83(struct ahciem_args *args, u8 *rbuf)
{
	u8 *p = rbuf;

	p[1] = 0x83;	/* this page */
	p += 4;
	/* piv=0, assoc=lu, code_set=ASCII, designator=vendor */
	p[0] = 2;
	p[1] = ATA_ID_SERNO_LEN;
	p += 4;
	ata_id_string(args->dev->id, (unsigned char *)p,
		      ATA_ID_SERNO, ATA_ID_SERNO_LEN);
	p += ATA_ID_SERNO_LEN;
	/* piv=0, assoc=lu, code_set=ASCII, designator=t10 vendor id */
	p[0] = 2;
	p[1] = 1;
	p[3] = 68;	/* sat model serial desc len */
	p += 4;
	memcpy(p, "ATA     ", 8);
	p += 8;
	ata_id_string(args->dev->id, (unsigned char *)p,
		      ATA_ID_PROD, ATA_ID_PROD_LEN);
	p += ATA_ID_PROD_LEN;
	ata_id_string(args->dev->id, (unsigned char *)p,
		      ATA_ID_SERNO, ATA_ID_SERNO_LEN);
	p += ATA_ID_SERNO_LEN;
	/* XXX: ignoring wwn stuff for now */
	rbuf[3] = p - rbuf - 4;
	return 0;
}

static unsigned int ahciem_scsiop_report_luns(struct ahciem_args *args, u8 *rbuf)
{
	/* XXX: Is this the right thing to do? */
	rbuf[3] = 8;	/* one lun, 8 bytes */
	return 0;
}

static unsigned int ahciem_sesop_rxdx_0(struct ahciem_args *args, u8 *rbuf)
{
	static const u8 pages[] = {
		0x0,	/* this page */
		0x1,
		0x2,
		0x7,
		0xa,
	};

	rbuf[1] = 0x0;	/* this page */
	rbuf[3] = sizeof(pages);
	memcpy(rbuf + 4, pages, sizeof(pages));
	return 0;
}

static unsigned int ahciem_sesop_rxdx_1(struct ahciem_args *args, u8 *rbuf)
{
	rbuf[1] = 0x1;	/* this page */
	/* TODO */
	return 1;
}

static unsigned int ahciem_sesop_rxdx_2(struct ahciem_args *args, u8 *rbuf)
{
	rbuf[1] = 0x2;	/* this page */
	/* TODO */
	return 1;
}

static unsigned int ahciem_sesop_rxdx_7(struct ahciem_args *args, u8 *rbuf)
{
	rbuf[1] = 0x7;	/* this page */
	/* TODO */
	return 1;
}

static unsigned int ahciem_sesop_rxdx_a(struct ahciem_args *args, u8 *rbuf)
{
	rbuf[1] = 0xa;	/* this page */
	/* TODO */
	return 1;
}

static void __ahciem_queuecmd(struct scsi_cmnd *cmd, struct ata_device *dev)
{
	struct ahciem_args args = { .cmd = cmd, .dev = dev };
	const u8 *cdb = cmd->cmnd;
	/* TODO: struct ahciem_enc *enc = ???; */

	//BUG_ON(dev->class != ATA_DEV_SEMB); TODO: what class are we?

	/*
	 * Commands required for SES devices by SPC:
	 *  - INQUIRY
	 *  - REPORT LUNS
	 *  - REQUEST SENSE
	 *  - TEST UNIT READY
	 *  - SEND DIAGNOSTIC
	 *  - RECEIVE DIAGNOSTIC RESULTS
	 */
	switch (cdb[0]) {
	case INQUIRY:
		if (cdb[1] & 2)			/* obsolete CMDDT set? */
			ata_scsi_set_invalid_field(dev, cmd, 1, 1);
		else if ((cdb[1] & 1) == 0) {	/* standard INQUIRY */
			if (cdb[2] != 0)
				ata_scsi_set_invalid_field(dev, cmd, 2, 0xff);
			else
				ahciem_rbuf_fill(&args, ahciem_scsiop_inq_std);
		} else switch (cdb[2]) {	/* VPD INQUIRY */
		case 0x00:	/* Supported VPD Pages */
			ahciem_rbuf_fill(&args, ahciem_scsiop_inq_00);
			break;
		case 0x83:	/* Device Identification */
			ahciem_rbuf_fill(&args, ahciem_scsiop_inq_83);
			break;
		/* TODO: optional/protocol specific pages? */
		default:
			ata_scsi_set_invalid_field(dev, cmd, 2, 0xff);
			break;
		}
		break;

	case REPORT_LUNS:
		ahciem_rbuf_fill(&args, ahciem_scsiop_report_luns);
		break;

	case REQUEST_SENSE:
		ata_scsi_set_sense(dev, cmd, 0, 0, 0);
		break;

	case TEST_UNIT_READY:
		/* born ready */
		break;

	case SEND_DIAGNOSTIC:
		switch (cdb[2]) {
		case 0x2:	/* Enclosure Control */
			/* XXX: are these the same?
			 * scsi_bufflen(cmd) vs (((u16)cdb[3] << 8) + cdb[4])
			 */
			if (scsi_bufflen(cmd) < (3 + enc->channels)) {
				ata_scsi_set_invalid_field(dev, cmd, 3, 0);
				break;
			}
			/* TODO: decode sent data and store in enc */
			break;
		default:
			ata_scsi_set_invalid_field(dev, cmd, 2, 0);
			break;
		}
		break;

	case RECEIVE_DIAGNOSTIC: {
		unsigned int (*action)(struct ahciem_args *args, u8 *rbuf) = NULL;
		unsigned minlen = 0;

		switch (cdb[2]) {
		case 0x0:	/* Supported Diagnostic Pages */
			minlen = 3;
			action = ahciem_sesop_rxdx_0;
			break;
		case 0x1:	/* Configuration */
			minlen = 16;
			action = ahciem_sesop_rxdx_1;
			break;
		case 0x2:	/* Enclosure Status */
			minlen = 3 + enc->channels;
			action = ahciem_sesop_rxdx_2;
			break;
		case 0x7:	/* Element Descriptor */
			minlen = 6 + 3 * enc->channels;
			action = ahciem_sesop_rxdx_7;
			break;
		case 0xa:	/* Additional Element Status */
			minlen = 2 + 3 * enc->channels;
			action = ahciem_sesop_rxdx_a;
			break;
		default:
			ata_scsi_set_invalid_field(dev, cmd, 2, 0);
			break;
		}
		if (action != NULL) {
			/* XXX: are these the same?
			 * scsi_bufflen(cmd) vs (((u16)cdb[3] << 8) + cdb[4])
			 */
			if (scsi_bufflen(cmd) < minlen)
				ata_scsi_set_invalid_field(dev, cmd, 3, 0);
			else
				ahciem_rbuf_fill(&args, action);
		}
		break;
	}
	default:
		ata_scsi_set_sense(dev, cmd, ILLEGAL_REQUEST, 0x20, 0x0);
		break;
	}
	cmd->scsi_done(cmd);
}

static int ahciem_queuecmd(struct Scsi_Host *shost, struct scsi_cmnd *cmd)
{
	struct ata_port *ap;
	struct ata_device *dev;
	struct scsi_device *scsidev = cmd->device;
	unsigned long irq_flags;

	ap = ata_shost_to_port(shost);

	spin_lock_irqsave(ap->lock, irq_flags);

	ata_scsi_dump_cdb(ap, cmd);

	dev = ata_scsi_find_dev(ap, scsidev);
	if (likely(dev))
		__ahciem_queuecmd(cmd, dev);
	else {
		cmd->result = (DID_BAD_TARGET << 16);
		cmd->scsi_done(cmd);
	}

	spin_unlock_irqrestore(ap->lock, irq_flags);

	return 0;
}

/* TODO: probe, init, fini... */
