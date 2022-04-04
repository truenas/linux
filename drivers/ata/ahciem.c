/*-
 * SPDX-License-Indentifier: (GPL-2.0-only OR BSD-2-Clause-FreeBSD)
 *
 * Emulated SCSI Enclosure Services for AHCI Enclosure Management
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
#include <linux/pci.h>
#include <linux/libata.h>
#include <linux/enclosure.h>
#include <linux/unaligned.h>

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_proto.h>
#include <target/target_core_base.h>

#include "ahci.h"

#define DRV_NAME	"ahciem"
#define DRV_VERSION	"0.1"

#define AHCIEM_RBUF_SIZE	576	/* size from libata-scsi.c */

static DEFINE_SPINLOCK(ahciem_rbuf_lock);
static u8 ahciem_rbuf[AHCIEM_RBUF_SIZE];

struct ahciem_enclosure {
	struct ata_host *host;
	u8 status[AHCI_MAX_PORTS][4];
};

struct ahciem_args {
	struct scsi_cmnd *cmd;
	struct ahciem_enclosure *enc;
};

/*
 * Utility functions
 */

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

static void ahciem_scsi_set_sense(struct scsi_cmnd *cmd,
				  u8 sk, u8 asc, u8 ascq)
{
	scsi_build_sense(cmd, false, sk, asc, ascq);
}

static void ahciem_scsi_set_invalid_field(struct scsi_cmnd *cmd,
					  u16 field, u8 bit, bool cd)
{
	ahciem_scsi_set_sense(cmd, ILLEGAL_REQUEST, 0x24, 0x0);
	scsi_set_sense_field_pointer(cmd->sense_buffer, SCSI_SENSE_BUFFERSIZE,
				     field, bit, cd);
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
		0x40,	/* enclosure services provided */
		0x2,	/* claim SAM-5 command management compatibility */
	};
	static const u8 versions[] = {
		0x00, 0xA0,	/* SAM-5 (no version claimed) */
		0x06, 0x80,	/* SES-4 (no version claimed) */
		0x05, 0xC0,	/* SPC-5 (no version claimed) */
	};

	memcpy(rbuf, hdr, sizeof(hdr));
	memcpy(rbuf + 8, "AHCI    ", INQUIRY_VENDOR_LEN);
	memcpy(rbuf + 16, "SGPIO Enclosure ", INQUIRY_MODEL_LEN);
	memcpy(rbuf + 32, "2.00", INQUIRY_REVISION_LEN);
	memcpy(rbuf + 58, versions, sizeof(versions));
	return 0;
}

static unsigned int ahciem_scsiop_inq_00(struct ahciem_args *args, u8 *rbuf)
{
	static const u8 pages[] = {
		0x00,	/* this page */
		0x83,	/* device ident page */
	};

	rbuf[0] = TYPE_ENCLOSURE;	/* peripheral device type */
	rbuf[1] = 0x00;	/* this page */
	put_unaligned_be16(sizeof(pages), rbuf + 2);

	memcpy(rbuf + 4, pages, sizeof(pages));

	return 0;
}

static unsigned int ahciem_scsiop_inq_83(struct ahciem_args *args, u8 *rbuf)
{
	u8 *p = rbuf;

	p[0] = TYPE_ENCLOSURE;	/* peripheral device type */
	p[1] = 0x83;	/* this page */
	/* length calculated at the end */
	p += 4;

	p[0] = 1;	/* code_set=binary */
	p[1] = 3;	/* piv=0, assoc=lu, designator=NAA */
	p[3] = 8;	/* NAA Locally Assigned designator length */
	p += 4;
	p[0] = 0x30;	/* NAA Locally Assigned */
	put_unaligned_be32(args->cmd->device->host->unique_id, p + 4);
	p += 8;

	put_unaligned_be16(p - rbuf - 4, rbuf + 2);	/* page length - 4 */

	return 0;
}

static unsigned int ahciem_scsiop_report_luns(struct ahciem_args *args, u8 *rbuf)
{
	put_unaligned_be32(8, rbuf);	/* one lun, 8 bytes */
	memset(rbuf + 8, 0, 8);
	return 0;
}

/*
 * SES operations
 */

static unsigned int ahciem_sesop_rxdx_0(struct ahciem_args *args, u8 *rbuf)
{
	static const u8 pages[] = {
		0x0,	/* this page */
		0x1,
		0x2,
		0x7,
		0xa,
	};

	rbuf[0] = 0x0;	/* this page */
	put_unaligned_be16(sizeof(pages), rbuf + 2);
	memcpy(rbuf + 4, pages, sizeof(pages));
	return 0;
}

static unsigned int ahciem_sesop_rxdx_1(struct ahciem_args *args, u8 *rbuf)
{
	static const u8 enc_desc[] = {
		0x11,	/* pid=1, #pid=1 */
		0,	/* subenclosure id */
		1,	/* # of type descriptor headers */
		36,	/* descriptor length - 4 */
	};
	static const char *desc_txt = "Drive Slots";
	static const int desc_txt_len = sizeof("Drive Slots") - 1;
	const u8 type_desc[] = {
		ENCLOSURE_COMPONENT_ARRAY_DEVICE,	/* element type */
		args->enc->host->n_ports,	/* max number of elements */
		0,		/* subenclosure id */
		desc_txt_len,	/* type descriptor text length */
	};
	u8 *p = rbuf;

	p[0] = 0x1;	/* this page */
	p[1] = 0;	/* number of secondary subenclosures */
	/* length calculated at the end */
	/* generation code fixed zeros */
	p += 8;

	/* enclosure logical identifier */
	memcpy(p, enc_desc, sizeof(enc_desc));
	p += sizeof(enc_desc);
	p[0] = 0x30;	/* NAA Locally Assigned */
	put_unaligned_be32(args->cmd->device->host->unique_id, p + 4);
	p += 8;

	/* enclosure vendor identification */
	memcpy(p, "AHCI    ", INQUIRY_VENDOR_LEN);
	p += INQUIRY_VENDOR_LEN;

	/* product identification */
	memcpy(p, "SGPIO Enclosure ", INQUIRY_MODEL_LEN);
	p += INQUIRY_MODEL_LEN;

	/* product revision level */
	memcpy(p, "2.00", INQUIRY_REVISION_LEN);
	p += INQUIRY_REVISION_LEN;

	/* type descriptor header list */
	memcpy(p, type_desc, sizeof(type_desc));
	p += sizeof(type_desc);

	/* type descriptor text list */
	memcpy(p, desc_txt, desc_txt_len);
	p += desc_txt_len;

	/* page length - 4 */
	put_unaligned_be16(p - rbuf - 4, rbuf + 2);

	return 0;
}

static unsigned int ahciem_sesop_rxdx_2(struct ahciem_args *args, u8 *rbuf)
{
	struct ata_host *host = args->enc->host;
	int n_ports = host->n_ports;
	int i;

	rbuf[0] = 0x2;	/* this page */
	rbuf[1] = 0;	/* invop=0, info=0, non-crit=0, crit=0, unrecov=0 */
	put_unaligned_be16(4 + 4 * (1 + n_ports), rbuf + 2); /* gencode + elems */
	/* generation code fixed zeros */

	for (i = 0; i < n_ports; i++) {
		struct ata_port *ap;
		struct ata_link *link;
		int offset = 4 + 4 + 4 * (1 + i); /* pghdr + gencode + elems */
		u8 status;

		/* XXX: potentially out of sync with emp->led_state */
		memcpy(rbuf + offset, args->enc->status[i], 4);

		ap = host->ports[i];
		link = &ap->link;
		if (sata_pmp_attached(ap))
			status = ENCLOSURE_STATUS_UNKNOWN;
		else if (ata_link_online(link))
			status = ENCLOSURE_STATUS_OK;
		else if (ata_link_offline(link))
			status = ENCLOSURE_STATUS_NOT_INSTALLED;
		else
			status = ENCLOSURE_STATUS_UNKNOWN;
		rbuf[offset] |= status;

		if (ata_dev_disabled(link->device))
			rbuf[offset + 3] |= 0x10; /* DEVICE OFF */
	}

	return 0;
}

static unsigned int ahciem_sesop_rxdx_7(struct ahciem_args *args, u8 *rbuf)
{
	int n_ports = args->enc->host->n_ports;
	int i;

	rbuf[0] = 0x7;	/* this page */
	put_unaligned_be16(4 + 15 + 11 * n_ports, rbuf + 2); /* gencode + "Drive Slots" + slots */
	/* generation code fixed zeros */

	/* overall descriptor */
	put_unaligned_be16(11, rbuf + 10);
	memcpy(rbuf + 12, "Drive Slots", 11);

	for (i = 0; i < n_ports; i++) {
		int offset = 4 + 4 + 15 + 11 * i; /* pghdr + gencode + "Drive Slots" + slots */

		/* element descriptor */
		put_unaligned_be16(7, rbuf + offset + 2);
		snprintf(rbuf + offset + 4, 8, "Slot %02d", i);
	}

	return 0;
}

static unsigned int ahciem_sesop_rxdx_a(struct ahciem_args *args, u8 *rbuf)
{
	struct ata_host *host = args->enc->host;
	int n_ports = host->n_ports;
	int i;

	rbuf[0] = 0xa;	/* this page */
	put_unaligned_be16(4 + (4 + 8) * n_ports, rbuf + 2); /* gencode + elements */
	/* generation code fixed zeros */

	for (i = 0; i < n_ports; i++) {
		struct ata_port *ap;
		int offset = 4 + 4 + (4 + 8) * i; /* pghdr + gencode + slots */

		/* Additional Element Status Descriptor */
		rbuf[offset] = 0x10 | SCSI_PROTOCOL_ATA;	/* eip=1, proto=ATA */
		rbuf[offset + 1] = 2 + 8;	/* length: index + ata elm */
		rbuf[offset + 2] = 0x01;	/* eiioe */
		rbuf[offset + 3] = 1 + i;	/* index */

		ap = host->ports[i];
		if (sata_pmp_attached(ap))
			rbuf[offset] |= 0x80;	/* invalid */

		/* ATA Element Status (NB: non-standard) */
		put_unaligned_be32(i, rbuf + offset + 4);
		put_unaligned_be32(ap->scsi_host->host_no, rbuf + offset + 8);
	}

	return 0;
}

static void ahciem_setleds(struct ahciem_enclosure *enc, int slot)
{
	struct ata_port *ap = enc->host->ports[slot];
	u32 port_led_state, val;

	if (!ap->ops->transmit_led_message)
		return;

	val = 0;
	if (enc->status[slot][2] & 0x80)		/* Activity */
		val |= (1 << 0);
	if (enc->status[slot][1] & 0x02)		/* Rebuild */
		val |= (1 << 6) | (1 << 3);
	else if (enc->status[slot][2] & 0x02)		/* Identification */
		val |= (1 << 3);
	else if (enc->status[slot][3] & 0x20)		/* Fault */
		val |= (1 << 6);

	port_led_state = (val << 16) | (slot & EM_MSG_LED_HBA_PORT);

	ap->ops->transmit_led_message(ap, port_led_state, 4);
}

static void ahciem_sesop_txdx(struct ahciem_enclosure *enc, struct scsi_cmnd *cmd)
{
	const u8 *ads0;
	u8 *page;
	u16 page_len = get_unaligned_be16(cmd->cmnd + 3);
	int n_ports = enc->host->n_ports;
	int i;

	page = kzalloc(page_len, GFP_KERNEL);
	if (!page) {
		ahciem_scsi_set_sense(cmd, ABORTED_COMMAND, 0x34, 0x0);
		return;
	}

	if (scsi_sg_copy_to_buffer(cmd, page, page_len) != page_len) {
		kfree(page);
		ahciem_scsi_set_sense(cmd, ABORTED_COMMAND, 0x34, 0x0);
		return;
	}

	if (page[0] != 0x02) {	/* Enclosure Control page */
		kfree(page);
		ahciem_scsi_set_invalid_field(cmd, 0, 0, false);
		return;
	}

	ads0 = page + 8;

	for (i = 0; i < n_ports; i++) {
		const u8 *ads = ads0 + 4 + 4 * i; /* start + overall elem + elems */

		if (ads[0] & 0x80) {
			enc->status[i][0] = 0;
			enc->status[i][1] = ads[1] & 0x02;		/* rebuild/remap */
			enc->status[i][2] = ads[2] & (0x80 | 0x02);	/* rqst active + rqst ident */
			enc->status[i][3] = ads[3] & 0x20;		/* rqst fault */
			ahciem_setleds(enc, i);
		} else if (ads0[0] & 0x80) {
			enc->status[i][0] = 0;
			enc->status[i][1] = ads0[1] & 0x02;		/* rebuild/remap */
			enc->status[i][2] = ads0[2] & (0x80 | 0x02);	/* rqst active + rqst ident */
			enc->status[i][3] = ads0[3] & 0x20;		/* rqst fault */
			ahciem_setleds(enc, i);
		}
	}

	kfree(page);
}

static int ahciem_queuecommand(struct Scsi_Host *shost, struct scsi_cmnd *cmd)
{
	struct ahciem_enclosure *enc = (struct ahciem_enclosure *)&shost->hostdata[0];
	struct ahciem_args args = { .cmd = cmd, .enc = enc };
	const u8 *cdb = cmd->cmnd;

	if (unlikely(!cmd->cmd_len)) {
		cmd->result = DID_ERROR << 16;
		scsi_done(cmd);
		return 0;
	}

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
			ahciem_scsi_set_invalid_field(cmd, 1, 1, true);
		else if ((cdb[1] & 1) == 0) {	/* standard INQUIRY */
			if (cdb[2] != 0)
				ahciem_scsi_set_invalid_field(cmd, 2, 0xff, true);
			else
				ahciem_rbuf_fill(&args, ahciem_scsiop_inq_std);
		} else switch (cdb[2]) {	/* VPD INQUIRY */
		case 0x00:	/* Supported VPD Pages */
			ahciem_rbuf_fill(&args, ahciem_scsiop_inq_00);
			break;
		case 0x83:	/* Device Identification */
			ahciem_rbuf_fill(&args, ahciem_scsiop_inq_83);
			break;
		default:
			ahciem_scsi_set_invalid_field(cmd, 2, 0xff, true);
			break;
		}
		break;

	case REPORT_LUNS:
		ahciem_rbuf_fill(&args, ahciem_scsiop_report_luns);
		break;

	case REQUEST_SENSE:
		ahciem_scsi_set_sense(cmd, 0, 0, 0);
		break;

	case TEST_UNIT_READY:
		/* born ready */
		break;

	case SEND_DIAGNOSTIC:
		if (cdb[1] & 0x10)	/* PF (page format) */
			ahciem_sesop_txdx(enc, cmd);
		else
			ahciem_scsi_set_invalid_field(cmd, 1, 4, true);
		break;

	case RECEIVE_DIAGNOSTIC:
		switch (cdb[2]) {
		case 0x0:	/* Supported Diagnostic Pages */
			ahciem_rbuf_fill(&args, ahciem_sesop_rxdx_0);
			break;
		case 0x1:	/* Configuration */
			ahciem_rbuf_fill(&args, ahciem_sesop_rxdx_1);
			break;
		case 0x2:	/* Enclosure Status */
			ahciem_rbuf_fill(&args, ahciem_sesop_rxdx_2);
			break;
		case 0x7:	/* Element Descriptor */
			ahciem_rbuf_fill(&args, ahciem_sesop_rxdx_7);
			break;
		case 0xa:	/* Additional Element Status */
			ahciem_rbuf_fill(&args, ahciem_sesop_rxdx_a);
			break;
		default:
			ahciem_scsi_set_invalid_field(cmd, 2, 0, true);
			break;
		}
		break;

	default:
		ahciem_scsi_set_sense(cmd, ILLEGAL_REQUEST, 0x20, 0x0);
		break;
	}

	scsi_done(cmd);

	return 0;
}

static struct scsi_host_template ahciem_sht = {
	.name = DRV_NAME,
	.proc_name = DRV_NAME,
	.queuecommand = ahciem_queuecommand,
	.sg_tablesize = SG_ALL,
};

bool scsi_is_ahciem(struct scsi_device *sdev)
{
	return sdev->host->hostt == &ahciem_sht;
}
EXPORT_SYMBOL(scsi_is_ahciem);

static atomic_t ahciem_unique_id = ATOMIC_INIT(0);

int ahciem_host_activate(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;
	struct Scsi_Host *shost;
	struct ahciem_enclosure *enc;
	int rc;

	shost = scsi_host_alloc(&ahciem_sht, sizeof(struct ahciem_enclosure));
	if (!shost)
		return -ENOMEM;

	enc = (struct ahciem_enclosure *)&shost->hostdata[0];
	enc->host = host;
	hpriv->em_shost = shost;
	shost->can_queue = 1;
	shost->eh_noresume = 1;
	shost->max_channel = 1;
	shost->max_cmd_len = MAX_COMMAND_SIZE;
	shost->max_host_blocked = 1;
	shost->max_id = 1;
	shost->max_lun = 1;
	shost->unique_id = atomic_inc_return(&ahciem_unique_id);
	rc = scsi_add_host(shost, host->dev);
	if (rc)
		return rc;

	return scsi_add_device(shost, 0, 0, 0);
}
EXPORT_SYMBOL(ahciem_host_activate);

MODULE_LICENSE("Dual BSD/GPL");
