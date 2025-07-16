/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/string_helpers.h>
#include <linux/sort.h>

#include "common.h"
#include "t4_regs.h"
#include "t4fw_interface.h"
#include "t4_linux_fs.h"

/*
 * debugfs support
 */

/*
 * generic seq_file support for showing a table of size rows x width.
 */

static void *seq_tab_get_idx(struct seq_tab *tb, loff_t pos)
{
	pos -= tb->skip_first;
	return pos >= tb->rows ? NULL : &tb->data[pos * tb->width];
}

static void *seq_tab_start(struct seq_file *seq, loff_t *pos)
{
	struct seq_tab *tb = seq->private;

	if (tb->skip_first && *pos == 0)
		return SEQ_START_TOKEN;

	return seq_tab_get_idx(tb, *pos);
}

static void *seq_tab_next(struct seq_file *seq, void *v, loff_t *pos)
{
	v = seq_tab_get_idx(seq->private, *pos + 1);
	++*pos;
	return v;
}

static void seq_tab_stop(struct seq_file *seq, void *v)
{
}

static int seq_tab_show(struct seq_file *seq, void *v)
{
	const struct seq_tab *tb = seq->private;

	/*
	 * index is bogus when v isn't within data, eg when it's
	 * SEQ_START_TOKEN, but that's OK
	 */
	return tb->show(seq, v, ((char *)v - tb->data) / tb->width);
}

static const struct seq_operations seq_tab_ops = {
	.start = seq_tab_start,
	.next  = seq_tab_next,
	.stop  = seq_tab_stop,
	.show  = seq_tab_show
};

struct seq_tab *seq_open_tab(struct file *f, unsigned int rows,
			     unsigned int width, unsigned int have_header,
			     int (*show)(struct seq_file *seq, void *v, int i))
{
	struct seq_tab *p;

	p = __seq_open_private(f, &seq_tab_ops, sizeof(*p) + rows * width);
	if (p) {
		p->show = show;
		p->rows = rows;
		p->width = width;
		p->skip_first = have_header != 0;
	}
	return p;
}

/*
 * Trim the size of a seq_tab to the supplied number of rows.  The opration is
 * irreversible.
 */
static int seq_tab_trim(struct seq_tab *p, unsigned int new_rows)
{
	if (new_rows > p->rows)
		return -EINVAL;
	p->rows = new_rows;
	return 0;
}

static int cim_la_show(struct seq_file *seq, void *v, int idx)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Status   Data      PC     LS0Stat  LS0Addr "
			 "            LS0Data\n");
	else {
		const u32 *p = v;

		seq_printf(seq,
			"  %02x   %x%07x %x%07x %08x %08x %08x%08x%08x%08x\n",
			(p[0] >> 4) & 0xff, p[0] & 0xf, p[1] >> 4, p[1] & 0xf,
			p[2] >> 4, p[2] & 0xf, p[3], p[4], p[5], p[6], p[7]);
	}
	return 0;
}

static int cim_la_show_3in1(struct seq_file *seq, void *v, int idx)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Status   Data      PC\n");
	else {
		const u32 *p = v;

		seq_printf(seq, "  %02x   %08x %08x\n", p[5] & 0xff, p[6],
			   p[7]);
		seq_printf(seq, "  %02x   %02x%06x %02x%06x\n",
			   (p[3] >> 8) & 0xff, p[3] & 0xff, p[4] >> 8,
			   p[4] & 0xff, p[5] >> 8);
		seq_printf(seq, "  %02x   %x%07x %x%07x\n", (p[0] >> 4) & 0xff,
			   p[0] & 0xf, p[1] >> 4, p[1] & 0xf, p[2] >> 4);
	}
	return 0;
}

static int cim_la_show_t6(struct seq_file *seq, void *v, int idx)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Status   Inst    Data      PC     LS0Stat  "
			 "LS0Addr  LS0Data  LS1Stat  LS1Addr  LS1Data\n");
	else {
		const u32 *p = v;

		seq_printf(seq, "  %02x   %04x%04x %04x%04x %04x%04x %08x %08x %08x %08x %08x %08x\n",
			   (p[9] >> 16) & 0xff,        /* Status */
			    p[9] & 0xffff, p[8] >> 16, /* Inst */
			    p[8] & 0xffff, p[7] >> 16, /* Data */
			    p[7] & 0xffff, p[6] >> 16, /* PC */
			    p[2], p[1], p[0],          /* LS0 Stat, Addr and Data */
			    p[5], p[4], p[3]);         /* LS1 Stat, Addr and Data */
	}
	return 0;
}

static int cim_la_show_pc_t6(struct seq_file *seq, void *v, int idx)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Status   Inst    Data      PC\n");
	else {
		const u32 *p = v;

		seq_printf(seq, "  %02x   %08x %08x %08x\n", p[3] & 0xff, p[2],
			   p[1], p[0]);
		seq_printf(seq, "  %02x   %02x%06x %02x%06x %02x%06x\n",
			   (p[6] >> 8) & 0xff, p[6] & 0xff, p[5] >> 8,
			   p[5] & 0xff, p[4] >> 8, p[4] & 0xff, p[3] >> 8);
		seq_printf(seq, "  %02x   %04x%04x %04x%04x %04x%04x\n",
			   (p[9] >> 16) & 0xff, p[9] & 0xffff, p[8] >> 16,
			   p[8] & 0xffff, p[7] >> 16, p[7] & 0xffff,
			   p[6] >> 16);
	}
	return 0;
}

static int cim_la_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	u8 coreid = d->coreid;
	struct seq_tab *p;
	unsigned int cfg;
	int ret;

	ret = t4_cim_read_core(adap, 1, coreid, A_UP_UP_DBG_LA_CFG, 1, &cfg);
	if (ret)
		return ret;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T6) {
		p = seq_open_tab(file, adap->params.cim_la_size / 10,
				 10 * sizeof(u32), 1,
				 cfg & F_UPDBGLACAPTPCONLY ?
				 cim_la_show_pc_t6 : cim_la_show_t6);
	} else {
		p = seq_open_tab(file, adap->params.cim_la_size / 8,
				 8 * sizeof(u32), 1,
				 cfg & F_UPDBGLACAPTPCONLY ?
				 cim_la_show_3in1 : cim_la_show);
	}
	if (!p)
		return -ENOMEM;

	ret = t4_cim_read_la_core(adap, coreid, (u32 *)p->data, NULL);
	if (ret)
		seq_release_private(inode, file);
	return ret;
}

static const struct file_operations cim_la_fops = {
	.owner   = THIS_MODULE,
	.open    = cim_la_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

static int cim_pif_la_show(struct seq_file *seq, void *v, int idx)
{
	const u32 *p = v;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Cntl ID DataBE   Addr                 Data\n");
	else if (idx < CIM_PIFLA_SIZE)
		seq_printf(seq, " %02x  %02x  %04x  %08x %08x%08x%08x%08x\n",
			   (p[5] >> 22) & 0xff, (p[5] >> 16) & 0x3f,
			   p[5] & 0xffff, p[4], p[3], p[2], p[1], p[0]);
	else {
		if (idx == CIM_PIFLA_SIZE)
			seq_puts(seq, "\nCntl ID               Data\n");
		seq_printf(seq, " %02x  %02x %08x%08x%08x%08x\n",
			   (p[4] >> 6) & 0xff, p[4] & 0x3f,
			   p[3], p[2], p[1], p[0]);
	}
	return 0;
}

static int cim_pif_la_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct seq_tab *p;

	p = seq_open_tab(file, 2 * CIM_PIFLA_SIZE, 6 * sizeof(u32), 1,
			 cim_pif_la_show);
	if (!p)
		return -ENOMEM;

	t4_cim_read_pif_la(adap, (u32 *)p->data,
			   (u32 *)p->data + 6 * CIM_PIFLA_SIZE, NULL, NULL);
	return 0;
}

static const struct file_operations cim_pif_la_fops = {
	.owner   = THIS_MODULE,
	.open    = cim_pif_la_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

static int cim_ma_la_show(struct seq_file *seq, void *v, int idx)
{
	const u32 *p = v;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "\n");
	else if (idx < CIM_MALA_SIZE)
		seq_printf(seq, "%02x%08x%08x%08x%08x\n",
			   p[4], p[3], p[2], p[1], p[0]);
	else {
		if (idx == CIM_MALA_SIZE)
			seq_puts(seq,
				 "\nCnt ID Tag UE       Data       RDY VLD\n");
		seq_printf(seq, "%3u %2u  %x   %u %08x%08x  %u   %u\n",
			   (p[2] >> 10) & 0xff, (p[2] >> 7) & 7,
			   (p[2] >> 3) & 0xf, (p[2] >> 2) & 1,
			   (p[1] >> 2) | ((p[2] & 3) << 30),
			   (p[0] >> 2) | ((p[1] & 3) << 30), (p[0] >> 1) & 1,
			   p[0] & 1);
	}
	return 0;
}

static int cim_ma_la_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct seq_tab *p;

	p = seq_open_tab(file, 2 * CIM_MALA_SIZE, 5 * sizeof(u32), 1,
			 cim_ma_la_show);
	if (!p)
		return -ENOMEM;

	t4_cim_read_ma_la(adap, (u32 *)p->data,
			  (u32 *)p->data + 5 * CIM_MALA_SIZE);
	return 0;
}

static const struct file_operations cim_ma_la_fops = {
	.owner   = THIS_MODULE,
	.open    = cim_ma_la_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

static int cim_qcfg_show_t4(struct seq_file *seq, struct adapter *adap)
{
	static const char * const qname_t4[] = {
		/* IBQ */
		"TP0", "TP1", "ULP", "SGE0", "SGE1", "NC-SI",
		/* OBQ */
		"ULP0", "ULP1", "ULP2", "ULP3", "SGE", "NC-SI",
	};
	u32 stat[(4 * (CIM_NUM_IBQ + CIM_NUM_OBQ))];
	u16 base[CIM_NUM_IBQ + CIM_NUM_OBQ];
	u16 size[CIM_NUM_IBQ + CIM_NUM_OBQ];
	u32 obq_wr[2 * CIM_NUM_OBQ];
	u16 thres[CIM_NUM_IBQ];
	u32 *wr = obq_wr;
	u32 *p = stat;
	int ret;
	u8 i;

	ret = t4_cim_read(adap, A_UP_IBQ_0_RDADDR, ARRAY_SIZE(stat), stat);
	if (ret < 0)
		return ret;

	ret = t4_cim_read(adap, A_UP_OBQ_0_REALADDR, ARRAY_SIZE(obq_wr),
			  obq_wr);
	if (ret < 0)
		return ret;

	t4_read_cimq_cfg(adap, base, size, thres);

	seq_printf(seq,
		   "  Queue  Base  Size Thres  RdPtr WrPtr  SOP  EOP Avail\n");

	for (i = 0; i < CIM_NUM_IBQ; i++, p += 4) {
		if (!size[i])
			continue;

		seq_printf(seq, "%7s %5x %5u %5u %6x  %4x %4u %4u %5u\n",
			   qname_t4[i], base[i], size[i], thres[i],
			   G_IBQRDADDR(p[0]), G_IBQWRADDR(p[1]),
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_QUEREMFLITS(p[2]) * 16);
	}

	for ( ; i < CIM_NUM_IBQ + CIM_NUM_OBQ; i++, p += 4, wr += 2) {
		if (!size[i])
			continue;

		seq_printf(seq, "%7s %5x %5u %12x  %4x %4u %4u %5u\n",
			   qname_t4[i], base[i], size[i],
			   G_QUERDADDR(p[0]) & 0x3fff, wr[0] - base[i],
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_QUEREMFLITS(p[2]) * 16);
	}

	return 0;
}

static int cim_qcfg_show_t5(struct seq_file *seq, struct adapter *adap)
{
	static const char * const qname_t5[] = {
		/* IBQ */
		"TP0", "TP1", "ULP", "SGE0", "SGE1", "NC-SI",
		/* OBQ */
		"ULP0", "ULP1", "ULP2", "ULP3", "SGE", "NC-SI",
		"SGE0-RX", "SGE1-RX"
	};
	u32 stat[(4 * (CIM_NUM_IBQ + CIM_NUM_OBQ_T5))];
	u16 base[CIM_NUM_IBQ + CIM_NUM_OBQ_T5];
	u16 size[CIM_NUM_IBQ + CIM_NUM_OBQ_T5];
	u32 obq_wr[2 * CIM_NUM_OBQ_T5];
	u16 thres[CIM_NUM_IBQ];
	u32 *wr = obq_wr;
	u32 *p = stat;
	int ret;
	u8 i;

	ret = t4_cim_read(adap, A_UP_IBQ_0_SHADOW_RDADDR, ARRAY_SIZE(stat),
			  stat);
	if (ret < 0)
		return ret;

	ret = t4_cim_read(adap, A_UP_OBQ_0_SHADOW_REALADDR, ARRAY_SIZE(obq_wr),
			  obq_wr);
	if (ret < 0)
		return ret;

	t4_read_cimq_cfg(adap, base, size, thres);

	seq_printf(seq,
		   "  Queue  Base  Size Thres  RdPtr WrPtr  SOP  EOP Avail\n");

	for (i = 0; i < CIM_NUM_IBQ; i++, p += 4) {
		if (!size[i])
			continue;

		seq_printf(seq, "%7s %5x %5u %5u %6x  %4x %4u %4u %5u\n",
			   qname_t5[i], base[i], size[i], thres[i],
			   G_IBQRDADDR(p[0]), G_IBQWRADDR(p[1]),
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_QUEREMFLITS(p[2]) * 16);
	}

	for ( ; i < CIM_NUM_IBQ + CIM_NUM_OBQ_T5; i++, p += 4, wr += 2) {
		if (!size[i])
			continue;

		seq_printf(seq, "%7s %5x %5u %12x  %4x %4u %4u %5u\n",
			   qname_t5[i], base[i], size[i],
			   G_QUERDADDR(p[0]) & 0x3fff, wr[0] - base[i],
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_QUEREMFLITS(p[2]) * 16);
	}

	return 0;
}

static int cim_qcfg_show_t7(struct seq_file *seq, struct adapter *adap,
			    u8 coreid)
{
	static const char * const qname_t7[] = {
		/* IBQ */
		"TP0", "TP1", "TP2", "TP3", "ULP", "SGE0", "SGE1", "NC-SI",
		"RSVD", "IPC1", "IPC2", "IPC3", "IPC4", "IPC5", "IPC6", "IPC7",
		/* OBQ */
		"ULP0", "ULP1", "ULP2", "ULP3", "SGE", "NC-SI", "SGE0-RX",
		"RSVD", "RSVD", "IPC1", "IPC2", "IPC3", "IPC4", "IPC5", "IPC6",
		"IPC7",
	};
	u32 stat[(4 * (CIM_NUM_IBQ_T7 + CIM_NUM_OBQ_T7))];
	u16 base[CIM_NUM_IBQ_T7 + CIM_NUM_OBQ_T7];
	u16 size[CIM_NUM_IBQ_T7 + CIM_NUM_OBQ_T7];
	u32 obq_wr[2 * CIM_NUM_OBQ_T7];
	u16 thres[CIM_NUM_IBQ_T7];
	u32 *wr = obq_wr;
	u32 *p = stat;
	u32 addr;
	int ret;
	u8 i;

	ret = t4_cim_read_core(adap, 1, coreid, A_T7_UP_IBQ_0_SHADOW_RDADDR,
			       4 * CIM_NUM_IBQ_T7, stat);
	if (ret < 0)
		return ret;

	ret = t4_cim_read_core(adap, 1, coreid, A_T7_UP_OBQ_0_SHADOW_RDADDR,
			       4 * CIM_NUM_OBQ_T7, &stat[4 * CIM_NUM_IBQ_T7]);
	if (ret < 0)
		return ret;

	addr = A_T7_UP_OBQ_0_SHADOW_REALADDR;
	for (i = 0; i < CIM_NUM_OBQ_T7 * 2; i++, addr += 8) {
		ret = t4_cim_read_core(adap, 1, coreid, addr, 1, &obq_wr[i]);
		if (ret < 0)
			return ret;
	}

	t4_read_cimq_cfg_core(adap, coreid, base, size, thres);

	seq_printf(seq,
		   "  Queue  Base  Size Thres  RdPtr WrPtr  SOP  EOP Avail\n");

	for (i = 0; i < CIM_NUM_IBQ_T7; i++, p += 4) {
		if (!size[i])
			continue;

		seq_printf(seq, "%7s %5x %5u %5u %6x  %4x %4u %4u %5u\n",
			   qname_t7[i], base[i], size[i], thres[i],
			   G_IBQRDADDR(p[0]) & 0xfff, G_IBQWRADDR(p[1]) & 0xfff,
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_T7_QUEREMFLITS(p[2]) * 16);
	}

	for ( ; i < CIM_NUM_IBQ_T7 + CIM_NUM_OBQ_T7; i++, p += 4, wr += 2) {
		if (!size[i])
			continue;

		seq_printf(seq, "%7s %5x %5u %12x  %4x %4u %4u %5u\n",
			   qname_t7[i], base[i], size[i],
			   G_QUERDADDR(p[0]) & 0xfff, (wr[0] << 1),
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_T7_QUEREMFLITS(p[2]) * 16);
	}

	return 0;
}

static int cim_qcfg_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	u8 coreid = d->coreid;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
		return cim_qcfg_show_t7(seq, adap, coreid);

	if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T4)
		return cim_qcfg_show_t5(seq, adap);

	return cim_qcfg_show_t4(seq, adap);
}

DEFINE_SIMPLE_DEBUGFS_FILE(cim_qcfg);

static int cimq_show(struct seq_file *seq, void *v, int idx)
{
	const u32 *p = v;

	seq_printf(seq, "%#06x: %08x %08x %08x %08x\n", idx * 16, p[0], p[1],
		   p[2], p[3]);
	return 0;
}

static int cim_ibq_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	unsigned int qid = d->data;
	u8 coreid = d->coreid;
	struct seq_tab *p;
	int ret;

	p = seq_open_tab(file, CIM_IBQ_SIZE, 4 * sizeof(u32), 0, cimq_show);
	if (!p)
		return -ENOMEM;

	ret = t4_read_cim_ibq_core(adap, coreid, qid, (u32 *)p->data,
				   CIM_IBQ_SIZE * 4);
	if (ret < 0)
		seq_release_private(inode, file);
	else
		ret = 0;
	return ret;
}

static const struct file_operations cim_ibq_fops = {
	.owner   = THIS_MODULE,
	.open    = cim_ibq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

static int cim_obq_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	unsigned int qid = d->data;
	u8 coreid = d->coreid;
	struct seq_tab *p;
	int ret;

	p = seq_open_tab(file, 6 * CIM_OBQ_SIZE, 4 * sizeof(u32), 0, cimq_show);
	if (!p)
		return -ENOMEM;

	ret = t4_read_cim_obq_core(adap, coreid, qid, (u32 *)p->data,
				   6 * CIM_OBQ_SIZE * 4);
	if (ret < 0)
		seq_release_private(inode, file);
	else {
		seq_tab_trim(p, ret / 4);
		ret = 0;
	}
	return ret;
}

static const struct file_operations cim_obq_fops = {
	.owner   = THIS_MODULE,
	.open    = cim_obq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

struct field_desc {
	const char *name;
	unsigned int start;
	unsigned int width;
};

static void field_desc_show(struct seq_file *seq, u64 v,
			    const struct field_desc *p)
{
	char buf[32];
	int line_size = 0;

	while (p->name) {
		u64 mask = (1ULL << p->width) - 1;
		int len = scnprintf(buf, sizeof(buf), "%s: %llu", p->name,
				    ((unsigned long long)v >> p->start) & mask);

		if (line_size + len >= 79) {
			line_size = 8;
			seq_puts(seq, "\n        ");
		}
		seq_printf(seq, "%s ", buf);
		line_size += len + 1;
		p++;
	}
	seq_putc(seq, '\n');
}

static struct field_desc tp_la0[] = {
	{ "RcfOpCodeOut", 60, 4 },
	{ "State", 56, 4 },
	{ "WcfState", 52, 4 },
	{ "RcfOpcSrcOut", 50, 2 },
	{ "CRxError", 49, 1 },
	{ "ERxError", 48, 1 },
	{ "SanityFailed", 47, 1 },
	{ "SpuriousMsg", 46, 1 },
	{ "FlushInputMsg", 45, 1 },
	{ "FlushInputCpl", 44, 1 },
	{ "RssUpBit", 43, 1 },
	{ "RssFilterHit", 42, 1 },
	{ "Tid", 32, 10 },
	{ "InitTcb", 31, 1 },
	{ "LineNumber", 24, 7 },
	{ "Emsg", 23, 1 },
	{ "EdataOut", 22, 1 },
	{ "Cmsg", 21, 1 },
	{ "CdataOut", 20, 1 },
	{ "EreadPdu", 19, 1 },
	{ "CreadPdu", 18, 1 },
	{ "TunnelPkt", 17, 1 },
	{ "RcfPeerFin", 16, 1 },
	{ "RcfReasonOut", 12, 4 },
	{ "TxCchannel", 10, 2 },
	{ "RcfTxChannel", 8, 2 },
	{ "RxEchannel", 6, 2 },
	{ "RcfRxChannel", 5, 1 },
	{ "RcfDataOutSrdy", 4, 1 },
	{ "RxDvld", 3, 1 },
	{ "RxOoDvld", 2, 1 },
	{ "RxCongestion", 1, 1 },
	{ "TxCongestion", 0, 1 },
	{ NULL }
};

static int tp_la_show(struct seq_file *seq, void *v, int idx)
{
	const u64 *p = v;

	field_desc_show(seq, *p, tp_la0);
	return 0;
}

static int tp_la_show2(struct seq_file *seq, void *v, int idx)
{
	const u64 *p = v;

	if (idx)
		seq_putc(seq, '\n');
	field_desc_show(seq, p[0], tp_la0);
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		field_desc_show(seq, p[1], tp_la0);
	return 0;
}

static int tp_la_show3(struct seq_file *seq, void *v, int idx)
{
	static struct field_desc tp_la1[] = {
		{ "CplCmdIn", 56, 8 },
		{ "CplCmdOut", 48, 8 },
		{ "ESynOut", 47, 1 },
		{ "EAckOut", 46, 1 },
		{ "EFinOut", 45, 1 },
		{ "ERstOut", 44, 1 },
		{ "SynIn", 43, 1 },
		{ "AckIn", 42, 1 },
		{ "FinIn", 41, 1 },
		{ "RstIn", 40, 1 },
		{ "DataIn", 39, 1 },
		{ "DataInVld", 38, 1 },
		{ "PadIn", 37, 1 },
		{ "RxBufEmpty", 36, 1 },
		{ "RxDdp", 35, 1 },
		{ "RxFbCongestion", 34, 1 },
		{ "TxFbCongestion", 33, 1 },
		{ "TxPktSumSrdy", 32, 1 },
		{ "RcfUlpType", 28, 4 },
		{ "Eread", 27, 1 },
		{ "Ebypass", 26, 1 },
		{ "Esave", 25, 1 },
		{ "Static0", 24, 1 },
		{ "Cread", 23, 1 },
		{ "Cbypass", 22, 1 },
		{ "Csave", 21, 1 },
		{ "CPktOut", 20, 1 },
		{ "RxPagePoolFull", 18, 2 },
		{ "RxLpbkPkt", 17, 1 },
		{ "TxLpbkPkt", 16, 1 },
		{ "RxVfValid", 15, 1 },
		{ "SynLearned", 14, 1 },
		{ "SetDelEntry", 13, 1 },
		{ "SetInvEntry", 12, 1 },
		{ "CpcmdDvld", 11, 1 },
		{ "CpcmdSave", 10, 1 },
		{ "RxPstructsFull", 8, 2 },
		{ "EpcmdDvld", 7, 1 },
		{ "EpcmdFlush", 6, 1 },
		{ "EpcmdTrimPrefix", 5, 1 },
		{ "EpcmdTrimPostfix", 4, 1 },
		{ "ERssIp4Pkt", 3, 1 },
		{ "ERssIp6Pkt", 2, 1 },
		{ "ERssTcpUdpPkt", 1, 1 },
		{ "ERssFceFipPkt", 0, 1 },
		{ NULL }
	};
	static struct field_desc tp_la2[] = {
		{ "CplCmdIn", 56, 8 },
		{ "MpsVfVld", 55, 1 },
		{ "MpsPf", 52, 3 },
		{ "MpsVf", 44, 8 },
		{ "SynIn", 43, 1 },
		{ "AckIn", 42, 1 },
		{ "FinIn", 41, 1 },
		{ "RstIn", 40, 1 },
		{ "DataIn", 39, 1 },
		{ "DataInVld", 38, 1 },
		{ "PadIn", 37, 1 },
		{ "RxBufEmpty", 36, 1 },
		{ "RxDdp", 35, 1 },
		{ "RxFbCongestion", 34, 1 },
		{ "TxFbCongestion", 33, 1 },
		{ "TxPktSumSrdy", 32, 1 },
		{ "RcfUlpType", 28, 4 },
		{ "Eread", 27, 1 },
		{ "Ebypass", 26, 1 },
		{ "Esave", 25, 1 },
		{ "Static0", 24, 1 },
		{ "Cread", 23, 1 },
		{ "Cbypass", 22, 1 },
		{ "Csave", 21, 1 },
		{ "CPktOut", 20, 1 },
		{ "RxPagePoolFull", 18, 2 },
		{ "RxLpbkPkt", 17, 1 },
		{ "TxLpbkPkt", 16, 1 },
		{ "RxVfValid", 15, 1 },
		{ "SynLearned", 14, 1 },
		{ "SetDelEntry", 13, 1 },
		{ "SetInvEntry", 12, 1 },
		{ "CpcmdDvld", 11, 1 },
		{ "CpcmdSave", 10, 1 },
		{ "RxPstructsFull", 8, 2 },
		{ "EpcmdDvld", 7, 1 },
		{ "EpcmdFlush", 6, 1 },
		{ "EpcmdTrimPrefix", 5, 1 },
		{ "EpcmdTrimPostfix", 4, 1 },
		{ "ERssIp4Pkt", 3, 1 },
		{ "ERssIp6Pkt", 2, 1 },
		{ "ERssTcpUdpPkt", 1, 1 },
		{ "ERssFceFipPkt", 0, 1 },
		{ NULL }
	};
	const u64 *p = v;

	if (idx)
		seq_putc(seq, '\n');
	field_desc_show(seq, p[0], tp_la0);
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		field_desc_show(seq, p[1], (p[0] & BIT(17)) ? tp_la2 : tp_la1);
	return 0;
}

static int tp_la_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct seq_tab *p;

	switch (G_DBGLAMODE(t4_read_reg(adap, A_TP_DBG_LA_CONFIG))) {
	case 2:
		p = seq_open_tab(file, TPLA_SIZE / 2, 2 * sizeof(u64), 0,
				 tp_la_show2);
		break;
	case 3:
		p = seq_open_tab(file, TPLA_SIZE / 2, 2 * sizeof(u64), 0,
				 tp_la_show3);
		break;
	default:
		p = seq_open_tab(file, TPLA_SIZE, sizeof(u64), 0, tp_la_show);
	}
	if (!p)
		return -ENOMEM;

	t4_tp_read_la(adap, (u64 *)p->data, NULL);
	return 0;
}

static ssize_t tp_la_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter *adap = d->adap;
	unsigned long val;
	size_t size;
	char s[32];
	int err;

	size = min(sizeof(s) - 1, count);

	if (copy_from_user(s, buf, size))
		return -EFAULT;
	s[size] = '\0';
	err = kstrtoul(s, 0, &val);
	if (err)
		return err;
	if (val > 0xffff)
		return -EINVAL;
	adap->params.tp.la_mask = val << 16;
	t4_set_reg_field(adap, A_TP_DBG_LA_CONFIG, 0xffff0000U,
			 adap->params.tp.la_mask);
	return count;
}

static const struct file_operations tp_la_fops = {
	.owner   = THIS_MODULE,
	.open    = tp_la_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
	.write   = tp_la_write
};

static int ulprx_la_show(struct seq_file *seq, void *v, int idx)
{
	const u32 *p = v;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "      Pcmd        Type   Message"
			 "                Data\n");
	else
		seq_printf(seq, "%08x%08x  %4x  %08x  %08x%08x%08x%08x\n",
			   p[1], p[0], p[2], p[3], p[7], p[6], p[5], p[4]);
	return 0;
}

static int ulprx_la_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct seq_tab *p;

	p = seq_open_tab(file, ULPRX_LA_SIZE, 8 * sizeof(u32), 1,
			 ulprx_la_show);
	if (!p)
		return -ENOMEM;

	t4_ulprx_read_la(adap, (u32 *)p->data);
	return 0;
}

static const struct file_operations ulprx_la_fops = {
	.owner   = THIS_MODULE,
	.open    = ulprx_la_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

/*
 * Format a value in a unit that differs from the value's native unit by the
 * given factor.
 */
char *unit_conv(char *buf, size_t len, unsigned int val,
		       unsigned int factor)
{
	unsigned int rem = val % factor;

	if (rem == 0)
		snprintf(buf, len, "%u", val / factor);
	else {
		while (rem % 10 == 0)
			rem /= 10;
		snprintf(buf, len, "%u.%u", val / factor, rem);
	}
	return buf;
}

static int clk_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	unsigned int cclk_ps, tre, dack_re, res;
	struct adapter *adap = d->adap;
	unsigned long long tp_tick_us;
	char buf[32];

	cclk_ps = 1000000000 / adap->params.vpd.cclk;  /* in ps */
	res = t4_read_reg(adap, A_TP_TIMER_RESOLUTION);
	tre = G_TIMERRESOLUTION(res);
	dack_re = G_DELAYEDACKRESOLUTION(res);
	tp_tick_us = (cclk_ps << tre) / 1000000; /* in us */

	seq_printf(seq, "Core clock period: %s ns\n",
		   unit_conv(buf, sizeof(buf), cclk_ps, 1000));
	seq_printf(seq, "TP timer tick: %s us\n",
		   unit_conv(buf, sizeof(buf), (cclk_ps << tre), 1000000));
	seq_printf(seq, "TCP timestamp tick: %s us\n",
		   unit_conv(buf, sizeof(buf),
			     (cclk_ps << G_TIMESTAMPRESOLUTION(res)), 1000000));
	seq_printf(seq, "DACK tick: %s us\n",
		   unit_conv(buf, sizeof(buf), (cclk_ps << dack_re), 1000000));
	seq_printf(seq, "DACK timer: %u us\n",
		   ((cclk_ps << dack_re) / 1000000) *
		   t4_read_reg(adap, A_TP_DACK_TIMER));
	seq_printf(seq, "Retransmit min: %llu us\n",
		   tp_tick_us * t4_read_reg(adap, A_TP_RXT_MIN));
	seq_printf(seq, "Retransmit max: %llu us\n",
		   tp_tick_us * t4_read_reg(adap, A_TP_RXT_MAX));
	seq_printf(seq, "Persist timer min: %llu us\n",
		   tp_tick_us * t4_read_reg(adap, A_TP_PERS_MIN));
	seq_printf(seq, "Persist timer max: %llu us\n",
		   tp_tick_us * t4_read_reg(adap, A_TP_PERS_MAX));
	seq_printf(seq, "Keepalive idle timer: %llu us\n",
		   tp_tick_us * t4_read_reg(adap, A_TP_KEEP_IDLE));
	seq_printf(seq, "Keepalive interval: %llu us\n",
		   tp_tick_us * t4_read_reg(adap, A_TP_KEEP_INTVL));
	seq_printf(seq, "Initial SRTT: %llu us\n",
		   tp_tick_us * G_INITSRTT(t4_read_reg(adap, A_TP_INIT_SRTT)));
	seq_printf(seq, "FINWAIT2 timer: %llu us\n",
		   tp_tick_us * t4_read_reg(adap, A_TP_FINWAIT2_TIMER));

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(clk);


/*
 * Dump the chip uP (microprocessor) Load Average if available.
 */
static int upload_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	u8 coreid = d->coreid;
	u32 param, val;
	int ret;

	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_LOAD) |
		 V_FW_PARAMS_PARAM_Y(coreid));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
			      &param, &val);
	if (ret < 0)
		return ret;

	if (val == 0xffffffff) {
		seq_printf(seq, "uP load: <not available>\n");
		return 0;
	}

	/* dump the three moving averages */
	seq_printf(seq, "uP core_%d load: %d, %d, %d\n",
		   coreid,
		   (val >>  0) & 0xff,
		   (val >>  8) & 0xff,
		   (val >> 16) & 0xff);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(upload);

/*
 * Firmware Device Log dump.
 * =========================
 */
static const char * const devlog_level_strings[] = {
	[FW_DEVLOG_LEVEL_EMERG]		= "EMERG",
	[FW_DEVLOG_LEVEL_CRIT]		= "CRIT",
	[FW_DEVLOG_LEVEL_ERR]		= "ERR",
	[FW_DEVLOG_LEVEL_NOTICE]	= "NOTICE",
	[FW_DEVLOG_LEVEL_INFO]		= "INFO",
	[FW_DEVLOG_LEVEL_DEBUG]		= "DEBUG"
};

static const char * const devlog_facility_strings[] = {
	[FW_DEVLOG_FACILITY_CORE]	= "CORE",
	[FW_DEVLOG_FACILITY_CF]		= "CF",
	[FW_DEVLOG_FACILITY_SCHED]	= "SCHED",
	[FW_DEVLOG_FACILITY_TIMER]	= "TIMER",
	[FW_DEVLOG_FACILITY_RES]	= "RES",
	[FW_DEVLOG_FACILITY_HW]		= "HW",
	[FW_DEVLOG_FACILITY_FLR]	= "FLR",
	[FW_DEVLOG_FACILITY_DMAQ]	= "DMAQ",
	[FW_DEVLOG_FACILITY_PHY]	= "PHY",
	[FW_DEVLOG_FACILITY_MAC]	= "MAC",
	[FW_DEVLOG_FACILITY_PORT]	= "PORT",
	[FW_DEVLOG_FACILITY_VI]		= "VI",
	[FW_DEVLOG_FACILITY_FILTER]	= "FILTER",
	[FW_DEVLOG_FACILITY_ACL]	= "ACL",
	[FW_DEVLOG_FACILITY_TM]		= "TM",
	[FW_DEVLOG_FACILITY_QFC]	= "QFC",
	[FW_DEVLOG_FACILITY_DCB]	= "DCB",
	[FW_DEVLOG_FACILITY_ETH]	= "ETH",
	[FW_DEVLOG_FACILITY_OFLD]	= "OFLD",
	[FW_DEVLOG_FACILITY_RI]		= "RI",
	[FW_DEVLOG_FACILITY_ISCSI]	= "ISCSI",
	[FW_DEVLOG_FACILITY_FCOE]	= "FCOE",
	[FW_DEVLOG_FACILITY_FOISCSI]	= "FOISCSI",
	[FW_DEVLOG_FACILITY_FOFCOE]	= "FOFCOE",
	[FW_DEVLOG_FACILITY_CHNET]	= "CHNET",
};

/*
 * Information gathered by Device Log Open routine for the display routine.
 */
struct devlog_info {
	unsigned int nentries;		/* number of entries in log[] */
	unsigned int first;		/* first [temporal] entry in log[] */
	struct fw_devlog_e log[];	/* Firmware Device Log */
};

/*
 * Dump a Firmaware Device Log entry.
 */
static int devlog_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%10s  %15s  %8s  %8s  %s\n",
			   "Seq#", "Tstamp", "Level", "Facility", "Message");
	else {
		struct devlog_info *dinfo = seq->private;
		int fidx = (uintptr_t)v - 2;
		unsigned long index;
		struct fw_devlog_e *e;

		/*
		 * Get a pointer to the log entry to display.  Skip unused log
		 * entries.
		 */
		index = dinfo->first + fidx;
		if (index >= dinfo->nentries)
			index -= dinfo->nentries;
		e = &dinfo->log[index];
		if (e->timestamp == 0)
			return 0;

		/*
		 * Print the message.  This depends on the firmware using
		 * exactly the same formating strings as the kernel so we may
		 * eventually have to put a format interpreter in here ...
		 */
		seq_printf(seq, "%10d  %15llu  %8s  %8s  ",
			   be32_to_cpu(e->seqno),
			   be64_to_cpu(e->timestamp),
			   (e->level < ARRAY_SIZE(devlog_level_strings)
			    ? devlog_level_strings[e->level]
			    : "UNKNOWN"),
			   (e->facility < ARRAY_SIZE(devlog_facility_strings)
			    ? devlog_facility_strings[e->facility]
			    : "UNKNOWN"));
		seq_printf(seq, e->fmt,
			   be32_to_cpu(e->params[0]),
			   be32_to_cpu(e->params[1]),
			   be32_to_cpu(e->params[2]),
			   be32_to_cpu(e->params[3]),
			   be32_to_cpu(e->params[4]),
			   be32_to_cpu(e->params[5]),
			   be32_to_cpu(e->params[6]),
			   be32_to_cpu(e->params[7]));
	}

	return 0;
}

/*
 * Sequential File Operations for Device Log.
 */
static inline void *devlog_get_idx(struct devlog_info *dinfo, loff_t pos)
{
	if (pos > dinfo->nentries)
		return NULL;

	return (void *)(uintptr_t)(pos + 1);
}

static void *devlog_start(struct seq_file *seq, loff_t *pos)
{
	struct devlog_info *dinfo = seq->private;

	return (*pos
		? devlog_get_idx(dinfo, *pos)
		: SEQ_START_TOKEN);
}

static void *devlog_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct devlog_info *dinfo = seq->private;

	(*pos)++;
	return devlog_get_idx(dinfo, *pos);
}

static void devlog_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations devlog_seq_ops = {
	.start = devlog_start,
	.next  = devlog_next,
	.stop  = devlog_stop,
	.show  = devlog_show
};

/*
 * Set up for reading the firmware's device log.  We read the entire log here
 * and then display it incrementally in devlog_show().
 */
static int devlog_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct devlog_params *dparams;
	struct devlog_info *dinfo;
	u8 coreid = d->coreid;
	unsigned int index;
	u32 fseqno;
	int ret;

	dparams = &adap->params.devlog[coreid];

	/*
	 * If we don't know where the log is we can't do anything.
	 */
	if (dparams->start == 0)
		return -ENXIO;

	/*
	 * Allocate the space to read in the firmware's device log and set up
	 * for the iterated call to our display function.
	 */
	dinfo = __seq_open_private(file, &devlog_seq_ops,
				   sizeof(*dinfo) + dparams->size);
	if (dinfo == NULL)
		return -ENOMEM;

	/*
	 * Record the basic log buffer information and read in the raw log.
	 */
	dinfo->nentries = (dparams->size / sizeof(struct fw_devlog_e));
	dinfo->first = 0;
	spin_lock(&adap->win0_lock);
	ret = t4_memory_rw(adap, adap->params.drv_memwin, dparams->memtype, dparams->start,
			   dparams->size, (__be32 *)dinfo->log,
			   T4_MEMORY_READ);
	spin_unlock(&adap->win0_lock);
	if (ret) {
		seq_release_private(inode, file);
		return ret;
	}

	/*
	 * Find the earliest (lowest Sequence Number) log entry in the
	 * circular Device Log.
	 */
	for (fseqno = ~((u32)0), index = 0; index < dinfo->nentries; index++) {
		struct fw_devlog_e *e = &dinfo->log[index];
		__u32 seqno;

		if (e->timestamp == 0)
			continue;

		seqno = be32_to_cpu(e->seqno);
		if (seqno < fseqno) {
			fseqno = seqno;
			dinfo->first = index;
		}
	}

	return 0;
}

static const struct file_operations devlog_fops = {
	.owner   = THIS_MODULE,
	.open    = devlog_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

static int devlog_level_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	unsigned int devlog_level;
	int ret;

	/* We can only do this if we have access to the firmware */
	if (!(adap->flags & FW_OK))
		return -EOPNOTSUPP;

	ret = t4_get_devlog_level(adap, &devlog_level);
	if (ret)
		return ret;

	seq_printf(seq, "Firmware Device Log Level = %u (%s)\n",
		   devlog_level,
		   (devlog_level < ARRAY_SIZE(devlog_level_strings)
		    ? devlog_level_strings[devlog_level]
		    : "UNKNOWN"));

	return 0;
}

static int devlog_level_open(struct inode *inode, struct file *file)
{
	return single_open(file, devlog_level_show, inode->i_private);
}

static ssize_t devlog_level_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter *adap = d->adap;
	unsigned int devlog_level;
	char c = '\n', s[256];
	int ret;

	/* We can only do this if we have access to the firmware */
	if (!(adap->flags & FW_OK))
		return -EOPNOTSUPP;

	if (count > sizeof(s) - 1 || !count)
		return -EINVAL;
	if (copy_from_user(s, buf, count))
		return -EFAULT;
	s[count] = '\0';

	if (sscanf(s, "%u%c", &devlog_level, &c) < 1 || c != '\n')
		return -EINVAL;
	if (devlog_level > FW_DEVLOG_LEVEL_MAX)
		return -EINVAL;

	ret = t4_set_devlog_level(adap, devlog_level);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations devlog_level_fops = {
	.owner   = THIS_MODULE,
	.open    = devlog_level_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = devlog_level_write,
};

#ifdef T4_OS_LOG_MBOX_CMDS
/*
 * Show Firmware Mailbox Command/Reply Log
 *
 * Note that we don't do any locking when dumping the Firmware Mailbox Log so
 * it's possible that we can catch things during a log update and therefore
 * see partially corrupted log entries.  But i9t's probably Good Enough(tm).
 * If we ever decide that we want to make sure that we're dumping a coherent
 * log, we'd need to perform locking in the mailbox logging and in
 * mboxlog_open() where we'd need to grab the entire mailbox log in one go
 * like we do for the Firmware Device Log.  But as stated above, meh ...
 */
static int mboxlog_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct mbox_cmd_log *log;
	struct mbox_cmd *entry;
	int entry_idx, i;

	log = adap->mbox_log;
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq,
			   "%10s  %15s  %5s  %5s  %s\n",
			   "Seq#", "Tstamp", "Atime", "Etime",
			   "Command/Reply");
		return 0;
	}

	entry_idx = log->cursor + ((uintptr_t)v - 2);
	if (entry_idx >= log->size)
		entry_idx -= log->size;
	entry = mbox_cmd_log_entry(log, entry_idx);

	/* skip over unused entries */
	if (entry->timestamp == 0)
		return 0;

	seq_printf(seq, "%10u  %15llu  %5d  %5d",
		   entry->seqno, entry->timestamp,
		   entry->access, entry->execute);
	for (i = 0; i < MBOX_LEN/8; i++) {
		u64 flit = entry->cmd[i];
		u32 hi = (u32)(flit >> 32);
		u32 lo = (u32)flit;

		seq_printf(seq, "  %08x %08x", hi, lo);
	}
	seq_puts(seq, "\n");
	return 0;
}

static inline void *mboxlog_get_idx(struct seq_file *seq, loff_t pos)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;

	return ((pos <= adap->mbox_log->size) ?
		(void *)(uintptr_t)(pos + 1) : NULL);
}

static void *mboxlog_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? mboxlog_get_idx(seq, *pos) : SEQ_START_TOKEN;
}

static void *mboxlog_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return mboxlog_get_idx(seq, *pos);
}

static void mboxlog_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations mboxlog_seq_ops = {
	.start = mboxlog_start,
	.next  = mboxlog_next,
	.stop  = mboxlog_stop,
	.show  = mboxlog_show
};

static int mboxlog_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &mboxlog_seq_ops);

	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = inode->i_private;
	}
	return res;
}

static const struct file_operations mboxlog_fops = {
	.owner   = THIS_MODULE,
	.open    = mboxlog_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};
#endif /* T4_OS_LOG_MBOX_CMDS */

static int mbox_show(struct seq_file *seq, void *v)
{
	static const char * const owner[] = {
		"none", "FW", "driver", "FW Deferred", "<unread>"
	};
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	unsigned int mbox = d->data;
	void __iomem *addr;
	int i;

	addr = adap->regs + PF_REG(mbox, A_CIM_PF_MAILBOX_DATA);

	/*
	 * For T4 we don't have a shadow copy of the Mailbox Control register.
	 * And since reading that real register causes a side effect of
	 * granting ownership, we're best of simply not reading it at all.
	 */
	if (is_t4(adap->params.chip))
		i = 4; /* index of "<unread>" */
	else {
		unsigned int ctrl_reg = A_CIM_PF_MAILBOX_CTRL_SHADOW_COPY;
		void __iomem *ctrl = adap->regs + PF_REG(mbox, ctrl_reg);

		i = G_MBOWNER(readl(ctrl));
	}

	seq_printf(seq, "mailbox owned by %s\n\n", owner[i]);

	for (i = 0; i < MBOX_LEN; i += 8)
		seq_printf(seq, "%016llx\n",
			   (unsigned long long)readq(addr + i));
	return 0;
}

static int mbox_open(struct inode *inode, struct file *file)
{
	return single_open(file, mbox_show, inode->i_private);
}

static ssize_t mbox_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter *adap = d->adap;
	unsigned int mbox = d->data;
	unsigned long long data[8];
	char s[256], c = '\n';
	void __iomem *addr;
	void __iomem *ctrl;
	int i;

	if (count > sizeof(s) - 1 || !count)
		return -EINVAL;
	if (copy_from_user(s, buf, count))
		return -EFAULT;
	s[count] = '\0';

	if (sscanf(s, "%llx %llx %llx %llx %llx %llx %llx %llx%c", &data[0],
		   &data[1], &data[2], &data[3], &data[4], &data[5], &data[6],
		   &data[7], &c) < 8 || c != '\n')
		return -EINVAL;

	addr = adap->regs + PF_REG(mbox, A_CIM_PF_MAILBOX_DATA);
	ctrl = addr + MBOX_LEN;

	if (G_MBOWNER(readl(ctrl)) != X_MBOWNER_PL)
		return -EBUSY;

	for (i = 0; i < 8; i++)
		writeq(data[i], addr + 8 * i);

	writel(F_MBMSGVALID | V_MBOWNER(X_MBOWNER_FW), ctrl);
	return count;
}

static const struct file_operations mbox_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mbox_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = mbox_write
};

int mem_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	
	file->private_data = inode->i_private;

	(void)t4_fwcache(adap, FW_PARAM_DEV_FWCACHE_FLUSH);
	
	return 0;
}

static ssize_t mem_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct t4_linux_debugfs_data *d = file->private_data;
	loff_t avail = file_inode(file)->i_size;
	struct adapter *adap = d->adap;
	unsigned int mem = d->data;
	loff_t pos = *ppos;
	__be32 *data;
	int ret;

	if (pos < 0)
		return -EINVAL;
	if (pos >= avail)
		return 0;
	if (count > avail - pos)
		count = avail - pos;

	data = t4_alloc_mem(count);
	if (!data)
		return -ENOMEM;
	spin_lock(&adap->win0_lock);
	ret = t4_memory_rw(adap, adap->params.drv_memwin, mem, pos, count, data, T4_MEMORY_READ);
	spin_unlock(&adap->win0_lock);
	if (ret) {
		t4_free_mem(data);
		return ret;
	}
	ret = copy_to_user(buf, data, count);
	t4_free_mem(data);
	if (ret)
		return -EFAULT;

	*ppos = pos + count;
	return count;
}

static const struct file_operations mem_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mem_open,
	.read    = mem_read,
	.llseek  = default_llseek,
};

static ssize_t flash_read(struct file *file, char __user *buf, size_t count,
			  loff_t *ppos)
{
	struct t4_linux_debugfs_data *d = file->private_data;
	loff_t avail = file_inode(file)->i_size;
	struct adapter *adap = d->adap;
	loff_t pos = *ppos;

	if (pos < 0)
		return -EINVAL;
	if (pos >= avail)
		return 0;
	if (count > avail - pos)
		count = avail - pos;

	while (count) {
		size_t len;
		int ret, ofst;
		u8 data[256];

		ofst = pos & 3;
		len = min(count + ofst, sizeof(data));
		ret = t4_read_flash(adap, pos - ofst, (len + 3) / 4,
				    (u32 *)data, 1);
		if (ret)
			return ret;

		len -= ofst;
		if (copy_to_user(buf, data + ofst, len))
			return -EFAULT;

		buf += len;
		pos += len;
		count -= len;
	}
	count = pos - *ppos;
	*ppos = pos;
	return count;
}

static const struct file_operations flash_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mem_open,
	.read    = flash_read,
	.llseek  = default_llseek,
};

static inline void tcamxy2valmask(u64 x, u64 y, u8 *addr, u64 *mask)
{
	*mask = x | y;
	y = (__force u64)cpu_to_be64(y);
	memcpy(addr, (char *)&y + 2, ETH_ALEN);
}

static int mps_tcam_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	unsigned int chip_ver;

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	if (v == SEQ_START_TOKEN) {
		if (chip_ver > CHELSIO_T5) {
			seq_puts(seq, "Idx  Ethernet address     Mask     "
				 "  VNI   Mask   IVLAN Vld "
				 "DIP_Hit   Lookup  Port "
				 "Vld Ports PF  VF                           "
				 "Replication                                "
				 "    P0 P1 P2 P3  ML\n");
		} else {
			if (adap->params.arch.mps_rplc_size > 128)
				seq_puts(seq, "Idx  Ethernet address     Mask     "
					 "Vld Ports PF  VF                           "
					 "Replication                                "
					 "    P0 P1 P2 P3  ML\n");
			else
				seq_puts(seq, "Idx  Ethernet address     Mask     "
					 "Vld Ports PF  VF              Replication"
					 "	         P0 P1 P2 P3  ML\n");
		}
	} else {
		u32 cls_lo, cls_hi, ctl, data2, vnix = 0, vniy = 0;
		bool replicate, dip_hit = false, vlan_vld = false;
		unsigned int idx = (uintptr_t)v - 2;
		u8 lookup_type = 0, port_num = 0;
		u64 tcamy, tcamx, val;
		u8 addr[ETH_ALEN];
		u32 rplc[8] = {0};
		u16 ivlan = 0;
		u64 mask;

		if (chip_ver >= CHELSIO_T7) {
			/* CtlReqID   - 1: use Host Driver Requester ID
			 * CtlCmdType - 0: Read, 1: Write
			 * CtlXYBitSel- 0: Y bit, 1: X bit
			  ####### for T7A ######
			 * CtlTcamSel        -       26:25    Control bit. 0: TCAM0, 1: TCAM1.
			 * CtlTcamIndex      -       24:17    Control bits. Index of TCAM location to be accessed.

			  ####### for T7B ######
			 * CtlTcamSel        -       27:26    Control bit. 0: TCAM0, 1: TCAM1, 2: TCAM2.
			 * CtlTcamIndex      -       25:17    Control bits. Index of TCAM location to be accessed.
			 */

			/* Read tcamy */
			ctl = (V_CTLREQID(1) |
			       V_CTLCMDTYPE(0) | V_CTLXYBITSEL(0));

			if (is_t7b(adap->params.chip)) {
				if (idx < 512)
					ctl |= V_T7_CTLTCAMINDEX(idx) | V_T7_CTLTCAMSEL(0);
				else if (idx < 1024)
					ctl |= V_T7_CTLTCAMINDEX(idx - 512) |
						V_T7_CTLTCAMSEL(1);
				else /* idx 1024 to 1535 */
					ctl |= V_T7_CTLTCAMINDEX(idx - 1024) |
						V_T7_CTLTCAMSEL(2);
			} else {
				/* t7a changes similar to t6 */
				if (idx < 256)
					ctl |= V_CTLTCAMINDEX(idx) | V_CTLTCAMSEL(0);
				else
					ctl |= V_CTLTCAMINDEX(idx - 256) |
						V_CTLTCAMSEL(1);
			}

			t4_write_reg(adap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(adap, A_MPS_CLS_TCAM0_RDATA1_REQ_ID1);
			tcamy = G_DMACH(val) << 32;
			tcamy |= t4_read_reg(adap, A_MPS_CLS_TCAM0_RDATA0_REQ_ID1);
			data2 = t4_read_reg(adap, A_MPS_CLS_TCAM0_RDATA2_REQ_ID1);
			lookup_type = G_DATALKPTYPE(data2);
			/* 0 - Outer header, 1 - Inner header
			 * [71:48] bit locations are overloaded for
			 * outer vs. inner lookup types.
			 */
			if (lookup_type && (lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI */
				vniy = (((data2 & F_DATAVIDH2) |
					 G_DATAVIDH1(data2)) << 16) |
					G_VIDL(val);
				dip_hit = data2 & F_DATADIPHIT;
			} else {
				vlan_vld = data2 & F_DATAVIDH2;
				ivlan = G_VIDL(val);
			}
			port_num = G_DATAPORTNUM(data2);

			/* Read tcamx. Change the control param */
			vnix = 0;
			ctl |= V_CTLXYBITSEL(1);
			t4_write_reg(adap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(adap, A_MPS_CLS_TCAM0_RDATA1_REQ_ID1);
			tcamx = G_DMACH(val) << 32;
			tcamx |= t4_read_reg(adap, A_MPS_CLS_TCAM0_RDATA0_REQ_ID1);
			data2 = t4_read_reg(adap, A_MPS_CLS_TCAM0_RDATA2_REQ_ID1);
			if (lookup_type && (lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI mask */
				vnix = (((data2 & F_DATAVIDH2) |
					 G_DATAVIDH1(data2)) << 16) |
					G_VIDL(val);
			}
		} else if (chip_ver > CHELSIO_T5) {
			/* CtlReqID   - 1: use Host Driver Requester ID
			 * CtlCmdType - 0: Read, 1: Write
			 * CtlTcamSel - 0: TCAM0, 1: TCAM1
			 * CtlXYBitSel- 0: Y bit, 1: X bit
			 */

			/* Read tcamy */
			ctl = (V_CTLREQID(1) |
			       V_CTLCMDTYPE(0) | V_CTLXYBITSEL(0));
			if (idx < 256)
				ctl |= V_CTLTCAMINDEX(idx) | V_CTLTCAMSEL(0);
			else
				ctl |= V_CTLTCAMINDEX(idx - 256) |
				       V_CTLTCAMSEL(1);

			t4_write_reg(adap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(adap, A_MPS_CLS_TCAM_RDATA1_REQ_ID1);
			tcamy = G_DMACH(val) << 32;
			tcamy |= t4_read_reg(adap, A_MPS_CLS_TCAM_RDATA0_REQ_ID1);
			data2 = t4_read_reg(adap, A_MPS_CLS_TCAM_RDATA2_REQ_ID1);
			lookup_type = G_DATALKPTYPE(data2);
			/* 0 - Outer header, 1 - Inner header
			 * [71:48] bit locations are overloaded for
			 * outer vs. inner lookup types.
			 */
			if (lookup_type && (lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI */
				vniy = (((data2 & F_DATAVIDH2) |
					 G_DATAVIDH1(data2)) << 16) |
					G_VIDL(val);
				dip_hit = data2 & F_DATADIPHIT;
			} else {
				vlan_vld = data2 & F_DATAVIDH2;
				ivlan = G_VIDL(val);
			}
			port_num = G_DATAPORTNUM(data2);

			/* Read tcamx. Change the control param */
			vnix = 0;
			ctl |= V_CTLXYBITSEL(1);
			t4_write_reg(adap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(adap, A_MPS_CLS_TCAM_RDATA1_REQ_ID1);
			tcamx = G_DMACH(val) << 32;
			tcamx |= t4_read_reg(adap, A_MPS_CLS_TCAM_RDATA0_REQ_ID1);
			data2 = t4_read_reg(adap, A_MPS_CLS_TCAM_RDATA2_REQ_ID1);
			if (lookup_type && (lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI mask */
				vnix = (((data2 & F_DATAVIDH2) |
					 G_DATAVIDH1(data2)) << 16) |
					G_VIDL(val);
			}
		} else {
			tcamy = t4_read_reg64(adap, MPS_CLS_TCAM_Y_L(idx));
			tcamx = t4_read_reg64(adap, MPS_CLS_TCAM_X_L(idx));
		}

		/* t7b changes A_MPS_T5_CLS_SRAM_H to indirect register */
		if (is_t7b(adap->params.chip)) {
			u32 tmp_ctl = 0;

			tmp_ctl |= V_SRAMWRN(0) |
				   V_SRAMINDEX(idx & M_SRAMINDEX);
			t4_write_reg(adap, A_MPS_T7B_CLS_SRAM_H, tmp_ctl);
			cls_lo = t4_read_reg(adap, A_MPS_T7B_CLS_SRAM_L);
			cls_hi = t4_read_reg(adap, A_MPS_T7B_CLS_SRAM_H);
		} else {
			cls_lo = t4_read_reg(adap, MPS_CLS_SRAM_L(idx));
			cls_hi = t4_read_reg(adap, MPS_CLS_SRAM_H(idx));
		}

		if (tcamx & tcamy) {
			seq_printf(seq, "%3u         -\n", idx);
			goto out;
		}

		rplc[0] = rplc[1] = rplc[2] = rplc[3] = 0;
		if (chip_ver >= CHELSIO_T7)
			replicate = (cls_lo & F_T7_REPLICATE);
		if (chip_ver > CHELSIO_T5)
			replicate = (cls_lo & F_T6_REPLICATE);
		else
			replicate = (cls_lo & F_REPLICATE);

		if (replicate) {
			struct fw_ldst_cmd ldst_cmd;
			int ret;
			struct fw_ldst_mps_rplc mps_rplc;

			memset(&ldst_cmd, 0, sizeof(ldst_cmd));
			ldst_cmd.op_to_addrspace =
				htonl(V_FW_CMD_OP(FW_LDST_CMD) |
				      F_FW_CMD_REQUEST |
				      F_FW_CMD_READ |
				      V_FW_LDST_CMD_ADDRSPACE(FW_LDST_ADDRSPC_MPS));
			ldst_cmd.cycles_to_len16 = htonl(FW_LEN16(ldst_cmd));
			ldst_cmd.u.mps.rplc.fid_idx =
				htons(V_FW_LDST_CMD_FID(FW_LDST_MPS_RPLC) |
				      V_FW_LDST_CMD_IDX(idx));
			ret = t4_wr_mbox(adap, adap->mbox, &ldst_cmd,
					 sizeof(ldst_cmd), &ldst_cmd);
			if (ret)
				dev_warn(adap->pdev_dev, "Can't read MPS "
					 "replication map for idx %d: %d\n",
					 idx, -ret);
			else {
				mps_rplc = ldst_cmd.u.mps.rplc;
				rplc[0] = ntohl(mps_rplc.rplc31_0);
				rplc[1] = ntohl(mps_rplc.rplc63_32);
				rplc[2] = ntohl(mps_rplc.rplc95_64);
				rplc[3] = ntohl(mps_rplc.rplc127_96);
				if (adap->params.arch.mps_rplc_size > 128) {
					rplc[4] = ntohl(mps_rplc.rplc159_128);
					rplc[5] = ntohl(mps_rplc.rplc191_160);
					rplc[6] = ntohl(mps_rplc.rplc223_192);
					rplc[7] = ntohl(mps_rplc.rplc255_224);
				}
			}
		}

		tcamxy2valmask(tcamx, tcamy, addr, &mask);
		if (chip_ver >= CHELSIO_T7) {
			/* Inner header lookup */
			if (lookup_type && lookup_type != M_DATALKPTYPE) {
				seq_printf(seq,
					   "%3u %02x:%02x:%02x:%02x:%02x:%02x "
					   "%012llx %06x %06x    -    -   %3c"
					   "      'I'  %4x   "
					   "%3c   %#x%4u%4d", idx, addr[0],
					   addr[1], addr[2], addr[3],
					   addr[4], addr[5],
					   (unsigned long long)mask,
					   vniy, (vnix | vniy),
					   dip_hit ? 'Y' : 'N',
					   port_num,
					   (cls_lo & F_T7_SRAM_VLD) ? 'Y' : 'N',
					   G_PORTMAP(cls_hi),
					   G_T7_PF(cls_lo),
					   (cls_lo & F_T7_VF_VALID) ?
					   G_T7_VF(cls_lo) : -1);
			} else {
				seq_printf(seq,
					   "%3u %02x:%02x:%02x:%02x:%02x:%02x "
					   "%012llx    -       -   ",
					   idx, addr[0], addr[1], addr[2],
					   addr[3], addr[4], addr[5],
					   (unsigned long long)mask);

				if (vlan_vld)
					seq_printf(seq, "%4u   Y     ", ivlan);
				else
					seq_puts(seq, "  -    N     ");

				seq_printf(seq,
					   "-      %3c  %4x   %3c   %#x%4u%4d",
					   lookup_type ? 'I' : 'O', port_num,
					   (cls_lo & F_T7_SRAM_VLD) ? 'Y' : 'N',
					   G_PORTMAP(cls_hi),
					   G_T7_PF(cls_lo),
					   (cls_lo & F_T7_VF_VALID) ?
					   G_T7_VF(cls_lo) : -1);
			}
		} else if (chip_ver > CHELSIO_T5) {
			/* Inner header lookup */
			if (lookup_type && (lookup_type != M_DATALKPTYPE)) {
				seq_printf(seq,
					   "%3u %02x:%02x:%02x:%02x:%02x:%02x "
					   "%012llx %06x %06x    -    -   %3c"
					   "      'I'  %4x   "
					   "%3c   %#x%4u%4d", idx, addr[0],
					   addr[1], addr[2], addr[3],
					   addr[4], addr[5],
					   (unsigned long long)mask,
					   vniy, (vnix | vniy),
					   dip_hit ? 'Y' : 'N',
					   port_num,
					   (cls_lo & F_T6_SRAM_VLD) ? 'Y' : 'N',
					   G_PORTMAP(cls_hi),
					   G_T6_PF(cls_lo),
					   (cls_lo & F_T6_VF_VALID) ?
					   G_T6_VF(cls_lo) : -1);
			} else {
				seq_printf(seq,
					   "%3u %02x:%02x:%02x:%02x:%02x:%02x "
					   "%012llx    -       -   ",
					   idx, addr[0], addr[1], addr[2],
					   addr[3], addr[4], addr[5],
					   (unsigned long long)mask);

				if (vlan_vld)
					seq_printf(seq, "%4u   Y     ", ivlan);
				else
					seq_puts(seq, "  -    N     ");

				seq_printf(seq,
					   "-      %3c  %4x   %3c   %#x%4u%4d",
					   lookup_type ? 'I' : 'O', port_num,
					   (cls_lo & F_T6_SRAM_VLD) ? 'Y' : 'N',
					   G_PORTMAP(cls_hi),
					   G_T6_PF(cls_lo),
					   (cls_lo & F_T6_VF_VALID) ?
					   G_T6_VF(cls_lo) : -1);
			}
		} else
			seq_printf(seq, "%3u %02x:%02x:%02x:%02x:%02x:%02x "
				   "%012llx%3c   %#x%4u%4d",
				   idx, addr[0], addr[1], addr[2], addr[3],
				   addr[4], addr[5], (unsigned long long)mask,
				   (cls_lo & F_SRAM_VLD) ? 'Y' : 'N',
				   G_PORTMAP(cls_hi),
				   G_PF(cls_lo),
				   (cls_lo & F_VF_VALID) ? G_VF(cls_lo) : -1);

		if (replicate) {
			if (adap->params.arch.mps_rplc_size > 128)
				seq_printf(seq, " %08x %08x %08x %08x "
					   "%08x %08x %08x %08x",
					   rplc[7], rplc[6], rplc[5], rplc[4],
					   rplc[3], rplc[2], rplc[1], rplc[0]);
			else
				seq_printf(seq, " %08x %08x %08x %08x",
					   rplc[3], rplc[2], rplc[1], rplc[0]);
		} else {
			if (adap->params.arch.mps_rplc_size > 128)
				seq_printf(seq, "%72c", ' ');
			else
				seq_printf(seq, "%36c", ' ');
		}

		if (chip_ver >= CHELSIO_T7)
			seq_printf(seq, "%4u%3u%3u%3u %#x\n",
				   G_T7_SRAM_PRIO0(cls_lo),
				   G_T7_SRAM_PRIO1(cls_lo),
				   G_T7_SRAM_PRIO2(cls_lo),
				   G_T7_SRAM_PRIO3(cls_lo),
				   (cls_lo >> S_T7_MULTILISTEN0) & 0xf);
		else if (chip_ver > CHELSIO_T5)
			seq_printf(seq, "%4u%3u%3u%3u %#x\n",
				   G_T6_SRAM_PRIO0(cls_lo),
				   G_T6_SRAM_PRIO1(cls_lo),
				   G_T6_SRAM_PRIO2(cls_lo),
				   G_T6_SRAM_PRIO3(cls_lo),
				   (cls_lo >> S_T6_MULTILISTEN0) & 0xf);
		else
			seq_printf(seq, "%4u%3u%3u%3u %#x\n",
				   G_SRAM_PRIO0(cls_lo), G_SRAM_PRIO1(cls_lo),
				   G_SRAM_PRIO2(cls_lo), G_SRAM_PRIO3(cls_lo),
				   (cls_lo >> S_MULTILISTEN0) & 0xf);
	}
out:	return 0;
}

static inline void *mps_tcam_get_idx(struct seq_file *seq, loff_t pos)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;

	return ((pos <= adap->params.arch.mps_tcam_size) ?
		(void *)(uintptr_t)(pos + 1) : NULL);
}

static void *mps_tcam_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? mps_tcam_get_idx(seq, *pos) : SEQ_START_TOKEN;
}

static void *mps_tcam_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return mps_tcam_get_idx(seq, *pos);
}

static void mps_tcam_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations mps_tcam_seq_ops = {
	.start = mps_tcam_start,
	.next  = mps_tcam_next,
	.stop  = mps_tcam_stop,
	.show  = mps_tcam_show
};

static int mps_tcam_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &mps_tcam_seq_ops);

	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = inode->i_private;
	}
	return res;
}

static const struct file_operations mps_tcam_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mps_tcam_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

/*
 * Display various sensor information.
 */
static int sensors_show(struct seq_file *seq, void *v)
{

	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	u32 param, val;
	int ret;

	/*
	 * Note that if the sensors haven't been initialized and turned on
	 * we'll get values of 0, so treat those as "<unknown>" ...  We'll
	 * also get errors for older Firmware which doesn't have the APIs to
	 * retrieve these values ...
	 */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DIAG) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAM_DEV_DIAG_TMP));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &param, &val);
	if (ret < 0 || val == 0)
		seq_printf(seq, "Temperature:     <unknown>\n");
	else
		seq_printf(seq, "Temperature:     %dC\n", val);

	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DIAG) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAM_DEV_DIAG_MAXTMPTHRESH));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &param, &val);
	if (ret < 0 || val == 0)
		seq_printf(seq, "Max Temperature: <unknown>\n");
	else
		seq_printf(seq, "Max Temperature: %dC\n", val);

	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DIAG) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAM_DEV_DIAG_VDD));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &param, &val);
	if (ret < 0 || val == 0)
		seq_printf(seq, "Core VDD:        <unknown>\n");
	else
		seq_printf(seq, "Core VDD:        %dmV\n", val);

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(sensors);

#ifdef __DRIVER_ETHTOOL_UNSUPPORTED__
static int lb_stats_show(struct seq_file *seq, void *v)
{
	static const char *stat_name[] = {
		"OctetsOK:", "FramesOK:", "BcastFrames:", "McastFrames:",
		"UcastFrames:", "ErrorFrames:", "Frames64:", "Frames65To127:",
		"Frames128To255:", "Frames256To511:", "Frames512To1023:",
		"Frames1024To1518:", "Frames1519ToMax:", "FramesDropped:",
		"BG0FramesDropped:", "BG1FramesDropped:", "BG2FramesDropped:",
		"BG3FramesDropped:", "BG0FramesTrunc:", "BG1FramesTrunc:",
		"BG2FramesTrunc:", "BG3FramesTrunc:"
	};
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct lb_port_stats s[2];
	u64 *p0, *p1;
	int i, j;

	memset(s, 0, sizeof(s));

	for (i = 0; i < adap->params.arch.nchan; i += 2) {
		t4_get_lb_stats(adap, i, &s[0]);
		t4_get_lb_stats(adap, i + 1, &s[1]);

		p0 = &s[0].octets;
		p1 = &s[1].octets;
		seq_printf(seq, "%s                       Loopback %u          "
			   " Loopback %u\n", i == 0 ? "" : "\n", i, i + 1);

		for (j = 0; j < ARRAY_SIZE(stat_name); j++)
			seq_printf(seq, "%-17s %20llu %20llu\n", stat_name[j],
				   (unsigned long long)*p0++,
				   (unsigned long long)*p1++);
	}
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(lb_stats);
#endif /* __DRIVER_ETHTOOL_UNSUPPORTED__ */

#define PRINT_ADAP_STATS(string, value) \
	seq_printf(seq, "%-25s %-20llu\n", (string), \
		   (unsigned long long)(value))

#define PRINT_CH_STATS(string, value) \
do { \
	seq_printf(seq, "%-25s ", (string)); \
	for (i = 0; i < adap->params.arch.nchan; i++) \
		seq_printf(seq, "%-20llu ", \
			   (unsigned long long)stats.value[i]); \
	seq_printf(seq, "\n"); \
} while (0)

#define PRINT_CH_STATS2(string, value) \
do { \
	seq_printf(seq, "%-25s ", (string)); \
	for (i = 0; i < adap->params.arch.nchan; i++) \
		seq_printf(seq, "%-20llu ", \
			   (unsigned long long)stats[i].value); \
	seq_printf(seq, "\n"); \
} while (0)

static void show_tcp_stats(struct seq_file *seq)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tp_tcp_stats v4, v6;

	spin_lock(&adap->stats_lock);
	t4_tp_get_tcp_stats(adap, &v4, &v6, false);
	spin_unlock(&adap->stats_lock);

	PRINT_ADAP_STATS("tcp_ipv4_out_rsts:", v4.tcp_out_rsts);
	PRINT_ADAP_STATS("tcp_ipv4_in_segs:", v4.tcp_in_segs);
	PRINT_ADAP_STATS("tcp_ipv4_out_segs:", v4.tcp_out_segs);
	PRINT_ADAP_STATS("tcp_ipv4_retrans_segs:", v4.tcp_retrans_segs);
	PRINT_ADAP_STATS("tcp_ipv6_out_rsts:", v6.tcp_out_rsts);
	PRINT_ADAP_STATS("tcp_ipv6_in_segs:", v6.tcp_in_segs);
	PRINT_ADAP_STATS("tcp_ipv6_out_segs:", v6.tcp_out_segs);
	PRINT_ADAP_STATS("tcp_ipv6_retrans_segs:", v6.tcp_retrans_segs);
}

static void show_ddp_stats(struct seq_file *seq)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tp_usm_stats stats;

	spin_lock(&adap->stats_lock);
	t4_get_usm_stats(adap, &stats, false);
	spin_unlock(&adap->stats_lock);

	PRINT_ADAP_STATS("usm_ddp_frames:", stats.frames);
	PRINT_ADAP_STATS("usm_ddp_octets:", stats.octets);
	PRINT_ADAP_STATS("usm_ddp_drops:", stats.drops);
}

static void show_rdma_stats(struct seq_file *seq)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tp_rdma_stats stats = {0};

	spin_lock(&adap->stats_lock);
	t4_tp_get_rdma_stats(adap, &stats, false);
	spin_unlock(&adap->stats_lock);

#define SWAP_U64(value) (((value) >> 32) | ((value) << 32))

	PRINT_ADAP_STATS("rdma_no_rqe_mod_defer:", stats.rqe_dfr_mod);
	PRINT_ADAP_STATS("rdma_no_rqe_pkt_defer:", stats.rqe_dfr_pkt);

	seq_puts(seq, "\n--------RDMA Stats per Port--------\n");
	/* prints rdma stats per port */
	seq_printf(seq, "      Object: %10s %10s %10s %10s\n", "Port 0", "Port 1",
		   "Port 2", "port 3");
	seq_printf(seq, "recv packets: %10u %10u %10u %10u\n",
		   stats.pkts_in[0], stats.pkts_in[1], stats.pkts_in[2], stats.pkts_in[3]);
	seq_printf(seq, "  recv bytes: %10llu %10llu %10llu %10llu\n",
		   SWAP_U64(stats.bytes_in[0]), SWAP_U64(stats.bytes_in[1]),
		   SWAP_U64(stats.bytes_in[2]), SWAP_U64(stats.bytes_in[3]));
	seq_printf(seq, "send packets: %10u %10u %10u %10u\n",
		   stats.pkts_out[0], stats.pkts_out[1], stats.pkts_out[2], stats.pkts_out[3]);
	seq_printf(seq, "  send bytes: %10llu %10llu %10llu %10llu\n",
		   SWAP_U64(stats.bytes_out[0]), SWAP_U64(stats.bytes_out[1]),
		   SWAP_U64(stats.bytes_out[2]), SWAP_U64(stats.bytes_out[3]));

#undef SWAP_U64
}

static void show_tp_err_adapter_stats(struct seq_file *seq)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tp_err_stats stats;

	spin_lock(&adap->stats_lock);
	t4_tp_get_err_stats(adap, &stats, false);
	spin_unlock(&adap->stats_lock);

	PRINT_ADAP_STATS("tp_err_ofld_no_neigh:", stats.ofld_no_neigh);
	PRINT_ADAP_STATS("tp_err_ofld_cong_defer:", stats.ofld_cong_defer);
}

static void show_cpl_stats(struct seq_file *seq)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tp_cpl_stats stats;
	u8 i;

	spin_lock(&adap->stats_lock);
	t4_tp_get_cpl_stats(adap, &stats, false);
	spin_unlock(&adap->stats_lock);

	PRINT_CH_STATS("tp_cpl_requests:", req);
	PRINT_CH_STATS("tp_cpl_responses:", rsp);
}

static void show_tp_err_channel_stats(struct seq_file *seq)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tp_err_stats stats;
	u8 i;

	spin_lock(&adap->stats_lock);
	t4_tp_get_err_stats(adap, &stats, false);
	spin_unlock(&adap->stats_lock);

	PRINT_CH_STATS("tp_mac_in_errs:", mac_in_errs);
	PRINT_CH_STATS("tp_hdr_in_errs:", hdr_in_errs);
	PRINT_CH_STATS("tp_tcp_in_errs:", tcp_in_errs);
	PRINT_CH_STATS("tp_tcp6_in_errs:", tcp6_in_errs);
	PRINT_CH_STATS("tp_tnl_cong_drops:", tnl_cong_drops);
	PRINT_CH_STATS("tp_tnl_tx_drops:", tnl_tx_drops);
	PRINT_CH_STATS("tp_ofld_vlan_drops:", ofld_vlan_drops);
	PRINT_CH_STATS("tp_ofld_chan_drops:", ofld_chan_drops);
}

static void show_fcoe_stats(struct seq_file *seq)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct tp_fcoe_stats stats[NCHAN];
	u8 i;

	spin_lock(&adap->stats_lock);
	for (i = 0; i < adap->params.arch.nchan; i++)
		t4_get_fcoe_stats(adap, i, &stats[i], false);
	spin_unlock(&adap->stats_lock);

	PRINT_CH_STATS2("fcoe_octets_ddp", octets_ddp);
	PRINT_CH_STATS2("fcoe_frames_ddp", frames_ddp);
	PRINT_CH_STATS2("fcoe_frames_drop", frames_drop);
}

#undef PRINT_CH_STATS2
#undef PRINT_CH_STATS
#undef PRINT_ADAP_STATS

static int tp_stats_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;

	seq_puts(seq, "\n--------Adapter Stats--------\n");
	show_tcp_stats(seq);
	show_ddp_stats(seq);
	show_tp_err_adapter_stats(seq);
	show_rdma_stats(seq);

	seq_puts(seq, "\n-------- Channel Stats --------\n");
	if (adap->params.arch.nchan == NCHAN)
		seq_printf(seq, "%-25s %-20s %-20s %-20s %-20s\n",
			   " ", "channel 0", "channel 1",
			   "channel 2", "channel 3");
	else
		seq_printf(seq, "%-25s %-20s %-20s\n",
			   " ", "channel 0", "channel 1");
	show_cpl_stats(seq);
	show_tp_err_channel_stats(seq);
	show_fcoe_stats(seq);

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(tp_stats);

/*
 * Show the PM memory stats.  These stats include:
 *
 * TX:
 *   Read: memory read operation
 *   Write Bypass: cut-through
 *   Bypass + mem: cut-through and save copy
 * 
 * RX:
 *   Read: memory read
 *   Write Bypass: cut-through
 *   Flush: payload trim or drop
 */
static int pm_stats_show(struct seq_file *seq, void *v)
{
	static const char *tx_pm_stats[] = {
		"Read:", "Write bypass:", "Write mem:", "Bypass + mem:"
	};
	static const char *rx_pm_stats[] = {
		"Read:", "Write bypass:", "Write mem:", "Flush:"
	};
	u32 tx_cnt[T6_PM_NSTATS], rx_cnt[T6_PM_NSTATS];
	u64 tx_cyc[T6_PM_NSTATS], rx_cyc[T6_PM_NSTATS];
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	int i;

	t4_pmtx_get_stats(adap, tx_cnt, tx_cyc);
	t4_pmrx_get_stats(adap, rx_cnt, rx_cyc);

	seq_printf(seq, "%13s %10s  %20s\n", " ", "Tx pcmds", "Tx bytes");
	for (i = 0; i < PM_NSTATS - 1; i++)
		seq_printf(seq, "%-13s %10u  %20llu\n",
			   tx_pm_stats[i], tx_cnt[i], tx_cyc[i]);

	seq_printf(seq, "%13s %10s  %20s\n", " ", "Rx pcmds", "Rx bytes");
	for (i = 0; i < PM_NSTATS - 1; i++)
		seq_printf(seq, "%-13s %10u  %20llu\n",
			   rx_pm_stats[i], rx_cnt[i], rx_cyc[i]);

	if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T5) {
		/* In T5 the granularity of the total wait is too fine.
		 * It is not useful as it reaches the max value too fast.
		 * Hence display this Input FIFO wait for T6 onwards.
		 */
		seq_printf(seq, "%13s %10s  %20s\n",
			   " ", "Total wait", "Total Occupancy");
		seq_printf(seq, "Tx FIFO wait  %10u  %20llu\n",
			   tx_cnt[i], tx_cyc[i]);
		seq_printf(seq, "Rx FIFO wait  %10u  %20llu\n",
			   rx_cnt[i], rx_cyc[i]);

		/* Skip index 6 as there is nothing useful ihere */
		i += 2;

		/* At index 7, a new stat for read latency (count, total wait)
		 * is added.
		 */
		seq_printf(seq, "%13s %10s  %20s\n",
			   " ", "Reads", "Total wait");
		seq_printf(seq, "Tx latency    %10u  %20llu\n",
			   tx_cnt[i], tx_cyc[i]);
		seq_printf(seq, "Rx latency    %10u  %20llu\n",
			   rx_cnt[i], rx_cyc[i]);
	}

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) {
		u32 stats[T7_PM_RX_CACHE_NSTATS];

		t4_pmrx_cache_get_stats(adap, stats);

		i = 0;
		seq_printf(seq, "\n\nPM RX Cache Stats\n");
		seq_printf(seq, "%-40s    %u\n", "ReqWrite", stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "ReqReadInv", stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "ReqReadNoInv", stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Write Split Request",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "Normal Read Split (Read Invalidate)", stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "Feedback Read Split (Read NoInvalidate)",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Write Hit", stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Normal Read Hit",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Feedback Read Hit",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Normal Read Hit Full Avail",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Normal Read Hit Full UnAvail",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "Normal Read Hit Partial Avail",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "FB Read Hit Full Avail",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "FB Read Hit Full UnAvail",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "FB Read Hit Partial Avail",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Normal Read Full Free",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "Normal Read Part-avail Mul-Regions",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "FB Read Part-avail Mul-Regions",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Write Miss FL Used",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Write Miss LRU Used",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "Write Miss LRU-Multiple Evict", stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "Write Hit Increasing Islands", stats[i++]);
		seq_printf(seq, "%-40s    %u\n",
			   "Normal Read Island Read split", stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Write Overflow Eviction",
			   stats[i++]);
		seq_printf(seq, "%-40s    %u\n", "Read Overflow Eviction",
			   stats[i++]);
	}

	return 0;
}

static int pm_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, pm_stats_show, inode->i_private);
}

static ssize_t pm_stats_clear(struct file *file, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter *adap = d->adap;

	t4_write_reg(adap, A_PM_RX_STAT_CONFIG, 0);
	t4_write_reg(adap, A_PM_TX_STAT_CONFIG, 0);
	return count;
}

static const struct file_operations pm_stats_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = pm_stats_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = pm_stats_clear
};


static int tx_rate_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	u64 nrate[NCHAN], orate[NCHAN];

	t4_get_chan_txrate(adap, nrate, orate);
	if (adap->params.arch.nchan == NCHAN) {
		seq_puts(seq, "              channel 0   channel 1   "
			 "channel 2   channel 3\n");
		seq_printf(seq, "NIC B/s:     %10llu  %10llu  %10llu  %10llu\n",
			   (unsigned long long)nrate[0],
			   (unsigned long long)nrate[1],
			   (unsigned long long)nrate[2],
			   (unsigned long long)nrate[3]);
		seq_printf(seq, "Offload B/s: %10llu  %10llu  %10llu  %10llu\n",
			   (unsigned long long)orate[0],
			   (unsigned long long)orate[1],
			   (unsigned long long)orate[2],
			   (unsigned long long)orate[3]);
	} else {
		seq_puts(seq, "              channel 0   channel 1\n");
		seq_printf(seq, "NIC B/s:     %10llu  %10llu\n",
			   (unsigned long long)nrate[0],
			   (unsigned long long)nrate[1]);
		seq_printf(seq, "Offload B/s: %10llu  %10llu\n",
			   (unsigned long long)orate[0],
			   (unsigned long long)orate[1]);
	}
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(tx_rate);

static int sched_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	unsigned int map, kbps, ipg, mode;
	unsigned int pace_tab[NTX_SCHED];
	struct adapter *adap = d->adap;
	int i;

	map = t4_read_reg(adap, A_TP_TX_MOD_QUEUE_REQ_MAP);
	mode = G_TIMERMODE(t4_read_reg(adap, A_TP_MOD_CONFIG));
	t4_read_pace_tbl(adap, pace_tab);

	seq_printf(seq, "Scheduler  Mode   Channel  Rate (Kbps)   "
		      "Class IPG (0.1 ns)   Flow IPG (us)\n");
	for (i = 0; i < NTX_SCHED; ++i, map >>= 2) {
		t4_get_tx_sched(adap, i, &kbps, &ipg, true);
		seq_printf(seq, "    %u      %-5s     %u     ", i,
			   (mode & (1 << i)) ? "flow" : "class", map & 3);
		if (kbps)
			seq_printf(seq, "%9u     ", kbps);
		else
			seq_puts(seq, " disabled     ");

		if (ipg)
			seq_printf(seq, "%13u        ", ipg);
		else
			seq_puts(seq, "     disabled        ");

		if (pace_tab[i])
			seq_printf(seq, "%10u\n", pace_tab[i]);
		else
			seq_puts(seq, "  disabled\n");
	}
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(sched);

static int cctrl_tbl_show(struct seq_file *seq, void *v)
{
	static const char *dec_fac[] = {
		"0.5", "0.5625", "0.625", "0.6875", "0.75", "0.8125", "0.875",
		"0.9375"
	};
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	u16 (*incr)[NCCTRL_WIN];
	int i;

	incr = kmalloc(sizeof(*incr) * NMTUS, GFP_KERNEL);
	if (!incr)
		return -ENOMEM;

	t4_read_cong_tbl(adap, incr);

	for (i = 0; i < NCCTRL_WIN; ++i) {
		seq_printf(seq, "%2d: %4u %4u %4u %4u %4u %4u %4u %4u\n", i,
			   incr[0][i], incr[1][i], incr[2][i], incr[3][i],
			   incr[4][i], incr[5][i], incr[6][i], incr[7][i]);
                seq_printf(seq, "%8u %4u %4u %4u %4u %4u %4u %4u %5u %s\n",
			   incr[8][i], incr[9][i], incr[10][i], incr[11][i],
			   incr[12][i], incr[13][i], incr[14][i], incr[15][i],
			   adap->params.a_wnd[i],
			   dec_fac[adap->params.b_wnd[i]]);
	}

	kfree(incr);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(cctrl_tbl);

/*
 * RSS Table.
 */

static int rss_show(struct seq_file *seq, void *v, int idx)
{
	u16 *entry = v;

	seq_printf(seq, "%4d:  %4u  %4u  %4u  %4u  %4u  %4u  %4u  %4u\n",
		   idx * 8, entry[0], entry[1], entry[2], entry[3], entry[4],
		   entry[5], entry[6], entry[7]);
	return 0;
}

static int rss_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct seq_tab *p;
	int ret, nentries;

	nentries = t4_chip_rss_size(adap);
	p = seq_open_tab(file, nentries / 8, 8 * sizeof(u16), 0, rss_show);
	if (!p)
		return -ENOMEM;

	ret = t4_read_rss(adap, (u16 *)p->data);
	if (ret)
		seq_release_private(inode, file);

	return ret;
}

static const struct file_operations rss_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = rss_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

/*
 * RSS Configuration.
 */

/*
 * Small utility function to return the strings "yes" or "no" if the supplied
 * argument is non-zero.
 */
static const char *yesno(int x)
{
	static const char *yes = "yes";
	static const char *no = "no";
	return x ? yes : no;
}

static int rss_config_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	static const char *keymode[] = {
		"global",
		"global and per-VF scramble",
		"per-PF and per-VF scramble",
		"per-VF and per-VF scramble",
	};
	u32 rssconf;

	rssconf = t4_read_reg(adap, A_TP_RSS_CONFIG);
	seq_printf(seq, "TP_RSS_CONFIG: %#x\n", rssconf);
	seq_printf(seq, "  Tnl4TupEnIpv6: %3s\n", yesno(rssconf & F_TNL4TUPENIPV6));
	seq_printf(seq, "  Tnl2TupEnIpv6: %3s\n", yesno(rssconf & F_TNL2TUPENIPV6));
	seq_printf(seq, "  Tnl4TupEnIpv4: %3s\n", yesno(rssconf & F_TNL4TUPENIPV4));
	seq_printf(seq, "  Tnl2TupEnIpv4: %3s\n", yesno(rssconf & F_TNL2TUPENIPV4));
	seq_printf(seq, "  TnlTcpSel:     %3s\n", yesno(rssconf & F_TNLTCPSEL));
	seq_printf(seq, "  TnlIp6Sel:     %3s\n", yesno(rssconf & F_TNLIP6SEL));
	seq_printf(seq, "  TnlVrtSel:     %3s\n", yesno(rssconf & F_TNLVRTSEL));
	seq_printf(seq, "  TnlMapEn:      %3s\n", yesno(rssconf & F_TNLMAPEN));
	seq_printf(seq, "  OfdHashSave:   %3s\n", yesno(rssconf & F_OFDHASHSAVE));
	seq_printf(seq, "  OfdVrtSel:     %3s\n", yesno(rssconf & F_OFDVRTSEL));
	seq_printf(seq, "  OfdMapEn:      %3s\n", yesno(rssconf & F_OFDMAPEN));
	seq_printf(seq, "  OfdLkpEn:      %3s\n", yesno(rssconf & F_OFDLKPEN));
	seq_printf(seq, "  Syn4TupEnIpv6: %3s\n", yesno(rssconf & F_SYN4TUPENIPV6));
	seq_printf(seq, "  Syn2TupEnIpv6: %3s\n", yesno(rssconf & F_SYN2TUPENIPV6));
	seq_printf(seq, "  Syn4TupEnIpv4: %3s\n", yesno(rssconf & F_SYN4TUPENIPV4));
	seq_printf(seq, "  Syn2TupEnIpv4: %3s\n", yesno(rssconf & F_SYN2TUPENIPV4));
	seq_printf(seq, "  Syn4TupEnIpv6: %3s\n", yesno(rssconf & F_SYN4TUPENIPV6));
	seq_printf(seq, "  SynIp6Sel:     %3s\n", yesno(rssconf & F_SYNIP6SEL));
	seq_printf(seq, "  SynVrt6Sel:    %3s\n", yesno(rssconf & F_SYNVRTSEL));
	seq_printf(seq, "  SynMapEn:      %3s\n", yesno(rssconf & F_SYNMAPEN));
	seq_printf(seq, "  SynLkpEn:      %3s\n", yesno(rssconf & F_SYNLKPEN));
	seq_printf(seq, "  ChnEn:         %3s\n", yesno(rssconf & F_CHANNELENABLE));
	seq_printf(seq, "  PrtEn:         %3s\n", yesno(rssconf & F_PORTENABLE));
	seq_printf(seq, "  TnlAllLkp:     %3s\n", yesno(rssconf & F_TNLALLLOOKUP));
	seq_printf(seq, "  VrtEn:         %3s\n", yesno(rssconf & F_VIRTENABLE));
	seq_printf(seq, "  CngEn:         %3s\n", yesno(rssconf & F_CONGESTIONENABLE));
	seq_printf(seq, "  HashToeplitz:  %3s\n", yesno(rssconf & F_HASHTOEPLITZ));
	seq_printf(seq, "  Udp4En:        %3s\n", yesno(rssconf & F_UDPENABLE));
	seq_printf(seq, "  Disable:       %3s\n", yesno(rssconf & F_DISABLE));

	seq_puts(seq, "\n");

	rssconf = t4_read_reg(adap, A_TP_RSS_CONFIG_TNL);
	seq_printf(seq, "TP_RSS_CONFIG_TNL: %#x\n", rssconf);
	seq_printf(seq, "  MaskSize:      %3d\n", G_MASKSIZE(rssconf));
	seq_printf(seq, "  MaskFilter:    %3d\n", G_MASKFILTER(rssconf));
	if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T5) {
		seq_printf(seq, "  HashAll:     %3s\n",
			   yesno(rssconf & F_HASHALL));
		seq_printf(seq, "  HashEth:     %3s\n",
			   yesno(rssconf & F_HASHETH));
	}
	seq_printf(seq, "  UseWireCh:     %3s\n", yesno(rssconf & F_USEWIRECH));

	seq_puts(seq, "\n");

	rssconf = t4_read_reg(adap, A_TP_RSS_CONFIG_OFD);
	seq_printf(seq, "TP_RSS_CONFIG_OFD: %#x\n", rssconf);
	seq_printf(seq, "  MaskSize:      %3d\n", G_MASKSIZE(rssconf));
	seq_printf(seq, "  RRCplMapEn:    %3s\n", yesno(rssconf & F_RRCPLMAPEN));
	seq_printf(seq, "  RRCplQueWidth: %3d\n", G_RRCPLQUEWIDTH(rssconf));

	seq_puts(seq, "\n");

	rssconf = t4_read_reg(adap, A_TP_RSS_CONFIG_SYN);
	seq_printf(seq, "TP_RSS_CONFIG_SYN: %#x\n", rssconf);
	seq_printf(seq, "  MaskSize:      %3d\n", G_MASKSIZE(rssconf));
	seq_printf(seq, "  UseWireCh:     %3s\n", yesno(rssconf & F_USEWIRECH));

	seq_puts(seq, "\n");

	rssconf = t4_read_reg(adap, A_TP_RSS_CONFIG_VRT);
	seq_printf(seq, "TP_RSS_CONFIG_VRT: %#x\n", rssconf);
	if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T5) {
		seq_printf(seq, "  KeyWrAddrX:     %3d\n",
			   G_KEYWRADDRX(rssconf));
		seq_printf(seq, "  KeyExtend:      %3s\n",
			   yesno(rssconf & F_KEYEXTEND));
	}
	seq_printf(seq, "  VfRdRg:        %3s\n", yesno(rssconf & F_VFRDRG));
	seq_printf(seq, "  VfRdEn:        %3s\n", yesno(rssconf & F_VFRDEN));
	seq_printf(seq, "  VfPerrEn:      %3s\n", yesno(rssconf & F_VFPERREN));
	seq_printf(seq, "  KeyPerrEn:     %3s\n", yesno(rssconf & F_KEYPERREN));
	seq_printf(seq, "  DisVfVlan:     %3s\n", yesno(rssconf & F_DISABLEVLAN));
	seq_printf(seq, "  EnUpSwt:       %3s\n", yesno(rssconf & F_ENABLEUP0));
	seq_printf(seq, "  HashDelay:     %3d\n", G_HASHDELAY(rssconf));
	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5)
		seq_printf(seq, "  VfWrAddr:      %3d\n", G_VFWRADDR(rssconf));
	else
		seq_printf(seq, "  VfWrAddr:      %3d\n",
			   G_T6_VFWRADDR(rssconf));
	seq_printf(seq, "  KeyMode:       %s\n", keymode[G_KEYMODE(rssconf)]);
	seq_printf(seq, "  VfWrEn:        %3s\n", yesno(rssconf & F_VFWREN));
	seq_printf(seq, "  KeyWrEn:       %3s\n", yesno(rssconf & F_KEYWREN));
	seq_printf(seq, "  KeyWrAddr:     %3d\n", G_KEYWRADDR(rssconf));

	seq_puts(seq, "\n");

	rssconf = t4_read_reg(adap, A_TP_RSS_CONFIG_CNG);
	seq_printf(seq, "TP_RSS_CONFIG_CNG: %#x\n", rssconf);
	seq_printf(seq, "  ChnCount3:     %3s\n", yesno(rssconf & F_CHNCOUNT3));
	seq_printf(seq, "  ChnCount2:     %3s\n", yesno(rssconf & F_CHNCOUNT2));
	seq_printf(seq, "  ChnCount1:     %3s\n", yesno(rssconf & F_CHNCOUNT1));
	seq_printf(seq, "  ChnCount0:     %3s\n", yesno(rssconf & F_CHNCOUNT0));
	seq_printf(seq, "  ChnUndFlow3:   %3s\n", yesno(rssconf & F_CHNUNDFLOW3));
	seq_printf(seq, "  ChnUndFlow2:   %3s\n", yesno(rssconf & F_CHNUNDFLOW2));
	seq_printf(seq, "  ChnUndFlow1:   %3s\n", yesno(rssconf & F_CHNUNDFLOW1));
	seq_printf(seq, "  ChnUndFlow0:   %3s\n", yesno(rssconf & F_CHNUNDFLOW0));
	seq_printf(seq, "  RstChn3:       %3s\n", yesno(rssconf & F_RSTCHN3));
	seq_printf(seq, "  RstChn2:       %3s\n", yesno(rssconf & F_RSTCHN2));
	seq_printf(seq, "  RstChn1:       %3s\n", yesno(rssconf & F_RSTCHN1));
	seq_printf(seq, "  RstChn0:       %3s\n", yesno(rssconf & F_RSTCHN0));
	seq_printf(seq, "  UpdVld:        %3s\n", yesno(rssconf & F_UPDVLD));
	seq_printf(seq, "  Xoff:          %3s\n", yesno(rssconf & F_XOFF));
	seq_printf(seq, "  UpdChn3:       %3s\n", yesno(rssconf & F_UPDCHN3));
	seq_printf(seq, "  UpdChn2:       %3s\n", yesno(rssconf & F_UPDCHN2));
	seq_printf(seq, "  UpdChn1:       %3s\n", yesno(rssconf & F_UPDCHN1));
	seq_printf(seq, "  UpdChn0:       %3s\n", yesno(rssconf & F_UPDCHN0));
	seq_printf(seq, "  Queue:         %3d\n", G_QUEUE(rssconf));

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(rss_config);

/*
 * RSS Secret Key.
 */

static int rss_key_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	u32 key[10];

	t4_read_rss_key(adap, key, true);
	seq_printf(seq, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n",
		   key[9], key[8], key[7], key[6], key[5], key[4], key[3],
		   key[2], key[1], key[0]);
	return 0;
}

static int rss_key_open(struct inode *inode, struct file *file)
{
	return single_open(file, rss_key_show, inode->i_private);
}

static ssize_t rss_key_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct t4_linux_debugfs_data *d = file_inode(file)->i_private;
	struct adapter *adap = d->adap;
	char s[100], *p;
	u32 key[10];
	int i, j;

	if (count > sizeof(s) - 1)
		return -EINVAL;
	if (copy_from_user(s, buf, count))
		return -EFAULT;
	for (i = count; i > 0 && isspace(s[i - 1]); i--)
		;
	s[i] = '\0';

	for (p = s, i = 9; i >= 0; i--) {
		key[i] = 0;
		for (j = 0; j < 8; j++, p++) {
			if (!isxdigit(*p))
				return -EINVAL;
			key[i] = (key[i] << 4) | hex2val(*p);
		}
	}

	t4_write_rss_key(adap, key, -1, true);
	return count;
}

static const struct file_operations rss_key_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = rss_key_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = rss_key_write
};

/*
 * PF RSS Configuration.
 */

struct rss_pf_conf {
	u32 rss_pf_map;
	u32 rss_pf_mask;
	u32 rss_pf_config;
};

static int rss_pf_config_show(struct seq_file *seq, void *v, int idx)
{
	struct rss_pf_conf *pfconf;

	if (v == SEQ_START_TOKEN) {
	/* use the 0th entry to dump the PF Map Index Size */
	pfconf = seq->private + offsetof(struct seq_tab, data);
	seq_printf(seq, "PF Map Index Size = %d\n\n",
		   G_LKPIDXSIZE(pfconf->rss_pf_map));

	seq_puts(seq, "     RSS              PF   VF    Hash Tuple Enable         Default\n");
	seq_puts(seq, "     Enable       IPF Mask Mask  IPv6      IPv4      UDP   Queue\n");
	seq_puts(seq, " PF  Map Chn Prt  Map Size Size  Four Two  Four Two  Four  Ch1  Ch0\n");
	} else {
		#define G_PFnLKPIDX(map, n) \
			(((map) >> S_PF1LKPIDX*(n)) & M_PF0LKPIDX)
		#define G_PFnMSKSIZE(mask, n) \
			(((mask) >> S_PF1MSKSIZE*(n)) & M_PF1MSKSIZE)

		pfconf = v;
		seq_printf(seq, "%3d  %3s %3s %3s  %3d  %3d  %3d   %3s %3s   %3s %3s   %3s  %3d  %3d\n",
			   idx,
			   yesno(pfconf->rss_pf_config & F_MAPENABLE),
			   yesno(pfconf->rss_pf_config & F_CHNENABLE),
			   yesno(pfconf->rss_pf_config & F_PRTENABLE),
			   G_PFnLKPIDX(pfconf->rss_pf_map, idx),
			   G_PFnMSKSIZE(pfconf->rss_pf_mask, idx),
			   G_IVFWIDTH(pfconf->rss_pf_config),
			   yesno(pfconf->rss_pf_config & F_IP6FOURTUPEN),
			   yesno(pfconf->rss_pf_config & F_IP6TWOTUPEN),
			   yesno(pfconf->rss_pf_config & F_IP4FOURTUPEN),
			   yesno(pfconf->rss_pf_config & F_IP4TWOTUPEN),
			   yesno(pfconf->rss_pf_config & F_UDPFOURTUPEN),
			   G_CH1DEFAULTQUEUE(pfconf->rss_pf_config),
			   G_CH0DEFAULTQUEUE(pfconf->rss_pf_config));

		#undef G_PFnLKPIDX
		#undef G_PFnMSKSIZE
	}
	return 0;
}

static int rss_pf_config_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	u32 rss_pf_map, rss_pf_mask;
	struct rss_pf_conf *pfconf;
	struct seq_tab *p;
	int pf;

	p = seq_open_tab(file, 8, sizeof(*pfconf), 1, rss_pf_config_show);
	if (!p)
		return -ENOMEM;

	pfconf = (struct rss_pf_conf *)p->data;
	rss_pf_map = t4_read_rss_pf_map(adap, true);
	rss_pf_mask = t4_read_rss_pf_mask(adap, true);
	for (pf = 0; pf < 8; pf++) {
		pfconf[pf].rss_pf_map = rss_pf_map;
		pfconf[pf].rss_pf_mask = rss_pf_mask;
		t4_read_rss_pf_config(adap, pf, &pfconf[pf].rss_pf_config,
				      true);
	}
	return 0;
}

static const struct file_operations rss_pf_config_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = rss_pf_config_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

/*
 * VF RSS Configuration.
 */

struct rss_vf_conf {
	u32 rss_vf_vfl;
	u32 rss_vf_vfh;
};

static int rss_vf_config_show(struct seq_file *seq, void *v, int idx)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "     RSS                     Hash Tuple Enable\n");
		seq_puts(seq, "     Enable   IVF  Dis  Enb  IPv6      IPv4      UDP    Def  Secret Key\n");
		seq_puts(seq, " VF  Chn Prt  Map  VLAN  uP  Four Two  Four Two  Four   Que  Idx       Hash\n");
	} else {
		struct rss_vf_conf *vfconf = v;
		seq_printf(seq, "%3d  %3s %3s  %3d   %3s %3s   %3s %3s   %3s %3s   %3s  %4d  %3d %#10x\n",
			   idx,
			   yesno(vfconf->rss_vf_vfh & F_VFCHNEN),
			   yesno(vfconf->rss_vf_vfh & F_VFPRTEN),
			   G_VFLKPIDX(vfconf->rss_vf_vfh),
			   yesno(vfconf->rss_vf_vfh & F_VFVLNEX),
			   yesno(vfconf->rss_vf_vfh & F_VFUPEN),
			   yesno(vfconf->rss_vf_vfh & F_VFIP4FOURTUPEN),
			   yesno(vfconf->rss_vf_vfh & F_VFIP6TWOTUPEN),
			   yesno(vfconf->rss_vf_vfh & F_VFIP4FOURTUPEN),
			   yesno(vfconf->rss_vf_vfh & F_VFIP4TWOTUPEN),
			   yesno(vfconf->rss_vf_vfh & F_ENABLEUDPHASH),
			   G_DEFAULTQUEUE(vfconf->rss_vf_vfh),
			   G_KEYINDEX(vfconf->rss_vf_vfh),
			   vfconf->rss_vf_vfl);
	}
	return 0;
}

static int rss_vf_config_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	struct rss_vf_conf *vfconf;
	struct seq_tab *p;
	int vf, vfcount;

	vfcount = adap->params.arch.vfcount;
	p = seq_open_tab(file, vfcount, sizeof(*vfconf), 1, rss_vf_config_show);
	if (!p)
		return -ENOMEM;

	vfconf = (struct rss_vf_conf *)p->data;
	for (vf = 0; vf < vfcount; vf++) {
		t4_read_rss_vf_config(adap, vf, &vfconf[vf].rss_vf_vfl,
				      &vfconf[vf].rss_vf_vfh, true);
	}
	return 0;
}

static const struct file_operations rss_vf_config_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = rss_vf_config_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};


#if DMABUF

static ssize_t dma_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct t4_linux_debugfs_data *d = file->private_data;
	const struct adapter *adap = d->adap;

	return simple_read_from_buffer(buf, count, ppos, adap->dma_virt,
				       DMABUF_SZ);
}

static ssize_t dma_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	struct t4_linux_debugfs_data *d = file->private_data;
	const struct adapter *adap = d->adap;
	size_t avail = DMABUF_SZ;
	loff_t pos = *ppos;

	file_inode(file)->i_size = avail;
	if (pos < 0)
		return -EINVAL;
	if (pos >= avail)
		return 0;
	if (count > avail - pos)
		count = avail - pos;
	if (copy_from_user(adap->dma_virt + pos, buf, count))
		return -EFAULT;
	*ppos = pos + count;
	return count;
}

static const struct file_operations dma_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mem_open,
	.read    = dma_read,
	.write   = dma_write
};
#endif

#ifdef T4_TRACE
void alloc_trace_bufs(struct adapter *adap)
{
	int i;
	char s[32];

	for (i = 0; i < ARRAY_SIZE(adap->tb); ++i) {
		sprintf(s, "sge_q%d", i);
		adap->tb[i] = t4_trace_alloc(adap->debugfs_root, s, 512);
	}
}

void free_trace_bufs(struct adapter *adap)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(adap->tb); ++i)
		t4_trace_free(adap->tb[i]);
}
#endif

struct mem_desc {
	u64 base;
	u64 limit;
	u32 idx;
};

static int mem_desc_cmp(const void *a, const void *b)
{
	return (((const struct mem_desc *)a)->base <
		((const struct mem_desc *)b)->base) ? -1 : 1;
}

static void mem_region_show(struct seq_file *seq, const char *name,
			    u64 from, u64 to)
{
	char buf[40];


	string_get_size((u64)to - from + 1, 1, STRING_UNITS_2, buf,
			sizeof(buf));
	
	seq_printf(seq, "%-20s %#llx-%#llx [%s]\n", name, from, to, buf);
}

static int meminfo_show(struct seq_file *seq, void *v)
{
	static const char *memory[] = { "EDC0:", "EDC1:", "MC:",
					"MC0:", "MC1:", "HMA:"};
	static const char *region[] = {
		"DBQ contexts:", "IMSG contexts:", "FLM cache:", "TCBs:",
		"Pstructs:", "Timers:", "Rx FL:", "Tx FL:", "Pstruct FL:",
		"Tx payload:", "Rx payload:", "LE hash:", "iSCSI region:",
		"TDDP region:", "TPT region:", "STAG region:", "RQ region:",
		"RQUDP region:", "PBL region:", "TXPBL region:",
		"TLSKey region:", "RRQ region:", "NVMe STAG region:",
		"NVMe RQ region:", "NVMe RXPBL region:", "NVMe TPT region:",
		"NVMe TXPBL region:", "DBVFIFO region:", "ULPRX state:",
		"ULPTX state:", "RoCE RRQ region:",
#ifndef __NO_DRIVER_OCQ_SUPPORT__
		"On-chip queues:"
#endif
	};
	u32 lo, hi, used, alloc, chip_ver, free_rx_cnt, free_tx_cnt, nchan;
	struct t4_linux_debugfs_data *d = seq->private;
	struct mem_desc *mem;
	struct adapter *adap = d->adap;
	struct mem_desc *md;
	struct mem_desc avail[4];
	int i, n, size;

	size = ARRAY_SIZE(region) + 3;                   /* up to 3 holes */

	mem = kmalloc(sizeof(struct mem_desc) * size, GFP_KERNEL);
	if(!mem)
		return -ENOMEM;

	md = mem;

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	for (i = 0; i < size; i++) {
		mem[i].limit = 0;
		mem[i].idx = i;
	}

	/* Find and sort the populated memory ranges */
	i = 0;
	lo = t4_read_reg(adap, A_MA_TARGET_MEM_ENABLE);
	if (lo & F_EDRAM0_ENABLE) {
		hi = t4_read_reg(adap, A_MA_EDRAM0_BAR);
		avail[i].base = G_T7_EDRAM0_BASE(hi) << 20;
		avail[i].limit = avail[i].base +
				 (G_T7_EDRAM0_SIZE(hi) << 20);
		avail[i].idx = 0;
		i++;
	}

	if (lo & F_EDRAM1_ENABLE) {
		hi = t4_read_reg(adap, A_MA_EDRAM1_BAR);
		avail[i].base = G_T7_EDRAM1_BASE(hi) << 20;
		avail[i].limit = avail[i].base +
				 (G_T7_EDRAM1_SIZE(hi) << 20);
		avail[i].idx = 1;
		i++;
	}

	if (lo & F_EXT_MEM_ENABLE) {
		switch (chip_ver) {
		case CHELSIO_T4:
		case CHELSIO_T6:
			hi = t4_read_reg(adap, A_MA_EXT_MEMORY_BAR);
			avail[i].base = G_EXT_MEM_BASE(hi) << 20;
			avail[i].limit = avail[i].base +
					 (G_EXT_MEM_SIZE(hi) << 20);
			avail[i].idx = 2;
			i++;
			break;
		default:
			hi = t4_read_reg(adap, A_MA_EXT_MEMORY0_BAR);
			avail[i].base = (u64)G_T7_EXT_MEM0_BASE(hi) << 20;
			avail[i].limit = avail[i].base +
					 ((u64)G_T7_EXT_MEM0_SIZE(hi) << 20);
			avail[i].idx = 3;
			i++;
			break;
		}
	}

	if (lo & F_EXT_MEM1_ENABLE) {
		switch (chip_ver) {
		case CHELSIO_T4:
		case CHELSIO_T6:
			/* No support for mc1 */
			break;
		default:
			/* No mc1 when split mode enabled */
			if (lo & F_MC_SPLIT)
				break;

			hi = t4_read_reg(adap, A_MA_EXT_MEMORY1_BAR);
			avail[i].base = (u64)G_T7_EXT_MEM1_BASE(hi) << 20;
			avail[i].limit = avail[i].base +
					 ((u64)G_T7_EXT_MEM1_SIZE(hi) << 20);
			avail[i].idx = 4;
			i++;
			break;
		}
	}

	if (lo & F_HMA_MUX) {
		switch (chip_ver) {
		case CHELSIO_T4:
		case CHELSIO_T5:
		       	/* No support for hma */
			break;
		case CHELSIO_T6:
			hi = t4_read_reg(adap, A_MA_EXT_MEMORY1_BAR);
			avail[i].base = G_EXT_MEM1_BASE(hi) << 20;
			avail[i].limit = avail[i].base +
					 (G_EXT_MEM1_SIZE(hi) << 20);
			avail[i].idx = 5;
			i++;
			break;
		default:
			hi = t4_read_reg(adap, A_MA_HOST_MEMORY_BAR);
			avail[i].base = (u64)G_HMATARGETBASE(hi) << 20;
			avail[i].limit = avail[i].base +
					 ((u64)G_T7_HMA_SIZE(hi) << 20);
			avail[i].idx = 5;
			i++;
			break;
		}
	}

	if (!i)                                    /* no memory available */
		goto out;

	sort(avail, i, sizeof(struct mem_desc), mem_desc_cmp, NULL);

	(md++)->base = t4_read_reg(adap, A_SGE_DBQ_CTXT_BADDR);
	(md++)->base = t4_read_reg(adap, A_SGE_IMSG_CTXT_BADDR);
	(md++)->base = t4_read_reg(adap, A_SGE_FLM_CACHE_BADDR);
	(md++)->base = t4_read_reg(adap, A_TP_CMM_TCB_BASE);
	(md++)->base = t4_read_reg(adap, A_TP_CMM_MM_BASE);
	(md++)->base = t4_read_reg(adap, A_TP_CMM_TIMER_BASE);
	(md++)->base = t4_read_reg(adap, A_TP_CMM_MM_RX_FLST_BASE);
	(md++)->base = t4_read_reg(adap, A_TP_CMM_MM_TX_FLST_BASE);
	(md++)->base = t4_read_reg(adap, A_TP_CMM_MM_PS_FLST_BASE);

	/* the next few have explicit upper bounds */
	md->base = t4_read_reg(adap, A_TP_PMM_TX_BASE);
	md->limit = md->base - 1 +
		    t4_read_reg(adap, A_TP_PMM_TX_PAGE_SIZE) *
		    G_PMTXMAXPAGE(t4_read_reg(adap, A_TP_PMM_TX_MAX_PAGE));
	md++;

	md->base = t4_read_reg(adap, A_TP_PMM_RX_BASE);
	md->limit = md->base - 1 +
		    t4_read_reg(adap, A_TP_PMM_RX_PAGE_SIZE) *
		    G_PMRXMAXPAGE(t4_read_reg(adap, A_TP_PMM_RX_MAX_PAGE));
	md++;

	if (t4_read_reg(adap, A_LE_DB_CONFIG) & F_HASHEN) {
		if (chip_ver <= CHELSIO_T5) {
			hi = t4_read_reg(adap, A_LE_DB_TID_HASHBASE) / 4;
			md->base = t4_read_reg(adap, A_LE_DB_HASH_TID_BASE);
		 } else {
			hi = t4_read_reg(adap, A_LE_DB_HASH_TID_BASE);
			md->base = t4_read_reg(adap,
					       A_LE_DB_HASH_TBL_BASE_ADDR);
		}
		md->limit = 0;
	} else {
		md->base = 0;
		md->idx = ARRAY_SIZE(region);  /* hide it */
	}
	md++;

#define ulp_region(reg) do { \
	(md)->base = t4_read_reg(adap, A_ULP_ ## reg ## _LLIMIT); \
	if (chip_ver >= CHELSIO_T7) { \
		(md)->base = (u64)(md)->base << 4; \
	} \
	(md)->limit = t4_read_reg(adap, A_ULP_ ## reg ## _ULIMIT); \
	if (chip_ver >= CHELSIO_T7) { \
		(md)->limit = ((u64)((md)->limit + 1) << 4) - 1; \
	} \
	(md)++; \
} while (0)

#define ulp_region_hide(md) do { \
	(md)->base = 0; \
	(md)->idx = ARRAY_SIZE(region); /* hide it */ \
	(md)++; \
} while (0)

#define ulp_region_le_chip(reg, chip) do { \
	if (chip_ver <= (chip)) { \
		ulp_region(reg); \
	} else { \
		ulp_region_hide(md); \
	} \
} while (0)

#define ulp_region_ge_chip(reg, chip) do { \
	if (chip_ver >= (chip)) { \
		ulp_region(reg); \
	} else { \
		ulp_region_hide(md); \
	} \
} while (0)

	ulp_region(RX_ISCSI);
	ulp_region(RX_TDDP);
	ulp_region(TX_TPT);
	ulp_region(RX_STAG);
	ulp_region(RX_RQ);
	ulp_region_le_chip(RX_RQUDP, CHELSIO_T6);
	ulp_region(RX_PBL);
	ulp_region(TX_PBL);
	ulp_region_ge_chip(RX_TLS_KEY, CHELSIO_T6);
	ulp_region_ge_chip(RX_RRQ, CHELSIO_T7);
	ulp_region_ge_chip(RX_NVME_TCP_STAG, CHELSIO_T7);
	ulp_region_ge_chip(RX_NVME_TCP_RQ, CHELSIO_T7);
	ulp_region_ge_chip(RX_NVME_TCP_PBL, CHELSIO_T7);
	ulp_region_ge_chip(TX_NVME_TCP_TPT, CHELSIO_T7);
	ulp_region_ge_chip(TX_NVME_TCP_PBL, CHELSIO_T7);

#undef ulp_region_ge_chip
#undef ulp_region_le_chip
#undef ulp_region_hide
#undef ulp_region

	if (!is_t4(adap->params.chip)) {
		md->base = t4_read_reg(adap, A_SGE_DBVFIFO_BADDR);
		if (is_t5(adap->params.chip)) {
			u32 sge_ctrl = t4_read_reg(adap, A_SGE_CONTROL2);
			u32 size = 0;

			if (sge_ctrl & F_VFIFO_ENABLE)
				size = t4_read_reg(adap, A_SGE_DBVFIFO_SIZE) * 4;

			md->limit = md->base + size - 1;
		} else {
			md->limit = 0;
		}
	} else {
		md->base = 0;
		md->idx = ARRAY_SIZE(region);
	}

	md++;

	md->base = t4_read_reg(adap, A_ULP_RX_CTX_BASE);
	md->limit = 0;
	md++;
	md->base = t4_read_reg(adap, A_ULP_TX_ERR_TABLE_BASE);
	md->limit = 0;
	md++;

	if (chip_ver >= CHELSIO_T7) {
		u32 roce_rrq_base = 0;

		t4_tp_pio_read(adap, &roce_rrq_base, 1, A_TP_ROCE_RRQ_BASE,
			       true);
		md->base = roce_rrq_base;
		md->limit = 0;
	} else {
		md->base = 0;
		md->idx = ARRAY_SIZE(region); /* hide it*/
	}
	md++;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#ifndef __NO_DRIVER_OCQ_SUPPORT__
	md->base = adap->uld.vres.ocq.start;
	if (adap->uld.vres.ocq.size)
		md->limit = md->base + adap->uld.vres.ocq.size - 1;
	else
		md->idx = ARRAY_SIZE(region);  /* hide it */
	md++;
#endif
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	/* add any address-space holes, there can be up to 3 */
	for (n = 0; n < i - 1; n++)
		if (avail[n].limit < avail[n + 1].base)
			(md++)->base = avail[n].limit;
	if (avail[n].limit)
		(md++)->base = avail[n].limit;

	n = md - mem;
	sort(mem, n, sizeof(struct mem_desc), mem_desc_cmp, NULL);

	for (lo = 0; lo < i; lo++)
		mem_region_show(seq, memory[avail[lo].idx], avail[lo].base,
				avail[lo].limit - 1);

	seq_putc(seq, '\n');
	for (i = 0; i < n; i++) {
		if (mem[i].idx >= ARRAY_SIZE(region))
			continue;                        /* skip holes */
		if (!mem[i].limit)
			mem[i].limit = i < n - 1 ? mem[i + 1].base - 1 : ~0;
		mem_region_show(seq, region[mem[i].idx], mem[i].base,
				mem[i].limit);
	}

	seq_putc(seq, '\n');
	lo = t4_read_reg(adap, A_CIM_SDRAM_BASE_ADDR);
	hi = t4_read_reg(adap, A_CIM_SDRAM_ADDR_SIZE) + lo - 1;
	mem_region_show(seq, "uP RAM:", lo, hi);

	lo = t4_read_reg(adap, A_CIM_EXTMEM2_BASE_ADDR);
	hi = t4_read_reg(adap, A_CIM_EXTMEM2_ADDR_SIZE) + lo - 1;
	mem_region_show(seq, "uP Extmem2:", lo, hi);

	lo = t4_read_reg(adap, A_TP_PMM_RX_MAX_PAGE);
	if (chip_ver >= CHELSIO_T7)
		nchan = (1 << G_T7_PMRXNUMCHN(lo));
	else
		nchan = (lo & F_PMRXNUMCHN) ? 2 : 1;
	for (i = 0, free_rx_cnt = 0; i < nchan; i++)
		free_rx_cnt += G_FREERXPAGECOUNT(t4_read_reg(adap, A_TP_FLM_FREE_RX_CNT));
	seq_printf(seq, "\n%u Rx pages (%u free) of size %uKiB for %u channels\n",
		   G_PMRXMAXPAGE(lo), free_rx_cnt,
		   t4_read_reg(adap, A_TP_PMM_RX_PAGE_SIZE) >> 10, nchan);

	lo = t4_read_reg(adap, A_TP_PMM_TX_MAX_PAGE);
	hi = t4_read_reg(adap, A_TP_PMM_TX_PAGE_SIZE);
	if (chip_ver >= CHELSIO_T7)
		nchan = (1 << G_T7_PMTXNUMCHN(lo));
	else
		nchan = (1 << G_PMTXNUMCHN(lo));
	for (i = 0, free_tx_cnt = 0; i < nchan; i++)
		free_tx_cnt += G_FREETXPAGECOUNT(t4_read_reg(adap, A_TP_FLM_FREE_TX_CNT));
	seq_printf(seq, "%u Tx pages (%u free) of size %u%ciB for %u channels\n",
		   G_PMTXMAXPAGE(lo), free_tx_cnt,
		   hi >= (1 << 20) ? (hi >> 20) : (hi >> 10),
		   hi >= (1 << 20) ? 'M' : 'K', nchan);
	seq_printf(seq, "%u p-structs (%u free)\n\n",
		   t4_read_reg(adap, A_TP_CMM_MM_MAX_PSTRUCT),
		   G_FREEPSTRUCTCOUNT(t4_read_reg(adap, A_TP_FLM_FREE_PS_CNT)));

	for (i = 0; i < 4; i++) {
		if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T5)
			lo = t4_read_reg(adap, A_MPS_RX_MAC_BG_PG_CNT0 + i * 4);
		else
			lo = t4_read_reg(adap, A_MPS_RX_PG_RSV0 + i * 4);
		if (is_t5(adap->params.chip)) {
			used = G_T5_USED(lo);
			alloc = G_T5_ALLOC(lo);
		} else {
			used = G_USED(lo);
			alloc = G_ALLOC(lo);
		}
		/* For T6+ these are MAC buffer groups */
		seq_printf(seq, "Port %d using %u pages out of %u allocated\n",
			   i, used, alloc);
	}
	for (i = 0; i < adap->params.arch.nchan; i++) {
		if (chip_ver > CHELSIO_T5)
			lo = t4_read_reg(adap,
					 A_MPS_RX_LPBK_BG_PG_CNT0 + i * 4);
		else
			lo = t4_read_reg(adap, A_MPS_RX_PG_RSV4 + i * 4);
		if (is_t5(adap->params.chip)) {
			used = G_T5_USED(lo);
			alloc = G_T5_ALLOC(lo);
		} else {
			used = G_USED(lo);
			alloc = G_ALLOC(lo);
		}
		/* For T6+ these are MAC buffer groups */
		seq_printf(seq,
			   "Loopback %d using %u pages out of %u allocated\n",
			   i, used, alloc);
	}
out:
	kfree(mem);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(meminfo);

static void create_debugfs_file_entry(struct t4_linux_debugfs_entry *f,
				      const char *name,
				      const struct file_operations *ops,
				      umode_t mode, unsigned char data,
				      unsigned int req)
{
	f->name = name;
	f->ops = ops;
	f->mode = mode;
	f->data = data;
	f->req = 0;
}

static void add_debugfs_file_size(struct adapter *adap, struct dentry *dentry,
				  struct t4_linux_debugfs_entry *f, u64 size)
{
	struct t4_linux_debugfs_data *data;

	data = devm_kzalloc(adap->pdev_dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return;

	data->adap = adap;
	data->data = f->data;
	data->coreid = 0;
	debugfs_create_file_size(f->name, f->mode, dentry, data, f->ops, size);
}

static void add_debugfs_mem(struct adapter *adap, const char *name,
			    unsigned int i, unsigned int size_mb)
{
	struct t4_linux_debugfs_entry f;

	create_debugfs_file_entry(&f, name, &mem_debugfs_fops, 0400, i, 0);
	add_debugfs_file_size(adap, adap->debugfs_root, &f, (u64)size_mb << 20);
}

/*
 * Add an array of Debug FS files.
 */
void add_debugfs_files(struct adapter *adap, struct dentry *dentry,
		       unsigned char coreid, struct t4_linux_debugfs_entry *f,
		       unsigned int n)
{
	struct t4_linux_debugfs_data *data;
	u32 i;

	/* debugfs support is best effort */
	for (i = 0; i < n; i++) {
		data = devm_kzalloc(adap->pdev_dev, sizeof(*data), GFP_KERNEL);
		if (!data)
			continue;

		data->adap = adap;
		data->data = f[i].data;
		data->coreid = coreid;
		debugfs_create_file(f[i].name, f[i].mode, dentry, data,
				    f[i].ops);
	}
}

static void add_debugfs_files_multicore(struct adapter *adap)
{
	static struct t4_linux_debugfs_entry common_files[] = {
		{ "cim_la", &cim_la_fops, 0400, 0 },
		{ "cim_pif_la", &cim_pif_la_fops, 0400, 0 },
		{ "cim_ma_la", &cim_ma_la_fops, 0400, 0 },
		{ "cim_qcfg", &cim_qcfg_debugfs_fops, 0400, 0 },
		{ "upload", &upload_debugfs_fops, 0400, 0 },
		{ "devlog", &devlog_fops, 0400, 0 },
		{ "devlog_level", &devlog_level_fops, 0400, 0 },
	};
	static struct t4_linux_debugfs_entry t4_files[] = {
		{ "ibq_tp0", &cim_ibq_fops, 0400, 0 },
		{ "ibq_tp1", &cim_ibq_fops, 0400, 1 },
		{ "ibq_ulp", &cim_ibq_fops, 0400, 2 },
		{ "ibq_sge0", &cim_ibq_fops, 0400, 3 },
		{ "ibq_sge1", &cim_ibq_fops, 0400, 4 },
		{ "ibq_ncsi", &cim_ibq_fops, 0400, 5 },
		{ "obq_ulp0", &cim_obq_fops, 0400, 0 },
		{ "obq_ulp1", &cim_obq_fops, 0400, 1 },
		{ "obq_ulp2", &cim_obq_fops, 0400, 2 },
		{ "obq_ulp3", &cim_obq_fops, 0400, 3 },
		{ "obq_sge", &cim_obq_fops, 0400, 4 },
		{ "obq_ncsi", &cim_obq_fops, 0400, 5 },
	};
	static struct t4_linux_debugfs_entry t5_files[] = {
		{ "ibq_tp0", &cim_ibq_fops, 0400, 0 },
		{ "ibq_tp1", &cim_ibq_fops, 0400, 1 },
		{ "ibq_ulp", &cim_ibq_fops, 0400, 2 },
		{ "ibq_sge0", &cim_ibq_fops, 0400, 3 },
		{ "ibq_sge1", &cim_ibq_fops, 0400, 4 },
		{ "ibq_ncsi", &cim_ibq_fops, 0400, 5 },
		{ "obq_ulp0", &cim_obq_fops, 0400, 0 },
		{ "obq_ulp1", &cim_obq_fops, 0400, 1 },
		{ "obq_ulp2", &cim_obq_fops, 0400, 2 },
		{ "obq_ulp3", &cim_obq_fops, 0400, 3 },
		{ "obq_sge", &cim_obq_fops, 0400, 4 },
		{ "obq_ncsi", &cim_obq_fops, 0400, 5 },
		{ "obq_sge_rx_q0", &cim_obq_fops, 0400, 6 },
		{ "obq_sge_rx_q1", &cim_obq_fops, 0400, 7 },
	};
	static struct t4_linux_debugfs_entry t7_files[] = {
		{ "ibq_tp0", &cim_ibq_fops, 0400, 0 },
		{ "ibq_tp1", &cim_ibq_fops, 0400, 1 },
		{ "ibq_tp2", &cim_ibq_fops, 0400, 2 },
		{ "ibq_tp3", &cim_ibq_fops, 0400, 3 },
		{ "ibq_ulp", &cim_ibq_fops, 0400, 4 },
		{ "ibq_sge0", &cim_ibq_fops, 0400, 5 },
		{ "ibq_sge1", &cim_ibq_fops, 0400, 6 },
		{ "ibq_ncsi", &cim_ibq_fops, 0400, 7 },
		{ "ibq_ipc1", &cim_ibq_fops, 0400, 9 },
		{ "ibq_ipc2", &cim_ibq_fops, 0400, 10 },
		{ "ibq_ipc3", &cim_ibq_fops, 0400, 11 },
		{ "ibq_ipc4", &cim_ibq_fops, 0400, 12 },
		{ "ibq_ipc5", &cim_ibq_fops, 0400, 13 },
		{ "ibq_ipc6", &cim_ibq_fops, 0400, 14 },
		{ "ibq_ipc7", &cim_ibq_fops, 0400, 15 },
		{ "obq_ulp0", &cim_obq_fops, 0400, 0 },
		{ "obq_ulp1", &cim_obq_fops, 0400, 1 },
		{ "obq_ulp2", &cim_obq_fops, 0400, 2 },
		{ "obq_ulp3", &cim_obq_fops, 0400, 3 },
		{ "obq_sge", &cim_obq_fops, 0400, 4 },
		{ "obq_ncsi", &cim_obq_fops, 0400, 5 },
		{ "obq_sge_rx_q0", &cim_obq_fops, 0400, 6 },
		{ "obq_ipc1", &cim_obq_fops, 0400, 9 },
		{ "obq_ipc2", &cim_obq_fops, 0400, 10 },
		{ "obq_ipc3", &cim_obq_fops, 0400, 11 },
		{ "obq_ipc4", &cim_obq_fops, 0400, 12 },
		{ "obq_ipc5", &cim_obq_fops, 0400, 13 },
		{ "obq_ipc6", &cim_obq_fops, 0400, 14 },
		{ "obq_ipc7", &cim_obq_fops, 0400, 15 },
	};
	static struct t4_linux_debugfs_entry t7_sec_files[] = {
		{ "ibq_tp0", &cim_ibq_fops, 0400, 0 },
		{ "ibq_tp1", &cim_ibq_fops, 0400, 1 },
		{ "ibq_tp2", &cim_ibq_fops, 0400, 2 },
		{ "ibq_tp3", &cim_ibq_fops, 0400, 3 },
		{ "ibq_ulp", &cim_ibq_fops, 0400, 4 },
		{ "ibq_sge0", &cim_ibq_fops, 0400, 5 },
		{ "ibq_ipc0", &cim_ibq_fops, 0400, 9 },
		{ "obq_ulp0", &cim_obq_fops, 0400, 0 },
		{ "obq_ulp1", &cim_obq_fops, 0400, 1 },
		{ "obq_ulp2", &cim_obq_fops, 0400, 2 },
		{ "obq_ulp3", &cim_obq_fops, 0400, 3 },
		{ "obq_sge", &cim_obq_fops, 0400, 4 },
		{ "obq_sge_rx_q0", &cim_obq_fops, 0400, 6 },
		{ "obq_ipc0", &cim_obq_fops, 0400, 9 },
	};
	u32 chip = CHELSIO_CHIP_VERSION(adap->params.chip);
	char name[8];
	u8 i;

	/* Add primary core files */
	add_debugfs_files(adap, adap->debugfs_root, 0, common_files,
			  ARRAY_SIZE(common_files));

	switch (chip) {
	case CHELSIO_T4:
		add_debugfs_files(adap, adap->debugfs_root, 0, t4_files,
				  ARRAY_SIZE(t4_files));
		break;
	case CHELSIO_T5:
	case CHELSIO_T6:
		add_debugfs_files(adap, adap->debugfs_root, 0, t5_files,
				  ARRAY_SIZE(t5_files));
		break;
	default:
		add_debugfs_files(adap, adap->debugfs_root, 0, t7_files,
				  ARRAY_SIZE(t7_files));
		break;
	}

	/* Add secondary core files */
	for (i = 1; i < adap->params.num_up_cores; i++) {
		snprintf(name, sizeof(name), "core_%u", i);
		adap->debugfs_multicore[i] =
			debugfs_create_dir(name, adap->debugfs_root);

		add_debugfs_files(adap, adap->debugfs_multicore[i], i,
				  common_files, ARRAY_SIZE(common_files));
		add_debugfs_files(adap, adap->debugfs_multicore[i], i,
				  t7_sec_files, ARRAY_SIZE(t7_sec_files));
	}
}

int setup_debugfs(struct adapter *adap)
{
	/*
	 * Debug FS nodes common to all T4 and later adapters.
	 */
	static struct t4_linux_debugfs_entry t4_debugfs_files[] = {
		{ "clk", &clk_debugfs_fops, 0400, 0 },
#ifdef T4_OS_LOG_MBOX_CMDS
		{ "mboxlog", &mboxlog_fops, 0400, 0 },
#endif
		{ "mbox0", &mbox_debugfs_fops, 0600, 0 },
		{ "mbox1", &mbox_debugfs_fops, 0600, 1 },
		{ "mbox2", &mbox_debugfs_fops, 0600, 2 },
		{ "mbox3", &mbox_debugfs_fops, 0600, 3 },
		{ "mbox4", &mbox_debugfs_fops, 0600, 4 },
		{ "mbox5", &mbox_debugfs_fops, 0600, 5 },
		{ "mbox6", &mbox_debugfs_fops, 0600, 6 },
		{ "mbox7", &mbox_debugfs_fops, 0600, 7 },
		{ "mps_tcam", &mps_tcam_debugfs_fops, 0400, 0 },
		{ "tp_la", &tp_la_fops, 0400, 0 },
		{ "ulprx_la", &ulprx_la_fops, 0400, 0 },
		{ "sensors", &sensors_debugfs_fops, 0400, 0 },
#ifdef __DRIVER_ETHTOOL_UNSUPPORTED__
		{ "lb_stats", &lb_stats_debugfs_fops, 0400, 0 },
#endif /* __DRIVER_ETHTOOL_UNSUPPORTED__ */
		{ "tp_stats", &tp_stats_debugfs_fops, 0400, 0 },
		{ "pm_stats", &pm_stats_debugfs_fops, 0400, 0 },
		{ "tx_rate", &tx_rate_debugfs_fops, 0400, 0 },
		{ "hw_sched", &sched_debugfs_fops, 0400, 0 },
		{ "cctrl", &cctrl_tbl_debugfs_fops, 0400, 0 },
		{ "rss", &rss_debugfs_fops, 0400, 0 },
		{ "rss_config", &rss_config_debugfs_fops, 0400, 0 },
		{ "rss_key", &rss_key_debugfs_fops, 0400, 0 },
		{ "rss_pf_config", &rss_pf_config_debugfs_fops, 0400, 0 },
		{ "rss_vf_config", &rss_vf_config_debugfs_fops, 0400, 0 },
		{ "meminfo", &meminfo_debugfs_fops, 0400, 0 },
	};
	u32 val, chip = CHELSIO_CHIP_VERSION(adap->params.chip);
	struct t4_linux_debugfs_entry f;
	int i;

	if (!adap->debugfs_root)
		return -1;

	add_debugfs_files(adap, adap->debugfs_root, 0, t4_debugfs_files,
			  ARRAY_SIZE(t4_debugfs_files));

	add_debugfs_files_multicore(adap);

	i = t4_read_reg(adap, A_MA_TARGET_MEM_ENABLE);
	if (i & F_EDRAM0_ENABLE) {
		val = t4_read_reg(adap, A_MA_EDRAM0_BAR);
		add_debugfs_mem(adap, "edc0", MEM_EDC0,
				G_T7_EDRAM0_SIZE(val));
	}

	if (i & F_EDRAM1_ENABLE) {
		val = t4_read_reg(adap, A_MA_EDRAM1_BAR);
		add_debugfs_mem(adap, "edc1", MEM_EDC1,
				G_T7_EDRAM1_SIZE(val));
	}

	if (i & F_EXT_MEM_ENABLE) {
		switch (chip) {
		case CHELSIO_T4:
		case CHELSIO_T6:
			val = t4_read_reg(adap, A_MA_EXT_MEMORY_BAR);
			add_debugfs_mem(adap, "mc", MEM_MC,
					G_EXT_MEM_SIZE(val));
			break;
		default:
			val = t4_read_reg(adap, A_MA_EXT_MEMORY0_BAR);
			add_debugfs_mem(adap, "mc0", MEM_MC0,
					G_T7_EXT_MEM0_SIZE(val));
			break;
		}
	}

	if (i & F_EXT_MEM1_ENABLE) {
		switch (chip) {
		case CHELSIO_T4:
		case CHELSIO_T6:
			/* No support for mc1 */
			break;
		default:
			/* No mc1 when split mode enabled */
			if (i & F_MC_SPLIT)
				break;

			val = t4_read_reg(adap, A_MA_EXT_MEMORY1_BAR);
			add_debugfs_mem(adap, "mc1", MEM_MC1,
					G_T7_EXT_MEM1_SIZE(val));
			break;
		}
	}

	if (i & F_HMA_MUX) {
		switch (chip) {
		case CHELSIO_T4:
		case CHELSIO_T5:
		       	/* No support for hma */
			break;
		case CHELSIO_T6:
			val = t4_read_reg(adap, A_MA_EXT_MEMORY1_BAR);
			add_debugfs_mem(adap, "hma", MEM_HMA,
					G_EXT_MEM_SIZE(val));
			break;
		default:
			val = t4_read_reg(adap, A_MA_HOST_MEMORY_BAR);
			add_debugfs_mem(adap, "hma", MEM_HMA,
					G_T7_HMA_SIZE(val));
			break;
		}
	}

	create_debugfs_file_entry(&f, "flash", &flash_debugfs_fops, 0400,
				  0, 0);
	add_debugfs_file_size(adap, adap->debugfs_root, &f,
			      adap->params.sf_size);

	debugfs_create_bool("use_backdoor", 0600, adap->debugfs_root,
			    &adap->use_bd);

#if DMABUF
	adap->dma_virt = dma_alloc_coherent(adap->pdev_dev, DMABUF_SZ,
					    &adap->dma_phys,
				      GFP_KERNEL);
	if (adap->dma_virt) {
		printk("DMA buffer at bus address %#llx, virtual 0x%p\n",
			(unsigned long long)adap->dma_phys, adap->dma_virt);
		create_debugfs_file_entry(&f, "dmabuf", &dma_debugfs_fops,
					  0644, 0, 0);
		add_debugfs_file_size(adap, adap->debugfs_root, &f, DMABUF_SZ);
	}
#endif

	alloc_trace_bufs(adap);
	return 0;
}
