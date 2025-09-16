// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)

/*
 * The Non-Transparent Bridge (NTB) is a device that allows you to connect
 * two or more systems using a PCI-e links, providing remote memory access.
 *
 * This module contains a driver for NT2.0 NTBs in Broadcom PCIe bridges.
 */

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/ntb.h>

#define NTB_NAME	"ntb_hw_broadcom"
#define NTB_DESC	"BROADCOM PCI-E Non-Transparent Bridge Driver"
#define NTB_VER		"1.0"

MODULE_DESCRIPTION(NTB_DESC);
MODULE_VERSION(NTB_VER);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Alexander Motin <alexander.motin@TrueNAS.com>");

#define BROADCOM_MAX_BARS	1	/* Specs mention 4 BARS, but describe only one. */
#define BROADCOM_NUM_SPAD	8	/* There are 8 scratchpads total. */
#define BROADCOM_NUM_DB		1	/* There is 1 doorbell per requester bus. */
#define BROADCOM_MAX_SPLIT	512	/* Allow at most 512 splits. */

static struct dentry *debugfs_dir;

struct broadcom_ntb_mw_info {
	int		mw_bar;
	int		mw_64bit;
	dma_addr_t	mw_pbase;
	resource_size_t	mw_size;
	struct {
		dma_addr_t mw_xlat_addr;
		resource_size_t mw_xlat_size;
	} splits[BROADCOM_MAX_SPLIT];
};

struct broadcom_ntb_dev {
	struct ntb_dev ntb;

	u32 lvsec;
	u32 local_port_gid;
	u32 peer_port_gid;
	u32 local_nt_gid;
	u32 peer_nt_gid;
	u64 segment_size;
	u32 alut;
	u32 split;  /* split BAR2 into 2^x parts */

	struct broadcom_ntb_mw_info mw_info[BROADCOM_MAX_BARS];
	unsigned char mw_count;
	unsigned char spad_cnt;   /* Number of standard spads */
	u32 sspad_off;  /* Offset of our spads */
	u32 pspad_off;  /* Offset of peer spads */

	void __iomem *self_mmio;

	struct dentry *debugfs_dir;
	struct dentry *debugfs_info;
};

#define NTB_LNK_STA_SPEED_MASK	0x000F
#define NTB_LNK_STA_WIDTH_MASK	0x03F0
#define NTB_LNK_STA_SPEED(x)	((x) & NTB_LNK_STA_SPEED_MASK)
#define NTB_LNK_STA_WIDTH(x)	(((x) & NTB_LNK_STA_WIDTH_MASK) >> 4)

#define BROADCOM_NT_CONFIGURATION_REG		0x118
#define BROADCOM_NT_LUT_SIZES_REG		0x11C

#define BROADCOM_NT_IRQ_STATUS_REG		0xC60
#define BROADCOM_NT_IRQ_MASK_SET_REG		0xC64
#define BROADCOM_NT_IRQ_MASK_CLEAR_REG		0xC68

#define BROADCOM_NT_INGRESS_CTRL_REG		0xCB0
#define BROADCOM_NT_EGRESS_CTRL_REG		0xCB4
#define BROADCOM_NT_DOORBELL_REG		0xCB8
#define BROADCOM_NT_EGRESS_INDEX_REG		0xCE0
#define BROADCOM_NT_INGRESS_INDEX_REG		0xCE4
#define BROADCOM_NT_INGRESS_ENTRY_REG		0xCE8
#define BROADCOM_NT_EGRESS_ENTRY_LOW_REG	0xCF0
#define BROADCOM_NT_EGRESS_ENTRY_HIGH_REG	0xCF4
#define BROADCOM_NT_EGRESS_ENTRY_COMMIT_REG	0xCF8

#define BROADCOM_NT_NOT_PAIRED			0x00FFFFFF

// TWC legacy NT capability offsets
#define BROADCOM_LEGACY_NT_VSEC_HDR_OFFSET	0x04  // VSEC header
#define BROADCOM_LEGACY_NT_MY_GID_OFFSET	0x08  // My GID
#define BROADCOM_LEGACY_NT_CAP_OFFSET		0x0C  // NT capabilities
#define BROADCOM_LEGACY_NT_PEER_GID_OFFSET	0x10  // GID of connected peer
#define BROADCOM_LEGACY_NT_CS_OFFSET		0x14  // NT control/status
#define BROADCOM_LEGACY_NT_RX_ADDR_LOW_OFFSET	0x18  // Rx FIFO base (low 32b)
#define BROADCOM_LEGACY_NT_RX_ADDR_HIGH_OFFSET	0x1C  // Rx FIFO base (high 32b)
#define BROADCOM_LEGACY_NT_RX_BUFF_SIZE_OFFSET	0x20  // Rx FIFO size
#define BROADCOM_LEGACY_NT_RX_FIFO_PTR_OFFSET	0x24  // Rx FIFO head & tail pointers
#define BROADCOM_LEGACY_NT_TX_ADDR_LOW_OFFSET	0x28  // Rx FIFO base (low 32b)
#define BROADCOM_LEGACY_NT_TX_ADDR_HIGH_OFFSET	0x2C  // Rx FIFO base (high 32b)
#define BROADCOM_LEGACY_NT_TX_BUFF_SIZE_OFFSET	0x30  // Rx FIFO size
#define BROADCOM_LEGACY_NT_TX_FIFO_PTR_OFFSET	0x34  // Rx FIFO head & tail pointers
#define BROADCOM_LEGACY_NT_SCRATCH_0_OFFSET	0x38  // Scratchpad 0
#define BROADCOM_LEGACY_NT_SCRATCH_1_OFFSET	0x3C  // Scratchpad 1
#define BROADCOM_LEGACY_NT_SCRATCH_2_OFFSET	0x40  // Scratchpad 2
#define BROADCOM_LEGACY_NT_SCRATCH_3_OFFSET	0x44  // Scratchpad 3
#define BROADCOM_LEGACY_NT_SCRATCH_4_OFFSET	0x48  // Scratchpad 4
#define BROADCOM_LEGACY_NT_SCRATCH_5_OFFSET	0x4C  // Scratchpad 5
#define BROADCOM_LEGACY_NT_SCRATCH_6_OFFSET	0x50  // Scratchpad 6
#define BROADCOM_LEGACY_NT_SCRATCH_7_OFFSET	0x54  // Scratchpad 7

// TWC legacy NT supported capabilities bit-specific
#define BROADCOM_LEGACY_NT_CAP_MCPU_MSG_SUPP	((U32)1 << 0)
#define BROADCOM_LEGACY_NT_CAP_FAILOVER_SUPP	((U32)1 << 1)
#define BROADCOM_LEGACY_NT_CAP_MCPU_MSG_INTERRUPT_SUPP	((U32)1 << 2)
#define BROADCOM_LEGACY_NT_CS_MCPU_MSG_ENABLE		((u32)1 << 18)
#define BROADCOM_LEGACY_NT_CS_MCPU_MSG_INTERRUPT_ENABLE	((u32)1 << 24)
#define BROADCOM_LEGACY_NT_CS_MCPU_MSG_INTERRUPT_STATUS	((u32)1 << 25)

// TWC legacy NT operation control/status bit-specific
#define BROADCOM_LEGACY_NT_CS_DONE_IDLE		((U32)1 << 0)
#define BROADCOM_LEGACY_NT_CS_OP_FAILED		((U32)1 << 1)
#define BROADCOM_LEGACY_NT_CS_PAIR_COMPLETE	((U32)1 << 8)

#define BROADCOM_LEGACY_NT_CS_START_FO		((U32)1 << 16)
#define BROADCOM_LEGACY_NT_CS_PAIR		((U32)1 << 17)

// TWC legacy NT operation status detail field
#define BROADCOM_LEGACY_NT_CS_STATUS_SHIFT	2
#define BROADCOM_LEGACY_NT_CS_STATUS_MASK	(U32)0x000000FC   // [7:2]

// TWC legacy NT operation status codes (Bits 7:2 of NT_CS Register)
#define BROADCOM_LEGACY_NT_CS_ERR_NONE		0   // No error
#define BROADCOM_LEGACY_NT_CS_ERR_FAILED	1   // Generic failure
#define BROADCOM_LEGACY_NT_CS_ERR_UNSUPPORTED	2   // Unsupported operation
#define BROADCOM_LEGACY_NT_CS_ERR_INVALID_OP	4   // Operation is invalid
#define BROADCOM_LEGACY_NT_CS_ERR_INVALID_PARAM	5   // Parameter is invalid
#define BROADCOM_LEGACY_NT_CS_ERR_INVALID_PEER	6   // Peer is invalid
#define BROADCOM_LEGACY_NT_CS_ERR_RESOURCE	7   // Resource error
#define BROADCOM_LEGACY_NT_CS_ERR_PAIR_FAILED	8   // Resource error

#define ntb_ndev(__ntb) container_of(__ntb, struct broadcom_ntb_dev, ntb)

/* Helper functions for BAR0 memory-mapped register access */
static inline u32 broadcom_nt_reg_read(struct broadcom_ntb_dev *ndev, u32 offset)
{
	return ioread32(ndev->self_mmio + offset);
}

static inline void broadcom_nt_reg_write(struct broadcom_ntb_dev *ndev, u32 offset, u32 val)
{
	iowrite32(val, ndev->self_mmio + offset);
}

/* PCI defines and macros */
#define powerof2(x)			((((x) - 1) & (x)) == 0)
#define PCIR_BAR(x)			(PCI_BASE_ADDRESS_0 + (x) * 4)

#define UINT32_MAX 0xFFFFFFFF
#define UINT64_MAX 0xFFFFFFFFFFFFFFFF

static uint usplit;
module_param(usplit, uint, 0644);
MODULE_PARM_DESC(usplit,
		 "Split BAR2 into 2^x parts, default is 0: valid entries (0..9)");

static u64 broadcom_ntb_link_is_up(struct ntb_dev *ntb, enum ntb_speed *speed, enum ntb_width *width)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u16 link;

	if (pcie_capability_read_word(ndev->ntb.pdev, PCI_EXP_LNKSTA, &link))
		return 0;
	if (speed)
		*speed = NTB_LNK_STA_SPEED(link);
	if (width)
		*width = NTB_LNK_STA_WIDTH(link);
	return NTB_LNK_STA_WIDTH(link) != 0;
}

static int broadcom_ntb_link_enable(struct ntb_dev *ntb, enum ntb_speed max_speed,
			       enum ntb_width max_width)
{
#if 0
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u32 val, reg;

	/* if we see the link interface, then the link is enabled */
	if (ndev->link) {
		ntb_link_event(&ndev->ntb);
		return 0;
	}

	reg = BROADCOM_PORT_CONTROL(ndev);
	val = ioread32(ndev->self_mmio + reg);
	if ((val & (1 << (ndev->port & 7))) == 0) {
		/* If already enabled, generate a link event and exit */
		ntb_link_event(&ndev->ntb);
		return 0;
	}
	val &= ~(1 << (ndev->port & 7));
	iowrite32(val, ndev->self_mmio + reg);
#endif

	return 0;
}

static int broadcom_ntb_link_disable(struct ntb_dev *ntb)
{
#if 0
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u32 val, reg;

	/* If there is no link interface, no need to disable link */
	if (ndev->link)
		return 0;

	dev_dbg(&ntb->pdev->dev, "Disabling link\n");

	reg = BROADCOM_PORT_CONTROL(ndev);
	val = ioread32(ndev->self_mmio + reg);
	val |= (1 << (ndev->port & 7));
	iowrite32(val, ndev->self_mmio + reg);
#endif

	return 0;
}

static int broadcom_ntb_mw_count(struct ntb_dev *ntb, int pidx)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	int res;

	res = ndev->mw_count;
	res += (1 << ndev->split) - 1;

	return res;
}

static int broadcom_ntb_peer_mw_count(struct ntb_dev *ntb)
{
	return broadcom_ntb_mw_count(ntb, 0);
}

static unsigned int broadcom_ntb_user_mw_to_idx(struct broadcom_ntb_dev *ndev, int idx, unsigned int *sp)
{
	unsigned int t;

	t = 1 << ndev->split;
	if (idx < t) {
		*sp = idx;
		return 0;
	}
	*sp = 0;

	return (idx - (t - 1));
}

static int broadcom_ntb_peer_mw_get_addr(struct ntb_dev *ntb, int idx, phys_addr_t *base,
				    resource_size_t *size)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	struct broadcom_ntb_mw_info *mw;
	resource_size_t ss;
	unsigned int sp, split;

	idx = broadcom_ntb_user_mw_to_idx(ndev, idx, &sp);
	if (idx >= ndev->mw_count)
		return -EINVAL;
	mw = &ndev->mw_info[idx];
	split = (mw->mw_bar == 2) ? ndev->split : 0;
	ss = mw->mw_size >> split;

	if (base)
		*base = mw->mw_pbase + ss * sp;
	if (size)
		*size = ss;

	return 0;
}

static int broadcom_ntb_mw_get_align(struct ntb_dev *ntb, int pidx, int idx,
				resource_size_t *addr_align,
				resource_size_t *size_align,
				resource_size_t *size_max)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	struct broadcom_ntb_mw_info *mw;
	unsigned int sp;

	idx = broadcom_ntb_user_mw_to_idx(ndev, idx, &sp);
	if (idx >= ndev->mw_count)
		return -EINVAL;
	mw = &ndev->mw_info[idx];

	/*
	 * Remote to local memory window translation address alignment.
	 */
	if (addr_align) {
		if (mw->mw_bar == 2 && ndev->alut)
			*addr_align = ndev->segment_size;
		else
			*addr_align = mw->mw_size;
	}

	/*
	 * Remote to local memory window size alignment.
	 */
	if (size_align) {
		if (mw->mw_bar == 2 && ndev->alut)
			*size_align = ndev->segment_size / 2;
		else
			*size_align = mw->mw_size;
	}

	/*
	 * Maximum window size.
	 */
	if (size_max) {
		if (mw->mw_bar == 2)
			*size_max = mw->mw_size >> ndev->split;
		else
			*size_max = mw->mw_size;
	}

	return 0;
}

static int broadcom_ntb_mw_set_trans_internal(struct ntb_dev *ntb, int idx)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	struct broadcom_ntb_mw_info *mw;
	u64 daddr, dsize, doff, ssize;
	u32 val;
	unsigned int i, sp, split;

	mw = &ndev->mw_info[idx];
	split = (mw->mw_bar == 2) ? ndev->split : 0;

	if (mw->mw_bar != 2 || ndev->alut == 0)
		return (EIO);	/* We have no documentaiton for those cases. */

	/* Enable all possible Egress ALUT entries. */
	broadcom_nt_reg_write(ndev, BROADCOM_NT_EGRESS_CTRL_REG, 0x5);

	ssize = mw->mw_size >> split;
	daddr = dsize = doff = 0;
	for (i = sp = 0; i < ndev->alut; i++) {
		if (doff == 0 || doff >= ssize) {
			if (sp >= (1 << split)) {
				daddr = dsize = doff = 0;
			} else {
				daddr = mw->splits[sp].mw_xlat_addr;
				dsize = mw->splits[sp++].mw_xlat_size;
				doff = 0;
			}
		}
		broadcom_nt_reg_write(ndev, BROADCOM_NT_EGRESS_INDEX_REG, i);
		if (doff < dsize) {
			val = ilog2(MIN(ndev->segment_size,
			    roundup_pow_of_two(dsize - doff))); /* Size */
			val |= 1 << 6;		/* Write Enable */
			val |= 1 << 7;		/* Read Enable */
			val |= 1 << 8;		/* GRID Check Enable */
			val |= 1 << 9;		/* Clear no snoop */
			val |= (daddr + doff) & 0xfffff000; /* Lower address */
		} else {
			val = 0;		/* No access */
		}
		dev_err(&ndev->ntb.pdev->dev, "EALUT %u %08x %08x %08x\n",
		    i, val, ndev->peer_nt_gid, (unsigned int)((daddr + doff) >> 32));
		broadcom_nt_reg_write(ndev, BROADCOM_NT_EGRESS_ENTRY_LOW_REG, val);
		val = ndev->peer_nt_gid;	/* Allowed access source GRID */
		broadcom_nt_reg_write(ndev, BROADCOM_NT_EGRESS_ENTRY_HIGH_REG, val);
		val = (daddr + doff) >> 32;	/* Upper address */
		broadcom_nt_reg_write(ndev, BROADCOM_NT_EGRESS_ENTRY_COMMIT_REG, val);
		doff += ndev->segment_size;
	}

	return 0;
}

static int broadcom_ntb_mw_set_trans(struct ntb_dev *ntb, int pidx, int idx,
				dma_addr_t addr, resource_size_t size)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	struct broadcom_ntb_mw_info *mw;
	unsigned int sp;

	idx = broadcom_ntb_user_mw_to_idx(ndev, idx, &sp);
	if (idx >= ndev->mw_count)
		return -EINVAL;

	mw = &ndev->mw_info[idx];
	mw->splits[sp].mw_xlat_addr = addr;
	mw->splits[sp].mw_xlat_size = size;
	dev_err(&ndev->ntb.pdev->dev, "set trans %u %u %llx %llx\n", idx, sp, addr, size);

	return broadcom_ntb_mw_set_trans_internal(ntb, idx);
}

static int broadcom_ntb_mw_clear_trans(struct ntb_dev *ntb, int pidx, int widx)
{
	return broadcom_ntb_mw_set_trans(ntb, pidx, widx, 0, 0);
}

static int broadcom_ntb_init_pci(struct broadcom_ntb_dev *ndev, struct pci_dev *pdev)
{
	int rc;

	pci_set_drvdata(pdev, ndev);

	rc = pcim_enable_device(pdev);
	if (rc)
		goto err_pci_enable;

	rc = pci_request_regions(pdev, NTB_NAME);
	if (rc)
		goto err_pci_enable;

	ndev->self_mmio = pcim_iomap(pdev, 0, 0);
	if (!ndev->self_mmio) {
		rc = -EIO;
		goto err_dma_mask;
	}

	return 0;

err_dma_mask:
	pci_clear_master(pdev);
	pci_release_regions(pdev);
err_pci_enable:
	pci_set_drvdata(pdev, NULL);
	return rc;
}

static void broadcom_ntb_deinit_pci(struct broadcom_ntb_dev *ndev)
{
	struct pci_dev *pdev = ndev->ntb.pdev;

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
}

static int broadcom_init_ntb(struct ntb_dev *ntb)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	struct pci_dev *pdev = ndev->ntb.pdev;
	u32 val;
	int i;

	/* Set Igress ALUT entries. */
	for (i = 0; i < ndev->alut; i++) {
		if (ndev->mw_count > 0 && ndev->mw_info[0].mw_bar == 2 &&
		    ndev->mw_info[0].mw_size > i * ndev->segment_size) {
			val = ndev->peer_nt_gid;	/* Target. */
			val |= i << 16;	/* Target's Egress entry index. */
			val |= 1 << 31;	/* Entry is valid. */
		} else {
			val = 0; /* Disable entries outsize the BAR2. */
		}
		dev_err(&ndev->ntb.pdev->dev, "IALUT %u %08x\n", i, val);
		pci_write_config_dword(pdev, BROADCOM_NT_INGRESS_INDEX_REG, i);
		pci_write_config_dword(pdev, BROADCOM_NT_INGRESS_ENTRY_REG, val);
	}

	/* Set Egress ALUT entries. */
	for (i = 0; i < ndev->mw_count; i++)
		broadcom_ntb_mw_set_trans_internal(ntb, i);

	return 0;
}

static irqreturn_t broadcom_isr(int irq, void *dev)
{
	struct broadcom_ntb_dev *ndev = dev;

	ntb_db_event(&ndev->ntb, 0);

	return IRQ_HANDLED;
}

static int broadcom_init_isr(struct broadcom_ntb_dev *ndev)
{
	struct pci_dev *pdev = ndev->ntb.pdev;
	int rc, irq;

	/*
	 * The device supports up to 32 MSI interrupts, but only one per peer bus.
	 */
	rc = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (rc < 0)
		return rc;
	irq = pci_irq_vector(pdev, 0);
	if (irq < 0) {
		pci_free_irq_vectors(pdev);
		return irq;
	}
	rc = devm_request_irq(&pdev->dev, irq, broadcom_isr, IRQF_SHARED,
			      NTB_NAME, ndev);
	if (rc) {
		pci_free_irq_vectors(pdev);
		return rc;
	}

	broadcom_nt_reg_write(ndev, BROADCOM_NT_IRQ_STATUS_REG, 0xffff);

	return 0;
}

static void broadcom_deinit_isr(struct broadcom_ntb_dev *ndev)
{
	struct pci_dev *pdev = ndev->ntb.pdev;

	broadcom_nt_reg_write(ndev, BROADCOM_NT_IRQ_MASK_SET_REG, 0xffff);

	devm_free_irq(&pdev->dev, pci_irq_vector(pdev, 0), ndev);
	pci_free_irq_vectors(pdev);
}

static int broadcom_init_dev(struct ntb_dev *ntb)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	struct broadcom_ntb_mw_info *mw;
	struct pci_dev *pdev;
	int i, rc = 0, b32 = 0, b64 = 0;
	u32 val, vsec;

	pdev = ndev->ntb.pdev;

	vsec = ndev->lvsec = pci_find_vsec_capability(pdev, 0x1000, 0x0500);
	if (vsec == 0)
		return -EIO;

	/*
	 * Fetch local/peer port GIDs (domain/switch ID/port number).
	 * We require peer GID to be set by configuration for discovery.
	 */
	pci_read_config_dword(pdev, vsec + BROADCOM_LEGACY_NT_MY_GID_OFFSET, &val);
	ndev->local_port_gid = val & 0x00ffffff;
	pci_read_config_dword(pdev, vsec + BROADCOM_LEGACY_NT_PEER_GID_OFFSET, &val);
	if (val == BROADCOM_NT_NOT_PAIRED) {
		if ((ndev->local_port_gid >> 16) == 0x01) {
			val = 0x020000 | (ndev->local_port_gid & 0xffff);
		} else if ((ndev->local_port_gid >> 16) == 0x02) {
			val = 0x010000 | (ndev->local_port_gid & 0xffff);
		} else {
			dev_err(&pdev->dev, "Can't guess peer domain (%x)\n",
			    (ndev->local_port_gid >> 16));
			return -ENXIO;
		}
		pci_write_config_dword(pdev, vsec + BROADCOM_LEGACY_NT_PEER_GID_OFFSET, val);
	}
	ndev->peer_port_gid = val & 0x00ffffff;

	/* Fetch domain/bus of local NT.  Expect the same domain. */
	pci_read_config_dword(pdev, BROADCOM_NT_CONFIGURATION_REG, &val);
	ndev->local_nt_gid = val & 0x0000ffff;
	if ((ndev->local_nt_gid >> 8) != (ndev->local_port_gid >> 16)) {
		dev_err(&pdev->dev, "Local domain is inconsistent (%x != %x)\n",
		    (ndev->local_nt_gid >> 8), (ndev->local_port_gid >> 16));
		return -ENXIO;
	}
	/* Assume peer has the same topology, just a different domain. */
	ndev->peer_nt_gid = (ndev->peer_port_gid & 0xff0000) >> 8 |
	    (val & 0x000000ff);

	/* Fetch ALUT configuration. */
	pci_read_config_dword(pdev, BROADCOM_NT_LUT_SIZES_REG, &val);
	ndev->segment_size = 1 << ((val & 0x0000fc00) >> 10);
	if (ndev->segment_size < 4096) {
		dev_err(&pdev->dev, "Segment size is less than 4KB (%llu)\n",
			ndev->segment_size);
		return -ENXIO;
	}
	ndev->alut = val & 0x000003ff;
	if (ndev->alut == 0) {
		/* Specs don't describe translation without ALUT */
		dev_err(&pdev->dev, "ALUT is disabled\n");
		return -ENXIO;
	}

	/* Find configured memory windows at BAR2-5 */
	ndev->mw_count = 0;
	for (i = 2; i <= 2 + BROADCOM_MAX_BARS - 1; i++) {
		mw = &ndev->mw_info[ndev->mw_count];
		mw->mw_bar = i;
		mw->mw_pbase = pci_resource_start(pdev, mw->mw_bar);
		mw->mw_size = pci_resource_len(pdev, mw->mw_bar);
		/* We can't map more BAR2 segments than number of ALUT entries. */
		if (i == 2 && ndev->alut > 0 &&
		    mw->mw_size > ndev->segment_size * ndev->alut) {
			dev_warn(&pdev->dev, "BAR2 is too big for the ALUT (%llu > %llu)\n",
			    (long long)mw->mw_size, (long long)ndev->segment_size * ndev->alut);
			mw->mw_size = ndev->segment_size * ndev->alut;
		}
		ndev->mw_count++;

		/* Skip over adjacent BAR for 64-bit BARs */
		rc = pci_read_config_dword(pdev, PCIR_BAR(mw->mw_bar), &val);
		if ((val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64) {
			mw->mw_64bit = 1;
			i++;
			b64++;
		} else {
			b32++;
		}
	}

	ndev->ntb.topo = NTB_TOPO_CROSSLINK;

	if (usplit == 0) {
		/* No memory window split. */
	} else if (ndev->mw_count == 0 || ndev->mw_info[0].mw_bar != 2) {
		dev_warn(&pdev->dev, "Can't split disabled BAR2\n");
		ndev->split = 0;
	} else if (usplit > 31 || (1U << usplit) > BROADCOM_MAX_SPLIT) {
		dev_warn(&pdev->dev, "Split value is too high (%u)\n", usplit);
		ndev->split = 0;
	} else if ((1 << usplit) > ndev->alut) {
		dev_warn(&pdev->dev, "Not enough A-LUT entries for the split (%u < %u)\n",
		    ndev->alut, 1 << usplit);
		ndev->split = 0;
	} else if ((ndev->segment_size << usplit) > ndev->mw_info[0].mw_size) {
		dev_warn(&pdev->dev, "BAR2 is too small for the split (%llu < %llu)\n",
		    (long long)ndev->mw_info[0].mw_size,
		    (long long)(ndev->segment_size << usplit));
		ndev->split = 0;
	} else {
		ndev->split = usplit;
		dev_info(&pdev->dev, "Splitting BAR2 into %d memory windows\n",
		    1 << ndev->split);
	}

	/* We have to share scratchpads with the peer. */
	ndev->pspad_off = ndev->sspad_off = vsec + BROADCOM_LEGACY_NT_SCRATCH_0_OFFSET;
	if (ndev->local_port_gid < ndev->peer_port_gid) {
		ndev->sspad_off += BROADCOM_NUM_SPAD / 2 * 4;
	} else {
		ndev->pspad_off += BROADCOM_NUM_SPAD / 2 * 4;
	}
	ndev->spad_cnt = BROADCOM_NUM_SPAD / 2;

	/* Apply static part of NTB configuration */
	rc = broadcom_init_ntb(ntb);
	if (rc)
		return rc;

	pci_set_master(pdev);

	/* Request 64-bit DMA if we have at least one 64-bit BAR. */
	rc = -EIO;
	if (b64)
		rc = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (rc)
		rc = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
	if (rc)
		return rc;

	/* Request 64-bit coherent DMA if we have 64-bit BAR(s), but not 32. */
	rc = -EIO;
	if (b64 && !b32)
		rc = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (rc)
		rc = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
	if (rc)
		return rc;

	/* Allocate and setup interrupts */
	rc = broadcom_init_isr(ndev);

	return rc;
}

static void broadcom_deinit_dev(struct broadcom_ntb_dev *ndev)
{
	broadcom_deinit_isr(ndev);
}

static int broadcom_ntb_spad_count(struct ntb_dev *ntb)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);

	return (ndev->spad_cnt);
}

static int broadcom_ntb_spad_write(struct ntb_dev *ntb, int idx, u32 val)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset;

	if (idx < 0 || idx >= ndev->spad_cnt)
		return -EINVAL;

	offset = ndev->sspad_off + idx * 4;
	pci_write_config_dword(ndev->ntb.pdev, offset, val);

	return 0;
}

static u32 broadcom_ntb_spad_read(struct ntb_dev *ntb, int idx)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset, val;

	if (idx < 0 || idx >= ndev->spad_cnt)
		return 0;

	offset = ndev->sspad_off + idx * 4;
	pci_read_config_dword(ndev->ntb.pdev, offset, &val);

	return val;
}

static int broadcom_ntb_peer_spad_write(struct ntb_dev *ntb, int pidx, int sidx, u32 val)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset;

	if (sidx < 0 || sidx >= ndev->spad_cnt)
		return -EINVAL;

	offset = ndev->pspad_off + sidx * 4;
	pci_write_config_dword(ndev->ntb.pdev, offset, val);

	return 0;
}

static u32 broadcom_ntb_peer_spad_read(struct ntb_dev *ntb, int pidx, int sidx)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset, val;

	if (sidx < 0 || sidx >= ndev->spad_cnt)
		return -EINVAL;

	offset = ndev->pspad_off + sidx * 4;
	pci_read_config_dword(ndev->ntb.pdev, offset, &val);

	return val;
}

static u64 broadcom_ntb_db_valid_mask(struct ntb_dev *ntb)
{
	return ((1LL << BROADCOM_NUM_DB) - 1);
}

static int broadcom_ntb_db_vector_count(struct ntb_dev *ntb)
{
	return 1;
}

static u64 broadcom_ntb_db_vector_mask(struct ntb_dev *ntb, int db_vector)
{
	if (db_vector > 0)
		return 0;

	return ((1LL << BROADCOM_NUM_DB) - 1);
}

static int broadcom_ntb_db_clear(struct ntb_dev *ntb, u64 db_bits)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);

	broadcom_nt_reg_write(ndev, BROADCOM_NT_IRQ_STATUS_REG, 0xffff);

	return 0;
}

static int broadcom_ntb_db_clear_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);

	broadcom_nt_reg_write(ndev, BROADCOM_NT_IRQ_MASK_CLEAR_REG, 0xffff);

	return 0;
}

static u64 broadcom_ntb_db_read(struct ntb_dev *ntb)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);
	u32 val;

	val = broadcom_nt_reg_read(ndev, BROADCOM_NT_IRQ_STATUS_REG);

	return val != 0;
}

static int broadcom_ntb_db_set_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);

	broadcom_nt_reg_write(ndev, BROADCOM_NT_IRQ_MASK_SET_REG, 0xffff);

	return 0;
}

static int broadcom_ntb_peer_db_addr(struct ntb_dev *ntb, phys_addr_t *db_addr,
    resource_size_t *db_size, u64 *db_data, int db_bit)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);

	*db_addr = pci_resource_start(ntb->pdev, 0) + BROADCOM_NT_DOORBELL_REG;
	*db_size = 4;
	if (db_data)
		*db_data = ndev->peer_nt_gid;

	return 0;
}

static int broadcom_ntb_peer_db_set(struct ntb_dev *ntb, u64 db_bits)
{
	struct broadcom_ntb_dev *ndev = ntb_ndev(ntb);

	broadcom_nt_reg_write(ndev, BROADCOM_NT_DOORBELL_REG, ndev->peer_nt_gid);

	return 0;
}

static ssize_t ndev_debugfs_read(struct file *filp, char __user *ubuf, size_t count,
				 loff_t *offp)
{
	struct broadcom_ntb_dev *ndev;
	struct pci_dev *pdev;
	void __iomem *mmio;
	ssize_t ret, off;
	size_t buf_size;
	char *buf;

	ndev = filp->private_data;
	pdev = ndev->ntb.pdev;
	mmio = ndev->self_mmio;

	buf_size = min(count, 0x800ul);

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	off = 0;
	off += scnprintf(buf + off, buf_size - off, "NTB Device Information:\n");
	off += scnprintf(buf + off, buf_size - off, "Connection Topology -\t%s\n",
			 ntb_topo_string(ndev->ntb.topo));
	off += scnprintf(buf + off, buf_size - off, "Local Port GID -\t\t%06x\n", ndev->local_port_gid);
	off += scnprintf(buf + off, buf_size - off, "Peer Port GID -\t\t%06x\n", ndev->peer_port_gid);
	off += scnprintf(buf + off, buf_size - off, "Local NT GID -\t\t%04x\n", ndev->local_nt_gid);
	off += scnprintf(buf + off, buf_size - off, "Peer NT GID -\t\t%04x\n", ndev->peer_nt_gid);
	off += scnprintf(buf + off, buf_size - off, "Segment Size -\t\t%04llx\n", ndev->segment_size);
	off += scnprintf(buf + off, buf_size - off, "ALUT entries -\t\t%04x\n", ndev->alut);
	off += scnprintf(buf + off, buf_size - off, "BAR2 Split -\t\t%u\n", ndev->split);
	off += scnprintf(buf + off, buf_size - off, "MW Count - \t\t%u\n", ndev->mw_count);
	off += scnprintf(buf + off, buf_size - off, "SPAD Count - \t\t%u\n", ndev->spad_cnt);
	off += scnprintf(buf + off, buf_size - off, "SPAD Offset - \t\t%u\n", ndev->sspad_off);

	ret = simple_read_from_buffer(ubuf, count, offp, buf, off);
	kfree(buf);
	return ret;
}

static void ndev_deinit_debugfs(struct broadcom_ntb_dev *ndev)
{
	debugfs_remove_recursive(ndev->debugfs_dir);
}

static const struct ntb_dev_ops broadcom_ntb_ops = {
	.mw_count = broadcom_ntb_mw_count,
	.mw_get_align = broadcom_ntb_mw_get_align,
	.mw_set_trans = broadcom_ntb_mw_set_trans,
	.mw_clear_trans = broadcom_ntb_mw_clear_trans,
	.peer_mw_count = broadcom_ntb_peer_mw_count,
	.peer_mw_get_addr = broadcom_ntb_peer_mw_get_addr,
	.link_is_up = broadcom_ntb_link_is_up,
	.link_enable = broadcom_ntb_link_enable,
	.link_disable = broadcom_ntb_link_disable,
	.db_valid_mask = broadcom_ntb_db_valid_mask,
	.db_vector_count = broadcom_ntb_db_vector_count,
	.db_vector_mask = broadcom_ntb_db_vector_mask,
	.db_read = broadcom_ntb_db_read,
	.db_clear = broadcom_ntb_db_clear,
	.db_set_mask = broadcom_ntb_db_set_mask,
	.db_clear_mask = broadcom_ntb_db_clear_mask,
	.peer_db_addr = broadcom_ntb_peer_db_addr,
	.peer_db_set = broadcom_ntb_peer_db_set,
	.spad_count = broadcom_ntb_spad_count,
	.spad_read = broadcom_ntb_spad_read,
	.spad_write = broadcom_ntb_spad_write,
	.peer_spad_read = broadcom_ntb_peer_spad_read,
	.peer_spad_write = broadcom_ntb_peer_spad_write,
};

static const struct file_operations broadcom_ntb_debugfs_info = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = ndev_debugfs_read,
};

static void ndev_init_debugfs(struct broadcom_ntb_dev *ndev)
{
	if (!debugfs_dir) {
		ndev->debugfs_dir = NULL;
		ndev->debugfs_info = NULL;
	} else {
		ndev->debugfs_dir = debugfs_create_dir(pci_name(ndev->ntb.pdev),
						       debugfs_dir);
		if (!ndev->debugfs_dir)
			ndev->debugfs_info = NULL;
		else
			ndev->debugfs_info = debugfs_create_file("info", 0400,
								 ndev->debugfs_dir, ndev,
								 &broadcom_ntb_debugfs_info);
	}
}

static int broadcom_ntb_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct broadcom_ntb_dev *ndev;
	int rc, node;

	node = dev_to_node(&pdev->dev);
	ndev = kzalloc_node(sizeof(*ndev), GFP_KERNEL, node);
	if (!ndev) {
		rc = -ENOMEM;
		goto err_ndev;
	}
	ndev->ntb.pdev = pdev;
	ndev->ntb.topo = NTB_TOPO_NONE;
	ndev->ntb.ops = &broadcom_ntb_ops;

	rc = broadcom_ntb_init_pci(ndev, pdev);
	if (rc)
		goto err_init_pci;

	rc = broadcom_init_dev(&ndev->ntb);
	if (rc)
		goto err_init_dev;

	ndev_init_debugfs(ndev);

	rc = ntb_register_device(&ndev->ntb);
	if (rc)
		goto err_register;

	dev_info(&pdev->dev, "NTB device registered.\n");

	return 0;

err_register:
	ndev_deinit_debugfs(ndev);
	broadcom_deinit_dev(ndev);
err_init_dev:
	broadcom_ntb_deinit_pci(ndev);
err_init_pci:
	kfree(ndev);
err_ndev:
	return rc;
}

static void broadcom_ntb_pci_remove(struct pci_dev *pdev)
{
	struct broadcom_ntb_dev *ndev = pci_get_drvdata(pdev);

	ntb_unregister_device(&ndev->ntb);
	ndev_deinit_debugfs(ndev);
	broadcom_deinit_dev(ndev);
	broadcom_ntb_deinit_pci(ndev);
	kfree(ndev);
}

static const struct pci_device_id broadcom_ntb_pci_tbl[] = {
	/* Broadcom NT2.0 devices identified by subsystem matching. */
	{PCI_DEVICE_SUB(0x1000, 0xC030, 0x1000, 0x2004), 0},
	{PCI_DEVICE_SUB(0x1000, 0xC034, 0x1000, 0x2004), 0},
	{0}
};
MODULE_DEVICE_TABLE(pci, broadcom_ntb_pci_tbl);

static struct pci_driver broadcom_ntb_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = broadcom_ntb_pci_tbl,
	.probe = broadcom_ntb_pci_probe,
	.remove = broadcom_ntb_pci_remove,
};

static int __init broadcom_ntb_pci_driver_init(void)
{
	pr_info("%s %s\n", NTB_DESC, NTB_VER);

	if (debugfs_initialized())
		debugfs_dir = debugfs_create_dir(KBUILD_MODNAME, NULL);

	return pci_register_driver(&broadcom_ntb_pci_driver);
}
module_init(broadcom_ntb_pci_driver_init);

static void __exit broadcom_ntb_pci_driver_exit(void)
{
	pci_unregister_driver(&broadcom_ntb_pci_driver);
	debugfs_remove_recursive(debugfs_dir);
}
module_exit(broadcom_ntb_pci_driver_exit);
