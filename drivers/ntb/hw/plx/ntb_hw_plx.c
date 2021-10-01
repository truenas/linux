// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)

/*
 * The Non-Transparent Bridge (NTB) is a device that allows you to connect
 * two or more systems using a PCI-e links, providing remote memory access.
 *
 * This module contains a driver for NTBs in PLX/Avago/Broadcom PCIe bridges.
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

#define NTB_NAME	"ntb_hw_plx"
#define NTB_DESC	"PLX PCI-E Non-Transparent Bridge Driver"
#define NTB_VER		"1.0"

MODULE_DESCRIPTION(NTB_DESC);
MODULE_VERSION(NTB_VER);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Jeff Kirsher <jkirsher@ixsystems.com>, Alexander Motin <mav@ixsystems.com>");

/* PCI device IDs */
#define PCI_DEVICE_ID_PLX_NT0_LINK 0x87A0
#define PCI_DEVICE_ID_PLX_NT1_LINK 0x87A1
#define PCI_DEVICE_ID_PLX_NT0_VIRT 0x87B0
#define PCI_DEVICE_ID_PLX_NT1_VIRT 0x87B1

#define PLX_MAX_BARS		4	/* There are at most 4 data BARs. */
#define PLX_NUM_SPAD		8	/* There are 8 scratchpads. */
#define PLX_NUM_SPAD_PATT	4	/* Use test pattern as 4 more. */
#define PLX_NUM_DB		16	/* There are 16 doorbells. */
#define PLX_MAX_SPLIT		128	/* Allow at most 128 splits. */

static struct dentry *debugfs_dir;

struct plx_ntb_mw_info {
	int		mw_bar;
	int		mw_64bit;
	void __iomem	*mw_res;
	unsigned long	mw_pbase;
	unsigned long	mw_size;
	struct {
		unsigned long mw_xlat_addr;
		unsigned long mw_xlat_size;
	} splits[PLX_MAX_SPLIT];
};

struct plx_ntb_dev {
	struct ntb_dev ntb;

	unsigned int ntx;
	unsigned int link;
	u32 port;
	u32 alut;
	u32 split;  /* split BAR2 into 2^x parts */

	struct plx_ntb_mw_info mw_info[PLX_MAX_BARS];
	unsigned char mw_count;
	unsigned char spad_cnt1;   /* Number of standard spads */
	unsigned char spad_cnt2;   /* Number of extra spads */
	u32 sspad_off1;  /* Offset of our spads */
	u32 sspad_off2;  /* Offset of our extra spads */
	u32 pspad_off1;  /* Offset of peer spads */
	u32 pspad_off2;  /* Offset of peer extra spads */

	struct msix_entry *msix;

	void __iomem *self_mmio;

	struct dentry *debugfs_dir;
	struct dentry *debugfs_info;

	/* Parameters of window shared with peer config access in B2B mode. */
	unsigned int b2b_mw;	/* Shared window number. */
	u64 b2b_off;	/* Offset in shared window. */
};

#define NTB_LNK_STA_SPEED_MASK	0x000F
#define NTB_LNK_STA_WIDTH_MASK	0x03F0
#define NTB_LNK_STA_SPEED(x)	((x) & NTB_LNK_STA_SPEED_MASK)
#define NTB_LNK_STA_WIDTH(x)	(((x) & NTB_LNK_STA_WIDTH_MASK) >> 4)

#define PLX_NT0_BASE			0x3E000
#define PLX_NT1_BASE			0x3C000
#define PLX_NTX_BASE(sc)		((sc)->ntx ? PLX_NT1_BASE : PLX_NT0_BASE)
#define PLX_NTX_LNK_OFFSET		0x01000

#define PLX_PHY_USR_TST_PATRN		0x20C

#define PLX_VS0_OFFSET			0x360
#define PLX_VS1_OFFSET			0x364

/* Interrupt Registers */
#define PLX_VIRT_INT_IRQ_SET		0xC4C
#define PLX_VIRT_INT_IRQ_CLEAR		0xC50
#define PLX_VIRT_INT_IRQ_MASK_SET	0xC54
#define PLX_VIRT_INT_IRQ_MASK_CLEAR	0xC58
#define PLX_LNK_INT_IRQ_SET		0xC5C
#define PLX_LNK_INT_IRQ_CLEAR		0xC60
#define PLX_LNK_INT_IRQ_MASK_SET	0xC64
#define PLX_LNK_INT_IRQ_MASK_CLEAR	0xC68

#define PLX_NTX_PORT_SCRATCH0		0xC6C
#define PLX_NTX_PORT_ID			0xC8C
#define PLX_NTX_REQ_ID_RD_BK		0xC90
#define PLX_NTX_LNK_ALUT_CNTRL		0xC94
#define PLX_NTX_REQ_ID_LUT00		0xD94
#define PLX_NTX_REQ_ID_LUT02		0xD98
#define PLX_NTX_REQ_ID_LUT04		0xD9C
#define PLX_NTX_REQ_ID_LUT16		0xDB4
#define PLX_NTX_REQ_ID_LUT18		0xDB8
#define PLX_NTX_REQ_ID_LUT20		0xDBC
#define PLX_VIRT_LNK_ERR_STATUS		0xFE0
#define PLX_VIRT_LNK_ERR_MASK		0xFE4

#define PLX_MEM_BAR2_ADDR		0xC3C
#define PLX_MEM_BAR0_SETUP		0xE4
#define PLX_MEM_BAR2_SETUP		0xE8

#define ntb_ndev(__ntb) container_of(__ntb, struct plx_ntb_dev, ntb)

/* Bases of NTx our/peer interface registers */
#define PLX_NTX_OUR_BASE(sc)				\
	(PLX_NTX_BASE(sc) + ((sc)->link ? PLX_NTX_LNK_OFFSET : 0))
#define PLX_NTX_PEER_BASE(sc)				\
	(PLX_NTX_BASE(sc) + ((sc)->link ? 0 : PLX_NTX_LNK_OFFSET))

/* NTx our interface registers */
#define SELF_BASE(n)			((n)->self_mmio + PLX_NTX_OUR_BASE(n))

/* NTx peer interface registers */
#define PEER_BASE(n)			((n)->self_mmio + PLX_NTX_PEER_BASE(n))

/* B2B NTx registers */
#define B2B_BASE(n)			((n)->mw_info[(n)->b2b_mw].mw_res)
#define B2B_REG(n, reg)			(PLX_NTX_BASE(n) + (reg))

#define PLX_PORT_BASE(p)		((p) << 12)
#define PLX_STATION_PORT_BASE(sc)	PLX_PORT_BASE((sc)->port & ~7)

#define PLX_PORT_CONTROL(sc)		(PLX_STATION_PORT_BASE(sc) + 0x208)

/* PCI defines and macros */
#define powerof2(x)			((((x) - 1) & (x)) == 0)
#define PCIR_BAR(x)			(PCI_BASE_ADDRESS_0 + (x) * 4)

#define UINT32_MAX 0xFFFFFFFF
#define UINT64_MAX 0xFFFFFFFFFFFFFFFF


static uint b2b_mode = 1;
module_param(b2b_mode, uint, 0644);
MODULE_PARM_DESC(b2b_mode,
		 "NTB-to-NTB (back-to-back) mode, default is 1: 1 = Enabled, 0 = Disabled");

static uint usplit;
module_param(usplit, uint, 0644);
MODULE_PARM_DESC(usplit,
		 "Split BAR2 into 2^x parts, default is 0: valid entries (0..7)");

static void ndev_deinit_isr(struct plx_ntb_dev *ndev)
{
	struct pci_dev *pdev;

	pdev = ndev->ntb.pdev;

	/* Link Interface has no Link Error registers. */
	if (!ndev->link)
		writel(0xf, SELF_BASE(ndev) + PLX_VIRT_LNK_ERR_MASK); /* Mask link interrupts */

	pci_intx(pdev, 0);
}

static int plx_ntb_init_pci(struct plx_ntb_dev *ndev, struct pci_dev *pdev)
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

static void plx_ntb_deinit_pci(struct plx_ntb_dev *ndev)
{
	struct pci_dev *pdev = ndev->ntb.pdev;
	struct plx_ntb_mw_info *mw;
	int i;

	for (i = 0; i < ndev->mw_count; i++) {
		mw = &ndev->mw_info[i];
		pcim_iounmap(pdev, mw->mw_res);
	}
	pcim_iounmap(pdev, ndev->self_mmio);

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
}

static void plx_deinit_dev(struct plx_ntb_dev *ndev)
{
	ndev_deinit_isr(ndev);
}

static u64 plx_ntb_link_is_up(struct ntb_dev *ntb, enum ntb_speed *speed, enum ntb_width *width)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	u16 link;

	if (pcie_capability_read_word(ndev->ntb.pdev, PCI_EXP_LNKSTA, &link))
		return 0;
	if (speed)
		*speed = NTB_LNK_STA_SPEED(link);
	if (width)
		*width = NTB_LNK_STA_WIDTH(link);
	return NTB_LNK_STA_WIDTH(link) != 0;
}

static int plx_ntb_link_enable(struct ntb_dev *ntb, enum ntb_speed max_speed,
			       enum ntb_width max_width)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	u32 val, reg;

	/* if we see the link interface, then the link is enabled */
	if (ndev->link) {
		ntb_link_event(&ndev->ntb);
		return 0;
	}

	reg = PLX_PORT_CONTROL(ndev);
	val = ioread32(ndev->self_mmio + reg);
	if ((val & (1 << (ndev->port & 7))) == 0) {
		/* If already enabled, generate a link event and exit */
		ntb_link_event(&ndev->ntb);
		return 0;
	}
	val &= ~(1 << (ndev->port & 7));
	iowrite32(val, ndev->self_mmio + reg);

	return 0;
}

static int plx_ntb_link_disable(struct ntb_dev *ntb)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	u32 val, reg;

	/* If there is no link interface, no need to disable link */
	if (ndev->link)
		return 0;

	dev_dbg(&ntb->pdev->dev, "Disabling link\n");

	reg = PLX_PORT_CONTROL(ndev);
	val = ioread32(ndev->self_mmio + reg);
	val |= (1 << (ndev->port & 7));
	iowrite32(val, ndev->self_mmio + reg);

	return 0;
}

static int plx_ntb_mw_count(struct ntb_dev *ntb, int pidx)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	int res;

	res = ndev->mw_count;
	res += (1 << ndev->split) - 1;
	if (ndev->b2b_mw >= 0 && ndev->b2b_off == 0)
		res--; /* B2B consumed the whole window */

	return res;
}

static int plx_ntb_peer_mw_count(struct ntb_dev *ntb)
{
	return plx_ntb_mw_count(ntb, 0);
}

static unsigned int plx_ntb_user_mw_to_idx(struct plx_ntb_dev *ndev, int idx, unsigned int *sp)
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

static int plx_ntb_peer_mw_get_addr(struct ntb_dev *ntb, int idx, phys_addr_t *base,
				    resource_size_t *size)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	struct plx_ntb_mw_info *mw;
	resource_size_t offset, ss;
	unsigned int sp, split;

	idx = plx_ntb_user_mw_to_idx(ndev, idx, &sp);
	if (idx >= ndev->mw_count)
		return -EINVAL;
	offset = 0;
	if (idx == ndev->b2b_mw) {
		/* User should not get non-shared B2B MW */
		BUG_ON(ndev->b2b_off != 0);
		offset = ndev->b2b_off;
	}
	mw = &ndev->mw_info[idx];
	split = (mw->mw_bar == 2) ? ndev->split : 0;
	ss = (mw->mw_size - offset) >> split;

	if (base)
		*base = mw->mw_pbase + offset + ss * sp;
	if (size)
		*size = ss;

	return 0;
}

static int plx_ntb_mw_get_align(struct ntb_dev *ntb, int pidx, int idx,
				resource_size_t *addr_align,
				resource_size_t *size_align,
				resource_size_t *size_max)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	struct plx_ntb_mw_info *mw;
	resource_size_t offset;
	unsigned int sp;

	idx = plx_ntb_user_mw_to_idx(ndev, idx, &sp);
	if (idx >= ndev->mw_count)
		return -EINVAL;
	offset = 0;
	if (idx == ndev->b2b_mw) {
		WARN(ndev->b2b_off != 0, "User should not get non-shared B2B MW\n");
		offset = ndev->b2b_off;
	}
	mw = &ndev->mw_info[idx];

	/* Remote to local memory window translation address alignment
	 * Translation address has to be aligned to the BAR size, but A-LUT
	 * entries re-map addresses can be aligned to 1/128 or 1/256 of it.
	 * XXX: In B2B mode we can change BAR size (and so alignment) live,
	 * but there is no way to report it here, so report safe value.
	 */
	if (addr_align) {
		if (ndev->alut && mw->mw_bar == 2)
			*addr_align = (mw->mw_size - offset) / 128 / ndev->alut;
		else
			*addr_align = mw->mw_size - offset;
	}

	/* Remote to local memory window size alignment
	 * The chip has no limit registers, but A-LUT (when available), allows
	 * access control with granularity of 1/128 or 1/256 of the BAR size.
	 * XXX: In B2B case we can change BAR size live, but there is no way to
	 * report it, so report half of the BAR size, that should be safe.  In
	 * non-B2B case there is no control at all, so report the BAR size.
	 */
	if (size_align) {
		if (ndev->alut && mw->mw_bar == 2)
			*size_align = (mw->mw_size - offset) / 128 / ndev->alut;
		else if (ndev->b2b_mw >= 0)
			*size_align = (mw->mw_size - offset) / 2;
		else
			*size_align = mw->mw_size - offset;
	}

	if (size_max) {
		*size_max = (mw->mw_size - offset) >> ndev->split;
	}

	return 0;
}

static int plx_ntb_mw_set_trans_internal(struct ntb_dev *ntb, int idx)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	struct plx_ntb_mw_info *mw;
	u64 addr, eaddr, off, size, bsize, esize, val64;
	u32 val;
	unsigned int i, sp, split;

	mw = &ndev->mw_info[idx];
	off = (idx == ndev->b2b_mw) ? ndev->b2b_off : 0;
	split = (mw->mw_bar == 2) ? ndev->split : 0;

	/* Get BAR size and in the case of split or B2RP we cannot change it */
	if (split || ndev->b2b_mw < 0) {
		bsize = mw->mw_size - off;
	} else {
		bsize = mw->splits[0].mw_xlat_size;
		if (!powerof2(bsize))
			bsize = 1LL << fls64(bsize);
		if (bsize > 0 && bsize < 1024 * 1024)
			bsize = 1024 * 1024;
	}

	/* While for B2B we can set any BAR size on a link side, for a shared window,
	 * we cannot go above a pre-configured size due to BAR address alignment
	 * requirements
	 */
	if ((off & (bsize - 1)) != 0)
		return -EINVAL;

	/* In B2B mode, set the Link Interface BAR size/address */
	if (ndev->b2b_mw >= 0 && mw->mw_64bit) {
		val64 = 0;
		if (bsize > 0)
			val64 = (~(bsize - 1) & ~0xfffff);
		val64 |= 0xc;
		writel(val64, PEER_BASE(ndev) + PLX_MEM_BAR2_SETUP + (mw->mw_bar - 2) * 4);
		writel(val64 >> 32, PEER_BASE(ndev) + PLX_MEM_BAR2_SETUP + (mw->mw_bar - 2) * 4);

		val64 = 0x2000000000000000 * mw->mw_bar + off;
		writel(val64, PEER_BASE(ndev) + PCIR_BAR(mw->mw_bar));
		writel(val64 >> 32, PEER_BASE(ndev) + PCIR_BAR(mw->mw_bar) + 4);
	} else if (ndev->b2b_mw >= 0) {
		val = 0;
		if (bsize > 0)
			val = (~(bsize - 1) & ~0xfffff);
		writel(val, PEER_BASE(ndev) + PLX_MEM_BAR2_SETUP + (mw->mw_bar - 2) * 4);

		val64 = 0x20000000 * mw->mw_bar + off;
		writel(val64, PEER_BASE(ndev) + PCIR_BAR(mw->mw_bar));
	}

	/* Set BARs address translation */
	addr = split ? UINT64_MAX : mw->splits[0].mw_xlat_addr;
	if (mw->mw_64bit) {
		writel(addr, PEER_BASE(ndev) + PLX_MEM_BAR2_ADDR + (mw->mw_bar - 2) * 4);
		writel(addr >> 32, PEER_BASE(ndev) + PLX_MEM_BAR2_ADDR + (mw->mw_bar - 2) * 4 + 4);
	} else {
		writel(addr, PEER_BASE(ndev) + PLX_MEM_BAR2_ADDR + (mw->mw_bar - 2) * 4);
	}

	/* Configure and enable A-LUT if we need it */
	size = split ? 0 : mw->splits[0].mw_xlat_size;
	if (ndev->alut && mw->mw_bar == 2 && (ndev->split > 0 ||
	    ((addr & (bsize - 1)) != 0 || size != bsize))) {
		esize = bsize / (128 * ndev->alut);
		for (i = sp = 0; i < 128 * ndev->alut; i++) {
			if (i % (128 * ndev->alut >> ndev->split) == 0) {
				eaddr = addr = mw->splits[sp].mw_xlat_addr;
				size = mw->splits[sp++].mw_xlat_size;
			}
			val = ndev->link ? 0 : 1;
			if (ndev->alut == 1)
				val += 2 * ndev->ntx;
			val *= 0x1000 * ndev->alut;
			val += 0x38000 + i * 4 + (i >= 128 ? 0x0e00 : 0);
			writel(eaddr, ndev->self_mmio + val);
			writel(eaddr >> 32, ndev->self_mmio + val + 0x400);
			writel((eaddr < addr + size) ? 0x3 : 0, ndev->self_mmio + val + 0x800);
			eaddr += esize;
		}
		writel(0x10000000, SELF_BASE(ndev) + PLX_NTX_LNK_ALUT_CNTRL);
	} else if (ndev->alut && mw->mw_bar == 2)
		writel(0, SELF_BASE(ndev) + PLX_NTX_LNK_ALUT_CNTRL);

	return 0;
}

static int plx_ntb_mw_set_trans(struct ntb_dev *ntb, int pidx, int idx,
				dma_addr_t addr, resource_size_t size)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	struct plx_ntb_mw_info *mw;
	unsigned int sp;

	if (pidx != NTB_DEF_PEER_IDX)
		return -EINVAL;

	idx = plx_ntb_user_mw_to_idx(ndev, idx, &sp);
	if (idx >= ndev->mw_count)
		return -EINVAL;

	mw = &ndev->mw_info[idx];
	if (!mw->mw_64bit && ((addr & UINT32_MAX) != addr ||
			      ((addr + size) & UINT32_MAX) != (addr + size)))
		return -ERANGE;

	mw->splits[sp].mw_xlat_addr = addr;
	mw->splits[sp].mw_xlat_size = size;

	return plx_ntb_mw_set_trans_internal(ntb, idx);
}

static int plx_init_ntb(struct ntb_dev *ntb)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	struct plx_ntb_mw_info *mw;
	u64 val64;
	u32 val;
	int i;

	if (ndev->b2b_mw >= 0) {
		/* Set peer BAR0/1 size and address for B2B NTx access */
		mw = &ndev->mw_info[ndev->b2b_mw];
		if (mw->mw_64bit) {
			writel(0x3, PEER_BASE(ndev) + PLX_MEM_BAR0_SETUP); /* 64-bit */
			val64 = 0x2000000000000000 * mw->mw_bar | 0x4;
			writel(val64, PEER_BASE(ndev) + PCIR_BAR(0));
			writel(val64 >> 32, PEER_BASE(ndev) + PCIR_BAR(0) + 4);
		} else {
			writel(0x2, PEER_BASE(ndev) + PLX_MEM_BAR0_SETUP); /* 32-bit */
			val = 0x20000000 * mw->mw_bar;
			writel(val, PEER_BASE(ndev) + PCIR_BAR(0));
		}

		/* Set Virtual to Link address translation for B2B */
		for (i = 0; i < ndev->mw_count; i++) {
			mw = &ndev->mw_info[i];
			if (mw->mw_64bit) {
				val64 = 0x2000000000000000 * mw->mw_bar;
				writel(val64, SELF_BASE(ndev) + PLX_MEM_BAR2_ADDR +
					      (mw->mw_bar - 2) * 4);
				writel(val64 >> 32, SELF_BASE(ndev) + PLX_MEM_BAR2_ADDR +
						    (mw->mw_bar - 2) * 4 + 4);
			} else {
				val = 0x20000000 * mw->mw_bar;
				writel(val, SELF_BASE(ndev) + PLX_MEM_BAR2_ADDR +
					    (mw->mw_bar - 2) * 4);
			}
		}

		/* Make sure Virtual to Link A-LUT is disabled */
		if (ndev->alut)
			writel(0, PEER_BASE(ndev) + PLX_NTX_LNK_ALUT_CNTRL);

		/* Enable all Link Interface LUT entries for peer */
		for (i = 0; i < 32; i += 2)
			writel(0x00010001 | ((i + 1) << 19) | (i << 3),
			       PEER_BASE(ndev) + PLX_NTX_REQ_ID_LUT16 + i * 2);
	}

	/* Enable Virtual Interface LUT entry 0 for 0:0.*
	 * Entry 1 is for our Requester ID reported by the chip and entries 2-5 are for
	 * 0/64/128/192:4.* of I/OAT DMA engines.
	 */
	val = (readl(SELF_BASE(ndev) + PLX_NTX_REQ_ID_RD_BK) << 16) | 0x00010001;
	writel(val, SELF_BASE(ndev) + (ndev->link ? PLX_NTX_REQ_ID_LUT16 : PLX_NTX_REQ_ID_LUT00));
	writel(0x40210021, SELF_BASE(ndev) + (ndev->link ? PLX_NTX_REQ_ID_LUT18 :
							   PLX_NTX_REQ_ID_LUT02));
	writel(0xc0218021, SELF_BASE(ndev) + (ndev->link ? PLX_NTX_REQ_ID_LUT20 :
							   PLX_NTX_REQ_ID_LUT04));

	/* Set Link to Virtual address translation */
	for (i = 0; i < ndev->mw_count; i++)
		plx_ntb_mw_set_trans_internal(ntb, i);

	if (ndev->b2b_mw >= 0)
		writel(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER, PEER_BASE(ndev) + PCI_COMMAND);

	return 0;
}

static irqreturn_t ndev_irq_isr(int irq, void *dev)
{
	struct plx_ntb_dev *ndev = dev;
	u32 val;

	ntb_db_event(&ndev->ntb, 0);

	/* Link Interface has no Link Error registers. */
	if (ndev->link)
		goto out;

	val = readl(SELF_BASE(ndev) + PLX_VIRT_LNK_ERR_STATUS);
	if (val == 0)
		goto out;
	writel(val, SELF_BASE(ndev) + PLX_VIRT_LNK_ERR_STATUS);
	if (val & 1)
		dev_info(&ndev->ntb.pdev->dev, "Correctable Error\n");
	if (val & 2)
		dev_info(&ndev->ntb.pdev->dev, "Uncorrectable Error\n");
	if (val & 4) {
		/* DL_Down resets link side registers, have to reinit */
		plx_init_ntb(&ndev->ntb);
		ntb_link_event(&ndev->ntb);
	}
	if (val & 8)
		dev_info(&ndev->ntb.pdev->dev, "Uncorrectable Error Message Drop\n");

out:
	return IRQ_HANDLED;
}

static int plx_init_isr(struct plx_ntb_dev *ndev)
{
	struct pci_dev *pdev;
	int rc;

	pdev = ndev->ntb.pdev;

	/* XXX: This hardware supports MSI, but it was found unusable.
	 * It generates new MSI only when doorbell register goes from zero,
	 * but does not generate it when another bit is set or on partial
	 * clear.  It makes operation very racy and unreliable.  The data book
	 * mentions some mask juggling magic to workaround that, but we failed
	 * to make it work.
	 */
	pci_intx(pdev, 1);
	rc = devm_request_irq(&pdev->dev, pdev->irq, ndev_irq_isr, IRQF_SHARED,
			      NTB_NAME, ndev);
	if (rc)
		return rc;

	/* Link Interface has no Link Error registers. */
	if (!ndev->link) {
		writel(0xf, SELF_BASE(ndev) + PLX_VIRT_LNK_ERR_STATUS); /* Clear link interrupts */
		writel(0x0, SELF_BASE(ndev) + PLX_VIRT_LNK_ERR_MASK); /* Unmask link interrupts */
	}

	return 0;
}

static int plx_init_dev(struct ntb_dev *ntb)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	struct plx_ntb_mw_info *mw;
	struct pci_dev *pdev;
	int i, rc = 0, b32 = 0, b64 = 0;
	u32 val;

	pdev = ndev->ntb.pdev;

	/* Identify what we are (what side of what NTx) */
	rc = pci_read_config_dword(pdev, PLX_NTX_PORT_ID, &val);
	if (rc)
		return -EIO;

	ndev->ntx = (val & 1) != 0;
	ndev->link = (val & 0x80000000) != 0;

	/* Identify chip port we are connected to */
	val = readl(ndev->self_mmio + PLX_VS0_OFFSET);
	ndev->port = (val >> ((ndev->ntx == 0) ? 8 : 16)) & 0x1f;

	/* Detect A-LUT enable and size */
	val >>= 30;
	ndev->alut = (val == 0x3) ? 1 : ((val & (1 << ndev->ntx)) ? 2 : 0);
	if (ndev->alut)
		dev_info(&pdev->dev, "%u A-LUT entries\n", 128 * ndev->alut);

	/* Find configured memory windows at BAR2-5 */
	ndev->mw_count = 0;
	for (i = 4; i <= 5; i++) {
		mw = &ndev->mw_info[ndev->mw_count];
		mw->mw_bar = i;
		mw->mw_res = pcim_iomap(pdev, mw->mw_bar, 0);
		if (!mw->mw_res)
			continue;
		mw->mw_pbase = pci_resource_start(pdev, mw->mw_bar);
		mw->mw_size = pci_resource_len(pdev, mw->mw_bar);
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

	/* Try to identify B2B mode, and check if B2B was disabled via module parameter */
	if (ndev->link) {
		dev_info(&pdev->dev, "NTB-to-Root Port mode (Link Interface)\n");
		ndev->b2b_mw = -1;
	} else if (b2b_mode == 0) {
		dev_info(&pdev->dev, "NTB-to-Root Port mode (Virtual Interface)\n");
		ndev->b2b_mw = -1;
	} else {
		dev_info(&pdev->dev, "NTB-to-NTB (back-to-back) mode\n");

		/* We need at least one memory window for B2B peer access */
		if (ndev->mw_count == 0) {
			dev_info(&pdev->dev, "No memory window BARs enabled.\n");
			rc = -ENXIO;
			goto out;
		}
		ndev->b2b_mw = ndev->mw_count - 1;

		/* Use half of the window for B2B, but no less than 1MB */
		mw = &ndev->mw_info[ndev->b2b_mw];
		if (mw->mw_size >= 2 * 1024 * 1024)
			ndev->b2b_off = mw->mw_size / 2;
		else
			ndev->b2b_off = 0;
	}

	/* Check the module parameter for user defined split value, default is 0 if
	 * no value was provided.
	 */
	if (usplit > 7) {
		dev_info(&pdev->dev, "Split value is too high (%u)\n", ndev->split);
		ndev->split = 0;
	} else if (usplit > 0 && ndev->alut == 0) {
		dev_info(&pdev->dev, "Cannot split with disabled A-LUT\n");
		ndev->split = 0;
	} else if (usplit > 0 && (ndev->mw_count == 0 || ndev->mw_info[0].mw_bar != 2)) {
		dev_info(&pdev->dev, "Can't split disabled BAR2\n");
		ndev->split = 0;
	} else if (usplit > 0 && (ndev->b2b_mw == 0 && ndev->b2b_off == 0)) {
		dev_info(&pdev->dev, "Can't split BAR2 consumed by B2B\n");
		ndev->split = 0;
	} else if (usplit > 0) {
		ndev->split = usplit;
		dev_info(&pdev->dev, "Splitting BAR2 into %d memory windows\n", 1 << ndev->split);
	}

	/* Use Physical Layer User Test Pattern as additional scratchpad and
	 * make sure they are preset and enabled by writing to them.
	 * XXX: Its a hack, but standard 8 registers are not enough
	 */
	ndev->pspad_off1 = ndev->sspad_off1 = PLX_NTX_OUR_BASE(ndev) + PLX_NTX_PORT_SCRATCH0;
	ndev->pspad_off2 = ndev->sspad_off2 = PLX_PORT_BASE(ndev->ntx * 8) + PLX_PHY_USR_TST_PATRN;
	if (ndev->b2b_mw >= 0) {
		/* In NTB-to-NTB mode each side has own scratchpads. */
		ndev->spad_cnt1 = PLX_NUM_SPAD;
		writel(0x12345678, ndev->self_mmio + ndev->sspad_off2);
		if (readl(ndev->self_mmio + ndev->sspad_off2) == 0x12345678)
			ndev->spad_cnt2 = PLX_NUM_SPAD_PATT;
	} else {
		/* Otherwise we have share scratchpads with the peer. */
		if (ndev->link) {
			ndev->sspad_off1 += PLX_NUM_SPAD / 2 * 4;
			ndev->sspad_off2 += PLX_NUM_SPAD_PATT / 2 * 4;
		} else {
			ndev->pspad_off1 += PLX_NUM_SPAD / 2 * 4;
			ndev->pspad_off2 += PLX_NUM_SPAD_PATT / 2 * 4;
		}
		ndev->spad_cnt1 = PLX_NUM_SPAD / 2;
		writel(0x12345678, ndev->self_mmio + ndev->sspad_off2);
		if (readl(ndev->self_mmio + ndev->sspad_off2) == 0x12345678)
			ndev->spad_cnt2 = PLX_NUM_SPAD_PATT / 2;
	}

	/* Apply static part of NTB configuration */
	rc = plx_init_ntb(ntb);
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
	rc = plx_init_isr(ndev);

out:
	return rc;
}

static int plx_ntb_mw_clear_trans(struct ntb_dev *ntb, int pidx, int widx)
{
	return plx_ntb_mw_set_trans(ntb, pidx, widx, 0, 0);
}

static int plx_ntb_spad_count(struct ntb_dev *ntb)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);

	return (ndev->spad_cnt1 + ndev->spad_cnt2);
}

static int plx_ntb_spad_write(struct ntb_dev *ntb, int idx, u32 val)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset;

	if (idx < 0 || idx >= ndev->spad_cnt1 + ndev->spad_cnt2)
		return -EINVAL;

	if (idx < ndev->spad_cnt1)
		offset = ndev->sspad_off1 + idx * 4;
	else
		offset = ndev->sspad_off2 + (idx - ndev->spad_cnt1) * 4;

	writel(val, ndev->self_mmio + offset);

	return 0;
}

static u32 plx_ntb_spad_read(struct ntb_dev *ntb, int idx)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset;

	if (idx < 0 || (idx >= ndev->spad_cnt1 + ndev->spad_cnt2))
		return 0;

	if (idx < ndev->spad_cnt1)
		offset = ndev->sspad_off1 + idx * 4;
	else
		offset = ndev->sspad_off2 + (idx - ndev->spad_cnt1) * 4;

	return readl(ndev->self_mmio + offset);
}

static int plx_ntb_peer_spad_write(struct ntb_dev *ntb, int pidx, int sidx, u32 val)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset;

	if (sidx < 0 || sidx >= ndev->spad_cnt1 + ndev->spad_cnt2)
		return -EINVAL;

	if (sidx < ndev->spad_cnt1)
		offset = ndev->pspad_off1 + sidx * 4;
	else
		offset = ndev->pspad_off2 + (sidx - ndev->spad_cnt1) * 4;
	if (ndev->b2b_mw >= 0)
		writel(val, ndev->mw_info[ndev->b2b_mw].mw_res + offset);
	else
		writel(val, ndev->self_mmio + offset);

	return 0;
}

static u32 plx_ntb_peer_spad_read(struct ntb_dev *ntb, int pidx, int sidx)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	u32 offset;

	if (sidx < 0 || sidx >= ndev->spad_cnt1 + ndev->spad_cnt2)
		return -EINVAL;

	if (sidx < ndev->spad_cnt1)
		offset = ndev->pspad_off1 + sidx * 4;
	else
		offset = ndev->pspad_off2 + (sidx - ndev->spad_cnt1) * 4;
	if (ndev->b2b_mw >= 0)
		return readl(ndev->mw_info[ndev->b2b_mw].mw_res + offset);
	else
		return readl(ndev->self_mmio + offset);
}

static u64 plx_ntb_db_valid_mask(struct ntb_dev *ntb)
{
	return ((1LL << PLX_NUM_DB) - 1);
}

static int plx_ntb_db_vector_count(struct ntb_dev *ntb)
{
	return 1;
}

static u64 plx_ntb_db_vector_mask(struct ntb_dev *ntb, int db_vector)
{
	if (db_vector > 0)
		return 0;

	return ((1LL << PLX_NUM_DB) - 1);
}

static int plx_ntb_db_clear(struct ntb_dev *ntb, u64 db_bits)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);

	writel(db_bits, SELF_BASE(ndev) + (ndev->link ? PLX_LNK_INT_IRQ_CLEAR :
							PLX_VIRT_INT_IRQ_CLEAR));

	return 0;
}

static int plx_ntb_db_clear_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);

	writel(db_bits, SELF_BASE(ndev) + (ndev->link ? PLX_LNK_INT_IRQ_MASK_CLEAR :
							PLX_VIRT_INT_IRQ_MASK_CLEAR));

	return 0;
}

static u64 plx_ntb_db_read(struct ntb_dev *ntb)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);

	return (u64)readl(SELF_BASE(ndev) + (ndev->link ? PLX_LNK_INT_IRQ_SET :
							  PLX_VIRT_INT_IRQ_SET));
}

static int plx_ntb_db_set_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);

	writel(db_bits, SELF_BASE(ndev) + (ndev->link ? PLX_LNK_INT_IRQ_MASK_SET :
							PLX_VIRT_INT_IRQ_MASK_SET));

	return 0;
}

static int plx_ntb_peer_db_addr(struct ntb_dev *ntb, phys_addr_t *db_addr, resource_size_t *db_size,
				u64 *db_data, int db_bit)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);
	struct plx_ntb_mw_info *mw;

	WARN((db_addr != NULL && db_size != NULL), "db_addr and db_size must be non-NULL\n");

	if (ndev->b2b_mw >= 0) {
		mw = &ndev->mw_info[ndev->b2b_mw];
		*db_addr = (u64)mw->mw_pbase + PLX_NTX_BASE(ndev) + PLX_VIRT_INT_IRQ_SET;
	} else {
		*db_addr = pci_resource_start(ntb->pdev, 0) + PLX_NTX_BASE(ndev);
		*db_addr += ndev->link ? PLX_VIRT_INT_IRQ_SET : PLX_LNK_INT_IRQ_SET;
	}
	*db_size = 4;

	if (db_data)
		*db_data = db_bit;

	return 0;
}

static int plx_ntb_peer_db_set(struct ntb_dev *ntb, u64 db_bits)
{
	struct plx_ntb_dev *ndev = ntb_ndev(ntb);

	if (ndev->b2b_mw >= 0)
		writel(db_bits, B2B_BASE(ndev) + B2B_REG(ndev, PLX_VIRT_INT_IRQ_SET));
	else
		writel(db_bits, SELF_BASE(ndev) + (ndev->link ? PLX_VIRT_INT_IRQ_SET :
							        PLX_LNK_INT_IRQ_SET));

	return 0;
}

static ssize_t ndev_debugfs_read(struct file *filp, char __user *ubuf, size_t count,
				 loff_t *offp)
{
	struct plx_ntb_dev *ndev;
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

	off += scnprintf(buf + off, buf_size - off,
			 "NTB Device Information:\n");

	off += scnprintf(buf + off, buf_size - off,
			 "Connection Topology -\t%s\n",
			 ntb_topo_string(ndev->ntb.topo));

	if (ndev->b2b_mw != UINT32_MAX) {
		off += scnprintf(buf + off, buf_size - off, "B2B MW Idx -\t\t%u\n",
				 ndev->b2b_mw);
		off += scnprintf(buf + off, buf_size - off, "B2B Offset -\t\t%#llx\n",
				 ndev->b2b_off);
	}

	off += scnprintf(buf + off, buf_size - off, "BAR Split -\t\t%s\n",
			 ndev->split ? "yes" : "no");

	off += scnprintf(buf + off, buf_size - off, "NTX Value -\t\t%u\n", ndev->ntx);

	off += scnprintf(buf + off, buf_size - off, "Link Status -\t\t%u\n", ndev->link);

	off += scnprintf(buf + off, buf_size - off, "Port Num - \t\t%u\n", ndev->port);

	off += scnprintf(buf + off, buf_size - off, "A-LUT Value - \t\t%u\n", ndev->alut);

	off += scnprintf(buf + off, buf_size - off, "MW Count - \t\t%u\n", ndev->mw_count);

	off += scnprintf(buf + off, buf_size - off, "SPAD Count - \t\t%u\n", ndev->spad_cnt1);

	off += scnprintf(buf + off, buf_size - off, "Extra SPAD - \t\t%u\n", ndev->spad_cnt2);

	off += scnprintf(buf + off, buf_size - off, "SPAD Offset - \t\t%u\n", ndev->sspad_off1);

	off += scnprintf(buf + off, buf_size - off, "Xtra SPAD Offset - \t%u\n", ndev->sspad_off2);

	off += scnprintf(buf + off, buf_size - off, "Peer SPAD Offset - \t%u\n", ndev->pspad_off1);

	off += scnprintf(buf + off, buf_size - off, "Peer Xtra SPAD - \t%u\n", ndev->pspad_off2);

	ret = simple_read_from_buffer(ubuf, count, offp, buf, off);
	kfree(buf);
	return ret;
}

static void ndev_deinit_debugfs(struct plx_ntb_dev *ndev)
{
	debugfs_remove_recursive(ndev->debugfs_dir);
}

static const struct ntb_dev_ops plx_ntb_ops = {
	.mw_count = plx_ntb_mw_count,
	.mw_get_align = plx_ntb_mw_get_align,
	.mw_set_trans = plx_ntb_mw_set_trans,
	.mw_clear_trans = plx_ntb_mw_clear_trans,
	.peer_mw_count = plx_ntb_peer_mw_count,
	.peer_mw_get_addr = plx_ntb_peer_mw_get_addr,
	.link_is_up = plx_ntb_link_is_up,
	.link_enable = plx_ntb_link_enable,
	.link_disable = plx_ntb_link_disable,
	.db_valid_mask = plx_ntb_db_valid_mask,
	.db_vector_count = plx_ntb_db_vector_count,
	.db_vector_mask = plx_ntb_db_vector_mask,
	.db_read = plx_ntb_db_read,
	.db_clear = plx_ntb_db_clear,
	.db_set_mask = plx_ntb_db_set_mask,
	.db_clear_mask = plx_ntb_db_clear_mask,
	.peer_db_addr = plx_ntb_peer_db_addr,
	.peer_db_set = plx_ntb_peer_db_set,
	.spad_count = plx_ntb_spad_count,
	.spad_read = plx_ntb_spad_read,
	.spad_write = plx_ntb_spad_write,
	.peer_spad_read = plx_ntb_peer_spad_read,
	.peer_spad_write = plx_ntb_peer_spad_write,
};

static const struct file_operations plx_ntb_debugfs_info = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = ndev_debugfs_read,
};

static inline void ndev_init_struct(struct plx_ntb_dev *ndev, struct pci_dev *pdev)
{
	ndev->ntb.pdev = pdev;
	ndev->ntb.topo = NTB_TOPO_NONE;
	ndev->ntb.ops = &plx_ntb_ops;

	ndev->ntx = 0;
	ndev->link = 0;
	ndev->port = 0;
	ndev->alut = 0;
	ndev->split = 0;

	ndev->mw_count = 0;
	ndev->spad_cnt1 = 0;
	ndev->spad_cnt2 = 0;
	ndev->sspad_off1 = 0;
	ndev->sspad_off2 = 0;
	ndev->pspad_off1 = 0;
	ndev->pspad_off2 = 0;

	ndev->b2b_off = 0;
	ndev->b2b_mw = UINT32_MAX;
}

static void ndev_init_debugfs(struct plx_ntb_dev *ndev)
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
								 &plx_ntb_debugfs_info);
	}
}

static int plx_ntb_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct plx_ntb_dev *ndev;
	int rc, node;

	node = dev_to_node(&pdev->dev);
	ndev = kzalloc_node(sizeof(*ndev), GFP_KERNEL, node);
	if (!ndev) {
		rc = -ENOMEM;
		goto err_ndev;
	}

	ndev_init_struct(ndev, pdev);

	rc = plx_ntb_init_pci(ndev, pdev);
	if (rc)
		goto err_init_pci;

	rc = plx_init_dev(&ndev->ntb);
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
	plx_deinit_dev(ndev);
err_init_dev:
	plx_ntb_deinit_pci(ndev);
err_init_pci:
	kfree(ndev);
err_ndev:
	return rc;
}

static void plx_ntb_pci_remove(struct pci_dev *pdev)
{
	struct plx_ntb_dev *ndev = pci_get_drvdata(pdev);

	ntb_unregister_device(&ndev->ntb);
	ndev_deinit_debugfs(ndev);
	plx_deinit_dev(ndev);
	plx_ntb_deinit_pci(ndev);
	kfree(ndev);
}

static const struct pci_device_id plx_ntb_pci_tbl[] = {
	{PCI_VDEVICE(PLX, PCI_DEVICE_ID_PLX_NT0_LINK)},
	{PCI_VDEVICE(PLX, PCI_DEVICE_ID_PLX_NT1_LINK)},
	{PCI_VDEVICE(PLX, PCI_DEVICE_ID_PLX_NT0_VIRT)},
	{PCI_VDEVICE(PLX, PCI_DEVICE_ID_PLX_NT1_VIRT)},
	{0}
};
MODULE_DEVICE_TABLE(pci, plx_ntb_pci_tbl);

static struct pci_driver plx_ntb_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = plx_ntb_pci_tbl,
	.probe = plx_ntb_pci_probe,
	.remove = plx_ntb_pci_remove,
};

static int __init plx_ntb_pci_driver_init(void)
{
	pr_info("%s %s\n", NTB_DESC, NTB_VER);

	if (debugfs_initialized())
		debugfs_dir = debugfs_create_dir(KBUILD_MODNAME, NULL);

	return pci_register_driver(&plx_ntb_pci_driver);
}
module_init(plx_ntb_pci_driver_init);

static void __exit plx_ntb_pci_driver_exit(void)
{
	pci_unregister_driver(&plx_ntb_pci_driver);
	debugfs_remove_recursive(debugfs_dir);
}
module_exit(plx_ntb_pci_driver_exit);
