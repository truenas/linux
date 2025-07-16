/*
 * This file is part of the Chelsio T4/T5/T6/T7 Ethernet driver for Linux.
 *
 * Copyright (C) 2023 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/crash_dump.h>

#include "common.h"
#include "t4_regs.h"

#include "cxgb4_pci.h"

static void cxgb4_pci_set_primary_pf(struct adapter *adap)
{
	adap->primary_pf = CXGB4_UNIFIED_PF;
}

struct device *cxgb4_pci_get_device(struct adapter *adap)
{
	struct pci_dev *pdev = cxgb4_pci_dev(adap);

	return &pdev->dev;
}

int cxgb4_pci_resource_init(struct adapter *adap)
{
	struct pci_dev *pdev = cxgb4_pci_dev(adap);
	int ret;

	ret = pci_request_regions(pdev, KBUILD_MODNAME);
	if (ret) {
		/* Just info, some other driver may have claimed the device. */
		dev_info(adap->pdev_dev, "cannot obtain PCI resources\n");
		return ret;
	}

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(adap->pdev_dev, "cannot enable PCI device\n");
		goto out_release_regions;
	}

	adap->regs = pci_ioremap_bar(pdev, 0);
	if (!adap->regs) {
		dev_err(adap->pdev_dev, "cannot map device registers\n");
		ret = -ENOMEM;
		goto out_disable_device;
	}

	adap->regs_start = 0;

	adap->sge.tx_db_addr = adap->regs + MYPF_REG(A_SGE_PF_KDOORBELL);
	adap->sge.rx_db_addr = adap->regs + MYPF_REG(A_SGE_PF_GTS);

	adap->name = pci_name(pdev);
	cxgb4_pci_set_primary_pf(adap);
	return 0;

out_disable_device:
	pci_disable_device(pdev);

out_release_regions:
	pci_release_regions(pdev);
	return ret;
}

void cxgb4_pci_resource_free(struct adapter *adap)
{
	struct pci_dev *pdev = cxgb4_pci_dev(adap);

	iounmap(adap->regs);
	if ((adap->flags & DEV_ENABLED))
		pci_disable_device(pdev);
	pci_release_regions(pdev);
}

struct resource *cxgb4_pci_resource_get(struct adapter *adap, u8 index)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
#define pci_resource_n(dev, bar) (&(dev)->resource[(bar)])
#endif
	return pci_resource_n(cxgb4_pci_dev(adap), index);
}

resource_size_t cxgb4_pci_resource_size(struct adapter *adap, u8 index)
{
	return pci_resource_len(cxgb4_pci_dev(adap), index);
}

int cxgb4_pci_chip_init(struct adapter *adap)
{
	struct pci_dev *pdev = cxgb4_pci_dev(adap);
	u16 device_id;
	u32 whoami;
	u8 func;
	int ret;

	/*
	 * Note that we use the PL_WHOAMI register to figure out to which PF
	 * we're actually attached rather than PCI_FUNC(pdev->devfn).  We do
	 * this because we could be operating within a Virtual Machine where,
	 * say, PF4 has been inserted via some form of "PCI Pass Through"
	 * resulting in the VM PCI Device having a completely different PCI
	 * Function Number, say, PF0.  However, there are many communications
	 * with the firmware (and the hardware) where we need to use the
	 * actual Physical Function Number and we can get this from the
	 * PL_WHOAMI register ...
	 */
	whoami = t4_read_reg(adap, A_PL_WHOAMI);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device_id);
	ret = t4_get_chip_type(adap, CHELSIO_PCI_ID_VER(device_id));
	if (ret < 0)
		return ret;

	adap->params.chip = ret;
	func = CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5 ?
	       G_SOURCEPF(whoami) : G_T6_SOURCEPF(whoami);

	adap->mbox = func;
	adap->pf = func;

	ret = cxgb4_mbox_log_init(adap);
	if (ret < 0)
		return ret;

	/*
	 * If we're not the MASTER Physical Function, there's not much more
	 * we need to do.
	 */
	if (!cxgb4_is_primary_pf(adap)) {
		/* We must be a PCIe SR-IOV Virtual Function.  We won't be
		 * doing any DMA, but we will be offering VF Management
		 * services ...
		 */
		pci_disable_device(pdev);
		pci_save_state(pdev); /* to restore SR-IOV later */
		return 0;
	}

	ret = dma_set_mask_and_coherent(adap->pdev_dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(adap->pdev_dev, "no usable DMA configuration\n");
		goto out_free_mbox_log;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	pci_enable_pcie_error_reporting(pdev);
#endif
	pci_set_master(pdev);
	pci_save_state(pdev);

	if (!is_t4(adap->params.chip)) {
		adap->bar2 = ioremap_wc(pci_resource_start(pdev, 2),
					pci_resource_len(pdev, 2));
		if (!adap->bar2) {
			dev_err(adap->pdev_dev,
				"cannot map device bar2 region\n");
			ret = -ENOMEM;
			goto out_free_mbox_log;
		}

		t4_write_reg(adap, A_SGE_STAT_CFG, V_STATSOURCE_T5(7) |
			     (is_t5(adap->params.chip) ? V_STATMODE(0) :
			      V_T6_STATMODE(0)));
	}

	/* check for PCI Express bandwidth capabiltites */
	pcie_print_link_status(pdev);

	/* PCIe EEH recovery on powerpc platforms needs fundamental reset */
	pdev->needs_freset = 1;

	return 0;

out_free_mbox_log:
	cxgb4_mbox_log_free(adap);
	return ret;
}

void cxgb4_pci_chip_free(struct adapter *adap)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	pci_disable_pcie_error_reporting(cxgb4_pci_dev(adap));
#endif
	if (!is_t4(adap->params.chip)){
		if (adap->bar2)
			iounmap(adap->bar2);
	}

	cxgb4_mbox_log_free(adap);
}

void cxgb4_pci_setup_memwin(struct adapter *adap)
{
	u32 nic_win_base = t4_get_util_window(adap, fw_attach);

	t4_setup_memwin(adap, nic_win_base, MEMWIN_NIC);
}

void cxgb4_pci_setup_memwin_rdma(struct adapter *adap)
{
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	unsigned int sz_kb;
	u32 start;

	if (!adap->uld.vres.ocq.size)
		return;

	start = t4_read_pcie_cfg4(adap, PCI_BASE_ADDRESS_2, fw_attach);
	start &= PCI_BASE_ADDRESS_MEM_MASK;
	start += OCQ_WIN_OFFSET(cxgb4_pci_dev(adap), &adap->uld.vres);
	sz_kb = roundup_pow_of_two(adap->uld.vres.ocq.size) >> X_WINDOW_SHIFT;

	/*
	 * Set up RDMA memory window for accessing adapter memory
	 * ranges.  (Read back MA register to ensure that changes
	 * propagate before we attempt to use the new values.)
	 */
	t4_write_reg(adap, t4_pcie_mem_access_base_win_reg(adap, MEMWIN_RDMA),
		     start | V_BIR(1) | V_WINDOW(ilog2(sz_kb)));
	t4_pcie_mem_access_offset_write(adap, adap->uld.vres.ocq.start,
					MEMWIN_RDMA, 0);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
}

void cxgb4_pci_fw_free(struct adapter *adap)
{
	t4_fw_bye(adap, adap->mbox);
}

int cxgb4_pci_fw_init(struct adapter *adap, enum dev_state *state)
{
	int ret;

	/* Contact FW, advertising Master capability */
	ret = t4_fw_hello(adap, adap->mbox, adap->mbox, MASTER_MAY, state);
	if ((ret < 0) && is_kdump_kernel())
		ret = t4_fw_hello(adap, adap->mbox, adap->mbox, MASTER_MUST,
				  state);
	if (ret < 0) {
		dev_err(adap->pdev_dev, "could not connect to FW, error %d\n",
			ret);
		return ret;
	}

	return ret;
}

int cxgb4_pci_vendor_id(struct adapter *adap)
{
	return cxgb4_pci_dev(adap)->vendor;
}

int cxgb4_pci_device_id(struct adapter *adap)
{
	return cxgb4_pci_dev(adap)->device;
}

bool cxgb4_pci_relaxed_ordering_enabled(struct adapter *adap)
{
	return pcie_relaxed_ordering_enabled(cxgb4_pci_dev(adap));
}

bool cxgb4_pci_msix_enabled(struct adapter *adap)
{
	if (!pci_dev_msi_enabled(cxgb4_pci_dev(adap)))
		return false;

	return cxgb4_pci_dev(adap)->msix_enabled;
}

bool cxgb4_pci_msi_enabled(struct adapter *adap)
{
	if (!pci_dev_msi_enabled(cxgb4_pci_dev(adap)))
		return false;

	return cxgb4_pci_dev(adap)->msi_enabled;
}

int cxgb4_pci_irq_vector(struct adapter *adap, int index)
{
	return pci_irq_vector(cxgb4_pci_dev(adap), index);
}

int cxgb4_pci_alloc_irqs(struct adapter *adap, u32 need, u32 want, u32 flags)
{
	return pci_alloc_irq_vectors(cxgb4_pci_dev(adap), need, want, flags);
}

void cxgb4_pci_free_irqs(struct adapter *adap)
{
	pci_free_irq_vectors(cxgb4_pci_dev(adap));
}

int cxgb4_pci_read_config_byte(struct adapter *adap, int where, u8 *val)
{
	return pci_read_config_byte(cxgb4_pci_dev(adap), where, val);
}

int cxgb4_pci_write_config_byte(struct adapter *adap, int where, u8 val)
{
	return pci_write_config_byte(cxgb4_pci_dev(adap), where, val);
}

int cxgb4_pci_read_config_word(struct adapter *adap, int where, u16 *val)
{
	return pci_read_config_word(cxgb4_pci_dev(adap), where, val);
}

int cxgb4_pci_write_config_word(struct adapter *adap, int where, u16 val)
{
	return pci_write_config_word(cxgb4_pci_dev(adap), where, val);
}

int cxgb4_pci_read_config_dword(struct adapter *adap, int where, u32 *val)
{
	return pci_read_config_dword(cxgb4_pci_dev(adap), where, val);
}

int cxgb4_pci_write_config_dword(struct adapter *adap, int where, u32 val)
{
	return pci_write_config_dword(cxgb4_pci_dev(adap), where, val);
}

u8 cxgb4_pci_find_capability(struct adapter *adap, int cap)
{
	return pci_find_capability(cxgb4_pci_dev(adap), cap);
}

ssize_t cxgb4_pci_read_vpd(struct adapter *adap, loff_t pos, size_t count,
			   void *buf)
{
	return pci_read_vpd(cxgb4_pci_dev(adap), pos, count, buf);
}

ssize_t cxgb4_pci_write_vpd(struct adapter *adap, loff_t pos, size_t count,
			    const void *buf)
{
	return pci_write_vpd(cxgb4_pci_dev(adap), pos, count, buf);
}

int cxgb4_pci_memory_rw(struct adapter *adap, int win, u64 addr, u64 len,
			void *buf, int dir)
{
	return t4_memory_rw_addr(adap, win, addr, len, buf, dir);
}

#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
int cxgb4_pci_iov_configure(struct adapter *adap, int num_vfs)
{
	return cxgb4_iov_configure(cxgb4_pci_dev(adap), num_vfs);
}

static int cxgb4_pci_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (pci_is_bridge(pdev))
		return -EOPNOTSUPP;

	return cxgb4_pci_iov_configure(pci_get_drvdata(pdev), num_vfs);
}
#endif

static int cxgb4_pci_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct adapter *adap;
	int ret;

	if (pci_is_bridge(pdev))
		return 0;

	adap = cxgb4_adap_alloc(&pdev->dev);
	if (!adap) {
		dev_err(&pdev->dev, "FAIL - Adapter alloc\n");
		return -ENOMEM;
	}

	pci_set_drvdata(pdev, adap);

	adap->pdev.pci_dev = pdev;
	adap->pdev_dev = &pdev->dev;

	ret = cxgb4_adap_probe(adap);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	pci_set_drvdata(pdev, NULL);
	return ret;
}

static void cxgb4_pci_remove_one(struct pci_dev *pdev)
{
	if (pci_is_bridge(pdev))
		return;

	cxgb4_adap_remove(pci_get_drvdata(pdev));
	pci_set_drvdata(pdev, NULL);
}

static void cxgb4_pci_shutdown_one(struct pci_dev *pdev)
{
	if (pci_is_bridge(pdev))
		return;

	cxgb4_adap_shutdown(pci_get_drvdata(pdev));
}

/* Macros needed to support the PCI Device ID Table ...
 */
#define CH_PCI_DEVICE_ID_TABLE_DEFINE_BEGIN \
	static const struct pci_device_id cxgb4_pci_tbl[] = {
/* Include PCI Device IDs for both PF4 and PF0-3 so our PCI probe() routine is
 * called for both.
 */
#define CH_PCI_DEVICE_ID_FUNCTION CXGB4_UNIFIED_PF
#define CH_PCI_DEVICE_ID_FUNCTION2 0x0

#define CH_PCI_ID_TABLE_ENTRY(devid) \
		{PCI_VDEVICE(CHELSIO, (devid)), CXGB4_UNIFIED_PF}

#define CH_PCI_DEVICE_ID_TABLE_DEFINE_END \
		{ 0, } \
	}

#ifdef CONFIG_CHELSIO_BYPASS
#define CH_PCI_DEVICE_ID_BYPASS_SUPPORTED 1
#endif

/*
 * ... and the PCI ID Table itself ...
 */
#include "t4_pci_id_tbl.h"

static PCI_ERR_HANDLERS_CONST struct pci_error_handlers cxgb4_pci_eeh = {
	.error_detected = cxgb4_pci_eeh_err_detected,
	.slot_reset     = cxgb4_pci_eeh_slot_reset,
	.resume         = cxgb4_pci_eeh_resume,
	.reset_prepare  = cxgb4_pci_eeh_reset_prepare,
	.reset_done     = cxgb4_pci_eeh_reset_done,
};

static struct pci_driver cxgb4_pci_driver = {
	.name     = KBUILD_MODNAME,
	.id_table = cxgb4_pci_tbl,
	.probe    = cxgb4_pci_init_one,
	.remove   = cxgb4_pci_remove_one,
	.shutdown = cxgb4_pci_shutdown_one,
#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
	.sriov_configure = cxgb4_pci_sriov_configure,
#endif
	.err_handler = &cxgb4_pci_eeh,
};

int cxgb4_pci_driver_register(void)
{
	return pci_register_driver(&cxgb4_pci_driver);
}

void cxgb4_pci_driver_unregister(void)
{
	pci_unregister_driver(&cxgb4_pci_driver);
}

MODULE_DEVICE_TABLE(pci, cxgb4_pci_tbl);
