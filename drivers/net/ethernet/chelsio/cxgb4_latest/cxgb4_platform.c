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

#include <linux/msi.h>

#include "common.h"
#include "t4_regs.h"

#include "cxgb4_platform.h"

static int cxgb4_plat_set_primary_pf(struct adapter *adap)
{
	struct of_phandle_args args;
	int ret;

	ret = of_parse_phandle_with_args(adap->pdev_dev->of_node, "mboxes",
					 "#mbox-cells", 0, &args);
	if (ret)
		return ret;

	if (!args.np || args.args_count != 1) {
		ret = -EINVAL;
		goto out_err;
	}

	adap->primary_pf = args.args[0];

out_err:
	of_node_put(args.np);
	return ret;
}

struct device *cxgb4_plat_get_device(struct adapter *adap)
{
	struct platform_device *pdev = cxgb4_plat_dev(adap);

	return &pdev->dev;
}

int cxgb4_plat_resource_init(struct adapter *adap)
{
	struct platform_device *pdev = cxgb4_plat_dev(adap);
	struct resource *res;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "pl");
	if (!res)
		return dev_err_probe(adap->pdev_dev, -ENXIO,
				     "FAIL - Registers not found\n");

	adap->regs = devm_ioremap(adap->pdev_dev, res->start,
				  resource_size(res));
	if (!adap->regs)
		return dev_err_probe(adap->pdev_dev, -ENOMEM,
				     "FAIL - Registers not mapped\n");

	adap->regs_start = res->start;

	adap->sge.tx_db_addr = devm_platform_ioremap_resource_byname(pdev, "db");
	if (IS_ERR(adap->sge.tx_db_addr))
		return dev_err_probe(adap->pdev_dev,
				     PTR_ERR(adap->sge.tx_db_addr),
				     "FAIL - Doorbell not found\n");

	adap->sge.rx_db_addr = adap->sge.tx_db_addr;

	adap->name = dev_name(adap->pdev_dev);
	return cxgb4_plat_set_primary_pf(adap);
}

void cxgb4_plat_resource_free(struct adapter *adap)
{
	devm_iounmap(adap->pdev_dev, adap->regs);
}

struct resource *cxgb4_plat_resource_get(struct adapter *adap, u8 index)
{
	if (index != 0)
		return NULL;

	return platform_get_resource(cxgb4_plat_dev(adap), IORESOURCE_MEM,
				     index);
}

resource_size_t cxgb4_plat_resource_size(struct adapter *adap, u8 index)
{
	struct resource *res = cxgb4_plat_resource_get(adap, index);

	if (!res)
		return 0;

	return resource_size(res);
}

int cxgb4_plat_chip_init(struct adapter *adap)
{
	int ret;

	ret = t4_get_chip_type(adap, G_CHIPID(t4_read_reg(adap, A_PL_REV)));
	if (ret < 0)
		return ret;

	adap->params.chip = ret;
	adap->mbox = adap->primary_pf;
	adap->pf = adap->primary_pf;

#ifdef CHELSIO_T4_DIAGS
	if (cxgb4_is_primary_pf(adap))
		return -EOPNOTSUPP;
#endif

	ret = cxgb4_mbox_log_init(adap);
	if (ret < 0)
		return ret;

	ret = dma_set_mask_and_coherent(adap->pdev_dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(adap->pdev_dev, "no usable DMA configuration\n");
		goto out_free_mbox_log;
	}

	return 0;

out_free_mbox_log:
	cxgb4_mbox_log_free(adap);
	return ret;
}

void cxgb4_plat_chip_free(struct adapter *adap)
{
	cxgb4_mbox_log_free(adap);
}

void cxgb4_plat_setup_memwin(struct adapter *adap)
{
	/* TODO: Need to see how to configure memwin since there's no BAR */
	dev_warn(adap->pdev_dev,
		 "FAIL - NIC Memory Window config not implemented\n");
}

void cxgb4_plat_setup_memwin_rdma(struct adapter *adap)
{
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (!adap->uld.vres.ocq.size)
		return;

	dev_warn(adap->pdev_dev,
		 "FAIL - RDMA OCQ requested, but not supported\n");
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
}

void cxgb4_plat_fw_free(struct adapter *adap)
{
	/* Nothing to do */
}

int cxgb4_plat_fw_init(struct adapter *adap, enum dev_state *state)
{
	u32 val = t4_read_reg(adap, A_PCIE_FW);
	bool valid = G_PCIE_FW_MASTER_VLD(val);
	u8 mbox = G_PCIE_FW_MASTER(val);

	/* FW mailbox should already be initialized by Boot loader */
	if (!G_PCIE_FW_INIT(val)) {
		dev_err(adap->pdev_dev, "Firmware not initialized\n");
		return -EIO;
	}

	if (valid && mbox != adap->primary_pf) {
		dev_err(adap->pdev_dev, "Mailbox %u != CHDPU Primary %u\n",
			mbox, adap->primary_pf);
		return -EINVAL;
	}

	*state = DEV_STATE_INIT;
	return valid ? mbox : adap->primary_pf;
}

int cxgb4_plat_vendor_id(struct adapter *adap)
{
	/* TODO: Need to handle platform device */
	dev_warn(adap->pdev_dev,
		 "FAIL - Get vendor ID not implemented\n");
	return 0;
}

int cxgb4_plat_device_id(struct adapter *adap)
{
	/* TODO: Need to handle platform device */
	dev_warn(adap->pdev_dev,
		 "FAIL - Get device ID not implemented\n");
	return 0;
}

bool cxgb4_plat_relaxed_ordering_enabled(struct adapter *adap)
{
	return false;
}

bool cxgb4_plat_msix_enabled(struct adapter *adap)
{
	return true;
}

bool cxgb4_plat_msi_enabled(struct adapter *adap)
{
	return false;
}

int cxgb4_plat_irq_vector(struct adapter *adap, int index)
{
	return msi_get_virq(adap->pdev_dev, index);
}

static void cxgb4_plat_msi_write(struct msi_desc *desc, struct msi_msg *msg)
{
	struct device *dev = msi_desc_to_dev(desc);
	struct adapter *adap;

	adap = dev_get_drvdata(dev);
#if 0
	writel_relaxed(msg->address_lo, ring->regs + RING_MSI_ADDR_LS);
	writel_relaxed(msg->address_hi, ring->regs + RING_MSI_ADDR_MS);
	writel_relaxed(msg->data, ring->regs + RING_MSI_DATA_VALUE);
#endif
}

int cxgb4_plat_alloc_irqs(struct adapter *adap, u32 need, u32 want, u32 flags)
{
	u32 nirq = want;
	int ret;

	ret = platform_msi_domain_alloc_irqs(adap->pdev_dev, nirq,
					     cxgb4_plat_msi_write);
	if (ret < 0) {
		nirq = need;
		ret = platform_msi_domain_alloc_irqs(adap->pdev_dev, nirq,
						     cxgb4_plat_msi_write);
	}

	return ret < 0 ? ret : nirq;
}

void cxgb4_plat_free_irqs(struct adapter *adap)
{
	if (adap->flags & (USING_INTR_MULTI | USING_INTR_SINGLE))
		platform_msi_domain_free_irqs(adap->pdev_dev);
}

int cxgb4_plat_read_config_byte(struct adapter *adap, int where, u8 *val)
{
	u32 tmp_val;

	t4_hw_pci_read_cfg(adap, where, &tmp_val, 1);
	*val = tmp_val & 0xff;
	return 0;
}

int cxgb4_plat_write_config_byte(struct adapter *adap, int where, u8 val)
{
	t4_hw_pci_write_cfg(adap, where, val, 1);
	return 0;
}

int cxgb4_plat_read_config_word(struct adapter *adap, int where, u16 *val)
{
	u32 tmp_val;

	t4_hw_pci_read_cfg(adap, where, &tmp_val, 2);
	*val = tmp_val & 0xffff;
	return 0;
}

int cxgb4_plat_write_config_word(struct adapter *adap, int where, u16 val)
{
	t4_hw_pci_write_cfg(adap, where, val, 2);
	return 0;
}

int cxgb4_plat_read_config_dword(struct adapter *adap, int where, u32 *val)
{
	t4_hw_pci_read_cfg(adap, where, val, 4);
	return 0;
}

int cxgb4_plat_write_config_dword(struct adapter *adap, int where, u32 val)
{
	t4_hw_pci_write_cfg(adap, where, val, 4);
	return 0;
}

u8 cxgb4_plat_find_capability(struct adapter *adap, int cap)
{
	/* No support for reading PCI capability */
	return 0;
}

ssize_t cxgb4_plat_read_vpd(struct adapter *adap, loff_t pos, size_t count,
			    void *buf)
{
	u32 *val = buf;
	size_t i;
	int ret;

	if (count & 3)
		return -EOPNOTSUPP;

	for (i = 0; i < count; i += 4, pos += 4, val++) {
		ret = t4_seeprom_read(adap, pos, val);
		if (ret < 0) {
			dev_warn(adap->pdev_dev,
				 "FAIL - could not read VPD pos: 0x%llx, err: %d\n",
				 pos, ret);
			break;
		}
	}

	return ret ? ret : count;
}

ssize_t cxgb4_plat_write_vpd(struct adapter *adap, loff_t pos, size_t count,
			     const void *buf)
{
	const u32 *val = buf;
	size_t i;
	int ret;

	if (count & 3)
		return -EOPNOTSUPP;

	for (i = 0; i < count; i += 4, pos += 4, val++) {
		ret = t4_seeprom_write(adap, pos, *val);
		if (ret < 0) {
			dev_warn(adap->pdev_dev,
				 "FAIL - could not write VPD pos: 0x%llx, err: %d\n",
				 pos, ret);
			break;
		}
	}

	return ret ? ret : count;
}

int cxgb4_plat_memory_rw(struct adapter *adap, int win, u64 addr, u64 len,
			 void *buf, int dir)
{
	/* TODO: Need to implement Memory RW via FW Mailbox */
	dev_warn(adap->pdev_dev,
		 "FAIL - Memory Read/Write not implemented\n");
	return -EOPNOTSUPP;
}

#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
int cxgb4_plat_iov_configure(struct adapter *adap, int num_vfs)
{
	return -EOPNOTSUPP;
}
#endif

static int cxgb4_plat_probe(struct platform_device *pdev)
{
	struct adapter *adap;
	int ret;

	adap = cxgb4_adap_alloc(&pdev->dev);
	if (!adap)
		return dev_err_probe(&pdev->dev, -ENOMEM,
				     "FAIL - Adapter alloc\n");

	platform_set_drvdata(pdev, adap);

	adap->plat_dev = true;
	adap->pdev.platform_dev = pdev;
	adap->pdev_dev = &pdev->dev;

	ret = cxgb4_adap_probe(adap);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	platform_set_drvdata(pdev, NULL);
	return ret;
}

static int cxgb4_plat_remove(struct platform_device *pdev)
{
	cxgb4_adap_remove(platform_get_drvdata(pdev));
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static const struct of_device_id cxgb4_plat_ids[] = {
	{ .compatible = "chelsio,chdpu-t7-eth" },
	{}
};

static struct platform_driver cxgb4_plat_driver = {
	.probe = cxgb4_plat_probe,
	.remove = cxgb4_plat_remove,
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = of_match_ptr(cxgb4_plat_ids),
	},
};

int cxgb4_platform_driver_register(void)
{
	return platform_driver_register(&cxgb4_plat_driver);
}

void cxgb4_platform_driver_unregister(void)
{
	platform_driver_unregister(&cxgb4_plat_driver);
}
