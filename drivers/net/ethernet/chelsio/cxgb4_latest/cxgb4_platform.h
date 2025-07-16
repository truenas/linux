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

#ifndef __CXGB4_PLATFORM_H__
#define __CXGB4_PLATFORM_H__

#include <linux/platform_device.h>

struct device *cxgb4_plat_get_device(struct adapter *adap);
int cxgb4_plat_resource_init(struct adapter *adap);
void cxgb4_plat_resource_free(struct adapter *adap);
struct resource *cxgb4_plat_resource_get(struct adapter *adap, u8 index);
resource_size_t cxgb4_plat_resource_size(struct adapter *adap, u8 index);
int cxgb4_plat_chip_init(struct adapter *adap);
void cxgb4_plat_chip_free(struct adapter *adap);
void cxgb4_plat_setup_memwin(struct adapter *adap);
void cxgb4_plat_setup_memwin_rdma(struct adapter *adap);
void cxgb4_plat_fw_free(struct adapter *adap);
int cxgb4_plat_fw_init(struct adapter *adap, enum dev_state *state);
int cxgb4_plat_vendor_id(struct adapter *adap);
int cxgb4_plat_device_id(struct adapter *adap);
bool cxgb4_plat_relaxed_ordering_enabled(struct adapter *adap);
bool cxgb4_plat_msix_enabled(struct adapter *adap);
bool cxgb4_plat_msi_enabled(struct adapter *adap);
int cxgb4_plat_irq_vector(struct adapter *adap, int index);
int cxgb4_plat_alloc_irqs(struct adapter *adap, u32 need, u32 want, u32 flags);
void cxgb4_plat_free_irqs(struct adapter *adap);
int cxgb4_plat_read_config_byte(struct adapter *adap, int where, u8 *val);
int cxgb4_plat_write_config_byte(struct adapter *adap, int where, u8 val);
int cxgb4_plat_read_config_word(struct adapter *adap, int where, u16 *val);
int cxgb4_plat_write_config_word(struct adapter *adap, int where, u16 val);
int cxgb4_plat_read_config_dword(struct adapter *adap, int where, u32 *val);
int cxgb4_plat_write_config_dword(struct adapter *adap, int where, u32 val);
u8 cxgb4_plat_find_capability(struct adapter *adap, int cap);
ssize_t cxgb4_plat_read_vpd(struct adapter *adap, loff_t pos, size_t count,
			    void *buf);
ssize_t cxgb4_plat_write_vpd(struct adapter *adap, loff_t pos, size_t count,
			     const void *buf);
int cxgb4_plat_memory_rw(struct adapter *adap, int win, u64 addr, u64 len,
			 void *buf, int dir);
#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
int cxgb4_plat_iov_configure(struct adapter *adap, int num_vfs);
#endif

int cxgb4_platform_driver_register(void);
void cxgb4_platform_driver_unregister(void);

#endif /* __CXGB4_PLATFORM_H__ */
