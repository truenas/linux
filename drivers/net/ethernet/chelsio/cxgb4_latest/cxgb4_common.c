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

#include "common.h"
#include "cxgb4_common.h"

#ifdef CXGB4_PLATFORM
#define CXGB4_COMMON_CALL_RET(adap, name) do { \
	if (!cxgb4_is_platform_device(adap)) { \
		return cxgb4_pci_##name(adap); \
	} else { \
		return cxgb4_plat_##name(adap); \
	} \
} while (0)
#else
#define CXGB4_COMMON_CALL_RET(adap, name) do { \
	return cxgb4_pci_##name(adap); \
} while (0)
#endif /* CXGB4_PLATFORM */

#ifdef CXGB4_PLATFORM
#define CXGB4_COMMON_CALL_RET_ARGS(adap, name, ...) do { \
	if (!cxgb4_is_platform_device(adap)) { \
		return cxgb4_pci_##name(adap, __VA_ARGS__); \
	} else { \
		return cxgb4_plat_##name(adap, __VA_ARGS__); \
	} \
} while (0)
#else
#define CXGB4_COMMON_CALL_RET_ARGS(adap, name, ...) do { \
	return cxgb4_pci_##name(adap, __VA_ARGS__); \
} while (0)
#endif /* CXGB4_PLATFORM */

#ifdef CXGB4_PLATFORM
#define CXGB4_COMMON_CALL(adap, name) do { \
	if (!cxgb4_is_platform_device(adap)) { \
		cxgb4_pci_##name(adap); \
	} else { \
		cxgb4_plat_##name(adap); \
	} \
} while (0)
#else
#define CXGB4_COMMON_CALL(adap, name) do { \
	cxgb4_pci_##name(adap); \
} while (0)
#endif /* CXGB4_PLATFORM */

struct device *cxgb4_common_get_device(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, get_device);
}

int cxgb4_common_resource_init(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, resource_init);
}

void cxgb4_common_resource_free(struct adapter *adap)
{
	CXGB4_COMMON_CALL(adap, resource_free);
}

struct resource *cxgb4_common_resource_get(struct adapter *adap, u8 index)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, resource_get, index);
}

resource_size_t cxgb4_common_resource_size(struct adapter *adap, u8 index)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, resource_size, index);
}

int cxgb4_common_chip_init(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, chip_init);
}

void cxgb4_common_chip_free(struct adapter *adap)
{
	CXGB4_COMMON_CALL(adap, chip_free);
}

void cxgb4_common_setup_memwin(struct adapter *adap)
{
	CXGB4_COMMON_CALL(adap, setup_memwin);
}

void cxgb4_common_setup_memwin_rdma(struct adapter *adap)
{
	CXGB4_COMMON_CALL(adap, setup_memwin_rdma);
}

void cxgb4_common_fw_free(struct adapter *adap)
{
	CXGB4_COMMON_CALL(adap, fw_free);
}

int cxgb4_common_fw_init(struct adapter *adap, enum dev_state *state)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, fw_init, state);
}

int cxgb4_common_vendor_id(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, vendor_id);
}

int cxgb4_common_device_id(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, device_id);
}

bool cxgb4_common_relaxed_ordering_enabled(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, relaxed_ordering_enabled);
}

bool cxgb4_common_msix_enabled(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, msix_enabled);
}

bool cxgb4_common_msi_enabled(struct adapter *adap)
{
	CXGB4_COMMON_CALL_RET(adap, msi_enabled);
}

int cxgb4_common_irq_vector(struct adapter *adap, int index)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, irq_vector, index);
}

int cxgb4_common_alloc_irqs(struct adapter *adap, u32 need, u32 want, u32 flags)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, alloc_irqs, need, want, flags);
}

void cxgb4_common_free_irqs(struct adapter *adap)
{
	CXGB4_COMMON_CALL(adap, free_irqs);
}

int cxgb4_common_read_config_byte(struct adapter *adap, int where, u8 *val)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, read_config_byte, where, val);
}

int cxgb4_common_write_config_byte(struct adapter *adap, int where, u8 val)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, write_config_byte, where, val);
}

int cxgb4_common_read_config_word(struct adapter *adap, int where, u16 *val)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, read_config_word, where, val);
}

int cxgb4_common_write_config_word(struct adapter *adap, int where, u16 val)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, write_config_word, where, val);
}

int cxgb4_common_read_config_dword(struct adapter *adap, int where, u32 *val)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, read_config_dword, where, val);
}

int cxgb4_common_write_config_dword(struct adapter *adap, int where, u32 val)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, write_config_dword, where, val);
}

u8 cxgb4_common_find_capability(struct adapter *adap, int cap)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, find_capability, cap);
}

ssize_t cxgb4_common_read_vpd(struct adapter *adap, loff_t pos, size_t count,
			      void *buf)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, read_vpd, pos, count, buf);
}

ssize_t cxgb4_common_write_vpd(struct adapter *adap, loff_t pos, size_t count,
			       const void *buf)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, write_vpd, pos, count, buf);
}

int cxgb4_common_memory_rw(struct adapter *adap, int win, u64 addr, u64 len,
			   void *buf, int dir)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, memory_rw, win, addr, len, buf, dir);
}

#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
int cxgb4_common_iov_configure(struct adapter *adap, int num_vfs)
{
	CXGB4_COMMON_CALL_RET_ARGS(adap, iov_configure, num_vfs);
}
#endif
