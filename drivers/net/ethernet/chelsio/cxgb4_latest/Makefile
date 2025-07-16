# SPDX-License-Identifier: GPL-2.0
#
# Chelsio T4/T5/T6/T7 driver (Latest Package Version)
#

ccflags-y += -I$(src)
ccflags-y += -I$(src)/../include
ccflags-y += -I$(src)/../cudbg_inc
ccflags-y += -DPCI_ERR_HANDLERS_CONST=const

obj-$(CONFIG_CHELSIO_T4) += cxgb4.o

# Core driver objects (from Chelsio package)
cxgb4-objs := cxgb4_main.o l2t.o clip_tbl.o cxgb4_ethtool.o cxgb4_cxgbtool.o \
	      cxgb4_filter.o cxgb4_debugfs.o t4_hw.o t4_linux_debugfs.o sge.o \
	      trace.o smt.o cxgb4_ptp.o cxgb4_mps.o cxgb4_tid.o \
	      cxgb4_pci.o cxgb4_common.o

# Chelsio package enhancements (always enabled by default)
# Platform support
cxgb4-objs += cxgb4_platform.o

# Debug components (cudbg - enabled by default unless disable_cudbg=1)
cxgb4-objs += cxgb4_cudbg.o fastlz_api.o fastlz.o cudbg_lib.o cudbg_wtp.o \
	      cudbg_flash_utils.o cudbg_common.o

# Offload components (enabled by default unless disable_offload=1)
cxgb4-objs += ocqp.o srq.o cxgb4_uld.o cxgb4_id_table.o cxgb4_rdma_resource.o

# Multi-Adapter Failover (enabled by default unless disable_mafo=1)
cxgb4-objs += cxgb4_ma_failover.o

# Generic allocator (enabled by default unless -DGEN_ALLOC is set)
cxgb4-objs += cxgb4_genalloc.o

# Thermal support (enabled by default unless -DCXGB4_THERMAL not set)
cxgb4-objs += cxgb4_thermal.o

# Conditional components (disabled by default, following Chelsio package logic)
# DCB support (only if enable_dcb=1)
cxgb4-$(CONFIG_CHELSIO_T4_DCB) += cxgb4_dcb.o

# FCoE support (only if po_fcoe=1)
cxgb4-$(CONFIG_CHELSIO_T4_FCOE) += cxgb4_fcoe.o

# Bypass support (disabled for POC - equivalent to #if 0)
# TODO: Enable bypass support in future iterations
# In Chelsio package, bypass is only enabled for 'bypass' target (enable_bypass=1)
# ccflags-y += -DCONFIG_CHELSIO_BYPASS
# cxgb4-objs += t4_bypass.o bypass_sysfs.o