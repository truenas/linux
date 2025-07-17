# SPDX-License-Identifier: GPL-2.0
#
# Chelsio T4/T5/T6/T7 iWARP RDMA driver (Latest Package Version)
#

ccflags-y += -I$(src)
ccflags-y += -I$(src)/../../../net/ethernet/chelsio/cxgb4_latest
ccflags-y += -I$(src)/../../../net/ethernet/chelsio/include
ccflags-y += -I$(src)/../../../net/ethernet/chelsio/cudbg_inc
# Driver-specific compatibility flags for kernel 6.12
ccflags-y += -DPCI_ERR_HANDLERS_CONST=const
ccflags-y += -DINET_HASHFN
ccflags-y += -DGEN_ALLOC
ccflags-y += -DCONFIG_CHELSIO_T4_OFFLOAD
ccflags-y += -DCONFIG_TCP_OFFLOAD

obj-$(CONFIG_INFINIBAND_CXGB4) += iw_cxgb4.o

# Core RDMA driver objects (from Chelsio package)
iw_cxgb4-objs := ev.o cm.o mem.o device.o resource.o provider.o cq.o qp.o \
		 iw_cxgb4_compat.o restrack.o