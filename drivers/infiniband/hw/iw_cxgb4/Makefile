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
# RDMA compatibility flags for kernel 6.12 (following Chelsio's detection pattern)
# Check for kref_read API
ifneq ($(shell grep -c 'kref_read' $(srctree)/include/linux/kref.h),0)
ccflags-y += -DHAVE_KREF_READ
endif

# Check for kref_get_unless_zero API
ifneq ($(shell grep -c 'kref_get_unless_zero' $(srctree)/include/linux/kref.h),0)
ccflags-y += -DKREF_GET_UNLESS_ZERO
endif

# Check for RDMA API compatibility
ifneq ($(wildcard $(srctree)/include/rdma/ib_verbs.h),)
  ifneq ($(shell grep -c 'ib_cq_init_attr' $(srctree)/include/rdma/ib_verbs.h),0)
    ccflags-y += -DIWARP_HAVE_CQ_INIT_ATTR
  endif
  ifneq ($(shell grep -c 'sg_offset' $(srctree)/include/rdma/ib_verbs.h),0)
    ccflags-y += -DIWARP_HAVE_SG_OFFSET
  endif
  ifneq ($(shell grep -c 'rdma_hw_stats' $(srctree)/include/rdma/ib_verbs.h),0)
    ccflags-y += -DIWARP_DEV_COUNTER_DYNAMIC
  endif
  ifneq ($(shell grep -c 'int.*max_send_sge' $(srctree)/include/rdma/ib_verbs.h),0)
    ccflags-y += -DIWARP_HAVE_MAX_SEND_SGE
  endif
  ifneq ($(shell grep -c 'ib_drain_qp' $(srctree)/include/rdma/ib_verbs.h),0)
    ccflags-y += -DIWARP_DRAIN_Q_SUPPORT
  endif
  ifneq ($(shell grep -c 'IB_FW_VERSION_NAME_MAX' $(srctree)/include/rdma/ib_verbs.h),0)
    ccflags-y += -DHAVE_IB_FW_VER_NAME
  endif
endif

# Check for user memory management API
ifneq ($(wildcard $(srctree)/include/rdma/ib_umem.h),)
  ifneq ($(shell grep -c 'ib_umem_chunk' $(srctree)/include/rdma/ib_umem.h),0)
    ccflags-y += -DHAVE_IB_UMEM_CHUNK
  endif
  ifneq ($(shell grep -c 'page_shift' $(srctree)/include/rdma/ib_umem.h),0)
    ccflags-y += -DHAVE_IB_UMEM_PAGE_SHIFT
  endif
endif

obj-$(CONFIG_INFINIBAND_CXGB4) += iw_cxgb4.o

# Core RDMA driver objects (from Chelsio package)
iw_cxgb4-objs := ev.o cm.o mem.o device.o resource.o provider.o cq.o qp.o \
		 iw_cxgb4_compat.o restrack.o