/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NVDIMM_PMEM_H__
#define __NVDIMM_PMEM_H__
#include <linux/page-flags.h>
#include <linux/badblocks.h>
#include <linux/types.h>
#include <linux/pfn_t.h>
#include <linux/fs.h>
#include <linux/dmaengine.h>

#define PMEM_SIGN_SHORT	0x4e564430
#define PMEM_SIGN_LONG	0x4e5644494d4d3030

enum {
	STATE_INCORRECT = 0,
	STATE_NONE,
	STATE_IDLE,
	STATE_WAITING,
	STATE_READY,
};

/* PMEM label */
struct pmem_label {
	u64	sign;		/* PMEM_SIGN_LONG signature */
	u64	array;		/* Unique array ID */
	u32	empty;		/* PMEM is empty and was never written */
	u32	dirty;		/* PMEM was written without NTB connection */
	u32	opened;		/* PMEM device is open now */
	u32	state;		/* Synchronization state */
};

/* this definition is in it's own header for tools/testing/nvdimm to consume */
struct pmem_device {
	/* One contiguous memory region per device */
	phys_addr_t		phys_addr;
	/* when non-zero this device is hosting a 'pfn' instance */
	phys_addr_t		data_offset;
	u64			pfn_flags;
	void			*virt_addr;
	/* immutable base size of the namespace */
	size_t			size;
	/* trim size when namespace capacity has been section aligned */
	u32			pfn_pad;
	struct kernfs_node	*bb_state;
	struct badblocks	bb;
	struct dax_device	*dax_dev;
	struct gendisk		*disk;
	struct dev_pagemap	pgmap;

	struct pmem_label	*label;		/* Local PMEM label */
	phys_addr_t		 rphys_addr;	/* Remote PMEM phys address */
	uint8_t			*rvirt_addr;	/* Remote PMEM KVA address */
	struct pmem_label	*rlabel;	/* Remote PMEM label */
	int			 node;		/* Local PMEM NUMA node */
	int			 rnode;		/* Remote PMEM (NTB) node */
	int			 opened;	/* Number of device opens */
	bool			 rdma_for_single; /* Prefer remote DMA */
	struct dma_chan		*dma_chan;	/* Local PMEM DMA channel */
	struct dma_chan		*rdma_chan;	/* Remote PMEM DMA channel */
};

long __pmem_direct_access(struct pmem_device *pmem, pgoff_t pgoff,
		long nr_pages, void **kaddr, pfn_t *pfn);

#ifdef CONFIG_MEMORY_FAILURE
static inline bool test_and_clear_pmem_poison(struct page *page)
{
	return TestClearPageHWPoison(page);
}
#else
static inline bool test_and_clear_pmem_poison(struct page *page)
{
	return false;
}
#endif

void ntb_pmem_register(struct pmem_device *pdev);
void ntb_pmem_unregister(struct pmem_device *pdev);
#endif /* __NVDIMM_PMEM_H__ */
