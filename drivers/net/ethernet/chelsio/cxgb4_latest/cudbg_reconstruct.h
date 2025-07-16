/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CUDBG_RECONSTRUCT_H__
#define __CUDBG_RECONSTRUCT_H__

#define CUDBG_RECON_DUMP_SIZE (4 * 1024 * 1024) /* 4 MB */

struct cudbg_recon_params {
	struct cudbg_buffer cudbg_hdr;
	struct cudbg_buffer buffers[CUDBG_MAX_ENTITY];
};

#ifndef CUDBG_LITE
void cudbg_recon_read_tp_indirect(struct cudbg_init *pdbg_init, u32 addr,
				  u32 *data, u32 nregs, u32 idx);
void cudbg_recon_read_sge_indirect(struct cudbg_init *pdbg_init, u32 addr,
				   u32 *data, u32 nregs, u32 idx);
void cudbg_recon_read_pcie_indirect(struct cudbg_init *pdbg_init, u32 addr,
				    u32 *data, u32 nregs, u32 idx);
u32 cudbg_recon_read_rss_pf_map(struct cudbg_init *pdbg_init);
u32 cudbg_recon_read_rss_pf_mask(struct cudbg_init *pdbg_init);
void cudbg_recon_rss_pf_config(struct cudbg_init *pdbg_init, u32 index,
			       u32 *valp);
void cudbg_recon_read_rss_key(struct cudbg_init *pdbg_init, u32 *key);
void cudbg_recon_tp_get_tcp_stats(struct cudbg_init *pdbg_init,
				  struct tp_tcp_stats *v4,
				  struct tp_tcp_stats *v6);
void cudbg_recon_tp_get_err_stats(struct cudbg_init *pdbg_init,
				  struct tp_err_stats *st);
void cudbg_recon_tp_get_rdma_stats(struct cudbg_init *pdbg_init,
				   struct tp_rdma_stats *st);
void cudbg_recon_get_fcoe_stats(struct cudbg_init *pdbg_init, u32 idx,
				struct tp_fcoe_stats *st);
void cudbg_recon_tp_get_cpl_stats(struct cudbg_init *pdbg_init,
				  struct tp_cpl_stats *st);
void cudbg_recon_get_usm_stats(struct cudbg_init *pdbg_init,
			       struct tp_usm_stats *st);
#else
/* No Reconstruction for Driver */
static inline int cudbg_recon_null(struct cudbg_init *pdbg_init, ...)
{
	return 0;
}

#define cudbg_recon_read_tp_indirect cudbg_recon_null
#define cudbg_recon_read_sge_indirect cudbg_recon_null
#define cudbg_recon_read_pcie_indirect cudbg_recon_null
#define cudbg_recon_read_rss_pf_map cudbg_recon_null
#define cudbg_recon_read_rss_pf_mask cudbg_recon_null
#define cudbg_recon_rss_pf_config cudbg_recon_null
#define cudbg_recon_read_rss_key cudbg_recon_null
#define cudbg_recon_tp_get_tcp_stats cudbg_recon_null
#define cudbg_recon_tp_get_err_stats cudbg_recon_null
#define cudbg_recon_tp_get_rdma_stats cudbg_recon_null
#define cudbg_recon_get_fcoe_stats cudbg_recon_null
#define cudbg_recon_tp_get_cpl_stats cudbg_recon_null
#define cudbg_recon_get_usm_stats cudbg_recon_null
#endif

typedef int (*cudbg_recon_callback_t)(struct cudbg_init *pdbg_init,
				      struct cudbg_buffer *pout_buff,
				      struct cudbg_error *cudbg_err);

struct cudbg_recon_entity {
	u32 entity_code;
	cudbg_recon_callback_t recon_cb;
};

static inline int cudbg_recon_dump_status(struct cudbg_init *pdbg_init,
					  u32 entity_code)
{
	if (!pdbg_init->recon_en)
		return 0;

	if (pdbg_init->recon->buffers[entity_code].size)
		return 0;

	return CUDBG_STATUS_ENTITY_NOT_FOUND;
}

int cudbg_reconstruct_entities(void *handle, void *in_buf, u32 in_buf_size,
			       u8 **out_buf, u32 *out_buf_size);
#endif /* __CUDBG_RECONSTRUCT_H__ */
