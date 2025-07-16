#ifndef __CUDBG_ZLIB_H__
#define __CUDBG_ZLIB_H__

#define CUDBG_ZLIB_COMP_ID	17
#define CUDBG_ZLIB_WIN_BITS	12
#define CUDBG_ZLIB_MEM_LVL	4

struct cudbg_compress_hdr {
	u32 cmp_id;
	u64 dcmp_size;
	u64 cmp_size;
	u64 rev[32];
};

#ifndef CUDBG_LITE
int cudbg_compress_zlib(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *pin_buff,
			struct cudbg_buffer *pout_buff);
int cudbg_decompress_zlib(struct cudbg_buffer *pc_buff,
			  struct cudbg_buffer *pdc_buff,
			  void *workspace);
#else
/* No ZLIB for driver yet */
#define cudbg_compress_zlib(pdbg_init, pin_buff, pout_buff) 0
#define cudbg_decompress_zlib(pc_buff, pdc_buff, workspace) 0
#endif /* __CUDBG_LITE__ */
#endif /* __CUDBG_ZLIB_H__ */
