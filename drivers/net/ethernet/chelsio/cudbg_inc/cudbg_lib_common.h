#ifndef __CUDBG_LIB_COMMON_H__
#define __CUDBG_LIB_COMMON_H__

/* Extended entity
 *
 * Layout of the cudbg dump file when extended entity is present.
 *
 *
 *           ----------------
 *           | Global header |
 *           |---------------|
 *           |entity headers |
 *           |---------------|
 *           | Entity data   |
 *           |      *        |
 *           |      *        |
 *           |      *        |
 *           |---------------|
 *           |extended entity|
 *           |    header     |
 *           |---------------|
 *           |extended entity|
 *           |     data      |
 *           -----------------
 *
 *
 * Extended entity: This comes into picture only when cudbg_collect() is called
 * multiple times.
 */

#ifndef CUDBG_LITE
#include <t4_hw.h>
#endif

#define CUDBG_EXT_DATA_BIT          0
#define CUDBG_EXT_DATA_VALID        (1 << CUDBG_EXT_DATA_BIT)

enum cudbg_compression_type {
	CUDBG_COMPRESSION_FASTLZ = 0,
	CUDBG_COMPRESSION_NONE = 1,
	CUDBG_COMPRESSION_ZLIB,
};

struct cudbg_hdr {
	u32 signature;
	u32 hdr_len;
	u16 major_ver;
	u16 minor_ver;
	u32 data_len;
	u32 hdr_flags;
	u16 max_entities;
	u8 chip_ver;
	u8 reserved1:4;
	u8 compress_type:4;
	u32 reserved[8];
};

struct cudbg_entity_hdr {
	u32 entity_type;
	u32 start_offset;
	u32 size;
	int hdr_flags;
	u32 sys_warn;
	u32 sys_err;
	u8 num_pad;
	u8 flag;		/* bit 0 is used to indicate ext data */
	u8 reserved1[2];
	u32 next_ext_offset;	/* pointer to next extended entity meta data */
	u32 reserved[5];
};

struct cudbg_ver_hdr {
	u32 signature;
	u16 revision;
	u16 size;
};

struct cudbg_buffer {
	u32 size;
	u32 offset;
	char *data;
};

struct cudbg_error {
	int sys_err;
	int sys_warn;
	int app_err;
};

struct cudbg_private {
	struct cudbg_init  dbg_init;
	struct cudbg_flash_sec_info *psec_info;
};

struct cudbg_flash_sec_info {
	int par_sec;		   /* Represent partially filled sector no */
	int par_sec_offset;	   /* Offset in partially filled sector */
	int cur_seq_no;
	u32 max_seq_no;
	u32 max_seq_sec;
	u32 hdr_data_len;	   /* Total data */
	u32 skip_size;		   /* Total size of large entities. */
	u64 max_timestamp;
	char sec_data[SF_SEC_SIZE];
	u8 sec_bitmap[8];
};

#define HTONL_NIBBLE(data) ( \
			    (((uint32_t)(data) >> 28) & 0x0000000F) | \
			    (((uint32_t)(data) >> 20)  & 0x000000F0) | \
			    (((uint32_t)(data) >> 12)  & 0x00000F00) | \
			    (((uint32_t)(data) >> 4) & 0x0000F000) | \
			    (((uint32_t)(data) << 4) & 0x000F0000) | \
			    (((uint32_t)(data) << 12)  & 0x00F00000) | \
			    (((uint32_t)(data) << 20)  & 0x0F000000) | \
			    (((uint32_t)(data) << 28) & 0xF0000000))

#define CDUMP_MAX_COMP_BUF_SIZE    ((64 * 1024) - 1)
#define CUDBG_CHUNK_SIZE  ((CDUMP_MAX_COMP_BUF_SIZE/1024) * 1024)

#define CUDBG_LEGACY_SIGNATURE 123
#define CUDBG_SIGNATURE 67856866 /* CUDB in ascii */
#define CUDBG_FL_SIGNATURE 0x4355464c /* CUFL in ascii */

#define CUDBG_FL_MAJOR_VERSION	    1
#define CUDBG_FL_MINOR_VERSION	    1
#define CUDBG_FL_BUILD_VERSION	    0

u32 get_skip_size(struct cudbg_flash_sec_info *psec_info);
void update_skip_size(struct cudbg_flash_sec_info *psec_info, u32 size);
void cudbg_update_entity_hdr(struct cudbg_init *pdbg_init, u32 size);
int write_compression_hdr(struct cudbg_init *, struct cudbg_buffer *,
			  struct cudbg_buffer *);
int compress_buff(struct cudbg_init *, struct cudbg_buffer *,
		  struct cudbg_buffer *);
int get_scratch_buff(struct cudbg_buffer *, u32, struct cudbg_buffer *);
int get_scratch_buff_aligned(struct cudbg_buffer *pdbg_buff, u32 size,
			     struct cudbg_buffer *pscratch_buff, u32 align);
void release_scratch_buff(struct cudbg_buffer *, struct cudbg_buffer *);
u16 get_entity_rev(struct cudbg_ver_hdr *ver_hdr);
void sort_t(void *base, int num, int size,
	    int (*cmp_func)(const void *, const void *),
	    void (*swap_func)(void *, void *, int size));
int cudbg_write_flash(void *handle, u64 timestamp, void *data,
		      u32 start_offset, u32 start_hdr_offset,
		      u32 cur_entity_size,
		      u32 ext_size);
void cudbg_tp_pio_read(struct cudbg_init *cudbg, u32 *buff, u32 nregs,
		       u32 start_index, u8 sleep_ok);
void cudbg_tp_tm_pio_read(struct cudbg_init *cudbg, u32 *buff, u32 nregs,
			  u32 start_index, u8 sleep_ok);
void cudbg_tp_mib_read(struct cudbg_init *cudbg, u32 *buff, u32 nregs,
		       u32 start_index, u8 sleep_ok);
int cudbg_sge_ctxt_check_valid(u32 *buf, int type);
void cudbg_append_string(char *dst, u32 dst_size, char *src);
#endif
