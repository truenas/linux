#ifndef __KERNEL__
#include <string.h>
#endif
#include <platdef.h>
#include <cudbg_if.h>
#include <cudbg_lib_common.h>
#include <fastlz_common.h>

struct cudbg_flash_sec_info sec_info;

int get_scratch_buff_aligned(struct cudbg_buffer *pdbg_buff, u32 size,
			     struct cudbg_buffer *pscratch_buff, u32 align)
{
	u64 off, mask = align - 1;
	u32 scratch_offset;
	int rc = 0;

	scratch_offset = pdbg_buff->size - size;
	off = (uintptr_t)((u8 *)pdbg_buff->data + scratch_offset) & mask;
	scratch_offset -= off;
	size += off;
	if (pdbg_buff->offset > (int)scratch_offset ||
	    pdbg_buff->size < size) {
		rc = CUDBG_STATUS_NO_SCRATCH_MEM;
		goto err;
	} else {
		pscratch_buff->data = (char *)pdbg_buff->data + scratch_offset;
		pscratch_buff->offset = 0;
		pscratch_buff->size = size;
		pdbg_buff->size -= size;
	}
err:
	return rc;
}

int get_scratch_buff(struct cudbg_buffer *pdbg_buff, u32 size,
		     struct cudbg_buffer *pscratch_buff)
{
	u32 scratch_offset;
	int rc = 0;

	scratch_offset = pdbg_buff->size - size;
	if (pdbg_buff->offset > (int)scratch_offset || pdbg_buff->size < size) {
		rc = CUDBG_STATUS_NO_SCRATCH_MEM;
		goto err;
	} else {
		pscratch_buff->data = (char *)pdbg_buff->data + scratch_offset;
		pscratch_buff->offset = 0;
		pscratch_buff->size = size;
		pdbg_buff->size -= size;
	}
err:
	return rc;
}

void release_scratch_buff(struct cudbg_buffer *pscratch_buff,
			  struct cudbg_buffer *pdbg_buff)
{
	pdbg_buff->size += pscratch_buff->size;
	/* Reset the used buffer to zero.
 	 * If we dont do this, then it will effect the ext entity logic.
 	 */
	memset(pscratch_buff->data, 0, pscratch_buff->size);
	pscratch_buff->data = NULL;
	pscratch_buff->offset = 0;
	pscratch_buff->size = 0;
}

struct cudbg_private g_context;
unsigned char *hash_table[FASTLZ_HASH_SIZE];
int cudbg_hello(struct cudbg_init *dbg_init, void **handle)
{
	int rc = 0;

	dbg_init->hash_table = (unsigned char *)hash_table;
	memset(&g_context, 0, sizeof(struct cudbg_private));
	memcpy(&(g_context.dbg_init), dbg_init, sizeof(struct cudbg_init));
	g_context.psec_info = (struct cudbg_flash_sec_info *)&sec_info;
	*handle = (void *) &g_context;
	return rc;
}

/* cudbg_hello2 : extended version of cudbg_hello
 * calling method:
 * 1. first call to cudbg_hello2 with buf_size == 0 will fill buf_size with
 *    required size
 * 2. second call will be actual cudbg_hello2 with previous call buf_size*/
int cudbg_hello2(struct cudbg_init *dbg_init, void **handle, u8 *buf,
				 u32 *buf_size)
{
	struct cudbg_private *context;
	u32 total_size = sizeof(struct cudbg_private) +
			 sizeof(struct cudbg_flash_sec_info) +
			 sizeof(char *) * FASTLZ_HASH_SIZE;

	if (*buf_size < total_size) {
			*buf_size = total_size;
			return CUDBG_STATUS_SMALL_BUFF;
	}

	if (buf == NULL)
		return CUDBG_STATUS_INVALID_BUFF;

	context = (struct cudbg_private *)buf;
	memset(context, 0, sizeof(struct cudbg_private));
	context->psec_info = (struct cudbg_flash_sec_info *)(buf +
				sizeof(struct cudbg_private));
	dbg_init->hash_table = (unsigned char *)(context->psec_info) +
				sizeof(struct cudbg_flash_sec_info);
	memcpy(&(context->dbg_init), dbg_init, sizeof(struct cudbg_init));
	*handle = (void *)context;

	return 0;
}

static void reset_sec_info(struct cudbg_flash_sec_info *psec_info)
{
	memset(psec_info, 0, sizeof(struct cudbg_flash_sec_info));
}

int cudbg_bye(void *handle)
{
	struct cudbg_private *context = (struct cudbg_private *)handle;

	reset_sec_info(context->psec_info);
	return 0;
}

int cudbg_sge_ctxt_check_valid(u32 *buf, int type)
{
	int index, bit, bit_pos = 0;

	switch (type) {
	case CTXT_EGRESS:
		bit_pos = 176;
		break;
	case CTXT_INGRESS:
		bit_pos = 141;
		break;
	case CTXT_FLM:
		bit_pos = 89;
		break;
	}
	index = bit_pos / 32;
	bit =  bit_pos % 32;
	return buf[index] & (1U << bit);
}

void cudbg_update_entity_hdr(struct cudbg_init *pdbg_init, u32 size)
{
	struct cudbg_entity_hdr *entity_hdr =
		(struct cudbg_entity_hdr *)pdbg_init->cur_entity_hdr;

	entity_hdr->size += size;
}

/* Entity Alias List for collecting/viewing several cudbg entities */
void cudbg_append_string(char *dst, u32 dst_size, char *src)
{
	strcat_s(dst, dst_size, src);
	strcat_s(dst, dst_size, ",");
}
