#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <platdef.h>
#include <fastlz_common.h>
#include <fastlz.h>

unsigned char sixpack_magic[8] = {137, '6', 'P', 'K', 13, 10, 26, 10};

int write_magic(struct cudbg_init *pdbg_init, struct cudbg_buffer *_out_buff)
{
	return write_to_buf(pdbg_init, _out_buff->data, _out_buff->size,
			    &_out_buff->offset, sixpack_magic, 8);
}

int write_to_buf(struct cudbg_init *pdbg_init, void *out_buf, u32 out_buf_size,
		 u32 *offset, void *in_buf, u32 in_buf_size)
{
	int rc = 0;

	if (*offset >= out_buf_size)
		return CUDBG_STATUS_OUTBUFF_OVERFLOW;

	if (pdbg_init && pdbg_init->write_to_file_cb) {
		/* Write only data to file.  Header will be updated later. */
		rc = pdbg_init->write_to_file_cb(CUDBG_FILE_WRITE_DATA, 0,
						 (u8 *)in_buf, in_buf_size);
		if (rc)
			return rc;

		/* Update entity header size now since the buffer will
		 * be reused
		 */
		cudbg_update_entity_hdr(pdbg_init, in_buf_size);
	} else {
		memcpy((char *)out_buf + *offset, in_buf, in_buf_size);
		*offset = *offset + in_buf_size;
	}

	return rc;
}

int write_chunk_header(struct cudbg_init *pdbg_init,
		       struct cudbg_buffer *_outbuf, int id, int options,
		       unsigned long size, unsigned long checksum,
		       unsigned long extra)
{
	unsigned char buffer[CUDBG_CHUNK_BUF_LEN];

	buffer[0] = id & 255;
	buffer[1] = (unsigned char)(id >> 8);
	buffer[2] = options & 255;
	buffer[3] = (unsigned char)(options >> 8);
	buffer[4] = size & 255;
	buffer[5] = (size >> 8) & 255;
	buffer[6] = (size >> 16) & 255;
	buffer[7] = (size >> 24) & 255;
	buffer[8] = checksum & 255;
	buffer[9] = (checksum >> 8) & 255;
	buffer[10] = (checksum >> 16) & 255;
	buffer[11] = (checksum >> 24) & 255;
	buffer[12] = extra & 255;
	buffer[13] = (extra >> 8) & 255;
	buffer[14] = (extra >> 16) & 255;
	buffer[15] = (extra >> 24) & 255;

	return write_to_buf(pdbg_init, _outbuf->data, _outbuf->size,
			    &_outbuf->offset, buffer, 16);
}

int write_compression_hdr(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *pin_buff,
			  struct cudbg_buffer *pout_buff)
{
	struct cudbg_buffer tmp_buffer;
	unsigned long fsize = pin_buff->size;
	unsigned char *buffer;
	unsigned long checksum;
	int rc;
	char *shown_name = "abc";

	if (fsize == 0)
		return CUDBG_STATUS_NO_DATA;

	/* Always release inner scratch buffer, before releasing outer. */
	rc = get_scratch_buff(pout_buff, 10, &tmp_buffer);

	if (rc)
		goto err;

	buffer = (unsigned char *)tmp_buffer.data;

	rc = write_magic(pdbg_init, pout_buff);

	if (rc)
		goto err1;

	/* chunk for File Entry */
	buffer[0] = fsize & 255;
	buffer[1] = (fsize >> 8) & 255;
	buffer[2] = (fsize >> 16) & 255;
	buffer[3] = (fsize >> 24) & 255;
	buffer[4] = 0;
	buffer[5] = 0;
	buffer[6] = 0;
	buffer[7] = 0;
	buffer[8] = (strlen(shown_name)+1) & 255;
	buffer[9] = (unsigned char)((strlen(shown_name)+1) >> 8);
	checksum = 1L;
	checksum = update_adler32(checksum, buffer, 10);
	checksum = update_adler32(checksum, shown_name,
				  (int)strlen(shown_name)+1);

	rc = write_chunk_header(pdbg_init, pout_buff, 1, 0,
				10+(unsigned long)strlen(shown_name)+1,
				checksum, 0);

	if (rc)
		goto err1;

	rc = write_to_buf(pdbg_init, pout_buff->data, pout_buff->size,
			  &(pout_buff->offset), buffer, 10);

	if (rc)
		goto err1;

	rc = write_to_buf(pdbg_init, pout_buff->data, pout_buff->size,
			  &(pout_buff->offset), shown_name,
			  (u32)strlen(shown_name)+1);

	if (rc)
		goto err1;

err1:
	release_scratch_buff(&tmp_buffer, pout_buff);
err:
	return rc;
}

int compress_buff(struct cudbg_init *pdbg_init, struct cudbg_buffer *pin_buff,
		  struct cudbg_buffer *pout_buff)
{
	unsigned char *hash_table = pdbg_init->hash_table;
	struct cudbg_buffer tmp_buffer;
	struct cudbg_hdr *cudbg_hdr;
	unsigned long checksum;
	unsigned char *result;
	unsigned int bytes_read;
	int chunk_size, level = 2, rc = 0;
	int compress_method = 1;

	bytes_read = pin_buff->size;
	rc = get_scratch_buff(pout_buff, CUDBG_BLOCK_SIZE, &tmp_buffer);

	if (rc)
		goto err;

	result = (unsigned char *)tmp_buffer.data;

	if (bytes_read < 32)
		compress_method = 0;

	cudbg_hdr = (struct cudbg_hdr *)  pout_buff->data;

	switch (compress_method) {
	case 1:
		chunk_size = fastlz_compress_level(hash_table, level,
						   pin_buff->data,
						   bytes_read, result);

		checksum = update_adler32(1L, result, chunk_size);

		/* This check is for debugging Bug #28806 */
		if ((chunk_size > 62000) && (cudbg_hdr->reserved[7] < (u32)
		    chunk_size))   /* 64512 */
			cudbg_hdr->reserved[7] = (u32) chunk_size;

		rc = write_chunk_header(pdbg_init, pout_buff, 17, 1, chunk_size,
					checksum, bytes_read);

		if (rc)
			goto err_put_buff;

		rc = write_to_buf(pdbg_init, pout_buff->data, pout_buff->size,
				  &pout_buff->offset, result, chunk_size);

		if (rc)
			goto err_put_buff;

		break;

		/* uncompressed, also fallback method */
	case 0:
	default:
		checksum = update_adler32(1L, pin_buff->data, bytes_read);

		rc = write_chunk_header(pdbg_init, pout_buff, 17, 0, bytes_read,
					checksum, bytes_read);

		if (rc)
			goto err_put_buff;

		rc = write_to_buf(pdbg_init, pout_buff->data, pout_buff->size,
				  &pout_buff->offset, pin_buff->data,
				  bytes_read);
		if (rc)
			goto err_put_buff;

		break;
	}

err_put_buff:
	release_scratch_buff(&tmp_buffer, pout_buff);
err:
	return rc;
}
