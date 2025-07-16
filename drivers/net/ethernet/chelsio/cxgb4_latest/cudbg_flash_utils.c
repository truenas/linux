#ifdef __KERNEL__
#include <platdef.h>
#else
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#endif
#include <t4_regs.h>
#ifndef CUDBG_LITE
#include <fcntl.h>
#include <unistd.h>
#include <adap_util.h>
#include <common.h>
#include <t4_hw.h>
#include <t4_chip_type.h>
#include <adapter.h>
#endif
#include <cudbg_if.h>
#include <cudbg_lib_common.h>

int write_flash(struct adapter *adap, u32 start_sec, void *data, u32 size);

void update_skip_size(struct cudbg_flash_sec_info *psec_info, u32 size)
{
	psec_info->skip_size += size;
}

u32 get_skip_size(struct cudbg_flash_sec_info *psec_info)
{
	return psec_info->skip_size;
}

static void set_sector_availability(struct adapter *adap,
				    struct cudbg_flash_sec_info *psec_info,
				    int sector_nu, int avail)
{
	sector_nu -= t4_flash_location_start_sec(adap, FLASH_LOC_CUDBG);
	if (avail)
		set_dbg_bitmap(psec_info->sec_bitmap, sector_nu);
	else
		reset_dbg_bitmap(psec_info->sec_bitmap, sector_nu);
}

/* This function will return empty sector available for filling */
static int find_empty_sec(struct adapter *adap, struct cudbg_flash_sec_info *psec_info)
{
	unsigned int start_sec = t4_flash_location_start_sec(adap, FLASH_LOC_CUDBG);
	unsigned int n = start_sec + t4_flash_location_nsecs(adap, FLASH_LOC_CUDBG);
	unsigned int i, index, bit;

	for (i = start_sec; i < n; i++) {
		index = (i - start_sec) / 8;
		bit = (i - start_sec) % 8;
		if (!(psec_info->sec_bitmap[index] & (1 << bit)))
			return i;
	}
	return CUDBG_STATUS_FLASH_FULL;
}

/* This function will get header initially. If header is already there
 * then it will update that header */
static void update_headers(void *handle, struct cudbg_buffer *dbg_buff,
			   u64 timestamp, u32 cur_entity_hdr_offset,
			   u32 start_offset, u32 ext_size)
{
	void *sec_hdr;
	struct cudbg_hdr *cudbg_hdr;
	struct cudbg_flash_hdr *flash_hdr;
	struct cudbg_entity_hdr *entity_hdr;
	struct cudbg_flash_sec_info *psec_info;
	u32 hdr_offset;
	u32 data_hdr_size;
	u32 total_hdr_size;
	u32 sec_hdr_start_addr;

	psec_info = ((struct cudbg_private *)handle)->psec_info; 
	data_hdr_size = CUDBG_MAX_ENTITY * sizeof(struct cudbg_entity_hdr) +
				sizeof(struct cudbg_hdr);
	total_hdr_size = data_hdr_size + sizeof(struct cudbg_flash_hdr);
	sec_hdr_start_addr = SF_SEC_SIZE - total_hdr_size;
	sec_hdr  = psec_info->sec_data + sec_hdr_start_addr;

	flash_hdr = (struct cudbg_flash_hdr *)(sec_hdr);
	cudbg_hdr = (struct cudbg_hdr *)dbg_buff->data;

	/* initially initialize flash hdr and copy all data headers and
	 * in next calling (else part) copy only current entity header
	 */
	if ((start_offset - psec_info->skip_size) == data_hdr_size) {
		flash_hdr->signature = CUDBG_FL_SIGNATURE;
		flash_hdr->major_ver = CUDBG_FL_MAJOR_VERSION;
		flash_hdr->minor_ver = CUDBG_FL_MINOR_VERSION;
		flash_hdr->build_ver = CUDBG_FL_BUILD_VERSION;
		flash_hdr->hdr_len = sizeof(struct cudbg_flash_hdr);
		hdr_offset =  sizeof(struct cudbg_flash_hdr);

		memcpy((void *)((char *)sec_hdr + hdr_offset),
		       (void *)((char *)dbg_buff->data), data_hdr_size);
	} else
		memcpy((void *)((char *)sec_hdr +
			sizeof(struct cudbg_flash_hdr) +
			cur_entity_hdr_offset),
			(void *)((char *)dbg_buff->data +
			cur_entity_hdr_offset),
			sizeof(struct cudbg_entity_hdr));

	hdr_offset = data_hdr_size + sizeof(struct cudbg_flash_hdr);
	flash_hdr->data_len = cudbg_hdr->data_len - psec_info->skip_size;
	flash_hdr->timestamp = timestamp;

	entity_hdr = (struct cudbg_entity_hdr *)((char *)sec_hdr +
		      sizeof(struct cudbg_flash_hdr) +
		      cur_entity_hdr_offset);
	/* big entity like mc need to be skipped */
	entity_hdr->start_offset -= psec_info->skip_size;

	cudbg_hdr = (struct cudbg_hdr *)((char *)sec_hdr +
			sizeof(struct cudbg_flash_hdr));
	cudbg_hdr->data_len = flash_hdr->data_len;
	flash_hdr->data_len += ext_size;
}

/* Write CUDBG data into serial flash */
int cudbg_write_flash(void *handle, u64 timestamp, void *data,
		      u32 start_offset, u32 cur_entity_hdr_offset,
		      u32 cur_entity_size,
		      u32 ext_size)
{
	struct cudbg_buffer *dbg_buff = (struct cudbg_buffer *)data;
	u32 data_hdr_size, total_hdr_size, tmp_size, space_left;
	u32 sec_data_offset, sec_hdr_start_addr, sec_data_size;
	struct cudbg_flash_hdr *flash_hdr = NULL;
	struct cudbg_flash_sec_info *psec_info;
	struct cudbg_init *cudbg_init = NULL;
	struct cudbg_private *context;
	struct adapter *adap = NULL;
	u32 cudbg_max_size;
	int sec, rc;

	context = (struct cudbg_private *)handle;
	cudbg_init = &(context->dbg_init);
	psec_info = context->psec_info;
	adap = cudbg_init->adap;

	rc = t4_flash_location_size(adap, FLASH_LOC_CUDBG);
	if (rc < 0)
		return -1;

	cudbg_max_size = rc;
	data_hdr_size = CUDBG_MAX_ENTITY * sizeof(struct cudbg_entity_hdr) +
			sizeof(struct cudbg_hdr);
	total_hdr_size = data_hdr_size + sizeof(struct cudbg_flash_hdr);
	sec_hdr_start_addr = SF_SEC_SIZE - total_hdr_size;
	sec_data_size = sec_hdr_start_addr;

	cudbg_init->print("\tWriting %u bytes to flash\n",
			  cur_entity_size);

	/* this function will get header if psec_info->sec_data does not
	 * have any header and
	 * will update the header if it has header
	 */
	update_headers(handle, dbg_buff, timestamp,
		       cur_entity_hdr_offset,
		       start_offset, ext_size);

	if (ext_size) {
		cur_entity_size += sizeof(struct cudbg_entity_hdr);
		start_offset = dbg_buff->offset - cur_entity_size;
	}

	flash_hdr = (struct cudbg_flash_hdr *)(psec_info->sec_data +
			sec_hdr_start_addr);

	if (flash_hdr->data_len > cudbg_max_size) {
		rc = CUDBG_STATUS_FLASH_FULL;
		goto out;
	}

	space_left = cudbg_max_size - flash_hdr->data_len;

	if (cur_entity_size > space_left) {
		rc = CUDBG_STATUS_FLASH_FULL;
		goto out;
	}

	while (cur_entity_size > 0) {
		sec = find_empty_sec(adap, psec_info);
		if (psec_info->par_sec) {
			sec_data_offset = psec_info->par_sec_offset;
			set_sector_availability(adap, psec_info,
						psec_info->par_sec, 0);
			psec_info->par_sec = 0;
			psec_info->par_sec_offset = 0;

		} else {
			psec_info->cur_seq_no++;
			flash_hdr->sec_seq_no = psec_info->cur_seq_no;
			sec_data_offset = 0;
		}

		if (cur_entity_size + sec_data_offset > sec_data_size) {
			tmp_size = sec_data_size - sec_data_offset;
		} else {
			tmp_size = cur_entity_size;
			psec_info->par_sec = sec;
			psec_info->par_sec_offset = cur_entity_size +
						  sec_data_offset;
		}

		memcpy((void *)((char *)psec_info->sec_data + sec_data_offset),
		       (void *)((char *)dbg_buff->data + start_offset),
		       tmp_size);

		rc = write_flash(adap, sec, psec_info->sec_data,
				 SF_SEC_SIZE);
		if (rc)
			goto out;

		cur_entity_size -= tmp_size;
		set_sector_availability(adap, psec_info, sec, 1);
		start_offset += tmp_size;
	}
out:
	return rc;
}

int write_flash(struct adapter *adap, u32 start_sec, void *data, u32 size)
{
	unsigned int i, n, addr, sf_sec_size;
	u8 *ptr = (u8 *)data;
	int rc = 0;

	sf_sec_size = adap->params.sf_size / adap->params.sf_nsec;
	addr =  start_sec * SF_SEC_SIZE;
	i = DIV_ROUND_UP(size, sf_sec_size); /* # of sectors spanned */
	rc = t4_flash_erase_sectors(adap, start_sec, start_sec + i - 1);

	/*
	 * If size == 0 then we're simply erasing the FLASH sectors associated
	 * with the on-adapter OptionROM Configuration File.
	 */
	if (rc || size == 0)
		goto out;

	/* this will write to the flash up to SF_PAGE_SIZE at a time */
	for (i = 0; i < size; i += SF_PAGE_SIZE) {
		if ((size - i) <  SF_PAGE_SIZE)
			n = size - i;
		else
			n = SF_PAGE_SIZE;
		rc = t4_write_flash(adap, addr, n, ptr, 0);
		if (rc)
			goto out;

		addr += n;
		ptr += n;
	}

	return 0;
out:
	return rc;
}
