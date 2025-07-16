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
#include <cudbg_entity.h>
#include <cudbg_lib.h>
#include <fastlz.h>
#include <cudbg_reconstruct.h>
#include <cudbg_zlib.h>
#include <cudbg_indir_reg.h>

#ifndef CUDBG_LITE
#include "t4_hw.c"
#endif

#include "cudbg_utls.c"

#ifdef ESX
	extern cxl_module_info cxl_info;
#endif

#define  BUFFER_WARN_LIMIT 10000000

#define GET_SCRATCH_BUFF(dbg_buff, size, scratch_buff) \
do { \
	rc = get_scratch_buff(dbg_buff, size, scratch_buff); \
	if (rc) \
		return rc; \
} while (0)

#define WRITE_AND_COMPRESS_SCRATCH_BUFF(scratch_buff, dbg_buff) \
do { \
	struct cudbg_hdr *cudbg_hdr; \
	if (pdbg_init->recon_en) \
		cudbg_hdr = \
			(struct cudbg_hdr *)(pdbg_init->recon->cudbg_hdr.data); \
	else \
		cudbg_hdr = (struct cudbg_hdr *)(dbg_buff->data); \
	if (cudbg_hdr->compress_type == CUDBG_COMPRESSION_NONE) { \
		rc = write_to_buf(pdbg_init, dbg_buff->data, dbg_buff->size, \
				  &dbg_buff->offset, (scratch_buff)->data, \
				  (scratch_buff)->size); \
	} else if (cudbg_hdr->compress_type == CUDBG_COMPRESSION_ZLIB){ \
		rc = cudbg_compress_zlib(pdbg_init, scratch_buff, dbg_buff); \
	} else { \
		rc = write_compression_hdr(pdbg_init, scratch_buff, dbg_buff); \
		if (rc) \
			goto err1; \
		rc = compress_buff(pdbg_init, scratch_buff, dbg_buff); \
	} \
} while (0)

#define WRITE_AND_RELEASE_SCRATCH_BUFF(scratch_buff, dbg_buff) \
do { \
	WRITE_AND_COMPRESS_SCRATCH_BUFF(scratch_buff, dbg_buff); \
err1: \
	release_scratch_buff(scratch_buff, dbg_buff); \
} while (0)


static int is_fw_attached(struct cudbg_init *pdbg_init)
{
	if (pdbg_init->dbg_params[CUDBG_FW_NO_ATTACH_PARAM].param_type ==
	    CUDBG_FW_NO_ATTACH_PARAM)
		return 0;
	return 1;
}

/* This function will add additional padding bytes into debug_buffer to make it
 * 4 byte aligned.*/
void align_debug_buffer(struct cudbg_buffer *dbg_buff,
			struct cudbg_entity_hdr *entity_hdr)
{
	u8 zero_buf[4] = {0};
	u8 padding, remain;

	remain = (dbg_buff->offset - entity_hdr->start_offset) % 4;
	padding = 4 - remain;
	if (remain) {
		memcpy(((u8 *) dbg_buff->data) + dbg_buff->offset, &zero_buf,
		       padding);
		dbg_buff->offset += padding;
		entity_hdr->num_pad = padding;
	}
	entity_hdr->size = dbg_buff->offset - entity_hdr->start_offset;
}

/* Same as align_debug_buffer() above, except, entity_hdr->size is not
 * calculated here, but rather updated only.
 */
static int align_and_update_debug_buffer(struct cudbg_init *pdbg_init,
					 struct cudbg_entity_hdr *entity_hdr)
{
	u8 zero_buf[4] = {0};
	u8 padding, remain;
	int rc;

	remain = entity_hdr->size % 4;
	padding = 4 - remain;
	if (remain) {
		rc = pdbg_init->write_to_file_cb(CUDBG_FILE_WRITE_DATA, 0,
						 zero_buf, padding);
		if (rc)
			return rc;

		entity_hdr->num_pad = padding;
		entity_hdr->size += padding;
	}
	return 0;
}

#ifndef CUDBG_LITE
static int find_adapter(struct cudbg_init *pdbg_init)
{
	struct adapter *padap = pdbg_init->adap;
	u32 val = 0;

	val = t4_read_reg(padap, A_PL_WHOAMI);
	if (val == 0xffffffff || val == X_CIM_PF_NOACCESS) {
		pdbg_init->print("%s FAIL - No access to PF BAR, WHOAMI returned: 0x%x\n",
				 __func__, val);
		return CUDBG_STATUS_ADAP_INVALID;
	}

	/* read chip version */
	padap->params.chip = t4_read_reg(padap, A_PL_REV);
	padap->pf = padap->mbox  = (CHELSIO_CHIP_VERSION(padap->params.chip) <=
				    CHELSIO_T5 ?
				    G_SOURCEPF(val) : G_T6_SOURCEPF(val));

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T6)
		padap->params.arch.mps_rplc_size = 256;

	return 0;
}
#endif

static void * cudbg_collect_indir_reg_init(struct cudbg_indir_reg_entity *e,
					   u16 rev, u32 indir_reg,
					   u32 indir_data, u32 nentries)
{
	struct cudbg_ver_hdr *ver_hdr = &e->ver_hdr;

	ver_hdr->signature = CUDBG_ENTITY_SIGNATURE;
	ver_hdr->revision = rev;
	ver_hdr->size = sizeof(*e) - sizeof(*ver_hdr);

	e->indir_reg = indir_reg;
	e->indir_data = indir_data;
	e->nentries = nentries;
	return e;
}

static void * cudbg_collect_indir_reg_init_next(struct cudbg_indir_reg_entity *e,
						u16 rev, u32 indir_reg,
						u32 indir_data, u32 nentries)
{
	struct cudbg_indir_reg_entity *n;

	n = (void *)((u8 *)e + (sizeof(*e) + sizeof(e->data[0]) * e->nentries));
	return cudbg_collect_indir_reg_init(n, rev, indir_reg, indir_data,
					    nentries);
}

static void cudbg_collect_indir_reg(struct adapter *padap,
				    struct cudbg_indir_reg_entity *e,
				    const struct cudbg_indir_type_entry *arr,
				    u16 rev, u32 indir_reg, u32 indir_data)
{
	struct cudbg_indir_reg_entity *entity;
	struct cudbg_indir_reg_data *reg_data;
	u32 i;

	entity = cudbg_collect_indir_reg_init(e, rev, indir_reg, indir_data,
					      arr->nentries);
	reg_data = entity->data;
	for (i = 0; i < entity->nentries; i++, reg_data++) {
		reg_data->offset = arr->reg_arr[i].addr;
		t4_read_indirect(padap, entity->indir_reg,
				 entity->indir_data, &reg_data->data,
				 1, reg_data->offset);
	}
}

static void cudbg_collect_indir_reg_next(struct adapter *padap,
					 struct cudbg_indir_reg_entity *e,
					 const struct cudbg_indir_type_entry *arr,
					 u16 rev, u32 indir_reg, u32 indir_data)
{
	struct cudbg_indir_reg_entity *n;

	n = (void *)((u8 *)e + (sizeof(*e) + sizeof(e->data[0]) * e->nentries));
	cudbg_collect_indir_reg(padap, n, arr, rev, indir_reg, indir_data);
}

void cudbg_tp_pio_read(struct cudbg_init *cudbg, u32 *buff, u32 nregs,
		       u32 start_index, u8 sleep_ok)
{
	if (cudbg->recon_en) {
		cudbg_recon_read_tp_indirect(cudbg, A_TP_PIO_ADDR, buff,
					     nregs, start_index);
		return;
	}

	cudbg_access_lock_aquire(cudbg);
	t4_tp_pio_read(cudbg->adap, buff, nregs, start_index, sleep_ok);
	cudbg_access_lock_release(cudbg);
}

void cudbg_tp_tm_pio_read(struct cudbg_init *cudbg, u32 *buff, u32 nregs,
			  u32 start_index, u8 sleep_ok)
{
	if (cudbg->recon_en) {
		cudbg_recon_read_tp_indirect(cudbg, A_TP_TM_PIO_ADDR, buff,
					     nregs, start_index);
		return;
	}
	cudbg_access_lock_aquire(cudbg);
	t4_tp_tm_pio_read(cudbg->adap, buff, nregs, start_index, sleep_ok);
	cudbg_access_lock_release(cudbg);
}

void cudbg_tp_mib_read(struct cudbg_init *cudbg, u32 *buff, u32 nregs,
		       u32 start_index, u8 sleep_ok)
{
	if (cudbg->recon_en) {
		cudbg_recon_read_tp_indirect(cudbg, A_TP_MIB_INDEX, buff,
					     nregs, start_index);
		return;
	}
	cudbg_access_lock_aquire(cudbg);
	t4_tp_mib_read(cudbg->adap, buff, nregs, start_index, sleep_ok);
	cudbg_access_lock_release(cudbg);
}

static void cudbg_pcie_cdbg_read(struct cudbg_init *pdbg_init, u32 *buff, u32 nregs,
			  u32 start_index)
{
	if (pdbg_init->recon_en) {
		cudbg_recon_read_pcie_indirect(pdbg_init, A_PCIE_CDEBUG_INDEX,
					       buff, nregs, start_index);
		return;
	}
	t4_read_indirect(pdbg_init->adap, A_PCIE_CDEBUG_INDEX, 0x5a18,
			 buff, nregs, start_index);
}

static int cudbg_sge_ctxt_rd(struct cudbg_init *cudbg, unsigned int mbox,
			     unsigned int cid, enum ctxt_type ctype, u32 *data)
{
	int rc = -1;

	cudbg_access_lock_aquire(cudbg);
	rc = t4_sge_ctxt_rd(cudbg->adap, mbox, cid, ctype, data);
	cudbg_access_lock_release(cudbg);
	return rc;
}

static int cudbg_get_portinfo(struct cudbg_init *cudbg, u8 port, struct port_data *pi)
{
	struct adapter *adapter = cudbg->adap;
	enum fw_port_module_type mod_type;
	int ret, mbox = adapter->mbox;
	enum fw_port_type port_type;
	int pf  = adapter->pf, vf = 0;
	struct fw_port_cmd cmd;
	unsigned int fw_caps;
	u32 param, val;
	u32 lstatus;

	/*
	 * find out 32-bit Port Capabilities is supported or not
	 */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_PORT_CAPS32));
	val = 1;
	ret = t4_set_params(adapter, mbox, pf, vf, 1, &param, &val);
	fw_caps = (ret == 0 ? FW_CAPS32 : FW_CAPS16);

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_portid = cpu_to_be32(V_FW_CMD_OP(FW_PORT_CMD) |
				       F_FW_CMD_REQUEST | F_FW_CMD_READ |
				       V_FW_PORT_CMD_PORTID(port));
	cmd.action_to_len16 =
		cpu_to_be32(V_FW_PORT_CMD_ACTION(fw_caps == FW_CAPS16 ?
						 FW_PORT_ACTION_GET_PORT_INFO :
						 FW_PORT_ACTION_GET_PORT_INFO32) |
			    FW_LEN16(cmd));
	ret = t4_wr_mbox(adapter, mbox, &cmd, sizeof(cmd), &cmd);
	if (ret)
		return ret;

	/*
	 * Extract the various fields from the Port Information message.
	 */
	if (fw_caps == FW_CAPS16) {
		lstatus = be32_to_cpu(cmd.u.info.lstatus_to_modtype);

		mod_type = G_FW_PORT_CMD_MODTYPE(lstatus);
		port_type = G_FW_PORT_CMD_PTYPE(lstatus);
	} else {
		u32 lstatus32 = be32_to_cpu(cmd.u.info32.lstatus32_to_cbllen32);

		mod_type = G_FW_PORT_CMD_MODTYPE32(lstatus32);
		port_type = G_FW_PORT_CMD_PORTTYPE32(lstatus32);
	}

	pi->tx_chan = port;

	pi->port_type = port_type;

	pi->mod_type = mod_type;

	return 0;
}

static int cudbg_get_module_info(struct cudbg_init *cudbg, struct port_data *pi,
				 struct cudbg_modinfo *modinfo)
{
	u8 sff8472_comp, sff_diag_type, sff_rev;
	struct adapter *adapter = cudbg->adap;
	int ret;

	if (!t4_is_inserted_mod_type(pi->mod_type))
		return -EINVAL;

	switch (pi->port_type) {
	case FW_PORT_TYPE_SFP:
	case FW_PORT_TYPE_QSA:
	case FW_PORT_TYPE_SFP28:
		ret = t4_i2c_rd(adapter, adapter->mbox, pi->tx_chan,
				I2C_DEV_ADDR_A0, SFF_8472_COMP_ADDR,
				SFF_8472_COMP_LEN, &sff8472_comp);
		if (ret)
			return ret;
		ret = t4_i2c_rd(adapter, adapter->mbox, pi->tx_chan,
				I2C_DEV_ADDR_A0, SFP_DIAG_TYPE_ADDR,
				SFP_DIAG_TYPE_LEN, &sff_diag_type);
		if (ret)
			return ret;

		if (!sff8472_comp || (sff_diag_type & 4)) {
			modinfo->type = CUDBG_MODULE_SFF_8079;
			modinfo->eeprom_len =
				eth_module_sff_len_array[CUDBG_MODULE_SFF_8079];
		} else {
			modinfo->type = CUDBG_MODULE_SFF_8472;
			modinfo->eeprom_len =
				eth_module_sff_len_array[CUDBG_MODULE_SFF_8472];
		}
		break;

	case FW_PORT_TYPE_QSFP:
	case FW_PORT_TYPE_QSFP_10G:
	case FW_PORT_TYPE_CR_QSFP:
	case FW_PORT_TYPE_CR2_QSFP:
	case FW_PORT_TYPE_CR4_QSFP:
		ret = t4_i2c_rd(adapter, adapter->mbox, pi->tx_chan,
				I2C_DEV_ADDR_A0, SFF_REV_ADDR,
				SFF_REV_LEN, &sff_rev);
		/* For QSFP type ports, revision value >= 3
		 * means the SFP is 8636 compliant.
		 */
		if (ret)
			return ret;
		if (sff_rev >= 0x3) {
			modinfo->type = CUDBG_MODULE_SFF_8636;
			modinfo->eeprom_len =
				eth_module_sff_len_array[CUDBG_MODULE_SFF_8636];
		} else {
			modinfo->type = CUDBG_MODULE_SFF_8436;
			modinfo->eeprom_len =
				eth_module_sff_len_array[CUDBG_MODULE_SFF_8436];
		}
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static void cudbg_get_fcoe_stats(struct cudbg_init *cudbg, unsigned int idx,
				 struct tp_fcoe_stats *st, bool sleep_ok)
{
	if (cudbg->recon_en) {
		cudbg_recon_get_fcoe_stats(cudbg, idx, st);
		return;
	}

	cudbg_access_lock_aquire(cudbg);
	t4_get_fcoe_stats(cudbg->adap, idx, st, sleep_ok);
	cudbg_access_lock_release(cudbg);
}

static int cudbg_query_params(struct cudbg_init *cudbg, unsigned int mbox,
			      unsigned int pf, unsigned int vf, unsigned int nparams,
			      const u32 *params, u32 *val)
{
	int rc;

	cudbg_access_lock_aquire(cudbg);
	rc = t4_query_params(cudbg->adap, mbox, pf, vf, nparams, params, val);
	cudbg_access_lock_release(cudbg);
	return rc;
}

static void read_sge_ctxt(struct cudbg_init *pdbg_init, u32 cid,
			  enum ctxt_type ctype, u32 *data)
{
	struct adapter *padap = pdbg_init->adap;
	int rc = -1;

	if (is_fw_attached(pdbg_init))
		rc = cudbg_sge_ctxt_rd(pdbg_init, padap->mbox, cid, ctype,
				       data);
	if (rc)
		t4_sge_ctxt_rd_bd(padap, cid, ctype, data);
}

static int get_next_ext_entity_hdr(void *outbuf, u32 *ext_size,
				   struct cudbg_buffer *dbg_buff,
				   struct cudbg_entity_hdr **entity_hdr)
{
	struct cudbg_hdr *cudbg_hdr = (struct cudbg_hdr *)outbuf;
	u32 ext_offset = cudbg_hdr->data_len;
	int rc = 0;

	*ext_size = 0;
	if (dbg_buff->size - dbg_buff->offset <=
		 sizeof(struct cudbg_entity_hdr)) {
		rc = CUDBG_STATUS_BUFFER_SHORT;
		goto err;
	}

	*entity_hdr = (struct cudbg_entity_hdr *)
		       ((char *)outbuf + cudbg_hdr->data_len);
	/* Find the last extended entity header */
	while ((*entity_hdr)->size) {

		ext_offset += sizeof(struct cudbg_entity_hdr) +
				     (*entity_hdr)->size;
		*ext_size += (*entity_hdr)->size +
			      sizeof(struct cudbg_entity_hdr);
		if (dbg_buff->size - dbg_buff->offset + *ext_size  <=
			sizeof(struct cudbg_entity_hdr)) {
			rc = CUDBG_STATUS_BUFFER_SHORT;
			goto err;
		}

		if (*ext_size != (*entity_hdr)->next_ext_offset) {
			ext_offset -= sizeof(struct cudbg_entity_hdr) +
				     (*entity_hdr)->size;
			*ext_size -= (*entity_hdr)->size +
				     sizeof(struct cudbg_entity_hdr);
			break;
		}
		(*entity_hdr)->next_ext_offset = *ext_size;
		*entity_hdr = (struct cudbg_entity_hdr *)
					   ((char *)outbuf +
					   ext_offset);
	}
	/* update the data offset */
	dbg_buff->offset = ext_offset;
err:
	return rc;
}

static int wr_entity_to_flash(void *handle, struct cudbg_buffer *dbg_buff,
			      u32 cur_entity_data_offset,
			      u32 cur_entity_size,
			      int entity_nu, u32 ext_size)
{
	u32 cur_entity_hdr_offset = sizeof(struct cudbg_hdr);
	struct cudbg_flash_sec_info *psec_info;
	struct cudbg_init *cudbg_init = NULL;
	struct cudbg_private *context;
	u32 remain_flash_size;
	u32 flash_data_offset;
	u32 data_hdr_size;
	u64 timestamp;
	int nsecs, rc;
	u32 size;

	context = (struct cudbg_private *)handle;
	cudbg_init = &(context->dbg_init);
	psec_info = context->psec_info;

	rc = t4_flash_location_size(cudbg_init->adap, FLASH_LOC_CUDBG);
	if (rc < 0)
		return -1;

	size = rc;
	nsecs = t4_flash_location_nsecs(cudbg_init->adap, FLASH_LOC_CUDBG);
	data_hdr_size = CUDBG_MAX_ENTITY * sizeof(struct cudbg_entity_hdr) +
			sizeof(struct cudbg_hdr);
	flash_data_offset = (nsecs *
			     (sizeof(struct cudbg_flash_hdr) +
			      data_hdr_size)) +
			    (cur_entity_data_offset - data_hdr_size) -
			    get_skip_size(psec_info);

	if (flash_data_offset > size) {
		update_skip_size(psec_info, cur_entity_size);
		cudbg_init->print("FAIL - no space left in flash. Skipping...\n");
		return -1;
	}

	remain_flash_size = size - flash_data_offset;
	if (cur_entity_size > remain_flash_size) {
		update_skip_size(psec_info, cur_entity_size);
		cudbg_init->print("FAIL - entity too large to write to flash. Skipping...\n");
	} else {
		timestamp =
			cudbg_init->dbg_params[CUDBG_TIMESTAMP_PARAM].
			u.time;

		cur_entity_hdr_offset +=
			(sizeof(struct cudbg_entity_hdr) *
			(entity_nu - 1));

		rc = cudbg_write_flash(handle, timestamp, dbg_buff,
				       cur_entity_data_offset,
				       cur_entity_hdr_offset,
				       cur_entity_size,
				       ext_size);
		if (rc == CUDBG_STATUS_FLASH_FULL)
			cudbg_init->print("\n\tFLASH is full... "
				"can not write in flash more\n\n");
	}
	return rc;
}

int cudbg_collect(void *handle, void *outbuf, u32 *outbuf_size)
{
	struct cudbg_private *context = (struct cudbg_private *)handle;
	struct cudbg_init *cudbg_init = &(context->dbg_init);
	struct cudbg_entity_hdr *ext_entity_hdr = NULL;
	u8 *dbg_bitmap = context->dbg_init.dbg_bitmap;
	int large_entity_code, large_entity_list_size;
	struct cudbg_entity_hdr *entity_hdr = NULL;
	struct large_entity large_entity_list[] = {
		{CUDBG_EDC0, 0, 0},
		{CUDBG_EDC1, 0, 0},
		{CUDBG_MC0, 0, 0},
		{CUDBG_MC1, 0, 0},
		{CUDBG_FLASH, 0, 0}
	};
	struct adapter *padap = cudbg_init->adap;
	struct cudbg_param *dbg_param = NULL;
	struct cudbg_error cudbg_err = {0};
	u32 total_size, remaining_buf_size;
	int index, bit, i, j, all, rc = -1;
	u32 hdr_size = 0, ext_off = 0;
	struct cudbg_buffer dbg_buff;
	struct cudbg_hdr *cudbg_hdr;
	int *el_list, el_list_size;
	bool do_file_write = 0;
	bool skip_se = false;
	bool flag_ext = 0;
	u32 ext_size = 0;
	u32 fw_err_val;
	u8 coreid = 0;

#ifdef ESX
	cxl_module_info *cxli = &cxl_info;
#endif

	large_entity_list_size = ARRAY_SIZE(large_entity_list);
	reset_skip_entity(large_entity_list, large_entity_list_size);

	dbg_param = &cudbg_init->dbg_params[CUDBG_FW_NO_ATTACH_PARAM];

	do_file_write = cudbg_init->write_to_file_cb ? true : false;

#ifndef CUDBG_LITE
	rc = find_adapter(cudbg_init);
	if (rc)
		return rc;
#endif

	/* Don't talk to firmware if it's crashed */
	fw_err_val = t4_read_reg(padap, A_PCIE_FW);
	if (dbg_param->param_type != CUDBG_FW_NO_ATTACH_PARAM &&
	    (fw_err_val & F_PCIE_FW_ERR))
		dbg_param->param_type = CUDBG_FW_NO_ATTACH_PARAM;

	/* If no valid mbox is found and if firmware is still alive,
	 * skip all side effect entities that may conflict with
	 * firmware or driver.
	 */
	if ((cudbg_init->dbg_params[CUDBG_SKIP_MBOX_PARAM].param_type ==
	     CUDBG_SKIP_MBOX_PARAM) && !(fw_err_val & F_PCIE_FW_ERR))
		skip_se = true;

	if (cudbg_init->dbg_params[CUDBG_UP_COREID_PARAM].param_type ==
	    CUDBG_UP_COREID_PARAM)
		coreid = cudbg_init->dbg_params[CUDBG_UP_COREID_PARAM].u.coreid;

	dbg_buff.data = outbuf;
	dbg_buff.size = *outbuf_size;
	dbg_buff.offset = 0;

	cudbg_hdr = (struct cudbg_hdr *)dbg_buff.data;
	cudbg_hdr->signature = CUDBG_SIGNATURE;
	cudbg_hdr->hdr_len = sizeof(struct cudbg_hdr);
	cudbg_hdr->major_ver = CUDBG_MAJOR_VERSION;
	cudbg_hdr->minor_ver = CUDBG_MINOR_VERSION;
	cudbg_hdr->max_entities = CUDBG_MAX_ENTITY;
	cudbg_hdr->chip_ver = padap->params.chip;
	if (cudbg_hdr->data_len)
		flag_ext = 1;

	if (cudbg_init->use_flash) {
		/* We can't do write to file and write to flash at the
		 * same time.
		 */
		if (do_file_write)
			return CUDBG_STATUS_NOT_SUPPORTED;

		rc = t4_get_flash_params(padap);
		if (rc) {
			cudbg_init->print("\nGet flash params failed.\n\n");
			cudbg_init->use_flash = 0;
		}

		/* Timestamp is mandatory. If it is not passed then disable
		 * flash support
		 */
		if (!cudbg_init->dbg_params[CUDBG_TIMESTAMP_PARAM].u.time) {
			cudbg_init->print("\nTimestamp param missing,"
					  "so ignoring flash write request\n\n");
			cudbg_init->use_flash = 0;
		}
	}

	if (sizeof(struct cudbg_entity_hdr) * CUDBG_MAX_ENTITY >
	    dbg_buff.size) {
		rc = CUDBG_STATUS_SMALL_BUFF;
		total_size = cudbg_hdr->hdr_len;
		goto err;
	}

	/* If ext flag is set then move the offset to the end of the buf
	 * so that we can add ext entities
	 */
	if (flag_ext) {
		ext_entity_hdr = (struct cudbg_entity_hdr *)
			      ((char *)outbuf + cudbg_hdr->hdr_len +
			      (sizeof(struct cudbg_entity_hdr) *
			      (CUDBG_EXT_ENTITY - 1)));
		ext_entity_hdr->start_offset = cudbg_hdr->data_len;
		ext_entity_hdr->entity_type = CUDBG_EXT_ENTITY;
		ext_entity_hdr->size = 0;
		dbg_buff.offset = cudbg_hdr->data_len;
	} else {
		dbg_buff.offset += cudbg_hdr->hdr_len; /* move 24 bytes*/
		dbg_buff.offset += CUDBG_MAX_ENTITY *
					sizeof(struct cudbg_entity_hdr);
	}

	hdr_size = cudbg_hdr->hdr_len + CUDBG_MAX_ENTITY *
		   sizeof(struct cudbg_entity_hdr);
	if (do_file_write) {
		/* Write initial cudbg header to file. Do this to ensure
		 * data gets written after the cudbg header.
		 */
		rc = cudbg_init->write_to_file_cb(CUDBG_FILE_WRITE_HEADER, 0,
						  (u8 *)cudbg_hdr, hdr_size);
		if (rc)
			goto err;
	}

	total_size = dbg_buff.offset;
	all = dbg_bitmap[0] & (1 << CUDBG_ALL);

	if (coreid) {
		el_list = entity_priority_list_sec_cores;
		el_list_size = sizeof(entity_priority_list_sec_cores) /
			       sizeof(*el_list);
	} else {
		el_list = entity_priority_list;
		el_list_size = sizeof(entity_priority_list) / sizeof(*el_list);
	}

	/* entity_priority_list_size does not include CUDBG_ALL so
	 * entity_priority_list_size + 1 */
	if (!coreid && el_list_size != (CUDBG_MAX_ENTITY - 1))
		cudbg_init->print("WARNING: CUDBG_MAX_ENTITY(%d) and "\
				  "entity_priority_list size(%d) mismatch\n",
				  CUDBG_MAX_ENTITY, el_list_size + 1);

	for (j = 0; j < el_list_size; j++) {
		i = el_list[j];
		index = i / 8;
		bit = i % 8;

#ifdef ESX
		if (cxli->config.mc_edc_dump == 0) {
			if (i == CUDBG_MC0 || i == CUDBG_MC1 || i == CUDBG_EDC0 || i == CUDBG_EDC1)
				continue;
		}
#endif

		if (entity_list[i].bit == CUDBG_EXT_ENTITY ||
		    entity_list[i].bit == CUDBG_QDESC)
			continue;

		if (all || (dbg_bitmap[index] & (1 << bit))) {

			if (!flag_ext) {
				rc = get_entity_hdr(outbuf, i, dbg_buff.size,
						    &entity_hdr);
				if (rc)
					cudbg_hdr->hdr_flags = rc;
			} else {
				rc = get_next_ext_entity_hdr(outbuf, &ext_size,
							     &dbg_buff,
							     &entity_hdr);
				if (rc)
					goto err;

				/* move the offset after the ext header */
				dbg_buff.offset +=
					sizeof(struct cudbg_entity_hdr);

				ext_off = total_size + ext_size;
				if (do_file_write) {
					/* Write initial entity header to
					 * file.  Do this to ensure ext entity
					 * data is written after the header.
					 */
					rc = cudbg_init->write_to_file_cb(
							CUDBG_FILE_WRITE_AT_OFFSET,
							ext_off, (u8 *)entity_hdr,
							sizeof(struct cudbg_entity_hdr));
					if (rc)
						goto err;
				}
			}

			entity_hdr->entity_type = i;
			if (do_file_write) {
				/* If we're immediately writing to file, then
				 * the outbuf is reused, so update the entity
				 * header accordingly.
				 */
				entity_hdr->start_offset = total_size;
				if (flag_ext)
					entity_hdr->start_offset += ext_size +
						sizeof(struct cudbg_entity_hdr);

				cudbg_init->cur_entity_hdr = (void *)entity_hdr;
			} else {
				entity_hdr->start_offset = dbg_buff.offset;
			}

			if (!do_file_write) {
				remaining_buf_size = dbg_buff.size -
						     dbg_buff.offset;
				if ((remaining_buf_size <= BUFFER_WARN_LIMIT) &&
				    is_large_entity(large_entity_list,
						    large_entity_list_size,
						    i)) {
					cudbg_init->print("Skipping %s\n",
							  entity_list[i].name);
					skip_entity(large_entity_list,
						    large_entity_list_size, i);
					continue;
				}
			}

			/* If fw_attach is 0, then skip entities which
			 * communicates with firmware
			 */

			if (dbg_param->param_type == CUDBG_FW_NO_ATTACH_PARAM &&
			    (entity_list[i].flag &
			     (1 << ENTITY_FLAG_FW_NO_ATTACH))) {
				cudbg_init->print("Skipping %s entity, because fw_attach is 0\n",
						  entity_list[i].name);
				continue;
			}

			cudbg_init->print("collecting debug entity[%d]: "\
					  "%s\n", padap->mbox, entity_list[i].name);
			memset(&cudbg_err, 0, sizeof(struct cudbg_error));
			if (skip_se &&
			    (entity_list[i].flag &
			     (1 << ENTITY_FLAG_NEED_MBOX))) {
				cudbg_init->print("No Mbox available. Skipping %s entity\n",
						  entity_list[i].name);
				rc = CUDBG_STATUS_NO_MBOX_PERM;
			} else {
				/* process each entity by calling process_entity
				 * fp
				 */
				rc = process_entity[i-1](cudbg_init, &dbg_buff,
							 &cudbg_err);
			}

			if (rc) {
				entity_hdr->size = 0;
				if (do_file_write)
					/* Reuse outbuf for collecting next
					 * entity
					 */
					dbg_buff.offset = hdr_size;
				else {
					memset((char *)outbuf + entity_hdr->start_offset, 0,
						   dbg_buff.offset - entity_hdr->start_offset);
					dbg_buff.offset =
						entity_hdr->start_offset;
					}
			} else {
				if (do_file_write) {
					rc = align_and_update_debug_buffer(cudbg_init,
									   entity_hdr);
					if (rc)
						return rc;
				} else {
					align_debug_buffer(&dbg_buff,
							   entity_hdr);
				}
			}

			if (cudbg_err.sys_err)
				rc = CUDBG_SYSTEM_ERROR;

			entity_hdr->hdr_flags =  rc;
			entity_hdr->sys_err = cudbg_err.sys_err;
			entity_hdr->sys_warn =	cudbg_err.sys_warn;

			/* We don't want to include ext entity size in global
			 * header
			 */
			if (!flag_ext)
				total_size += entity_hdr->size;

			cudbg_hdr->data_len = total_size;
			*outbuf_size = total_size;

			/* consider the size of the ext entity header and data
			 * also
			 */
			if (flag_ext) {
				ext_size += (sizeof(struct cudbg_entity_hdr) +
					     entity_hdr->size);
				entity_hdr->start_offset -= cudbg_hdr->data_len;
				ext_entity_hdr->size = ext_size;
				entity_hdr->next_ext_offset = ext_size;
				entity_hdr->flag |= CUDBG_EXT_DATA_VALID;
				if (do_file_write) {
					/* Flush all cached data to file. Do
					 * this to ensure that we can write
					 * the next extended entity's header
					 * appropriately after the data.
					 */
					rc = cudbg_init->write_to_file_cb(
							CUDBG_FILE_WRITE_FLUSH,
							0, NULL, 0);
					if (rc)
						goto err;

					/* Update entity header in file */
					rc = cudbg_init->write_to_file_cb(
							CUDBG_FILE_WRITE_AT_OFFSET,
							ext_off, (u8 *)entity_hdr,
							sizeof(struct cudbg_entity_hdr));
					if (rc)
						goto err;
				}
			}

			if (cudbg_init->use_flash) {
				if (flag_ext) {
					wr_entity_to_flash(handle,
							   &dbg_buff,
							   ext_entity_hdr->
							   start_offset,
							   entity_hdr->
							   size,
							   CUDBG_EXT_ENTITY,
							   ext_size);
				}
				else
					wr_entity_to_flash(handle,
							   &dbg_buff,
							   entity_hdr->\
							   start_offset,
							   entity_hdr->size,
							   i, ext_size);
			}
		}
	}

	for (i = 0; i < sizeof(large_entity_list) / sizeof(struct large_entity);
	     i++) {
		large_entity_code = large_entity_list[i].entity_code;
		if (large_entity_list[i].skip_flag) {
			if (!flag_ext) {
				rc = get_entity_hdr(outbuf, large_entity_code,
						    dbg_buff.size, &entity_hdr);
				if (rc)
					cudbg_hdr->hdr_flags = rc;
			} else {
				rc = get_next_ext_entity_hdr(outbuf, &ext_size,
							     &dbg_buff,
							     &entity_hdr);
				if (rc)
					goto err;

				dbg_buff.offset +=
					sizeof(struct cudbg_entity_hdr);
			}

			/* If fw_attach is 0, then skip entities which
			 * communicates with firmware
			 */

			if (dbg_param->param_type ==
			    CUDBG_FW_NO_ATTACH_PARAM &&
			    (entity_list[large_entity_code].flag &
			    (1 << ENTITY_FLAG_FW_NO_ATTACH))) {
				cudbg_init->print("Skipping %s entity,"\
						  "because fw_attach "\
						  "is 0\n",
						  entity_list[large_entity_code]
						  .name);
				continue;
			}

			entity_hdr->entity_type = large_entity_code;
			entity_hdr->start_offset = dbg_buff.offset;
			cudbg_init->print("Re-trying debug entity: %s\n",
					  entity_list[large_entity_code].name);

			memset(&cudbg_err, 0, sizeof(struct cudbg_error));
			if (skip_se &&
			    (entity_list[i].flag &
			     (1 << ENTITY_FLAG_NEED_MBOX))) {
				cudbg_init->print("No Mbox available. Skipping %s entity\n",
						  entity_list[i].name);
				rc = CUDBG_STATUS_NO_MBOX_PERM;
			} else {
				rc = process_entity[large_entity_code - 1]
				     (cudbg_init, &dbg_buff, &cudbg_err);
			}

			if (rc) {
				entity_hdr->size = 0;
				memset((char *)outbuf + entity_hdr->start_offset, 0,
					   dbg_buff.offset - entity_hdr->start_offset);
				dbg_buff.offset = entity_hdr->start_offset;
			} else
				align_debug_buffer(&dbg_buff, entity_hdr);

			if (cudbg_err.sys_err)
				rc = CUDBG_SYSTEM_ERROR;

			entity_hdr->hdr_flags = rc;
			entity_hdr->sys_err = cudbg_err.sys_err;
			entity_hdr->sys_warn =	cudbg_err.sys_warn;

			/* We don't want to include ext entity size in global
			 * header
			 */
			if (!flag_ext)
				total_size += entity_hdr->size;

			cudbg_hdr->data_len = total_size;
			*outbuf_size = total_size;

			/* consider the size of the ext entity header and
			 * data also
			 */
			if (flag_ext) {
				ext_size += (sizeof(struct cudbg_entity_hdr) +
						   entity_hdr->size);
				entity_hdr->start_offset -=
							cudbg_hdr->data_len;
				ext_entity_hdr->size = ext_size;
				entity_hdr->flag |= CUDBG_EXT_DATA_VALID;
			}

			if (cudbg_init->use_flash) {
				if (flag_ext)
					wr_entity_to_flash(handle,
							   &dbg_buff,
							   ext_entity_hdr->
							   start_offset,
							   entity_hdr->size,
							   CUDBG_EXT_ENTITY,
							   ext_size);
				else
					wr_entity_to_flash(handle,
							   &dbg_buff,
							   entity_hdr->
							   start_offset,
							   entity_hdr->
							   size,
							   large_entity_list[i].
							   entity_code,
							   ext_size);
			}
		}
	}

	if (flag_ext)
		total_size += ext_size;

	*outbuf_size = total_size;
	cudbg_hdr->data_len = total_size;

	if (do_file_write) {
		/* Flush all cached data to file */
		rc = cudbg_init->write_to_file_cb(CUDBG_FILE_WRITE_FLUSH, 0,
						  NULL, 0);
		if (rc)
			return rc;

		/* Update cudbg header */
		rc = cudbg_init->write_to_file_cb(CUDBG_FILE_WRITE_HEADER, 0,
						  (void *)cudbg_hdr, hdr_size);
		if (rc)
			return rc;
	}

	return 0;
err:
	return rc;
}

void reset_skip_entity(struct large_entity *large_entity_list,
		       int large_entity_list_size)
{
	int i;

	for (i = 0; i < large_entity_list_size; i++)
		large_entity_list[i].skip_flag = 0;
}

void skip_entity(struct large_entity *large_entity_list,
		 int large_entity_list_size, int entity_code)
{
	int i;

	for (i = 0; i < large_entity_list_size; i++)
		if (large_entity_list[i].entity_code == entity_code)
			large_entity_list[i].skip_flag = 1;
}

int is_large_entity(struct large_entity *large_entity_list,
		    int large_entity_list_size, int entity_code)
{
	int i;

	for (i = 0; i < large_entity_list_size; i++)
		if (large_entity_list[i].entity_code == entity_code)
			return 1;
	return 0;
}

int get_entity_hdr(void *outbuf, int i, u32 size,
		   struct cudbg_entity_hdr **entity_hdr)
{
	struct cudbg_hdr *cudbg_hdr = (struct cudbg_hdr *)outbuf;
	int rc = 0;

	if (cudbg_hdr->hdr_len + (sizeof(struct cudbg_entity_hdr)*i) > size)
		return CUDBG_STATUS_SMALL_BUFF;

	*entity_hdr = (struct cudbg_entity_hdr *)
		      ((char *)outbuf+cudbg_hdr->hdr_len +
		       (sizeof(struct cudbg_entity_hdr)*(i-1)));
	return rc;
}

int cudbg_collect_rss(struct cudbg_init *pdbg_init,
		      struct cudbg_buffer *dbg_buff,
		      struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	u32 nentries = 0;
	int rc = 0;

	nentries = t4_chip_rss_size(padap);
	GET_SCRATCH_BUFF(dbg_buff, nentries * sizeof(u16), &scratch_buff);
	rc = t4_read_rss(padap, (u16 *)scratch_buff.data);
	if (rc) {
		pdbg_init->print("%s(), t4_read_rss failed!, rc: %d\n",
				 __func__, rc);
		cudbg_err->sys_err = rc;
		goto err1;
	}
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_sw_state(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_param *dbg_param = NULL;
	struct cudbg_buffer scratch_buff;
	struct sw_state *swstate;
	int rc = 0;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*swstate), &scratch_buff);
	swstate = (struct sw_state *) scratch_buff.data;
	swstate->fw_state = t4_read_reg(padap, A_PCIE_FW);
	dbg_param = &pdbg_init->dbg_params[CUDBG_SW_STATE_PARAM];
	if (dbg_param->param_type == CUDBG_SW_STATE_PARAM) {
		strncpy_s((char *)swstate->caller_string,
			  sizeof(swstate->caller_string),
			  (char *)dbg_param->u.sw_state_param.caller_string,
			  sizeof(swstate->caller_string));
		swstate->os_type = dbg_param->u.sw_state_param.os_type;
	} else {
		strncpy_s((char *)swstate->caller_string,
			  sizeof(swstate->caller_string),
			  "Unknown", sizeof(swstate->caller_string));
		swstate->os_type = CUDBG_OS_TYPE_UNKNOWN;
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_ddp_stats(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct tp_usm_stats  *tp_usm_stats_buff;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*tp_usm_stats_buff), &scratch_buff);
	tp_usm_stats_buff = (struct tp_usm_stats *) scratch_buff.data;
	if (pdbg_init->recon_en) {
		cudbg_recon_get_usm_stats(pdbg_init, tp_usm_stats_buff);
	} else {
		cudbg_access_lock_aquire(pdbg_init);
		t4_get_usm_stats(padap, tp_usm_stats_buff, true);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_ulptx_la(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_ulptx_la *ulptx_la_buff;
	struct cudbg_buffer scratch_buff;
	struct cudbg_ver_hdr *ver_hdr;
	int rc = 0;
	u32 i, j;

	GET_SCRATCH_BUFF(dbg_buff,
			 sizeof(struct cudbg_ver_hdr) + sizeof(*ulptx_la_buff),
			 &scratch_buff);
	ver_hdr = (struct cudbg_ver_hdr *)scratch_buff.data;
	ver_hdr->signature = CUDBG_ENTITY_SIGNATURE;
	ver_hdr->revision = CUDBG_ULPTX_LA_REV;
	ver_hdr->size = sizeof(struct cudbg_ulptx_la);

	ulptx_la_buff = (struct cudbg_ulptx_la *) (scratch_buff.data +
						sizeof(struct cudbg_ver_hdr));

	for (i = 0; i < CUDBG_NUM_ULPTX; i++) {
		ulptx_la_buff->rdptr[i] = t4_read_reg(padap,
						      A_ULP_TX_LA_RDPTR_0 +
						      0x10 * i);
		ulptx_la_buff->wrptr[i] = t4_read_reg(padap,
						      A_ULP_TX_LA_WRPTR_0 +
						      0x10 * i);
		ulptx_la_buff->rddata[i] = t4_read_reg(padap,
						       A_ULP_TX_LA_RDDATA_0 +
						       0x10 * i);
		for (j = 0; j < CUDBG_NUM_ULPTX_READ; j++) {
			ulptx_la_buff->rd_data[i][j] =
				t4_read_reg(padap,
					    A_ULP_TX_LA_RDDATA_0 + 0x10 * i);
		}
	}

	/* dumping ULP_TX_ASIC_DEBUG */
	for (i = 0; i < CUDBG_NUM_ULPTX_ASIC_READ; i++) {
		t4_write_reg(padap, A_ULP_TX_ASIC_DEBUG_CTRL, 0x1);
		ulptx_la_buff->rdptr_asic[i] =
				t4_read_reg(padap, A_ULP_TX_ASIC_DEBUG_CTRL);
		ulptx_la_buff->rddata_asic[i][0] =
				t4_read_reg(padap, A_ULP_TX_ASIC_DEBUG_0);
		ulptx_la_buff->rddata_asic[i][1] =
				t4_read_reg(padap, A_ULP_TX_ASIC_DEBUG_1);
		ulptx_la_buff->rddata_asic[i][2] =
				t4_read_reg(padap, A_ULP_TX_ASIC_DEBUG_2);
		ulptx_la_buff->rddata_asic[i][3] =
				t4_read_reg(padap, A_ULP_TX_ASIC_DEBUG_3);
		ulptx_la_buff->rddata_asic[i][4] =
				t4_read_reg(padap, A_ULP_TX_ASIC_DEBUG_4);
		ulptx_la_buff->rddata_asic[i][5] =
				t4_read_reg(padap, PM_RX_BASE_ADDR);
	}

	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_ulprx_la(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_ulprx_la *ulprx_la_buff;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*ulprx_la_buff), &scratch_buff);
	ulprx_la_buff = (struct struct_ulprx_la *) scratch_buff.data;
	t4_ulprx_read_la(padap, (u32 *)ulprx_la_buff->data);
	ulprx_la_buff->size = ULPRX_LA_SIZE;
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_cpl_stats(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err)
{
	struct struct_tp_cpl_stats *tp_cpl_stats_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*tp_cpl_stats_buff), &scratch_buff);
	tp_cpl_stats_buff = (struct struct_tp_cpl_stats *) scratch_buff.data;
	tp_cpl_stats_buff->nchan = padap->params.arch.nchan;
	if (pdbg_init->recon_en) {
		cudbg_recon_tp_get_cpl_stats(pdbg_init,
					     &tp_cpl_stats_buff->stats);
	} else {
		cudbg_access_lock_aquire(pdbg_init);
		t4_tp_get_cpl_stats(padap, &tp_cpl_stats_buff->stats, true);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_wc_stats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_wc_stats *wc_stats_buff;
	struct cudbg_buffer scratch_buff;
	u32 val1, val2;
	int rc = 0;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*wc_stats_buff), &scratch_buff);
	wc_stats_buff = (struct struct_wc_stats *) scratch_buff.data;
	if (!is_t4(padap->params.chip)) {
		val1 = t4_read_reg(padap, A_SGE_STAT_TOTAL);
		val2 = t4_read_reg(padap, A_SGE_STAT_MATCH);
		wc_stats_buff->wr_cl_success = val1 - val2;
		wc_stats_buff->wr_cl_fail = val2;
	} else {
		wc_stats_buff->wr_cl_success = 0;
		wc_stats_buff->wr_cl_fail = 0;
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

static int fill_meminfo(struct adapter *padap,
			struct struct_meminfo *meminfo_buff)
{
	struct struct_mem_desc *md;
	u32 size, lo, hi;
	int n, i, rc = 0;
	u32 used, alloc;

	size = sizeof(struct struct_meminfo);

	memset(meminfo_buff->avail, 0,
	       ARRAY_SIZE(meminfo_buff->avail) *
	       sizeof(struct struct_mem_desc));
	memset(meminfo_buff->mem, 0,
	       (ARRAY_SIZE(region) + 3) * sizeof(struct struct_mem_desc));
	md  = meminfo_buff->mem;

	for (i = 0; i < ARRAY_SIZE(meminfo_buff->mem); i++) {
		meminfo_buff->mem[i].limit = 0;
		meminfo_buff->mem[i].idx = i;
	}

	i = 0;
	lo = t4_read_reg(padap, A_MA_TARGET_MEM_ENABLE);
	if (lo & F_EDRAM0_ENABLE) {
		hi = t4_read_reg(padap, A_MA_EDRAM0_BAR);
		meminfo_buff->avail[i].base = G_EDRAM0_BASE(hi) << 20;
		meminfo_buff->avail[i].limit = meminfo_buff->avail[i].base +
					       (G_EDRAM0_SIZE(hi) << 20);
		meminfo_buff->avail[i].idx = 0;
		i++;
	}

	if (lo & F_EDRAM1_ENABLE) {
		hi =  t4_read_reg(padap, A_MA_EDRAM1_BAR);
		meminfo_buff->avail[i].base = G_EDRAM1_BASE(hi) << 20;
		meminfo_buff->avail[i].limit = meminfo_buff->avail[i].base +
					       (G_EDRAM1_SIZE(hi) << 20);
		meminfo_buff->avail[i].idx = 1;
		i++;
	}

	if (is_t5(padap->params.chip)) {
		if (lo & F_EXT_MEM0_ENABLE) {
			hi = t4_read_reg(padap, A_MA_EXT_MEMORY0_BAR);
			meminfo_buff->avail[i].base = G_EXT_MEM_BASE(hi) << 20;
			meminfo_buff->avail[i].limit =
				meminfo_buff->avail[i].base +
				(G_EXT_MEM_SIZE(hi) << 20);
			meminfo_buff->avail[i].idx = 3;
			i++;
		}

		if (lo & F_EXT_MEM1_ENABLE) {
			hi = t4_read_reg(padap, A_MA_EXT_MEMORY1_BAR);
			meminfo_buff->avail[i].base = G_EXT_MEM1_BASE(hi) << 20;
			meminfo_buff->avail[i].limit =
				meminfo_buff->avail[i].base +
				(G_EXT_MEM1_SIZE(hi) << 20);
			meminfo_buff->avail[i].idx = 4;
			i++;
		}
	} else {
		if (lo & F_EXT_MEM_ENABLE) {
			hi = t4_read_reg(padap, A_MA_EXT_MEMORY_BAR);
			meminfo_buff->avail[i].base = G_EXT_MEM_BASE(hi) << 20;
			meminfo_buff->avail[i].limit =
				meminfo_buff->avail[i].base +
				(G_EXT_MEM_SIZE(hi) << 20);
			meminfo_buff->avail[i].idx = 2;
			i++;
		}

		if (lo & F_HMA_MUX) {
			hi = t4_read_reg(padap, A_MA_EXT_MEMORY1_BAR);
			meminfo_buff->avail[i].base = G_EXT_MEM1_BASE(hi) << 20;
			meminfo_buff->avail[i].limit =
				meminfo_buff->avail[i].base +
				(G_EXT_MEM1_SIZE(hi) << 20);
			meminfo_buff->avail[i].idx = 5;
			i++;
		}
	}

	if (!i) {				   /* no memory available */
		rc = CUDBG_STATUS_ENTITY_NOT_FOUND;
		goto err;
	}

	meminfo_buff->avail_c = i;
	sort_t(meminfo_buff->avail, i, sizeof(struct struct_mem_desc),
	       mem_desc_cmp, NULL);
	(md++)->base = t4_read_reg(padap, A_SGE_DBQ_CTXT_BADDR);
	(md++)->base = t4_read_reg(padap, A_SGE_IMSG_CTXT_BADDR);
	(md++)->base = t4_read_reg(padap, A_SGE_FLM_CACHE_BADDR);
	(md++)->base = t4_read_reg(padap, A_TP_CMM_TCB_BASE);
	(md++)->base = t4_read_reg(padap, A_TP_CMM_MM_BASE);
	(md++)->base = t4_read_reg(padap, A_TP_CMM_TIMER_BASE);
	(md++)->base = t4_read_reg(padap, A_TP_CMM_MM_RX_FLST_BASE);
	(md++)->base = t4_read_reg(padap, A_TP_CMM_MM_TX_FLST_BASE);
	(md++)->base = t4_read_reg(padap, A_TP_CMM_MM_PS_FLST_BASE);

	/* the next few have explicit upper bounds */
	md->base = t4_read_reg(padap, A_TP_PMM_TX_BASE);
	md->limit = md->base - 1 +
		    t4_read_reg(padap,
				A_TP_PMM_TX_PAGE_SIZE) *
				G_PMTXMAXPAGE(t4_read_reg(padap,
							  A_TP_PMM_TX_MAX_PAGE)
					     );
	md++;

	md->base = t4_read_reg(padap, A_TP_PMM_RX_BASE);
	md->limit = md->base - 1 +
		    t4_read_reg(padap,
				A_TP_PMM_RX_PAGE_SIZE) *
				G_PMRXMAXPAGE(t4_read_reg(padap,
							  A_TP_PMM_RX_MAX_PAGE)
					      );
	md++;
	if (t4_read_reg(padap, A_LE_DB_CONFIG) & F_HASHEN) {
		if (CHELSIO_CHIP_VERSION(padap->params.chip) <= CHELSIO_T5) {
			hi = t4_read_reg(padap, A_LE_DB_TID_HASHBASE) / 4;
			md->base = t4_read_reg(padap, A_LE_DB_HASH_TID_BASE);
		} else {
			hi = t4_read_reg(padap, A_LE_DB_HASH_TID_BASE);
			md->base = t4_read_reg(padap,
					       A_LE_DB_HASH_TBL_BASE_ADDR);
		}
		md->limit = 0;
	} else {
		md->base = 0;
		md->idx = ARRAY_SIZE(region);  /* hide it */
	}
	md++;
#define ulp_region(reg) \
	{\
		md->base = t4_read_reg(padap, A_ULP_ ## reg ## _LLIMIT);\
		(md++)->limit = t4_read_reg(padap, A_ULP_ ## reg ## _ULIMIT);\
	}

	ulp_region(RX_ISCSI);
	ulp_region(RX_TDDP);
	ulp_region(TX_TPT);
	ulp_region(RX_STAG);
	ulp_region(RX_RQ);
	ulp_region(RX_RQUDP);
	ulp_region(RX_PBL);
	ulp_region(TX_PBL);
#undef ulp_region
	md->base = 0;
	md->idx = ARRAY_SIZE(region);
	if (!is_t4(padap->params.chip)) {
		u32 sge_ctrl = t4_read_reg(padap, A_SGE_CONTROL2);
		u32 fifo_size = t4_read_reg(padap, A_SGE_DBVFIFO_SIZE);

		if (is_t5(padap->params.chip)) {
			if (sge_ctrl & F_VFIFO_ENABLE)
				size = G_DBVFIFO_SIZE(fifo_size);
		} else
			size = G_T6_DBVFIFO_SIZE(fifo_size);

		if (size) {
			md->base = G_BASEADDR(t4_read_reg(padap,
							  A_SGE_DBVFIFO_BADDR));
			md->limit = md->base + (size << 2) - 1;
		}
	}

	md++;

	md->base = t4_read_reg(padap, A_ULP_RX_CTX_BASE);
	md->limit = 0;
	md++;
	md->base = t4_read_reg(padap, A_ULP_TX_ERR_TABLE_BASE);
	md->limit = 0;
	md++;
#ifndef __NO_DRIVER_OCQ_SUPPORT__
	md->idx = ARRAY_SIZE(region);  /* hide it */
	md++;
#endif

	/* add any address-space holes, there can be up to 3 */
	for (n = 0; n < i - 1; n++)
		if (meminfo_buff->avail[n].limit <
		    meminfo_buff->avail[n + 1].base)
			(md++)->base = meminfo_buff->avail[n].limit;

	if (meminfo_buff->avail[n].limit)
		(md++)->base = meminfo_buff->avail[n].limit;

	n = (int) (md - meminfo_buff->mem);
	meminfo_buff->mem_c = n;

	sort_t(meminfo_buff->mem, n, sizeof(struct struct_mem_desc),
	       mem_desc_cmp, NULL);

	lo = t4_read_reg(padap, A_CIM_SDRAM_BASE_ADDR);
	hi = t4_read_reg(padap, A_CIM_SDRAM_ADDR_SIZE) + lo - 1;
	meminfo_buff->up_ram_lo = lo;
	meminfo_buff->up_ram_hi = hi;

	lo = t4_read_reg(padap, A_CIM_EXTMEM2_BASE_ADDR);
	hi = t4_read_reg(padap, A_CIM_EXTMEM2_ADDR_SIZE) + lo - 1;
	meminfo_buff->up_extmem2_lo = lo;
	meminfo_buff->up_extmem2_hi = hi;

	lo = t4_read_reg(padap, A_TP_PMM_RX_MAX_PAGE);
	for (i = 0, meminfo_buff->free_rx_cnt = 0; i < 2; i++)
		meminfo_buff->free_rx_cnt +=
			G_FREERXPAGECOUNT(t4_read_reg(padap,
						      A_TP_FLM_FREE_RX_CNT));
	meminfo_buff->rx_pages_data[0] =  G_PMRXMAXPAGE(lo);
	meminfo_buff->rx_pages_data[1] =
		t4_read_reg(padap, A_TP_PMM_RX_PAGE_SIZE) >> 10;
	meminfo_buff->rx_pages_data[2] = (lo & F_PMRXNUMCHN) ? 2 : 1 ;

	lo = t4_read_reg(padap, A_TP_PMM_TX_MAX_PAGE);
	hi = t4_read_reg(padap, A_TP_PMM_TX_PAGE_SIZE);
	for (i = 0, meminfo_buff->free_tx_cnt = 0; i < 4; i++)
		meminfo_buff->free_tx_cnt +=
			G_FREETXPAGECOUNT(t4_read_reg(padap,
						      A_TP_FLM_FREE_TX_CNT));
	meminfo_buff->tx_pages_data[0] = G_PMTXMAXPAGE(lo);
	meminfo_buff->tx_pages_data[1] =
		hi >= (1 << 20) ? (hi >> 20) : (hi >> 10);
	meminfo_buff->tx_pages_data[2] =
		hi >= (1 << 20) ? 'M' : 'K';
	meminfo_buff->tx_pages_data[3] = 1 << G_PMTXNUMCHN(lo);

	meminfo_buff->p_structs = t4_read_reg(padap, A_TP_CMM_MM_MAX_PSTRUCT);
	meminfo_buff->pstructs_free_cnt =
		G_FREEPSTRUCTCOUNT(t4_read_reg(padap, A_TP_FLM_FREE_PS_CNT));

	for (i = 0; i < 4; i++) {
		if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5)
			lo = t4_read_reg(padap,
					 A_MPS_RX_MAC_BG_PG_CNT0 + i * 4);
		else
			lo = t4_read_reg(padap, A_MPS_RX_PG_RSV0 + i * 4);
		if (is_t5(padap->params.chip)) {
			used = G_T5_USED(lo);
			alloc = G_T5_ALLOC(lo);
		} else {
			used = G_USED(lo);
			alloc = G_ALLOC(lo);
		}
		meminfo_buff->port_used[i] = used;
		meminfo_buff->port_alloc[i] = alloc;
	}

	for (i = 0; i < padap->params.arch.nchan; i++) {
		if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5)
			lo = t4_read_reg(padap,
					 A_MPS_RX_LPBK_BG_PG_CNT0 + i * 4);
		else
			lo = t4_read_reg(padap, A_MPS_RX_PG_RSV4 + i * 4);
		if (is_t5(padap->params.chip)) {
			used = G_T5_USED(lo);
			alloc = G_T5_ALLOC(lo);
		} else {
			used = G_USED(lo);
			alloc = G_ALLOC(lo);
		}
		meminfo_buff->loopback_used[i] = used;
		meminfo_buff->loopback_alloc[i] = alloc;
	}
err:
	return rc;
}

int cudbg_collect_meminfo(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_meminfo *meminfo_buff;
	struct cudbg_buffer scratch_buff;
	struct cudbg_ver_hdr *ver_hdr;
	int rc = 0;

	GET_SCRATCH_BUFF(dbg_buff,
			 sizeof(struct cudbg_ver_hdr) + sizeof(*meminfo_buff),
			 &scratch_buff);
	ver_hdr = (struct cudbg_ver_hdr *)scratch_buff.data;
	ver_hdr->signature = CUDBG_ENTITY_SIGNATURE;
	ver_hdr->revision = CUDBG_MEMINFO_REV;
	ver_hdr->size = sizeof(struct struct_meminfo);

	meminfo_buff = (struct struct_meminfo *) (scratch_buff.data +
						sizeof(struct cudbg_ver_hdr));
	rc = fill_meminfo(padap, meminfo_buff);
	if (rc)
		goto err1;
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

static int get_port_count(struct cudbg_init *pdbg_init)
{
	struct adapter *padap = pdbg_init->adap;
	u8 port_type[PORT_TYPE_LEN + 1] = { 0 };
	u32 v, port_vec, port_count;
	unsigned int i;
	int rc = 0;
	char *tmp;

	v = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_PORTVEC);
	port_count = 0;
	if (is_fw_attached(pdbg_init)) {
		rc = cudbg_query_params(pdbg_init, padap->mbox, padap->pf, 0,
					1, &v, &port_vec);
		if (rc >= 0)
			port_count = count_set_bits(port_vec);
	}

	if (port_count == 0) {
		rc = read_vpd_reg(padap, PORT_TYPE_ADDR, PORT_TYPE_LEN,
				  port_type);
		if (rc)
			return rc;

		/* port_vec will be like 0x0e0effff
		 * ff means not active
		 * rather than ff means active port
		 */
		tmp = (char *)port_type;
		for (i = 0; i < PORT_TYPE_LEN; i += 2) {
			if (!strncmp(&tmp[i], "FF", 2))
				continue;
			port_count++;
		}
	}
	return port_count;
}

int cudbg_collect_lb_stats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_lb_stats *lb_stats_buff;
	struct cudbg_buffer scratch_buff;
	struct lb_port_stats *tmp_stats;
	u32 i, n, size;
	int rc = 0;

	if (pdbg_init->recon_en) {
		n = 1 << G_NUMPORTS(t4_read_reg(padap, A_MPS_CMN_CTL));
	} else {
		rc = get_port_count(pdbg_init);
		if (rc < 0)
			return rc;
		n = rc;
	}

	size = sizeof(struct struct_lb_stats) +
	       n * sizeof(struct lb_port_stats);
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	lb_stats_buff = (struct struct_lb_stats *) scratch_buff.data;
	lb_stats_buff->nchan = n;
	tmp_stats = lb_stats_buff->s;
	for (i = 0; i < n; i += 2, tmp_stats += 2) {
		cudbg_access_lock_aquire(pdbg_init);
		t4_get_lb_stats(padap, i, tmp_stats);
		t4_get_lb_stats(padap, i + 1, tmp_stats+1);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_rdma_stats(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_er)
{
	struct adapter *padap = pdbg_init->adap;
	struct tp_rdma_stats *rdma_stats_buff;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*rdma_stats_buff), &scratch_buff);
	rdma_stats_buff = (struct tp_rdma_stats *) scratch_buff.data;
	if (pdbg_init->recon_en) {
		cudbg_recon_tp_get_rdma_stats(pdbg_init, rdma_stats_buff);
	} else {
		cudbg_access_lock_aquire(pdbg_init);
		t4_tp_get_rdma_stats(padap, rdma_stats_buff, true);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

static int cudbg_get_module_eeprom(struct cudbg_init *pdbg_init,
				   struct port_data *pi, u8 *data, u32 data_len)
{
	struct adapter *adapter = pdbg_init->adap;
	int ret = 0, offset = 0;
	u32 len = data_len;

	memset(data, 0, data_len);
	if (offset + len <= I2C_PAGE_SIZE)
		return t4_i2c_rd(adapter, adapter->mbox, pi->tx_chan,
				 I2C_DEV_ADDR_A0, offset, len, data);

	/* offset + len spans 0xa0 and 0xa1 pages */
	if (offset <= I2C_PAGE_SIZE) {
		/* read 0xa0 page */
		len = I2C_PAGE_SIZE - offset;
		ret =  t4_i2c_rd(adapter, adapter->mbox, pi->tx_chan,
				 I2C_DEV_ADDR_A0, offset, len, data);
		if (ret)
			return ret;
		offset = I2C_PAGE_SIZE;
		/* Remaining bytes to be read from second page =
		 * Total length - bytes read from first page
		 */
		len = data_len - len;
	}
	/* Read additional optical diagnostics from page 0xa2 if supported */
	return t4_i2c_rd(adapter, adapter->mbox, pi->tx_chan, I2C_DEV_ADDR_A2,
			 offset, len, &data[data_len - len]);
}

int cudbg_collect_module_eeprom(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err)
{
	struct cudbg_module_eeprom *mod_eeprom;
	struct cudbg_modinfo modinfo[MAX_NPORTS];
	struct cudbg_buffer scratch_buff;
	struct port_data pi[MAX_NPORTS];
	u32 size, offset;
	u8 nports, i;
	int rc;

	rc = get_port_count(pdbg_init);
	if (rc < 0) {
		cudbg_err->sys_err = rc;
		return rc;
	}
	nports = (u8)rc;

	size = sizeof(*mod_eeprom);
	for (i = 0; i < nports; i++) {
		rc = cudbg_get_portinfo(pdbg_init, i, &pi[i]);
		if (rc) {
			cudbg_err->sys_err = rc;
			return rc;
		}

		rc = cudbg_get_module_info(pdbg_init, &pi[i], &modinfo[i]);
		if (rc) {
			modinfo[i].eeprom_len = 0;
			rc = 0;
		}
		size += modinfo[i].eeprom_len;
	}

	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	memset(scratch_buff.data, 0, size);
	mod_eeprom = (struct cudbg_module_eeprom *)scratch_buff.data;
	mod_eeprom->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	mod_eeprom->ver_hdr.revision = CUDBG_MODEEPROM_REV;
	/* size of structure of version CUDBG_MODEEPROM_REV */
	mod_eeprom->ver_hdr.size = sizeof(struct cudbg_module_eeprom) -
				   sizeof(struct cudbg_ver_hdr);

	mod_eeprom->nports = nports;
	memcpy(mod_eeprom->modinfo, modinfo,
	       nports * sizeof(struct cudbg_modinfo));

	offset = 0;
	for (i = 0; i < nports; i++) {
		cudbg_get_module_eeprom(pdbg_init, &pi[i],
					mod_eeprom->data + offset,
					modinfo[i].eeprom_len);
		offset += modinfo[i].eeprom_len;
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_clk_info(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_clk_info *clk_info_buff;
	struct cudbg_buffer scratch_buff;
	u64 tp_tick_us;
	int rc = 0;

	if (!padap->params.vpd.cclk)
		return CUDBG_STATUS_CCLK_NOT_DEFINED;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*clk_info_buff), &scratch_buff);
	clk_info_buff = (struct struct_clk_info *) scratch_buff.data;
	clk_info_buff->cclk_ps = 1000000000 / padap->params.vpd.cclk;  /* in ps
	*/
	clk_info_buff->res = t4_read_reg(padap, A_TP_TIMER_RESOLUTION);
	clk_info_buff->tre = G_TIMERRESOLUTION(clk_info_buff->res);
	clk_info_buff->dack_re = G_DELAYEDACKRESOLUTION(clk_info_buff->res);
	tp_tick_us = (clk_info_buff->cclk_ps << clk_info_buff->tre) / 1000000;
	/* in us */
	clk_info_buff->dack_timer = ((clk_info_buff->cclk_ps <<
				      clk_info_buff->dack_re) / 1000000) *
				     t4_read_reg(padap, A_TP_DACK_TIMER);
	clk_info_buff->retransmit_min =
		tp_tick_us * t4_read_reg(padap, A_TP_RXT_MIN);
	clk_info_buff->retransmit_max =
		tp_tick_us * t4_read_reg(padap, A_TP_RXT_MAX);
	clk_info_buff->persist_timer_min =
		tp_tick_us * t4_read_reg(padap, A_TP_PERS_MIN);
	clk_info_buff->persist_timer_max =
		tp_tick_us * t4_read_reg(padap, A_TP_PERS_MAX);
	clk_info_buff->keepalive_idle_timer =
		tp_tick_us * t4_read_reg(padap, A_TP_KEEP_IDLE);
	clk_info_buff->keepalive_interval =
		tp_tick_us * t4_read_reg(padap, A_TP_KEEP_INTVL);
	clk_info_buff->initial_srtt =
		tp_tick_us * G_INITSRTT(t4_read_reg(padap, A_TP_INIT_SRTT));
	clk_info_buff->finwait2_timer =
		tp_tick_us * t4_read_reg(padap, A_TP_FINWAIT2_TIMER);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_macstats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct struct_mac_stats_rev1 *mac_stats_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc = 0;
	u32 i, n;

	if (pdbg_init->recon_en) {
		n = 1 << G_NUMPORTS(t4_read_reg(padap, A_MPS_CMN_CTL));
	} else {
		rc = get_port_count(pdbg_init);
		if (rc < 0)
			return rc;
		n = rc;
	}

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*mac_stats_buff), &scratch_buff);
	mac_stats_buff = (struct struct_mac_stats_rev1 *) scratch_buff.data;
	mac_stats_buff->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	mac_stats_buff->ver_hdr.revision = CUDBG_MAC_STATS_REV;
	mac_stats_buff->ver_hdr.size = sizeof(struct struct_mac_stats_rev1) -
				       sizeof(struct cudbg_ver_hdr);
	mac_stats_buff->port_count = n;
	for (i = 0; i <  mac_stats_buff->port_count; i++) {
		cudbg_access_lock_aquire(pdbg_init);
		t4_get_port_stats(padap, i, &mac_stats_buff->stats[i]);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_cim_pif_la(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cim_pif_la *cim_pif_la_buff;
	struct cudbg_buffer scratch_buff;
	int rc = 0;
	u32 size;

	size = sizeof(*cim_pif_la_buff) + 2 * CIM_PIFLA_SIZE * 6 * sizeof(u32);
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	cim_pif_la_buff = (struct cim_pif_la *) scratch_buff.data;
	cim_pif_la_buff->size = CIM_PIFLA_SIZE;
	t4_cim_read_pif_la(padap, (u32 *)cim_pif_la_buff->data,
			   (u32 *)cim_pif_la_buff->data + 6 * CIM_PIFLA_SIZE,
			   NULL, NULL);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_tp_la(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	struct struct_tp_la *tp_la_buff;
	int rc = 0;
	u32 size;

	size = sizeof(struct struct_tp_la) + TPLA_SIZE *  sizeof(u64);
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	tp_la_buff = (struct struct_tp_la *) scratch_buff.data;
	tp_la_buff->mode = G_DBGLAMODE(t4_read_reg(padap, A_TP_DBG_LA_CONFIG));
	t4_tp_read_la(padap, (u64 *)tp_la_buff->data, NULL);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_fcoe_stats(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err)
{
	struct struct_tp_fcoe_stats  *tp_fcoe_stats_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*tp_fcoe_stats_buff), &scratch_buff);
	tp_fcoe_stats_buff = (struct struct_tp_fcoe_stats *) scratch_buff.data;
	cudbg_get_fcoe_stats(pdbg_init, 0, &(tp_fcoe_stats_buff->stats[0]), true);
	cudbg_get_fcoe_stats(pdbg_init, 1, &(tp_fcoe_stats_buff->stats[1]), true);
	if (padap->params.arch.nchan == NCHAN) {
		cudbg_get_fcoe_stats(pdbg_init, 2, &(tp_fcoe_stats_buff->stats[2]),
				  true);
		cudbg_get_fcoe_stats(pdbg_init, 3, &(tp_fcoe_stats_buff->stats[3]),
				  true);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_tp_err_stats(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	struct struct_tp_err_stats *tp_err_stats_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*tp_err_stats_buff), &scratch_buff);
	tp_err_stats_buff = (struct struct_tp_err_stats *) scratch_buff.data;
	if (pdbg_init->recon_en) {
		cudbg_recon_tp_get_err_stats(pdbg_init,
					     &tp_err_stats_buff->stats);
	} else {
		cudbg_access_lock_aquire(pdbg_init);
		t4_tp_get_err_stats(padap, &tp_err_stats_buff->stats, true);
		cudbg_access_lock_release(pdbg_init);
	}
	tp_err_stats_buff->nchan = padap->params.arch.nchan;
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_tcp_stats(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_tcp_stats *tcp_stats_buff;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*tcp_stats_buff), &scratch_buff);
	tcp_stats_buff = (struct struct_tcp_stats *) scratch_buff.data;
	if (pdbg_init->recon_en) {
		cudbg_recon_tp_get_tcp_stats(pdbg_init, &tcp_stats_buff->v4,
					     &tcp_stats_buff->v6);
	} else {
		cudbg_access_lock_aquire(pdbg_init);
		t4_tp_get_tcp_stats(padap, &tcp_stats_buff->v4,
				    &tcp_stats_buff->v6, true);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_hw_sched(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_hw_sched *hw_sched_buff;
	struct cudbg_buffer scratch_buff;
	int i, rc = 0;

	if (!padap->params.vpd.cclk)
		return CUDBG_STATUS_CCLK_NOT_DEFINED;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*hw_sched_buff), &scratch_buff);
	hw_sched_buff = (struct struct_hw_sched *) scratch_buff.data;
	hw_sched_buff->map = t4_read_reg(padap, A_TP_TX_MOD_QUEUE_REQ_MAP);
	hw_sched_buff->mode = G_TIMERMODE(t4_read_reg(padap, A_TP_MOD_CONFIG));
	t4_read_pace_tbl(padap, hw_sched_buff->pace_tab);
	for (i = 0; i < NTX_SCHED; ++i) {
		cudbg_access_lock_aquire(pdbg_init);
		t4_get_tx_sched(padap, i, &(hw_sched_buff->kbps[i]),
				&(hw_sched_buff->ipg[i]), true);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_pm_stats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_pm_stats *pm_stats_buff;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*pm_stats_buff), &scratch_buff);
	pm_stats_buff = (struct struct_pm_stats *) scratch_buff.data;
	t4_pmtx_get_stats(padap, pm_stats_buff->tx_cnt, pm_stats_buff->tx_cyc);
	t4_pmrx_get_stats(padap, pm_stats_buff->rx_cnt, pm_stats_buff->rx_cyc);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_path_mtu(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	GET_SCRATCH_BUFF(dbg_buff, NMTUS * sizeof(u16), &scratch_buff);
	t4_read_mtu_tbl(padap, (u16 *)scratch_buff.data, NULL);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_rss_key(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, 10 * sizeof(u32), &scratch_buff);
	if (pdbg_init->recon_en) {
		cudbg_recon_read_rss_key(pdbg_init, (u32 *)scratch_buff.data);
	} else {
		cudbg_access_lock_aquire(pdbg_init);
		t4_read_rss_key(padap, (u32 *)scratch_buff.data, true);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_rss_config(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	struct rss_config *rss_conf;
	int rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(struct rss_config), &scratch_buff);
	rss_conf =  (struct rss_config *)scratch_buff.data;
	rss_conf->tp_rssconf = t4_read_reg(padap, A_TP_RSS_CONFIG);
	rss_conf->tp_rssconf_tnl = t4_read_reg(padap, A_TP_RSS_CONFIG_TNL);
	rss_conf->tp_rssconf_ofd = t4_read_reg(padap, A_TP_RSS_CONFIG_OFD);
	rss_conf->tp_rssconf_syn = t4_read_reg(padap, A_TP_RSS_CONFIG_SYN);
	rss_conf->tp_rssconf_vrt = t4_read_reg(padap, A_TP_RSS_CONFIG_VRT);
	rss_conf->tp_rssconf_cng = t4_read_reg(padap, A_TP_RSS_CONFIG_CNG);
	rss_conf->chip = padap->params.chip;
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_rss_vf_config(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	struct rss_vf_conf *vfconf;
	int vf, rc, vf_count;

	vf_count = padap->params.arch.vfcount;
	GET_SCRATCH_BUFF(dbg_buff, vf_count * sizeof(*vfconf), &scratch_buff);
	vfconf = (struct rss_vf_conf *)scratch_buff.data;
	for (vf = 0; vf < vf_count; vf++) {
		cudbg_access_lock_aquire(pdbg_init);	
		t4_read_rss_vf_config(padap, vf, &vfconf[vf].rss_vf_vfl,
				      &vfconf[vf].rss_vf_vfh, true);
		cudbg_access_lock_release(pdbg_init);	
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_rss_pf_config(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	u32 rss_pf_map = 0, rss_pf_mask = 0;
	struct cudbg_buffer scratch_buff;
	struct rss_pf_conf *pfconf;
	int pf, rc;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_TP_INDIRECT);
	if (rc)
		return rc;

	GET_SCRATCH_BUFF(dbg_buff, 8 * sizeof(*pfconf), &scratch_buff);
	pfconf = (struct rss_pf_conf *)scratch_buff.data;
	if (pdbg_init->recon_en) {
		rss_pf_map = cudbg_recon_read_rss_pf_map(pdbg_init);
		rss_pf_mask = cudbg_recon_read_rss_pf_mask(pdbg_init);
	} else {
		cudbg_access_lock_aquire(pdbg_init);
		rss_pf_map = t4_read_rss_pf_map(padap, true);
		rss_pf_mask = t4_read_rss_pf_mask(padap, true);
		cudbg_access_lock_release(pdbg_init);
	}
	for (pf = 0; pf < 8; pf++) {
		pfconf[pf].rss_pf_map = rss_pf_map;
		pfconf[pf].rss_pf_mask = rss_pf_mask;
		if (pdbg_init->recon_en) {
			cudbg_recon_rss_pf_config(pdbg_init, pf,
						  &pfconf[pf].rss_pf_config);
			continue;
		}
		cudbg_access_lock_aquire(pdbg_init);
		t4_read_rss_pf_config(padap, pf, &pfconf[pf].rss_pf_config,
				      true);
		cudbg_access_lock_release(pdbg_init);
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

/* Fetch the @region_name's start and end from @meminfo. */
int cudbg_get_mem_region(struct struct_meminfo *meminfo,
			 const char *region_name,
			 struct struct_mem_desc *mem_desc)
{
	u32 i, idx = 0, found = 0;

	for (i = 0; i < ARRAY_SIZE(region); i++) {
		if (!strcmp(region[i], region_name)) {
			found = 1;
			idx = i;
			break;
		}
	}
	if (!found)
		return -EINVAL;

	found = 0;
	for (i = 0; i < meminfo->mem_c; i++) {
		if (meminfo->mem[i].idx >= ARRAY_SIZE(region))
			continue; /* Skip holes */

		if (!(meminfo->mem[i].limit))
			meminfo->mem[i].limit =
				i < meminfo->mem_c - 1 ?
				meminfo->mem[i + 1].base - 1 : ~0;

		if (meminfo->mem[i].idx == idx) {
			memcpy(mem_desc, &meminfo->mem[i],
			       sizeof(struct struct_mem_desc));
			found = 1;
			break;
		}
	}
	if (!found)
		return -EINVAL;

	return 0;
}

/* Fetch and update the start and end of the requested memory region w.r.t 0
 * in the corresponding EDC/MC/HMA.
 */
void cudbg_get_mem_relative(struct struct_meminfo *meminfo,
			    u32 *out_base, u32 *out_end,
			    u8 *mem_type)
{
	u32 base = 0, end = 0;
	u8 i;

	for (i = 0; i < 4; i++) {
		if (i && !meminfo->avail[i].base)
			continue;

		if (*out_base > meminfo->avail[i].limit)
			continue;

		base = *out_base - meminfo->avail[i].base;
		end = *out_end - meminfo->avail[i].base;
		break;
	}

	*out_base = base;
	*out_end = end;
	/* Check if both MC0 and MC1 exist. If we stopped at MC0, then see
	 * if the actual index corresponds to MC1 (4) or above. if yes,
	 * then MC0 is not present and hence update the real index
	 * appropriately. See fill_meminfo for more information.
	 */
	if (i == MEM_MC0)
		if (meminfo->avail[i].idx > 3)
			i += meminfo->avail[i].idx - 3;
	*mem_type = i;
}

static int cudbg_get_ctxt_region_info(struct adapter *padap, u8 sge_ctxt_size,
				      struct struct_meminfo *meminfo,
				      struct struct_region_info *ctx_info)
{
	struct struct_mem_desc mem_desc = { 0 };
	u32 i, value;
	u8 flq;
	int rc;

	/* Get EGRESS and INGRESS context region size */
	for (i = CTXT_EGRESS; i <= CTXT_INGRESS; i++) {
		memset(&mem_desc, 0, sizeof(struct struct_mem_desc));
		rc = cudbg_get_mem_region(meminfo, region[i], &mem_desc);
		if (rc) {
			ctx_info[i].exist = false;
		} else {
			ctx_info[i].exist = true;
			ctx_info[i].start = mem_desc.base;
			ctx_info[i].end = mem_desc.limit;
		}
	}

	/* Get FLM and CNM max qid. */
	value = t4_read_reg(padap, A_SGE_FLM_CFG);

	/* Get number of data freelist queues */
	flq = G_HDRSTARTFLQ(value);
	ctx_info[CTXT_FLM].exist = true;
	ctx_info[CTXT_FLM].end = (CUDBG_MAX_FL_QIDS >> flq) * sge_ctxt_size;

	/* The number of CONM contexts are same as number of freelist
	 * queues.
	 */
	ctx_info[CTXT_CNM].exist = true;
	ctx_info[CTXT_CNM].end = ctx_info[CTXT_FLM].end;

	return 0;
}

int cudbg_dump_context_size(struct adapter *padap, u8 sge_ctxt_size)
{
	struct struct_region_info region_info[CTXT_CNM + 1] = {{ 0 }};
	struct struct_meminfo meminfo = {{{ 0 }}};
	u32 i, size = 0;
	int rc;

	rc = fill_meminfo(padap, &meminfo);
	if (rc)
		return rc;

	/* Get max valid qid for each type of queue */
	rc = cudbg_get_ctxt_region_info(padap, sge_ctxt_size, &meminfo,
					region_info);
	if (rc)
		return rc;

	for (i = 0; i < CTXT_CNM; i++) {
		if (!region_info[i].exist) {
			if (i == CTXT_EGRESS || i == CTXT_INGRESS)
				size += CUDBG_LOWMEM_MAX_CTXT_QIDS *
					sge_ctxt_size;
			continue;
		}

		size += region_info[i].end - region_info[i].start + 1;
	}
	return size * sizeof(struct struct_sge_ctxt_rev1_data);
}

static u32 cudbg_get_sge_ctxt_fw(struct cudbg_init *pdbg_init, u8 sge_ctxt_size,
				 u32 max_qid, u8 ctxt_type,
				 struct struct_sge_ctxt_rev1 *ctxt_buff,
				 struct struct_sge_ctxt_rev1_data **out_buff)
{
	struct struct_sge_ctxt_rev1_data *buff = *out_buff;
	u32 j, total_size = 0;
	int rc;

	for (j = 0; j < max_qid; j++) {
		read_sge_ctxt(pdbg_init, j, ctxt_type, buff->data);
		rc = cudbg_sge_ctxt_check_valid(buff->data, ctxt_type);
		if (!rc)
			continue;

		buff->ctxt_type = ctxt_type;
		buff->ctxt_id = j;
		buff->size = sge_ctxt_size;
		total_size += sizeof(*buff);
		ctxt_buff->nentries++;
		buff++;
		if (ctxt_type == CTXT_FLM) {
			read_sge_ctxt(pdbg_init, j, CTXT_CNM, buff->data);
			buff->ctxt_type = CTXT_CNM;
			buff->ctxt_id = j;
			buff->size = sge_ctxt_size;
			total_size += sizeof(*buff);
			ctxt_buff->nentries++;
			buff++;
		}
	}

	*out_buff = buff;
	return total_size;
}

int cudbg_collect_dump_context(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	struct struct_region_info region_info[CTXT_CNM + 1] = {{ 0 }};
	u32 size = 0, next_offset = 0, total_size = 0;
	struct cudbg_buffer scratch_buff, temp_buff;
	struct adapter *padap = pdbg_init->adap;
	struct struct_sge_ctxt_rev1 *ctxt_buff;
	struct struct_sge_ctxt_rev1_data *buff;
	u8 mem_type[CTXT_INGRESS + 1] = { 0 };
	struct struct_meminfo meminfo;
	u32 max_ctx_size, max_ctx_qid;
	u64 *dst_off, *src_off;
	u8 i, k, sge_ctxt_size;
	int bytes = 0, rc = 0;
	u32 j;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
		sge_ctxt_size = SGE_CTXT_SIZE_T7;
	else
		sge_ctxt_size = SGE_CTXT_SIZE;

	rc = fill_meminfo(padap, &meminfo);
	if (rc)
		goto err;

	/* Get max valid qid for each type of queue */
	rc = cudbg_get_ctxt_region_info(padap, sge_ctxt_size, &meminfo,
					region_info);
	if (rc)
		goto err;

	rc = cudbg_dump_context_size(padap, sge_ctxt_size);
	if (rc < 0)
		goto err;

	size = rc;
	GET_SCRATCH_BUFF(dbg_buff, size + sizeof(*ctxt_buff), &scratch_buff);
	ctxt_buff = (void *)scratch_buff.data;
	ctxt_buff->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	ctxt_buff->ver_hdr.revision = CUDBG_SGE_CTXT_REV;
	ctxt_buff->ver_hdr.size = sizeof(*ctxt_buff) -
				  sizeof(struct cudbg_ver_hdr);
	ctxt_buff->nentries = 0;
	total_size = sizeof(*ctxt_buff);

	/* Get the relative start and end of context regions w.r.t 0;
	 * in the corresponding memory.
	 */
	for (i = CTXT_EGRESS; i <= CTXT_INGRESS; i++) {
		if (!region_info[i].exist)
			continue;

		cudbg_get_mem_relative(&meminfo, &region_info[i].start,
				       &region_info[i].end, &mem_type[i]);
	}

	/* Get buffer with enough space to read the biggest context
	 * region in memory.
	 */
	max_ctx_size = max(region_info[CTXT_EGRESS].end -
			   region_info[CTXT_EGRESS].start + 1,
			   region_info[CTXT_INGRESS].end -
			   region_info[CTXT_INGRESS].start + 1);
	rc = get_scratch_buff(dbg_buff, max_ctx_size, &temp_buff);
	if (rc)
		goto err1;

	buff = (void *)ctxt_buff->data;

	/* Collect EGRESS and INGRESS context data.
	 * In case of failures, fallback to collecting via FW or
	 * backdoor access.
	 */
	for (i = CTXT_EGRESS; i <= CTXT_INGRESS; i++) {
		if (!region_info[i].exist) {
			max_ctx_qid = CUDBG_LOWMEM_MAX_CTXT_QIDS;
			total_size += cudbg_get_sge_ctxt_fw(pdbg_init,
							    sge_ctxt_size,
							    max_ctx_qid, i,
							    ctxt_buff,
							    &buff);
			continue;
		}

		max_ctx_size = region_info[i].end - region_info[i].start + 1;
		max_ctx_qid = max_ctx_size / sge_ctxt_size;

		if (is_fw_attached(pdbg_init)) {
			t4_sge_ctxt_flush(padap, padap->mbox, i);
			rc = t4_memory_rw(padap, MEMWIN_NIC, mem_type[i],
					  region_info[i].start, max_ctx_size,
					  (__be32 *)temp_buff.data, 1);
		}

		if (rc || !is_fw_attached(pdbg_init)) {
			max_ctx_qid = CUDBG_LOWMEM_MAX_CTXT_QIDS;
			total_size += cudbg_get_sge_ctxt_fw(pdbg_init,
							    sge_ctxt_size,
							    max_ctx_qid, i,
							    ctxt_buff,
							    &buff);
			continue;
		}

		for (j = 0; j < max_ctx_qid; j++) {
			src_off = (u64 *)(temp_buff.data + j * sge_ctxt_size);
			dst_off = (u64 *)buff->data;

			/* The data is stored in 64-bit cpu order.  Convert it to
			 * big endian before parsing.
			 */
			for (k = 0; k < sge_ctxt_size / sizeof(u64); k++)
				dst_off[k] = cpu_to_be64(src_off[k]);

			rc = cudbg_sge_ctxt_check_valid(buff->data, i);
			if (!rc)
				continue;

			buff->ctxt_type = i;
			buff->ctxt_id = j;
			buff->size = sge_ctxt_size;
			total_size += sizeof(*buff);
			ctxt_buff->nentries++;
			buff++;
		}
	}

	release_scratch_buff(&temp_buff, dbg_buff);

	/* Collect FREELIST and CONGESTION MANAGER contexts */
	max_ctx_size = region_info[CTXT_FLM].end -
		       region_info[CTXT_FLM].start + 1;
	max_ctx_qid = max_ctx_size / sge_ctxt_size;
	/* Since FLM and CONM are 1-to-1 mapped, the below function
	 * will fetch both FLM and CONM contexts.
	 */
	total_size += cudbg_get_sge_ctxt_fw(pdbg_init, sge_ctxt_size,
					    max_ctx_qid, CTXT_FLM,
					    ctxt_buff, &buff);

	scratch_buff.size = total_size;
	rc = write_compression_hdr(pdbg_init, &scratch_buff, dbg_buff);
	if (rc)
		goto err1;

	/* Splitting buffer and writing in terms of CUDBG_CHUNK_SIZE */
	while (total_size > 0) {
		bytes = min_t(unsigned long, (unsigned long)total_size,
			      (unsigned long)CUDBG_CHUNK_SIZE);
		temp_buff.size = bytes;
		temp_buff.data = (void *)((char *)scratch_buff.data +
					  next_offset);

		rc = compress_buff(pdbg_init, &temp_buff, dbg_buff);
		if (rc)
			goto err1;

		total_size -= bytes;
		next_offset += bytes;
	}

err1:
	scratch_buff.size = size;
	release_scratch_buff(&scratch_buff, dbg_buff);
err:
	return rc;
}

int cudbg_collect_fw_devlog(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_param *params = NULL;
	struct cudbg_buffer scratch_buff;
	struct devlog_params *dparams;
	u8 i, coreid = 0;
	int rc = 0;
	u32 offset;


	if (pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].param_type ==
	    CUDBG_UP_COREID_PARAM)
		coreid = pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].u.coreid;

	dparams = &padap->params.devlog[coreid];

	cudbg_access_lock_aquire(pdbg_init);
	rc = t4_init_devlog_params(padap, 1);
	cudbg_access_lock_release(pdbg_init);
	if (rc < 0) {
		pdbg_init->print("%s(), t4_init_devlog_params failed!, rc: "\
				 "%d\n", __func__, rc);
		for (i = 0; i < pdbg_init->dbg_params_cnt; i++) {
			if (pdbg_init->dbg_params[i].param_type ==
			    CUDBG_DEVLOG_PARAM) {
				params = &pdbg_init->dbg_params[i];
				break;
			}
		}

		if (params) {
			dparams->memtype = params->u.devlog_param.memtype;
			dparams->start = params->u.devlog_param.start;
			dparams->size = params->u.devlog_param.size;
		} else {
			cudbg_err->sys_err = rc;
			goto err;
		}
	}

	GET_SCRATCH_BUFF(dbg_buff, dparams->size, &scratch_buff);
	/* Collect FW devlog */
	if (dparams->start != 0) {
		offset = scratch_buff.offset;
		rc = t4_memory_rw(padap, padap->params.drv_memwin,
				  dparams->memtype, dparams->start,
				  dparams->size,
				  (__be32 *)((char *)scratch_buff.data +
					     offset), 1);

		if (rc) {
			pdbg_init->print("%s(), t4_memory_rw failed!, rc: "\
					 "%d\n", __func__, rc);
			cudbg_err->sys_err = rc;
			goto err1;
		}
	}
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
err:
	return rc;
}

/* CIM OBQ */
static int read_cim_obq(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err, u8 qid)
{
	struct struct_cim_obq_rev1 *cim_obq_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int no_of_read_words, rc = 0;
	u8 coreid = 0;
	u32 qsize;

	if (qid >= t4_cim_num_obq(padap))
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	if (pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].param_type ==
	    CUDBG_UP_COREID_PARAM)
		coreid = pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].u.coreid;

	/* collect CIM OBQ */
	qsize = 6 * CIM_OBQ_SIZE * 4 * sizeof(u32);
	GET_SCRATCH_BUFF(dbg_buff, sizeof(*cim_obq_buff) + qsize,
			 &scratch_buff);
	cim_obq_buff = (void *)((u8 *)scratch_buff.data + scratch_buff.offset);
	cim_obq_buff->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	cim_obq_buff->ver_hdr.revision = CUDBG_CIM_OBQ_REV;
	cim_obq_buff->ver_hdr.size = sizeof(*cim_obq_buff) -
				     sizeof(struct cudbg_ver_hdr);
	cim_obq_buff->qid = qid;
	cim_obq_buff->coreid = coreid;

	/* t4_read_cim_obq will return no. of read words or error */
	no_of_read_words = t4_read_cim_obq_core(padap, coreid, qid,
						cim_obq_buff->data, qsize);

	/* no_of_read_words is less than or equal to 0 means error */
	if (no_of_read_words <= 0) {
		if (no_of_read_words == 0)
			rc = CUDBG_SYSTEM_ERROR;
		else
			rc = no_of_read_words;
		pdbg_init->print("%s(), t4_read_cim_obq failed!, rc: %d\n",
				 __func__, rc);
		cudbg_err->sys_err = rc;
		goto err1;
	}
	scratch_buff.size = sizeof(*cim_obq_buff) + no_of_read_words * 4;
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_cim_obq_ulp0(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 0);
}

int cudbg_collect_cim_obq_ulp1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 1);
}

int cudbg_collect_cim_obq_ulp2(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 2);
}

int cudbg_collect_cim_obq_ulp3(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 3);
}

int cudbg_collect_cim_obq_sge(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 4);
}

int cudbg_collect_cim_obq_ncsi(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 5);
}

int cudbg_collect_cim_obq_sge_rx_q0(struct cudbg_init *pdbg_init,
				    struct cudbg_buffer *dbg_buff,
				    struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 6);
}

int cudbg_collect_cim_obq_sge_rx_q1(struct cudbg_init *pdbg_init,
				    struct cudbg_buffer *dbg_buff,
				    struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 7);
}

int cudbg_collect_cim_obq_ipc1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 9);
}

int cudbg_collect_cim_obq_ipc2(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 10);
}

int cudbg_collect_cim_obq_ipc3(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 11);
}

int cudbg_collect_cim_obq_ipc4(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 12);
}

int cudbg_collect_cim_obq_ipc5(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 13);
}

int cudbg_collect_cim_obq_ipc6(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 14);
}

int cudbg_collect_cim_obq_ipc7(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_obq(pdbg_init, dbg_buff, cudbg_err, 15);
}

/* CIM IBQ */
static int read_cim_ibq(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err, u8 qid)
{
	struct struct_cim_ibq_rev1 *cim_ibq_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int no_of_read_words, rc = 0;
	u8 coreid = 0;
	u32 qsize;

	if (qid >= t4_cim_num_ibq(padap))
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	if (pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].param_type ==
	    CUDBG_UP_COREID_PARAM)
		coreid = pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].u.coreid;

	/* collect CIM IBQ */
	qsize = CIM_IBQ_SIZE * 4 * sizeof(u32);
	GET_SCRATCH_BUFF(dbg_buff, sizeof(*cim_ibq_buff) + qsize,
			 &scratch_buff);
	cim_ibq_buff = (void *)((u8 *)scratch_buff.data + scratch_buff.offset);
	cim_ibq_buff->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	cim_ibq_buff->ver_hdr.revision = CUDBG_CIM_IBQ_REV;
	cim_ibq_buff->ver_hdr.size = sizeof(*cim_ibq_buff) -
				     sizeof(struct cudbg_ver_hdr);
	cim_ibq_buff->qid = qid;
	cim_ibq_buff->coreid = coreid;

	/* t4_read_cim_ibq will return no. of read words or error */
	no_of_read_words = t4_read_cim_ibq_core(padap, coreid, qid,
						cim_ibq_buff->data, qsize);
	/* no_of_read_words is less than or equal to 0 means error */
	if (no_of_read_words <= 0) {
		if (no_of_read_words == 0)
			rc = CUDBG_SYSTEM_ERROR;
		else
			rc = no_of_read_words;
		pdbg_init->print("%s(), t4_read_cim_ibq failed!, rc: %d\n",
				 __func__, rc);
		cudbg_err->sys_err = rc;
		goto err1;
	}
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_cim_ibq_tp0(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 0);
}

int cudbg_collect_cim_ibq_tp1(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 1);
}

int cudbg_collect_cim_ibq_tp2(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) <= CHELSIO_T6)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 2);
}

int cudbg_collect_cim_ibq_tp3(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) <= CHELSIO_T6)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 3);
}

int cudbg_collect_cim_ibq_ulp(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
		return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 4);

	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 2);
}

int cudbg_collect_cim_ibq_sge0(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
		return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 5);

	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 3);
}

int cudbg_collect_cim_ibq_sge1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
		return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 6);

	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 4);
}

int cudbg_collect_cim_ibq_ncsi(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
		return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 7);

	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 5);
}

int cudbg_collect_cim_ibq_ipc1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 9);
}

int cudbg_collect_cim_ibq_ipc2(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 10);
}

int cudbg_collect_cim_ibq_ipc3(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 11);
}

int cudbg_collect_cim_ibq_ipc4(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 12);
}

int cudbg_collect_cim_ibq_ipc5(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 13);
}

int cudbg_collect_cim_ibq_ipc6(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 14);
}

int cudbg_collect_cim_ibq_ipc7(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return read_cim_ibq(pdbg_init, dbg_buff, cudbg_err, 15);
}

int cudbg_collect_cim_ma_la(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc = 0;

	/* collect CIM MA LA */
	scratch_buff.size =  2 * CIM_MALA_SIZE * 5 * sizeof(u32);
	GET_SCRATCH_BUFF(dbg_buff, scratch_buff.size, &scratch_buff);
	t4_cim_read_ma_la(padap,
			  (u32 *) ((char *)scratch_buff.data +
				   scratch_buff.offset),
			  (u32 *) ((char *)scratch_buff.data +
				   scratch_buff.offset + 5 * CIM_MALA_SIZE));
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_cim_la(struct cudbg_init *pdbg_init,
			 struct cudbg_buffer *dbg_buff,
			 struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_cim_la_rev1 *cim_la_buff;
	struct cudbg_buffer scratch_buff;
	u8 ncol, coreid = 0;
	int size, rc = 0;
	u32 cfg = 0;
	u16 nrow;

	/* collect CIM LA */
	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T6)
		ncol = 10;
	else
		ncol = 8;

	if (pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].param_type ==
	    CUDBG_UP_COREID_PARAM)
		coreid = pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].u.coreid;

	nrow = padap->params.cim_la_size / ncol;
	size = sizeof(*cim_la_buff) + padap->params.cim_la_size * sizeof(u32);
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	cim_la_buff = (void *)scratch_buff.data;
	cim_la_buff->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	cim_la_buff->ver_hdr.revision = CUDBG_CIM_LA_REV;
	cim_la_buff->ver_hdr.size = sizeof(*cim_la_buff) -
				    sizeof(struct cudbg_ver_hdr);

	rc = t4_cim_read_core(padap, 1, coreid, A_UP_UP_DBG_LA_CFG, 1, &cfg);
	if (rc) {
		pdbg_init->print("%s(), t4_cim_read failed!, rc: %d\n",
				 __func__, rc);
		cudbg_err->sys_err = rc;
		goto err1;
	}

	rc = t4_cim_read_la_core(padap, coreid, cim_la_buff->data, NULL);
	if (rc < 0) {
		pdbg_init->print("%s(), t4_cim_read_la failed!, rc: %d\n",
				 __func__, rc);
		cudbg_err->sys_err = rc;
		goto err1;
	}

	cim_la_buff->coreid = coreid;
	cim_la_buff->config = cfg;
	cim_la_buff->ncol = ncol;
	cim_la_buff->nrow = nrow;

	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

static void cudbg_cim_qcfg_copy(struct struct_cim_qcfg_rev1_data *data,
				u8 num_cim_ibq, u8 num_cim_obq,
				u16 *base, u16 *size, u16 *thres,
				u32 *stat, u32 *obq_wr)
{
	u8 i = 0;

	while (i < num_cim_ibq) {
		data->qtype = CUDBG_ENTITY_CIM_QCFG_QTYPE_IBQ;
		data->qid = i;
		data->base = *base;
		data->size = *size;
		data->thres = *thres;
		memcpy(data->stat, stat, sizeof(data->stat));

		stat += ARRAY_SIZE(data->stat);
		thres++;
		size++;
		base++;
		data++;
		i++;
	}

	while (i < num_cim_ibq + num_cim_obq) {
		data->qtype = CUDBG_ENTITY_CIM_QCFG_QTYPE_OBQ;
		data->qid = i - num_cim_ibq;
		data->base = *base;
		data->size = *size;
		memcpy(data->stat, stat, sizeof(data->stat));
		memcpy(data->obq_wr, obq_wr, sizeof(data->obq_wr));

		obq_wr += ARRAY_SIZE(data->obq_wr);
		stat += ARRAY_SIZE(data->stat);
		size++;
		base++;
		data++;
		i++;
	}
}

static int cudbg_collect_cim_qcfg_t5(struct cudbg_init *pdbg_init,
				     struct struct_cim_qcfg_rev1_data *data,
				     u8 num_cim_ibq, u8 num_cim_obq)
{
	u32 stat[4 * (CIM_NUM_IBQ + CIM_NUM_OBQ_T5)];
	struct adapter *padap = pdbg_init->adap;
	u16 base[CIM_NUM_IBQ + CIM_NUM_OBQ_T5];
	u16 size[CIM_NUM_IBQ + CIM_NUM_OBQ_T5];
	u32 obq_wr[2 * CIM_NUM_OBQ_T5];
	u16 thres[CIM_NUM_IBQ];
	int ret;

	ret = t4_cim_read(padap, A_UP_IBQ_0_SHADOW_RDADDR,
			  4 * (num_cim_ibq + num_cim_obq), stat);
	if (ret < 0) {
		pdbg_init->print("%s(), IBQ/OBQ stats failed!, ret: %d\n",
				 __func__, ret);
		return ret;
	}

	ret = t4_cim_read(padap, A_UP_OBQ_0_SHADOW_REALADDR, 2 * num_cim_obq,
			  obq_wr);
	if (ret < 0) {
		pdbg_init->print("%s(), OBQ WR failed!, ret: %d\n",
				 __func__, ret);
		return ret;
	}

	t4_read_cimq_cfg(padap, base, size, thres);

	cudbg_cim_qcfg_copy(data, num_cim_ibq, num_cim_obq, base, size, thres,
			    stat, obq_wr);
	return 0;
}

static int cudbg_collect_cim_qcfg_t7(struct cudbg_init *pdbg_init, u8 coreid,
				     struct struct_cim_qcfg_rev1_data *data,
				     u8 num_cim_ibq, u8 num_cim_obq)
{
	u32 stat[4 * (CIM_NUM_IBQ_T7 + CIM_NUM_OBQ_T7)];
	u16 base[CIM_NUM_IBQ_T7 + CIM_NUM_OBQ_T7];
	u16 size[CIM_NUM_IBQ_T7 + CIM_NUM_OBQ_T7];
	struct adapter *padap = pdbg_init->adap;
	u32 obq_wr[2 * CIM_NUM_OBQ_T7];
	u16 thres[CIM_NUM_IBQ_T7];
	u32 addr;
	int ret;
	u8 i;

	ret = t4_cim_read_core(padap, 1, coreid, A_T7_UP_IBQ_0_SHADOW_RDADDR,
			       4 * num_cim_ibq, stat);
	if (ret < 0) {
		pdbg_init->print("%s(), IBQ stats failed!, rc: %d\n",
				 __func__, ret);
		return ret;
	}

	ret = t4_cim_read_core(padap, 1, coreid, A_T7_UP_OBQ_0_SHADOW_RDADDR,
			       4 * num_cim_obq, &stat[4 * num_cim_ibq]);
	if (ret < 0) {
		pdbg_init->print("%s(), OBQ stats failed!, rc: %d\n",
				 __func__, ret);
		return ret;
	}

	addr = A_T7_UP_OBQ_0_SHADOW_REALADDR;
	for (i = 0; i < num_cim_obq * 2; i++, addr += 8) {
		ret = t4_cim_read_core(padap, 1, coreid, addr, 1, &obq_wr[i]);
		if (ret < 0) {
			pdbg_init->print("%s(), OBQ WR failed!, rc: %d\n",
					 __func__, ret);
			return ret;
		}
	}

	t4_read_cimq_cfg_core(padap, coreid, base, size, thres);

	cudbg_cim_qcfg_copy(data, num_cim_ibq, num_cim_obq, base, size, thres,
			    stat, obq_wr);
	return 0;
}

int cudbg_collect_cim_qcfg(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct struct_cim_qcfg_rev1 *cim_qcfg_buff;
	u8 num_cim_ibq, num_cim_obq, coreid = 0;
	struct adapter *padap = pdbg_init->adap;
	struct struct_cim_qcfg_rev1_data *data;
	struct cudbg_buffer scratch_buff;
	int rc = 0;
	u32 size;

	if (pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].param_type ==
	    CUDBG_UP_COREID_PARAM)
		coreid = pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].u.coreid;

	num_cim_ibq = t4_cim_num_ibq(padap);
	num_cim_obq = t4_cim_num_obq(padap);
	size = sizeof(*cim_qcfg_buff) +
	       ((num_cim_ibq + num_cim_obq) * sizeof(*data));

	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	cim_qcfg_buff = (void *)((u8 *)scratch_buff.data + scratch_buff.offset);
	cim_qcfg_buff->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	cim_qcfg_buff->ver_hdr.revision = CUDBG_CIM_QCFG_REV;
	cim_qcfg_buff->ver_hdr.size = sizeof(*cim_qcfg_buff) -
				      sizeof(struct cudbg_ver_hdr);

	cim_qcfg_buff->num_cim_ibq = num_cim_ibq;
	cim_qcfg_buff->num_cim_obq = num_cim_obq;
	cim_qcfg_buff->coreid = coreid;
	data = cim_qcfg_buff->data;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
		rc = cudbg_collect_cim_qcfg_t7(pdbg_init, coreid, data,
					       num_cim_ibq, num_cim_obq);
	else
		rc = cudbg_collect_cim_qcfg_t5(pdbg_init, data, num_cim_ibq,
					       num_cim_obq);

	if (rc)
		cudbg_err->sys_err = rc;

	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

/**
 * Fetch the TX/RX payload regions start and end.
 *
 * @padap (IN): adapter handle.
 * @mem_type (IN): EDC0, EDC1, MC/MC0/MC1.
 * @mem_tot_len (IN): total length of @mem_type memory region to read.
 * @payload_type (IN): TX or RX Payload.
 * @reg_info (OUT): store the payload region info.
 *
 * Fetch the TX/RX payload region information from meminfo.
 * However, reading from the @mem_type region starts at 0 and not
 * from whatever base info is stored in meminfo.  Hence, if the
 * payload region exists, then calculate the payload region
 * start and end wrt 0 and @mem_tot_len, respectively, and set
 * @reg_info->exist to true. Otherwise, set @reg_info->exist to false.
 */
static int get_payload_range(struct adapter *padap, u8 mem_type,
			     unsigned long mem_tot_len, u8 payload_type,
			     struct struct_region_info *reg_info)
{
	struct struct_mem_desc mem_region;
	struct struct_mem_desc payload;
	struct struct_meminfo meminfo;
	u32 i, idx, found = 0;
	u8 mc_type;
	int rc;

	/* Get meminfo of all regions */
	rc = fill_meminfo(padap, &meminfo);
	if (rc)
		return rc;

	/* Extract the specified TX or RX Payload region range */
	memset(&payload, 0, sizeof(struct struct_mem_desc));
	for (i = 0; i < meminfo.mem_c; i++) {
		if (meminfo.mem[i].idx >= ARRAY_SIZE(region))
			continue;                        /* skip holes */

		idx = meminfo.mem[i].idx;
		/* Get TX or RX Payload region start and end */
		if (idx == payload_type) {
			if (!(meminfo.mem[i].limit))
				meminfo.mem[i].limit =
					i < meminfo.mem_c - 1 ?
					meminfo.mem[i + 1].base - 1 : ~0;

			memcpy(&payload, &meminfo.mem[i], sizeof(payload));
			found = 1;
			break;
		}
	}

	/* If TX or RX Payload region is not found return error. */
	if (!found)
		return -EINVAL;

	if (mem_type < MEM_MC) {
		memcpy(&mem_region, &meminfo.avail[mem_type],
		       sizeof(mem_region));
	} else {
		/* Check if both MC0 and MC1 exist by checking if a
		 * base address for the specified @mem_type exists.
		 * If a base address exists, then there is MC1 and
		 * hence use the base address stored at index 3.
		 * Otherwise, use the base address stored at index 2.
		 */
		mc_type = meminfo.avail[mem_type].base ?
			  mem_type : mem_type - 1;
		memcpy(&mem_region, &meminfo.avail[mc_type],
		       sizeof(mem_region));
	}

	/* Check if payload region exists in current memory */
	if (payload.base < mem_region.base && payload.limit < mem_region.base) {
		reg_info->exist = false;
		return 0;
	}

	/* Get Payload region start and end with respect to 0 and
	 * mem_tot_len, respectively.  This is because reading from the
	 * memory region starts at 0 and not at base info stored in meminfo.
	 */
	if (payload.base < mem_region.limit) {
		reg_info->exist = true;
		if (payload.base >= mem_region.base)
			reg_info->start = payload.base - mem_region.base;
		else
			reg_info->start = 0;

		if (payload.limit < mem_region.limit)
			reg_info->end = payload.limit - mem_region.base;
		else
			reg_info->end = mem_tot_len;
	}

	return 0;
}

static int cudbg_memory_read_addr(struct cudbg_init *pdbg_init, int win,
				  u32 addr, u32 len, void *hbuf)
{
	u32 win_pf, mem_reg, mem_aperture, mem_base;
	struct adapter *adap = pdbg_init->adap;
	u32 pos, offset, resid, read_len;
	u32 *buf;

	/* Argument sanity checks ...
	 */
	if (addr & 0x3 || (uintptr_t)hbuf & 0x3)
		return -EINVAL;
	buf = (u32 *)hbuf;

	/* It's convenient to be able to handle lengths which aren't a
	 * multiple of 32-bits because we often end up transferring files to
	 * the firmware.  So we'll handle that by normalizing the length here
	 * and then handling any residual transfer at the end.
	 */
	resid = len & 0x3;
	len -= resid;

	/* Each PCI-E Memory Window is programmed with a window size -- or
	 * "aperture" -- which controls the granularity of its mapping onto
	 * adapter memory.  We need to grab that aperture in order to know
	 * how to use the specified window.  The window is also programmed
	 * with the base address of the Memory Window in BAR0's address
	 * space.  For T4 this is an absolute PCI-E Bus Address.  For T5
	 * the address is relative to BAR0.
	 */
	mem_reg = t4_read_reg(adap, t4_pcie_mem_access_base_win_reg(adap, win));

	/* a dead adapter will return 0xffffffff for PIO reads */
	if (mem_reg == 0xffffffff)
		return -ENXIO;

	mem_aperture = 1 << (G_WINDOW(mem_reg) + X_WINDOW_SHIFT);
	mem_base = G_PCIEOFST(mem_reg) << X_PCIEOFST_SHIFT;
	if (is_t4(adap->params.chip))
		mem_base -= adap->t4_bar0;
	win_pf = is_t4(adap->params.chip) ? 0 : V_PFNUM(adap->pf);

	/* Calculate our initial PCI-E Memory Window Position and Offset into
	 * that Window.
	 */
	pos = addr & ~(mem_aperture - 1);
	offset = addr - pos;

	/* Set up initial PCI-E Memory Window to cover the start of our
	 * transfer.  (Read it back to ensure that changes propagate before we
	 * attempt to use the new value.)
	 */
	t4_pcie_mem_access_offset_write(adap, pos, win, win_pf);

	/* Transfer data to/from the adapter */
	while (len > 0) {
		if (!pdbg_init->intrinsic_cb) {
			*buf++ = le32_to_cpu((__force __le32)
					     t4_read_reg(adap,
							 mem_base + offset));
			offset += sizeof(__be32);
			len -= sizeof(__be32);
		} else {
			read_len = pdbg_init->intrinsic_cb(pdbg_init, mem_base,
							   offset, len,
							   mem_aperture,
							   (u8 *)buf);
			buf += read_len / sizeof(u32);
			offset += read_len;
			len -= read_len;
		}

		/* If we've reached the end of our current window aperture,
		 * move the PCI-E Memory Window on to the next.  Note that
		 * doing this here after "len" may be 0 allows us to set up
		 * the PCI-E Memory Window for a possible final residual
		 * transfer below ...
		 */
		if (offset == mem_aperture) {
			pos += mem_aperture;
			offset = 0;
			t4_pcie_mem_access_offset_write(adap, pos, win, win_pf);
		}
	}

	/* If the original transfer had a length which wasn't a multiple of
	 * 32-bits, now's where we need to finish off the transfer of the
	 * residual amount.  The PCI-E Memory Window has already been moved
	 * above (if necessary) to cover this final transfer.
	 */
	if (resid) {
		union {
			u32 word;
			char byte[4];
		} last;
		unsigned char *bp;
		int i;

		last.word = le32_to_cpu((__force __le32)
					t4_read_reg(adap, mem_base + offset));
		for (bp = (unsigned char *)buf, i = resid; i < 4; i++)
			bp[i] = last.byte[i];
	}

	return 0;
}

int cudbg_memory_read_mtype(struct cudbg_init *pdbg_init, int win, int mtype,
			    u32 maddr, u32 len, void *hbuf)
{
	struct adapter *adap = pdbg_init->adap;
	u32 edc_size, mc_size;
	u32 mtype_offset;

	/* Offset into the region of memory which is being accessed
	 * MEM_EDC0 = 0
	 * MEM_EDC1 = 1
	 * MEM_MC   = 2 -- MEM_MC for chips with only 1 memory controller
	 * MEM_MC1  = 3 -- for chips with 2 memory controllers (e.g. T5)
	 * MEM_HMA  = 4
	 */
	edc_size  = G_EDRAM0_SIZE(t4_read_reg(adap, A_MA_EDRAM0_BAR));
	if (mtype == MEM_HMA) {
		mtype_offset = 2 * (edc_size * 1024 * 1024);
	} else if (mtype != MEM_MC1) {
		mtype_offset = (mtype * (edc_size * 1024 * 1024));
	} else {
		mc_size = G_EXT_MEM0_SIZE(t4_read_reg(adap,
						      A_MA_EXT_MEMORY0_BAR));
		mtype_offset = (MEM_MC0 * edc_size + mc_size) * 1024 * 1024;
	}

	return cudbg_memory_read_addr(pdbg_init, win, mtype_offset + maddr,
				      len, hbuf);
}

static int read_fw_mem(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff, u8 mem_type,
			unsigned long tot_len, struct cudbg_error *cudbg_err)
{
	unsigned long compress_bytes, compress_bytes_left, compress_bytes_read;
	struct struct_region_info payload[2]; /* TX and RX Payload Region */
	unsigned long bytes, bytes_left, bytes_read = 0;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff = { 0 };
	u32 yield_itr = CUDBG_YIELD_ITERATION;
	struct cudbg_buffer temp_buff = { 0 };
	u16 get_payload_flag;
	u32 yield_count = 0;
	u16 yield_flag;
	int rc = 0;
	u8 i;

	get_payload_flag =
		pdbg_init->dbg_params[CUDBG_GET_PAYLOAD_PARAM].param_type;

	yield_flag =
		pdbg_init->dbg_params[CUDBG_YIELD_ITER_PARAM].param_type;

	/* If explicitly asked to get TX/RX Payload data,
	 * then don't zero out the payload data. Otherwise,
	 * zero out the payload data.
	 */
	if (!get_payload_flag) {
		u8 region_index[2] = {0};
		u8 j = 0;

		/* Find the index of TX and RX Payload regions in meminfo */
		for (i = 0; i < ARRAY_SIZE(region); i++) {
			if (!strcmp(region[i], "Tx payload:") ||
			    !strcmp(region[i], "Rx payload:")) {
				region_index[j] = i;
				j++;
				if (j == 2)
					break;
			}
		}

		/* Get TX/RX Payload region range if they exist */
		memset(payload, 0, ARRAY_SIZE(payload) * sizeof(payload[0]));
		for (i = 0; i < ARRAY_SIZE(payload); i++) {
			rc = get_payload_range(padap, mem_type, tot_len,
					       region_index[i],
					       &payload[i]);
			if (rc)
				goto err;

			if (payload[i].exist) {
				/* Align start and end to avoid wrap around */
				payload[i].start =
					cudbg_round_up(payload[i].start,
						       CUDBG_CHUNK_SIZE);
				payload[i].end =
				       	cudbg_round_down(payload[i].end,
							 CUDBG_CHUNK_SIZE);
			}
		}
	}

	bytes_left = tot_len;
	scratch_buff.size = tot_len;
	rc = write_compression_hdr(pdbg_init, &scratch_buff, dbg_buff);
	if (rc)
		goto err;

	if (yield_flag)
		yield_itr = pdbg_init->dbg_params[CUDBG_YIELD_ITER_PARAM].u.yield_param.itr;

	while (bytes_left > 0) {
		/* As mc size is huge, this loop will hold cpu for a longer time.
		 * OS may think that the process is hanged and will generate
		 * deadlock trace.
		 * So yield the cpu regularly, after some iterations.
		 */
		yield_count++;
		if (yield_count % yield_itr == 0)
			if (pdbg_init->yield_cb)
				pdbg_init->yield_cb(pdbg_init);

		bytes = min_t(unsigned long, bytes_left,
			      (unsigned long)(CUDBG_MEM_TOT_READ_SIZE));
		rc = get_scratch_buff_aligned(dbg_buff, bytes, &scratch_buff,
					      CUDBG_MEM_ALIGN);
		if (rc) {
			rc = CUDBG_STATUS_NO_SCRATCH_MEM;
			goto err;
		}

		if (!get_payload_flag) {
			for (i = 0; i < ARRAY_SIZE(payload); i++) {
				if (payload[i].exist &&
				    bytes_read >= payload[i].start &&
				    (bytes_read + bytes) <= payload[i].end) {
					memset(scratch_buff.data, 0, bytes);
					/* TX and RX Payload regions
					 * can't overlap.
					 */
					goto skip_read;
				}
			}
		}

		if (!pdbg_init->mc_collect_cb)
			rc = t4_memory_rw(padap, MEMWIN_NIC, mem_type,
					  bytes_read, bytes,
					  (__be32 *)scratch_buff.data, 1);
		else
			rc = pdbg_init->mc_collect_cb(pdbg_init, mem_type,
						      bytes_read, bytes,
						      (u8 *)scratch_buff.data);
		if (rc) {
			pdbg_init->print("%s(), t4_memory_rw failed!, rc: %d\n",
					 __func__, rc);
			cudbg_err->sys_err = rc;
			goto err1;
		}

skip_read:
		/* Compress collected data */
		compress_bytes_left = bytes;
		compress_bytes_read = 0;
		while (compress_bytes_left > 0) {
			compress_bytes = min_t(unsigned long,
					       compress_bytes_left,
					       (unsigned long)CUDBG_CHUNK_SIZE);
			temp_buff.data =
				(char *)scratch_buff.data + compress_bytes_read;
			temp_buff.offset = 0;
			temp_buff.size = compress_bytes;
			rc = compress_buff(pdbg_init, &temp_buff, dbg_buff);
			if (rc)
				goto err1;
			compress_bytes_left -= compress_bytes;
			compress_bytes_read += compress_bytes;
		}
		bytes_left -= bytes;
		bytes_read += bytes;
		release_scratch_buff(&scratch_buff, dbg_buff);
	}

err1:
	if (rc)
		release_scratch_buff(&scratch_buff, dbg_buff);
err:
	return rc;
}

static void collect_mem_info(struct cudbg_init *pdbg_init,
			     struct card_mem *mem_info)
{
	struct adapter *padap = pdbg_init->adap;
	int t4 = 0;
	u32 value;

	if (is_t4(padap->params.chip))
		t4 = 1;

	if (t4) {
		value = t4_read_reg(padap, A_MA_EXT_MEMORY_BAR);
		value = G_EXT_MEM_SIZE(value);
		mem_info->size_mc0 = (u16)value;  /* size in MB */

		value = t4_read_reg(padap, A_MA_TARGET_MEM_ENABLE);
		if (value & F_EXT_MEM_ENABLE)
			mem_info->mem_flag |= (1 << MC0_FLAG); /* set mc0 flag
								  bit */
	} else {
		value = t4_read_reg(padap, A_MA_EXT_MEMORY0_BAR);
		value = G_EXT_MEM0_SIZE(value);
		mem_info->size_mc0 = (u16)value;

		value = t4_read_reg(padap, A_MA_EXT_MEMORY1_BAR);
		value = G_EXT_MEM1_SIZE(value);
		mem_info->size_mc1 = (u16)value;
		/*in t6 no mc1 so HMA shares mc1 address space */
		mem_info->size_hma = (u16)value;

		value = t4_read_reg(padap, A_MA_TARGET_MEM_ENABLE);
		if (value & F_EXT_MEM0_ENABLE)
			mem_info->mem_flag |= (1 << MC0_FLAG);
		if (value & F_HMA_MUX)
			mem_info->mem_flag |= (1 << HMA_FLAG);
		else if (value & F_EXT_MEM1_ENABLE)
			mem_info->mem_flag |= (1 << MC1_FLAG);
	}

	value = t4_read_reg(padap, A_MA_EDRAM0_BAR);
	value = G_EDRAM0_SIZE(value);
	mem_info->size_edc0 = (u16)value;

	value = t4_read_reg(padap, A_MA_EDRAM1_BAR);
	value = G_EDRAM1_SIZE(value);
	mem_info->size_edc1 = (u16)value;

	value = t4_read_reg(padap, A_MA_TARGET_MEM_ENABLE);
	if (value & F_EDRAM0_ENABLE)
		mem_info->mem_flag |= (1 << EDC0_FLAG);
	if (value & F_EDRAM1_ENABLE)
		mem_info->mem_flag |= (1 << EDC1_FLAG);
}

static void cudbg_t4_fwcache(struct cudbg_init *pdbg_init,
				struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	int rc;

	if (is_fw_attached(pdbg_init)) {
		cudbg_access_lock_aquire(pdbg_init);	
		/* Flush uP dcache before reading edcX/mcX  */
		rc = t4_fwcache(padap, FW_PARAM_DEV_FWCACHE_FLUSH);
		cudbg_access_lock_release(pdbg_init);
		if (rc) {
			pdbg_init->print("%s(), Warning: t4_fwcache failed!, rc: %d\n",
				 __func__, rc);
			cudbg_err->sys_warn = rc;
		}
	}
}

static int collect_mem_region(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err,
			      u8 mem_type)
{
	struct card_mem mem_info = {0};
	unsigned long flag, size;
	int rc;

	cudbg_t4_fwcache(pdbg_init, cudbg_err);
	collect_mem_info(pdbg_init, &mem_info);
	switch (mem_type) {
	case MEM_EDC0:
		flag = (1 << EDC0_FLAG);
		size = (((unsigned long)mem_info.size_edc0) * 1024 * 1024);
		break;
	case MEM_EDC1:
		flag = (1 << EDC1_FLAG);
		size = (((unsigned long)mem_info.size_edc1) * 1024 * 1024);
		break;
	case MEM_MC0:
		flag = (1 << MC0_FLAG);
		size = (((unsigned long)mem_info.size_mc0) * 1024 * 1024);
		break;
	case MEM_MC1:
		flag = (1 << MC1_FLAG);
		size = (((unsigned long)mem_info.size_mc1) * 1024 * 1024);
		break;
	default:
		rc = CUDBG_STATUS_ENTITY_NOT_FOUND;
		goto err;
	}

	if (mem_info.mem_flag & flag) {
		rc = read_fw_mem(pdbg_init, dbg_buff, mem_type,
				 size, cudbg_err);
		if (rc)
			goto err;
	} else {
		rc = CUDBG_STATUS_ENTITY_NOT_FOUND;
		pdbg_init->print("%s(), collect_mem_info failed!, %s\n",
				 __func__, err_msg[-rc]);
		goto err;
	}
err:
	return rc;
}

int cudbg_collect_edc0_meminfo(struct cudbg_init *pdbg_init,
			 struct cudbg_buffer *dbg_buff,
			 struct cudbg_error *cudbg_err)
{
	return collect_mem_region(pdbg_init, dbg_buff, cudbg_err, MEM_EDC0);
}

int cudbg_collect_edc1_meminfo(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	return collect_mem_region(pdbg_init, dbg_buff, cudbg_err, MEM_EDC1);
}

int cudbg_collect_mc0_meminfo(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	return collect_mem_region(pdbg_init, dbg_buff, cudbg_err, MEM_MC0);
}

int cudbg_collect_mc1_meminfo(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	return collect_mem_region(pdbg_init, dbg_buff, cudbg_err, MEM_MC1);
}

int cudbg_collect_hma_meminfo(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	struct card_mem mem_info = {0};
	unsigned long hma_size;
	int rc;

	cudbg_t4_fwcache(pdbg_init, cudbg_err);
	collect_mem_info(pdbg_init, &mem_info);
	if (mem_info.mem_flag & (1 << HMA_FLAG)) {
		hma_size = (((unsigned long)mem_info.size_hma) * 1024 * 1024);
		rc = read_fw_mem(pdbg_init, dbg_buff, MEM_HMA,
				 hma_size, cudbg_err);
	} else {
		rc = CUDBG_STATUS_ENTITY_NOT_FOUND;
		pdbg_init->print("%s(), collect_mem_info failed!, %s\n",
				 __func__, err_msg[-rc]);
	}

	return rc;
}

int cudbg_collect_reg_dump(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct cudbg_buffer tmp_scratch_buff, scratch_buff;
	unsigned long bytes, bytes_left, bytes_read = 0;
	struct adapter *padap = pdbg_init->adap;
	u32 buf_size = 0;
	int rc = 0;

	if (is_t4(padap->params.chip))
		buf_size = T4_REGMAP_SIZE ;/*+ sizeof(unsigned int);*/
	else
		buf_size = T5_REGMAP_SIZE;

	scratch_buff.size = buf_size;
	tmp_scratch_buff = scratch_buff;
	GET_SCRATCH_BUFF(dbg_buff, scratch_buff.size, &scratch_buff);
	t4_get_regs(padap, (void *)scratch_buff.data, scratch_buff.size);
	bytes_left = scratch_buff.size;
	rc = write_compression_hdr(pdbg_init, &scratch_buff, dbg_buff);
	if (rc)
		goto err1;

	while (bytes_left > 0) {
		tmp_scratch_buff.data =
			((char *)scratch_buff.data) + bytes_read;
		bytes = min_t(unsigned long, bytes_left, (unsigned long)CUDBG_CHUNK_SIZE);
		tmp_scratch_buff.size = bytes;
		compress_buff(pdbg_init, &tmp_scratch_buff, dbg_buff);
		bytes_left -= bytes;
		bytes_read += bytes;
	}
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_cctrl(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	u32 size;
	int rc;

	size = sizeof(u16) * NMTUS * NCCTRL_WIN;
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	t4_read_cong_tbl(padap, (void *)scratch_buff.data);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

static int check_busy_bit(struct adapter *padap)
{
	int status = 0, retry = 10, i = 0;
	u32 val, busy = 1;
	u32 hostbusy;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
		hostbusy = F_T7_HOSTBUSY;
	else
		hostbusy = F_HOSTBUSY;

	while (busy & (1 < retry)) {
		val = t4_read_reg(padap, A_CIM_HOST_ACC_CTRL);
		busy = (0 != (val & hostbusy));
		i++;
	}
	if (busy)
		status = -1;
	return status;
}

static int cim_ha_rreg(struct adapter *padap, u32 addr, u32 *val)
{
	int rc = 0;

	/* write register address into the A_CIM_HOST_ACC_CTRL */
	t4_write_reg(padap, A_CIM_HOST_ACC_CTRL, addr);
	/* Poll HOSTBUSY */
	rc = check_busy_bit(padap);
	if (rc)
		goto err;
	/* Read value from A_CIM_HOST_ACC_DATA */
	*val = t4_read_reg(padap, A_CIM_HOST_ACC_DATA);
err:
	return rc;
}

int cudbg_collect_up_cim_indirect(struct cudbg_init *pdbg_init,
				  struct cudbg_buffer *dbg_buff,
				  struct cudbg_error *cudbg_err)
{
	const struct cudbg_indir_type_entry *cim_arr, *up_arr;
	struct cudbg_indir_reg_entity *cim_entity, *up_entity;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_indir_reg_data *reg_data;
	struct cudbg_buffer scratch_buff;
	u8 coreid = 0, groupid = 0;
	u32 chip_ver, size, i;
	int rc;

	chip_ver = CHELSIO_CHIP_VERSION(padap->params.chip);
	cim_arr = cudbg_get_indir_reg_info(chip_ver, CUDBG_INDIR_TYPE_CIM_CTL);
	up_arr = cudbg_get_indir_reg_info(chip_ver, CUDBG_INDIR_TYPE_UP);

	if (!cim_arr || !up_arr)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	if (pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].param_type ==
	    CUDBG_UP_COREID_PARAM)
		coreid = pdbg_init->dbg_params[CUDBG_UP_COREID_PARAM].u.coreid;

	size = sizeof(*cim_entity) + sizeof(*up_entity) +
	       sizeof(*reg_data) * (cim_arr->nentries + up_arr->nentries);

	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);

	cim_entity = cudbg_collect_indir_reg_init((void *)scratch_buff.data,
						  CUDBG_UP_CIM_INDIR_REG_REV,
						  A_CIM_HOST_ACC_CTRL,
						  A_CIM_HOST_ACC_DATA,
						  cim_arr->nentries);

	up_entity = cudbg_collect_indir_reg_init_next(cim_entity,
						      CUDBG_UP_CIM_INDIR_REG_REV,
						      A_CIM_HOST_ACC_CTRL,
						      A_CIM_HOST_ACC_DATA,
						      up_arr->nentries);

	reg_data = cim_entity->data;
	for (i = 0; i < cim_entity->nentries; i++, reg_data++) {
		reg_data->offset = cim_arr->reg_arr[i].addr;
		t4_cim_read_core(padap, groupid, coreid, reg_data->offset, 1,
				 &reg_data->data);
	}

	if (chip_ver >= CHELSIO_T7)
		groupid = 1;

	reg_data = up_entity->data;
	for (i = 0; i < up_entity->nentries; i++, reg_data++) {
		reg_data->offset = up_arr->reg_arr[i].addr;
		t4_cim_read_core(padap, groupid, coreid, reg_data->offset, 1,
				 &reg_data->data);
	}

	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_mbox_log(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct cudbg_mbox_log *mboxlog = NULL;
	struct cudbg_buffer scratch_buff;
	struct mbox_cmd_log *log = NULL;
	struct mbox_cmd *entry;
	unsigned int entry_idx;
	u16 mbox_cmds;
	int i, k, rc;
	u64 flit;
	u32 size;

	if (pdbg_init->dbg_params[CUDBG_MBOX_LOG_PARAM].u.mboxlog_param.log) {
		log = pdbg_init->dbg_params[CUDBG_MBOX_LOG_PARAM].u.
			mboxlog_param.log;
		mbox_cmds = pdbg_init->dbg_params[CUDBG_MBOX_LOG_PARAM].u.
				mboxlog_param.mbox_cmds;
	} else {
		pdbg_init->print("Mbox log is not requested\n");
		return CUDBG_STATUS_ENTITY_NOT_REQUESTED;
	}

	size = sizeof(struct cudbg_mbox_log) * mbox_cmds;
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	mboxlog = (struct cudbg_mbox_log *)scratch_buff.data;
	for (k = 0; k < mbox_cmds; k++) {
		entry_idx = log->cursor + k;
		if (entry_idx >= log->size)
			entry_idx -= log->size;

		entry = mbox_cmd_log_entry(log, entry_idx);
		/* skip over unused entries */
		if (entry->timestamp == 0)
			continue;

		memcpy(&mboxlog->entry, entry, sizeof(struct mbox_cmd));
		for (i = 0; i < MBOX_LEN / 8; i++) {
			flit = entry->cmd[i];
			mboxlog->hi[i] = (u32)(flit >> 32);
			mboxlog->lo[i] = (u32)flit;
		}
		mboxlog++;
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_pbt_tables(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_pbt_tables *pbt = NULL;
	struct cudbg_buffer scratch_buff;
	int i, rc;
	u32 addr;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*pbt), &scratch_buff);
	pbt = (struct cudbg_pbt_tables *)scratch_buff.data;
	/* PBT dynamic entries */
	addr = CUDBG_CHAC_PBT_ADDR;
	for (i = 0; i < CUDBG_PBT_DYNAMIC_ENTRIES; i++) {
		rc = cim_ha_rreg(padap, addr + (i * 4), &pbt->pbt_dynamic[i]);
		if (rc) {
			pdbg_init->print("BUSY timeout reading"
					 "CIM_HOST_ACC_CTRL\n");
			goto err1;
		}
	}

	/* PBT static entries */
	/* static entries start when bit 6 is set */
	addr = CUDBG_CHAC_PBT_ADDR + (1 << 6);
	for (i = 0; i < CUDBG_PBT_STATIC_ENTRIES; i++) {
		rc = cim_ha_rreg(padap, addr + (i * 4), &pbt->pbt_static[i]);
		if (rc) {
			pdbg_init->print("BUSY timeout reading"
					 "CIM_HOST_ACC_CTRL\n");
			goto err1;
		}
	}

	/* LRF entries */
	addr = CUDBG_CHAC_PBT_LRF;
	for (i = 0; i < CUDBG_LRF_ENTRIES; i++) {
		rc = cim_ha_rreg(padap, addr + (i * 4), &pbt->lrf_table[i]);
		if (rc) {
			pdbg_init->print("BUSY timeout reading"
					 "CIM_HOST_ACC_CTRL\n");
			goto err1;
		}
	}

	/* PBT data entries */
	addr = CUDBG_CHAC_PBT_DATA;
	for (i = 0; i < CUDBG_PBT_DATA_ENTRIES; i++) {
		rc = cim_ha_rreg(padap, addr + (i * 4), &pbt->pbt_data[i]);
		if (rc) {
			pdbg_init->print("BUSY timeout reading"
					 "CIM_HOST_ACC_CTRL\n");
			goto err1;
		}
	}
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_pm_indirect(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	const struct cudbg_indir_type_entry *pm_rx_arr, *pm_tx_arr;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	u32 chip_ver, size;
	int rc;

	chip_ver = CHELSIO_CHIP_VERSION(padap->params.chip);
	pm_rx_arr = cudbg_get_indir_reg_info(chip_ver,
					     CUDBG_INDIR_TYPE_PM_RX_DBG_CTRL);
	pm_tx_arr = cudbg_get_indir_reg_info(chip_ver,
					     CUDBG_INDIR_TYPE_PM_TX_DBG_CTRL);
	if (!pm_rx_arr || !pm_tx_arr)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	size = sizeof(struct cudbg_indir_reg_entity) +
	       sizeof(struct cudbg_indir_reg_data) * pm_rx_arr->nentries;
	size += sizeof(struct cudbg_indir_reg_entity) +
		sizeof(struct cudbg_indir_reg_data) * pm_tx_arr->nentries;

	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);

	cudbg_collect_indir_reg(padap, (void *)scratch_buff.data, pm_rx_arr,
				CUDBG_PM_INDIR_REG_REV, A_PM_RX_DBG_CTRL,
				A_PM_RX_DBG_CTRL + 4);

	cudbg_collect_indir_reg_next(padap, (void *)scratch_buff.data,
				     pm_tx_arr, CUDBG_PM_INDIR_REG_REV,
				     A_PM_TX_DBG_CTRL, A_PM_TX_DBG_CTRL + 4);

	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

static int calculate_max_tids(struct cudbg_init *pdbg_init)
{
	struct adapter *padap = pdbg_init->adap;
	u32 max_tids, value, hash_base;

	/* Check whether hash is enabled and calculate the max tids */
	value = t4_read_reg(padap, A_LE_DB_CONFIG);
	if ((value >> S_HASHEN) & 1) {
		value = t4_read_reg(padap, A_LE_DB_HASH_CONFIG);
		if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5) {
			hash_base = t4_read_reg(padap,
						A_T6_LE_DB_HASH_TID_BASE);
			max_tids = (value & 0xFFFFF) + hash_base;
		} else {
			hash_base = t4_read_reg(padap, A_LE_DB_TID_HASHBASE);
			max_tids = (1 << G_HASHTIDSIZE(value)) +
				   (hash_base >> 2);
		}
	} else {
		if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5) {
			value = t4_read_reg(padap, A_LE_DB_CONFIG);
			max_tids = (value & F_ASLIPCOMPEN) ?
				   CUDBG_MAX_TID_COMP_EN :
				   CUDBG_MAX_TID_COMP_DIS;
		} else {
			max_tids = CUDBG_MAX_TCAM_TID;
		}
	}

	if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5)
		max_tids += CUDBG_T6_CLIP;

	return max_tids;
}

static u8 cudbg_letcam_get_regions(struct cudbg_init *pdbg_init,
				   struct cudbg_letcam *letcam,
				   struct cudbg_letcam_region *le_region);

int cudbg_collect_tid(struct cudbg_init *pdbg_init,
		      struct cudbg_buffer *dbg_buff,
		      struct cudbg_error *cudbg_err)
{
	struct cudbg_letcam_region *le_region = NULL, *tmp_region;
	struct cudbg_buffer scratch_buff, region_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_letcam letcam = {{ 0 }};
	struct tid_info_region_rev1 *tid1;
	struct tid_info_region *tid;
	u32 para[2], val[2], pf;
	int rc;
	u8 i;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*tid1), &scratch_buff);

#define FW_PARAM_DEV_A(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param))
#define FW_PARAM_PFVF_A(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param) | \
	 V_FW_PARAMS_PARAM_Y(0) | \
	 V_FW_PARAMS_PARAM_Z(0))
#define MAX_ATIDS_A 8192U

	tid1 = (struct tid_info_region_rev1 *)scratch_buff.data;
	tid = &(tid1->tid);
	tid1->ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	tid1->ver_hdr.revision = CUDBG_TID_INFO_REV;
	tid1->ver_hdr.size = sizeof(struct tid_info_region_rev1) -
			     sizeof(struct cudbg_ver_hdr);

	tid->le_db_conf = t4_read_reg(padap, A_LE_DB_CONFIG);

	letcam.max_tid = calculate_max_tids(pdbg_init);
	tid->ntids = letcam.max_tid;
	if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5)
		tid->ntids -= CUDBG_T6_CLIP;

	/* Fill ATIDS */
	tid->natids = min(tid->ntids / 2, MAX_ATIDS_A);
	letcam.region_hdr_size = sizeof(struct cudbg_letcam_region);
	letcam.tid_data_hdr_size = sizeof(struct cudbg_tid_data);

	region_buff.size = LE_ET_TCAM_MAX * letcam.region_hdr_size;
	GET_SCRATCH_BUFF(dbg_buff, CUDBG_CHUNK_SIZE, &region_buff);
	le_region = (struct cudbg_letcam_region *)(region_buff.data);
	letcam.nregions = cudbg_letcam_get_regions(pdbg_init, &letcam,
						   le_region);

	/* Update tid regions range */
	tmp_region = le_region;
	for (i = 0; i < LE_ET_TCAM_MAX; i++) {
		switch (tmp_region->type) {
		case LE_ET_TCAM_HPFILTER:
			tid->hpftid_base = tmp_region->start;
			tid->nhpftids = tmp_region->nentries;
			break;

		case LE_ET_TCAM_CON:
			tid->aftid_base = tmp_region->start;
			tid->aftid_end = tmp_region->nentries;
			break;

		case LE_ET_TCAM_SERVER:
			tid->stid_base = tmp_region->start;
			tid->nstids = tmp_region->nentries;
			break;

		case LE_ET_TCAM_FILTER:
			tid->ftid_base = tmp_region->start;
			tid->nftids = tmp_region->nentries;
			break;

		case LE_ET_TCAM_CLIP:
			tid1->clip_base = tmp_region->start;
			tid1->nclip = tmp_region->nentries;
			break;

		case LE_ET_TCAM_ROUTING:
			tid1->route_base = tmp_region->start;
			tid1->nroute = tmp_region->nentries;
			break;

		case LE_ET_HASH_CON:
			tid->hash_base = tmp_region->start;
			tid1->nhash = tmp_region->nentries;
			break;
		}
		tmp_region = (struct cudbg_letcam_region *)
			     (((u8 *)tmp_region) +
			      letcam.region_hdr_size);
	}

	/* Free up region_buff */
	release_scratch_buff(&region_buff, dbg_buff);

	/*UO context range*/
	para[0] = FW_PARAM_PFVF_A(ETHOFLD_START);
	para[1] = FW_PARAM_PFVF_A(ETHOFLD_END);

	for (pf = 0; pf <= M_PCIE_FW_MASTER; pf++) {
		rc = cudbg_query_params(pdbg_init, padap->mbox, pf, 0, 2, para,
					val);
		if (rc || !val[0] || !val[1])
			continue;

		if (!tid->nuotids)
			tid->uotid_base = val[0];
		else
			tid->uotid_base = min(tid->uotid_base, val[0]);

		tid->nuotids += val[1] - val[0] + 1;
	}

	tid->IP_users = t4_read_reg(padap, A_LE_DB_ACT_CNT_IPV4);
	tid->IPv6_users = t4_read_reg(padap, A_LE_DB_ACT_CNT_IPV6);

#undef FW_PARAM_PFVF_A
#undef FW_PARAM_DEV_A
#undef MAX_ATIDS_A

	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_tx_rate(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	struct tx_rate *tx_rate;
	int rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*tx_rate), &scratch_buff);
	tx_rate = (struct tx_rate *)scratch_buff.data;
	t4_get_chan_txrate(padap, tx_rate->nrate, tx_rate->orate);
	tx_rate->nchan = padap->params.arch.nchan;
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

static inline void cudbg_tcamxy2valmask(u64 x, u64 y, u8 *addr, u64 *mask)
{
	*mask = x | y;
	y = (__force u64)cpu_to_be64(y);
	memcpy(addr, (char *)&y + 2, ETH_ALEN);
}

static void cudbg_mps_rpl_backdoor(struct adapter *padap,
				   struct fw_ldst_mps_rplc *mps_rplc)
{
	if (is_t5(padap->params.chip)) {
		mps_rplc->rplc255_224 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP3));
		mps_rplc->rplc223_192 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP2));
		mps_rplc->rplc191_160 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP1));
		mps_rplc->rplc159_128 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP0));
	} else {
		mps_rplc->rplc255_224 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP7));
		mps_rplc->rplc223_192 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP6));
		mps_rplc->rplc191_160 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP5));
		mps_rplc->rplc159_128 = htonl(t4_read_reg(padap,
							  A_MPS_VF_RPLCT_MAP4));
	}
	mps_rplc->rplc127_96 = htonl(t4_read_reg(padap, A_MPS_VF_RPLCT_MAP3));
	mps_rplc->rplc95_64 = htonl(t4_read_reg(padap, A_MPS_VF_RPLCT_MAP2));
	mps_rplc->rplc63_32 = htonl(t4_read_reg(padap, A_MPS_VF_RPLCT_MAP1));
	mps_rplc->rplc31_0 = htonl(t4_read_reg(padap, A_MPS_VF_RPLCT_MAP0));
}

int cudbg_collect_mps_tcam(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_mps_tcam *tcam = NULL;
	u32 size = 0, i, n, total_size = 0;
	struct cudbg_buffer scratch_buff;
	u64 tcamy, tcamx, val;
	u32 ctl, data2;
	int rc;

	n = padap->params.arch.mps_tcam_size;
	size = sizeof(struct cudbg_mps_tcam) * n;
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	memset(scratch_buff.data, 0, size);
	tcam = (struct cudbg_mps_tcam *)scratch_buff.data;
	for (i = 0; i < n; i++) {
		if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7) {
			/* CtlReqID   - 1: use Host Driver Requester ID
			 * CtlCmdType - 0: Read, 1: Write
			 * CtlTcamSel - 0: TCAM0, 1: TCAM1
			 * CtlXYBitSel- 0: Y bit, 1: X bit
			 */

			/* Read tcamy */
			ctl = (V_CTLREQID(1) |
			       V_CTLCMDTYPE(0) | V_CTLXYBITSEL(0));
			if (i < 256)
				ctl |= V_CTLTCAMINDEX(i) | V_T7_CTLTCAMSEL(0);
			else
				ctl |= V_CTLTCAMINDEX(i - 256) |
				       V_T7_CTLTCAMSEL(1);

			t4_write_reg(padap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(padap, A_MPS_CLS_TCAM0_RDATA1_REQ_ID1);
			tcamy = G_DMACH(val) << 32;
			tcamy |= t4_read_reg(padap, A_MPS_CLS_TCAM0_RDATA0_REQ_ID1);
			data2 = t4_read_reg(padap, A_MPS_CLS_TCAM0_RDATA2_REQ_ID1);
			tcam->lookup_type = G_DATALKPTYPE(data2);

			/* 0 - Outer header, 1 - Inner header
			 * [71:48] bit locations are overloaded for
			 * outer vs. inner lookup types.
			 */
			if (tcam->lookup_type &&
			    (tcam->lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI */
				tcam->vniy = (((data2 & F_DATAVIDH2)  |
					     (G_DATAVIDH1(data2))) << 16) |
					     G_VIDL(val);
				tcam->dip_hit = data2 & F_DATADIPHIT;
			} else {
				tcam->vlan_vld = data2 & F_DATAVIDH2;
				tcam->ivlan = G_VIDL(val);
			}

			tcam->port_num = G_DATAPORTNUM(data2);

			/* Read tcamx. Change the control param */
			ctl |= V_CTLXYBITSEL(1);
			t4_write_reg(padap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(padap, A_MPS_CLS_TCAM0_RDATA1_REQ_ID1);
			tcamx = G_DMACH(val) << 32;
			tcamx |= t4_read_reg(padap, A_MPS_CLS_TCAM0_RDATA0_REQ_ID1);
			data2 = t4_read_reg(padap, A_MPS_CLS_TCAM0_RDATA2_REQ_ID1);
			if (tcam->lookup_type &&
			    (tcam->lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI mask */
				tcam->vnix = (((data2 & F_DATAVIDH2) |
					     (G_DATAVIDH1(data2))) << 16) |
					     G_VIDL(val);
			}
		} else if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5) {
			/* CtlReqID   - 1: use Host Driver Requester ID
			 * CtlCmdType - 0: Read, 1: Write
			 * CtlTcamSel - 0: TCAM0, 1: TCAM1
			 * CtlXYBitSel- 0: Y bit, 1: X bit
			 */

			/* Read tcamy */
			ctl = (V_CTLREQID(1) |
			       V_CTLCMDTYPE(0) | V_CTLXYBITSEL(0));
			if (i < 256)
				ctl |= V_CTLTCAMINDEX(i) | V_CTLTCAMSEL(0);
			else
				ctl |= V_CTLTCAMINDEX(i - 256) |
				       V_CTLTCAMSEL(1);

			t4_write_reg(padap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(padap, A_MPS_CLS_TCAM_RDATA1_REQ_ID1);
			tcamy = G_DMACH(val) << 32;
			tcamy |= t4_read_reg(padap, A_MPS_CLS_TCAM_RDATA0_REQ_ID1);
			data2 = t4_read_reg(padap, A_MPS_CLS_TCAM_RDATA2_REQ_ID1);
			tcam->lookup_type = G_DATALKPTYPE(data2);

			/* 0 - Outer header, 1 - Inner header
			 * [71:48] bit locations are overloaded for
			 * outer vs. inner lookup types.
			 */

			if (tcam->lookup_type &&
			    (tcam->lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI */
				tcam->vniy = (((data2 & F_DATAVIDH2)  |
					     (G_DATAVIDH1(data2))) << 16) |
					     G_VIDL(val);
				tcam->dip_hit = data2 & F_DATADIPHIT;
			} else {
				tcam->vlan_vld = data2 & F_DATAVIDH2;
				tcam->ivlan = G_VIDL(val);
			}

			tcam->port_num = G_DATAPORTNUM(data2);

			/* Read tcamx. Change the control param */
			ctl |= V_CTLXYBITSEL(1);
			t4_write_reg(padap, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
			val = t4_read_reg(padap, A_MPS_CLS_TCAM_RDATA1_REQ_ID1);
			tcamx = G_DMACH(val) << 32;
			tcamx |= t4_read_reg(padap, A_MPS_CLS_TCAM_RDATA0_REQ_ID1);
			data2 = t4_read_reg(padap, A_MPS_CLS_TCAM_RDATA2_REQ_ID1);
			if (tcam->lookup_type &&
			    (tcam->lookup_type != M_DATALKPTYPE)) {
				/* Inner header VNI mask */
				tcam->vnix = (((data2 & F_DATAVIDH2) |
					     (G_DATAVIDH1(data2))) << 16) |
					     G_VIDL(val);
			}
		} else {
			tcamy = t4_read_reg64(padap, MPS_CLS_TCAM_Y_L(i));
			tcamx = t4_read_reg64(padap, MPS_CLS_TCAM_X_L(i));
		}

		if (tcamx & tcamy)
			continue;

		tcam->cls_lo = t4_read_reg(padap, MPS_CLS_SRAM_L(i));
		tcam->cls_hi = t4_read_reg(padap, MPS_CLS_SRAM_H(i));

		if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T7)
			tcam->repli = (tcam->cls_lo & F_T7_REPLICATE);
		else if (CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5)
			tcam->repli = (tcam->cls_lo & F_T6_REPLICATE);
		else
			tcam->repli = (tcam->cls_lo & F_REPLICATE);

		if (tcam->repli) {
			struct fw_ldst_cmd ldst_cmd;
			struct fw_ldst_mps_rplc mps_rplc;

			memset(&ldst_cmd, 0, sizeof(ldst_cmd));
			ldst_cmd.op_to_addrspace =
				htonl(V_FW_CMD_OP(FW_LDST_CMD) |
				      F_FW_CMD_REQUEST |
				      F_FW_CMD_READ |
				      V_FW_LDST_CMD_ADDRSPACE(
					      FW_LDST_ADDRSPC_MPS));

			ldst_cmd.cycles_to_len16 = htonl(FW_LEN16(ldst_cmd));

			ldst_cmd.u.mps.rplc.fid_idx =
				htons(V_FW_LDST_CMD_FID(FW_LDST_MPS_RPLC) |
				      V_FW_LDST_CMD_IDX(i));

			if (is_fw_attached(pdbg_init)) {
				cudbg_access_lock_aquire(pdbg_init);
				rc = t4_wr_mbox(padap, padap->mbox, &ldst_cmd,
						sizeof(ldst_cmd), &ldst_cmd);
				cudbg_access_lock_release(pdbg_init);
			}

			if (rc || !is_fw_attached(pdbg_init))
				cudbg_mps_rpl_backdoor(padap, &mps_rplc);
			else
				mps_rplc = ldst_cmd.u.mps.rplc;

			tcam->rplc[0] = ntohl(mps_rplc.rplc31_0);
			tcam->rplc[1] = ntohl(mps_rplc.rplc63_32);
			tcam->rplc[2] = ntohl(mps_rplc.rplc95_64);
			tcam->rplc[3] = ntohl(mps_rplc.rplc127_96);
			if (padap->params.arch.mps_rplc_size >
					CUDBG_MAX_RPLC_SIZE) {
				tcam->rplc[4] = ntohl(mps_rplc.rplc159_128);
				tcam->rplc[5] = ntohl(mps_rplc.rplc191_160);
				tcam->rplc[6] = ntohl(mps_rplc.rplc223_192);
				tcam->rplc[7] = ntohl(mps_rplc.rplc255_224);
			}
		}
		cudbg_tcamxy2valmask(tcamx, tcamy, tcam->addr, &tcam->mask);

		tcam->idx = i;
		tcam->rplc_size = padap->params.arch.mps_rplc_size;

		total_size += sizeof(struct cudbg_mps_tcam);

		tcam++;
	}

	if (total_size == 0) {
		rc = CUDBG_SYSTEM_ERROR;
		goto err1;
	}

	scratch_buff.size = total_size;
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	scratch_buff.size = size;
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_pcie_config(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	u32 size, *value, j;
	int i, rc, n;

	size = sizeof(u32) * NUM_PCIE_CONFIG_REGS;
	n = sizeof(t5_pcie_config_array) / (2 * sizeof(u32));
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	value = (u32 *)scratch_buff.data;
	for (i = 0; i < n; i++) {
		for (j = t5_pcie_config_array[i][0];
		     j <= t5_pcie_config_array[i][1]; j += 4) {
			t4_hw_pci_read_cfg4(padap, j, value);
			value++;
		}
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

static int cudbg_read_tid(struct cudbg_init *pdbg_init, u32 tid,
			  struct cudbg_tid_data *tid_data)
{
	struct adapter *padap = pdbg_init->adap;
	int i, cmd_retry = 8;
	u32 val;

	/* Fill REQ_DATA regs with 0's */
	for (i = 0; i < CUDBG_NUM_REQ_REGS; i++)
		t4_write_reg(padap, A_LE_DB_DBGI_REQ_DATA + (i << 2), 0);

	/* Write DBIG command */
	val = (0x4 << S_DBGICMD) | tid;
	t4_write_reg(padap, A_LE_DB_DBGI_REQ_TCAM_CMD, val);
	tid_data->dbig_cmd = val;

	val = 0;
	val |= 1 << S_DBGICMDSTRT;
	val |= 1;  /* LE mode */
	t4_write_reg(padap, A_LE_DB_DBGI_CONFIG, val);
	tid_data->dbig_conf = val;

	/* Poll the DBGICMDBUSY bit */
	val = 1;
	while (val) {
		val = t4_read_reg(padap, A_LE_DB_DBGI_CONFIG);
		val = (val >> S_DBGICMDBUSY) & 1;
		cmd_retry--;
		if (!cmd_retry) {
			pdbg_init->print("%s(): Timeout waiting for "
					 "non-busy tid: 0x%x\n",
					 __func__, tid);
			return CUDBG_SYSTEM_ERROR;
		}
	}

	/* Check RESP status */
	val = 0;
	val = t4_read_reg(padap, A_LE_DB_DBGI_RSP_STATUS);
	tid_data->dbig_rsp_stat = val;
	if (!(val & 1)) {
		pdbg_init->print("%s(): DBGI command failed\n", __func__);
		return CUDBG_SYSTEM_ERROR;
	}

	/* Read RESP data */
	for (i = 0; i < CUDBG_NUM_REQ_REGS; i++)
		tid_data->data[i] = t4_read_reg(padap,
						A_LE_DB_DBGI_RSP_DATA +
						(i << 2));

	tid_data->tid = tid;
	return 0;
}

static int cudbg_letcam_cmp(const void *a, const void *b)
{
	const struct cudbg_letcam_region *rega =
		(const struct cudbg_letcam_region *)a;
	const struct cudbg_letcam_region *regb =
		(const struct cudbg_letcam_region *)b;

	if (rega->start < regb->start)
		return -1;
	if (rega->start > regb->start)
		return 1;

	if (rega->type < regb->type)
		return -1;
	if (rega->type > regb->type)
		return 1;

	return 0;
}

static u8 cudbg_letcam_get_regions(struct cudbg_init *pdbg_init,
				   struct cudbg_letcam *letcam,
				   struct cudbg_letcam_region *le_region)
{
	struct cudbg_letcam_region *cur_region, *next_region;
	struct adapter *padap = pdbg_init->adap;
	u32 value, *reg_arr;
	u8 i, n = 0;

	/* Get the LE regions */
	reg_arr = CHELSIO_CHIP_VERSION(padap->params.chip) > CHELSIO_T5 ?
		  letcam_region_reg_array : t5_letcam_region_reg_array;

	cur_region = le_region;
	for (i = 0; i < LE_ET_TCAM_MAX; i++) {
		if (!reg_arr[i])
			continue;

		/* Only consider HASH region if it's enabled */
		if (i == LE_ET_HASH_CON) {
			value = t4_read_reg(padap, A_LE_DB_CONFIG);
			if (!(value & F_HASHEN))
				continue;
		}

		/* Only consider regions that are enabled */
		value = t4_read_reg(padap, reg_arr[i]);

		/* Each TID occupies 4 entries on T5 TCAM. */
		if (CHELSIO_CHIP_VERSION(padap->params.chip) < CHELSIO_T6)
			value >>= 2;

		if (value >= letcam->max_tid)
			continue;

		cur_region->type = i;
		cur_region->start = value;
		cur_region++;
		n++;
	}

	/* T5 doesn't have any register to read active region start
	 * since it always start from 0. So, explicitly add active
	 * region entry for T5 here.
	 */
	if (CHELSIO_CHIP_VERSION(padap->params.chip) < CHELSIO_T6) {
		cur_region->type = LE_ET_TCAM_CON;
		cur_region->start = 0;
		cur_region++;
		n++;
	}

	sort_t(le_region, n, sizeof(struct cudbg_letcam_region),
	       cudbg_letcam_cmp, NULL);

	cur_region = le_region;
	next_region = le_region + 1;
	for (i = 0; i < n; i++, cur_region++, next_region++) {
		if (i == n - 1)
			cur_region->nentries = letcam->max_tid -
					       cur_region->start;
		else
			cur_region->nentries = next_region->start -
					       cur_region->start;
	}

	return n;
}

int cudbg_collect_le_tcam(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err)
{
	struct cudbg_letcam *out_letcam, letcam = {{ 0 }};
	struct cudbg_letcam_region *out_region, *le_region;
	struct cudbg_buffer scratch_buff, region_buff;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_tid_data *tid_data = NULL;
	u32 bytes = 0, bytes_left  = 0;
	u32 i, size;
	u8 type;
	int rc;

	letcam.ver_hdr.signature = CUDBG_ENTITY_SIGNATURE;
	letcam.ver_hdr.revision = CUDBG_LETCAM_REV;
	letcam.ver_hdr.size = sizeof(struct cudbg_letcam) -
			      sizeof(struct cudbg_ver_hdr);

	letcam.max_tid = calculate_max_tids(pdbg_init);
	letcam.region_hdr_size = sizeof(struct cudbg_letcam_region);
	letcam.tid_data_hdr_size = sizeof(struct cudbg_tid_data);

	/* Get separate region scratch buffer to store region info.
	 * The final scratch buffer allocated later will be freed up
	 * after every CUDBG_CHUNK_SIZE max is filled up and written.
	 * This causes the region info to be lost. Hence, the reason
	 * to allocate a separate buffer for storing region info.
	 *
	 * This region info is needed below for determining which
	 * region the TID belongs to and skip subsequent TIDs for
	 * IPv6 entries.
	 */
	region_buff.size = LE_ET_TCAM_MAX * letcam.region_hdr_size;
	GET_SCRATCH_BUFF(dbg_buff, CUDBG_CHUNK_SIZE, &region_buff);
	le_region = (struct cudbg_letcam_region *)(region_buff.data);
	letcam.nregions = cudbg_letcam_get_regions(pdbg_init, &letcam, le_region);

	size = sizeof(letcam);
	size += letcam.nregions * letcam.region_hdr_size;
	size += letcam.max_tid * letcam.tid_data_hdr_size;
	scratch_buff.size = size;

	rc = write_compression_hdr(pdbg_init, &scratch_buff, dbg_buff);
	if (rc)
		goto err;

	/* LETCAM entity is stored in following format:
	 *
	 * ====================================================================
	 * | letcam_hdr | letcam_region_0 |...| letcam_region_n | letcam_data |
	 * ====================================================================
	 *
	 * Get scratch buffer to store everything above. This buffer
	 * will be allocated after the region scratch buffer allocated
	 * earlier above.
	 */
	GET_SCRATCH_BUFF(dbg_buff, CUDBG_CHUNK_SIZE, &scratch_buff);
	bytes_left = CUDBG_CHUNK_SIZE;
	bytes = 0;

	out_letcam = (struct cudbg_letcam *)scratch_buff.data;
	memcpy(out_letcam, &letcam, sizeof(letcam));
	bytes_left -= sizeof(letcam);
	bytes += sizeof(letcam);

	out_region = (struct cudbg_letcam_region *)(out_letcam + 1);
	memcpy(out_region, le_region, letcam.nregions * letcam.region_hdr_size);
	bytes_left -= letcam.nregions * letcam.region_hdr_size;
	bytes += letcam.nregions * letcam.region_hdr_size;

	tid_data = (struct cudbg_tid_data *)(out_region + letcam.nregions);

	/* read all tid */
	for (i = 0; i < letcam.max_tid;) {
		if (bytes_left < sizeof(struct cudbg_tid_data)) {
			scratch_buff.size = bytes;
			rc = compress_buff(pdbg_init, &scratch_buff, dbg_buff);
			if (rc)
				goto err1;
			scratch_buff.size = CUDBG_CHUNK_SIZE;
			release_scratch_buff(&scratch_buff, dbg_buff);

			/* new alloc */
			GET_SCRATCH_BUFF(dbg_buff, CUDBG_CHUNK_SIZE,
					 &scratch_buff);
			tid_data = (struct cudbg_tid_data *)(scratch_buff.data);
			bytes_left = CUDBG_CHUNK_SIZE;
			bytes = 0;
		}

		rc = cudbg_read_tid(pdbg_init, i, tid_data);
		if (rc) {
			/* We have already written the letcam header,
			 * so there's no way to go back and undo it.
			 * Instead, mark current tid larger than
			 * max_tid. When parser encounters the larger
			 * tid value, it'll break immediately.
			 */
			tid_data->tid = letcam.max_tid;
			bytes_left -= sizeof(struct cudbg_tid_data);
			bytes += sizeof(struct cudbg_tid_data);
			cudbg_err->sys_warn = CUDBG_STATUS_PARTIAL_DATA;
			goto stop;
		}

		/* IPv6 take 2 or more tids based on region */
		if (cudbg_letcam_is_ipv6_entry(tid_data, &letcam, le_region)) {
			type = cudbg_letcam_get_type(tid_data->tid, &letcam,
						     le_region);
			if (CHELSIO_CHIP_VERSION(padap->params.chip) >
			    CHELSIO_T5) {
				/* T6 CLIP TCAM IPv6 takes 4 entries */
				if (type == LE_ET_TCAM_CLIP)
					i += 4;
				else
					i += 2;
			} else {
				/* T5 Filter region IPv6 takes 4 entries */
				if (type == LE_ET_TCAM_FILTER)
					i += 4;
				else
					i += 2;
			}
		} else {
			i++;
		}

		tid_data++;
		bytes_left -= sizeof(struct cudbg_tid_data);
		bytes += sizeof(struct cudbg_tid_data);
	}

stop:
	if (bytes) {
		scratch_buff.size = bytes;
		rc = compress_buff(pdbg_init, &scratch_buff, dbg_buff);
	}

err1:
	scratch_buff.size = CUDBG_CHUNK_SIZE;
	release_scratch_buff(&scratch_buff, dbg_buff);
	release_scratch_buff(&region_buff, dbg_buff);
err:
	return rc;
}

int cudbg_collect_ma_indirect(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	const struct cudbg_indir_type_entry *ma_arr, *ma_perf_arr;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	u32 chip_ver, size;
	int rc;

	chip_ver = CHELSIO_CHIP_VERSION(padap->params.chip);
	ma_arr = cudbg_get_indir_reg_info(chip_ver,
				       CUDBG_INDIR_TYPE_MA_LOCAL_DEBUG_CFG);
	ma_perf_arr = cudbg_get_indir_reg_info(chip_ver,
					       CUDBG_INDIR_TYPE_MA_LOCAL_DEBUG_PERF_CFG);
	if (!ma_arr)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	if (chip_ver >= CHELSIO_T7 && !ma_perf_arr)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	size = sizeof(struct cudbg_indir_reg_entity) +
	       sizeof(struct cudbg_indir_reg_data) * ma_arr->nentries;

	if (ma_perf_arr)
		size += sizeof(struct cudbg_indir_reg_entity) +
			sizeof(struct cudbg_indir_reg_data) *
			ma_perf_arr->nentries;

	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);

	cudbg_collect_indir_reg(padap, (void *)scratch_buff.data, ma_arr,
				CUDBG_MA_INDIR_REG_REV, A_MA_LOCAL_DEBUG_CFG,
				A_MA_LOCAL_DEBUG_CFG + 4);

	if (ma_perf_arr)
		cudbg_collect_indir_reg_next(padap, (void *)scratch_buff.data,
					     ma_perf_arr, CUDBG_MA_INDIR_REG_REV,
					     A_MA_LOCAL_DEBUG_PERF_CFG,
					     A_MA_LOCAL_DEBUG_PERF_CFG + 4);

	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_hma_indirect(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	const struct cudbg_indir_type_entry *hma_arr;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	u32 chip_ver, size;
	int rc;

	chip_ver = CHELSIO_CHIP_VERSION(padap->params.chip);
	hma_arr = cudbg_get_indir_reg_info(chip_ver,
					   CUDBG_INDIR_TYPE_HMAT6_LOCAL_DEBUG_CFG);
	if (!hma_arr)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	size = sizeof(struct cudbg_indir_reg_entity) +
	       sizeof(struct cudbg_indir_reg_data) * hma_arr->nentries;

	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);

	cudbg_collect_indir_reg(padap,(void *)scratch_buff.data, hma_arr,
				CUDBG_HMA_INDIR_REG_REV, A_HMA_LOCAL_DEBUG_CFG,
				A_HMA_LOCAL_DEBUG_CFG + 4);

	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_pcie_indirect(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	struct ireg_buf *ch_pcie;
	int i, rc, n;
	u32 size;

	n = sizeof(t5_pcie_pdbg_array) / (4 * sizeof(u32));
	size = sizeof(struct ireg_buf) * n * 2;
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	ch_pcie = (struct ireg_buf *)scratch_buff.data;
	/*PCIE_PDBG*/
	for (i = 0; i < n; i++) {
		struct ireg_field *pcie_pio = &ch_pcie->tp_pio;
		u32 *buff = ch_pcie->outbuf;

		pcie_pio->ireg_addr = t5_pcie_pdbg_array[i][0];
		pcie_pio->ireg_data = t5_pcie_pdbg_array[i][1];
		pcie_pio->ireg_local_offset = t5_pcie_pdbg_array[i][2];
		pcie_pio->ireg_offset_range = t5_pcie_pdbg_array[i][3];
		t4_read_indirect(padap,
				pcie_pio->ireg_addr,
				pcie_pio->ireg_data,
				buff,
				pcie_pio->ireg_offset_range,
				pcie_pio->ireg_local_offset);
		ch_pcie++;
	}

	/*PCIE_CDBG*/
	n = sizeof(t5_pcie_cdbg_array) / (4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		struct ireg_field *pcie_pio = &ch_pcie->tp_pio;
		u32 *buff = ch_pcie->outbuf;

		pcie_pio->ireg_addr = t5_pcie_cdbg_array[i][0];
		pcie_pio->ireg_data = t5_pcie_cdbg_array[i][1];
		pcie_pio->ireg_local_offset = t5_pcie_cdbg_array[i][2];
		pcie_pio->ireg_offset_range = t5_pcie_cdbg_array[i][3];
		t4_read_indirect(padap,
				pcie_pio->ireg_addr,
				pcie_pio->ireg_data,
				buff,
				pcie_pio->ireg_offset_range,
				pcie_pio->ireg_local_offset);
		ch_pcie++;
	}
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_tp_indirect(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err)
{
	struct cudbg_indir_reg_entity *tp_tm_entity, *tp_pio_entity, *tp_mib_entity;
	const struct cudbg_indir_type_entry *tp_tm_arr, *tp_pio_arr, *tp_mib_arr;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_indir_reg_data *reg_data;
	struct cudbg_buffer scratch_buff;
	u32 chip_ver, size, i;
	int rc;

	chip_ver = CHELSIO_CHIP_VERSION(padap->params.chip);
	tp_tm_arr = cudbg_get_indir_reg_info(chip_ver,
					     CUDBG_INDIR_TYPE_TP_TM_PIO_ADDR);
	tp_pio_arr = cudbg_get_indir_reg_info(chip_ver,
					      CUDBG_INDIR_TYPE_TP_PIO_ADDR);
	tp_mib_arr = cudbg_get_indir_reg_info(chip_ver,
					      CUDBG_INDIR_TYPE_TP_MIB_INDEX);

	if (!tp_tm_arr || !tp_pio_arr || !tp_mib_arr)
		return CUDBG_STATUS_ENTITY_NOT_FOUND;

	size = sizeof(*tp_tm_entity) + sizeof(*tp_pio_entity) +
	       sizeof(*tp_mib_entity) + sizeof(*reg_data) *
	       (tp_tm_arr->nentries + tp_pio_arr->nentries +
		tp_mib_arr->nentries);

	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);

	tp_tm_entity = cudbg_collect_indir_reg_init((void *)scratch_buff.data,
						    CUDBG_TP_INDIR_REG_REV,
						    A_TP_TM_PIO_ADDR,
						    A_TP_TM_PIO_DATA,
						    tp_tm_arr->nentries);

	tp_pio_entity = cudbg_collect_indir_reg_init_next(tp_tm_entity,
							  CUDBG_TP_INDIR_REG_REV,
							  A_TP_PIO_ADDR,
							  A_TP_PIO_DATA,
							  tp_pio_arr->nentries);

	tp_mib_entity = cudbg_collect_indir_reg_init_next(tp_pio_entity,
							  CUDBG_TP_INDIR_REG_REV,
							  A_TP_MIB_INDEX,
							  A_TP_MIB_DATA,
							  tp_mib_arr->nentries);

	reg_data = tp_tm_entity->data;
	for (i = 0; i < tp_tm_entity->nentries; i++, reg_data++) {
		reg_data->offset = tp_tm_arr->reg_arr[i].addr;
		cudbg_tp_tm_pio_read(pdbg_init, &reg_data->data, 1,
				     reg_data->offset, true);
	}

	reg_data = tp_pio_entity->data;
	for (i = 0; i < tp_pio_entity->nentries; i++, reg_data++) {
		reg_data->offset = tp_pio_arr->reg_arr[i].addr;
		cudbg_tp_pio_read(pdbg_init, &reg_data->data, 1,
				  reg_data->offset, true);
	}

	reg_data = tp_mib_entity->data;
	for (i = 0; i < tp_mib_entity->nentries; i++, reg_data++) {
		reg_data->offset = tp_mib_arr->reg_arr[i].addr;
		cudbg_tp_mib_read(pdbg_init, &reg_data->data, 1,
				  reg_data->offset, true);
	}

	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

static int cudbg_read_sge_qbase_indirect_reg(struct adapter *padap,
					     struct sge_qbase_reg_field *sge_qbase,
					     u32 pf_vf_no, int isPF)
{
	u32 *buff;

	if (isPF) {
		if (pf_vf_no >= 8)
			return CUDBG_STATUS_INVALID_INDEX;

		buff = sge_qbase->pf_data_value[pf_vf_no];
	} else {
		if (pf_vf_no >= 256)
			return CUDBG_STATUS_INVALID_INDEX;

		buff = sge_qbase->vf_data_value[pf_vf_no];
		pf_vf_no += 8;
		/* in SGE_QBASE_INDEX,
 		 * Qbase map index. Entries 0->7 are PF0->7, Entries 8->263 are VFID0->256.
 		 */
	}

	t4_write_reg(padap, sge_qbase->reg_addr, pf_vf_no);
	*buff++ = t4_read_reg(padap, sge_qbase->reg_data[0]);
	*buff++ = t4_read_reg(padap, sge_qbase->reg_data[1]);
	*buff++ = t4_read_reg(padap, sge_qbase->reg_data[2]);
	*buff++ = t4_read_reg(padap, sge_qbase->reg_data[3]);

	return 0;
}

int cudbg_collect_sge_indirect(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct sge_qbase_reg_field *sge_qbase;
	struct cudbg_buffer scratch_buff;
	struct ireg_buf *ch_sge_dbg;
	int i, rc, pf, vf;
	u8 secollect = 0;
	u32 size;

	if (pdbg_init->dbg_params[CUDBG_SECOLLECT_PARAM].param_type ==
	    CUDBG_SECOLLECT_PARAM)
		secollect = 1;

	size = 2 * sizeof(*ch_sge_dbg);
	if (secollect)
		size += sizeof(*sge_qbase);
	GET_SCRATCH_BUFF(dbg_buff, size, &scratch_buff);
	ch_sge_dbg = (struct ireg_buf *)scratch_buff.data;
	for (i = 0; i < 2; i++) {
		struct ireg_field *sge_pio = &ch_sge_dbg->tp_pio;
		u32 *buff = ch_sge_dbg->outbuf;

		sge_pio->ireg_addr = t5_sge_dbg_index_array[i][0];
		sge_pio->ireg_data = t5_sge_dbg_index_array[i][1];
		sge_pio->ireg_local_offset = t5_sge_dbg_index_array[i][2];
		sge_pio->ireg_offset_range = t5_sge_dbg_index_array[i][3];
		t4_read_indirect(padap,
				sge_pio->ireg_addr,
				sge_pio->ireg_data,
				buff,
				sge_pio->ireg_offset_range,
				sge_pio->ireg_local_offset);
		ch_sge_dbg++;
	}

	if (is_t5(padap->params.chip) || !secollect)
		goto out;

	scratch_buff.offset = 2 * sizeof(*ch_sge_dbg);

	sge_qbase = (struct sge_qbase_reg_field *)(scratch_buff.data + scratch_buff.offset);
	sge_qbase->reg_addr = t6_sge_qbase_index_array[0];
	/* 1 addr reg SGE_QBASE_INDEX and 4 data reg SGE_QBASE_MAP[0-3] */
	sge_qbase->reg_data[0] = t6_sge_qbase_index_array[1];
	sge_qbase->reg_data[1] = t6_sge_qbase_index_array[2];
	sge_qbase->reg_data[2] = t6_sge_qbase_index_array[3];
	sge_qbase->reg_data[3] = t6_sge_qbase_index_array[4];
	for (pf = 0; pf < 8; pf++) {
		rc = cudbg_read_sge_qbase_indirect_reg(padap, sge_qbase, pf, 1);
		if (rc)
			break;
	}
	
	for (vf = 0; vf < padap->params.arch.vfcount; vf++) {
		rc = cudbg_read_sge_qbase_indirect_reg(padap, sge_qbase, vf, 0);
		if (rc)
			break;
	}
	sge_qbase->vfcount = padap->params.arch.vfcount;

out:
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_full(struct cudbg_init *pdbg_init,
		       struct cudbg_buffer *dbg_buff,
		       struct cudbg_error *cudbg_err)
{
	u32 reg_addr, reg_data, reg_local_offset, reg_offset_range;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	int rc, nreg = 0;
	u32 *sp;

	rc = cudbg_recon_dump_status(pdbg_init, CUDBG_PCIE_INDIRECT);
	if (rc)
		return rc;

	/* Collect Registers:
	 * TP_DBG_SCHED_TX (0x7e40 + 0x6a),
	 * TP_DBG_SCHED_RX (0x7e40 + 0x6b),
	 * TP_DBG_CSIDE_INT (0x7e40 + 0x23f),
	 * TP_DBG_ESIDE_INT (0x7e40 + 0x148),
	 * PCIE_CDEBUG_INDEX[AppData0] (0x5a10 + 2),
	 * PCIE_CDEBUG_INDEX[AppData1] (0x5a10 + 3)  This is for T6
	 * SGE_DEBUG_DATA_HIGH_INDEX_10 (0x12a8)
	 **/

	if (is_t5(padap->params.chip))
		nreg = 6;
	else
		nreg = 7;

	scratch_buff.size = nreg * sizeof(u32);
	GET_SCRATCH_BUFF(dbg_buff, scratch_buff.size, &scratch_buff);
	sp = (u32 *)scratch_buff.data;

	/* TP_DBG_SCHED_TX */
	reg_local_offset = t5_tp_pio_array[3][2] + 0xa;
	reg_offset_range = 1;
	cudbg_tp_pio_read(pdbg_init, sp, reg_offset_range, reg_local_offset,
			  true);
	sp++;

	/* TP_DBG_SCHED_RX */
	reg_local_offset = t5_tp_pio_array[3][2] + 0xb;
	reg_offset_range = 1;
	cudbg_tp_pio_read(pdbg_init, sp, reg_offset_range, reg_local_offset,
			  true);
	sp++;

	/* TP_DBG_CSIDE_INT */
	reg_local_offset = t5_tp_pio_array[9][2] + 0xf;
	reg_offset_range = 1;
	cudbg_tp_pio_read(pdbg_init, sp, reg_offset_range, reg_local_offset,
			  true);
	sp++;

	/* TP_DBG_ESIDE_INT */
	reg_local_offset = t5_tp_pio_array[8][2] + 3;
	reg_offset_range = 1;
	cudbg_tp_pio_read(pdbg_init, sp, reg_offset_range, reg_local_offset,
			  true);
	sp++;

	/* PCIE_CDEBUG_INDEX[AppData0] */
	reg_addr = t5_pcie_cdbg_array[0][0];
	reg_data = t5_pcie_cdbg_array[0][1];
	reg_local_offset = t5_pcie_cdbg_array[0][2] + 2;
	reg_offset_range = 1;
	cudbg_pcie_cdbg_read(pdbg_init, sp, reg_offset_range, reg_local_offset);
	sp++;

	if (CHELSIO_CHIP_VERSION(padap->params.chip) >= CHELSIO_T6) {
		/* PCIE_CDEBUG_INDEX[AppData1] */
		reg_addr = t5_pcie_cdbg_array[0][0];
		reg_data = t5_pcie_cdbg_array[0][1];
		reg_local_offset = t5_pcie_cdbg_array[0][2] + 3;
		reg_offset_range = 1;
		cudbg_pcie_cdbg_read(pdbg_init, sp, reg_offset_range,
				     reg_local_offset);
		sp++;
	}

	/* SGE_DEBUG_DATA_HIGH_INDEX_10 */
	*sp = t4_read_reg(padap, A_SGE_DEBUG_DATA_HIGH_INDEX_10);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_vpd_data(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct struct_vpd_data *vpd_data;
	struct cudbg_buffer scratch_buff;
	char vpd_ver[VPD_VER_LEN + 2] = { 0 };
	u32 fw_vers = 0;
	int rc;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(*vpd_data), &scratch_buff);
	vpd_data = (struct struct_vpd_data *)scratch_buff.data;
	memset(vpd_data, 0, sizeof(*vpd_data));
	if (is_t5(padap->params.chip)) {
		read_vpd_reg(padap, SN_REG_ADDR, SN_MAX_LEN, vpd_data->sn);
		read_vpd_reg(padap, BN_REG_ADDR, BN_MAX_LEN, vpd_data->bn);
		read_vpd_reg(padap, NA_REG_ADDR, NA_MAX_LEN, vpd_data->na);
		read_vpd_reg(padap, MN_REG_ADDR, MN_MAX_LEN, vpd_data->mn);
	} else {
		read_vpd_reg(padap, SN_T6_ADDR, SN_MAX_LEN, vpd_data->sn);
		read_vpd_reg(padap, BN_T6_ADDR, BN_MAX_LEN, vpd_data->bn);
		read_vpd_reg(padap, NA_T6_ADDR, NA_MAX_LEN, vpd_data->na);
		read_vpd_reg(padap, MN_T6_ADDR, MN_MAX_LEN, vpd_data->mn);
	}
	
	if (is_fw_attached(pdbg_init)) {
		cudbg_access_lock_aquire(pdbg_init);
		rc = t4_get_scfg_version(padap, &vpd_data->scfg_vers);
		cudbg_access_lock_release(pdbg_init);
	} else {
		rc = 1;
	}

	if (rc) {
		/* Now trying with backdoor mechanism */
		rc = read_vpd_reg(padap, SCFG_VER_ADDR, SCFG_VER_LEN,
				  (u8 *)&vpd_data->scfg_vers);
		if (rc) {
			cudbg_debug(pdbg_init, "FAIL - reading serial config version. Continuing...\n");
			rc = 0;
		}
	}

	if (is_fw_attached(pdbg_init)) {
		cudbg_access_lock_aquire(pdbg_init);
		rc = t4_get_vpd_version(padap, &vpd_data->vpd_vers);
		cudbg_access_lock_release(pdbg_init);
	} else {
		rc = 1;
	}

	if (rc) {
		/* Now trying with backdoor mechanism */
		rc = read_vpd_reg(padap, VPD_VER_ADDR, VPD_VER_LEN,
				  (u8 *)vpd_ver);
		if (rc) {
			cudbg_debug(pdbg_init, "FAIL - reading VPD version. Continuing...\n");
			rc = 0;
		} else {
			/* read_vpd_reg return string of stored hex
			 * converting hex string to char string
			 * vpd version is 2 bytes only
			 */
			snprintf(vpd_ver, VPD_VER_LEN + 2, "%c%c\n", vpd_ver[0], vpd_ver[1]);
			vpd_data->vpd_vers = simple_strtoul(vpd_ver, NULL, 16);
		}
	}

	/* Get FW version if it's not already filled in */
	fw_vers = padap->params.fw_vers;
	if (!fw_vers) {
		rc = t4_get_flash_params(padap);
		if (rc) {
			cudbg_debug(pdbg_init, "FAIL - reading flash params for fw version. Continuing...\n");
			rc = 0;
		} else {
			rc = t4_get_fw_version(padap, &fw_vers);
			if (rc) {
				cudbg_debug(pdbg_init, "FAIL - reading fw version. Continuing...\n");
				fw_vers = 0;
				rc = 0;
			}
		}
	}

	vpd_data->fw_major = G_FW_HDR_FW_VER_MAJOR(fw_vers);
	vpd_data->fw_minor = G_FW_HDR_FW_VER_MINOR(fw_vers);
	vpd_data->fw_micro = G_FW_HDR_FW_VER_MICRO(fw_vers);
	vpd_data->fw_build = G_FW_HDR_FW_VER_BUILD(fw_vers);
	WRITE_AND_RELEASE_SCRATCH_BUFF(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_upload(struct cudbg_init *pdbg_init,
			 struct cudbg_buffer *dbg_buff,
			 struct cudbg_error *cudbg_err)
{
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer scratch_buff;
	u32 param, *value;
	int rc;

	if (!is_fw_attached(pdbg_init))
		return CUDBG_SYSTEM_ERROR;

	GET_SCRATCH_BUFF(dbg_buff, sizeof(u32), &scratch_buff);
	value = (u32 *)scratch_buff.data;
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_LOAD));
	rc = cudbg_query_params(pdbg_init, padap->mbox, padap->pf, 0, 1,
				&param, value);
	if (rc < 0)
		goto err1;
	WRITE_AND_COMPRESS_SCRATCH_BUFF(&scratch_buff, dbg_buff);
err1:
	release_scratch_buff(&scratch_buff, dbg_buff);
	return rc;
}

int cudbg_collect_flash(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err)
{
	u32 compress_bytes, compress_bytes_read, compress_bytes_left;
	struct adapter *padap = pdbg_init->adap;
	struct cudbg_buffer temp_buff = { 0 };
	u32 bytes, bytes_read, bytes_left;
	struct cudbg_buffer scratch_buff;
	u32 addr, i, n, size;
	u32 *ptr;
	int rc;

	if (!padap->params.sf_size) {
		rc = t4_get_flash_params(padap);
		if (rc || !padap->params.sf_size)
			return CUDBG_SYSTEM_ERROR;
	}

	size = padap->params.sf_size / 4;
	bytes_left = padap->params.sf_size;
	scratch_buff.size = bytes_left;
	rc = write_compression_hdr(pdbg_init, &scratch_buff, dbg_buff);
	if (rc)
		goto err;

	addr = 0;
	i = 0;
	while (bytes_left > 0) {
		bytes_read = 0;
		bytes = min_t(u32, bytes_left,
			      (u32)CUDBG_MEM_FLASH_READ_CHUNK_SIZE);
		rc = get_scratch_buff_aligned(dbg_buff, bytes, &scratch_buff,
					      CUDBG_MEM_ALIGN);
		if (rc) {
			rc = CUDBG_STATUS_NO_SCRATCH_MEM;
			goto err;
		}

		ptr = (u32 *)scratch_buff.data;
		while (i < size) {
			if ((size - i) < SF_PAGE_SIZE)
				n = size - i;
			else
				n = SF_PAGE_SIZE;

			rc = t4_read_flash(padap, addr, n, ptr, 1);
			if (rc < 0) {
				cudbg_err->sys_err = rc;
				goto err1;
			}

			addr += (n * 4);
			ptr += n;
			i += SF_PAGE_SIZE;

			bytes -= (n * 4);
			bytes_read += (n * 4);
			bytes_left -= (n * 4);
			if (!bytes)
				break;
		}

		/* Compress collected data */
		compress_bytes_left = bytes_read;
		compress_bytes_read = 0;
		while (compress_bytes_left > 0) {
			compress_bytes = min_t(u32, compress_bytes_left,
					       (u32)CUDBG_CHUNK_SIZE);
			temp_buff.data = (char *)scratch_buff.data +
					 compress_bytes_read;
			temp_buff.offset = 0;
			temp_buff.size = compress_bytes;
			rc = compress_buff(pdbg_init, &temp_buff, dbg_buff);
			if (rc) {
				cudbg_err->sys_err = rc;
				goto err1;
			}
			compress_bytes_left -= compress_bytes;
			compress_bytes_read += compress_bytes;
		}

		release_scratch_buff(&scratch_buff, dbg_buff);
	}
err1:
	if (rc)
		release_scratch_buff(&scratch_buff, dbg_buff);
err:
	return rc;
}
