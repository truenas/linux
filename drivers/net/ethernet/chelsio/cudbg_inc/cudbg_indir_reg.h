#ifndef __CUDBG_INDIR_REG_H__
#define __CUDBG_INDIR_REG_H__

enum cudbg_indir_type {
	CUDBG_INDIR_TYPE_CIM_CTL,
	CUDBG_INDIR_TYPE_PM_RX_DBG_CTRL,
	CUDBG_INDIR_TYPE_PM_TX_DBG_CTRL,
	CUDBG_INDIR_TYPE_TP_MIB_INDEX,
	CUDBG_INDIR_TYPE_TP_PIO_ADDR,
	CUDBG_INDIR_TYPE_TP_TM_PIO_ADDR,
	CUDBG_INDIR_TYPE_UP,
	CUDBG_INDIR_TYPE_HMAT6_LOCAL_DEBUG_CFG,
	CUDBG_INDIR_TYPE_MA_LOCAL_DEBUG_CFG,
	CUDBG_INDIR_TYPE_MA_LOCAL_DEBUG_PERF_CFG,
	CUDBG_INDIR_TYPE_MAX, /* New members need to be added at end */
};

struct cudbg_indir_reg {
	u32 addr;
};

struct cudbg_indir_type_entry {
	struct cudbg_indir_reg *reg_arr;
	u32 nentries;
};

#include <cudbg_indir_reg_t5.h>
#include <cudbg_indir_reg_t6.h>
#include <cudbg_indir_reg_t7.h>

static inline struct cudbg_indir_type_entry *
cudbg_get_indir_reg_info(u32 chip_ver, enum cudbg_indir_type type)
{
	switch (chip_ver) {
	case CHELSIO_T5:
		return &t5_indir_type_arr[type];
	case CHELSIO_T6:
		return &t6_indir_type_arr[type];
	case CHELSIO_T7:
		return &t7_indir_type_arr[type];
	}

	return NULL;
}

#endif /* __CUDBG_INDIR_REG_H__ */
