/*
 * Chelsio Unified Debug Interface header file.
 * Version 1.1
 */
#ifndef _CUDBG_IF_H_
#define _CUDBG_IF_H_
/*
 * Use inlined functions for supported systems.
 */
#if defined(__GNUC__) || defined(__DMC__) || defined(__POCC__) || \
	defined(__WATCOMC__) || defined(__SUNPRO_C)

#elif defined(__BORLANDC__) || defined(_MSC_VER) || defined(__LCC__)
#define inline __inline
#else
#define inline
#endif

#ifdef __GNUC__
#define ATTRIBUTE_UNUSED __attribute__ ((unused))
#else
#define ATTRIBUTE_UNUSED
#endif

#if defined(CONFIG_CUDBG_DEBUG)
#define cudbg_debug(pdbg_init, format,  ...) do {\
	pdbg_init->print(format, ##__VA_ARGS__); \
} while (0)
#else
#define cudbg_debug(pdbg_init, format,  ...) do { } while (0)
#endif

#define OUT
#define IN
#define INOUT

/* Error codes */
#define CUDBG_STATUS_SUCCESS		     0
#define CUDBG_STATUS_NOSPACE		    -2
#define CUDBG_STATUS_FLASH_WRITE_FAIL	    -3
#define CUDBG_STATUS_FLASH_READ_FAIL	    -4
#define CUDBG_STATUS_UNDEFINED_OUT_BUF	    -5
#define CUDBG_STATUS_UNDEFINED_CBFN	    -6
#define CUDBG_STATUS_UNDEFINED_PRINTF_CBFN  -7
#define CUDBG_STATUS_ADAP_INVALID	    -8
#define CUDBG_STATUS_FLASH_EMPTY	    -9
#define CUDBG_STATUS_NO_ADAPTER		    -10
#define CUDBG_STATUS_NO_SIGNATURE	    -11
#define CUDBG_STATUS_MULTIPLE_REG	    -12
#define CUDBG_STATUS_UNREGISTERED	    -13
#define CUDBG_STATUS_UNDEFINED_ENTITY	    -14
#define CUDBG_STATUS_REG_FAIlED		    -15
#define CUDBG_STATUS_DEVLOG_FAILED	    -16
#define CUDBG_STATUS_SMALL_BUFF		    -17
#define CUDBG_STATUS_CHKSUM_MISSMATCH	    -18
#define CUDBG_STATUS_NO_SCRATCH_MEM	    -19
#define CUDBG_STATUS_OUTBUFF_OVERFLOW	    -20
#define CUDBG_STATUS_INVALID_BUFF	    -21  /* Invalid magic */
#define CUDBG_STATUS_FILE_OPEN_FAIL	    -22
#define CUDBG_STATUS_DEVLOG_INT_FAIL	    -23
#define CUDBG_STATUS_ENTITY_NOT_FOUND	    -24
#define CUDBG_STATUS_DECOMPRESS_FAIL	    -25
#define CUDBG_STATUS_BUFFER_SHORT	    -26
#define CUDBG_METADATA_VERSION_MISMATCH     -27
#define CUDBG_STATUS_NOT_IMPLEMENTED	    -28
#define CUDBG_SYSTEM_ERROR		    -29
#define CUDBG_STATUS_MMAP_FAILED	    -30
#define CUDBG_STATUS_FILE_WRITE_FAILED	    -31
#define CUDBG_STATUS_CCLK_NOT_DEFINED	    -32
#define CUDBG_STATUS_FLASH_FULL            -33
#define CUDBG_STATUS_SECTOR_EMPTY          -34
#define CUDBG_STATUS_ENTITY_NOT_REQUESTED  -35
#define CUDBG_STATUS_NOT_SUPPORTED         -36
#define CUDBG_STATUS_FILE_READ_FAILED      -37
#define CUDBG_STATUS_CORRUPTED             -38
#define CUDBG_STATUS_INVALID_INDEX         -39
#define CUDBG_STATUS_NO_DATA               -40
#define CUDBG_STATUS_PARTIAL_DATA          -41
#define CUDBG_STATUS_NO_MBOX_PERM          -42
#define CUDBG_STATUS_NO_BAR_ACCESS         -43
#define CUDBG_STATUS_IOCTL_FAILED          -44

#define CUDBG_MAJOR_VERSION		    1
#define CUDBG_MINOR_VERSION		    14
#define CUDBG_BUILD_VERSION		    0

#define CUDBG_MAX_PARAMS		    16

#define CUDBG_NTHREADS 8

#define CUDBG_MAX_BITMAP_LEN 16

static char ATTRIBUTE_UNUSED * err_msg[] = {
	"Success",
	"Unknown",
	"No space",
	"Flash write fail",
	"Flash read fail",
	"Undefined out buf",
	"Callback function undefined",
	"Print callback function undefined",
	"ADAP invalid. May be Invalid Interface",
	"Flash empty",
	"No adapter",
	"No signature",
	"Multiple registration",
	"Unregistered",
	"Undefined entity",
	"Reg failed",
	"Devlog failed",
	"Small buff",
	"Checksum mismatch",
	"No scratch memory",
	"Outbuff overflow",
	"Invalid buffer",
	"File open fail",
	"Devlog int fail",
	"Entity not found",
	"Decompress fail",
	"Buffer short",
	"Version mismatch",
	"Not implemented",
	"System error",
	"Mmap failed",
	"File write failed",
	"cclk not defined",
	"Flash full",
	"Sector empty",
	"Entity not requested",
	"Not supported",
	"File read fail",
	"Corrupted",
	"Invalid Index",
	"No data found",
	"Partial data",
	"No valid mbox found",
	"No BAR access",
	"IOCTL failed",
};

enum CUDBG_DBG_ENTITY_TYPE {
	CUDBG_ALL	   = 0,
	CUDBG_REG_DUMP	   = 1,
	CUDBG_DEV_LOG	   = 2,
	CUDBG_CIM_LA	   = 3,
	CUDBG_CIM_MA_LA    = 4,
	CUDBG_CIM_QCFG	   = 5,
	CUDBG_CIM_IBQ_TP0  = 6,
	CUDBG_CIM_IBQ_TP1  = 7,
	CUDBG_CIM_IBQ_ULP  = 8,
	CUDBG_CIM_IBQ_SGE0 = 9,
	CUDBG_CIM_IBQ_SGE1 = 10,
	CUDBG_CIM_IBQ_NCSI = 11,
	CUDBG_CIM_OBQ_ULP0 = 12,
	CUDBG_CIM_OBQ_ULP1 = 13,
	CUDBG_CIM_OBQ_ULP2 = 14,
	CUDBG_CIM_OBQ_ULP3 = 15,
	CUDBG_CIM_OBQ_SGE  = 16,
	CUDBG_CIM_OBQ_NCSI = 17,
	CUDBG_EDC0	   = 18,
	CUDBG_EDC1	   = 19,
	CUDBG_MC0	   = 20,
	CUDBG_MC1	   = 21,
	CUDBG_RSS	   = 22,
	CUDBG_RSS_PF_CONF  = 23,
	CUDBG_RSS_KEY	   = 24,
	CUDBG_RSS_VF_CONF  = 25,
	CUDBG_RSS_CONF	   = 26,
	CUDBG_PATH_MTU	   = 27,
	CUDBG_SW_STATE	   = 28,
	CUDBG_WTP	   = 29,
	CUDBG_PM_STATS	   = 30,
	CUDBG_HW_SCHED	   = 31,
	CUDBG_TCP_STATS    = 32,
	CUDBG_TP_ERR_STATS = 33,
	CUDBG_FCOE_STATS   = 34,
	CUDBG_RDMA_STATS   = 35,
	CUDBG_TP_INDIRECT  = 36,
	CUDBG_SGE_INDIRECT = 37,
	CUDBG_CPL_STATS    = 38,
	CUDBG_DDP_STATS    = 39,
	CUDBG_WC_STATS	   = 40,
	CUDBG_ULPRX_LA	   = 41,
	CUDBG_LB_STATS	   = 42,
	CUDBG_TP_LA	   = 43,
	CUDBG_MEMINFO	   = 44,
	CUDBG_CIM_PIF_LA   = 45,
	CUDBG_CLK	   = 46,
	CUDBG_CIM_OBQ_SGE_RXQ0 = 47,
	CUDBG_CIM_OBQ_SGE_RXQ1 = 48,
	CUDBG_MAC_STATS    = 49,
	CUDBG_PCIE_INDIRECT = 50,
	CUDBG_PM_INDIRECT  = 51,
	CUDBG_FULL	   = 52,
	CUDBG_TX_RATE	   = 53,
	CUDBG_TID_INFO	   = 54,
	CUDBG_PCIE_CONFIG  = 55,
	CUDBG_DUMP_CONTEXT = 56,
	CUDBG_MPS_TCAM	   = 57,
	CUDBG_VPD_DATA	   = 58,
	CUDBG_LE_TCAM	   = 59,
	CUDBG_CCTRL	   = 60,
	CUDBG_MA_INDIRECT  = 61,
	CUDBG_ULPTX_LA	   = 62,
	CUDBG_EXT_ENTITY   = 63,
	CUDBG_UP_CIM_INDIRECT = 64,
	CUDBG_PBT_TABLE    = 65,
	CUDBG_MBOX_LOG     = 66,
	CUDBG_HMA_INDIRECT = 67,
	CUDBG_HMA          = 68,
	CUDBG_UPLOAD       = 69,
	CUDBG_QDESC        = 70,
	CUDBG_MOD_EEPROM   = 71,
	CUDBG_FLASH        = 72,
	CUDBG_CIM_IBQ_TP2  = 73,
	CUDBG_CIM_IBQ_TP3  = 74,
	CUDBG_CIM_IBQ_IPC1 = 75,
	CUDBG_CIM_IBQ_IPC2 = 76,
	CUDBG_CIM_IBQ_IPC3 = 77,
	CUDBG_CIM_IBQ_IPC4 = 78,
	CUDBG_CIM_IBQ_IPC5 = 79,
	CUDBG_CIM_IBQ_IPC6 = 80,
	CUDBG_CIM_IBQ_IPC7 = 81,
	CUDBG_CIM_OBQ_IPC1 = 82,
	CUDBG_CIM_OBQ_IPC2 = 83,
	CUDBG_CIM_OBQ_IPC3 = 84,
	CUDBG_CIM_OBQ_IPC4 = 85,
	CUDBG_CIM_OBQ_IPC5 = 86,
	CUDBG_CIM_OBQ_IPC6 = 87,
	CUDBG_CIM_OBQ_IPC7 = 88,
	CUDBG_MAX_ENTITY,
};

#define ENTITY_FLAG_NULL 0
#define ENTITY_FLAG_REGISTER 1
#define ENTITY_FLAG_BINARY 2
#define ENTITY_FLAG_FW_NO_ATTACH    3
#define ENTITY_FLAG_NEED_MBOX 4

/* file_name matches Linux cxgb4 debugfs entry names. */
struct el {char *name; char *file_name; int bit; u32 flag; };
static struct el ATTRIBUTE_UNUSED entity_list[] = {
	{"all", "all", CUDBG_ALL, ENTITY_FLAG_NULL},
	{"regdump", "regdump", CUDBG_REG_DUMP, 1 << ENTITY_FLAG_REGISTER},
	/* {"reg", CUDBG_REG_DUMP},*/
	{"devlog", "devlog", CUDBG_DEV_LOG, 1 << ENTITY_FLAG_NEED_MBOX},
	{"cimla", "cim_la", CUDBG_CIM_LA, 1 << ENTITY_FLAG_NEED_MBOX},
	{"cimmala", "cim_ma_la", CUDBG_CIM_MA_LA, 1 << ENTITY_FLAG_NEED_MBOX},
	{"cimqcfg", "cim_qcfg", CUDBG_CIM_QCFG, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqtp0", "ibq_tp0", CUDBG_CIM_IBQ_TP0, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqtp1", "ibq_tp1", CUDBG_CIM_IBQ_TP1, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqulp", "ibq_ulp", CUDBG_CIM_IBQ_ULP, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqsge0", "ibq_sge0", CUDBG_CIM_IBQ_SGE0, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqsge1", "ibq_sge1", CUDBG_CIM_IBQ_SGE1, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqncsi", "ibq_ncsi", CUDBG_CIM_IBQ_NCSI, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqulp0", "obq_ulp0", CUDBG_CIM_OBQ_ULP0, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqulp1", "obq_ulp1", CUDBG_CIM_OBQ_ULP1, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqulp2", "obq_ulp2", CUDBG_CIM_OBQ_ULP2, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqulp3", "obq_ulp3", CUDBG_CIM_OBQ_ULP3, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqsge", "obq_sge", CUDBG_CIM_OBQ_SGE, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqncsi", "obq_ncsi", CUDBG_CIM_OBQ_NCSI, 1 << ENTITY_FLAG_NEED_MBOX},
	{"edc0", "edc0", CUDBG_EDC0, (1 << ENTITY_FLAG_BINARY)},
	{"edc1", "edc1", CUDBG_EDC1, (1 << ENTITY_FLAG_BINARY)},
	{"mc0", "mc0", CUDBG_MC0, (1 << ENTITY_FLAG_BINARY)},
	{"mc1", "mc1", CUDBG_MC1, (1 << ENTITY_FLAG_BINARY)},
	{"rss", "rss", CUDBG_RSS, 1 << ENTITY_FLAG_NEED_MBOX},
	{"rss_pf_config", "rss_pf_config", CUDBG_RSS_PF_CONF,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"rss_key", "rss_key", CUDBG_RSS_KEY, 1 << ENTITY_FLAG_NEED_MBOX},
	{"rss_vf_config", "rss_vf_config", CUDBG_RSS_VF_CONF,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"rss_config", "rss_config", CUDBG_RSS_CONF, ENTITY_FLAG_NULL},
	{"pathmtu", "path_mtus", CUDBG_PATH_MTU, 1 << ENTITY_FLAG_NEED_MBOX},
	{"swstate", "sw_state", CUDBG_SW_STATE, ENTITY_FLAG_NULL},
	{"wtp", "wtp", CUDBG_WTP, 1 << ENTITY_FLAG_NEED_MBOX},
	{"pmstats", "pm_stats", CUDBG_PM_STATS, 1 << ENTITY_FLAG_NEED_MBOX},
	{"hwsched", "hw_sched", CUDBG_HW_SCHED, 1 << ENTITY_FLAG_NEED_MBOX},
	{"tcpstats", "tcp_stats", CUDBG_TCP_STATS, 1 << ENTITY_FLAG_NEED_MBOX},
	{"tperrstats", "tp_err_stats", CUDBG_TP_ERR_STATS,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"fcoestats", "fcoe_stats", CUDBG_FCOE_STATS,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"rdmastats", "rdma_stats", CUDBG_RDMA_STATS,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"tpindirect", "tp_indirect", CUDBG_TP_INDIRECT,
	 (1 << ENTITY_FLAG_REGISTER) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"sgeindirect", "sge_indirect", CUDBG_SGE_INDIRECT,
	 (1 << ENTITY_FLAG_REGISTER) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"cplstats", "cpl_stats", CUDBG_CPL_STATS, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ddpstats", "ddp_stats", CUDBG_DDP_STATS, 1 << ENTITY_FLAG_NEED_MBOX},
	{"wcstats", "wc_stats", CUDBG_WC_STATS, ENTITY_FLAG_NULL},
	{"ulprxla", "ulprx_la", CUDBG_ULPRX_LA, 1 << ENTITY_FLAG_NEED_MBOX},
	{"lbstats", "lb_stats", CUDBG_LB_STATS, ENTITY_FLAG_NULL},
	{"tpla", "tp_la", CUDBG_TP_LA, 1 << ENTITY_FLAG_NEED_MBOX},
	{"meminfo", "meminfo", CUDBG_MEMINFO, ENTITY_FLAG_NULL},
	{"cimpifla", "cim_pif_la", CUDBG_CIM_PIF_LA,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"clk", "clk", CUDBG_CLK, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obq_sge_rx_q0", "obq_sge_rx_q0", CUDBG_CIM_OBQ_SGE_RXQ0,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"obq_sge_rx_q1", "obq_sge_rx_q1", CUDBG_CIM_OBQ_SGE_RXQ1,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"macstats", "mac_stats", CUDBG_MAC_STATS, ENTITY_FLAG_NULL},
	{"pcieindirect", "pcie_indirect", CUDBG_PCIE_INDIRECT,
	 (1 << ENTITY_FLAG_REGISTER) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"pmindirect", "pm_indirect", CUDBG_PM_INDIRECT,
	 (1 << ENTITY_FLAG_REGISTER) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"full", "full", CUDBG_FULL, 1 << ENTITY_FLAG_NEED_MBOX},
	{"txrate", "tx_rate", CUDBG_TX_RATE, ENTITY_FLAG_NULL},
	{"tidinfo", "tids", CUDBG_TID_INFO,
	 (1 << ENTITY_FLAG_FW_NO_ATTACH) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"pcieconfig", "pcie_config", CUDBG_PCIE_CONFIG,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"dumpcontext", "dump_context", CUDBG_DUMP_CONTEXT,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"mpstcam", "mps_tcam", CUDBG_MPS_TCAM, 1 << ENTITY_FLAG_NEED_MBOX},
	{"vpddata", "vpd_data", CUDBG_VPD_DATA, ENTITY_FLAG_NULL},
	{"letcam", "le_tcam", CUDBG_LE_TCAM, 1 << ENTITY_FLAG_NEED_MBOX},
	{"cctrl", "cctrl", CUDBG_CCTRL, 1 << ENTITY_FLAG_NEED_MBOX},
	{"maindirect", "ma_indirect", CUDBG_MA_INDIRECT,
	 (1 << ENTITY_FLAG_REGISTER) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"ulptxla", "ulptx_la", CUDBG_ULPTX_LA, ENTITY_FLAG_NULL},
	{"extentity", "ext_entity", CUDBG_EXT_ENTITY, ENTITY_FLAG_NULL},
	{"upcimindirect", "up_cim_indirect", CUDBG_UP_CIM_INDIRECT,
	 (1 << ENTITY_FLAG_REGISTER) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"pbttables", "pbt_tables", CUDBG_PBT_TABLE,
	 1 << ENTITY_FLAG_NEED_MBOX},
	{"mboxlog", "mboxlog", CUDBG_MBOX_LOG, ENTITY_FLAG_NULL},
	{"hmaindirect", "hma_indirect", CUDBG_HMA_INDIRECT,
	 (1 << ENTITY_FLAG_REGISTER) | (1 << ENTITY_FLAG_NEED_MBOX)},
	{"hma", "hma", CUDBG_HMA, (1 << ENTITY_FLAG_BINARY)},
	{"upload", "upload", CUDBG_UPLOAD, ENTITY_FLAG_NULL},
	{"qdesc", "qdesc", CUDBG_QDESC, ENTITY_FLAG_NULL},
	{"modeeprom", "modeeprom", CUDBG_MOD_EEPROM, 1 << ENTITY_FLAG_NEED_MBOX},
	{"flash", "flash", CUDBG_FLASH, 1 << ENTITY_FLAG_BINARY},
	{"ibqtp2", "ibq_tp2", CUDBG_CIM_IBQ_TP2, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqtp3", "ibq_tp3", CUDBG_CIM_IBQ_TP3, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqipc1", "ibq_ipc1", CUDBG_CIM_IBQ_IPC1, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqipc2", "ibq_ipc2", CUDBG_CIM_IBQ_IPC2, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqipc3", "ibq_ipc3", CUDBG_CIM_IBQ_IPC3, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqipc4", "ibq_ipc4", CUDBG_CIM_IBQ_IPC4, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqipc5", "ibq_ipc5", CUDBG_CIM_IBQ_IPC5, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqipc6", "ibq_ipc6", CUDBG_CIM_IBQ_IPC6, 1 << ENTITY_FLAG_NEED_MBOX},
	{"ibqipc7", "ibq_ipc7", CUDBG_CIM_IBQ_IPC7, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqipc1", "obq_ipc1", CUDBG_CIM_OBQ_IPC1, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqipc2", "obq_ipc2", CUDBG_CIM_OBQ_IPC2, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqipc3", "obq_ipc3", CUDBG_CIM_OBQ_IPC3, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqipc4", "obq_ipc4", CUDBG_CIM_OBQ_IPC4, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqipc5", "obq_ipc5", CUDBG_CIM_OBQ_IPC5, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqipc6", "obq_ipc6", CUDBG_CIM_OBQ_IPC6, 1 << ENTITY_FLAG_NEED_MBOX},
	{"obqipc7", "obq_ipc7", CUDBG_CIM_OBQ_IPC7, 1 << ENTITY_FLAG_NEED_MBOX},
};

typedef int (*cudbg_print_cb) (char *str, ...);

struct cudbg_recon_params;

struct cudbg_init_hdr {
	u8   major_ver;
	u8   minor_ver;
	u8   build_ver;
	u8   res;
	u16  init_struct_size;
};

struct cudbg_flash_hdr {
	u32 signature;
	u8 major_ver;
	u8 minor_ver;
	u8 build_ver;
	u8 res;
	u64 timestamp;
	u64 time_res;
	u32 hdr_len;
	u32 data_len;
	u32 hdr_flags;
	u32 sec_seq_no;
	u32 reserved[22];
};

struct cudbg_param {
	u16			 param_type;
	u16			 reserved;
	union {
		struct {
			u32 memtype;	/* which memory (EDC0, EDC1, MC) */
			u32 start;	/* start of log in firmware memory */
			u32 size;	/* size of log */
		} devlog_param;
		struct {
			struct mbox_cmd_log *log;
			u16 mbox_cmds;
		} mboxlog_param;
		struct {
			const char *caller_string;
			u8 os_type;
		} sw_state_param;
		struct {
			u32 itr;
		} yield_param;
		u64 time;
		u8 tcb_bit_param;
		void *adap;
		u8 coreid;
	} u;
};

/* params for tcb_bit_param */
#define CUDBG_TCB_BRIEF_PARAM      0x1
#define CUDBG_TCB_FROM_CARD_PARAM  0x2
#define CUDBG_TCB_AS_SCB_PARAM     0x4
#define CUDBG_TCB_AS_FCB_PARAM     0x8

enum {
	CUDBG_FILE_WRITE_FLUSH = 0,
	CUDBG_FILE_WRITE_HEADER = 1,
	CUDBG_FILE_WRITE_DATA = 2,
	CUDBG_FILE_WRITE_AT_OFFSET = 3,
};

#define CUDBG_YIELD_ITERATION 200

struct cudbg_init;
typedef int (*cudbg_mc_collect_t)(struct cudbg_init *pdbg_init, u8 mem_type,
				  u32 start, u32 size, u8 *buf);
typedef u32 (*cudbg_intrinsic_t)(struct cudbg_init *pdbg_init, u32 start,
				 u32 offset, u32 size, u32 max_size, u8 *buf);
typedef int (*cudbg_write_to_file_t)(u8 op, int off, u8 *data, u32 data_size);
typedef void (*cudbg_lock_t)(void *access_lock);
typedef void (*cudbg_unlock_t)(void *access_lock);
typedef void (*cudbg_yield_t)(struct cudbg_init *pdbg_init);

/*
 * * What is OFFLINE_VIEW_ONLY mode?
 *
 * cudbg frame work will be used only to interpret previously collected
 * data store in a file (i.e NOT hw flash)
 */

struct cudbg_init {
	struct cudbg_init_hdr	 header;
	cudbg_print_cb		 print;		 /* Platform dependent print
						    function */
	u32			 verbose:1;	 /* Turn on verbose print */
	u32			 use_flash:1;	 /* Use flash to collect or view
						    debug */
	u32			 full_mode:1;	 /* If set, cudbg will pull in
						    common code */
	u32			 no_compress:1;  /* Dont compress will storing
						    the collected debug */
	u32			 info:1;	 /* Show just the info, Dont
						    interpret */
	u32 recon_en:1;	 /* 1 if we're attempting reconstruction. */
	u32 use_ioctl:1; /* 1 if we're attempting IOCTL, instead of SYSFS */
	u32			 reserved:25;
	u8			 dbg_bitmap[CUDBG_MAX_BITMAP_LEN];
						/* Bit map to select the dbg
						    data type to be collect
						    or viewed */
	void			 *sw_state_buf;		/* */
	u32			 sw_state_buflen;	  /* */

	unsigned char		 *hash_table; /* hash table used in
					       * fastlz compression */
	/* Optional for OFFLINE_VIEW_ONLY mode. Set to NULL for
	 * OFFLINE_VIEW_ONLY mode */
	struct adapter		 *adap;		 /* Pointer to adapter structure
						    with filled fields */
	u16		   dbg_params_cnt;
	u16		   dbg_reserved;
	struct cudbg_param dbg_params[CUDBG_MAX_PARAMS];
	struct cudbg_recon_params *recon;
	/* Holds temporarily extracted data needed for reconstruction.
	 * Only valid if @recon_en is set to 1
	 */
	cudbg_intrinsic_t intrinsic_cb;
	cudbg_mc_collect_t mc_collect_cb;
	cudbg_write_to_file_t write_to_file_cb;
	void *cur_entity_hdr;
	void *access_lock;
	cudbg_lock_t lock_cb;
	cudbg_unlock_t unlock_cb;
	cudbg_yield_t yield_cb;
};

enum {
	CUDBG_DEVLOG_PARAM = 1,
	CUDBG_TIMESTAMP_PARAM = 2,
	CUDBG_FW_NO_ATTACH_PARAM = 3,
	CUDBG_MBOX_LOG_PARAM = 4,
	CUDBG_TCB_BIT_PARAM = 5,
	CUDBG_ADAP_PARAM = 6,
	CUDBG_GET_PAYLOAD_PARAM = 7,
	CUDBG_SW_STATE_PARAM = 8,
	CUDBG_FORCE_PARAM = 9,
	CUDBG_YIELD_ITER_PARAM = 10,
	CUDBG_SKIP_MBOX_PARAM = 11,
	CUDBG_SECOLLECT_PARAM = 12,
	CUDBG_UP_COREID_PARAM = 13,
};

enum {
	/* params for os_type */
	CUDBG_OS_TYPE_WINDOWS = 1,
	CUDBG_OS_TYPE_LINUX = 2,
	CUDBG_OS_TYPE_ESX = 3,
	CUDBG_OS_TYPE_UNKNOWN = 4,
};

#define CUDBG_IOCTL_VERSION 0x1

#ifndef __GNUC__
#pragma warning(disable : 4200)
#endif

struct cudbg_ioctl {
	u32 cmd;

	u32 version;
	u64 size;

	u8 dbg_bitmap[CUDBG_MAX_BITMAP_LEN];
	u16 dbg_params_cnt;
	struct cudbg_param dbg_params[CUDBG_MAX_PARAMS];

	u8 data[0]; /* Must be last */
};

/********************************* Helper functions *************************/
static inline void set_dbg_bitmap(u8 *bitmap, enum CUDBG_DBG_ENTITY_TYPE type)
{
	int index = type / 8;
	int bit = type % 8;

	bitmap[index] |= (1 << bit);
}

static inline void reset_dbg_bitmap(u8 *bitmap, enum CUDBG_DBG_ENTITY_TYPE type)
{
	int index = type / 8;
	int bit = type % 8;

	bitmap[index] &= ~(1 << bit);
}

static inline void init_cudbg_hdr(struct cudbg_init_hdr *hdr)
{
	hdr->major_ver = CUDBG_MAJOR_VERSION;
	hdr->minor_ver = CUDBG_MINOR_VERSION;
	hdr->build_ver = CUDBG_BUILD_VERSION;
	hdr->init_struct_size = sizeof(struct cudbg_init);
}

/**************************** End of Helper functions *************************/

/* API Prototypes */

/**
 *  cudbg_hello - To initialize cudbg framework. Needs to called
 *  first before calling anyother function
 *  ## Parameters ##
 *  @dbg_init : A pointer to cudbg_init structure.
 *  @handle : A pointer to void
 *  ##	Return ##
 *  If the function succeeds, returns 0 and a handle will be copied to @handle.
 *  -ve value represent error.
 */
int cudbg_hello(IN struct cudbg_init *dbg_init, OUT void **handle);

/*
 *  cudbg_hello2 - Extended cudbg_hello. Caller has provide required memory
 *                 buffer for library initialization.
 *  ## Parameters ##
 *  @dbg_init : Pointer to cudbg_init structure.
 *  @handle : Pointer to the handle that will be returned by cudbglib.
 *  @buf : Pointer to the buffer, for the use of cudbglib.
 *  @buf_size : Pointer to the variable containing the size of buffer.
 *              Cudbglib  sets the size of the required buffer if
 *              CUDBG_STATUS_SMALL_BUFF is returned.
 *  ##   Return ##
 *  If the function succeeds, returns 0.
 *  -ve value represent error.

 * Caller can first pass buf_size as 0, to find the size of buffer required by cudbglib. Then
 * call cudbg_hello2() with correct buf and buf_size, after buffer allocation.
 */
int cudbg_hello2(IN struct cudbg_init *dbg_init, OUT void **handle, IN u8 *buf,
		 INOUT u32 *buf_size);

/**
 *  cudbg_collect - To collect and store debug information.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_init.
 *  @outbuf : pointer to output buffer, to store the collected information
 *	      or to use it as a scratch buffer in case HW flash is used to
 *	      store the debug information.
 *  @outbuf_size : Size of output buffer.
 *  ##	Return ##
 *  If the function succeeds, the return value will be size of debug information
 *  collected and stored.
 *  -ve value represent error.
 */
int cudbg_collect(IN void *handle, OUT void *outbuf, INOUT u32 *outbuf_size);

/**
 *  cudbg_bye - To exit cudbg framework.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_hello.
 */
int cudbg_bye(IN void *handle);

int cudbg_memory_read_mtype(struct cudbg_init *pdbg_init, int win, int mtype,
			    u32 maddr, u32 len, void *hbuf);
#endif /* _CUDBG_IF_H_ */
