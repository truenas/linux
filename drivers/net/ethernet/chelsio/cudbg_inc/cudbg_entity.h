#ifndef __CUDBG_ENTITY_H__
#define __CUDBG_ENTITY_H__

#ifdef __GNUC__
#define ATTRIBUTE_UNUSED __attribute__ ((unused))
#else
#define ATTRIBUTE_UNUSED
#endif

#define MC0_FLAG    1
#define MC1_FLAG    2
#define EDC0_FLAG   3
#define EDC1_FLAG   4
#define HMA_FLAG    5

#define CUDBG_MEM_ALIGN 32
#define CUDBG_MEM_CHUNK_SIZE 65536 /* Must be a multiple of @CUDBG_MEM_ALIGN */
#define CUDBG_MEM_TOT_READ_SIZE (CUDBG_MEM_CHUNK_SIZE * CUDBG_NTHREADS)
#define CUDBG_MEM_FLASH_READ_CHUNK_SIZE (CUDBG_MEM_CHUNK_SIZE * CUDBG_NTHREADS)

#define NUM_PCIE_CONFIG_REGS 0x61
#define CUDBG_MAX_FL_QIDS 1024
#define CUDBG_LOWMEM_MAX_CTXT_QIDS 256
#define ETH_ALEN 6
#define CUDBG_MAX_RPLC_SIZE 128
#define CUDBG_NUM_REQ_REGS 17
#define CUDBG_MAX_TCAM_TID 0x800
#define CUDBG_T6_CLIP 1536
#define CUDBG_MAX_TID_COMP_EN 6144
#define CUDBG_MAX_TID_COMP_DIS 3072
#define CUDBG_NUM_ULPTX 11
#define CUDBG_NUM_ULPTX_READ 512
#define CUDBG_NUM_ULPTX_ASIC 6
#define CUDBG_NUM_ULPTX_ASIC_READ 128

#define SN_REG_ADDR 0x183f
#define BN_REG_ADDR 0x1819
#define NA_REG_ADDR 0x185a
#define MN_REG_ADDR 0x1803

#define A_MPS_VF_RPLCT_MAP0 0x1111c
#define A_MPS_VF_RPLCT_MAP1 0x11120
#define A_MPS_VF_RPLCT_MAP2 0x11124
#define A_MPS_VF_RPLCT_MAP3 0x11128
#define A_MPS_VF_RPLCT_MAP4 0x11300
#define A_MPS_VF_RPLCT_MAP5 0x11304
#define A_MPS_VF_RPLCT_MAP6 0x11308
#define A_MPS_VF_RPLCT_MAP7 0x1130c

#define PORT_TYPE_ADDR 0x1869
#define PORT_TYPE_LEN 8

/* For T6 */
#define SN_T6_ADDR 0x83f
#define BN_T6_ADDR 0x819
#define NA_T6_ADDR 0x85a
#define MN_T6_ADDR 0x803

#define SN_MAX_LEN	 24
#define BN_MAX_LEN	 16
#define NA_MAX_LEN	 12
#define MN_MAX_LEN	 16
#define MAX_VPD_DATA_LEN 32

#define VPD_VER_ADDR     0x18c7
#define VPD_VER_LEN      2
#define SCFG_VER_ADDR    0x06
#define SCFG_VER_LEN     4

#define CUDBG_CIM_BUSY_BIT (1 << 17)

#define CUDBG_CHAC_PBT_ADDR 0x2800
#define CUDBG_CHAC_PBT_LRF  0x3000
#define CUDBG_CHAC_PBT_DATA 0x3800
#define CUDBG_PBT_DYNAMIC_ENTRIES 8
#define CUDBG_PBT_STATIC_ENTRIES 16
#define CUDBG_LRF_ENTRIES 8
#define CUDBG_PBT_DATA_ENTRIES 512

#define CUDBG_ENTITY_SIGNATURE 0xCCEDB001
#define CUDBG_TID_INFO_REV 1
#define CUDBG_MAC_STATS_REV 1
#define CUDBG_ULPTX_LA_REV 1
#define CUDBG_MEMINFO_REV 1
#define CUDBG_LETCAM_REV 1
#define CUDBG_MODEEPROM_REV 0

enum le_entry_types {
	LE_ET_UNKNOWN = 0,
	LE_ET_TCAM_HPFILTER = 1,
	LE_ET_TCAM_CON = 2,
	LE_ET_TCAM_SERVER = 3,
	LE_ET_TCAM_FILTER = 4,
	LE_ET_TCAM_CLIP = 5,
	LE_ET_TCAM_ROUTING = 6,
	LE_ET_HASH_CON = 7,
	/* Reserve for future regions */
	LE_ET_TCAM_MAX = 16,
};

struct port_data {
	u8     port_type;		/* firmware port type */
	u8     mod_type;		/* firmware module type */
	u8     tx_chan;
};

struct cudbg_pbt_tables {
	u32 pbt_dynamic[CUDBG_PBT_DYNAMIC_ENTRIES];
	u32 pbt_static[CUDBG_PBT_STATIC_ENTRIES];
	u32 lrf_table[CUDBG_LRF_ENTRIES];
	u32 pbt_data[CUDBG_PBT_DATA_ENTRIES];
};

struct card_mem {
	u16 size_mc0;
	u16 size_mc1;
	u16 size_edc0;
	u16 size_edc1;
	u16 size_hma;
	u16 mem_flag;
	u16 res;
};

struct rss_pf_conf {
	u32 rss_pf_map;
	u32 rss_pf_mask;
	u32 rss_pf_config;
};

#define CUDBG_SGE_CTXT_REV 1
#define CUDBG_SGE_CTXT_DATA_MAX 16

struct struct_sge_ctxt_rev1_data {
	u8 ctxt_type;
	u8 size;
	u32 ctxt_id;
	u32 data[CUDBG_SGE_CTXT_DATA_MAX];
};

struct struct_sge_ctxt_rev1 {
	struct cudbg_ver_hdr ver_hdr;
	u32 nentries;
	struct struct_sge_ctxt_rev1_data data[0]; /* Must be last */
};

struct cudbg_tcam {
	u32 filter_start;
	u32 server_start;
	u32 clip_start;
	u32 routing_start;
	u32 tid_hash_base;
	u32 max_tid;
};

struct cudbg_letcam_region {
	u8 type;
	u32 start;
	u32 nentries;

	u8 reserved[64];
};

struct cudbg_letcam {
	struct cudbg_ver_hdr ver_hdr;

	u8 nregions;
	u32 region_hdr_size;

	u32 max_tid;
	u32 tid_data_hdr_size;

	u8 reserved[64];
};

struct cudbg_mbox_log {
	struct mbox_cmd entry;
	u32 hi[MBOX_LEN / 8];
	u32 lo[MBOX_LEN / 8];
};

struct cudbg_tid_data {
	u32 tid;
	u32 dbig_cmd;
	u32 dbig_conf;
	u32 dbig_rsp_stat;
	u32 data[CUDBG_NUM_REQ_REGS];
};

struct cudbg_cntxt_field {
	char *name;
	u32 start_bit;
	u32 end_bit;
	u32 shift;
	u32 islog2;
};

struct cudbg_mps_tcam {
	u64 mask;
	u32 rplc[8];
	u32 idx;
	u32 cls_lo;
	u32 cls_hi;
	u32 rplc_size;
	u32 vniy;
	u32 vnix;
	u32 dip_hit;
	u32 vlan_vld;
	u32 repli;
	u16 ivlan;
	u8 addr[ETH_ALEN];
	u8 lookup_type;
	u8 port_num;
	u8 reserved[2];
};

struct rss_vf_conf {
	u32 rss_vf_vfl;
	u32 rss_vf_vfh;
};

struct rss_config {
	u32 tp_rssconf;		/* A_TP_RSS_CONFIG	*/
	u32 tp_rssconf_tnl;	/* A_TP_RSS_CONFIG_TNL	*/
	u32 tp_rssconf_ofd;	/* A_TP_RSS_CONFIG_OFD	*/
	u32 tp_rssconf_syn;	/* A_TP_RSS_CONFIG_SYN	*/
	u32 tp_rssconf_vrt;	/* A_TP_RSS_CONFIG_VRT	*/
	u32 tp_rssconf_cng;	/* A_TP_RSS_CONFIG_CNG	*/
	u32 chip;
};

struct struct_pm_stats {
	u32 tx_cnt[T6_PM_NSTATS];
	u32 rx_cnt[T6_PM_NSTATS];
	u64 tx_cyc[T6_PM_NSTATS];
	u64 rx_cyc[T6_PM_NSTATS];
};

struct struct_hw_sched {
	u32 kbps[NTX_SCHED];
	u32 ipg[NTX_SCHED];
	u32 pace_tab[NTX_SCHED];
	u32 mode;
	u32 map;
};

struct struct_tcp_stats {
	struct tp_tcp_stats v4, v6;
};

struct struct_tp_err_stats {
	struct tp_err_stats stats;
	u32 nchan;
};

struct struct_tp_fcoe_stats {
	struct tp_fcoe_stats stats[4];
	u32 nchan;
};

struct struct_mac_stats {
	u32 port_count;
	struct port_stats stats[4];
};

struct struct_mac_stats_rev1 {
	struct cudbg_ver_hdr ver_hdr;
	u32 port_count;
	u32 reserved;
	struct port_stats stats[4];
};

struct struct_tp_cpl_stats {
	struct tp_cpl_stats stats;
	u32 nchan;
};

struct struct_wc_stats {
	u32 wr_cl_success;
	u32 wr_cl_fail;
};

struct cudbg_ulptx_la {
	u32 rdptr[CUDBG_NUM_ULPTX];
	u32 wrptr[CUDBG_NUM_ULPTX];
	u32 rddata[CUDBG_NUM_ULPTX];
	u32 rd_data[CUDBG_NUM_ULPTX][CUDBG_NUM_ULPTX_READ];
	u32 rdptr_asic[CUDBG_NUM_ULPTX_ASIC_READ];
	u32 rddata_asic[CUDBG_NUM_ULPTX_ASIC_READ][CUDBG_NUM_ULPTX_ASIC];
};

struct struct_ulprx_la {
	u32 data[ULPRX_LA_SIZE * 8];
	u32 size;
};

#define CUDBG_CIM_IBQ_REV 1

struct struct_cim_ibq_rev1 {
	struct cudbg_ver_hdr ver_hdr;
	u8 qid;
	u8 coreid;
	u32 data[0]; /* Must be last */
};

#define CUDBG_CIM_OBQ_REV 1

struct struct_cim_obq_rev1 {
	struct cudbg_ver_hdr ver_hdr;
	u8 qid;
	u8 coreid;
	u32 data[0]; /* Must be last */
};

#define CUDBG_CIM_QCFG_REV 1

enum cudbg_entity_cim_qcfg_qtype {
	CUDBG_ENTITY_CIM_QCFG_QTYPE_IBQ = 0,
	CUDBG_ENTITY_CIM_QCFG_QTYPE_OBQ,
};

struct struct_cim_qcfg_rev1_data {
	u8 qtype;
	u8 qid;
	u16 base;
	u16 size;
	u16 thres;
	u32 obq_wr[2];
	u32 stat[4];
};

struct struct_cim_qcfg_rev1 {
	struct cudbg_ver_hdr ver_hdr;
	u8 num_cim_ibq;
	u8 num_cim_obq;
	u8 coreid;
	struct struct_cim_qcfg_rev1_data data[0]; /* Must be last */
};

#define CUDBG_CIM_LA_REV 1

struct struct_cim_la_rev1 {
	struct cudbg_ver_hdr ver_hdr;
	u8 coreid;
	u8 ncol;
	u16 nrow;
	u32 config;
	u32 data[0]; /* Must be last */
};

enum region_index {
	REGN_DBQ_CONTEXS_IDX,
	REGN_IMSG_CONTEXTS_IDX,
	REGN_FLM_CACHE_IDX,
	REGN_TCBS_IDX,
	REGN_PSTRUCT_IDX,
	REGN_TIMERS_IDX,
	REGN_RX_FL_IDX,
	REGN_TX_FL_IDX,
	REGN_PSTRUCT_FL_IDX,
	REGN_TX_PAYLOAD_IDX,
	REGN_RX_PAYLOAD_IDX,
	REGN_LE_HASH_IDX,
	REGN_ISCSI_IDX,
	REGN_TDDP_IDX,
	REGN_TPT_IDX,
	REGN_STAG_IDX,
	REGN_RQ_IDX,
	REGN_RQUDP_IDX,
	REGN_PBL_IDX,
	REGN_TXPBL_IDX,
	REGN_DBVFIFO_IDX,
	REGN_ULPRX_STATE_IDX,
	REGN_ULPTX_STATE_IDX,
#ifndef __NO_DRIVER_OCQ_SUPPORT__
	REGN_ON_CHIP_Q_IDX,
#endif
};

static const char * const region[] = {
	"DBQ contexts:", "IMSG contexts:", "FLM cache:", "TCBs:",
	"Pstructs:", "Timers:", "Rx FL:", "Tx FL:", "Pstruct FL:",
	"Tx payload:", "Rx payload:", "LE hash:", "iSCSI region:",
	"TDDP region:", "TPT region:", "STAG region:", "RQ region:",
	"RQUDP region:", "PBL region:", "TXPBL region:",
	"DBVFIFO region:", "ULPRX state:", "ULPTX state:",
#ifndef __NO_DRIVER_OCQ_SUPPORT__
	"On-chip queues:"
#endif
};

/* Info relative to memory region (i.e. wrt 0). */
struct struct_region_info {
	bool exist; /* Does region exists in current memory region? */
	u32 start;  /* Start wrt 0 */
	u32 end;    /* End wrt 0 */
};

struct struct_port_usage {
	u32 id;
	u32 used;
	u32 alloc;
};

struct struct_mem_desc {
	u32 base;
	u32 limit;
	u32 idx;
};

struct struct_meminfo {
	struct struct_mem_desc avail[4];
	struct struct_mem_desc mem[ARRAY_SIZE(region) + 3];
	u32 avail_c;
	u32 mem_c;
	u32 up_ram_lo;
	u32 up_ram_hi;
	u32 up_extmem2_lo;
	u32 up_extmem2_hi;
	u32 rx_pages_data[3];
	u32 tx_pages_data[4];
	u32 p_structs;
	struct struct_port_usage port_data[4];
	u32 port_used[4];
	u32 port_alloc[4];
	u32 loopback_used[NCHAN];
	u32 loopback_alloc[NCHAN];
	u32 pstructs_free_cnt;
	u32 free_rx_cnt;
	u32 free_tx_cnt;
};

#ifndef __GNUC__
#pragma warning(disable : 4200)
#endif

struct struct_lb_stats {
	int nchan;
	struct lb_port_stats s[0];
};

struct struct_clk_info {
	u64 retransmit_min;
	u64 retransmit_max;
	u64 persist_timer_min;
	u64 persist_timer_max;
	u64 keepalive_idle_timer;
	u64 keepalive_interval;
	u64 initial_srtt;
	u64 finwait2_timer;
	u32 dack_timer;
	u32 res;
	u32 cclk_ps;
	u32 tre;
	u32 dack_re;
	u8 reserved[128];
};

struct cim_pif_la {
	int size;
	u8 data[0];
};

struct struct_tp_la {
	u32 size;
	u32 mode;
	u8 data[0];
};

struct field_desc {
	const char *name;
	u32 start;
	u32 width;
};

struct tp_mib_type {
	char *key;
	u32 addr;
	u32 value;
};

struct wtp_type_0 {
	u32   sop;
	u32   eop;
};

struct wtp_type_1 {
	u32   sop[2];
	u32   eop[2];
};

struct wtp_type_2 {
	u32   sop[4];
	u32   eop[4];
};

struct wtp_type_3 {
	u32   sop[4];
	u32   eop[4];
	u32   drops;
};

struct wtp_data {
	/*TX path, Request Work request sub-path:*/

	struct wtp_type_1 sge_pcie_cmd_req;	  /*SGE_DEBUG	PC_Req_xOPn*/
	struct wtp_type_1 pcie_core_cmd_req;	  /*PCIE_CMDR_REQ_CNT*/


	/*TX path, Work request to uP sub-path*/
	struct wtp_type_1 core_pcie_cmd_rsp;	  /*PCIE_CMDR_RSP_CNT*/
	struct wtp_type_1 pcie_sge_cmd_rsp;	  /*SGE_DEBUG	PC_Rsp_xOPn*/
	struct wtp_type_1 sge_cim;		  /*SGE_DEBUG CIM_xOPn*/

	/*TX path, Data request path from ULP_TX to core*/
	struct wtp_type_2 utx_sge_dma_req;	 /*SGE UD_Rx_xOPn*/
	struct wtp_type_2 sge_pcie_dma_req;	 /*SGE PD_Req_Rdn (no eops)*/
	struct wtp_type_2 pcie_core_dma_req;	 /*PCIE_DMAR_REQ_CNT (no eops)*/

	/*Main TX path, from core to wire*/
	struct wtp_type_2 core_pcie_dma_rsp;	/*PCIE_DMAR_RSP_SOP_CNT/
						  PCIE_DMAR_EOP_CNT*/
	struct wtp_type_2 pcie_sge_dma_rsp;	/*SGE_DEBUG PD_Rsp_xOPn*/
	struct wtp_type_2 sge_utx;		/*SGE_DEBUG U_Tx_xOPn*/
	struct wtp_type_2 utx_tp;	   /*ULP_TX_SE_CNT_CHn[xOP_CNT_ULP2TP]*/
	struct wtp_type_2 utx_tpcside;	   /*TP_DBG_CSIDE_RXn[RxXoPCnt]*/

	struct wtp_type_2 tpcside_rxpld;
	struct wtp_type_2 tpcside_rxarb;       /*TP_DBG_CSIDE_RXn[RxArbXopCnt]*/
	struct wtp_type_2 tpcside_rxcpl;

	struct wtp_type_2 tpeside_mps;	       /*TP_DBG_ESDIE_PKT0[TxXoPCnt]*/
	struct wtp_type_2 tpeside_pm;
	struct wtp_type_2 tpeside_pld;

	/*Tx path, PCIE t5 DMA stat*/
	struct wtp_type_2 pcie_t5_dma_stat3;

	/*Tx path, SGE debug data high index 6*/
	struct wtp_type_2 sge_debug_data_high_index_6;

	/*Tx path, SGE debug data high index 3*/
	struct wtp_type_2 sge_debug_data_high_index_3;

	/*Tx path, ULP SE CNT CHx*/
	struct wtp_type_2 ulp_se_cnt_chx;

	/*pcie cmd stat 2*/
	struct wtp_type_2 pcie_cmd_stat2;

	/*pcie cmd stat 3*/
	struct wtp_type_2 pcie_cmd_stat3;

	struct wtp_type_2 pcie_dma1_stat2_core;

	struct wtp_type_1 sge_work_req_pkt;

	struct wtp_type_2 sge_debug_data_high_indx5;

	/*Tx path, mac portx pkt count*/
	struct wtp_type_2 mac_portx_pkt_count;

	/*Rx path, mac porrx pkt count*/
	struct wtp_type_2 mac_porrx_pkt_count;

	/*Rx path, PCIE T5 dma1 stat 2*/
	struct wtp_type_2 pcie_dma1_stat2;

	/*Rx path, sge debug data high index 7*/
	struct wtp_type_2 sge_debug_data_high_indx7;

	/*Rx path, sge debug data high index 1*/
	struct wtp_type_1 sge_debug_data_high_indx1;

	/*Rx path, TP debug CSIDE Tx register*/
	struct wtp_type_1 utx_tpcside_tx;

	/*Rx path, LE DB response count*/
	struct wtp_type_0 le_db_rsp_cnt;

	/*Rx path, TP debug Eside PKTx*/
	struct wtp_type_2 tp_dbg_eside_pktx;

	/*Rx path, sge debug data high index 9*/
	struct wtp_type_1 sge_debug_data_high_indx9;

	/*Tx path, mac portx aFramesTransmittesok*/
	struct wtp_type_2 mac_portx_aframestra_ok;

	/*Rx path, mac portx aFramesTransmittesok*/
	struct wtp_type_2 mac_porrx_aframestra_ok;

	/*Tx path, MAC_PORT_MTIP_1G10G_RX_etherStatsPkts*/
	struct wtp_type_1 mac_portx_etherstatspkts;

	/*Rx path, MAC_PORT_MTIP_1G10G_RX_etherStatsPkts*/
	struct wtp_type_1 mac_porrx_etherstatspkts;

	struct wtp_type_3 tp_mps;	    /*MPS_TX_SE_CNT_TP01 and
					      MPS_TX_SE_CNT_TP34*/
	struct wtp_type_3 mps_xgm;	    /*MPS_TX_SE_CNT_MAC01 and
					      MPS_TX_SE_CNT_MAC34*/
	struct wtp_type_2 tx_xgm_xgm;	    /*XGMAC_PORT_PKT_CNT_PORT_n*/
	struct wtp_type_2 xgm_wire;   /*XGMAC_PORT_XGM_STAT_TX_FRAME_LOW_PORT_N
				      (clear on read)*/

	/*RX path, from wire to core.*/
	struct wtp_type_2 wire_xgm;   /*XGMAC_PORT_XGM_STAT_RX_FRAMES_LOW_PORT_N
					(clear on read)*/
	struct wtp_type_2 rx_xgm_xgm;	    /*XGMAC_PORT_PKT_CNT_PORT_n*/
	struct _xgm_mps {		    /*MPS_RX_SE_CNT_INn*/
		u32   sop[8];		    /*	=> undef,*/
		u32   eop[8];		    /*	=> undef,*/
		u32   drop;		    /* => undef,*/
		u32   cls_drop;		    /* => undef,*/
		u32   err;		    /* => undef,*/
		u32   bp;		    /*	 => undef,*/
	} xgm_mps;

	struct wtp_type_3 mps_tp;	    /*MPS_RX_SE_CNT_OUT01 and
					      MPS_RX_SE_CNT_OUT23*/
	struct wtp_type_2 mps_tpeside;	    /*TP_DBG_ESIDE_PKTn*/
	struct wtp_type_1 tpeside_pmrx;	    /*???*/
	struct wtp_type_2 pmrx_ulprx;	    /*ULP_RX_SE_CNT_CHn[xOP_CNT_INn]*/
	struct wtp_type_2 ulprx_tpcside;    /*ULP_RX_SE_CNT_CHn[xOP_CNT_OUTn]*/
	struct wtp_type_2 tpcside_csw;	    /*TP_DBG_CSIDE_TXn[TxSopCnt]*/
	struct wtp_type_2 tpcside_pm;
	struct wtp_type_2 tpcside_uturn;
	struct wtp_type_2 tpcside_txcpl;
	struct wtp_type_1 tp_csw;	     /*SGE_DEBUG CPLSW_TP_Rx_xOPn*/
	struct wtp_type_1 csw_sge;	     /*SGE_DEBUG T_Rx_xOPn*/
	struct wtp_type_2 sge_pcie;	     /*SGE_DEBUG PD_Req_SopN -
					       PD_Req_RdN - PD_ReqIntN*/
	struct wtp_type_2 sge_pcie_ints;     /*SGE_DEBUG PD_Req_IntN*/
	struct wtp_type_2 pcie_core_dmaw;    /*PCIE_DMAW_SOP_CNT and
					       PCIE_DMAW_EOP_CNT*/
	struct wtp_type_2 pcie_core_dmai;    /*PCIE_DMAI_CNT*/

};

struct tp_mib_data {
	struct tp_mib_type TP_MIB_MAC_IN_ERR_0;
	struct tp_mib_type TP_MIB_MAC_IN_ERR_1;
	struct tp_mib_type TP_MIB_MAC_IN_ERR_2;
	struct tp_mib_type TP_MIB_MAC_IN_ERR_3;
	struct tp_mib_type TP_MIB_HDR_IN_ERR_0;
	struct tp_mib_type TP_MIB_HDR_IN_ERR_1;
	struct tp_mib_type TP_MIB_HDR_IN_ERR_2;
	struct tp_mib_type TP_MIB_HDR_IN_ERR_3;
	struct tp_mib_type TP_MIB_TCP_IN_ERR_0;
	struct tp_mib_type TP_MIB_TCP_IN_ERR_1;
	struct tp_mib_type TP_MIB_TCP_IN_ERR_2;
	struct tp_mib_type TP_MIB_TCP_IN_ERR_3;
	struct tp_mib_type TP_MIB_TCP_OUT_RST;
	struct tp_mib_type TP_MIB_TCP_IN_SEG_HI;
	struct tp_mib_type TP_MIB_TCP_IN_SEG_LO;
	struct tp_mib_type TP_MIB_TCP_OUT_SEG_HI;
	struct tp_mib_type TP_MIB_TCP_OUT_SEG_LO;
	struct tp_mib_type TP_MIB_TCP_RXT_SEG_HI;
	struct tp_mib_type TP_MIB_TCP_RXT_SEG_LO;
	struct tp_mib_type TP_MIB_TNL_CNG_DROP_0;
	struct tp_mib_type TP_MIB_TNL_CNG_DROP_1;
	struct tp_mib_type TP_MIB_TNL_CNG_DROP_2;
	struct tp_mib_type TP_MIB_TNL_CNG_DROP_3;
	struct tp_mib_type TP_MIB_OFD_CHN_DROP_0;
	struct tp_mib_type TP_MIB_OFD_CHN_DROP_1;
	struct tp_mib_type TP_MIB_OFD_CHN_DROP_2;
	struct tp_mib_type TP_MIB_OFD_CHN_DROP_3;
	struct tp_mib_type TP_MIB_TNL_OUT_PKT_0;
	struct tp_mib_type TP_MIB_TNL_OUT_PKT_1;
	struct tp_mib_type TP_MIB_TNL_OUT_PKT_2;
	struct tp_mib_type TP_MIB_TNL_OUT_PKT_3;
	struct tp_mib_type TP_MIB_TNL_IN_PKT_0;
	struct tp_mib_type TP_MIB_TNL_IN_PKT_1;
	struct tp_mib_type TP_MIB_TNL_IN_PKT_2;
	struct tp_mib_type TP_MIB_TNL_IN_PKT_3;
	struct tp_mib_type TP_MIB_TCP_V6IN_ERR_0;
	struct tp_mib_type TP_MIB_TCP_V6IN_ERR_1;
	struct tp_mib_type TP_MIB_TCP_V6IN_ERR_2;
	struct tp_mib_type TP_MIB_TCP_V6IN_ERR_3;
	struct tp_mib_type TP_MIB_TCP_V6OUT_RST;
	struct tp_mib_type TP_MIB_TCP_V6IN_SEG_HI;
	struct tp_mib_type TP_MIB_TCP_V6IN_SEG_LO;
	struct tp_mib_type TP_MIB_TCP_V6OUT_SEG_HI;
	struct tp_mib_type TP_MIB_TCP_V6OUT_SEG_LO;
	struct tp_mib_type TP_MIB_TCP_V6RXT_SEG_HI;
	struct tp_mib_type TP_MIB_TCP_V6RXT_SEG_LO;
	struct tp_mib_type TP_MIB_OFD_ARP_DROP;
	struct tp_mib_type TP_MIB_OFD_DFR_DROP;
	struct tp_mib_type TP_MIB_CPL_IN_REQ_0;
	struct tp_mib_type TP_MIB_CPL_IN_REQ_1;
	struct tp_mib_type TP_MIB_CPL_IN_REQ_2;
	struct tp_mib_type TP_MIB_CPL_IN_REQ_3;
	struct tp_mib_type TP_MIB_CPL_OUT_RSP_0;
	struct tp_mib_type TP_MIB_CPL_OUT_RSP_1;
	struct tp_mib_type TP_MIB_CPL_OUT_RSP_2;
	struct tp_mib_type TP_MIB_CPL_OUT_RSP_3;
	struct tp_mib_type TP_MIB_TNL_LPBK_0;
	struct tp_mib_type TP_MIB_TNL_LPBK_1;
	struct tp_mib_type TP_MIB_TNL_LPBK_2;
	struct tp_mib_type TP_MIB_TNL_LPBK_3;
	struct tp_mib_type TP_MIB_TNL_DROP_0;
	struct tp_mib_type TP_MIB_TNL_DROP_1;
	struct tp_mib_type TP_MIB_TNL_DROP_2;
	struct tp_mib_type TP_MIB_TNL_DROP_3;
	struct tp_mib_type TP_MIB_FCOE_DDP_0;
	struct tp_mib_type TP_MIB_FCOE_DDP_1;
	struct tp_mib_type TP_MIB_FCOE_DDP_2;
	struct tp_mib_type TP_MIB_FCOE_DDP_3;
	struct tp_mib_type TP_MIB_FCOE_DROP_0;
	struct tp_mib_type TP_MIB_FCOE_DROP_1;
	struct tp_mib_type TP_MIB_FCOE_DROP_2;
	struct tp_mib_type TP_MIB_FCOE_DROP_3;
	struct tp_mib_type TP_MIB_FCOE_BYTE_0_HI;
	struct tp_mib_type TP_MIB_FCOE_BYTE_0_LO;
	struct tp_mib_type TP_MIB_FCOE_BYTE_1_HI;
	struct tp_mib_type TP_MIB_FCOE_BYTE_1_LO;
	struct tp_mib_type TP_MIB_FCOE_BYTE_2_HI;
	struct tp_mib_type TP_MIB_FCOE_BYTE_2_LO;
	struct tp_mib_type TP_MIB_FCOE_BYTE_3_HI;
	struct tp_mib_type TP_MIB_FCOE_BYTE_3_LO;
	struct tp_mib_type TP_MIB_OFD_VLN_DROP_0;
	struct tp_mib_type TP_MIB_OFD_VLN_DROP_1;
	struct tp_mib_type TP_MIB_OFD_VLN_DROP_2;
	struct tp_mib_type TP_MIB_OFD_VLN_DROP_3;
	struct tp_mib_type TP_MIB_USM_PKTS;
	struct tp_mib_type TP_MIB_USM_DROP;
	struct tp_mib_type TP_MIB_USM_BYTES_HI;
	struct tp_mib_type TP_MIB_USM_BYTES_LO;
	struct tp_mib_type TP_MIB_TID_DEL;
	struct tp_mib_type TP_MIB_TID_INV;
	struct tp_mib_type TP_MIB_TID_ACT;
	struct tp_mib_type TP_MIB_TID_PAS;
	struct tp_mib_type TP_MIB_RQE_DFR_MOD;
	struct tp_mib_type TP_MIB_RQE_DFR_PKT;
};

struct ireg_field {
	u32 ireg_addr;
	u32 ireg_data;
	u32 ireg_local_offset;
	u32 ireg_offset_range;
};

struct ireg_buf {
	struct ireg_field tp_pio;
	u32 outbuf[32];
};

#define CUDBG_TP_INDIR_REG_REV 1
#define CUDBG_PM_INDIR_REG_REV 1
#define CUDBG_MA_INDIR_REG_REV 1
#define CUDBG_UP_CIM_INDIR_REG_REV 1
#define CUDBG_HMA_INDIR_REG_REV 1

struct cudbg_indir_reg_data {
	u32 offset;
	u32 data;
};

struct cudbg_indir_reg_entity {
	struct cudbg_ver_hdr ver_hdr;
	u32 indir_reg;
	u32 indir_data;
	u32 nentries;
	struct cudbg_indir_reg_data data[0];
};

struct sge_qbase_reg_field {
	u32 reg_addr;
	u32 reg_data[4];
	u32 pf_data_value[8][4]; /* [max pf][4 data reg SGE_QBASE_MAP[0-3] */
	u32 vf_data_value[256][4]; /* [max vf][4 data reg SGE_QBASE_MAP[0-3] */
	u32 vfcount;
};

struct tx_rate {
	u64 nrate[NCHAN];
	u64 orate[NCHAN];
	u32 nchan;
};

struct tid_info_region {
	u32 ntids;
	u32 nstids;
	u32 stid_base;
	u32 hash_base;

	u32 natids;
	u32 nftids;
	u32 ftid_base;
	u32 aftid_base;
	u32 aftid_end;

	/* Server filter region */
	u32 sftid_base;
	u32 nsftids;

	/* UO context range */
	u32 uotid_base;
	u32 nuotids;

	u32 sb;
	u32 flags;
	u32 le_db_conf;
	u32 IP_users;
	u32 IPv6_users;

	u32 hpftid_base;
	u32 nhpftids;
};

struct tid_info_region_rev1 {
	struct cudbg_ver_hdr ver_hdr;
	struct tid_info_region tid;
	u32 tid_start;
	u32 nhash;
	u32 clip_base;
	u32 nclip;
	u32 route_base;
	u32 nroute;
	u32 reserved[11];
};

struct struct_vpd_data {
	u8 sn[SN_MAX_LEN + 1];
	u8 bn[BN_MAX_LEN + 1];
	u8 na[NA_MAX_LEN + 1];
	u8 mn[MN_MAX_LEN + 1];
	u16 fw_major;
	u16 fw_minor;
	u16 fw_micro;
	u16 fw_build;
	u32 scfg_vers;
	u32 vpd_vers;
};

struct sw_state {
	u32 fw_state;
	u8 caller_string[100];
	u8 os_type;
	u8 reserved[3];
	u32 reserved1[16];
};

enum cudbg_qdesc_qtype {
	CUDBG_QTYPE_UNKNOWN = 0,
	CUDBG_QTYPE_NIC_TXQ,
	CUDBG_QTYPE_NIC_RXQ,
	CUDBG_QTYPE_NIC_FLQ,
	CUDBG_QTYPE_CTRLQ,
	CUDBG_QTYPE_FWEVTQ,
	CUDBG_QTYPE_INTRQ,
	CUDBG_QTYPE_PTP_TXQ,
	CUDBG_QTYPE_OFLD_TXQ,
	CUDBG_QTYPE_RDMA_RXQ,
	CUDBG_QTYPE_RDMA_FLQ,
	CUDBG_QTYPE_RDMA_CIQ,
	CUDBG_QTYPE_ISCSI_RXQ,
	CUDBG_QTYPE_ISCSI_FLQ,
	CUDBG_QTYPE_ISCSIT_RXQ,
	CUDBG_QTYPE_ISCSIT_FLQ,
	CUDBG_QTYPE_CRYPTO_TXQ,
	CUDBG_QTYPE_CRYPTO_RXQ,
	CUDBG_QTYPE_CRYPTO_FLQ,
	CUDBG_QTYPE_TLS_RXQ,
	CUDBG_QTYPE_TLS_FLQ,
	CUDBG_QTYPE_ETHOFLD_TXQ,
	CUDBG_QTYPE_ETHOFLD_RXQ,
	CUDBG_QTYPE_ETHOFLD_FLQ,
	CUDBG_QTYPE_MAX,
};

#define CUDBG_QDESC_REV 1

struct cudbg_qdesc_entry {
	u32 data_size;
	u32 qtype;
	u32 qid;
	u32 desc_size;
	u32 num_desc;
	u8 data[0]; /* Must be last */
};

struct cudbg_qdesc_info {
	u32 qdesc_entry_size;
	u32 num_queues;
	u8 data[0]; /* Must be last */
};

/* EEPROM Standards for plug in modules */
enum {
	CUDBG_MODULE_SFF_8079 = 1,
	CUDBG_MODULE_SFF_8472 = 2,
	CUDBG_MODULE_SFF_8636 = 3,
	CUDBG_MODULE_SFF_8436 = 4,
	CUDBG_MODULE_SFF_MAX,
};

#define CUDBG_MODULE_SFF_8079_LEN		256
#define CUDBG_MODULE_SFF_8472_LEN		512
#define CUDBG_MODULE_SFF_8636_LEN		256
#define CUDBG_MODULE_SFF_8436_LEN		256

static u32 ATTRIBUTE_UNUSED eth_module_sff_len_array[CUDBG_MODULE_SFF_MAX] = {
	[CUDBG_MODULE_SFF_8079] = CUDBG_MODULE_SFF_8079_LEN,
	[CUDBG_MODULE_SFF_8472] = CUDBG_MODULE_SFF_8472_LEN,
	[CUDBG_MODULE_SFF_8636] = CUDBG_MODULE_SFF_8636_LEN,
	[CUDBG_MODULE_SFF_8436] = CUDBG_MODULE_SFF_8436_LEN,
};

/**
 * struct cudbg_modinfo - plugin module eeprom information
 * @type: Standard the module information conforms to %ETH_MODULE_SFF_xxxx
 * @eeprom_len: Length of the eeprom
 *
 */
struct cudbg_modinfo {
	__u32   type;
	__u32   eeprom_len;
};

struct cudbg_module_eeprom {
	struct cudbg_ver_hdr ver_hdr;
	struct cudbg_modinfo modinfo[MAX_NPORTS];
	u8 nports;
	u8 data[0]; /* Must be last */
};

static u32 ATTRIBUTE_UNUSED t6_tp_pio_array[][4] = {
	{0x7e40, 0x7e44, 0x020, 28}, /* t6_tp_pio_regs_20_to_3b */
	{0x7e40, 0x7e44, 0x040, 10}, /* t6_tp_pio_regs_40_to_49 */
	{0x7e40, 0x7e44, 0x050, 10}, /* t6_tp_pio_regs_50_to_59 */
	{0x7e40, 0x7e44, 0x060, 14}, /* t6_tp_pio_regs_60_to_6d */
	{0x7e40, 0x7e44, 0x06F, 1}, /* t6_tp_pio_regs_6f */
	{0x7e40, 0x7e44, 0x070, 6}, /* t6_tp_pio_regs_70_to_75 */
	{0x7e40, 0x7e44, 0x130, 18},  /* t6_tp_pio_regs_130_to_141 */
	{0x7e40, 0x7e44, 0x145, 19}, /* t6_tp_pio_regs_145_to_157 */
	{0x7e40, 0x7e44, 0x160, 1}, /* t6_tp_pio_regs_160 */
	{0x7e40, 0x7e44, 0x230, 25}, /* t6_tp_pio_regs_230_to_248 */
	{0x7e40, 0x7e44, 0x24a, 3}, /* t6_tp_pio_regs_24c */
	{0x7e40, 0x7e44, 0x8C0, 1} /* t6_tp_pio_regs_8c0 */
};

static u32 ATTRIBUTE_UNUSED t5_tp_pio_array[][4] = {
	{0x7e40, 0x7e44, 0x020, 28}, /* t5_tp_pio_regs_20_to_3b */
	{0x7e40, 0x7e44, 0x040, 19}, /* t5_tp_pio_regs_40_to_52 */
	{0x7e40, 0x7e44, 0x054, 2}, /* t5_tp_pio_regs_54_to_55 */
	{0x7e40, 0x7e44, 0x060, 13}, /* t5_tp_pio_regs_60_to_6c */
	{0x7e40, 0x7e44, 0x06F, 1}, /* t5_tp_pio_regs_6f */
	{0x7e40, 0x7e44, 0x120, 4}, /* t5_tp_pio_regs_120_to_123 */
	{0x7e40, 0x7e44, 0x12b, 2},  /* t5_tp_pio_regs_12b_to_12c */
	{0x7e40, 0x7e44, 0x12f, 21}, /* t5_tp_pio_regs_12f_to_143 */
	{0x7e40, 0x7e44, 0x145, 19}, /* t5_tp_pio_regs_145_to_157 */
	{0x7e40, 0x7e44, 0x230, 25}, /* t5_tp_pio_regs_230_to_248 */
	{0x7e40, 0x7e44, 0x8C0, 1} /* t5_tp_pio_regs_8c0 */
};

static u32 ATTRIBUTE_UNUSED t6_ma_ireg_array[][4] = {
	{0x78f8, 0x78fc, 0xa000, 23}, /* t6_ma_regs_a000_to_a016 */
	{0x78f8, 0x78fc, 0xa400, 30}, /* t6_ma_regs_a400_to_a41e */
	{0x78f8, 0x78fc, 0xa800, 20}  /* t6_ma_regs_a800_to_a813 */
};

static u32 ATTRIBUTE_UNUSED t6_ma_ireg_array2[][4] = {
	{0x78f8, 0x78fc, 0xe400, 17}, /* t6_ma_regs_e400_to_e600 */
	{0x78f8, 0x78fc, 0xe640, 13} /* t6_ma_regs_e640_to_e7c0 */
};

static u32 ATTRIBUTE_UNUSED t6_hma_ireg_array[][4] = {
	{0x51320, 0x51324, 0xa000, 32} /* t6_hma_regs_a000_to_a01f */
};
static u32 ATTRIBUTE_UNUSED t5_pcie_pdbg_array[][4] = {
	{0x5a04, 0x5a0c, 0x00, 0x20}, /* t5_pcie_pdbg_regs_00_to_20 */
	{0x5a04, 0x5a0c, 0x21, 0x20}, /* t5_pcie_pdbg_regs_21_to_40 */
	{0x5a04, 0x5a0c, 0x41, 0x10}, /* t5_pcie_pdbg_regs_41_to_50 */
};

static u32 ATTRIBUTE_UNUSED t5_pcie_config_array[][2] = {
	{0x0, 0x34},
	{0x3c, 0x40},
	{0x50, 0x64},
	{0x70, 0x80},
	{0x94, 0xa0},
	{0xb0, 0xb8},
	{0xd0, 0xd4},
	{0x100, 0x128},
	{0x140, 0x148},
	{0x150, 0x164},
	{0x170, 0x178},
	{0x180, 0x194},
	{0x1a0, 0x1b8},
	{0x1c0, 0x208},
};

static u32 ATTRIBUTE_UNUSED t5_pcie_cdbg_array[][4] = {
	{0x5a10, 0x5a18, 0x00, 0x20}, /* t5_pcie_cdbg_regs_00_to_20 */
	{0x5a10, 0x5a18, 0x21, 0x18}, /* t5_pcie_cdbg_regs_21_to_37 */
};

static u32 ATTRIBUTE_UNUSED t6_tp_tm_pio_array[1][4] = {
	{0x7e18, 0x7e1c, 0x0, 12}
};

static u32 ATTRIBUTE_UNUSED t5_tp_tm_pio_array[1][4] = {
	{0x7e18, 0x7e1c, 0x0, 12}
};

static u32 ATTRIBUTE_UNUSED t5_pm_rx_array[][4] = {
	{0x8FD0, 0x8FD4, 0x10000, 0x20}, /* t5_pm_rx_regs_10000_to_10020 */
	{0x8FD0, 0x8FD4, 0x10021, 0x0D}, /* t5_pm_rx_regs_10021_to_1002c */
};

static u32 ATTRIBUTE_UNUSED t5_pm_tx_array[][4] = {
	{0x8FF0, 0x8FF4, 0x10000, 0x20}, /* t5_pm_tx_regs_10000_to_10020 */
	{0x8FF0, 0x8FF4, 0x10021, 0x1D}, /* t5_pm_tx_regs_10021_to_1003c */
};

static u32 ATTRIBUTE_UNUSED t6_tp_mib_index_array[6][4] = {
	{0x7e50, 0x7e54, 0x0, 13},
	{0x7e50, 0x7e54, 0x10, 6},
	{0x7e50, 0x7e54, 0x18, 21},
	{0x7e50, 0x7e54, 0x30, 32},
	{0x7e50, 0x7e54, 0x50, 22},
	{0x7e50, 0x7e54, 0x68, 12}
};

static u32 ATTRIBUTE_UNUSED t5_tp_mib_index_array[9][4] = {
	{0x7e50, 0x7e54, 0x0, 13},
	{0x7e50, 0x7e54, 0x10, 6},
	{0x7e50, 0x7e54, 0x18, 8},
	{0x7e50, 0x7e54, 0x20, 13},
	{0x7e50, 0x7e54, 0x30, 16},
	{0x7e50, 0x7e54, 0x40, 16},
	{0x7e50, 0x7e54, 0x50, 16},
	{0x7e50, 0x7e54, 0x60, 6},
	{0x7e50, 0x7e54, 0x68, 4}
};

static u32 ATTRIBUTE_UNUSED t5_sge_dbg_index_array[9][4] = {
	{0x10cc, 0x10d0, 0x0, 16},
	{0x10cc, 0x10d4, 0x0, 16},
};

static u32 ATTRIBUTE_UNUSED t6_sge_qbase_index_array[5] = {
	/* 1 addr reg SGE_QBASE_INDEX and 4 data reg SGE_QBASE_MAP[0-3] */
	0x1250, 0x1240, 0x1244, 0x1248, 0x124c,
};

static u32 ATTRIBUTE_UNUSED t6_up_cim_reg_array[][5] = {
	{0x7b50, 0x7b54, 0x2000, 0x20, 0},   /* up_cim_2000_to_207c */
	{0x7b50, 0x7b54, 0x2080, 0x1d, 0},   /* up_cim_2080_to_20fc */
	{0x7b50, 0x7b54, 0x00, 0x20, 0},     /* up_cim_00_to_7c */
	{0x7b50, 0x7b54, 0x80, 0x20, 0},     /* up_cim_80_to_fc */
	{0x7b50, 0x7b54, 0x100, 0x11, 0},    /* up_cim_100_to_14c */
	{0x7b50, 0x7b54, 0x200, 0x10, 0},    /* up_cim_200_to_23c */
	{0x7b50, 0x7b54, 0x240, 0x2, 0},     /* up_cim_240_to_244 */
	{0x7b50, 0x7b54, 0x250, 0x2, 0},     /* up_cim_250_to_254 */
	{0x7b50, 0x7b54, 0x260, 0x2, 0},     /* up_cim_260_to_264 */
	{0x7b50, 0x7b54, 0x270, 0x2, 0},     /* up_cim_270_to_274 */
	{0x7b50, 0x7b54, 0x280, 0x20, 0},    /* up_cim_280_to_2fc */
	{0x7b50, 0x7b54, 0x300, 0x20, 0},    /* up_cim_300_to_37c */
	{0x7b50, 0x7b54, 0x380, 0x14, 0},    /* up_cim_380_to_3cc */
	{0x7b50, 0x7b54, 0x4900, 0x4, 0x4},  /* up_cim_4900_to_4c60 */
	{0x7b50, 0x7b54, 0x4904, 0x4, 0x4},  /* up_cim_4904_to_4c64 */
	{0x7b50, 0x7b54, 0x4908, 0x4, 0x4},  /* up_cim_4908_to_4c68 */
	{0x7b50, 0x7b54, 0x4910, 0x4, 0x4},  /* up_cim_4910_to_4c70 */
	{0x7b50, 0x7b54, 0x4914, 0x4, 0x4},  /* up_cim_4914_to_4c74 */
	{0x7b50, 0x7b54, 0x4920, 0x10, 0x10},/* up_cim_4920_to_4a10 */
	{0x7b50, 0x7b54, 0x4924, 0x10, 0x10},/* up_cim_4924_to_4a14 */
	{0x7b50, 0x7b54, 0x4928, 0x10, 0x10},/* up_cim_4928_to_4a18 */
	{0x7b50, 0x7b54, 0x492c, 0x10, 0x10},/* up_cim_492c_to_4a1c */
};

static u32 ATTRIBUTE_UNUSED t5_up_cim_reg_array[][5] = {
	{0x7b50, 0x7b54, 0x2000, 0x20, 0},   /* up_cim_2000_to_207c */
	{0x7b50, 0x7b54, 0x2080, 0x19, 0},   /* up_cim_2080_to_20ec */
	{0x7b50, 0x7b54, 0x00, 0x20, 0},     /* up_cim_00_to_7c */
	{0x7b50, 0x7b54, 0x80, 0x20, 0},     /* up_cim_80_to_fc */
	{0x7b50, 0x7b54, 0x100, 0x11, 0},    /* up_cim_100_to_14c */
	{0x7b50, 0x7b54, 0x200, 0x10, 0},    /* up_cim_200_to_23c */
	{0x7b50, 0x7b54, 0x240, 0x2, 0},     /* up_cim_240_to_244 */
	{0x7b50, 0x7b54, 0x250, 0x2, 0},     /* up_cim_250_to_254 */
	{0x7b50, 0x7b54, 0x260, 0x2, 0},     /* up_cim_260_to_264 */
	{0x7b50, 0x7b54, 0x270, 0x2, 0},     /* up_cim_270_to_274 */
	{0x7b50, 0x7b54, 0x280, 0x20, 0},    /* up_cim_280_to_2fc */
	{0x7b50, 0x7b54, 0x300, 0x20, 0},    /* up_cim_300_to_37c */
	{0x7b50, 0x7b54, 0x380, 0x14, 0},    /* up_cim_380_to_3cc */
};

static u32 ATTRIBUTE_UNUSED t5_letcam_region_reg_array[LE_ET_TCAM_MAX] = {
	[LE_ET_TCAM_SERVER] = A_LE_DB_SERVER_INDEX,
	[LE_ET_TCAM_FILTER] = A_LE_DB_FILTER_TABLE_INDEX,
	[LE_ET_TCAM_CLIP] = A_LE_DB_CLIP_TABLE_INDEX,
	[LE_ET_TCAM_ROUTING] = A_LE_DB_ROUTING_TABLE_INDEX,
	[LE_ET_HASH_CON] = A_LE_DB_TID_HASHBASE,
};

static u32 ATTRIBUTE_UNUSED letcam_region_reg_array[LE_ET_TCAM_MAX] = {
	[LE_ET_TCAM_HPFILTER] = A_LE_DB_HPRI_FILT_TABLE_START_INDEX,
	[LE_ET_TCAM_CON] = A_LE_DB_ACTIVE_TABLE_START_INDEX,
	[LE_ET_TCAM_SERVER] = A_LE_DB_SRVR_START_INDEX,
	[LE_ET_TCAM_FILTER] = A_LE_DB_NORM_FILT_TABLE_START_INDEX,
	[LE_ET_TCAM_CLIP] = A_LE_DB_CLCAM_TID_BASE,
	[LE_ET_HASH_CON] = A_T6_LE_DB_HASH_TID_BASE,
};

static inline char *cudbg_letcam_type_to_string(u8 type)
{
	switch (type) {
	case LE_ET_TCAM_HPFILTER:
		return "HP Filter";
	case LE_ET_TCAM_CON:
		return "Active";
	case LE_ET_TCAM_SERVER:
		return "Server";
	case LE_ET_TCAM_FILTER:
		return "Filter";
	case LE_ET_TCAM_CLIP:
		return "Clip";
	case LE_ET_TCAM_ROUTING:
		return "Route";
	case LE_ET_HASH_CON:
		return "Hash";
	case LE_ET_TCAM_MAX:
		return "Max";
	}

	return "Unknown";
}

#define CUDBG_LETCAM_RSPDATA_IPV6_INDEX 16
#define CUDBG_LETCAM_RSPDATA_IPV6_MASK 0x8000

#define CUDBG_LETCAM_RSPDATA_IPV6_ACTIVE_INDEX 9
#define CUDBG_LETCAM_RSPDATA_IPV6_ACTIVE_VALUE 0x00C00000

static inline u8 cudbg_letcam_get_type(u32 tid, struct cudbg_letcam *letcam,
				       struct cudbg_letcam_region *le_region)
{
	u32 i;

	for (i = 0; i < letcam->nregions; i++) {
		if (tid >= le_region->start &&
		    tid < le_region->start + le_region->nentries)
			return le_region->type;

		le_region = (struct cudbg_letcam_region *)
			    (((u8 *)le_region) +
			     letcam->region_hdr_size);
	}

	return LE_ET_UNKNOWN;
}

static inline int cudbg_letcam_is_ipv6_entry(struct cudbg_tid_data *tid_data,
					     struct cudbg_letcam *letcam,
					     struct cudbg_letcam_region *le_region)
{
	int ipv6;

	/* IPv6 TIDs must at least be on a 2-slot boundary */
	if (tid_data->tid & 1)
		return 0;

	/* Ensure IPv6 protocol MSB bit is set in the response data */
	if (!(tid_data->data[CUDBG_LETCAM_RSPDATA_IPV6_INDEX] &
	      CUDBG_LETCAM_RSPDATA_IPV6_MASK))
		return 0;

	ipv6 = 1;

	/* For active region, an additional check is needed
	 * to ensure IPv6 connection is really offloaded.
	 */
	if (cudbg_letcam_get_type(tid_data->tid, letcam, le_region) ==
	    LE_ET_TCAM_CON &&
	    tid_data->data[CUDBG_LETCAM_RSPDATA_IPV6_ACTIVE_INDEX] !=
	    CUDBG_LETCAM_RSPDATA_IPV6_ACTIVE_VALUE)
		ipv6 = 0;

	return ipv6;
}

int cudbg_view_sge_ctxt(u8 ctxt_type, u32 qid, u32 *ctxt_data,
			struct cudbg_cntxt_field *field,
			struct cudbg_buffer *cudbg_poutbuf);
#endif
