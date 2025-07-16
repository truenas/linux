#ifndef __CUDBG_LIB_H__
#define __CUDBG_LIB_H__

#ifndef min_t
#define min_t(type, _a, _b)   (((type)(_a) < (type)(_b)) ? (type)(_a) : (type)(_b))
#endif

int cudbg_collect_reg_dump(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_fw_devlog(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err);
int cudbg_collect_cim_qcfg(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_cim_la(struct cudbg_init *pdbg_init,
			 struct cudbg_buffer *dbg_buff,
			 struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ma_la(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ulp0(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ulp1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ulp2(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ulp3(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_sge(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ncsi(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_tp0(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_tp1(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ulp(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_sge0(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_sge1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ncsi(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_edc0_meminfo(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_edc1_meminfo(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_mc0_meminfo(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_mc1_meminfo(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_rss(struct cudbg_init *pdbg_init,
		      struct cudbg_buffer *dbg_buff,
		      struct cudbg_error *cudbg_err);
int cudbg_collect_rss_key(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err);
int cudbg_collect_rss_pf_config(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err);
int cudbg_collect_rss_vf_config(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err);
int cudbg_collect_rss_config(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err);
int cudbg_collect_path_mtu(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_sw_state(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_wtp_data(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_pm_stats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_hw_sched(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_tcp_stats(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err);
int cudbg_collect_tp_err_stats(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_fcoe_stats(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err);
int cudbg_collect_rdma_stats(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err);
int cudbg_collect_tp_indirect(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_sge_indirect(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cpl_stats(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err);
int cudbg_collect_ddp_stats(struct cudbg_init *pdbg_init,
			    struct cudbg_buffer *dbg_buff,
			    struct cudbg_error *cudbg_err);
int cudbg_collect_wc_stats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_ulprx_la(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_lb_stats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_tp_la(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err);
int cudbg_collect_meminfo(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err);
int cudbg_collect_cim_pif_la(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err);
int cudbg_collect_clk_info(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_sge_rx_q0(struct cudbg_init *pdbg_init,
				    struct cudbg_buffer *dbg_buff,
				    struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_sge_rx_q1(struct cudbg_init *pdbg_init,
				    struct cudbg_buffer *dbg_buff,
				    struct cudbg_error *cudbg_err);
int cudbg_collect_macstats(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_pcie_indirect(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err);
int cudbg_collect_pm_indirect(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_full(struct cudbg_init *pdbg_init,
		       struct cudbg_buffer *dbg_buff,
		       struct cudbg_error *cudbg_err);
int cudbg_collect_tx_rate(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err);
int cudbg_collect_tid(struct cudbg_init *pdbg_init,
		      struct cudbg_buffer *dbg_buff,
		      struct cudbg_error *cudbg_err);
int cudbg_collect_pcie_config(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_dump_context(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_mps_tcam(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_vpd_data(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_le_tcam(struct cudbg_init *pdbg_init,
			  struct cudbg_buffer *dbg_buff,
			  struct cudbg_error *cudbg_err);
int cudbg_collect_cctrl(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err);
int cudbg_collect_ma_indirect(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_ulptx_la(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_up_cim_indirect(struct cudbg_init *pdbg_init,
				  struct cudbg_buffer *dbg_buff,
				  struct cudbg_error *cudbg_err);
int cudbg_collect_pbt_tables(struct cudbg_init *pdbg_init,
			     struct cudbg_buffer *dbg_buff,
			     struct cudbg_error *cudbg_err);
int cudbg_collect_mbox_log(struct cudbg_init *pdbg_init,
			   struct cudbg_buffer *dbg_buff,
			   struct cudbg_error *cudbg_err);
int cudbg_collect_hma_indirect(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_hma_meminfo(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_upload(struct cudbg_init *pdbg_init,
			 struct cudbg_buffer *dbg_buff,
			 struct cudbg_error *cudbg_err);
int cudbg_collect_module_eeprom(struct cudbg_init *pdbg_init,
				struct cudbg_buffer *dbg_buff,
				struct cudbg_error *cudbg_err);
int cudbg_collect_flash(struct cudbg_init *pdbg_init,
			struct cudbg_buffer *dbg_buff,
			struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_tp2(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_tp3(struct cudbg_init *pdbg_init,
			      struct cudbg_buffer *dbg_buff,
			      struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ipc1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ipc2(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ipc3(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ipc4(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ipc5(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ipc6(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_ibq_ipc7(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ipc1(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ipc2(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ipc3(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ipc4(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ipc5(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ipc6(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);
int cudbg_collect_cim_obq_ipc7(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err);

static int (*process_entity[])(struct cudbg_init *pdbg_init,
			       struct cudbg_buffer *dbg_buff,
			       struct cudbg_error *cudbg_err) = {
		cudbg_collect_reg_dump,
		cudbg_collect_fw_devlog,
		cudbg_collect_cim_la,		/*3*/
		cudbg_collect_cim_ma_la,
		cudbg_collect_cim_qcfg,
		cudbg_collect_cim_ibq_tp0,
		cudbg_collect_cim_ibq_tp1,
		cudbg_collect_cim_ibq_ulp,
		cudbg_collect_cim_ibq_sge0,
		cudbg_collect_cim_ibq_sge1,
		cudbg_collect_cim_ibq_ncsi,
		cudbg_collect_cim_obq_ulp0,
		cudbg_collect_cim_obq_ulp1,	/*13*/
		cudbg_collect_cim_obq_ulp2,
		cudbg_collect_cim_obq_ulp3,
		cudbg_collect_cim_obq_sge,
		cudbg_collect_cim_obq_ncsi,
		cudbg_collect_edc0_meminfo,
		cudbg_collect_edc1_meminfo,
		cudbg_collect_mc0_meminfo,
		cudbg_collect_mc1_meminfo,
		cudbg_collect_rss,		/*22*/
		cudbg_collect_rss_pf_config,
		cudbg_collect_rss_key,
		cudbg_collect_rss_vf_config,
		cudbg_collect_rss_config,	/*26*/
		cudbg_collect_path_mtu,	/*27*/
		cudbg_collect_sw_state,
		cudbg_collect_wtp_data,
		cudbg_collect_pm_stats,
		cudbg_collect_hw_sched,
		cudbg_collect_tcp_stats,
		cudbg_collect_tp_err_stats,
		cudbg_collect_fcoe_stats,
		cudbg_collect_rdma_stats,
		cudbg_collect_tp_indirect,
		cudbg_collect_sge_indirect,
		cudbg_collect_cpl_stats,
		cudbg_collect_ddp_stats,
		cudbg_collect_wc_stats,
		cudbg_collect_ulprx_la,
		cudbg_collect_lb_stats,
		cudbg_collect_tp_la,
		cudbg_collect_meminfo,
		cudbg_collect_cim_pif_la,
		cudbg_collect_clk_info,
		cudbg_collect_cim_obq_sge_rx_q0,
		cudbg_collect_cim_obq_sge_rx_q1,
		cudbg_collect_macstats,
		cudbg_collect_pcie_indirect,
		cudbg_collect_pm_indirect,
		cudbg_collect_full,
		cudbg_collect_tx_rate,
		cudbg_collect_tid,
		cudbg_collect_pcie_config,
		cudbg_collect_dump_context,
		cudbg_collect_mps_tcam,
		cudbg_collect_vpd_data,
		cudbg_collect_le_tcam,
		cudbg_collect_cctrl,
		cudbg_collect_ma_indirect,
		cudbg_collect_ulptx_la,
		NULL,			/* ext entity */
		cudbg_collect_up_cim_indirect,
		cudbg_collect_pbt_tables,
		cudbg_collect_mbox_log,
		cudbg_collect_hma_indirect,
		cudbg_collect_hma_meminfo,
		cudbg_collect_upload,
		NULL, /* queue descriptors - Driver specific */
		cudbg_collect_module_eeprom,
		cudbg_collect_flash,
		cudbg_collect_cim_ibq_tp2,
		cudbg_collect_cim_ibq_tp3,
		cudbg_collect_cim_ibq_ipc1,
		cudbg_collect_cim_ibq_ipc2,
		cudbg_collect_cim_ibq_ipc3,
		cudbg_collect_cim_ibq_ipc4,
		cudbg_collect_cim_ibq_ipc5,
		cudbg_collect_cim_ibq_ipc6,
		cudbg_collect_cim_ibq_ipc7,
		cudbg_collect_cim_obq_ipc1,
		cudbg_collect_cim_obq_ipc2,
		cudbg_collect_cim_obq_ipc3,
		cudbg_collect_cim_obq_ipc4,
		cudbg_collect_cim_obq_ipc5,
		cudbg_collect_cim_obq_ipc6,
		cudbg_collect_cim_obq_ipc7,
};

static int ATTRIBUTE_UNUSED entity_priority_list[] = {
	CUDBG_MBOX_LOG,
	CUDBG_QDESC,
	CUDBG_REG_DUMP,
	CUDBG_DEV_LOG,
	CUDBG_CIM_LA,
	CUDBG_CIM_MA_LA,
	CUDBG_CIM_QCFG,
	CUDBG_CIM_IBQ_TP0,
	CUDBG_CIM_IBQ_TP1,
	CUDBG_CIM_IBQ_TP2,
	CUDBG_CIM_IBQ_TP3,
	CUDBG_CIM_IBQ_ULP,
	CUDBG_CIM_IBQ_SGE0,
	CUDBG_CIM_IBQ_SGE1,
	CUDBG_CIM_IBQ_NCSI,
	CUDBG_CIM_IBQ_IPC1,
	CUDBG_CIM_IBQ_IPC2,
	CUDBG_CIM_IBQ_IPC3,
	CUDBG_CIM_IBQ_IPC4,
	CUDBG_CIM_IBQ_IPC5,
	CUDBG_CIM_IBQ_IPC6,
	CUDBG_CIM_IBQ_IPC7,
	CUDBG_CIM_OBQ_ULP0,
	CUDBG_CIM_OBQ_ULP1,
	CUDBG_CIM_OBQ_ULP2,
	CUDBG_CIM_OBQ_ULP3,
	CUDBG_CIM_OBQ_SGE,
	CUDBG_CIM_OBQ_NCSI,
	CUDBG_CIM_OBQ_SGE_RXQ0,
	CUDBG_CIM_OBQ_SGE_RXQ1,
	CUDBG_CIM_OBQ_IPC1,
	CUDBG_CIM_OBQ_IPC2,
	CUDBG_CIM_OBQ_IPC3,
	CUDBG_CIM_OBQ_IPC4,
	CUDBG_CIM_OBQ_IPC5,
	CUDBG_CIM_OBQ_IPC6,
	CUDBG_CIM_OBQ_IPC7,
	CUDBG_EDC0,
	CUDBG_EDC1,
	CUDBG_MC0,
	CUDBG_MC1,
	CUDBG_RSS,
	CUDBG_RSS_PF_CONF,
	CUDBG_RSS_KEY,
	CUDBG_RSS_VF_CONF,
	CUDBG_RSS_CONF,
	CUDBG_PATH_MTU,
	CUDBG_SW_STATE,
	CUDBG_WTP,
	CUDBG_PM_STATS,
	CUDBG_HW_SCHED,
	CUDBG_TCP_STATS,
	CUDBG_TP_ERR_STATS,
	CUDBG_FCOE_STATS,
	CUDBG_RDMA_STATS,
	CUDBG_TP_INDIRECT,
	CUDBG_SGE_INDIRECT,
	CUDBG_CPL_STATS,
	CUDBG_DDP_STATS,
	CUDBG_WC_STATS,
	CUDBG_ULPRX_LA,
	CUDBG_LB_STATS,
	CUDBG_TP_LA,
	CUDBG_MEMINFO,
	CUDBG_CIM_PIF_LA,
	CUDBG_CLK,
	CUDBG_MAC_STATS,
	CUDBG_PCIE_INDIRECT,
	CUDBG_PM_INDIRECT,
	CUDBG_FULL,
	CUDBG_TX_RATE,
	CUDBG_TID_INFO,
	CUDBG_PCIE_CONFIG,
	CUDBG_DUMP_CONTEXT,
	CUDBG_MPS_TCAM,
	CUDBG_VPD_DATA,
	CUDBG_LE_TCAM,
	CUDBG_CCTRL,
	CUDBG_MA_INDIRECT,
	CUDBG_ULPTX_LA,
	CUDBG_EXT_ENTITY,
	CUDBG_UP_CIM_INDIRECT,
	CUDBG_PBT_TABLE,
	CUDBG_HMA_INDIRECT,
	CUDBG_HMA,
	CUDBG_UPLOAD,
	CUDBG_MOD_EEPROM,
	CUDBG_FLASH,
};

static int ATTRIBUTE_UNUSED entity_priority_list_sec_cores[] = {
	CUDBG_DEV_LOG,
	CUDBG_CIM_LA,
	CUDBG_CIM_MA_LA,
	CUDBG_CIM_QCFG,
	CUDBG_CIM_IBQ_TP0,
	CUDBG_CIM_IBQ_TP1,
	CUDBG_CIM_IBQ_TP2,
	CUDBG_CIM_IBQ_TP3,
	CUDBG_CIM_IBQ_ULP,
	CUDBG_CIM_IBQ_SGE0,
	CUDBG_CIM_IBQ_IPC1,
	CUDBG_CIM_OBQ_ULP0,
	CUDBG_CIM_OBQ_ULP1,
	CUDBG_CIM_OBQ_ULP2,
	CUDBG_CIM_OBQ_ULP3,
	CUDBG_CIM_OBQ_SGE,
	CUDBG_CIM_OBQ_SGE_RXQ0,
	CUDBG_CIM_OBQ_IPC1,
	CUDBG_CIM_PIF_LA,
	CUDBG_UPLOAD,
};

struct large_entity {
	int entity_code;
	int skip_flag;
	int priority; /* 1 is high priority */
};

static inline void cudbg_access_lock_aquire(struct cudbg_init *dbg_init)
{
	if (dbg_init->lock_cb)
		dbg_init->lock_cb(dbg_init->access_lock);
}

static inline void cudbg_access_lock_release(struct cudbg_init *dbg_init)
{
	if (dbg_init->unlock_cb)
		dbg_init->unlock_cb(dbg_init->access_lock);
}

int get_entity_hdr(void *outbuf, int i, u32 size, struct cudbg_entity_hdr **);
void skip_entity(struct large_entity *, int large_entity_list_size,
		 int entity_code);
void reset_skip_entity(struct large_entity *, int large_entity_list_size);
int is_large_entity(struct large_entity *, int large_entity_list_size,
		    int entity_code);

int cudbg_get_mem_region(struct struct_meminfo *meminfo,
			 const char *region_name,
			 struct struct_mem_desc *mem_desc);
void cudbg_get_mem_relative(struct struct_meminfo *meminfo,
			    u32 *out_base, u32 *out_end,
			    u8 *mem_type);
int cudbg_dump_context_size(struct adapter *padap, u8 sge_ctxt_size);
void align_debug_buffer(struct cudbg_buffer *dbg_buff,
			struct cudbg_entity_hdr *entity_hdr);
#endif
