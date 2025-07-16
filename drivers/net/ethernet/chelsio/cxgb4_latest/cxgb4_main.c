/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bitmap.h>
#include <linux/crc32.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/firmware.h>
#include <linux/if_vlan.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/sockios.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/neighbour.h>
#include <net/netevent.h>
#include <net/addrconf.h>
#include <asm/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/mii.h>
#include <linux/proc_fs.h>
#include <linux/sort.h>
#include <linux/notifier.h>
#include <linux/string_helpers.h>
#include <net/inet6_hashtables.h>
#include <linux/crash_dump.h>
#include <net/udp_tunnel.h>

#include "common.h"
#include "cxgbtool.h"
#include "cxgb4_cxgbtool.h"
#include "cxgb4_filter.h"
#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_msg.h"
#include "t4_tcb.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "t4_linux_fs.h"

#include "t4_bypass.h"
#include "bypass_sysfs.h"

#include "cxgb4_dcb.h"
#include "smt.h"
#include "srq.h"
#include "cxgb4_debugfs.h"
#include "clip_tbl.h"
#include "l2t.h"
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
#include "cxgb4_ptp.h"
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include "cxgb4_ofld.h"
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

#if defined(BOND_SUPPORT)
#include <net/bonding.h>
#include <net/bond_3ad.h>
#endif

#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
#include <net/xfrm.h>
#endif

#include "cxgb4_common.h"

char cxgb4_driver_name[] = KBUILD_MODNAME;

#ifdef DRV_VERSION
#undef DRV_VERSION
#endif
#define DRV_VERSION "4.1.0.3"
const char cxgb4_driver_version[] = DRV_VERSION;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#define DRV_DESC "Chelsio T4/T5/T6/T7 Offload Network Driver"
#else
#define DRV_DESC "Chelsio T4/T5/T6/T7 Non-Offload Network Driver"
#endif

#ifdef CONFIG_PCI_IOV
enum {
	VF_MONITOR_PERIOD = 4 * HZ,
};
#endif

#define PORT_MASK ((1 << MAX_NPORTS) - 1)

#define DFLT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK | \
			 NETIF_MSG_TIMER | NETIF_MSG_IFDOWN | NETIF_MSG_IFUP |\
			 NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR)

#define FW4_FNAME "cxgb4/t4fw.bin"
#define FW5_FNAME "cxgb4/t5fw.bin"
#define FW6_FNAME "cxgb4/t6fw.bin"
#define FW7_FNAME "cxgb4/t7fw.bin"
#define FW4_CFNAME "cxgb4/t4-config.txt"
#define FW5_CFNAME "cxgb4/t5-config.txt"
#define FW6_CFNAME "cxgb4/t6-config.txt"
#define FW7_CFNAME "cxgb4/t7-config.txt"
#define FW4_FPGA_CFNAME "cxgb4/t4-config_fpga.txt"
#define FW5_FPGA_CFNAME "cxgb4/t5-config_fpga.txt"
#define FW6_FPGA_CFNAME "cxgb4/t6-config_fpga.txt"
#define FW7_FPGA_CFNAME "cxgb4/t7-config_fpga.txt"
#define PHY_AQ1202_FIRMWARE "cxgb4/aq1202_fw.cld"
#define PHY_BCM84834_FIRMWARE "cxgb4/bcm8483.bin"
#define PHY_AQ1202_DEVICEID 0x4409
#define PHY_BCM84834_DEVICEID 0x4486

MODULE_DESCRIPTION(DRV_DESC);
MODULE_AUTHOR("Chelsio Communications");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_FIRMWARE(FW4_FNAME);
MODULE_FIRMWARE(FW5_FNAME);
MODULE_FIRMWARE(FW6_FNAME);
MODULE_FIRMWARE(FW7_FNAME);
MODULE_FIRMWARE(FW4_CFNAME);
MODULE_FIRMWARE(FW5_CFNAME);
MODULE_FIRMWARE(FW6_CFNAME);
MODULE_FIRMWARE(FW7_CFNAME);

#ifdef CHELSIO_T4_DIAGS
/*
 * The master PF is normally PF4 but can be changed to PF0 via the attach_pf0
 * module parameter.  Note that PF0 does have extra privileges and can access
 * all the other PFs' VPDs and the entire EEPROM which the other PFs cannot.
 * This functionality is vital for diagnostics which needs access to the entire
 * EEPROM.
 */
static bool attach_pf0;

module_param(attach_pf0, bool, 0644);
MODULE_PARM_DESC(attach_pf0, "Attach to Master Physical Function 0");

/*
 * Allow firmware to initialize the external memory so that diagnostics can
 * run BIST. Normally, the memory is initialized only when it is needed, but
 * this parameter allows the memory to be initialized from the driver by
 * sending a FW command to do so.
 */
static bool extmem_init = 0;
module_param(extmem_init, bool, 0644);
MODULE_PARM_DESC(extmem_init, "Initialize external memory");

static unsigned short diag_memtest_size;
module_param(diag_memtest_size, ushort, 0644);
MODULE_PARM_DESC(diag_memtest_size,
		 "CIM Diag Memtest Size in KB. 0 - Disable (default), 65535 - Max");
#endif

/*
 * The driver uses the best interrupt scheme available on a platform in the
 * order MSI-X, MSI, legacy INTx interrupts.  This parameter determines which
 * of these schemes the driver may consider as follows:
 *
 * msi = 2: choose from among all three options
 * msi = 1: only consider MSI and INTx interrupts
 * msi = 0: force INTx interrupts
 */
static unsigned int msi = 2;
module_param(msi, uint, 0644);
MODULE_PARM_DESC(msi, "whether to use INTx (0), MSI (1) or MSI-X (2)");

/*
 * TX Packet coalescing.  Set to 0, disables all TX Coalescing.  Set to 1,
 * we perform TX Coalescing when it looks like a TX Queue is "getting full."
 * Set to 2, we perform TX Coalescing most of the time with a consequent
 * impact to TX Latency ...
 */
static int tx_coal = 1;

module_param(tx_coal, int, 0644);
MODULE_PARM_DESC(tx_coal, "use tx WR coalescing, if set to 2, coalescing "
		 " will be used most of the time improving packets per "
		 " second troughput but affecting latency");

/*
 * TX Doorbell Write Combining support.  Set to 0, disables this
 * functionality.  Set to 1 (default), it enables it on chip and system
 * architectures which support this and Write-Combined memory mappings.
 */
#ifdef ARCH_HAS_IOREMAP_WC
static int tx_db_wc = 1;
#else
static int tx_db_wc = 0;
#endif
module_param(tx_db_wc, int, 0644);
MODULE_PARM_DESC(tx_db_wc, "use tx WR combining");

/*
 * Normally we tell the chip to deliver Ingress Packets into our DMA buffers
 * offset by 2 bytes in order to have the IP headers line up on 4-byte
 * boundaries.  This is a requirement for many architectures which will throw
 * a machine check fault if an attempt is made to access one of the 4-byte IP
 * header fields on a non-4-byte boundary.  And it's a major performance issue
 * even on some architectures which allow it like some implementations of the
 * x86 ISA.  However, some architectures don't mind this and for some very
 * edge-case performance sensitive applications (like forwarding large volumes
 * of small packets), setting this DMA offset to 0 will decrease the number of
 * PCI-E Bus transfers enough to measurably affect performance.
 */
static int rx_dma_offset = 2;

module_param(rx_dma_offset, int, 0644);
MODULE_PARM_DESC(rx_dma_offset, "Offset of RX packets into DMA buffers -- "
		 " legal values 2 (default) and 0");

/*
 * Firmware auto-install by driver during attach (0, 1, 2 = prohibited, allowed,
 * encouraged respectively).
 */
static int t4_fw_install = 1;
module_param(t4_fw_install, int, 0644);
MODULE_PARM_DESC(t4_fw_install, "whether to have FW auto-installed by driver "
		 "during attach (0, 1, 2 = prohibited, allowed, encouraged "
		 "respectively).");

/*
 * If fw_attach is 0 the driver will not connect to FW.  This is intended only
 * for FW debugging.  fw_attach must be 1 for normal operation.
 */
int fw_attach = 1;

module_param(fw_attach, int, 0644);
MODULE_PARM_DESC(fw_attach, "whether to connect to FW");

/*
 * If intr_en is false, driver uses status page based completions for TxQ WRs. 
 * When enabled, driver requests for per WR interrupt for completion. This is 
 * intended only for specific use cases and not enabled in general.
 */
bool intr_en = 0;
module_param(intr_en, bool, 0644);
MODULE_PARM_DESC(intr_en, "Per WR interrupt for TxQ completions, default(disabled)");

/*
 * SGE Doorbell FIFO Overflow recovery ...
 */
int dbfifo_int_thresh = 5; /* 5 == 320 entry threshold */
module_param(dbfifo_int_thresh, int, 0644);
MODULE_PARM_DESC(dbfifo_int_thresh, "doorbell fifo interrupt threshold");

/*
 * usecs to sleep while draining the dbfifo
 */
static int dbfifo_drain_delay = 1000;
module_param(dbfifo_drain_delay, int, 0644);
MODULE_PARM_DESC(dbfifo_drain_delay, 
		 "usecs to sleep while draining the dbfifo");

int allow_nonroot_ioctl = 0;
module_param(allow_nonroot_ioctl, int, 0644);
MODULE_PARM_DESC(allow_nonroot_ioctl,
		 "Allow nonroot access to IOCTL (default = 0)");

static int attempt_err_recovery = 0;
module_param(attempt_err_recovery, int, 0644);
MODULE_PARM_DESC(attempt_err_recovery,
		 "Attempt to reset and recover from fatal hw errors (default = 0)");

/* TX Queue select used to determine what algorithm to use for selecting TX
 * queue. Select between the kernel provided function (select_queue=0) or user
 * cxgb_select_queue function (select_queue=1)
 *
 * Default: select_queue=0
 */
static int select_queue = 0;
module_param(select_queue, int, 0644);
MODULE_PARM_DESC(select_queue,
		 "Select between kernel provided method of selecting or driver method of selecting TX queue. Default is kernel method.");

int max_eth_qsets = 32;
module_param(max_eth_qsets, int, 0644);
MODULE_PARM_DESC(max_eth_qsets, "Maximum number of queue sets that will be "
		 "allocated per adapter, for Nic traffic. Valid values - "
		 "32..64, Default value is 32.");
 
#ifndef CONFIG_CHELSIO_BYPASS
/*
 * Host Deadman Watchdog Timer.  If this is enabled, then the Host Driver will
 * set up a firmware watchdog timer to cause the firmware to shut down the
 * adapter if mode is set to zero and turnoff pause if mode is non zero,
 * if the Host Driver stops resetting the watchdog timer.  One use of
 * this is to prevent a dead host from causing its attached switch from going
 * down.  This can happen with some switches when the dead host stops
 * processing ingress packets which will eventually result in an endless
 * stream of Pause Frames being sent.  A Good Switch would simply disable that
 * port but there are Less Good Switches out there that crash.
 *
 * This feature isn't available for Bypass adapters because they already use
 * the adapter watchdog support for their special needs.
 */
#define DEADMAN_WATCHDOG_MIN 1000
#define DEADMAN_SHUTDOWN_MAX 60000
static int deadman_watchdog[2] = {0,0};
module_param_array(deadman_watchdog, int, NULL, 0644);
MODULE_PARM_DESC(deadman_watchdog,
		 "Array of elements representing pair of {n,m} "
		 "where n is timer (min=1000ms, max=60000ms, 0=watchdog off) default 0;"
		 " m is the mode(Optional), valid values (0=shutdown, 1=pauseoff) default 0");
#endif /* CONFIG_CHELSIO_BYPASS */

static unsigned int mq_with_1G;
module_param(mq_with_1G, uint, 0644);
MODULE_PARM_DESC(mq_with_1G,
		 "Support core no of queues per port, even for 1G port");

int user_filter_perc = 33;
module_param(user_filter_perc, int, 0444);
MODULE_PARM_DESC(user_filter_perc,
	         "Percentage of total Filter region space to be allotted for"
		 " user-filters. Valid values - 0..100. Default is 33");

/*
 * Enable use of DDR Filters.
 */
unsigned int use_ddr_filters;
module_param(use_ddr_filters, uint, 0444);
MODULE_PARM_DESC(use_ddr_filters,
		 "Use DDR Filters to support more no. of User-Filters");

/*
 * Offload RX queue intr cnt threshold.
 */
static unsigned int offload_rx_intr_cnt = 1;
module_param(offload_rx_intr_cnt, uint, 0444);
MODULE_PARM_DESC(offload_rx_intr_cnt,
		"Offload RX queue intr cnt threshold (default=1)");

/*
 * Enable Traffic Mirroring.
 */
static unsigned int enable_mirror;
module_param(enable_mirror, uint, 0444);
MODULE_PARM_DESC(enable_mirror,
		 "Enable Traffic Mirroring to Mirror Rx Queues (default=0)."
		 " DDR Filters needs to be enabled for this");


unsigned int enable_traceq;
module_param(enable_traceq, uint, 0444);
MODULE_PARM_DESC(enable_traceq,
		 "Enable separate Rx Queues for Tracing (default=0).");

static bool enable_ringbb;
module_param(enable_ringbb, bool, 0444);
MODULE_PARM_DESC(enable_ringbb,
		 "Enable MAC based Ringbackbone Topology (default=0).");

enum cxgb4_modparam_enable_ulds_mask {
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_RDMA,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_ISCSI,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_ISCSIT,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_NVME_TCP_HOST,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_NVME_TCP_TARGET,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_CSTOR,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_CRYPTO,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_CHTCP,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_IPSEC,
	CXGB4_MODPARAM_ENABLE_ULDS_MASK_MAX,
};

static unsigned int enable_ulds = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_MAX) - 1;
module_param(enable_ulds, uint, 0444);
MODULE_PARM_DESC(enable_ulds,
		"Bitmask OR of enabled ULDs. 0x1 - TOE, 0x2 - RDMA, 0x4 - iSCSI, 0x8 - iSCSIT,"
		"0x10 - NVME_TCP_HOST, 0x20 - NVME_TCP_TARGET, 0x40 - CSTOR,"
		"0x80 - CRYPTO, 0x100 - CHTCP, 0x200 - IPSEC. Some ULDs may share resources"
		"with other ULDs and may automatically enable the dependent ULDs.");

/* Forcefully disable Relaxed Ordering */
static bool ro_force_off = 0;
module_param(ro_force_off, bool, 0444);
MODULE_PARM_DESC(ro_force_off,
		 "When set to 1, forcefully turns off PCIe Relaxed Ordering for all queues. (default=0)");

bool cxgb4_modparam_attempt_err_recovery(void)
{
	return !!attempt_err_recovery;
}

static struct dentry *cxgb4_debugfs_root;
static struct net_device_ops cxgb4_netdev_ops;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static LIST_HEAD(adapter_list);
DEFINE_MUTEX(uld_mutex);
struct cxgb4_uld_info cxgb4_ulds[CXGB4_ULD_TYPE_MAX];

static unsigned int registered_notifier_block;
enum {
	CXGB4_NETDEV_REGISTERED		= 1 << 0,
	CXGB4_INET6ADDR_REGISTERED	= 1 << 1,
	CXGB4_NETEVENT_REGISTERED	= 1 << 2
};
#endif

static unsigned int cxgb4_modparam_msi(void)
{
	return msi > 2 ? 2 : msi;
}

bool cxgb4_modparam_enable_ringbb(void)
{
	return enable_ringbb;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static unsigned int cxgb4_modparam_enable_ulds(void)
{
	return enable_ulds;
}

static bool cxgb4_modparam_enable_ulds_supported(enum cxgb4_uld_type uld)
{
	unsigned int dep_mask = 0, uld_mask = 0;

	switch (uld) {
	case CXGB4_ULD_TYPE_RDMA:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_RDMA);
		/* Shares TOE Txqs */
		dep_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE);
		break;
	case CXGB4_ULD_TYPE_ISCSI:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_ISCSI);
		/* Shares TOE Txqs */
		dep_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE);
		break;
	case CXGB4_ULD_TYPE_ISCSIT:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_ISCSIT);
		/* Shares TOE Txqs */
		dep_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE);
		break;
	case CXGB4_ULD_TYPE_NVME_TCP_HOST:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_NVME_TCP_HOST);
		/* Shares TOE Txqs */
		dep_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE);
		break;
	case CXGB4_ULD_TYPE_NVME_TCP_TARGET:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_NVME_TCP_TARGET);
		/* Shares TOE Txqs */
		dep_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE);
		break;
	case CXGB4_ULD_TYPE_CSTOR:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_CSTOR);
		/* Shares TOE Txqs */
		dep_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE);
		break;
	case CXGB4_ULD_TYPE_CRYPTO:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_CRYPTO);
		break;
	case CXGB4_ULD_TYPE_TOE:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_TOE);
		break;
	case CXGB4_ULD_TYPE_CHTCP:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_CHTCP);
		break;
	case CXGB4_ULD_TYPE_IPSEC:
		uld_mask = BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_IPSEC);
		break;
	default:
		break;
	}

	/* Some ULDs are dependent on others. So update modparam to reflect
	 * this.
	 */
	if ((enable_ulds & uld_mask) && !(enable_ulds & dep_mask))
		enable_ulds |= dep_mask;

	enable_ulds &= BIT(CXGB4_MODPARAM_ENABLE_ULDS_MASK_MAX) - 1;
	return !!(enable_ulds & uld_mask);
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

static bool cxgb4_modparam_ro_force_off(void)
{
	return ro_force_off;
}

static bool cxgb4_pcie_relaxed_ordering_enabled(struct adapter *adap)
{
	return cxgb4_common_relaxed_ordering_enabled(adap) &&
	       !cxgb4_modparam_ro_force_off();
}

static int cfg_queues(struct adapter *adap);

/**
 *	link_report - show link status and link speed/duplex
 *	@dev: the port whose settings are to be reported
 *
 *	Shows the link status, speed, and duplex of a port.
 */
static void link_report(struct net_device *dev)
{
	if (!netif_carrier_ok(dev))
		printk(KERN_INFO "%s: link down\n", dev->name);
	else {
		static const char * const fc[] = { "no", "Rx", "Tx", "Tx/Rx" };
		const struct port_info *p = netdev_priv(dev);
		u8 cur_fc = p->link_cfg.fc & ~PAUSE_AUTONEG;
		const char *s;

		switch (p->link_cfg.speed) {
		case 100:
			s = "100Mbps";
			break;
		case 1000:
			s = "1Gbps";
			break;
		case 10000:
			s = "10Gbps";
			break;
		case 25000:
			s = "25Gbps";
			break;
		case 40000:
			s = "40Gbps";
			break;
		case 50000:
			s = "50Gbps";
			break;
		case 100000:
			s = "100Gbps";
			break;
		case 200000:
			s = "200Gbps";
			break;
		case 400000:
			s = "400Gbps";
			break;

		default:
			printk(KERN_INFO "%s: unsupported speed: %u\n",
			       dev->name, p->link_cfg.speed);
			return;
		}

		printk(KERN_INFO "%s: link up, %s, full-duplex, %s PAUSE\n",
		       dev->name, s, fc[cur_fc]);
	}
}

#ifdef CONFIG_CXGB4_DCB
extern char *dcb_ver_array[];

/* Set up/tear down Data Center Bridging Priority mapping for a net device. */
static void dcb_tx_queue_prio_enable(struct net_device *dev, int enable)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	struct sge_eth_txq *txq = &adap->sge.ethtxq[pi->first_qset];
	int i;

	/* We use a simple mapping of Port TX Queue Index to DCB
	 * Priority when we're enabling DCB.
	 */
	for (i = 0; i < pi->nqsets; i++, txq++) {
		u32 name, value;
		int err;

		name = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_DCBPRIO_ETH) |
			V_FW_PARAMS_PARAM_YZ(txq->q.cntxt_id));
		value = enable ? i : 0xffffffff;

		/* Since we can be called while atomic (from "interrupt
		 * level") we need to issue the Set Parameters Commannd
		 * without sleeping (timeout < 0).
		 */
		err = t4_set_params_timeout(adap, adap->mbox, adap->pf, 0, 1,
					    &name, &value,
					    -FW_CMD_MAX_TIMEOUT);

		if (err)
			CH_ERR(adap,
				"Can't %s DCB Priority on port %d, TX Queue %d: err=%d\n",
				enable ? "set" : "unset", pi->port_id, i, -err);
		else
			txq->dcb_prio = enable ? value : 0;
	}
}
#endif /* CONFIG_CXGB4_DCB */

int cxgb4_dcb_enabled(const struct net_device *dev)
{
#ifdef CONFIG_CXGB4_DCB
	struct port_info *pi = netdev_priv(dev);

	if (!pi->dcb.enabled)
		return 0;

	return ((pi->dcb.state == CXGB4_DCB_STATE_FW_ALLSYNCED) ||
		(pi->dcb.state == CXGB4_DCB_STATE_HOST));
#else
	return 0;
#endif
}
EXPORT_SYMBOL(cxgb4_dcb_enabled);

/**
 *	t4_os_link_changed - handle link status changes
 *	@adapter: the adapter associated with the link change
 *	@port_id: the port index whose link status has changed
 *	@link_stat: the new status of the link
 *
 *	This is the OS-dependent handler for link status changes.  The OS
 *	neutral handler takes care of most of the processing for these events,
 *	then calls this handler for any OS-specific processing.
 */
void t4_os_link_changed(struct adapter *adapter, int port_id, int link_stat)
{
	struct net_device *dev = adapter->port[port_id];

	/* Skip changes from disabled ports. */
	if (netif_running(dev) && link_stat != netif_carrier_ok(dev)) {
		if (link_stat)
			netif_carrier_on(dev);
		else {
#ifdef CONFIG_CXGB4_DCB
			if (cxgb4_dcb_enabled(dev)) {
				cxgb4_dcb_reset(dev);
				dcb_tx_queue_prio_enable(dev, false);
			}
#endif /* CONFIG_CXGB4_DCB */
			netif_carrier_off(dev);
		}

		link_report(dev);
	}
}

/**
 *	t4_os_portmod_changed - handle port module changes
 *	@adap: the adapter associated with the module change
 *	@port_id: the port index whose module status has changed
 *
 *	This is the OS-dependent handler for port module changes.  It is
 *	invoked when a port module is removed or inserted for any OS-specific
 *	processing.
 */
void t4_os_portmod_changed(struct adapter *adap, int port_id)
{
	static const char *mod_str[] = {
		NULL, "LR", "SR", "ER", "passive DA", "active DA", "LRM",
		"LR_SIMPLEX", "DR"
	};

	struct net_device *dev = adap->port[port_id];
	struct port_info *pi = netdev_priv(dev);

	if (pi->mod_type == FW_PORT_MOD_TYPE_NONE)
		printk(KERN_INFO "%s: port module unplugged\n", dev->name);
	else if (pi->mod_type < ARRAY_SIZE(mod_str))
		printk(KERN_INFO "%s: %s port module inserted\n", dev->name,
		       mod_str[pi->mod_type]);
	else if (pi->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		printk(KERN_INFO "%s: unsupported port module inserted\n",
		       dev->name);
	else if (pi->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		printk(KERN_INFO "%s: unknown port module inserted\n",
		       dev->name);
	else if (pi->mod_type == FW_PORT_MOD_TYPE_ERROR)
		printk(KERN_INFO "%s: transceiver module error\n", dev->name);
	else
		printk(KERN_INFO "%s: unknown module type %d inserted\n",
		       dev->name, pi->mod_type);

	/*
	 * If the interface is running, then we'll need any "sticky" Link
	 * Parameters redone with a new Transceiver Module.
	 */
	pi->link_cfg.redo_l1cfg = netif_running(dev);
}

void cxgb4_work_queue(struct workqueue_struct *workq, struct work_struct *work)
{
	if (!workq)
		return;

	queue_work(workq, work);
}

void cxgb4_work_cancel(struct workqueue_struct *workq, struct work_struct *work)
{
	if (!workq)
		return;

	cancel_work_sync(work);
}

static void cxgb4_workqueues_destroy(struct adapter *adap)
{
	if (adap->eeh_workq) {
		flush_workqueue(adap->eeh_workq);
		destroy_workqueue(adap->eeh_workq);
		adap->eeh_workq = NULL;
	}

	if (adap->workq) {
		flush_workqueue(adap->workq);
		destroy_workqueue(adap->workq);
		adap->workq = NULL;
	}
}

static int cxgb4_workqueues_create(struct adapter *adap)
{
	adap->workq = create_singlethread_workqueue("cxgb4");
	if (!adap->workq)
		return -ENOMEM;

	if (cxgb4_modparam_attempt_err_recovery()) {
		adap->eeh_workq = create_singlethread_workqueue("cxgb4_eeh");
		if (!adap->eeh_workq)
			goto out_free_default_workq;
	}

	return 0;

out_free_default_workq:
	destroy_workqueue(adap->workq);
	adap->workq = NULL;
	return -ENOMEM;
}

static inline int cxgb4_set_addr_hash(struct port_info *pi)
{
	struct adapter *adap = pi->adapter;
	u64 vec = 0;
	bool ucast = false;
	struct hash_mac_addr *entry;

	/* Calculate the hash vector for the updated list and program it */
	list_for_each_entry(entry, &adap->mac_hlist, list) {
		ucast |= is_unicast_ether_addr(entry->addr);
		vec |= (1ULL << hash_mac_addr(entry->addr));
	}
	return t4_set_addr_hash(adap, adap->mbox, pi->viid, ucast,
				vec, false);
}

static int cxgb4_mac_sync(struct net_device *netdev, const u8 *mac_addr)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adap = pi->adapter;
	int ret;
	u64 mhash = 0;
	u64 uhash = 0;
	/**
	 * idx is used to store the index of allocated filters,
	 * its size should be modified based on the number of
	 * MAC addresses that we allocate filters for
	 **/
	u16 idx[1] = {};
	bool free = false;
	bool ucast = is_unicast_ether_addr(mac_addr);
	const u8 *maclist[1] = {mac_addr};
	struct hash_mac_addr *new_entry;

	ret = cxgb_alloc_mac_filt(adap, pi->viid, free, 1, maclist,
				  idx, ucast ? &uhash : &mhash, false);
	if (ret < 0)
		goto out;

	if (cxgb4_modparam_enable_ringbb() && pi->viid_mirror &&
	    is_multicast_ether_addr(mac_addr))
		ret = cxgb_alloc_mac_filt(adap, pi->viid_mirror, free,
					  1, maclist, idx, &mhash, false);
	if (ret < 0)
		goto out;
	/* if hash != 0, then add the addr to hash addr list
	 * so on the end we will calculate the hash for the
	 * list and program it
	 */
	if (uhash || mhash) {
		new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
		if (!new_entry)
			return -ENOMEM;
		ether_addr_copy(new_entry->addr, mac_addr);
		list_add_tail(&new_entry->list, &adap->mac_hlist);
		ret = cxgb4_set_addr_hash(pi);
	}
out:
	return ret < 0 ? ret : 0;
}

static int cxgb4_mac_unsync(struct net_device *netdev, const u8 *mac_addr)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adap = pi->adapter;
	int ret;
	const u8 *maclist[1] = {mac_addr};
	struct hash_mac_addr *entry, *tmp;

	/* If the MAC address to be removed is in the hash addr
	 * list, delete it from the list and update hash vector
	 */
	list_for_each_entry_safe(entry, tmp, &adap->mac_hlist, list) {
		if (ether_addr_equal(entry->addr, mac_addr)) {
			list_del(&entry->list);
			kfree(entry);
			return cxgb4_set_addr_hash(pi);
		}
	}

	ret = cxgb_free_mac_filt(adap, pi->viid, 1, maclist, false);
	if (ret < 0)
		goto out;

	if (cxgb4_modparam_enable_ringbb() && pi->viid_mirror &&
	    is_multicast_ether_addr(mac_addr))
		ret = cxgb_free_mac_filt(adap, pi->viid_mirror, 1,
					 maclist, false);
out:
	return ret < 0 ? -EINVAL : 0;
}

/*
 * Set Rx properties of a port, such as promiscruity, address filters, and MTU.
 * If @mtu is -1 it is left unchanged.
 */
static int set_rxmode(struct net_device *dev, int mtu, bool sleep_ok)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int ret;

	/* synchronize all of the addresses */
	__dev_uc_sync(dev, cxgb4_mac_sync, cxgb4_mac_unsync);
	__dev_mc_sync(dev, cxgb4_mac_sync, cxgb4_mac_unsync);

	ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid, mtu,
			    (dev->flags & IFF_PROMISC) ? 1 : 0,
			    (dev->flags & IFF_ALLMULTI) ? 1 : 0, 1, -1,
			    sleep_ok);
	if (ret < 0)
		goto out;

	if (is_hashfilter(adapter) && enable_mirror) {
		ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid_mirror,
				    mtu, (dev->flags & IFF_PROMISC) ? 1 : 0,
				    (dev->flags & IFF_ALLMULTI) ? 1 : 0, 1, -1,
				    sleep_ok);
	}

	/* Set ringbb mirror vi in all multi mode.
	 * Mirror vi will handle multicast/broadcast packets only
	 */
	if (cxgb4_modparam_enable_ringbb() && !pi->port_id)
		ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid_mirror,
				    mtu, 0, 1, 1, -1,
				    sleep_ok);
out:
	return ret;
}

static void cxgb_set_rxmode(struct net_device *dev)
{
	/* unfortunately we can't return errors to the stack */
	set_rxmode(dev, -1, false);
}

static inline int cxgb_update_smac_addr(struct net_device *dev, const u8 *addr)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	int addr_filt = pi->xact_addr_filt;
	int ret = 0, i;

	for_each_port(adap, i) {
		pi = adap2pinfo(adap, i);
		/* First delete old entry from smac region */
		if (addr_filt >= 0) {
			ret = cxgb_del_mac(adap, pi->viid,
					 dev->dev_addr, true);
			if (ret < 0)
				return ret;
		}

		ret = cxgb_add_mac(adap, pi, FW_VI_MAC_ADD_PERSIST_MAC,
				   addr, true, true);
	}
	return ret;
}

/**
 *	cxgb4_change_mac - Update match filter for a MAC address.
 *	@pi: the port_info
 *	@viid: the VI id
 *	@tcam_idx: TCAM index of existing filter for old value of MAC address,
 *		   or -1
 *	@addr: the new MAC address value
 *	@persist: whether a new MAC allocation should be persistent
 *	@add_smt: if true also add the address to the HW SMT
 *
 *	Modifies an MPS filter and sets it to the new MAC address if
 *	@tcam_idx >= 0, or adds the MAC address to a new filter if
 *	@tcam_idx < 0. In the latter case the address is added persistently
 *	if @persist is %true.
 *	Addresses are programmed to hash region, if tcam runs out of entries.
 *
 */
int cxgb4_change_mac(struct port_info *pi, unsigned int viid,
		     int *tcam_idx, const u8 *addr,
		     bool persistent, u8 *smt_idx)
{
	struct adapter *adapter = pi->adapter;
	struct hash_mac_addr *entry, *new_entry;
	int ret;

	ret = t4_change_mac(adapter, adapter->mbox, viid,
			    *tcam_idx, addr, persistent, smt_idx);
	/* We ran out of TCAM entries. try programming hash region. */
	if (ret == -ENOMEM) {
		/* If the MAC address to be updated is in the hash addr
		 * list, update it from the list
		 */
		list_for_each_entry(entry, &adapter->mac_hlist, list) {
			if (entry->iface_mac) {
				ether_addr_copy(entry->addr, addr);
				goto set_hash;
			}
		}
		new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
		if (!new_entry)
			return -ENOMEM;
		ether_addr_copy(new_entry->addr, addr);
		new_entry->iface_mac = true;
		list_add_tail(&new_entry->list, &adapter->mac_hlist);
set_hash:
		ret = cxgb4_set_addr_hash(pi);
	} else if (ret >= 0) {
		*tcam_idx = ret;
		ret = 0;
	}

	return ret;
}

/*
 *	link_start - enable a port
 *	@dev: the port to enable
 *
 *	Performs the MAC and PHY actions needed to enable a port.
 */
static int link_start(struct net_device *dev)
{
	int ret, idx = -1;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	/*
	 * We do not set address filters and promiscuity here, the stack does
	 * that step explicitly.
	 */
	ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid, dev->mtu, -1, -1,
			    -1, !!(dev->features & NETIF_F_HW_VLAN_CTAG_RX),
			    true);
	if (ret == 0) {
		ret = cxgb4_update_mac_filt(pi, pi->viid, &pi->xact_addr_filt,
				      dev->dev_addr, true, &pi->smt_idx);
		if (!ret) {
			int smac_ret;

			if (adapter->params.smac_add_support) {
				smac_ret = cxgb_update_smac_addr(dev,
								 dev->dev_addr);
				if (smac_ret < 0) {
					dev_err(adapter->pdev_dev,
						"SMAC update failed with error %d\n",
						smac_ret);
					return smac_ret;
				}
			}
		} else {
			return ret;
		}

		if (is_hashfilter(adapter) && enable_mirror) {
			ret = cxgb4_update_mac_filt(pi, pi->viid_mirror, &idx,
					      dev->dev_addr, true,
					      &pi->smt_idx_mirror);
		}
	}
	if (ret == 0)
		ret = t4_link_l1cfg(adapter, adapter->mbox, pi->lport,
				    &pi->link_cfg);
	if (ret == 0) {
		/*
		 * Enabling a Virtual Interface can result in an interrupt
		 * during the processing of the VI Enable command and, in some
		 * paths, result in an attempt to issue another command in the
		 * interrupt context.  Thus, we disable interrupts during the
		 * course of the VI Enable command ...
		 */

		local_bh_disable();
		ret = t4_enable_pi_params(adapter, adapter->mbox, pi,
					  true, true, CXGB4_DCB_ENABLED);
		if (is_hashfilter(adapter) && enable_mirror) {
			ret = t4_enable_vi_params(adapter, adapter->mbox,
						  pi->viid_mirror,
						  true, true, false);
		}

		if (cxgb4_modparam_enable_ringbb()) {
			/* For ring backbone configuration, port0 will always
			 * receive and port1 will always send. Hence setting
			 * tx/rx channel values appropriately.
			 */
			pi->tx_chan = t4_get_tp_port_chan(adapter, 1);
			pi->rx_chan = t4_get_tp_port_chan(adapter, 0);

			if (!pi->port_id) {
				ret = t4_enable_vi_params(adapter,
							  adapter->mbox,
							  pi->viid_mirror,
							  true, true, false);
			}
		}
		local_bh_enable();
	}

	return ret;
}

#ifdef CONFIG_CXGB4_DCB
/* Handle a Data Center Bridging update message from the firmware. */
static void dcb_rpl(struct adapter *adap, const struct fw_port_cmd *pcmd)
{
	int port = G_FW_PORT_CMD_PORTID(ntohl(pcmd->op_to_portid));
	int old_dcb_enabled, new_dcb_enabled;
	struct net_device *dev;

	dev = cxgb4_port_chan_to_netdev(adap, port);
	if (!dev) {
		dev_warn(adap->pdev_dev,
			 "Could not get netdevice for handling dcb_rpl for port %d\n",
			 port);
		return;
	}

	old_dcb_enabled = cxgb4_dcb_enabled(dev);

	cxgb4_dcb_handle_fw_update(adap, pcmd);
	new_dcb_enabled = cxgb4_dcb_enabled(dev);

	/* If the DCB has become enabled or disabled on the port then we're
	 * going to need to set up/tear down DCB Priority parameters for the
	 * TX Queues associated with the port.
	 */
	if (new_dcb_enabled != old_dcb_enabled)
		dcb_tx_queue_prio_enable(dev, new_dcb_enabled);
}
#endif /* CONFIG_CXGB4_DCB */

/* Response queue handler for the FW event queue.
 */
static int fwevtq_handler(struct sge_rspq *q, const __be64 *rsp,
			  const struct pkt_gl *gl)
{
	u8 opcode = ((const struct rss_header *)rsp)->opcode;

	rsp++;                                          /* skip RSS header */

	/* FW can send EGR_UPDATEs encapsulated in a CPL_FW4_MSG.
	 */
	if (unlikely(opcode == CPL_FW4_MSG &&
	   ((const struct cpl_fw4_msg *)rsp)->type == FW_TYPE_RSSCPL)) {
		rsp++;
		opcode = ((const struct rss_header *)rsp)->opcode;
		rsp++;
		if (opcode != CPL_SGE_EGR_UPDATE) {
			CH_ERR(q->adap,
				"unexpected FW4/CPL %#x on FW event queue\n",
				opcode);
			goto out;
		}
	}

#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	if (unlikely(opcode == CPL_FW6_MSG &&
	    ((const struct cpl_fw6_msg *)rsp)->type == FW_TYPE_IPSEC_SA)) {
		struct cxgb4_uld_info *uld = &cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC];

		uld->rx_handler(q->adap->uld_handle[CXGB4_ULD_TYPE_IPSEC],
				rsp, gl);
		goto out;
	}
#endif /* CONFIG_CHELSIO_T4_IPSEC_INLINE */

	if (likely(opcode == CPL_SGE_EGR_UPDATE)) {
		const struct cpl_sge_egr_update *p = (void *)rsp;
		unsigned int qid = G_EGR_QID(ntohl(p->opcode_qid));
		struct sge_txq *txq;

		txq = cxgb4_sge_egr_map_get(&q->adap->sge.egr_map, qid);
		if (txq->q_type == CXGB4_TXQ_ETH) {
			struct sge_eth_txq *eq;

			eq = container_of(txq, struct sge_eth_txq, q);
			t4_sge_eth_txq_egress_update(q->adap, eq, -1, false);
		} else {
			struct sge_ofld_txq *oq;

			txq->restarts++;
			oq = container_of(txq, struct sge_ofld_txq, q);
			tasklet_schedule(&oq->qresume_tsk);
		}
	} else if (opcode == CPL_FW6_MSG || opcode == CPL_FW4_MSG) {
		const struct cpl_fw6_msg *msg = (void *)rsp;
#ifdef CONFIG_CXGB4_DCB
		const struct fw_port_cmd *pcmd;
		unsigned int cmd;
		unsigned int action;
#endif

		if (msg->type == FW_TYPE_WRERR_RPL) {
			u16 pfn_vfn;
			const struct fw_error_cmd *cmd =
						(const void *)msg->data;

			opcode =
			      G_FW_ERROR_CMD_TYPE(be32_to_cpu(cmd->op_to_type));
			pfn_vfn = be16_to_cpu(cmd->u.acl.pfn_vfn);

			if (printk_ratelimit()) {
				if (opcode == FW_ERROR_TYPE_ACL)
					dev_warn(q->adap->pdev_dev,
						"ACL error received for "
						"Tx ring %u of pf%u-vf%u\n",
						be32_to_cpu(cmd->u.acl.eqid),
						G_FW_ERROR_CMD_PFN(pfn_vfn),
						G_FW_ERROR_CMD_VFN(pfn_vfn));
				else
					dev_warn(q->adap->pdev_dev,
						"Unknowm firmware wr error "
						"reply %d\n", opcode);
			}
			goto out;
		}

#ifdef CONFIG_CXGB4_DCB
		/*
		 * This might be a PORT command with a DCB update ... this
		 * simplifies the following conditionals ...  We can get away
		 * with pre-dereferencing op_to_portid and action_to_len16
		 * because they're both in the first 16 bytes and all messages
		 * will be at least that long.
		 */
		pcmd = (const void *)msg->data;
		cmd = G_FW_CMD_OP(ntohl(pcmd->op_to_portid));
		action = G_FW_PORT_CMD_ACTION(ntohl(pcmd->action_to_len16));

		/*
		 * If this is a DCB update from the firmware, process it.
		 * Otherwise throw the message at the general firmware reply
		 * handler.  We also catch the DCB Disabled/not Disabled from
		 * the general Port Information message to drive the DCB state
		 * machine.  (And yes, we could skip the #ifdef here since
		 * cxgb4_handle_fw_dcb_update() is defined to be a no-op.  But
		 * doing it this way will cause any Data Center Bridging
		 * messages we receive from the firmware to be sent to the
		 * general firmware reply handler which will then issue a
		 * warning about the unexpected messages.  Which may help
		 * someone realize that they need to turn DCB support on in
		 * the driver ...)
		 */
		if (cmd == FW_PORT_CMD &&
		    (action == FW_PORT_ACTION_GET_PORT_INFO ||
		     action == FW_PORT_ACTION_GET_PORT_INFO32)) {
			int port = G_FW_PORT_CMD_PORTID(
					be32_to_cpu(pcmd->op_to_portid));
			int dcbxdis, state_input;
			struct net_device *dev;

			dev = cxgb4_port_chan_to_netdev(q->adap, port);
			if (!dev) {
				dev_warn(q->adap->pdev_dev,
					 "Could not get netdevice for handling DCB event for port %d\n",
					 port);
				goto out;
			}

			dcbxdis = (action == FW_PORT_ACTION_GET_PORT_INFO
			? !!(pcmd->u.info.dcbxdis_pkd &
			     F_FW_PORT_CMD_DCBXDIS)
			: !!(be32_to_cpu(pcmd->u.info32.lstatus32_to_cbllen32) &
			     F_FW_PORT_CMD_DCBXDIS32));
			state_input = (dcbxdis
				       ? CXGB4_DCB_INPUT_FW_DISABLED
				       : CXGB4_DCB_INPUT_FW_ENABLED);

			cxgb4_dcb_state_fsm(dev, state_input);
		}

		if (cmd == FW_PORT_CMD &&
		    action == FW_PORT_ACTION_L2_DCB_CFG)
			dcb_rpl(q->adap, pcmd);
		else
#endif
			t4_handle_fw_rpl(q->adap, msg->data);
	} else if (opcode == CPL_SET_TCB_RPL) {
		const struct cpl_set_tcb_rpl *p = (void *)rsp;

		cxgb4_filter_normal_rpl(q->adap, p);
	} else if (opcode == CPL_ACT_OPEN_RPL) {
		const struct cpl_act_open_rpl *p = (void *)rsp;

		cxgb4_filter_hash_create_rpl(q->adap, p);
	} else if (opcode == CPL_ABORT_RPL_RSS) {
		const struct cpl_abort_rpl_rss *p = (void *)rsp;

		cxgb4_filter_hash_delete_rpl(q->adap, p);
	} else if (opcode == CPL_SMT_WRITE_RPL) {
		const struct cpl_smt_write_rpl *p = (void *)rsp;

		do_smt_write_rpl(q->adap, p);
        } else if (opcode == CPL_L2T_WRITE_RPL) {
		const struct cpl_l2t_write_rpl *p = (void *)rsp;

		do_l2t_write_rpl(q->adap, p);
	} else if (opcode == CPL_SRQ_TABLE_RPL) {
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		const struct cpl_srq_table_rpl *p = (void *)rsp;

		do_srq_table_rpl(q->adap, p);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	} else {
		CH_ERR(q->adap,
			"unexpected CPL %#x on FW event queue\n", opcode);
	}
out:
	return 0;
}

#ifdef CONFIG_T4_MA_FAILOVER
static int uldma_failover_handler(struct sge_rspq *q, const __be64 *rsp,
               const struct pkt_gl *gl)
{
       if (cxgb4_ulds[q->uld].ma_failover_handler(q->adap->uld_handle[q->uld], rsp, gl)) {
               return -1;
       }
       return 0;
}
#endif /* CONFIG_T4_MA_FAILOVER */

#ifdef CONFIG_CHELSIO_T4_OFFLOAD

/* Flush the aggregated lro sessions */
static void uldrx_flush_handler(struct sge_rspq *q)
{
	if (cxgb4_ulds[q->uld].lro_flush)
		cxgb4_ulds[q->uld].lro_flush(&q->lro_mgr);
}

/**
 *	uldrx_handler - response queue handler for ULD queues
 *	@q: the response queue that received the packet
 *	@rsp: the response queue descriptor holding the offload message
 *	@gl: the gather list of packet fragments
 *
 *	Deliver an ingress offload packet to a ULD.  All processing is done by
 *	the ULD, we just maintain statistics.
 */
static int uldrx_handler(struct sge_rspq *q, const __be64 *rsp,
			 const struct pkt_gl *gl)
{
	struct sge_ofld_rxq *rxq = container_of(q, struct sge_ofld_rxq, rspq);
	int ret;

	/* FW can send CPLs encapsulated in a CPL_FW4_MSG.
	 */
	if (((const struct rss_header *)rsp)->opcode == CPL_FW4_MSG &&
	    ((const struct cpl_fw4_msg *)(rsp + 1))->type == FW_TYPE_RSSCPL)
		rsp += 2;

	if (q->flush_handler)
		ret = cxgb4_ulds[q->uld].lro_rx_handler(q->adap->uld_handle[q->uld],
							rsp, gl, &q->lro_mgr,
							&q->napi);
	else
		ret = cxgb4_ulds[q->uld].rx_handler(q->adap->uld_handle[q->uld],
					      rsp, gl);

	if (ret) {
		rxq->stats.nomem++;
		return -1;
	}
	if (gl == NULL)
		rxq->stats.imm++;
	else if (gl == CXGB4_MSG_AN)
		rxq->stats.an++;
	else
		rxq->stats.pkts++;
	return 0;
}
#endif

static void cxgb4_disable_irqs(struct adapter *adapter)
{
	cxgb4_common_free_irqs(adapter);
	adapter->flags &= ~(USING_INTR_MULTI | USING_INTR_SINGLE);
}

/*
 * Interrupt handler for non-data events used with MSI-X.
 */
static irqreturn_t t4_nondata_intr(int irq, void *cookie)
{
	struct adapter *adap = cookie;

	u32 v = t4_read_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE));
	if (v & F_PFSW) {
		adap->swintr = 1;
		t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE), v);
	}
	if (adap->flags & MASTER_PF)
		t4_slow_intr_handler(adap);
	return IRQ_HANDLED;
}

/*
 * Name the MSI-X interrupts.
 */
static void name_msix_vecs(struct adapter *adap)
{
	int i, j, msi_idx = 2, n = sizeof(adap->msix_info[0].desc);

	/* non-data interrupts */
	snprintf(adap->msix_info[0].desc, n, "%s", adap->name);

	/* FW events */
	snprintf(adap->msix_info[1].desc, n, "%s-FWeventq", adap->name);

	/* Ethernet queues */
	for_each_port(adap, j) {
		struct net_device *d = adap->port[j];
		const struct port_info *pi = netdev_priv(d);

		for (i = 0; i < pi->nqsets; i++, msi_idx++)
			snprintf(adap->msix_info[msi_idx].desc, n,
				 "%s (queue %d)", d->name, i);
	}

	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq) {
		for_each_tracerxq(&adap->sge, i) {
		       snprintf(adap->msix_info[msi_idx++].desc, n,
				"%s-traceq%d", adap->name, i);
		}
	}

	if (is_hashfilter(adap) && enable_mirror) {
		for_each_port(adap, j) {
			struct net_device *d = adap->port[j];
			const struct port_info *pi = netdev_priv(d);

			for (i = 0; i < pi->nqsets; i++, msi_idx++)
				snprintf(adap->msix_info[msi_idx].desc, n,
					 "%s-mirrorq%d", d->name, i);
		}
	}

	/* offload queues */
	for_each_ofldrxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-ofld%d",
			 adap->name, i);

	for_each_rdmarxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-rdma%d",
			 adap->name, i);

	for_each_rdmaciq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-rdma-ciq%d",
			 adap->name, i);

	for_each_iscsirxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-iSCSI%d",
			 adap->name, i);
	for_each_iscsitrxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-iSCSIT%d",
			 adap->name, i);
	for_each_nvmehrxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-nvmeh%d",
			 adap->name, i);
	for_each_nvmetrxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-nvmet%d",
			 adap->name, i);
	for_each_cstorrxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-cstor%d",
			 adap->name, i);
	for_each_cstorciq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-cstor-ciq%d",
			 adap->name, i);
	for_each_cryptorxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-crypto%d",
			 adap->name, i);
#ifdef CONFIG_T4_MA_FAILOVER
	if (adap->sge.nfailoverq) {
		/* MA-Failover queue */
		snprintf(adap->msix_info[msi_idx].desc, n, "%s-ma-failoverq",
			 adap->name);
	}
#endif /* CONFIG_T4_MA_FAILOVER */

}

static int cxgb4_set_msix_aff(struct adapter *adap, unsigned short vec,
			      cpumask_var_t *aff_mask, int idx)
{
	int rv;

	if (!zalloc_cpumask_var(aff_mask, GFP_KERNEL)) {
		dev_err(adap->pdev_dev, "alloc_cpumask_var failed\n");
		return -ENOMEM;
	}

	cpumask_set_cpu(cpumask_local_spread(idx, dev_to_node(adap->pdev_dev)),
			*aff_mask);

	rv = irq_set_affinity_hint(vec, *aff_mask);
	if (rv)
		dev_warn(adap->pdev_dev,
			 "irq_set_affinity_hint %u failed %d\n",
			 vec, rv);

	return 0;
}

static inline void cxgb4_clear_msix_aff(unsigned short vec, cpumask_var_t aff_mask)
{
	irq_set_affinity_hint(vec, NULL);
	free_cpumask_var(aff_mask);
}

/* Function to clear msix cxgb4 affinity and clear interrupt requests
 */
static inline void free_msi_aff_and_irq(struct msix_info *minfo, struct sge_rspq *rspq)
{
	cxgb4_clear_msix_aff(minfo->vec, minfo->aff_mask);
	free_irq(minfo->vec, rspq);
}

static int request_msix_queue_irqs(struct adapter *adap)
{
	struct sge *s = &adap->sge;
	struct msix_info *minfo;
	int msi_index = 2;
	int err, ethqidx;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	int ofldqidx = 0, rdmaqidx = 0, rdmaciqqidx = 0, iscsiqidx = 0;
	int iscsitqidx = 0, nvmehqidx = 0, nvmetqidx = 0;
	int cstorqidx = 0, cstorciqqidx = 0;
#endif
	int mirrorqidx = 0;
	int cryptoqidx = 0;
	int traceqidx = 0;

	err = request_irq(adap->msix_info[1].vec, t4_sge_intr_msix, 0,
			  adap->msix_info[1].desc, &s->fw_evtq);
	if (err)
		return err;

	for_each_ethrxq(s, ethqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->ethrxq[ethqidx].rspq);
		if (err)
			goto unwind;

		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, ethqidx);
		msi_index++;
	}

	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq) {
		for_each_tracerxq(s, traceqidx) {
			err = request_irq(adap->msix_info[msi_index].vec,
					  t4_sge_intr_msix, 0,
					  adap->msix_info[msi_index].desc,
					  &s->traceq[traceqidx].rspq);
			if (err) {
				printk("%s: got error for traceq[%d].rspq, err = %d\n",
					__func__, traceqidx, err);
				goto unwind;
			}
			msi_index++;
		}
	}

	if (is_hashfilter(adap) && enable_mirror) {
		for_each_mirrorrxq(s, mirrorqidx) {
			err = request_irq(adap->msix_info[msi_index].vec,
					  t4_sge_intr_msix, 0,
					  adap->msix_info[msi_index].desc,
					  &s->mirrorq[mirrorqidx].rspq);
			if (err)
				goto unwind;
			msi_index++;
		}
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	for_each_ofldrxq(s, ofldqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->ofldrxq[ofldqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, ofldqidx);
		msi_index++;
	}

	for_each_rdmarxq(s, rdmaqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->rdmarxq[rdmaqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, rdmaqidx);
		msi_index++;
	}

	for_each_rdmaciq(s, rdmaciqqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->rdmaciq[rdmaciqqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, rdmaciqqidx);
		msi_index++;
	}

	for_each_iscsirxq(s, iscsiqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->iscsirxq[iscsiqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, iscsiqidx);
		msi_index++;
	}

	for_each_iscsitrxq(s, iscsitqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->iscsitrxq[iscsitqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, iscsitqidx);
		msi_index++;
	}

	for_each_nvmehrxq(s, nvmehqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->nvmehrxq[nvmehqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, nvmehqidx);
		msi_index++;
	}

	for_each_nvmetrxq(s, nvmetqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->nvmetrxq[nvmetqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, nvmetqidx);
		msi_index++;
	}

	for_each_cstorrxq(s, cstorqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->cstorrxq[cstorqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, cstorqidx);
		msi_index++;
	}

	for_each_cstorciq(s, cstorciqqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->cstorciq[cstorciqqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, cstorciqqidx);
		msi_index++;
	}

	for_each_cryptorxq(s, cryptoqidx) {
		minfo = &adap->msix_info[msi_index];
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &s->cryptorxq[cryptoqidx].rspq);
		if (err)
			goto unwind;
		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, cryptoqidx);
		msi_index++;
	}
#ifdef CONFIG_T4_MA_FAILOVER
	if (s->nfailoverq) {
		err = request_irq(adap->msix_info[msi_index].vec,
				  t4_sge_intr_msix, 0,
				  adap->msix_info[msi_index].desc,
				  &s->failoverq.rspq);
		if (err)
			goto unwind;
	}
#endif /* CONFIG_T4_MA_FAILOVER */
#endif

	return 0;

unwind:
	if (adap->params.ulp_crypto & ULP_CRYPTO_LOOKASIDE) {
		while (--cryptoqidx >= 0)
			free_msi_aff_and_irq(&adap->msix_info[--msi_index],
					     &s->cryptorxq[cryptoqidx].rspq);
	}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	while (--cstorciqqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->cstorciq[cstorciqqidx].rspq);
	while (--cstorqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->cstorrxq[cstorqidx].rspq);
	while (--nvmetqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->nvmetrxq[nvmetqidx].rspq);
	while (--nvmehqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->nvmehrxq[nvmehqidx].rspq);
	while (--iscsitqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->iscsitrxq[iscsitqidx].rspq);
	while (--iscsiqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->iscsirxq[iscsiqidx].rspq);
	while (--rdmaciqqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->rdmaciq[rdmaciqqidx].rspq);
	while (--rdmaqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->rdmarxq[rdmaqidx].rspq);
	while (--ofldqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->ofldrxq[ofldqidx].rspq);
#endif
	while (--mirrorqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->mirrorq[mirrorqidx].rspq);
	while (--traceqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->traceq[traceqidx].rspq);
	while (--ethqidx >= 0)
		free_msi_aff_and_irq(&adap->msix_info[--msi_index],
				     &s->ethrxq[ethqidx].rspq);
	free_irq(adap->msix_info[1].vec, &s->fw_evtq);
	return err;
}

static void free_msix_queue_irqs(struct adapter *adap)
{
	struct sge *s = &adap->sge;
	int i, msi_index = 2;

	free_irq(adap->msix_info[1].vec, &s->fw_evtq);
	for_each_ethrxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->ethrxq[i].rspq);
	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq)
		for_each_tracerxq(s, i)
			free_irq(adap->msix_info[msi_index++].vec, &s->traceq[i].rspq);
	if (is_hashfilter(adap) && enable_mirror)
		for_each_mirrorrxq(s, i)
			free_irq(adap->msix_info[msi_index++].vec,
				 &s->mirrorq[i].rspq);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	for_each_ofldrxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->ofldrxq[i].rspq);
	for_each_rdmarxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->rdmarxq[i].rspq);
	for_each_rdmaciq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->rdmaciq[i].rspq);
	for_each_iscsirxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->iscsirxq[i].rspq);
	for_each_iscsitrxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->iscsitrxq[i].rspq);
	for_each_nvmehrxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->nvmehrxq[i].rspq);
	for_each_nvmetrxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->nvmetrxq[i].rspq);
	for_each_cstorrxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->cstorrxq[i].rspq);
	for_each_cstorciq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->cstorciq[i].rspq);
	for_each_cryptorxq(s, i)
		free_msi_aff_and_irq(&adap->msix_info[msi_index++],
				     &s->cryptorxq[i].rspq);
#ifdef CONFIG_T4_MA_FAILOVER
	if (s->nfailoverq)
		free_irq(adap->msix_info[msi_index].vec, &s->failoverq.rspq);
#endif /* CONFIG_T4_MA_FAILOVER */
#endif
}

static int setup_ppod_edram(struct adapter *adap)
{
	int ret;
	unsigned int param, val;

	/*
	 * Driver sends FW_PARAMS_PARAM_DEV_PPOD_EDRAM read command to check
	 * if fw supports ppod edram feature or not. If fw returns 1, then driver
	 * can enable this feature by sending
	 * FW_PARAMS_PARAM_DEV_PPOD_EDRAM write command with value 1 to 
	 * enable ppod edram feature.
	 */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_PPOD_EDRAM));

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &param, &val);
	if (ret < 0) {
		dev_warn(adap->pdev_dev,
			 "querying PPOD_EDRAM support failed: %d\n",
			 ret);
		return -1;
	}

	if (val != 1)
		return -1;

	ret = t4_set_params(adap, adap->mbox, adap->pf, 0, 1, &param, &val);
	if (ret < 0) {
		dev_err(adap->pdev_dev,
			"setting PPOD_EDRAM failed: %d\n", ret);
		return -1;
 	}

	return 0;
}

/**
 *	cxgb4_write_rss - write the RSS table for a given port
 *	@pi: the port
 *	@queues: array of queue indices for RSS
 *
 *	Sets up the portion of the HW RSS table for the port's VI to distribute
 *	packets to the Rx queues in @queues.
 *	Should never be called before setting up sge eth rx queues
 */
int cxgb4_write_rss(const struct port_info *pi, const u16 *queues, bool mirror)
{
	u16 *rss;
	int i, err;
	struct adapter *adapter = pi->adapter;
	const struct sge_eth_rxq *rxq;

	if (mirror)
		rxq = &adapter->sge.mirrorq[pi->first_qset];
	else
		rxq = &adapter->sge.ethrxq[pi->first_qset];

	rss = kmalloc(pi->rss_size * sizeof(u16), GFP_KERNEL);
	if (!rss)
		return -ENOMEM;

	/* map the queue indices to queue ids */
	for (i = 0; i < pi->rss_size; i++, queues++)
		rss[i] = rxq[*queues].rspq.abs_id;

	err = t4_config_rss_range(adapter, adapter->pf,
				  mirror ? pi->viid_mirror : pi->viid, 0,
				  pi->rss_size, rss, pi->rss_size);
	/* If Tunnel All Lookup isn't specified in the global RSS
	 * Configuration, then we need to specify a default Ingress
	 * Queue for any ingress packets which aren't hashed.  We'll
	 * use our first ingress queue ...
	 */
	if (!err)
		err = t4_config_vi_rss(adapter, adapter->mbox,
				       mirror ? pi->viid_mirror : pi->viid,
				       F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_IP6TWOTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_IP4TWOTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_UDPEN,
				       rss[0], 0 , 0);
	kfree(rss);
	return err;
}

/**
 *	setup_rss - configure RSS
 *	@adap: the adapter
 *
 *	Sets up RSS to distribute packets to multiple receive queues.  We
 *	configure the RSS CPU lookup table to distribute to the number of HW
 *	receive queues, and the response queue lookup table to narrow that
 *	down to the response queues actually configured for each port.
 *	We always configure the RSS mapping for all ports since the mapping
 *	table has plenty of entries.
 */
static int setup_rss(struct adapter *adap)
{
	int i, j, err;
#ifdef CONFIG_PO_FCOE
	u32 rss_config;
#endif

	for_each_port(adap, i) {
		const struct port_info *pi = adap2pinfo(adap, i);

		/* Fill default values with equal distribution */
		for (j = 0; j < pi->rss_size; j++)
			pi->rss[j] = j % pi->nqsets;

		err = cxgb4_write_rss(pi, pi->rss, false);
		if (err)
			return err;

		if (is_hashfilter(adap) && enable_mirror) {
			err = cxgb4_write_rss(pi, pi->rss, true);
			if (err)
				return err;
		}
	}

#ifdef CONFIG_PO_FCOE
	rss_config = t4_read_reg(adap, A_TP_RSS_CONFIG);
	rss_config |= F_TNLFCOEEN | F_TNLFCOEMODE;
	t4_write_reg(adap, A_TP_RSS_CONFIG, rss_config);
#endif
	return 0;
}

/*
 * Wait until all NAPI handlers are descheduled.
 */
static void quiesce_rx(struct adapter *adap)
{
	int i;

	for (i = 0; i < adap->sge.ingr_sz; i++) {
		struct sge_rspq *q = adap->sge.ingr_map[i];

		if (q && q->handler) {
			napi_disable(&q->napi);
		}

	}
}

/* Disable interrupt and napi handler */
static void disable_interrupts(struct adapter *adap)
{
	if (adap->flags & FULL_INIT_DONE) {
		t4_intr_disable(adap);
		if (adap->flags & USING_INTR_MULTI) {
			free_msix_queue_irqs(adap);
			free_irq(adap->msix_info[0].vec, adap);
		} else {
			free_irq(adap->msix_info[0].vec, adap);
		}
	}
}

/*
 * Enable NAPI scheduling and interrupt generation for all Rx queues.
 */
static void enable_rx(struct adapter *adap)
{
	int i;

	for (i = 0; i < adap->sge.ingr_sz; i++) {
		struct sge_rspq *q = adap->sge.ingr_map[i];

		if (!q)
			continue;
		if (q->handler)
			napi_enable(&q->napi);
		/* 0-increment GTS to start the timer and enable interrupts */
		t4_write_reg(adap, MYPF_REG(A_SGE_PF_GTS),
			     V_SEINTARM(q->intr_params) |
			     V_INGRESSQID(q->cntxt_id));
	}
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static int alloc_ofld_rxqs(struct adapter *adap, struct sge_ofld_rxq *q,
			   unsigned int nq, unsigned int per_chan, int msi_idx,
			   u16 *ids, u8 lro)
{
	int i, err;

	for (i = 0; i < nq; i++, q++) {
		if (msi_idx > 0)
			msi_idx++;
		err = t4_sge_alloc_rxq(adap, &q->rspq, false,
				       adap->port[i / per_chan],
				       msi_idx, q->fl.size ? &q->fl : NULL,
				       uldrx_handler,
				       lro ? uldrx_flush_handler : NULL, 0,
				       false);
		if (err)
			return err;
		memset(&q->stats, 0, sizeof(q->stats));
		if (ids)
			ids[i] = q->rspq.abs_id;
	}
	return 0;
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/**
 *	setup_sge_queues - configure SGE Tx/Rx/response queues
 *	@adap: the adapter
 *
 *	Determines how many sets of SGE queues to use and initializes them.
 *	We support multiple queue sets per port if we have MSI-X, otherwise
 *	just one queue set per port.
 */
static int setup_sge_queues(struct adapter *adap)
{
	struct sge *s = &adap->sge;
	int err, msi_idx, i, j;

	bitmap_zero(s->starving_fl, s->egr_sz);

	if (adap->flags & USING_INTR_MULTI) {
		msi_idx = 1;         /* vector 0 is for non-queue interrupts */
	} else {
		err = t4_sge_alloc_rxq(adap, &s->intrq, false, adap->port[0], 0,
				       NULL, NULL, NULL, -1, false);
		if (err)
			goto freeout;
		msi_idx = -((int)s->intrq.abs_id + 1);
	}

	/* NOTE: If you add/delete any Ingress/Egress Queue allocations in here,
	 * don't forget to update the following which need to be
	 * synchronized to and changes here.
	 *
	 * 1. The calculations of MAX_INGQ in adapter.h.
	 *
	 * 2. Update cxgb_enable_msix/name_msix_vecs/request_msix_queue_irqs
	 *    to accommodate any new/deleted Ingress Queues
	 *    which need MSI-X Vectors.
	 *
	 * 3. Update sge_qinfo_show() to include information on the
	 *    new/deleted queues.
	 */
	err = t4_sge_alloc_rxq(adap, &s->fw_evtq, true, adap->port[0],
			       msi_idx, NULL, fwevtq_handler, NULL, -1, false);
	if (err)
		goto freeout;

	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];
		struct port_info *pi = netdev_priv(dev);
		struct sge_eth_rxq *q = &s->ethrxq[pi->first_qset];
		struct sge_eth_txq *t = &s->ethtxq[pi->first_qset];

		for (j = 0; j < pi->nqsets; j++, q++) {
			if (msi_idx > 0)
				msi_idx++;
			err = t4_sge_alloc_rxq(adap, &q->rspq, false, dev,
					       msi_idx, &q->fl,
					       t4_ethrx_handler, NULL,
					       t4_get_tp_ch_map(adap, pi->lport),
					       false);
			if (err)
				goto freeout;
			q->rspq.idx = j;
			memset(&q->stats, 0, sizeof(q->stats));

#if IS_ENABLED(CONFIG_VXLAN)
			memset(&q->hdr_buf, 0, sizeof(q->hdr_buf));
			if (is_t5(adap->params.chip))
				refill_vxlan_hdr_buf(adap, q, GFP_KERNEL);
#endif
		}

		q = &s->ethrxq[pi->first_qset];
		for (j = 0; j < pi->nqsets; j++, t++, q++) {
			err = t4_sge_alloc_eth_txq(adap, t, dev,
					netdev_get_tx_queue(dev, j),
					q->rspq.cntxt_id,
					!!(adap->flags & SGE_DBQ_TIMER));
			if (err)
				goto freeout;
		}
#if IS_ENABLED(CONFIG_VXLAN)
		if (is_t5(adap->params.chip)) {
			struct netdev_queue *netdevq;
			unsigned int iqid;

			t = &s->vxlantxq[pi->first_qset];
			iqid = s->fw_evtq.cntxt_id;

			/* Create a transmit queue to loopback vxlan packets
			 * for verifying checksum. We will create as many
			 * vxlan txqs as we have regular ethernet rxqs.
			 */
			s->nvxlanq += pi->nqsets;
			for (j = 0; j < pi->nqsets; j++, t++) {
				netdevq = netdev_get_tx_queue(dev, j);
				err = t4_sge_alloc_eth_txq(adap, t, dev,
							   netdevq, iqid,
							   false);
				if (err)
					goto freeout;
				t->q.lb_queue_type = CXGB4_TXQ_LB_TYPE_VXLAN;
			}
		}
#endif
	}

	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq) {
		j = s->ntraceq / adap->params.nports;
		for_each_tracerxq(s, i) {
			err = t4_sge_alloc_rxq(adap, &(s->traceq[i].rspq),
					       false,
					       adap->port[j ? (i / j) : i],
					       ++msi_idx, &(s->traceq[i].fl),
					       t4_trace_handler, NULL, 0,
					       false);
			if (err)
				goto freeout;
			memset(&s->traceq[i].stats, 0, sizeof(s->traceq[i].stats));
		}
	}

	if (is_hashfilter(adap) && enable_mirror) {
		for_each_port(adap, i) {
			struct net_device *dev = adap->port[i];
			struct port_info *pi = netdev_priv(dev);
			struct sge_eth_rxq *q = &s->mirrorq[pi->first_qset];

			for (j = 0; j < pi->nqsets; j++, q++) {
				if (msi_idx > 0)
					msi_idx++;

				err = t4_sge_alloc_rxq(adap, &q->rspq, false,
						       dev, msi_idx, &q->fl,
						       t4_ethrx_handler, NULL,
						       0, true);
				if (err)
					goto freeout;
				q->rspq.idx = j;
				memset(&q->stats, 0, sizeof(q->stats));
			}
		}
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	j = s->ofldqsets / adap->params.nports; /* ofld queues per channel */

#define ALLOC_OFLD_RXQS(firstq, nq, per_chan, ids, lro) do { \
	err = alloc_ofld_rxqs(adap, firstq, nq, per_chan, msi_idx, ids, lro); \
	if (err) \
		goto freeout; \
	if (msi_idx > 0) \
		msi_idx += nq; \
} while (0)

	/* LRO is enabled only for TOE queues */
	ALLOC_OFLD_RXQS(s->ofldrxq, s->ofldqsets, j, s->ofld_rxq, 1);
	j = s->rdmaqs / adap->params.nports;
	ALLOC_OFLD_RXQS(s->rdmarxq, s->rdmaqs, j, s->rdma_rxq, 0);
	j = s->rdmaciqs / adap->params.nports; /* rdmaq queues per channel */
	ALLOC_OFLD_RXQS(s->rdmaciq, s->rdmaciqs, j, s->rdma_ciq, 0);
	j = s->niscsiq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->iscsirxq, s->niscsiq, j, s->iscsi_rxq, 1);
	j = s->niscsitq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->iscsitrxq, s->niscsitq, j, s->iscsit_rxq, 1);
	j = s->n_nvmehq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->nvmehrxq, s->n_nvmehq, j, s->nvmeh_rxq, 1);
	j = s->n_nvmetq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->nvmetrxq, s->n_nvmetq, j, s->nvmet_rxq, 1);
	j = s->ncstorq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->cstorrxq, s->ncstorq, j, s->cstor_rxq, 0);
	j = s->ncstorciq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->cstorciq, s->ncstorciq, j, s->cstor_ciq, 0);
	j = s->ncryptoq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->cryptorxq, s->ncryptoq, j, s->crypto_rxq, 0);
#undef ALLOC_OFLD_RXQS

#ifdef CONFIG_T4_MA_FAILOVER
	if (s->nfailoverq) {
		err = t4_sge_alloc_rxq(adap, &(s->failoverq.rspq), false,
				       adap->port[0],
				       ++msi_idx, &(s->failoverq.fl),
				       uldma_failover_handler, NULL,
				       0, false);
		if (err)
			goto freeout;
		memset(&s->failoverq.stats, 0, sizeof(s->failoverq.stats));
	}
#endif /* CONFIG_T4_MA_FAILOVER */

	if (adap->tidinfo.sftids.size) {
		/*
		 * Note that ->rdmarxq[i].rspq.cntxt_id below is 0 if we don't
		 * have RDMA queues, and that's the right value.
		 */
		err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[0], adap->port[0],
					    s->fw_evtq.cntxt_id,
					    s->rdmarxq[0].rspq.cntxt_id);
		if (err)
			goto freeout;
		goto ptp_txq_setup;
	}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	/* control Tx queues */
	for_each_port(adap, i) {
		j = i + CXGB4_ULD_CTRLQ_INDEX_TOE;
		err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[j], adap->port[i],
					    s->fw_evtq.cntxt_id,
					    adap->params.ulptx_memwrite_dsgl ?
					    s->ofldrxq[i].rspq.cntxt_id : 0);
		if (err)
			goto freeout;
	}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	for_each_port(adap, i) {
		if (!s->rdmarxq[i].rspq.cntxt_id)
			continue;

		j = i + CXGB4_ULD_CTRLQ_INDEX_RDMA;
		err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[j],	adap->port[i],
					    s->fw_evtq.cntxt_id,
					    s->rdmarxq[i].rspq.cntxt_id);
		if (err)
			goto freeout;
	}

	if (cxgb4_uld_sendpath_enabled(adap)) {
		for_each_port(adap, i) {
			if (!s->iscsirxq[i].rspq.cntxt_id)
				continue;

			j = i + CXGB4_ULD_CTRLQ_INDEX_ISCSI;
			err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[j],
						    adap->port[i],
						    s->fw_evtq.cntxt_id,
						    s->iscsirxq[i].rspq.cntxt_id);
			if (err)
				goto freeout;
		}

		for_each_port(adap, i) {
			if (!s->iscsitrxq[i].rspq.cntxt_id)
				continue;

			j = i + CXGB4_ULD_CTRLQ_INDEX_ISCSIT;
			err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[j],
						    adap->port[i],
						    s->fw_evtq.cntxt_id,
						    s->iscsitrxq[i].rspq.cntxt_id);
			if (err)
				goto freeout;
		}
	}

	for_each_port(adap, i) {
		if (!s->nvmehrxq[i].rspq.cntxt_id)
			continue;

		j = i + CXGB4_ULD_CTRLQ_INDEX_NVMEH;
		err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[j],
					    adap->port[i],
					    s->fw_evtq.cntxt_id,
					    s->nvmehrxq[i].rspq.cntxt_id);
		if (err)
			goto freeout;
	}

	for_each_port(adap, i) {
		if (!s->nvmetrxq[i].rspq.cntxt_id)
			continue;

		j = i + CXGB4_ULD_CTRLQ_INDEX_NVMET;
		err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[j],
					    adap->port[i],
					    s->fw_evtq.cntxt_id,
					    s->nvmetrxq[i].rspq.cntxt_id);
		if (err)
			goto freeout;
	}

	for_each_port(adap, i) {
		if (!s->cstorrxq[i].rspq.cntxt_id)
			continue;

		j = i + CXGB4_ULD_CTRLQ_INDEX_CSTOR;
		err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[j],
					    adap->port[i],
					    s->fw_evtq.cntxt_id,
					    s->cstorrxq[i].rspq.cntxt_id);
		if (err)
			goto freeout;
	}

ptp_txq_setup:
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adap->params.chip)) {
		err = t4_sge_alloc_eth_txq(adap, &s->ptptxq, adap->port[0],
					   netdev_get_tx_queue(adap->port[0],
							       0),
					   s->fw_evtq.cntxt_id, false);
		if (err)
			goto freeout;
	}
#endif

	t4_set_trace_rss_control(adap, netdev2pinfo(adap->port[0])->tx_chan,
				 s->ethrxq[0].rspq.abs_id);
	return 0;

freeout:
	dev_err(adap->pdev_dev, "Can't allocate queues, err=%d\n", -err);
	t4_free_sge_resources(adap);
	return err;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static int setup_loopback(struct adapter *adap)
{
	u8 mac0[] = { 0, 0, 0, 0, 0, 0 };
	struct port_info *pi;
	int i, err;
	int idx = -1;

	for_each_port(adap, i) {
		pi = adap2pinfo(adap, i);
		err = cxgb4_update_mac_filt(pi, pi->viid, &idx, mac0, true, NULL);
		if (err < 0)
			return err;
	}
	return 0;
}
#endif

/*
 * Allocate a chunk of memory using kmalloc or, if that fails, vmalloc.
 * The allocated memory is cleared.
 */
void *t4_alloc_mem(size_t size)
{
	void *p = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);

	if (!p)
		p = vzalloc(size);
	return p;
}

/*
 * Free memory allocated through alloc_mem().
 */
void t4_free_mem(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}

/*
   For UDP traffic, sk->sk_dst_cache remains NULL, preventing the invocation of
   sk_tx_queue_set within netdev_pick_tx. This happens because __sk_get_hash()
   relies on the current socket state when calculating the hash, yet
   sk_tx_queue_mapping has not been initialized at this point. As a result, all
   packets—regardless of whether they originate from different or the same
   connection—are assigned the same index.

   To address this, we now balance the UDP traffic workload across all n queues
   based on the source port. Whenever the calculated index exceeds the valid range
   [0, real_num_tx_queues], we compute a new index using the source port and
   initialize it via sk_tx_queue_set, ensuring optimal queue distribution.
*/
static u16 ofld_cxgb_select_queue(struct net_device *dev, struct sk_buff *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

	if (ip_header->protocol == IPPROTO_UDP) {
		struct sock *sk = skb->sk;
		int queue_index = sk_tx_queue_get(sk);

		if (queue_index < 0 || skb->ooo_okay ||
		    queue_index >= dev->real_num_tx_queues) {
			struct udphdr *udp_header = (struct udphdr *)
				((__be32 *)ip_header + ip_header->ihl);
			unsigned int source_port = ntohs(udp_header->source);
			unsigned int new_index = source_port %
				dev->real_num_tx_queues;

			if (queue_index != new_index && sk && sk_fullsock(sk))
				sk_tx_queue_set(sk, new_index);

			queue_index = new_index;
		}
		return queue_index;
	} else {
		return netdev_pick_tx(dev, skb, NULL) %
			dev->real_num_tx_queues;
	}
}

static u16 cxgb_select_queue(struct net_device *dev, struct sk_buff *skb,
			     struct net_device *sb_dev)
{
	int txq;

#ifdef CONFIG_CXGB4_DCB
	/* If a Data Center Bridging has been successfully negotiated on this
	 * link then we'll use the skb's priority to map it to a TX Queue.
	 * The skb's priority is determined via the VLAN Tag Priority Code
	 * Point field.
	 */
	if (cxgb4_dcb_enabled(dev)) {
		if (unlikely(!skb_vlan_tag_present(skb))) {
			struct ethhdr *ethhdr = (struct ethhdr *)skb->data;
			unsigned short proto = ntohs(ethhdr->h_proto);

			/*
			 * IEEE802.3ad, Link Aggregation Control Protocol,
			 * operates below the level of VLANs and is a direct,
			 * Port-to-Port low level Link Protocol to convey Link
			 * Aggregation information.
			 */
			if (proto != ETH_P_SLOW && printk_ratelimit()) {
				struct adapter *adap = netdev2adap(dev);

				dev_warn(adap->pdev_dev,
					 "TX Packet without "
					 "VLAN Tag on DCB Link\n");
			}
			txq = 0;
		} else {
			u16 vlan_tci = skb_vlan_tag_get(skb);
			txq = (vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
#ifdef CONFIG_PO_FCOE
			if (skb->protocol == htons(ETH_P_FCOE))
				txq = skb->priority & 0x7;
#endif /* CONFIG_PO_FCOE */
		}
		return txq;
	}
#endif /* CONFIG_CXGB4_DCB */

	if (select_queue) {
		txq = (skb_rx_queue_recorded(skb)
			? skb_get_rx_queue(skb)
			: smp_processor_id());

		while (unlikely(txq >= dev->real_num_tx_queues))
			txq -= dev->real_num_tx_queues;

		return txq;
	}
	return ofld_cxgb_select_queue(dev, skb);
}

static struct net_device_stats *cxgb_get_stats(struct net_device *dev)
{
	struct port_stats stats;
	struct port_info *p = netdev_priv(dev);
	struct adapter *adapter = p->adapter;
	struct net_device_stats *ns = &dev->stats;
	u32 tp_tnl_cong_drops[MAX_NPORTS];

	/* Block retrieving statistics during EEH error
	 * recovery. Otherwise, the recovery might fail
	 * and the PCI device will be removed permanently
	 */
	spin_lock(&adapter->stats_lock);
	if (!netif_device_present(dev)) {
		spin_unlock(&adapter->stats_lock);
		return ns;
	}
	t4_get_port_stats_offset(adapter, p->lport, &stats,
				 &p->stats_base);
	t4_read_indirect(adapter, A_TP_MIB_INDEX, A_TP_MIB_DATA,
			 tp_tnl_cong_drops, adapter->params.nports,
			 A_TP_MIB_TNL_CNG_DROP_0);
	tp_tnl_cong_drops[p->port_id] -=
		adapter->tp_err_stats_base.tnl_cong_drops[p->port_id];
	spin_unlock(&adapter->stats_lock);

	ns->tx_bytes   = stats.tx_octets;
	ns->tx_packets = stats.tx_frames;
	ns->rx_bytes   = stats.rx_octets;
	ns->rx_packets = stats.rx_frames;
	ns->multicast  = stats.rx_mcast_frames;

	/* detailed rx_errors */
	ns->rx_length_errors = stats.rx_jabber + stats.rx_too_long +
			       stats.rx_runt;
	ns->rx_over_errors   = 0;
	ns->rx_crc_errors    = stats.rx_fcs_err;
	ns->rx_frame_errors  = stats.rx_symbol_err;
	ns->rx_dropped = stats.rx_ovflow0 + stats.rx_ovflow1 +
			 stats.rx_ovflow2 + stats.rx_ovflow3 +
			 stats.rx_trunc0 + stats.rx_trunc1 +
			 stats.rx_trunc2 + stats.rx_trunc3 +
			 tp_tnl_cong_drops[p->port_id];
	ns->rx_missed_errors = 0;

	/* detailed tx_errors */
	ns->tx_aborted_errors   = 0;
	ns->tx_carrier_errors   = 0;
	ns->tx_fifo_errors      = 0;
	ns->tx_heartbeat_errors = 0;
	ns->tx_window_errors    = 0;

	ns->tx_errors = stats.tx_error_frames;
	ns->rx_errors = stats.rx_symbol_err + stats.rx_fcs_err +
		ns->rx_length_errors + stats.rx_len_err + ns->rx_fifo_errors;
	return ns;
}

int cxgb4_closest_timer(const struct sge *s, int time)
{
	int i, delta, match = 0, min_delta = INT_MAX;

	for (i = 0; i < ARRAY_SIZE(s->timer_val); i++) {
		delta = time - s->timer_val[i];
		if (delta < 0)
			delta = -delta;
		if (delta < min_delta) {
			min_delta = delta;
			match = i;
		}
	}
	return match;
}

static int closest_thres(const struct sge *s, int thres)
{
	int i, delta, match = 0, min_delta = INT_MAX;

	for (i = 0; i < ARRAY_SIZE(s->counter_val); i++) {
		delta = thres - s->counter_val[i];
		if (delta < 0)
			delta = -delta;
		if (delta < min_delta) {
			min_delta = delta;
			match = i;
		}
	}
	return match;
}

/**
 *	cxgb4_set_rspq_intr_params - set a queue's interrupt holdoff parameters
 *	@q: the Rx queue
 *	@us: the hold-off time in us, or 0 to disable timer
 *	@cnt: the hold-off packet count, or 0 to disable counter
 *
 *	Sets an Rx queue's interrupt hold-off time and packet count.  At least
 *	one of the two needs to be enabled for the queue to generate interrupts.
 */
int cxgb4_set_rspq_intr_params(struct sge_rspq *q,
			       unsigned int us, unsigned int cnt)
{
	struct adapter *adap = q->adap;

	if ((us | cnt) == 0)
		cnt = 1;

	if (cnt) {
		int err;
		u32 v, new_idx;

		new_idx = closest_thres(&adap->sge, cnt);
		if (q->desc && q->pktcnt_idx != new_idx) {
			/* the queue has already been created, update it */
			v = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_IQ_INTCNTTHRESH) |
			    V_FW_PARAMS_PARAM_YZ(q->cntxt_id);
			err = t4_set_params(adap, adap->mbox, adap->pf, 0, 1,
					    &v, &new_idx);
			if (err)
				return err;
		}
		q->pktcnt_idx = new_idx;
	}

	us = us == 0 ? X_TIMERREG_RESTART_COUNTER : cxgb4_closest_timer(&adap->sge, us);
	q->intr_params = V_QINTR_TIMER_IDX(us) | V_QINTR_CNT_EN(cnt > 0);

	return 0;
}

static ssize_t show_cclk(struct device *d, struct device_attribute *attr,
			 char *buf)
{
	ssize_t len;
	struct adapter *adap = netdev2adap(to_net_dev(d));
	char temp[32];
	unsigned int cclk_ps = 1000000000 / adap->params.vpd.cclk;  /* in ps */

	/*
	 * Display the core clock in units of ns, the same way it is
	 * displayed in debugfs.
	 */
	len = sprintf(buf, "Core clock period: %s ns\n",
		   unit_conv(temp, sizeof(temp), cclk_ps, 1000));

	return len;
}

#define T4_DISPLAY_ATTR(name) \
static DEVICE_ATTR(name, S_IRUGO, show_##name, NULL)

T4_DISPLAY_ATTR(cclk);

static struct attribute *t4_attrs[] = {
	&dev_attr_cclk.attr,
	NULL
};

static struct attribute_group t4_attr_group = { .attrs = t4_attrs };

/**
 *	cxgb4_best_mtu - find the entry in the MTU table closest to an MTU
 *	@mtus: the HW MTU table
 *	@mtu: the target MTU
 *	@idx: index of selected entry in the MTU table
 *
 *	Returns the index and the value in the HW MTU table that is closest to
 *	but does not exceed @mtu, unless @mtu is smaller than any value in the
 *	table, in which case that smallest available value is selected.
 */
unsigned int cxgb4_best_mtu(const unsigned short *mtus, unsigned short mtu,
			    unsigned int *idx)
{
	unsigned int i = 0;

	while (i < NMTUS - 1 && mtus[i + 1] <= mtu)
		++i;
	if (idx)
		*idx = i;
	return mtus[i];
}
EXPORT_SYMBOL(cxgb4_best_mtu);

/**
 *	cxgb4_best_aligned_mtu - find best MTU, [hopefully] data size aligned
 *	@mtus: the HW MTU table
 *	@header_size: Header Size
 *	@data_size_max: maximum Data Segment Size
 *	@data_size_align: desired Data Segment Size Alignment (2^N)
 *	@mtu_idxp: HW MTU Table Index return value pointer (possibly NULL)
 *
 *	Similar to cxgb4_best_mtu() but instead of searching the Hardware
 *	MTU Table based solely on a Maximum MTU parameter, we break that
 *	parameter up into a Header Size and Maximum Data Segment Size, and
 *	provide a desired Data Segment Size Alignment.  If we find an MTU in
 *	the Hardware MTU Table which will result in a Data Segment Size with
 *	the requested alignment _and_ that MTU isn't "too far" from the
 *	closest MTU, then we'll return that rather than the closest MTU.
 */
unsigned int cxgb4_best_aligned_mtu(const unsigned short *mtus,
				    unsigned short header_size,
				    unsigned short data_size_max,
				    unsigned short data_size_align,
				    unsigned int *mtu_idxp)
{
	unsigned short max_mtu = header_size + data_size_max;
	unsigned short data_size_align_mask = data_size_align - 1;
	int mtu_idx, aligned_mtu_idx;

	/* Scan the MTU Table till we find an MTU which is larger than our
	 * Maximum MTU or we reach the end of the table.  Along the way,
	 * record the last MTU found, if any, which will result in a Data
	 * Segment Length matching the requested alignment.
	 */
	for (mtu_idx = 0, aligned_mtu_idx = -1; mtu_idx < NMTUS; mtu_idx++) {
		unsigned short data_size = mtus[mtu_idx] - header_size;

		/* If this MTU minus the Header Size would result in a
		 * Data Segment Size of the desired alignment, remember it.
		 */
		if ((data_size & data_size_align_mask) == 0)
			aligned_mtu_idx = mtu_idx;

		/* If we're not at the end of the Hardware MTU Table and the
		 * next element is larger than our Maximum MTU, drop out of
		 * the loop.
		 */
		if (mtu_idx+1 < NMTUS && mtus[mtu_idx+1] > max_mtu)
			break;
	}

	/* If we fell out of the loop because we ran to the end of the table,
	 * then we just have to use the last [largest] entry.
	 */
	if (mtu_idx == NMTUS)
		mtu_idx--;

	/* If we found an MTU which resulted in the requested Data Segment
	 * Length alignment and that's "not far" from the largest MTU which is
	 * less than or equal to the maximum MTU, then use that.
	 */
	if (aligned_mtu_idx >= 0 &&
	    mtu_idx - aligned_mtu_idx <= 1)
		mtu_idx = aligned_mtu_idx;

	/* If the caller has passed in an MTU Index pointer, pass the
	 * MTU Index back.  Return the MTU value.
	 */
	if (mtu_idxp)
		*mtu_idxp = mtu_idx;
	return mtus[mtu_idx];
}
EXPORT_SYMBOL(cxgb4_best_aligned_mtu);

/**
 *      cxgb4_get_ringbb_egress - Get egress dev for Ring-BB config
 *      @dev: input device
 *
 *      API currently statically returns Port-1 netdev for the
 *      Single-Direction Ring-BB configuration.
 */
struct net_device *cxgb4_get_ringbb_egress(struct net_device *dev)
{
	struct adapter *adap = netdev2adap(dev);

	/* currently, we simply return Port-1 netdev for the
	 * Single-Direction Ring.
	 */
	if (cxgb4_modparam_enable_ringbb())
		return adap->port[1];
	else
		return dev;
}
EXPORT_SYMBOL(cxgb4_get_ringbb_egress);

/**
 *	cxgb4_port_chan - get the HW channel of a port
 *	@dev: the net device for the port
 *
 *	Return the HW channel of the given port.
 */
unsigned int cxgb4_port_chan(const struct net_device *dev)
{
	return netdev2pinfo(dev)->lport;
}
EXPORT_SYMBOL(cxgb4_port_chan);

struct net_device * cxgb4_port_chan_to_netdev(struct adapter *adap,
					      u8 chan)
{
	struct port_info *pi;
	u8 i;

	for_each_port(adap, i) {
		pi = adap2pinfo(adap, i);
		if (pi->lport == chan)
			return adap->port[pi->port_id];
	}

	return NULL;
}

/**
 * cxgb4_port_tx_chan - get the HW Tx channel of a port
 * @dev: the net device for the port
 *
 * Return the HW Tx channel of the given port
 */
u8 cxgb4_port_tx_chan(const struct net_device *dev)
{
	return netdev2pinfo(dev)->tx_chan;
}
EXPORT_SYMBOL(cxgb4_port_tx_chan);

/**
 * cxgb4_port_rx_chan - get the HW Rx channel of a port
 * @dev: the net device for the port
 *
 * Return the HW Rx channel of the given port
 */
u8 cxgb4_port_rx_chan(const struct net_device *dev)
{
	return netdev2pinfo(dev)->rx_chan;
}
EXPORT_SYMBOL(cxgb4_port_rx_chan);

/**
 *      cxgb4_port_e2cchan - get the HW c-channel of a port
 *      @dev: the net device for the port
 *
 *      Return the HW RX c-channel of the given port.
 */
unsigned int cxgb4_port_e2cchan(const struct net_device *dev)
{
	return netdev2pinfo(dev)->rx_cchan;
}
EXPORT_SYMBOL(cxgb4_port_e2cchan);

unsigned int cxgb4_dbfifo_count(const struct net_device *dev, int lpfifo)
{
	struct adapter *adap = netdev2adap(dev);
	u32 v1, lp_count, hp_count;

	v1 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS);
	if (is_t4(adap->params.chip)) {
		lp_count = G_LP_COUNT(v1);
		hp_count = G_HP_COUNT(v1);
	} else {
		u32 v2;
		v2 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS2);
		lp_count = G_LP_COUNT_T5(v1);
		hp_count = G_HP_COUNT_T5(v2);
	}
	return lpfifo ? lp_count : hp_count;
}
EXPORT_SYMBOL(cxgb4_dbfifo_count);

/**
 *	cxgb4_port_viid - get the VI id of a port
 *	@dev: the net device for the port
 *
 *	Return the VI id of the given port.
 */
unsigned int cxgb4_port_viid(const struct net_device *dev)
{
	return netdev2pinfo(dev)->viid;
}
EXPORT_SYMBOL(cxgb4_port_viid);

/**
 *	cxgb4_port_idx - get the index of a port
 *	@dev: the net device for the port
 *
 *	Return the index of the given port.
 */
unsigned int cxgb4_port_idx(const struct net_device *dev)
{
	return netdev2pinfo(dev)->port_id;
}
EXPORT_SYMBOL(cxgb4_port_idx);

void cxgb4_get_tcp_stats(struct net_device *dev, struct tp_tcp_stats *v4,
			 struct tp_tcp_stats *v6)
{
	struct adapter *adap = netdev2adap(dev);

	spin_lock(&adap->stats_lock);
	t4_tp_get_tcp_stats(adap, v4, v6, false);
	spin_unlock(&adap->stats_lock);
}
EXPORT_SYMBOL(cxgb4_get_tcp_stats);

/**
 *	cxgb4_netdev_by_hwid - return the net device of a HW port
 *	@pdev: identifies the adapter
 *	@id: the HW port id
 *
 *	Return the net device associated with the interface with the given HW
 *	id.
 */
struct net_device *cxgb4_netdev_by_hwid(struct pci_dev *pdev, unsigned int id)
{
	const struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap || id >= NCHAN)
		return NULL;
	id = adap->chan_map[id];
	return id < MAX_NPORTS ? adap->port[id] : NULL;
}
EXPORT_SYMBOL(cxgb4_netdev_by_hwid);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
int cxgb4_wr_mbox(struct net_device *dev, const void *cmd,
		  int size, void *rpl)
{
	struct adapter *adap = netdev2adap(dev);

	return t4_wr_mbox(adap, adap->mbox, cmd, size, rpl);
}
EXPORT_SYMBOL(cxgb4_wr_mbox);

int cxgb4_flush_eq_cache(struct net_device *dev)
{
	struct adapter *adap = netdev2adap(dev);

	return t4_sge_ctxt_flush(adap, adap->mbox, CTXT_EGRESS);
}
EXPORT_SYMBOL(cxgb4_flush_eq_cache);

int cxgb4_read_tpte(struct net_device *dev, u32 stag, __be32 *tpte)
{
	struct adapter *adap = netdev2adap(dev);
	u32 offset;
	int ret;

	offset = ((stag >> 8) * 32) + adap->uld.vres.stag.start;
	if (offset >= adap->uld.vres.stag.start + adap->uld.vres.stag.size)
		goto err;

	spin_lock(&adap->win0_lock);
	ret = t4_memory_rw_addr(adap, MEMWIN_NIC, offset, 32, tpte,
				T4_MEMORY_READ);
	spin_unlock(&adap->win0_lock);
	return ret;

err:
	dev_err(adap->pdev_dev, "stag %#x, offset %#x out of range\n",
		stag, offset);
	return -EINVAL;
}
EXPORT_SYMBOL(cxgb4_read_tpte);

static void check_neigh_update(struct neighbour *neigh)
{
	const struct device *parent = NULL;
	struct net_device *netdev = neigh->dev;
#if defined(BOND_SUPPORT)
	struct bonding *bond;
	struct slave *slave;
#endif

	if (netdev->priv_flags & IFF_802_1Q_VLAN)
		netdev = vlan_dev_real_dev(netdev);
#if defined(BOND_SUPPORT)
	if (netdev->flags & IFF_MASTER) {
		bond = (struct bonding *)netdev_priv(netdev);
		/* We select the first child since we can only bond
		 * offload devices belonging to the same adapter.
		 */
		rcu_read_lock();
		slave = bond_first_slave_rcu(bond);
		if (slave)
			netdev = slave->dev;
		else
			netdev = NULL;
		rcu_read_unlock();
	}
#endif

	if (netdev)
		parent = netdev->dev.parent;

	if (parent && netdev->netdev_ops == &cxgb4_netdev_ops)
		t4_l2t_update(dev_get_drvdata(parent), neigh);
}

static int cxgb4_inet6addr_handler(struct notifier_block *this,
					unsigned long event, void *data)
{
	struct inet6_ifaddr *ifa = data;
	struct net_device *event_dev = ifa->idev->dev;
#if defined(BOND_SUPPORT)
	struct adapter *adap;
#endif
	if (event_dev->priv_flags & IFF_802_1Q_VLAN)
		event_dev = vlan_dev_real_dev(event_dev);
#if defined(BOND_SUPPORT)
	if (event_dev->flags & IFF_MASTER) {
		list_for_each_entry(adap, &adapter_list, list_node) {
			switch (event) {
			case NETDEV_UP:
				cxgb4_clip_get(adap->port[0],
							(const u32 *)ifa, 1);
				break;
			case NETDEV_DOWN:
				cxgb4_clip_release(adap->port[0],
							(const u32 *)ifa, 1);
				break;
			default:
				break;
			}
		}
		return NOTIFY_OK;
	}
#endif

	if (event_dev && event_dev->netdev_ops == &cxgb4_netdev_ops) {
		switch (event) {
		case NETDEV_UP:
			cxgb4_clip_get(event_dev, (const u32 *)ifa, 1);
			break;
		case NETDEV_DOWN:
			cxgb4_clip_release(event_dev, (const u32 *)ifa, 1);
			break;
		default:
			break;
		}
	}
	return NOTIFY_OK;
}


static struct notifier_block cxgb4_inet6addr_notifier = {
	.notifier_call = cxgb4_inet6addr_handler
};

int cxgb4_set_params(struct net_device *dev, unsigned int nparams,
		     const u32 *params, const u32 *val)
{
	struct adapter *adap;

	adap = netdev2adap(dev);
	return t4_set_params(adap, adap->mbox, adap->pf, 0, nparams, params,
			     val);
}
EXPORT_SYMBOL(cxgb4_set_params);

u64 cxgb4_read_sge_timestamp(struct net_device *dev)
{
	u32 hi, lo;
	struct adapter *adap;

	adap = netdev2adap(dev);
	lo = t4_read_reg(adap, A_SGE_TIMESTAMP_LO);
	hi = G_TSVAL(t4_read_reg(adap, A_SGE_TIMESTAMP_HI));

	return ((u64)hi << 32) | (u64)lo;
}
EXPORT_SYMBOL(cxgb4_read_sge_timestamp);

int cxgb4_bar2_sge_qregs(struct net_device *dev,
			 unsigned int qid,
			 enum cxgb4_bar2_qtype qtype,
			 int user,
			 u64 *pbar2_qoffset,
			 unsigned int *pbar2_qid)
{
	return t4_bar2_sge_qregs(netdev2adap(dev),
				 qid,
				 (qtype == CXGB4_BAR2_QTYPE_EGRESS
				  ? T4_BAR2_QTYPE_EGRESS
				  : T4_BAR2_QTYPE_INGRESS),
				 user,
				 pbar2_qoffset,
				 pbar2_qid);
}
EXPORT_SYMBOL(cxgb4_bar2_sge_qregs);

struct resource *cxgb4_bar_resource(struct net_device *dev, u8 index)
{
	return cxgb4_common_resource_get(netdev2adap(dev), index);
}
EXPORT_SYMBOL(cxgb4_bar_resource);

static int netevent_cb(struct notifier_block *nb, unsigned long event,
		       void *data)
{
	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		check_neigh_update(data);
		break;
	case NETEVENT_REDIRECT:
	default:
		break;
	}
	return 0;
}

static struct notifier_block cxgb4_netevent_nb = {
	.notifier_call = netevent_cb
};

static void uld_attach(struct adapter *adap, unsigned int uld)
{
	void *handle;
	struct cxgb4_lld_info lli = {0};
	unsigned short i;

	if (!cxgb4_uld_supported_any(adap))
		return;

	lli.dev = cxgb4_common_get_device(adap);
	lli.name = adap->name;
	lli.vendor_id = cxgb4_common_vendor_id(adap);
	lli.device_id = cxgb4_common_device_id(adap);
	lli.pf = adap->pf;
	lli.l2t = adap->l2t;
	lli.uld_tids.tids.start = adap->tidinfo.tids.start;
	lli.uld_tids.tids.size = adap->tidinfo.tids.size;
	lli.uld_tids.atids.start = adap->tidinfo.atids.start;
	lli.uld_tids.atids.size = adap->tidinfo.atids.size;
	lli.uld_tids.hpftids.start = adap->tidinfo.hpftids.start;
	lli.uld_tids.hpftids.size = adap->tidinfo.hpftids.size;
	lli.uld_tids.ftids.start = adap->tidinfo.ftids.start;
	lli.uld_tids.ftids.size = adap->tidinfo.ftids.size;
	lli.uld_tids.stids.start = adap->tidinfo.stids.start;
	lli.uld_tids.stids.size = adap->tidinfo.stids.size;
	lli.ports = adap->port;
	lli.vr = &adap->uld.vres;
	lli.mtus = adap->params.mtus;
	if (uld == CXGB4_ULD_TYPE_RDMA) {
		lli.rxq_ids = adap->sge.rdma_rxq;
		lli.ciq_ids = adap->sge.rdma_ciq;
		lli.nrxq = adap->sge.rdmaqs;
		lli.nciq = adap->sge.rdmaciqs;
		lli.ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_RDMA;
	} else if (uld == CXGB4_ULD_TYPE_ISCSI) {
		lli.rxq_ids = adap->sge.iscsi_rxq;
		lli.nrxq = adap->sge.niscsiq;
		if (cxgb4_uld_sendpath_enabled(adap))
			lli.ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_ISCSI;
	} else if (uld == CXGB4_ULD_TYPE_ISCSIT) {
		lli.rxq_ids = adap->sge.iscsit_rxq;
		lli.nrxq = adap->sge.niscsitq;
		if (cxgb4_uld_sendpath_enabled(adap))
			lli.ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_ISCSIT;
	} else if (uld == CXGB4_ULD_TYPE_NVME_TCP_HOST) {
		lli.rxq_ids = adap->sge.nvmeh_rxq;
		lli.nrxq = adap->sge.n_nvmehq;
		lli.ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_NVMEH;
	} else if (uld == CXGB4_ULD_TYPE_NVME_TCP_TARGET) {
		lli.rxq_ids = adap->sge.nvmet_rxq;
		lli.nrxq = adap->sge.n_nvmetq;
		lli.ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_NVMET;
	} else if (uld == CXGB4_ULD_TYPE_CSTOR) {
		lli.rxq_ids = adap->sge.cstor_rxq;
		lli.ciq_ids = adap->sge.cstor_ciq;
		lli.nrxq = adap->sge.ncstorq;
		lli.nciq = adap->sge.ncstorciq;
		lli.ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_CSTOR;
	} else if (uld == CXGB4_ULD_TYPE_TOE) {
		lli.rxq_ids = adap->sge.ofld_rxq;
		lli.nrxq = adap->sge.ofldqsets;
		lli.ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_TOE;
	} else if (uld == CXGB4_ULD_TYPE_CRYPTO) {
		lli.rxq_ids = adap->sge.crypto_rxq;
		lli.nrxq = adap->sge.ncryptoq;
	}
	if (uld == CXGB4_ULD_TYPE_CRYPTO)
		lli.ntxq = adap->sge.ncryptoq;
	else
		lli.ntxq = adap->sge.ofldqsets;
	lli.nchan = adap->params.nports;
	lli.nports = adap->params.nports;
	lli.wr_cred = adap->params.ofldq_wr_cred;
	lli.nsched_cls = adap->params.nsched_cls;
	lli.adapter_type = adap->params.chip;
	lli.iscsi_ppm = &adap->uld.iscsi_ppm;
	lli.iscsi_iolen = G_MAXRXDATA(t4_read_reg(adap, A_TP_PARA_REG2));
	lli.iscsi_tagmask = t4_read_reg(adap, A_ULP_RX_ISCSI_TAGMASK);
	lli.iscsi_pgsz_order = t4_read_reg(adap, A_ULP_RX_ISCSI_PSZ);

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T6)
		/* TODO Write Macros to get bits in
		 * ULP_RX_MISC_FEATURE_ENABLE register
		 */
		lli.iscsi_all_cmp_mode = !!(t4_read_reg(adap, 0x1925c) &
					   (1U << 9));

	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T6) {
		lli.iscsi_llimit = t4_read_reg(adap, A_ULP_RX_ISCSI_LLIMIT);
	} else {
		lli.iscsi_llimit = t4_read_reg(adap, A_ULP_RX_ISCSI_LLIMIT) << 4;

		if (!is_t7a(adap->params.chip)) {
			u32 val = t4_read_reg(adap, A_SGE_CONTROL2);

			/* TODO Write Macros to get the bits in register */
			lli.cpl_iscsi_data_iqe = !!(val & (1U << 28));
			lli.cpl_nvmt_data_iqe = !!(val & (1U << 27));

			val = t4_read_reg(adap, 0x19330);
			lli.non_ddp_bit = !!(val & (1U << 27));
		}
	}

	lli.cnvme_ddp = &adap->uld.cnvme_ddp;
	lli.rdma_resource = &adap->uld.rdma_resource;
	lli.cclk_ps = 1000000000 / adap->params.vpd.cclk;
	lli.udb_density = 1 << adap->params.sge.eq_qpp;
	lli.ucq_density = 1 << adap->params.sge.iq_qpp;
	lli.sge_host_page_size = 1 << (adap->params.sge.hps + 10);
	lli.tx_db_wc = adap->tx_db_wc;
	lli.filt_mode = adap->params.tp.vlan_pri_map;
	
	for (i = 0; i < NCHAN; i++)
		lli.tx_modq[i] = adap->params.tp.tx_modq[i];
	lli.gts_reg = adap->regs + MYPF_REG(A_SGE_PF_GTS);
	lli.db_reg = adap->regs + MYPF_REG(A_SGE_PF_KDOORBELL);
	lli.fw_vers = adap->params.fw_vers;
	lli.dbfifo_int_thresh = G_LP_INT_THRESH(t4_read_reg(adap,
						A_SGE_DBFIFO_STATUS));
	lli.sge_ingpadboundary = adap->sge.fl_align;
	lli.sge_pktshift = adap->sge.pktshift;
	lli.sge_egrstatuspagesize = adap->sge.stat_len;
	lli.enable_fw_ofld_conn = adap->flags & FW_OFLD_CONN &&
				  !is_bypass(adap);
	lli.max_ordird_qp = adap->params.max_ordird_qp;
	lli.max_ird_adapter = adap->params.max_ird_adapter;
	lli.ulptx_memwrite_dsgl = adap->params.ulptx_memwrite_dsgl;
	lli.dev_512sgl_mr = adap->params.dev_512sgl_mr;
	lli.ulp_t10dif = adap->params.ulp_t10dif;
	lli.ulp_crypto = adap->params.ulp_crypto;
	lli.nodeid = dev_to_node(adap->pdev_dev);
	lli.fr_nsmr_tpte_wr_support = adap->params.fr_nsmr_tpte_wr_support;
	lli.write_w_imm_support = adap->params.write_w_imm_support;
	lli.relaxed_ordering = cxgb4_pcie_relaxed_ordering_enabled(adap);
	lli.write_cmpl_support = adap->params.write_cmpl_support;
	lli.neq = adap->params.pfres.neq;
	lli.sendpath_enabled = cxgb4_uld_sendpath_enabled(adap);
	lli.tid_qid_sel_mask = adap->params.tid_qid_sel_mask;
	lli.tid_qid_sel_shift = adap->params.tid_qid_sel_shift;

	handle = cxgb4_ulds[uld].add(&lli);
	if (IS_ERR(handle)) {
		CH_WARN(adap, "could not attach to the %s driver, error %ld\n",
			cxgb4_uld_type_to_name(uld), PTR_ERR(handle));
		return;
	}

	adap->uld_handle[uld] = handle;

	if (!(registered_notifier_block & CXGB4_NETEVENT_REGISTERED)) {
		register_netevent_notifier(&cxgb4_netevent_nb);
		registered_notifier_block |= CXGB4_NETEVENT_REGISTERED;
	}

	if (adap->flags & FULL_INIT_DONE)
		cxgb4_ulds[uld].state_change(handle, CXGB4_STATE_UP);
}

static void attach_ulds(struct adapter *adap)
{
	unsigned int i;

	mutex_lock(&uld_mutex);
	list_add_tail(&adap->list_node, &adapter_list);
	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++) {
		mutex_lock(&adap->uld.uld_mutex);
		if (cxgb4_ulds[i].add) {
			if (adap->flags & FULL_INIT_DONE)
				cxgb4_uld_txq_alloc_shared(adap, i);
			uld_attach(adap, i);
		}
		mutex_unlock(&adap->uld.uld_mutex);
	}
	mutex_unlock(&uld_mutex);
}

static void detach_ulds(struct adapter *adap)
{
	unsigned int i;

	mutex_lock(&uld_mutex);
	if (!list_empty(&adap->list_node))
		list_del_init(&adap->list_node);
	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++) {
		mutex_lock(&adap->uld.uld_mutex);
		if (adap->uld_handle[i]) {
			cxgb4_ulds[i].state_change(adap->uld_handle[i],
						   CXGB4_STATE_DETACH);
			if (adap->flags & FULL_INIT_DONE)
				cxgb4_uld_txq_free_shared(adap, i);
			adap->uld_handle[i] = NULL;
		}
		mutex_unlock(&adap->uld.uld_mutex);
	}
	if ((registered_notifier_block & CXGB4_NETEVENT_REGISTERED) &&
	    list_empty(&adapter_list)) {
		unregister_netevent_notifier(&cxgb4_netevent_nb);
		registered_notifier_block &= ~CXGB4_NETEVENT_REGISTERED;
	}
	mutex_unlock(&uld_mutex);
}

static void shutdown_ulds(struct adapter *adap)
{
	unsigned int i;

	mutex_lock(&uld_mutex);
	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++) {
		if (adap->uld_handle[i])
			cxgb4_ulds[i].state_change(adap->uld_handle[i],
						   CXGB4_STATE_SHUTDOWN);
	}
	mutex_unlock(&uld_mutex);
}

static void notify_rdma_uld(struct adapter *adap, enum cxgb4_control cmd)
{
	if (!adap->uld_handle[CXGB4_ULD_TYPE_RDMA])
		return;

	cxgb4_ulds[CXGB4_ULD_TYPE_RDMA].control(adap->uld_handle[CXGB4_ULD_TYPE_RDMA],
						cmd);
}

static void drain_db_fifo(struct adapter *adap, int usecs)
{
	u32 v1, lp_count, hp_count;

	do {
		v1 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS);
		if (is_t4(adap->params.chip)) {
			lp_count = G_LP_COUNT(v1);
			hp_count = G_HP_COUNT(v1);
		} else {
			u32 v2;
			v2 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS2);
			lp_count = G_LP_COUNT_T5(v1);
			hp_count = G_HP_COUNT_T5(v2);
		}

		if (lp_count == 0 && hp_count == 0)
			break;
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(usecs_to_jiffies(usecs));
	} while (1);
}

static void cxgb4_disable_dbs(struct adapter *adap)
{
	int i;

	for_each_ethrxq(&adap->sge, i)
		cxgb4_sge_txq_disable_db(&adap->sge.ethtxq[i].q);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_uld_txq_all_disable_dbs(adap);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	for_each_port(adap, i) {
		cxgb4_sge_txq_disable_db(&adap->sge.ctrlq[i].q);
		cxgb4_sge_txq_disable_db(&adap->sge.ctrlq[NCHAN + i].q);
	}
}

static void cxgb4_enable_dbs(struct adapter *adap)
{
	int i;

	for_each_ethrxq(&adap->sge, i)
		cxgb4_sge_txq_enable_db(adap, &adap->sge.ethtxq[i].q);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_uld_txq_all_enable_dbs(adap);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	for_each_port(adap, i) {
		cxgb4_sge_txq_enable_db(adap, &adap->sge.ctrlq[i].q);
		cxgb4_sge_txq_enable_db(adap, &adap->sge.ctrlq[NCHAN + i].q);
	}
}

static void process_db_full(struct work_struct *work)
{
	struct adapter *adap;

	adap = container_of(work, struct adapter, db_full_task);

	drain_db_fifo(adap, dbfifo_drain_delay);
	cxgb4_enable_dbs(adap);
	notify_rdma_uld(adap, CXGB4_CONTROL_DB_EMPTY);
	adap->db_stats.db_empty++;
	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5)
		t4_set_reg_field(adap, A_SGE_INT_ENABLE3,
				 F_DBFIFO_HP_INT | F_DBFIFO_LP_INT,
				 F_DBFIFO_HP_INT | F_DBFIFO_LP_INT);
	else
		t4_set_reg_field(adap, A_SGE_INT_ENABLE3,
				 F_DBFIFO_LP_INT, F_DBFIFO_LP_INT);
}

static void cxgb4_recover_all_queues(struct adapter *adap)
{
	int i;

	for_each_ethrxq(&adap->sge, i) {
		struct sge_rspq *rspq = &adap->sge.ethrxq[i].rspq;

		cxgb4_sge_txq_sync_pidx_locked(rspq->netdev,
					       &adap->sge.ethtxq[i].q);
	}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_uld_txq_all_recover(adap);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
	for_each_port(adap, i) {
		cxgb4_sge_txq_sync_pidx_locked(adap->port[0],
					       &adap->sge.ctrlq[i].q);
		cxgb4_sge_txq_sync_pidx_locked(adap->port[0],
					       &adap->sge.ctrlq[NCHAN + i].q);
	}
}

static void process_db_drop(struct work_struct *work)
{
	struct adapter *adap = container_of(work, struct adapter, db_drop_task);

	if (is_t4(adap->params.chip)) {
		drain_db_fifo(adap, dbfifo_drain_delay);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_DROP);
		drain_db_fifo(adap, dbfifo_drain_delay);
		cxgb4_recover_all_queues(adap);
		drain_db_fifo(adap, dbfifo_drain_delay);
		cxgb4_enable_dbs(adap);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_EMPTY);
	} else if (is_t5(adap->params.chip)) {
		u32 dropped_db = t4_read_reg(adap, 0x010ac);
		u16 qid = (dropped_db >> 15) & 0x1ffff;
		u16 pidx_inc = dropped_db & 0x1fff;
		u64 bar2_qoffset;
		unsigned int bar2_qid;
		int ret;

		ret = t4_bar2_sge_qregs(adap, qid, T4_BAR2_QTYPE_EGRESS, 0,
					&bar2_qoffset, &bar2_qid);
		if (ret)
			dev_err(adap->pdev_dev, "doorbell drop recovery: "
				"qid=%d, pidx_inc=%d\n", qid, pidx_inc);
		else
			writel(V_PIDX_T5(pidx_inc) | V_QID(bar2_qid),
			       adap->bar2 + bar2_qoffset + SGE_UDB_KDOORBELL);

		/* Re-enable BAR2 WC */
		t4_set_reg_field(adap, A_SGE_DOORBELL_THROTTLE_CONTROL,
				 F_CLRCOALESCEDISABLE,
				 F_CLRCOALESCEDISABLE);
	}

	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5)
		t4_set_reg_field(adap, A_SGE_DOORBELL_CONTROL, F_DROPPED_DB, 0);
}

void t4_db_full(struct adapter *adap)
{
	if (is_t4(adap->params.chip)) {
		cxgb4_disable_dbs(adap);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_FULL);
		t4_set_reg_field(adap, A_SGE_INT_ENABLE3,
				 F_DBFIFO_HP_INT | F_DBFIFO_LP_INT, 0);
		cxgb4_work_queue(adap->workq, &adap->db_full_task);
	}
	adap->db_stats.db_full++;
}

void t4_db_dropped(struct adapter *adap)
{
	if (is_t4(adap->params.chip)) {
		cxgb4_disable_dbs(adap);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_FULL);
	}
	cxgb4_work_queue(adap->workq, &adap->db_drop_task);
	adap->db_stats.db_drop++;
}

static void notify_ulds(struct adapter *adap, enum cxgb4_state new_state)
{
	unsigned int i;

	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++) {
		mutex_lock(&adap->uld.uld_mutex);
		if (adap->uld_handle[i])
			cxgb4_ulds[i].state_change(adap->uld_handle[i], new_state);
		mutex_unlock(&adap->uld.uld_mutex);
	}
}

/**
 *	cxgb4_register_uld - register an upper-layer driver
 *	@type: the ULD type
 *	@p: the ULD methods
 *
 *	Registers an upper-layer driver with this driver and notifies the ULD
 *	about any presently available devices that support its type.  Returns
 *	%-EBUSY if a ULD of the same type is already registered.
 */
static int cxgb4_register_uld(enum cxgb4_uld_type type,
			      const struct cxgb4_uld_info *p)
{
	struct adapter *adap = NULL;
	int ret = 0;

	if (type >= CXGB4_ULD_TYPE_MAX)
		return -EINVAL;

	if (!cxgb4_modparam_enable_ulds_supported(type)) {
		pr_err("ULD %s is explicitly disabled by enable_ulds modparam: 0x%x\n",
		       cxgb4_uld_type_to_name(type),
		       cxgb4_modparam_enable_ulds());
		return -EOPNOTSUPP;
	}

	mutex_lock(&uld_mutex);
	if (cxgb4_ulds[type].add) {
		ret = -EBUSY;
		goto out;
	}
	cxgb4_ulds[type] = *p;
	list_for_each_entry(adap, &adapter_list, list_node) {
		mutex_lock(&adap->uld.uld_mutex);
		if (adap->flags & FULL_INIT_DONE)
			cxgb4_uld_txq_alloc_shared(adap, type);
		uld_attach(adap, type);
		mutex_unlock(&adap->uld.uld_mutex);
	}
out:	mutex_unlock(&uld_mutex);

	return ret;
}

/**
 *	cxgb4_unregister_uld - unregister an upper-layer driver
 *	@type: the ULD type
 *
 *	Unregisters an existing upper-layer driver.
 */
static int cxgb4_unregister_uld(enum cxgb4_uld_type type)
{
	struct adapter *adap;

	if (type >= CXGB4_ULD_TYPE_MAX)
		return -EINVAL;
	mutex_lock(&uld_mutex);
	list_for_each_entry(adap, &adapter_list, list_node) {
		mutex_lock(&adap->uld.uld_mutex);
		if (adap->flags & FULL_INIT_DONE)
			cxgb4_uld_txq_free_shared(adap, type);
		adap->uld_handle[type] = NULL;
		mutex_unlock(&adap->uld.uld_mutex);
	}
	cxgb4_ulds[type].add = NULL;
	mutex_unlock(&uld_mutex);
	return 0;
}

/**
 * cxgb4_register_uld_type: wrapper for cxgb4_register_uld()
 * @type: the ULD type
 * @p: the ULD info
 *
 * Provides a wrapper for cxgb4_register_uld() to prevent inbox
 * ULD drivers from interacting with outbox cxgb4 LLD driver. Note
 * that if kernel is compiled with CONFIG_MODVERSIONS, the module version
 * is automatically checked when trying to load inbox ULD drivers and
 * hence they fail load accordingly. However, when CONFIG_MODVERSIONS is
 * disabled, then it's up to the outbox cxgb4 LLD driver to maintain
 * binary compatibility, which will lead to crashes due to mismatch
 * between inbox and outbox version of cxgb4_uld_info, cxgb4_lld_info,
 * etc. structures.
 *
 * This wrapper function must only be used by outbox ULD drivers and
 * must not be used by inbox ULD drivers.
 */
int cxgb4_register_uld_type(enum cxgb4_uld_type type,
			    const struct cxgb4_uld_info *p)
{
	return cxgb4_register_uld(type, p);
}
EXPORT_SYMBOL(cxgb4_register_uld_type);

/**
 * cxgb4_unregister_uld_type: wrapper for cxgb4_unregister_uld()
 * @type: the ULD type
 *
 * Provides a wrapper for cxgb4_unregister_uld() to prevent inbox
 * ULD drivers from interacting with outbox cxgb4 LLD driver. Note
 * that if kernel is compiled with CONFIG_MODVERSIONS, the module version
 * is automatically checked when trying to load inbox ULD drivers and
 * hence they fail load accordingly. However, when CONFIG_MODVERSIONS is
 * disabled, then it's up to the outbox cxgb4 LLD driver to maintain
 * binary compatibility, which will lead to crashes due to mismatch
 * between inbox and outbox version of cxgb4_uld_info, cxgb4_lld_info,
 * etc. structures.
 *
 * This wrapper function must only be used by outbox ULD drivers and
 * must not be used by inbox ULD drivers.
 */
int cxgb4_unregister_uld_type(enum cxgb4_uld_type type)
{
	return cxgb4_unregister_uld(type);
}
EXPORT_SYMBOL(cxgb4_unregister_uld_type);

bool cxgb4_uld_is_registered(struct adapter *adap, enum cxgb4_uld_type type)
{
	bool enabled = false;

	mutex_lock(&adap->uld.uld_mutex);
	if (adap->uld_handle[type])
		enabled = true;
	mutex_unlock(&adap->uld.uld_mutex);

	return enabled;
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

#ifndef CONFIG_CHELSIO_BYPASS
/*
 * Recurring task to kick the Adapter Shutdown Watchdog Timer.  This gets set
 * up when a non-zero Host Deadman Watchdog Timer has been specified
 * (deadman_watchdog module parameter).
 */
static void deadman_watchdog_task(struct work_struct *work)
{
	struct adapter *adapter = container_of(work, struct adapter,
					       deadman_watchdog_task.work);
	int ret, port;

	/*
	 * Kick the Adapter Shutdown Watchdog Timer and schedule the next time
	 * we get called.  Note that we reschedule ourselves at half the
	 * period of the watchdog timer so we can successfully come and kick
	 * it before it expires.
	 */
	ret = t4_config_watchdog(adapter, adapter->mbox, adapter->pf, 0,
				 deadman_watchdog[0],
				 deadman_watchdog[1] ?
				 FW_WATCHDOG_ACTION_PAUSEOFF :
				 FW_WATCHDOG_ACTION_SHUTDOWN);
 
	/*
	 * If the firmware WATCHDOG command succeeds, it' and the chip are
	 * still alive so schedule our next Watchdog Ping and return.
	 */
	if (ret == 0) {
		schedule_delayed_work(&adapter->deadman_watchdog_task,
				      (HZ * deadman_watchdog[0]) / 1000 / 2);
		return;
	}
 
	/*
	 * Otherwise, the firmware and/or chip are in trouble so issue error
	 * messages and mark all the adapter interfaces as down.  Note that
	 * normally we'd also call t4_enable_vi() to disable the Virtual
	 * Interfaces but if the firmware/chip are truly down, that would
	 * most likely lead to a long firmware command timeout for every
	 * interface.  So we don't do that here.
	 */
	t4_shutdown_adapter(adapter);
	for_each_port(adapter, port) {
		struct net_device *dev = adapter->port[port];
 
		netif_tx_stop_all_queues(dev);
		netif_carrier_off(dev);
		dev_err(adapter->pdev_dev, "%s stopped\n", dev->name);
	}
	dev_err(adapter->pdev_dev, "unable to contact firmware (%d); marked"
		" all interfaces as down\n", -ret);
}
#endif /* !CONFIG_CHELSIO_BYPASS */

/**
 *	cxgb_up - enable the adapter
 *	@adap: adapter being enabled
 *
 *	Called when the first port is enabled, this function performs the
 *	actions necessary to make an adapter operational, such as completing
 *	the initialization of HW modules, and enabling interrupts.
 *
 *	Must be called with the rtnl lock held.
 */
static int cxgb_up(struct adapter *adap)
{
	int err;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	u8 i;
#endif

	err = setup_sge_queues(adap);
	if (err)
		goto out;
	err = setup_rss(adap);
	if (err)
		goto freeq;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adap))
		setup_loopback(adap);
#endif

	if (adap->flags & USING_INTR_MULTI) {
		name_msix_vecs(adap);
		err = request_irq(adap->msix_info[0].vec, t4_nondata_intr, 0,
				  adap->msix_info[0].desc, adap);
		if (err)
			goto irq_err;

		err = request_msix_queue_irqs(adap);
		if (err) {
			free_irq(adap->msix_info[0].vec, adap);
			goto irq_err;
		}
	} else {
		unsigned long flags = 0;

		if (!cxgb4_msix_enabled(adap) && !cxgb4_msi_enabled(adap))
			flags = IRQF_SHARED;

		err = request_irq(adap->msix_info[0].vec, t4_intr_handler(adap),
				  flags, adap->name, adap);
		if (err)
			goto irq_err;
	}
	enable_rx(adap);
	t4_sge_start(adap);
	t4_intr_enable(adap);
	adap->flags |= FULL_INIT_DONE;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++) {
		mutex_lock(&adap->uld.uld_mutex);
		if (adap->uld_handle[i])
			cxgb4_uld_txq_alloc_shared(adap, i);
		mutex_unlock(&adap->uld.uld_mutex);
	}
	notify_ulds(adap, CXGB4_STATE_UP);
#endif

#ifndef CONFIG_CHELSIO_BYPASS
	/*
	 * If a non-zero Host Deadman Watchdog Timer has been specified, then
	 * set up the Adapter Shutdown Watchdog Timer and schedule our
	 * recurring task to keep kicking the watchdog ...
	 */
	if (deadman_watchdog[0]) {
		INIT_DELAYED_WORK(&adap->deadman_watchdog_task,
				  deadman_watchdog_task);

		err = t4_config_watchdog(adap, adap->mbox, adap->pf, 0,
					 deadman_watchdog[0],
					 deadman_watchdog[1] ?
					 FW_WATCHDOG_ACTION_PAUSEOFF :
					 FW_WATCHDOG_ACTION_SHUTDOWN);

		/*
		 * If there's an error there's not point in scheduling our
		 * recurring watchdog task but we want to let the system
		 * adminitrator know about this [non-fatal] problem.
		 */
		if (err) {
			dev_err(adap->pdev_dev, "Unable to schedule firmware Adapter "
				"Shutdown/Pauseoff Watchdog timer: error %d\n", -err);
			err = 0;
		} else {
			schedule_delayed_work(&adap->deadman_watchdog_task,
					(HZ * deadman_watchdog[0]) / 1000 / 2);
			dev_info(adap->pdev_dev,
				 "Successfully scheduled firmware Adapter "
				 "%s Watchdog timer with %d ms period\n",
				 deadman_watchdog[1] ? "Pauseoff" : "Shutdown",
				 deadman_watchdog[0]);
		}
	}
#endif /* !CONFIG_CHELSIO_BYPASS */

 out:
	return err;
 irq_err:
	CH_ERR(adap, "request_irq failed, err %d\n", err);
 freeq:
	t4_free_sge_resources(adap);
	goto out;
}

static void cxgb_down(struct adapter *adapter)
{
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	u8 i;
#endif

#ifndef CONFIG_CHELSIO_BYPASS
	/* If a non-zero Host Deadman Watchdog Timer has been specified, then
	 * cancel our recurring task to kick the Adapter Shutdown Watchdog and
	 * then disable the watchdog.  We do it in this order to prevent a race.
	 */
	if (deadman_watchdog[0]) {
		cancel_delayed_work_sync(&adapter->deadman_watchdog_task);
		t4_config_watchdog(adapter, adapter->mbox, adapter->pf, 0,
				   0, deadman_watchdog[1] ?
				   FW_WATCHDOG_ACTION_PAUSEOFF :
				   FW_WATCHDOG_ACTION_SHUTDOWN);
	}
#endif /* !CONFIG_CHELSIO_BYPASS */

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_work_cancel(adapter->workq, &adapter->db_full_task);
	cxgb4_work_cancel(adapter->workq, &adapter->db_drop_task);

	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++) {
		mutex_lock(&adapter->uld.uld_mutex);
		if (adapter->uld_handle[i])
			cxgb4_uld_txq_free_shared(adapter, i);
		mutex_unlock(&adapter->uld.uld_mutex);
	}
#endif

	t4_sge_stop(adapter);
	t4_free_sge_resources(adapter);

	adapter->flags &= ~FULL_INIT_DONE;
}

/*
 * Release resources when all the ports and offloading have been stopped.
 */
static int cxgb_open(struct net_device *dev)
{
	int err;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	/*
	 * If we don't have a connection to the firmware there's nothing we
	 * can do.
	 */
	if (!(adapter->flags & FW_OK))
		return -ENXIO;

	netif_carrier_off(dev);

	if (!(adapter->flags & FULL_INIT_DONE)) {
		err = cxgb_up(adapter);
		if (err < 0)
			return err;
	}

	/*
	 * It's possible that the basic port information could have
	 * changed since we first read it.
	 */
	err = t4_update_port_info(pi);
	if (err < 0)
		return err;

	err = link_start(dev);
	if (err)
		return err;

	netif_tx_start_all_queues(dev);
	udp_tunnel_get_rx_info(dev);
	return 0;
}

static int cxgb_close(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int ret;

	netif_tx_stop_all_queues(dev);
	netif_carrier_off(dev);
	ret = t4_enable_pi_params(adapter, adapter->mbox, pi,
				  false, false, false);

#ifdef CONFIG_CXGB4_DCB
	cxgb4_dcb_reset(dev);
	dcb_tx_queue_prio_enable(dev, false);
#endif

	return ret;
}

/*
 * driver-specific ioctl support
 */

/*
 * net_device operations
 */

/* IEEE 802.3 specified MDIO devices */
enum {
	MDIO_DEV_PMA_PMD = 1,
	MDIO_DEV_VEND2   = 31
};

static int cxgb_siocdevprivate(struct net_device *dev, struct ifreq *ifr,
			       void __user *data, int cmd)
{
	return cxgb_extension_ioctl(dev, data);
}

static int cxgb_ioctl(struct net_device *dev, struct ifreq *req, int cmd)
{
	int ret = 0, mmd;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct mii_ioctl_data *data = (struct mii_ioctl_data *)&req->ifr_data;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = pi->mdio_addr;
		break;
	case SIOCGMIIREG: {
		u32 val;

		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_10G) {
			mmd = data->phy_id >> 8;
			if (!mmd)
				mmd = MDIO_DEV_PMA_PMD;
			else if (mmd > MDIO_DEV_VEND2)
				return -EINVAL;

			ret = t4_mdio_rd(adapter, adapter->mbox,
					 data->phy_id & 0x1f, mmd,
					 data->reg_num, &val);
		} else
			ret = t4_mdio_rd(adapter, adapter->mbox,
					 data->phy_id & 0x1f, 0,
					 data->reg_num & 0x1f, &val);
		if (!ret)
			data->val_out = val;
		break;
	}
	case SIOCSMIIREG:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_10G) {
			mmd = data->phy_id >> 8;
			if (!mmd)
				mmd = MDIO_DEV_PMA_PMD;
			else if (mmd > MDIO_DEV_VEND2)
				return -EINVAL;

			ret = t4_mdio_wr(adapter, adapter->mbox,
					 data->phy_id & 0x1f, mmd,
					 data->reg_num, data->val_in);
		} else
			ret = t4_mdio_wr(adapter, adapter->mbox,
					 data->phy_id & 0x1f, 0,
					 data->reg_num & 0x1f, data->val_in);
		break;

	case SIOCGHWTSTAMP:
		return copy_to_user(req->ifr_data, &pi->tstamp_config,
				    sizeof(pi->tstamp_config)) ?
			-EFAULT : 0;

	case SIOCSHWTSTAMP:
		if (copy_from_user(&pi->tstamp_config, req->ifr_data,
				   sizeof(pi->tstamp_config)))
			return -EFAULT;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		/* For T5+ adapters */
		if (!is_t4(adapter->params.chip)) {
			switch (pi->tstamp_config.tx_type) {
			case HWTSTAMP_TX_OFF:
			case HWTSTAMP_TX_ON:
				break;
			default:
				return -ERANGE;
			}

			switch (pi->tstamp_config.rx_filter) {
			case HWTSTAMP_FILTER_NONE:
				pi->rxtstamp = false;
				break;
			case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
			case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
				cxgb4_ptprx_timestamping(pi, pi->port_id,
							 PTP_TS_L4);
				break;
			case HWTSTAMP_FILTER_PTP_V2_EVENT:
				cxgb4_ptprx_timestamping(pi, pi->port_id,
							 PTP_TS_L2_L4);
				break;
			case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
				cxgb4_ptprx_timestamping(pi, pi->port_id,
							 PTP_TS_L2);
				break;
			case HWTSTAMP_FILTER_ALL:
			case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
			case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
			case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
			case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
			case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
				pi->rxtstamp = true;
				break;
			default:
				pi->tstamp_config.rx_filter =
					HWTSTAMP_FILTER_NONE;
				return -ERANGE;
			}

			if ((pi->tstamp_config.tx_type == HWTSTAMP_TX_OFF) &&
			    (pi->tstamp_config.rx_filter ==
			     HWTSTAMP_FILTER_NONE)) {
				if (cxgb4_ptp_txtype(adapter, pi->port_id) >= 0)
					pi->ptp_enable = false;
			}

			if (pi->tstamp_config.rx_filter !=
			    HWTSTAMP_FILTER_NONE) {
				if (cxgb4_ptp_redirect_rx_packet(adapter,
								 pi) >= 0)
					pi->ptp_enable = true;
			}
		} else
#endif
			/* For T4 Adapters */
		{
			switch (pi->tstamp_config.rx_filter) {
			case HWTSTAMP_FILTER_NONE:
				pi->rxtstamp = false;
				break;
			case HWTSTAMP_FILTER_ALL:
				pi->rxtstamp = true;
				break;
			default:
				pi->tstamp_config.rx_filter =
					HWTSTAMP_FILTER_NONE;
				return -ERANGE;
			}
		}
		return copy_to_user(req->ifr_data, &pi->tstamp_config,
				    sizeof(pi->tstamp_config)) ? -EFAULT : 0;
	default:
		return -EOPNOTSUPP;
	}
	return ret;
}

static int cxgb_change_mtu(struct net_device *dev, int new_mtu)
{
	int ret;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid, new_mtu, -1, -1,
			    -1, -1, true);
	if (!ret)
		dev->mtu = new_mtu;
	else
		goto out;

	if ((is_hashfilter(adapter) && enable_mirror) ||
	    (cxgb4_modparam_enable_ringbb() && !pi->port_id)) {
		ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid_mirror,
				    new_mtu, -1, -1, -1, -1, true);
		if (ret)
			dev_err(adapter->pdev_dev,
				"MTU change for mirror vi %d failed\n",
				pi->viid_mirror);
	}
out:
	return ret;
}

static int cxgb_set_mac_addr(struct net_device *dev, void *p)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct sockaddr *addr = p;
	int ret;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	ret = cxgb4_update_mac_filt(pi, pi->viid, &pi->xact_addr_filt,
			      addr->sa_data, true, &pi->smt_idx);
	if (ret < 0)
		return ret;
	/* Add it to source region as well */
	if (adapter->params.smac_add_support) {
		int smac_ret;

		smac_ret = cxgb_update_smac_addr(dev, addr->sa_data);
		if (smac_ret < 0) {
			dev_err(adapter->pdev_dev,
				"SMAC update failed with error %d\n", smac_ret);
			return smac_ret;
		}
	}

	eth_hw_addr_set(dev, addr->sa_data);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adapter)) {
		unsigned int uld;

		/* Send out the MAC_ADDR_CHANGE event to all the ULD's */
		for (uld = 0; uld < CXGB4_ULD_TYPE_MAX; uld++) {
			mutex_lock(&adapter->uld.uld_mutex);
			if (adapter->uld_handle[uld] && cxgb4_ulds[uld].control)
				cxgb4_ulds[uld].control(adapter->uld_handle[uld],
							CXGB4_CONTROL_MAC_ADDR_CHANGE,
							pi->port_id);
			mutex_unlock(&adapter->uld.uld_mutex);
		}
	}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void cxgb_netpoll(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;

	if (adap->flags & USING_INTR_MULTI) {
		struct sge_eth_rxq *rx = &adap->sge.ethrxq[pi->first_qset];
		int i;

		for (i = pi->nqsets; i; i--, rx++)
			t4_sge_intr_msix(0, &rx->rspq);
	} else {
		t4_intr_handler(adap)(0, adap);
	}
}
#endif

void t4_fatal_err(struct adapter *adap)
{
	int port;

	/* Avoid race between multiple fatal error/ AER / EEH
	 * If fatal error reset/recovery is already in progress return
	 */
	if (test_and_set_bit(ADAPTER_ERROR, &adap->adap_err_state))
		return;

	/* Disable the SGE since ULDs are going to free resources that
	 * could be exposed to the adapter.  RDMA MWs for example...
	 */
	t4_shutdown_adapter(adap);
	for_each_port(adap, port) {
		struct net_device *dev = adap->port[port];

		/* If we get here in very early initialization the network
		 * devices may not have been set up yet.
		 */
		if (dev == NULL)
			continue;

		netif_tx_stop_all_queues(dev);
		netif_carrier_off(dev);
		dev_err(adap->pdev_dev, "%s stopped\n", dev->name);
	}
	dev_alert(adap->pdev_dev, "encountered fatal error, adapter stopped\n");
	cxgb4_work_queue(adap->eeh_workq, &adap->fatal_err_task);
}

void cxgb4_fatal_err(struct net_device *dev)
{
	t4_fatal_err(netdev2adap(dev));
}
EXPORT_SYMBOL(cxgb4_fatal_err);

/*
 * Phase 0 of initialization: contact FW, obtain config, perform basic init.
 *
 * If the firmware we're dealing with has Configuration File support, then
 * we use that to perform all configuration -- either using the configuration
 * file stored in flash on the adapter or using a filesystem-local file
 * if available.
 *
 * If we don't have configuration file support in the firmware, then we'll
 * have to set things up the old fashioned way with hard-coded register
 * writes and firmware commands ...
 */

/*
 * Tweak configuration based on module parameters, etc.  Most of these have
 * defaults assigned to them by Firmware Configuration Files (if we're using
 * them) but need to be explicitly set if we're using hard-coded
 * initialization.  But even in the case of using Firmware Configuration
 * Files, we'd like to expose the ability to change these via module
 * parameters so these are essentially common tweaks/settings for
 * Configuration Files and hard-coded initialization ...
 */
static int adap_init0_tweaks(struct adapter *adapter)
{
	/*
	 * Fix up various Host-Dependent Parameters like Page Size, Cache
	 * Line Size, etc.  The firmware default is for a 4KB Page Size and
	 * 64B Cache Line Size ...
	 */
	t4_fixup_host_params_compat(adapter, PAGE_SIZE, L1_CACHE_BYTES,
				    T5_LAST_REV);

	/*
	 * Process module parameters which affect early initialization.
	 */
	if (rx_dma_offset != 2 && rx_dma_offset != 0) {
		dev_err(adapter->pdev_dev,
			"Ignoring illegal rx_dma_offset=%d, using 2\n",
			rx_dma_offset);
		rx_dma_offset = 2;
	}
	t4_set_reg_field(adapter, A_SGE_CONTROL,
			 V_PKTSHIFT(M_PKTSHIFT),
			 V_PKTSHIFT(rx_dma_offset));

	/*
	 * Don't include the "IP Pseudo Header" in CPL_RX_PKT checksums: Linux
	 * adds the pseudo header itself.
	 */
	t4_tp_wr_bits_indirect(adapter, A_TP_INGRESS_CONFIG,
			       F_CSUM_HAS_PSEUDO_HDR, 0);

	return 0;
}

/* 10Gb/s-BT PHY Support. chip-external 10Gb/s-BT PHYs are complex chips
 * unto themselves and they contain their own firmware to perform their
 * tasks ...
 */
static int phy_aq1202_version(const u8 *phy_fw_data,
			      size_t phy_fw_size)
{
	int offset;

	/* At offset 0x8 you're looking for the primary image's
	 * starting offset which is 3 Bytes wide
	 *
	 * At offset 0xa of the primary image, you look for the offset
	 * of the DRAM segment which is 3 Bytes wide.
	 *
	 * The FW version is at offset 0x27e of the DRAM and is 2 Bytes
	 * wide
	 */
	#define be16(__p) (((__p)[0] << 8) | (__p)[1])
	#define le16(__p) ((__p)[0] | ((__p)[1] << 8))
	#define le24(__p) (le16(__p) | ((__p)[2] << 16))

	offset = le24(phy_fw_data + 0x8) << 12;
	offset = le24(phy_fw_data + offset + 0xa);
	return be16(phy_fw_data + offset + 0x27e);

	#undef be16
	#undef le16
	#undef le24
}

static struct info_10gbt_phy_fw {
	unsigned int phy_fw_id;		/* PCI Device ID */
	char *phy_fw_file;		/* /lib/firmware/ PHY Firmware file */
	int (*phy_fw_version)(const u8 *phy_fw_data, size_t phy_fw_size);
	int phy_flash;			/* Has FLASH for PHY Firmware */
} phy_info_array[] = {
	{
		PHY_AQ1202_DEVICEID,
		PHY_AQ1202_FIRMWARE,
		phy_aq1202_version,
		1,
	},
	{
		PHY_BCM84834_DEVICEID,
		PHY_BCM84834_FIRMWARE,
		NULL,
		0,
	},
	{ 0, NULL, NULL },
};

static struct info_10gbt_phy_fw *find_phy_info(struct adapter *adap)
{
	int i, devid = cxgb4_common_device_id(adap);

	for (i = 0; i < ARRAY_SIZE(phy_info_array); i++) {
		if (phy_info_array[i].phy_fw_id == devid)
			return &phy_info_array[i];
	}
	return NULL;
}

/* Handle updating of chip-external 10Gb/s-BT PHY firmware.  This needs to
 * happen after the FW_RESET_CMD but before the FW_INITIALIZE_CMD.  On error
 * we return a negative error number.  If we transfer new firmware we return 1
 * (from t4_load_phy_fw()).  If we don't do anything we return 0.
 */
static int adap_init0_phy(struct adapter *adap)
{
	struct info_10gbt_phy_fw *phy_info = NULL;
	const struct firmware *phyf;
	int ret;

	/* Use the device ID to determine which PHY file to flash.
	 */
	phy_info = find_phy_info(adap);
	if (!phy_info) {
		dev_warn(adap->pdev_dev,
			 "No PHY Firmware file found for this PHY\n");
		return -EOPNOTSUPP;
	}

	/* If we have a T4 PHY firmware file under /lib/firmware/cxgb4/, then
	 * use that. The adapter firmware provides us with a memory buffer
	 * where we can load a PHY firmware file from the host if we want to
	 * override the PHY firmware File in flash.
	 */
	ret = request_firmware_direct(&phyf, phy_info->phy_fw_file,
				      adap->pdev_dev);
	if (ret < 0) {
		/* For adapters without FLASH attached to PHY for their
		 * firmware, it's obviously a fatal error if we can't get the
		 * firmware to the adapter.  For adapters with PHY firmware
		 * FLASH storage, it's worth a warning if we can't find the
		 * PHY Firmware but we'll neuter the error ...
		 */
		dev_err(adap->pdev_dev, "unable to find PHY Firmware image "
			"/lib/firmware/%s, error %d\n",
			phy_info->phy_fw_file, -ret);
		if (phy_info->phy_flash) {
			int cur_phy_fw_ver = 0;

			t4_phy_fw_ver(adap, &cur_phy_fw_ver);
			dev_warn(adap->pdev_dev, "continuing with, on-adapter "
				 "FLASH copy, version %#x\n", cur_phy_fw_ver);
			ret = 0;
		}

		return ret;
	}

	/* Load PHY Firmware onto adapter.
	 */
	ret = t4_load_phy_fw(adap, MEMWIN_NIC, &adap->win0_lock,
			     phy_info->phy_fw_version,
			     (u8 *)phyf->data, phyf->size);
	if (ret < 0)
		dev_err(adap->pdev_dev, "PHY Firmware transfer error %d\n",
			-ret);
	else if (ret > 0) {
		int new_phy_fw_ver = 0;

		if (phy_info->phy_fw_version)
			new_phy_fw_ver = phy_info->phy_fw_version(phyf->data,
								  phyf->size);
		dev_info(adap->pdev_dev, "Successfully transferred PHY "
			 "Firmware /lib/firmware/%s, version %#x\n",
			 phy_info->phy_fw_file, new_phy_fw_ver);
	}

	release_firmware(phyf);

	return ret;
}

static void adap_config_hpfilter(struct adapter *adapter)
{
	u32 param, val = 0;
	int ret;

	/* Enable HP filter region. Older fw will fail this request and
	 * it is fine.
	 */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_HPFILTER_REGION_SUPPORT));
	ret = t4_set_params(adapter, adapter->mbox, adapter->pf, 0,
			      1, &param, &val);

	/* An error means FW doesn't know about HP filter support,
	 * it's not a problem, don't return an error.
	 */
	if (ret < 0)
		dev_err(adapter->pdev_dev,
			"HP filter region isn't supported by FW\n");
}

static void adap_smt_index(struct adapter *adapter, u32 *smt_start_idx, 
			   u32 *smt_size)
{
	u32 params[2], smt_val[2];
	int ret;

	params[0] = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
		     V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_GET_SMT_START));
	params[1] = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
		     V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_GET_SMT_SIZE));
	ret = t4_query_params(adapter, adapter->mbox, adapter->pf, 0,
			      2, params, smt_val);

	/* if FW doesn't recognize this command then set it to default setting
	 * which is start index as 0 and szie as 256.
	 */
	if (ret < 0) {
		*smt_start_idx = 0;
		*smt_size = SMT_SIZE;
	} else {
		*smt_start_idx = smt_val[0];
		/* smt size can be zero, if nsmt is not yet configured in 
		 * the config file or set as zero, then configure all the 
		 * remaining entries to this PF itself.
		 */
		if (!smt_val[1]) {
			dev_err(adapter->pdev_dev,
				"%s: check the config file for nsmt (%u)\n", 
				__func__, smt_val[1]);
			*smt_size = SMT_SIZE - *smt_start_idx;
		} else {
			*smt_size = smt_val[1];
		}
	}
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/* HMA Definitions */

/* The maximum number of address that can be send in a single FW cmd */
#define HMA_MAX_ADDR_IN_CMD	5

#define HMA_PAGE_SIZE		PAGE_SIZE

/* HW supports max 16M page size */
#define HMA_MAX_PAGE_SIZE	(16UL << 20)

#define HMA_MAX_NO_FW_ADDRESS	(16 << 10)  /* FW supports 16K addresses */

#define HMA_PAGE_ORDER					\
	((HMA_PAGE_SIZE < HMA_MAX_NO_FW_ADDRESS) ?	\
	ilog2(HMA_MAX_NO_FW_ADDRESS / HMA_PAGE_SIZE) : 0)

/* The minimum and maximum possible HMA sizes that can be specified in the FW
 * configuration(in units of MB).
 */
#define HMA_MIN_TOTAL_SIZE	1
#define HMA_MAX_TOTAL_SIZE				\
	(((HMA_PAGE_SIZE << HMA_PAGE_ORDER) *		\
	  HMA_MAX_NO_FW_ADDRESS) >> 20)

static void adap_free_hma_mem(struct adapter *adapter)
{
	struct scatterlist *iter;
	struct page *page;
	int i;

	if (!adapter->hma.sgt)
		return;

	if (adapter->hma.flags & HMA_DMA_MAPPED_FLAG) {
		dma_unmap_sg(adapter->pdev_dev, adapter->hma.sgt->sgl,
			     adapter->hma.sgt->nents, DMA_BIDIRECTIONAL);
		adapter->hma.flags &= ~HMA_DMA_MAPPED_FLAG;
	}

	for_each_sg(adapter->hma.sgt->sgl, iter,
		    adapter->hma.sgt->orig_nents, i) {
		page = sg_page(iter);
		if (page)
			__free_pages(page, HMA_PAGE_ORDER);
	}

	kfree(adapter->hma.phy_addr);
	sg_free_table(adapter->hma.sgt);
	kfree(adapter->hma.sgt);
	adapter->hma.sgt = NULL;
}

static int adap_config_hma(struct adapter *adapter)
{
	struct scatterlist *sgl, *iter;
	struct sg_table *sgt;
	struct page *newpage;
	unsigned int ncmds;
	unsigned int nents;
	unsigned int i, j, k;
	size_t page_size;
	u32 best_page_size;
	u32 param, hma_size;
	u32 page_order;
	int node, ret;

	/* HMA is supported only for T6+ cards.
	 * Avoid initializing HMA in kdump kernels.
	 */
	if (is_kdump_kernel() ||
	    CHELSIO_CHIP_VERSION(adapter->params.chip) < CHELSIO_T6)
		return 0;

	/* Get the HMA region size required by fw */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_HMA_SIZE));
	ret = t4_query_params(adapter, adapter->mbox, adapter->pf, 0,
			      1, &param, &hma_size);
	/* An error means card has its own memory or HMA is not supported by
	 * the firmware. Return without any errors.
	 */
	if (ret || !hma_size)
		return 0;

	if (hma_size < HMA_MIN_TOTAL_SIZE ||
	    hma_size > HMA_MAX_TOTAL_SIZE) {
		dev_err(adapter->pdev_dev,
			"HMA size %uMB beyond bounds(%u-%lu)MB\n",
			hma_size, HMA_MIN_TOTAL_SIZE, HMA_MAX_TOTAL_SIZE);
		return -EINVAL;
	}

	page_size = HMA_PAGE_SIZE;
	page_order = HMA_PAGE_ORDER;
	adapter->hma.sgt = kzalloc(sizeof(*adapter->hma.sgt), GFP_KERNEL);
	if (unlikely(!adapter->hma.sgt)) {
		dev_err(adapter->pdev_dev, "HMA SG table allocation failed\n");
		return -ENOMEM;
	}
	sgt = adapter->hma.sgt;
	/* FW returned value will be in MB's
	 */
	sgt->orig_nents = (hma_size << 20) / (page_size << page_order);
	if (sg_alloc_table(sgt, sgt->orig_nents, GFP_KERNEL)) {
		dev_err(adapter->pdev_dev, "HMA SGL allocation failed\n");
		kfree(adapter->hma.sgt);
		adapter->hma.sgt = NULL;
		return -ENOMEM;
	}

	sgl = adapter->hma.sgt->sgl;
	node = dev_to_node(adapter->pdev_dev);
	for_each_sg(sgl, iter, sgt->orig_nents, i) {
		newpage = alloc_pages_node(node, __GFP_NOWARN | GFP_KERNEL,
					   page_order);
		if (!newpage) {
			dev_err(adapter->pdev_dev,
				"Not enough memory for HMA page allocation\n");
			ret = -ENOMEM;
			goto free_hma;
		}
		sg_set_page(iter, newpage, page_size << page_order, 0);
	}

	sgt->nents = dma_map_sg(adapter->pdev_dev, sgl, sgt->orig_nents,
				DMA_BIDIRECTIONAL);
	if (!sgt->nents) {
		dev_err(adapter->pdev_dev,
			"Not enough memory for HMA DMA mapping");
		ret = -ENOMEM;
		goto free_hma;
	}
	adapter->hma.flags |= HMA_DMA_MAPPED_FLAG;

	best_page_size = HMA_MAX_PAGE_SIZE;
	for_each_sg(sgl, iter, sgt->nents, i) {
		if (!is_power_of_2(sg_dma_len(iter))) {
			best_page_size = min(page_size << page_order,
					     HMA_MAX_PAGE_SIZE);
			break;
		}

		if (sg_dma_len(iter) < best_page_size)
			best_page_size = sg_dma_len(iter);
	}

	nents = (hma_size << 20) / best_page_size;
	adapter->hma.phy_addr = kcalloc(nents, sizeof(dma_addr_t), GFP_KERNEL);
	if (unlikely(!adapter->hma.phy_addr))
		goto free_hma;

	k = 0;
	for_each_sg(sgl, iter, sgt->nents, i) {
		u32 npages = sg_dma_len(iter) / best_page_size;

		for (j = 0; j < npages; j++)
			adapter->hma.phy_addr[k++] =
				sg_dma_address(iter) + (j * best_page_size);
	}

	ncmds = DIV_ROUND_UP(nents, HMA_MAX_ADDR_IN_CMD);
	/* Pass on the addresses to firmware */
	for (i = 0, k = 0; i < ncmds; i++, k += HMA_MAX_ADDR_IN_CMD) {
		struct fw_hma_cmd hma_cmd;
		u8 naddr = HMA_MAX_ADDR_IN_CMD;
		u8 soc = 0, eoc = 0;
		u8 hma_mode = 1; /* Presently we support only Page table mode */

		soc = (i == 0) ? 1 : 0;
		eoc = (i == ncmds - 1) ? 1 : 0;

		/* For last cmd, set naddr corresponding to remaining
		 * addresses
		 */
		if (i == ncmds - 1) {
			naddr = nents % HMA_MAX_ADDR_IN_CMD;
			naddr = naddr ? naddr : HMA_MAX_ADDR_IN_CMD;
		}
		memset(&hma_cmd, 0, sizeof(hma_cmd));
		hma_cmd.op_pkd = htonl(V_FW_CMD_OP(FW_HMA_CMD) |
				       F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
		hma_cmd.retval_len16 = htonl(FW_LEN16(hma_cmd));

		hma_cmd.mode_to_pcie_params =
			htonl(V_FW_HMA_CMD_MODE(hma_mode) |
			      V_FW_HMA_CMD_SOC(soc) | V_FW_HMA_CMD_EOC(eoc));

		/* HMA cmd size specified in MB's */
		hma_cmd.naddr_size =
			htonl(V_FW_HMA_CMD_SIZE(hma_size) |
			      V_FW_HMA_CMD_NADDR(naddr));

		/* Total Page size specified in units of 4K */
		hma_cmd.addr_size_pkd =
			htonl(V_FW_HMA_CMD_ADDR_SIZE(best_page_size >> 12));

		/* Fill the 5 addresses */
		for (j = 0; j < naddr; j++) {
			hma_cmd.phy_address[j] =
				cpu_to_be64(adapter->hma.phy_addr[j + k]);
		}
		ret = t4_wr_mbox(adapter, adapter->mbox, &hma_cmd,
				 sizeof(hma_cmd), &hma_cmd);
		if (ret) {
			dev_err(adapter->pdev_dev,
				"HMA FW command failed with err %d\n", ret);
			goto free_hma;
		}
	}

	if (!ret)
		dev_info(adapter->pdev_dev,
			 "Reserved %uMB host memory for HMA\n", hma_size);
	return ret;

free_hma:
	adap_free_hma_mem(adapter);
	return ret;
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/* If we're a pure NIC driver then disable all offloading facilities.
 * This will allow the firmware to optimize aspects of the hardware
 * configuration which will result in improved performance.
 */
static void cxgb4_offload_caps_remove(struct adapter *adap,
				      struct fw_caps_config_cmd *caps_cmd)
{
	if (!(use_ddr_filters &&
	      CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T4))
		caps_cmd->niccaps &= htons(~FW_CAPS_CONFIG_NIC_HASHFILTER);

	caps_cmd->niccaps &= htons(~FW_CAPS_CONFIG_NIC_ETHOFLD);
	caps_cmd->toecaps = 0;
	caps_cmd->iscsicaps = 0;
	caps_cmd->rdmacaps = 0;
	caps_cmd->fcoecaps = 0;
	caps_cmd->cryptocaps = 0;
}

/*
 * Enable the fw support to return vin and smt indexes as part
 * of VI and VI_MAC commands respectively.
 * For Master PF, it enables this feature and
 * for Slave, it gets the current setting.
 */
static void adap_enable_viid_extn(struct adapter *adap)
{
	int ret;
	u32 param, val;

	/* Check if FW supports returning vin and smt index.
	 * If this is not supported, driver will interpret
	 * these values from viid.
	 */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_OPAQUE_VIID_SMT_EXTN));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
			      1, &param, &val);
	adap->params.viid_smt_extn_support = (ret == 0 && val != 0);
}

/*
 * Attempt to initialize the adapter via a Firmware Configuration File.
 */
static int adap_init0_config(struct adapter *adapter, int reset)
{
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	char *fw_config_file, fw_config_file_path[256];
	u32 finiver, finicsum, cfcsum, param, val;
	struct fw_caps_config_cmd caps_cmd;
	unsigned long mtype = 0, maddr = 0;
	int ret, config_issued = 0;
	const struct firmware *cf;
	char *config_name = NULL;
	int devid = 0;

	/*
	 * Reset device if necessary.
	 */
	if (reset) {
		ret = t4_fw_reset(adapter, adapter->mbox,
				  F_PIORSTMODE | F_PIORST);
		if (ret < 0) {
			dev_warn(adapter->pdev_dev, "Firmware reset failed, "
				 "error %d\n", -ret);
			goto bye;
		}
	}

	/* If this is a 10Gb/s-BT adapter make sure the chip-external
	 * 10Gb/s-BT PHYs have up-to-date firmware.  Note that this step needs
	 * to be performed after any global adapter RESET above since some
	 * PHYs only have local RAM copies of the PHY firmware.
	 */
	devid = cxgb4_common_device_id(adapter);
	if (is_10gbt_device(devid)) {
		ret = adap_init0_phy(adapter);
		if (ret < 0)
			goto bye;
	}
	/*
	 * If we have a T4 configuration file under /lib/firmware/cxgb4/,
	 * then use that.  Otherwise, use the configuration file stored
	 * in the adapter flash ...
	 */
	switch (chip_ver) {
	case CHELSIO_T4:
		if (is_fpga(adapter->params.chip))
			fw_config_file = FW4_FPGA_CFNAME;
		else
			fw_config_file = FW4_CFNAME;
		break;
	case CHELSIO_T5:
		if (is_fpga(adapter->params.chip))
			fw_config_file = FW5_FPGA_CFNAME;
		else
			fw_config_file = FW5_CFNAME;
		break;
	case CHELSIO_T6:
		if (is_fpga(adapter->params.chip))
			fw_config_file = FW6_FPGA_CFNAME;
		else
			fw_config_file = FW6_CFNAME;
		break;
	case CHELSIO_T7:
		if (is_fpga(adapter->params.chip))
			fw_config_file = FW7_FPGA_CFNAME;
		else
			fw_config_file = FW7_CFNAME;
		break;
	default:
		CH_ERR(adapter, "Device %d is not supported\n", devid);
		ret = -EINVAL;
		goto bye;
	}

	ret = request_firmware_direct(&cf, fw_config_file, adapter->pdev_dev);
	if (ret < 0) {
		int cfg_addr = t4_flash_cfg_addr(adapter);

		if (cfg_addr < 0) {
			ret = cfg_addr;
			dev_warn(adapter->pdev_dev, "Finding address for firmware config "
				 "file in flash failed, error %d\n", -ret);
			goto bye;
		}

		config_name = "On FLASH";
		mtype = FW_MEMTYPE_CF_FLASH;
		maddr = cfg_addr;
	} else {
		u32 param, val;

		sprintf(fw_config_file_path,
			"/lib/firmware/%s", fw_config_file);
		config_name = fw_config_file_path;

		ret = t4_flash_location_size(adapter, FLASH_LOC_CFG);
		if (ret < 0 || cf->size >= ret) {
			ret = -ENOMEM;
			dev_warn(adapter->pdev_dev, "Not enough memory in flash "
				 "to hold config file, error %d\n", -ret);
		} else {
			param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
				 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_CF));
			ret = t4_query_params(adapter, adapter->mbox,
					      adapter->pf, 0, 1, &param, &val);
			if (ret == 0) {
				mtype = val >> 8;
				maddr = (val & 0xff) << 16;

				spin_lock(&adapter->win0_lock);
				ret = t4_memory_rw(adapter, MEMWIN_NIC, mtype, maddr,
						   cf->size, (__be32*)cf->data,
						   T4_MEMORY_WRITE);
				spin_unlock(&adapter->win0_lock);
				if (ret)
					dev_warn(adapter->pdev_dev, "Writing firmware config "
						 "file to adapter failed, "
						 "error %d\n", -ret);
			} else
				dev_warn(adapter->pdev_dev, "Finding adapter memory address to "
					 "write firmware config file failed, "
					 "error %d\n", -ret);
		}

		release_firmware(cf);
		if (ret)
			goto bye;
	}
	val = 0;

	/* Ofld + Hash filter is supported. Older fw will fail this request and
	 * it is fine.
	 */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_HASHFILTER_WITH_OFLD));
	ret = t4_set_params(adapter, adapter->mbox, adapter->pf, 0,
			      1, &param, &val);

	/* FW doesn't know about Hash filter + ofld support,
	 * it's not a problem, don't return an error.
	 */
	if (ret < 0)
		dev_warn(adapter->pdev_dev,
			"Hash filter with ofld is not supported by FW\n");

	/*
	 * Issue a Capability Configuration command to the firmware to get it
	 * to parse the Configuration File.  We don't use t4_fw_config_file()
	 * because we want the ability to modify various features after we've
	 * processed the configuration file ...
	 */
	memset(&caps_cmd, 0, sizeof(caps_cmd));
	caps_cmd.op_to_write =
		htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
		      F_FW_CMD_REQUEST |
		      F_FW_CMD_READ);
	caps_cmd.cfvalid_to_len16 =
		htonl(F_FW_CAPS_CONFIG_CMD_CFVALID |
		      V_FW_CAPS_CONFIG_CMD_MEMTYPE_CF(mtype) |
		      V_FW_CAPS_CONFIG_CMD_MEMADDR64K_CF(maddr >> 16) |
		      FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adapter, adapter->mbox, &caps_cmd, sizeof(caps_cmd),
			 &caps_cmd);

	/* If the CAPS_CONFIG failed with an ENOENT (for a Firmware
	 * Configuration File in FLASH), our last gasp effort is to use the
	 * Firmware Configuration File which is embedded in the firmware.  A
	 * very few early versions of the firmware didn't have one embedded
	 * but we can ignore those.
	 */
	if (ret == -ENOENT) {
		memset(&caps_cmd, 0, sizeof(caps_cmd));
		caps_cmd.op_to_write =
			htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
					F_FW_CMD_REQUEST |
					F_FW_CMD_READ);
		caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
		ret = t4_wr_mbox(adapter, adapter->mbox, &caps_cmd,
				sizeof(caps_cmd), &caps_cmd);
		config_name = "Firmware Default";
	}

	config_issued = 1;
	if (ret < 0)
		goto bye;

	finiver = ntohl(caps_cmd.finiver);
	finicsum = ntohl(caps_cmd.finicsum);
	cfcsum = ntohl(caps_cmd.cfcsum);
	if (finicsum != cfcsum)
		dev_warn(adapter->pdev_dev, "Configuration File checksum "
			 "mismatch: [fini] csum=%#x, computed csum=%#x\n",
			 finicsum, cfcsum);

#ifndef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_offload_caps_remove(adapter, &caps_cmd);
#endif

	/*
	 * And now tell the firmware to use the configuration we just loaded.
	 */
	caps_cmd.op_to_write =
		htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
		      F_FW_CMD_REQUEST |
		      F_FW_CMD_WRITE);
	caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adapter, adapter->mbox, &caps_cmd, sizeof(caps_cmd),
			 NULL);
	if (ret < 0) {
		dev_warn(adapter->pdev_dev, "Unable to finalize Firmware Capabilities "
			"%d\n", -ret);
		goto bye;
	}

#ifdef CHELSIO_T4_DIAGS
	if (diag_memtest_size) {
		ret = t4_diag_memtest(adapter, FW_DIAG_CMD_MEMDIAG_TEST_INIT,
				      NULL, &diag_memtest_size, NULL);
		if (ret) {
			dev_err(adapter->pdev_dev,
				"Initializing Diag Memory failed. ret: %d\n",
				ret);
			goto bye;
		}
	}
#endif /* CHELSIO_T4_DIAGS */

	/* Disabling Ringbackbone for T4 and less
	 */ 
	if (cxgb4_modparam_enable_ringbb() && chip_ver <= CHELSIO_T4) {
		dev_warn(adapter->pdev_dev,
			 "Ringbackbone supported only on T5 and greater adapters\n");
		enable_ringbb = false;
	}

	if (cxgb4_modparam_enable_ringbb()) {
		dev_info(adapter->pdev_dev, "Enabling Ringbackbone features..\n");
		if (t4_configure_add_smac(adapter))
			dev_warn(adapter->pdev_dev,
				 "Using older FW or error in configuring SMAC addition API, You may face multicast packet loops in ring backbone configuration\n");

		ret = t4_configure_ringbb(adapter);
		if (ret < 0) {
			dev_warn(adapter->pdev_dev, "Ringbackbone initialization failed, err %d\n",
				 ret);
			goto bye;
		}
	}
	/*
	 * Tweak configuration based on system architecture, module
	 * parameters, etc.
	 */
	ret = adap_init0_tweaks(adapter);
	if (ret < 0)
		goto bye;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	ret = adap_config_hma(adapter);
	if (ret)
		dev_err(adapter->pdev_dev,
			"HMA configuration failed with error %d\n", ret);
#endif
	if (chip_ver >= CHELSIO_T6) {

		/* Request HP filter support */
		adap_config_hpfilter(adapter);

		ret = setup_ppod_edram(adapter);
		if (!ret)
			dev_info(adapter->pdev_dev, "Successfully enabled "
				 "ppod edram feature\n");
	}

	adap_enable_viid_extn(adapter);
	/*
	 * And finally tell the firmware to initialize itself using the
	 * parameters from the Configuration File.
	 */
	ret = t4_fw_initialize(adapter, adapter->mbox);
	if (ret < 0) {
		dev_warn(adapter->pdev_dev, "Initializing Firmware failed, "
			 "error %d\n", -ret);
		goto bye;
	}

	/* Emit Firmware Configuration File information and return
	 * successfully.
	 */
	dev_info(adapter->pdev_dev, "Successfully configured using Firmware "
		 "Configuration File \"%s\", version %#x, computed checksum %#x\n",
		 config_name, finiver, cfcsum);
	return 0;

	/*
	 * Something bad happened.  Return the error ...  (If the "error"
	 * is that there's no Configuration File on the adapter we don't
	 * want to issue a warning since this is fairly common.)
	 */
bye:
	if (config_issued && ret != -ENOENT)
		dev_warn(adapter->pdev_dev, "Configuration error %d. "
			 "Configuration file \"%s\".\n",
			 -ret, config_name);
	return ret;
}

static struct fw_info fw_info_array[] = {
	{
		.chip = CHELSIO_T4,
		.fs_name = FW4_CFNAME,
		.fw_mod_name = FW4_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T4,
			.fw_ver = __cpu_to_be32(FW_VERSION(T4)),
			.intfver_nic = FW_INTFVER(T4, NIC),
			.intfver_vnic = FW_INTFVER(T4, VNIC),
			.intfver_ofld = FW_INTFVER(T4, OFLD),
			.intfver_ri = FW_INTFVER(T4, RI),
			.intfver_iscsipdu = FW_INTFVER(T4, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T4, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T4, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T4, FCOE),
		},
	}, {
		.chip = CHELSIO_T5,
		.fs_name = FW5_CFNAME,
		.fw_mod_name = FW5_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T5,
			.fw_ver = __cpu_to_be32(FW_VERSION(T5)),
			.intfver_nic = FW_INTFVER(T5, NIC),
			.intfver_vnic = FW_INTFVER(T5, VNIC),
			.intfver_ofld = FW_INTFVER(T5, OFLD),
			.intfver_ri = FW_INTFVER(T5, RI),
			.intfver_iscsipdu = FW_INTFVER(T5, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T5, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T5, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T5, FCOE),
		},
	}, {
		.chip = CHELSIO_T6,
		.fs_name = FW6_CFNAME,
		.fw_mod_name = FW6_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T6,
			.fw_ver = __cpu_to_be32(FW_VERSION(T6)),
			.intfver_nic = FW_INTFVER(T6, NIC),
			.intfver_vnic = FW_INTFVER(T6, VNIC),
			.intfver_ofld = FW_INTFVER(T6, OFLD),
			.intfver_ri = FW_INTFVER(T6, RI),
			.intfver_iscsipdu = FW_INTFVER(T6, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T6, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T6, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T6, FCOE),
		},
	}, {
		.chip = CHELSIO_T7,
		.fs_name = FW7_CFNAME,
		.fw_mod_name = FW7_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T7,
			.fw_ver = __cpu_to_be32(FW_VERSION(T7)),
			.intfver_nic = FW_INTFVER(T7, NIC),
			.intfver_vnic = FW_INTFVER(T7, VNIC),
			.intfver_ofld = FW_INTFVER(T7, OFLD),
			.intfver_ri = FW_INTFVER(T7, RI),
			.intfver_iscsipdu = FW_INTFVER(T7, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T7, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T7, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T7, FCOE),
		},
	}
};

static struct fw_info *find_fw_info(int chip)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fw_info_array); i++) {
		if (fw_info_array[i].chip == chip)
			return (&fw_info_array[i]);
	}
	return (NULL);
}

static int adap_init_check_config(struct adapter *adap, int reset)
{
	u32 params, val;
	int ret;

	dev_info(adap->pdev_dev, "Coming up as MASTER: "
		 "Initializing adapter\n");

	/* Find out whether we're dealing with a version of the
	 * firmware which has configuration file support.
	 */
	params = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		     V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_CF));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
			      &params, &val);

	/* If the firmware doesn't support Configuration Files, return
	 * an error.
	 */
	if (ret < 0) {
		dev_err(adap->pdev_dev, "firmware doesn't support "
			"Firmware Configuration Files\n");
		return ret;
	}

	/* The firmware provides us with a memory buffer where we can
	 * load a Configuration File from the host if we want to
	 * override the Configuration File in flash.
	 */
	ret = adap_init0_config(adap, reset);
	if (ret == -ENOENT)
		dev_err(adap->pdev_dev, "no Configuration File "
				"present on adapter.\n");
	if (ret < 0)
		dev_err(adap->pdev_dev, "could not initialize "
				"adapter, error %d\n", -ret);
	return ret;
}

static int adap_init1(struct adapter *adap, struct fw_caps_config_cmd *c)
{
	int ret=0;
	u32 params, val;

	ret = adap_init_check_config(adap, 0); /* reset = 0 */
	if (ret < 0)
		goto bye;

	/* Now that we've successfully configured and initialized the adapter
	 * can ask the Firmware what resources it has provisioned for us.
	 */
	ret = t4_get_pfres(adap);
	if (ret) {
		dev_err(adap->pdev_dev,
			"Unable to retrieve resource provisioning information\n");
		goto bye;
	}

	/* Give the SGE code a chance to pull in anything that it needs ...
	 * Note that this must be called after we retrieve our VPD parameters
	 * in order to know how to convert core ticks to seconds, etc.
	 */
	ret = t4_sge_init(adap);
	if (ret < 0)
		goto bye;

	/* Grab some of our basic fundamental operating parameters.
	 */

	/* If we're running on newer firmware, let it know that we're
	 * prepared to deal with encapsulated CPL messages.  Older
	 * firmware won't understand this and we'll just get
	 * unencapsulated messages ...
	 */
	params = FW_PARAM_PFVF(CPLFW4MSG_ENCAP);
	val = 1;
	(void) t4_set_params(adap, adap->mbox, adap->pf, 0, 1, &params, &val);

	/* Find out whether we're allowed to use the T5+ ULPTX MEMWRITE DSGL
	 * capability.  Earlier versions of the firmware didn't have the
	 * ULPTX_MEMWRITE_DSGL so we'll interpret a query failure as no
	 * permission to use ULPTX MEMWRITE DSGL.
	 */
	if (is_t4(adap->params.chip))
		adap->params.ulptx_memwrite_dsgl = false;
	else {
		params = FW_PARAM_DEV(ULPTX_MEMWRITE_DSGL);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
				      1, &params, &val);
		adap->params.ulptx_memwrite_dsgl = (ret == 0 && val != 0);

		/* See if FW supports writing 512 pbl entries per FR MR*/
		params = FW_PARAM_DEV(DEV_512SGL_MR);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
				      1, &params, &val);
		adap->params.dev_512sgl_mr = (ret == 0 && val != 0);

		t4_write_reg(adap, A_SGE_STAT_CFG, V_STATSOURCE_T5(7) |
			     (is_t5(adap->params.chip) ? V_STATMODE(0) :
			      V_T6_STATMODE(0)));
	}

bye:
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_uld_cleanup(adap);
	adap_free_hma_mem(adap);
#endif
	if (ret != -ETIMEDOUT && ret != -EIO)
		cxgb4_common_fw_free(adap);
	return ret;
}

static int adap_init0(struct adapter *adap, int vpd_skip)
{
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	struct fw_caps_config_cmd caps_cmd;
	u32 port_vec, v, params[7], val[7];
	enum dev_state state;
	int ret, reset;

	/* Grab Firmware Device Log parameters as early as possible so we have
	 * access to it for debugging, etc.
	 */
	ret = t4_init_devlog_params(adap, fw_attach);
	if (ret < 0)
		return !fw_attach ? 0 : ret;

	/*
	 * If we're not attaching to the firmware, there's nothing more we do
	 * here ...
	 */
	if (!fw_attach)
		return 0;

	ret = cxgb4_common_fw_init(adap, &state);
	if (ret < 0)
		return ret;

	if (ret == adap->mbox)
		adap->flags |= MASTER_PF;

	/* TODO: Resetting will cause Firmware to reload, which will
	 * result in resetting DPU. So, skip reset for Platform Device.
	 */
	reset = cxgb4_is_platform_device(adap) ? 0 : 1;

	/*
	 * If we're the Master PF Driver and the device is uninitialized,
	 * then let's consider upgrading the firmware ...  (We always want
	 * to check the firmware version number in order to A. get it for
	 * later reporting and B. to warn if the currently loaded firmware
	 * is excessively mismatched relative to the driver.)
	 */
	t4_get_version_info(adap);
	ret = t4_check_fw_version(adap);
	/* If firmware is too old (not supported by driver) force an update. */
	if (ret == -EFAULT)
		state = DEV_STATE_UNINIT;
	if ((adap->flags & MASTER_PF) && state != DEV_STATE_INIT) {
		const struct firmware *fw;
		const u8 *fw_data = NULL;
		unsigned int fw_size = 0;
		struct fw_info *fw_info;
		struct fw_hdr *card_fw;

		/* This is the firmware whose headers the driver was compiled
		 * against
		 */
		fw_info = find_fw_info(chip_ver);
		if (fw_info == NULL) {
			CH_ERR(adap,
				"unable to look up firmware information for chip %d.\n",
				chip_ver);
			return -EINVAL;
		}

		/* allocate memory to read the header of the firmware on the
		 * card
		 */
		card_fw = t4_alloc_mem(sizeof(*card_fw));
		if (!card_fw) {
			ret = -ENOMEM;
			goto bye;
		}

		/* Get FW from from /lib/firmware/ */
		ret = request_firmware_direct(&fw, fw_info->fw_mod_name,
					      adap->pdev_dev);
		if (ret < 0) {
			dev_info(adap->pdev_dev,
				"firmware image %s not found; continuing with on-adapter Firmware version %d.%d.%d.%d\n",
				fw_info->fw_mod_name,
				 G_FW_HDR_FW_VER_MAJOR(adap->params.fw_vers),
				 G_FW_HDR_FW_VER_MINOR(adap->params.fw_vers),
				 G_FW_HDR_FW_VER_MICRO(adap->params.fw_vers),
				 G_FW_HDR_FW_VER_BUILD(adap->params.fw_vers));
		} else {
			fw_data = fw->data;
			fw_size = fw->size;
		}

		/* upgrade FW logic */
		ret = t4_prep_fw(adap, fw_info, fw_data, fw_size, card_fw,
				 t4_fw_install, state, &reset);

		/* Cleaning up */
		release_firmware(fw);
		t4_free_mem(card_fw);

		if (ret < 0)
			goto bye;
	}

	/* If the firmware is initialized already, emit a simply note to that
	 * effect. Otherwise, it's time to try initializing the adapter.
	 */
	if (state == DEV_STATE_INIT) {
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		ret = adap_config_hma(adap);
		if (ret)
			dev_err(adap->pdev_dev,
				"HMA configuration failed with error %d\n",
				ret);
#endif
		adap_enable_viid_extn(adap);

		dev_info(adap->pdev_dev, "Coming up as %s: "
			 "Adapter already initialized\n",
			 adap->flags & MASTER_PF ? "MASTER" : "SLAVE");
	} else {
		if(adap_init_check_config(adap, reset))
			goto bye;
	}

	/* Now that we've successfully configured and initialized the adapter
	 * (or found it already initialized), we can ask the Firmware what
	 * resources it has provisioned for us.
	 */
	ret = t4_get_pfres(adap);
	if (ret) {
		dev_err(adap->pdev_dev,
			"Unable to retrieve resource provisioning information\n");
		goto bye;
	}

	/*
	 * Grab VPD parameters.  This should be done after we establish a
	 * connection to the firmware since some of the VPD parameters
	 * (notably the Core Clock frequency) are retrieved via requests to
	 * the firmware.  On the other hand, we need these fairly early on
	 * so we do this right after getting ahold of the firmware.
	 *
	 * We need to do this after initializing the adapter because someone
	 * could have FLASHed a new VPD which won't be read by the firmware
	 * until we do the RESET ...
	 */
	if (!vpd_skip) {
		ret = t4_get_vpd_params(adap, &adap->params.vpd);
		if (ret < 0)
			goto bye;
	}

	/*
	 * Find out what ports are available to us.
	 */
	v =
	    V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_PORTVEC);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &v, &port_vec);
	if (ret < 0)
		goto bye;

#ifdef CHELSIO_T4_DIAGS
	/*
	 * If attach_pf0 is specified we can only access a single port because
	 * the default configuration only provisions a single Virtual Interface
	 * for PF0. So we whack the Port Vector bitmask to only include the
	 * lowest available port number.
	 */
	if (attach_pf0)
		port_vec ^= (port_vec & (port_vec - 1));
#endif

	adap->params.nports = hweight32(port_vec);
	adap->params.portvec = port_vec;

	/* Give the SGE code a chance to pull in anything that it needs ...
	 * Note that this must be called after we retrieve our VPD parameters
	 * in order to know how to convert core ticks to seconds, etc.
	 */
	ret = t4_sge_init(adap);
	if (ret < 0)
		goto bye;

	/* Grab the SGE Doorbell Queue Timer values.  If successful, that
	 * indicates that the Firmware and Hardware support this.
	 */
	params[0] = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DBQ_TIMERTICK));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
			      1, params, val);
	if (!ret) {
		adap->sge.dbqtimer_tick = val[0];
		ret = t4_read_sge_dbqtimers(adap,
					    ARRAY_SIZE(adap->sge.dbqtimer_val),
					    adap->sge.dbqtimer_val);
	}
	if (!ret)
		adap->flags |= SGE_DBQ_TIMER;

	if (is_bypass_device(cxgb4_common_device_id(adap)))
		adap->params.bypass = 1;

	/*
	 * Grab some of our basic fundamental operating parameters.
	 */
	params[0] = FW_PARAM_PFVF(EQ_START);
	params[1] = FW_PARAM_PFVF(L2T_START);
	params[2] = FW_PARAM_PFVF(L2T_END);
	params[3] = FW_PARAM_PFVF(IQFLINT_START);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 4, params, val);
	if (ret < 0)
		goto bye;
	adap->sge.egr_start = val[0];
	adap->l2t_start = val[1];
	adap->l2t_end = val[2];
	adap->sge.ingr_start = val[3];

	if (chip_ver > CHELSIO_T5) {
		/* Read the raw mps entries. In T6, the last 2 tcam entries
		 * are reserved for raw mac addresses (rawf = 2, one per port).
		 */
		params[0] = FW_PARAM_PFVF(RAWF_START);
		params[1] = FW_PARAM_PFVF(RAWF_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (ret == 0) {
			adap->rawf_start = val[0];
			adap->rawf_cnt = val[1] - val[0] + 1;
		}
	}

	/* qids (ingress/egress) returned from firmware can be anywhere
	 * in the range from EQ(IQFLINT)_START to EQ(IQFLINT)_END.
	 * Hence driver needs to allocate memory for this range to
	 * store the queue info. Get the highest IQFLINT/EQ index returned
	 * in FW_EQ_*_CMD.alloc command.
	 */
	params[0] = FW_PARAM_PFVF(EQ_END);
	params[1] = FW_PARAM_PFVF(IQFLINT_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (ret < 0)
		goto bye;
	adap->sge.egr_sz = val[0] - adap->sge.egr_start + 1;
	adap->sge.ingr_sz = val[1] - adap->sge.ingr_start + 1;

	cxgb4_sge_egr_map_init(adap);

	adap->sge.ingr_map = kcalloc(adap->sge.ingr_sz,
				     sizeof(*adap->sge.ingr_map), GFP_KERNEL);
	if (!adap->sge.ingr_map) {
		ret = -ENOMEM;
		goto bye;
	}

	/* Allocate the memory for the vaious egress queue bitmaps
	 * ie starving_fl, txq_maperr and blocked_fl.
	 */
	adap->sge.starving_fl =	kcalloc(BITS_TO_LONGS(adap->sge.egr_sz),
					sizeof(long), GFP_KERNEL);
	if (!adap->sge.starving_fl) {
		ret = -ENOMEM;
		goto bye;
	}

	adap->sge.blocked_fl = kcalloc(BITS_TO_LONGS(adap->sge.egr_sz),
				       sizeof(long), GFP_KERNEL);
	if (!adap->sge.blocked_fl) {
		ret = -ENOMEM;
		goto bye;
	}

	params[0] = FW_PARAM_PFVF(CLIP_START);
	params[1] = FW_PARAM_PFVF(CLIP_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (ret < 0)
		goto bye;
	adap->clipt_start = val[0];
	adap->clipt_end = val[1];

	/* Get the supported number of traffic classes */
	params[0] = FW_PARAM_DEV(NUM_TM_CLASS);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, params, val);
	if (ret < 0) {
		/*
		 * We don't yet have a PARAMs calls to retrieve the number of
		 * Traffic Classes supported by the hardware/firmware.
		 * So we hard code it here for now.
		 */
		adap->params.nsched_cls = is_t4(adap->params.chip) ? 15 : 16;
	} else
		adap->params.nsched_cls = val[0];

	/* If we're running on newer firmware, let it know that we're
	 * prepared to deal with encapsulated CPL messages.  Older
	 * firmware won't understand this and we'll just get
	 * unencapsulated messages ...
	 */
	params[0] = FW_PARAM_PFVF(CPLFW4MSG_ENCAP);
	val[0] = 1;
	(void)t4_set_params(adap, adap->mbox, adap->pf, 0, 1, params, val);

	/*
	 * Find out whether we're allowed to use the T5+ ULPTX MEMWRITE DSGL
	 * capability.  Earlier versions of the firmware didn't have the
	 * ULPTX_MEMWRITE_DSGL so we'll interpret a query failure as no
	 * permission to use ULPTX MEMWRITE DSGL.
	 */
	if (is_t4(adap->params.chip)) {
		adap->params.ulptx_memwrite_dsgl = false;
	} else {
		params[0] = FW_PARAM_DEV(ULPTX_MEMWRITE_DSGL);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
				      1, params, val);
		adap->params.ulptx_memwrite_dsgl = (ret == 0 && val[0] != 0);
	}

	/* See if FW supports FW_RI_FR_NSMR_TPTE_WR work request */
	params[0] = FW_PARAM_DEV(RI_FR_NSMR_TPTE_WR);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
			      1, params, val);
	adap->params.fr_nsmr_tpte_wr_support = (ret == 0 && val[0] != 0);

	/* See if FW supports writing 512 pbl entries per FR MR*/
	params[0] = FW_PARAM_DEV(DEV_512SGL_MR);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, params, val);
	adap->params.dev_512sgl_mr = (ret == 0 && val[0] != 0);

	/* See if FW supports FW_FILTER2 work request */
	if (is_t4(adap->params.chip)) {
		adap->params.filter2_wr_support = 0;
	} else {
		params[0] = FW_PARAM_DEV(FILTER2_WR);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
				      1, params, val);
		adap->params.filter2_wr_support = (ret == 0 && val[0] != 0);
	}

	/* See if FW supports CLIP2_CMD */
	params[0] = FW_PARAM_DEV(CLIP2_CMD);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, params, val);
	adap->params.clip2_cmd_support = (!ret && val[0]);

	/*
	 * Get device capabilities so we can determine what resources we need
	 * to manage.
	 */
	memset(&caps_cmd, 0, sizeof(caps_cmd));
	caps_cmd.op_to_write = htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
				     F_FW_CMD_REQUEST | F_FW_CMD_READ);
	caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adap, adap->mbox, &caps_cmd, sizeof(caps_cmd),
			 &caps_cmd);
	if (ret < 0)
		goto bye;

	ret = cxgb4_tid_info_init(adap, &caps_cmd);
	if (ret) {
		dev_warn(adap->pdev_dev,
			 "could not allocate TID table, continuing\n");
		cxgb4_offload_caps_remove(adap, &caps_cmd);
		caps_cmd.niccaps &= htons(~FW_CAPS_CONFIG_NIC_HASHFILTER);
	}

	if (cxgb4_hash_filter_init(adap) < 0)
		goto bye;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	ret = cxgb4_uld_init(adap, &caps_cmd);
	if (ret)
		goto bye;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	/*
	 * The MTU/MSS Table is initialized by now, so load their values.  If
	 * we're initializing the adapter, then we'll make any modifications
	 * we want to the MTU/MSS Table and also initialize the congestion
	 * parameters.
	 */
	t4_read_mtu_tbl(adap, adap->params.mtus, NULL);
	if (state != DEV_STATE_INIT) {
		int i;

		/*
		 * The default MTU Table contains values 1492 and 1500.
		 * However, for TCP, it's better to have two values which are
		 * a multiple of 8 +/- 4 bytes apart near this popular MTU.
		 * This allows us to have a TCP Data Payload which is a
		 * multiple of 8 regardless of what combination of TCP Options
		 * are in use (always a multiple of 4 bytes) which is
		 * important for performance reasons.  For instance, if no
		 * options are in use, then we have a 20-byte IP header and a
		 * 20-byte TCP header.  In this case, a 1500-byte MSS would
		 * result in a TCP Data Payload of 1500 - 40 == 1460 bytes
		 * which is not a multiple of 8.  So using an MSS of 1488 in
		 * this case results in a TCP Data Payload of 1448 bytes which
		 * is a multiple of 8.  On the other hand, if 12-byte TCP Time
		 * Stamps have been negotiated, then an MTU of 1500 bytes
		 * results in a TCP Data Payload of 1448 bytes which, as
		 * above, is a multiple of 8 bytes ...
		 */
		for (i = 0; i < NMTUS; i++)
			if (adap->params.mtus[i] == 1492) {
				adap->params.mtus[i] = 1488;
				break;
			}

		t4_load_mtus(adap, adap->params.mtus, adap->params.a_wnd,
			     adap->params.b_wnd);
	}
	t4_init_sge_params(adap);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if ((adap->uld.vres.qp.size % (1 << adap->params.sge.eq_qpp)) ||
	    (adap->uld.vres.cq.size % (1 << adap->params.sge.iq_qpp)))
		BUG();
#endif

	adap->flags |= FW_OK;
	t4_init_tp_params(adap, true);
	adap->params.drv_memwin = MEMWIN_NIC;
	return 0;

	/*
	 * Something bad happened.  If a command timed out or failed with EIO
	 * FW does not operate within its spec or something catastrophic
	 * happened to HW/FW, stop issuing commands.
	 */
bye:
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_uld_cleanup(adap);
	adap_free_hma_mem(adap);
#endif

	cxgb4_sge_egr_map_destroy(adap);
	kfree(adap->sge.ingr_map);
	kfree(adap->sge.starving_fl);
	kfree(adap->sge.blocked_fl);
	if (ret != -ETIMEDOUT && ret != -EIO)
		cxgb4_common_fw_free(adap);
	return ret;
}

#ifndef PCI_RESET_SLOTBUS
static int pci_parent_bus_reset(struct pci_dev *dev)
{
        u16 ctrl;
        struct pci_dev *pdev;

        if (pci_is_root_bus(dev->bus) || dev->subordinate || !dev->bus->self)
                return -ENOTTY;

        list_for_each_entry(pdev, &dev->bus->devices, bus_list) {
		if (pdev->vendor == PCI_VENDOR_ID_CHELSIO)
			pci_save_state(pdev);
	}

	/* Assert the Secondary Bus Reset */
	pci_read_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, &ctrl);
	ctrl |= PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, ctrl);

	/* Read config again to flush previous write */
	pci_read_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, &ctrl);

	msleep(100);

	/* De-assert the Secondary Bus Reset */
	ctrl &= ~PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, ctrl);

	/* Wait for completion */
	msleep(1000);

	list_for_each_entry(pdev, &dev->bus->devices, bus_list) {
		if (pdev->vendor == PCI_VENDOR_ID_CHELSIO) {
			pci_restore_state(pdev);
			pci_save_state(pdev);
		}
	}
        return 0;
}
#endif

#define FATAL_ERR_RETRY_COUNT 3

static int cxgb_reset_pci(struct adapter *adap, int reset)
{
	int i, ret = 0;

	if (adap->flags & DEV_ENABLED) {
		struct pci_dev *pdev = cxgb4_pci_dev(adap);

		if (reset) {
			for (i = 0; i < FATAL_ERR_RETRY_COUNT; i++) {
#ifdef PCI_RESET_SLOTBUS
				if (!pci_probe_reset_slot(pdev->slot))
					ret = pci_try_reset_slot(pdev->slot);
				else if (!pci_probe_reset_bus(pdev->bus))
					ret = pci_try_reset_bus(pdev->bus);
#else
				msleep(10);
				ret = pci_parent_bus_reset(pdev);
#endif
				if (!ret)
					break;
			}
		}

		pci_disable_device(pdev);
		adap->flags &= ~DEV_ENABLED;
	}
	return ret;
}

static pci_ers_result_t t4_fatal_err_detected(struct adapter *adap, int reset)
{
	int i;

	adap->flags &= ~FW_OK;

	if (adap->flags & FULL_INIT_DONE)
		quiesce_rx(adap);

	rtnl_lock();
	spin_lock(&adap->stats_lock);
	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];

		netif_device_detach(dev);
		netif_carrier_off(dev);
	}
	spin_unlock(&adap->stats_lock);
	rtnl_unlock();

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adap)) {
		/* let any in-flight DMA finish */
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(usecs_to_jiffies(1000000));

		/*
		 * Flush any pending skbs from all l2t entries to
		 * ensure that ULD arp failure handlers are not called
		 * after we begin ULD recovery.
		 */
		t4_flush_l2t_arpq(adap->l2t);

		notify_ulds(adap, CXGB4_STATE_START_RECOVERY);
		detach_ulds(adap);
		cxgb4_uld_queues_cleanup(adap);
	}
#endif

	/* reenable the SGE */
	t4_set_reg_field(adap, A_SGE_CONTROL, F_GLOBALENABLE, F_GLOBALENABLE);

	if (adap->flags & FULL_INIT_DONE) {
		/* If we allocated filters, free up state associated with any
		 * valid filters ...
		 */
		cxgb4_filter_clear_all(adap);

		disable_interrupts(adap);
		rtnl_lock();
		cxgb_down(adap);
		rtnl_unlock();
	}

	if (cxgb_reset_pci(adap, reset))
		return PCI_ERS_RESULT_DISCONNECT;
	else
		return 0;
}

static pci_ers_result_t cxgb_enable_pci_device(struct adapter *adap)
{
	struct pci_dev *pdev = cxgb4_pci_dev(adap);
	int i;

	for (i = 0; i < FATAL_ERR_RETRY_COUNT; i++) {
		if (!cxgb_reset_pci(adap, /*reset=*/1)) {
			if (!(adap->flags & DEV_ENABLED)) {
				if (!pci_enable_device(pdev)) {
					dev_err(&pdev->dev,
						"Cannot reenable PCI device after reset\n");
					continue;
				}
				adap->flags |= DEV_ENABLED;
			}

			pci_set_master(pdev);
			pci_restore_state(pdev);
			pci_save_state(pdev);
			if (!t4_wait_dev_ready(adap))
				return 0;
		}
	}

	if (adap->flags & DEV_ENABLED) {
		pci_disable_device(pdev);
		adap->flags &= ~DEV_ENABLED;
	}
	return PCI_ERS_RESULT_DISCONNECT;
}

static pci_ers_result_t t4_fatal_slot_reset(struct adapter *adap, bool aer)
{
	struct pci_dev *pdev = cxgb4_pci_dev(adap);
	struct fw_caps_config_cmd c;
	enum dev_state state;
	int ret, i;

	if (!(adap->flags & DEV_ENABLED)) {
		if (pci_enable_device(pdev)) {
			dev_err(&pdev->dev, "Cannot reenable PCI "
				"device after reset\n");
			return PCI_ERS_RESULT_DISCONNECT;
		}
		adap->flags |= DEV_ENABLED;
	}

	pci_set_master(pdev);
	pci_restore_state(pdev);
	pci_save_state(pdev);

	if (aer)
		pci_aer_clear_nonfatal_status(pdev);

	if (t4_wait_dev_ready(adap) < 0) {
		if (cxgb_enable_pci_device(adap))
			return PCI_ERS_RESULT_DISCONNECT;
	}

	cxgb4_common_setup_memwin(adap);
	cxgb4_common_setup_memwin_rdma(adap);

	/* Grab Firmware Device Log parameters as early as possible so we have
	 * access to it for debugging, etc.
	 */
        ret = t4_init_devlog_params(adap, fw_attach);
        if (ret < 0)
               	goto out;

	ret = t4_fw_hello(adap, adap->mbox, adap->mbox, MASTER_MAY, &state);
	if ((ret < 0) && is_kdump_kernel())
		ret = t4_fw_hello(adap, adap->mbox, adap->mbox,	MASTER_MUST, &state);

	if(ret < 0) {
		CH_ERR(adap, "could not connect to FW, error %d\n", -ret);
		goto out;
	}

	adap->params.drv_memwin = MEMWIN_NIC;
	adap->flags |= FW_OK;
	if (ret == adap->mbox)
		adap->flags |= MASTER_PF;

	if (adap_init1(adap, &c))
		goto out;

	t4_sge_init_tasklet(adap);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (t4_reset_l2t(adap->l2t)) {
		dev_alert(adap->pdev_dev, "L2T not empty after reset\n");
		goto out_stop_sge;
	}
#endif
	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);
		u8 vivld = 0, vin = 0;

		ret = t4_alloc_vi(adap, adap->pf, pi->lport, adap->pf, 0, 1,
				  NULL, NULL, &vivld, &vin);
		if (ret < 0)
			goto out_free_vi;
		pi->viid = ret;
		pi->xact_addr_filt = -1;

		/* If fw supports returning the VIN as part of FW_VI_CMD,
		 * save the returned values.
		 */
		if (adap->params.viid_smt_extn_support) {
			pi->vivld = vivld;
			pi->vin = vin;
		} else {
			/* Retrieve the values from VIID */
			pi->vivld = G_FW_VIID_VIVLD(pi->viid);
			pi->vin = G_FW_VIID_VIN(pi->viid);
		}
	}

	/*
	 * The MTU/MSS Table is initialized by now, so load their values.  If
	 * we're initializing the adapter, then we'll make any modifications
	 * we want to the MTU/MSS Table and also initialize the congestion
	 * parameters.
	 */
	t4_read_mtu_tbl(adap, adap->params.mtus, NULL);
	if (state != DEV_STATE_INIT) {
		int i;

		/*
		 * The default MTU Table contains values 1492 and 1500.
		 * However, for TCP, it's better to have two values which are
		 * a multiple of 8 +/- 4 bytes apart near this popular MTU.
		 * This allows us to have a TCP Data Payload which is a
		 * multiple of 8 regardless of what combination of TCP Options
		 * are in use (always a multiple of 4 bytes) which is
		 * important for performance reasons.  For instance, if no
		 * options are in use, then we have a 20-byte IP header and a
		 * 20-byte TCP header.  In this case, a 1500-byte MSS would
		 * result in a TCP Data Payload of 1500 - 40 == 1460 bytes
		 * which is not a multiple of 8.  So using an MSS of 1488 in
		 * this case results in a TCP Data Payload of 1448 bytes which
		 * is a multiple of 8.  On the other hand, if 12-byte TCP Time
		 * Stamps have been negotiated, then an MTU of 1500 bytes
		 * results in a TCP Data Payload of 1448 bytes which, as
		 * above, is a multiple of 8 bytes ...
		 */
		for (i = 0; i < NMTUS; i++)
			if (adap->params.mtus[i] == 1492) {
				adap->params.mtus[i] = 1488;
				break;
			}

		t4_load_mtus(adap, adap->params.mtus, adap->params.a_wnd,
			     adap->params.b_wnd);
	}

	rtnl_lock();
	if (cxgb_up(adap)) {
		rtnl_unlock();
		goto out_free_vi;
	}
	rtnl_unlock();

	dev_alert(adap->pdev_dev, "adapter recovered from fatal error\n");
	return PCI_ERS_RESULT_RECOVERED;

out_free_vi:
	for_each_port(adap, i)
		if (adap->port[i]) {
			struct port_info *pi = netdev_priv(adap->port[i]);
			if (pi->viid != 0)
				t4_free_vi(adap, adap->mbox, adap->pf,
					   0, pi->viid);
		}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
out_stop_sge:
#endif
	t4_sge_stop(adap);
out:
	return PCI_ERS_RESULT_DISCONNECT;
}

static pci_ers_result_t t4_fatal_err_resume(struct adapter *adap)
{
	int i, ret;

	rtnl_lock();
	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];

		if (netif_running(dev)) {
			ret = link_start(dev);
			if (ret) {
				rtnl_unlock();
				goto fail;
			}
			cxgb_set_rxmode(dev);
		}
		netif_device_attach(dev);
	}

	smp_mb__before_atomic();
	clear_bit(ADAPTER_ERROR, &adap->adap_err_state);
	rtnl_unlock();
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adap)) {
		cxgb4_uld_queues_init(adap);
		attach_ulds(adap);
	}
#endif
	return PCI_ERS_RESULT_RECOVERED;
fail:
	return PCI_ERS_RESULT_DISCONNECT;
}

/* Processes a fatal error.
 * Bring the ports down, reset the chip, bring the ports back up.
 */
static void process_fatal_err(struct work_struct *work)
{
	struct adapter *adap = container_of(work, struct adapter, fatal_err_task);
	int i;
	pci_ers_result_t pci_err = PCI_ERS_RESULT_DISCONNECT;

	pci_err = t4_fatal_err_detected(adap, /*slot reset=*/1);
	if (!pci_err) {
		for (i = 0; i < FATAL_ERR_RETRY_COUNT; i++) {
			pci_err = t4_fatal_slot_reset(adap, 0);
			if (pci_err == PCI_ERS_RESULT_RECOVERED) {
				pci_err = t4_fatal_err_resume(adap);
				if (pci_err != PCI_ERS_RESULT_RECOVERED ) {
					t4_fatal_err_detected(adap, 1);
				} else
					break;
			} else {
				cxgb_reset_pci(adap, 1);
			}
		}
	}

	CH_ALERT(adap, "adapter reset %s\n", pci_err != PCI_ERS_RESULT_RECOVERED ?
					     "failed" : "succeeded");

	/* If recovery failed after multiple attempts, set adapter state to
	 * ADAPTER_DEAD
	 */
	if (pci_err != PCI_ERS_RESULT_RECOVERED)
		set_bit(ADAPTER_DEAD, &adap->adap_err_state);
}

/* EEH callbacks */

pci_ers_result_t cxgb4_pci_eeh_err_detected(struct pci_dev *pdev,
					    pci_channel_state_t state)
{
	struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap)
		goto out;

	/* Wait over here if fatal error recovery is in progress, if fatal error
	 * recovery fails after multiple attempts we need to break from the
	 * while loop else we will up in an infinite loop.
	 * Since this is called from the aer/eeh stack we cannot return, we
	 * have to wait if recovery is in progress
	 */
	while (test_and_set_bit(ADAPTER_ERROR, &adap->adap_err_state)) {
		if (test_bit(ADAPTER_DEAD, &adap->adap_err_state))
			return PCI_ERS_RESULT_DISCONNECT;
		usleep_range(1000, 2000);
	}

	t4_fatal_err_detected(adap, /*slot reset=*/0);
out:
	return state == pci_channel_io_perm_failure ?
		PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_NEED_RESET;
}

pci_ers_result_t cxgb4_pci_eeh_slot_reset(struct pci_dev *pdev)
{
	struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap) {
		pci_restore_state(pdev);
		pci_save_state(pdev);
		return PCI_ERS_RESULT_RECOVERED;
	}

	return t4_fatal_slot_reset(adap, 1);
}

void cxgb4_pci_eeh_resume(struct pci_dev *pdev)
{
	struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap)
		return;

	t4_fatal_err_resume(adap);
}

void cxgb4_pci_eeh_reset_prepare(struct pci_dev *pdev)
{
	struct adapter *adapter = pci_get_drvdata(pdev);
	int i;

	if (adapter->pf != 4)
		return;

	adapter->flags &= ~FW_OK;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	notify_ulds(adapter, CXGB4_STATE_DOWN);
#endif

	for_each_port(adapter, i)
		if (adapter->port[i]->reg_state == NETREG_REGISTERED)
			cxgb_close(adapter->port[i]);

	disable_interrupts(adapter);
	cxgb_free_mps_ref_entries(adapter);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cxgb4_uld_cleanup(adapter);
	adap_free_hma_mem(adapter);
#endif

	if (adapter->flags & FULL_INIT_DONE) {
		cxgb_down(adapter);
	}
}

void cxgb4_pci_eeh_reset_done(struct pci_dev *pdev)
{
	struct adapter *adapter = pci_get_drvdata(pdev);
	int err, i;

	if (adapter->pf != 4)
		return;

	err = t4_wait_dev_ready(adapter);
	if (err < 0) {
		dev_err(adapter->pdev_dev,
			"Device not ready, err %d", err);
		return;
	}

	cxgb4_common_setup_memwin(adapter);

	err = adap_init0(adapter, 1);
	if (err) {
		dev_err(adapter->pdev_dev,
			"Adapter init failed, err %d", err);
		return;
	}

	cxgb4_common_setup_memwin_rdma(adapter);

	if (adapter->flags & FW_OK) {
		err = t4_port_init(adapter, adapter->pf, adapter->pf, 0);
		if (err) {
			dev_err(adapter->pdev_dev,
				"Port init failed, err %d", err);
			return;
		}
	}

	err = cfg_queues(adapter);
	if (err) {
		dev_err(adapter->pdev_dev,
			"Config queues failed, err %d", err);
		return;
	}

	cxgb_init_mps_ref_entries(adapter);

	for_each_port(adapter, i)
		if (adapter->port[i]->reg_state == NETREG_REGISTERED) {
			rtnl_lock();
			cxgb_open(adapter->port[i]);
			rtnl_unlock();
		}
}

static inline void init_rspq(struct adapter *adap, struct sge_rspq *q,
			     unsigned int us, unsigned int cnt,
			     unsigned int size, unsigned int iqe_size)
{
	q->adap = adap;
	cxgb4_set_rspq_intr_params(q, us, cnt);
	q->iqe_len = iqe_size;
	q->size = size;
	q->cong_mode = -1;
}

/* forward declaration */
static void reduce_ethqs(struct adapter *adap, int n);

/*
 * Perform default configuration of DMA queues depending on the number and type
 * of ports we found and the number of available CPUs.  Most settings can be
 * modified by the admin prior to actual use.
 */
static int cfg_queues(struct adapter *adap)
{
	int niqflint, neq, avail_qsets, avail_eth_qsets;
	int avail_tunable_qsets, tunable_qsets;
	struct sge *s = &adap->sge;
	int i, n10g = 0, qidx = 0;
#ifndef CONFIG_CXGB4_DCB
	int q10g = 0;
#endif
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	int ciq_size;
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	/* Calculate the number of Ethernet Queue Sets available based on
	 * resources provisioned for us.  We always have an Asynchronous
	 * Firmware Event Ingress Queue.  If we're operating in MSI or Legacy
	 * IRQ Pin Interrupt mode, then we'll also have a Forwarded Interrupt
	 * Ingress Queue.  Meanwhile, we need two Egress Queues for each
	 * Queue Set: one for the Free List and one for the Ethernet TX Queue.
	 *
	 * Note that we should also take into account all of the various
	 * Offload Queues.  But, in any situation where we're operating in
	 * a Resource Constrained Provisioning environment, doing any Offload
	 * at all is problematic ...
	 */
	niqflint = adap->params.pfres.niqflint - 1;
	if (!(adap->flags & USING_INTR_MULTI))
		niqflint--;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if ((CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) &&
	    (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_CSTOR))) {
		int ncstor_poll_rxq = min_t(int, MAX_CSTOR_POLL_RXQ,
					    num_online_cpus() *
					    adap->params.nports);

		if (niqflint < ncstor_poll_rxq)
			ncstor_poll_rxq = adap->params.nports;

		if (niqflint > ncstor_poll_rxq) {
			niqflint -= ncstor_poll_rxq;
		} else {
			dev_err(adap->pdev_dev,
				"niqflint=%d < ncstor_poll_rxq=%d\n",
				niqflint, ncstor_poll_rxq);
			return -ENOMEM;
		}
	}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	neq = adap->params.pfres.neq/2;
	avail_qsets = min(niqflint, neq);

	avail_eth_qsets = avail_qsets;
	if (avail_eth_qsets > max_eth_qsets)
		avail_eth_qsets = max_eth_qsets;

	if (avail_eth_qsets < adap->params.nports) {
		dev_err(adap->pdev_dev, "avail_eth_qsets=%d < nports=%d\n",
			avail_eth_qsets, adap->params.nports);
		return -ENOMEM;
	}

	/* Count the number to 10Gb/s or better ports */
	for_each_port(adap, i) {
		if (mq_with_1G || is_fpga(adap->params.chip))
			n10g += 1;
		else
			n10g += is_x_10g_port(&adap2pinfo(adap, i)->link_cfg);
	}

#ifdef CONFIG_CXGB4_DCB
	/* For Data Center Bridging support we need to be able to support up
	 * to 8 Traffic Priorities; each of which will be assigned to its
	 * own TX Queue in order to prevent Head-Of-Line Blocking.
	 */
	if (adap->params.nports * 8 > avail_eth_qsets) {
		dev_err(adap->pdev_dev, "DCB avail_eth_qsets=%d < %d!\n",
			avail_eth_qsets, adap->params.nports * 8);
		return -ENOMEM;
	}

	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		pi->first_qset = qidx;
		pi->nqsets = is_kdump_kernel() ? 1 : 8;
		qidx += pi->nqsets;
	}
#else /* !CONFIG_CXGB4_DCB */
	/*
	 * We default to 1 queue per non-10G port and up to # of cores queues
	 * per 10G port.
	 */
	if (n10g)
		q10g = (avail_eth_qsets - (adap->params.nports - n10g)) / n10g;
	if (q10g > num_online_cpus())
		q10g = num_online_cpus();

	/* Reduce memory usage in kdump environment by using only one queue */
	if (is_kdump_kernel())
		q10g = 1;

	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		pi->first_qset = qidx;
		pi->nqsets = (is_x_10g_port(&pi->link_cfg) ||
			      mq_with_1G || is_fpga(adap->params.chip))
				? q10g : 1;
		if (pi->nqsets > pi->rss_size)
			pi->nqsets = pi->rss_size;
		qidx += pi->nqsets;
	}
#endif /* !CONFIG_CXGB4_DCB */

	s->ethqsets = qidx;
	s->max_ethqsets = qidx;   /* MSI-X may lower it later */

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adap)) {
		/*
		 * For offload we use 1 queue/channel if all ports are up to 1G,
		 * otherwise we divide all available queues amongst the channels
		 * capped by the number of available cores.
		 */
		if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_RDMA)) {
			/* For RDMA one Rx queue per channel suffices */
			s->rdmaqs = adap->params.nports;
			/* Try and allow at least 1 CIQ per cpu rounding down
			 * to the number of ports, with a minimum of 1 per port.
			 * A 2 port card in a 6 cpu system: 6 CIQs, 3 / port.
			 * A 4 port card in a 6 cpu system: 4 CIQs, 1 / port.
			 * A 4 port card in a 2 cpu system: 4 CIQs, 1 / port.
			 */
			s->rdmaciqs = min_t(int, DEFAULT_RDMA_CIQS,
					    num_online_cpus());
			s->rdmaciqs = (s->rdmaciqs / adap->params.nports) *
				      adap->params.nports;
			s->rdmaciqs = max_t(int, s->rdmaciqs,
					    adap->params.nports);
		}

#ifdef SCSI_CXGB4_ISCSI
		if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_ISCSI)) {
			if (n10g) {
				s->niscsiq = min_t(int, DEFAULT_ISCSI_QUEUES,
						   num_online_cpus());
				s->niscsiq = rounddown(s->niscsiq,
						       adap->params.nports);
				s->niscsiq = max_t(u32, s->niscsiq,
						   adap->params.nports);
			} else {
				s->niscsiq = adap->params.nports;
			}
		}
#endif
#ifdef CONFIG_CXGBIT
		if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_ISCSIT)) {
			if (!is_t4(adap->params.chip)) {
				if (n10g) {
					s->niscsitq = min_t(int,
							    DEFAULT_ISCSIT_QUEUES,
							    num_online_cpus());
					s->niscsitq = rounddown(s->niscsitq,
								adap->params.nports);
					s->niscsitq = max_t(u32, s->niscsitq,
							    adap->params.nports);
				} else {
					s->niscsitq = adap->params.nports;
				}
			}
		}
#endif

		if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) {
			if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_NVME_TCP_HOST)) {
				if (n10g) {
					s->n_nvmehq = min_t(int, DEFAULT_NVMEH_QUEUES,
							    num_online_cpus());
					s->n_nvmehq = rounddown(s->n_nvmehq,
								adap->params.nports);
					s->n_nvmehq = max_t(u32, s->n_nvmehq,
							    adap->params.nports);
				} else {
					s->n_nvmehq = adap->params.nports;
				}
			}

			if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_NVME_TCP_TARGET)) {
				if (n10g) {
					s->n_nvmetq = min_t(int, DEFAULT_NVMET_QUEUES,
							    num_online_cpus());
					s->n_nvmetq = rounddown(s->n_nvmetq,
								adap->params.nports);
					s->n_nvmetq = max_t(u32, s->n_nvmetq,
							    adap->params.nports);
				} else {
					s->n_nvmetq = adap->params.nports;
				}
			}

			if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_CSTOR)) {
				/* For CSTOR one Rx queue per channel suffices */
				s->ncstorq = adap->params.nports;
				/* Try and allow at least 1 CIQ per cpu rounding down
				 * to the number of ports, with a minimum of 1 per port.
				 * A 2 port card in a 6 cpu system: 6 CIQs, 3 / port.
				 * A 4 port card in a 6 cpu system: 4 CIQs, 1 / port.
				 * A 4 port card in a 2 cpu system: 4 CIQs, 1 / port.
				 */
				s->ncstorciq = min_t(int, DEFAULT_CSTOR_CIQS,
						     num_online_cpus());
				s->ncstorciq = (s->ncstorciq / adap->params.nports) *
						 adap->params.nports;
				s->ncstorciq = max_t(int, s->ncstorciq,
						     adap->params.nports);
			}
		}

		if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_TOE)) {
			if (n10g) {
				i = min_t(int, num_online_cpus(),
					  DEFAULT_OFLD_QSETS);

				/* ofld queues */
				i = adap->params.nports *
				    roundup(i, adap->params.nports);
				if (i > MAX_OFLD_QSETS)
					i = MAX_OFLD_QSETS;
				s->ofldqsets = i;
			} else {
				s->ofldqsets = adap->params.nports;
			}

			if (adap->params.tid_qid_sel_mask &&
			    s->ofldqsets < adap->params.num_up_cores)
				s->ofldqsets = adap->params.num_up_cores;
		}

	}

	if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_CRYPTO)) {
		if (adap->params.ulp_crypto & ULP_CRYPTO_LOOKASIDE) {
			s->ncryptoq = min3((u32)MAX_CRYPTO_QUEUES,
					   num_online_cpus(),
					   adap->uld.vres.ncrypto_fc);
			s->ncryptoq = (s->ncryptoq / adap->params.nports) *
				      adap->params.nports;
			s->ncryptoq = max_t(int, s->ncryptoq,
					    adap->params.nports);
		}
	}

	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq)
		s->ntraceq = 4;

#ifdef CONFIG_T4_MA_FAILOVER
	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_TOE))
		s->nfailoverq = MAX_FAILOVER_QUEUES;
#endif /* CONFIG_T4_MA_FAILOVER */
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	if (is_hashfilter(adap) && enable_mirror)
		s->nmirrorq = s->ethqsets;

	/* This max may be lowered by cxgb_enable_msix() */
	s->max_ofldqsets = s->ofldqsets + s->rdmaqs + s->rdmaciqs +
			   s->niscsiq + s->niscsitq + s->n_nvmehq +
			   s->n_nvmetq + s->ncstorq + s->ncstorciq + s->ncryptoq;

	/* If we have exceeded the FW provided limit of available qsets, try
	 * reducing the values of each tunable queue by a factor of its
	 * weight with respect to total queues.
	 */

	/* rdmaqs, traceq, and failoverqs are per channel, so not tunable */
	avail_tunable_qsets =
			avail_qsets - (s->ntraceq + s->rdmaqs + s->nfailoverq);

	/* Total number of qsets that we are going to tune down */
	tunable_qsets = (s->max_ofldqsets - s->rdmaqs) + s->max_ethqsets +
			s->nmirrorq;

#define NORMALISE(Q) \
	if (Q > adap->params.nports) \
		Q = rounddown(((Q * avail_tunable_qsets) / tunable_qsets), \
			      adap->params.nports)
	if (tunable_qsets > avail_tunable_qsets) {
		int remain;

		NORMALISE(s->max_ethqsets);
		NORMALISE(s->ofldqsets);
		NORMALISE(s->rdmaciqs);
		NORMALISE(s->niscsiq);
		NORMALISE(s->niscsitq);
		NORMALISE(s->n_nvmehq);
		NORMALISE(s->n_nvmetq);
		NORMALISE(s->ncstorciq);
		NORMALISE(s->ncryptoq);
		NORMALISE(s->nmirrorq);

		/* If any leftovers are there, assign them all to ethernet queues.
		 * Note that we need to recalculate all queues again here, since
		 * its values are updated by NORMALISE.
		 */
		s->max_ofldqsets = s->ofldqsets + s->rdmaqs + s->rdmaciqs +
				   s->niscsiq + s->niscsitq + s->n_nvmehq +
				   s->n_nvmetq + s->ncstorq + s->ncstorciq +
				   s->ncryptoq;
		tunable_qsets = (s->max_ofldqsets - s->rdmaqs) +
				s->max_ethqsets + s->nmirrorq;
		remain = (avail_tunable_qsets - tunable_qsets);
		/* If we have mirror queues, skip leftover assignment, as there
		 * is not much leftover we can share between mirror and ethernet
		 * queues.
		 */
		if (remain >= adap->params.nports &&
		    !(is_hashfilter(adap) && enable_mirror)) {
			s->max_ethqsets += rounddown(remain, adap->params.nports);
			if (s->max_ethqsets > s->ethqsets)
				s->max_ethqsets = s->ethqsets;
		}

		if (s->max_ethqsets < s->ethqsets) {
			reduce_ethqs(adap, s->max_ethqsets);
		}
	}

	for (i = 0; i < ARRAY_SIZE(s->ethrxq); i++) {
		struct sge_eth_rxq *r = &s->ethrxq[i];

		init_rspq(adap, &r->rspq, 5, 10, 1024, 64);
		r->fl.size = 72;
	}

	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq) {
		for (i = 0; i < ARRAY_SIZE(s->traceq); i++) {
			struct sge_eth_rxq *r = &s->traceq[i];

			init_rspq(adap, &r->rspq, 5, 10, 1024, 64);
			r->fl.size = 72;
		}
	}

	if (is_hashfilter(adap) && enable_mirror) {
		for (i = 0; i < ARRAY_SIZE(s->mirrorq); i++) {
			struct sge_eth_rxq *r = &s->mirrorq[i];

			init_rspq(adap, &r->rspq, 5, 10, 1024, 64);
			r->fl.size = 72;
		}
	}

	for (i = 0; i < ARRAY_SIZE(s->ethtxq); i++)
#ifdef CONFIG_PO_FCOE
		s->ethtxq[i].q.size = 8192;
#else
		s->ethtxq[i].q.size = 1024;
#endif /* CONFIG_PO_FCOE */

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	/* Single ctrl queue is a requirement for LE workaround path */
	if (adap->tidinfo.sftids.size)
		s->ctrlq[0].q.size = 1024;
	else
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
		for (i = 0; i < ARRAY_SIZE(s->ctrlq); i++)
			s->ctrlq[i].q.size = 512;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	for (i = 0; i < ARRAY_SIZE(s->ofldrxq); i++) {
		struct sge_ofld_rxq *r = &s->ofldrxq[i];

		init_rspq(adap, &r->rspq, 5, offload_rx_intr_cnt, 1024, 64);
		r->rspq.uld = CXGB4_ULD_TYPE_TOE;
		r->fl.size = 72;
	}

	for (i = 0; i < ARRAY_SIZE(s->rdmarxq); i++) {
		struct sge_ofld_rxq *r = &s->rdmarxq[i];

		init_rspq(adap, &r->rspq, 5, 1, 511, 64);
		r->rspq.uld = CXGB4_ULD_TYPE_RDMA;
		r->fl.size = 72;
	}

	ciq_size = 64 + adap->uld.vres.cq.size + adap->tidinfo.ftids.size;
	if (ciq_size > SGE_MAX_IQ_SIZE) {
		CH_WARN(adap, "CIQ size too small for available IQs\n");
		ciq_size = SGE_MAX_IQ_SIZE;
	}

	for (i = 0; i < ARRAY_SIZE(s->rdmaciq); i++) {
		struct sge_ofld_rxq *r = &s->rdmaciq[i];

		init_rspq(adap, &r->rspq, 5, 1, ciq_size, 64);
		r->rspq.uld = CXGB4_ULD_TYPE_RDMA;
	}

	for (i = 0; i < ARRAY_SIZE(s->iscsirxq); i++) {
		struct sge_ofld_rxq *r = &s->iscsirxq[i];

		init_rspq(adap, &r->rspq, 5, 8, 1024, 64);
		r->rspq.uld = CXGB4_ULD_TYPE_ISCSI;
		r->fl.size = 72;
	}

	if (!is_t4(adap->params.chip)) {
		for (i = 0; i < ARRAY_SIZE(s->iscsitrxq); i++) {
			struct sge_ofld_rxq *r = &s->iscsitrxq[i];

			init_rspq(adap, &r->rspq, 5, 1, 1024, 64);
			r->rspq.uld = CXGB4_ULD_TYPE_ISCSIT;
			r->fl.size = 72;
		}
	}

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) {
		if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_NVME_TCP_HOST)) {
			for (i = 0; i < ARRAY_SIZE(s->nvmehrxq); i++) {
				struct sge_ofld_rxq *r = &s->nvmehrxq[i];

				init_rspq(adap, &r->rspq, 5, 1, 1024, 128);
				r->rspq.uld = CXGB4_ULD_TYPE_NVME_TCP_HOST;
				r->fl.size = 72;
			}
		}

		if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_NVME_TCP_TARGET)) {
			for (i = 0; i < ARRAY_SIZE(s->nvmetrxq); i++) {
				struct sge_ofld_rxq *r = &s->nvmetrxq[i];

				init_rspq(adap, &r->rspq, 5, 1, 1024, 128);
				r->rspq.uld = CXGB4_ULD_TYPE_NVME_TCP_TARGET;
				r->fl.size = 72;
			}
		}
		if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_CSTOR)) {
			for (i = 0; i < ARRAY_SIZE(s->cstorrxq); i++) {
				struct sge_ofld_rxq *r = &s->cstorrxq[i];

				init_rspq(adap, &r->rspq, 5, 1, 511, 64);
				r->rspq.uld = CXGB4_ULD_TYPE_CSTOR;
				r->fl.size = 72;
			}

			for (i = 0; i < ARRAY_SIZE(s->cstorciq); i++) {
				struct sge_ofld_rxq *r = &s->cstorciq[i];

				init_rspq(adap, &r->rspq, 5, 1, ciq_size, 64);
				r->rspq.uld = CXGB4_ULD_TYPE_CSTOR;
			}
		}
	}

	for (i = 0; i < ARRAY_SIZE(s->cryptorxq); i++) {
		struct sge_ofld_rxq *r = &s->cryptorxq[i];

		init_rspq(adap, &r->rspq, 5, 1, 1024, 64);
		r->rspq.uld = CXGB4_ULD_TYPE_CRYPTO;
		r->fl.size = 72;
	}

#ifdef CONFIG_T4_MA_FAILOVER
	if (s->nfailoverq) {
		struct sge_ofld_rxq *r = &s->failoverq;

		init_rspq(adap, &r->rspq, 5, 1, 1024, 64);
		r->rspq.uld = CXGB4_ULD_TYPE_TOE;
		r->fl.size = 72;
	}
#endif /* CONFIG_T4_MA_FAILOVER */
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	init_rspq(adap, &s->fw_evtq, 0, 1, 1024, 64);
	init_rspq(adap, &s->intrq, 0, 1, 2 * MAX_INGQ, 64);

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adap->params.chip))
		s->ptptxq.q.size = 8;
#endif

#if IS_ENABLED(CONFIG_VXLAN)
	if (is_t5(adap->params.chip)) {
		for (i = 0; i < ARRAY_SIZE(s->vxlantxq); i++)
			s->vxlantxq[i].q.size = 1024;
	}
#endif

	return 0;
}

bool cxgb4_msix_enabled(struct adapter *adap)
{
	return cxgb4_common_msix_enabled(adap);
}

bool cxgb4_msi_enabled(struct adapter *adap)
{
	return cxgb4_common_msi_enabled(adap);
}

/*
 * Interrupt handler used to check if MSI/MSI-X works on this platform.
 */
static irqreturn_t check_intr_handler(int irq, void *data)
{
	struct adapter *adap = data;

	adap->swintr = 1;
	t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE), F_PFSW);
	t4_read_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE));          /* flush */
	return IRQ_HANDLED;
}

static int cxgb4_check_msi(struct adapter *adap)
{
	int ret, vec;

	vec = cxgb4_common_irq_vector(adap, 0);
	ret = request_irq(vec, check_intr_handler, 0, adap->name, adap);
	if (ret)
		return ret;

	adap->swintr = 0;
	t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_ENABLE), F_PFSW);
	t4_write_reg(adap, MYPF_REG(A_PL_PF_CTL), F_SWINT);
	msleep(10);
	t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_ENABLE), 0);
	free_irq(vec, adap);

	if (!adap->swintr) {
		const char *s = cxgb4_msix_enabled(adap) ? "MSI-X" : "MSI";

		cxgb4_disable_irqs(adap);
		dev_err(adap->pdev_dev,
			"The kernel believes that %s is available on this platform, but the driver's %s test has failed.\n ",
			 s, s);
		return -EINVAL;
	}

	return 0;
}

/*
 * Reduce the number of Ethernet queues across all ports to at most n.
 * n provides at least one queue per port.
 */
static void reduce_ethqs(struct adapter *adap, int n)
{
	int i;
	struct port_info *pi;

	while (n < adap->sge.ethqsets)
		for_each_port(adap, i) {
			pi = adap2pinfo(adap, i);
			if (pi->nqsets > 1) {
				pi->nqsets--;
				adap->sge.ethqsets--;
				if (adap->sge.ethqsets <= n)
					break;
			}
		}

	n = 0;
	for_each_port(adap, i) {
		pi = adap2pinfo(adap, i);
		pi->first_qset = n;
		n += pi->nqsets;
	}
}

/* 2 MSI-X vectors needed for the FW queue and non-data interrupts */
#define EXTRA_VECS 2

static int cxgb4_enable_irqs(struct adapter *adap)
{
	u16 max_ethqsets = 0, ntraceq = 0, nmirrorq = 0;
	int nchan = adap->params.nports;
	struct sge *s = &adap->sge;
	int i, temp_i, allocated;
	unsigned int flags = 0;
	int need, want;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	u16 nvmehq = 0, nvmetq = 0, cstorq = 0, cstorciq = 0;
	u16 rdmaqs = 0, rdmaciqs = 0;
	u16 ofldqsets = 0;
	u16 ncryptoq = 0;
#ifdef SCSI_CXGB4_ISCSI
	u16 niscsiq = 0;
#endif
#ifdef CONFIG_CXGBIT
	u16 niscsitq = 0;
#endif
#ifdef CONFIG_T4_MA_FAILOVER
	u16 nfailoverq = 0;
#endif
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	switch (cxgb4_modparam_msi()) {
	case 2:
		flags |= PCI_IRQ_MSIX;
		fallthrough;
	case 1:
		flags |= PCI_IRQ_MSI;
		fallthrough;
	case 0:
		flags |= PCI_IRQ_INTX;
		break;
	default:
		return -EINVAL;
	}

	need = EXTRA_VECS;
	want = EXTRA_VECS;

#define CXGB4_VEC_NEED_WANT(save, n, w) do { \
	need += (n); \
	want += (w); \
	(save) = (w); \
	(w) = 0; \
} while (0)

#ifdef CONFIG_CXGB4_DCB
	CXGB4_VEC_NEED_WANT(max_ethqsets, s->max_ethqsets, s->max_ethqsets);
#else
	CXGB4_VEC_NEED_WANT(max_ethqsets, nchan, s->max_ethqsets);
#endif

	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq)
		CXGB4_VEC_NEED_WANT(ntraceq, s->ntraceq, s->ntraceq);

	if (is_hashfilter(adap) && enable_mirror)
		CXGB4_VEC_NEED_WANT(nmirrorq, nchan, s->nmirrorq);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adap)) {
		CXGB4_VEC_NEED_WANT(ofldqsets, nchan, s->ofldqsets);
		CXGB4_VEC_NEED_WANT(rdmaqs, nchan, s->rdmaqs);
		CXGB4_VEC_NEED_WANT(rdmaciqs, nchan, s->rdmaciqs);
#ifdef CONFIG_T4_MA_FAILOVER
		CXGB4_VEC_NEED_WANT(nfailoverq, 1, s->nfailoverq);
#endif
#ifdef SCSI_CXGB4_ISCSI
		CXGB4_VEC_NEED_WANT(niscsiq, nchan, s->niscsiq);
#endif
#ifdef CONFIG_CXGBIT
		CXGB4_VEC_NEED_WANT(niscsitq, nchan, s->niscsitq);
#endif
		if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) {
			CXGB4_VEC_NEED_WANT(nvmehq, nchan, s->n_nvmehq);
			CXGB4_VEC_NEED_WANT(nvmetq, nchan, s->n_nvmetq);

			CXGB4_VEC_NEED_WANT(cstorq, nchan, s->ncstorq);
			CXGB4_VEC_NEED_WANT(cstorciq, nchan, s->ncstorciq);
		}
	}

	if (adap->params.ulp_crypto & ULP_CRYPTO_LOOKASIDE)
		CXGB4_VEC_NEED_WANT(ncryptoq, nchan, s->ncryptoq);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

#undef CXGB4_VEC_NEED_WANT

	allocated = cxgb4_common_alloc_irqs(adap, 1, want, flags);
	if (allocated < 0) {
		dev_info(adap->pdev_dev,
			 "Could not alloc %u interrupts. ret: %d\n",
			 want, allocated);
		return allocated;
	}

	if (allocated >= need) {
		adap->flags |= USING_INTR_MULTI;
	} else {
		adap->flags |= USING_INTR_SINGLE;
		dev_info(adap->pdev_dev,
			 "Interrupts allocated(%u) < need(%u). Falling back to Forward Interrupt mode\n",
			 allocated, need);

		cxgb4_common_free_irqs(adap);
		allocated = cxgb4_common_alloc_irqs(adap, 1, 1, flags);
		if (allocated < 0) {
			dev_info(adap->pdev_dev,
				 "Could not alloc 1 interrupt. ret: %d\n",
				 allocated);
			adap->flags &= ~USING_INTR_SINGLE;
			return allocated;
		}
	}

#define CXGB4_VEC_ALLOC(qs, inc, max) do { \
	if ((qs) < (max)) { \
		if (allocated < need) { \
			(qs) += (inc); \
		} else if (i - (inc) >= 0) { \
			(qs) += (inc); \
			i -= (inc); \
		} \
	} \
} while (0)

	/* Distribute available vectors to the various queue groups. */
	i = allocated;
	if (i > EXTRA_VECS)
		i -= EXTRA_VECS;

	while (i) {
		temp_i = i;

#ifdef CONFIG_CXGB4_DCB
		CXGB4_VEC_ALLOC(s->max_ethqsets, max_ethqsets, max_ethqsets);
#else
		CXGB4_VEC_ALLOC(s->max_ethqsets, nchan, max_ethqsets);
#endif /* CONFIG_CXGB4_DCB */

		if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
		    enable_traceq)
			CXGB4_VEC_ALLOC(s->ntraceq, nchan, ntraceq);

		if (is_hashfilter(adap) && enable_mirror)
			CXGB4_VEC_ALLOC(s->nmirrorq, nchan, nmirrorq);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		if (cxgb4_uld_supported_any(adap)) {
			CXGB4_VEC_ALLOC(s->ofldqsets, nchan, ofldqsets);
			CXGB4_VEC_ALLOC(s->rdmaqs, nchan, rdmaqs);
			CXGB4_VEC_ALLOC(s->rdmaciqs, nchan, rdmaciqs);
#ifdef CONFIG_T4_MA_FAILOVER
			CXGB4_VEC_ALLOC(s->nfailoverq, 1, nfailoverq);
#endif
#ifdef SCSI_CXGB4_ISCSI
			CXGB4_VEC_ALLOC(s->niscsiq, nchan, niscsiq);
#endif
#ifdef CONFIG_CXGBIT
			CXGB4_VEC_ALLOC(s->niscsitq, nchan, niscsitq);
#endif

			if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) {
				CXGB4_VEC_ALLOC(s->n_nvmehq, nchan, nvmehq);
				CXGB4_VEC_ALLOC(s->n_nvmetq, nchan, nvmetq);

				CXGB4_VEC_ALLOC(s->ncstorq, nchan, cstorq);
				CXGB4_VEC_ALLOC(s->ncstorciq, nchan, cstorciq);
			}
		}

		if (adap->params.ulp_crypto & ULP_CRYPTO_LOOKASIDE)
			CXGB4_VEC_ALLOC(s->ncryptoq, nchan, ncryptoq);

#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

		/* If nothing claimed interrupt vector, bail */
		if (i == temp_i)
			break;
	}

#undef CXGB4_VEC_ALLOC

	reduce_ethqs(adap, s->max_ethqsets);

	/* This is the max no of vectors available for
	 * the various offload queues (ofld + rdma + rciq + iscsi + iscsit
	 * nvmehq + nvmetq + cstorq + cstorciq)
	 */
	s->max_ofldqsets = s->ofldqsets + s->rdmaqs + s->rdmaciqs + s->niscsiq +
			   s->niscsitq + s->n_nvmehq + s->n_nvmetq +
			   s->ncstorq + s->ncstorciq + s->ncryptoq;

	for (i = 0; i < allocated; ++i)
		adap->msix_info[i].vec = cxgb4_common_irq_vector(adap, i);

	if (cxgb4_msix_enabled(adap))
		dev_info(adap->pdev_dev, "%d MSI-X vectors allocated, ",
			 allocated);
	else if (cxgb4_msi_enabled(adap))
		dev_info(adap->pdev_dev, "%d MSI vectors allocated, ",
			 allocated);
	else
		dev_info(adap->pdev_dev, "%d Legacy vectors allocated, ",
			 allocated);

	dev_info(adap->pdev_dev,
		 "nic %d, ofld %d, rdma cpl %d, rdma ciq %d, iscsi %d, iscsit %d, "
		 "nvmeh %d, nvmet %d, cstor rxq %d, cstor ciq %d\n",
		 s->max_ethqsets, s->ofldqsets, s->rdmaqs,
		 s->rdmaciqs, s->niscsiq, s->niscsitq, s->n_nvmehq,
		 s->n_nvmetq, s->ncstorq, s->ncstorciq);

#ifdef CONFIG_T4_MA_FAILOVER
	dev_info(adap->pdev_dev, " failover rx %d\n", s->nfailoverq);
#endif /* CONFIG_T4_MA_FAILOVER */
	if (adap->params.ulp_crypto & ULP_CRYPTO_LOOKASIDE)
		dev_info(adap->pdev_dev, " crypto rx %d\n", s->ncryptoq);
	if ((is_hashfilter(adap) && is_t5(adap->params.chip)) ||
	    enable_traceq)
		dev_info(adap->pdev_dev, " trace %d\n", s->ntraceq);
	if (is_hashfilter(adap) && enable_mirror)
		dev_info(adap->pdev_dev, " mirror %d\n", s->nmirrorq);

	return 0;
}

#undef EXTRA_VECS

static int init_rss(struct adapter *adap)
{
	unsigned int i;
	int err;

	err = t4_init_rss_mode(adap, adap->mbox);
	if (err)
		return err;

	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		pi->rss = kcalloc(pi->rss_size, sizeof(u16), GFP_KERNEL);
		if (!pi->rss)
			return -ENOMEM;
	}
	return 0;
}

/*
 * Dump basic information about the adapter.
 */
static void print_adapter_info(adapter_t *adapter)
{
	/*
	 * Hardware/Firmware/etc. Version/Revision IDs.
	 */
	t4_dump_version_info(adapter);

	/*
	 * Software/Hardware configuration.
	 */
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	dev_info(adapter->pdev_dev, "Configuration: %sNIC %s, %s capable\n",
		 cxgb4_uld_supported_any(adapter) ? "R" : "",
		 cxgb4_msix_enabled(adapter) ? "MSI-X" :
		 (cxgb4_msi_enabled(adapter) ? "MSI" : ""),
		 cxgb4_uld_supported_any(adapter) ? "Offload" : "non-Offload");
#else
	dev_info(adapter->pdev_dev,
		 "Configuration: NIC %s, non-Offload capable\n",
		 cxgb4_msix_enabled(adapter) ? "MSI-X" :
		 (cxgb4_msi_enabled(adapter) ? "MSI" : ""));
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */
}

static void print_port_info(adapter_t *adap)
{
	int i;
	char buf[80];
	const char *spd="";

	if (adap->params.pci.speed == PCI_EXP_LNKSTA_CLS_2_5GB)
		spd = " 2.5 GT/s";
	else if (adap->params.pci.speed == PCI_EXP_LNKSTA_CLS_5_0GB)
		spd = " 5 GT/s";
	else if (adap->params.pci.speed == PCI_EXP_LNKSTA_CLS_8_0GB)
		spd = " 8 GT/s";

	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];
		const struct port_info *pi = netdev_priv(dev);
		char *bufp = buf;

		if (!test_bit(i, &adap->registered_device_map))
			continue;

		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_100M)
			bufp += sprintf(bufp, "100M/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_1G)
			bufp += sprintf(bufp, "1G/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_10G)
			bufp += sprintf(bufp, "10G/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_25G)
			bufp += sprintf(bufp, "25G/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_40G)
			bufp += sprintf(bufp, "40G/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_50G)
			bufp += sprintf(bufp, "50G/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_100G)
			bufp += sprintf(bufp, "100G/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_200G)
			bufp += sprintf(bufp, "200G/");
		if (pi->link_cfg.pcaps & FW_PORT_CAP32_SPEED_400G)
			bufp += sprintf(bufp, "400G/");
		if (bufp != buf)
			--bufp;
		sprintf(bufp, "BASE-%s",
			t4_get_port_type_description(pi->port_type));

		printk(KERN_INFO "%s: Chelsio %s (%s) %s\n",
		       dev->name, adap->params.vpd.id,
		       adap->name,
		       buf);

	}
}

static int cxgb_t5_udp_tunnel_unset_port(struct net_device *netdev,
					 unsigned int table, unsigned int entry,
					 struct udp_tunnel_info *ti)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adapter = pi->adapter;

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		adapter->vxlan_port = 0;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int cxgb_t5_udp_tunnel_set_port(struct net_device *netdev,
				       unsigned int table, unsigned int entry,
				       struct udp_tunnel_info *ti)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adapter = pi->adapter;

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		adapter->vxlan_port = ti->port;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct udp_tunnel_nic_info cxgb_t5_udp_tunnels = {
	.set_port	= cxgb_t5_udp_tunnel_set_port,
	.unset_port	= cxgb_t5_udp_tunnel_unset_port,
	.tables		= {
		{ .n_entries = 1, .tunnel_types = UDP_TUNNEL_TYPE_VXLAN,  },
	},
};

static int cxgb_udp_tunnel_unset_port(struct net_device *netdev,
				      unsigned int table, unsigned int entry,
				      struct udp_tunnel_info *ti)
{
	struct port_info *pi = netdev_priv(netdev);
	u8 match_all_mac[] = { 0, 0, 0, 0, 0, 0 };
	struct adapter *adapter = pi->adapter;
	u32 chip_ver, reg;
	int ret = 0, i;

	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		adapter->vxlan_port = 0;
		reg = chip_ver >= CHELSIO_T7 ?
		      A_T7_MPS_RX_VXLAN_TYPE : A_MPS_RX_VXLAN_TYPE;
		break;
	case UDP_TUNNEL_TYPE_GENEVE:
		adapter->geneve_port = 0;
		reg = chip_ver >= CHELSIO_T7 ?
		      A_T7_MPS_RX_GENEVE_TYPE : A_MPS_RX_GENEVE_TYPE;
		break;
	default:
		return -EINVAL;
	}

	/* Matchall mac entries can be deleted only after all tunnel ports
	 * are brought down or removed.
	 */
	for_each_port(adapter, i) {
		pi = adap2pinfo(adapter, i);
		ret = cxgb_free_raw_mac_filt(adapter, pi->viid,
					     match_all_mac, match_all_mac,
					     adapter->rawf_start + pi->port_id,
					     1, pi->port_id, false);
		if (ret < 0)
			netdev_info(netdev,
				    "RAW MAC Filter free failed for port %d, UDP port %u, ret: %d\n",
				    i, be16_to_cpu(ti->port), ret);
	}

	t4_write_reg(adapter, reg, 0);
	return 0;
}

static int cxgb_udp_tunnel_set_port(struct net_device *netdev,
				    unsigned int table, unsigned int entry,
				    struct udp_tunnel_info *ti)
{
	struct port_info *pi = netdev_priv(netdev);
	u8 match_all_mac[] = { 0, 0, 0, 0, 0, 0 };
	struct adapter *adapter = pi->adapter;
	u32 chip_ver, reg, val;
	__be16 *port_save;
	int i, ret;

	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		port_save = &adapter->vxlan_port;
		reg = chip_ver >= CHELSIO_T7 ?
		      A_T7_MPS_RX_VXLAN_TYPE : A_MPS_RX_VXLAN_TYPE;
		val = V_VXLAN(be16_to_cpu(ti->port)) | F_VXLAN_EN;
		break;
	case UDP_TUNNEL_TYPE_GENEVE:
		port_save = &adapter->geneve_port;
		reg = chip_ver >= CHELSIO_T7 ?
		      A_T7_MPS_RX_GENEVE_TYPE : A_MPS_RX_GENEVE_TYPE;
		val = V_GENEVE(be16_to_cpu(ti->port)) | F_GENEVE_EN;
		break;
	default:
		return -EINVAL;
	}

	/* Create a 'match all' mac filter entry for inner mac,
	 * if raw mac interface is supported. Once the linux kernel provides
	 * driver entry points for adding/deleting the inner mac addresses,
	 * we will remove this 'match all' entry and fallback to adding
	 * exact match filters.
	 */
	for_each_port(adapter, i) {
		pi = adap2pinfo(adapter, i);

		ret = cxgb_alloc_raw_mac_filt(adapter, pi->viid,
					      match_all_mac, match_all_mac,
					      adapter->rawf_start + pi->port_id,
					      1, pi->port_id, false);
		if (ret < 0) {
			netdev_info(netdev,
				    "RAW MAC Filter alloc failed for port %d, UDP port %u, ret: %d\n",
				    i, be16_to_cpu(ti->port), ret);
			goto out_free;
		}
	}

	*port_save = ti->port;
	t4_write_reg(adapter, reg, val);
	return 0;

out_free:
	while (i-- > 0) {
		pi = adap2pinfo(adapter, i);
		cxgb_free_raw_mac_filt(adapter, pi->viid, match_all_mac,
				       match_all_mac,
				       adapter->rawf_start + pi->port_id,
				       1, pi->port_id, false);
	}

	return ret;
}

static const struct udp_tunnel_nic_info cxgb_udp_tunnels = {
	.set_port	= cxgb_udp_tunnel_set_port,
	.unset_port	= cxgb_udp_tunnel_unset_port,
	.tables		= {
		{ .n_entries = 1, .tunnel_types = UDP_TUNNEL_TYPE_VXLAN,  },
		{ .n_entries = 1, .tunnel_types = UDP_TUNNEL_TYPE_GENEVE, },
	},
};

static netdev_features_t cxgb_features_check(struct sk_buff *skb,
					     struct net_device *dev,
					     netdev_features_t features)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	if (is_t4(adapter->params.chip))
		return features;

	/* Check if hw supports offload for this packet */
	if (!skb->encapsulation || cxgb_encap_offload_supported(skb))
		return features;

	/* Offload is not supported for this encapsulated packet */
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

static netdev_features_t cxgb_fix_features(struct net_device *dev,
					   netdev_features_t features)
{
	/* Disable GRO, if RX_CSUM is disabled */
	if (!(features & NETIF_F_RXCSUM))
		features &= ~NETIF_F_GRO;

	return features;
}

static struct net_device_ops cxgb4_netdev_ops = {
	.ndo_open             = cxgb_open,
	.ndo_stop             = cxgb_close,
	.ndo_start_xmit       = t4_start_xmit,
	.ndo_select_queue     = cxgb_select_queue,
	.ndo_get_stats        = cxgb_get_stats,
	.ndo_set_rx_mode      = cxgb_set_rxmode,
	.ndo_set_mac_address  = cxgb_set_mac_addr,
	.ndo_validate_addr    = eth_validate_addr,
	.ndo_eth_ioctl        = cxgb_ioctl,
	.ndo_siocdevprivate   = cxgb_siocdevprivate,
	.ndo_change_mtu       = cxgb_change_mtu,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller  = cxgb_netpoll,
#endif
#ifdef CONFIG_PO_FCOE
	.ndo_fcoe_ddp_target  = cxgb_fcoe_ddp_setup,
	.ndo_fcoe_ddp_done    = cxgb_fcoe_ddp_done,
	.ndo_fcoe_enable      = cxgb_fcoe_enable,
	.ndo_fcoe_disable     = cxgb_fcoe_disable,
#endif /* CONFIG_PO_FCOE */
	.ndo_features_check   = cxgb_features_check,
	.ndo_fix_features     = cxgb_fix_features,
};

#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
/**
 *	vf_monitor - monitor VFs for potential problems
 *	@work: the adapter's vf_monitor_task
 *
 *	VFs can get into trouble in various ways so we monitor them to see if
 *	they need to be kicked, reset, etc.
 */
static void vf_monitor(struct work_struct *work)
{
	struct adapter *adapter = container_of(work, struct adapter,
					       vf_monitor_task.work);
	struct pci_dev *pdev;
	u32 pcie_cdebug;
	unsigned int reqfn;
	const unsigned int vf_offset = 8;
	const unsigned int vf_stride = 4;
	unsigned int vfdevfn, pf, vf;
	struct pci_dev *vfdev;
	int pos, i;
	u16 control;

	/*
	 * Read the PCI-E Debug Register to see if it's hanging with a
	 * Request Valid condition.  But we check it several times to be
	 * Absolutely Sure since we can see the PCI-E block being busy
	 * transiently during normal operation.
	 */
	for (i = 0; i < 4; i++) {
		t4_write_reg(adapter, A_PCIE_CDEBUG_INDEX, 0x3c003c);
		pcie_cdebug = t4_read_reg(adapter, A_PCIE_CDEBUG_DATA_HIGH);
		if ((pcie_cdebug & 0x100) == 0)
			goto reschedule_vf_monitor;
	}

	/*
	 * We're not prepared to deal with anything other than a VF.
	 */
	pdev = cxgb4_pci_dev(adapter);
	reqfn = (pcie_cdebug >> 24) & 0xff;
	if (reqfn < vf_offset) {
		dev_info(&pdev->dev, "vf_monitor: hung ReqFn %d is a PF!\n",
			 reqfn);
		goto reschedule_vf_monitor;
	}

	/*
	 * Grab a handle on the VF's PCI State.
	 */
	pf = (reqfn - vf_offset) & (vf_stride - 1);
	vf = ((reqfn - vf_offset) & ~(vf_stride - 1))/vf_stride + 1;
	vfdevfn = PCI_SLOT(pdev->devfn) + reqfn;
	vfdev = pci_get_slot(pdev->bus, vfdevfn);
	if (vfdev == NULL) {
		dev_info(&pdev->dev, "vf_monitor: can't find PF%d/VF%d",
			 pf, vf);
		goto reschedule_vf_monitor;
	}

	/*
	 * Now that we have a handle on the VF which is hung, we need to
	 * mask and re-enable its interrupts, reset it and then disable its
	 * interrupts again.
	 */
	pos = pci_find_capability(vfdev, PCI_CAP_ID_MSIX);
	if (!pos) {
		dev_err(&pdev->dev, "vf_monitor: can't find MSI-X PF%d/VF%d\n",
			pf, vf);
		goto drop_vfdev_reference;
	}
	pci_read_config_word(vfdev, pos+PCI_MSIX_FLAGS, &control);
	if (control & PCI_MSIX_FLAGS_ENABLE) {
		dev_info(&pdev->dev, "vf_monitor: MSI-X already enabled PF%d/VF%d\n",
			 pf, vf);
		goto drop_vfdev_reference;
	}
	pci_write_config_word(vfdev, pos+PCI_MSIX_FLAGS,
			      control |
			      PCI_MSIX_FLAGS_ENABLE |
			      PCI_MSIX_FLAGS_MASKALL);
	pci_reset_function(vfdev);
	pci_write_config_word(vfdev, pos+PCI_MSIX_FLAGS, control);
	dev_warn(&pdev->dev, "vf_monitor: reset hung PF%d/VF%d\n", pf, vf);

drop_vfdev_reference:
	/*
	 * Drop reference to the VF's CI State.
	 */
	pci_dev_put(vfdev);

reschedule_vf_monitor:
	/*
	 * Set up for the next time we need to check things ...
	 */
	schedule_delayed_work(&adapter->vf_monitor_task, VF_MONITOR_PERIOD);
}

/*
 * Fill MAC address that will be assigned by the Firmware.  Everything about
 * this routine is wrong.  The Firmware generates Locally Assigned Ethernet
 * MAC Addresses for all of the VFs (byte[0]bit[1] set) based on the base
 * Vendor Assigned MAC Address for the Port.  But this should be completely
 * opaque to the Host Code.  We should be asking the Firmware for these
 * addresses, not duplicating the Firmware code!  However, there's currently
 * no Firmware API for this ... (sigh)
 */
static void cxgb4_mgmt_fill_vf_station_mac_addr(struct adapter *adap)
{
	unsigned int i, vf, nvfs;
	u8 hw_addr[ETH_ALEN], macaddr[ETH_ALEN];
	int err;
	u8 *na;
	u16 a, b;

	adap->params.pci.vpd_cap_addr = pci_find_capability(cxgb4_pci_dev(adap),
							    PCI_CAP_ID_VPD);
	err = t4_get_raw_vpd_params(adap, &adap->params.vpd);
	if (err)
		return;

	na = adap->params.vpd.na;
	for (i = 0; i < ETH_ALEN; i++)
		hw_addr[i] = (hex2val(na[2 * i + 0]) * 16 +
			      hex2val(na[2 * i + 1]));

	a = (hw_addr[0] << 8) | hw_addr[1];
	b = (hw_addr[1] << 8) | hw_addr[2];
	a ^= b;
	a |= 0x0200;    /* locally assigned Ethernet MAC address */
	a &= ~0x0100;   /* not a multicast Ethernet MAC address */
	macaddr[0] = a >> 8;
	macaddr[1] = a & 0xff;

	for (i = 2; i < 5; i++)
		macaddr[i] = hw_addr[i + 1];

	for (vf = 0, nvfs = pci_sriov_get_totalvfs(cxgb4_pci_dev(adap));
	     vf < nvfs; vf++) {
		macaddr[5] = adap->pf * nvfs + vf;
		ether_addr_copy(adap->vfinfo[vf].vf_mac_addr, macaddr);
	}
}

static int cxgb4_mgmt_set_vf_mac(struct net_device *dev, int vf, u8 *mac)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	int ret;

	/* verify MAC addr is valid */
	if (!is_valid_ether_addr(mac)) {
		dev_err(pi->adapter->pdev_dev,
			"Invalid Ethernet address %pM for VF %d\n",
			mac, vf);
		return -EINVAL;
	}

	dev_info(pi->adapter->pdev_dev,
		 "Setting MAC %pM on VF %d\n", mac, vf);
	ret = t4_set_vf_mac_acl(adap, vf + 1, pi->lport, 1, mac);
	if (!ret)
		ether_addr_copy(adap->vfinfo[vf].vf_mac_addr, mac);
	return ret;
}

static int cxgb4_mgmt_get_vf_config(struct net_device *dev,
				    int vf, struct ifla_vf_info *ivi)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	struct vf_info *vfinfo;

	if (vf >= adap->num_vfs)
		return -EINVAL;
	vfinfo = &adap->vfinfo[vf];

	ivi->vf = vf;
	ivi->max_tx_rate = vfinfo->tx_rate;
	ivi->min_tx_rate = 0;
	ether_addr_copy(ivi->mac, vfinfo->vf_mac_addr);
	ivi->vlan = vfinfo->vlan;
	ivi->linkstate = vfinfo->link_state;
	return 0;
}

static int cxgb4_mgmt_set_vf_rate(struct net_device *dev, int vf,
				  int min_tx_rate, int max_tx_rate)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	unsigned int link_ok, speed, mtu;
        u32 fw_pfvf, fw_class;
	int class_id = vf % 16; /* XXX Bogus!  Need a new scheme. */
	int ret;
	u16 pktsize;

	if (vf >= adap->num_vfs)
		return -EINVAL;

        if (min_tx_rate) {
                dev_err(adap->pdev_dev,
			"Min tx rate (%d) (> 0) for VF %d is Invalid.\n",
                        min_tx_rate, vf);
                return -EINVAL;
        }

	if (max_tx_rate == 0) {
		/* unbind VF to to any Traffic Class */
	        fw_pfvf =
		    (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
		     V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_SCHEDCLASS_ETH));
	        fw_class = 0xffffffff;
	        ret = t4_set_params(adap, adap->mbox, adap->pf, vf + 1, 1,
				    &fw_pfvf, &fw_class);
		if (ret) {
			dev_err(adap->pdev_dev,
				"Err %d in unbinding PF %d VF %d from TX Rate Limiting\n",
				ret, adap->pf, vf);
			return -EINVAL;
		}
		dev_info(adap->pdev_dev,
			 "PF %d VF %d is unbound from TX Rate Limiting\n",
			 adap->pf, vf);
		adap->vfinfo[vf].tx_rate = 0;
		return 0;
	}

	ret = t4_get_link_params(pi, &link_ok, &speed, &mtu);
	if (ret != FW_SUCCESS) {
		dev_err(adap->pdev_dev,
			"Failed to get link information for VF %d\n", vf);
		return -EINVAL;
	}

	if (!link_ok) {
		dev_err(adap->pdev_dev, "Link down for VF %d\n", vf);
		return -EINVAL;
	}

	if (max_tx_rate > speed) {
		dev_err(adap->pdev_dev,
			"Max tx rate %d for VF %d can't be > link-speed %u",
			max_tx_rate, vf, speed);
		return -EINVAL;
	}

	pktsize = mtu;
	/* subtract ethhdr size and 4 bytes crc since, f/w appends it */
	pktsize = pktsize - sizeof(struct ethhdr) - 4;
	/* subtract ipv4 hdr size, tcp hdr size to get typical IPv4 MSS size */
	pktsize = pktsize - sizeof(struct iphdr) - sizeof(struct tcphdr);

	/* configure Traffic Class for rate-limiting */
	ret = t4_sched_params(adap, pi->lport, class_id,
			      FW_SCHED_PARAMS_LEVEL_CL_RL,
			      FW_SCHED_PARAMS_MODE_CLASS,
			      FW_SCHED_TYPE_PKTSCHED,
			      FW_SCHED_PARAMS_UNIT_BITRATE,
			      FW_SCHED_PARAMS_RATE_ABS, 0,
			      max_tx_rate * 1000, 0, pktsize, 0);
	if (ret) {
		dev_err(adap->pdev_dev, "Err %d for Traffic Class config\n",
			ret);
		return -EINVAL;
	}
	dev_info(adap->pdev_dev,
		 "Class %d with MSS %u configured with rate %u\n",
		 class_id, pktsize, max_tx_rate);

	/* bind VF to configured Traffic Class */
        fw_pfvf = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
                   V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_SCHEDCLASS_ETH));
        fw_class = class_id;
        ret = t4_set_params(adap, adap->mbox, adap->pf, vf + 1, 1, &fw_pfvf,
			    &fw_class);
	if (ret) {
		dev_err(adap->pdev_dev,
			"Err %d in binding PF %d VF %d to Traffic Class %d\n",
			ret, adap->pf, vf, class_id);
		return -EINVAL;
	}
	dev_info(adap->pdev_dev, "PF %d VF %d is bound to Class %d\n",
		 adap->pf, vf, class_id);
	adap->vfinfo[vf].tx_rate = max_tx_rate;
	return 0;
}

static int cxgb4_mgmt_set_vf_vlan(struct net_device *dev, int vf,
				  u16 vlan, u8 qos, __be16 vlan_proto)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	int ret;

	if ((vf >= adap->num_vfs) || (vlan > 4095) || (qos > 7))
		return -EINVAL;
	if (vlan_proto != htons(ETH_P_8021Q) || qos != 0)
		return -EPROTONOSUPPORT;

	ret = t4_set_vlan_acl(adap, adap->mbox, vf + 1, vlan);
	if (!ret) {
		adap->vfinfo[vf].vlan = vlan;
		return 0;
	}

	dev_err(adap->pdev_dev, "Err %d %s VLAN ACL for PF/VF %d/%d\n",
		ret, (vlan ? "setting" : "clearing"),
		adap->pf, vf);
	return ret;
}

static int cxgb4_mgmt_set_vf_link_state(struct net_device *dev, int vf,
					int link)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	int ret = 0;
	u32 param, val;

	if (vf >= adap->num_vfs)
		return -EINVAL;

	switch (link) {
	case IFLA_VF_LINK_STATE_AUTO:
		val = VF_LINK_STATE_AUTO;
		break;

	case IFLA_VF_LINK_STATE_ENABLE:
		val = VF_LINK_STATE_ENABLE;
		break;

	case IFLA_VF_LINK_STATE_DISABLE:
		val = VF_LINK_STATE_DISABLE;
		break;

	default:
		return -EINVAL;
	}

	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_LINK_STATE));
	ret = t4_set_params(adap, adap->mbox, adap->pf, vf + 1, 1,
			    &param, &val);
	if (ret) {
		dev_err(adap->pdev_dev,
			"Error %d in setting PF %d VF %d link state\n",
			ret, adap->pf, vf);
		return -EINVAL;
	}

	adap->vfinfo[vf].link_state = link;
	return ret;
}

static int cxgb4_mgmt_open(struct net_device *dev)
{
	/* Turn carrier off since we don't have to transmit anything on this
	 * interface.
	 */
	netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops cxgb4_mgmt_netdev_ops = {
	.ndo_open		= cxgb4_mgmt_open,
	.ndo_set_vf_mac		= cxgb4_mgmt_set_vf_mac,
	.ndo_get_vf_config	= cxgb4_mgmt_get_vf_config,
	.ndo_set_vf_rate	= cxgb4_mgmt_set_vf_rate,
	.ndo_set_vf_vlan	= cxgb4_mgmt_set_vf_vlan,
	.ndo_set_vf_link_state	= cxgb4_mgmt_set_vf_link_state,
};

static void cxgb4_mgmt_get_drvinfo(struct net_device *dev,
				   struct ethtool_drvinfo *info)
{
	struct adapter *adapter = netdev2adap(dev);

	strscpy(info->driver, cxgb4_driver_name, sizeof(info->driver));
	strscpy(info->version, cxgb4_driver_version,
		sizeof(info->version));
	strscpy(info->bus_info, pci_name(cxgb4_pci_dev(adapter)),
		sizeof(info->bus_info));
}

static const struct ethtool_ops cxgb4_mgmt_ethtool_ops = {
	.get_drvinfo       = cxgb4_mgmt_get_drvinfo,
};

static void cxgb4_mgmt_setup(struct net_device *dev)
{
	dev->type = ARPHRD_NONE;
	dev->mtu = 0;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 0;
	dev->flags |= IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;

	/* Initialize the device structure. */
	dev->netdev_ops = &cxgb4_mgmt_netdev_ops;
	dev->ethtool_ops = &cxgb4_mgmt_ethtool_ops;
}

int cxgb4_iov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct adapter *adap = pci_get_drvdata(pdev);
	int err = 0;
	int current_vfs = pci_num_vf(pdev);
	u32 pcie_fw;

	/* Check if cxgb4 is the MASTER and fw is initialized if we want
	 * to instantiate VFs ...
	 */
	pcie_fw = t4_read_reg(adap, A_PCIE_FW);
	if (!(pcie_fw & F_PCIE_FW_INIT)) {
		dev_warn(&pdev->dev, "Device not initialized\n");
		return -EOPNOTSUPP;
	}

	/* If any of the VF's is already assigned to Guest OS, then
	 * SRIOV for the same cannot be modified
	 */
	if (current_vfs && pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev,
			"Cannot modify SR-IOV while VFs are assigned\n");
		return current_vfs;
	}

	/* Note that the upper-level code ensures that we're never called with
	 * a non-zero "num_vfs" when we already have VFs instantiated.  But
	 * it never hurts to code defensively.
	 */
	if (num_vfs != 0 && current_vfs != 0)
		return -EBUSY;

	/* Nothing to do for no change.
	 */
	if (num_vfs == current_vfs)
		return num_vfs;

	/* Disable SRIOV when zero is passed.
	 */
	if (!num_vfs) {
		pci_disable_sriov(pdev);

		/* free VF Management Interface */
		unregister_netdev(adap->port[0]);
		free_netdev(adap->port[0]);
		adap->port[0] = NULL;

		/* free VF resources */
		adap->num_vfs = 0;
		kfree(adap->vfinfo);
		adap->vfinfo = NULL;

		/* cancel VF Monitor Task for T4 chips */
		if (is_t4(adap->params.chip))
			cancel_delayed_work_sync(&adap->vf_monitor_task);

		return 0;
	}

	/* If there aren't any current VFs instantiated, there's some work we
	 * need to do.  Note that this should always be the case given that
	 * the upper-level code ensures that we're never called with a
	 * non-zero "num_vfs" when we already have VFs instantiated.  But it
	 * never hurts to code defensively ...
	 */
	if (!current_vfs) {
		struct pci_dev *pbridge;
		int pos;
		u16 flags;
		u32 devcap2;
		struct net_device *netdev;
		struct port_info *pi;
		struct fw_pfvf_cmd port_cmd, port_rpl;
		unsigned int pmask, port;
		char name[IFNAMSIZ];

		/* If we want to instantiate Virtual Functions, then our
		 * parent bridge's PCI-E needs to support Alternative Routing
		 * ID (ARI) because our VFs will show up at function offset 8
		 * and above.  One could easily argue that the core Linux
		 * functions should do all of this checking but they don't ...
		 */
		pbridge = pdev->bus->self;
		pos = pci_find_capability(pbridge, PCI_CAP_ID_EXP);
		pci_read_config_word(pbridge, pos+PCI_EXP_FLAGS, &flags);
		pci_read_config_dword(pbridge, pos+PCI_EXP_DEVCAP2, &devcap2);

		if ((flags & PCI_EXP_FLAGS_VERS) < 2 ||
		    !(devcap2 & PCI_EXP_DEVCAP2_ARI)) {
			/* Our parent bridge does not support ARI so issue a
			 * warning and skip instantiating the VFs.  They
			 * won't be reachable.
			 */
			dev_warn(&pdev->dev, "Parent bridge %02x:%02x.%x doesn't "
				 "support ARI; can't instantiate Virtual Functions\n",
				 pbridge->bus->number,
				 PCI_SLOT(pbridge->devfn),
				 PCI_FUNC(pbridge->devfn));
			return -ENOTSUPP;
		}

		/* The Linux VF Management stuff is rife with all sorts of
		 * broken assumptions:
		 *
		 *  1. A VF only has the ability to instantiate a single
		 *     Virtual Interface.
		 *  2. A VF only has access to one Port, to which the one
		 *     VI will be bound.
		 *  3. The PF of the VF also has these same restrictions.
		 *  4. The Port that a VF has access to is the same as that
		 *     of its PF.
		 *
		 * Every single one of these assumptions is incorrect.  But
		 * we have to emulate this broken system until a complete
		 * rewrite of the Linux VF Management infrastructure.  So
		 * we determine the lowest numbered Port that the PF has
		 * access to here and use that for all of its VFs. (sigh)
		 */
		memset(&port_cmd, 0, sizeof(port_cmd));
		port_cmd.op_to_vfn = cpu_to_be32(V_FW_CMD_OP(FW_PFVF_CMD) |
						 F_FW_CMD_REQUEST |
						 F_FW_CMD_READ |
						 V_FW_PFVF_CMD_PFN(adap->pf) |
						 V_FW_PFVF_CMD_VFN(0));
		port_cmd.retval_len16 = cpu_to_be32(FW_LEN16(port_cmd));
		err = t4_wr_mbox(adap, adap->mbox, &port_cmd, sizeof(port_cmd),
				 &port_rpl);
		if (err)
			return err;
		pmask = G_FW_PFVF_CMD_PMASK(be32_to_cpu(port_rpl.type_to_neq));
		port = ffs(pmask) - 1;

		/* Allocate VF Management Interface.
		 */
		snprintf(name, IFNAMSIZ, "mgmtpf%d,%d", adap->adap_idx,
			 adap->pf);
		netdev = alloc_netdev(sizeof (struct port_info),
				      name, NET_NAME_UNKNOWN, cxgb4_mgmt_setup);
		if (!netdev)
			return -ENOMEM;

		pi = netdev_priv(netdev);
		pi->adapter = adap;
		pi->lport = pi->tx_chan = port;
		SET_NETDEV_DEV(netdev, &pdev->dev);

		adap->port[0] = netdev;
		pi->port_id = 0;

		err = register_netdev(adap->port[0]);
		if (err) {
			pr_info("Unable to register VF mgmt netdev %s\n", name);
			free_netdev(adap->port[0]);
			adap->port[0] = NULL;
			return err;
		}

		/* Allocate and set up VF Information.
		 */
		adap->vfinfo = kcalloc(pci_sriov_get_totalvfs(pdev),
				       sizeof(struct vf_info), GFP_KERNEL);
		if (!adap->vfinfo) {
			unregister_netdev(adap->port[0]);
			free_netdev(adap->port[0]);
			adap->port[0] = NULL;
			return -ENOMEM;
		}
		cxgb4_mgmt_fill_vf_station_mac_addr(adap);

		/* For T4 chips we need to have a monitor running to see if
		 * the chip gets stuck and then kick it to get it unstuck.  So
		 * if we're going from zero to non-zero or non-zero to zero,
		 * we have to start/stop the VF Monitor, respectively.
		 */
		if (is_t4(adap->params.chip)) {
			INIT_DELAYED_WORK(&adap->vf_monitor_task, vf_monitor);
			schedule_delayed_work(&adap->vf_monitor_task,
					      VF_MONITOR_PERIOD);
		}
	}

	/* Instantiate the requested number of VFs.
	 */
	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		pr_info("Unable to instantiate %d VFs\n", num_vfs);
		if (!current_vfs) {
			unregister_netdev(adap->port[0]);
			free_netdev(adap->port[0]);
			adap->port[0] = NULL;
			kfree(adap->vfinfo);
			adap->vfinfo = NULL;
		}
		return err;
	}

	adap->num_vfs = num_vfs;
	return num_vfs;
}
#endif /* !CHELSIO_T4_DIAGS && CONFIG_PCI_IOV */

u16 cxgb4_uld_xfrm_ipsecidx_get(struct xfrm_state *xfrm)
{
#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	struct adapter *adap;
	u16 ret = 0;

	if (!xfrm)
		return 0;

	mutex_lock(&uld_mutex);
	adap = netdev2adap(xfrm->xso.dev);

	mutex_lock(&adap->uld.uld_mutex);
	if (likely(adap->uld_handle[CXGB4_ULD_TYPE_IPSEC]))
		ret = cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrm_ipsecidx_get(xfrm);
	mutex_unlock(&adap->uld.uld_mutex);

	mutex_unlock(&uld_mutex);
	return ret;
#else
	return 0;
#endif
}
EXPORT_SYMBOL(cxgb4_uld_xfrm_ipsecidx_get);

#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)

static int chcr_offload_state(struct adapter *adap,
			      enum cxgb4_netdev_tls_ops op_val)
{
	switch (op_val) {
	case CXGB4_XFRMDEV_OPS:
		if (!adap->uld_handle[CXGB4_ULD_TYPE_IPSEC]) {
			dev_dbg(adap->pdev_dev, "chipsec driver is not loaded\n");
			return -EOPNOTSUPP;
		}
		if (!cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrmdev_ops) {
			dev_dbg(adap->pdev_dev,
				"chipsec driver has no registered xfrmdev_ops\n");
			return -EOPNOTSUPP;
		}
		break;
	default:
		dev_dbg(adap->pdev_dev,
			"driver has no support for offload %d\n", op_val);
		return -EOPNOTSUPP;
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int cxgb4_xfrm_add_state(struct xfrm_state *x,
				struct netlink_ext_ack *extack)
#else
static int cxgb4_xfrm_add_state(struct xfrm_state *x)
#endif
{
	struct adapter *adap = netdev2adap(x->xso.dev);
	int ret;

	ret = chcr_offload_state(adap, CXGB4_XFRMDEV_OPS);
	if (ret)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrmdev_ops->xdo_dev_state_add(x, extack);
#else
	ret = cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrmdev_ops->xdo_dev_state_add(x);
#endif

out:
	return ret;
}

static void cxgb4_xfrm_del_state(struct xfrm_state *x)
{
	struct adapter *adap = netdev2adap(x->xso.dev);

	if (chcr_offload_state(adap, CXGB4_XFRMDEV_OPS))
		return;

	cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrmdev_ops->xdo_dev_state_delete(x);
}

static void cxgb4_xfrm_free_state(struct xfrm_state *x)
{
	struct adapter *adap = netdev2adap(x->xso.dev);

	if (chcr_offload_state(adap, CXGB4_XFRMDEV_OPS))
		return;

	cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrmdev_ops->xdo_dev_state_free(x);
}

static bool cxgb4_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	struct adapter *adap = netdev2adap(x->xso.dev);
	bool ret = false;

	if (chcr_offload_state(adap, CXGB4_XFRMDEV_OPS))
		goto out;

	ret = cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrmdev_ops->xdo_dev_offload_ok(skb, x);

out:
	return ret;
}

static void cxgb4_advance_esn_state(struct xfrm_state *x)
{
	struct adapter *adap = netdev2adap(x->xso.dev);

	if (chcr_offload_state(adap, CXGB4_XFRMDEV_OPS))
		return;

	cxgb4_ulds[CXGB4_ULD_TYPE_IPSEC].xfrmdev_ops->xdo_dev_state_advance_esn(x);
}

static const struct xfrmdev_ops cxgb4_xfrmdev_ops = {
	.xdo_dev_state_add      = cxgb4_xfrm_add_state,
	.xdo_dev_state_delete   = cxgb4_xfrm_del_state,
	.xdo_dev_state_free     = cxgb4_xfrm_free_state,
	.xdo_dev_offload_ok     = cxgb4_ipsec_offload_ok,
	.xdo_dev_state_advance_esn = cxgb4_advance_esn_state,
};

#endif /* CONFIG_CHELSIO_T4_IPSEC_INLINE */

#define TSO_FLAGS (NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)
#define VLAN_FEAT (NETIF_F_SG | NETIF_F_IP_CSUM | TSO_FLAGS | \
		   NETIF_F_GRO | NETIF_F_IPV6_CSUM | NETIF_F_HIGHDMA)

/*
 * We control everything via a single PF (which we refer to as the "Master
 * PF").  This Master PF is identifed with a special PCI Device ID separate
 * from the "normal" NIC Device IDs so for the most part we just advertise
 * that we want to be hooked up with the Unified PF and everything works out.
 *
 * However, note that the "PE10K" FPGA is very annoying since both of its two
 * Physical Functions have the same Device ID so we need to explcitly skip
 * working with any PF other than Master PF, which we hardwire to PF0.  This
 * means that we have to undo all the I/O mapping, etc.  once we get here and
 * discover that we're actually dealing with PF1.  Hopefully the next FPGA
 * will use different PCI Device IDs for each of the PFs.
 *
 * Our PCIe Device ID Table includes PCI Device IDs both for PF4 and for
 * PF0..3.  So we'll get called for PF0..3 as well as PF4.  For production
 * Drivers (CHELSIO_T4_DIAGS not defined), we only use PF0..3 for SR-IOV
 * management.  For Diagnostics Drivers, we either attached to the normal PF4
 * or to PF0 if the module parameter attach_pf0 is set.
 */
static int cxgb4_primary_pf(struct adapter *adapter)
{
#ifndef CHELSIO_T4_DIAGS
	return (is_fpga(adapter->params.chip) ?
		0 : adapter->primary_pf);
#else
	return (attach_pf0 ? 0 : adapter->primary_pf);
#endif
}

int cxgb4_is_primary_pf(struct adapter *adapter)
{
	return adapter->pf == cxgb4_primary_pf(adapter);
}

struct adapter *cxgb4_adap_alloc(struct device *dev)
{
	return devm_kzalloc(dev, sizeof(struct adapter), GFP_KERNEL);
}

int cxgb4_mbox_log_init(struct adapter *adap)
{
	adap->mbox_log = kzalloc(sizeof(struct mbox_cmd_log) +
				 (sizeof(struct mbox_cmd) *
				  T4_OS_LOG_MBOX_CMDS), GFP_KERNEL);
	if (!adap->mbox_log)
		return -ENOMEM;

	t4_os_lock_init(&adap->mbox_lock);
	INIT_LIST_HEAD(&adap->mbox_list.list);
	adap->mbox_log->size = T4_OS_LOG_MBOX_CMDS;
	return 0;
}

void cxgb4_mbox_log_free(struct adapter *adap)
{
	kfree(adap->mbox_log);
}

int cxgb4_adap_probe(struct adapter *adapter)
{
	u32 smt_start_idx, smt_size;
	static int adap_idx = 1;
	struct port_info *pi;
	int chip_ver;
	int i, err;

	printk_once(KERN_INFO "%s - version %s\n", DRV_DESC, DRV_VERSION);

	err = cxgb4_common_resource_init(adapter);
	if (err < 0)
		return err;

	err = t4_wait_dev_ready(adapter);
	if (err < 0)
		goto out_free_resources;

	/*
	 * Initialize fields early which are accessed all over the place and
	 * are common to both the Primary PF and the SR-IOV PFs (if in use).
	 */
	err = cxgb4_common_chip_init(adapter);
	if (err < 0)
		goto out_free_resources;

	if (!cxgb4_is_primary_pf(adapter))
		return 0;

	/* Everything from here down is now the Primary Physical Function!
	 */
	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

	/* Device has been enabled */
	adapter->flags |= DEV_ENABLED;
	adapter->adap_idx = adap_idx;
	adap_idx++;

	memset(adapter->chan_map, 0xff, sizeof(adapter->chan_map));

#ifdef CHELSIO_T4_DIAGS
	dev_info(adapter->pdev_dev,
		 "Diagnostic Driver attaching to PCIe Function %d\n",
		 adapter->pf);
#endif

	/* Default message set for the interfaces. This can be changed later
	 * via "ethtool -s ethX msglvl N".
	 */
	adapter->msg_enable = DFLT_MSG_ENABLE;

	err = cxgb4_workqueues_create(adapter);
	if (err < 0)
		goto out_free_adapter;

	/*
	 * Copy all applicable "Module Parameters" into their slots within the
	 * adapter data structure early so all driver code can depend on them.
	 * We also do sanity checking here for conflicting Module arameters,
	 * etc.
	 */

#ifndef ARCH_HAS_IOREMAP_WC
	if (tx_db_wc)
		dev_warn(adapter->pdev_dev,
			 "Turning on tx_db_wc will lower performance\n");
#endif
	adapter->tx_db_wc = tx_db_wc;
	adapter->tx_coal = tx_coal;

	/* If possible, we use PCIe Relaxed Ordering Attribute to deliver
	 * Ingress Packet Data to Free List Buffers in order to allow for
	 * chipset performance optimizations between the Root Complex and
	 * Memory Controllers.  (Messages to the associated Ingress Queue
	 * notifying new Packet Placement in the Free Lists Buffers will be
	 * send without the Relaxed Ordering Attribute thus guaranteeing that
	 * all preceding PCIe Transaction Layer Packets will be processed
	 * first.)  But some Root Complexes have various issues with Upstream
	 * Transaction Layer Packets with the Relaxed Ordering Attribute set.
	 * The PCIe devices which under the Root Complexes will be cleared the
	 * Relaxed Ordering bit in the configuration space, So we check our
	 * PCIe configuration space to see if it's flagged with advice against
	 * using Relaxed Ordering.
	 */
	if (!cxgb4_pcie_relaxed_ordering_enabled(adapter))
		adapter->flags |= ROOT_NO_RELAXED_ORDERING;

	spin_lock_init(&adapter->mdio_lock);
	spin_lock_init(&adapter->win0_lock);
	spin_lock_init(&adapter->stats_lock);
	mutex_init(&adapter->user_mutex);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	INIT_WORK(&adapter->db_full_task, process_db_full);
	INIT_WORK(&adapter->db_drop_task, process_db_drop);
#endif
	INIT_WORK(&adapter->fatal_err_task, process_fatal_err);

	err = t4_prep_adapter(adapter, false);
	if (err)
		goto out_free_adapter;

#ifdef CHELSIO_T4_DIAGS
	/*
	 * FW may not always initialize external memories.  This flag tells
	 * FW to initialize memory (mainly for BIST test).  Need to run this
	 * after t4_prep_adapter() so params.chip gets initialized.
	 */
	if (extmem_init) {
		/* Do not attach to firmware */
		fw_attach = 0;
		err = t5_fw_init_extern_mem(adapter);
		if (err)
			dev_err(adapter->pdev_dev,
				"Failed to initialize external memory, error %d",
				-err);
	}

#endif

	cxgb4_common_setup_memwin(adapter);
	err = adap_init0(adapter, 0);
	if (err)
		dev_err(adapter->pdev_dev,
			"Adapter initialization failed, error %d. Continuing in debug mode\n",
			-err);

	cxgb4_common_setup_memwin_rdma(adapter);

#ifdef CONFIG_CUDBG
	/* cudbg feature is only supported for T5 & T6 cards for now */
	if (chip_ver >= CHELSIO_T5) {
		err = cxgb4_register_panic_notifier(adapter);
		if (err) {
			dev_err(adapter->pdev_dev,
				"Fail registering panic notifier, ret: %d. Continuing...\n",
				err);
			err = 0;
		}
	}
#endif

	bitmap_zero(adapter->sge.blocked_fl, adapter->sge.egr_sz);
	if ((max_eth_qsets < 32) || (max_eth_qsets > MAX_ETH_QSETS))
		max_eth_qsets = 32;

	/* Initialize hash mac addr list */
	INIT_LIST_HEAD(&adapter->mac_hlist);

	for_each_port(adapter, i) {
		struct net_device *netdev;

		netdev = alloc_etherdev_mq(sizeof(struct port_info),
					   max_eth_qsets);
		if (!netdev) {
			err = -ENOMEM;
			goto out_free_dev;
		}

		SET_NETDEV_DEV(netdev, adapter->pdev_dev);

		adapter->port[i] = netdev;
		pi = netdev_priv(netdev);
		pi->adapter = adapter;
		pi->xact_addr_filt = -1;
		pi->port_id = i;
		netdev->irq = adapter->msix_info[0].vec;

		netdev->hw_features = NETIF_F_SG | TSO_FLAGS |
			NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			NETIF_F_RXCSUM | NETIF_F_GRO |
			NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX |
			NETIF_F_HIGHDMA;

		/* Adding GRE offload and outer UDP checksum offload for
		 * T6 and onwards.
		 */
		if (chip_ver >= CHELSIO_T6 && adapter->rawf_cnt) {
			netdev->hw_enc_features |= NETIF_F_IP_CSUM |
						   NETIF_F_IPV6_CSUM |
						   NETIF_F_RXCSUM |
						   NETIF_F_GSO_GRE |
						   NETIF_F_GSO_UDP_TUNNEL |
						   NETIF_F_GSO_UDP_TUNNEL_CSUM |
						   NETIF_F_TSO | NETIF_F_TSO6;
			netdev->hw_features |= NETIF_F_GSO_GRE |
					       NETIF_F_GSO_UDP_TUNNEL |
					       NETIF_F_GSO_UDP_TUNNEL_CSUM;
			netdev->udp_tunnel_nic_info = &cxgb_udp_tunnels;
		} else if (chip_ver == CHELSIO_T5) {
			netdev->hw_enc_features |= NETIF_F_IP_CSUM |
						   NETIF_F_IPV6_CSUM |
						   NETIF_F_RXCSUM |
						   NETIF_F_GSO_UDP_TUNNEL |
						   NETIF_F_TSO | NETIF_F_TSO6;
			netdev->hw_features |= NETIF_F_GSO_UDP_TUNNEL;
			netdev->udp_tunnel_nic_info = &cxgb_t5_udp_tunnels;
		}

		netdev->features |= netdev->hw_features;
		netdev->vlan_features = netdev->features & VLAN_FEAT;

#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
#define CXGB_ESP_FEATURES      (NETIF_F_HW_ESP | \
				NETIF_F_HW_ESP_TX_CSUM | \
				NETIF_F_GSO_ESP)
	if (pi->adapter->params.ulp_crypto & ULP_CRYPTO_INLINE_IPSEC) {
		if (chip_ver == CHELSIO_T7 || chip_ver == CHELSIO_T7_FPGA) {
			netdev->hw_enc_features |= CXGB_ESP_FEATURES;
			netdev->features |= CXGB_ESP_FEATURES;
			netdev->hw_features |= CXGB_ESP_FEATURES;
		} else {
			netdev->hw_enc_features |= NETIF_F_HW_ESP;
			netdev->features |= NETIF_F_HW_ESP;
		}
		netdev->xfrmdev_ops = &cxgb4_xfrmdev_ops;
	}
#endif /* CONFIG_CHELSIO_T4_IPSEC_INLINE */

		netdev->priv_flags |= IFF_UNICAST_FLT;

		/* MTU range: 81 - 9600 */
		netdev->min_mtu = 81;	/* accomodate SACK */
		netdev->max_mtu = MAX_MTU;

		netdev->netdev_ops = &cxgb4_netdev_ops;
#ifdef CONFIG_CXGB4_DCB
		netdev->dcbnl_ops = &cxgb4_dcb_ops;
		cxgb4_dcb_state_init(netdev);
		cxgb4_dcb_version_init(netdev);
#endif
		cxgb4_set_ethtool_ops(netdev);
	}

	if (chip_ver >= CHELSIO_T6)
		t4_write_reg(adapter, A_MPS_RX_GRE_PROT_TYPE,
			     F_GRE_EN | F_NVGRE_EN | V_GRE(IPPROTO_GRE));

	if (adapter->flags & FW_OK) {
		err = t4_port_init(adapter, adapter->mbox, adapter->pf, 0);
		if (err)
			goto out_free_dev;

		if ((is_hashfilter(adapter) && enable_mirror) ||
		    cxgb4_modparam_enable_ringbb()) {
			err = t4_mirror_init(adapter, adapter->mbox,
					     adapter->pf, 0,
					     cxgb4_modparam_enable_ringbb());
			if (err)
				goto out_free_dev;

			/* emit a warning if vnic_id match is not enabled */
			if (!((F_VNIC_ID & adapter->params.tp.vlan_pri_map) &&
			      (F_VNIC & adapter->params.tp.ingress_config)))
				dev_warn(adapter->pdev_dev,
					 "vnic_id match not enabled with Mirror traffic. Filtering on Mirror traffic will not work!!");
		}

		for_each_port(adapter, i) {
			struct port_info *p = adap2pinfo(adapter, i);
			init_ma_fail_data(p);
			adapter->port[i]->dev_port = p->lport;
		}
	} else if (adapter->params.nports == 1) {
		/* If we don't have a connection to the firmware -- either
		 * because of an error or because fw_attach=0 was specified --
		 * grab the raw VPD parameters so we can set the proper MAC
		 * Address on the debug network interface that we've created.
		 */
		u8 hw_addr[ETH_ALEN];
		u8 *na = adapter->params.vpd.na;

		err = t4_get_raw_vpd_params(adapter, &adapter->params.vpd);
		if (!err) {
			for (i = 0; i < ETH_ALEN; i++)
				hw_addr[i] = (hex2val(na[2 * i + 0]) * 16 +
					      hex2val(na[2 * i + 1]));
			t4_os_set_hw_addr(adapter, 0, hw_addr);
		}
	}

	if (!(adapter->flags & FW_OK))
		goto fw_attach_fail;

	adap_smt_index(adapter, &smt_start_idx, &smt_size);
	adapter->smt = t4_init_smt(smt_start_idx, smt_size);
	if (!adapter->smt)
		dev_warn(adapter->pdev_dev,
			 "could not allocate SMT, continuing\n");

	adapter->l2t = t4_init_l2t(adapter->l2t_start, adapter->l2t_end);
	if (!adapter->l2t) {
		/* We tolerate a lack of L2T, giving up some functionality */
		dev_warn(adapter->pdev_dev,
			 "could not allocate L2T, continuing\n");
	}

	if ((chip_ver <= CHELSIO_T5) &&
	    (!(t4_read_reg(adapter, A_LE_DB_CONFIG) & F_ASLIPCOMPEN))) {
		/* CLIP functionality is not present in hardware,
		 * hence disable all offload features
 		 */
		dev_warn(adapter->pdev_dev,
			 "CLIP not enabled in hardware, continuing\n");
	} else {
		adapter->clipt = t4_init_clip_tbl(adapter->clipt_start,
						  adapter->clipt_end);
		if (!adapter->clipt) {
			/* We tolerate a lack of clip_table, giving up
			 * some functionality
			 */
			dev_warn(adapter->pdev_dev,
				 "could not allocate Clip table, continuing\n");
		}
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adapter))
		__set_bit(OFFLOAD_DEVMAP_BIT, &adapter->registered_device_map);
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

#ifdef CONFIG_CHELSIO_BYPASS
	/*
	 * We need to call the Bypass Adapter's setup routine very early on in
	 * order to set the current and failure modes correctly.  These will
	 * be set to the failover mode of the previous incarnation of the
	 * driver.  This early call also means that these are reported
	 * correctly via the interface even though the interfaces haven't been
	 * brought up yet.
	 */
	if (is_bypass(adapter))
		t4_bypass_setup(adapter);
#endif

	err = cfg_queues(adapter);  // XXX move after we know interrupt type
	if (err)
		goto out_free_dev;

	err = init_rss(adapter);
	if (err)
		goto out_disable_interrupts;

	/*
	 * See what interrupts we'll be using.  Note that we need to enable
	 * our interrupts before we register the network devices since certain
	 * installations can have the network devices setup for automatic
	 * configuration.  When that happens, we can get a Port Link Status
	 * message from the firmware on our Asynchronous Firmware Event Queue
	 * and end up losing the interrupt.
	 */
	err = cxgb4_enable_irqs(adapter);
	if (err)
		goto out_disable_interrupts;

	if (cxgb4_msix_enabled(adapter) || cxgb4_msi_enabled(adapter)) {
		/* TODO: Re-enable once MSI-X works on Platform */
		if (!cxgb4_is_platform_device(adapter)) {
			err = cxgb4_check_msi(adapter);
			if (err)
				goto out_disable_interrupts;
		} else {
			dev_warn(adapter->pdev_dev,
				 "FAIL - MSI check not implemented\n");
		}
	}

fw_attach_fail:
	cxgb_init_mps_ref_entries(adapter);

	/*
	 * The card is now ready to go.  If any errors occur during device
	 * registration we do not fail the whole card but rather proceed only
	 * with the ports we manage to register successfully.  However we must
	 * register at least one net device.
	 */
	for_each_port(adapter, i) {
		pi = adap2pinfo(adapter, i);
		adapter->port[i]->dev_port = pi->lport;
		netif_set_real_num_tx_queues(adapter->port[i], pi->nqsets);
		netif_set_real_num_rx_queues(adapter->port[i], pi->nqsets);

		err = register_netdev(adapter->port[i]);
		if (err)
			dev_warn(adapter->pdev_dev,
				 "cannot register net device %s, skipping\n",
				 adapter->port[i]->name);
		else {
			u8 idx, nchan;

			/*
			 * Change the name we use for messages to the name of
			 * the first successfully registered interface.
			 */
			if (!adapter->registered_device_map)
				adapter->name = adapter->port[i]->name;

			__set_bit(i, &adapter->registered_device_map);
			switch (adapter->params.tp.lb_mode) {
			case 1:
				nchan = 4;
				break;
			case 2:
				nchan = 2;
				break;
			default:
				nchan = 1;
				break;
			}

			for (idx = 0; idx < nchan; idx++)
				adapter->chan_map[pi->lport * nchan + idx] = i;

			netif_carrier_off(adapter->port[i]);
		}
	}
	if (!adapter->registered_device_map) {
		dev_err(adapter->pdev_dev, "could not register any net devices\n");
		goto out_disable_interrupts;
	}

	if (cxgb4_debugfs_root) {
		const char *dir_name = cxgb4_is_platform_device(adapter) ?
						adapter->name :
						pci_name(adapter->pdev.pci_dev);
		adapter->debugfs_root = debugfs_create_dir(dir_name,
							   cxgb4_debugfs_root);
		cxgb4_setup_debugfs(adapter);
	}

	/*
	 * Setup sysfs
	 */
	for_each_port(adapter, i)
		if (sysfs_create_group(&adapter->port[i]->dev.kobj,
				       &t4_attr_group))
			dev_warn(adapter->pdev_dev,
				 "cannot create sysfs t4_attr_group net device %s\n",
				 adapter->port[i]->name);

#ifdef CONFIG_CHELSIO_BYPASS
	if (is_bypass(adapter))
		bypass_sysfs_create(adapter);
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adapter)) {
		cxgb4_uld_queues_init(adapter);
		attach_ulds(adapter);
	}

	if (!(registered_notifier_block & CXGB4_INET6ADDR_REGISTERED)) {
		register_inet6addr_notifier(&cxgb4_inet6addr_notifier);
		registered_notifier_block |= CXGB4_INET6ADDR_REGISTERED;
	}
#endif

	print_adapter_info(adapter);
	print_port_info(adapter);

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adapter->params.chip) && (adapter->flags & FW_OK))
		cxgb4_ptp_init(adapter);
#endif
#ifdef CONFIG_THERMAL
	if (!is_t4(adapter->params.chip) && (adapter->flags & FW_OK))
		cxgb4_thermal_init(adapter);
#endif /* CONFIG_THERMAL */

#define A_TP_CDSP_CONFIG 0x242
	t4_tp_wr_bits_indirect(adapter, A_TP_CDSP_CONFIG, 1U << 2, 1U << 2); //TODO remove it later

	if (chip_ver >= CHELSIO_T6)
		t4_set_reg_field(adapter, 0x1925c, (1U << 9), (1U << 9));

	if (is_t7a(adapter->params.chip)) {
		t4_set_reg_field(adapter, A_TP_IN_CONFIG,
				 (1U << 28) | (1U << 29) | (1U << 30) | (1U << 31), 0);
	} else if (chip_ver >= CHELSIO_T7) {
		t4_set_reg_field(adapter, 0x19330, (1U << 25) | (1U << 27),
				 (1U << 25) | (1U << 27));
		t4_set_reg_field(adapter, A_SGE_CONTROL2,
				 (1U << 27) | (1U << 28),
				 (1U << 27) | (1U << 28));
#define A_ULP_RX_CTL1 0x19330
		t4_set_reg_field(adapter, A_ULP_RX_CTL1,
				 (1U << 16) | (1U << 17) | (1U << 20),
				 (1U << 16) | (1U << 17) | (1U << 20));
	}

	return 0;

	/*
	 * Non-standard returns ...
	 */
out_disable_interrupts:
	cxgb4_disable_irqs(adapter);

out_free_dev:
	t4_free_mem(adapter->l2t);
	t4_free_mem(adapter->smt);
	for_each_port(adapter, i)
		if (adapter->port[i]) {
			pi = netdev_priv(adapter->port[i]);
			if (pi->viid != 0)
				t4_free_vi(adapter, adapter->mbox, adapter->pf,
					   0, pi->viid);
			if (pi->viid_mirror != 0)
				t4_free_vi(adapter, adapter->mbox, adapter->pf,
					   0, pi->viid_mirror);
			kfree(adap2pinfo(adapter, i)->rss);
			free_netdev(adapter->port[i]);
		}
	if (adapter->flags & FW_OK)
		cxgb4_common_fw_free(adapter);

out_free_adapter:
	mutex_destroy(&adapter->user_mutex);

	cxgb4_workqueues_destroy(adapter);

#ifdef CONFIG_CUDBG
	cxgb4_unregister_panic_notifier(adapter);
#endif
	cxgb4_common_chip_free(adapter);

out_free_resources:
	cxgb4_common_resource_free(adapter);
	return err;
}

void cxgb4_adap_remove(struct adapter *adapter)
{
	struct hash_mac_addr *entry, *tmp;
	int i;

	/*
	 * There are some cases where we end up probing more than one function
	 * in init_one() -- the T4 FPGA where both PFs have the Device ID of
	 * 0xa000, the Diagnostics driver which attaches to PF0 because of a
	 * mis-design "feature" in T4 where PF0..3 all have the same PCI
	 * Device ID, etc.  init_one() doesn't return an error for these
	 * probes because that would unnecessarily confuse people with
	 * warnings in the System Logs, etc.  However, that means that we'll
	 * also get called on all of those same devices here.  We could
	 * perform the same Device/Function ID checks that are in init_one()
	 * but it's simpler to just see if init_one() left an adapter
	 * structure in the Linux PCI Driver Data pointer ...
	 */
	if (!adapter)
		return;

	/*
	 * If we're the MASTER PF, then we have quite a lot of cleanup to do.
	 */
	if (cxgb4_is_primary_pf(adapter)) {
		if (adapter->debugfs_root) {
			free_trace_bufs(adapter);
#if DMABUF
			dma_free_coherent(adapter->pdev_dev, DMABUF_SZ,
					  adapter->dma_virt,
					  adapter->dma_phys);
#endif
		}

		debugfs_remove_recursive(adapter->debugfs_root);

		/*
		 * Tear down per-adapter Work Queue first since it can contain
		 * references to our adapter data structure.
		 */
		cxgb4_workqueues_destroy(adapter);

#ifdef CONFIG_CHELSIO_BYPASS
		/*
		 * We call the Bypass Adapter's shutdown logic here, redundantly
		 * with same call in cxgb_down().  We do this because the
		 * interface may never have been brought up but the adapter's
		 * failover mode may have been set to a new value ...
		 */
		if (is_bypass(adapter)) {
			t4_bypass_shutdown(adapter);
			bypass_sysfs_remove(adapter);
		}
#endif
		/*
		 * If we allocated filters, free up state associated with any
		 * valid filters ...
		 */
		cxgb4_filter_clear_all(adapter);

		disable_interrupts(adapter);
		quiesce_rx(adapter);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		if (cxgb4_uld_supported_any(adapter)) {
			if (!list_empty(&adapter->list_node))
				detach_ulds(adapter);
			cxgb4_uld_queues_cleanup(adapter);
		}
		if ((registered_notifier_block & CXGB4_INET6ADDR_REGISTERED) &&
		    list_empty(&adapter_list)) {
			unregister_inet6addr_notifier(&cxgb4_inet6addr_notifier);
			registered_notifier_block &=
				~CXGB4_INET6ADDR_REGISTERED;
		}
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
		cxgb4_uld_cleanup(adapter);
		adap_free_hma_mem(adapter);
#endif

		/*
		 * Remove sysfs group
		 */
		for_each_port(adapter, i)
			sysfs_remove_group(&adapter->port[i]->dev.kobj,
					   &t4_attr_group);

		for_each_port(adapter, i)
			if (test_bit(i, &adapter->registered_device_map))
				unregister_netdev(adapter->port[i]);

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		if (!is_t4(adapter->params.chip))
			cxgb4_ptp_remove(adapter);
#endif

		if (adapter->flags & FULL_INIT_DONE)
			cxgb_down(adapter);
		t4_free_mem(adapter->l2t);
		t4_free_mem(adapter->smt);
		cxgb4_tid_info_cleanup(adapter);
		t4_free_mem(adapter->filters);
		cxgb4_sge_egr_map_destroy(adapter);
		kfree(adapter->sge.ingr_map);
		kfree(adapter->sge.starving_fl);
		kfree(adapter->sge.blocked_fl);
		ehash_filter_locks_free(&adapter->filter_tcphash);
		ehash_filter_locks_free(&adapter->filter_udphash);
		t4_free_mem(adapter->filter_tcphash.ehash);
		t4_free_mem(adapter->filter_udphash.ehash);
		cxgb4_disable_irqs(adapter);
		cxgb_free_mps_ref_entries(adapter);

		for_each_port(adapter, i)
			if (adapter->port[i]) {
				struct port_info *pi = adap2pinfo(adapter, i);

				if (pi->viid != 0)
					t4_free_vi(adapter, adapter->mbox,
						   adapter->pf, 0, pi->viid);
				if (pi->viid_mirror != 0)
					t4_free_vi(adapter, adapter->mbox,
						   adapter->pf, 0,
						   pi->viid_mirror);
				kfree(adap2pinfo(adapter, i)->rss);
				free_netdev(adapter->port[i]);
			}

		list_for_each_entry_safe(entry, tmp, &adapter->mac_hlist, list) {
			list_del(&entry->list);
			kfree(entry);
		}

		if (adapter->flags & FW_OK)
			cxgb4_common_fw_free(adapter);

		t4_cleanup_clip_tbl(adapter);

#ifdef CONFIG_THERMAL
		if (!is_t4(adapter->params.chip))
			cxgb4_thermal_remove(adapter);
#endif
	}
#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
	else {
		/* If we're not the normal Unified Physical Function, we must
		 * be one of the PCIe SR-IOV PFs, so clean up any Virtual
		 * Function state.
		 */
		cxgb4_common_iov_configure(adapter, 0);
	}
#endif /* !CHELSIO_T4_DIAGS && CONFIG_PCI_IOV */

	cxgb4_common_chip_free(adapter);
	cxgb4_common_resource_free(adapter);
	adapter->flags &= ~DEV_ENABLED;
#ifdef CONFIG_CUDBG
	cxgb4_unregister_panic_notifier(adapter);
#endif
}

/*
 * "Shutdown" quiesces the device, stopping Ingress Packet and Interrupt
 * delivery.  This is essentially a stripped down version of the PCI remove()
 * function where we do the minimal amount of work necessary to shutdown any
 * further activity.
 *
 * Caveat by DM :  We're leaving stale state behind, hot unplug might trip on that
 */

void cxgb4_adap_shutdown(struct adapter *adapter)
{
	int i;

	/*
	 * As with remove_one() above (see extended comment), we only want do
	 * do cleanup on PCI Devices which went all the way through init_one()
	 * ...
	 */
	if (!adapter)
		return;

#ifdef CONFIG_PCI_IOV
	/*
	 * If we're not the normal Unified Physical Function, we must be one
	 * of the PCIe SR-IOV PFs, so clean up any Virtual Function state.
	 */
	if (!cxgb4_is_primary_pf(adapter) &&
	    !cxgb4_is_platform_device(adapter)) {
		struct pci_dev *pdev = cxgb4_pci_dev(adapter);

		if (pci_num_vf(pdev)) {
			if (is_t4(adapter->params.chip))
				cancel_delayed_work_sync(&adapter->vf_monitor_task);
			pci_disable_sriov(pdev);
		}
	}
#endif

#ifdef CONFIG_CHELSIO_BYPASS
	/*
	 * We call the Bypass Adapter's shutdown logic here, redundantly with
	 * same call in cxgb_down().  We do this because the interface may
	 * never have been brought up but the adapter's failover mode may have
	 * been set to a new value ...
	 */
	if (is_bypass(adapter))
		t4_bypass_shutdown(adapter);
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (cxgb4_uld_supported_any(adapter))
		shutdown_ulds(adapter);
#endif
	for_each_port(adapter, i)
		if (test_bit(i, &adapter->registered_device_map))
			cxgb_close(adapter->port[i]);

	disable_interrupts(adapter);
	quiesce_rx(adapter);

	cxgb4_disable_irqs(adapter);

	t4_sge_stop(adapter);
	if (adapter->flags & FW_OK)
		cxgb4_common_fw_free(adapter);
}

static int __init cxgb4_init_module(void)
{
	int ret;

	/* Debugfs support is optional, just warn if this fails */
	cxgb4_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (!cxgb4_debugfs_root)
		pr_warn("could not create debugfs entry, continuing\n");

#ifndef CONFIG_CHELSIO_BYPASS
	/*
	 * If we have an Adapter Shutdown Watchdog Timer configured make sure
	 * that A. we can service the requested watchdog timer frequently
	 * enough (i.e. the timer needs to be at least twice the minumum
	 * ersceduling time: HZ) and B. that the timer is at least as large as
	 * the minimum firmware watchdog scheduling quantum (10ms).  Finally,
	 * to prevent absurd performance problems, we limit the minimum period
	 * to DEADMAN_WATCHDOG_MIN.  Since this last constraint is likely to
	 * be larger than the other two constraints we could just use that but
	 * it's better to be explicit about things and let the compiler
	 * optimize the condition ...
	 */
	if (deadman_watchdog[0]) {
		const int min_sched = 1000/HZ * 2;
		const int min_quanta = 10;
		const int min_watchdog = DEADMAN_WATCHDOG_MIN;
		const int max_watchdog = DEADMAN_SHUTDOWN_MAX; 
			
		deadman_watchdog[0] =
			min(max_watchdog,max(deadman_watchdog[0],
			    max(min_sched, max(min_quanta, min_watchdog))));
	}
#endif /* !CONFIG_CHELSIO_BYPASS */

	ret = cxgb4_pci_driver_register();
	if (ret < 0)
		goto out_err;

#ifdef CXGB4_PLATFORM
	ret = cxgb4_platform_driver_register();
	if (ret < 0)
		goto out_pci_unregister;
#endif

	return 0;

#ifdef CXGB4_PLATFORM
out_pci_unregister:
	cxgb4_pci_driver_unregister();
#endif
out_err:
	debugfs_remove(cxgb4_debugfs_root);
	return ret;
}

static void __exit cxgb4_cleanup_module(void)
{
#ifdef CXGB4_PLATFORM
	cxgb4_platform_driver_unregister();
#endif
	cxgb4_pci_driver_unregister();
	debugfs_remove(cxgb4_debugfs_root);  /* NULL ok */
}

module_init(cxgb4_init_module);
module_exit(cxgb4_cleanup_module);
