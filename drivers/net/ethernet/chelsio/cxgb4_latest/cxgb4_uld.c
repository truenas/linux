/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/crash_dump.h>

#include <net/offload.h>

#include "common.h"
#include "t4_regs.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "srq.h"
#include "cxgb4_ctl_defs.h"
#include "cxgb4_ofld.h"

/* Return number of active-open TIDs currently in use.
 */
u32 cxgb4_uld_atid_in_use(struct net_device *dev)
{
	return cxgb4_atid_in_use(netdev2adap(dev));
}
EXPORT_SYMBOL(cxgb4_uld_atid_in_use);

/* Lookup active-open TID data
 */
void *cxgb4_uld_atid_lookup(struct net_device *dev, u32 atid)
{
	return cxgb4_atid_lookup(netdev2adap(dev), atid);
}
EXPORT_SYMBOL(cxgb4_uld_atid_lookup);

/* Allocate an active-open TID and set it to the supplied value.
 */
int cxgb4_uld_atid_alloc(struct net_device *dev, void *data)
{
	return cxgb4_atid_alloc(netdev2adap(dev), data);
}
EXPORT_SYMBOL(cxgb4_uld_atid_alloc);

/* Release an active-open TID.
 */
void cxgb4_uld_atid_free(struct net_device *dev, u32 atid)
{
	cxgb4_atid_free(netdev2adap(dev), atid);
}
EXPORT_SYMBOL(cxgb4_uld_atid_free);

/* Return number of TIDs currently in use.
 */
u32 cxgb4_uld_tid_in_use(struct net_device *dev)
{
	return cxgb4_tid_in_use(netdev2adap(dev));
}
EXPORT_SYMBOL(cxgb4_uld_tid_in_use);

/* Return if specified TIDs is out of range.
 */
bool cxgb4_uld_tid_out_of_range(struct net_device *dev, u32 tid)
{
	return cxgb4_tid_out_of_range(netdev2adap(dev), tid);
}
EXPORT_SYMBOL(cxgb4_uld_tid_out_of_range);

/* Lookup TID data
 */
void *cxgb4_uld_tid_lookup(struct net_device *dev, u32 tid)
{
	return cxgb4_tid_lookup(netdev2adap(dev), tid);
}
EXPORT_SYMBOL(cxgb4_uld_tid_lookup);

/* Insert value at specified TID location.
 */
int cxgb4_uld_tid_insert(struct net_device *dev, u16 family, u32 tid,
			 void *data)
{
	return cxgb4_tid_insert(netdev2adap(dev), tid, data,
				family == AF_INET6);
}
EXPORT_SYMBOL(cxgb4_uld_tid_insert);

/* Remove value as specified TID location and release the TID.
 */
void cxgb4_uld_tid_remove(struct net_device *dev, u8 chan, u16 family, u32 tid)
{
	cxgb4_tid_remove(netdev2adap(dev), chan, tid, family == AF_INET6);
}
EXPORT_SYMBOL(cxgb4_uld_tid_remove);

/* Allocate a server filter TID and set it to the supplied value.
 */
int cxgb4_uld_sftid_alloc(struct net_device *dev, u16 family, void *data)
{
	return cxgb4_sftid_alloc(netdev2adap(dev), data, family == PF_INET6);
}
EXPORT_SYMBOL(cxgb4_uld_sftid_alloc);

/* Lookup server TID data
 */
void *cxgb4_uld_stid_lookup(struct net_device *dev, u32 stid)
{
	return cxgb4_stid_lookup(netdev2adap(dev), stid);
}
EXPORT_SYMBOL(cxgb4_uld_stid_lookup);

/* Allocate a server TID and set it to the supplied value.
 */
int cxgb4_uld_stid_alloc(struct net_device *dev, u16 family, void *data)
{
	return cxgb4_stid_alloc(netdev2adap(dev), data, family == PF_INET6);
}
EXPORT_SYMBOL(cxgb4_uld_stid_alloc);

/* Release a server TID.
 */
void cxgb4_uld_stid_free(struct net_device *dev, u16 family, u32 stid)
{
	cxgb4_stid_free(netdev2adap(dev), stid, family == PF_INET6);
}
EXPORT_SYMBOL(cxgb4_uld_stid_free);

/* Lookup UO TID data
 */
void *cxgb4_uld_uotid_lookup(struct net_device *dev, u32 uotid)
{
	return cxgb4_uotid_lookup(netdev2adap(dev), uotid);
}
EXPORT_SYMBOL(cxgb4_uld_uotid_lookup);

/* Allocate a UO TID and set it to the supplied value.
 */
int cxgb4_uld_uotid_alloc(struct net_device *dev, void *data)
{
	return cxgb4_uotid_alloc(netdev2adap(dev), data);
}
EXPORT_SYMBOL(cxgb4_uld_uotid_alloc);

/* Release a UO TID.
 */
void cxgb4_uld_uotid_free(struct net_device *dev, u32 uotid)
{
	cxgb4_uotid_free(netdev2adap(dev), uotid);
}
EXPORT_SYMBOL(cxgb4_uld_uotid_free);

/* Return the channel of the ingress queue with the given qid.
 */
static unsigned int cxgb4_uld_rxq_to_chan(const struct sge *p, unsigned int qid)
{
	qid -= p->ingr_start;
	return netdev2pinfo(p->ingr_map[qid]->netdev)->tx_chan;
}

/**
 *	cxgb4_uld_server_create_restricted - create a "restricted" IPv4 server
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IP address to bind server to
 *	@sport: the server's TCP port
 *	@filter_value: Filter Value
 *	@filter_mask: Filter Mask
 *	@queue: queue to which to direct messages from this server
 *
 *	Creates an IPv4 Server for the given TCP Port and IPv4 Local
 *	Address.  (The Local end of a listening socket are often referred to
 *	as the "Source" for odd historical reasons.)
 *
 *	The Server entry is rewritten with the specified Filter Value/Mask
 *	tuple in order to restrict the incoming SYNs to which the Server
 *	Entry will match (and thus respond).  This uses the extended "Filter
 *	Information" capabilities of Server Control Blocks (SCB).  (See
 *	"Classification and Filtering" in the Data Book for a description
 *	of Ingress Packet pattern matching capabilities.  See also
 *	documentation on the TP_VLAN_PRI_MAP register.)
 *
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
static int cxgb4_uld_server_create_restricted(const struct net_device *dev,
					      unsigned int stid,
					      __be32 sip, __be16 sport,
					      u64 filter_value,
					      u64 filter_mask,
					      unsigned int queue)
{
	/* We need to program the extended Filter Information for our
	 * Listening Server.  Unfortunately the Passive Open Request CPL only
	 * lets us program the "value" portion of the extended Filter
	 * Information which is stored in the LE TCAM for the Listening Server
	 * ... and programs the "mask" portion to 0 ... which doesn't do
	 * anyone any good.  So we have to send in the Passive Open Request
	 * _and_ several Set LE CPLs to completely reprogram the LE TCAM line
	 * associated with the Listening Server (the LE TCAM doesn't support
	 * partial writes).
	 *
	 * Since each Set LE TCAM CPL can write 128 bits and since an IPv4 LE
	 * TCAM Entry is 132 bits for T4 (136 for T5 and later), we need 2 Set
	 * LE TCAM CPLs.  We accomplish this by wrapping all of the messages
	 * in a Firmware ULP TX Work Request with the "atomic" bit set ...
	 *
	 * Note that each ULP_TXPKT wrapped CPL needs to be an integral number
	 * of 16-byte units ...
	 *
	 * Also note that the embedded CPLs are _only_ the CPLs themselves and
	 * do _not_ include the firmware Work Request Headers.  This is very
	 * awkward given the data structure definitions in t4_msg.h so we have
	 * to play some games here ...
	 */
	struct pass_open_req_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_pass_open_req) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	struct set_le_req_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_set_le_req) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	/* The number of 128-bit Set LE TCAM CPLs needed for IPv4 */
	#define SETLE128_IPV4 DIV_ROUND_UP(132, 128) /* match LE_SZ_132 */
	struct atomic_pass_open_req {
		struct fw_ulptx_wr		ulptx_wr;
		struct pass_open_req_ulp_txpkt	pass_open;
		struct set_le_req_ulp_txpkt	set_le[SETLE128_IPV4];
	} *req;

	struct cpl_set_le_req *setler[SETLE128_IPV4];
	struct adapter *adap = netdev2adap(dev);
	unsigned int reqlen = sizeof(*req);
	struct cpl_pass_open_req *popenr;
	unsigned int chan, chip_ver;
	struct sk_buff *skb;
	int ret, i;

	chan = cxgb4_uld_rxq_to_chan(&adap->sge, queue);
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	/* Allocate an skb large enough to hold our atomic request.
	 */
	skb = alloc_skb(reqlen, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	req = (struct atomic_pass_open_req *)__skb_put(skb, reqlen);
	memset(req, 0, reqlen);

	/* Initialize the Firmware ULP TX Work Request and all of the ULP
	 * TX Packet routing messages ...
	 */
	req->ulptx_wr.op_to_compl =
		cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) | F_FW_WR_ATOMIC);
	req->ulptx_wr.flowid_len16 =
		cpu_to_be32(V_FW_WR_LEN16(reqlen / 16));

	/* Everything is going to TP */
	req->pass_open.ulptx.cmd_dest =
		cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
			    V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].ulptx.cmd_dest =
			cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
				    V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));

	/* Size of the ULP_TXPKT embedded CPL Passive Open Request */
	req->pass_open.ulptx.len =
		cpu_to_be32(sizeof(struct pass_open_req_ulp_txpkt) / 16);

	/* Size of the ULP_TXPKT embedded CPL Set LE Requests */
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].ulptx.len =
			cpu_to_be32(sizeof(struct set_le_req_ulp_txpkt) / 16);

	/* Fill in the Immediate Data information for the embedded CPLs */
	req->pass_open.sc.cmd_more = cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].sc.cmd_more =
			cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	req->pass_open.sc.len =
		cpu_to_be32(sizeof(struct cpl_pass_open_req) -
			      sizeof(struct work_request_hdr));
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].sc.len =
			cpu_to_be32(sizeof(struct cpl_set_le_req) -
				    sizeof(struct work_request_hdr));

	/* Initialize the CPL Passive Open Request ...  Note again the
	 * need to deal with the omitted firmware Work Request Header ...
	 * Also note that as a result we do _not_ need to do the standard
	 * INIT_TP_WR() to initialize the non-existant Work Request header.
	 */
	popenr = (struct cpl_pass_open_req *)
		 (req->pass_open.req - sizeof(struct work_request_hdr));
	OPCODE_TID(popenr) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ, stid));
	popenr->local_port = sport;
	popenr->local_ip = sip;
	popenr->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	popenr->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				   F_SYN_RSS_ENABLE |
				   V_SYN_RSS_QUEUE(queue) |
				   (filter_value << ((chip_ver == CHELSIO_T4)
						  ? S_FILT_INFO
						  : S_T5_FILT_INFO)));

	/* And now the difficult part: rewriting the entire LE TCAM line
	 * for the Listen Server ...  First we initialize everything
	 * other than the values and masks ...
	 */
	for (i = 0; i < SETLE128_IPV4; i++) {
		setler[i] = (struct cpl_set_le_req *)
			(req->set_le[i].req - sizeof(struct work_request_hdr));
		OPCODE_TID(setler[i]) =
			cpu_to_be32(MK_OPCODE_TID(CPL_SET_LE_REQ, stid << 2));
		setler[i]->reply_ctrl = cpu_to_be16(F_NO_REPLY);
		setler[i]->params =
			cpu_to_be16((chip_ver >= CHELSIO_T7 ?
				     V_CPL_T7_SET_LE_REQ_REQTYPE(0) :
				     V_LE_REQ_IP6(0)) |
				    V_LE_CHAN(chan) |
				    V_LE_OFFSET(i) |
				    V_LE_MORE(i != SETLE128_IPV4 - 1) |
				    V_LE_REQSIZE((chip_ver <= CHELSIO_T5) ?
						 LE_SZ_132 : 0) |
				    V_LE_REQCMD(LE_CMD_WRITE));
	}

	/* Now we need to write the value/mask portions of the Set LE TCAM
	 * Requests.  For T5 there are 136 bits in the IPv4 LE TCAM entry which
	 * are addressed as follows (T4 has 4 fewer bits in the Compressed
	 * Filter):
	 *
	 *   T5 IPv4 LE TCAM Entry:
	 *   ----------------------
	 *    135                                                    0
	 *   +--------------------------------------------------------+
	 *   |    Compressed  |   Local   | Foreign | Local | Foreign |
	 *   |    Filter      |   IP      | IP      | Port  | Port    |
	 *   +--------------------------------------------------------+
	 *           -40-          -32-       -32-     -16-     -16-
	 *
	 *   Set LE TCAM CPLs:
	 *   -----------------
	 *        127                   64 63                        0
	 *   +--------------------------------------------------------+
	 *   |1: |     0:val_hi/mask_hi   |      0:val_lo/mask_lo     |
	 *   +--------------------------------------------------------+
	 *    -8-            -64-                       -64-
	 *
	 * The Set LE Request with Offset=0 covers the lowest 128 bits and the
	 * one with Offset=1 covers the remaining 8 bits (4 bits for T4).  We
	 * need to replicate the TP logic for computing masks for the Local
	 * and Foreign IP Addresses and Ports which default to all 0s if the
	 * corresponding value is zero and all 1s if it's non-zero.
	 *
	 * Remember that when dealng with offsets within the Set LE Value/
	 * Mask High/Low fields, we're dealing with Big Endian objects.  So,
	 * for instance, the Local Port number is 4 bytes into the Low tuple
	 * of SetLEreq[0] ...
	 */
	if (sport) {
		((__be16 *)&setler[0]->val_lo)[2] = sport;
		((__be16 *)&setler[0]->mask_lo)[2] = (__force __be16)0xffff;
	}
	if (sip) {
		((__be32 *)&setler[0]->val_hi)[1] = sip;
		((__be32 *)&setler[0]->mask_hi)[1] = (__force __be32)0xffffffff;
	}

	/* The lower 32-bits of the Filter Value/Mask go into the high (first)
	 * four bytes of the Big Endian val_hi/mask_hi of the Set LE
	 * Request[0].  The high 8-bits go into the low (last) byte of the
	 * Big Endian val_lo/mask_lo of the Set LE Request[1].
	 */
	((__be32 *)&setler[0]->val_hi)[0] = cpu_to_be32((u32)filter_value);
	((__be32 *)&setler[0]->mask_hi)[0] = cpu_to_be32((u32)filter_mask);

	((u8 *)&setler[1]->val_lo)[7] = (u8)(filter_value >> 32);
	((u8 *)&setler[1]->mask_lo)[7] = (u8)(filter_mask >> 32);

	/* Finally it's time to send the whole thing off ...
	 */
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
	#undef SETLE128_IPV4
}

/**
 *	cxgb4_uld_server_vlan_create - create IPv4 server restricted to a VLAN
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IP address to bind server to
 *	@sport: the server's TCP port
 *	@vlan: the VLAN to which to restrict the Offloaded Connections
 *	@queue: queue to which to direct messages from this server
 *
 *	This is mostly a convenience API front end to the far more general
 *	purpose cxgb4_server_create_restricted() API.  It also serves as a
 *	good example of how one would use the more general API.
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
static int cxgb4_uld_server_vlan_create(const struct net_device *dev,
					unsigned int stid,
					__be32 sip, __be16 sport,
					__be16 vlan_id,
					unsigned int queue)
{
	struct adapter *adapter = netdev2adap(dev);
	u64 filter_value, filter_mask;

	/* Compute the extended Filter Information we'll be attaching to the
	 * Listen Server in the LE TCAM.  Note that all of the fields that
	 * we set here need to be specified in the Firmware Configuration
	 * File "filterMask" specification.
	 *
	 * We also want to specify the TCP Protocol in order to avoid
	 * aliasing with UDP servers.
	 */
	if (cxgb4_uld_create_filter_info(dev,
					 &filter_value, &filter_mask,
					 /*fcoe*/ -1,
					 /*port*/ -1,
					 /*vnic*/ -1,
					 /*vlan_id*/ be16_to_cpu(vlan_id) & 0xfff,
					 /*vlan_pcp*/ -1,
					 /*vlan_dei*/ -1,
					 /*tos*/ -1,
					 /*protocol*/ IPPROTO_TCP,
					 /*ethertype*/ -1,
					 /*macmatch*/ -1,
					 /*matchtype*/ -1,
					 /*frag*/ -1) < 0) {
		dev_warn(adapter->pdev_dev,
			 "Can't differentiate Offloaded incoming connections based on VLAN + TCP; not set in TP_VLAN_PRI_MAP\n");
		return -EOPNOTSUPP;
	}

	return cxgb4_uld_server_create_restricted(dev, stid, sip, sport,
						  filter_value, filter_mask,
						  queue);
}

int cxgb4_uld_server_create(const struct net_device *dev, unsigned int stid,
			    __be32 sip, __be16 sport, __be16 vlan,
			    unsigned int queue, const u8 *tx_chan)
{
	struct cpl_pass_open_req *req;
	struct adapter *adap;
	struct sk_buff *skb;
	unsigned int chan;
	int ret;

	/* This code demonstrates how one would selectively Offload
	 * (TOE) certain incoming connections by using the extended
	 * "Filter Information" capabilities of Server Control Blocks
	 * (SCB).  (See "Classification and Filtering" in the T4 Data
	 * Book for a description of Ingress Packet pattern matching
	 * capabilities.  See also documentation on the
	 * TP_VLAN_PRI_MAP register.)  Because this selective
	 * Offloading is happening in the chip, this allows
	 * non-Offloading and Offloading drivers to coexist.  For
	 * example, an Offloading Driver might be running in a
	 * Hypervisor while non-Offloading vNIC Drivers might be
	 * running in Virtual Machines.
	 *
	 * This particular example code demonstrates how one would
	 * selectively Offload incoming connections based on VLANs.
	 * We allow one VLAN to be designated as the "Offloading
	 * VLAN".  Ingress SYNs on this Offload VLAN will match the
	 * filter which we put into the Listen SCB and will result in
	 * Offloaded Connections on that VLAN.  Incoming SYNs on other
	 * VLANs will not match and will go through normal NIC
	 * processing.
	 *
	 * This is not production code since one would want a lot more
	 * infrastructure to allow a variety of filter specifications
	 * on a per-server basis.  But this demonstrates the
	 * fundamental mechanisms one would use to build such an
	 * infrastructure.
	 */
	if (vlan)
		return cxgb4_uld_server_vlan_create(dev, stid, sip, sport,
						    vlan, queue);

	skb = alloc_skb(sizeof(*req), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	adap = netdev2adap(dev);
	req = (struct cpl_pass_open_req *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ, stid));
	req->local_port = sport;
	req->peer_port = htons(0);
	req->local_ip = sip;
	req->peer_ip = htonl(0);
	chan = tx_chan ? *tx_chan : cxgb4_uld_rxq_to_chan(&adap->sge, queue);
	req->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	req->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				F_SYN_RSS_ENABLE | V_SYN_RSS_QUEUE(queue));
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_uld_server_create);

/**
 *	cxgb4_uld_server6_create_restricted - create a "restricted" IPv6 server
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IPv6 address to bind server to
 *	@sport: the server's TCP port
 *	@filter_value: the Compressed Filter value
 *	@filter_mask: the Compressed Filter mask
 *	@queue: queue to direct messages from this server to
 *
 *	Creates an IPv6 Server for the given TCP Port and IPv6 Local
 *	Address.  (The Local end of a listening socket are often referred to
 *	as the "Source" for odd historical reasons.)
 *
 *	The Server entry is rewritten with the specified Filter Value/Mask
 *	tuple in order to restrict the incoming SYNs to which the Server
 *	Entry will match (and thus respond).  This uses the extended "Filter
 *	Information" capabilities of Server Control Blocks (SCB).  (See
 *	"Classification and Filtering" in the Data Book for a description
 *	of Ingress Packet pattern matching capabilities.  See also
 *	documentation on the TP_VLAN_PRI_MAP register.)
 *
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
static int cxgb4_uld_server6_create_restricted(const struct net_device *dev,
					       unsigned int stid,
					       const struct in6_addr *sip,
					       __be16 sport,
					       __be64 filter_value,
					       __be64 filter_mask,
					       unsigned int queue)
{
	/* We need to program the extended Filter Information for our
	 * Listening Server.  Unfortunately the Passive Open Request CPL only
	 * lets us program the "value" portion of the extended Filter
	 * Information which is stored in the LE TCAM for the Listening Server
	 * ... and programs the "mask" portion to 0 ... which doesn't do
	 * anyone any good.  So we have to send in the Passive Open Request
	 * _and_ several Set LE CPLs to completely reprogram the LE TCAM line
	 * associated with the Listening Server (the LE TCAM doesn't support
	 * partial writes).
	 *
	 * Since each Set LE TCAM CPL can write 128 bits and since an IPv6 LE
	 * TCAM Entry is 324 bits for T4 (328 for T5 and later), we need 3 Set
	 * LE TCAM CPLs.  We accomplish this by wrapping all of the messages
	 * in a Firmware ULP TX Work Request with the "atomic" bit set ...
	 *
	 * Note that each ULP_TXPKT wrapped CPL needs to be an integral number
	 * of 16-byte units ...
	 *
	 * Also note that the embedded CPLs are _only_ the CPLs themselves and
	 * do _not_ include the firmware Work Request Headers.  This is very
	 * awkward given the data structure definitions in t4_msg.h so we have
	 * to play some games here ...
	 */
	struct pass_open_req6_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_pass_open_req6) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	struct set_le_req_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_set_le_req) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	/* The number of 128-bit Set LE TCAM CPLs needed for IPv6 */
	#define SETLE128_IPV6 DIV_ROUND_UP(264, 128) /* match LE_SZ_264 */
	struct atomic_pass_open_req6 {
		struct fw_ulptx_wr		ulptx_wr;
		struct pass_open_req6_ulp_txpkt	pass_open6;
		struct set_le_req_ulp_txpkt	set_le[SETLE128_IPV6];
	} *req;

	__be64 vbuf[2 * SETLE128_IPV6], mbuf[2 * SETLE128_IPV6], *vbufp, *mbufp;
	struct cpl_set_le_req *setler[SETLE128_IPV6];
	struct adapter *adap = netdev2adap(dev);
	unsigned int reqlen = sizeof(*req);
	struct cpl_pass_open_req6 *popenr;
	unsigned int chan, chip_ver;
	unsigned char *vbcp, *mbcp;
	struct sk_buff *skb;
	int offset, resid;
	int ret, i;

	chan = cxgb4_uld_rxq_to_chan(&adap->sge, queue);
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	/* XXX We currently don't know how to do this for T6 and later
	 * XXX which use apparently a different LE TCAM rewrite.  We
	 * XXX also can't handle Local IPv6 Addresses which are
	 * XXX anything other than the "any" address (all 0s) because,
	 * XXX for T5 and earlier, we need the Clip Table Index for
	 * XXX the IPv6 Address and the firmware Clip Table API
	 * XXX doesn't return that [yet] ...
	 */
	if (chip_ver > CHELSIO_T5 || ipv6_addr_type(sip) != IPV6_ADDR_ANY)
		return -EOPNOTSUPP;

	/* Allocate an skb large enough to hold our atomic request.
	 */
	skb = alloc_skb(reqlen, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	req = (struct atomic_pass_open_req6 *)__skb_put(skb, reqlen);
	memset(req, 0, reqlen);

	/* Initialize the Firmware ULP TX Work Request and all of the ULP
	 * TX Packet routing messages ...
	 */
	req->ulptx_wr.op_to_compl =
		cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) | F_FW_WR_ATOMIC);
	req->ulptx_wr.flowid_len16 =
		cpu_to_be32(V_FW_WR_LEN16(reqlen / 16));

	/* Everything is going to TP */
	req->pass_open6.ulptx.cmd_dest =
		cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
			    V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].ulptx.cmd_dest =
			cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
				    V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));

	/* Size of the ULP_TXPKT embedded CPL Passive Open Request */
	req->pass_open6.ulptx.len =
		cpu_to_be32(sizeof(struct pass_open_req6_ulp_txpkt) / 16);

	/* Size of the ULP_TXPKT embedded CPL Set LE Requests */
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].ulptx.len =
			cpu_to_be32(sizeof(struct set_le_req_ulp_txpkt) / 16);

	/* Fill in the Immediate Data information for the embedded CPLs */
	req->pass_open6.sc.cmd_more = cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].sc.cmd_more =
			cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	req->pass_open6.sc.len =
		cpu_to_be32(sizeof(struct cpl_pass_open_req6) -
			    sizeof(struct work_request_hdr));
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].sc.len =
			cpu_to_be32(sizeof(struct cpl_set_le_req) -
				    sizeof(struct work_request_hdr));

	/* Initialize the CPL Passive Open IPv6 Request ...  Note again the
	 * need to deal with the omitted firmware Work Request Header ...
	 * Also note that as a result we do _not_ need to do the standard
	 * INIT_TP_WR() to initialize the non-existent Work Request header.
	 */
	popenr = (struct cpl_pass_open_req6 *)
		(req->pass_open6.req - sizeof(struct work_request_hdr));
	OPCODE_TID(popenr) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ6, stid));
	popenr->local_port = sport;
	popenr->local_ip_hi = *(__be64 *)(sip->s6_addr);
	popenr->local_ip_lo = *(__be64 *)(sip->s6_addr + 8);
	popenr->peer_ip_hi = cpu_to_be64(0);
	popenr->peer_ip_lo = cpu_to_be64(0);
	popenr->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	popenr->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				   F_SYN_RSS_ENABLE |
				   V_SYN_RSS_QUEUE(queue) |
				   (filter_value << ((chip_ver == CHELSIO_T4)
						  ? S_FILT_INFO
						  : S_T5_FILT_INFO)));

	/* And now the difficult part: rewriting the entire LE TCAM line
	 * for the Listen Server ...  First we initialize everything
	 * other than the values and masks ...
	 */
	for (i = 0; i < SETLE128_IPV6; i++) {
		setler[i] = (struct cpl_set_le_req *)
			(req->set_le[i].req - sizeof(struct work_request_hdr));
		OPCODE_TID(setler[i]) =
			cpu_to_be32(MK_OPCODE_TID(CPL_SET_LE_REQ, stid << 2));
		setler[i]->reply_ctrl = cpu_to_be16(F_NO_REPLY);
		setler[i]->params =
			cpu_to_be16(V_LE_REQ_IP6(1) |
				    V_LE_CHAN(chan) |
				    V_LE_OFFSET(i) |
				    V_LE_MORE(i != SETLE128_IPV6 - 1) |
				    V_LE_REQSIZE((chip_ver <= CHELSIO_T5) ?
						 LE_SZ_264 : 0) |
				    V_LE_REQCMD(LE_CMD_WRITE));
	}

	/* Now we need to write the value/mask portions of the Set LE TCAM
	 * Requests.  For T5 there are 213 bits in the IPv6 LE TCAM entry
	 * which are addressed as follows (T4 has 4 fewer bits in the
	 * Compressed Filter):
	 *
	 *   LE TCAM Entry:
	 *   --------------
	 *    212                                                     0
	 *   +---------------------------------------------------------+
	 *   |Cmprsd|Local IPv6|          Foreign        |Local|Foreign|
	 *   |Filter|Clip Index|          IPv6           |Port |Port   |
	 *   +---------------------------------------------------------+
	 *      -40-    -13-             -128-            -16-    -16-
	 *
	 *   Set LE TCAM CPLs:
	 *   -----------------
	 *    212                128 127                              0
	 *   +---------------------------------------------------------+
	 *   |  1:  val/mask hi/lo  |         0:  val/mask hi/lo       |
	 *   +---------------------------------------------------------+
	 *                 -85-                      -128-
	 *
	 * The Set LE Request with Offset=0 covers the lowest 128 bits and the
	 * one with Offset=1 covers the remaining 85 bits (81 bits for T4).
	 * We need to replicate the TP logic for computing masks for the Local
	 * and Foreign IP Addresses and Ports which default to all 0s if the
	 * corresponding value is zero and all 1s if it's non-zero.
	 *
	 * Remember that when dealng with offsets within the Set LE Value/
	 * Mask High/Low fields, we're dealing with Big Endian objects.  So,
	 * for instance, the Local Port number is 4 bytes into the Low tuple
	 * of SetLEreq[0] ...
	 *
	 * The mapping of the various elements above is complex enough that
	 * it's worth our time to simply construct this in intermediate
	 * contiguous Value/Mask Buffers and then copy the individual 64-bit
	 * Big Endian values into the various Set LE Requeuest Value/Mask
	 * High/Low values.  The buffers contains Big-Endian values and are
	 * laid out in a Big-Endian format with 64-bit Word0 in *buf[5] and
	 * Word5 in *buf[0].
	 */
	memset(vbuf, 0, sizeof(vbuf));
	memset(mbuf,  0, sizeof(mbuf));

	/* Local TCP Port */
	if (sport) {
		offset = sizeof(vbuf) - 2 * 16 / 8;
		*(__be16 *)((char *)vbuf + offset) = sport;
		*(__be16 *)((char *)mbuf + offset) = (__force __be16)0xffff;
	}

	/* Local IPv6 Address */
	if (ipv6_addr_type(sip) != IPV6_ADDR_ANY) {
		/* XXX For T4/T5 we need the 13-bit Clip Table Index.
		 * XXX For T6 we apparently write the actual 128-bit Local
		 * XXX IPv6 Address and the CPL Set LE Request does the
		 * XXX Clip Table lookup (just like the CPL Passive Open
		 * XXX Request6).  It's a mess and we don't know how to
		 * XXX really handle this.  See the code above which
		 * XXX rejects calls to this function if we're working
		 * XXX with a T6 or the Local IPv6 Address is anything
		 * XXX other than the all-0 "any" address.
		 */
		BUG_ON(1);
	}

	/* Copy Filter Value/Mask tuple into Big-Endian Value/Mask Buffer.  We
	 * insert these a byte at a time so we completely cntrol the Big-
	 * Endian translation into the buffers.
	 */

	/* Offset of lowest order byte containing value/mask tuple */
	offset = sizeof(vbuf) - 2 * 16 / 8 - 128 / 8 - (13 + 8 - 1) / 8;
	resid = 2 * 8 - 13;
	vbcp = (char *)vbuf + offset;
	mbcp = (char *)mbuf + offset;

	/* Lowest order byte holds the lowest order few bits ... */
	*vbcp-- |= (unsigned char)(filter_value << (8 - resid));
	filter_value >>= (resid);
	*mbcp-- |= (unsigned char)(filter_mask << (8 - resid));
	filter_mask >>= (resid);

	/* ... and then the remaining bits get streamed in ... */
	while (filter_value || filter_mask) {
		*vbcp-- |= (unsigned char)filter_value;
		filter_value >>= 8;
		*mbcp-- |= (unsigned char)filter_mask;
		filter_mask >>= 8;
	}

	/* Copy the completed Value/Mask Buffers into the Set LE Requests.
	 */
	vbufp = vbuf + 2 * SETLE128_IPV6;
	mbufp = mbuf + 2 * SETLE128_IPV6;
	for (i = 0; i < SETLE128_IPV6; i++) {
		setler[i]->val_lo = *--vbufp;
		setler[i]->val_hi = *--vbufp;
		setler[i]->mask_lo = *--mbufp;
		setler[i]->mask_hi = *--mbufp;
	}

	/* Finally it's time to send the whole thing off ...
	 */
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
	#undef SETLE128_IPV6
}

/**
 *	cxgb4_uld_server6_vlan_create - create IPv6 server restricted to a VLAN
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IPv6 address to bind server to
 *	@sport: the server's TCP port
 *	@vlan: the VLAN to which to restrict the Offloaded Connections
 *	@queue: queue to which to direct messages from this server
 *
 *	This is mostly a convenience API front end to the far more general
 *	purpose cxgb4_uld_server6_create_restricted() API.  It also serves as a
 *	good example of how one would use the more general API.
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
static int cxgb4_uld_server6_vlan_create(const struct net_device *dev,
					 unsigned int stid,
					 const struct in6_addr *sip,
					 __be16 sport, __be16 vlan_id,
					 unsigned int queue)
{
	struct adapter *adapter = netdev2adap(dev);
	u64 filter_value, filter_mask;

	/* Compute the extended Filter Information we'll be attaching to the
	 * Listen Server in the LE TCAM.  Note that all of the fields that
	 * we set here need to be specified in the Firmware Configuration
	 * File "filterMask" specification.
	 *
	 * We also want to specify the TCP Protocol in order to avoid
	 * aliasing with UDP servers.
	 */
	if (cxgb4_uld_create_filter_info(dev,
					 &filter_value, &filter_mask,
					 /*fcoe*/ -1,
					 /*port*/ -1,
					 /*vnic*/ -1,
					 /*vlan_id*/ be16_to_cpu(vlan_id) & 0xfff,
					 /*vlan_pcp*/ -1,
					 /*vlan_dei*/ -1,
					 /*tos*/ -1,
					 /*protocol*/ IPPROTO_TCP,
					 /*ethertype*/ -1,
					 /*macmatch*/ -1,
					 /*matchtype*/ -1,
					 /*frag*/ -1) < 0) {
		dev_warn(adapter->pdev_dev,
			 "Can't differentiate Offloaded incoming connections based on VLAN + TCP; not set in TP_VLAN_PRI_MAP\n");
		return -EOPNOTSUPP;
	}

	return cxgb4_uld_server6_create_restricted(dev, stid, sip, sport,
						   filter_value, filter_mask,
						   queue);
}

int cxgb4_uld_server6_create(const struct net_device *dev, unsigned int stid,
			     const struct in6_addr *sip, __be16 sport,
			     __be16 vlan, unsigned int queue,
			     const u8 *tx_chan)
{
	struct cpl_pass_open_req6 *req;
	struct adapter *adap;
	struct sk_buff *skb;
	unsigned int chan;
	int ret;

	/* This code demonstrates how one would selectively Offload
	 * (TOE) certain incoming connections by using the extended
	 * "Filter Information" capabilities of Server Control Blocks
	 * (SCB).  (See "Classification and Filtering" in the T4 Data
	 * Book for a description of Ingress Packet pattern matching
	 * capabilities.  See also documentation on the
	 * TP_VLAN_PRI_MAP register.)  Because this selective
	 * Offloading is happening in the chip, this allows
	 * non-Offloading and Offloading drivers to coexist.  For
	 * example, an Offloading Driver might be running in a
	 * Hypervisor while non-Offloading vNIC Drivers might be
	 * running in Virtual Machines.
	 *
	 * This particular example code demonstrates how one would
	 * selectively Offload incoming connections based on VLANs.
	 * We allow one VLAN to be designated as the "Offloading
	 * VLAN".  Ingress SYNs on this Offload VLAN will match the
	 * filter which we put into the Listen SCB and will result in
	 * Offloaded Connections on that VLAN.  Incoming SYNs on other
	 * VLANs will not match and will go through normal NIC
	 * processing.
	 *
	 * This is not production code since one would want a lot more
	 * infrastructure to allow a variety of filter specifications
	 * on a per-server basis.  But this demonstrates the
	 * fundamental mechanisms one would use to build such an
	 * infrastructure.
	 */
	if (vlan)
		return cxgb4_uld_server6_vlan_create(dev, stid, sip, sport,
						     vlan, queue);

	skb = alloc_skb(sizeof(*req), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	adap = netdev2adap(dev);
	req = (struct cpl_pass_open_req6 *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ6, stid));
	req->local_port = sport;
	req->peer_port = htons(0);
	req->local_ip_hi = *(__be64 *)(sip->s6_addr);
	req->local_ip_lo = *(__be64 *)(sip->s6_addr + 8);
	req->peer_ip_hi = cpu_to_be64(0);
	req->peer_ip_lo = cpu_to_be64(0);
	chan = tx_chan ? *tx_chan : cxgb4_uld_rxq_to_chan(&adap->sge, queue);
	req->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	req->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				F_SYN_RSS_ENABLE | V_SYN_RSS_QUEUE(queue));
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_uld_server6_create);

int __cxgb4_uld_server_remove(const struct net_device *dev, unsigned int stid,
			      unsigned int queue, bool ipv6, struct sk_buff *skb)
{
	struct adapter *adap;
	struct cpl_close_listsvr_req *req;
	int ret;

	adap = netdev2adap(dev);

	req = (struct cpl_close_listsvr_req *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_CLOSE_LISTSRV_REQ, stid));
	req->reply_ctrl = htons(V_NO_REPLY(0) |
				(ipv6 ? V_LISTSVR_IPV6(1) : V_LISTSVR_IPV6(0)) |
				V_QUEUENO(queue));
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
}
EXPORT_SYMBOL(__cxgb4_uld_server_remove);

int cxgb4_uld_server_remove(const struct net_device *dev, unsigned int stid,
			    unsigned int queue, bool ipv6)
{
	struct sk_buff *skb;
	int ret;

	skb = alloc_skb(sizeof(struct cpl_close_listsvr_req), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	ret = __cxgb4_uld_server_remove(dev, stid, queue, ipv6, skb);
	return ret;
}
EXPORT_SYMBOL(cxgb4_uld_server_remove);

static void cxgb4_uld_queues_txq_shared_replace(struct net_device *dev,
						enum cxgb4_uld_type uld,
						u16 old_qid, u16 new_qid);

void cxgb4_uld_tid_qid_sel_update(struct net_device *dev, enum cxgb4_uld_type uld,
				  u32 tid, u16 *qid)
{
	struct cxgb4_uld_queue_tid_qid_group *qid_arr;
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_queue_map *map;
	u16 orig_qid = *qid;
	u8 group;

	map = cxgb4_uld_queues_txq_map_get(dev, CXGB4_ULD_TXQ_TYPE_SHARED,
					   uld == CXGB4_ULD_TYPE_CRYPTO ?
					   uld : CXGB4_ULD_TYPE_TOE);

	if (!map->tid_qid_map)
		return;

	group = (tid & adap->params.tid_qid_sel_mask) >>
		adap->params.tid_qid_sel_shift;
	qid_arr = &map->tid_qid_map->qid_arr[group];
	if (!qid_arr || !qid_arr->cur_entry)
		return;

	spin_lock_bh(&qid_arr->lock);
	*qid = qid_arr->cur_entry->ofldtxq->q.cntxt_id;
	qid_arr->cur_entry = list_next_entry_circular(qid_arr->cur_entry,
						      &qid_arr->list_head,
						      tid_qid_group);
	if (orig_qid != *qid)
		cxgb4_uld_queues_txq_shared_replace(dev, uld, orig_qid, *qid);
	spin_unlock_bh(&qid_arr->lock);
}
EXPORT_SYMBOL(cxgb4_uld_tid_qid_sel_update);

static void cxgb4_uld_tid_qid_sel_map_delete(struct net_device *dev,
					     struct cxgb4_uld_queue_map *map,
					     struct cxgb4_uld_txq *txq)
{
	struct cxgb4_uld_queue_tid_qid_group *qid_group;

	qid_group = &map->tid_qid_map->qid_arr[txq->tid_qid_group_id];
	spin_lock_bh(&qid_group->lock);
	list_del(&txq->tid_qid_group);
	if (qid_group->cur_entry == txq)
		qid_group->cur_entry =
			list_first_entry_or_null(&qid_group->list_head,
						 struct cxgb4_uld_txq,
						 tid_qid_group);
	spin_unlock_bh(&qid_group->lock);
}

static void cxgb4_uld_tid_qid_sel_map_insert(struct net_device *dev,
					     struct cxgb4_uld_queue_map *map,
					     struct cxgb4_uld_txq *txq)
{
	struct cxgb4_uld_queue_tid_qid_group *qid_group;

	qid_group = &map->tid_qid_map->qid_arr[txq->tid_qid_group_id];
	spin_lock_bh(&qid_group->lock);
	list_add_tail(&txq->tid_qid_group, &qid_group->list_head);
	if (!qid_group->cur_entry)
		qid_group->cur_entry = txq;
	spin_unlock_bh(&qid_group->lock);
}

static void cxgb4_uld_tid_qid_sel_map_free(struct adapter *adap,
					   struct cxgb4_uld_queue_map *map)
{
	kfree(map->tid_qid_map->qid_arr);
	kfree(map->tid_qid_map);
	map->tid_qid_map = NULL;
}

static int cxgb4_uld_tid_qid_sel_map_init(struct adapter *adap,
					  struct cxgb4_uld_queue_map *map)
{
	struct cxgb4_uld_queue_tid_qid_group *qid_arr;
	struct cxgb4_uld_queue_tid_qid_map *qid_map;
	u8 i, ngroups;

	ngroups = (adap->params.tid_qid_sel_mask >>
		   adap->params.tid_qid_sel_shift) + 1;

	qid_map = kzalloc(sizeof(*qid_map), GFP_KERNEL);
	if (!qid_map)
		return -ENOMEM;

	qid_arr = kcalloc(ngroups, sizeof(*qid_arr), GFP_KERNEL);
	if (!qid_arr) {
		kfree(qid_map);
		return -ENOMEM;
	}

	qid_map->ngroups = ngroups;
	for (i = 0; i < qid_map->ngroups; i++) {
		INIT_LIST_HEAD(&qid_arr[i].list_head);
		spin_lock_init(&qid_arr[i].lock);
	}

	qid_map->qid_arr = qid_arr;
	map->tid_qid_map = qid_map;
	return 0;
}

bool cxgb4_uld_sendpath_enabled(struct adapter *adap)
{
	return adap->params.tx_sendpath;
}

void cxgb4_uld_sendpath_qp_free(struct net_device *dev, unsigned int index)
{
	struct adapter *adap = netdev2adap(dev);

	ida_free(&adap->uld.res.sendpath_res.qp_ida,
		 index - adap->uld.vres.sendpath_qp.start);
}

int cxgb4_uld_sendpath_qp_alloc(struct net_device *dev)
{
	struct adapter *adap = netdev2adap(dev);
	int ret;

	ret = ida_alloc_max(&adap->uld.res.sendpath_res.qp_ida,
			    adap->uld.vres.sendpath_qp.size - 1,
			    GFP_NOWAIT);
	return ret < 0 ? ret : ret + adap->uld.vres.sendpath_qp.start;
}

struct cxgb4_uld_queue_map *cxgb4_uld_queues_txq_map_get(struct net_device *dev,
							 enum cxgb4_uld_txq_type qtype,
							 enum cxgb4_uld_type uld)
{
	struct port_info *pi = netdev2pinfo(dev);
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_queue_info *qinfo;

	qinfo = &adap->uld.qinfo[pi->port_id];

	if (qtype == CXGB4_ULD_TXQ_TYPE_SHARED) {
		if (uld == CXGB4_ULD_TYPE_CRYPTO)
			return &qinfo->cryptoqs.shared_txqs;

		return &qinfo->toeqs.shared_txqs;
	}

	switch (uld) {
	case CXGB4_ULD_TYPE_RDMA:
		return &qinfo->rdmaqs.txqs;
	case CXGB4_ULD_TYPE_ISCSI:
		return &qinfo->iscsiqs.txqs;
	case CXGB4_ULD_TYPE_ISCSIT:
		return &qinfo->iscsitqs.txqs;
	case CXGB4_ULD_TYPE_NVME_TCP_HOST:
		return &qinfo->nvmehqs.txqs;
	case CXGB4_ULD_TYPE_NVME_TCP_TARGET:
		return &qinfo->nvmetqs.txqs;
	case CXGB4_ULD_TYPE_CSTOR:
		return &qinfo->cstorqs.txqs;
	case CXGB4_ULD_TYPE_CRYPTO:
		return &qinfo->cryptoqs.txqs;
	case CXGB4_ULD_TYPE_CHTCP:
		return &qinfo->chtcpqs.txqs;
	default:
		break;
	}

	return &qinfo->toeqs.txqs;
}

static void cxgb4_uld_queues_txq_free_work(struct work_struct *work)
{
	struct cxgb4_uld_txq *txq;

	txq = container_of(work, struct cxgb4_uld_txq, task_txq_free);
	cxgb4_sge_uld_txq_free(txq->dev, txq);
	kfree(txq->ofldtxq);
	kfree(txq);
}

static void cxgb4_uld_queues_txq_free(struct net_device *dev,
				      struct cxgb4_uld_queue_map *map,
				      unsigned int index, u64 cookie)
{
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_txq *txq;

	xa_lock_bh(&map->queues);
	txq = xa_load(&map->queues, index);
	if (!txq)
		goto out_unlock;

	txq->users--;
	if (!txq->users) {
		txq->info.cookie = cookie;
		__xa_erase(&map->queues, index);
		map->num_queues--;
		if (map->tid_qid_map)
			cxgb4_uld_tid_qid_sel_map_delete(dev, map, txq);
		/* Defer the free because some ULDs try to free in
		 * interrupt context and the queue's scheduled tasklets
		 * can't be killed.
		 */
		cxgb4_work_queue(adap->workq, &txq->task_txq_free);
	}

out_unlock:
	xa_unlock_bh(&map->queues);
}

static struct cxgb4_uld_txq *cxgb4_uld_queues_txq_alloc(struct net_device *dev,
							enum cxgb4_uld_type uld,
							struct cxgb4_uld_queue_map *map,
							struct cxgb4_uld_txq_info *info,
							enum cxgb4_uld_txq_type qtype)
{
	struct sge_ofld_txq *ofldtxq;
	struct cxgb4_uld_txq *txq;
	int ret;

	txq = kzalloc(sizeof(*txq), GFP_NOWAIT);
	if (!txq)
		return NULL;

	ofldtxq = kzalloc(sizeof(*ofldtxq), GFP_NOWAIT);
	if (!ofldtxq)
		goto out_free_txq;

	memcpy(&txq->info, info, sizeof(txq->info));
	txq->ofldtxq = ofldtxq;
	txq->qtype = qtype;
	txq->uld = uld;

	if (txq->qtype == CXGB4_ULD_TXQ_TYPE_SENDPATH) {
		txq->ofldtxq->q.size = CXGB4_ULD_TXQ_SENDPATH_DESC_NUM;
	} else {
		txq->ofldtxq->q.size = CXGB4_ULD_TXQ_DESC_NUM;
		if (map->tid_qid_map)
			txq->tid_qid_group_id = info->uld_index %
						map->tid_qid_map->ngroups;
	}

	ret = cxgb4_sge_uld_txq_alloc(dev, txq);
	if (ret < 0)
		goto out_free_uld_txq;

	xa_lock_bh(&map->queues);
	ret = __xa_insert(&map->queues, txq->ofldtxq->q.cntxt_id, txq,
			  GFP_NOWAIT);
	if (ret < 0) {
		xa_unlock_bh(&map->queues);
		goto out_free_uld_txq_hw;
	}

	txq->ofldtxq->uldtxq = txq;
	txq->users = 1;
	txq->dev = dev;
	INIT_WORK(&txq->task_txq_free, cxgb4_uld_queues_txq_free_work);
	map->num_queues++;
	xa_unlock_bh(&map->queues);

	if (map->tid_qid_map)
		cxgb4_uld_tid_qid_sel_map_insert(dev, map, txq);

	return txq;

out_free_uld_txq_hw:
	cxgb4_sge_uld_txq_free(dev, txq);
out_free_uld_txq:
	kfree(txq->ofldtxq);
out_free_txq:
	kfree(txq);
	return NULL;
}

static void cxgb4_uld_queues_txq_shared_replace(struct net_device *dev,
						enum cxgb4_uld_type uld,
						u16 old_qid, u16 new_qid)
{
	struct cxgb4_uld_txq *old_txq, *new_txq;
	struct cxgb4_uld_queue_map *map;

	map = cxgb4_uld_queues_txq_map_get(dev, CXGB4_ULD_TXQ_TYPE_SHARED,
					   uld == CXGB4_ULD_TYPE_CRYPTO ?
					   uld : CXGB4_ULD_TYPE_TOE);
	xa_lock_bh(&map->queues);
	old_txq = xa_load(&map->queues, old_qid);
	if (!old_txq)
		goto out_unlock;

	new_txq = xa_load(&map->queues, new_qid);
	if (!new_txq)
		goto out_unlock;

	old_txq->users--;
	new_txq->users++;

out_unlock:
	xa_unlock_bh(&map->queues);
}

static void cxgb4_uld_queues_txq_shared_free(struct net_device *dev,
					     enum cxgb4_uld_type uld,
					     unsigned int index)
{
	struct cxgb4_uld_queue_map *map;

	map = cxgb4_uld_queues_txq_map_get(dev, CXGB4_ULD_TXQ_TYPE_SHARED,
					   uld == CXGB4_ULD_TYPE_CRYPTO ?
					   uld : CXGB4_ULD_TYPE_TOE);
	cxgb4_uld_queues_txq_free(dev, map, index, 0);
}

static struct cxgb4_uld_txq *cxgb4_uld_queues_txq_shared_alloc(struct net_device *dev,
							       enum cxgb4_uld_type uld,
							       struct cxgb4_uld_txq_info *info)
{
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	unsigned long index;
	u32 idx, i = 0;

	map = cxgb4_uld_queues_txq_map_get(dev, CXGB4_ULD_TXQ_TYPE_SHARED,
					   uld == CXGB4_ULD_TYPE_CRYPTO ?
					   uld : CXGB4_ULD_TYPE_TOE);
	idx = info->uld_index % map->max_queues;

	xa_lock_bh(&map->queues);
	xa_for_each(&map->queues, index, txq) {
		if (i == idx && txq) {
			txq->users++;
			break;
		}
		i++;
	}
	xa_unlock_bh(&map->queues);

	if (txq)
		return txq;

	info->iqid = adap->sge.fw_evtq.cntxt_id;
	return cxgb4_uld_queues_txq_alloc(dev, uld, map, info,
					  CXGB4_ULD_TXQ_TYPE_SHARED);
}

static struct cxgb4_uld_txq *cxgb4_uld_txq_get_from_egr_map(struct adapter *adap,
							    unsigned int index)
{
	struct sge_ofld_txq *ofldtxq;

	ofldtxq = cxgb4_sge_egr_map_get(&adap->sge.egr_map, index);
	if (!ofldtxq)
		return NULL;

	return ofldtxq->uldtxq;
}

void cxgb4_uld_txq_purge(struct net_device *dev, enum cxgb4_uld_type uld,
			 struct cxgb4_uld_txq_info *info)
{
	struct adapter *adap = netdev2adap(dev);
	struct sge_ofld_txq *ofldtxq;
	struct cxgb4_uld_txq *txq;

	txq = cxgb4_uld_txq_get_from_egr_map(adap, info->lld_index);
	if (!txq)
		return;

	ofldtxq = txq->ofldtxq;

	spin_lock_bh(&ofldtxq->sendq.lock);
	__skb_queue_purge(&ofldtxq->sendq);
	spin_unlock_bh(&ofldtxq->sendq.lock);
}
EXPORT_SYMBOL(cxgb4_uld_txq_purge);

void cxgb4_uld_txq_free(struct net_device *dev, enum cxgb4_uld_type uld,
			struct cxgb4_uld_txq_info *info)
{
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_txq *txq;

	txq = cxgb4_uld_txq_get_from_egr_map(adap, info->lld_index);
	if (!txq)
		return;

	if (txq->qtype == CXGB4_ULD_TXQ_TYPE_SENDPATH) {
		struct cxgb4_uld_queue_map *map;

		map = cxgb4_uld_queues_txq_map_get(dev,
						   CXGB4_ULD_TXQ_TYPE_SENDPATH,
						   uld);
		cxgb4_uld_queues_txq_free(dev, map, info->lld_index,
					  info->cookie);
	} else {
		cxgb4_uld_queues_txq_shared_free(dev, uld, info->lld_index);
	}
}
EXPORT_SYMBOL(cxgb4_uld_txq_free);

int cxgb4_uld_txq_alloc(struct net_device *dev, enum cxgb4_uld_type uld,
			struct cxgb4_uld_txq_info *info)
{
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_txq *txq = NULL;

	if (info->flags & CXGB4_ULD_TXQ_INFO_FLAG_SENDPATH) {
		struct cxgb4_uld_queue_map *map;

		if (!cxgb4_uld_sendpath_enabled(adap))
			return -EOPNOTSUPP;

		map = cxgb4_uld_queues_txq_map_get(dev,
						   CXGB4_ULD_TXQ_TYPE_SENDPATH,
						   uld);
		txq = cxgb4_uld_queues_txq_alloc(dev, uld, map, info,
						 CXGB4_ULD_TXQ_TYPE_SENDPATH);
	} else {
		txq = cxgb4_uld_queues_txq_shared_alloc(dev, uld, info);
	}

	if (!txq)
		return -ENOMEM;

	info->lld_index = txq->ofldtxq->q.cntxt_id;
	info->size = txq->ofldtxq->q.size;
	return 0;
}
EXPORT_SYMBOL(cxgb4_uld_txq_alloc);

int cxgb4_uld_xmit(struct net_device *dev, struct sk_buff *skb)
{
	u16 index = cxgb4_uld_skb_get_queue(skb);
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_txq *txq;

	if (unlikely(cxgb4_sge_is_ctrl_pkt(skb)))
		return cxgb4_sge_xmit_ctrl(dev, skb);

	txq = cxgb4_uld_txq_get_from_egr_map(adap, index);
	if (unlikely(!txq))
		goto out_drop;

	return cxgb4_sge_uld_xmit_data(txq->ofldtxq, skb);

out_drop:
	dev_kfree_skb_any(skb);
	return NET_XMIT_DROP;
}
EXPORT_SYMBOL(cxgb4_uld_xmit);

int cxgb4_uld_xmit_direct(struct net_device *dev, bool control,
			  unsigned int index, const void *data,
			  unsigned int len)
{
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_txq *txq;

	if (unlikely(control))
		return cxgb4_sge_xmit_ctrl_direct(dev, index, data, len);

	txq = cxgb4_uld_txq_get_from_egr_map(adap, index);
	if (unlikely(!txq))
		return -EINVAL;

	return cxgb4_sge_uld_xmit_data_direct(txq->ofldtxq, data, len);
}
EXPORT_SYMBOL(cxgb4_uld_xmit_direct);

void cxgb4_uld_txq_cidx_update(struct net_device *dev, u32 index, u16 cidx)
{
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_txq *txq;

	txq = cxgb4_uld_txq_get_from_egr_map(adap, index);
	if (unlikely(!txq))
		return;

	WRITE_ONCE(txq->ofldtxq->q.stat->cidx, cpu_to_be16(cidx));
	cxgb4_sge_uld_xmit_check_and_restart(txq->ofldtxq);
}
EXPORT_SYMBOL(cxgb4_uld_txq_cidx_update);

bool cxgb4_uld_txq_full(struct net_device *dev, unsigned int index)
{
	struct adapter *adap = netdev2adap(dev);
	struct cxgb4_uld_txq *txq;

	txq = cxgb4_uld_txq_get_from_egr_map(adap, index);
	if (unlikely(!txq))
		return false;

	return cxgb4_sge_uld_txq_full(txq->ofldtxq);
}
EXPORT_SYMBOL(cxgb4_uld_txq_full);

void cxgb4_uld_txq_all_stop(struct adapter *adap)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	unsigned long index;
	u8 uld, q, port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		for (uld = 0; uld < CXGB4_ULD_TYPE_MAX; uld++) {
			for (q = 0; q < CXGB4_ULD_TXQ_TYPE_MAX; q++) {
				map = cxgb4_uld_queues_txq_map_get(dev, q, uld);
				xa_for_each(&map->queues, index, txq)
					tasklet_kill(&txq->ofldtxq->qresume_tsk);
			}
		}
	}
}

void cxgb4_uld_txq_all_start(struct adapter *adap)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	unsigned long index;
	u8 uld, q, port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		for (uld = 0; uld < CXGB4_ULD_TYPE_MAX; uld++) {
			for (q = 0; q < CXGB4_ULD_TXQ_TYPE_MAX; q++) {
				map = cxgb4_uld_queues_txq_map_get(dev, q, uld);
				xa_for_each(&map->queues, index, txq)
					tasklet_init(&txq->ofldtxq->qresume_tsk,
						     cxgb4_sge_uld_xmit_restart,
						     (unsigned long)txq->ofldtxq);
			}
		}
	}
}

void cxgb4_uld_txq_all_disable_dbs(struct adapter *adap)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	unsigned long index;
	u8 uld, q, port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		for (uld = 0; uld < CXGB4_ULD_TYPE_MAX; uld++) {
			for (q = 0; q < CXGB4_ULD_TXQ_TYPE_MAX; q++) {
				map = cxgb4_uld_queues_txq_map_get(dev, q, uld);
				xa_for_each(&map->queues, index, txq)
					cxgb4_sge_txq_disable_db(&txq->ofldtxq->q);
			}
		}
	}
}

void cxgb4_uld_txq_all_enable_dbs(struct adapter *adap)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	unsigned long index;
	u8 uld, q, port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		for (uld = 0; uld < CXGB4_ULD_TYPE_MAX; uld++) {
			for (q = 0; q < CXGB4_ULD_TXQ_TYPE_MAX; q++) {
				map = cxgb4_uld_queues_txq_map_get(dev, q, uld);
				xa_for_each(&map->queues, index, txq)
					cxgb4_sge_txq_enable_db(adap,
								&txq->ofldtxq->q);
			}
		}
	}
}

void cxgb4_uld_txq_all_recover(struct adapter *adap)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	unsigned long index;
	u8 uld, q, port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		for (uld = 0; uld < CXGB4_ULD_TYPE_MAX; uld++) {
			for (q = 0; q < CXGB4_ULD_TXQ_TYPE_MAX; q++) {
				map = cxgb4_uld_queues_txq_map_get(dev, q, uld);
				xa_for_each(&map->queues, index, txq)
					cxgb4_sge_txq_sync_pidx_locked(dev,
								       &txq->ofldtxq->q);
			}
		}
	}
}

int cxgb4_uld_txq_sync_pidx(struct net_device *dev, u16 qid, u16 pidx, u16 size)
{
	return cxgb4_sge_txq_sync_pidx(dev, qid, pidx, size);
}
EXPORT_SYMBOL(cxgb4_uld_txq_sync_pidx);

struct cxgb4_uld_txq *cxgb4_uld_txq_get_by_qid(struct net_device *dev,
					       enum cxgb4_uld_type uld,
					       u32 qid)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	unsigned long index;
	u8 q;

	for (q = 0; q < CXGB4_ULD_TXQ_TYPE_MAX; q++) {
		map = cxgb4_uld_queues_txq_map_get(dev, q, uld);
		xa_for_each(&map->queues, index, txq)
			if (txq->ofldtxq->q.cntxt_id == qid)
				return txq;
	}

	return NULL;
}

int cxgb4_uld_txq_get_desc(struct adapter *adap, enum cxgb4_uld_type uld,
			   u32 qid, void *data, u32 off, u32 len)
{
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	u8 port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		txq = cxgb4_uld_txq_get_by_qid(dev, uld, qid);
		if (!txq)
			continue;

		if (off <= txq->ofldtxq->q.size) {
			memcpy(data, &txq->ofldtxq->q.desc[off], len);
			return 0;
		}
	}

	return -EINVAL;
}

void cxgb4_uld_txq_free_shared(struct adapter *adap, enum cxgb4_uld_type uld)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	unsigned long index;
	u8 port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		map = cxgb4_uld_queues_txq_map_get(dev,
						   CXGB4_ULD_TXQ_TYPE_SHARED,
						   uld == CXGB4_ULD_TYPE_CRYPTO ?
						   uld : CXGB4_ULD_TYPE_TOE);
		xa_for_each(&map->queues, index, txq)
			cxgb4_uld_queues_txq_shared_free(dev, uld, index);
	}
}

void cxgb4_uld_txq_alloc_shared(struct adapter *adap, enum cxgb4_uld_type uld)
{
	struct cxgb4_uld_queue_map *map;
	struct cxgb4_uld_txq_info info;
	struct cxgb4_uld_txq *txq;
	struct net_device *dev;
	u8 i, port;

	for_each_port(adap, port) {
		dev = adap->port[port];
		map = cxgb4_uld_queues_txq_map_get(dev,
						   CXGB4_ULD_TXQ_TYPE_SHARED,
						   uld == CXGB4_ULD_TYPE_CRYPTO ?
						   uld : CXGB4_ULD_TYPE_TOE);
		for (i = 0; i < map->max_queues; i++) {
			info.uld_index = i;
			txq = cxgb4_uld_queues_txq_shared_alloc(dev, uld,
								&info);
			if (!txq)
				dev_warn(adap->pdev_dev,
					 "Failed to create ULD(%u) Txq: %u. Continuing...\n",
					 uld, i);
		}
	}
}

static void cxgb4_uld_queues_txqs_cleanup(struct adapter *adap,
					  enum cxgb4_uld_type uld)
{
	struct cxgb4_uld_queue_map *map;
	struct net_device *dev;
	u8 qtype, port;

	for (qtype = 0; qtype < CXGB4_ULD_TXQ_TYPE_MAX; qtype++) {
		for_each_port(adap, port) {
			dev = adap->port[port];
			map = cxgb4_uld_queues_txq_map_get(dev, qtype, uld);
			if (!map->max_queues)
				continue;

			if (map->tid_qid_map)
				cxgb4_uld_tid_qid_sel_map_free(adap, map);

			xa_destroy(&map->queues);
			map->max_queues = 0;
			map->num_queues = 0;
		}
	}
}

static void cxgb4_uld_queues_txqs_init(struct adapter *adap,
				       enum cxgb4_uld_type uld)
{
	struct cxgb4_uld_queue_map *map;
	struct net_device *dev;
	u8 qtype, port;
	u32 num_txqs;

	for (qtype = 0; qtype < CXGB4_ULD_TXQ_TYPE_MAX; qtype++) {
		switch (qtype) {
		case CXGB4_ULD_TXQ_TYPE_SHARED:
			if (uld == CXGB4_ULD_TYPE_TOE)
				num_txqs = adap->sge.ofldqsets /
					   adap->params.nports;
			else if (uld == CXGB4_ULD_TYPE_CRYPTO)
				num_txqs = adap->sge.ncryptoq /
					   adap->params.nports;
			else
				num_txqs = 0;
			break;
		case CXGB4_ULD_TXQ_TYPE_SENDPATH:
			if (cxgb4_uld_sendpath_enabled(adap))
				num_txqs = adap->uld.vres.sendpath_qp.size;
			else
				num_txqs = 0;
			break;
		default:
			num_txqs = 0;
			break;
		}

		for_each_port(adap, port) {
			dev = adap->port[port];
			map = cxgb4_uld_queues_txq_map_get(dev, qtype, uld);
			if (map->max_queues)
				continue;

			xa_init_flags(&map->queues, XA_FLAGS_LOCK_BH);
			map->max_queues = num_txqs;
			map->num_queues = 0;
			if (adap->params.tid_qid_sel_mask &&
			    qtype == CXGB4_ULD_TXQ_TYPE_SHARED) {
				int ret;

				ret = cxgb4_uld_tid_qid_sel_map_init(adap, map);
				if (ret < 0)
					dev_warn(adap->pdev_dev,
						 "FAIL - creating tid_qid map for ULD %u. ret: %d. Continuing...\n",
						 qtype, ret);
			}
		}
	}
}

void cxgb4_uld_queues_cleanup(struct adapter *adap)
{
	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_TOE)) {
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_TOE);
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_CHTCP);
	}

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_RDMA))
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_RDMA);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_ISCSI)) {
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_ISCSI);
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_ISCSIT);
	}

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST))
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET))
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CSTOR))
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_CSTOR);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CRYPTO))
		cxgb4_uld_queues_txqs_cleanup(adap, CXGB4_ULD_TYPE_CRYPTO);
}

void cxgb4_uld_queues_init(struct adapter *adap)
{
	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_TOE)) {
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_TOE);
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_CHTCP);
	}

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_RDMA))
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_RDMA);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_ISCSI)) {
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_ISCSI);
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_ISCSIT);
	}

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST))
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET))
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CSTOR))
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_CSTOR);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CRYPTO))
		cxgb4_uld_queues_txqs_init(adap, CXGB4_ULD_TYPE_CRYPTO);
}

bool cxgb4_uld_crypto_supported_ulp_tls(const struct net_device *dev)
{
	struct adapter *adap = netdev2adap(dev);

	return adap && (adap->params.ulp_crypto & ULP_CRYPTO_INLINE_TLS);
}
EXPORT_SYMBOL(cxgb4_uld_crypto_supported_ulp_tls);

bool cxgb4_uld_supported_any(struct adapter *adap)
{
	return !!adap->params.offload;
}

bool cxgb4_uld_supported(struct adapter *adap, enum cxgb4_uld_type uld)
{
	return !!(adap->params.offload & BIT(uld));
}

static void cxgb4_uld_enable(struct adapter *adap, enum cxgb4_uld_type uld)
{
	adap->params.offload |= BIT(uld);
}

static void cxgb4_uld_disable(struct adapter *adap, enum cxgb4_uld_type uld)
{
	adap->params.offload &= ~BIT(uld);
}

const char *cxgb4_uld_type_to_name(enum cxgb4_uld_type uld)
{
	switch (uld) {
	case CXGB4_ULD_TYPE_RDMA:
		return "rdma";
	case CXGB4_ULD_TYPE_ISCSI:
		return "iscsi";
	case CXGB4_ULD_TYPE_ISCSIT:
		return "iscsit";
	case CXGB4_ULD_TYPE_NVME_TCP_HOST:
		return "nvmeh";
	case CXGB4_ULD_TYPE_NVME_TCP_TARGET:
		return "nvmet";
	case CXGB4_ULD_TYPE_CSTOR:
		return "cstor";
	case CXGB4_ULD_TYPE_CRYPTO:
		return "crypto";
	case CXGB4_ULD_TYPE_TOE:
		return "toe";
	case CXGB4_ULD_TYPE_CHTCP:
		return "chtcp";
	case CXGB4_ULD_TYPE_IPSEC:
		return "ipsec";
	default:
		break;
	}

	return NULL;
}

static void cxgb4_uld_cleanup_toe(struct adapter *adap)
{
#ifdef CONFIG_PO_FCOE
	cxgb_fcoe_exit_ddp(adap);
#endif /* CONFIG_PO_FCOE */
	adap->params.ofldq_wr_cred = 0;
	memset(&adap->uld.vres.ddp, 0, sizeof(adap->uld.vres.ddp));
	cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_TOE);
	cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_CHTCP);
}

static int cxgb4_uld_init_toe(struct adapter *adap,
			      const struct fw_caps_config_cmd *caps_cmd)
{
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	u32 params[7], val[7];
	int ret;

	/* Query offload-related parameters */
	params[0] = FW_PARAM_PFVF(TDDP_START);
	params[1] = FW_PARAM_PFVF(TDDP_END);
	params[2] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 3,	params, val);
	if (ret < 0)
		return ret;
	adap->uld.vres.ddp.start = val[0];
	adap->uld.vres.ddp.size = val[1] - val[0] + 1;
	adap->params.ofldq_wr_cred = val[2];

	if (caps_cmd->toecaps & cpu_to_be16(FW_CAPS_CONFIG_TOE_SENDPATH)) {
		params[0] = FW_PARAM_PFVF(SQRQ_START);
		params[1] = FW_PARAM_PFVF(SQRQ_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (ret < 0) {
			adap->params.tx_sendpath = false;
		} else {
			adap->params.tx_sendpath = true;
			adap->uld.vres.sendpath_qp.start = val[0];
			adap->uld.vres.sendpath_qp.size = val[1] - val[0] + 1;
		}
	}

#ifdef CONFIG_PO_FCOE
	if (ntohs(caps_cmd->fcoecaps) & FW_CAPS_CONFIG_POFCOE_TARGET)
		cxgb_fcoe_init_ddp(adap);
#endif /* CONFIG_PO_FCOE */

	if (chip_ver >= CHELSIO_T7 && adap->params.num_up_cores > 1) {
		params[0] = FW_PARAM_DEV(TID_QID_SEL_MASK);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
				      params, val);
		adap->params.tid_qid_sel_mask = (ret == 0 ? val[0] : 0);
		if (adap->params.tid_qid_sel_mask)
			adap->params.tid_qid_sel_shift =
				ffs(adap->params.tid_qid_sel_mask) - 1;
		else
			adap->params.tid_qid_sel_shift = 0;
	}

	cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_TOE);
	cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_CHTCP);
	return 0;
}

static void cxgb4_uld_cleanup_rdma(struct adapter *adap)
{
	if (adap->uld.oc_mw_kva) {
		iounmap(adap->uld.oc_mw_kva);
		adap->uld.oc_mw_kva = 0;
		adap->uld.oc_mw_pa = 0;
		cxgb4_ocqp_pool_destroy(adap);
	}

	adap->params.write_cmpl_support = 0;
	adap->params.write_w_imm_support = 0;
	adap->params.max_ird_adapter = 0;
	adap->params.max_ordird_qp = 0;
	cxgb4_srq_cleanup(adap);
	memset(&adap->uld.vres.ocq, 0, sizeof(adap->uld.vres.ocq));
	memset(&adap->uld.vres.cq, 0, sizeof(adap->uld.vres.cq));
	memset(&adap->uld.vres.qp, 0, sizeof(adap->uld.vres.qp));
	memset(&adap->uld.vres.pbl, 0, sizeof(adap->uld.vres.pbl));
	memset(&adap->uld.vres.rq, 0, sizeof(adap->uld.vres.rq));
	memset(&adap->uld.vres.stag, 0, sizeof(adap->uld.vres.stag));
	memset(&adap->uld.vres.nvme_pbl, 0, sizeof(adap->uld.vres.nvme_pbl));
	memset(&adap->uld.vres.nvme_stag, 0, sizeof(adap->uld.vres.nvme_stag));
	cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_RDMA);

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) {
		cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST);
		cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET);
		cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_CSTOR);
	}
}

static int cxgb4_uld_init_rdma(struct adapter *adap)
{
	u32 params[7], val[7];
	int ret;
	u32 size;

	params[0] = FW_PARAM_PFVF(STAG_START);
	params[1] = FW_PARAM_PFVF(STAG_END);
	params[2] = FW_PARAM_PFVF(RQ_START);
	params[3] = FW_PARAM_PFVF(RQ_END);
	params[4] = FW_PARAM_PFVF(PBL_START);
	params[5] = FW_PARAM_PFVF(PBL_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6, params, val);
	if (ret < 0)
		return ret;

	size = val[1] - val[0] + 1;
	adap->uld.vres.stag.start = val[0];
	adap->uld.vres.stag.size = size / 2;
	adap->uld.vres.nvme_stag.start = val[0] + (size / 2);
	adap->uld.vres.nvme_stag.size = size / 2;

	adap->uld.vres.rq.start = val[2];
	adap->uld.vres.rq.size = val[3] - val[2] + 1;

	size = val[5] - val[4] + 1;
	adap->uld.vres.pbl.start = val[4];
	adap->uld.vres.pbl.size = size / 2;
	adap->uld.vres.nvme_pbl.start = val[4] + (size / 2);
	adap->uld.vres.nvme_pbl.size = size / 2;

	params[0] = FW_PARAM_PFVF(SQRQ_START);
	params[1] = FW_PARAM_PFVF(SQRQ_END);
	params[2] = FW_PARAM_PFVF(CQ_START);
	params[3] = FW_PARAM_PFVF(CQ_END);
	params[4] = FW_PARAM_PFVF(OCQ_START);
	params[5] = FW_PARAM_PFVF(OCQ_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6, params, val);
	if (ret < 0)
		goto out_err;
	adap->uld.vres.qp.start = val[0];
	adap->uld.vres.qp.size = val[1] - val[0] + 1;
	adap->uld.vres.cq.start = val[2];
	adap->uld.vres.cq.size = val[3] - val[2] + 1;
	adap->uld.vres.ocq.start = val[4];
	adap->uld.vres.ocq.size = val[5] - val[4] + 1;

	params[0] = FW_PARAM_PFVF(SRQ_START);
	params[1] = FW_PARAM_PFVF(SRQ_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (!ret) {
		adap->uld.vres.srq.start = val[0];
		adap->uld.vres.srq.size = val[1] - val[0] + 1;
		if (adap->uld.vres.srq.size) {
			ret = cxgb4_srq_init(adap, adap->uld.vres.srq.size);
			if (ret < 0) {
				dev_warn(adap->pdev_dev,
					 "could not allocate SRQ, continuing\n");
				ret = 0;
			}
		}
	}

	params[0] = FW_PARAM_DEV(MAXORDIRD_QP);
	params[1] = FW_PARAM_DEV(MAXIRD_ADAPTER);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (ret < 0) {
		adap->params.max_ordird_qp = 8;
		adap->params.max_ird_adapter = 32 * adap->tidinfo.tids.size;
		ret = 0;
	} else {
		adap->params.max_ordird_qp = val[0];
		adap->params.max_ird_adapter = val[1];
	}
	dev_info(adap->pdev_dev, "max_ordird_qp %d max_ird_adapter %d\n",
		 adap->params.max_ordird_qp, adap->params.max_ird_adapter);

	/* Enable WRITE_WITH_IMMEDIATE if FW supports it */
	params[0] = FW_PARAM_DEV(RDMA_WRITE_WITH_IMM);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, params, val);
	if (!ret && val[0] != 0)
		adap->params.write_w_imm_support = 1;

	/* Enable WRITE_CMPL if FW supports it */
	params[0] = FW_PARAM_DEV(RI_WRITE_CMPL_WR);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, params, val);
	if (!ret && val[0] != 0)
		adap->params.write_cmpl_support = 1;

	/* On-chip queues are available only on T4 adapters
	 */
	if (CHELSIO_CHIP_VERSION(adap->params.chip) < CHELSIO_T5) {
		ret = cxgb4_ocqp_pool_create(adap);
		if (ret) {
			dev_warn(adap->pdev_dev,
				 "Could not create OCQP memory pool, ret: %d. Continuing...",
				 ret);
			ret = 0;
		} else {
			adap->uld.oc_mw_pa = pci_resource_start(cxgb4_pci_dev(adap), 2) +
					     (pci_resource_len(cxgb4_pci_dev(adap), 2) -
					      roundup_pow_of_two(adap->uld.vres.ocq.size));
			adap->uld.oc_mw_kva = ioremap_wc(adap->uld.oc_mw_pa,
							 adap->uld.vres.ocq.size);
		}
	}

	cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_RDMA);

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7) {
		cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST);
		cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET);
		cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_CSTOR);
	}

	return 0;

out_err:
	cxgb4_uld_cleanup_rdma(adap);
	return ret;
}

static void cxgb4_uld_cleanup_iscsi(struct adapter *adap)
{
	memset(&adap->uld.vres.ppod_edram, 0, sizeof(adap->uld.vres.ppod_edram));
	adap->params.ulp_t10dif &= ~ULP_T10DIF_ISCSI;
	memset(&adap->uld.vres.iscsi, 0, sizeof(adap->uld.vres.iscsi));
	cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_ISCSI);
	cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_ISCSIT);
}

static int cxgb4_uld_init_iscsi(struct adapter *adap,
				const struct fw_caps_config_cmd *caps_cmd)
{
	u32 params[7], val[7];
	int ret;

	params[0] = FW_PARAM_PFVF(ISCSI_START);
	params[1] = FW_PARAM_PFVF(ISCSI_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (ret < 0)
		return ret;
	adap->uld.vres.iscsi.start = val[0];
	adap->uld.vres.iscsi.size = val[1] - val[0] + 1;
	if  (ntohs(caps_cmd->iscsicaps) & FW_CAPS_CONFIG_ISCSI_T10DIF)
		adap->params.ulp_t10dif |= ULP_T10DIF_ISCSI;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T6) {
		params[0] = FW_PARAM_PFVF(PPOD_EDRAM_START);
		params[1] = FW_PARAM_PFVF(PPOD_EDRAM_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (!ret) {
			adap->uld.vres.ppod_edram.start = val[0];
			adap->uld.vres.ppod_edram.size = val[1] - val[0] + 1;
			dev_info(adap->pdev_dev,
				 "iscsi_caps: ppod edram start 0x%x end 0x%x size 0x%x\n",
				 val[0], val[1],
				 adap->uld.vres.ppod_edram.size);
		}
	}

	cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_ISCSI);
	cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_ISCSIT);
	return 0;
}

static void cxgb4_uld_cleanup_crypto(struct adapter *adap)
{
	adap->params.ulp_crypto = 0;
	memset(&adap->uld.vres.key, 0, sizeof(adap->uld.vres.key));
	adap->uld.vres.ncrypto_fc = 0;
	cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_CRYPTO);
}

static int cxgb4_uld_init_crypto(struct adapter *adap,
				 const struct fw_caps_config_cmd *caps_cmd)
{
	u16 cryptocaps = ntohs(caps_cmd->cryptocaps);
	u32 params[7], val[7];
	unsigned int chip_ver;
	int ret;

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	if (cryptocaps & FW_CAPS_CONFIG_CRYPTO_LOOKASIDE) {
		params[0] = FW_PARAM_PFVF(NCRYPTO_LOOKASIDE);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
				      params, val);
		if (ret < 0) {
			if (ret != -EINVAL)
				return ret;
		} else {
			adap->uld.vres.ncrypto_fc = val[0];
		}
	}

	if (cryptocaps & FW_CAPS_CONFIG_TLSKEYS) {
		params[0] = FW_PARAM_PFVF(TLS_START);
		params[1] = FW_PARAM_PFVF(TLS_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (ret < 0)
			goto out_err;
		adap->uld.vres.key.start = val[0];
		adap->uld.vres.key.size = val[1] - val[0] + 1;
		dev_info(adap->pdev_dev, "crypto_caps: key start:%x end:%x\n",
			 val[0], val[1]);
	}

#if IS_ENABLED(CONFIG_CHELSIO_T4_IPSEC_INLINE)
	if (chip_ver == CHELSIO_T7 && cryptocaps & ULP_CRYPTO_INLINE_IPSEC) {
		params[0] = FW_PARAM_PFVF(NIPSEC_TUNNEL);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
				      params, val);
		if (ret < 0)
			goto out_err;
		adap->uld.vres.ipsec_max_nic_tunnel = val[0];

		params[0] = FW_PARAM_PFVF(NIPSEC_TRANSPORT);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
				      params, val);
		if (ret < 0)
			goto out_err;
		adap->uld.vres.ipsec_max_nic_transport = val[0];
	}

	if (chip_ver == CHELSIO_T7 && cryptocaps & ULP_CRYPTO_OFLD_OVER_IPSEC_INLINE) {
		params[0] = FW_PARAM_PFVF(OFLD_NIPSEC_TUNNEL);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
				      params, val);
		if (ret < 0)
			goto out_err;
		adap->uld.vres.ipsec_max_ofld_conn = val[0];
	}
#endif /* CONFIG_CHELSIO_T4_IPSEC_INLINE */

	adap->params.ulp_crypto = cryptocaps;

	cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_CRYPTO);
	return 0;

out_err:
	cxgb4_uld_cleanup_crypto(adap);
	return ret;
}

static void cxgb4_uld_tweak_resources_sendpath(struct adapter *adap)
{
	u32 eq_qpp, npages;

	eq_qpp = t4_sge_get_qpp(adap, A_SGE_EGRESS_QUEUES_PER_PAGE_PF);
	if (!eq_qpp) {
		adap->params.tx_sendpath = false;
		memset(&adap->uld.vres.sendpath_qp, 0,
		       sizeof(adap->uld.vres.sendpath_qp));
		return;
	}

	/* Reserve 1/3 of the pages to SENDPATH */
	npages = (adap->uld.vres.qp.size / (1 << eq_qpp)) / 3;
	adap->uld.vres.sendpath_qp.size = npages * (1 << eq_qpp);
	adap->uld.vres.qp.size -= adap->uld.vres.sendpath_qp.size;
	adap->uld.vres.cq.size -= adap->uld.vres.sendpath_qp.size;
	adap->uld.vres.sendpath_qp.start = adap->uld.vres.qp.start +
					   adap->uld.vres.qp.size;
}

static void cxgb4_uld_tweak_resources(struct adapter *adap)
{
	if (cxgb4_uld_sendpath_enabled(adap) &&
	    cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_RDMA))
		cxgb4_uld_tweak_resources_sendpath(adap);
}

static void cxgb4_uld_cleanup_resources_sendpath(struct adapter *adap)
{
	ida_destroy(&adap->uld.res.sendpath_res.qp_ida);
}

static void cxgb4_uld_cleanup_resources(struct adapter *adap)
{
	if (cxgb4_uld_sendpath_enabled(adap))
		cxgb4_uld_cleanup_resources_sendpath(adap);
}

static void cxgb4_uld_init_resources_sendpath(struct adapter *adap)
{
	ida_init(&adap->uld.res.sendpath_res.qp_ida);
}

static void cxgb4_uld_init_resources(struct adapter *adap)
{
	if (cxgb4_uld_sendpath_enabled(adap))
		cxgb4_uld_init_resources_sendpath(adap);
}

void cxgb4_uld_cleanup(struct adapter *adap)
{
	cxgb4_uld_cleanup_resources(adap);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_TOE))
		cxgb4_uld_cleanup_toe(adap);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_RDMA))
		cxgb4_uld_cleanup_rdma(adap);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_ISCSI))
		cxgb4_uld_cleanup_iscsi(adap);

	if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_CRYPTO))
		cxgb4_uld_cleanup_crypto(adap);

	mutex_destroy(&adap->uld.uld_mutex);
}

int cxgb4_uld_init(struct adapter *adap,
		   const struct fw_caps_config_cmd *caps_cmd)
{
	int ret;

	mutex_init(&adap->uld.uld_mutex);

	/* Disable offload when in kdump kernel */
	if (is_kdump_kernel()) {
		adap->params.offload = 0;
		return 0;
	}

	if (caps_cmd->toecaps) {
		ret = cxgb4_uld_init_toe(adap, caps_cmd);
		if (ret < 0) {
			dev_err(adap->pdev_dev,
				"Could not initialize TOE, ret: %d\n", ret);
			goto out_err;
		}
	}

	if (caps_cmd->rdmacaps) {
		ret = cxgb4_uld_init_rdma(adap);
		if (ret < 0) {
			dev_warn(adap->pdev_dev,
				 "Could not initialize RDMA, ret: %d. Continuing...\n",
				 ret);
			ret = 0;
		}
	}

	if (caps_cmd->iscsicaps) {
		ret = cxgb4_uld_init_iscsi(adap, caps_cmd);
		if (ret < 0) {
			dev_warn(adap->pdev_dev,
				 "Could not initialize iSCSI, ret: %d. Continuing...\n",
				 ret);
			ret = 0;
		}
	}

	if (caps_cmd->cryptocaps) {
		ret = cxgb4_uld_init_crypto(adap, caps_cmd);
		if (ret < 0) {
			dev_warn(adap->pdev_dev,
				 "Could not initialize CRYPTO, ret: %d. Continuing...\n",
				 ret);
			ret = 0;
		}
	}

	cxgb4_uld_tweak_resources(adap);
	cxgb4_uld_init_resources(adap);
	return 0;

out_err:
	mutex_destroy(&adap->uld.uld_mutex);
	return ret;
}
