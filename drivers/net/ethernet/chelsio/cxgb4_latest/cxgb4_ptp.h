/*
 * This file is part of the Chelsio T5/T6 Ethernet driver for Linux.
 *
 * Copyright 2015-2018 (C) Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_PTP_H__
#define __CXGB4_PTP_H__

/* Maximum parts-per-billion adjustment that is acceptable */
#define MAX_PTP_FREQ_ADJ		1000000
#define PTP_CLOCK_MAX_ADJTIME		10000000 /* 10 ms */

#define PTP_MIN_LENGTH			63
#define PTP_IN_TRANSMIT_PACKET_MAXNUM	240
#define PTP_EVENT_PORT			319

enum ptp_rx_filter_mode {
	PTP_TS_NONE = 0,
	PTP_TS_L2,
	PTP_TS_L4,
	PTP_TS_L2_L4
};

struct port_info;

static inline bool cxgb4_xmit_with_hwtstamp(struct sk_buff *skb)
{
	return skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP;
}

static inline void cxgb4_xmit_hwtstamp_pending(struct sk_buff *skb)
{
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
}

void cxgb4_ptp_init(struct adapter *adap);
void cxgb4_ptp_remove(struct adapter *adap);
bool cxgb4_ptp_is_ptp_tx(struct sk_buff *skb);
bool cxgb4_ptp_is_ptp_rx(struct sk_buff *skb);
int cxgb4_ptprx_timestamping(struct port_info *pi, u8 port, u16 mode);
int cxgb4_ptp_redirect_rx_packet(struct adapter *adap, struct port_info *pi);
int cxgb4_ptp_txtype(struct adapter *adap, u8 port_id);
void cxgb4_ptp_read_hwstamp(struct adapter *adap, struct port_info *);
bool is_ptp_enabled(struct sk_buff *skb, struct net_device *dev);
#endif /* __CXGB4_PTP_H__ */

