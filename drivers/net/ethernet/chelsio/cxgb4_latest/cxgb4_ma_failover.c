/*
 * Copyright 2014-2018 (C) Chelsio Communications.  All rights reserved.
 *
 * Written by Kumar Sanghvi (kumaras@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Software in this file is covered under US Patent "Failover and migration
 * for full-offload network interface devices : US 8346919 B1".
 */

#include <linux/module.h>
#include "t4_ma_failover.h"
#include "cxgbtool.h"
#include "cxgb4_filter.h"

#ifdef CONFIG_T4_MA_FAILOVER

void init_ma_fail_data(struct port_info *p)
{

	p->ma_fail_data.flags = MA_FAILOVER_NONE;
	p->ma_fail_data.this_dev = p->ma_fail_data.backup_dev = NULL;
	atomic_set(&p->ma_fail_data.conn_moved, 0);
	p->ma_fail_data.fidx = p->ma_fail_data.fidx6 = -1;
}

int ma_fail_check_rx_pkt(struct port_info *pi, struct sk_buff *skb)
{
	if (pi->ma_fail_data.flags == MA_FAILOVER
			&& (skb->cb[0] == CPL_RX_PKT)) {
		/*
		 * If we are in ma-failover and above condition is
		 * true then, this packet is coming from peer, and
		 * is intended for the connection which still exists
		 * on failed_dev. So, loopback it.
		 */
		return 1;
	} else
		return 0;
}

int cxgb4_uld_ma_failover_filter_create(struct net_device *dev,
					u8 loop_port, unsigned int queue,
					__be32 sip, u8 use_ipv6,
					const struct in6_addr *sip6)
{
	struct ch_filter_specification fs = { 0 };
	u8 i, *val;

	fs.val.iport = loop_port;
	fs.mask.iport = ~0;

	if (use_ipv6) {
		val = (u8 *)sip6->s6_addr;
		for (i = 0; i < 16; i++) {
			fs.val.fip[i] = val[i];
			fs.mask.fip[i] = ~0;
		}
		fs.type = 1;
	} else {
		val = (u8 *)&sip;
		if ((val[0] | val[1] | val[2] | val[3]) != 0) {
			for (i = 0; i < 4; i++) {
				fs.val.fip[i] = val[i];
				fs.mask.fip[i] = ~0;
			}
		}
	}

	fs.dirsteer = 1;
	fs.iq = queue;
	fs.rpttid = 1;
	fs.hitcnts = 1;
	fs.prio = 1;

	return cxgb4_filter_normal_create(dev, CXGB4_FILTER_ID_ANY, &fs, NULL, GFP_ATOMIC);
}
EXPORT_SYMBOL(cxgb4_uld_ma_failover_filter_create);

int cxgb4_uld_ma_failover_filter_delete(struct net_device *dev, u32 fidx)
{
	return cxgb4_filter_delete(dev, fidx, NULL, NULL, GFP_ATOMIC);
}
EXPORT_SYMBOL(cxgb4_uld_ma_failover_filter_delete);

#endif /* CONFIG_T4_MA_FAILOVER */
