/*
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __IW_CXGB4_COMPAT_H
#define __IW_CXGB4_COMPAT_H

#include <linux/version.h>

static inline void t4_tcp_parse_options(const struct net *net,
					const struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(net, skb, opt_rx, estab, NULL);
}
#endif /* __IW__CXGB4_COMPAT_H */
