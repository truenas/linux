/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Kumar Sanghvi (kumaras@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __T4_MA_FAILOVER_H
#define __T4_MA_FAILOVER_H

#ifndef __CHELSIO_COMMON_H
#include "common.h"
#endif
#include "t4_msg.h"

#ifdef CONFIG_T4_MA_FAILOVER

void init_ma_fail_data(struct port_info *p);
int ma_fail_check_rx_pkt(struct port_info *pi, struct sk_buff *skb);
int cxgb4_uld_ma_failover_filter_create(struct net_device *dev,
					u8 loop_port, unsigned int queue,
					__be32 sip, u8 use_ipv6,
					const struct in6_addr *sip6);
int cxgb4_uld_ma_failover_filter_delete(struct net_device *dev, u32 fidx);
int ma_fail_mk_fw_act_open_req(struct sock *sk, unsigned int atid,
                               const struct l2t_entry *e);
void ma_fail_active_open_rpl(struct sock *sk, struct sk_buff *skb);
void ma_fail_do_fw6_msg(struct sock *sk, struct sk_buff *skb);
void ma_fail_t4_connect(struct sock *sk);
void ma_fail_mk_pass_sock(void *data);
void ma_fail_do_rx_pkt_init(void *data);
void ma_fail_process_set_tcb_rpl(struct sock *sk, struct sk_buff *skb);
void ma_fail_wr_ack(struct sock *sk);
int ma_fail_t4_init_cpl_io(void);
void t4_toe_ma_failover(struct net_device *slave_dev,
			struct net_device *failed_dev, unsigned int req,
			void *data);
int ma_fail_process_close_con_rpl(struct sock *sk, int state);
int ma_fail_do_peer_fin(struct sock *sk, int state);
int ma_fail_process_abort_rpl(struct sock *sk);
int ma_fail_process_abort_req(struct sock *sk);
int ma_fail_do_rx_pkt(void *td_ptr, struct sk_buff *skb);
int ma_fail_chelsio_sendpage(struct sock *sk, long timeo);
int ma_fail_chelsio_sendmsg(struct sock *sk, long timeo);
int ma_fail_chelsio_shutdown(struct sock *sk);
int ma_fail_chelsio_close(struct sock *sk);
int ma_fail_t4_send_reset(struct sock *sk);
int t4tom_ma_failover_handler(void *handle, const __be64 *rsp,
			      const struct pkt_gl *gl);
int ma_fail_t4_send_rx_credits(struct sock *sk);
void process_get_tcb_mafo_rpl(struct sock *sk, struct sk_buff *skb);

#else
static inline void init_ma_fail_data(struct port_info *p) {}

static inline int ma_fail_check_rx_pkt(struct port_info *pi, struct sk_buff *skb)
{
	return 0;
}

static inline int cxgb4_create_ma_failover_filter(struct net_device *dev,
						  u8 loop_port,
						  unsigned int queue,
						  __be32 sip, u8 use_ipv6,
						  const struct in6_addr *sip6)
{
	return 0;
}

static inline int cxgb4_delete_ma_failover_filter(struct net_device *dev,
						  u8 use_ipv6, int fidx)
{
	return 0;
}

static inline int ma_fail_process_close_con_rpl(struct sock *sk, int state)
{
	return 0;
}

static inline int ma_fail_do_peer_fin(struct sock *sk, int state)
{
	return 0;
}

static inline int ma_fail_process_abort_rpl(struct sock *sk)
{
	return 0;
}

static inline int ma_fail_process_abort_req(struct sock *sk)
{
	return 0;
}

static inline int ma_fail_do_rx_pkt(void *td_ptr, struct sk_buff *skb)
{
	return 0;
}

static inline int ma_fail_chelsio_sendpage(struct sock *sk, long timeo)
{
	return 0;
}

static inline int ma_fail_chelsio_sendmsg(struct sock *sk, long timeo)
{
	return 0;
}

static inline int ma_fail_chelsio_shutdown(struct sock *sk)
{
	return 0;
}

static inline int ma_fail_chelsio_close(struct sock *sk)
{
	return 0;
}

static inline int ma_fail_t4_send_reset(struct sock *sk)
{
	return 0;
}

static inline int t4tom_ma_failover_handler(void *handle, const __be64 *rsp,
					    const struct pkt_gl *gl)
{
	return 0;
}

static inline int ma_fail_mk_fw_act_open_req(struct sock *sk, unsigned int atid,
					     const struct l2t_entry *e)
{
	return 0;
}

static inline int ma_fail_t4_send_rx_credits(struct sock *sk)
{
	return 0;
}

static inline int ma_fail_t4_init_cpl_io(void)
{
	return 0;
}

static inline void ma_fail_active_open_rpl(struct sock *sk, struct sk_buff *skb) {}
static inline void ma_fail_do_fw6_msg(struct sock *sk, struct sk_buff *skb) {}
static inline void ma_fail_t4_connect(struct sock *sk) {}
static inline void ma_fail_mk_pass_sock(void *data) {}
static inline void ma_fail_do_rx_pkt_init(void *data) {}
static inline void ma_fail_wr_ack(struct sock *sk) {}
static inline void t4_toe_ma_failover(struct net_device *slave_dev,
				      struct net_device *failed_dev,
				      unsigned int req,
				      void *data) {}

#endif

#endif /* __T4_MA_FAILOVER_H */
