/*
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _NET_OFFLOAD_H
#define _NET_OFFLOAD_H

#include <net/tcp.h>

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
# define SOCK_OFFLOADED (31)		// connected socket is offloaded
# define SOCK_NO_DDP	(30)		// socket should not do DDP
#endif

enum {
	DISABLE_WALK_SUPPORT,
	ENABLE_WALK_SUPPORT
};

enum {
	OFFLOAD_LISTEN_START,
	OFFLOAD_LISTEN_STOP
};

struct sock;
struct sk_buff;
struct toedev;
struct notifier_block;
struct pipe_inode_info;

/*
 * Extended 'struct proto' with additional members used by offloaded
 * connections.
 */
struct sk_ofld_proto {
	struct proto proto;    /* keep this first */
	int (*read_sock)(struct sock *sk, read_descriptor_t *desc,
			 sk_read_actor_t recv_actor);
	ssize_t (*splice_read)(struct sock *sk, loff_t *ppos,
			       struct pipe_inode_info *pipe, size_t len,
			       unsigned int flags);
	void *ptr;		/* offload connection state */
	struct proto *self;	/* static offload handler checking */
};

static inline struct sk_ofld_proto *sk_ofld_proto_get(const struct sock *sk)
{
	return (struct sk_ofld_proto *)sk->sk_prot;
}

static inline void sk_copy_ofldproto(struct sk_ofld_proto *oproto_dynamic,
				     const struct sk_ofld_proto *oproto_static)
{
	*oproto_dynamic = *oproto_static;
}

static inline void sk_ofld_proto_set_ptr(struct sk_ofld_proto *oproto,
					 const void *ptr)
{
	oproto->ptr = (void *)ptr;
}

static inline void **sk_ofld_proto_get_ptr_addr(const struct sock *sk)
{
	struct sk_ofld_proto *oproto = sk_ofld_proto_get(sk);

	return &oproto->ptr;
}

static inline void sk_ofld_proto_set_tomhandlers(struct sk_ofld_proto *oproto,
						 struct proto *ps)
{
	oproto->self = ps;
}

static inline struct proto *sk_ofld_proto_get_tomhandlers(const struct sock *sk)
{
	struct sk_ofld_proto *oproto = (struct sk_ofld_proto *)sk->sk_prot;

	return oproto->self;
}

/* Per-skb backlog handler.  Run when a socket's backlog is processed. */
struct blog_skb_cb {
	void (*backlog_rcv) (struct sock *sk, struct sk_buff *skb);
	struct toedev *dev;
};

#define BLOG_SKB_CB(skb) ((struct blog_skb_cb *)(skb)->cb)

#ifndef LINUX_2_4
struct offload_req {
	__be32 sip[4];
	__be32 dip[4];
	__be16 sport;
	__be16 dport;
	__u8   ipvers_opentype;
	__u8   tos;
	__be16 vlan;
	__u32  mark;
};

enum { OPEN_TYPE_LISTEN, OPEN_TYPE_ACTIVE, OPEN_TYPE_PASSIVE };

struct offload_settings {
	__u8  offload;
	__s8  ddp;
	__s8  rx_coalesce;
	__s8  cong_algo;
	__s32 rssq;
	__s16 sched_class;
	__s8  tstamp;
	__s8  sack;
	__u8  tls;
	__s8  nagle;
	__u16 mss;
};

enum {
	QUEUE_RANDOM = -2,
	QUEUE_CPU = -3,
};

struct ofld_prog_inst {          /* offload policy program "instructions" */
	s32 offset;
	u32 mask;
	u32 value;
	s32 next[2];
};

struct offload_policy {
	struct rcu_head rcu_head;
	int match_all;
	int use_opt;
	int txt_len;
	void *txt_data;
	unsigned int cop_txt_hdr_vers;
	const struct offload_settings *settings;
	const u32 *opt_prog_start;
	struct ofld_prog_inst prog[0];
};

struct cop_txt_hdr {
        uint8_t sig[4];
        uint32_t vers;
        uint32_t offset;
        uint32_t size;
};


struct ofld_policy_file {
	unsigned int vers;
	int output_everything;
	unsigned int nrules;
	unsigned int prog_size;
	unsigned int opt_prog_size;
	unsigned int nsettings;
	const struct ofld_prog_inst prog[0];
};
#endif /* !LINUX_2_4 */

#if defined(CONFIG_TCP_OFFLOAD) || \
    (defined(CONFIG_TCP_OFFLOAD_MODULE) && defined(MODULE))
int register_listen_offload_notifier(struct notifier_block *nb);
int unregister_listen_offload_notifier(struct notifier_block *nb);
int start_listen_offload(struct sock *sk);
int stop_listen_offload(struct sock *sk);
int tcp_connect_offload(struct sock *sk);
void security_inet_conn_estab(struct sock *sk, struct sk_buff *skb);
void walk_listens(void *handle, int (*func)(void *handle, struct sock *sk), bool support_walk);
int get_cop_txt_data(struct toedev *dev, void **addr, unsigned int *vers);
int set_offload_policy(struct toedev *dev, const struct ofld_policy_file *f, uint32_t length);
void offload_req_from_sk(struct offload_req *req, struct sock *sk, int otype);
const struct offload_settings *
lookup_ofld_policy(const struct toedev *dev, const struct offload_req *req,
		   int cop_managed_offloading);
ssize_t tcp_sendpage_offload(struct socket *sock, struct page *page,
                                    int offset, size_t size, int flags);

int tcp_sendmsg_offload(struct socket *sock,
			struct msghdr *msg, size_t size);
ssize_t tcp_splice_read_offload(struct socket *sock, loff_t *ppos,
                                       struct pipe_inode_info *pipe, size_t len,
                                       unsigned int flags);
#else
static inline int tcp_connect_offload(struct sock *sk)
{
	return 0;
}

static inline int start_listen_offload(struct sock *sk)
{
	return -EPROTONOSUPPORT;
}

static inline int stop_listen_offload(struct sock *sk)
{
	return -EPROTONOSUPPORT;
}
#endif

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
int  check_special_data_ready(const struct sock *sk);
int  install_special_data_ready(struct sock *sk);
void restore_special_data_ready(struct sock *sk);
int  skb_splice_bits_pub(struct sk_buff *skb, unsigned int offset,
			 struct pipe_inode_info *pipe, unsigned int len,
			 unsigned int flags);
#else
static inline int check_special_data_ready(const struct sock *sk) { return 0; }
static inline int install_special_data_ready(struct sock *sk) { return 0; }
static inline void restore_special_data_ready(struct sock *sk) {}
#define skb_splice_bits_pub skb_splice_bits
#endif

#if defined(CONFIG_STRICT_KERNEL_RWX) && defined(CONFIG_TCP_OFFLOAD_MODULE)
void offload_socket_ops(struct sock *sk);
void restore_socket_ops(struct sock *sk);
#else
static inline void offload_socket_ops(struct sock *sk) {}
static inline void restore_socket_ops(struct sock *sk) {}
#endif

#endif /* !_NET_OFFLOAD_H */
