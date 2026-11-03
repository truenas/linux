// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lio_ha_tcp.c -- TCP channel for lio_ha.ko
 *
 * Connection model
 * ----------------
 * Both nodes run a listen socket (bound to local_addr:port) AND a
 * connect loop (targeting peer_addr:port) simultaneously.  The first
 * TCP connection established -- whether accepted or connected -- becomes
 * the active link.  Subsequent inbound connections are dropped until
 * the active link is torn down.
 *
 * This symmetric approach avoids any need to configure which node is
 * "server" and which is "client", and handles split-brain recovery
 * gracefully: if both nodes restart simultaneously, the first TCP SYN
 * that succeeds determines the link direction.
 *
 * Thread model
 * ------------
 * ha_listen_task : bind -> listen -> loop on kernel_accept.
 *                  On accept: calls ha_tcp_on_connected().  Any failure
 *                  is retried after 5 s with the address read again.
 *
 * ha_connect_task: loop: if disconnected, try kernel_connect with 5 s
 *                  connect timeout; exponential backoff (1 s -> 30 s) on
 *                  failure.  On success: calls ha_tcp_on_connected().
 *                  Only the node with the lower local address dials, so
 *                  the pair never has two connections to choose from.
 *
 * ha_rx_task     : started per-connection inside ha_tcp_on_connected().
 *                  Reads wire header + payload in a loop.  On error:
 *                  calls ha_tcp_on_disconnected(), then exits.  Held by a
 *                  task reference until it is joined with kthread_stop():
 *                  by the next ha_tcp_on_connected(), or by
 *                  lio_ha_tcp_exit(), so no rx thread is still running
 *                  module code when a new one starts or the module goes.
 *
 * Locking
 * -------
 * ha_tcp_lock (mutex): protects ha_conn_sock, ha_connecting_sock,
 *     ha_rx_task, and the ha_state field in lio_ha_cfg.  ha_connecting_sock
 *     holds the socket ha_connect_task is currently blocked inside
 *     kernel_connect() with (NULL otherwise), so lio_ha_tcp_exit() can shut
 *     it down the same way it does ha_conn_sock/ha_listen_sock -- without
 *     it, a peer that never answers the SYN leaves kernel_connect() blocked
 *     for the kernel's own TCP retry timeout (~127 s by default), and
 *     kthread_stop(ha_connect_task) blocks right along with it.
 *
 * ha_send_lock (mutex): serialises concurrent callers of
 *     lio_ha_tcp_send() so that header and payload are sent as a unit.
 *     Taken before ha_tcp_lock.  lio_ha_tcp_send() reads ha_conn_sock
 *     with it held, and whoever clears ha_conn_sock takes and drops it
 *     before calling sock_release(), so the socket is not freed while a
 *     send is using it.
 *
 * Every owner of ha_conn_sock, ha_listen_sock and ha_connecting_sock
 * clears the pointer under ha_tcp_lock before releasing the socket, so
 * a socket read under ha_tcp_lock may be shut down before it is dropped.
 *
 *
 * Message dispatch
 * ----------------
 * CTL-channel payloads start with lio_ha_msg_hdr (type field).
 * ctl_handlers[] is a sparse array mapping msg_type -> handler fn.
 * Entries are NULL until registered by higher-level subsystems.
 * Unregistered types are dropped with a debug log.
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>    /* in4_pton */
#include <linux/tcp.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>    /* kvmalloc / kvfree */
#include <linux/hashtable.h>
#include <linux/scatterlist.h>

#include <target/target_core_ha.h>

#include "lio_ha.h"
#include "lio_ha_wire.h"
#include "lio_ha_tcp.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

/*
 * Connect-loop timing.  All values are in milliseconds.
 */
#define LIO_HA_CONNECT_TIMEOUT_MS   5000   /* kernel_connect SO_SNDTIMEO */
#define LIO_HA_CONNECT_BACKOFF_INIT 1000   /* initial retry delay */
#define LIO_HA_CONNECT_BACKOFF_MAX  30000  /* maximum retry delay */

/*
 * A connected socket gives up on a peer that has not acknowledged sent
 * data for this long (TCP_USER_TIMEOUT), and a send that cannot make
 * progress for this long fails (SO_SNDTIMEO).  Either way the connection
 * is closed and in-flight commands complete with BUSY.  Keepalive covers
 * an idle link; these cover one with data outstanding, which keepalive
 * does not probe, and which would otherwise hold ha_send_lock, and every
 * sender behind it, for the kernel's retransmission timeout (~15 min).
 */
#define LIO_HA_IO_TIMEOUT_MS        10000

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

static DEFINE_MUTEX(ha_tcp_lock);
static DEFINE_MUTEX(ha_send_lock);

static struct socket      *ha_conn_sock;       /* active TCP connection  */
static struct socket      *ha_listen_sock;     /* server accept socket   */
static struct socket      *ha_connecting_sock; /* socket mid-kernel_connect() */
static struct task_struct *ha_listen_task;
static struct task_struct *ha_connect_task;
static struct task_struct *ha_rx_task;
static struct ha_tcp_rx   *ha_rx_state;  /* ha_rx_task's argument */

/*
 * One per rx thread, owned by it: allocated with the thread, freed by the
 * thread on its way out (or by lio_ha_tcp_exit() if the thread was stopped
 * before it ran).  The assembly table is touched only by the thread, so it
 * needs no lock, and a later connection's thread has a table of its own.
 */
struct ha_tcp_rx {
	struct socket *sock;
	DECLARE_HASHTABLE(asm_ht, 6);
	void          *drain;    /* HA_TCP_DRAIN_LEN scratch */
};

/* A DATA transfer being assembled from its chunks. */
struct ha_tcp_asm {
	u64               cookie;
	u32               total;
	u32               received;   /* == offset of the next chunk */
	void             *buf;        /* kvmalloc(total) */
	struct hlist_node node;
};

#define HA_TCP_DRAIN_LEN	(64 * 1024)

/*
 * Bounce buffer for lio_ha_tcp_send_data(), used and cleared under
 * ha_send_lock: senders on the ACTIVE's completion path can still run
 * after lio_ha_tcp_exit(), and must then see NULL, not freed memory.
 */
static void *ha_send_bounce;

static atomic_t ha_tcp_stopping = ATOMIC_INIT(0);

/*
 * Set under ha_tcp_lock while ha_tcp_on_disconnected() runs the disconnect
 * handlers for a dropped connection.  ha_tcp_on_connected() refuses a new
 * connection meanwhile, so nothing from the old connection -- a response
 * to a command, a session, buffered data -- is still being cleaned up when
 * the new one starts.  The peer retries the connection.
 */
static bool ha_tcp_disconnecting;

/*
 * Connection generation: incremented under ha_tcp_lock each time a new
 * connection is installed, so it names one connection.  A sender that
 * must not reach a later connection than the one it started on captures
 * it with lio_ha_tcp_generation() and sends with lio_ha_tcp_send_gen().
 * It starts at 1, so 0 is never a generation; lio_ha_tcp_send() passes
 * 0 for "any".
 */
static atomic64_t ha_conn_gen = ATOMIC64_INIT(1);

/*
 * CTL-channel dispatch table.  Indexed by enum lio_ha_msg_type.
 * Protected by module load ordering: handlers are registered at init
 * time, before any messages can arrive.
 */
static void (*ctl_handlers[_LIO_HA_MSG_MAX])(const void *buf, size_t len);

/*
 * DATA-channel handler: registered by lio_ha_fwd.c at init time.
 * Called with (cookie, raw_data_ptr, raw_data_len) for each DATA message.
 */
static void (*data_handler_fn)(u64 cookie, void *data, u32 data_len);

/*
 * Disconnect handlers: called when the TCP link drops (not at module exit).
 * lio_ha_fwd flushes its in-flight command tables so initiators get
 * SAM_STAT_BUSY; lio_ha_recv tears down the sessions it created for the
 * peer's initiators.
 */
#define HA_TCP_MAX_DISCONNECT_HANDLERS	2
static void (*disconnect_handler_fns[HA_TCP_MAX_DISCONNECT_HANDLERS])(void);

/*
 * Connect handler: called when a new TCP connection is established.
 * On ACTIVE (forward_active == 0), triggers LUN_SYNC bulk PR export.
 */
static void (*connect_handler_fn)(void);

/* ------------------------------------------------------------------ */
/* Socket helpers                                                      */
/* ------------------------------------------------------------------ */

/*
 * Receive exactly @len bytes.  Returns 0 on success, negative errno
 * on socket error, -ECONNRESET if the peer closed the connection.
 */
static int ha_tcp_recv_full(struct socket *sock, void *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		struct kvec iov = {
			.iov_base = (u8 *)buf + done,
			.iov_len  = len - done,
		};
		struct msghdr msg = {};
		int r;

		r = kernel_recvmsg(sock, &msg, &iov, 1, len - done, 0);
		if (r <= 0)
			return r < 0 ? r : -ECONNRESET;
		done += r;
	}
	return 0;
}

/*
 * Send exactly @len bytes.  Returns 0 on success, negative errno on
 * error.  Must be called with ha_send_lock held.
 */
static int ha_tcp_send_full(struct socket *sock, const void *buf, size_t len)
{
	size_t sent = 0;

	while (sent < len) {
		struct kvec iov = {
			.iov_base = (void *)((const u8 *)buf + sent),
			.iov_len  = len - sent,
		};
		struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
		int r;

		r = kernel_sendmsg(sock, &msg, &iov, 1, len - sent);
		if (r <= 0)
			return r < 0 ? r : -ECONNRESET;
		sent += r;
	}
	return 0;
}

/*
 * Parse a dotted-decimal IPv4 string and fill a sockaddr_in.
 */
static int ha_tcp_make_addr(const char *addr_str, u16 port,
			    struct sockaddr_in *sin)
{
	u8 addr[4];

	if (!in4_pton(addr_str, -1, addr, -1, NULL))
		return -EINVAL;

	memset(sin, 0, sizeof(*sin));
	sin->sin_family      = AF_INET;
	sin->sin_port        = htons(port);
	memcpy(&sin->sin_addr.s_addr, addr, 4);
	return 0;
}

/* ------------------------------------------------------------------ */
/* CTL-channel dispatch                                                */
/* ------------------------------------------------------------------ */

/*
 * Returns -EPROTO, which closes the connection, for a message header this
 * node does not accept: one with its reserved field set was written to a
 * layout this node does not know.
 */
static int ha_tcp_dispatch_ctl(const void *payload, size_t len)
{
	const struct lio_ha_msg_hdr *hdr = payload;
	u32 type;
	void (*fn)(const void *buf, size_t len);

	if (len < sizeof(*hdr)) {
		pr_warn("ha_tcp: CTL payload too short (%zu bytes)\n", len);
		return 0;
	}

	type = be32_to_cpu(hdr->type);
	if (hdr->reserved) {
		pr_err_ratelimited("ha_tcp: CTL msg type %u has reserved 0x%08x set, closing the connection\n",
				   type, be32_to_cpu(hdr->reserved));
		return -EPROTO;
	}

	fn = (type < _LIO_HA_MSG_MAX) ? ctl_handlers[type] : NULL;
	if (!fn) {
		pr_debug("ha_tcp: unhandled CTL msg type %u len %zu\n",
			 type, len);
		return 0;
	}

	fn(payload, len);
	return 0;
}

/* ------------------------------------------------------------------ */
/* DATA-channel assembly                                               */
/* ------------------------------------------------------------------ */

static struct ha_tcp_rx *ha_tcp_rx_alloc(struct socket *sock)
{
	struct ha_tcp_rx *rx = kzalloc(sizeof(*rx), GFP_KERNEL);

	if (!rx)
		return NULL;
	rx->drain = kvmalloc(HA_TCP_DRAIN_LEN, GFP_KERNEL);
	if (!rx->drain) {
		kfree(rx);
		return NULL;
	}
	rx->sock = sock;
	hash_init(rx->asm_ht);
	return rx;
}

static void ha_tcp_asm_free(struct ha_tcp_asm *a)
{
	hash_del(&a->node);
	kvfree(a->buf);
	kfree(a);
}

/* Free @rx and every transfer it was still assembling. */
static void ha_tcp_rx_free(struct ha_tcp_rx *rx)
{
	struct ha_tcp_asm *a;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(rx->asm_ht, bkt, tmp, a, node)
		ha_tcp_asm_free(a);
	kvfree(rx->drain);
	kfree(rx);
}

static struct ha_tcp_asm *ha_tcp_asm_find(struct ha_tcp_rx *rx, u64 cookie)
{
	struct ha_tcp_asm *a;

	hash_for_each_possible(rx->asm_ht, a, node, cookie)
		if (a->cookie == cookie)
			return a;
	return NULL;
}

/*
 * Start assembling a transfer.  NULL means the transfer is dropped: its
 * chunks are read and discarded, and the command it belongs to gets BUSY
 * (or, if larger than any command may be, was already refused).  Neither
 * case is the peer's fault, so neither closes the link.
 */
static struct ha_tcp_asm *ha_tcp_asm_start(struct ha_tcp_rx *rx, u64 cookie,
					   u32 total)
{
	struct ha_tcp_asm *a;

	if (total > LIO_HA_MAX_DATA_TOTAL) {
		pr_warn_ratelimited("ha_tcp: DATA transfer of %u bytes for cookie %016llx too large, dropped\n",
				    total, (unsigned long long)cookie);
		return NULL;
	}
	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		goto nomem;
	/*
	 * kvmalloc() does not take __GFP_NORETRY.  It does not reclaim for
	 * the contiguous attempt at this size; its vmalloc fallback may.
	 */
	a->buf = kvmalloc(total, GFP_KERNEL | __GFP_NOWARN);
	if (!a->buf) {
		kfree(a);
		goto nomem;
	}
	a->cookie = cookie;
	a->total  = total;
	hash_add(rx->asm_ht, &a->node, cookie);
	return a;

nomem:
	pr_warn_ratelimited("ha_tcp: no memory for a DATA transfer of %u bytes, dropped\n",
			    total);
	return NULL;
}

/* Read and discard @len bytes. */
static int ha_tcp_drain(struct ha_tcp_rx *rx, u32 len)
{
	while (len) {
		u32 n = min_t(u32, len, HA_TCP_DRAIN_LEN);
		int ret = ha_tcp_recv_full(rx->sock, rx->drain, n);

		if (ret)
			return ret;
		len -= n;
	}
	return 0;
}

/*
 * Receive one DATA message of @plen bytes, the wire header already read.
 * Returns an error only for a broken connection or a chunk no matching
 * peer sends; both close the link.
 */
static int ha_tcp_rx_data(struct ha_tcp_rx *rx, u32 plen)
{
	struct lio_ha_data_hdr dhdr;
	struct ha_tcp_asm *a;
	u32 clen, total, off;
	u64 cookie;
	int ret;

	if (plen <= sizeof(dhdr) ||
	    plen - sizeof(dhdr) > LIO_HA_MAX_DATA_CHUNK) {
		pr_err("ha_tcp: DATA message of %u bytes, closing the connection\n",
		       plen);
		return -EPROTO;
	}
	ret = ha_tcp_recv_full(rx->sock, &dhdr, sizeof(dhdr));
	if (ret)
		return ret;
	clen   = plen - sizeof(dhdr);
	cookie = be64_to_cpu(dhdr.cmd_cookie);
	total  = be32_to_cpu(dhdr.total_len);
	off    = be32_to_cpu(dhdr.offset);
	if (off > total || clen > total - off) {
		pr_err("ha_tcp: DATA chunk %u+%u past the end of %u, closing the connection\n",
		       off, clen, total);
		return -EPROTO;
	}

	a = ha_tcp_asm_find(rx, cookie);
	if (off == 0) {
		/*
		 * Offset 0 starts a transfer.  Cookies are se_cmd pointers and
		 * are reused, so a partial transfer under the same cookie is a
		 * dropped one: discard it.
		 */
		if (a)
			ha_tcp_asm_free(a);
		a = ha_tcp_asm_start(rx, cookie, total);
	} else if (a && (a->total != total || a->received != off)) {
		pr_warn_ratelimited("ha_tcp: DATA chunk out of sequence for cookie %016llx, dropped\n",
				    (unsigned long long)cookie);
		ha_tcp_asm_free(a);
		a = NULL;
	}
	if (!a)
		return ha_tcp_drain(rx, clen);

	ret = ha_tcp_recv_full(rx->sock, (u8 *)a->buf + off, clen);
	if (ret)
		return ret;
	a->received += clen;
	if (a->received == a->total) {
		void *buf = a->buf;

		hash_del(&a->node);
		kfree(a);
		if (data_handler_fn)
			data_handler_fn(cookie, buf, total);
		else
			kvfree(buf);
	}
	return 0;
}

/* Forward declarations for functions used before their definitions. */
static int  ha_tcp_rx_fn(void *arg);
static void ha_tcp_on_disconnected(struct socket *sock);

/* ------------------------------------------------------------------ */
/* Connection lifecycle                                                */
/* ------------------------------------------------------------------ */

/*
 * Called (from listen or connect thread) when a TCP connection has
 * been established.  Starts the rx task.  If a connection is already
 * active, drops the new socket.
 */
static void ha_tcp_on_connected(struct socket *sock)
{
	struct task_struct *rx;
	struct ha_tcp_rx *rxs;

	mutex_lock(&ha_tcp_lock);

	if (ha_conn_sock || ha_tcp_disconnecting ||
	    atomic_read(&ha_tcp_stopping)) {
		/*
		 * Already connected, still cleaning up after the previous
		 * connection, or module is shutting down -- drop.
		 */
		mutex_unlock(&ha_tcp_lock);
		sock_release(sock);
		return;
	}

	/*
	 * Aggressive TCP keepalive + TCP_NODELAY on the HA wire.
	 *
	 * The HA backplane is a dedicated low-latency link; we want a
	 * crashed/unreachable peer detected within seconds, not the Linux
	 * default (~2 hours of idle before the first keepalive probe).
	 *
	 * Values mirror FreeBSD CTL HA (cam/ctl/ctl_ha.c) which has shipped
	 * with idle=1s, intvl=1s, cnt=5 for years on the same kind of HA
	 * interconnect.  Detection time is roughly idle + cnt*intvl ~= 6s.
	 *
	 * NODELAY: control messages (CMD_FORWARD, CMD_RESPONSE, LUN_SYNC,
	 * etc.) are tiny -- Nagle would coalesce them and add latency for
	 * no throughput benefit.
	 *
	 * Errors are logged but non-fatal: the connection still works at
	 * default TCP timing, just without fast dead-peer detection.
	 */
	sock_set_keepalive(sock->sk);
	if (tcp_sock_set_keepidle(sock->sk, 1))
		pr_warn("ha_tcp: failed to set TCP_KEEPIDLE\n");
	if (tcp_sock_set_keepintvl(sock->sk, 1))
		pr_warn("ha_tcp: failed to set TCP_KEEPINTVL\n");
	if (tcp_sock_set_keepcnt(sock->sk, 5))
		pr_warn("ha_tcp: failed to set TCP_KEEPCNT\n");
	tcp_sock_set_nodelay(sock->sk);
	tcp_sock_set_user_timeout(sock->sk, LIO_HA_IO_TIMEOUT_MS);
	sock->sk->sk_sndtimeo = msecs_to_jiffies(LIO_HA_IO_TIMEOUT_MS);

	/*
	 * Join the previous connection's rx thread.  It has run its
	 * disconnect handling (ha_tcp_disconnecting is clear) and takes no
	 * lock on its way out, so this does not wait on us.
	 */
	if (ha_rx_task) {
		kthread_stop(ha_rx_task);
		put_task_struct(ha_rx_task);
		ha_rx_task  = NULL;
		ha_rx_state = NULL;	/* freed by the thread */
	}

	rxs = ha_tcp_rx_alloc(sock);
	if (!rxs) {
		pr_err("ha_tcp: no memory for the rx thread's state\n");
		mutex_unlock(&ha_tcp_lock);
		sock_release(sock);
		return;
	}
	rx = kthread_create(ha_tcp_rx_fn, rxs, "lio_ha_rx");
	if (IS_ERR(rx)) {
		pr_err("ha_tcp: failed to start rx thread: %ld\n", PTR_ERR(rx));
		ha_tcp_rx_free(rxs);
		mutex_unlock(&ha_tcp_lock);
		sock_release(sock);
		return;
	}
	get_task_struct(rx);
	ha_rx_task   = rx;
	ha_rx_state  = rxs;
	ha_conn_sock = sock;
	atomic64_inc(&ha_conn_gen);
	wake_up_process(rx);

	spin_lock(&lio_ha_cfg.lock);
	lio_ha_cfg.ha_state = LIO_HA_CONNECTED;
	spin_unlock(&lio_ha_cfg.lock);

	mutex_unlock(&ha_tcp_lock);

	pr_info("ha_tcp: connected\n");

	if (connect_handler_fn)
		connect_handler_fn();
}

/*
 * Called by ha_rx_task when the socket produces an error (peer closed
 * or network failure).  Also called by lio_ha_tcp_exit() for cleanup.
 *
 * Clears ha_conn_sock, waits for any in-progress send to finish (by
 * acquiring ha_send_lock), then releases the socket.
 */
static void ha_tcp_on_disconnected(struct socket *sock)
{
	mutex_lock(&ha_tcp_lock);

	if (ha_conn_sock != sock) {
		/* Stale call -- socket was already replaced. */
		mutex_unlock(&ha_tcp_lock);
		goto done;
	}

	ha_conn_sock = NULL;
	ha_tcp_disconnecting = true;

	spin_lock(&lio_ha_cfg.lock);
	lio_ha_cfg.ha_state = LIO_HA_DISCONNECTED;
	spin_unlock(&lio_ha_cfg.lock);

	mutex_unlock(&ha_tcp_lock);

	/*
	 * Wait for any lio_ha_tcp_send() in progress to complete before
	 * releasing the socket.  lio_ha_tcp_send() reads ha_conn_sock with
	 * ha_send_lock held, and it is cleared above, so once we hold
	 * ha_send_lock no send is using @sock.  Shut it down first so that
	 * a send blocked on a dead peer returns instead of holding
	 * ha_send_lock.
	 */
	kernel_sock_shutdown(sock, SHUT_RDWR);
	mutex_lock(&ha_send_lock);
	mutex_unlock(&ha_send_lock);

	/*
	 * Notify subsystems (lio_ha_fwd, ha_recv) that the link is down so
	 * they can complete in-flight commands with SAM_STAT_BUSY.  Called
	 * only on a real link drop; not during module exit (ha_tcp_stopping).
	 */
	if (!atomic_read(&ha_tcp_stopping)) {
		int i;

		for (i = 0; i < HA_TCP_MAX_DISCONNECT_HANDLERS; i++)
			if (disconnect_handler_fns[i])
				disconnect_handler_fns[i]();
	}

	mutex_lock(&ha_tcp_lock);
	ha_tcp_disconnecting = false;
	mutex_unlock(&ha_tcp_lock);

	if (!atomic_read(&ha_tcp_stopping))
		pr_info("ha_tcp: disconnected\n");

done:
	sock_release(sock);
}

/* ------------------------------------------------------------------ */
/* RX thread                                                           */
/* ------------------------------------------------------------------ */

static int ha_tcp_rx_fn(void *arg)
{
	struct ha_tcp_rx *rx = arg;
	struct socket *sock = rx->sock;
	struct lio_ha_wire_hdr hdr;
	void *payload;
	u32 channel, plen;
	int ret;

	while (!kthread_should_stop()) {
		ret = ha_tcp_recv_full(sock, &hdr, sizeof(hdr));
		if (ret)
			goto out;

		if (be32_to_cpu(hdr.magic) != LIO_HA_WIRE_MAGIC) {
			pr_err_ratelimited("ha_tcp: bad message magic 0x%08x, closing the connection\n",
					   be32_to_cpu(hdr.magic));
			ret = -EPROTO;
			goto out;
		}
		if (be16_to_cpu(hdr.version) != LIO_HA_WIRE_VERSION) {
			pr_err_ratelimited("ha_tcp: peer runs wire version %u, this node %u; closing the connection\n",
					   be16_to_cpu(hdr.version),
					   LIO_HA_WIRE_VERSION);
			ret = -EPROTO;
			goto out;
		}

		channel = be16_to_cpu(hdr.channel);
		plen    = be32_to_cpu(hdr.length);

		/* Sanity-check the channel and payload length. */
		if (channel != LIO_HA_CHAN_CTL && channel != LIO_HA_CHAN_DATA) {
			pr_err("ha_tcp: unknown channel %u, closing the connection\n",
			       channel);
			ret = -EPROTO;
			goto out;
		}
		if (channel == LIO_HA_CHAN_DATA) {
			/* Read straight into the transfer's buffer. */
			ret = ha_tcp_rx_data(rx, plen);
			if (ret)
				goto out;
			continue;
		}
		if (plen > LIO_HA_MAX_CTL_PAYLOAD) {
			pr_err("ha_tcp: CTL payload (%u bytes) too large, dropping\n", plen);
			ret = -EMSGSIZE;
			goto out;
		}

		/* kvmalloc handles both small (kmalloc) and large (vmalloc) payloads. */
		payload = kvmalloc(plen, GFP_KERNEL);
		if (!payload) {
			ret = -ENOMEM;
			goto out;
		}

		ret = ha_tcp_recv_full(sock, payload, plen);
		if (ret) {
			kvfree(payload);
			goto out;
		}

		ret = ha_tcp_dispatch_ctl(payload, plen);
		kvfree(payload);
		if (ret)
			goto out;
	}

out:
	if (ret && !atomic_read(&ha_tcp_stopping))
		pr_debug("ha_tcp: rx error %d\n", ret);

	ha_tcp_on_disconnected(sock);
	/* Partial transfers go with the connection. */
	ha_tcp_rx_free(rx);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Listen thread                                                       */
/* ------------------------------------------------------------------ */

/* Sleep @ms unless the thread is stopped meanwhile; true if it should stop. */
static bool ha_tcp_sleep(unsigned long ms)
{
	schedule_timeout_interruptible(msecs_to_jiffies(ms));
	return kthread_should_stop() || atomic_read(&ha_tcp_stopping);
}

#define LIO_HA_LISTEN_RETRY_MS	5000

/*
 * Listen for the peer's connection.  Any failure -- an address that does
 * not parse or is not up yet, a failed bind, an accept error -- is logged
 * and retried with the configuration read again, so the thread lasts as
 * long as the module.
 */
static int ha_tcp_listen_fn(void *unused)
{
	char local[LIO_HA_ADDR_LEN];
	u16 port;
	struct sockaddr_in sin;
	struct socket *lsock;
	int ret;

	while (!kthread_should_stop() && !atomic_read(&ha_tcp_stopping)) {
		spin_lock(&lio_ha_cfg.lock);
		memcpy(local, lio_ha_cfg.local_addr, LIO_HA_ADDR_LEN);
		port = lio_ha_cfg.port;
		spin_unlock(&lio_ha_cfg.lock);

		/* Wait until local_addr and port are configured. */
		if (!local[0] || !port) {
			ha_tcp_sleep(1000);
			continue;
		}

		ret = ha_tcp_make_addr(local, port, &sin);
		if (ret) {
			pr_err_ratelimited("ha_tcp: invalid local_addr '%s': %d\n",
					   local, ret);
			goto retry;
		}

		ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
				       IPPROTO_TCP, &lsock);
		if (ret) {
			pr_err_ratelimited("ha_tcp: sock_create_kern failed: %d\n",
					   ret);
			goto retry;
		}

		lsock->sk->sk_reuse = SK_CAN_REUSE;

		ret = kernel_bind(lsock, (struct sockaddr_unsized *)&sin,
				  sizeof(sin));
		if (ret) {
			pr_err_ratelimited("ha_tcp: kernel_bind(%s:%u) failed: %d\n",
					   local, port, ret);
			sock_release(lsock);
			goto retry;
		}

		ret = kernel_listen(lsock, 4);
		if (ret) {
			pr_err_ratelimited("ha_tcp: kernel_listen failed: %d\n",
					   ret);
			sock_release(lsock);
			goto retry;
		}

		mutex_lock(&ha_tcp_lock);
		ha_listen_sock = lsock;
		mutex_unlock(&ha_tcp_lock);

		pr_info("ha_tcp: listening on %s:%u\n", local, port);

		while (!kthread_should_stop() && !atomic_read(&ha_tcp_stopping)) {
			struct socket *new_sock;

			ret = kernel_accept(lsock, &new_sock, 0);
			if (ret < 0) {
				if (!atomic_read(&ha_tcp_stopping) &&
				    !kthread_should_stop())
					pr_warn("ha_tcp: kernel_accept error: %d; listening again\n",
						ret);
				break;
			}

			ha_tcp_on_connected(new_sock);
		}

		mutex_lock(&ha_tcp_lock);
		ha_listen_sock = NULL;
		mutex_unlock(&ha_tcp_lock);

		sock_release(lsock);
retry:
		if (ha_tcp_sleep(LIO_HA_LISTEN_RETRY_MS))
			break;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Connect thread                                                      */
/* ------------------------------------------------------------------ */

static int ha_tcp_connect_fn(void *unused)
{
	char peer[LIO_HA_ADDR_LEN];
	char local[LIO_HA_ADDR_LEN];
	u16 port;
	unsigned long delay_ms = LIO_HA_CONNECT_BACKOFF_INIT;

	/* Wait until peer_addr is configured (local_addr and port too). */
	while (!kthread_should_stop()) {
		spin_lock(&lio_ha_cfg.lock);
		memcpy(peer,  lio_ha_cfg.peer_addr,  LIO_HA_ADDR_LEN);
		memcpy(local, lio_ha_cfg.local_addr, LIO_HA_ADDR_LEN);
		port = lio_ha_cfg.port;
		spin_unlock(&lio_ha_cfg.lock);

		if (peer[0] && local[0] && port)
			break;

		schedule_timeout_interruptible(msecs_to_jiffies(1000));
	}

	while (!kthread_should_stop() && !atomic_read(&ha_tcp_stopping)) {
		struct socket *sock;
		struct sockaddr_in peer_sin, local_sin;
		int ret;

		/* Skip connect attempt if already connected. */
		mutex_lock(&ha_tcp_lock);
		if (ha_conn_sock) {
			mutex_unlock(&ha_tcp_lock);
			/*
			 * Wait until the connection is dropped before trying
			 * again.  Poll every 5 s to catch the stopping flag.
			 */
			schedule_timeout_interruptible(msecs_to_jiffies(5000));
			delay_ms = LIO_HA_CONNECT_BACKOFF_INIT;
			continue;
		}
		mutex_unlock(&ha_tcp_lock);

		/* Refresh addresses (may have been reconfigured). */
		spin_lock(&lio_ha_cfg.lock);
		memcpy(peer,  lio_ha_cfg.peer_addr,  LIO_HA_ADDR_LEN);
		memcpy(local, lio_ha_cfg.local_addr, LIO_HA_ADDR_LEN);
		port = lio_ha_cfg.port;
		spin_unlock(&lio_ha_cfg.lock);

		if (!peer[0] || !local[0] || !port)
			goto backoff;

		if (ha_tcp_make_addr(peer,  port, &peer_sin)  < 0 ||
		    ha_tcp_make_addr(local, 0,    &local_sin) < 0)
			goto backoff;

		/*
		 * Only the node with the lower address dials; the other only
		 * accepts.  When both dialled at once, each could keep its own
		 * outbound connection and drop the one it accepted, closing
		 * both links, again and again.
		 */
		if (ntohl(local_sin.sin_addr.s_addr) >
		    ntohl(peer_sin.sin_addr.s_addr)) {
			schedule_timeout_interruptible(msecs_to_jiffies(5000));
			delay_ms = LIO_HA_CONNECT_BACKOFF_INIT;
			continue;
		}

		ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
				       IPPROTO_TCP, &sock);
		if (ret) {
			pr_debug("ha_tcp: sock_create_kern: %d\n", ret);
			goto backoff;
		}

		/* Bind to local_addr so the peer knows which node is calling. */
		sock->sk->sk_reuse = SK_CAN_REUSE;
		ret = kernel_bind(sock, (struct sockaddr_unsized *)&local_sin,
				  sizeof(local_sin));
		if (ret) {
			sock_release(sock);
			goto backoff;
		}

		/*
		 * sk_sndtimeo bounds blocking sends, not kernel_connect()
		 * itself -- an unanswered SYN can otherwise block here for the
		 * kernel's own TCP retry timeout (~127 s by default).  Publish
		 * the socket first so lio_ha_tcp_exit() can shut it down and
		 * unblock us on module removal.
		 */
		sock->sk->sk_sndtimeo = msecs_to_jiffies(LIO_HA_CONNECT_TIMEOUT_MS);

		mutex_lock(&ha_tcp_lock);
		ha_connecting_sock = sock;
		mutex_unlock(&ha_tcp_lock);

		ret = kernel_connect(sock, (struct sockaddr *)&peer_sin,
				     sizeof(peer_sin), 0);

		mutex_lock(&ha_tcp_lock);
		ha_connecting_sock = NULL;
		mutex_unlock(&ha_tcp_lock);

		if (ret) {
			sock_release(sock);
			pr_debug("ha_tcp: connect to %s:%u failed: %d (retry in %lu ms)\n",
				 peer, port, ret, delay_ms);
			goto backoff;
		}

		ha_tcp_on_connected(sock);
		delay_ms = LIO_HA_CONNECT_BACKOFF_INIT;
		continue;

backoff:
		schedule_timeout_interruptible(msecs_to_jiffies(delay_ms));
		delay_ms = min(delay_ms * 2, (unsigned long)LIO_HA_CONNECT_BACKOFF_MAX);
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

u64 lio_ha_tcp_generation(void)
{
	return atomic64_read(&ha_conn_gen);
}

int lio_ha_tcp_send(enum lio_ha_channel chan, const void *payload, u32 len)
{
	return lio_ha_tcp_send_gen(chan, payload, len, 0);
}

/*
 * Send one message whose payload is @p1 followed by @p2 (either may be
 * empty), on the connection of generation @gen (0: whichever is up).
 * Called with ha_send_lock held.
 */
static int __ha_tcp_send(enum lio_ha_channel chan, const void *p1, u32 l1,
			 const void *p2, u32 l2, u64 gen)
{
	struct lio_ha_wire_hdr hdr = {
		.magic   = cpu_to_be32(LIO_HA_WIRE_MAGIC),
		.version = cpu_to_be16(LIO_HA_WIRE_VERSION),
		.channel = cpu_to_be16(chan),
		.length  = cpu_to_be32(l1 + l2),
	};
	struct socket *sock;
	int ret = -ENOTCONN;

	lockdep_assert_held(&ha_send_lock);

	/*
	 * Read ha_conn_sock with ha_send_lock held.  The socket may be
	 * disconnected after we drop ha_tcp_lock, but whoever clears
	 * ha_conn_sock waits for ha_send_lock before sock_release() (see
	 * ha_tcp_on_disconnected), so the pointer stays valid until our
	 * caller drops ha_send_lock.
	 */
	mutex_lock(&ha_tcp_lock);
	sock = ha_conn_sock;
	/* A later connection than the caller's: refuse, as if down. */
	if (gen && gen != atomic64_read(&ha_conn_gen))
		sock = NULL;
	mutex_unlock(&ha_tcp_lock);

	if (sock) {
		ret = ha_tcp_send_full(sock, &hdr, sizeof(hdr));
		if (!ret && l1)
			ret = ha_tcp_send_full(sock, p1, l1);
		if (!ret && l2)
			ret = ha_tcp_send_full(sock, p2, l2);
		/*
		 * A failed send may have written part of the message, and
		 * the stream can no longer be framed: close the connection.
		 * The rx thread sees it and runs the disconnect handling.
		 */
		if (ret) {
			pr_warn_ratelimited("ha_tcp: send failed (%d), closing the connection\n",
					    ret);
			kernel_sock_shutdown(sock, SHUT_RDWR);
		}
	}
	return ret;
}

int lio_ha_tcp_send_gen(enum lio_ha_channel chan, const void *payload,
			u32 len, u64 gen)
{
	int ret;

	mutex_lock(&ha_send_lock);
	ret = __ha_tcp_send(chan, payload, len, NULL, 0, gen);
	mutex_unlock(&ha_send_lock);
	return ret;
}

int lio_ha_tcp_send_data(u64 cookie, struct scatterlist *sg,
			 unsigned int nents, u32 total, u64 gen)
{
	u32 off = 0;

	while (off < total) {
		u32 n = min_t(u32, LIO_HA_DATA_CHUNK, total - off);
		struct lio_ha_data_hdr dhdr = {
			.cmd_cookie = cpu_to_be64(cookie),
			.total_len  = cpu_to_be32(total),
			.offset     = cpu_to_be32(off),
		};
		int ret;

		/*
		 * The lock is taken per chunk, so other messages can go out
		 * between the chunks of a large transfer.
		 */
		mutex_lock(&ha_send_lock);
		/* Cleared under ha_send_lock by lio_ha_tcp_exit(). */
		if (!ha_send_bounce) {
			mutex_unlock(&ha_send_lock);
			return -ENOTCONN;
		}
		if (sg_pcopy_to_buffer(sg, nents, ha_send_bounce, n, off) != n) {
			/* Nothing of this chunk was sent: the stream is fine. */
			mutex_unlock(&ha_send_lock);
			WARN_ONCE(1, "ha_tcp: data shorter than %u bytes\n", total);
			return -EIO;
		}
		ret = __ha_tcp_send(LIO_HA_CHAN_DATA, &dhdr, sizeof(dhdr),
				    ha_send_bounce, n, gen);
		mutex_unlock(&ha_send_lock);
		if (ret)
			return ret;
		off += n;
	}
	return 0;
}

void lio_ha_tcp_register_data_handler(void (*handler)(u64 cookie, void *data, u32 data_len))
{
	data_handler_fn = handler;
}

void lio_ha_tcp_register_disconnect_handler(void (*handler)(void))
{
	int i;

	for (i = 0; i < HA_TCP_MAX_DISCONNECT_HANDLERS; i++) {
		if (!disconnect_handler_fns[i]) {
			disconnect_handler_fns[i] = handler;
			return;
		}
	}
	WARN(1, "ha_tcp: no free disconnect handler slot\n");
}

void lio_ha_tcp_register_connect_handler(void (*handler)(void))
{
	connect_handler_fn = handler;
}

void lio_ha_tcp_register_ctl_handler(u32 msg_type,
				     void (*handler)(const void *buf,
						     size_t len))
{
	if (msg_type < _LIO_HA_MSG_MAX)
		ctl_handlers[msg_type] = handler;
}

int lio_ha_tcp_init(void)
{
	ha_send_bounce = kvmalloc(LIO_HA_DATA_CHUNK, GFP_KERNEL);
	if (!ha_send_bounce)
		return -ENOMEM;

	/*
	 * Each channel thread can return on its own, e.g. when bind() or
	 * listen() fails, and a kthread that has returned is freed unless
	 * someone holds a reference.  lio_ha_tcp_exit() calls kthread_stop()
	 * on these pointers whether or not the thread is still running, so
	 * hold a reference on each task for as long as the pointer is kept.
	 *
	 * The reference is taken between kthread_create() and
	 * wake_up_process() because kthread_run() could let the thread run
	 * to completion, and be freed, before get_task_struct() is called.
	 */
	ha_listen_task = kthread_create(ha_tcp_listen_fn, NULL, "lio_ha_listen");
	if (IS_ERR(ha_listen_task)) {
		int err = PTR_ERR(ha_listen_task);

		pr_err("ha_tcp: failed to start listen thread: %d\n", err);
		ha_listen_task = NULL;
		kvfree(ha_send_bounce);
		ha_send_bounce = NULL;
		return err;
	}
	get_task_struct(ha_listen_task);
	wake_up_process(ha_listen_task);

	ha_connect_task = kthread_create(ha_tcp_connect_fn, NULL, "lio_ha_connect");
	if (IS_ERR(ha_connect_task)) {
		int err = PTR_ERR(ha_connect_task);

		pr_err("ha_tcp: failed to start connect thread: %d\n", err);
		ha_connect_task = NULL;
		kthread_stop(ha_listen_task);
		put_task_struct(ha_listen_task);
		ha_listen_task = NULL;
		kvfree(ha_send_bounce);
		ha_send_bounce = NULL;
		return err;
	}
	get_task_struct(ha_connect_task);
	wake_up_process(ha_connect_task);

	pr_debug("ha_tcp: channel threads started\n");
	return 0;
}

void lio_ha_tcp_exit(void)
{
	struct task_struct *task;
	struct ha_tcp_rx *rxs;
	struct socket *sock;
	void *bounce;

	atomic_set(&ha_tcp_stopping, 1);

	/*
	 * Shut down active sockets to unblock any threads currently blocked
	 * in kernel_accept / kernel_recvmsg / kernel_connect.
	 */
	mutex_lock(&ha_tcp_lock);
	if (ha_conn_sock)
		kernel_sock_shutdown(ha_conn_sock, SHUT_RDWR);
	if (ha_listen_sock)
		kernel_sock_shutdown(ha_listen_sock, SHUT_RDWR);
	if (ha_connecting_sock)
		kernel_sock_shutdown(ha_connecting_sock, SHUT_RDWR);
	mutex_unlock(&ha_tcp_lock);

	/*
	 * Stop listen and connect threads.  A thread that already returned
	 * on its own is still a valid task here because of the reference
	 * taken in lio_ha_tcp_init(); kthread_stop() then just returns its
	 * exit code.  Drop the reference once the thread is stopped.
	 */
	if (ha_listen_task) {
		kthread_stop(ha_listen_task);
		put_task_struct(ha_listen_task);
		ha_listen_task = NULL;
	}
	if (ha_connect_task) {
		kthread_stop(ha_connect_task);
		put_task_struct(ha_connect_task);
		ha_connect_task = NULL;
	}

	/*
	 * Join the rx thread.  The socket shutdown above unblocks its
	 * kernel_recvmsg(); it runs ha_tcp_on_disconnected(), which releases
	 * the socket, and returns.  The listen and connect threads are
	 * stopped, so no new rx thread can start.
	 */
	mutex_lock(&ha_tcp_lock);
	task = ha_rx_task;
	rxs  = ha_rx_state;
	ha_rx_task  = NULL;
	ha_rx_state = NULL;
	mutex_unlock(&ha_tcp_lock);
	if (task) {
		/* -EINTR: stopped before it ran, so it did not free its state. */
		if (kthread_stop(task) == -EINTR)
			ha_tcp_rx_free(rxs);
		put_task_struct(task);
	}

	/* Release any remaining socket: none, once the rx thread is joined. */
	mutex_lock(&ha_tcp_lock);
	sock = ha_conn_sock;
	ha_conn_sock = NULL;
	mutex_unlock(&ha_tcp_lock);
	if (sock) {
		mutex_lock(&ha_send_lock);	/* as ha_tcp_on_disconnected() */
		mutex_unlock(&ha_send_lock);
		sock_release(sock);
	}

	mutex_lock(&ha_send_lock);
	bounce = ha_send_bounce;
	ha_send_bounce = NULL;
	mutex_unlock(&ha_send_lock);
	kvfree(bounce);

	atomic_set(&ha_tcp_stopping, 0);
	pr_debug("ha_tcp: channel stopped\n");
}
