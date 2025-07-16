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

/*
 *      Definitions and inline functions for the T4 trace buffers.
 *
 *      Authors:
 *              Felix Marti <felix@chelsio.com>
 */

#ifndef __T4_TRACE_H__
#define __T4_TRACE_H__

#ifdef T4_TRACE

#include <linux/time.h>
#include <linux/timex.h>

#define T4_TRACE_NUM_PARAM 6

typedef unsigned long tracearg_t;

#define T4_TRACE0(b, s) \
	if ((b) != NULL) \
		(void) t4_trace((b), (s));
#define	T4_TRACE1(b, s, p0) \
	if ((b) != NULL) { \
		tracearg_t *_p = t4_trace((b), (s)); \
		_p[0] = (tracearg_t) (p0); \
	}
#define T4_TRACE2(b, s, p0, p1) \
	if ((b) != NULL) { \
		tracearg_t *_p = t4_trace((b), (s)); \
		_p[0] = (tracearg_t) (p0); \
		_p[1] = (tracearg_t) (p1); \
	}
#define T4_TRACE3(b, s, p0, p1, p2) \
	if ((b) != NULL) { \
		tracearg_t *_p = t4_trace((b), (s)); \
		_p[0] = (tracearg_t) (p0); \
		_p[1] = (tracearg_t) (p1); \
		_p[2] = (tracearg_t) (p2); \
	}
#define T4_TRACE4(b, s, p0, p1, p2, p3) \
	if ((b) != NULL) { \
		tracearg_t *_p = t4_trace((b), (s)); \
		_p[0] = (tracearg_t) (p0); \
		_p[1] = (tracearg_t) (p1); \
		_p[2] = (tracearg_t) (p2); \
		_p[3] = (tracearg_t) (p3); \
	}
#define T4_TRACE5(b, s, p0, p1, p2, p3, p4) \
	if ((b) != NULL) { \
		tracearg_t *_p = t4_trace((b), (s)); \
		_p[0] = (tracearg_t) (p0); \
		_p[1] = (tracearg_t) (p1); \
		_p[2] = (tracearg_t) (p2); \
		_p[3] = (tracearg_t) (p3); \
		_p[4] = (tracearg_t) (p4); \
	}
#define T4_TRACE6(b, s, p0, p1, p2, p3, p4, p5) \
	if ((b) != NULL) { \
		tracearg_t *_p = t4_trace((b), (s)); \
		_p[0] = (tracearg_t) (p0); \
		_p[1] = (tracearg_t) (p1); \
		_p[2] = (tracearg_t) (p2); \
		_p[3] = (tracearg_t) (p3); \
		_p[4] = (tracearg_t) (p4); \
		_p[5] = (tracearg_t) (p5); \
	}

struct trace_entry {
	cycles_t   tsc;
	char      *fmt;
	tracearg_t param[T4_TRACE_NUM_PARAM];
};

struct dentry;

struct trace_buf {
	unsigned int capacity;          /* size of ring buffer */
	unsigned int idx;               /* index of next entry to write */
	struct dentry *debugfs_dentry;
	struct trace_entry ep[];       /* the ring buffer */
};

static inline unsigned long *t4_trace(struct trace_buf *tb, char *fmt)
{
	struct trace_entry *ep = &tb->ep[tb->idx++ & (tb->capacity - 1)];

	ep->fmt = fmt;
	ep->tsc = get_cycles();

	return (unsigned long *) &ep->param[0];
}

struct trace_buf *t4_trace_alloc(struct dentry *root, const char *name,
			      unsigned int capacity);
void t4_trace_free(struct trace_buf *tb);

#else
#define T4_TRACE0(b, s)
#define T4_TRACE1(b, s, p0)
#define T4_TRACE2(b, s, p0, p1)
#define T4_TRACE3(b, s, p0, p1, p2)
#define T4_TRACE4(b, s, p0, p1, p2, p3)
#define T4_TRACE5(b, s, p0, p1, p2, p3, p4)
#define T4_TRACE6(b, s, p0, p1, p2, p3, p4, p5)

#define t4_trace_alloc(root, name, capacity) NULL
#define t4_trace_free(tb)
#endif

#endif /* __T4_TRACE_H__ */
