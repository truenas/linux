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
 *      Routines to allocate and free T4 trace buffers.
 *
 *      Authors:
 *              Felix Marti <felix@chelsio.com>
 *
 *      The code suffers from a trace buffer count increment race, which might
 *      lead to entries being overwritten. I don't really care about this,
 *      because the trace buffer is a simple debug/perfomance tuning aid.
 *
 *      Trace buffers are created in /proc, which needs to be fixed.
 */

#include "trace.h"

#ifdef T4_TRACE
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/log2.h>
#include <linux/slab.h>

/*
 * SEQ OPS
 */
static void *t4_trace_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct trace_buf *tb = seq->private;
	struct trace_entry *e = NULL;
	unsigned int start, count;

	if (tb->idx > tb->capacity) {
		start = tb->idx & (tb->capacity - 1);
		count = tb->capacity;
	} else {
		start = 0;
		count = tb->idx;
	}

	if (*pos < count)
		e = &tb->ep[(start + *pos) & (tb->capacity - 1)];

	return e;
}

static void *t4_trace_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct trace_buf *tb = seq->private;
	struct trace_entry *e = v;
	unsigned int count = min(tb->idx, tb->capacity);

	if (++*pos < count) {
		e++;
		if (e >= &tb->ep[tb->capacity])
			e = tb->ep;
	} else
		e = NULL;

	return e;
}

static void t4_trace_seq_stop(struct seq_file *seq, void *v)
{
}

static int t4_trace_seq_show(struct seq_file *seq, void *v)
{
	struct trace_entry *ep = v;

	seq_printf(seq, "%016llx ", (unsigned long long) ep->tsc);
	seq_printf(seq, ep->fmt, ep->param[0], ep->param[1], ep->param[2],
		   ep->param[3], ep->param[4], ep->param[5]);
	seq_printf(seq, "\n");
	return 0;
}

static const struct seq_operations t4_trace_seq_ops = {
	.start = t4_trace_seq_start,
	.next  = t4_trace_seq_next,
	.stop  = t4_trace_seq_stop,
	.show  = t4_trace_seq_show
};

/*
 * FILE OPS
 */
static int t4_trace_seq_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &t4_trace_seq_ops);

	if (!rc) {
		struct seq_file *seq = file->private_data;

		seq->private = inode->i_private;
	}

	return rc;
}

static const struct file_operations t4_trace_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = t4_trace_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

/*
 * TRACEBUFFER API
 */
struct trace_buf *t4_trace_alloc(struct dentry *root, const char *name,
				 unsigned int capacity)
{
	struct trace_buf *tb;
	unsigned int size;

	if (!name || !is_power_of_2(capacity))
		return NULL;

	size = sizeof(*tb) + sizeof(struct trace_entry) * capacity;
	tb = kmalloc(size, GFP_KERNEL);
	if (!tb)
		return NULL;

	memset(tb, 0, size);
	tb->capacity = capacity;
	tb->debugfs_dentry = debugfs_create_file(name, S_IFREG | 0444, root, tb,
						 &t4_trace_seq_fops);
	if (!tb->debugfs_dentry) {
		kfree(tb);
		return NULL;
	}

	return tb;
}

void t4_trace_free(struct trace_buf *tb)
{
	if (tb) {
		if (tb->debugfs_dentry)
			debugfs_remove(tb->debugfs_dentry);
		kfree(tb);
	}
}
EXPORT_SYMBOL(t4_trace_alloc);
EXPORT_SYMBOL(t4_trace_free);
#endif /* T4_TRACE */
