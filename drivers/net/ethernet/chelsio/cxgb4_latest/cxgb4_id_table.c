/*
 * Copyright (c) 2011-2025 Chelsio Communications.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include "cxgb4_rdma_resource.h"

#define CXGB4_RANDOM_SKIP 16

/*
 * Trivial bitmap-based allocator. If the random flag is set, the
 * allocator is designed to:
 * - pseudo-randomize the id returned such that it is not trivially predictable.
 * - avoid reuse of recently used id (at the expense of predictability)
 */
u32 cxgb4_alloc_id(struct cxgb4_id_table *alloc)
{
	unsigned long flags;
	u32 obj;

	spin_lock_irqsave(&alloc->lock, flags);

	obj = find_next_zero_bit(alloc->table, alloc->max, alloc->last);
	if (obj >= alloc->max)
		obj = find_first_zero_bit(alloc->table, alloc->max);

	if (obj < alloc->max) {
		if (alloc->flags & CXGB4_ID_TABLE_F_RANDOM)
			alloc->last += get_random_u32() % CXGB4_RANDOM_SKIP;
		else
			alloc->last = obj + 1;

		if (alloc->last >= alloc->max)
			alloc->last = 0;

		set_bit(obj, alloc->table);
		obj += alloc->start;
	} else {
		obj = -1;
	}

	spin_unlock_irqrestore(&alloc->lock, flags);
	return obj;
}

void cxgb4_free_id(struct cxgb4_id_table *alloc, u32 obj)
{
	unsigned long flags;

	obj -= alloc->start;

	spin_lock_irqsave(&alloc->lock, flags);
	clear_bit(obj, alloc->table);
	spin_unlock_irqrestore(&alloc->lock, flags);
}

int cxgb4_uld_alloc_id_table(struct cxgb4_id_table *alloc, u32 start, u32 num,
			     u32 reserved, u32 flags)
{
	int i;

	alloc->start = start;
	alloc->flags = flags;
	if (flags & CXGB4_ID_TABLE_F_RANDOM)
		alloc->last = get_random_u32() % CXGB4_RANDOM_SKIP;
	else
		alloc->last = 0;

	alloc->max  = num;
	spin_lock_init(&alloc->lock);
	alloc->table = kmalloc(BITS_TO_LONGS(num) * sizeof(long), GFP_KERNEL);
	if (!alloc->table)
		return -ENOMEM;

	bitmap_zero(alloc->table, num);
	if (!(alloc->flags & CXGB4_ID_TABLE_F_EMPTY)) {
		for (i = 0; i < reserved; ++i)
			set_bit(i, alloc->table);
	}

	return 0;
}
EXPORT_SYMBOL(cxgb4_uld_alloc_id_table);

void cxgb4_uld_free_id_table(struct cxgb4_id_table *alloc)
{
	kfree(alloc->table);
}
EXPORT_SYMBOL(cxgb4_uld_free_id_table);
