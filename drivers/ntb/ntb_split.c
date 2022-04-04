// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)

/*
 * PCIe NTB Resource Split driver.
 */

#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "linux/ntb.h"

#define NTB_SPLIT_VER	"1"
#define NTB_SPLIT_NAME	"ntb_split"
#define NTB_SPLIT_DESC	"NTB Resource Split driver"

MODULE_DESCRIPTION(NTB_SPLIT_DESC);
MODULE_VERSION(NTB_SPLIT_VER);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Alexander Motin <mav@ixsystems.com>");

static char *config;
module_param(config, charp, 0);
MODULE_PARM_DESC(config, "Configuration of child devices");

struct ntb_child {
	struct ntb_dev	dev;
	int		function;
	int		enabled;
	int		mwoff;
	int		mwcnt;
	int		spadoff;
	int		spadcnt;
	int		dboff;
	int		dbcnt;
	uint64_t	dbmask;
	struct ntb_child *first;
	struct ntb_child *next;
};

#define ntb_child(__ntb) \
	container_of(__ntb, struct ntb_child, dev)

#define ntb_parent(__ntb) \
	dev_ntb((__ntb)->dev.parent)

static void ntb_split_link_event(void *ctx)
{
	struct ntb_dev *ntb = ctx;
	struct ntb_child *nc;
	enum ntb_speed speed;
	enum ntb_width width;

	if (ntb_link_is_up(ntb, &speed, &width)) {
		dev_info(&ntb->dev, "Link is up (PCIe %d.x / x%d)\n",
		    (int)speed, (int)width);
	} else {
		dev_info(&ntb->dev, "Link is down\n");
	}
	for (nc = dev_get_drvdata(&ntb->dev); nc != NULL; nc = nc->next)
		ntb_link_event(&nc->dev);
}

static void ntb_split_db_event(void *ctx, int vec)
{
	struct ntb_dev *ntb = ctx;
	struct ntb_child *nc;

	for (nc = dev_get_drvdata(&ntb->dev); nc != NULL; nc = nc->next)
		ntb_db_event(&nc->dev, vec);
}

static const struct ntb_ctx_ops ntb_split_ops = {
	.link_event = ntb_split_link_event,
	.db_event = ntb_split_db_event,
};

static int ntb_split_port_number(struct ntb_dev *ntb)
{
	return ntb_port_number(ntb_parent(ntb));
}

static int ntb_split_peer_port_count(struct ntb_dev *ntb)
{
	return ntb_peer_port_count(ntb_parent(ntb));
}

static int ntb_split_peer_port_number(struct ntb_dev *ntb, int pidx)
{
	return ntb_peer_port_number(ntb_parent(ntb), pidx);
}

static int ntb_split_peer_port_idx(struct ntb_dev *ntb, int port)
{
	return ntb_peer_port_idx(ntb_parent(ntb), port);
}

static u64 ntb_split_link_is_up(struct ntb_dev *ntb, enum ntb_speed *speed,
    enum ntb_width *width)
{
	return ntb_link_is_up(ntb_parent(ntb), speed, width);
}

static int ntb_split_link_enable(struct ntb_dev *ntb, enum ntb_speed max_speed,
    enum ntb_width max_width)
{
	struct ntb_child *nc = ntb_child(ntb), *nc1;

	for (nc1 = nc->first; nc1 != NULL; nc1 = nc1->next) {
		if (nc1->enabled) {
			nc->enabled = 1;
			return (0);
		}
	}
	nc->enabled = 1;
	return ntb_link_enable(ntb_parent(ntb), max_speed, max_width);
}

static int ntb_split_link_disable(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb), *nc1;

	if (!nc->enabled)
		return (0);
	nc->enabled = 0;
	for (nc1 = nc->first; nc1 != NULL; nc1 = nc1->next) {
		if (nc1->enabled)
			return (0);
	}
	return ntb_link_disable(ntb_parent(ntb));
}

static int ntb_split_mw_count(struct ntb_dev *ntb, int pidx)
{
	struct ntb_child *nc = ntb_child(ntb);

	return min(nc->mwcnt,
	    max(0, ntb_mw_count(ntb_parent(ntb), pidx) - nc->mwoff));
}

static int ntb_split_mw_get_align(struct ntb_dev *ntb, int pidx, int widx,
    resource_size_t *addr_align, resource_size_t *size_align,
    resource_size_t *size_max)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_mw_get_align(ntb_parent(ntb), pidx, widx + nc->mwoff,
	    addr_align, size_align, size_max);
}

static int ntb_split_mw_set_trans(struct ntb_dev *ntb, int pidx, int widx,
    dma_addr_t addr, resource_size_t size)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_mw_set_trans(ntb_parent(ntb), pidx, widx + nc->mwoff,
	    addr, size);
}

static int ntb_split_mw_clear_trans(struct ntb_dev *ntb, int pidx, int widx)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_mw_clear_trans(ntb_parent(ntb), pidx, widx + nc->mwoff);
}

static int ntb_split_peer_mw_count(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb);

	return min(nc->mwcnt,
	    max(0, ntb_peer_mw_count(ntb_parent(ntb)) - nc->mwoff));
}

static int ntb_split_peer_mw_get_addr(struct ntb_dev *ntb, int widx,
    phys_addr_t *base, resource_size_t *size)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_mw_get_addr(ntb_parent(ntb), widx + nc->mwoff,
	    base, size);
}

static int ntb_split_peer_mw_set_trans(struct ntb_dev *ntb, int pidx, int widx,
    u64 addr, resource_size_t size)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_mw_set_trans(ntb_parent(ntb), pidx, widx + nc->mwoff,
	    addr, size);
}

static int ntb_split_peer_mw_clear_trans(struct ntb_dev *ntb, int pidx, int widx)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_mw_clear_trans(ntb_parent(ntb), pidx, widx + nc->mwoff);
}

static int ntb_split_db_is_unsafe(struct ntb_dev *ntb)
{
	return ntb_db_is_unsafe(ntb_parent(ntb));
}

static u64 ntb_split_db_valid_mask(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb);

	return (ntb_db_valid_mask(ntb_parent(ntb)) >> nc->dboff) & nc->dbmask;
}

static int ntb_split_db_vector_count(struct ntb_dev *ntb)
{
	return ntb_db_vector_count(ntb_parent(ntb));
}

static u64 ntb_split_db_vector_mask(struct ntb_dev *ntb, int db_vector)
{
	struct ntb_child *nc = ntb_child(ntb);

	return (ntb_db_vector_mask(ntb_parent(ntb), db_vector) >> nc->dboff) &
	    nc->dbmask;
}

static u64 ntb_split_db_read(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb);

	return (ntb_db_read(ntb_parent(ntb)) >> nc->dboff) & nc->dbmask;
}

static int ntb_split_db_set(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_db_set(ntb_parent(ntb), db_bits << nc->dboff);
}

static int ntb_split_db_clear(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_db_clear(ntb_parent(ntb), db_bits << nc->dboff);
}

static u64 ntb_split_db_read_mask(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb);

	return (ntb_db_read_mask(ntb_parent(ntb)) >> nc->dboff) & nc->dbmask;
}

static int ntb_split_db_set_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_db_set_mask(ntb_parent(ntb), db_bits << nc->dboff);
}

static int ntb_split_db_clear_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_db_clear_mask(ntb_parent(ntb), db_bits << nc->dboff);
}

static int ntb_split_peer_db_addr(struct ntb_dev *ntb, phys_addr_t *db_addr,
    resource_size_t *db_size, u64 *db_data, int db_bit)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_db_addr(ntb_parent(ntb), db_addr, db_size, db_data,
	    db_bit + nc->dboff);
}

static u64 ntb_split_peer_db_read(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb);

	return (ntb_peer_db_read(ntb_parent(ntb)) >> nc->dboff) & nc->dbmask;
}

static int ntb_split_peer_db_set(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_db_set(ntb_parent(ntb), db_bits << nc->dboff);
}

static int ntb_split_peer_db_clear(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_db_clear(ntb_parent(ntb), db_bits << nc->dboff);
}

static u64 ntb_split_peer_db_read_mask(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb);

	return (ntb_peer_db_read_mask(ntb_parent(ntb)) >> nc->dboff) & nc->dbmask;
}

static int ntb_split_peer_db_set_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_db_set_mask(ntb_parent(ntb), db_bits << nc->dboff);
}

static int ntb_split_peer_db_clear_mask(struct ntb_dev *ntb, u64 db_bits)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_db_clear_mask(ntb_parent(ntb), db_bits << nc->dboff);
}

static int ntb_split_spad_is_unsafe(struct ntb_dev *ntb)
{
	return ntb_spad_is_unsafe(ntb_parent(ntb));
}

static int ntb_split_spad_count(struct ntb_dev *ntb)
{
	struct ntb_child *nc = ntb_child(ntb);

	return min(nc->spadcnt,
	    max(0, ntb_spad_count(ntb_parent(ntb)) - nc->spadoff));
}

static u32 ntb_split_spad_read(struct ntb_dev *ntb, int sidx)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_spad_read(ntb_parent(ntb), sidx + nc->spadoff);
}

static int ntb_split_spad_write(struct ntb_dev *ntb, int sidx, u32 val)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_spad_write(ntb_parent(ntb), sidx + nc->spadoff, val);
}

static int ntb_split_peer_spad_addr(struct ntb_dev *ntb, int pidx, int sidx,
    phys_addr_t *spad_addr)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_spad_addr(ntb_parent(ntb), pidx, sidx + nc->spadoff,
	    spad_addr);
}

static u32 ntb_split_peer_spad_read(struct ntb_dev *ntb, int pidx, int sidx)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_spad_read(ntb_parent(ntb), pidx, sidx + nc->spadoff);
}

static int ntb_split_peer_spad_write(struct ntb_dev *ntb, int pidx, int sidx,
    u32 val)
{
	struct ntb_child *nc = ntb_child(ntb);

	return ntb_peer_spad_write(ntb_parent(ntb), pidx, sidx + nc->spadoff,
	    val);
}

static const struct ntb_dev_ops ntb_split_dev_ops = {
	.port_number = ntb_split_port_number,
	.peer_port_count = ntb_split_peer_port_count,
	.peer_port_number = ntb_split_peer_port_number,
	.peer_port_idx = ntb_split_peer_port_idx,
	.link_is_up = ntb_split_link_is_up,
	.link_enable = ntb_split_link_enable,
	.link_disable = ntb_split_link_disable,
	.mw_count = ntb_split_mw_count,
	.mw_get_align = ntb_split_mw_get_align,
	.mw_set_trans = ntb_split_mw_set_trans,
	.mw_clear_trans = ntb_split_mw_clear_trans,
	.peer_mw_count = ntb_split_peer_mw_count,
	.peer_mw_get_addr = ntb_split_peer_mw_get_addr,
	.peer_mw_set_trans = ntb_split_peer_mw_set_trans,
	.peer_mw_clear_trans = ntb_split_peer_mw_clear_trans,
	.db_is_unsafe = ntb_split_db_is_unsafe,
	.db_valid_mask = ntb_split_db_valid_mask,
	.db_vector_count = ntb_split_db_vector_count,
	.db_vector_mask = ntb_split_db_vector_mask,
	.db_read = ntb_split_db_read,
	.db_set = ntb_split_db_set,
	.db_clear = ntb_split_db_clear,
	.db_read_mask = ntb_split_db_read_mask,
	.db_set_mask = ntb_split_db_set_mask,
	.db_clear_mask = ntb_split_db_clear_mask,
	.peer_db_addr = ntb_split_peer_db_addr,
	.peer_db_read = ntb_split_peer_db_read,
	.peer_db_set = ntb_split_peer_db_set,
	.peer_db_clear = ntb_split_peer_db_clear,
	.peer_db_read_mask = ntb_split_peer_db_read_mask,
	.peer_db_set_mask = ntb_split_peer_db_set_mask,
	.peer_db_clear_mask = ntb_split_peer_db_clear_mask,
	.spad_is_unsafe = ntb_split_spad_is_unsafe,
	.spad_count = ntb_split_spad_count,
	.spad_read = ntb_split_spad_read,
	.spad_write = ntb_split_spad_write,
	.peer_spad_addr = ntb_split_peer_spad_addr,
	.peer_spad_read = ntb_split_peer_spad_read,
	.peer_spad_write = ntb_split_peer_spad_write,
};

static int ntb_split_probe(struct ntb_client *client, struct ntb_dev *ntb)
{
	struct ntb_child *cp = NULL, *fcp = NULL, **cpp = &cp, *nc;
	int ret, i, l, mw, mwu, mwt, spad, spadu, spadt, db, dbu, dbt;
	char *cfg, *n, *np, *p, *name;
	char buf[128];

	if (!config)
		return -EINVAL;
	cfg = kstrdup(config, GFP_KERNEL);
	if (!cfg)
		return -ENOMEM;

	mwu = 0;
	mwt = ntb_mw_count(ntb, 0);
	spadu = 0;
	spadt = ntb_spad_count(ntb);
	dbu = 0;
	dbt = fls64(ntb_db_valid_mask(ntb));
	dev_info(&ntb->dev, "%d memory windows, %d scratchpads, "
	    "%d doorbells\n", mwt, spadt, dbt);

	ret = ntb_set_ctx(ntb, ntb, &ntb_split_ops);
	if (ret) {
		kfree(cfg);
		return ret;
	}

	n = cfg;
	i = 0;
	while ((np = strsep(&n, ",")) != NULL) {
		name = strsep(&np, ":");
		if (name && name[0] == 0)
			name = NULL;
		p = strsep(&np, ":");
		if (p && p[0] != 0) {
			if (kstrtoint(p, 10, &mw)) {
				dev_warn(&ntb->dev, "Can't parse mw '%s'\n", p);
				mw = 0;
			}
		} else {
			mw = mwt - mwu;
		}
		p = strsep(&np, ":");
		if (p && p[0] != 0) {
			if (kstrtoint(p, 10, &spad)) {
				dev_warn(&ntb->dev, "Can't parse spad '%s'\n", p);
				spad = 0;
			}
		} else {
			spad = spadt - spadu;
		}
		if (np && np[0] != 0) {
			if (kstrtoint(np, 10, &db)) {
				dev_warn(&ntb->dev, "Can't parse db '%s'\n", np);
				db = 0;
			}
		} else {
			db = dbt - dbu;
		}

		if (mw > mwt - mwu || spad > spadt - spadu || db > dbt - dbu) {
			dev_warn(&ntb->dev, "Not enough resources for config\n");
			break;
		}

		l = 0;
		buf[0] = 0;
		if (mw > 1)
			l += sprintf(buf + l, " memory windows %d-%d", mwu, mwu + mw - 1);
		else if (mw > 0)
			l += sprintf(buf + l, " memory window %d", mwu);
		if (spad > 1)
			l += sprintf(buf + l, " scratchpads %d-%d", spadu, spadu + spad - 1);
		else if (spad > 0)
			l += sprintf(buf + l, " scratchpad %d", spadu);
		if (db > 1)
			l += sprintf(buf + l, " doorbells %d-%d", dbu, dbu + db - 1);
		else if (db > 0)
			l += sprintf(buf + l, " doorbell %d", dbu);
		dev_info(&ntb->dev, "%d \"%s\":%s\n", i, name, buf);

		nc = devm_kzalloc(&ntb->dev, sizeof(*nc), GFP_KERNEL);
		if (!nc) {
			dev_warn(&ntb->dev, "Can't allocate child memory\n");
			break;
		}
		if (!fcp) {
			fcp = nc;
			dev_set_drvdata(&ntb->dev, fcp);
		}

		nc->function = i;
		nc->mwoff = mwu;
		nc->mwcnt = mw;
		nc->spadoff = spadu;
		nc->spadcnt = spad;
		nc->dboff = dbu;
		nc->dbcnt = db;
		nc->dbmask = (db == 0) ? 0 : (0xffffffffffffffff >> (64 - db));
		nc->first = fcp;

		nc->dev.dev.parent = &ntb->dev;
		dev_set_name(&nc->dev.dev, "%s-%d", dev_name(&ntb->dev), i);
		nc->dev.pdev = ntb->pdev;
		nc->dev.topo = ntb->topo;
		nc->dev.ops = &ntb_split_dev_ops;
		if (name)
			nc->dev.driver_override = kstrdup(name, GFP_KERNEL);
		ret = ntb_register_device(&nc->dev);
		if (ret) {
			dev_warn(&ntb->dev, "Can't register child device\n");
			break;
		}
		*cpp = nc;
		cpp = &nc->next;

		mwu += mw;
		spadu += spad;
		dbu += db;
		i++;
	}
	kfree(cfg);

	return 0;
}

static void ntb_split_remove(struct ntb_client *client, struct ntb_dev *ntb)
{
	struct ntb_child *nc;

	for (nc = dev_get_drvdata(&ntb->dev); nc != NULL; nc = nc->next)
		ntb_unregister_device(&nc->dev);

	ntb_link_disable(ntb);
	ntb_db_set_mask(ntb, ntb_db_valid_mask(ntb));
	ntb_clear_ctx(ntb);
}

static struct ntb_client ntb_split_client = {
	.ops = {
		.probe = ntb_split_probe,
		.remove = ntb_split_remove,
	},
};

static int __init ntb_split_init(void)
{
	int ret;

	pr_info("%s, version %s\n", NTB_SPLIT_DESC, NTB_SPLIT_VER);

	ret = ntb_register_client(&ntb_split_client);
	if (ret)
		return ret;

	return 0;
}
module_init(ntb_split_init);

static void __exit ntb_split_exit(void)
{

	ntb_unregister_client(&ntb_split_client);
}
module_exit(ntb_split_exit);
