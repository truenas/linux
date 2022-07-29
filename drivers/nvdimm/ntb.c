// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)

/*
 * PCIe NTB PMEM mirroring driver.
 */

#include <linux/async.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "linux/ntb.h"
#include <linux/libnvdimm.h>
#include "nd.h"
#include "pmem.h"

#define NTB_PMEM_VER	"1"
#define NTB_PMEM_NAME	"ntb_pmem"
#define NTB_PMEM_DESC	"NTB PMEM mirroring driver"

static unsigned long	start_timeout = 120;
module_param(start_timeout, ulong, 0644);
MODULE_PARM_DESC(start_timeout, "Synchronization wait timeout (seconds)");

MODULE_DESCRIPTION(NTB_PMEM_DESC);
MODULE_VERSION(NTB_PMEM_VER);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Alexander Motin <mav@ixsystems.com>");

/* Only two-ports NTB devices are supported */
#define PIDX		NTB_DEF_PEER_IDX

/* NTB PMEM device */
struct ntb_pmem {
	struct ntb_dev		*ndev;
	int			 id;
	struct pmem_device	*pmem;
	async_cookie_t		 wait;
	unsigned long		 wait_till;
	struct delayed_work	 link_work;
	struct work_struct	 link_cleanup;
	phys_addr_t		 ntb_paddr;	/* MW physical address */
	resource_size_t		 ntb_size;	/* MW size */
	void			*ntb_vaddr;	/* MW KVA address */
	phys_addr_t		 ntb_xalign;	/* XLAT address allignment */
	phys_addr_t		 ntb_xpaddr;	/* XLAT physical address */
	resource_size_t		 ntb_xsize;	/* XLAT size */
};

enum {
	NTBN_SIGN = 0,
	NTBN_SIZE_HIGH,
	NTBN_OFF_HIGH,
	NTBN_OFF_LOW,
};

#define MAX_PMEMS	4
static struct ntb_pmem_links {
	struct mutex lock;
	struct pmem_device *pmem;
	struct ntb_pmem *ntb;
} links[MAX_PMEMS];

static void ntb_pmem_sync(struct ntb_pmem *sc)
{
	struct ntb_dev *ndev = sc->ndev;
	struct pmem_device *pmem = sc->pmem;
	struct pmem_label *ll = pmem->label;
	struct pmem_label *rl = pmem->rlabel;
	long b;
	u32 state;
	int dir;

	if (rl == NULL || rl->sign != PMEM_SIGN_LONG) {
		dev_err(&ndev->dev, "Can't see label on other side.\n");
		return;
	}

	/* Decide direciton of copy. */
	dir = 0;
	if (rl->empty && !ll->empty) {
		dev_info(&ndev->dev, "Other side is empty.\n");
		dir = 1;
	} else if (ll->empty && !rl->empty) {
		dev_info(&ndev->dev, "Our side is empty.\n");
		dir = -1;
	} else if (rl->array != ll->array) {
		if (ll->empty && rl->empty)
			dev_info(&ndev->dev, "Both sides are empty.\n");
		else
			dev_notice(&ndev->dev, "Two different arrays!\n");
		if (ll->array > rl->array)
			dir = 1;	/* Forcefully sync l->r. */
		else
			dir = -1;	/* Forcefully sync r->l. */
	} else if (!ll->dirty && !rl->dirty) {
		dev_info(&ndev->dev, "Both sides are clean.\n");
	} else if (ll->opened && rl->opened) {
		dev_info(&ndev->dev, "Both sides are opened!\n");
	} else if (ll->opened) {
		dev_info(&ndev->dev, "Local side is opened.\n");
		dir = 1;
	} else if (rl->opened) {
		dev_info(&ndev->dev, "Remote side is opened.\n");
		dir = -1;
	} else if (ll->dirty) {
		dev_info(&ndev->dev, "Local side is dirty.\n");
		dir = 1;
	} else if (rl->dirty) {
		dev_info(&ndev->dev, "Remote side is dirty.\n");
		dir = -1;
	}

	/* Let the other side to get to the same conclusion. */
	smp_store_release(&ll->state, STATE_WAITING);
	while (((state = smp_load_acquire(&rl->state)) == STATE_NONE ||
	    state == STATE_IDLE) && pmem->rlabel != NULL)
		cpu_relax();

	/* Source side is copying, destination is waiting for it. */
	if (dir > 0) {
		dev_info(&ndev->dev, "Copying local to remote.\n");
		b = jiffies;
		memcpy(pmem->rvirt_addr, pmem->virt_addr,
		    pmem->size - PAGE_SIZE);
		b = max_t(long, jiffies - b, 1);
		dev_info(&ndev->dev, "Copied %zuMB at %zuMB/s\n",
		    pmem->size / 1024 / 1024,
		    pmem->size * HZ / 1024 / 1024 / b);
		rl->array = ll->array;
		rl->empty = ll->empty;
		rl->dirty = ll->dirty = 0;
		smp_store_release(&ll->state, STATE_READY);
		smp_store_release(&rl->state, STATE_READY);
		arch_wb_cache_pmem(ll, sizeof(struct pmem_label));
	} else if (dir < 0) {
		dev_info(&ndev->dev, "Waiting for remote to local copy.\n");
		while (smp_load_acquire(&rl->state) == STATE_WAITING &&
		    pmem->rlabel != NULL)
			cpu_relax();
		disk_force_media_change(pmem->disk);
	} else {
		dev_info(&ndev->dev, "No need to copy.\n");
		smp_store_release(&ll->state, STATE_READY);
	}
	dev_info(&ndev->dev, "Sync is done.\n");
}

static int ntb_pmem_set_trans(struct ntb_pmem *sc)
{
	struct ntb_dev *ndev = sc->ndev;
	struct pmem_device *pmem = sc->pmem;
	int error;

	/*
	 * Once NTB is connected, we can finally get the peer's required window
	 * alignment.  Depending on it and the pmem physical address the window
	 * may have to be up to twice bigger than pmem size to cover it.  If
	 * that is true, set up the translation address and size accordingly.
	 */
	error = ntb_mw_get_align(ndev, PIDX, 0, &sc->ntb_xalign, NULL, NULL);
	if (error != 0) {
		dev_err(&ndev->dev, "ntb_mw_get_align() error %d\n", error);
		return error;
	}
	sc->ntb_xpaddr = pmem->phys_addr & ~(sc->ntb_xalign - 1);
	sc->ntb_xsize = pmem->phys_addr - sc->ntb_xpaddr + pmem->size;
	if (sc->ntb_size < sc->ntb_xsize) {
		dev_err(&ndev->dev, "Memory window is too small (%pa < %pa).\n",
		    &sc->ntb_size, &sc->ntb_xsize);
		return -ENOMEM;
	} else if (sc->ntb_size < 2 * pmem->size) {
		dev_notice(&ndev->dev,
		    "Memory window may be too small (%pa < %zu).\n",
		    &sc->ntb_size, 2 * pmem->size);
	}
	error = ntb_mw_set_trans(ndev, PIDX, 0, sc->ntb_xpaddr, sc->ntb_xsize);
	if (error != 0) {
		dev_err(&ndev->dev, "ntb_mw_set_trans() error %d\n", error);
		return error;
	}
	return (0);
}

static void ntb_pmem_link_work(struct work_struct *work)
{
	struct ntb_pmem *sc = container_of(work, struct ntb_pmem,
	    link_work.work);
	struct ntb_dev *ndev = sc->ndev;
	struct pmem_device *pmem = sc->pmem;
	phys_addr_t off;
	u32 val;

	if (!sc->ntb_xsize && ntb_pmem_set_trans(sc))
		return;

	/*
	 * Report our parameters to the peer.  The most important is a pmem
	 * offset within the memory window due to its required alignment.
	 */
	off = pmem->phys_addr - sc->ntb_xpaddr;
	ntb_peer_spad_write(ndev, PIDX, NTBN_OFF_LOW, off & 0xffffffff);
	ntb_peer_spad_write(ndev, PIDX, NTBN_OFF_HIGH, off >> 32);
	ntb_peer_spad_write(ndev, PIDX, NTBN_SIZE_HIGH, pmem->size >> 32);
	ntb_peer_spad_write(ndev, PIDX, NTBN_SIGN, PMEM_SIGN_SHORT);

	/* Look for peer signature.  It is written last, but read first. */
	val = ntb_spad_read(ndev, NTBN_SIGN);
	if (val != PMEM_SIGN_SHORT)
		goto out;

	/* Approximately compare pmems sizes due to limited scratch space. */
	val = ntb_spad_read(ndev, NTBN_SIZE_HIGH);
	if (val != (pmem->size >> 32)) {
		dev_err(&ndev->dev, "PMEM sizes don't match (%u != %u)\n",
		    val << 2, (u32)(pmem->size >> 30));
		return;
	}

	/* Fetch pmem offset within peer's memory window. */
	val = ntb_spad_read(ndev, NTBN_OFF_HIGH);
	off = (phys_addr_t)val << 32;
	val = ntb_spad_read(ndev, NTBN_OFF_LOW);
	off |= val;

	dev_info(&ndev->dev, "Connection established\n");
	pmem->rphys_addr = sc->ntb_paddr + off;
	pmem->rvirt_addr = sc->ntb_vaddr + off;
	pmem->rlabel = (struct pmem_label *)(pmem->rvirt_addr + pmem->size -
	    PAGE_SIZE);

	ntb_pmem_sync(sc);
	return;
out:
	if (ntb_link_is_up(ndev, NULL, NULL))
		schedule_delayed_work(&sc->link_work, msecs_to_jiffies(100));
}

static void ntb_pmem_link_cleanup_work(struct work_struct *work)
{
	struct ntb_pmem *sc = container_of(work, struct ntb_pmem, link_cleanup);
	struct ntb_dev *ndev = sc->ndev;
	struct pmem_device *pmem = sc->pmem;

	cancel_delayed_work_sync(&sc->link_work);

	pmem->rphys_addr = 0;
	pmem->rvirt_addr = NULL;
	pmem->rlabel = NULL;
	if (pmem->label->state > STATE_IDLE)
		pmem->label->state = STATE_IDLE;

	ntb_mw_clear_trans(ndev, PIDX, 0);
	sc->ntb_xsize = 0;

	/*
	 * The scratchpad registers keep the values if the remote side
	 * goes down, blast them now to give them a sane value the next
	 * time they are accessed.
	 */
	ntb_spad_write(ndev, NTBN_SIGN, 0);
	ntb_spad_write(ndev, NTBN_SIZE_HIGH, 0);
	ntb_spad_write(ndev, NTBN_OFF_HIGH, 0);
	ntb_spad_write(ndev, NTBN_OFF_LOW, 0);
}

static void ntb_pmem_link_event(void *ctx)
{
	struct ntb_pmem *sc = ctx;
	struct ntb_dev *ndev = sc->ndev;
	enum ntb_speed speed;
	enum ntb_width width;

	if (ntb_link_is_up(ndev, &speed, &width)) {
		dev_info(&ndev->dev, "Link is up (PCIe %d.x / x%d)\n",
		    (int)speed, (int)width);
		schedule_delayed_work(&sc->link_work, 0);
	} else {
		dev_info(&ndev->dev, "Link is down\n");
		schedule_work(&sc->link_cleanup);
	}
}

static const struct ntb_ctx_ops ntb_pmem_ops = {
	.link_event = ntb_pmem_link_event,
};

static ASYNC_DOMAIN(ntb_pmem_async_domain);

static void ntb_pmem_wait(void *_data, async_cookie_t c)
{
	struct ntb_pmem *sc = _data;
	struct device *dev = &sc->ndev->dev;
	struct pmem_label *ll = sc->pmem->label;
	long left;
	int t = 50;
	u32 state;

	while ((state = smp_load_acquire(&ll->state)) == STATE_IDLE ||
	    state == STATE_WAITING) {
		left = sc->wait_till - jiffies;
		if (left <= 0) {
			dev_notice(dev, "Gave up waiting for NTB peer.\n");
			return;
		}
		if (t-- <= 0) {
			dev_info(dev, "Waiting for NTB peer to sync (%lds).\n",
			    left / HZ);
			/* Reschedule to not block queue for too long. */
			async_schedule_domain(ntb_pmem_wait, sc,
			    &ntb_pmem_async_domain);
			return;
		}
		msleep(100);
	}
}

static void ntb_pmem_attach(struct ntb_pmem *sc)
{
	struct ntb_dev *ndev = sc->ndev;
	struct pmem_device *pmem = sc->pmem;
	int error;

	pmem->rnode = dev_to_node(&ndev->dev);

	/*
	 * If the pmem was synchronized before, delay boot until the new
	 * synchronization complete or timeout expire.  It should reduce
	 * the race when both peers are powered on same time and the first
	 * booted may try to access stale data before hearing from another.
	 */
	sc->wait_till = jiffies + start_timeout * HZ;
	async_schedule_domain(ntb_pmem_wait, sc, &ntb_pmem_async_domain);

	/* Bring up the link. */
	error = ntb_set_ctx(ndev, sc, &ntb_pmem_ops);
	if (error != 0)
		dev_err(&ndev->dev, "ntb_set_ctx() error %d\n", error);
	error = ntb_link_enable(ndev, NTB_SPEED_AUTO, NTB_WIDTH_AUTO);
	if (error != 0)
		dev_err(&ndev->dev, "ntb_link_enable() error %d\n", error);
	ntb_link_event(ndev);
}

static void ntb_pmem_detach(struct ntb_pmem *sc)
{
	struct ntb_dev *ndev = sc->ndev;
	struct pmem_device *pmem = sc->pmem;

	ntb_link_disable(ndev);
	ntb_clear_ctx(ndev);
	cancel_work_sync(&sc->link_cleanup);
	ntb_pmem_link_cleanup_work(&sc->link_cleanup);

	if (pmem->label->state >= STATE_IDLE)
		pmem->label->state = STATE_READY;
	async_synchronize_full_domain(&ntb_pmem_async_domain);
}

void ntb_pmem_register(struct pmem_device *pmem)
{
	struct device *dev = pmem->bb.dev;
	struct nd_region *nd_region = to_nd_region(dev->parent);
	struct pmem_label *label;
	int id = nd_region->id;

	/*
	 * Associate the pmem with ntb_pmem using its region id, which are
	 * hoped to be sequential and have only one namespace each, since
	 * we attach only to raw namespaces, not using standard labels.
	 */
	if (id < 0 || id >= MAX_PMEMS)
		return;

	/* Reserve last page of NVDIMM for our custom label. */
	pmem->pfn_pad = PAGE_SIZE;
	pmem->label = label = (struct pmem_label *)(pmem->virt_addr +
	    pmem->size - pmem->pfn_pad);

	if (label->sign != PMEM_SIGN_LONG) {
		dev_notice(dev, "PMEM not labeled, new or data loss!\n");
		memset(label, 0, PAGE_SIZE);
		label->sign = PMEM_SIGN_LONG;
		get_random_bytes(&label->array, sizeof(label->array));
		label->empty = 1;
		label->dirty = 0;
		label->state = STATE_NONE;
	}
	label->opened = 0;
	if (label->state > STATE_IDLE)
		label->state = STATE_IDLE;
	arch_wb_cache_pmem(label, sizeof(struct pmem_label));

	mutex_lock(&links[id].lock);
	links[id].pmem = pmem;
	if (links[id].ntb) {
		links[id].ntb->pmem = pmem;
		ntb_pmem_attach(links[id].ntb);
	}
	mutex_unlock(&links[id].lock);
}
EXPORT_SYMBOL(ntb_pmem_register);

void ntb_pmem_unregister(struct pmem_device *pmem)
{
	struct device *dev = pmem->bb.dev;
	struct nd_region *nd_region = to_nd_region(dev->parent);
	int id = nd_region->id;

	if (id < 0 || id >= MAX_PMEMS)
		return;

	mutex_lock(&links[id].lock);
	links[id].pmem = NULL;
	if (links[id].ntb) {
		ntb_pmem_detach(links[id].ntb);
		links[id].ntb->pmem = NULL;
	}
	mutex_unlock(&links[id].lock);

	pmem->label = NULL;
}
EXPORT_SYMBOL(ntb_pmem_unregister);

static int ntb_pmem_probe(struct ntb_client *client, struct ntb_dev *ndev)
{
	struct ntb_pmem *sc;
	char *p;
	int error, node;
	int id;

	/* Make sure we have enough NTB resources. */
	if (ntb_peer_port_count(ndev) != 1) {
		dev_err(&ndev->dev, "Multi-port NTB is not supported.\n");
		return -ENXIO;
	}
	if (ntb_mw_count(ndev, PIDX) < 1) {
		dev_err(&ndev->dev, "At least 1 memory window required.\n");
		return -ENXIO;
	}
	if (ntb_spad_count(ndev) < 4) {
		dev_err(&ndev->dev, "At least 4 scratchpads required.\n");
		return -ENXIO;
	}

	/*
	 * Associate the ntb_pmem with pmem based on its position in ntb_split.
	 * It limits potential NTB configurations, but it is OK for now.
	 */
	id = 0;
	p = strrchr(dev_name(&ndev->dev), '-');
	if (p && p[1] >= '0' && p[1] <= '9')
		id = p[1] - '0';
	if (id < 0 || id >= MAX_PMEMS) {
		dev_err(&ndev->dev, "Can't get ID (%d).\n", id);
		return -ENXIO;
	}

	node = dev_to_node(&ndev->dev);
	sc = kzalloc_node(sizeof(*sc), GFP_KERNEL, node);
	if (!sc)
		return -ENOMEM;
	sc->ndev = ndev;
	sc->id = id;

	error = ntb_peer_mw_get_addr(ndev, 0, &sc->ntb_paddr, &sc->ntb_size);
	if (error != 0) {
		dev_err(&ndev->dev, "ntb_peer_mw_get_addr() error %d\n", error);
		kfree(sc);
		return -ENXIO;
	}
	sc->ntb_vaddr = devm_memremap(&ndev->dev, sc->ntb_paddr, sc->ntb_size,
	    MEMREMAP_WC);
	if (!sc->ntb_vaddr) {
		dev_err(&ndev->dev, "devm_memremap() error\n");
		kfree(sc);
		return -ENOMEM;
	}

	INIT_DELAYED_WORK(&sc->link_work, ntb_pmem_link_work);
	INIT_WORK(&sc->link_cleanup, ntb_pmem_link_cleanup_work);

	mutex_lock(&links[id].lock);
	links[id].ntb = sc;
	sc->pmem = links[id].pmem;
	if (sc->pmem)
		ntb_pmem_attach(sc);
	mutex_unlock(&links[id].lock);

	return 0;
}

static void ntb_pmem_remove(struct ntb_client *client, struct ntb_dev *ndev)
{
	struct ntb_pmem *sc = ndev->ctx;
	int id = sc->id;

	mutex_lock(&links[id].lock);
	links[id].ntb = NULL;
	if (sc->pmem)
		ntb_pmem_detach(sc);
	mutex_unlock(&links[id].lock);
	kfree(sc);
}

static struct ntb_client ntb_pmem_client = {
	.ops = {
		.probe = ntb_pmem_probe,
		.remove = ntb_pmem_remove,
	},
};

static int __init ntb_pmem_init(void)
{
	int i;

	pr_info("%s, version %s\n", NTB_PMEM_DESC, NTB_PMEM_VER);
	for (i = 0; i < MAX_PMEMS; i++)
		mutex_init(&links[i].lock);
	return ntb_register_client(&ntb_pmem_client);
}
module_init(ntb_pmem_init);

static void __exit ntb_pmem_exit(void)
{
	int i;

	ntb_unregister_client(&ntb_pmem_client);
	for (i = 0; i < MAX_PMEMS; i++)
		mutex_destroy(&links[i].lock);
}
module_exit(ntb_pmem_exit);
