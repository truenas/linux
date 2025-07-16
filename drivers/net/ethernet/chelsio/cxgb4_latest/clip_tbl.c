/*
 *  This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *  Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 *  Written by Deepak (deepak.s@chelsio.com)
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 *  release for licensing terms and conditions.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <net/addrconf.h>
#include "common.h"
#include "t4_linux_fs.h"
#include "clip_tbl.h"

static const u64 clip_ipv6_exact_mask[2] = { ~0, ~0 };

static inline unsigned int ipv4_clip_hash(struct clip_tbl *c, const u32 *key)
{
	unsigned int clipt_size_half = c->clipt_size / 2;

	return jhash_1word(*key, 0) % clipt_size_half;
}

static inline unsigned int ipv6_clip_hash(struct clip_tbl *d, const u32 *key)
{
	unsigned int clipt_size_half = d->clipt_size / 2;
	u32 xor = key[0] ^ key[1] ^ key[2] ^ key[3];

	return clipt_size_half +
		(jhash_1word(xor, 0) % clipt_size_half);
}

static unsigned int clip_addr_hash(struct clip_tbl *ctbl, const u32 *addr,
								u8 v6)
{
	return v6 ? ipv6_clip_hash(ctbl, addr) :
				ipv4_clip_hash(ctbl, addr);
}

static int clip6_get_mbox(const struct net_device *dev,
			  const struct in6_addr *lip,
			  const struct in6_addr *lipm)
{
	struct adapter *adap = netdev2adap(dev);
	struct fw_clip2_cmd c;

	if (!adap->params.clip2_cmd_support) {
		struct fw_clip_cmd old_cmd;

		memset(&old_cmd, 0, sizeof(old_cmd));
		old_cmd.op_to_write = htonl(V_FW_CMD_OP(FW_CLIP_CMD) |
					    F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
		old_cmd.alloc_to_len16 = htonl(F_FW_CLIP_CMD_ALLOC |
					       FW_LEN16(old_cmd));
		old_cmd.ip_hi = *(__be64 *)(lip->s6_addr);
		old_cmd.ip_lo = *(__be64 *)(lip->s6_addr + 8);

		return t4_wr_mbox_meat(adap, adap->mbox, &old_cmd,
				       sizeof(old_cmd), &old_cmd, false);
	}

	memset(&c, 0, sizeof(c));
	c.op_to_write = htonl(V_FW_CMD_OP(FW_CLIP2_CMD) |
			      F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
	c.alloc_to_len16 = htonl(F_FW_CLIP_CMD_ALLOC | FW_LEN16(c));
	c.ip_hi = *(__be64 *)(lip->s6_addr);
	c.ip_lo = *(__be64 *)(lip->s6_addr + 8);
	c.ipm_hi = *(__be64 *)(lipm->s6_addr);
	c.ipm_lo = *(__be64 *)(lipm->s6_addr + 8);

	return t4_wr_mbox_meat(adap, adap->mbox, &c, sizeof(c), &c, false);
}

static int clip6_release_mbox(const struct net_device *dev,
			      const struct in6_addr *lip,
			      const struct in6_addr *lipm)
{
	struct adapter *adap = netdev2adap(dev);
	struct fw_clip2_cmd c;

	if (!adap->params.clip2_cmd_support) {
		struct fw_clip_cmd old_cmd;

		memset(&old_cmd, 0, sizeof(old_cmd));
		old_cmd.op_to_write = htonl(V_FW_CMD_OP(FW_CLIP_CMD) |
					    F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
		old_cmd.alloc_to_len16 = htonl(F_FW_CLIP_CMD_FREE |
					       FW_LEN16(old_cmd));
		old_cmd.ip_hi = *(__be64 *)(lip->s6_addr);
		old_cmd.ip_lo = *(__be64 *)(lip->s6_addr + 8);

		return t4_wr_mbox_meat(adap, adap->mbox, &old_cmd,
				       sizeof(old_cmd), &old_cmd, false);
	}

	memset(&c, 0, sizeof(c));
	c.op_to_write = htonl(V_FW_CMD_OP(FW_CLIP2_CMD) |
			      F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
	c.alloc_to_len16 = htonl(F_FW_CLIP_CMD_FREE | FW_LEN16(c));
	c.ip_hi = *(__be64 *)(lip->s6_addr);
	c.ip_lo = *(__be64 *)(lip->s6_addr + 8);
	c.ipm_hi = *(__be64 *)(lipm->s6_addr);
	c.ipm_lo = *(__be64 *)(lipm->s6_addr + 8);

	return t4_wr_mbox_meat(adap, adap->mbox, &c, sizeof(c), &c, false);
}

static int clip_get(const struct net_device *dev, const u32 *lip,
		    const u32 *lipm, u8 v6)
{
	struct adapter *adap = netdev2adap(dev);
	struct clip_tbl *ctbl = adap->clipt;
	struct clip_entry *ce, *cte;
	u32 *addr = (u32 *)lip;
	int hash;
	int ret = 1;

	if (!ctbl)
		return 0;

	if (!lipm)
		lipm = (const u32 *)clip_ipv6_exact_mask;

	hash = clip_addr_hash(ctbl, addr, v6);

	read_lock_bh(&ctbl->lock);
	list_for_each_entry(cte, &ctbl->hash_list[hash], list) {
		if (cte->val.addr6.sin6_family == AF_INET6 && v6)
			ret = (memcmp(lip, &cte->val.addr6.sin6_addr.s6_addr,
				      sizeof(struct in6_addr)) ||
			       memcmp(lipm, &cte->mask.addr6.sin6_addr.s6_addr,
				      sizeof(struct in6_addr)));
		else if (cte->val.addr.sin_family == AF_INET && !v6)
			ret = (memcmp(lip, (char *)(&cte->val.addr.sin_addr),
				      sizeof(struct in_addr)) ||
			       memcmp(lipm, (char *)(&cte->mask.addr.sin_addr),
				      sizeof(struct in_addr)));

		if (!ret) {
			ce = cte;
			read_unlock_bh(&ctbl->lock);
			goto found;
		}
	}
	read_unlock_bh(&ctbl->lock);
	write_lock_bh(&ctbl->lock);
	if (!list_empty(&ctbl->ce_free_head)) {
		ce = list_first_entry(&ctbl->ce_free_head,
					struct clip_entry, list);
		list_del(&ce->list);
		INIT_LIST_HEAD(&ce->list);
		spin_lock_init(&ce->lock);
		atomic_set(&ce->refcnt, 0);
		atomic_dec(&ctbl->nfree);
		list_add_tail(&ce->list, &ctbl->hash_list[hash]);
		if (v6) {
			ce->val.addr6.sin6_family = AF_INET6;
			ce->mask.addr6.sin6_family = AF_INET6;
			memcpy(ce->val.addr6.sin6_addr.s6_addr,
			       lip, sizeof(struct in6_addr));
			memcpy(ce->mask.addr6.sin6_addr.s6_addr,
			       lipm, sizeof(struct in6_addr));

			ret = clip6_get_mbox(dev, (const struct in6_addr *)lip,
					     (const struct in6_addr *)lipm);
			if (ret) {
				write_unlock_bh(&ctbl->lock);
				dev_err(adap->pdev_dev,
				    "CLIP FW cmd failed with error %d, "
				    "Connections using %pI6c wont be offloaded",
				    ret, ce->val.addr6.sin6_addr.s6_addr);
				return ret;
			}
		} else {
			ce->val.addr.sin_family = AF_INET;
			ce->mask.addr.sin_family = AF_INET;
			memcpy((char *)(&ce->val.addr.sin_addr), lip,
			       sizeof(struct in_addr));
			memcpy((char *)(&ce->mask.addr.sin_addr), lipm,
			       sizeof(struct in_addr));
		}
	} else {
		write_unlock_bh(&ctbl->lock);
		dev_info(adap->pdev_dev, "CLIP table overflow, "
			"Connections using %pI6c wont be offloaded",
			(void *)lip);
		return -ENOMEM;
	}
	write_unlock_bh(&ctbl->lock);

found:
	atomic_inc(&ce->refcnt);
	return 0;
}

int cxgb4_clip_get(const struct net_device *dev, const u32 *lip, u8 v6)
{
	return clip_get(dev, lip, NULL, v6);
}
EXPORT_SYMBOL(cxgb4_clip_get);

int cxgb4_clip_get_filter(const struct net_device *dev, const u32 *lip,
			  const u32 *lipm, u8 v6)
{
	return clip_get(dev, lip, lipm, v6);
}

static void clip_release(const struct net_device *dev, const u32 *lip,
			 const u32 *lipm, u8 v6)
{
	struct adapter *adap = netdev2adap(dev);
	struct clip_tbl *ctbl = adap->clipt;
	struct clip_entry *ce, *cte;
	u32 *addr = (u32 *)lip;
	int hash;
	int ret = 1;

	if (!ctbl)
		return;

	if (!lipm)
		lipm = (const u32 *)clip_ipv6_exact_mask;

	hash = clip_addr_hash(ctbl, addr, v6);

	read_lock_bh(&ctbl->lock);
	list_for_each_entry(cte, &ctbl->hash_list[hash], list) {
		if (cte->val.addr6.sin6_family == AF_INET6 && v6)
			ret = (memcmp(lip, &cte->val.addr6.sin6_addr.s6_addr,
				      sizeof(struct in6_addr)) ||
			       memcmp(lipm, &cte->mask.addr6.sin6_addr.s6_addr,
				      sizeof(struct in6_addr)));
		else if (cte->val.addr.sin_family == AF_INET && !v6)
			ret = (memcmp(lip, (char *)(&cte->val.addr.sin_addr),
				      sizeof(struct in_addr)) ||
			       memcmp(lipm, (char *)(&cte->mask.addr.sin_addr),
				      sizeof(struct in_addr)));
		if (!ret) {
			ce = cte;
			read_unlock_bh(&ctbl->lock);
			goto found;
		}
	}
	read_unlock_bh(&ctbl->lock);

	return;
found:
	write_lock_bh(&ctbl->lock);
	spin_lock_bh(&ce->lock);
	if (atomic_dec_and_test(&ce->refcnt)) {
		list_del(&ce->list);
		INIT_LIST_HEAD(&ce->list);
		list_add_tail(&ce->list, &ctbl->ce_free_head);
		atomic_inc(&ctbl->nfree);
		if (v6)
			clip6_release_mbox(dev, (const struct in6_addr *)lip,
					   (const struct in6_addr *)lipm);
	}
	spin_unlock_bh(&ce->lock);
	write_unlock_bh(&ctbl->lock);

	return;
}

void cxgb4_clip_release(const struct net_device *dev, const u32 *lip, u8 v6)
{
	return clip_release(dev, lip, NULL, v6);
}
EXPORT_SYMBOL(cxgb4_clip_release);

void cxgb4_clip_release_filter(const struct net_device *dev, const u32 *lip,
			       const u32 *lipm, u8 v6)
{
	return clip_release(dev, lip, lipm, v6);
}

/*
 * Retrieves IPv6 addresses from a root device (bond, vlan) associated with
 * a physical device.
 * The physical device reference is needed to send the actul CLIP command.
 */
static int cxgb4_update_dev_clip(struct net_device *root_dev, struct net_device *dev)
{
        struct inet6_dev *idev = NULL;
        struct inet6_ifaddr *ifa;
        int ret = 0;

        idev = __in6_dev_get(root_dev);
        if (!idev)
                return ret;

        read_lock_bh(&idev->lock);
        list_for_each_entry(ifa, &idev->addr_list, if_list) {
                ret = cxgb4_clip_get(dev, (const u32 *)ifa->addr.s6_addr, 1);
                if (ret < 0)
                        break;
        }
        read_unlock_bh(&idev->lock);

        return ret;
}

int cxgb4_update_root_dev_clip(struct net_device *dev)
{
	struct net_device *root_dev = NULL;
	int i, ret = 0;

	/* First populate the real net device's IPv6 addresses */
	ret = cxgb4_update_dev_clip(dev, dev);
	if (ret)
		return ret;

        /* Parse all bond and vlan devices layered on top of the physical dev */
        root_dev = netdev_master_upper_dev_get_rcu(dev);
        if (root_dev) {
                ret = cxgb4_update_dev_clip(root_dev, dev);
                if (ret)
                        return ret;
        }

        for (i = 0; i < VLAN_N_VID; i++) {
                root_dev = __vlan_find_dev_deep_rcu(dev, htons(ETH_P_8021Q), i);
                if (!root_dev)
                        continue;

                ret = cxgb4_update_dev_clip(root_dev, dev);
                if (ret)
                        break;
        }

        return ret;
}
EXPORT_SYMBOL(cxgb4_update_root_dev_clip);

int clip_tbl_show(struct seq_file *seq, void *v)
{
	struct t4_linux_debugfs_data *d = seq->private;
	struct adapter *adap = d->adap;
	struct clip_tbl *ctbl;
	struct clip_entry *ce;
	char ip[96];
	int i;

	ctbl = adap->clipt;
	if (!ctbl)
		return 0;

	read_lock_bh(&ctbl->lock);

	seq_printf(seq, "%-83s   %s\n", "IP Address / IP Mask", "Users");
	for (i = 0 ; i < ctbl->clipt_size;  ++i) {
		list_for_each_entry(ce, &ctbl->hash_list[i], list) {
			ip[0] = '\0';
			sprintf(ip, "%pISc / %pISc", &ce->val.addr,
				&ce->mask.addr);
			seq_printf(seq, "%-83s   %d\n", ip,
				   atomic_read(&ce->refcnt));
		}
	}
	seq_printf(seq, "Free clip entries : %d\n", atomic_read(&ctbl->nfree));

	read_unlock_bh(&ctbl->lock);

	return 0;
}

struct clip_tbl *t4_init_clip_tbl(unsigned int clipt_start,
						unsigned int clipt_end)
{
	unsigned int clipt_size;
	struct clip_entry *cl_list;
	struct clip_tbl *ctbl;
	int i;

	if (clipt_start >= clipt_end)
		return NULL;
	clipt_size = clipt_end - clipt_start + 1;
	if (clipt_size < CLIPT_MIN_HASH_BUCKETS)
		return NULL;
	ctbl = t4_alloc_mem(sizeof(*ctbl) +
				clipt_size*sizeof(struct list_head));
	if (!ctbl)
		return NULL;

	ctbl->clipt_start = clipt_start;
	ctbl->clipt_size = clipt_size;
	INIT_LIST_HEAD(&ctbl->ce_free_head);

	atomic_set(&ctbl->nfree, clipt_size);
	rwlock_init(&ctbl->lock);

	for (i = 0; i < ctbl->clipt_size; ++i)
		INIT_LIST_HEAD(&ctbl->hash_list[i]);

	cl_list = t4_alloc_mem(clipt_size*sizeof(struct clip_entry));
	if (!cl_list) {
		t4_free_mem(ctbl);
		return NULL;
	}
	ctbl->cl_list = (void *)cl_list;
	for (i = 0; i < clipt_size; i++) {
		INIT_LIST_HEAD(&cl_list[i].list);
		list_add_tail(&cl_list[i].list, &ctbl->ce_free_head);
	}
	return ctbl;
}

void t4_cleanup_clip_tbl(struct adapter *adap)
{
	struct clip_tbl *ctbl = adap->clipt;

	if (ctbl) {
		if (ctbl->cl_list)
			t4_free_mem(ctbl->cl_list);
		t4_free_mem(ctbl);
	}
}
EXPORT_SYMBOL(t4_cleanup_clip_tbl);
