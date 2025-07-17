/*
 * Copyright (c) 2009-2021 Chelsio, Inc. All rights reserved.
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
#include <linux/kconfig.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/inetdevice.h>
#include <linux/io.h>

#include <asm/irq.h>
#include <asm/byteorder.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_cache.h>
//#include <rdma/cxgb4-abi.h>

#include <net/xfrm.h>

#include "iw_cxgb4.h"

static int fastreg_support = 1;
module_param(fastreg_support, int, 0644);
MODULE_PARM_DESC(fastreg_support, "Advertise fastreg support (default=1)");

static int map_udb_as_wc = 1;
module_param(map_udb_as_wc, int, 0644);
MODULE_PARM_DESC(map_udb_as_wc, "Map UDB as WC on T5 (default=1)");

static int chrd_iw_modify_port(struct ib_device *ibdev,
			       u32 port, int port_modify_mask,
			       struct ib_port_modify *props)
{
	return -ENOSYS;
}

static int chrd_iw_create_ah(struct ib_ah *ah,
			     struct rdma_ah_init_attr *ah_attr,
			     struct ib_udata *udata)
{
	return -ENOSYS;
}

static int chrd_iw_destroy_ah(struct ib_ah *ah, u32 flags)
{
	return -ENOSYS;
}

static int chrd_roce_create_ah(struct ib_ah *ah,
			       struct rdma_ah_init_attr *ah_init_attr,
			       struct ib_udata *udata)
{
	struct chrd_ah *ahp = to_chrd_ah(ah);
	const struct ib_gid_attr *sgid_attr;
	struct chrd_create_ah_resp uresp;
	u16 vlan_id;
	int ret = 0;

	rdma_copy_ah_attr(&ahp->attr, ah_init_attr->ah_attr);
	ahp->wr_waitp = chrd_alloc_wr_wait(GFP_KERNEL);
	if (!ahp->wr_waitp)
		return -ENOMEM;

	ahp->dst_port = CHRD_ROCE_PORT;
	vlan_id = VLAN_N_VID;
	ahp->dest_qp = 1;
	if (ah_init_attr->ah_attr->ah_flags & IB_AH_GRH) {
	//	new_roce_attr.gsi_attr.ttl = ah_init_attr->ah_attr->grh.hop_limit;
	//	new_roce_attr.gsi_attr.flow_label = ah_init_attr->ah_attr->grh.flow_label;	/*Todo: Check the Commented Code */
	//	new_roce_attr.gsi_attr.tos = ah_init_attr->ah_attr->grh.traffic_class;
		ahp->src_port = rdma_get_udp_sport(ah_init_attr->ah_attr->grh.flow_label,
						   1, ahp->dest_qp);
		pr_debug("GRH NA for v2, src_port = %u\n", ahp->src_port);
	} else {
		ahp->src_port = 0xd000;
		pr_debug("GRH not set, src_port = %u\n", ahp->src_port);
	}	
	sgid_attr = ah_init_attr->ah_attr->grh.sgid_attr;
	ahp->net_type = rdma_gid_attr_network_type(sgid_attr);
	memcpy(ahp->dmac, ah_init_attr->ah_attr->roce.dmac, ETH_ALEN);
	ret = rdma_read_gid_l2_fields(sgid_attr, &vlan_id, ahp->smac);
	if (ret)
		return ret;

	if (vlan_id < VLAN_N_VID) {
		ahp->insert_vlan_tag = true;
		ahp->vlan_id = vlan_id;
	} else {
		ahp->insert_vlan_tag = false;
	}
	rdma_gid2ip((struct sockaddr *)&ahp->sgid_addr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&ahp->dgid_addr, &ah_init_attr->ah_attr->grh.dgid);
	if (ahp->net_type == RDMA_NETWORK_IPV6) {
		__be32 *daddr =	ahp->dgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;
		__be32 *saddr =	ahp->sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;

		memcpy(ahp->dest_ip_addr, daddr, sizeof(ahp->dest_ip_addr));
		memcpy(ahp->local_ip_addr, saddr, sizeof(ahp->local_ip_addr));

		ahp->ipv4 = false;

		ahp->dst = find_route6(to_chrd_dev(ah->device), (__u8 *)ahp->local_ip_addr,
				       (__u8 *)ahp->dest_ip_addr, ahp->src_port,
				       ahp->dst_port, 0, 0);
		
		pr_debug("ahp 0x%llx sport %u dport %u smac %pM dmac %pM "
			 "dest_ip %pI6, src_ip %pI6\n", (unsigned long long)ahp,
			 ahp->src_port, ahp->dst_port, ahp->smac, ahp->dmac,
			 &ahp->dest_ip_addr[0], &ahp->local_ip_addr[0]);
	} else if (ahp->net_type == RDMA_NETWORK_IPV4) {
		ahp->ipv4 = true;
		memset(ahp->dest_ip_addr, 0, sizeof(ahp->dest_ip_addr));
		memset(ahp->local_ip_addr, 0, sizeof(ahp->local_ip_addr));

		ahp->dest_ip_addr[3] = ahp->dgid_addr.saddr_in.sin_addr.s_addr;
		ahp->local_ip_addr[3] = ahp->sgid_addr.saddr_in.sin_addr.s_addr;

		ahp->dst = find_route(to_chrd_dev(ah->device),
				      ahp->local_ip_addr[3], ahp->dest_ip_addr[3],
				      ahp->src_port, ahp->dst_port, 0);

		pr_debug("ahp 0x%llx sport %u dport %u smac %pM dmac %pM "
			 "dest_ip %pI4, src_ip %pI4\n", (unsigned long long)ahp,
			 ahp->src_port, ahp->dst_port, ahp->smac, ahp->dmac,
			 &ahp->dest_ip_addr[3], &ahp->local_ip_addr[3]);
	}

	if (ahp->dst && !IS_ERR(ahp->dst)) {
		struct xfrm_state *x = ahp->dst->xfrm;

		ahp->xfrm.ipsec_en = false;
		if (x && x->xso.offload_handle) {
			ahp->xfrm.ipsecidx = cxgb4_uld_xfrm_ipsecidx_get(x);
			if (ahp->xfrm.ipsecidx && ahp->xfrm.ipsecidx != 0xffff) {
				ahp->xfrm.ipsec_en = true;
				ahp->xfrm.ipsec_mode = x->props.mode;
				ahp->xfrm.ipv6 = x->props.family == AF_INET6;

				if (ahp->xfrm.ipv6) {
					memcpy(ahp->xfrm.dest_ip_addr, x->id.daddr.a6,
					       sizeof(ahp->xfrm.dest_ip_addr));
					memcpy(ahp->xfrm.local_ip_addr, x->props.saddr.a6,
					       sizeof(ahp->xfrm.local_ip_addr));
				} else {
					ahp->xfrm.dest_ip_addr[3] = x->id.daddr.a4;
					ahp->xfrm.local_ip_addr[3] = x->props.saddr.a4;
				}
			} else
				pr_err("%s Invalid IPsec configuration\n", __func__);
		}
	}

	if (udata) {
		uresp.ah_id = ahp->ah_id;
		ret = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if(ret)
			pr_err("need to handle error\n");
	}

	return ret;
}

static int chrd_roce_destroy_ah(struct ib_ah *ah, u32 flags)
{
	struct chrd_ah *ahp = to_chrd_ah(ah);

	rdma_destroy_ah_attr(&ahp->attr);
	return 0;
}

static int chrd_roce_query_ah(struct ib_ah *ah,
			      struct rdma_ah_attr *ah_attr)
{
	//Todo: add when needed later point of time
	return 0;
}

static enum rdma_link_layer chrd_roce_link_layer(struct ib_device *ibdev,
						 u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

#if 0
static int chrd_multicast_attach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct chrd_raw_qp *rqp;
	int ret;

	if (ibqp->qp_type != IB_QPT_RAW_ETH)
		return -ENOSYS;

	pr_debug("- mcast %02x:%02x:%02x:%02x:%02x:%02x\n",
		 gid->raw[0], gid->raw[1], gid->raw[2],
		 gid->raw[3], gid->raw[4], gid->raw[5]);

	rqp = to_chrd_raw_qp(ibqp);
	rtnl_lock();
	ret = dev_mc_add_global(rqp->netdev, gid->raw);
	rtnl_unlock();
	return ret;
}

static int chrd_multicast_detach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct chrd_raw_qp *rqp;
	int ret;

	if (ibqp->qp_type != IB_QPT_RAW_ETH)
		return -ENOSYS;

	pr_debug("- mcast %02x:%02x:%02x:%02x:%02x:%02x\n",
		 gid->raw[0], gid->raw[1], gid->raw[2],
		 gid->raw[3], gid->raw[4], gid->raw[5]);

	rqp = to_chrd_raw_qp(ibqp);
	rtnl_lock();
	ret = dev_mc_del(rqp->netdev, gid->raw);
	rtnl_unlock();
	return ret;
}

static int chrd_process_mad(struct ib_device *ibdev, int mad_flags,
#ifdef IWARP_HAVE_CQ_INIT_ATTR
			    u8 port_num, const struct ib_wc *in_wc,
			    const struct ib_grh *in_grh,
			    const struct ib_mad_hdr *in_mad,
			    size_t in_mad_size,
			    struct ib_mad_hdr *out_mad,
			    size_t *out_mad_size,
			    u16 *out_mad_pkey_index)
#else
			    u8 port_num, struct ib_wc *in_wc,
			    struct ib_grh *in_grh, struct ib_mad *in_mad,
			    struct ib_mad *out_mad)
#endif
{
	return -ENOSYS;
}
#endif

static void chrd_dealloc_ucontext(struct ib_ucontext *context)
{
	struct chrd_ucontext *ucontext = to_chrd_ucontext(context);
	struct chrd_dev *rhp;
	struct chrd_mm_entry *mm, *tmp;

	pr_debug("context %p\n", context);
	rhp = to_chrd_dev(ucontext->ibucontext.device);

	list_for_each_entry_safe(mm, tmp, &ucontext->mmaps, entry)
		kfree(mm);
	cxgb4_uld_release_dev_ucontext(rhp->rdev.rdma_res, &ucontext->uctx);
}

static int chrd_alloc_ucontext(struct ib_ucontext *ucontext,
			       struct ib_udata *udata)
{
	struct ib_device *ibdev = ucontext->device;
	struct chrd_ucontext *context = to_chrd_ucontext(ucontext);
	struct chrd_dev *rhp = to_chrd_dev(ibdev);
	struct chrd_alloc_ucontext_resp uresp;
	int ret = 0;
	struct chrd_mm_entry *mm = NULL;

	pr_debug("ibdev %p\n", ibdev);
	cxgb4_uld_init_dev_ucontext(&context->uctx);
	INIT_LIST_HEAD(&context->mmaps);
	spin_lock_init(&context->mmap_lock);

	if (udata->outlen < sizeof(uresp) - sizeof(uresp.reserved)) {
		pr_err_once("Warning - downlevel libcxgb4 (non-fatal), device status page disabled\n");
		rhp->rdev.flags |= T4_STATUS_PAGE_DISABLED;
	} else {
		mm = kmalloc(sizeof(*mm), GFP_KERNEL);
		if (!mm) {
			ret = -ENOMEM;
			goto err;
		}

		uresp.status_page_size = PAGE_SIZE;

		spin_lock(&context->mmap_lock);
		uresp.status_page_key = context->key;
		context->key += PAGE_SIZE;
		spin_unlock(&context->mmap_lock);

		ret = ib_copy_to_udata(udata, &uresp,
				       sizeof(uresp) - sizeof(uresp.reserved));
		if (ret)
			goto err_mm;

		mm->key = uresp.status_page_key;
		mm->addr = virt_to_phys(rhp->rdev.status_page);
		mm->vaddr = rhp->rdev.status_page;
		mm->dma_addr = rhp->rdev.daddr;
		mm->len = PAGE_SIZE;
		insert_mmap(context, mm);
	}
	return 0;
err_mm:
	kfree(mm);
err:
	return ret;
}

static int chrd_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	int len = vma->vm_end - vma->vm_start;
	u32 key = vma->vm_pgoff << PAGE_SHIFT;
	struct chrd_ucontext *ucontext;
	struct resource *res0, *res2;
	struct chrd_mm_entry *mm;
	struct chrd_rdev *rdev;
	int ret = 0;
	u64 addr;
	size_t size;
	void *vaddr;
	unsigned long vm_pgoff;
	dma_addr_t dma_addr;

	pr_debug("pgoff 0x%lx key 0x%x len %d\n", vma->vm_pgoff, key, len);

	if (vma->vm_start & (PAGE_SIZE-1))
		return -EINVAL;

	rdev = &(to_chrd_dev(context->device)->rdev);
	ucontext = to_chrd_ucontext(context);

	res0 = cxgb4_bar_resource(rdev->lldi.ports[0], 0);
	if (!res0)
		return -EOPNOTSUPP;

	res2 = cxgb4_bar_resource(rdev->lldi.ports[0], 2);
	if (!res2)
		return -EOPNOTSUPP;

	mm = remove_mmap(ucontext, key, len);
	if (!mm)
		return -EINVAL;
	addr = mm->addr;
	vaddr = mm->vaddr;
	dma_addr = mm->dma_addr;
	size = mm->len;
	kfree(mm);

	if ((addr >= res0->start) &&
	    (addr < (res0->start + resource_size(res0)))) {
		if (!is_t4(rdev->lldi.adapter_type)) {
			pr_warn(MOD "%s: Invalid T5/T6/T7 mmap request on BAR0!\n",
				rdev->lldi.name);
			ret = -EINVAL;
		} else {

			/*
			 * MA_SYNC register...
			 */
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
			if (vaddr && is_vmalloc_addr(vaddr)) {
				vm_pgoff = vma->vm_pgoff;
				vma->vm_pgoff = 0;
				ret = dma_mmap_coherent(rdev->lldi.dev, vma,
							vaddr, dma_addr, size);
				vma->vm_pgoff = vm_pgoff;
			} else {
				ret = io_remap_pfn_range(vma, vma->vm_start,
							 addr >> PAGE_SHIFT,
							 len, vma->vm_page_prot);
			}
		}
	} else if ((addr >= res2->start) &&
		   (addr < (res2->start + resource_size(res2)))) {
		/*
		 * Map user DB or OCQP memory...
		 */
		if (chrd_onchip_pa(rdev, addr))
			vma->vm_page_prot = t4_pgprot_wc(vma->vm_page_prot);
		else {
			if (!is_t4(rdev->lldi.adapter_type) && map_udb_as_wc)
				vma->vm_page_prot = t4_pgprot_wc(vma->vm_page_prot);
			else
				vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		}
		if (vaddr && is_vmalloc_addr(vaddr)) {
			vm_pgoff = vma->vm_pgoff;
			vma->vm_pgoff = 0;
			ret = dma_mmap_coherent(rdev->lldi.dev, vma,
						vaddr, dma_addr, size);
			vma->vm_pgoff = vm_pgoff;
		} else {
			ret = io_remap_pfn_range(vma, vma->vm_start,
						 addr >> PAGE_SHIFT,
						 len, vma->vm_page_prot);
		}
	} else {

		/*
		 * Map WQ or CQ contig dma memory...
		 */
		if (vaddr && is_vmalloc_addr(vaddr)) {
			vm_pgoff = vma->vm_pgoff;
			vma->vm_pgoff = 0;
			ret = dma_mmap_coherent(rdev->lldi.dev, vma,
						vaddr, dma_addr, size);
			vma->vm_pgoff = vm_pgoff;
		} else {
			ret = remap_pfn_range(vma, vma->vm_start,
					      addr >> PAGE_SHIFT,
					      len, vma->vm_page_prot);
		}
	}

	return ret;
}

static int chrd_deallocate_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct chrd_dev *rhp;
	struct chrd_pd *php;

	php = to_chrd_pd(pd);
	rhp = php->rhp;
	pr_debug("ibpd %p pdid 0x%x\n", pd, php->pdid);
	cxgb4_uld_put_pdid(rhp->rdev.rdma_res, php->pdid);

	return 0;
}

static int chrd_allocate_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct chrd_pd *php = to_chrd_pd(pd);
	struct ib_device *ibdev = pd->device;
	u32 pdid;
	struct chrd_dev *rhp;

	pr_debug("ibdev %p\n", ibdev);
	rhp = (struct chrd_dev *) ibdev;
	pdid = cxgb4_uld_get_pdid(rhp->rdev.rdma_res);
	if (!pdid)
		return -EINVAL;

	php->pdid = pdid;
	php->rhp = rhp;
	if (udata) {
		if (ib_copy_to_udata(udata, &php->pdid, sizeof(u32))) {
			chrd_deallocate_pd(&php->ibpd, udata);
			return -EFAULT;
		}
	}
	pr_debug("pdid 0x%0x ptr 0x%p\n", pdid, php);
	return 0;
}

static int chrd_iw_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
			   u16 *pkey)
{
	pr_debug("ibdev %p\n", ibdev);
	*pkey = 0;	/*Todo: hardcoded value*/
	return 0;
}

static int chrd_roce_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
			   u16 *pkey)
{
	pr_debug("port %u index %u\n", port, index);
	if (index > 0)
		return -EINVAL;
	*pkey = IB_DEFAULT_PKEY_FULL;
	return 0;
}

static int chrd_query_gid(struct ib_device *ibdev, u32 port, int index,
			  union ib_gid *gid)
{
	struct chrd_dev *dev;

	pr_debug("ibdev %p, port %d, index %d, gid %p\n",
		 ibdev, port, index, gid);
	if (!port)
		return -EINVAL;
	dev = to_chrd_dev(ibdev);
	memset(&(gid->raw[0]), 0, sizeof(gid->raw));
	memcpy(&(gid->raw[0]), dev->rdev.lldi.ports[port-1]->dev_addr, 6);
	return 0;
}

#if 0
static int chrd_add_gid(const struct ib_gid_attr *attr, void **context)
{
	return 0;
}

static int chrd_del_gid(const struct ib_gid_attr *attr, void **context)
{
	return 0;
}
#endif

static int chrd_query_device(struct ib_device *ibdev,
#ifdef IWARP_HAVE_CQ_INIT_ATTR
			     struct ib_device_attr *props, struct ib_udata *uhw)
#else
			     struct ib_device_attr *props)
#endif
{

	struct chrd_dev *dev;
	pr_debug("ibdev %p\n", ibdev);

#ifdef IWARP_HAVE_CQ_INIT_ATTR
	if (uhw->inlen || uhw->outlen)
		return -EINVAL;
#endif

	dev = to_chrd_dev(ibdev);
	memset(props, 0, sizeof *props);
	memcpy(&props->sys_image_guid, dev->rdev.lldi.ports[0]->dev_addr, 6);
	props->hw_ver = CHELSIO_CHIP_RELEASE(dev->rdev.lldi.adapter_type);
	props->fw_ver = dev->rdev.lldi.fw_vers;
	props->device_cap_flags = IB_DEVICE_MEM_WINDOW;
	props->kernel_cap_flags = IBK_LOCAL_DMA_LKEY;
	if (fastreg_support)
		props->device_cap_flags |= IB_DEVICE_MEM_MGT_EXTENSIONS;
#ifdef HAVE_PEER_MEM_SUPPORT
	props->device_cap_flags |= IB_DEVICE_PEER_MEMORY;
#endif
	props->page_size_cap = T4_PAGESIZE_MASK;
	props->vendor_id = dev->rdev.lldi.vendor_id;
	props->vendor_part_id = dev->rdev.lldi.device_id;
	props->max_mr_size = T4_MAX_MR_SIZE;
	props->max_qp = dev->rdev.lldi.vr->qp.size / 2;
	props->max_qp_wr = dev->rdev.hw_queue.t4_max_qp_depth;
	props->max_srq_wr = dev->rdev.hw_queue.t4_max_qp_depth;
	props->max_srq_sge = T4_MAX_RECV_SGE;
	props->max_srq = dev->rdev.lldi.vr->srq.size;
#ifdef IWARP_HAVE_MAX_SEND_SGE
	props->max_send_sge = min(T4_MAX_SEND_SGE, T4_MAX_WRITE_SGE);
	props->max_recv_sge = T4_MAX_RECV_SGE;
#else
	props->max_sge = T4_MAX_RECV_SGE;
#endif
	props->max_sge_rd = T7_MAX_RD_SGE;
	props->max_res_rd_atom = dev->rdev.lldi.max_ird_adapter;
	props->max_qp_rd_atom = min(dev->rdev.lldi.max_ordird_qp,
				    chrd_max_read_depth);
	props->max_qp_init_rd_atom = props->max_qp_rd_atom;
	props->max_cq = dev->rdev.lldi.vr->qp.size;
	props->max_cqe = dev->rdev.hw_queue.t4_max_cq_depth;
	props->max_mr = chrd_num_stags(&dev->rdev);
	props->max_pd = T4_MAX_NUM_PD;
	props->local_ca_ack_delay = 0;
	props->max_fast_reg_page_list_len = t4_max_fr_depth(&dev->rdev, use_dsgl);
	props->max_ah = dev->rdev.lldi.uld_tids.hpftids.size; /* Todo: Need to set appropriately */
	props->max_ee = dev->rdev.lldi.sge_ingpadboundary;
	props->max_raw_ethy_qp = dev->rdev.lldi.neq;
	props->max_pkeys = 1;				/*Todo: hardcoded value*/

	/* pass nfids via max_rdd to user space for raw QPs [iWARP].
 	 * since max_rdd is not used anywhere for iWARP, this will
 	 * eventually break when RoCE enabled, as these are RoCE-specific
 	 * attributes.
 	 */
	props->max_rdd = dev->rdev.nfids;

	return 0;
}

static int chrd_iw_query_port(struct ib_device *ibdev, u32 port,
			   struct ib_port_attr *props)
{
	pr_debug("ibdev %p\n", ibdev);

	props->port_cap_flags =
	    IB_PORT_CM_SUP |
	    IB_PORT_SNMP_TUNNEL_SUP |
	    IB_PORT_REINIT_SUP |
	    IB_PORT_DEVICE_MGMT_SUP |
	    IB_PORT_VENDOR_CLASS_SUP | IB_PORT_BOOT_MGMT_SUP;
	props->gid_tbl_len = 1;
	props->pkey_tbl_len = 1;	/*Todo: hardcoded values*/
	props->active_width = 2;
	props->active_speed = 2;
	props->max_msg_sz = -1;

	return 0;
}

static int chrd_roce_query_port(struct ib_device *ibdev, u32 port,
			   struct ib_port_attr *props)
{
	pr_debug("ibdev %p\n", ibdev);

	props->port_cap_flags =
	    IB_PORT_CM_SUP |
	    IB_PORT_SNMP_TUNNEL_SUP |
	    IB_PORT_REINIT_SUP |
	    IB_PORT_DEVICE_MGMT_SUP |
	    IB_PORT_VENDOR_CLASS_SUP | IB_PORT_BOOT_MGMT_SUP |
	    RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP;
	props->gid_tbl_len = 1024; /*Todo: set it appropriately*/
	props->ip_gids = true;
	props->lid = 0;
	props->max_mtu = IB_MTU_4096;
	props->active_mtu = IB_MTU_1024;
	props->state = IB_PORT_ACTIVE;
	props->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	props->sm_lid = 0;
	props->pkey_tbl_len = 1;
	props->active_width = 2; /*Todo: set it appropriately*/
	props->active_speed = 2; /*Todo: set it appropriately*/
	props->max_msg_sz = 0x800000; /*Todo: set it appropriately*/

	return 0;
}

static ssize_t hw_rev_show(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	struct chrd_dev *chrd_dev =
			rdma_device_to_drv_device(dev, struct chrd_dev, ibdev);
	pr_debug("dev 0x%p\n", dev);
	return sprintf(buf, "%d\n",
		       CHELSIO_CHIP_RELEASE(chrd_dev->rdev.lldi.adapter_type));
}
static DEVICE_ATTR_RO(hw_rev);

static ssize_t hca_type_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct chrd_dev *chrd_dev =
			rdma_device_to_drv_device(dev, struct chrd_dev, ibdev);
	struct ethtool_drvinfo info;
	struct net_device *lldev = chrd_dev->rdev.lldi.ports[0];

	pr_debug("dev 0x%p\n", dev);
	lldev->ethtool_ops->get_drvinfo(lldev, &info);
	return sprintf(buf, "%s\n", info.driver);
}
static DEVICE_ATTR_RO(hca_type);

static ssize_t board_id_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct chrd_dev *chrd_dev =
			rdma_device_to_drv_device(dev, struct chrd_dev, ibdev);
	pr_debug("dev 0x%p\n", dev);
	return sprintf(buf, "%x.%x\n", chrd_dev->rdev.lldi.vendor_id,
		       chrd_dev->rdev.lldi.device_id);
}
static DEVICE_ATTR_RO(board_id);

#ifdef IWARP_DEV_COUNTER_DYNAMIC
enum counters {
	IP4INSEGS,
	IP4OUTSEGS,
	IP4RETRANSSEGS,
	IP4OUTRSTS,
	IP6INSEGS,
	IP6OUTSEGS,
	IP6RETRANSSEGS,
	IP6OUTRSTS,
	NR_COUNTERS
};

static const struct rdma_stat_desc cxgb4_descs[] = {
	[IP4INSEGS].name = "ip4InSegs",
	[IP4OUTSEGS].name = "ip4OutSegs",
	[IP4RETRANSSEGS].name = "ip4RetransSegs",
	[IP4OUTRSTS].name = "ip4OutRsts",
	[IP6INSEGS].name = "ip6InSegs",
	[IP6OUTSEGS].name = "ip6OutSegs",
	[IP6RETRANSSEGS].name = "ip6RetransSegs",
	[IP6OUTRSTS].name = "ip6OutRsts"
};

static struct rdma_hw_stats *chrd_alloc_device_stats(struct ib_device *ibdev)
{
	BUILD_BUG_ON(ARRAY_SIZE(cxgb4_descs) != NR_COUNTERS);

	return rdma_alloc_hw_stats_struct(cxgb4_descs, NR_COUNTERS,
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}
#endif

static int chrd_get_mib(struct ib_device *ibdev,
#ifdef IWARP_DEV_COUNTER_DYNAMIC
			struct rdma_hw_stats *stats,
			u32 port, int index)
#else
			union rdma_protocol_stats *stats)
#endif
{
	struct tp_tcp_stats v4, v6;
	struct chrd_dev *chrd_dev = to_chrd_dev(ibdev);

	cxgb4_get_tcp_stats(chrd_dev->rdev.lldi.ports[0], &v4, &v6);
#ifdef IWARP_DEV_COUNTER_DYNAMIC
	stats->value[IP4INSEGS] = v4.tcp_in_segs;
	stats->value[IP4OUTSEGS] = v4.tcp_out_segs;
	stats->value[IP4RETRANSSEGS] = v4.tcp_retrans_segs;
	stats->value[IP4OUTRSTS] = v4.tcp_out_rsts;
	stats->value[IP6INSEGS] = v6.tcp_in_segs;
	stats->value[IP6OUTSEGS] = v6.tcp_out_segs;
	stats->value[IP6RETRANSSEGS] = v6.tcp_retrans_segs;
	stats->value[IP6OUTRSTS] = v6.tcp_out_rsts;

	return stats->num_counters;
#else
	memset(stats, 0, sizeof(*stats));
	stats->iw.tcpInSegs = v4.tcp_in_segs + v6.tcp_in_segs;
	stats->iw.tcpOutSegs = v4.tcp_out_segs + v6.tcp_out_segs;
	stats->iw.tcpRetransSegs = v4.tcp_retrans_segs + v6.tcp_retrans_segs;
	stats->iw.tcpOutRsts = v4.tcp_out_rsts + v6.tcp_out_rsts;

	return 0;
#endif
}

static struct attribute *chrd_class_attributes[] = {
	&dev_attr_hw_rev.attr,
	&dev_attr_hca_type.attr,
	&dev_attr_board_id.attr,
	NULL
};

static const struct attribute_group chrd_attr_group = {
	.attrs = chrd_class_attributes,
};

static int chrd_iw_port_immutable(struct ib_device *ibdev, u32 port_num,
			       struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	err = chrd_iw_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->core_cap_flags = RDMA_CORE_PORT_IWARP;

	return 0;
}

static int chrd_roce_port_immutable(struct ib_device *ibdev, u32 port_num,
			       struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	err = chrd_roce_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

#ifdef HAVE_IB_FW_VER_NAME
static void get_dev_fw_str(struct ib_device *dev, char *str)
#else
static void get_dev_fw_str(struct ib_device *dev, char *str,
			   size_t str_len)
#endif
{
	struct chrd_dev *chrd_dev = container_of(dev, struct chrd_dev,
						 ibdev);
	pr_debug("dev 0x%p\n", dev);

#ifdef HAVE_IB_FW_VER_NAME
	snprintf(str, IB_FW_VERSION_NAME_MAX, "%u.%u.%u.%u",
#else
	snprintf(str, str_len, "%u.%u.%u.%u",
#endif
		 G_FW_HDR_FW_VER_MAJOR(chrd_dev->rdev.lldi.fw_vers),
		 G_FW_HDR_FW_VER_MINOR(chrd_dev->rdev.lldi.fw_vers),
		 G_FW_HDR_FW_VER_MICRO(chrd_dev->rdev.lldi.fw_vers),
		 G_FW_HDR_FW_VER_BUILD(chrd_dev->rdev.lldi.fw_vers));
}

static const struct ib_device_ops chrd_common_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_CXGB4,
	.uverbs_abi_ver = CHRD_UVERBS_ABI_VERSION,

#ifdef IWARP_DEV_COUNTER_DYNAMIC
	.alloc_hw_device_stats = chrd_alloc_device_stats,
	.get_hw_stats = chrd_get_mib,
#endif
	.alloc_mr = chrd_alloc_mr,
	.alloc_mw = chrd_alloc_mw,
	.alloc_pd = chrd_allocate_pd,
	.alloc_ucontext = chrd_alloc_ucontext,
	.create_cq = chrd_create_cq,
	.create_qp = chrd_create_qp,
	.create_srq = chrd_create_srq,
	.dealloc_mw = chrd_dealloc_mw,
	.dealloc_pd = chrd_deallocate_pd,
	.dealloc_ucontext = chrd_dealloc_ucontext,
	.dereg_mr = chrd_dereg_mr,
	.destroy_cq = chrd_destroy_cq,
	.destroy_qp = chrd_destroy_qp,
	.destroy_srq = chrd_destroy_srq,
	.query_gid = chrd_query_gid,
	.fill_res_cm_id_entry = chrd_fill_res_cm_id_entry,
	.fill_res_cq_entry = chrd_fill_res_cq_entry,
	.fill_res_mr_entry = chrd_fill_res_mr_entry,
	.get_dev_fw_str = get_dev_fw_str,
	.get_dma_mr = chrd_get_dma_mr,
	.map_mr_sg = chrd_map_mr_sg,
	.mmap = chrd_mmap,
	.modify_srq = chrd_modify_srq,
	.poll_cq = chrd_poll_cq,
	.post_recv = chrd_post_receive,
	.post_srq_recv = chrd_post_srq_recv,
	.query_device = chrd_query_device,
	.query_qp = chrd_query_qp,
	.reg_user_mr = chrd_reg_user_mr,
	.req_notify_cq = chrd_arm_cq,
	INIT_RDMA_OBJ_SIZE(ib_pd, chrd_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_qp, chrd_qp, ibqp),
	INIT_RDMA_OBJ_SIZE(ib_cq, chrd_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_srq, chrd_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, chrd_ucontext, ibucontext),
};

static const struct ib_device_ops chrd_iw_dev_ops = {
	.get_port_immutable = chrd_iw_port_immutable,
	.query_port = chrd_iw_query_port,
	.modify_port = chrd_iw_modify_port,
	.iw_accept = chrd_iw_accept_cr,
	.iw_add_ref = chrd_iw_qp_add_ref,
	.iw_connect = chrd_iw_connect,
	.iw_create_listen = chrd_iw_create_listen,
	.iw_destroy_listen = chrd_iw_destroy_listen,
	.iw_get_qp = chrd_iw_get_qp,
	.iw_reject = chrd_iw_reject_cr,
	.iw_rem_ref = chrd_iw_qp_rem_ref,
	.post_send = chrd_iw_post_send,
	.modify_qp = chrd_iw_modify_qp,
	.query_pkey = chrd_iw_query_pkey,
	.create_ah = chrd_iw_create_ah,
	.destroy_ah = chrd_iw_destroy_ah,
};

static const struct ib_device_ops chrd_roce_dev_ops = {
	.get_port_immutable = chrd_roce_port_immutable,
	.get_link_layer = chrd_roce_link_layer,
	.query_port = chrd_roce_query_port,
//	.add_gid = chrd_add_gid,		/*Todo: Check the Commented Code*/
//	.del_gid = chrd_del_gid,
	.query_pkey = chrd_roce_query_pkey,
	.create_ah = chrd_roce_create_ah,
	.create_user_ah = chrd_roce_create_ah, /*Bhar: Recheck and enable for User mode*/
	.destroy_ah = chrd_roce_destroy_ah,
//	.modify_ah = chrd_modify_ah, /* add when needed*/
	.query_ah = chrd_roce_query_ah,
	.modify_qp = chrd_roce_modify_qp,
	.post_send = chrd_roce_post_send,
	INIT_RDMA_OBJ_SIZE(ib_ah, chrd_ah, ibah),
};

static int set_netdevs(struct ib_device *ib_dev, struct chrd_rdev *rdev,
		       u32 nports)
{
	int ret;
	int i;

	for (i = 0; i < nports; i++) {
		ret = ib_device_set_netdev(ib_dev, rdev->lldi.ports[i],
					   i + 1);
		if (ret)
			return ret;
	}
	return 0;
}

static void chrd_init_roce_dev(struct chrd_dev *dev)
{
	addrconf_addr_eui48((unsigned char *)&dev->ibdev.node_guid,
			    dev->rdev.lldi.ports[0]->dev_addr);
	dev->ibdev.node_type = RDMA_NODE_IB_CA;
	ib_set_device_ops(&dev->ibdev, &chrd_roce_dev_ops);
}

static void chrd_init_iw_dev(struct chrd_dev *dev)
{
	memset(&dev->ibdev.node_guid, 0, sizeof(dev->ibdev.node_guid));
	memcpy(&dev->ibdev.node_guid, dev->rdev.lldi.ports[0]->dev_addr, 6);
	dev->ibdev.node_type = RDMA_NODE_RNIC;
	ib_set_device_ops(&dev->ibdev, &chrd_iw_dev_ops);
}

void chrd_register_device(struct work_struct *work)
{
	struct uld_ctx *ctx = container_of(work, struct uld_ctx, reg_work);
	struct chrd_dev *dev = ctx->dev;
	u64 dma_mask;
	int ret;

	pr_debug("chrd_dev %p\n", dev);
	strscpy(dev->ibdev.name, "cxgb4_%d", IB_DEVICE_NAME_MAX);
	dev->ibdev.local_dma_lkey = 0;
	dev->ibdev.uverbs_cmd_mask =
#ifdef SIM
	    (1ull << IB_USER_VERBS_CMD_RESIZE_CQ) |
#endif
	    (1ull << IB_USER_VERBS_CMD_ATTACH_MCAST) |
	    (1ull << IB_USER_VERBS_CMD_DETACH_MCAST) |
	    (1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
	    (1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_REG_MR) |
	    (1ull << IB_USER_VERBS_CMD_DEREG_MR) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_QP) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_QP) |
	    (1ull << IB_USER_VERBS_CMD_POLL_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_QP) |
	    (1ull << IB_USER_VERBS_CMD_POST_SEND) |
	    (1ull << IB_USER_VERBS_CMD_POST_RECV) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_SRQ);
	memcpy(dev->ibdev.node_desc, CHRD_NODE_DESC, sizeof(CHRD_NODE_DESC));
	dev->ibdev.num_comp_vectors =  dev->rdev.lldi.nciq;
	dev->ibdev.dev.parent = dev->rdev.lldi.dev;
#ifndef IWARP_DEV_COUNTER_DYNAMIC
	dev->ibdev.get_protocol_stats = chrd_get_mib;
#endif
	ib_set_device_ops(&dev->ibdev, &chrd_common_dev_ops);
	dev->ibdev.dev.dma_parms = &dev->dma_parms;
	dma_set_max_seg_size(dev->rdev.lldi.dev, UINT_MAX);
	dma_mask = IS_ENABLED(CONFIG_64BIT) ? DMA_BIT_MASK(64) : DMA_BIT_MASK(32);
	dma_coerce_mask_and_coherent(&dev->ibdev.dev, dma_mask);

	if (roce_mode) {
		dev->ibdev.phys_port_cnt = dev->rdev.lldi.nports; //nports should be one for RoCE as per per-port design
		//dev->ibdev.phys_port_cnt = 1; //nports should be one for RoCE as per per-port design
		ret = set_netdevs(&dev->ibdev, &dev->rdev,
				  dev->ibdev.phys_port_cnt);
		if (ret)
			goto err_dealloc_ctx;
		chrd_init_roce_dev(dev);
	} else {
		dev->ibdev.phys_port_cnt = dev->rdev.lldi.nports;
		ret = set_netdevs(&dev->ibdev, &dev->rdev,
				  dev->ibdev.phys_port_cnt);
		if (ret)
			goto err_dealloc_ctx;
		chrd_init_iw_dev(dev);
	}
#ifdef IBREGDEV2
	ret = ib_register_device(&dev->ibdev, "chrd_%d");
#else
	ret = ib_register_device(&dev->ibdev, "chrd_%d",
				 dev->rdev.lldi.dev);
#endif
	if (ret)
		goto err_dealloc_ctx;

	return;
err_dealloc_ctx:
	pr_err("%s - Failed registering iwarp device: %d\n",
	       ctx->lldi.name, ret);
	chrd_dealloc(ctx);
	return;
}

void chrd_unregister_device(struct chrd_dev *dev)
{
	pr_debug("chrd_dev %p\n", dev);
	ib_unregister_device(&dev->ibdev);
	return;
}
