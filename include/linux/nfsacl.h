/* SPDX-License-Identifier: GPL-2.0 */
/*
 * File: linux/nfsacl.h
 *
 * (C) 2003 Andreas Gruenbacher <agruen@suse.de>
 */
#ifndef __LINUX_NFSACL_H
#define __LINUX_NFSACL_H


#include <linux/posix_acl.h>
#include <linux/sunrpc/xdr.h>
#include <uapi/linux/nfsacl.h>
#if CONFIG_TRUENAS
#include <linux/nfs4.h>		/* For struct nfs4_acl */
#endif /* CONFIG_TRUENAS */

/* Maximum number of ACL entries over NFS */
#define NFS_ACL_MAX_ENTRIES	1024

#define NFSACL_MAXWORDS		(2*(2+3*NFS_ACL_MAX_ENTRIES))
#define NFSACL_MAXPAGES		((2*(8+12*NFS_ACL_MAX_ENTRIES) + PAGE_SIZE-1) \
				 >> PAGE_SHIFT)

#define NFS_ACL_MAX_ENTRIES_INLINE	(5)
#define NFS_ACL_INLINE_BUFSIZE	((2*(2+3*NFS_ACL_MAX_ENTRIES_INLINE)) << 2)

static inline unsigned int
nfsacl_size(struct posix_acl *acl_access, struct posix_acl *acl_default)
{
	unsigned int w = 16;
	w += max(acl_access ? (int)acl_access->a_count : 3, 4) * 12;
	if (acl_default)
		w += max((int)acl_default->a_count, 4) * 12;
	return w;
}

extern int
nfsacl_encode(struct xdr_buf *buf, unsigned int base, struct inode *inode,
	      struct posix_acl *acl, int encode_entries, int typeflag);
extern int
nfsacl_decode(struct xdr_buf *buf, unsigned int base, unsigned int *aclcnt,
	      struct posix_acl **pacl);
extern bool
nfs_stream_decode_acl(struct xdr_stream *xdr, unsigned int *aclcnt,
		      struct posix_acl **pacl);
extern bool
nfs_stream_encode_acl(struct xdr_stream *xdr, struct inode *inode,
		      struct posix_acl *acl, int encode_entries, int typeflag);

#if CONFIG_TRUENAS
extern int
convert_nfs41xdr_to_nfs40_acl(u32 *xdrbuf, size_t remaining, struct nfs4_acl *acl);
extern int
generate_nfs41acl_buf(u32 *xdrbuf, const struct nfs4_acl *acl);
#endif /* CONFIG_TRUENAS */

#endif  /* __LINUX_NFSACL_H */
