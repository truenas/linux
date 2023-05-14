#ifndef _NFS41ACL_H_RPCGEN
#define _NFS41ACL_H_RPCGEN

/*
 * Native ZFS NFSv41-style ACL is packed in xattr as
 * follows:
 *
 * struct nfsace4i {
 *    uint32_t type; RFC 5661 Section 6.2.1.1
 *    uint32_t flag; RFC 5661 Section 6.2.1.4
 *    uint32_t iflag;
 *    uint32_t access_mask; RFC 5661 Section 6.2.1.3
 *    uint32_t who_id;
 * };
 *
 * struct nfsacl4 {
 *     uint32_t acl_flags; RFC 5661 Section 6.4.3.2
 *     uint32_t ace_count;
 *     struct nfsace4i aces<>;
 * };
 *
 * iflag and who_id combined are sufficent for NFS server to convert into ACE
 * who (RFC 5661 Section 6.2.1.5).
 */

#define NA41_NAME "system.nfs4_acl_xdr"

#define ACE4_FILE_INHERIT_ACE 0x00000001
#define ACE4_DIRECTORY_INHERIT_ACE 0x00000002
#define ACE4_NO_PROPAGATE_INHERIT_ACE 0x00000004
#define ACE4_INHERIT_ONLY_ACE 0x00000008
#define ACE4_SUCCESSFUL_ACCESS_ACE_FLAG 0x00000010
#define ACE4_FAILED_ACCESS_ACE_FLAG 0x00000020
#define ACE4_IDENTIFIER_GROUP 0x00000040
#define ACE4_INHERITED_ACE 0x00000080
#define NFS41_FLAGS	(ACE4_DIRECTORY_INHERIT_ACE| \
			 ACE4_FILE_INHERIT_ACE| \
			 ACE4_NO_PROPAGATE_INHERIT_ACE| \
			 ACE4_INHERIT_ONLY_ACE| \
			 ACE4_INHERITED_ACE| \
			 ACE4_IDENTIFIER_GROUP)

#define ACEI4_SPECIAL_WHO 0x00000001
#define ACE4_SPECIAL_OWNER 1
#define ACE4_SPECIAL_GROUP 2
#define ACE4_SPECIAL_EVERYONE 3
#define NACE41_LEN 5

#define ACL4_AUTO_INHERIT 0x00000001
#define ACL4_PROTECTED 0x00000002
#define ACL4_DEFAULTED 0x00000004

/*
 * Macros for sanity checks related to XDR and ACL buffer sizes
 */
#define NFS41ACL_MAX_ENTRIES	128
#define ACE4SIZE                (NACE41_LEN * sizeof(u32))
#define XDRBASE                 (2 * sizeof (u32))

#define ACES_TO_SIZE(x, y)      (x + (y * ACE4SIZE))
#define SIZE_IS_VALID(x, y)     ((x >= ACES_TO_SIZE(y, 0)) && \
                                (((x - y) % ACE4SIZE) == 0))

#define ACES_TO_XDRSIZE(x)      (ACES_TO_SIZE(XDRBASE, x))
#define XDRSIZE_IS_VALID(x)     (SIZE_IS_VALID(x, XDRBASE))

#endif /* !_NFS41ACL_H_RPCGEN */
