#ifndef _NFS41ACL_H
#define _NFS41ACL_H

/*
 * Native ZFS NFSv41-style ACL is packed (using network byte order) in xattr as
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
#define NA_TYPE_OFFSET 0
#define NA_FLAG_OFFSET 1
#define NA_IFLAG_OFFSET 2
#define NA_ACCESS_MASK_OFFSET 3
#define NA_WHO_OFFSET 4

/*
 * Following are defined in RFC 5661 Section 6.2.1.3 ACE Access Mask
 */
#define ACE4_READ_DATA 0x00000001
#define ACE4_WRITE_DATA 0x00000002
#define ACE4_APPEND_DATA 0x00000004
#define ACE4_READ_NAMED_ATTRS 0x00000008
#define ACE4_WRITE_NAMED_ATTRS 0x00000010
#define ACE4_EXECUTE 0x00000020
#define ACE4_DELETE_CHILD 0x00000040
#define ACE4_READ_ATTRIBUTES 0x00000080
#define ACE4_WRITE_ATTRIBUTES 0x00000100
#define ACE4_DELETE 0x00010000
#define ACE4_READ_ACL 0x00020000
#define ACE4_WRITE_ACL 0x00040000
#define ACE4_WRITE_OWNER 0x00080000
#define ACE4_SYNCHRONIZE 0x00100000

#define ACE4_READ_PERMS  (ACE4_READ_DATA|ACE4_READ_ACL|ACE4_READ_ATTRIBUTES| \
    ACE4_READ_NAMED_ATTRS)

#define ACE4_WRITE_PERMS (ACE4_WRITE_DATA|ACE4_APPEND_DATA|ACE4_WRITE_ATTRIBUTES| \
    ACE4_WRITE_NAMED_ATTRS)

#define ACE4_MODIFY_PERMS (ACE4_READ_PERMS|ACE4_WRITE_PERMS|ACE4_SYNCHRONIZE| \
    ACE4_EXECUTE|ACE4_DELETE_CHILD|ACE4_DELETE)

#define ACE4_ALL_PERMS (ACE4_MODIFY_PERMS|ACE4_WRITE_ACL|ACE4_WRITE_OWNER)

/*
 * Following are defined in RFC 5661 Section 6.2.1.4 ACE flags
 */
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
#define DIR_ONLY_FLAGS	(ACE4_DIRECTORY_INHERIT_ACE| \
			 ACE4_FILE_INHERIT_ACE| \
			 ACE4_NO_PROPAGATE_INHERIT_ACE| \
			 ACE4_INHERIT_ONLY_ACE)

#define ACEI4_SPECIAL_WHO 0x00000001
#define ACE4_SPECIAL_OWNER 1
#define ACE4_SPECIAL_GROUP 2
#define ACE4_SPECIAL_EVERYONE 3
#define NACE41_LEN 5
#define NACL_OFFSET 2

/*
 * Follow ACL flags are defined in RFC 5661 Section 6.4.3.2 and are mapped to
 * NT Security Descriptor control bits (MS-DTYP Section 2.4.6) on an as-needed
 * basis. From a practical standpoint the primary concern is preserving the
 * DACL Protected bit as this alters Windows SMB client auto-inheritance
 * behavior when propagating ACL changes recursively.
 */
#define ACL4_AUTO_INHERIT 0x00000001
#define ACL4_PROTECTED 0x00000002
#define ACL4_DEFAULTED 0x00000004

/* Non-RFC ZFS flag indicating that ACL is a directory */
#define ACL4_ISDIR 0x00020000

/*
 * Following are defined in RFC 5661 Section 6.2.1.1
 */
#define ACE4_ACCESS_ALLOWED_ACE_TYPE 0x0000
#define ACE4_ACCESS_DENIED_ACE_TYPE 0x0001
#define ACE4_SYSTEM_AUDIT_ACE_TYPE 0x0002
#define ACE4_SYSTEM_ALARM_ACE_TYPE 0x0003

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

/*
 * Supported flags for /proc/fs/cifs/zfsacl_configuration_flags
 */
#define MODFLAG_UNDEFINED		0x00000000

/* if SID is unknown map it to current fsuid */
#define MODFLAG_MAP_UNKNOWN_SID		0x00000001

/* if SID is unknown, skip it */
#define MODFLAG_SKIP_UNKNOWN_SID	0x00000002

/* if SID is unknown, fail the operation */
#define MODFLAG_FAIL_UNKNOWN_SID	0x00000004

/* Allow writing ACL through xattr (off by default) */
#define MODFLAG_ALLOW_ACL_WRITE		0x00000008

#define MODFLAG_ALL_IDMAP (MODFLAG_FAIL_UNKNOWN_SID | MODFLAG_MAP_UNKNOWN_SID |\
    MODFLAG_SKIP_UNKNOWN_SID)

#define MODFLAG_ALL (MODFLAG_ALL_IDMAP | MODFLAG_ALLOW_ACL_WRITE)

#define MODFLAG_DEFAULTS (MODFLAG_FAIL_UNKNOWN_SID)

#endif /* !_NFS41ACL_H */
