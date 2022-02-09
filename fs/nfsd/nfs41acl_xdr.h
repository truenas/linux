#ifndef _NFS41ACL_H_RPCGEN
#define _NFS41ACL_H_RPCGEN
/*
 * Initially generated through RPCGEN
 * spec file is used in openzfs to
 * manage system.nfs4_acl_xdr xattr
 */

#define NA41_NAME "system.nfs4_acl_xdr"

typedef u_int acetype4;
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

typedef u_int aceflag4;
#define ACEI4_SPECIAL_WHO 0x00000001

typedef u_int aceiflag4;
#define ACE4_SPECIAL_OWNER 1
#define ACE4_SPECIAL_GROUP 2
#define ACE4_SPECIAL_EVERYONE 3
#define ACE4_SPECIAL_INTERACTIVE 4
#define ACE4_SPECIAL_NETWORK 5
#define ACE4_SPECIAL_DIALUP 6
#define ACE4_SPECIAL_BATCH 7
#define ACE4_SPECIAL_ANONYMOUS 8
#define ACE4_SPECIAL_AUTHENTICATED 9
#define ACE4_SPECIAL_SERVICE 10

typedef u_int acemask4;

struct nfsace4i {
	acetype4 type;
	aceflag4 flag;
	aceiflag4 iflag;
	acemask4 access_mask;
	u_int who;
};
typedef struct nfsace4i nfsace4i;
#define NACE41_LEN 5
#define ACL4_AUTO_INHERIT 0x00000001
#define ACL4_PROTECTED 0x00000002
#define ACL4_DEFAULTED 0x00000004

typedef u_int aclflag4;

struct nfsacl41i {
	aclflag4 na41_flag;
	struct {
		u_int na41_aces_len;
		nfsace4i *na41_aces_val;
	} na41_aces;
};
typedef struct nfsacl41i nfsacl41i;

/*
 * Macros for sanity checks related to XDR and ACL buffer sizes
 */
#define NFS41ACL_MAX_ENTRIES	128
#define ACE4SIZE                (sizeof (nfsace4i))
#define XDRBASE                 (2 * sizeof (u32))

#define ACES_TO_SIZE(x, y)      (x + (y * ACE4SIZE))
#define SIZE_TO_ACES(x, y)      ((y - x) / ACE4SIZE)
#define SIZE_IS_VALID(x, y)     ((x >= ACES_TO_SIZE(y, 0)) && \
                                (((x - y) % ACE4SIZE) == 0))

#define ACES_TO_XDRSIZE(x)      (ACES_TO_SIZE(XDRBASE, x))
#define XDRSIZE_TO_ACES(x)      (SIZE_TO_ACES(XDRBASE, x))
#define XDRSIZE_IS_VALID(x)     (SIZE_IS_VALID(x, XDRBASE))

#endif /* !_NFS41ACL_H_RPCGEN */
