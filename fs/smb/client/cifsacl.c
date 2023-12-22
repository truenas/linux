// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 *   Contains the routines for mapping CIFS/NTFS ACLs
 *
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <uapi/linux/posix_acl.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <keys/user-type.h>
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsacl.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "fs_context.h"
#include "cifs_fs_sb.h"
#include "cifs_unicode.h"
#ifdef CONFIG_TRUENAS
#include "nfs41acl_xdr.h"
#endif

/* security id for everyone/world system group */
static const struct cifs_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
#ifdef CONFIG_TRUENAS
static const struct cifs_sid sid_creator_owner = {
	1, 1, {0, 0, 0, 0, 0, 3}, {0} };

static const struct cifs_sid sid_creator_group = {
	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(1)} };
#endif /* CONFIG_TRUENAS */
/* security id for Authenticated Users system group */
static const struct cifs_sid sid_authusers = {
	1, 1, {0, 0, 0, 0, 0, 5}, {cpu_to_le32(11)} };

/* S-1-22-1 Unmapped Unix users */
static const struct cifs_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-2 Unmapped Unix groups */
static const struct cifs_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * See https://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */

/* S-1-5-88 MS NFS and Apple style UID/GID/mode */

/* S-1-5-88-1 Unix uid */
static const struct cifs_sid sid_unix_NFS_users = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-2 Unix gid */
static const struct cifs_sid sid_unix_NFS_groups = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-3 Unix mode */
static const struct cifs_sid sid_unix_NFS_mode = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(3), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

static const struct cred *root_cred;

static int
cifs_idmap_key_instantiate(struct key *key, struct key_preparsed_payload *prep)
{
	char *payload;

	/*
	 * If the payload is less than or equal to the size of a pointer, then
	 * an allocation here is wasteful. Just copy the data directly to the
	 * payload.value union member instead.
	 *
	 * With this however, you must check the datalen before trying to
	 * dereference payload.data!
	 */
	if (prep->datalen <= sizeof(key->payload)) {
		key->payload.data[0] = NULL;
		memcpy(&key->payload, prep->data, prep->datalen);
	} else {
		payload = kmemdup(prep->data, prep->datalen, GFP_KERNEL);
		if (!payload)
			return -ENOMEM;
		key->payload.data[0] = payload;
	}

	key->datalen = prep->datalen;
	return 0;
}

static inline void
cifs_idmap_key_destroy(struct key *key)
{
	if (key->datalen > sizeof(key->payload))
		kfree(key->payload.data[0]);
}

static struct key_type cifs_idmap_key_type = {
	.name        = "cifs.idmap",
	.instantiate = cifs_idmap_key_instantiate,
	.destroy     = cifs_idmap_key_destroy,
	.describe    = user_describe,
};

static char *
sid_to_key_str(struct cifs_sid *sidptr, unsigned int type)
{
	int i, len;
	unsigned int saval;
	char *sidstr, *strptr;
	unsigned long long id_auth_val;

	/* 3 bytes for prefix */
	sidstr = kmalloc(3 + SID_STRING_BASE_SIZE +
			 (SID_STRING_SUBAUTH_SIZE * sidptr->num_subauth),
			 GFP_KERNEL);
	if (!sidstr)
		return sidstr;

	strptr = sidstr;
	len = sprintf(strptr, "%cs:S-%hhu", type == SIDOWNER ? 'o' : 'g',
			sidptr->revision);
	strptr += len;

	/* The authority field is a single 48-bit number */
	id_auth_val = (unsigned long long)sidptr->authority[5];
	id_auth_val |= (unsigned long long)sidptr->authority[4] << 8;
	id_auth_val |= (unsigned long long)sidptr->authority[3] << 16;
	id_auth_val |= (unsigned long long)sidptr->authority[2] << 24;
	id_auth_val |= (unsigned long long)sidptr->authority[1] << 32;
	id_auth_val |= (unsigned long long)sidptr->authority[0] << 48;

	/*
	 * MS-DTYP states that if the authority is >= 2^32, then it should be
	 * expressed as a hex value.
	 */
	if (id_auth_val <= UINT_MAX)
		len = sprintf(strptr, "-%llu", id_auth_val);
	else
		len = sprintf(strptr, "-0x%llx", id_auth_val);

	strptr += len;

	for (i = 0; i < sidptr->num_subauth; ++i) {
		saval = le32_to_cpu(sidptr->sub_auth[i]);
		len = sprintf(strptr, "-%u", saval);
		strptr += len;
	}

	return sidstr;
}

/*
 * if the two SIDs (roughly equivalent to a UUID for a user or group) are
 * the same returns zero, if they do not match returns non-zero.
 */
static int
compare_sids(const struct cifs_sid *ctsid, const struct cifs_sid *cwsid)
{
	int i;
	int num_subauth, num_sat, num_saw;

	if ((!ctsid) || (!cwsid))
		return 1;

	/* compare the revision */
	if (ctsid->revision != cwsid->revision) {
		if (ctsid->revision > cwsid->revision)
			return 1;
		else
			return -1;
	}

	/* compare all of the six auth values */
	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i]) {
			if (ctsid->authority[i] > cwsid->authority[i])
				return 1;
			else
				return -1;
		}
	}

	/* compare all of the subauth values if any */
	num_sat = ctsid->num_subauth;
	num_saw = cwsid->num_subauth;
	num_subauth = num_sat < num_saw ? num_sat : num_saw;
	if (num_subauth) {
		for (i = 0; i < num_subauth; ++i) {
			if (ctsid->sub_auth[i] != cwsid->sub_auth[i]) {
				if (le32_to_cpu(ctsid->sub_auth[i]) >
					le32_to_cpu(cwsid->sub_auth[i]))
					return 1;
				else
					return -1;
			}
		}
	}

	return 0; /* sids compare/match */
}

static bool
is_well_known_sid(const struct cifs_sid *psid, uint32_t *puid, bool is_group)
{
	int i;
	int num_subauth;
	const struct cifs_sid *pwell_known_sid;

	if (!psid || (puid == NULL))
		return false;

	num_subauth = psid->num_subauth;

	/* check if Mac (or Windows NFS) vs. Samba format for Unix owner SID */
	if (num_subauth == 2) {
		if (is_group)
			pwell_known_sid = &sid_unix_groups;
		else
			pwell_known_sid = &sid_unix_users;
	} else if (num_subauth == 3) {
		if (is_group)
			pwell_known_sid = &sid_unix_NFS_groups;
		else
			pwell_known_sid = &sid_unix_NFS_users;
	} else
		return false;

	/* compare the revision */
	if (psid->revision != pwell_known_sid->revision)
		return false;

	/* compare all of the six auth values */
	for (i = 0; i < NUM_AUTHS; ++i) {
		if (psid->authority[i] != pwell_known_sid->authority[i]) {
			cifs_dbg(FYI, "auth %d did not match\n", i);
			return false;
		}
	}

	if (num_subauth == 2) {
		if (psid->sub_auth[0] != pwell_known_sid->sub_auth[0])
			return false;

		*puid = le32_to_cpu(psid->sub_auth[1]);
	} else /* 3 subauths, ie Windows/Mac style */ {
		*puid = le32_to_cpu(psid->sub_auth[0]);
		if ((psid->sub_auth[0] != pwell_known_sid->sub_auth[0]) ||
		    (psid->sub_auth[1] != pwell_known_sid->sub_auth[1]))
			return false;

		*puid = le32_to_cpu(psid->sub_auth[2]);
	}

	cifs_dbg(FYI, "Unix UID %d returned from SID\n", *puid);
	return true; /* well known sid found, uid returned */
}

static __u16
cifs_copy_sid(struct cifs_sid *dst, const struct cifs_sid *src)
{
	int i;
	__u16 size = 1 + 1 + 6;

	dst->revision = src->revision;
	dst->num_subauth = min_t(u8, src->num_subauth, SID_MAX_SUB_AUTHORITIES);
	for (i = 0; i < NUM_AUTHS; ++i)
		dst->authority[i] = src->authority[i];
	for (i = 0; i < dst->num_subauth; ++i)
		dst->sub_auth[i] = src->sub_auth[i];
	size += (dst->num_subauth * 4);

	return size;
}

static int
id_to_sid(unsigned int cid, uint sidtype, struct cifs_sid *ssid)
{
	int rc;
	struct key *sidkey;
	struct cifs_sid *ksid;
	unsigned int ksid_size;
	char desc[3 + 10 + 1]; /* 3 byte prefix + 10 bytes for value + NULL */
	const struct cred *saved_cred;

	rc = snprintf(desc, sizeof(desc), "%ci:%u",
			sidtype == SIDOWNER ? 'o' : 'g', cid);
	if (rc >= sizeof(desc))
		return -EINVAL;

	rc = 0;
	saved_cred = override_creds(root_cred);
	sidkey = request_key(&cifs_idmap_key_type, desc, "");
	if (IS_ERR(sidkey)) {
		rc = -EINVAL;
		cifs_dbg(FYI, "%s: Can't map %cid %u to a SID\n",
			 __func__, sidtype == SIDOWNER ? 'u' : 'g', cid);
		goto out_revert_creds;
	} else if (sidkey->datalen < CIFS_SID_BASE_SIZE) {
		rc = -EIO;
		cifs_dbg(FYI, "%s: Downcall contained malformed key (datalen=%hu)\n",
			 __func__, sidkey->datalen);
		goto invalidate_key;
	}

	/*
	 * A sid is usually too large to be embedded in payload.value, but if
	 * there are no subauthorities and the host has 8-byte pointers, then
	 * it could be.
	 */
	ksid = sidkey->datalen <= sizeof(sidkey->payload) ?
		(struct cifs_sid *)&sidkey->payload :
		(struct cifs_sid *)sidkey->payload.data[0];

	ksid_size = CIFS_SID_BASE_SIZE + (ksid->num_subauth * sizeof(__le32));
	if (ksid_size > sidkey->datalen) {
		rc = -EIO;
		cifs_dbg(FYI, "%s: Downcall contained malformed key (datalen=%hu, ksid_size=%u)\n",
			 __func__, sidkey->datalen, ksid_size);
		goto invalidate_key;
	}

	cifs_copy_sid(ssid, ksid);
out_key_put:
	key_put(sidkey);
out_revert_creds:
	revert_creds(saved_cred);
	return rc;

invalidate_key:
	key_invalidate(sidkey);
	goto out_key_put;
}

int
sid_to_id(struct cifs_sb_info *cifs_sb, struct cifs_sid *psid,
		struct cifs_fattr *fattr, uint sidtype)
{
	int rc = 0;
	struct key *sidkey;
	char *sidstr;
	const struct cred *saved_cred;
	kuid_t fuid = cifs_sb->ctx->linux_uid;
	kgid_t fgid = cifs_sb->ctx->linux_gid;

	/*
	 * If we have too many subauthorities, then something is really wrong.
	 * Just return an error.
	 */
	if (unlikely(psid->num_subauth > SID_MAX_SUB_AUTHORITIES)) {
		cifs_dbg(FYI, "%s: %u subauthorities is too many!\n",
			 __func__, psid->num_subauth);
		return -EIO;
	}

	if ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_UID_FROM_ACL) ||
	    (cifs_sb_master_tcon(cifs_sb)->posix_extensions)) {
		uint32_t unix_id;
		bool is_group;

		if (sidtype != SIDOWNER)
			is_group = true;
		else
			is_group = false;

		if (is_well_known_sid(psid, &unix_id, is_group) == false)
			goto try_upcall_to_get_id;

		if (is_group) {
			kgid_t gid;
			gid_t id;

			id = (gid_t)unix_id;
			gid = make_kgid(&init_user_ns, id);
			if (gid_valid(gid)) {
				fgid = gid;
				goto got_valid_id;
			}
		} else {
			kuid_t uid;
			uid_t id;

			id = (uid_t)unix_id;
			uid = make_kuid(&init_user_ns, id);
			if (uid_valid(uid)) {
				fuid = uid;
				goto got_valid_id;
			}
		}
		/* If unable to find uid/gid easily from SID try via upcall */
	}

try_upcall_to_get_id:
	sidstr = sid_to_key_str(psid, sidtype);
	if (!sidstr)
		return -ENOMEM;

	saved_cred = override_creds(root_cred);
	sidkey = request_key(&cifs_idmap_key_type, sidstr, "");
	if (IS_ERR(sidkey)) {
		cifs_dbg(FYI, "%s: Can't map SID %s to a %cid\n",
			 __func__, sidstr, sidtype == SIDOWNER ? 'u' : 'g');
		goto out_revert_creds;
	}

	/*
	 * FIXME: Here we assume that uid_t and gid_t are same size. It's
	 * probably a safe assumption but might be better to check based on
	 * sidtype.
	 */
	BUILD_BUG_ON(sizeof(uid_t) != sizeof(gid_t));
	if (sidkey->datalen != sizeof(uid_t)) {
		cifs_dbg(FYI, "%s: Downcall contained malformed key (datalen=%hu)\n",
			 __func__, sidkey->datalen);
		key_invalidate(sidkey);
		goto out_key_put;
	}

	if (sidtype == SIDOWNER) {
		kuid_t uid;
		uid_t id;
		memcpy(&id, &sidkey->payload.data[0], sizeof(uid_t));
		uid = make_kuid(&init_user_ns, id);
		if (uid_valid(uid))
			fuid = uid;
	} else {
		kgid_t gid;
		gid_t id;
		memcpy(&id, &sidkey->payload.data[0], sizeof(gid_t));
		gid = make_kgid(&init_user_ns, id);
		if (gid_valid(gid))
			fgid = gid;
	}

out_key_put:
	key_put(sidkey);
out_revert_creds:
	revert_creds(saved_cred);
	kfree(sidstr);

	/*
	 * Note that we return 0 here unconditionally. If the mapping
	 * fails then we just fall back to using the ctx->linux_uid/linux_gid.
	 */
got_valid_id:
	rc = 0;
	if (sidtype == SIDOWNER)
		fattr->cf_uid = fuid;
	else
		fattr->cf_gid = fgid;
	return rc;
}

int
init_cifs_idmap(void)
{
	struct cred *cred;
	struct key *keyring;
	int ret;

	cifs_dbg(FYI, "Registering the %s key type\n",
		 cifs_idmap_key_type.name);

	/* create an override credential set with a special thread keyring in
	 * which requests are cached
	 *
	 * this is used to prevent malicious redirections from being installed
	 * with add_key().
	 */
	cred = prepare_kernel_cred(&init_task);
	if (!cred)
		return -ENOMEM;

	keyring = keyring_alloc(".cifs_idmap",
				GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred,
				(KEY_POS_ALL & ~KEY_POS_SETATTR) |
				KEY_USR_VIEW | KEY_USR_READ,
				KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto failed_put_cred;
	}

	ret = register_key_type(&cifs_idmap_key_type);
	if (ret < 0)
		goto failed_put_key;

	/* instruct request_key() to use this special keyring as a cache for
	 * the results it looks up */
	set_bit(KEY_FLAG_ROOT_CAN_CLEAR, &keyring->flags);
	cred->thread_keyring = keyring;
	cred->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
	root_cred = cred;

	cifs_dbg(FYI, "cifs idmap keyring: %d\n", key_serial(keyring));
	return 0;

failed_put_key:
	key_put(keyring);
failed_put_cred:
	put_cred(cred);
	return ret;
}

void
exit_cifs_idmap(void)
{
	key_revoke(root_cred->thread_keyring);
	unregister_key_type(&cifs_idmap_key_type);
	put_cred(root_cred);
	cifs_dbg(FYI, "Unregistered %s key type\n", cifs_idmap_key_type.name);
}

/* copy ntsd, owner sid, and group sid from a security descriptor to another */
static __u32 copy_sec_desc(const struct cifs_ntsd *pntsd,
				struct cifs_ntsd *pnntsd,
				__u32 sidsoffset,
				struct cifs_sid *pownersid,
				struct cifs_sid *pgrpsid)
{
	struct cifs_sid *owner_sid_ptr, *group_sid_ptr;
	struct cifs_sid *nowner_sid_ptr, *ngroup_sid_ptr;

	/* copy security descriptor control portion */
	pnntsd->revision = pntsd->revision;
	pnntsd->type = pntsd->type;
	pnntsd->dacloffset = cpu_to_le32(sizeof(struct cifs_ntsd));
	pnntsd->sacloffset = 0;
	pnntsd->osidoffset = cpu_to_le32(sidsoffset);
	pnntsd->gsidoffset = cpu_to_le32(sidsoffset + sizeof(struct cifs_sid));

	/* copy owner sid */
	if (pownersid)
		owner_sid_ptr = pownersid;
	else
		owner_sid_ptr = (struct cifs_sid *)((char *)pntsd +
				le32_to_cpu(pntsd->osidoffset));
	nowner_sid_ptr = (struct cifs_sid *)((char *)pnntsd + sidsoffset);
	cifs_copy_sid(nowner_sid_ptr, owner_sid_ptr);

	/* copy group sid */
	if (pgrpsid)
		group_sid_ptr = pgrpsid;
	else
		group_sid_ptr = (struct cifs_sid *)((char *)pntsd +
				le32_to_cpu(pntsd->gsidoffset));
	ngroup_sid_ptr = (struct cifs_sid *)((char *)pnntsd + sidsoffset +
					sizeof(struct cifs_sid));
	cifs_copy_sid(ngroup_sid_ptr, group_sid_ptr);

	return sidsoffset + (2 * sizeof(struct cifs_sid));
}


/*
   change posix mode to reflect permissions
   pmode is the existing mode (we only want to overwrite part of this
   bits to set can be: S_IRWXU, S_IRWXG or S_IRWXO ie 00700 or 00070 or 00007
*/
static void access_flags_to_mode(__le32 ace_flags, int type, umode_t *pmode,
				 umode_t *pdenied, umode_t mask)
{
	__u32 flags = le32_to_cpu(ace_flags);
	/*
	 * Do not assume "preferred" or "canonical" order.
	 * The first DENY or ALLOW ACE which matches perfectly is
	 * the permission to be used. Once allowed or denied, same
	 * permission in later ACEs do not matter.
	 */

	/* If not already allowed, deny these bits */
	if (type == ACCESS_DENIED) {
		if (flags & GENERIC_ALL &&
				!(*pmode & mask & 0777))
			*pdenied |= mask & 0777;

		if (((flags & GENERIC_WRITE) ||
				((flags & FILE_WRITE_RIGHTS) == FILE_WRITE_RIGHTS)) &&
				!(*pmode & mask & 0222))
			*pdenied |= mask & 0222;

		if (((flags & GENERIC_READ) ||
				((flags & FILE_READ_RIGHTS) == FILE_READ_RIGHTS)) &&
				!(*pmode & mask & 0444))
			*pdenied |= mask & 0444;

		if (((flags & GENERIC_EXECUTE) ||
				((flags & FILE_EXEC_RIGHTS) == FILE_EXEC_RIGHTS)) &&
				!(*pmode & mask & 0111))
			*pdenied |= mask & 0111;

		return;
	} else if (type != ACCESS_ALLOWED) {
		cifs_dbg(VFS, "unknown access control type %d\n", type);
		return;
	}
	/* else ACCESS_ALLOWED type */

	if ((flags & GENERIC_ALL) &&
			!(*pdenied & mask & 0777)) {
		*pmode |= mask & 0777;
		cifs_dbg(NOISY, "all perms\n");
		return;
	}

	if (((flags & GENERIC_WRITE) ||
			((flags & FILE_WRITE_RIGHTS) == FILE_WRITE_RIGHTS)) &&
			!(*pdenied & mask & 0222))
		*pmode |= mask & 0222;

	if (((flags & GENERIC_READ) ||
			((flags & FILE_READ_RIGHTS) == FILE_READ_RIGHTS)) &&
			!(*pdenied & mask & 0444))
		*pmode |= mask & 0444;

	if (((flags & GENERIC_EXECUTE) ||
			((flags & FILE_EXEC_RIGHTS) == FILE_EXEC_RIGHTS)) &&
			!(*pdenied & mask & 0111))
		*pmode |= mask & 0111;

	/* If DELETE_CHILD is set only on an owner ACE, set sticky bit */
	if (flags & FILE_DELETE_CHILD) {
		if (mask == ACL_OWNER_MASK) {
			if (!(*pdenied & 01000))
				*pmode |= 01000;
		} else if (!(*pdenied & 01000)) {
			*pmode &= ~01000;
			*pdenied |= 01000;
		}
	}

	cifs_dbg(NOISY, "access flags 0x%x mode now %04o\n", flags, *pmode);
	return;
}

/*
   Generate access flags to reflect permissions mode is the existing mode.
   This function is called for every ACE in the DACL whose SID matches
   with either owner or group or everyone.
*/

static void mode_to_access_flags(umode_t mode, umode_t bits_to_use,
				__u32 *pace_flags)
{
	/* reset access mask */
	*pace_flags = 0x0;

	/* bits to use are either S_IRWXU or S_IRWXG or S_IRWXO */
	mode &= bits_to_use;

	/* check for R/W/X UGO since we do not know whose flags
	   is this but we have cleared all the bits sans RWX for
	   either user or group or other as per bits_to_use */
	if (mode & S_IRUGO)
		*pace_flags |= SET_FILE_READ_RIGHTS;
	if (mode & S_IWUGO)
		*pace_flags |= SET_FILE_WRITE_RIGHTS;
	if (mode & S_IXUGO)
		*pace_flags |= SET_FILE_EXEC_RIGHTS;

	cifs_dbg(NOISY, "mode: %04o, access flags now 0x%x\n",
		 mode, *pace_flags);
	return;
}

static __u16 cifs_copy_ace(struct cifs_ace *dst, struct cifs_ace *src, struct cifs_sid *psid)
{
	__u16 size = 1 + 1 + 2 + 4;

	dst->type = src->type;
	dst->flags = src->flags;
	dst->access_req = src->access_req;

	/* Check if there's a replacement sid specified */
	if (psid)
		size += cifs_copy_sid(&dst->sid, psid);
	else
		size += cifs_copy_sid(&dst->sid, &src->sid);

	dst->size = cpu_to_le16(size);

	return size;
}

static __u16 fill_ace_for_sid(struct cifs_ace *pntace,
			const struct cifs_sid *psid, __u64 nmode,
			umode_t bits, __u8 access_type,
			bool allow_delete_child)
{
	int i;
	__u16 size = 0;
	__u32 access_req = 0;

	pntace->type = access_type;
	pntace->flags = 0x0;
	mode_to_access_flags(nmode, bits, &access_req);

	if (access_type == ACCESS_ALLOWED && allow_delete_child)
		access_req |= FILE_DELETE_CHILD;

	if (access_type == ACCESS_ALLOWED && !access_req)
		access_req = SET_MINIMUM_RIGHTS;
	else if (access_type == ACCESS_DENIED)
		access_req &= ~SET_MINIMUM_RIGHTS;

	pntace->access_req = cpu_to_le32(access_req);

	pntace->sid.revision = psid->revision;
	pntace->sid.num_subauth = psid->num_subauth;
	for (i = 0; i < NUM_AUTHS; i++)
		pntace->sid.authority[i] = psid->authority[i];
	for (i = 0; i < psid->num_subauth; i++)
		pntace->sid.sub_auth[i] = psid->sub_auth[i];

	size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (psid->num_subauth * 4);
	pntace->size = cpu_to_le16(size);

	return size;
}


#ifdef CONFIG_CIFS_DEBUG2
static void dump_ace(struct cifs_ace *pace, char *end_of_acl)
{
	int num_subauth;

	/* validate that we do not go past end of acl */

	if (le16_to_cpu(pace->size) < 16) {
		cifs_dbg(VFS, "ACE too small %d\n", le16_to_cpu(pace->size));
		return;
	}

	if (end_of_acl < (char *)pace + le16_to_cpu(pace->size)) {
		cifs_dbg(VFS, "ACL too small to parse ACE\n");
		return;
	}

	num_subauth = pace->sid.num_subauth;
	if (num_subauth) {
		int i;
		cifs_dbg(FYI, "ACE revision %d num_auth %d type %d flags %d size %d\n",
			 pace->sid.revision, pace->sid.num_subauth, pace->type,
			 pace->flags, le16_to_cpu(pace->size));
		for (i = 0; i < num_subauth; ++i) {
			cifs_dbg(FYI, "ACE sub_auth[%d]: 0x%x\n",
				 i, le32_to_cpu(pace->sid.sub_auth[i]));
		}

		/* BB add length check to make sure that we do not have huge
			num auths and therefore go off the end */
	}

	return;
}
#endif

static void parse_dacl(struct cifs_acl *pdacl, char *end_of_acl,
		       struct cifs_sid *pownersid, struct cifs_sid *pgrpsid,
		       struct cifs_fattr *fattr, bool mode_from_special_sid)
{
	int i;
	int num_aces = 0;
	int acl_size;
	char *acl_base;
	struct cifs_ace **ppace;

	/* BB need to add parm so we can store the SID BB */

	if (!pdacl) {
		/* no DACL in the security descriptor, set
		   all the permissions for user/group/other */
		fattr->cf_mode |= 0777;
		return;
	}

	/* validate that we do not go past end of acl */
	if (end_of_acl < (char *)pdacl + le16_to_cpu(pdacl->size)) {
		cifs_dbg(VFS, "ACL too small to parse DACL\n");
		return;
	}

	cifs_dbg(NOISY, "DACL revision %d size %d num aces %d\n",
		 le16_to_cpu(pdacl->revision), le16_to_cpu(pdacl->size),
		 le32_to_cpu(pdacl->num_aces));

	/* reset rwx permissions for user/group/other.
	   Also, if num_aces is 0 i.e. DACL has no ACEs,
	   user/group/other have no permissions */
	fattr->cf_mode &= ~(0777);

	acl_base = (char *)pdacl;
	acl_size = sizeof(struct cifs_acl);

	num_aces = le32_to_cpu(pdacl->num_aces);
	if (num_aces > 0) {
		umode_t denied_mode = 0;

		if (num_aces > ULONG_MAX / sizeof(struct cifs_ace *))
			return;
		ppace = kmalloc_array(num_aces, sizeof(struct cifs_ace *),
				      GFP_KERNEL);
		if (!ppace)
			return;

		for (i = 0; i < num_aces; ++i) {
			ppace[i] = (struct cifs_ace *) (acl_base + acl_size);
#ifdef CONFIG_CIFS_DEBUG2
			dump_ace(ppace[i], end_of_acl);
#endif
			if (mode_from_special_sid &&
			    (compare_sids(&(ppace[i]->sid),
					  &sid_unix_NFS_mode) == 0)) {
				/*
				 * Full permissions are:
				 * 07777 = S_ISUID | S_ISGID | S_ISVTX |
				 *         S_IRWXU | S_IRWXG | S_IRWXO
				 */
				fattr->cf_mode &= ~07777;
				fattr->cf_mode |=
					le32_to_cpu(ppace[i]->sid.sub_auth[2]);
				break;
			} else {
				if (compare_sids(&(ppace[i]->sid), pownersid) == 0) {
					access_flags_to_mode(ppace[i]->access_req,
							ppace[i]->type,
							&fattr->cf_mode,
							&denied_mode,
							ACL_OWNER_MASK);
				} else if (compare_sids(&(ppace[i]->sid), pgrpsid) == 0) {
					access_flags_to_mode(ppace[i]->access_req,
							ppace[i]->type,
							&fattr->cf_mode,
							&denied_mode,
							ACL_GROUP_MASK);
				} else if ((compare_sids(&(ppace[i]->sid), &sid_everyone) == 0) ||
						(compare_sids(&(ppace[i]->sid), &sid_authusers) == 0)) {
					access_flags_to_mode(ppace[i]->access_req,
							ppace[i]->type,
							&fattr->cf_mode,
							&denied_mode,
							ACL_EVERYONE_MASK);
				}
			}


/*			memcpy((void *)(&(cifscred->aces[i])),
				(void *)ppace[i],
				sizeof(struct cifs_ace)); */

			acl_base = (char *)ppace[i];
			acl_size = le16_to_cpu(ppace[i]->size);
		}

		kfree(ppace);
	}

	return;
}

unsigned int setup_authusers_ACE(struct cifs_ace *pntace)
{
	int i;
	unsigned int ace_size = 20;

	pntace->type = ACCESS_ALLOWED_ACE_TYPE;
	pntace->flags = 0x0;
	pntace->access_req = cpu_to_le32(GENERIC_ALL);
	pntace->sid.num_subauth = 1;
	pntace->sid.revision = 1;
	for (i = 0; i < NUM_AUTHS; i++)
		pntace->sid.authority[i] =  sid_authusers.authority[i];

	pntace->sid.sub_auth[0] =  sid_authusers.sub_auth[0];

	/* size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (psid->num_subauth*4) */
	pntace->size = cpu_to_le16(ace_size);
	return ace_size;
}

/*
 * Fill in the special SID based on the mode. See
 * https://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */
unsigned int setup_special_mode_ACE(struct cifs_ace *pntace, __u64 nmode)
{
	int i;
	unsigned int ace_size = 28;

	pntace->type = ACCESS_DENIED_ACE_TYPE;
	pntace->flags = 0x0;
	pntace->access_req = 0;
	pntace->sid.num_subauth = 3;
	pntace->sid.revision = 1;
	for (i = 0; i < NUM_AUTHS; i++)
		pntace->sid.authority[i] = sid_unix_NFS_mode.authority[i];

	pntace->sid.sub_auth[0] = sid_unix_NFS_mode.sub_auth[0];
	pntace->sid.sub_auth[1] = sid_unix_NFS_mode.sub_auth[1];
	pntace->sid.sub_auth[2] = cpu_to_le32(nmode & 07777);

	/* size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (psid->num_subauth*4) */
	pntace->size = cpu_to_le16(ace_size);
	return ace_size;
}

unsigned int setup_special_user_owner_ACE(struct cifs_ace *pntace)
{
	int i;
	unsigned int ace_size = 28;

	pntace->type = ACCESS_ALLOWED_ACE_TYPE;
	pntace->flags = 0x0;
	pntace->access_req = cpu_to_le32(GENERIC_ALL);
	pntace->sid.num_subauth = 3;
	pntace->sid.revision = 1;
	for (i = 0; i < NUM_AUTHS; i++)
		pntace->sid.authority[i] = sid_unix_NFS_users.authority[i];

	pntace->sid.sub_auth[0] = sid_unix_NFS_users.sub_auth[0];
	pntace->sid.sub_auth[1] = sid_unix_NFS_users.sub_auth[1];
	pntace->sid.sub_auth[2] = cpu_to_le32(current_fsgid().val);

	/* size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (psid->num_subauth*4) */
	pntace->size = cpu_to_le16(ace_size);
	return ace_size;
}

static void populate_new_aces(char *nacl_base,
		struct cifs_sid *pownersid,
		struct cifs_sid *pgrpsid,
		__u64 *pnmode, u32 *pnum_aces, u16 *pnsize,
		bool modefromsid)
{
	__u64 nmode;
	u32 num_aces = 0;
	u16 nsize = 0;
	__u64 user_mode;
	__u64 group_mode;
	__u64 other_mode;
	__u64 deny_user_mode = 0;
	__u64 deny_group_mode = 0;
	bool sticky_set = false;
	struct cifs_ace *pnntace = NULL;

	nmode = *pnmode;
	num_aces = *pnum_aces;
	nsize = *pnsize;

	if (modefromsid) {
		pnntace = (struct cifs_ace *) (nacl_base + nsize);
		nsize += setup_special_mode_ACE(pnntace, nmode);
		num_aces++;
		pnntace = (struct cifs_ace *) (nacl_base + nsize);
		nsize += setup_authusers_ACE(pnntace);
		num_aces++;
		goto set_size;
	}

	/*
	 * We'll try to keep the mode as requested by the user.
	 * But in cases where we cannot meaningfully convert that
	 * into ACL, return back the updated mode, so that it is
	 * updated in the inode.
	 */

	if (!memcmp(pownersid, pgrpsid, sizeof(struct cifs_sid))) {
		/*
		 * Case when owner and group SIDs are the same.
		 * Set the more restrictive of the two modes.
		 */
		user_mode = nmode & (nmode << 3) & 0700;
		group_mode = nmode & (nmode >> 3) & 0070;
	} else {
		user_mode = nmode & 0700;
		group_mode = nmode & 0070;
	}

	other_mode = nmode & 0007;

	/* We need DENY ACE when the perm is more restrictive than the next sets. */
	deny_user_mode = ~(user_mode) & ((group_mode << 3) | (other_mode << 6)) & 0700;
	deny_group_mode = ~(group_mode) & (other_mode << 3) & 0070;

	*pnmode = user_mode | group_mode | other_mode | (nmode & ~0777);

	/* This tells if we should allow delete child for group and everyone. */
	if (nmode & 01000)
		sticky_set = true;

	if (deny_user_mode) {
		pnntace = (struct cifs_ace *) (nacl_base + nsize);
		nsize += fill_ace_for_sid(pnntace, pownersid, deny_user_mode,
				0700, ACCESS_DENIED, false);
		num_aces++;
	}

	/* Group DENY ACE does not conflict with owner ALLOW ACE. Keep in preferred order*/
	if (deny_group_mode && !(deny_group_mode & (user_mode >> 3))) {
		pnntace = (struct cifs_ace *) (nacl_base + nsize);
		nsize += fill_ace_for_sid(pnntace, pgrpsid, deny_group_mode,
				0070, ACCESS_DENIED, false);
		num_aces++;
	}

	pnntace = (struct cifs_ace *) (nacl_base + nsize);
	nsize += fill_ace_for_sid(pnntace, pownersid, user_mode,
			0700, ACCESS_ALLOWED, true);
	num_aces++;

	/* Group DENY ACE conflicts with owner ALLOW ACE. So keep it after. */
	if (deny_group_mode && (deny_group_mode & (user_mode >> 3))) {
		pnntace = (struct cifs_ace *) (nacl_base + nsize);
		nsize += fill_ace_for_sid(pnntace, pgrpsid, deny_group_mode,
				0070, ACCESS_DENIED, false);
		num_aces++;
	}

	pnntace = (struct cifs_ace *) (nacl_base + nsize);
	nsize += fill_ace_for_sid(pnntace, pgrpsid, group_mode,
			0070, ACCESS_ALLOWED, !sticky_set);
	num_aces++;

	pnntace = (struct cifs_ace *) (nacl_base + nsize);
	nsize += fill_ace_for_sid(pnntace, &sid_everyone, other_mode,
			0007, ACCESS_ALLOWED, !sticky_set);
	num_aces++;

set_size:
	*pnum_aces = num_aces;
	*pnsize = nsize;
}

static __u16 replace_sids_and_copy_aces(struct cifs_acl *pdacl, struct cifs_acl *pndacl,
		struct cifs_sid *pownersid, struct cifs_sid *pgrpsid,
		struct cifs_sid *pnownersid, struct cifs_sid *pngrpsid)
{
	int i;
	u16 size = 0;
	struct cifs_ace *pntace = NULL;
	char *acl_base = NULL;
	u32 src_num_aces = 0;
	u16 nsize = 0;
	struct cifs_ace *pnntace = NULL;
	char *nacl_base = NULL;
	u16 ace_size = 0;

	acl_base = (char *)pdacl;
	size = sizeof(struct cifs_acl);
	src_num_aces = le32_to_cpu(pdacl->num_aces);

	nacl_base = (char *)pndacl;
	nsize = sizeof(struct cifs_acl);

	/* Go through all the ACEs */
	for (i = 0; i < src_num_aces; ++i) {
		pntace = (struct cifs_ace *) (acl_base + size);
		pnntace = (struct cifs_ace *) (nacl_base + nsize);

		if (pnownersid && compare_sids(&pntace->sid, pownersid) == 0)
			ace_size = cifs_copy_ace(pnntace, pntace, pnownersid);
		else if (pngrpsid && compare_sids(&pntace->sid, pgrpsid) == 0)
			ace_size = cifs_copy_ace(pnntace, pntace, pngrpsid);
		else
			ace_size = cifs_copy_ace(pnntace, pntace, NULL);

		size += le16_to_cpu(pntace->size);
		nsize += ace_size;
	}

	return nsize;
}

static int set_chmod_dacl(struct cifs_acl *pdacl, struct cifs_acl *pndacl,
		struct cifs_sid *pownersid,	struct cifs_sid *pgrpsid,
		__u64 *pnmode, bool mode_from_sid)
{
	int i;
	u16 size = 0;
	struct cifs_ace *pntace = NULL;
	char *acl_base = NULL;
	u32 src_num_aces = 0;
	u16 nsize = 0;
	struct cifs_ace *pnntace = NULL;
	char *nacl_base = NULL;
	u32 num_aces = 0;
	bool new_aces_set = false;

	/* Assuming that pndacl and pnmode are never NULL */
	nacl_base = (char *)pndacl;
	nsize = sizeof(struct cifs_acl);

	/* If pdacl is NULL, we don't have a src. Simply populate new ACL. */
	if (!pdacl) {
		populate_new_aces(nacl_base,
				pownersid, pgrpsid,
				pnmode, &num_aces, &nsize,
				mode_from_sid);
		goto finalize_dacl;
	}

	acl_base = (char *)pdacl;
	size = sizeof(struct cifs_acl);
	src_num_aces = le32_to_cpu(pdacl->num_aces);

	/* Retain old ACEs which we can retain */
	for (i = 0; i < src_num_aces; ++i) {
		pntace = (struct cifs_ace *) (acl_base + size);

		if (!new_aces_set && (pntace->flags & INHERITED_ACE)) {
			/* Place the new ACEs in between existing explicit and inherited */
			populate_new_aces(nacl_base,
					pownersid, pgrpsid,
					pnmode, &num_aces, &nsize,
					mode_from_sid);

			new_aces_set = true;
		}

		/* If it's any one of the ACE we're replacing, skip! */
		if (((compare_sids(&pntace->sid, &sid_unix_NFS_mode) == 0) ||
				(compare_sids(&pntace->sid, pownersid) == 0) ||
				(compare_sids(&pntace->sid, pgrpsid) == 0) ||
				(compare_sids(&pntace->sid, &sid_everyone) == 0) ||
				(compare_sids(&pntace->sid, &sid_authusers) == 0))) {
			goto next_ace;
		}

		/* update the pointer to the next ACE to populate*/
		pnntace = (struct cifs_ace *) (nacl_base + nsize);

		nsize += cifs_copy_ace(pnntace, pntace, NULL);
		num_aces++;

next_ace:
		size += le16_to_cpu(pntace->size);
	}

	/* If inherited ACEs are not present, place the new ones at the tail */
	if (!new_aces_set) {
		populate_new_aces(nacl_base,
				pownersid, pgrpsid,
				pnmode, &num_aces, &nsize,
				mode_from_sid);

		new_aces_set = true;
	}

finalize_dacl:
	pndacl->num_aces = cpu_to_le32(num_aces);
	pndacl->size = cpu_to_le16(nsize);

	return 0;
}

static int parse_sid(struct cifs_sid *psid, char *end_of_acl)
{
	/* BB need to add parm so we can store the SID BB */

	/* validate that we do not go past end of ACL - sid must be at least 8
	   bytes long (assuming no sub-auths - e.g. the null SID */
	if (end_of_acl < (char *)psid + 8) {
		cifs_dbg(VFS, "ACL too small to parse SID %p\n", psid);
		return -EINVAL;
	}

#ifdef CONFIG_CIFS_DEBUG2
	if (psid->num_subauth) {
		int i;
		cifs_dbg(FYI, "SID revision %d num_auth %d\n",
			 psid->revision, psid->num_subauth);

		for (i = 0; i < psid->num_subauth; i++) {
			cifs_dbg(FYI, "SID sub_auth[%d]: 0x%x\n",
				 i, le32_to_cpu(psid->sub_auth[i]));
		}

		/* BB add length check to make sure that we do not have huge
			num auths and therefore go off the end */
		cifs_dbg(FYI, "RID 0x%x\n",
			 le32_to_cpu(psid->sub_auth[psid->num_subauth-1]));
	}
#endif

	return 0;
}


/* Convert CIFS ACL to POSIX form */
static int parse_sec_desc(struct cifs_sb_info *cifs_sb,
		struct cifs_ntsd *pntsd, int acl_len, struct cifs_fattr *fattr,
		bool get_mode_from_special_sid)
{
	int rc = 0;
	struct cifs_sid *owner_sid_ptr, *group_sid_ptr;
	struct cifs_acl *dacl_ptr; /* no need for SACL ptr */
	char *end_of_acl = ((char *)pntsd) + acl_len;
	__u32 dacloffset;

	if (pntsd == NULL)
		return -EIO;

	owner_sid_ptr = (struct cifs_sid *)((char *)pntsd +
				le32_to_cpu(pntsd->osidoffset));
	group_sid_ptr = (struct cifs_sid *)((char *)pntsd +
				le32_to_cpu(pntsd->gsidoffset));
	dacloffset = le32_to_cpu(pntsd->dacloffset);
	dacl_ptr = (struct cifs_acl *)((char *)pntsd + dacloffset);
	cifs_dbg(NOISY, "revision %d type 0x%x ooffset 0x%x goffset 0x%x sacloffset 0x%x dacloffset 0x%x\n",
		 pntsd->revision, pntsd->type, le32_to_cpu(pntsd->osidoffset),
		 le32_to_cpu(pntsd->gsidoffset),
		 le32_to_cpu(pntsd->sacloffset), dacloffset);
/*	cifs_dump_mem("owner_sid: ", owner_sid_ptr, 64); */
	rc = parse_sid(owner_sid_ptr, end_of_acl);
	if (rc) {
		cifs_dbg(FYI, "%s: Error %d parsing Owner SID\n", __func__, rc);
		return rc;
	}
	rc = sid_to_id(cifs_sb, owner_sid_ptr, fattr, SIDOWNER);
	if (rc) {
		cifs_dbg(FYI, "%s: Error %d mapping Owner SID to uid\n",
			 __func__, rc);
		return rc;
	}

	rc = parse_sid(group_sid_ptr, end_of_acl);
	if (rc) {
		cifs_dbg(FYI, "%s: Error %d mapping Owner SID to gid\n",
			 __func__, rc);
		return rc;
	}
	rc = sid_to_id(cifs_sb, group_sid_ptr, fattr, SIDGROUP);
	if (rc) {
		cifs_dbg(FYI, "%s: Error %d mapping Group SID to gid\n",
			 __func__, rc);
		return rc;
	}

	if (dacloffset)
		parse_dacl(dacl_ptr, end_of_acl, owner_sid_ptr,
			   group_sid_ptr, fattr, get_mode_from_special_sid);
	else
		cifs_dbg(FYI, "no ACL\n"); /* BB grant all or default perms? */

	return rc;
}

/* Convert permission bits from mode to equivalent CIFS ACL */
static int build_sec_desc(struct cifs_ntsd *pntsd, struct cifs_ntsd *pnntsd,
	__u32 secdesclen, __u32 *pnsecdesclen, __u64 *pnmode, kuid_t uid, kgid_t gid,
	bool mode_from_sid, bool id_from_sid, int *aclflag)
{
	int rc = 0;
	__u32 dacloffset;
	__u32 ndacloffset;
	__u32 sidsoffset;
	struct cifs_sid *owner_sid_ptr, *group_sid_ptr;
	struct cifs_sid *nowner_sid_ptr = NULL, *ngroup_sid_ptr = NULL;
	struct cifs_acl *dacl_ptr = NULL;  /* no need for SACL ptr */
	struct cifs_acl *ndacl_ptr = NULL; /* no need for SACL ptr */
	char *end_of_acl = ((char *)pntsd) + secdesclen;
	u16 size = 0;

	dacloffset = le32_to_cpu(pntsd->dacloffset);
	if (dacloffset) {
		dacl_ptr = (struct cifs_acl *)((char *)pntsd + dacloffset);
		if (end_of_acl < (char *)dacl_ptr + le16_to_cpu(dacl_ptr->size)) {
			cifs_dbg(VFS, "Server returned illegal ACL size\n");
			return -EINVAL;
		}
	}

	owner_sid_ptr = (struct cifs_sid *)((char *)pntsd +
			le32_to_cpu(pntsd->osidoffset));
	group_sid_ptr = (struct cifs_sid *)((char *)pntsd +
			le32_to_cpu(pntsd->gsidoffset));

	if (pnmode && *pnmode != NO_CHANGE_64) { /* chmod */
		ndacloffset = sizeof(struct cifs_ntsd);
		ndacl_ptr = (struct cifs_acl *)((char *)pnntsd + ndacloffset);
		ndacl_ptr->revision =
			dacloffset ? dacl_ptr->revision : cpu_to_le16(ACL_REVISION);

		ndacl_ptr->size = cpu_to_le16(0);
		ndacl_ptr->num_aces = cpu_to_le32(0);

		rc = set_chmod_dacl(dacl_ptr, ndacl_ptr, owner_sid_ptr, group_sid_ptr,
				    pnmode, mode_from_sid);

		sidsoffset = ndacloffset + le16_to_cpu(ndacl_ptr->size);
		/* copy the non-dacl portion of secdesc */
		*pnsecdesclen = copy_sec_desc(pntsd, pnntsd, sidsoffset,
				NULL, NULL);

		*aclflag |= CIFS_ACL_DACL;
	} else {
		ndacloffset = sizeof(struct cifs_ntsd);
		ndacl_ptr = (struct cifs_acl *)((char *)pnntsd + ndacloffset);
		ndacl_ptr->revision =
			dacloffset ? dacl_ptr->revision : cpu_to_le16(ACL_REVISION);
		ndacl_ptr->num_aces = dacl_ptr ? dacl_ptr->num_aces : 0;

		if (uid_valid(uid)) { /* chown */
			uid_t id;
			nowner_sid_ptr = kzalloc(sizeof(struct cifs_sid),
								GFP_KERNEL);
			if (!nowner_sid_ptr) {
				rc = -ENOMEM;
				goto chown_chgrp_exit;
			}
			id = from_kuid(&init_user_ns, uid);
			if (id_from_sid) {
				struct owner_sid *osid = (struct owner_sid *)nowner_sid_ptr;
				/* Populate the user ownership fields S-1-5-88-1 */
				osid->Revision = 1;
				osid->NumAuth = 3;
				osid->Authority[5] = 5;
				osid->SubAuthorities[0] = cpu_to_le32(88);
				osid->SubAuthorities[1] = cpu_to_le32(1);
				osid->SubAuthorities[2] = cpu_to_le32(id);

			} else { /* lookup sid with upcall */
				rc = id_to_sid(id, SIDOWNER, nowner_sid_ptr);
				if (rc) {
					cifs_dbg(FYI, "%s: Mapping error %d for owner id %d\n",
						 __func__, rc, id);
					goto chown_chgrp_exit;
				}
			}
			*aclflag |= CIFS_ACL_OWNER;
		}
		if (gid_valid(gid)) { /* chgrp */
			gid_t id;
			ngroup_sid_ptr = kzalloc(sizeof(struct cifs_sid),
								GFP_KERNEL);
			if (!ngroup_sid_ptr) {
				rc = -ENOMEM;
				goto chown_chgrp_exit;
			}
			id = from_kgid(&init_user_ns, gid);
			if (id_from_sid) {
				struct owner_sid *gsid = (struct owner_sid *)ngroup_sid_ptr;
				/* Populate the group ownership fields S-1-5-88-2 */
				gsid->Revision = 1;
				gsid->NumAuth = 3;
				gsid->Authority[5] = 5;
				gsid->SubAuthorities[0] = cpu_to_le32(88);
				gsid->SubAuthorities[1] = cpu_to_le32(2);
				gsid->SubAuthorities[2] = cpu_to_le32(id);

			} else { /* lookup sid with upcall */
				rc = id_to_sid(id, SIDGROUP, ngroup_sid_ptr);
				if (rc) {
					cifs_dbg(FYI, "%s: Mapping error %d for group id %d\n",
						 __func__, rc, id);
					goto chown_chgrp_exit;
				}
			}
			*aclflag |= CIFS_ACL_GROUP;
		}

		if (dacloffset) {
			/* Replace ACEs for old owner with new one */
			size = replace_sids_and_copy_aces(dacl_ptr, ndacl_ptr,
					owner_sid_ptr, group_sid_ptr,
					nowner_sid_ptr, ngroup_sid_ptr);
			ndacl_ptr->size = cpu_to_le16(size);
		}

		sidsoffset = ndacloffset + le16_to_cpu(ndacl_ptr->size);
		/* copy the non-dacl portion of secdesc */
		*pnsecdesclen = copy_sec_desc(pntsd, pnntsd, sidsoffset,
				nowner_sid_ptr, ngroup_sid_ptr);

chown_chgrp_exit:
		/* errors could jump here. So make sure we return soon after this */
		kfree(nowner_sid_ptr);
		kfree(ngroup_sid_ptr);
	}

	return rc;
}

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
struct cifs_ntsd *get_cifs_acl_by_fid(struct cifs_sb_info *cifs_sb,
				      const struct cifs_fid *cifsfid, u32 *pacllen,
				      u32 __maybe_unused unused)
{
	struct cifs_ntsd *pntsd = NULL;
	unsigned int xid;
	int rc;
	struct tcon_link *tlink = cifs_sb_tlink(cifs_sb);

	if (IS_ERR(tlink))
		return ERR_CAST(tlink);

	xid = get_xid();
	rc = CIFSSMBGetCIFSACL(xid, tlink_tcon(tlink), cifsfid->netfid, &pntsd,
				pacllen);
	free_xid(xid);

	cifs_put_tlink(tlink);

	cifs_dbg(FYI, "%s: rc = %d ACL len %d\n", __func__, rc, *pacllen);
	if (rc)
		return ERR_PTR(rc);
	return pntsd;
}

static struct cifs_ntsd *get_cifs_acl_by_path(struct cifs_sb_info *cifs_sb,
		const char *path, u32 *pacllen)
{
	struct cifs_ntsd *pntsd = NULL;
	int oplock = 0;
	unsigned int xid;
	int rc;
	struct cifs_tcon *tcon;
	struct tcon_link *tlink = cifs_sb_tlink(cifs_sb);
	struct cifs_fid fid;
	struct cifs_open_parms oparms;

	if (IS_ERR(tlink))
		return ERR_CAST(tlink);

	tcon = tlink_tcon(tlink);
	xid = get_xid();

	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.cifs_sb = cifs_sb,
		.desired_access = READ_CONTROL,
		.create_options = cifs_create_options(cifs_sb, 0),
		.disposition = FILE_OPEN,
		.path = path,
		.fid = &fid,
	};

	rc = CIFS_open(xid, &oparms, &oplock, NULL);
	if (!rc) {
		rc = CIFSSMBGetCIFSACL(xid, tcon, fid.netfid, &pntsd, pacllen);
		CIFSSMBClose(xid, tcon, fid.netfid);
	}

	cifs_put_tlink(tlink);
	free_xid(xid);

	cifs_dbg(FYI, "%s: rc = %d ACL len %d\n", __func__, rc, *pacllen);
	if (rc)
		return ERR_PTR(rc);
	return pntsd;
}

/* Retrieve an ACL from the server */
struct cifs_ntsd *get_cifs_acl(struct cifs_sb_info *cifs_sb,
				      struct inode *inode, const char *path,
			       u32 *pacllen, u32 info)
{
	struct cifs_ntsd *pntsd = NULL;
	struct cifsFileInfo *open_file = NULL;

	if (inode)
		open_file = find_readable_file(CIFS_I(inode), true);
	if (!open_file)
		return get_cifs_acl_by_path(cifs_sb, path, pacllen);

	pntsd = get_cifs_acl_by_fid(cifs_sb, &open_file->fid, pacllen, info);
	cifsFileInfo_put(open_file);
	return pntsd;
}

 /* Set an ACL on the server */
int set_cifs_acl(struct cifs_ntsd *pnntsd, __u32 acllen,
			struct inode *inode, const char *path, int aclflag)
{
	int oplock = 0;
	unsigned int xid;
	int rc, access_flags;
	struct cifs_tcon *tcon;
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct tcon_link *tlink = cifs_sb_tlink(cifs_sb);
	struct cifs_fid fid;
	struct cifs_open_parms oparms;

	if (IS_ERR(tlink))
		return PTR_ERR(tlink);

	tcon = tlink_tcon(tlink);
	xid = get_xid();

	if (aclflag == CIFS_ACL_OWNER || aclflag == CIFS_ACL_GROUP)
		access_flags = WRITE_OWNER;
	else
		access_flags = WRITE_DAC;

	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.cifs_sb = cifs_sb,
		.desired_access = access_flags,
		.create_options = cifs_create_options(cifs_sb, 0),
		.disposition = FILE_OPEN,
		.path = path,
		.fid = &fid,
	};

	rc = CIFS_open(xid, &oparms, &oplock, NULL);
	if (rc) {
		cifs_dbg(VFS, "Unable to open file to set ACL\n");
		goto out;
	}

	rc = CIFSSMBSetCIFSACL(xid, tcon, fid.netfid, pnntsd, acllen, aclflag);
	cifs_dbg(NOISY, "SetCIFSACL rc = %d\n", rc);

	CIFSSMBClose(xid, tcon, fid.netfid);
out:
	free_xid(xid);
	cifs_put_tlink(tlink);
	return rc;
}
#endif /* CONFIG_CIFS_ALLOW_INSECURE_LEGACY */

/* Translate the CIFS ACL (similar to NTFS ACL) for a file into mode bits */
int
cifs_acl_to_fattr(struct cifs_sb_info *cifs_sb, struct cifs_fattr *fattr,
		  struct inode *inode, bool mode_from_special_sid,
		  const char *path, const struct cifs_fid *pfid)
{
	struct cifs_ntsd *pntsd = NULL;
	u32 acllen = 0;
	int rc = 0;
	struct tcon_link *tlink = cifs_sb_tlink(cifs_sb);
	struct smb_version_operations *ops;
	const u32 info = 0;

	cifs_dbg(NOISY, "converting ACL to mode for %s\n", path);

	if (IS_ERR(tlink))
		return PTR_ERR(tlink);

	ops = tlink_tcon(tlink)->ses->server->ops;

	if (pfid && (ops->get_acl_by_fid))
		pntsd = ops->get_acl_by_fid(cifs_sb, pfid, &acllen, info);
	else if (ops->get_acl)
		pntsd = ops->get_acl(cifs_sb, inode, path, &acllen, info);
	else {
		cifs_put_tlink(tlink);
		return -EOPNOTSUPP;
	}
	/* if we can retrieve the ACL, now parse Access Control Entries, ACEs */
	if (IS_ERR(pntsd)) {
		rc = PTR_ERR(pntsd);
		cifs_dbg(VFS, "%s: error %d getting sec desc\n", __func__, rc);
	} else if (mode_from_special_sid) {
		rc = parse_sec_desc(cifs_sb, pntsd, acllen, fattr, true);
		kfree(pntsd);
	} else {
		/* get approximated mode from ACL */
		rc = parse_sec_desc(cifs_sb, pntsd, acllen, fattr, false);
		kfree(pntsd);
		if (rc)
			cifs_dbg(VFS, "parse sec desc failed rc = %d\n", rc);
	}

	cifs_put_tlink(tlink);

	return rc;
}

/* Convert mode bits to an ACL so we can update the ACL on the server */
int
id_mode_to_cifs_acl(struct inode *inode, const char *path, __u64 *pnmode,
			kuid_t uid, kgid_t gid)
{
	int rc = 0;
	int aclflag = CIFS_ACL_DACL; /* default flag to set */
	__u32 secdesclen = 0;
	__u32 nsecdesclen = 0;
	__u32 dacloffset = 0;
	struct cifs_acl *dacl_ptr = NULL;
	struct cifs_ntsd *pntsd = NULL; /* acl obtained from server */
	struct cifs_ntsd *pnntsd = NULL; /* modified acl to be sent to server */
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct tcon_link *tlink = cifs_sb_tlink(cifs_sb);
	struct smb_version_operations *ops;
	bool mode_from_sid, id_from_sid;
	const u32 info = 0;

	if (IS_ERR(tlink))
		return PTR_ERR(tlink);

	ops = tlink_tcon(tlink)->ses->server->ops;

	cifs_dbg(NOISY, "set ACL from mode for %s\n", path);

	/* Get the security descriptor */

	if (ops->get_acl == NULL) {
		cifs_put_tlink(tlink);
		return -EOPNOTSUPP;
	}

	pntsd = ops->get_acl(cifs_sb, inode, path, &secdesclen, info);
	if (IS_ERR(pntsd)) {
		rc = PTR_ERR(pntsd);
		cifs_dbg(VFS, "%s: error %d getting sec desc\n", __func__, rc);
		cifs_put_tlink(tlink);
		return rc;
	}

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MODE_FROM_SID)
		mode_from_sid = true;
	else
		mode_from_sid = false;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_UID_FROM_ACL)
		id_from_sid = true;
	else
		id_from_sid = false;

	/* Potentially, five new ACEs can be added to the ACL for U,G,O mapping */
	nsecdesclen = secdesclen;
	if (pnmode && *pnmode != NO_CHANGE_64) { /* chmod */
		if (mode_from_sid)
			nsecdesclen += 2 * sizeof(struct cifs_ace);
		else /* cifsacl */
			nsecdesclen += 5 * sizeof(struct cifs_ace);
	} else { /* chown */
		/* When ownership changes, changes new owner sid length could be different */
		nsecdesclen = sizeof(struct cifs_ntsd) + (sizeof(struct cifs_sid) * 2);
		dacloffset = le32_to_cpu(pntsd->dacloffset);
		if (dacloffset) {
			dacl_ptr = (struct cifs_acl *)((char *)pntsd + dacloffset);
			if (mode_from_sid)
				nsecdesclen +=
					le32_to_cpu(dacl_ptr->num_aces) * sizeof(struct cifs_ace);
			else /* cifsacl */
				nsecdesclen += le16_to_cpu(dacl_ptr->size);
		}
	}

	/*
	 * Add three ACEs for owner, group, everyone getting rid of other ACEs
	 * as chmod disables ACEs and set the security descriptor. Allocate
	 * memory for the smb header, set security descriptor request security
	 * descriptor parameters, and security descriptor itself
	 */
	nsecdesclen = max_t(u32, nsecdesclen, DEFAULT_SEC_DESC_LEN);
	pnntsd = kmalloc(nsecdesclen, GFP_KERNEL);
	if (!pnntsd) {
		kfree(pntsd);
		cifs_put_tlink(tlink);
		return -ENOMEM;
	}

	rc = build_sec_desc(pntsd, pnntsd, secdesclen, &nsecdesclen, pnmode, uid, gid,
			    mode_from_sid, id_from_sid, &aclflag);

	cifs_dbg(NOISY, "build_sec_desc rc: %d\n", rc);

	if (ops->set_acl == NULL)
		rc = -EOPNOTSUPP;

	if (!rc) {
		/* Set the security descriptor */
		rc = ops->set_acl(pnntsd, nsecdesclen, inode, path, aclflag);
		cifs_dbg(NOISY, "set_cifs_acl rc: %d\n", rc);
	}
	cifs_put_tlink(tlink);

	kfree(pnntsd);
	kfree(pntsd);
	return rc;
}

struct posix_acl *cifs_get_acl(struct mnt_idmap *idmap,
			       struct dentry *dentry, int type)
{
#if defined(CONFIG_CIFS_ALLOW_INSECURE_LEGACY) && defined(CONFIG_CIFS_POSIX)
	struct posix_acl *acl = NULL;
	ssize_t rc = -EOPNOTSUPP;
	unsigned int xid;
	struct super_block *sb = dentry->d_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct tcon_link *tlink;
	struct cifs_tcon *pTcon;
	const char *full_path;
	void *page;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink))
		return ERR_CAST(tlink);
	pTcon = tlink_tcon(tlink);

	xid = get_xid();
	page = alloc_dentry_path();

	full_path = build_path_from_dentry(dentry, page);
	if (IS_ERR(full_path)) {
		acl = ERR_CAST(full_path);
		goto out;
	}

	/* return alt name if available as pseudo attr */
	switch (type) {
	case ACL_TYPE_ACCESS:
		if (sb->s_flags & SB_POSIXACL)
			rc = cifs_do_get_acl(xid, pTcon, full_path, &acl,
					     ACL_TYPE_ACCESS,
					     cifs_sb->local_nls,
					     cifs_remap(cifs_sb));
		break;

	case ACL_TYPE_DEFAULT:
		if (sb->s_flags & SB_POSIXACL)
			rc = cifs_do_get_acl(xid, pTcon, full_path, &acl,
					     ACL_TYPE_DEFAULT,
					     cifs_sb->local_nls,
					     cifs_remap(cifs_sb));
		break;
	}

	if (rc < 0) {
		if (rc == -EINVAL)
			acl = ERR_PTR(-EOPNOTSUPP);
		else
			acl = ERR_PTR(rc);
	}

out:
	free_dentry_path(page);
	free_xid(xid);
	cifs_put_tlink(tlink);
	return acl;
#else
	return ERR_PTR(-EOPNOTSUPP);
#endif
}

int cifs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		 struct posix_acl *acl, int type)
{
#if defined(CONFIG_CIFS_ALLOW_INSECURE_LEGACY) && defined(CONFIG_CIFS_POSIX)
	int rc = -EOPNOTSUPP;
	unsigned int xid;
	struct super_block *sb = dentry->d_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct tcon_link *tlink;
	struct cifs_tcon *pTcon;
	const char *full_path;
	void *page;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink))
		return PTR_ERR(tlink);
	pTcon = tlink_tcon(tlink);

	xid = get_xid();
	page = alloc_dentry_path();

	full_path = build_path_from_dentry(dentry, page);
	if (IS_ERR(full_path)) {
		rc = PTR_ERR(full_path);
		goto out;
	}

	if (!acl)
		goto out;

	/* return dos attributes as pseudo xattr */
	/* return alt name if available as pseudo attr */

	/* if proc/fs/cifs/streamstoxattr is set then
		search server for EAs or streams to
		returns as xattrs */
	if (posix_acl_xattr_size(acl->a_count) > CIFSMaxBufSize) {
		cifs_dbg(FYI, "size of EA value too large\n");
		rc = -EOPNOTSUPP;
		goto out;
	}

	switch (type) {
	case ACL_TYPE_ACCESS:
		if (sb->s_flags & SB_POSIXACL)
			rc = cifs_do_set_acl(xid, pTcon, full_path, acl,
					     ACL_TYPE_ACCESS,
					     cifs_sb->local_nls,
					     cifs_remap(cifs_sb));
		break;

	case ACL_TYPE_DEFAULT:
		if (sb->s_flags & SB_POSIXACL)
			rc = cifs_do_set_acl(xid, pTcon, full_path, acl,
					     ACL_TYPE_DEFAULT,
					     cifs_sb->local_nls,
					     cifs_remap(cifs_sb));
		break;
	}

out:
	free_dentry_path(page);
	free_xid(xid);
	cifs_put_tlink(tlink);
	return rc;
#else
	return -EOPNOTSUPP;
#endif
}

#ifdef CONFIG_TRUENAS
enum account_special_sid_type {
	ACCOUNT_SID_UNKNOWN,
	ACCOUNT_SID_UNIX_USER,
	ACCOUNT_SID_UNIX_GROUP,
	ACCOUNT_SID_NFS_USER,
	ACCOUNT_SID_NFS_GROUP,
};

unsigned int global_zfsaclflags = MODFLAG_DEFAULTS;

static const struct {
	u32 nfs_perm;
	u32 smb_perm;
} nfsperm2smb[] = {
	{ ACE4_READ_DATA, FILE_READ_DATA},
	{ ACE4_WRITE_DATA, FILE_WRITE_DATA},
	{ ACE4_APPEND_DATA, FILE_APPEND_DATA},
	{ ACE4_READ_NAMED_ATTRS, FILE_READ_EA},
	{ ACE4_WRITE_NAMED_ATTRS, FILE_WRITE_EA},
	{ ACE4_EXECUTE, FILE_EXECUTE},
	{ ACE4_DELETE_CHILD, FILE_DELETE_CHILD},
	{ ACE4_READ_ATTRIBUTES, FILE_READ_ATTRIBUTES},
	{ ACE4_WRITE_ATTRIBUTES, FILE_WRITE_ATTRIBUTES},
	{ ACE4_DELETE, DELETE},
	{ ACE4_READ_ACL, READ_CONTROL},
	{ ACE4_WRITE_ACL, WRITE_DAC},
	{ ACE4_WRITE_OWNER, WRITE_OWNER},
	{ ACE4_SYNCHRONIZE, SYNCHRONIZE},
};

static const struct {
	u32 nfs_flag;
	u8 smb_flag;
} nfsflag2smb[] = {
	{ ACE4_FILE_INHERIT_ACE, OBJECT_INHERIT_ACE},
	{ ACE4_DIRECTORY_INHERIT_ACE, CONTAINER_INHERIT_ACE},
	{ ACE4_NO_PROPAGATE_INHERIT_ACE, NO_PROPAGATE_INHERIT_ACE},
	{ ACE4_INHERIT_ONLY_ACE, INHERIT_ONLY_ACE},
	{ ACE4_INHERITED_ACE, INHERITED_ACE},
};

static int
set_xdr_ace(u32 *acep,
	    u32 who_iflag,
	    u32 who_id,
	    u32 ace_type,
	    u32 access_mask,
	    u32 flags)
{
        /* Audit and Alarm are not currently supported */
        if (ace_type > ACE4_ACCESS_DENIED_ACE_TYPE)
                return -EINVAL;

        *acep++ = htonl(ace_type);
        *acep++ = htonl(flags);
        *acep++ = htonl(who_iflag);
        *acep++ = htonl(access_mask);
        *acep++ = htonl(who_id);

        return 0;
}

static enum account_special_sid_type
get_account_special_sid_type(struct cifs_sid *psid)
{
	if (psid->num_subauth == 2) {
		if (psid->sub_auth[0] == sid_unix_groups.sub_auth[0]) {
			return ACCOUNT_SID_UNIX_GROUP;
		} else if (psid->sub_auth[0] == sid_unix_users.sub_auth[0]) {
			return ACCOUNT_SID_UNIX_USER;
		}
	} else if (psid->num_subauth == 3) {
		// S-1-5-88-1-<uid> - NFS user
		// S-1-5-88-2-<gid> - NFS group
		if (psid->sub_auth[0] !=  sid_unix_NFS_groups.sub_auth[0]) {
			// First subauth doesn't match, not an NFS SID
			return ACCOUNT_SID_UNKNOWN;
		}
		if (psid->sub_auth[1] == sid_unix_NFS_groups.sub_auth[1]) {
			return ACCOUNT_SID_NFS_GROUP;
		} else if (psid->sub_auth[1] == sid_unix_NFS_groups.sub_auth[1]) {
			return ACCOUNT_SID_NFS_USER;
		}
	}

	return ACCOUNT_SID_UNKNOWN;
}

/*
 * Per Microsoft Win32 documentation, an empty DACL (i.e. one that
 * is properly initialized and contains no ACEs) grants no access to the
 * object it is assigned to. We can't set an empty ACL on ZFS, and so the
 * best we can do is create an ACL with a single entry granting file owner
 * owner@ no rights. Note that in Windows and Unix the file owner is able
 * to override the ACL.
 */
static int
generate_empty_zfsacl(char **buf_out)
{
	u32 *xdrbuf = NULL, *zfsacl;
	xdrbuf = kzalloc(ACES_TO_XDRSIZE(1), GFP_KERNEL);
	if (!xdrbuf)
		return -ENOMEM;

	zfsacl = xdrbuf;
	*zfsacl++ = 0; /* acl_flags */
	*zfsacl++ = htonl(1); /* acl count */

	set_xdr_ace(zfsacl, ACEI4_SPECIAL_WHO, ACE4_SPECIAL_OWNER,
		    ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0);

	*buf_out = (char *)xdrbuf;
	return ACES_TO_XDRSIZE(1);
}

/*
 * Per Microsoft Win32 documentation, a NULL DACL grants full access to
 * any user that requests it; normal security checking is not performed
 * with respect to the object. We can't set a NULL ZFS ACL and so
 * the best we can do is set one granting everyone@ full control.
 */
static int
generate_null_zfsacl(char **buf_out)
{
	u32 *xdrbuf = NULL, *zfsacl;

	xdrbuf = kzalloc(ACES_TO_XDRSIZE(1), GFP_KERNEL);
	if (!xdrbuf)
		return -ENOMEM;

	zfsacl = xdrbuf;
	*zfsacl++ = 0; /* acl_flags */
	*zfsacl++ = htonl(1); /* acl count */

	set_xdr_ace(zfsacl, ACEI4_SPECIAL_WHO, ACE4_SPECIAL_EVERYONE,
		    ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_ALL_PERMS, 0);

	*buf_out = (char *)xdrbuf;
	return ACES_TO_XDRSIZE(1);
}

/*
 * Convert generic access into NFSv4 perms
 */
static u32
generic_to_nfs(u32 generic_access)
{
	u32 out = 0;
	if (generic_access == GENERIC_ALL) {
		return ACE4_ALL_PERMS;
	}

	if (generic_access & GENERIC_READ) {
		out |= ACE4_READ_PERMS;
	}

	if (generic_access & GENERIC_EXECUTE) {
		out |= ACE4_EXECUTE;
	}

	if (generic_access & GENERIC_WRITE) {
		out |= (ACE4_WRITE_PERMS|ACE4_DELETE);
	}

	return out;
}

static int
convert_smb_access_to_nfs(u32 smbaccess, u32 *nfs_access_out)
{
	int i;
	u32 perms = generic_to_nfs(smbaccess);

	if (perms == ACE4_ALL_PERMS) {
		*nfs_access_out = perms;
		return 0;
	}

	for (i = 0; i < (sizeof(nfsperm2smb) / sizeof(nfsperm2smb[0])); i++) {
		if (smbaccess & nfsperm2smb[i].smb_perm)
			perms |= nfsperm2smb[i].nfs_perm;
	}

	*nfs_access_out = perms;
	return 0;
}

static int
convert_smb_flags_to_nfs(u8 smbflags, u32 *nfs_flags_out)
{
	int i;
	u32 flags = 0;

	if (smbflags & (SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG)) {
		cifs_dbg(VFS, "%s: ACE contains unsupported flags 0x%04x\n",
			 __func__, smbflags);
		return -EINVAL;
	}

	for (i = 0; i < (sizeof(nfsflag2smb) / sizeof(nfsflag2smb[0])); i++) {
		if (smbflags & nfsflag2smb[i].smb_flag)
			flags |= nfsflag2smb[i].nfs_flag;
	}

	*nfs_flags_out = flags;
	return 0;
}

static int
convert_smb_ace_type_to_nfs(u8 smbacetype, u32 *nfs_ace_type_out)
{
	switch (smbacetype) {
	case ACCESS_ALLOWED_ACE_TYPE:
		*nfs_ace_type_out = ACE4_ACCESS_ALLOWED_ACE_TYPE;
		break;
	case ACCESS_DENIED_ACE_TYPE:
		*nfs_ace_type_out = ACE4_ACCESS_DENIED_ACE_TYPE;
		break;
	default:
		cifs_dbg(VFS, "%s: ACE contains unsupported ace type 0x%04x\n",
			 __func__, smbacetype);
		return -EINVAL;
	}

	return 0;
}

/*
 * Convert SID into NFS4 ID and type. Try to map BUILTIN / SPECIAL sids
 * directly to NFS4 special type where possible (to avoid upcall to winbindd).
 *
 * Since the existing idmap key implementation does support return of both
 * users and groups in one call, we first try to retrieve group (because this
 * is in real life much more likely). If retrieving as group fails, we retry
 * as user.
 */
static int
convert_smb_sid_to_nfs_who_special(struct cifs_sid *psid,
				   u32 *iflag,
				   u32 *who_id,
				   u32 *flags)
{
	/*
	 * Check for direct mapping of owner@, group@, and everyone@
	 */
	if (psid->num_subauth > 3) {
		return -ENOENT;
	}

	if (compare_sids(psid, &sid_everyone) == 0) {
		*iflag = ACEI4_SPECIAL_WHO;
		*who_id = ACE4_SPECIAL_EVERYONE;
		return 0;
	}

	if (compare_sids(psid, &sid_creator_owner) == 0) {
		*iflag = ACEI4_SPECIAL_WHO;
		*who_id = ACE4_SPECIAL_OWNER;
		return 0;
	}

	if (compare_sids(psid, &sid_creator_group) == 0) {
		*iflag = ACEI4_SPECIAL_WHO;
		*who_id = ACE4_SPECIAL_GROUP;
		*flags |= ACE4_IDENTIFIER_GROUP;
		return 0;
	}

	/*
	 * SID communicating Unix mode can be safely skipped since we will
	 * get permissions info from other ACL entries
	 */
	if (compare_sids(psid, &sid_unix_NFS_mode) == 0)
		return -EAGAIN;

	/*
	 * SID may directly encode a Unix uid or gid.
	 */
	switch (get_account_special_sid_type(psid)) {
	case ACCOUNT_SID_UNIX_GROUP:
		*flags |= ACE4_IDENTIFIER_GROUP;
		*who_id = le32_to_cpu(psid->sub_auth[1]);
		return 0;
	case ACCOUNT_SID_UNIX_USER:
		*who_id = le32_to_cpu(psid->sub_auth[1]);
		return 0;
	case ACCOUNT_SID_NFS_GROUP:
		*flags |= ACE4_IDENTIFIER_GROUP;
		*who_id = le32_to_cpu(psid->sub_auth[2]);
		return 0;
	case ACCOUNT_SID_NFS_USER:
		*who_id = le32_to_cpu(psid->sub_auth[2]);
		return 0;
	case ACCOUNT_SID_UNKNOWN:
		// This SID most likely is for a user or group
		// which means we must make an upcall
		break;
	}

	return -ENOENT;
}

static int
convert_smb_sid_to_nfs_who(struct cifs_sid *psid, u32 *iflag, u32 *who_id, u32 *flags)
{
	char *sidstr;
	const struct cred *saved_cred;
	struct key *sidkey;
	uint sidtype = SIDGROUP;
	int rc;

	if (unlikely(psid->num_subauth > SID_MAX_SUB_AUTHORITIES)) {
		cifs_dbg(FYI, "%s: subauthority count [%u] exceeds "
			 "maxiumum possible value.\n",
			 __func__, psid->num_subauth);
		return -EINVAL;
	}

	rc = convert_smb_sid_to_nfs_who_special(psid, iflag, who_id, flags);
	switch (rc) {
	case -ENOENT:
		// We need to perform a lookup;
		break;
	case -EAGAIN:
	case 0:
		// EAGAIN means skip this entry
		// zero means that it was converted
		return rc;
	}

	saved_cred = override_creds(root_cred);

try_upcall_to_get_id:
	sidstr = sid_to_key_str(psid, sidtype);
	if (!sidstr) {
		revert_creds(saved_cred);
		return -ENOMEM;
	}
	sidkey = request_key(&cifs_idmap_key_type, sidstr, "");
	if (IS_ERR(sidkey)) {
		if (sidkey == NULL) {
			revert_creds(saved_cred);
			kfree(sidstr);
			return -ENOMEM;
		}

		if ((PTR_ERR(sidkey) == -ENOKEY) &&
		    (sidtype == SIDGROUP)) {
			/*
			 * No group, retry as SIDOWNER
			 */
			kfree(sidstr);
			sidtype = SIDOWNER;
			goto try_upcall_to_get_id;
		}

		cifs_dbg(FYI, "%s: Can't map SID %s to a %cid\n",
			 __func__, sidstr, sidtype == SIDOWNER ? 'u' : 'g');

		kfree(sidstr);
		revert_creds(saved_cred);
		return PTR_ERR(sidkey);
	}

	BUILD_BUG_ON(sizeof(uid_t) != sizeof(gid_t));
	if (sidkey->datalen != sizeof(uid_t)) {
		cifs_dbg(FYI, "%s: Downcall for sid [%s] contained malformed "
			 "key (datalen=%hu)\n",
			 __func__, sidstr, sidkey->datalen);
		key_invalidate(sidkey);
		key_put(sidkey);
		revert_creds(saved_cred);
		kfree(sidstr);
		return -ENOKEY;
	}

	if (sidtype == SIDGROUP) {
		*flags |= ACE4_IDENTIFIER_GROUP;
	}

	memcpy(who_id, &sidkey->payload.data[0], sizeof(uid_t));
	key_put(sidkey);
	revert_creds(saved_cred);
	kfree(sidstr);

	return 0;
}

static int
do_ace_conversion(struct cifs_ace *pace,
		  u32 *p_perms,
		  u32 *p_iflag,
		  u32 *p_who_id,
		  u32 *p_flags,
		  u32 *p_ace_type)
{
	int error;
	char *sid_str;

	if (le16_to_cpu(pace->size) < 16) {
		cifs_dbg(VFS, "%s: NT ACE size is invalid %d\n",
			 __func__, le16_to_cpu(pace->size));
		return -E2BIG;
	}

	error = convert_smb_ace_type_to_nfs(pace->type, p_ace_type);
	if (error) {
		return error;
	}

	error = convert_smb_access_to_nfs(pace->access_req, p_perms);
	if (error) {
		return error;
	}

	error = convert_smb_flags_to_nfs(pace->flags, p_flags);
	if (error) {
		return error;
	}

	error = convert_smb_sid_to_nfs_who(&pace->sid, p_iflag, p_who_id, p_flags);
	if (error == -ENOKEY) {
		if (*p_ace_type == ACE4_ACCESS_DENIED_ACE_TYPE) {
			sid_str = sid_to_key_str(&pace->sid, SIDOWNER);
			if (sid_str == NULL) {
				return -ENOMEM;
			}

			cifs_dbg(VFS,
				 "%s: [%s] unable to convert SID into a local "
				 "ID for a DENY ACL entry. Since omission or "
				 "alteration of the ACL entry would increase "
				 "access to the file, this error may not be "
				 "overriden via client configuration change. "
				 "Administrative action will be required to "
				 "either remove the ACL entry from the remote "
				 "server or map the unknown SID to a local "
				 "Unix ID on this client\n", __func__, sid_str);
			kfree(sid_str);
			return -ENOKEY;
                }
		if (global_zfsaclflags & MODFLAG_SKIP_UNKNOWN_SID) {
			return -EAGAIN;
		} else if (global_zfsaclflags & MODFLAG_MAP_UNKNOWN_SID) {
			*p_who_id = from_kuid(&init_user_ns, current_fsuid());
			return 0;
		}
	}

	return error;
}

static bool
combine_with_next(struct cifs_ace *pace,
		  u32 *p_perms,
		  u32 *p_iflag,
		  u32 *p_who_id,
		  u32 *p_flags,
		  u32 *p_ace_type)
{
	u32 perms = 0, iflag = 0, who_id = 0, flags = 0, ace_type = 0;
	int error;

	error = do_ace_conversion(pace,
				  &perms,
				  &iflag,
				  &who_id,
				  &flags,
				  &ace_type);

	/*
	 * If an error is encountered here, it will also
	 * be picked up when we formally parse next ACE
	 * and so we'll handle the error there.
	 */
	if (error) {
		return false;
	}

	if (perms != *p_perms) {
		return false;
	}

	if (ace_type != *p_ace_type) {
		return false;
	}

	if ((flags & ACE4_INHERIT_ONLY_ACE) == 0) {
		return false;
	}

	if (iflag != ACEI4_SPECIAL_WHO) {
		return false;
	}

	*p_iflag = iflag;
	*p_who_id = who_id;
	*p_flags = (flags & ~ACE4_INHERIT_ONLY_ACE);
	return true;
}

/*
 * There are various situations where admin may want to just skip
 * certain aces in case of conversion failure. A primary example
 * is if ACL contains an ACE for a local user on the remote server.
 * In this case (as long as the ACE is ALLOW rather than DENY) it
 * is safe (although perhaps incorrect) to simply skip the entry.
 *
 * Currently this function on success returns number of good ACEs
 * added to the acl.
 *
 * On error return -errno.
 */
static int
convert_smbace_to_nfsace(struct cifs_ace *pace,
			 u32 *zfsacl,
			 bool isdir,
			 uid_t owner,
			 uid_t group,
			 bool islast,
			 bool *pskip_next)
{
	u32 *zace = zfsacl;
	u32 perms = 0, iflag = 0, who_id = 0, flags = 0, ace_type = 0;
	uid_t to_check;
	int error;

	error = do_ace_conversion(pace,
				  &perms,
				  &iflag,
				  &who_id,
				  &flags,
				  &ace_type);
	if (error) {
		return error;
	}

	to_check = flags & ACE4_IDENTIFIER_GROUP ? group : owner;

	/*
	 * This is a Samba server implementation detail for NFS4 ACL.
	 * S-1-3-0 and S-1-3-1 are only valid with INHERIT_ONLY set
	 * whereas owner@ and group@ in NFS4 ACL carry no such restriction.
	 * Therefore the server will split owner@ into two separate aces:
	 * one with S-1-3-0 (or S-1-3-1 in case of group@) and INHERIT_ONLY
	 * and the other as a normal non-special entry for the ID of the user
	 * or group with no inheritance flags set.
	 *
	 * The SMB server will always present the next ACE as the second of
	 * the pair and so we peek ahead here. If both halves of pair are
	 * present, then we combine into a single owner@ or group@ entry.
	 */
	if ((iflag == 0) &&
	    (who_id == to_check) &&
	    ((flags & ~(ACE4_INHERITED_ACE | ACE4_IDENTIFIER_GROUP)) == 0)) {
		struct cifs_ace *next;
		if (!isdir) {
			iflag = ACEI4_SPECIAL_WHO;
			if (flags & ACE4_IDENTIFIER_GROUP) {
				who_id = ACE4_SPECIAL_GROUP;

			} else {
				who_id = ACE4_SPECIAL_OWNER;
			}

		} else if (!islast) {
			next = (struct cifs_ace *)((char *)pace +
			    le16_to_cpu(pace->size));
			*pskip_next = combine_with_next(next,
							&perms,
							&iflag,
							&who_id,
							&flags,
							&ace_type);
		}
	}

	error = set_xdr_ace(zace, iflag, who_id, ace_type, perms, flags);
	if (error) {
		return error;
	}

	return 1;
}

static int
convert_dacl_to_zfsacl(struct cifs_acl *dacl_ptr,
		       char *end,
		       struct inode *inode,
		       char **buf_out)
{
	int good_aces = 0, aces_set;
	char *acl_base;
	u32 *xdr_base, *zfsacl, num_aces, i;
	struct cifs_ace *pace;
	bool skip_next = false;
	bool isdir = S_ISDIR(inode->i_mode);
	uid_t owner, group;

	num_aces = le32_to_cpu(dacl_ptr->num_aces);
	if (num_aces > NFS41ACL_MAX_ENTRIES)
		return -E2BIG;

	if (num_aces == 0)
		return generate_empty_zfsacl(buf_out);

	if (end < (char *)dacl_ptr + le16_to_cpu(dacl_ptr->size)) {
		cifs_dbg(VFS, "%s: ACL size [%u] encoded in NT DACL "
			 "is invalid.\n",
			 __func__, le16_to_cpu(dacl_ptr->size));
		return -EINVAL;
	}

	xdr_base = kzalloc(ACES_TO_XDRSIZE(num_aces), GFP_KERNEL);
	if (!xdr_base)
		return -ENOMEM;

	zfsacl = (u32 *)xdr_base + NACL_OFFSET;
	acl_base = (char *)dacl_ptr + sizeof(struct cifs_acl);

	owner = from_kuid(&init_user_ns, inode->i_uid);
	group = from_kgid(&init_user_ns, inode->i_gid);

	for (i = 0; i < num_aces; i++) {
		pace = (struct cifs_ace *)(acl_base);
		acl_base += pace->size;

		if (end < (char *)acl_base) {
			cifs_dbg(VFS, "%s: ACL entry %d in NT DACL has a size "
				 "[%u] that would exceed the buffer size "
				 "allocated for DACL.",
				 __func__, i, pace->size);
			kfree(xdr_base);
			return -EINVAL;
		}

		if (parse_sid(&pace->sid, end)) {
			kfree(xdr_base);
			return -EINVAL;
		}

		if (skip_next) {
			skip_next = false;
			continue;
		}

		aces_set = convert_smbace_to_nfsace(pace, zfsacl, isdir, owner,
		    group, i == (num_aces -1), &skip_next);
		if (aces_set < 0) {
			switch (aces_set) {
			case -EAGAIN:
				// Entry should be skipped
				aces_set = 0;
				break;
			default:
				cifs_dbg(VFS, "%s: conversion of ACE %d in "
					 "DACL could not be converted into "
					 "local ZFS ACE format: %d\n",
					 __func__, i, aces_set);
				kfree(xdr_base);
				return aces_set;
			}
		}

		good_aces += aces_set;
		zfsacl += (aces_set * NACE41_LEN);
	}

	xdr_base[0] = htonl(isdir ? ACL4_ISDIR : 0);
	xdr_base[1] = htonl(good_aces);

	*buf_out = (char *)xdr_base;
	return ACES_TO_XDRSIZE(good_aces);
}

int ntsd_to_zfsacl_xattr(struct cifs_ntsd *pntsd,
			 u32 acl_len,
			 struct inode *inode,
			 char **buf_out)
{
	struct cifs_acl *dacl_ptr; /* no need for SACL ptr */
	char *end_of_acl = ((char *)pntsd) + acl_len;
	__u32 dacloffset;

	if (pntsd == NULL)
		return -EIO;

	dacloffset = le32_to_cpu(pntsd->dacloffset);
	if (!dacloffset) {
		return generate_null_zfsacl(buf_out);
	}

	dacl_ptr = (struct cifs_acl *)((char *)pntsd + dacloffset);
	if (dacl_ptr == NULL) {
		return generate_null_zfsacl(buf_out);
	}

	return convert_dacl_to_zfsacl(dacl_ptr, end_of_acl, inode, buf_out);
}

/*
 * Creator-owner and creator-owner-group SIDs are only valid if flags are
 * set to INHERIT_ONLY. This means other ones will need to be split into two
 * separate entries.
 */
static int calculate_ntsd_acecnt(u32 *zfsacl, u32 acecnt, struct inode *inode, u32 *cnt)
{
	u32 *ace = zfsacl;
	u32 i, cnt_out = 0;
	u32 flag, iflag, who_id;
	bool isdir = S_ISDIR(inode->i_mode);

	for (i = 0; i < acecnt; i++) {
		flag = ntohl(*(ace + NA_FLAG_OFFSET));
		iflag = ntohl(*(ace + NA_IFLAG_OFFSET));
		who_id = ntohl(*(ace + NA_WHO_OFFSET));

		if (!isdir && (flag & DIR_ONLY_FLAGS)) {
			/* Not all flags are valid for files */
			return -EINVAL;
		}

		if ((flag & ACE4_INHERIT_ONLY_ACE) &&
		    ((flag & (ACE4_DIRECTORY_INHERIT_ACE | \
		    ACE4_FILE_INHERIT_ACE)) == 0)) {
			/* INHERIT_ONLY without some inherit flags is invalid */
			return -EINVAL;
		}

		if (isdir && (iflag == ACEI4_SPECIAL_WHO) &&
		    ((flag & ACE4_INHERIT_ONLY_ACE) == 0) &&
		    ((who_id == ACE4_SPECIAL_OWNER) || (who_id == ACE4_SPECIAL_GROUP))) {
			cnt_out += 1;
		}

		cnt_out += 1;
		ace += NACE41_LEN;
	}

	*cnt = cnt_out;

	return 0;
}

static int
convert_zfsperm_to_ntperm(u32 zfsperms, struct cifs_ace *ace)
{
	u32 access_mask = 0;
	int i;

	for (i = 0; i < (sizeof(nfsperm2smb) / sizeof(nfsperm2smb[0])); i++) {
		if (zfsperms & nfsperm2smb[i].nfs_perm) {
			access_mask |= nfsperm2smb[i].smb_perm;
		}
	}

	ace->access_req = cpu_to_le32(access_mask);

	return 0;
}

static int
convert_zfsflag_to_ntflag(u32 zfsflags, struct cifs_ace *ace)
{
	u8 flags = 0;
	int i;

	for (i = 0; i < (sizeof(nfsflag2smb) / sizeof(nfsflag2smb[0])); i++) {

		if (zfsflags & nfsflag2smb[i].nfs_flag) {
			flags |= nfsflag2smb[i].smb_flag;
		}
	}

	ace->flags = flags;
	return 0;
}

static int
convert_zfstype_to_nttype(u32 ace_type, struct cifs_ace *ace)
{
	switch (ace_type) {
	case ACE4_ACCESS_ALLOWED_ACE_TYPE:
		ace->type = ACCESS_ALLOWED_ACE_TYPE;
		break;
	case ACE4_ACCESS_DENIED_ACE_TYPE:
		ace->type = ACCESS_DENIED_ACE_TYPE;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int
convert_zfswho_to_ntsid(u32 iflag, u32 who_id, struct inode *inode, u32 flags, struct cifs_ace *ace)
{

	uint sidtype = flags & ACE4_IDENTIFIER_GROUP;
	uid_t id;

	if ((iflag & ACEI4_SPECIAL_WHO) == 0) {
		/*
		 * This is not a special entry (owner@, group@, everyone@)
		 * and so we need to make go through normal conversion
		 */
		return id_to_sid(who_id, sidtype, &ace->sid);
	}

	switch (who_id) {
	case ACE4_SPECIAL_EVERYONE:
		cifs_copy_sid(&ace->sid, &sid_everyone);
		return 0;
		break;
	case ACE4_SPECIAL_OWNER:
		id = from_kuid(&init_user_ns, inode->i_uid);

		if (flags & ACE4_INHERIT_ONLY_ACE) {
			cifs_copy_sid(&ace->sid, &sid_creator_owner);
			return 0;
		} else {
			return id_to_sid(id, SIDOWNER, &ace->sid);
		}
		break;
	case ACE4_SPECIAL_GROUP:
		id = from_kgid(&init_user_ns, inode->i_gid);
		if (flags & ACE4_INHERIT_ONLY_ACE) {
			cifs_copy_sid(&ace->sid, &sid_creator_group);
			return 0;
		} else {
			return id_to_sid(id, SIDGROUP, &ace->sid);
		}
		break;
	}
	return -EINVAL;
}

#define BASE_ACE_SIZE (1 + 1 + 2 + 4) /* struct cifs_ace: type, flags, size, access_req */
#define CIFS_ACE_SIZE(cnt) (BASE_ACE_SIZE + (CIFS_SID_BASE_SIZE + (cnt * 4)))

static int
convert_zfsace_to_cifs_aces(u32 *zfsace, char *acl_base, struct inode *inode, u16 *size)
{
	u32 perms, flags, iflag, who_id, ace_type;
	int error;
	u16 out_sz = 0, ace_sz;
	struct cifs_ace *ace = (struct cifs_ace *)acl_base;

	ace_type = ntohl(*(zfsace + NA_TYPE_OFFSET));
	flags = ntohl(*(zfsace + NA_FLAG_OFFSET));
	iflag = ntohl(*(zfsace + NA_IFLAG_OFFSET));
	perms = ntohl(*(zfsace + NA_ACCESS_MASK_OFFSET));
	who_id = ntohl(*(zfsace + NA_WHO_OFFSET));

	/*
	 * Creator-owner and Creator-owner-group SIDS are only valid
	 * for ACES with INHERIT_ONLY set. This means that we split
	 * inheriting owner@ and group@ entries into two separate ACEs with
	 * an identical access mask. One is non-inheriting for the inode owner
	 * or group, and the other is inherit-only with the special SID value.
	 */
	if ((iflag & ACEI4_SPECIAL_WHO) && (who_id != ACE4_SPECIAL_EVERYONE) &&
	    S_ISDIR(inode->i_mode) && ((flags & ACE4_INHERIT_ONLY_ACE) == 0)) {
		convert_zfsperm_to_ntperm(perms, ace);
		convert_zfsflag_to_ntflag(flags | ACE4_INHERIT_ONLY_ACE, ace);
		error = convert_zfstype_to_nttype(ace_type, ace);
		if (error) {
			return error;
		}

		error = convert_zfswho_to_ntsid(iflag,
						who_id,
						inode,
						flags | ACE4_INHERIT_ONLY_ACE,
						ace);
		if (error) {
			return error;
		}

		ace_sz = CIFS_ACE_SIZE(ace->sid.num_subauth);
		ace->size = cpu_to_le16(ace_sz);
		out_sz += ace_sz;

		/* skip forward to next ACE slot */
		ace = (struct cifs_ace *)(acl_base + ace_sz);
		flags &= ~DIR_ONLY_FLAGS;

		convert_zfsperm_to_ntperm(perms, ace);
		convert_zfsflag_to_ntflag(flags, ace);
		error = convert_zfstype_to_nttype(ace_type, ace);
		if (error) {
			return error;
		}

		error = convert_zfswho_to_ntsid(iflag,
						who_id,
						inode,
						flags,
						ace);
		if (error) {
			return error;
		}

		ace_sz = CIFS_ACE_SIZE(ace->sid.num_subauth);
		ace->size = cpu_to_le16(ace_sz);
		out_sz += ace_sz;
	} else {
		convert_zfsperm_to_ntperm(perms, ace);
		convert_zfsflag_to_ntflag(flags, ace);
		error = convert_zfstype_to_nttype(ace_type, ace);
		if (error) {
			return error;
		}
		error = convert_zfswho_to_ntsid(iflag,
						who_id,
						inode,
						flags,
						ace);
		if (error) {
			return error;
		}

		ace_sz = CIFS_ACE_SIZE(ace->sid.num_subauth);
		ace->size = cpu_to_le16(ace_sz);
		out_sz += ace_sz;
	}

	if (error) {
		return error;
	}

	*size = out_sz;

	return 0;
}

static int
convert_zfsacl_to_cifsacl(u32 *aclbuf,
			  u32 acecnt,
			  struct inode *inode,
			  struct cifs_acl *pdacl,
			  u32 dacl_ace_cnt,
			  u16 *pacl_size_out)
{
	u32 i, nsize = sizeof(struct cifs_acl);
	char *acl_base = (char *)pdacl;
	u16 size;
	int error;

	for (i = 0; i < acecnt; i++) {
		u32 *zfsace = aclbuf + (i * NACE41_LEN);
		error = convert_zfsace_to_cifs_aces(zfsace, acl_base + nsize, inode, &size);
		if (error)
			return error;

		nsize += size;
	}

	*pacl_size_out = nsize;
	pdacl->size = cpu_to_le16(nsize);
	pdacl->revision = cpu_to_le16(ACL_REVISION);
	pdacl->num_aces = cpu_to_le32(dacl_ace_cnt);

	return 0;
}

static void
force_smb3_dacl_info(struct smb3_sd *sd, u32 acl_flag)
{
	u16 control = ACL_CONTROL_SR | ACL_CONTROL_DP;

	if (acl_flag & ACL4_PROTECTED) {
		control |= ACL_CONTROL_PD;
	}

	/*
	 * kzalloc call zero-initialized
	 * sd->Sbz1, which is correct since we are not
	 * using resource manager
	 */
	sd->Revision = 1;
	sd->Control = cpu_to_le16(control);
}

/*
 * This is special handling for either NULL or empty ACLs.
 * Returns 0 if ACL is generated, -EAGAIN if regular parsing
 * required, and otherwise -errno.
 */
static int
parse_single_ace(u32 *zfsace, struct cifs_ntsd **ppntsd_out, u32 *acllen_out)
{
	u32 perms, flags, iflag, who_id, ace_type;
	bool dacl_is_null = false, dacl_is_empty = false;
	u32 secdesclen = sizeof(struct cifs_ntsd);
	struct cifs_ntsd *pnntsd = NULL;
	struct cifs_acl *dacl = NULL;

	perms = ntohl(*(zfsace + NA_ACCESS_MASK_OFFSET));
	flags = ntohl(*(zfsace + NA_FLAG_OFFSET));
	iflag = ntohl(*(zfsace + NA_IFLAG_OFFSET));
	who_id = ntohl(*(zfsace + NA_WHO_OFFSET));
	ace_type = ntohl(*(zfsace + NA_TYPE_OFFSET));

	if ((iflag == ACEI4_SPECIAL_WHO) && (who_id == ACE4_SPECIAL_EVERYONE) &&
	    (perms == ACE4_ALL_PERMS) && (flags == 0) &&
	    (ace_type == ACE4_ACCESS_ALLOWED_ACE_TYPE)) {
		dacl_is_null = true;
	}

	if ((iflag == ACEI4_SPECIAL_WHO) && (who_id == ACE4_SPECIAL_OWNER) &&
	    (perms == 0) && (flags == 0) &&
	    (ace_type == ACE4_ACCESS_ALLOWED_ACE_TYPE)) {
		dacl_is_empty = true;
		secdesclen += sizeof(struct cifs_acl);
	}

	if (!dacl_is_null && !dacl_is_empty) {
		return -EAGAIN;
	}

	pnntsd = kzalloc(secdesclen, GFP_KERNEL);
	if (pnntsd == NULL) {
		return -ENOMEM;
	}

	force_smb3_dacl_info((struct smb3_sd *)pnntsd, 0);

	*ppntsd_out = pnntsd;
	*acllen_out = secdesclen;

	if (dacl_is_null) {
		return 0;
	}

	/* dacl_is_empty */
	pnntsd->dacloffset = cpu_to_le32(sizeof(struct cifs_ntsd));
	dacl = (struct cifs_acl *)(pnntsd + sizeof(struct cifs_ntsd));
	dacl->size = cpu_to_le16(sizeof(struct cifs_acl));
	dacl->revision = cpu_to_le16(ACL_REVISION);
	return 0;
}

/*
 * This method converts ZFS ACL format into a Security Descriptor. The
 * resulting SD only contains a DACL and is limited to only ALLOW and DENY
 * entries.
 */
int zfsacl_xattr_to_ntsd(char *aclbuf,
			 size_t size,
			 struct inode *inode,
			 struct cifs_ntsd **ppntsd_out,
			 u32 *acllen_out)
{
	int error;
	u32 *zfsacl = (u32 *)aclbuf;
	u32 control, acecnt, dacl_ace_cnt, secdesclen;
	struct cifs_ntsd *pnntsd = NULL;
	struct cifs_acl *dacl = NULL;
	u16 acl_size_out = 0;

	if (!XDRSIZE_IS_VALID(size)) {
		return -EINVAL;
	}

	control = ntohl(*(zfsacl++));
	acecnt = ntohl(*(zfsacl++));

	/*
	 * C.f. notes about S-1-3-0 and S-1-3-1 above. There are some
	 * circumstances when one ZFS ACL entry may need to expand to two
	 * SMB DACL entries.
	 */
	error = calculate_ntsd_acecnt(zfsacl, acecnt, inode, &dacl_ace_cnt);
	if (error) {
		return error;
	}

	/*
	 * Special handling for NULL or empty DACL. A single ACL entry
	 * is unusual and so we first check to see whether it's a NULL or empty
	 * DACL, if it isn't then the function returns -EAGAIN so that we
	 * fall back to normal parsing.
	 */
	if (dacl_ace_cnt == 1) {
		error = parse_single_ace(zfsacl, ppntsd_out, acllen_out);
		if ((error == 0) || (error != -EAGAIN)) {
			return error;
		}
	}

	secdesclen = dacl_ace_cnt * sizeof(struct cifs_ace);
	secdesclen = max_t(u32, secdesclen, DEFAULT_SEC_DESC_LEN);
	secdesclen += sizeof(struct cifs_ntsd);

	pnntsd = kzalloc(secdesclen, GFP_KERNEL);
	if (pnntsd == NULL) {
		return -ENOMEM;
	}

	/*
	 * Format of Security Descriptor has changed over time. We require
	 * support for setting ACL-wide control bits and so this method
	 * is gated on whether connection is SMB3+. Hence, we are safe in
	 * assuming we can recast as an smb3_sd for setting our control bits.
	 */
	force_smb3_dacl_info((struct smb3_sd *)pnntsd, control);

	pnntsd->dacloffset = cpu_to_le32(sizeof(struct cifs_ntsd));

	dacl = (struct cifs_acl *)((char*)pnntsd + pnntsd->dacloffset);
	error = convert_zfsacl_to_cifsacl(zfsacl, acecnt, inode, dacl,
	    dacl_ace_cnt, &acl_size_out);

	dacl->size = cpu_to_le16(acl_size_out);
	if (error) {
		kfree(pnntsd);
		return error;
	}

	*ppntsd_out = pnntsd;
	*acllen_out = secdesclen;

	return 0;
}
#endif /* CONFIG_TRUENAS */
