/* SPDX-License-Identifier: LGPL-2.1 */
/*
 *
 *   Copyright (c) iXsystems, inc (2024)
 *   Author(s): Andrew Walker
 *
 */

#include <linux/xattr.h>
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "truenas_streams.h"
#include "cifs_unicode.h"
#include "smb2glob.h"
#include "smb2pdu.h"
#include "smb2proto.h"

#define STREAM_MAX_RETRIES 5

unsigned int streams_samba_compat_enabled = 1;

struct parsed_stream_info {
	u32 size;
	u32 allocation_size;
	char *stream_name;
};

/*
 * See MS-FSCC 2.4.43 FileStreamInformation
 *
 * NOTE regarding stream name:
 * It is a sequence of unicode characters containing the name of the stream
 * using the form ":streamname:$DATA" or "::$DATA" for the default data stream.
 * as specified in MS-FSCC 2.1.4. The field is not null-terminated and MUST
 * be handled as a sequence of `namelength` bytes.
 *
 * NOTE regarding aligment:
 * When multiple FILE_STREAM_INFORMATION data elements are present in the
 * buffer, each MUST be alinged on an 8-byte boundaries; any bytes inserted
 * for alignment SHOULD be set to zero and the receiver MUST ignore them.
 */

static int
validate_stream_info(struct smb2_file_stream_info *stream,
		     char *end)
{
	// Check overall stream info
	char *stream_buf = (char *)stream + sizeof(struct smb2_file_stream_info);
	if ((stream_buf + stream->StreamNameLength) > end) {
		return -EOVERFLOW;
	}

	if (stream->StreamNameLength < DEFAULT_DATA_STREAMLEN) {
		return -EINVAL;
	}

	return 0;
}

static struct smb2_file_stream_info
*get_next_stream(struct smb2_file_stream_info *in,
		 char *end_of_streams, int *perror)
{
	char *stream_buf = (char *)in;

	if (in->NextEntryOffset == 0) {
		// MS-FSCC 2.4.43 - zero means no more entries
		return NULL;
	}

	stream_buf += in->NextEntryOffset;
	if (stream_buf > end_of_streams) {
		*perror = -EOVERFLOW;
		return NULL;
	}

	return (struct smb2_file_stream_info *)stream_buf;
}

static int
parse_to_xat_buf(struct cifs_sb_info *cifs_sb,
		 char *dst, size_t dstsz,
		 struct smb2_file_stream_info *in,
		 char *end_of_streams,
		 u32 *pused)
{
	char *name = NULL, *stream_name;
	struct smb2_file_stream_info *stream = NULL;
	int error = 0;
	u32 used = 0;
	size_t namelen = 0;

	for (stream = in;
	     stream != NULL;
	     stream = get_next_stream(stream, end_of_streams, &error)) {
		error = validate_stream_info(stream, end_of_streams);
		if (error) {
			break;
		}

		/*
		 * `name` is UTF-16 and not NULL-terminated and so convert
		 * to NULL-terminated UTF-8 string
		 */
		name = (char *)stream + sizeof(struct smb2_file_stream_info);

		stream_name = cifs_strndup_from_utf16(name,
		    stream->StreamNameLength, true, cifs_sb->local_nls);
		if (stream_name == NULL) {
			error = -ENOMEM;
			break;
		}
		namelen = strlen(stream_name);

		// skip default data stream.
		if (strcmp(stream_name, DEFAULT_DATA_STREAM) == 0) {
			kfree(stream_name);
			continue;
		}

		// dstsz == 0 means that caller is trying to figure out buffer
		// size needed for the xattr names. See man(2) listxattr.
		if (dstsz == 0) {
			used += (namelen + STREAM_XATTR_PREFIXLEN);
			kfree(stream_name);
			continue;
		}

		if ((namelen + STREAM_XATTR_PREFIXLEN) > dstsz) {
			kfree(stream_name);
			error = -ERANGE;
			break;
		}

		dstsz -= STREAM_XATTR_PREFIXLEN;
		memcpy(dst, STREAM_XATTR_PREFIX, STREAM_XATTR_PREFIXLEN);
		dst += STREAM_XATTR_PREFIXLEN;

		// we'll eat the leading ':' in stream name. `namelen` is
		// fine because we want the terminating NULL to be copied over
		dstsz -= namelen;
		memcpy(dst, stream_name + 1, namelen);
		dst += namelen;

		used += (namelen + STREAM_XATTR_PREFIXLEN);
		kfree(stream_name);
	}

	*pused = used;
	return error;
}

static int
get_streams_by_path(struct dentry *dentry, const char *path,
		    unsigned int xid, struct cifs_tcon *tcon,
		    struct smb2_file_stream_info **ppstreams,
		    u32 *pstreamlen)
{
	u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_sb_info *cifs_sb = CIFS_SB(dentry->d_sb);
	int rc;
	struct cifs_fid fid;
	struct cifs_open_parms oparms;
	__le16 *utf16_path;
	struct smb2_file_stream_info *pstreams = NULL;
	u32 plen;

	cifs_dbg(FYI, "get smb3 streams for path %s\n", path);

	utf16_path = cifs_convert_path_to_utf16(path, cifs_sb);
	if (!utf16_path) {
		return -ENOMEM;
	}

	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.path = path,
		.desired_access = FILE_READ_ATTRIBUTES,
		.disposition = FILE_OPEN,
		.create_options = cifs_create_options(cifs_sb, 0) |
			OPEN_REPARSE_POINT,
		.fid = &fid,
	};

	// TODO: refactor to use smb2_query_info_compound() to reduce
	// network traffic. This would require changing path parsing
	// and so currently beyond scope.
	rc = SMB2_open(xid, &oparms, utf16_path, &oplock, NULL, NULL, NULL,
		       NULL);
	kfree(utf16_path);
	if (rc)
		return rc;


	rc = SMB2_query_streams(xid, tcon,
				fid.persistent_fid,
				fid.volatile_fid,
				&pstreams, &plen);
	SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
	if (rc < 0) {
		return rc;
	}

	*ppstreams = pstreams;
	*pstreamlen = plen;

        return 0;
}

static int
get_streams_by_fid(const struct cifs_fid *fid,
		   unsigned int xid, struct cifs_tcon *tcon,
		   struct smb2_file_stream_info **ppstreams,
		   u32 *pstreamlen)
{
	int rc = -EOPNOTSUPP;
	u32 plen;
	struct smb2_file_stream_info *pstreams = NULL;

	rc = SMB2_query_streams(xid, tcon,
				fid->persistent_fid,
				fid->volatile_fid,
				&pstreams, &plen);
	if (rc < 0) {
		return rc;
	}

	*ppstreams = pstreams;
	*pstreamlen = plen;

	return 0;
}

static int
get_smb2_streams(struct dentry *dentry, const char *path,
		 unsigned int xid, struct cifs_tcon *tcon,
		 struct smb2_file_stream_info **ppstreams,
		 u32 *pstreamlen)
{
	int error;
	struct cifsFileInfo *open_file = NULL;
	struct inode *inode = d_inode(dentry);

	if (inode)
		open_file = find_readable_file(CIFS_I(inode), true);

	if (!open_file)
		return get_streams_by_path(dentry, path, xid, tcon, ppstreams, pstreamlen);

	error = get_streams_by_fid(&open_file->fid, xid, tcon, ppstreams, pstreamlen);
	cifsFileInfo_put(open_file);

	return error;
}

enum stream_open_type {
	STREAM_OPEN_READ,
	STREAM_OPEN_WRITE,
	STREAM_OPEN_DELETE,
};

static int
do_stream_open(struct cifs_tcon *tcon, struct cifs_sb_info *sb,
	       enum stream_open_type otype, unsigned int xid,
	       const char *path, const char *stream,
	       int xattr_flags, struct cifs_fid *fid_out,
	       struct smb2_file_all_info *info_out)
{
	int rc;
	__le16 *utf16_path = NULL;
	struct cifs_open_parms oparms;
	u8 oplock = SMB2_OPLOCK_LEVEL_NONE;

	switch (otype) {
	case STREAM_OPEN_WRITE:
		oparms = (struct cifs_open_parms) {
			.tcon = tcon,
			.cifs_sb = sb,
			.desired_access = FILE_WRITE_ATTRIBUTES |
				FILE_WRITE_DATA | SYNCHRONIZE,
			.create_options = cifs_create_options(sb, CREATE_NOT_DIR) |
				OPEN_REPARSE_POINT,
			.path = path,
			.fid = fid_out,
			.mode = ACL_NO_MODE,
		};
		switch (xattr_flags) {
		case XATTR_CREATE:
			oparms.disposition = FILE_CREATE;
			break;
		case XATTR_REPLACE:
			oparms.disposition = FILE_OPEN;
			break;
		default:
			// We may be able to optimize here by
			// setting FILE_SUPERSEDE on open and avoid
			// setting EOF as a separate operation.  
			oparms.disposition = FILE_OPEN_IF;
			break;
		};
		break;
	case STREAM_OPEN_READ:
		oparms = (struct cifs_open_parms) {
			.tcon = tcon,
			.cifs_sb = sb,
			.desired_access = FILE_READ_ATTRIBUTES |
				FILE_READ_DATA | SYNCHRONIZE,
			.create_options = cifs_create_options(sb, CREATE_NOT_DIR) |
				OPEN_REPARSE_POINT,
			.disposition = FILE_OPEN,
			.path = path,
			.fid = fid_out,
		};
		break;
	case STREAM_OPEN_DELETE:
		oparms = (struct cifs_open_parms) {
			.tcon = tcon,
			.cifs_sb = sb,
			.desired_access = DELETE | FILE_WRITE_ATTRIBUTES,
			.create_options = cifs_create_options(sb, CREATE_NOT_DIR) |
				OPEN_REPARSE_POINT | CREATE_DELETE_ON_CLOSE,
			.disposition = FILE_OPEN,
			.path = path,
			.fid = fid_out,
		};
		break;
	default:
		BUG();
	};

	utf16_path = cifs_convert_stream_path_to_utf16(path, stream, sb);
	if (!utf16_path) {
		return -ENOMEM;
	}

	rc = SMB2_open(xid, &oparms, utf16_path, &oplock, info_out, NULL, NULL, NULL);
	kfree(utf16_path);

	return rc;
}

static int
delete_stream(struct dentry *dentry, struct cifs_tcon *tcon,
	      unsigned int xid, const char *path, const char *stream)
{
	int rc;
	struct cifs_fid fid;
	struct smb2_file_all_info info;

	rc = do_stream_open(tcon, CIFS_SB(dentry->d_sb), STREAM_OPEN_DELETE, xid, path, stream, 0, &fid, &info);
        if (rc) {
		// To maintain consistency with removexattr
		// failure modes, convert ENOENT to ENODATA.
		if (rc == -ENOENT)
			rc = -ENODATA;

		return rc;
        }

	SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
	return rc;
}

static int
write_stream(struct dentry *dentry, struct cifs_tcon *tcon,
	     const char *data, size_t sz, int flags, unsigned int xid,
	     const char *path, const char *stream)
{
	/*
	 * Write alternate data stream for file specified by dentry.
	 * The stream is temporarily opened to perform IO (there is
	 * no open for stream associated in VFS).
	 */
	int rc;
	struct cifs_fid fid;
	struct cifs_io_parms io_parms;
	struct kvec iov[2]; // header, data
	struct smb2_file_all_info info;
	unsigned int written = 0;
	unsigned int total_written;
	unsigned int wsize;
	struct TCP_Server_Info *server;

	server = cifs_pick_channel(tcon->ses);
	if (!server->ops->sync_write)
		return -ENOSYS;

	// We will potentially need to break up stream write into chunks.
	// Typical IO size in SMB is 1 MiB and typical streams are much
	// smaller than this.
	wsize = tcon->ses->server->ops->wp_retry_size(d_inode(dentry));

	// See "Samba background" note in truenas_streams.h
	if (streams_samba_compat_enabled) {
		sz -= 1; /* Remove NULL appended by samba */
	}
	rc = do_stream_open(tcon, CIFS_SB(dentry->d_sb), STREAM_OPEN_WRITE,
			    xid, path, stream, flags, &fid, &info);
        if (rc) {
		return rc;
        }

	// We may have a short write and so should loop until
	// all of payload written
	for (total_written = 0; sz > total_written;
	     total_written += written) {
		unsigned int len = min(wsize, sz - total_written);
		unsigned int retries = 0;
		rc = -EAGAIN;

		io_parms = (struct cifs_io_parms) {
			.persistent_fid = fid.persistent_fid,
			.volatile_fid = fid.volatile_fid,
			.pid = current->tgid,
			.tcon = tcon,
			.server = server,
			.offset = total_written,
			.length = len,
		};

		iov[1].iov_base = (char *)data + total_written;
		iov[1].iov_len = len;
		while ((rc == -EAGAIN) && ((retries += 1) < STREAM_MAX_RETRIES)) {
			rc = server->ops->sync_write(xid, &fid, &io_parms,
						     &written, iov, 1);
		}

		if (rc || (written == 0)) {
			break;
		}
	}

	if (total_written < le64_to_cpu(info.EndOfFile)) {
		int err;
		__le64 eof = cpu_to_le64(total_written);
		err = SMB2_set_eof(xid, tcon, fid.persistent_fid,
		    fid.volatile_fid, current->tgid, &eof);
	}

	server->ops->close(xid, tcon, &fid);
	if (rc) {
		return rc;
	}

	return 0;
}

static int
read_stream(struct dentry *dentry, struct cifs_tcon *tcon,
	    char *dst, size_t dstsz, unsigned int xid,
	    const char *path, const char *stream, u32 *pused)
{
	int rc, buf_type = CIFS_NO_BUFFER;
	struct cifs_fid fid;
	struct cifs_io_parms io_parms;
	struct smb2_file_all_info info;
	unsigned int bytes_read = 0;
	unsigned int total_read;
	u32 to_read;
	struct TCP_Server_Info *server;

	server = cifs_pick_channel(tcon->ses);
	if (!server->ops->sync_read)
		return -ENOSYS;

	rc = do_stream_open(tcon, CIFS_SB(dentry->d_sb), STREAM_OPEN_READ, xid,
	    path, stream, 0, &fid, &info);
        if (rc) {
		return rc;
        }

	if (dstsz == 0) {
		server->ops->close(xid, tcon, &fid);
		*pused = le64_to_cpu(info.EndOfFile) + streams_samba_compat_enabled;
		return 0;
	}

	to_read = le64_to_cpu(info.EndOfFile);
	if ((to_read >= XATTR_LARGE_SIZE_MAX) ||
	    ((to_read + streams_samba_compat_enabled) > dstsz)) {
		/*
		 * The SMB protocol and MS-FSCC does not provide an upper-bound
		 * on the maximum size of an alternate data stream. ReFS on
		 * windows limits ADS max size to 64 KiB, MacOS has no
		 * real limit on size of resource forks. ZFS doesn't
		 * have an upper bound on xattr size (these get written as
		 * files when they're too large), but since our APIs here
		 * are somewhat terrible (no pwrite / pread equivalent) we
		 * limit to XATTR_LARGE_SIZE_MAX to reduce maximum allocation
		 * size that we need to perform.
		 *
		 * Typically an alternate data stream will be less than 1 KiB.
		 */

		server->ops->close(xid, tcon, &fid);
		return -ERANGE;
	}

	for (total_read = 0; to_read > total_read; total_read += bytes_read) {
		unsigned int len = min(to_read, CIFSMaxBufSize);
		unsigned int retries = 0;
		rc = -EAGAIN;
		char *pbuf = dst + total_read;

		io_parms = (struct cifs_io_parms) {
			.persistent_fid = fid.persistent_fid,
			.volatile_fid = fid.volatile_fid,
			.pid = current->tgid,
			.tcon = tcon,
			.server = server,
			.offset = total_read,
			.length = len,
		};

		while ((rc == -EAGAIN) &&
		       ((retries += 1) < STREAM_MAX_RETRIES)) {
			rc = server->ops->sync_read(xid, &fid, &io_parms,
			    &bytes_read, &pbuf, &buf_type);
		}

		// If we've read to end of stream, rc will be 0 and bytes_read 0
		if (rc || (bytes_read == 0))
			break;
	}

	server->ops->close(xid, tcon, &fid);
	if (rc == 0) {
		// See "Samba background" note in truenas_streams.h
		if (streams_samba_compat_enabled) {
			*pused = total_read + 1;
			*(dst + total_read) = '\0';
		} else {
			*pused = total_read;
		}
	}

	return rc;
}

static int
get_stream_name(const char *name_in, char **name_out)
{
	/*
	 * `name_in` will be of format: "user.DosStream.<stream name>:$DATA".
	 * This format matches standard naming convention in Samba's
	 * vfs_streams_xattr.
	 *
	 * `name_out` will contain only the <stream name> portion of `name_in`
	 * NOTE: caller must free `name_out`.
	 *
	 * Some care needs to be taken here because of the following edge case
	 * Both <filename> and <filename>::$DATA may be used to open the default
	 * data stream for a file. We need to guard against ever generating the
	 * latter as a path for getting or setting named streams via an xattr
	 * handler.
	 *
	 * <filename>:$DATA:$DATA is also a valid stream name and so strstr
	 * and similar string-related functions operating "$DATA" should be
	 * used in a way that avoids or handles this edge case. We avoid
	 * this here by not including the stream separator as part of the
	 * xattr name and trimming off sufix starting with the separator ":"
	 * for the stream suffix.
	 */
	char *stream_name, *suffix;

	if (strcmp(name_in, DEFAULT_DATA_STREAM) == 0) {
		// This is our default data stream "<filename>::$DATA"
		return -EINVAL;
	}

	if (strncmp(name_in, STREAM_XATTR, STREAM_XATTR_LEN) != 0) {
		// `name_in` does not start with "user.DosStream."
		return -EINVAL;
	}

	// Remove the user.DosStream. prefix
	stream_name = kstrdup(name_in + STREAM_XATTR_LEN, GFP_KERNEL);
	if (stream_name == NULL) {
		return -ENOMEM;
	}

	suffix = strstr(stream_name, STREAM_SUFFIX);
	if (suffix == NULL) {
		// malformed stream name (no :$DATA suffix)
		kfree(stream_name);
		return -EINVAL;
	}

	// Remove the stream type suffix and separator ":$DATA"
	*suffix = '\0';
	*name_out = stream_name;
	return 0;
}

int set_stream_xattr(struct dentry *dentry, const char *full_path,
		     unsigned int xid, struct cifs_tcon *tcon,
		     const char *name, const void *value, size_t size,
		     int flags)
{
	char *stream_name;
	int rc = 0;

	rc = get_stream_name(name, &stream_name);
	if (rc) {
		return rc;
	}

	if ((value == NULL) || (size == 0)) {
		rc = delete_stream(dentry, tcon, xid, full_path, stream_name);
	} else {
		rc = write_stream(dentry, tcon, value, size, flags, xid,
				  full_path, stream_name);
	}

	kfree(stream_name);

	return rc;
}

int get_stream_xattr(struct dentry *dentry, const char *full_path,
		     unsigned int xid, struct cifs_tcon *tcon,
		     const char *name, void *value, size_t size)
{
	char *stream_name;
	u32 used;
	int rc;

	rc = get_stream_name(name, &stream_name);
	if (rc) {
		return rc;
	}

	rc = read_stream(dentry, tcon, (char *)value, size, xid,
			 full_path, stream_name, &used);
	kfree(stream_name);
	if (rc) {
		if (rc == -ENOENT)
			rc = -ENODATA;

		return rc;
	}

	return used;
}

int list_streams_xattr(struct dentry *dentry, const char *path,
                       unsigned int xid, struct cifs_tcon *tcon,
                       char *dst, size_t dstsz)
{
	int error;
	struct smb2_file_stream_info *streams = NULL;
	u32 slen;

	error = get_smb2_streams(dentry, path, xid, tcon,
				 &streams, &slen);
	if (error)
		return error;

	if (slen) {
		error = parse_to_xat_buf(CIFS_SB(dentry->d_sb), dst, dstsz,
					 streams, (char *)streams + slen,
					 &slen);
	}
	kfree(streams);
	if (error)
		return error;

	return slen;
}
