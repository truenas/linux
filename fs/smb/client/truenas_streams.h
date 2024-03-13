/* SPDX-License-Identifier: LGPL-2.1 */
/*
 *
 *   Copyright (c) iXsystems, inc (2024)
 *   Author(s): Andrew Walker
 *
 */

/*
 * SMB Protocol Background:
 * ------------------------
 * Filesystems presented over the SMB protocol may support alternate data
 * streams ("named streams") within a file or a directory. This support is
 * designated by the filesystem attribute FILE_NAMED_STREAMS. Named streams
 * are not identical to extended attributes (EAs), which may also be
 * supported by the same SMB server.
 *
 * A named stream is a place within a file in addition to the main stream
 * (normal file data) where data is stored. Named streams have different
 * data than the main stream (and than each other) and may be written and
 * read independenly of each other. Named streams for a file are designated
 * by appending a ":" colon character to the file name followed by the
 * name of the alternate data stream. Stream names may be no more than 255
 * characters in length and are subject to the characteristics and
 * limitations documented in MS-FSCC Section 2.1.5 Pathname and following.
 *
 * A list of named streams for a file can be gathered by submitting an
 * SMB2_QUERY_INFO request for FILE_STREAM_INFORMATION. The expected server
 * response is documented in MS-FSS Section 2.4.43 FileStreamInformation.
 *
 * Streams are typically smallish in size (less than 200 bytes individually),
 * and are rarely used apart from MacOS SMB clients.
 *
 * TrueNAS /ZFS background:
 * ------------------------
 * Solaris supported a similar feature set through its file-backed xattr
 * capabilities and APIs. This meant that the kernel SMB server in solaris
 * was able to seamlessly provide support for named streams. When ZFS was
 * ported to FreeBSD and Linux the extattr and xattr OS APIs were layered
 * on top of the ZFS file-backed xattrs. As time progressed and ZFS on
 * Linux saw more use, it was determined that the performance and lack of
 * atomocity of operations on file-backed xattrs was insufficient for
 * some application requirements (this was especially the case for Samba
 * shares), this eventually led to the ZFS dataset configuration parameter
 * for SA-backed xattrs on Linux (which is the TrueNAS default). With this
 * configuration, xattrs up to a certain size are written as SA, and larger
 * xattrs are written as files. The practical result of this is that
 * TrueNAS can support extended attributes that are much greater in size
 * than a traditional Linux file server. Unfortunately, due to inability
 * to perform partial reads and writes on extended attributes a 2 MiB
 * upper bound is placed as the maximum size of a single extended attribute
 * / named stream in TrueNAS.
 *
 * Samba background:
 * -----------------
 * Samba has the ability to present extended attributes as named streams
 * to SMB clients. This is achieved by prepending a special prefix to
 * the exended attribute (to differentiate the streams xattrs from normal
 * xattrs that are presented as EAs over the SMB protocol). Due to
 * historical design decisions, the Samba module in charge of translating
 * xattrs into streams appends an extra NULL byte to the xattr on writes
 * to the local filesystem and strips it off when converting to a stream
 * for SMB clients.
 *
 * Implementation details:
 * -----------------------
 * This commit adds support for the Linux kernel SMB2/3 client to enumerate
 * streams on a remote SMB server by including them in the output of
 * listxattr with the special Samba prefix. Streams may be written to
 * the remote SMB server via setxattr and read through getxtattr. The
 * Samba-specific behavior for appending / removing an extra byte to
 * the xattr can be disabled by setting /proc/fs/cifs/stream_samba_compat
 * to 0.
 */

#ifndef _STREAMS_H
#define _STREAMS_H

#define STREAM_SUFFIX ":$DATA"
#define DEFAULT_DATA_STREAM ":" STREAM_SUFFIX
#define DEFAULT_DATA_STREAMLEN (sizeof(DEFAULT_DATA_STREAM) - 1)

/* This is the default Samba prefix for a named stream */
#define STREAM_XATTR "DosStream."
#define STREAM_XATTR_LEN (sizeof(STREAM_XATTR) - 1)

#define STREAM_XATTR_PREFIX "user." STREAM_XATTR
#define STREAM_XATTR_PREFIXLEN (sizeof(STREAM_XATTR_PREFIX) - 1)

int list_streams_xattr(struct dentry *dentry, const char *path,
		       unsigned int xid, struct cifs_tcon *tcon,
		       char *dst, size_t dstsz);

int set_stream_xattr(struct dentry *dentry, const char *full_path,
		     unsigned int xid, struct cifs_tcon *tcon,
		     const char *name, const void *value, size_t size,
		     int flags);

int get_stream_xattr(struct dentry *dentry, const char *full_path,
		     unsigned int xid, struct cifs_tcon *tcon,
		     const char *name, void *value, size_t size);

#endif /* _STREAMS_H */
