#ifndef _ADAP_UTIL_H_
#define _ADAP_UTIL_H_

#include "platdef.h"

/* Vital Product Data */

#define PCI_VPD_ADDR		2	/* Address to access (15 bits!) */
#define PCI_VPD_ADDR_MASK	0x7FFF	/* Address mask */
#define PCI_VPD_ADDR_F		0x8000	/* Write 0, 1 indicates completion */
#define PCI_VPD_DATA		4	/* 32-bits of data returned here */

#define PCI_EXP_DEVCTL		0x0008
#define PCI_EXP_DEVCTL_PAYLOAD	0x00E0
#define PCI_EXP_DEVCTL_READRQ	0x7000	/* Max_Read_Request_Size */

#define PCI_CAP_ID_EXP		0x10	/* PCI Express */
#define PCI_EXP_LNKSTA		18	/* Link Status */
#define PCI_EXP_LNKCTL		16	/* Link Status */
#define PCI_EXP_LNKCAP		12	/* Link Status */
#define PCI_CAP_ID_VPD		0x03	/* Vital Product Data */
#define PCI_STATUS		0x06	/* 16 bits */
#define PCI_STATUS_CAP_LIST	0x10	/* Support Capability List */
#define PCI_CAPABILITY_LIST	0x34	/* Offset of first capability list \
					   entry */
#define PCI_CAP_LIST_ID		0	/* Capability ID */
#define PCI_CAP_LIST_NEXT	1	/* Next capability in the list */

#define PCI_STATUS_COMMAND	0x4

#ifndef ESX 
static int ilog2(unsigned long v)
{
	int l = 0;
	while ((1UL << l) < v)
		l++;
	return l;
}

static int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif 

#define __iomem

#define true 1
#define false 0

#define ARRAY_SIZE(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#if !defined(_LINUX_ERRNO_H) && !defined(_ERRNO_H)

#define    EPERM		1    /* Operation not permitted */
#define    ENOENT		2    /* No such file or directory */
#define    ESRCH		3    /* No such process */
#define    EINTR		4    /* Interrupted system call */
#define    EIO			5    /* I/O error */
#define    ENXIO		6    /* No such device or address */
#define    E2BIG		7    /* Argument list too long */
#define    ENOEXEC		8    /* Exec format error */
#define    EBADF		9    /* Bad file number */
#define    ECHILD		10    /* No child processes */
#define    EAGAIN		11    /* Try again */
#define    ENOMEM		12    /* Out of memory */
#define    EACCES		13    /* Permission denied */
#define    EFAULT		14    /* Bad address */
#define    ENOTBLK		15    /* Block device required */
#define    EBUSY		16    /* Device or resource busy */
#define    EEXIST		17    /* File exists */
#define    EXDEV		18    /* Cross-device link */
#define    ENODEV		19    /* No such device */
#define    ENOTDIR		20    /* Not a directory */
#define    EISDIR		21    /* Is a directory */
#define    EINVAL		22    /* Invalid argument */
#define    ENFILE		23    /* File table overflow */
#define    EMFILE		24    /* Too many open files */
#define    ENOTTY		25    /* Not a typewriter */
#define    ETXTBSY		26    /* Text file busy */
#define    EFBIG		27    /* File too large */
#define    ENOSPC		28    /* No space left on device */
#define    ESPIPE		29    /* Illegal seek */
#define    EROFS		30    /* Read-only file system */
#define    EMLINK		31    /* Too many links */
#define    EPIPE		32    /* Broken pipe */
#define    EDOM			33    /* Math argument out of domain of func */
#define    ERANGE		34    /* Math result not representable */

#define    EDEADLK		36    /* Resource deadlock would occur */
#define    ENAMETOOLONG		38    /* File name too long */
#define    ENOLCK		39    /* No record locks available */
#define    ENOSYS		40    /* Function not implemented */
#define    ENOTEMPTY		41    /* Directory not empty */
#define    ELOOP		ENAMETOOLONG	/* Too many symbolic links
						   encountered */
#define    EWOULDBLOCK		EAGAIN	  /* Operation would block */
#define    ENOMSG		42    /* No message of desired type */
#define    EIDRM		43    /* Identifier removed */
#define    ECHRNG		44    /* Channel number out of range */
#define    EL2NSYNC		45    /* Level 2 not synchronized */
#define    EL3HLT		46    /* Level 3 halted */
#define    EL3RST		47    /* Level 3 reset */
#define    ELNRNG		48    /* Link number out of range */
#define    EUNATCH		49    /* Protocol driver not attached */
#define    ENOCSI		50    /* No CSI structure available */
#define    EL2HLT		51    /* Level 2 halted */
#define    EBADE		52    /* Invalid exchange */
#define    EBADR		53    /* Invalid request descriptor */
#define    EXFULL		54    /* Exchange full */
#define    ENOANO		55    /* No anode */
#define    EBADRQC		56    /* Invalid request code */
#define    EBADSLT		57    /* Invalid slot */

/*#define    EDEADLOCK		  EDEADLK*/

#define    EBFONT		59    /* Bad font file format */
#define    ENOSTR		60    /* Device not a stream */
#define    ENODATA		61    /* No data available */
#define    ETIME		62    /* Timer expired */
#define    ENOSR		63    /* Out of streams resources */
#define    ENONET		64    /* Machine is not on the network */
#define    ENOPKG		65    /* Package not installed */
#define    EREMOTE		66    /* Object is remote */
#define    ENOLINK		67    /* Link has been severed */
#define    EADV			68    /* Advertise error */
#define    ESRMNT		69    /* Srmount error */
#define    ECOMM		70    /* Communication error on send */
#define    EPROTO		71    /* Protocol error */
#define    EMULTIHOP		72    /* Multihop attempted */
#define    EDOTDOT		73    /* RFS specific error */
#define    EBADMSG		74    /* Not a data message */
#define    EOVERFLOW		75    /* Value too large for defined data type*/
#define    ENOTUNIQ		76    /* Name not unique on network */
#define    EBADFD		77    /* File descriptor in bad state */
#define    EREMCHG		78    /* Remote address changed */
#define    ELIBACC		79    /* Can not access a needed shared
					 library */
#define    ELIBBAD		80    /* Accessing a corrupted shared library */
#define    ELIBSCN		81    /* .lib section in a.out corrupted */
#define    ELIBMAX		82    /* Attempting to link in too many shared
					 libraries */
#define    ELIBEXEC		83    /* Cannot exec a shared library directly*/
#define    EILSEQ		42    /* Illegal byte sequence */
#define    ERESTART		85    /* Interrupted system call should be
					 restarted */
#define    ESTRPIPE		86    /* Streams pipe error */
#define    EUSERS		87    /* Too many users */
#define    ENOTSOCK		88    /* Socket operation on non-socket */
#define    EDESTADDRREQ		89    /* Destination address required */
#define    EMSGSIZE		90    /* Message too long */
#define    EPROTOTYPE		91    /* Protocol wrong type for socket */
#define    ENOPROTOOPT		92    /* Protocol not available */
#define    EPROTONOSUPPORT	93    /* Protocol not supported */
#define    ESOCKTNOSUPPORT	94    /* Socket type not supported */
#define    EOPNOTSUPP		95    /* Operation not supported on transport
					 endpoint */
#define    EPFNOSUPPORT		96    /* Protocol family not supported */
#define    EAFNOSUPPORT		97    /* Address family not supported by
					 protocol */
#define    EADDRINUSE		98    /* Address already in use */
#define    EADDRNOTAVAIL	99    /* Cannot assign requested address */
#define    ENETDOWN		100    /* Network is down */
#define    ENETUNREACH		101    /* Network is unreachable */
#define    ENETRESET		102    /* Network dropped connection because of
					  reset */
#define    ECONNABORTED		103    /* Software caused connection abort */
#define    ECONNRESET		104    /* Connection reset by peer */
#define    ENOBUFS		105    /* No buffer space available */
#define    EISCONN		106    /* Transport endpoint is already
					  connected */
#define    ENOTCONN		107    /* Transport endpoint is not connected */
#define    ESHUTDOWN		108    /* Cannot send after transport endpoint
					  shutdown */
#define    ETOOMANYREFS		109    /* Too many references: cannot splice */
#define    ETIMEDOUT		110    /* Connection timed out */
#define    ECONNREFUSED		111    /* Connection refused */
#define    EHOSTDOWN		112    /* Host is down */
#define    EHOSTUNREACH		113    /* No route to host */
#define    EALREADY		114    /* Operation already in progress */
#define    EINPROGRESS		115    /* Operation now in progress */
#define    ESTALE		116    /* Stale NFS file handle */
#define    EUCLEAN		117    /* Structure needs cleaning */
#define    ENOTNAM		118    /* Not a XENIX named type file */
#define    ENAVAIL		119    /* No XENIX semaphores available */
#define    EISNAM		120    /* Is a named type file */
#define    EREMOTEIO		121    /* Remote I/O error */
#define    EDQUOT		122    /* Quota exceeded */

#define    ENOMEDIUM		123    /* No medium found */
#define    EMEDIUMTYPE		124    /* Wrong medium type */
#define    ECANCELED		125    /* Operation Canceled */
#define    ENOKEY		126    /* Required key not available */
#define    EKEYEXPIRED		127    /* Key has expired */
#define    EKEYREVOKED		128    /* Key has been revoked */
#define    EKEYREJECTED		129    /* Key was rejected by service */

/* for robust mutexes */
#define    EOWNERDEAD		130    /* Owner died */
#define    ENOTRECOVERABLE	131    /* State not recoverable */

#endif

#define PCI_BASE_ADDRESS_0		0x10	/* 32 bits */
#define PCI_BASE_ADDRESS_1		0x14	/* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2		0x18	/* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3		0x1c	/* 32 bits */
#define PCI_BASE_ADDRESS_4		0x20	/* 32 bits */
#define PCI_BASE_ADDRESS_5		0x24	/* 32 bits */
#define PCI_BASE_ADDRESS_SPACE		0x01	/* 0 = memory, 1 = I/O */
#define PCI_BASE_ADDRESS_SPACE_IO	0x01
#define PCI_BASE_ADDRESS_SPACE_MEMORY	0x00
#define PCI_BASE_ADDRESS_MEM_TYPE_MASK	0x06
#define PCI_BASE_ADDRESS_MEM_TYPE_32	0x00	/* 32 bit address */
#define PCI_BASE_ADDRESS_MEM_TYPE_1M	0x02	/* Below 1M [obsolete] */
#define PCI_BASE_ADDRESS_MEM_TYPE_64	0x04	/* 64 bit address */
#define PCI_BASE_ADDRESS_MEM_PREFETCH	0x08	/* prefetchable? */
#define PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)
#define PCI_BASE_ADDRESS_IO_MASK	(~0x03UL)

#define AUTONEG_DISABLE		0x0
#define AUTONEG_ENABLE		0x1

#define PCI_VENDOR_ID		0x00
#define PCI_DEVICE_ID		0x02

#define PCI_CAP_ID_VPD		0x03
#define PCI_CAP_ID_EXP		0x10

#define PCI_EXP_LNKSTA		18
#define PCI_EXP_LNKSTA_CLS	0x000f
#define PCI_EXP_LNKSTA_NLW	0x03f0
#define PCI_EXP_DEVCTL2		40


static inline u32  swab32(u32 _Val)
{
	u32  Ret = 0;

	Ret = (((_Val & 0x000000ffUL) << 24) |
			((_Val & 0x0000ff00UL) <<  8) |
			((_Val & 0x00ff0000UL) >>  8) |
			((_Val & 0xff000000UL) >> 24));

	return Ret;

}

/* ---------------------------------------------------------------------------*/

static inline u16  NTOHS(u16 _Val)
{
	u16  Ret = 0;

	Ret = (((_Val & 0xFF00) >> 8) | ((_Val & 0x00FF) << 8));

	return Ret;
}

#define ntohs(x)	((unsigned int) NTOHS(x))

/* ---------------------------------------------------------------------------*/

static inline u16  HTONS(u16 _Val)
{
	u16  Ret = 0;

	Ret = (((_Val & 0xFF00) >> 8) | ((_Val & 0x00FF) << 8));

	return Ret;
}

#define htons(x)	HTONS(x)

/* ---------------------------------------------------------------------------*/

static inline u32 NTOHL(u32 _Val)
{
	u32  Ret = 0;

	Ret = (((_Val >> 24) & 0x000000FF) |
			((_Val >> 8) & 0x0000FF00) |
			((_Val << 8) & 0x00FF0000) |
			((_Val << 24) & 0xFF000000));

	return Ret;

}

#define ntohl(x)	NTOHL(x)

/* ---------------------------------------------------------------------------*/

static inline u32 HTONL(u32 _Val)
{
	u32 Ret = 0;

	Ret = (((_Val >> 24) & 0x000000FF) |
			((_Val >> 8) & 0x0000FF00) |
			((_Val << 8) & 0x00FF0000) |
			((_Val << 24) & 0xFF000000));

	return Ret;
}

#define htonl(x)	HTONL(x)

/* ---------------------------------------------------------------------------*/

static inline u64 NTOHLL(u64 _Val)
{
	u64 Ret = 0;

	Ret = (((_Val >> 56) & 0x00000000000000FF) |
			((_Val >> 40) & 0x000000000000FF00) |
			((_Val >> 24) & 0x0000000000FF0000) |
			((_Val >> 8) & 0x00000000FF000000) |
			((_Val << 8) & 0x000000FF00000000) |
			((_Val << 24) & 0x0000FF0000000000) |
			((_Val << 40) & 0x00FF000000000000) |
			((_Val << 56) & 0xFF00000000000000));

	return Ret;
}

/* ---------------------------------------------------------------------------*/

static inline u64 HTONLL(u64 _Val)
{
	u64 Ret = 0;

	Ret = (((_Val >> 56) & 0x00000000000000FF) |
			((_Val >> 40) & 0x000000000000FF00) |
			((_Val >> 24) & 0x0000000000FF0000) |
			((_Val >> 8) & 0x00000000FF000000) |
			((_Val << 8) & 0x000000FF00000000) |
			((_Val << 24) & 0x0000FF0000000000) |
			((_Val << 40) & 0x00FF000000000000) |
			((_Val << 56) & 0xFF00000000000000));

	return Ret;
}

/* ---------------------------------------------------------------------------*/

static inline u32 cpu_to_be32(u32 _Val)
{
	u32 Ret = 0;

	Ret = (((_Val >> 24) & 0x000000FF) |
			((_Val >> 8) & 0x0000FF00) |
			((_Val << 8) & 0x00FF0000) |
			((_Val << 24) & 0xFF000000));

	return Ret;
}

/* ---------------------------------------------------------------------------*/

static inline u64 cpu_to_be64(u64 _Val)
{
	u64 Ret = 0;

	Ret = (((_Val >> 56) & 0x00000000000000FF) |
			((_Val >> 40) & 0x000000000000FF00) |
			((_Val >> 24) & 0x0000000000FF0000) |
			((_Val >> 8) & 0x00000000FF000000) |
			((_Val << 8) & 0x000000FF00000000) |
			((_Val << 24) & 0x0000FF0000000000) |
			((_Val << 40) & 0x00FF000000000000) |
			((_Val << 56) & 0xFF00000000000000));

	return Ret;

}

/* ---------------------------------------------------------------------------*/

#define be16_to_cpu(data)	NTOHS((data))
#define be32_to_cpu(data)	NTOHL((data))
#define be64_to_cpu(data)	NTOHLL((data))
#define cpu_to_be16(data)	HTONS((data))

#define le16_to_cpu(x)	x
#define le32_to_cpu(x)	x
#define cpu_to_le32(x)	x

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define min(_a, _b)	(((_a) < (_b)) ? (_a) : (_b))
#define max(_a, _b)	(((_a) > (_b)) ? (_a) : (_b))

#define CH_INFO(adap, fmt, ...)  /*dev_info(adap->pdev_dev, fmt,\
				   ## __VA_ARGS__)*/
#define CH_ERR(adap, fmt, ...)	 /*dev_err(adap->pdev_dev, fmt,\
				   ## __VA_ARGS__)*/
#define CH_WARN(adap, fmt, ...)  /*dev_warn(adap->pdev_dev, fmt,\
				   ## __VA_ARGS__)*/
#define CH_ALERT(adap, fmt, ...) /*dev_alert(adap->pdev_dev, fmt,\
				   ## __VA_ARGS__)*/

#define CH_WARN_RATELIMIT(adap, fmt, ...)
#if 0
do {\
	/*if (printk_ratelimited()) \
			dev_warn(adap->pdev_dev, fmt, ## __VA_ARGS__); */\
	pr_warn_ratelimited(fmt, ## __VA_ARGS__);
} while (0)
#endif
/*
 * More powerful macro that selectively prints messages based on msg_enable.
 * For info and debugging messages.
 */
#define CH_MSG(adapter, level, category, fmt, ...)
#if 0
do { \
	if ((adapter)->msg_enable & NETIF_MSG_##category) \
		dev_printk(KERN_##level, adapter->pdev_dev, fmt, \
## __VA_ARGS__); \
} while (0)
#endif
#ifdef DEBUG
# define CH_DBG(adapter, category, fmt, ...) \
		       CH_MSG(adapter, DEBUG, category, fmt, ## __VA_ARGS__)
#else
# define CH_DBG(adapter, category, fmt, ...)
#endif

#define CH_DUMP_MBOX(adap, mbox, data_reg, size) \
		       CH_MSG(adap, INFO, MBOX, \
			      "mbox %u: %016llx %016llx %016llx %016llx "\
			      "%016llx %016llx %016llx %016llx\n", (mbox), \
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg),\
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg + 8), \
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg + 16),\
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg + 24),\
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg + 32),\
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg + 40),\
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg + 48),\
			      (unsigned long long)t4_read_reg64(adap,\
								data_reg + 56));

#endif /* _ADAP_UTIL_H_ */
