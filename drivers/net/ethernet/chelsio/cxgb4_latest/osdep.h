/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_OSDEP_H
#define __CXGB4_OSDEP_H

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ethtool.h>

#ifndef fallthrough
#define fallthrough do {} while (0)
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD_MODULE
# define CONFIG_CHELSIO_T4_OFFLOAD
#endif

#ifdef CHELSIO_LINUX_VERSION_CODE
#define CHELSIO_KERNEL_VERSION(a, b, c) (((a) << 24) + ((b) << 16) + (c))
#endif /* CHELSIO_LINUX_VERSION_CODE */

typedef struct adapter adapter_t;

/*
 * The Linux drivers have been converted to deal with the new 32-bit Firmware
 * Port Capabilities.
 */
#define T4_OS_NEW_FW_CAPS32 1

#ifndef strcat_s
#define strcat_s(dst, dst_size, src) strcat(dst, src)
#endif

#ifndef strcpy_s
#define strcpy_s(dst, dst_size, src) strcpy(dst, src)
#endif

#ifndef strncpy_s
#define strncpy_s(dst, dst_size, src, count) strncpy(dst, src, count)
#endif

#endif  /* !__CXGB4_OSDEP_H */
