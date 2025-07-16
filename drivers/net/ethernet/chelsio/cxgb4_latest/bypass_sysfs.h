/*
 * This file is part of the Chelsio T3 Ethernet driver.
 *
 * Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CHELSIO_DX804_SYSFS_H
#define __CHELSIO_DX804_SYSFS_H

#ifdef CONFIG_CHELSIO_BYPASS

int bypass_sysfs_create(adapter_t *adap);
int bypass_sysfs_remove(adapter_t *adap);

#else /* CONFIG_CHELSIO_BYPASS */

static inline int bypass_sysfs_create(adapter_t *adap)
{
	return -EIO;
}

static inline int bypass_sysfs_remove(adapter_t *adap)
{
	return -EIO;
}

#endif /* CONFIG_CHELSIO_BYPASS */

#endif /* __CHELSIO_DX804_SYSFS_H */
