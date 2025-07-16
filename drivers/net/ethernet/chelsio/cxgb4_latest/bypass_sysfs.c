/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * This file contains support code for managing the Chelsio Bypass adapter.
 * Most of this management is enabled via standard Linux "SYSFS" interfaces
 * under /sys/class/bypass/{adapter}/{parameter}.  These SYSFS nodes allow
 * changing the current and failover modes of the adapter, a watchdog timer,
 * and packet classification/action rules.
 */
#ifndef LINUX_2_4

#include <linux/device.h>

#include "common.h"
#include "t4_bypass.h"

/*
 * Declarations for /sys filesystem entries ...
 */

#define CXGB4_SHOW_FUNC(func, d, attr, buf)                     \
        static ssize_t func(struct device *d,      		\
                            struct device_attribute *attr,      \
                            char *buf)                          \

#define CXGB4_STORE_FUNC(func, d, attr, buf, len)               \
        static ssize_t func(struct device *d,      		\
                            struct device_attribute *attr,      \
                            const char *buf,                    \
                            size_t len)

#define CXGB4_DEVICE_ATTR DEVICE_ATTR

int bypass_sysfs_create(adapter_t *adap);
int bypass_sysfs_remove(adapter_t *adap);

static inline struct kobject *net2kobj(struct net_device *dev)
{
        return &dev->dev.kobj;
}

#define BYPASS_ATTR(_name_) \
	CXGB4_SHOW_FUNC(_name_##_show, dev, attr, buf); \
	CXGB4_STORE_FUNC(_name_##_store, dev, attr, buf, len); \
	CXGB4_DEVICE_ATTR(_name_, 0644, \
			  _name_##_show, \
			  _name_##_store)

BYPASS_ATTR(current_mode);
BYPASS_ATTR(failover_mode);
BYPASS_ATTR(watchdog);
BYPASS_ATTR(watchdog_ping);
BYPASS_ATTR(watchdog_lock);

static struct attribute *bypass_attrs[] = {
	&dev_attr_current_mode.attr,
	&dev_attr_failover_mode.attr,
	&dev_attr_watchdog.attr,
	&dev_attr_watchdog_ping.attr,
	&dev_attr_watchdog_lock.attr,
	NULL,
};

static struct attribute_group bypass_attr_group = {
	.name = "bypass",
	.attrs = bypass_attrs,
};

/*
 * Routines to create and remove /sys filesystem entries.
 */

/*
 * Create all of the SYSFS nodes needed for managing the bypass card
 * capabilities.  Return 0 on success, an error on failure.
 */
int bypass_sysfs_create(adapter_t *adap)
{
	if (!is_bypass(adap))
		return -EINVAL;
	return sysfs_create_group(net2kobj(adap->port[0]),
				  &bypass_attr_group);
	return -ENXIO;
}

/*
 * Remove all of the SYSFS nodes created to manage the bypass card
 * capabilities.  Return 0 on success, an error on failure.
 */
int bypass_sysfs_remove(adapter_t *adap)
{
	if (!is_bypass(adap))
		return -EINVAL;
	sysfs_remove_group(net2kobj(adap->port[0]),
			   &bypass_attr_group);
	return 0;
}

/*
 * Individual /sys file system implementation routines.
 */

/*
 * Small convenience macro to evaluate an expression and perform a "return"
 * with the value of that expression if it's less than zero.
 */
#define RETERR(expression) \
	do { \
		int ret = (expression); \
		if (ret < 0) { \
			return ret; \
		} \
	} while (0)

/*
 * Convert a pointer to a net device's "class dev" pointer to a pointer to the
 * corresponding adapter.
 */
#define netdev_class_to_adapter(d) \
	((struct port_info *)netdev_priv(to_net_dev(d)))->adapter

/*
 * Constant strings for decoding/encoding requests.
 */
static const char bypass_mode[] = "bypass";
static const char normal_mode[] = "normal";
static const char drop_mode[] = "drop";

/*
 * show/store routines for "current mode".
 */
CXGB4_SHOW_FUNC(current_mode_show, dev, attr, buf)
{
	adapter_t *adap = netdev_class_to_adapter(dev);
	int mode;

	RETERR(t4_bypass_read_current_bypass_mode(adap, &mode));
	switch (mode) {
	    case T4_BYPASS_MODE_BYPASS:
		return sprintf(buf, "%s\n", bypass_mode);

	    case T4_BYPASS_MODE_NORMAL:
		return sprintf(buf, "%s\n", normal_mode);

	    case T4_BYPASS_MODE_DROP:
		return sprintf(buf, "%s\n", drop_mode);

	    default:
		return sprintf(buf, "illegal mode %d\n", mode);
	}
}

CXGB4_STORE_FUNC(current_mode_store, dev, attr, buf, len)
{
	adapter_t *adap = netdev_class_to_adapter(dev);
	int mode;

	if (strncmp(buf, bypass_mode, sizeof bypass_mode - 1) == 0)
		mode = T4_BYPASS_MODE_BYPASS;
	else if (strncmp(buf, normal_mode, sizeof normal_mode - 1) == 0)
		mode = T4_BYPASS_MODE_NORMAL;
	else if (strncmp(buf, drop_mode, sizeof drop_mode - 1) == 0)
		mode = T4_BYPASS_MODE_DROP;
	else
		return -EINVAL;

	RETERR(t4_bypass_write_current_bypass_mode(adap, mode));
	return len;
}

/*
 * show/store routines for "failover mode".
 */
CXGB4_SHOW_FUNC(failover_mode_show, dev, attr, buf)
{
	adapter_t *adap = netdev_class_to_adapter(dev);
	int mode;

	RETERR(t4_bypass_read_failover_bypass_mode(adap, &mode));
	switch (mode) {
	    case T4_BYPASS_MODE_BYPASS:
		return sprintf(buf, "%s\n", bypass_mode);

	    case T4_BYPASS_MODE_DROP:
		return sprintf(buf, "%s\n", drop_mode);

	    default:
		return sprintf(buf, "illegal mode %d\n", mode);
	}
}

CXGB4_STORE_FUNC(failover_mode_store, dev, attr, buf, len)
{
	adapter_t *adap = netdev_class_to_adapter(dev);
	int mode;

	if (strncmp(buf, bypass_mode, sizeof bypass_mode - 1) == 0)
		mode = T4_BYPASS_MODE_BYPASS;
	else if (strncmp(buf, drop_mode, sizeof drop_mode - 1) == 0)
		mode = T4_BYPASS_MODE_DROP;
	else
		return -EINVAL;

	RETERR(t4_bypass_write_failover_bypass_mode(adap, mode));
	return len;
}

/*
 * show/store routines for "watchdog".
 */
CXGB4_SHOW_FUNC(watchdog_show, dev, attr, buf)
{
	adapter_t *adap = netdev_class_to_adapter(dev);
	int ms;

	RETERR(t4_bypass_read_watchdog(adap, &ms));
	return sprintf(buf, "%d\n", ms);
}

CXGB4_STORE_FUNC(watchdog_store, dev, attr, buf, len)
{
	adapter_t *adap = netdev_class_to_adapter(dev);
	char *endp;
	unsigned int ms;

	ms = simple_strtoul(buf, &endp, 0);
	if (endp == buf)
		return -EINVAL;

	if (adap->bypass_watchdog_lock == 1 &&
	    ms != adap->bypass_watchdog_timeout)
		return -EPERM;

	RETERR(t4_bypass_write_watchdog(adap, ms));
	return len;
}

CXGB4_SHOW_FUNC(watchdog_ping_show, dev, attr, buf)
{
	return sprintf(buf, "write only");
}

CXGB4_STORE_FUNC(watchdog_ping_store, dev, attr, buf, len)
{
	adapter_t *adap = netdev_class_to_adapter(dev);

	RETERR(t4_bypass_ping_watchdog(adap));
	return len;
}

CXGB4_SHOW_FUNC(watchdog_lock_show, dev, attr, buf)
{
	adapter_t *adap = netdev_class_to_adapter(dev);

	if (adap->bypass_watchdog_lock == 1)
		return sprintf(buf, "locked");
	else
		return sprintf(buf, "unlocked");
}

CXGB4_STORE_FUNC(watchdog_lock_store, dev, attr, buf, len)
{
	adapter_t *adap = netdev_class_to_adapter(dev);

	adap->bypass_watchdog_lock = 1;

	return len;
}

#endif /* LINUX_2_4 */
