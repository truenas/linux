/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2011-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "common.h"

#define CXGB4_NUM_TRIPS 1

static int cxgb4_thermal_get_temp(struct thermal_zone_device *tzdev,
				  int *temp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	struct adapter *adap = thermal_zone_device_priv(tzdev);
#else
	struct adapter *adap = tzdev->devdata;
#endif
	u32 param, val;
	int ret;

	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DIAG) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAM_DEV_DIAG_TMP));

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
			      &param, &val);
	if (ret < 0 || val == 0)
		return -1;

	*temp = val * 1000;
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
static int cxgb4_thermal_get_trip_type(struct thermal_zone_device *tzdev,
				       int trip, enum thermal_trip_type *type)
{
	struct adapter *adap = tzdev->devdata;

	if (!adap->ch_thermal.trip_temp)
		return -EINVAL;

	*type = adap->ch_thermal.trip_type;
	return 0;
}

static int cxgb4_thermal_get_trip_temp(struct thermal_zone_device *tzdev,
				       int trip, int *temp)
{
	struct adapter *adap = tzdev->devdata;

	if (!adap->ch_thermal.trip_temp)
		return -EINVAL;

	*temp = adap->ch_thermal.trip_temp;
	return 0;
}
#endif

static struct thermal_zone_device_ops cxgb4_thermal_ops = {
	.get_temp = cxgb4_thermal_get_temp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
	.get_trip_type = cxgb4_thermal_get_trip_type,
	.get_trip_temp = cxgb4_thermal_get_trip_temp,
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static struct thermal_trip trip = { .type = THERMAL_TRIP_CRITICAL } ;
#endif

int cxgb4_thermal_init(struct adapter *adap)
{
	struct ch_thermal *ch_thermal = &adap->ch_thermal;
	char ch_tz_name[THERMAL_NAME_LENGTH];
	int num_trip = CXGB4_NUM_TRIPS;
	u32 param, val;
	int ret;

	/* on older firmwares we may not get the trip temperature,
	 * set the num of trips to 0.
	 */
	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DIAG) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAM_DEV_DIAG_MAXTMPTHRESH));

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
			      &param, &val);
	if (ret < 0) {
		num_trip = 0; /* could not get trip temperature */
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		trip.temperature = val * 1000;
#else
		ch_thermal->trip_temp = val * 1000;
		ch_thermal->trip_type = THERMAL_TRIP_CRITICAL;
#endif
	}

	snprintf(ch_tz_name, sizeof(ch_tz_name), "cxgb4_%s", adap->name);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ch_thermal->tzdev = thermal_zone_device_register_with_trips(ch_tz_name, &trip, num_trip,
								    adap, &cxgb4_thermal_ops,
								    NULL, 0, 0);
#else
	ch_thermal->tzdev = thermal_zone_device_register(ch_tz_name, num_trip,
							 0, adap,
							 &cxgb4_thermal_ops,
							 NULL, 0, 0);
#endif
	if (IS_ERR(ch_thermal->tzdev)) {
		ret = PTR_ERR(ch_thermal->tzdev);
		dev_err(adap->pdev_dev, "Failed to register thermal zone\n");
		ch_thermal->tzdev = NULL;
		return ret;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = thermal_zone_device_enable(ch_thermal->tzdev);
	if (ret) {
		dev_err(adap->pdev_dev, "Failed to enable thermal zone\n");
		thermal_zone_device_unregister(adap->ch_thermal.tzdev);
		return ret;
	}
#endif

	return 0;
}

int cxgb4_thermal_remove(struct adapter *adap)
{
	if (adap->ch_thermal.tzdev) {
		thermal_zone_device_unregister(adap->ch_thermal.tzdev);
		adap->ch_thermal.tzdev = NULL;
	}
	return 0;
}
