/*
 * This file is part of the Chelsio T4/T5 Ethernet driver.
 *
 * Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * This file contains OS-Independent support code for Bypass Adapters.  These
 * are adapters which support the capability of operating on a link in an
 * "interposed" manner where two ports are either routed directly two each
 * other (BYPASS) or directed through to the host (NORMAL).  Additionally, in
 * the event the host becomes unresponsive, the adapters support the
 * capability of automatically switching the links to each other (BYPASS) or
 * unconnected (DROP).
 */

#ifndef __T4_BYPASS_H__
#define __T4_BYPASS_H__

#include "t4fw_interface.h"

#define T4_BYPASS_MODE_NORMAL	FW_PARAMS_PARAM_DEV_BYPASS_NORMAL
#define T4_BYPASS_MODE_DROP	FW_PARAMS_PARAM_DEV_BYPASS_DROP
#define T4_BYPASS_MODE_BYPASS	FW_PARAMS_PARAM_DEV_BYPASS_BYPASS

int t4_bypass_read_current_bypass_mode(adapter_t *adap, int *mode);
int t4_bypass_write_current_bypass_mode(adapter_t *adap, int mode);
int t4_bypass_read_failover_bypass_mode(adapter_t *adap, int *mode);
int t4_bypass_write_failover_bypass_mode(adapter_t *adap, int mode);

int t4_bypass_read_watchdog(adapter_t *adap, unsigned int *ms);
int t4_bypass_write_watchdog(adapter_t *adap, unsigned int ms);
int t4_bypass_ping_watchdog(adapter_t *adap);

int t4_bypass_setup(adapter_t *adap);
int t4_bypass_shutdown(adapter_t *adap);

#endif /* __T4_BYPASS_H__ */
