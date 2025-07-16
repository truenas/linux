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

#include "common.h"
#include "t4_bypass.h"
#include "t4_regs.h"
#include "t4fw_interface.h"

/*
 * Small convenience macro to evaluate an expression and perform a "return"
 * with the value of that expression if it's non-zero.
 */
#define RETERR(expression) \
	do { \
		int ret = (expression); \
		if (ret) { \
			return ret; \
		} \
	} while (0)

/*
 * Support code for managing the state of the bypass mode.  There are two
 * bypass modes: current and failover.  The current mode can be one of bypass,
 * normal or drop.  The failover mode can be one of bypass or drop.  The
 * failover mode is entered when either the watchdog timer expires or the
 * system power fails.
 *
 * In bypass mode, an optical switch that sits between the adapter connectors
 * and the optical PHYs is put into a mode where all optical signals on each
 * connector are shunted to the other connector.  The optical switch is a
 * Micro-Electro-Mechanical System (MEMS) with mirrors which, once put into a
 * stable state, will remain in that state even after power is removed.
 *
 * In normal mode, the optical switch is configured to pass optical signals on
 * the connectors to their associated optical PHYs.  This allows the adapter
 * to process packets, either for delivery to the host, bridged to the other
 * link or any other action programmable in the policy action table.
 * Normal mode can only be used when the system has power.
 *
 * In drop mode, the optical switch is configured to pass optical signals to
 * the PHYs, but the PHYs are put in reset (or powered off in the event of a
 * power failure).  Thus, a "dead link" is presented to the peers and any
 * incoming signals are dropped.
 */

/*
 * Read the current mode of the optical bypass switch.  Return 0 on success,
 * an error on failure.
 */
int t4_bypass_read_current_bypass_mode(adapter_t *adap, int *mode)
{
	u32 bname, bmode;
	int ret;

	bname =(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_BYPASS) |
		V_FW_PARAMS_PARAM_Y(FW_PARAMS_PARAM_DEV_BYPASS_CURRENT));

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &bname, &bmode);
	if (ret)
		return ret;

	/*
	 * Translate from firmware Bypass Mode values to our values.
	 */
	switch (bmode) {
	    case FW_PARAMS_PARAM_DEV_BYPASS_BYPASS:
		*mode = T4_BYPASS_MODE_BYPASS;
		break;

	    case FW_PARAMS_PARAM_DEV_BYPASS_NORMAL:
		*mode = T4_BYPASS_MODE_NORMAL;
		break;

	    case FW_PARAMS_PARAM_DEV_BYPASS_DROP:
		*mode = T4_BYPASS_MODE_DROP;
		break;

	    default:
		return -EIO;
	}

	return 0;
}

/*
 * Write the current mode of the optical bypass switch.  Return 0 on success,
 * an error on failure.
 */
int t4_bypass_write_current_bypass_mode(adapter_t *adap, int mode)
{
	u32 bname, bmode;
	int ret;

	/*
	 * Translate from our Bypass Mode values into the firmware's.
	 */
	switch (mode) {
	    case T4_BYPASS_MODE_BYPASS:
		bmode = FW_PARAMS_PARAM_DEV_BYPASS_BYPASS;
		break;

	    case T4_BYPASS_MODE_NORMAL:
		bmode = FW_PARAMS_PARAM_DEV_BYPASS_NORMAL;
		break;

	    case T4_BYPASS_MODE_DROP:
		bmode = FW_PARAMS_PARAM_DEV_BYPASS_DROP;
		break;

	    default:
		return -EINVAL;
	}

	bname = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_BYPASS) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAMS_PARAM_DEV_BYPASS_CURRENT));

	ret = t4_set_params(adap, adap->mbox, adap->pf, 0, 1, &bname, &bmode);
	if (ret < 0)
		return ret;

	if (mode == T4_BYPASS_MODE_DROP) {
		adap->flags |= BYPASS_DROP;
	} else {
		adap->flags &= ~BYPASS_DROP;
	}

	return 0;
}

/*
 * Read the failover mode.  Return 0 on success, an error on failure.
 */
int t4_bypass_read_failover_bypass_mode(adapter_t *adap, int *mode)
{
	u32 pname, pfail;
	int ret;

	pname = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_BYPASS) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAMS_PARAM_DEV_BYPASS_PFAIL));

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &pname, &pfail);

	/*
	 * Translate from firmware Bypass Mode values to our values.
	 */
	*mode = (pfail == FW_PARAMS_PARAM_DEV_BYPASS_DROP
		 ? T4_BYPASS_MODE_DROP
		 : T4_BYPASS_MODE_BYPASS);

	return ret;
}

/*
 * Write the failover mode.  Return 0 on success, an error on failure.
 */
int t4_bypass_write_failover_bypass_mode(adapter_t *adap, int mode)
{
	u32 pname, pfail;
	int ms;
	int ret;

	/*
	 * Make sure parameters are legal.
	 */
	if (mode != T4_BYPASS_MODE_BYPASS &&
	    mode != T4_BYPASS_MODE_DROP)
		return -EINVAL;

	/*
	 * The T4 firmware has two separate ways of controlling the Failover
	 * Mode.  One is what to do on Power Failure and the other is via
	 * separate watchdog timers for the actions Adapter Shutdown and
	 * Bypass Mode.  So, in order to implement the single Failover Mode
	 * semantic that we want for the Bypass Adapter, we have to fix up
	 * both.
	 */

	/*
	 * Set Power Failure Mode.
	 */
	pfail = (mode == T4_BYPASS_MODE_DROP
		 ? FW_PARAMS_PARAM_DEV_BYPASS_DROP
		 : FW_PARAMS_PARAM_DEV_BYPASS_BYPASS);
	pname = (
		 V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_BYPASS) |
		 V_FW_PARAMS_PARAM_Y(FW_PARAMS_PARAM_DEV_BYPASS_PFAIL));
	ret = t4_set_params(adap, adap->mbox, adap->pf, 0, 1, &pname, &pfail);
	if (ret)
		return ret;;

	/*
	 * If that was successful and we have a current watchdog set up, we
	 * need to disable the watchdog for the previous Failover Mode and
	 * start up a watchdog for the new Failover Mode.  Note that we have
	 * to save the current watchdog timeout value because
	 * t4_bypass_write_watchdog() will rewrite it ...
	 */
	ms = adap->bypass_watchdog_timeout;
	if (ms) {
		ret = t4_bypass_write_watchdog(adap, 0);
		if (ret)
			return ret;
	}
	adap->bypass_failover_mode = mode;
	if (ms)
		ret = t4_bypass_write_watchdog(adap, ms);

	return ret;
}

int t4_bypass_read_watchdog(adapter_t *adap, unsigned int *ms)
{
	*ms = adap->bypass_watchdog_timeout;	

	return 0;
}

/*
 * Write current watchdog timeout.  A non-zero value indicates the number of
 * milseconds till the watchdog timer expires.  A zero indicates that the
 * watchdog timer is disabled.  Return 0 on success, an error on failure.
 */
int t4_bypass_write_watchdog(adapter_t *adap, unsigned int ms)
{
	struct fw_watchdog_cmd wd;
	int ret;

	memset(&wd, 0, sizeof(wd));
	wd.retval_len16 = htonl(FW_LEN16(wd));
	wd.op_to_vfn =
	    htonl(V_FW_CMD_OP(FW_WATCHDOG_CMD) | F_FW_CMD_REQUEST |
		      F_FW_CMD_WRITE | V_FW_IQ_CMD_PFN(adap->pf) |
		      V_FW_IQ_CMD_VFN(0));
	wd.timeout = htonl(ms == 0 ? 0 : max((unsigned int)1, ms/10));
	wd.action = htonl(FW_WATCHDOG_ACTION_BYPASS);
	ret = t4_wr_mbox(adap, adap->mbox, &wd, sizeof(wd), NULL);
	
	if (ret == 0)
		adap->bypass_watchdog_timeout = ms;	
	return ret;
}

/*
 * Ping the firmware that the software is still alive.
 * Return 0 on success, an error on failure.
 */
int t4_bypass_ping_watchdog(adapter_t *adap)
{
	if (adap->bypass_watchdog_timeout != 0)
		t4_bypass_write_watchdog(adap, adap->bypass_watchdog_timeout);

	return 0;
}

/*
 * Initialize the bypass adapter.
 */
int t4_bypass_setup(adapter_t *adap)
{
	int ret;
	int bypass_failover_mode;

	ret = t4_bypass_read_current_bypass_mode(adap, &bypass_failover_mode);
	if (ret) {
		bypass_failover_mode = T4_BYPASS_MODE_BYPASS;
		CH_ERR(adap, "t4_bypass_setup: unable to read current failover"
		       " mode (err=%d); defauling to BYPASS\n", -ret);
	}

	adap->bypass_watchdog_lock = 0;
	adap->bypass_failover_mode = bypass_failover_mode;
	adap->bypass_watchdog_timeout = 0;

	return ret;
}

/*
 * Take the adapter down cleanly.
 */
int t4_bypass_shutdown(adapter_t *adap)
{
	int failover_mode, err, ret = 0;

	/*
	 * Shutting down the Bypass Adapter constitutes a communication
	 * failure so we need to change the current mode to the failover
	 * mode _before_ we shut down the adapter.
	 */
	err = t4_bypass_read_failover_bypass_mode(adap, &failover_mode);
	if (err) {
		CH_ERR(adap, "t4_bypass_shutdown: unable to read failover mode:"
		       " error=%d\n", -err);
		ret = err;
	} else {
		err = t4_bypass_write_current_bypass_mode(adap, failover_mode);
		if (err) {
			CH_ERR(adap, "t4_bypass_shutdown: unable to write"
			       " current mode: mode=%d, error=%d\n",
			       failover_mode, err);
			ret = err;
		}
	}

	return ret;
}
