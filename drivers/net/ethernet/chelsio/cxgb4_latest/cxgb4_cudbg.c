#include <linux/version.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/panic_notifier.h>

#include "t4_hw.h"
#include "common.h"
#include "t4_regs.h"
#include "t4_msg.h"
#include "platdef.h"
#include "cudbg_if.h"
#include "cxgb4_cxgbtool.h"

static struct cudbg_init cudbg = {{0}};

static enum CUDBG_DBG_ENTITY_TYPE large_entity_list[] = {
	CUDBG_MC0,
	CUDBG_MC1,
	CUDBG_HMA,
};

static void cxgb4_cudbg_yield(struct cudbg_init *pdbg_init)
{
	struct adapter *adap = pdbg_init->adap;

	if (!(adap->flags & K_CRASH))
		schedule();
}

static void cxgb4_cudbg_fill_default_dbg_params(struct adapter *adap)
{
	struct devlog_params *dparams = &adap->params.devlog[0];

	cudbg.dbg_params[CUDBG_DEVLOG_PARAM].param_type = CUDBG_DEVLOG_PARAM;
	cudbg.dbg_params[CUDBG_DEVLOG_PARAM].u.devlog_param.memtype =
			dparams->memtype;
	cudbg.dbg_params[CUDBG_DEVLOG_PARAM].u.devlog_param.start =
			dparams->start;
	cudbg.dbg_params[CUDBG_DEVLOG_PARAM].u.devlog_param.size =
			dparams->size;
	cudbg.dbg_params_cnt++;

#ifdef T4_OS_LOG_MBOX_CMDS
	cudbg.dbg_params[CUDBG_MBOX_LOG_PARAM].param_type =
			CUDBG_MBOX_LOG_PARAM;
	cudbg.dbg_params[CUDBG_MBOX_LOG_PARAM].u.mboxlog_param.log =
			adap->mbox_log;
	cudbg.dbg_params[CUDBG_MBOX_LOG_PARAM].u.mboxlog_param.mbox_cmds =
			T4_OS_LOG_MBOX_CMDS;
	cudbg.dbg_params_cnt++;
#endif

	if (!(adap->flags & FW_OK)) {
		cudbg.dbg_params[CUDBG_FW_NO_ATTACH_PARAM].param_type =
			CUDBG_FW_NO_ATTACH_PARAM;
		cudbg.dbg_params_cnt++;
	}
}

static void do_collect(struct adapter *adap, void *buf, unsigned long size)
{
	struct cudbg_param *dbg_param;
	struct timespec64 ts;
	void *handle = NULL;
	int ret;
	u32 i;

	init_cudbg_hdr(&cudbg.header);
	/* Enable collecting all entities for now.  We may remove some
	 * of the entities from collection based on @adap->cudbg_kcrash_flags
	 */
	for (i = 1; i < CUDBG_MAX_ENTITY; i++) {
		/* Skip extended entity */
		if (i == CUDBG_EXT_ENTITY)
			continue;

		set_dbg_bitmap(cudbg.dbg_bitmap, i);
	}
	cudbg.adap = adap;
	cudbg.print = (cudbg_print_cb) _printk;
	cudbg.sw_state_buf = NULL;
	cudbg.sw_state_buflen = 0;

	if (adap->cudbg_kcrash_flags & CUDBG_KCRASH_SKIP_ENTITY_ALL)
		goto out;

	if (adap->cudbg_kcrash_flags & CUDBG_KCRASH_SKIP_FLASH_WRITE)
		cudbg.use_flash = 0;
	else
		cudbg.use_flash = 1;

	if (adap->cudbg_kcrash_flags & CUDBG_KCRASH_SKIP_ENTITY_LARGE)
		for (i = 0; i < ARRAY_SIZE(large_entity_list); i++)
			reset_dbg_bitmap(cudbg.dbg_bitmap,
					 large_entity_list[i]);

	cxgb4_cudbg_fill_default_dbg_params(adap);

	ktime_get_ts64(&ts);
	cudbg.dbg_params[CUDBG_TIMESTAMP_PARAM].u.time = ts.tv_sec;
	cudbg.dbg_params[CUDBG_TIMESTAMP_PARAM].param_type =
			CUDBG_TIMESTAMP_PARAM;
	cudbg.dbg_params_cnt++;

	dbg_param = &(cudbg.dbg_params[CUDBG_SW_STATE_PARAM]);
	dbg_param->param_type = CUDBG_SW_STATE_PARAM;
	dbg_param->u.sw_state_param.os_type = CUDBG_OS_TYPE_LINUX;
	dbg_param->u.sw_state_param.caller_string = "KERNEL PANIC";
	cudbg.dbg_params_cnt++;

	ret = cudbg_hello(&cudbg, &handle);
	if (ret) {
		dev_err(adap->pdev_dev,
			"cudbg failed to initialize, hello cmd failed, ret=%d",
			 ret);
		goto out;
	}

	ret = cudbg_collect(handle, buf, (u32 *)&size);
	if (ret) {
		dev_err(adap->pdev_dev,
			"cudbg collect failed, ret=%d", ret);
		goto out;
	}

	dev_info(adap->pdev_dev, "cudbg collect success, size=%lu", size);

out:
	if (handle)
		cudbg_bye(handle);
}

/* Allocate enough to collect all entities.  Let cudbg library handle
 * how much can be collected into this buffer and how much can be flashed
 * on to the card
 */
#define DUMP_BUF_SIZE (32 * 1024 * 1024)

static int panic_notify(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	struct adapter *adap = container_of(this, struct adapter, panic_nb);

	dev_info(adap->pdev_dev, "Initialized cxgb4 crash handler");

	adap->flags |= K_CRASH;
	do_collect(adap, adap->dump_buf, DUMP_BUF_SIZE);
	dev_info(adap->pdev_dev, "cxgb4 debug collection succeeded..");

	return NOTIFY_DONE;
}

int cxgb4_register_panic_notifier(struct adapter *adap)
{
	adap->dump_buf = t4_alloc_mem(DUMP_BUF_SIZE);
	if (!adap->dump_buf) {
		return -ENOMEM;
	} else {
		dev_info(adap->pdev_dev,
			 "Registering cxgb4 panic handler.., Buffer start address = %p, size: %d",
			 adap->dump_buf, DUMP_BUF_SIZE);
		adap->panic_nb.notifier_call = panic_notify;
		adap->panic_nb.priority = INT_MAX;

		atomic_notifier_chain_register(&panic_notifier_list,
					       &adap->panic_nb);
	}

	return 0;
}

void cxgb4_unregister_panic_notifier(struct adapter *adap)
{
	if (adap->dump_buf) {
		atomic_notifier_chain_unregister(&panic_notifier_list,
						 &adap->panic_nb);
		t4_free_mem(adap->dump_buf);
	}
}

static void cxgb4_cudbg_ioctl_parse_dbg_params(struct adapter *adap,
					       u8 *dbg_bitmap,
					       u16 dbg_bitmap_cnt,
					       void *dbg_params,
					       size_t dbg_params_data_size,
					       u16 dbg_params_cnt,
					       u16 dbg_params_max)
{
	u8 bmap, bit;
	u16 i, ptype;

	for (i = 0; i < dbg_bitmap_cnt; i++) {
		bmap = dbg_bitmap[i / 8];
		bit = i % 8;
		if (bmap & (1 << bit))
			set_dbg_bitmap(cudbg.dbg_bitmap, i);
	}

	cxgb4_cudbg_fill_default_dbg_params(adap);

	for (i = CUDBG_DEVLOG_PARAM; i < dbg_params_max; i++) {
		dbg_params += dbg_params_data_size;
		if (!dbg_params_cnt)
			break;

		ptype = *(u16 *)dbg_params;
		if (ptype != i)
			continue;

		if (ptype == CUDBG_DEVLOG_PARAM ||
		    ptype == CUDBG_MBOX_LOG_PARAM) {
			/* These default params can't be overwritten */
			dbg_params_cnt--;
			continue;
		}

		/* If we're just updating the default params filled
		 * earlier, then no need to increment count.
		 */
		if (cudbg.dbg_params[i].param_type != i)
			cudbg.dbg_params_cnt++;

		memcpy(&cudbg.dbg_params[i], dbg_params,
		       min_t(size_t, sizeof(cudbg.dbg_params[0]),
			     dbg_params_data_size));

		dbg_params_cnt--;
	}
}

static int cxgb4_cudbg_ioctl_compat(struct adapter *adap, u32 vers,
				    void __user *useraddr)
{
	switch (vers) {
	case 0x1:
		/* Handle version 0x1 copy_from_user(). Allocate
		 * a buffer based on size gotten from (ioctl -
		 * sizeof(ioctl)). Process the ioctl and collect
		 * the logs into the allocated buffer according to
		 * version 0x1 spec. Update the version and size in
		 * the cudbg_ioctl and ship it back to the user with
		 * copy_to_user().
		 */
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

int cxgb4_cudbg_ioctl(struct adapter *adap, void __user *useraddr)
{
	void *buf = NULL, *handle = NULL;
	struct cudbg_ioctl cmd;
	int ret = 0;
	u64 size;

	if (copy_from_user(&cmd, useraddr,
			   offsetof(struct cudbg_ioctl, size) +
			   sizeof(cmd.size))) {
		ret = -EFAULT;
		goto out;
	}

	size = cmd.size;
	if (!size)
		goto send_reply;

	memset(&cudbg, 0, sizeof(cudbg));
	init_cudbg_hdr(&cudbg.header);

	cudbg.adap = adap;
	cudbg.print = (cudbg_print_cb) _printk;
	cudbg.sw_state_buf = NULL;
	cudbg.sw_state_buflen = 0;
	cudbg.yield_cb = cxgb4_cudbg_yield;

	if (cmd.version != CUDBG_IOCTL_VERSION) {
		ret = cxgb4_cudbg_ioctl_compat(adap, cmd.version, useraddr);
		/* Skip rest of the processing since it's already
		 * handled in compatibility code above.
		 */
		goto out;
	}

	if (copy_from_user(&cmd, useraddr, sizeof(cmd))) {
		ret = -EFAULT;
		goto out;
	}

	size -= sizeof(cmd);
	buf = t4_os_alloc(size);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	cxgb4_cudbg_ioctl_parse_dbg_params(adap, cmd.dbg_bitmap,
					   CUDBG_MAX_ENTITY,
					   cmd.dbg_params,
					   sizeof(cmd.dbg_params[0]),
					   cmd.dbg_params_cnt,
					   CUDBG_MAX_PARAMS);

	ret = cudbg_hello(&cudbg, &handle);
	if (ret) {
		dev_err(adap->pdev_dev,
			"cudbg failed to initialize, hello cmd failed, ret=%d",
			 ret);
		goto out;
	}

	ret = cudbg_collect(handle, buf, (u32 *)&size);
	if (ret) {
		dev_err(adap->pdev_dev,
			"cudbg collect failed, ret=%d", ret);
		goto out;
	}

	if (copy_to_user(useraddr + sizeof(cmd), buf, size)) {
		ret = -EFAULT;
		goto out;
	}

send_reply:
	cmd.version = min_t(u32, cmd.version, CUDBG_IOCTL_VERSION);
	cmd.size = sizeof(cmd) + size;
	if (copy_to_user(useraddr, &cmd, sizeof(cmd))) {
		ret = -EFAULT;
		goto out;
	}

out:
	if (handle)
		cudbg_bye(handle);

	if (buf)
		t4_free_mem(buf);

	return ret;
}
