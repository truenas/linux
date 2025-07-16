/*
 *  This file is part of the Chelsio T4 Ethernet driver for Linux.
 *  Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *  
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 *  release for licensing terms and conditions.
 */


extern int allow_nonroot_ioctl;
int cxgb4_closest_timer(const struct sge *s, int time);
int cxgb_extension_ioctl(struct net_device *dev, void __user *useraddr);
int cxgb4_cudbg_ioctl(struct adapter *adap, void __user *useraddr);
u32 cxgb4_cxgbtool_filter_id_to_ftid(struct adapter *adap, u32 filter_id,
                                     struct ch_filter_specification *fs);
u32 cxgb4_cxgbtool_ftid_to_filter_id(struct adapter *adap, u32 ftid,
                                     struct ch_filter_specification *fs);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
enum {
	SZ_VER_1 = sizeof(struct offload_settings),
	SZ_VER_0 = offsetof(struct offload_settings, tls) };

#define PAR_POLICY_LEN(b, c) (sizeof(struct ofld_policy_file) +\
			      (b * sizeof(struct ofld_prog_inst)) +\
			      (c * sizeof(u32)))

#define SETTINGS_LEN(a, b, c, d) (PAR_POLICY_LEN(b, c) +\
				  ((a + 1) * (d)))

int cxgb4_get_filter_count(struct adapter *adapter, unsigned int fidx,
			    u64 *c, int hash, bool get_byte);
#endif

enum {
	MAX_BURST_SIZE       = USHRT_MAX
};
