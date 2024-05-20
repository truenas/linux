# SPDX-License-Identifier: GPL-2.0

# needed for trace events
ccflags-y			+= -I$(src)

obj-$(CONFIG_BLK_DEV_NULL_BLK)	+= null_blk.o
null_blk-objs			:= main.o
null_blk-$(CONFIG_TRACING) 	+= trace.o
null_blk-$(CONFIG_BLK_DEV_ZONED) += zoned.o
