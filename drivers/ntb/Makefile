# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_NTB) += ntb.o hw/ test/
obj-$(CONFIG_NTB_SPLIT) += ntb_split.o
obj-$(CONFIG_NTB_TRANSPORT) += ntb_transport.o

ntb-y			:= core.o
ntb-$(CONFIG_NTB_MSI)	+= msi.o
