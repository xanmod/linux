# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I$(src)			# needed for trace events

obj-y					+= ion/

ashmem_linux-y				+= ashmem.o
obj-$(CONFIG_ASHMEM)			+= ashmem_linux.o
