# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux Random Number Generator.
#

obj-y				+= lrng_es_mgr.o lrng_aux.o \
				   lrng_es_irq.o lrng_es_archrandom.o \
				   lrng_drng.o lrng_chacha20.o \
				   lrng_interfaces.o lrng_es_aux.o

obj-$(CONFIG_NUMA)		+= lrng_numa.o
obj-$(CONFIG_SYSCTL)		+= lrng_proc.o
obj-$(CONFIG_LRNG_DRNG_SWITCH)	+= lrng_switch.o
