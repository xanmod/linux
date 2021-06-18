# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux Random Number Generator.
#

obj-y				+= lrng_pool.o lrng_aux.o \
				   lrng_sw_noise.o lrng_archrandom.o \
				   lrng_drng.o lrng_chacha20.o \
				   lrng_interfaces.o

obj-$(CONFIG_NUMA)		+= lrng_numa.o
obj-$(CONFIG_SYSCTL)		+= lrng_proc.o
obj-$(CONFIG_LRNG_DRNG_SWITCH)	+= lrng_switch.o
obj-$(CONFIG_LRNG_KCAPI_HASH)	+= lrng_kcapi_hash.o
obj-$(CONFIG_LRNG_DRBG)		+= lrng_drbg.o
