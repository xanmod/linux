# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux Random Number Generator.
#

obj-y				+= lrng_es_mgr.o lrng_aux.o \
				   lrng_drng.o lrng_chacha20.o \
				   lrng_interfaces.o lrng_es_aux.o

obj-$(CONFIG_LRNG_IRQ)		+= lrng_es_irq.o
obj-$(CONFIG_SYSCTL)		+= lrng_proc.o
obj-$(CONFIG_NUMA)		+= lrng_numa.o
obj-$(CONFIG_LRNG_CPU)		+= lrng_es_archrandom.o
obj-$(CONFIG_LRNG_DRNG_SWITCH)	+= lrng_switch.o
obj-$(CONFIG_LRNG_KCAPI_HASH)	+= lrng_kcapi_hash.o
obj-$(CONFIG_LRNG_DRBG)		+= lrng_drbg.o
obj-$(CONFIG_LRNG_KCAPI)	+= lrng_kcapi.o
obj-$(CONFIG_LRNG_JENT)		+= lrng_es_jent.o
obj-$(CONFIG_LRNG_HEALTH_TESTS)	+= lrng_health.o
