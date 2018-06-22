ccflags-y += -I$(src)			# needed for trace events

obj-y					+= ion/

obj-$(CONFIG_ASHMEM)			+= ashmem_linux.o
ashmem_linux-y += ashmem.o
obj-$(CONFIG_ANDROID_VSOC)		+= vsoc.o
