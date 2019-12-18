
MODULE := zunicode

obj-$(CONFIG_ZFS) := $(MODULE).o

ccflags-y := $(ZFS_MODULE_CFLAGS) $(ZFS_MODULE_CPPFLAGS)

$(MODULE)-objs += u8_textprep.o
$(MODULE)-objs += uconv.o
