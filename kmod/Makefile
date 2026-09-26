ifneq ($(KERNELRELEASE),)
obj-m += sysmon.o
sysmon-y := main.o sysmon_probes.o log.o match.o block.o off.o ioctl.o
ccflags-y += -I$(src)/../include
else
KDIR ?= /lib/modules/$(shell uname -r)/build
.PHONY: all clean
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
endif
