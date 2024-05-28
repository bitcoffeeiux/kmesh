# Copyright 2024 The Kmesh Authors.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation
#

obj-m := kmesh_workload.o
kmesh_workload-objs = workload_main.o migration.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ccflags-y += -Wno-discarded-qualifiers

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

install:
	install -dp -m 0500 /lib/modules/kmesh
	install -Dp -m 0400 kmesh_workload.ko /lib/modules/kmesh
	ln -sf /lib/modules/kmesh/kmesh_workload.ko /lib/modules/`uname -r`
	depmod -a

uninstall:
	rm -rf /lib/modules/`uname -r`/kmesh_workload.ko
	rm -rf /lib/modules/kmesh
	depmod -a

clean:
	@rm -rf *.o *.mod *.mod.c *.mod.o *.ko *.order *.symvers .*.cmd
