# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

# Copyright (c) 2025, Broadcom. All rights reserved. The term Broadcom
# refers to Broadcom Inc. and/or its subsidiaries.

obj-m += rdma_uprot.o

rdma_uprot-objs := \
	uprot.o \
 	uprot_pool.o \
	uprot_verbs.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

