
CC=gcc
CLANG=clang

LIBFABRIC=../libfabric
LF_HDRS=-I$(LIBFABRIC) -I$(LIBFABRIC)/include
LF_LIBS=-L$(LIBFABRIC)/src/.libs -lfabric

LF_LOCAL_HDRS=-I./libfabric_headers -I./libfabric_headers/include

INCS=-I. -I./util -I./nic_shim -I./crypto
CFLAGS=-Wall \
       -Wno-unused-variable \
       -Wno-implicit-function-declaration \
       -Wno-int-conversion \
       -Wno-address-of-packed-member
LDFLAGS=

HDRS=$(wildcard *.h util/*.h nic_shim/*.h crypto/*.h)

# Shared library
LIBNAME=uet
LIB=lib$(LIBNAME).so
LIB_SRC=$(filter-out uet.c, \
	$(filter-out $(wildcard nic_shim/*xdp*), \
		     $(wildcard *.c \
				util/*.c \
				nic_shim/*.c \
				crypto/*.c)))
LIB_OBJ_DIR=obj_lib
LIB_OBJ=$(patsubst %.c, $(LIB_OBJ_DIR)/%.o, $(LIB_SRC))

# Main executable
BIN=uet
MAIN_SRC=uet.c
OBJ_DIR=obj
MAIN_OBJ=$(OBJ_DIR)/uet.o

# XDP shared library
XDP_LIBNAME=xdpuet
XDP_LIB=lib$(XDP_LIBNAME).so
XDP_LIB_SRC=$(filter-out uet.c, \
	    $(filter-out nic_shim/*xdp_kern*, \
			 $(wildcard *.c \
				    util/*.c \
				    nic_shim/*.c \
				    crypto/*.c)))
XDP_LIB_OBJ_DIR=obj_xdp_lib
XDP_LIB_OBJ=$(patsubst %.c, $(XDP_LIB_OBJ_DIR)/%.o, $(XDP_LIB_SRC))

# XDP executable
XDP_BIN=uet_xdp
XDP_MAIN_SRC=uet.c
XDP_OBJ_DIR=obj_xdp
XDP_MAIN_OBJ=$(XDP_OBJ_DIR)/uet.o
XDP_KERN_SRC=$(wildcard nic_shim/*xdp_kern*)
XDP_KERN_BIN=uet_xdp_kern.o

xdp: CFLAGS+=-DENABLE_XDP -DXDP_PROG=$(XDP_KERN_BIN)
xdp: LDFLAGS+=-lpthread -lbpf -lxdp

CC_SIM_BIN=uet_cc_sim
CC_SIM_SRC=$(wildcard cc/*.c cc_sim/*.c)
CC_SIM_OBJ_DIR=obj_cc_sim
CC_SIM_OBJ=$(patsubst %.c, $(CC_SIM_OBJ_DIR)/%.o, $(CC_SIM_SRC))

# Default target
all: $(BIN)

# XDP target
xdp: $(XDP_BIN) $(XDP_KERN_BIN)

# CC sim target
cc_sim: $(CC_SIM_BIN)

# Shared library object files (compiled with -fPIC)
$(LIB_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(LIB_OBJ_DIR)/$(dir $<)
	@echo 'Building library object: $<'
	@$(CC) $(CFLAGS) $(INCS) $(LF_LOCAL_HDRS) -fPIC -c -o $@ $<

# Shared library
$(LIB): $(LIB_OBJ)
	@echo 'Building shared library: $@'
	@$(CC) -shared $(LIB_OBJ) -o $@ $(LDFLAGS)

# XDP shared library object files (compiled with -fPIC) (w/ extra CFLAGS)
$(XDP_LIB_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(XDP_LIB_OBJ_DIR)/$(dir $<)
	@echo 'Building XDP library object: $<'
	@$(CC) $(CFLAGS) $(INCS) $(LF_LOCAL_HDRS) -fPIC -c -o $@ $<

# XDP shared library (w/ extra LDFLAGS)
$(XDP_LIB): $(XDP_LIB_OBJ)
	@echo 'Building XDP shared library: $@'
	@$(CC) -shared $(XDP_LIB_OBJ) -o $@ $(LDFLAGS)

# Main executable object file
$(OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(OBJ_DIR)/$(dir $<)
	@echo 'Building file: $<'
	@$(CC) $(CFLAGS) $(INCS) $(LF_HDRS) -c -o $@ $<

# Main executable (links against shared library)
$(BIN): $(LIB) $(MAIN_OBJ)
	@echo 'Building program: $@'
	@$(CC) $(MAIN_OBJ) -o $@ -L. -l$(LIBNAME) $(LDFLAGS) $(LF_LIBS)

# XDP executable object file (w/ extra CFLAGS)
$(XDP_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(XDP_OBJ_DIR)/$(dir $<)
	@echo 'Building XDP file: $<'
	@$(CC) $(CFLAGS) $(INCS) $(LF_HDRS) -c -o $@ $<

# XDP executable (links against XDP shared library) (w/ extra LDFLAGS)
$(XDP_BIN): $(XDP_LIB) $(XDP_MAIN_OBJ)
	@echo 'Building XDP program: $@'
	@$(CC) $(XDP_MAIN_OBJ) -o $@ -L. -l$(XDP_LIBNAME) $(LDFLAGS) $(LF_LIBS)

$(XDP_KERN_BIN): $(XDP_KERN_SRC)
	@echo 'Building XDP kernel program: $@'
	@$(CLANG) -O2 -g -Wall -target bpf \
		  -I/usr/include/$(shell uname -m)-linux-gnu \
		  -c -o $(XDP_KERN_BIN) $(XDP_KERN_SRC)

$(CC_SIM_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(CC_SIM_OBJ_DIR)/$(dir $<)
	@echo 'Building file: $<'
	@$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

$(CC_SIM_BIN): $(CC_SIM_OBJ)
	@echo 'Building program: $@'
	@$(CC) $(CC_SIM_OBJ) -o $@ $(LDFLAGS)

clean:
	@rm -rf $(LIB_OBJ_DIR) $(LIB) \
		$(OBJ_DIR) $(BIN) \
		$(XDP_LIB_OBJ_DIR) $(XDP_LIB) \
		$(XDP_OBJ_DIR) $(XDP_BIN) \
		$(XDP_KERN_BIN) \
		$(CC_SIM_OBJ_DIR) $(CC_SIM_BIN)

.PHONY: all xdp cc_sim clean

