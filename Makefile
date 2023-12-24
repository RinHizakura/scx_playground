CLANG ?= clang-17

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

CURDIR := $(abspath .)
SCXDIR := $(abspath ..)
TOOLSDIR := $(abspath ../..)
OUTDIR ?= $(CURDIR)/build
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOL_DIR := $(TOOLSDIR)/bpf/bpftool
APIDIR := $(TOOLSINCDIR)/uapi
OBJ_DIR := $(OUTDIR)/obj
BPFOBJ_DIR := $(OBJ_DIR)/libbpf
BPFTOOLOBJ_DIR := $(OBJ_DIR)/bpftool

BINARY := $(OUTDIR)/sched
BPFOBJ := $(BPFOBJ_DIR)/libbpf.a
BPFTOOL := $(OUTDIR)/sbin/bpftool

GIT_HOOKS := .git/hooks/applied

VMLINUX_BTF := $(abspath ../../../)/vmlinux
VMLINUX_H := vmlinux.h

CFLAGS = -Wall -Wextra -I$(OUTDIR) -I$(SCXDIR)/include -I$(LIBDIR) -I$(dir $(VMLINUX_H))
LDFLAGS =
BPF_CFLAGS = -g -O2 -Wall -D__TARGET_ARCH_$(ARCH) \
	     -Wno-compare-distinct-pointer-types  \
	     -mcpu=v3                             \
	     -I$(SCXDIR)/include -I$(dir $(VMLINUX_H)) -I$(OUTDIR)/include -I$(APIDIR)

CSRCS = $(shell find ./src -name '*.c')

vpath %.c $(sort $(dir $(CSRCS)))

all: $(GIT_HOOKS) $(BINARY)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(OUTDIR) $(BPFOBJ_DIR) $(BPFTOOLOBJ_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(BPFTOOL): | $(BPFTOOLOBJ_DIR)
	$(call msg,BPFTOOL,$@)
	$(MAKE) ARCH= CROSS_COMPILE=                        \
		-C $(BPFTOOL_DIR)                           \
		OUTPUT=$(BPFTOOLOBJ_DIR)/                   \
		LIBBPF_OUTPUT=$(BPFOBJ_DIR)/                \
		LIBBPF_DESTDIR=$(OUTDIR)/                   \
		EXTRA_CFLAGS='-g -O0'                       \
		prefix= DESTDIR=$(OUTDIR)/ install-bin

$(VMLINUX_H): $(VMLINUX_BTF) $(BPFTOOL)
	$(call msg,GEN,,$@)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) | $(BPFOBJ_DIR)
	$(call msg,LIB,$@)
	$(MAKE) -C $(BPFDIR) OUTPUT=$(BPFOBJ_DIR)/                    \
		EXTRA_CFLAGS='-g -O0 -fPIC'                           \
		DESTDIR=$(OUTDIR) prefix= all install_headers

$(OUTDIR)/%.bpf.o: %.bpf.c $(BPFOBJ) $(wildcard %.h) $(VMLINUX_H) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(CLANG) -target bpf $(BPF_CFLAGS)                                \
		-c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

$(OUTDIR)/%.bpf.skel.h: $(OUTDIR)/%.bpf.o $(VMLINUX_H) | $(OUTDIR) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTDIR)/sched.bpf.skel.h: $(OUTDIR)/sched.bpf.o | $(OUTDIR) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

$(patsubst %,%.o,$(BINARY)): %.o: %.bpf.skel.h

$(OUTDIR)/%.o: %.c $(wildcard %.h) | $(OUTDIR)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) -c $(filter %.c,$^) -o $@

$(BINARY): %: %.o $(BPFOBJ) | $(OUTDIR)
	$(call msg,BINARY,$@)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -lelf -lz -o $@

clean:
	$(call msg,CLEAN)
	$(RM) -rf $(OUTDIR) $(VMLINUX_H)

check:
	cd ../../../; vng

.PHONY: all $(BINARY) clean

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.bpf.skel.h, .bpf.o, etc) targets
.SECONDARY:
