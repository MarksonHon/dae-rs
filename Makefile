.PHONY: all build ebpf release clean run submodule

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CFLAGS := -O2 -Wall -Werror -target bpf -g $(CFLAGS)
MAX_MATCH_SET_LEN ?= 1024
CFLAGS := -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(CFLAGS)

# eBPF C source path
EBPF_KERN_DIR := bpf/kern
EBPF_HEADERS := $(EBPF_KERN_DIR)/headers

all: build

# Initialize Git submodules (ensures bpf/kern/headers exists)
submodule:
	git submodule update --init --recursive

# Compile the C eBPF code → ebpf.o
# Compile tproxy.c into BPF bytecode with clang (keeping debug info)
ebpf: submodule
	$(CLANG) $(CFLAGS) \
		-I $(EBPF_HEADERS) \
		-I $(EBPF_KERN_DIR) \
		-c $(EBPF_KERN_DIR)/tproxy.c \
		-o ebpf.o
	@echo "eBPF bytecode compiled: ebpf.o"

# debug build (keeps debug info)
build: ebpf
	cargo build

# release build (strip debug info from the compiled eBPF, then run a release build)
release: ebpf
	$(LLVM_STRIP) -g ebpf.o
	@echo "eBPF bytecode stripped for release build"
	cargo build --release

clean:
	cargo clean
	rm -f ebpf.o
	rm -f bpf/kern/tproxy.o

run: build
	cargo run -- $(ARGS)
