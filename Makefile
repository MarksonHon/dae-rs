.PHONY: all build ebpf release clean run submodule

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CFLAGS := -O2 -Wall -Werror -target bpf -g $(CFLAGS)
MAX_MATCH_SET_LEN ?= 1024
CFLAGS := -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(CFLAGS)

# eBPF C 源码路径
EBPF_KERN_DIR := bpf/kern
EBPF_HEADERS := $(EBPF_KERN_DIR)/headers

all: build

# 初始化 Git 子模块（确保 bpf/kern/headers 存在）
submodule:
	git submodule update --init --recursive

# 编译 C eBPF 代码 → ebpf.o
# 使用 clang 编译 tproxy.c 为 BPF 字节码（保留 debug 信息）
ebpf: submodule
	$(CLANG) $(CFLAGS) \
		-I $(EBPF_HEADERS) \
		-I $(EBPF_KERN_DIR) \
		-c $(EBPF_KERN_DIR)/tproxy.c \
		-o ebpf.o
	@echo "eBPF bytecode compiled: ebpf.o"

# debug 构建（保留 debug 信息）
build: ebpf
	cargo build

# release 构建（编译 eBPF 后剥离 debug 信息，再执行 release 构建）
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
