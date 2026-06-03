.PHONY: all build ebpf clean

# 默认编译所有
all: build

# 编译主程序 + eBPF 字节码
build: ebpf
	cargo build

release: ebpf-release
	cargo build --release

# 编译 eBPF 字节码（使用 bpfel-unknown-none 目标）
ebpf:
	cd ebpf && cargo build --release --target=bpfel-unknown-none

ebpf-release:
	cd ebpf && cargo build --release --target=bpfel-unknown-none

# 将 eBPF 字节码安装到默认路径
install-ebpf: ebpf
	@mkdir -p /etc/dae-rs
	cp ebpf/target/bpfel-unknown-none/release/ebpf /etc/dae-rs/ebpf.o

# 清理
clean:
	cargo clean
	cd ebpf && cargo clean

# 运行（会自动安装 eBPF 字节码）
run: install-ebpf
	cargo run -- $(ARGS)

# 完整构建并运行
.PHONY: run
