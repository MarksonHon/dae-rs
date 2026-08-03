#!/bin/bash
# 为 musl 交叉编译构建 libbpf-sys 所需的 glibc 补充库：
#   argp-standalone (argp), musl-fts (fts), musl-obstack (obstack)
# elfutils 的 configure 在 musl 上缺少这些 glibc-only API 会直接报错：
#   - "failed to find argp_parse"
#   - "failed to find fts_close"
#
# 用法: ./scripts/build-musl-deps.sh <zig-target> [prefix]
#   例如: ./scripts/build-musl-deps.sh x86_64-linux-musl
#         ./scripts/build-musl-deps.sh aarch64-linux-musl /tmp/musl-deps
#
# 输出前缀目录（默认 /tmp/dae-rs-musl-deps），随后需将
#   CFLAGS_<target>="-I<prefix>/include -L<prefix>/lib"
# 传给 cargo zigbuild，供 libbpf-sys 的 elfutils configure 找到这些库。
set -euo pipefail

ZIG_TARGET="${1:?usage: $0 <zig-target> e.g. x86_64-linux-musl}"
PREFIX="${2:-/tmp/dae-rs-musl-deps}"

case "$ZIG_TARGET" in
  x86_64-linux-musl)  HOST_TRIPLET="x86_64-unknown-linux-musl" ;;
  aarch64-linux-musl) HOST_TRIPLET="aarch64-unknown-linux-musl" ;;
  *) echo "unsupported zig target: $ZIG_TARGET" >&2; exit 1 ;;
esac

CC="zig cc -target $ZIG_TARGET"
AR="zig ar"
RANLIB="zig ranlib"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$PREFIX/lib" "$PREFIX/include"

echo "==> building argp-standalone for $ZIG_TARGET"
git clone -q --depth 1 https://github.com/argp-standalone/argp-standalone "$WORK/argp-standalone"
cd "$WORK/argp-standalone"
# 等价于其 meson 构建生成的 config.h
cat > config.h <<'EOF'
#ifndef _GNU_SOURCE
# undef _GNU_SOURCE
#endif
#define HAVE_CONFIG_H 1
#define HAVE_UNISTD_H 1
#define HAVE_ALLOCA_H 1
#define HAVE_EX_USAGE 1
#define HAVE_ASPRINTF 1
#define HAVE_STRCHRNUL 1
#define HAVE_STRNDUP 1
#define HAVE_MEMPCPY 1
#define HAVE_DECL_PROGRAM_INVOCATION_NAME 1
#define HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME 1
#define HAVE_DECL_FWRITE_UNLOCKED 0
#define HAVE_DECL_CLEARERR_UNLOCKED 0
#define HAVE_DECL_FEOF_UNLOCKED 0
#define HAVE_DECL_FERROR_UNLOCKED 0
#define HAVE_DECL_FFLUSH_UNLOCKED 0
#define HAVE_DECL_FGETS_UNLOCKED 0
#define HAVE_DECL_FPUTC_UNLOCKED 0
#define HAVE_DECL_FPUTS_UNLOCKED 0
#define HAVE_DECL_FLOCKFILE 1
#define HAVE_DECL_PUTC_UNLOCKED 0
#define HAVE_GCC_ATTRIBUTE 1
#if __GNUC__ && HAVE_GCC_ATTRIBUTE
# define NORETURN __attribute__ ((__noreturn__))
# define PRINTF_STYLE(f, a) __attribute__ ((__format__ (__printf__, f, a)))
# define UNUSED __attribute__ ((__unused__))
#else
# define NORETURN
# define PRINTF_STYLE(f, a)
# define UNUSED
#endif
EOF
for f in argp-ba argp-eexst argp-fmtstream argp-help argp-parse argp-pv argp-pvh; do
  $CC -O2 -std=gnu99 -D_GNU_SOURCE -DHAVE_CONFIG_H=1 -I. -c "$f.c" -o "$f.o"
done
$AR rcs "$PREFIX/lib/libargp.a" argp-*.o
cp argp.h "$PREFIX/include/"

echo "==> building musl-fts for $ZIG_TARGET"
git clone -q --depth 1 https://github.com/pullmoll/musl-fts "$WORK/musl-fts"
cd "$WORK/musl-fts"
./bootstrap.sh >/dev/null
CC="$CC" AR="$AR" RANLIB="$RANLIB" ./configure --host="$HOST_TRIPLET" --prefix="$PREFIX" >/dev/null
make >/dev/null
make install >/dev/null

echo "==> building musl-obstack for $ZIG_TARGET"
git clone -q --depth 1 https://github.com/pullmoll/musl-obstack "$WORK/musl-obstack"
cd "$WORK/musl-obstack"
./bootstrap.sh >/dev/null
CC="$CC" AR="$AR" RANLIB="$RANLIB" ./configure --host="$HOST_TRIPLET" --prefix="$PREFIX" >/dev/null
make >/dev/null
make install >/dev/null

# 只保留静态库：动态 .so 可能在跨架构复用前缀目录时被错误链接
rm -f "$PREFIX"/lib/*.so* "$PREFIX"/lib/*.la

echo "==> done: $PREFIX"
echo "    CFLAGS_${ZIG_TARGET/-/_}=-I${PREFIX}/include -L${PREFIX}/lib"
