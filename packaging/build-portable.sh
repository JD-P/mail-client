#!/bin/bash -p
set -euo pipefail

LC_ALL=C
TZ=UTC
export LC_ALL TZ
unset CDPATH ENV BASH_ENV RUSTFLAGS
umask 022

usage() {
    echo "Usage: $0 [--target TARGET] --target-dir DIR" >&2
    exit 2
}

target=x86_64-unknown-linux-musl
target_dir=
while (($#)); do
    case "$1" in
        --target)
            (($# >= 2)) || usage
            target=$2
            shift 2
            ;;
        --target-dir)
            (($# >= 2)) || usage
            target_dir=$2
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ -n "$target_dir" ]] || usage
[[ "$target" =~ ^[A-Za-z0-9_.-]+$ ]] || {
    echo "portable-build: invalid target: $target" >&2
    exit 1
}
for command in cargo rustc; do
    command -v "$command" >/dev/null || {
        echo "portable-build: missing required command: $command" >&2
        exit 1
    }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
mkdir -p -- "$target_dir"
target_dir=$(cd -- "$target_dir" && pwd -P)

separator=$'\x1f'
encoded_rustflags="--remap-path-prefix=$repo_root=/usr/src/lizard-mail"
encoded_rustflags+="$separator--remap-path-prefix=$target_dir=/usr/src/lizard-mail/target"
encoded_rustflags+="$separator-C${separator}link-arg=-Wl,--build-id=none"
encoded_rustflags+="$separator-C${separator}strip=symbols"
export CARGO_ENCODED_RUSTFLAGS=$encoded_rustflags
export CARGO_INCREMENTAL=0
export LIZARD_MAIL_LIBEXEC_DIR=/usr/libexec/lizard-mail

if [[ "$target" == x86_64-unknown-linux-musl ]]; then
    command -v musl-gcc >/dev/null || {
        echo "portable-build: musl-gcc is required for $target" >&2
        exit 1
    }
    export CC_x86_64_unknown_linux_musl=musl-gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
    prefix_map="-ffile-prefix-map=$repo_root=/usr/src/lizard-mail"
    prefix_map+=" -fdebug-prefix-map=$repo_root=/usr/src/lizard-mail"
    prefix_map+=" -ffile-prefix-map=$target_dir=/usr/src/lizard-mail/target"
    prefix_map+=" -fdebug-prefix-map=$target_dir=/usr/src/lizard-mail/target"
    export CFLAGS_x86_64_unknown_linux_musl=$prefix_map
fi

CARGO_TARGET_DIR="$target_dir" cargo build \
    --manifest-path "$repo_root/Cargo.toml" \
    --locked --release --target "$target" \
    -p lizard-mail-tui \
    -p lizard-mail-backend \
    --bins

for binary in \
    lizard-mail-tui \
    lizard-mail-tui-render-worker \
    lizard-mail-sync-worker \
    lizard-mail-archive-worker
do
    path="$target_dir/$target/release/$binary"
    [[ -f "$path" && -x "$path" ]] || {
        echo "portable-build: expected executable was not produced: $path" >&2
        exit 1
    }
done

printf 'portable-build: wrote binaries to %s\n' "$target_dir/$target/release"
