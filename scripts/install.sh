#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "cornela installer: Linux is required for the release binary build" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cornela installer: cargo is required to build the release binary" >&2
  exit 1
fi

if ! command -v clang >/dev/null 2>&1; then
  echo "cornela installer: clang is required to compile the embedded eBPF program" >&2
  exit 1
fi

prefix="${PREFIX:-/usr/local}"
bin_dir="$prefix/bin"
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$repo_dir"
cargo build --release

if [ ! -d "$bin_dir" ]; then
  if [ -w "$(dirname -- "$bin_dir")" ]; then
    mkdir -p "$bin_dir"
  else
    sudo mkdir -p "$bin_dir"
  fi
fi

if [ -w "$bin_dir" ]; then
  install -m 0755 target/release/cornela "$bin_dir/cornela"
else
  sudo install -m 0755 target/release/cornela "$bin_dir/cornela"
fi

echo "installed $bin_dir/cornela"
echo "try: sudo $bin_dir/cornela monitor --jsonl --max-events 20"
