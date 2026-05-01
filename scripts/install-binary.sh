#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "cornela binary installer: Linux is required" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary="$script_dir/cornela"

if [ ! -f "$binary" ]; then
  echo "cornela binary installer: expected $binary" >&2
  exit 1
fi

prefix="${PREFIX:-/usr/local}"
bin_dir="$prefix/bin"

if [ ! -d "$bin_dir" ]; then
  if [ -w "$(dirname -- "$bin_dir")" ]; then
    mkdir -p "$bin_dir"
  else
    sudo mkdir -p "$bin_dir"
  fi
fi

if [ -w "$bin_dir" ]; then
  install -m 0755 "$binary" "$bin_dir/cornela"
else
  sudo install -m 0755 "$binary" "$bin_dir/cornela"
fi

echo "installed $bin_dir/cornela"
echo "try: sudo $bin_dir/cornela monitor --jsonl --max-events 20"
