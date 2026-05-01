#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "cornela package: Linux is required so the embedded eBPF object matches the target platform" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cornela package: cargo is required to build the release binary" >&2
  exit 1
fi

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_dir/Cargo.toml" | head -n 1)
arch=$(uname -m)
name="cornela-$version-$arch-linux"
dist_dir="$repo_dir/dist"
stage_dir="$dist_dir/$name"

cd "$repo_dir"
cargo build --release

rm -rf "$stage_dir"
mkdir -p "$stage_dir/scripts"
install -m 0755 target/release/cornela "$stage_dir/cornela"
install -m 0644 README.md "$stage_dir/README.md"
install -m 0644 handover.md "$stage_dir/handover.md"
install -m 0644 scripts/safe_trigger_afalg_splice.py "$stage_dir/scripts/safe_trigger_afalg_splice.py"

tar -C "$dist_dir" -czf "$dist_dir/$name.tar.gz" "$name"
echo "wrote $dist_dir/$name.tar.gz"
