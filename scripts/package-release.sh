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
latest_name="cornela-latest-$arch-linux"
dist_dir="$repo_dir/dist"
stage_dir="$dist_dir/$name"

cd "$repo_dir"
cargo build --release

rm -rf "$stage_dir"
mkdir -p "$stage_dir/scripts"
install -m 0755 target/release/cornela "$stage_dir/cornela"
install -m 0755 scripts/install-binary.sh "$stage_dir/install.sh"
install -m 0644 scripts/safe_trigger_afalg_splice.py "$stage_dir/scripts/safe_trigger_afalg_splice.py"
install -m 0644 scripts/demo_copy_fail_signals.py "$stage_dir/scripts/demo_copy_fail_signals.py"

tar -C "$dist_dir" -czf "$dist_dir/$name.tar.gz" "$name"
cp "$dist_dir/$name.tar.gz" "$dist_dir/$latest_name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$dist_dir/$name.tar.gz" > "$dist_dir/$name.tar.gz.sha256"
  sha256sum "$dist_dir/$latest_name.tar.gz" > "$dist_dir/$latest_name.tar.gz.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$dist_dir/$name.tar.gz" > "$dist_dir/$name.tar.gz.sha256"
  shasum -a 256 "$dist_dir/$latest_name.tar.gz" > "$dist_dir/$latest_name.tar.gz.sha256"
fi
echo "wrote $dist_dir/$name.tar.gz"
echo "wrote $dist_dir/$latest_name.tar.gz"
