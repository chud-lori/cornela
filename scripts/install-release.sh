#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "cornela installer: Linux is required" >&2
  exit 1
fi

repo="${CORNELA_REPO:-}"
if [ -z "$repo" ]; then
  echo "cornela installer: set CORNELA_REPO=owner/repo or edit the README install URL after publishing" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64 | amd64)
    arch="x86_64"
    ;;
  aarch64 | arm64)
    arch="aarch64"
    ;;
  *)
    echo "cornela installer: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

version="${CORNELA_VERSION:-latest}"
prefix="${PREFIX:-/usr/local}"

if command -v curl >/dev/null 2>&1; then
  fetch="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  fetch="wget -qO-"
else
  echo "cornela installer: curl or wget is required" >&2
  exit 1
fi

if [ "$version" = "latest" ]; then
  base_url="https://github.com/$repo/releases/latest/download"
else
  base_url="https://github.com/$repo/releases/download/$version"
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

archive="$tmp_dir/cornela.tar.gz"
checksum="$tmp_dir/cornela.tar.gz.sha256"

asset_version=${version#v}
archive_url="$base_url/cornela-$asset_version-$arch-linux.tar.gz"
checksum_url="$archive_url.sha256"

if [ "$version" = "latest" ]; then
  archive_url="$base_url/cornela-latest-$arch-linux.tar.gz"
  checksum_url="$archive_url.sha256"
fi

echo "downloading $archive_url"
$fetch "$archive_url" > "$archive"

if $fetch "$checksum_url" > "$checksum" 2>/dev/null; then
  if command -v sha256sum >/dev/null 2>&1; then
    expected=$(awk '{print $1}' "$checksum")
    actual=$(sha256sum "$archive" | awk '{print $1}')
    if [ "$expected" != "$actual" ]; then
      echo "cornela installer: checksum mismatch" >&2
      exit 1
    fi
  elif command -v shasum >/dev/null 2>&1; then
    expected=$(awk '{print $1}' "$checksum")
    actual=$(shasum -a 256 "$archive" | awk '{print $1}')
    if [ "$expected" != "$actual" ]; then
      echo "cornela installer: checksum mismatch" >&2
      exit 1
    fi
  fi
fi

tar -xzf "$archive" -C "$tmp_dir"
release_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name 'cornela-*-linux' | head -n 1)
if [ -z "$release_dir" ]; then
  echo "cornela installer: release archive layout is invalid" >&2
  exit 1
fi

PREFIX="$prefix" "$release_dir/install.sh"
