#!/usr/bin/env bash
set -euo pipefail

if command -v softhsm2-util >/dev/null 2>&1; then
  echo "SoftHSM2 already installed"
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SoftHSM2 auto-install is currently supported only on Linux." >&2
  echo "Install SoftHSM2 manually and re-run tests." >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not found; cannot auto-install SoftHSM2." >&2
  echo "Install SoftHSM2 manually and re-run tests." >&2
  exit 1
fi

APT_PREFIX=()
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    APT_PREFIX=(sudo)
  else
    echo "Root privileges are required to install SoftHSM2 (sudo not found)." >&2
    exit 1
  fi
fi

echo "Installing SoftHSM2 via apt-get..."
"${APT_PREFIX[@]}" apt-get update
"${APT_PREFIX[@]}" apt-get install -y softhsm2

if ! command -v softhsm2-util >/dev/null 2>&1; then
  echo "SoftHSM2 install completed but softhsm2-util is still unavailable." >&2
  exit 1
fi

echo "SoftHSM2 installation complete"
