#!/usr/bin/env bash
set -euo pipefail

RECREATE_VENV=false
WITH_OPENSC=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --recreate-venv)
      RECREATE_VENV=true
      shift
      ;;
    --with-opensc)
      WITH_OPENSC=true
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

function write_step() {
  echo "==> $1"
}

function get_python_command() {
  if command -v python3 >/dev/null 2>&1; then
    echo "python3"
  else
    echo "Python 3 is required but was not found. Install Python 3.10+ and retry." >&2
    exit 1
  fi
}

function get_uv_command() {
  if command -v uv >/dev/null 2>&1; then
    echo "uv"
  fi
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

UV_EXE=$(get_uv_command)

if [[ -z "$UV_EXE" ]]; then
  write_step "uv was not found; install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

VENV_DIR="$REPO_ROOT/.venv"
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"

if [[ "$RECREATE_VENV" == "true" ]]; then
  if [[ -d "$VENV_DIR" ]]; then
    write_step "Removing existing virtual environment at .venv"
    rm -rf "$VENV_DIR"
  else
    write_step "No existing .venv found; continuing with fresh create"
  fi
fi

if [[ ! -x "$VENV_PYTHON" ]]; then
  write_step "Creating virtual environment at .venv with uv"
  "$UV_EXE" venv "$VENV_DIR"
else
  write_step "Using existing virtual environment at .venv"
fi

write_step "Installing editable test dependencies with uv"
"$UV_EXE" pip install --python "$VENV_PYTHON" -e ".[test]"

write_step "Ensuring pytest and coverage are installed"
"$UV_EXE" pip install --python "$VENV_PYTHON" pytest pytest-cov coverage

write_step "Attempting to install system test dependencies (SoftHSM2)"
if bash "$REPO_ROOT/scripts/install_test_deps.sh"; then
  write_step "System test dependencies installed successfully"
else
  write_step "Note: System test dependencies installation failed or SoftHSM2 is already installed"
fi

# Verify SoftHSM2 tools are available
if command -v softhsm2-util >/dev/null 2>&1; then
  write_step "SoftHSM2 is available (softhsm2-util found)"
  
  # Check for libsofthsm2.so as well
  SOFTHSM_LIB=""
  for lib_path in /usr/lib/softhsm /usr/lib/x86_64-linux-gnu/softhsm /usr/local/lib/softhsm /usr/lib64/softhsm /opt/softhsm/lib; do
    if [[ -f "$lib_path/libsofthsm2.so" ]]; then
      SOFTHSM_LIB="$lib_path/libsofthsm2.so"
      break
    fi
  done
  
  if [[ -n "$SOFTHSM_LIB" ]]; then
    write_step "SoftHSM2 library found: $SOFTHSM_LIB"
  else
    echo "Warning: softhsm2-util found but libsofthsm2.so not found in standard locations."
    echo "  Set SOFTHSM2_MODULE environment variable to the full path to libsofthsm2.so"
  fi
else
  echo "Warning: softhsm2-util not found in PATH. Some tests will be skipped."
  echo "  To enable PKCS#11 tests, install SoftHSM2:"
  echo "    - Debian/Ubuntu: sudo apt-get install softhsm2"
  echo "    - macOS: brew install softhsm"
  echo "    - Fedora/RHEL: sudo dnf install softhsm"
  echo "    - Or download: https://github.com/opendnssec/SoftHSMv2/releases"
fi

if [[ "$WITH_OPENSC" == "true" ]]; then
  write_step "Attempting to install OpenSC (for real hardware token support)"
  
  if command -v apt-get >/dev/null 2>&1; then
    APT_PREFIX=()
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      if command -v sudo >/dev/null 2>&1; then
        APT_PREFIX=(sudo)
      fi
    fi
    if [[ ${#APT_PREFIX[@]} -gt 0 ]] || [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      echo "Installing OpenSC via apt-get..."
      "${APT_PREFIX[@]}" apt-get update
      "${APT_PREFIX[@]}" apt-get install -y opensc
    fi
  elif command -v brew >/dev/null 2>&1; then
    echo "Installing OpenSC via brew..."
    brew install opensc
  else
    echo "Could not auto-install OpenSC. Install manually from:"
    echo "  https://github.com/OpenSC/OpenSC/releases"
  fi
  
  if command -v pkcs11-tool >/dev/null 2>&1; then
    write_step "OpenSC is available (pkcs11-tool found)"
  else
    echo "Warning: pkcs11-tool not found in PATH. OpenSC may not be properly installed."
  fi
fi

write_step "Running token provider discovery"
"$VENV_PYTHON" -c "from reticulum_pkcs11_identity import enumerate_token_inventory, format_token_inventory; print(format_token_inventory(enumerate_token_inventory()))"

echo ""
echo "Bootstrap complete."
echo ""
echo "Next steps:"
echo "  1. Run tests: .venv/bin/python -m pytest tests -v"
echo "  2. For real hardware token support (optional), re-run with --with-opensc:"
echo "     bash scripts/bootstrap_test_env.sh --with-opensc"
echo ""
