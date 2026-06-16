param(
    [switch]$RecreateVenv,
    [switch]$WithOpenSC
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Get-PythonCommand {
    # Prefer the Python launcher on Windows, then fall back to python.
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @("py", "-3")
    }

    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @("python")
    }

    throw "Python 3 is required but was not found. Install Python 3.10+ and retry."
}

function Invoke-Python {
    param(
        [string[]]$PythonCmd,
        [string[]]$Arguments
    )

    if ($PythonCmd.Length -gt 1) {
        & $PythonCmd[0] @($PythonCmd[1..($PythonCmd.Length - 1)]) @Arguments
    }
    else {
        & $PythonCmd[0] @Arguments
    }
}

function Get-UvCommand {
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) {
        return $uv.Path
    }

    return $null
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$uvExe = Get-UvCommand

if (-not $uvExe) {
    Write-Step "uv was not found; attempting install via winget"

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Astral-sh.uv -e --accept-source-agreements --accept-package-agreements | Out-Host
        $uvExe = Get-UvCommand
    }
}

if (-not $uvExe) {
    throw "uv is required but was not found. Install it with 'winget install --id Astral-sh.uv -e' and re-run this script."
}

$venvDir = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

if ($RecreateVenv) {
    if (Test-Path $venvDir) {
        Write-Step "Removing existing virtual environment at .venv"
        Remove-Item -Path $venvDir -Recurse -Force
    }
    else {
        Write-Step "No existing .venv found; continuing with fresh create"
    }
}

if (-not (Test-Path $venvPython)) {
    Write-Step "Creating virtual environment at .venv with uv"
    & $uvExe venv $venvDir
}
else {
    Write-Step "Using existing virtual environment at .venv"
}

Write-Step "Installing editable test dependencies with uv"
& $uvExe pip install --python $venvPython -e ".[test]"

Write-Step "Ensuring pytest and coverage are installed"
& $uvExe pip install --python $venvPython pytest pytest-cov coverage

Write-Step "Attempting to install SoftHSM2 (optional, for hardware token tests)"
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "Chocolatey found; attempting to install SoftHSM2..."
    choco install softhsm2 -y
} else {
    Write-Host "Chocolatey not found. To enable hardware token tests, install SoftHSM2 manually:"
    Write-Host "  1. Download from: https://github.com/opendnssec/SoftHSMv2/releases"
    Write-Host "  2. Or use Chocolatey: choco install softhsm2"
    Write-Host "  3. Or use vcpkg: vcpkg install softhsm2:x64-windows"
}

# Verify SoftHSM2 tools are available
$softHsmFound = $false
if (Get-Command softhsm2-util -ErrorAction SilentlyContinue) {
    Write-Step "SoftHSM2 is available (softhsm2-util found)"
    $softHsmFound = $true
} else {
    Write-Host "Warning: softhsm2-util not found in PATH. Some tests will be skipped."
    Write-Host "  To fix: Add SoftHSM2 to your PATH or reinstall it."
    Write-Host "  Default Windows paths:"
    Write-Host "    - C:\Program Files\SoftHSM2\bin"
    Write-Host "    - C:\Program Files (x86)\SoftHSM2\bin"
}

if ($WithOpenSC) {
    Write-Step "Attempting to install OpenSC (for real hardware token support)"
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "Chocolatey found; attempting to install OpenSC..."
        choco install opensc -y
    } else {
        Write-Host "Chocolatey not found. To enable real hardware token support, install OpenSC manually:"
        Write-Host "  1. Download from: https://github.com/OpenSC/OpenSC/releases"
        Write-Host "  2. Or use Chocolatey: choco install opensc"
    }
    
    if (Get-Command pkcs11-tool -ErrorAction SilentlyContinue) {
        Write-Step "OpenSC is available (pkcs11-tool found)"
    } else {
        Write-Host "Warning: pkcs11-tool not found in PATH. OpenSC may not be properly installed."
        Write-Host "  Default Windows path:"
        Write-Host "    - C:\Program Files\OpenSC Project\OpenSC\bin"
    }
}

Write-Step "Running token provider discovery"
& $venvPython -c "from reticulum_pkcs11_identity import enumerate_token_inventory, format_token_inventory; print(format_token_inventory(enumerate_token_inventory()))"

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Run tests: .venv\Scripts\python.exe -m pytest tests -v"
Write-Host "  2. For real hardware token support (optional), run bootstrap with -WithOpenSC flag"
Write-Host "     .venv\Scripts\python.exe -m pytest tests -v"
Write-Host ""
Write-Host "Optional: To also install OpenSC for real hardware token support, re-run:"
Write-Host "  powershell -File scripts\bootstrap_test_env.ps1 -WithOpenSC"
Write-Host ""
