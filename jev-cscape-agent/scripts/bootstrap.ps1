# scripts/bootstrap.ps1 - Idempotent Bootstrap for JEV Cscape Agent
[CmdletBinding()]
param(
    [switch]$ForceReinstall
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  JEV Cscape Agent: Idempotent Environment Bootstrap" -ForegroundColor Cyan
Write-Host "  Project Root: $ProjectRoot" -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Resolve Python 3.12 (prefer 3.12, fallback to available python)
$PythonCmd = $null
try {
    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $pyCheck = & py.exe -3.12 --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $pyCheck -match "Python 3\.12") {
            $PythonCmd = @("py.exe", "-3.12")
            Write-Host "[OK] Detected Python via py.exe launcher: $pyCheck" -ForegroundColor Green
        }
    }
} catch { }

if (-not $PythonCmd) {
    $systemPy = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($systemPy) {
        $pyVer = & python.exe --version 2>&1
        $PythonCmd = @("python.exe")
        Write-Host "[OK] Using system python: $pyVer" -ForegroundColor Green
    } else {
        Write-Error "[FAIL] No Python executable found in PATH or launcher."
        exit 1
    }
}

# 2. Check / Create Virtual Environment (.venv) with system-site-packages for offline robustness
$VenvDir = Join-Path $ProjectRoot ".venv"
$VenvPy = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPy) -or $ForceReinstall) {
    Write-Host "[*] Creating virtual environment (system-site-packages) at $VenvDir..." -ForegroundColor Yellow
    if (Test-Path $VenvDir) {
        Remove-Item -Path $VenvDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    & $PythonCmd[0] ($PythonCmd[1..($PythonCmd.Length-1)] + @("-m", "venv", "--system-site-packages", $VenvDir))
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[FAIL] Failed to create virtual environment."
        exit 1
    }
    Write-Host "[OK] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[OK] Virtual environment already exists at $VenvDir." -ForegroundColor Green
}

# 3. Verify Required Core Dependencies (offline-safe verification)
Write-Host "[*] Verifying core dependencies in virtual environment..." -ForegroundColor Yellow
$testScript = "import pefile, pydantic, psutil, win32gui, pytest; print('ALL_CORE_DEPS_VERIFIED')"
$depCheck = & $VenvPy -c $testScript 2>&1

if ($LASTEXITCODE -eq 0 -and $depCheck -match "ALL_CORE_DEPS_VERIFIED") {
    Write-Host "[OK] Core dependencies verified (pefile, pydantic, psutil, pywin32, pytest)." -ForegroundColor Green
} else {
    Write-Host "[WARN] Some dependencies missing from site-packages, attempting local pip install..." -ForegroundColor Yellow
    $deps = @("pydantic", "pefile", "psutil", "pywin32", "pytest")
    & $VenvPy -m pip install --no-warn-script-location @deps 2>&1 | Out-Null
    $depCheckRetry = & $VenvPy -c $testScript 2>&1
    if ($depCheckRetry -match "ALL_CORE_DEPS_VERIFIED") {
        Write-Host "[OK] Dependencies installed and verified." -ForegroundColor Green
    } else {
        Write-Warning "[WARN] Dependencies verification: $depCheckRetry"
    }
}

# 4. Verify Local Git Safety Invariants
$gitDir = Join-Path $ProjectRoot ".git"
if (Test-Path $gitDir) {
    $remotes = & git -C $ProjectRoot remote -v 2>&1
    if ($remotes) {
        Write-Warning "[SECURITY WARNING] Git remotes detected! JEV agent policy strictly mandates no-push / local-only tracking."
    } else {
        Write-Host "[OK] Git change tracking initialized with ZERO remote repositories (no push capability)." -ForegroundColor Green
    }
} else {
    Write-Host "[*] Initializing local git repository..." -ForegroundColor Yellow
    & git -C $ProjectRoot init
    & git -C $ProjectRoot config user.name "Armando Silva"
    & git -C $ProjectRoot config user.email "turismo@miwayki.co"
    Write-Host "[OK] Git initialized locally." -ForegroundColor Green
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Bootstrap Complete. Ready to run scripts/doctor.ps1" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
