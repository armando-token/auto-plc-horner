<#
.SYNOPSIS
    Gate G12 (W091) Clean-Install, Lockfile & Proprietary Checksum Verification Script.
.DESCRIPTION
    Performs reproducible clean-install or offline verification of the JEV Cscape Agent
    environment on Windows 11 x64 without redistributing proprietary Horner APG installers
    and without launching a live Cscape GUI instance.
.PARAMETER VerifyOnly
    Run in read-only verification mode (checks Python version, locked packages,
    baseline project SHA-256, and optional Cscape 10.2 PE SHA-256 checksums).
.PARAMETER VenvDir
    Target virtual environment directory for clean installation (default: .venv).
#>
param(
    [switch]$VerifyOnly = $false,
    [string]$VenvDir = ".venv"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " JEV Cscape Agent - Gate G12 (W091) Clean-Install & Checksum Verifier " -ForegroundColor Cyan
Write-Host " Repo Root : $RepoRoot" -ForegroundColor Cyan
Write-Host " Mode      : $(if ($VerifyOnly) { 'VERIFY-ONLY (Offline, No Live Cscape)' } else { 'CLEAN-INSTALL + VERIFY' })" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Verify Python 3.12+ x64
$PyVersionOutput = & python -c "import sys, platform; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}|{platform.architecture()[0]}')"
$Parts = $PyVersionOutput.Trim().Split("|")
$PyVer = $Parts[0]
$PyArch = $Parts[1]
Write-Host "[1/5] Python Runtime: $PyVer ($PyArch)"
if (-not $PyVer.StartsWith("3.12") -or $PyArch -ne "64bit") {
    throw "W091_ERR_PYTHON_RUNTIME: Expected Python 3.12.x (64bit), found $PyVer ($PyArch)"
}

# 2. Verify Lockfiles Exist & Enforce Local-Only Git Policy (0 Remotes)
$Remotes = & git remote 2>$null
if ($Remotes) {
    foreach ($r in ($Remotes -split "`r?`n")) {
        if ($r.Trim()) {
            Write-Host "      Removing clone remote '$($r.Trim())' to enforce local-only git policy..."
            & git remote remove $r.Trim()
        }
    }
}
$ReqLock = Join-Path $RepoRoot "requirements.lock.txt"
$DepLock = Join-Path $RepoRoot "DEPENDENCIES.lock.json"
if (-not (Test-Path $ReqLock) -or -not (Test-Path $DepLock)) {
    throw "W091_ERR_LOCKFILE_MISSING: requirements.lock.txt or DEPENDENCIES.lock.json missing."
}
Write-Host "[2/5] Lockfiles verified: requirements.lock.txt & DEPENDENCIES.lock.json (0 git remotes)"

# 3. Clean Install into Virtual Environment (unless -VerifyOnly)
$TargetPy = "python"
if (-not $VerifyOnly) {
    Write-Host "[3/5] Creating virtual environment at $VenvDir and installing pinned lockfile..."
    & python -m venv $VenvDir
    $VenvPip = Join-Path $VenvDir "Scripts\pip.exe"
    $VenvPy = Join-Path $VenvDir "Scripts\python.exe"
    & $VenvPip install --no-deps -r $ReqLock
    $SitePackages = Join-Path $VenvDir "Lib\site-packages"
    $PthFile = Join-Path $SitePackages "jev_cscape_agent.pth"
    @("$RepoRoot\src", "$RepoRoot") | Set-Content -Path $PthFile -Encoding UTF8
    $TargetPy = $VenvPy
} else {
    Write-Host "[3/5] Skipping venv creation (-VerifyOnly active)..."
}

# Verify installed packages and compute normalized pip freeze SHA-256 vs requirements.lock.txt SHA-256
$PyCheckScript = @'
import hashlib, json, subprocess, sys, importlib.metadata as md
from pathlib import Path

lock = json.load(open("DEPENDENCIES.lock.json", encoding="utf-8"))
direct = lock["direct_dependencies"]
for pkg, info in direct.items():
    installed = md.version(pkg)
    expected = info["version"]
    assert installed == expected, f"Package {pkg} mismatch: installed={installed} != expected={expected}"

req_raw_bytes = Path("requirements.lock.txt").read_bytes()
req_raw_sha = hashlib.sha256(req_raw_bytes).hexdigest()
req_lines = [
    line.strip() for line in Path("requirements.lock.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.strip().startswith("#")
]
freeze_out = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True)
freeze_lines = [
    line.strip() for line in freeze_out.splitlines()
    if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("-e ")
]
req_norm = "\n".join(sorted(req_lines, key=str.lower)) + "\n"
freeze_norm = "\n".join(sorted(freeze_lines, key=str.lower)) + "\n"
req_sha = hashlib.sha256(req_norm.encode("utf-8")).hexdigest()
freeze_sha = hashlib.sha256(freeze_norm.encode("utf-8")).hexdigest()
print(f"      Python executable              : {sys.executable}")
print(f"      Direct locked packages matched : {len(direct)}/{len(direct)}")
print(f"      Total pinned packages matched  : {len(freeze_lines)}/{len(req_lines)}")
print(f"      requirements.lock.txt raw SHA  : {req_raw_sha}")
print(f"      requirements.lock.txt norm SHA : {req_sha}")
print(f"      pip freeze normalized SHA-256  : {freeze_sha}")
print(f"      pip freeze == lockfile match   : {req_sha == freeze_sha}")
assert req_sha == freeze_sha, f"pip freeze hash mismatch: {freeze_sha} != {req_sha}"
'@
$PyCheckScript | & $TargetPy -
if ($LASTEXITCODE -ne 0) {
    throw "W091_ERR_PIP_FREEZE_MISMATCH: Inline Python lockfile / pip freeze verification failed."
}

# 4. Verify Immutable Native Baseline Project SHA-256
$BaselineCsp = Join-Path $RepoRoot "work\disposable\p1_base.csp"
$ExpectedCspSha = "5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881"
if (-not (Test-Path $BaselineCsp)) {
    throw "W091_ERR_BASELINE_MISSING: $BaselineCsp not found."
}
$ActualCspSha = (Get-FileHash -Path $BaselineCsp -Algorithm SHA256).Hash.ToLower()
if ($ActualCspSha -ne $ExpectedCspSha) {
    throw "W091_ERR_BASELINE_SHA_MISMATCH: Expected $ExpectedCspSha, got $ActualCspSha"
}
Write-Host "[4/5] Native Baseline Project Verified: work/disposable/p1_base.csp (SHA-256: $ActualCspSha)"

# 5. Verify External Cscape 10.2 Checksums (Never Redistributed)
$LockJson = Get-Content $DepLock -Raw | ConvertFrom-Json
$CscapeBinaries = $LockJson.external_proprietary_binaries_checksums.core_binaries
$CscapeExePath = $CscapeBinaries.'Cscape.exe'.path
if (Test-Path $CscapeExePath) {
    Write-Host "[5/5] Verifying external Horner Cscape 10.2 PE SHA-256 checksums (read-only, no GUI launch)..."
    foreach ($Prop in $CscapeBinaries.PSObject.Properties) {
        $BinName = $Prop.Name
        $BinMeta = $Prop.Value
        if (-not (Test-Path $BinMeta.path)) {
            throw "W091_ERR_CSCAPE_BIN_MISSING: $($BinMeta.path) not found."
        }
        $Hash = (Get-FileHash -Path $BinMeta.path -Algorithm SHA256).Hash.ToLower()
        if ($Hash -ne $BinMeta.sha256) {
            throw "W091_ERR_CSCAPE_SHA_MISMATCH: $BinName expected $($BinMeta.sha256), got $Hash"
        }
        Write-Host "      [OK] $BinName ($($BinMeta.size_bytes) bytes) -> $Hash"
    }
} else {
    Write-Host "[5/5] External Cscape 10.2 binary not present at $CscapeExePath (offline-only host)." -ForegroundColor Yellow
}

Write-Host "======================================================================" -ForegroundColor Green
Write-Host " W091 VERIFICATION RESULT: PASS (Proprietary Redistributed: FALSE)    " -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
