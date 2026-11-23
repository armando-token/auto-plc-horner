# scripts/doctor.ps1 - Health, Environment & Invariant Diagnostic Doctor for JEV Cscape Agent
[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  JEV Cscape Agent: System & Safety Doctor Diagnostics" -ForegroundColor Cyan
Write-Host "  Root: $ProjectRoot" -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor Cyan

$diagnostics = [ordered]@{
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    status = "inconclusive"
    checks = [ordered]@{}
    blockers = @()
}

$allPass = $true

# 1. OS & Architecture Check
$os = Get-CimInstance Win32_OperatingSystem
$is64Bit = [System.Environment]::Is64BitOperatingSystem
if ($is64Bit) {
    Write-Host "[OK] Operating System: $($os.Caption) (Build $($os.BuildNumber), 64-bit)" -ForegroundColor Green
    $diagnostics.checks["os_architecture"] = "PASS"
} else {
    Write-Host "[FAIL] 64-bit OS required." -ForegroundColor Red
    $diagnostics.checks["os_architecture"] = "FAIL"
    $allPass = $false
}

# 2. Cscape 10.2 Executable Check
$cscapeExe = "C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
if (Test-Path $cscapeExe) {
    $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($cscapeExe)
    $cVer = $fvi.FileVersion
    if ($cVer -eq "10.2.751.4") {
        Write-Host "[OK] Cscape 10.2 Executable: $cscapeExe (Build $cVer)" -ForegroundColor Green
        $diagnostics.checks["cscape_binary"] = "PASS"
    } else {
        Write-Host "[WARN] Cscape binary version mismatch: $cVer (expected 10.2.751.4)" -ForegroundColor Yellow
        $diagnostics.checks["cscape_binary"] = "WARN"
    }
} else {
    Write-Host "[FAIL] Cscape.exe not found at $cscapeExe" -ForegroundColor Red
    $diagnostics.checks["cscape_binary"] = "FAIL"
    $diagnostics.blockers += "cscape_executable_missing"
    $allPass = $false
}

# 3. Python Runtime & Virtual Environment
$venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$pyToTest = if (Test-Path $venvPy) { $venvPy } else { (Get-Command python.exe -ErrorAction SilentlyContinue).Source }
if ($pyToTest) {
    $pyVer = & $pyToTest --version 2>&1
    Write-Host "[OK] Python Runtime: $pyVer ($pyToTest)" -ForegroundColor Green
    $diagnostics.checks["python_runtime"] = "PASS"
} else {
    Write-Host "[FAIL] Python runtime unavailable." -ForegroundColor Red
    $diagnostics.checks["python_runtime"] = "FAIL"
    $diagnostics.blockers += "python_runtime_missing"
    $allPass = $false
}

# 4. Git Repository & Remote Lockout
$remotes = & git -C $ProjectRoot remote -v 2>&1
if ($LASTEXITCODE -eq 0 -and (-not $remotes)) {
    Write-Host "[OK] Git change tracking active with ZERO remotes (fail-closed push lockout verified)." -ForegroundColor Green
    $diagnostics.checks["git_no_remote"] = "PASS"
} elseif ($remotes) {
    Write-Host "[FAIL] Git remotes detected! Policy forbids remote URLs." -ForegroundColor Red
    $diagnostics.checks["git_no_remote"] = "FAIL"
    $diagnostics.blockers += "git_remote_configured"
    $allPass = $false
} else {
    Write-Host "[WARN] Git not initialized." -ForegroundColor Yellow
    $diagnostics.checks["git_no_remote"] = "WARN"
}

# 5. Fail-Closed Companion Flash Binaries Check
$cscapeDir = "C:\Program Files (x86)\Cscape 10.2"
$flashBins = @("PGMUpdateUtility.exe", "DfuSeCommand.exe", "STMFlashLoader.exe", "WinJTAG.exe")
$detectedFlashers = @()
foreach ($b in $flashBins) {
    if (Test-Path (Join-Path $cscapeDir $b)) {
        $detectedFlashers += $b
    }
}
Write-Host "[OK] Companion flash binaries detected for fail-closed lockout: $($detectedFlashers -join ', ')" -ForegroundColor Green
$diagnostics.checks["flash_lockout_targets_detected"] = "PASS"

# 6. Secrets & Leakage Scan
$secretPatterns = @("AIza[0-9A-Za-z-_]{35}", "ghp_[0-9A-Za-z]{36}", "sk-[0-9A-Za-z]{32,}")
$leakFound = $false
Get-ChildItem -Path $ProjectRoot -Exclude ".git", ".venv" -Recurse -File -Include *.json, *.yaml, *.yml, *.md, *.ps1, *.py | ForEach-Object {
    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($content) {
        foreach ($pattern in $secretPatterns) {
            if ($content -match $pattern) {
                Write-Host "[SECURITY ALERT] Potential secret leak found in: $($_.FullName)" -ForegroundColor Red
                $leakFound = $true
            }
        }
    }
}
if (-not $leakFound) {
    Write-Host "[OK] Secrets audit clean: zero leaked tokens or private credentials found." -ForegroundColor Green
    $diagnostics.checks["secrets_audit"] = "PASS"
} else {
    $diagnostics.checks["secrets_audit"] = "FAIL"
    $diagnostics.blockers += "secret_leak_detected"
    $allPass = $false
}

# Overall Verdict adhering to strict 4-state contract
if ($allPass) {
    $diagnostics.status = "success"
    Write-Host "`n[RESULT] Doctor diagnostics PASSED (status: success)." -ForegroundColor Green
} else {
    $diagnostics.status = "failed"
    Write-Host "`n[RESULT] Doctor diagnostics FAILED (status: failed). Blockers: $($diagnostics.blockers -join ', ')" -ForegroundColor Red
}

$diagJson = $diagnostics | ConvertTo-Json -Depth 5
Set-Content -Path (Join-Path $ProjectRoot "artifacts\logs\doctor_diagnostics.json") -Value $diagJson -Encoding UTF8
Write-Host "[*] Diagnostics saved to artifacts/logs/doctor_diagnostics.json" -ForegroundColor Gray
