# CI (windows-latest, Windows PowerShell 5.1, Administrator): agentni markaziy o'chirish
# (Start-AgentRemoval.ps1 -> SYSVOL UNINSTALL belgisi -> Deploy -> Uninstall) HAQIQIY
# pywin32 xizmati, haqiqiy Scheduled Task va Machine muhit o'zgaruvchilari bilan sinaladi.
param(
    [Parameter(Mandatory = $true)][string]$Exe,       # dist\NetworkSecurityAgent.exe
    [Parameter(Mandatory = $true)][string]$GpoDir     # deploy\windows_agent_gpo
)
$ErrorActionPreference = "Continue"
$failed = 0
function Check([string]$name, [bool]$cond) {
    if ($cond) { Write-Host "OK   $name" } else { Write-Host "FAIL $name"; $script:failed++ }
}
$svcName = "NetworkSecurityEndpointAgent"
$installDir = "C:\Program Files\NetworkSecurityAgent"
$dataDir = "C:\ProgramData\NetworkSecurityAgent"
$envNames = @("API_SERVER_URL", "AGENT_API_KEY", "AGENT_VERSION", "AGENT_CA_BUNDLE_FILE")
function TaskExists([string]$n) { $null = schtasks.exe /Query /TN $n 2>&1; return ($LASTEXITCODE -eq 0) }
function MachineEnv([string]$n) { [Environment]::GetEnvironmentVariable($n, "Machine") }
function RunPs([string]$file, [string[]]$extra) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file @extra | Out-Host
    return $LASTEXITCODE
}
function AgentProcs {
    @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith("$installDir\", [StringComparison]::OrdinalIgnoreCase) })
}
function Assert-Removed([string]$label) {
    Check "$label - xizmat yo'q" ($null -eq (Get-Service -Name $svcName -ErrorAction SilentlyContinue))
    Check "$label - watchdog vazifasi yo'q" (-not (TaskExists "NSA-Agent-Watchdog"))
    Check "$label - dastur papkasi yo'q" (-not (Test-Path $installDir))
    Check "$label - agent jarayonlari yo'q" ((AgentProcs).Count -eq 0)
    foreach ($n in $envNames) { Check "$label - $n o'chirilgan" ($null -eq (MachineEnv $n)) }
}

# --- SYSVOL o'rnida vaqtinchalik paket papkasi (haqiqiy release paketi tarkibi) ---
$share = Join-Path $env:RUNNER_TEMP "sysvol\scripts\NetworkSecurityAgent"
New-Item -ItemType Directory -Force -Path $share | Out-Null
Copy-Item $Exe $share
Copy-Item "windows_agent\VERSION" $share
# Hozirgi production SYSVOL holati: Uninstall va Restore-Quarantine hali yo'q - ularni Start-AgentRemoval qo'yadi
foreach ($f in "Deploy-NetworkSecurityAgent.ps1", "Watchdog-NetworkSecurityAgent.ps1", "AgentTls.ps1", "agent-ca.crt") {
    Copy-Item (Join-Path $GpoDir $f) $share
}
# Server yo'q (o'chirilgan holat): ulanishlar darhol rad etiladi
Set-Content -Path (Join-Path $share ".env") -Value "API_SERVER_URL=http://127.0.0.1:9`r`nAGENT_API_KEY=ci-test-key`r`nAGENT_API_TLS_PORT=9" -Encoding ASCII
$deploy = Join-Path $share "Deploy-NetworkSecurityAgent.ps1"

# --- 1) Odatdagi o'rnatish ---
$rc = RunPs $deploy @("-ServerShare", $share)
Check "Deploy o'rnatdi (exit $rc)" ($rc -eq 0)
Check "xizmat Running" ((Get-Service -Name $svcName -ErrorAction SilentlyContinue).Status -eq "Running")
Check "watchdog vazifasi bor" (TaskExists "NSA-Agent-Watchdog")
Check "API_SERVER_URL o'rnatilgan" ($null -ne (MachineEnv "API_SERVER_URL"))

# token va karantin yozuvi (agent ishlagan kompyuter holati)
Set-Content -Path (Join-Path $dataDir "agent_api_token.secret") -Value "ci-token" -NoNewline
$q = Join-Path $dataDir "Quarantine\ci0001"
New-Item -ItemType Directory -Force -Path $q | Out-Null
Set-Content -Path (Join-Path $q "metadata.json") -Value '{"filename":"x.exe","original_path":"C:\\x.exe","sha256":"00","threat_name":"ci"}'

# --- 2) DC skripti: DryRun hech narsa yozmaydi ---
$removal = Join-Path $GpoDir "Start-AgentRemoval.ps1"
$rc = RunPs $removal @("-SysvolDir", $share, "-SkipLocal", "-DryRun")
Check "Start-AgentRemoval -DryRun (exit $rc)" ($rc -eq 0)
Check "DryRun belgi yaratmadi" (-not (Test-Path (Join-Path $share "UNINSTALL")))
Check "DryRun Uninstall skriptini nusxalamadi" (-not (Test-Path (Join-Path $share "Uninstall-NetworkSecurityAgent.ps1")))

# --- 3) DC skripti: o'chirishni yoqish ---
$rc = RunPs $removal @("-SysvolDir", $share, "-SkipLocal")
Check "Start-AgentRemoval (exit $rc)" ($rc -eq 0)
Check "UNINSTALL belgisi SYSVOL'da" (Test-Path (Join-Path $share "UNINSTALL"))
Check "Uninstall skripti SYSVOL'da" (Test-Path (Join-Path $share "Uninstall-NetworkSecurityAgent.ps1"))
Check "eski Deploy zaxiralangan" (@(Get-ChildItem "$dataDir\removal-backup\*\Deploy-NetworkSecurityAgent.ps1" -ErrorAction SilentlyContinue).Count -ge 1)
Check "-SkipLocal: agent hali ishlayapti" ($null -ne (Get-Service -Name $svcName -ErrorAction SilentlyContinue))

# --- 4) Kompyuterdagi vazifa Deploy'ni ishga tushiradi -> agent olib tashlanadi ---
$rc = RunPs $deploy @("-ServerShare", $share)
Check "Deploy (UNINSTALL belgisi bilan) exit $rc" ($rc -eq 0)
Assert-Removed "belgi orqali"
Check "token o'chirilgan" (-not (Test-Path (Join-Path $dataDir "agent_api_token.secret")))
Check "karantin saqlangan" (Test-Path (Join-Path $q "metadata.json"))
Check "Restore-Quarantine.ps1 saqlangan" (Test-Path (Join-Path $dataDir "Restore-Quarantine.ps1"))
Check "uninstall.log yozilgan" (Select-String -Path (Join-Path $dataDir "uninstall.log") -Pattern "to'liq olib tashlandi" -SimpleMatch -Quiet)

# --- 5) Takroriy ishga tushirish: hech narsa qilmaydi, jurnalni to'ldirmaydi ---
$before = (Get-Content (Join-Path $dataDir "uninstall.log")).Count
$rc = RunPs $deploy @("-ServerShare", $share)
Check "takroriy Deploy exit $rc" ($rc -eq 0)
Check "takroriy Deploy uninstall.log'ga yozmadi" ((Get-Content (Join-Path $dataDir "uninstall.log")).Count -eq $before)
$rc = RunPs (Join-Path $share "Uninstall-NetworkSecurityAgent.ps1") @()
Check "takroriy Uninstall exit $rc" ($rc -eq 0)

# --- 6) Bekor qilish: belgi olinadi -> agent qayta o'rnatiladi ---
$rc = RunPs $removal @("-SysvolDir", $share, "-Undo")
Check "Start-AgentRemoval -Undo (exit $rc)" ($rc -eq 0)
Check "-Undo belgini olib tashladi" (-not (Test-Path (Join-Path $share "UNINSTALL")))
$rc = RunPs $deploy @("-ServerShare", $share)
Check "Undo'dan keyin Deploy qayta o'rnatdi (exit $rc)" ($rc -eq 0)
Check "qayta o'rnatilgan xizmat Running" ((Get-Service -Name $svcName -ErrorAction SilentlyContinue).Status -eq "Running")
Check "Uninstall skripti kompyuterda ham bor (qo'lda o'chirish uchun)" (Test-Path "$installDir\Uninstall-NetworkSecurityAgent.ps1")

# --- 7) Qo'lda (to'g'ridan-to'g'ri) Uninstall ---
$rc = RunPs (Join-Path $share "Uninstall-NetworkSecurityAgent.ps1") @()
Check "qo'lda Uninstall exit $rc" ($rc -eq 0)
Assert-Removed "qo'lda"

# --- 8) Noto'g'ri papka parametri - hech narsa o'chirilmaydi ---
$rc = RunPs (Join-Path $share "Uninstall-NetworkSecurityAgent.ps1") @("-InstallDir", "C:\Program Files")
Check "begona papka rad etildi (exit $rc)" ($rc -eq 1 -and (Test-Path "C:\Program Files"))

Get-Content (Join-Path $dataDir "uninstall.log") -ErrorAction SilentlyContinue | Write-Host
if ($failed -gt 0) { Write-Host "$failed ta tekshiruv muvaffaqiyatsiz"; exit 1 }
Write-Host "Barcha agent o'chirish tekshiruvlari o'tdi"
