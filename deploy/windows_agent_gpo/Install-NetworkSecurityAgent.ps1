# Install-NetworkSecurityAgent.ps1
#
# Bitta Windows kompyuterda QO'LDA (yoki test uchun) NetworkSecurityAgent
# .exe'sini o'rnatish uchun. GPO orqali avtomatik tarqatish uchun
# `Deploy-NetworkSecurityAgent.ps1`dan foydalaning (u versiya
# solishtiruvi va SYSVOL bilan ishlaydi) - bu skript esa sodda,
# to'g'ridan-to'g'ri "shu paketni shu kompyuterga o'rnat" vazifasini
# bajaradi.
#
# Ishlatish (Administrator PowerShell'da, paket papkasida turib):
#     .\Install-NetworkSecurityAgent.ps1 -ApiServerUrl "https://172.16.0.5:8443" -ApiKey "sizning-kalitingiz"
#
# MUHIM (yangilandi): -ApiServerUrl/-ApiKey endi IXTIYORIY - agar
# ko'rsatilmasa, skript shu papkadagi `.env` faylidan (`API_SERVER_URL=`
# va `AGENT_API_KEY=` qatorlari) o'qishga urinadi. Bu Deploy-
# NetworkSecurityAgent.ps1 (GPO)dagi bilan bir xil format - shuning
# uchun SYSVOL paket papkasidan shu skript ishlatilayotgan joyga
# `.env`ni ko'chirib qo'ysangiz, parametrlarni har safar qo'lda
# kiritish shart bo'lmaydi. Hech qaysi manbada topilmasa, xato beriladi.
#
# MUHIM: bu skript Administrator huquqi bilan ishga tushirilishi kerak
# (xizmat o'rnatish uchun). Agar PowerShell skript ijrosi bloklangan
# bo'lsa: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

param(
    [string]$ApiServerUrl = "",
    [string]$ApiKey = "",
    [string]$InstallDir = "C:\Program Files\NetworkSecurityAgent",
    [string]$ServiceName = "NetworkSecurityEndpointAgent"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExeSource = Join-Path $ScriptDir "NetworkSecurityAgent.exe"

function Read-DotEnv {
    param([string]$Path)
    $result = @{}
    if (-not (Test-Path $Path)) { return $result }
    foreach ($line in Get-Content $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        $parts = $trimmed.Split("=", 2)
        if ($parts.Count -eq 2) {
            $result[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
    return $result
}

if (-not $ApiServerUrl -or -not $ApiKey) {
    $envValues = Read-DotEnv -Path (Join-Path $ScriptDir ".env")
    if (-not $ApiServerUrl -and $envValues.ContainsKey("API_SERVER_URL")) {
        $ApiServerUrl = $envValues["API_SERVER_URL"]
        Write-Host "API_SERVER_URL '.env' faylidan o'qildi: $ApiServerUrl"
    }
    if (-not $ApiKey -and $envValues.ContainsKey("AGENT_API_KEY")) {
        $ApiKey = $envValues["AGENT_API_KEY"]
        Write-Host "AGENT_API_KEY '.env' faylidan o'qildi"
    }
}

if (-not $ApiServerUrl -or -not $ApiKey) {
    Write-Error "-ApiServerUrl va -ApiKey berilmagan, va shu papkada '.env' faylida ham topilmadi (API_SERVER_URL=... / AGENT_API_KEY=...)."
    exit 1
}

# --- 0) Administrator huquqi tekshiruvi ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Bu skript Administrator huquqi bilan ishga tushirilishi kerak (PowerShell'ni 'Run as Administrator' orqali oching)"
    exit 1
}

# --- 1) .exe fayli mavjudligini tekshirish ---
if (-not (Test-Path $ExeSource)) {
    Write-Error "NetworkSecurityAgent.exe topilmadi: $ExeSource`nBu skript bilan bir papkada bo'lishi kerak (GitHub Actions'dagi release zip'ni to'liq oching)."
    exit 1
}

Write-Host "=== Network Security Endpoint Agent o'rnatilmoqda ===" -ForegroundColor Cyan

# --- 2) Mavjud xizmatni to'g'ri o'chirish (agar qayta o'rnatilayotgan bo'lsa) ---
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Mavjud xizmat topildi - to'xtatilib, olib tashlanmoqda..."
    $existingExe = Join-Path $InstallDir "NetworkSecurityAgent.exe"
    if (Test-Path $existingExe) {
        & $existingExe stop 2>&1 | Out-Null
        & $existingExe remove 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }
}

# --- 3) Fayllarni nusxalash ---
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Copy-Item -Path $ExeSource -Destination $InstallDir -Force
$versionSource = Join-Path $ScriptDir "VERSION"
if (Test-Path $versionSource) {
    Copy-Item -Path $versionSource -Destination $InstallDir -Force
}
Write-Host "Fayllar nusxalandi: $InstallDir"

# --- 4) Muhit o'zgaruvchilarini o'rnatish (agent shu orqali sozlamalarni o'qiydi) ---
[Environment]::SetEnvironmentVariable("API_SERVER_URL", $ApiServerUrl, "Machine")
[Environment]::SetEnvironmentVariable("AGENT_API_KEY", $ApiKey, "Machine")
Write-Host "Muhit o'zgaruvchilari o'rnatildi (API_SERVER_URL, AGENT_API_KEY)"

# --- 5) Xizmat sifatida o'rnatish va ishga tushirish ---
$exePath = Join-Path $InstallDir "NetworkSecurityAgent.exe"
& $exePath install
Start-Service -Name $ServiceName

# --- 6) Tekshirish ---
Start-Sleep -Seconds 2
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "✅ Muvaffaqiyatli o'rnatildi va ishga tushdi: $ServiceName" -ForegroundColor Green
} else {
    Write-Warning "Xizmat o'rnatildi, lekin holati noaniq: $($service.Status). Windows Event Viewer'da (Application log) xatolarni tekshiring."
}
