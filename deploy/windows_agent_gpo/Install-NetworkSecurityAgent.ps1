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
#     .\Install-NetworkSecurityAgent.ps1 -ApiServerUrl "http://172.16.0.5:8443" -ApiKey "sizning-kalitingiz"
#
# MUHIM: bu skript Administrator huquqi bilan ishga tushirilishi kerak
# (xizmat o'rnatish uchun). Agar PowerShell skript ijrosi bloklangan
# bo'lsa: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiServerUrl,

    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    [string]$InstallDir = "C:\Program Files\NetworkSecurityAgent",
    [string]$ServiceName = "NetworkSecurityEndpointAgent"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExeSource = Join-Path $ScriptDir "NetworkSecurityAgent.exe"

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
