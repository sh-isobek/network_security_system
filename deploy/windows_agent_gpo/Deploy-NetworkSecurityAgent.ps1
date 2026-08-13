# Deploy-NetworkSecurityAgent.ps1
#
# GPO orqali avtomatik o'rnatish - yangi TZ 6-bo'lim (Windows Agent
# avtomatlashtirilgan tarqatish).
#
# Bu skript Active Directory Group Policy'ning "Computer Configuration
# -> Windows Settings -> Scripts -> Startup" bo'limiga qo'shiladi -
# domenga a'zo har bir kompyuter YOQILGANDA (foydalanuvchi login
# qilishidan OLDIN), SYSTEM huquqi bilan avtomatik ishga tushadi.
#
# MUHIM (halol tushuntirish): bu skript Linux sandbox muhitida ISHGA
# TUSHIRIB SINALMAGAN (PowerShell bu yerda mavjud emas - Zeek/Grafana
# kabi holat). Kod PowerShell sintaksisi va Windows Service/GPO
# konventsiyalariga ehtiyotkorlik bilan mos yozilgan, lekin production'ga
# qo'yishdan oldin bitta test kompyuterda albatta qo'lda sinab ko'ring.
#
# IDEMPOTENT: bu skript har safar kompyuter yoqilganda ishga tushadi
# (GPO Startup Script'ning tabiati shunday) - shuning uchun agent
# ALLAQACHON o'rnatilgan va YANGI bo'lsa, hech narsa qilmasdan chiqadi
# (versiya solishtirish orqali).

param(
    [string]$ServerShare = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\scripts\NetworkSecurityAgent",
    [string]$ApiServerUrl = "https://172.16.0.5:8443",
    [string]$ApiKeyRegistryPath = "HKLM:\SOFTWARE\NetworkSecuritySystem",
    [string]$InstallDir = "C:\Program Files\NetworkSecurityAgent",
    [string]$ServiceName = "NetworkSecurityEndpointAgent",
    [string]$LogFile = "C:\ProgramData\NetworkSecurityAgent\deploy.log"
)

$ErrorActionPreference = "Stop"

function Write-DeployLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    "$timestamp [Deploy-NetworkSecurityAgent] $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

function Get-InstalledVersion {
    # O'rnatilgan agent versiyasini VERSION faylidan o'qiydi (bo'sh
    # bo'lsa, hali o'rnatilmagan deb hisoblanadi)
    $versionFile = Join-Path $InstallDir "VERSION"
    if (Test-Path $versionFile) {
        return (Get-Content $versionFile -Raw).Trim()
    }
    return $null
}

function Get-AvailableVersion {
    # SYSVOL'dagi eng so'nggi versiyani tekshiradi
    $versionFile = Join-Path $ServerShare "VERSION"
    if (Test-Path $versionFile) {
        return (Get-Content $versionFile -Raw).Trim()
    }
    return $null
}

# --- 1) Versiya tekshiruvi (idempotentlik) ---
Write-DeployLog "Deploy skripti ishga tushdi (kompyuter: $env:COMPUTERNAME)"

$installedVersion = Get-InstalledVersion
$availableVersion = Get-AvailableVersion

if ($null -eq $availableVersion) {
    Write-DeployLog "OGOHLANTIRISH: $ServerShare\VERSION topilmadi - SYSVOL ulanishi yoki agent paketi sozlanmagan bo'lishi mumkin. Chiqilmoqda."
    exit 0
}

if ($installedVersion -eq $availableVersion) {
    Write-DeployLog "Agent allaqachon eng so'nggi versiyada ($installedVersion) - hech narsa qilinmadi."
    exit 0
}

Write-DeployLog "Yangilanish kerak: o'rnatilgan='$installedVersion' -> mavjud='$availableVersion'. O'rnatish boshlanmoqda..."

# --- 2) Mavjud xizmatni to'xtatish (agar bor bo'lsa) ---
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -eq "Running") {
    Write-DeployLog "Mavjud xizmat to'xtatilmoqda..."
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
}

# --- 3) Fayllarni SYSVOL'dan nusxalash ---
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

try {
    # -Exclude orqali eski konfiguratsiya fayllarini saqlab qolamiz
    # (agar mahalliy sozlash bo'lsa, ustidan yozilmasin)
    Copy-Item -Path "$ServerShare\*" -Destination $InstallDir -Recurse -Force `
        -Exclude @("*.local.cfg")
    Write-DeployLog "Fayllar nusxalandi: $ServerShare -> $InstallDir"
} catch {
    Write-DeployLog "XATOLIK: fayllarni nusxalashda muvaffaqiyatsizlik: $_"
    exit 1
}

# --- 4) API kalitini xavfsiz saqlash (registry, ochiq matn fayl emas) ---
if (-not (Test-Path $ApiKeyRegistryPath)) {
    New-Item -Path $ApiKeyRegistryPath -Force | Out-Null
}
Set-ItemProperty -Path $ApiKeyRegistryPath -Name "ApiServerUrl" -Value $ApiServerUrl

# MUHIM: AGENT_API_KEY qiymati bu skriptda HECH QACHON qattiq
# kodlanmagan (GPO orqali tarqatiladigan skript domendagi barcha
# kompyuterlarda o'qilishi mumkin bo'lgani uchun bu jiddiy xavfsizlik
# xatosi bo'lardi). Kalit alohida, cheklangan ACL bilan himoyalangan
# GPO Preference (Registry item) orqali yoki alohida, faqat
# kompyuter hisobiga o'qish huquqi berilgan SYSVOL faylidan olinishi
# kerak - buni tashkilotingizning AD administratori sozlashi kerak.
$apiKeyFile = Join-Path $ServerShare "api_key.secret"
if (Test-Path $apiKeyFile) {
    $apiKey = (Get-Content $apiKeyFile -Raw).Trim()
    Set-ItemProperty -Path $ApiKeyRegistryPath -Name "ApiKey" -Value $apiKey
} else {
    Write-DeployLog "OGOHLANTIRISH: api_key.secret topilmadi - agent kalitsiz ishga tushishi mumkin"
}

# --- 5) Windows Service sifatida o'rnatish/qayta o'rnatish ---
$pythonExe = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pythonExe) {
    # Python o'rnatilgan holat
    if ($existingService) {
        & python.exe "$InstallDir\windows_agent\service_wrapper.py" remove
    }
    & python.exe "$InstallDir\windows_agent\service_wrapper.py" install
    & python.exe "$InstallDir\windows_agent\service_wrapper.py" start
} elseif (Test-Path "$InstallDir\NetworkSecurityAgent.exe") {
    # PyInstaller bilan quril
    if (-not $existingService) {
        & sc.exe create $ServiceName binPath= "`"$InstallDir\NetworkSecurityAgent.exe`"" start= auto
    }
    & sc.exe start $ServiceName
} else {
    Write-DeployLog "XATOLIK: na Python, na NetworkSecurityAgent.exe topilmadi - o'rnatib bo'lmadi"
    exit 1
}

# --- 6) Versiyani belgilash (keyingi ishga tushishda idempotentlik uchun) ---
Set-Content -Path (Join-Path $InstallDir "VERSION") -Value $availableVersion

Write-DeployLog "✅ Deploy muvaffaqiyatli yakunlandi: versiya $availableVersion"
exit 0
