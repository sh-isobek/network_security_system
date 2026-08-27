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
    [string]$ServerShare = "",
    [string]$ApiServerUrl = "http://172.16.0.5:8443",
    [string]$InstallDir = "C:\Program Files\NetworkSecurityAgent",
    [string]$ServiceName = "NetworkSecurityEndpointAgent",
    [string]$LogFile = "C:\ProgramData\NetworkSecurityAgent\deploy.log"
)

$ErrorActionPreference = "Stop"

# MUHIM (real production'da aniqlangan xato): $env:USERDNSDOMAIN GPO
# Computer Startup Script SYSTEM kontekstida (foydalanuvchi hali login
# qilmasdan OLDIN, kompyuter yoqilganda) ISHONCHLI EMAS - bo'sh qiymat
# qaytarishi mumkin, chunki bu o'zgaruvchi foydalanuvchi sessiyasiga
# bog'liq, SYSTEM'ning esa "foydalanuvchi sessiyasi" yo'q. Natijada
# $ServerShare "\\\SYSVOL\\scripts\..." kabi buzilgan yo'lga aylanadi.
#
# [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
# kompyuterning AD'dagi domen a'zoligidan TO'G'RIDAN-TO'G'RI o'qiydi -
# foydalanuvchi sessiyasiga bog'liq emas, SYSTEM kontekstida ham
# (login'dan oldin ham) ishonchli ishlaydi.
if (-not $ServerShare) {
    try {
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    } catch {
        # Zaxira: agar domen bilan aloqa vaqtincha yo'q bo'lsa (masalan
        # tarmoq hali to'liq ko'tarilmagan bo'lsa), USERDNSDOMAIN'ga qaytamiz
        $DomainName = $env:USERDNSDOMAIN
    }
    $ServerShare = "\\$DomainName\SYSVOL\$DomainName\scripts\NetworkSecurityAgent"
}

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

# MUHIM (real production'da aniqlangan xato): faqat VERSION faylini
# solishtirish YETARLI EMAS - agar xizmat biror sababdan (masalan
# qo'lda "remove" buyrug'i orqali, yoki muvaffaqiyatsiz avvalgi
# urinishdan keyin) o'chirilgan bo'lsa-yu, VERSION fayli qolib ketgan
# bo'lsa, skript "hammasi joyida" deb noto'g'ri xulosa chiqarib,
# xizmatni HECH QACHON qayta o'rnatmay qo'yardi. Shuning uchun
# xizmatning HAQIQATAN mavjudligini ham tekshiramiz.
$serviceExists = $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)

if ($installedVersion -eq $availableVersion -and $serviceExists) {
    Write-DeployLog "Agent allaqachon eng so'nggi versiyada ($installedVersion) va xizmat mavjud - hech narsa qilinmadi."
    exit 0
}

if ($installedVersion -eq $availableVersion -and -not $serviceExists) {
    Write-DeployLog "OGOHLANTIRISH: versiya bir xil ($installedVersion), lekin XIZMAT MAVJUD EMAS (o'chirilgan yoki hech qachon muvaffaqiyatli o'rnatilmagan) - qayta o'rnatilmoqda."
}

Write-DeployLog "Yangilanish kerak: o'rnatilgan='$installedVersion' -> mavjud='$availableVersion'. O'rnatish boshlanmoqda..."

# --- 2) Mavjud xizmatni to'g'ri o'chirish (raw Stop-Service emas -
#         pywin32 xizmatlari uchun exe'ning o'z 'stop'/'remove'
#         buyruqlari ISHLATILISHI SHART, aks holda pywin32 saqlagan
#         xizmat ro'yxatga olish ma'lumotlari (Python sinf yo'li)
#         "yetim" bo'lib qolib, keyingi 'install' xato beradi) ---
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$exePath = Join-Path $InstallDir "NetworkSecurityAgent.exe"
if ($existingService) {
    Write-DeployLog "Mavjud xizmat to'xtatilmoqda va olib tashlanmoqda..."
    if (Test-Path $exePath) {
        & $exePath stop 2>&1 | Out-Null
        & $exePath remove 2>&1 | Out-Null
    } else {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
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

# --- 4) API sozlamalarini MUHIT O'ZGARUVCHISI sifatida o'rnatish ---
# MUHIM: Python kodi (agent_core/agent.py) API_SERVER_URL va
# AGENT_API_KEY qiymatlarini `os.getenv()` orqali o'qiydi - REGISTRY'DAN
# EMAS. Shuning uchun bu qiymatlar aynan tizim (Machine-scope) muhit
# o'zgaruvchisi sifatida o'rnatilishi SHART, aks holda agent ularni
# hech qachon topmaydi. Machine-scope o'zgaruvchi xizmat ishga
# tushirilganda avtomatik meros olinadi - alohida reboot shart emas,
# lekin xizmatni QAYTA ishga tushirish kerak (buni pastda 6-bosqichda
# qilamiz).
#
# MUHIM (yangilandi): endi SYSVOL'da BITTA `.env` fayli orqali sozlash
# tavsiya etiladi (`API_SERVER_URL=...` va `AGENT_API_KEY=...` qatorlari
# - loyihaning server tomonidagi `.env.example` bilan bir xil, tanish
# format) - bu avvalgi ikkita alohida faylni (`api_server_url.txt` +
# `api_key.secret`) bitta joyga birlashtiradi. ORQAGA MOSLIK: agar
# `.env` topilmasa, eski ikkita fayl hali ham o'qiladi - mavjud SYSVOL
# joylashuvlarini yangilash SHART EMAS.
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

$envFile = Join-Path $ServerShare ".env"
$envValues = Read-DotEnv -Path $envFile
$bootstrapApiKey = $null

if ($envValues.Count -gt 0) {
    Write-DeployLog "'.env' fayli topildi: $envFile"
    if ($envValues.ContainsKey("API_SERVER_URL") -and $envValues["API_SERVER_URL"]) {
        $ApiServerUrl = $envValues["API_SERVER_URL"]
        Write-DeployLog "API_SERVER_URL '.env' faylidan o'qildi: $ApiServerUrl"
    }
    if ($envValues.ContainsKey("AGENT_API_KEY") -and $envValues["AGENT_API_KEY"]) {
        $bootstrapApiKey = $envValues["AGENT_API_KEY"]
    }
} else {
    # Orqaga moslik - eski, alohida fayllar (agar '.env' hali yaratilmagan bo'lsa)
    $serverUrlFile = Join-Path $ServerShare "api_server_url.txt"
    if (Test-Path $serverUrlFile) {
        $configuredUrl = (Get-Content $serverUrlFile -Raw).Trim()
        if ($configuredUrl) {
            $ApiServerUrl = $configuredUrl
            Write-DeployLog "API_SERVER_URL 'api_server_url.txt' faylidan o'qildi (eski format): $ApiServerUrl"
        }
    } else {
        Write-DeployLog "OGOHLANTIRISH: '.env' ham, api_server_url.txt' ham topilmadi - skript standart qiymati ishlatilmoqda: $ApiServerUrl"
    }

    # MUHIM: AGENT_API_KEY qiymati bu skriptda HECH QACHON qattiq
    # kodlanmagan (GPO orqali tarqatiladigan skript domendagi barcha
    # kompyuterlarda o'qilishi mumkin bo'lgani uchun bu jiddiy xavfsizlik
    # xatosi bo'lardi). SYSVOL fayllarining (`.env` yoki `api_key.secret`)
    # ACL'ini cheklash tashkilotingizning AD administratori tomonidan
    # amalga oshirilishi kerak.
    $apiKeyFile = Join-Path $ServerShare "api_key.secret"
    if (Test-Path $apiKeyFile) {
        $bootstrapApiKey = (Get-Content $apiKeyFile -Raw).Trim()
    }
}

[Environment]::SetEnvironmentVariable("API_SERVER_URL", $ApiServerUrl, "Machine")
[Environment]::SetEnvironmentVariable("AGENT_VERSION", $availableVersion, "Machine")

# --- 4.5) Har bir kompyuter uchun ALOHIDA API token (AD auto-enroll) ---
# MUHIM (yangi funksiya): shu paytgacha BARCHA agentlar bitta umumiy
# $bootstrapApiKey'ni ishlatgan (yuqoridagi `.env`/`api_key.secret`dan) -
# agar bu kalit o'g'irlansa/kompaundlansa, HAMMA kompyuter uchun bekor
# qilinishi kerak bo'lardi. Endi birinchi marta ishga tushganda markaziy
# serverdan (`/api/v1/agent_enroll`) shu KOMPYUTERGA ALOHIDA tegishli
# token so'raladi va mahalliy (`$agentTokenFile`) saqlanadi - shundan
# keyin xizmat umumiy bootstrap kalit o'rniga SHU tokenni ishlatadi.
#
# Enroll FAQAT token fayli hali yo'q bo'lsagina chaqiriladi (har
# reboot'da emas) - aks holda har xizmat qayta ishga tushganda oldingi
# token bekor qilinib, keraksiz "churn" yaratilardi (`token_manager.
# enroll_agent_token` bir xil hostname uchun qayta chaqirilsa, eski
# tokenni avtomatik bekor qiladi).
$agentTokenFile = "C:\ProgramData\NetworkSecurityAgent\agent_api_token.secret"
$finalApiKey = $bootstrapApiKey

if (Test-Path $agentTokenFile) {
    $existingAgentToken = (Get-Content $agentTokenFile -Raw).Trim()
    if ($existingAgentToken) {
        $finalApiKey = $existingAgentToken
        Write-DeployLog "Mavjud, shu kompyuterga xos API token ishlatilmoqda ($agentTokenFile)"
    }
} elseif ($bootstrapApiKey) {
    try {
        $body = @{ hostname = $env:COMPUTERNAME } | ConvertTo-Json
        $response = Invoke-RestMethod -Uri "$ApiServerUrl/api/v1/agent_enroll" -Method Post `
            -Headers @{ "X-API-Key" = $bootstrapApiKey } -ContentType "application/json" -Body $body -TimeoutSec 15
        if ($response.token) {
            $tokenDir = Split-Path $agentTokenFile -Parent
            if (-not (Test-Path $tokenDir)) { New-Item -ItemType Directory -Path $tokenDir -Force | Out-Null }
            Set-Content -Path $agentTokenFile -Value $response.token -NoNewline
            $finalApiKey = $response.token
            Write-DeployLog "Yangi, shu kompyuterga xos API token markazdan olindi va saqlandi ($agentTokenFile)"
        }
    } catch {
        # Fail-safe: enroll muvaffaqiyatsiz bo'lsa (masalan tarmoq hali
        # to'liq ko'tarilmagan) - umumiy bootstrap kalit bilan davom
        # etiladi, deploy butunlay to'xtamaydi. Keyingi qayta yoqilishda
        # (token fayli hali yo'q bo'lgani uchun) yana urinib ko'radi.
        Write-DeployLog "OGOHLANTIRISH: agent_enroll muvaffaqiyatsiz bo'ldi ($_) - hozircha umumiy bootstrap kalit bilan davom etilmoqda"
    }
}

if ($finalApiKey) {
    [Environment]::SetEnvironmentVariable("AGENT_API_KEY", $finalApiKey, "Machine")
} else {
    Write-DeployLog "OGOHLANTIRISH: hech qanday API kalit topilmadi ('.env'dagi AGENT_API_KEY, api_key.secret yoki enroll) - agent kalitsiz ishga tushishi mumkin"
}

# --- 5) Windows Service sifatida o'rnatish (exe'ning O'Z 'install'
#         buyrug'i orqali - raw sc.exe EMAS, chunki pywin32 xizmatlari
#         qo'shimcha registry ma'lumotini o'zi yozishi kerak) ---
$pythonExe = Get-Command python.exe -ErrorAction SilentlyContinue
if (Test-Path $exePath) {
    # Asosiy yo'l: mustaqil .exe (Python o'rnatish shart emas)
    #
    # MUHIM (real production'da aniqlangan xato): tashqi dastur (.exe)
    # chaqiruvi PowerShell'ning $ErrorActionPreference'iga BO'YSUNMAYDI -
    # agar `install` buyrug'i ichki xatolik bilan muvaffaqiyatsiz
    # bo'lsa ham, PowerShell buni avtomatik "xato" deb bilmaydi va
    # keyingi qatorga o'tib ketaveradi. Shuning uchun $LASTEXITCODE'ni
    # QO'LDA tekshirish SHART - aks holda "muvaffaqiyat" deb noto'g'ri
    # log yozilib, xizmat aslida umuman ro'yxatga olinmagan holatda
    # qoladi (bu aynan sodir bo'lgan real xato edi).
    # Pywin32/pyinstaller CLI'da option command'dan OLDIN kelishi kerak:
    #   NetworkSecurityAgent.exe --startup auto install
    $installOutput = & $exePath --startup auto install 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-DeployLog "XATOLIK: '$exePath --startup auto install' muvaffaqiyatsiz tugadi (chiqish kodi: $LASTEXITCODE). Natija: $installOutput"
        exit 1
    }
    Write-DeployLog "Xizmat .exe orqali AUTO_START bilan o'rnatildi: $exePath (chiqish: $installOutput)"
} elseif ($pythonExe) {
    # Zaxira yo'l: agar .exe topilmasa, lekin Python o'rnatilgan bo'lsa
    & python.exe "$InstallDir\windows_agent\service_wrapper.py" install
    Write-DeployLog "Xizmat Python orqali o'rnatildi (zaxira yo'l)"
} else {
    Write-DeployLog "XATOLIK: na NetworkSecurityAgent.exe, na Python topilmadi - o'rnatib bo'lmadi"
    exit 1
}

# --- 5.5) Xizmat HAQIQATAN ro'yxatga olinganini tasdiqlash (install
#          buyrug'i "muvaffaqiyatli" ko'rinsa ham, SCM'da yo'q bo'lishi
#          mumkin edi - bu aynan sodir bo'lgan real xato) ---
$registeredService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $registeredService) {
    Write-DeployLog "XATOLIK: 'install' buyrug'i xato bermadi, lekin xizmat SCM'da topilmadi ($ServiceName). Qo'lda tekshiring: & '$exePath' install"
    exit 1
}

# --- 6) Xizmatni ishga tushirish (muhit o'zgaruvchilari yangi
#         jarayonga meros olinishi uchun) ---
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 3
    $runningService = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($runningService.Status -ne 'Running') {
        throw "Xizmat ishga tushdi, lekin holati '$($runningService.Status)' bo'lib qoldi."
    }
} catch {
    Write-DeployLog "XATOLIK: xizmatni ishga tushirib bo'lmadi: $_"
    Write-DeployLog "SCM diagnostikasi: sc.exe query $ServiceName"
    exit 1
}

# --- 7) Versiyani belgilash (keyingi ishga tushishda idempotentlik uchun) ---
Set-Content -Path (Join-Path $InstallDir "VERSION") -Value $availableVersion

Write-DeployLog "✅ Deploy muvaffaqiyatli yakunlandi: versiya $availableVersion"
exit 0
