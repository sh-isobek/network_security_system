# Watchdog-NetworkSecurityAgent.ps1
#
# Foydalanuvchi so'rovi: Dashboard'da "Qayta ulanishga urinish" bosilganda o'sha qurilmada
# agentni qayta ishga tushirish skripti ishga tushsin; 1 daqiqa ichida ulana olmasa xabar
# berilsin. Bu skript aynan shu vazifani bajaradi - har daqiqada (Scheduled Task, SYSTEM,
# eng yuqori huquqlar, ASOSIY agent xizmatidan MUSTAQIL - xizmat o'lik bo'lsa ham ishlaydi):
#
#   1) Agent Windows xizmati "Running" emasligini (masalan qayta yoqilgandan keyin
#      avtomatik boshlanmagan yoki to'xtab qolgan) MAHALLIY tekshiradi va ishga tushiradi.
#      Bu qism tarmoq/serverga BOG'LIQ EMAS.
#
#   2) Bir daqiqa ichida ~20 soniya oralig'ida (3 marta) serverdan "admin Dashboard'dan
#      qayta ulanish so'radimi" deb so'raydi. So'ralgan bo'lsa xizmatni MAJBURIY qayta
#      ishga tushiradi (Stop -> kerak bo'lsa jarayonni o'ldirish -> Start; xizmat Windows
#      nazarida "Running" bo'lsa-da heartbeat'i osilib qolgan holatni ham qamraydi) va
#      natijani serverga xabar qiladi (/api/v1/agent_watchdog_report). Server heartbeat
#      kelishini kutadi; 60s ichida kelmasa Dashboard'da sabab ko'rsatiladi va Alert
#      (Telegram/Email) yaratiladi.
#
# MUHIM (xavfsizlik): skript FAQAT so'rov-javob tarzida ishlaydi (BU KOMPYUTER so'raydi) -
# server bu kompyuterga hech qachon o'zi ulanmaydi/buyruq yubormaydi. Agentning o'zi
# ishlatadigan bir xil chiquvchi HTTP so'rovi, xuddi shu autentifikatsiya bilan.

param(
    [string]$ServiceName = "NetworkSecurityEndpointAgent",
    [string]$LogFile = "C:\ProgramData\NetworkSecurityAgent\watchdog.log",
    [string]$TokenFile = "C:\ProgramData\NetworkSecurityAgent\agent_api_token.secret",
    [int]$Polls = 3,
    [int]$PollIntervalSeconds = 20
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Log([string]$m) {
    try {
        $d = Split-Path $LogFile -Parent
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 2MB)) {
            Move-Item $LogFile "$LogFile.old" -Force
        }
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m" | Out-File -FilePath $LogFile -Append -Encoding utf8
    } catch { }
}

# --- 1) Mahalliy xizmat holati (server bilan aloqa shart emas) ---
function Ensure-ServiceRunning {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { Log "Xizmat topilmadi ($ServiceName) - hali o'rnatilmagan bo'lishi mumkin"; return }
    if ($svc.Status -eq 'Running') { return }
    Log "Xizmat holati: $($svc.Status) - ishga tushirilmoqda"
    try {
        $cfg = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($cfg -and $cfg.StartMode -eq 'Disabled') {
            Set-Service -Name $ServiceName -StartupType Automatic
            Log "Xizmat 'Disabled' edi - 'Automatic'ga o'zgartirildi"
        }
        Start-Service -Name $ServiceName -ErrorAction Stop
        Log "Muvaffaqiyatli ishga tushirildi"
    } catch { Log "Ishga tushirishda xato: $_" }
}

# --- Majburiy qayta ishga tushirish: natija (success, message) qaytaradi ---
function Invoke-ForcedRestart {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return @{ success = $false; message = "Xizmat ($ServiceName) o'rnatilmagan" } }
    try {
        if ($svc.Status -ne 'Stopped') {
            try {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
            } catch {
                # Xizmat to'xtamayapti (osilib qolgan) - jarayonni majburan o'ldiramiz
                $procId = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").ProcessId
                if ($procId -and $procId -gt 0) {
                    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                    Log "Xizmat to'xtamadi - jarayon (PID $procId) majburan o'ldirildi"
                    Start-Sleep -Seconds 3
                }
            }
        }
        $cfg = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($cfg -and $cfg.StartMode -eq 'Disabled') { Set-Service -Name $ServiceName -StartupType Automatic }
        Start-Service -Name $ServiceName -ErrorAction Stop
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
        $final = (Get-Service -Name $ServiceName).Status
        if ($final -eq 'Running') { return @{ success = $true; message = "Xizmat qayta ishga tushirildi (Running)" } }
        return @{ success = $false; message = "Xizmat holati '$final' (Running emas)" }
    } catch {
        return @{ success = $false; message = "$_" }
    }
}

# --- Server bilan aloqa yordamchilari ---
function Get-ApiConfig {
    $url = [Environment]::GetEnvironmentVariable("API_SERVER_URL", "Machine")
    $key = [Environment]::GetEnvironmentVariable("AGENT_API_KEY", "Machine")
    if (Test-Path $TokenFile) {
        $t = (Get-Content $TokenFile -Raw -ErrorAction SilentlyContinue)
        if ($t -and $t.Trim()) { $key = $t.Trim() }
    }
    return @{ url = $url; key = $key }
}

function Get-Identity {
    # Dashboard'da bir kompyuter turli hostname bilan bir necha qator bo'lishi mumkin -
    # server kompyuterni nomi, MAC va IP bo'yicha taniydi.
    $ips = @(); $macs = @()
    try {
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            ForEach-Object { $_.IPAddress })
        $macs = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object { $_.MacAddress })
    } catch { }
    return @{ hostname = $env:COMPUTERNAME; ips = $ips; macs = $macs }
}

function Invoke-Api([string]$Path, $Body, $Cfg) {
    Invoke-RestMethod -Uri "$($Cfg.url)/api/v1/$Path" -Method Post -Headers @{ "X-API-Key" = $Cfg.key } `
        -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 4) -TimeoutSec 10
}

Ensure-ServiceRunning

$cfg = Get-ApiConfig
if (-not $cfg.url -or -not $cfg.key) {
    Log "OGOHLANTIRISH: API_SERVER_URL/AGENT_API_KEY topilmadi - server so'rovi o'tkazib yuborildi (faqat mahalliy tekshiruv)"
    exit 0
}
$identity = Get-Identity

$errLogged = $false
for ($i = 1; $i -le $Polls; $i++) {
    try {
        $resp = Invoke-Api "agent_watchdog_check" $identity $cfg
        if ($resp.restart_requested) {
            Log "Admin Dashboard'dan qayta ulanish so'ragan - xizmat MAJBURIY qayta ishga tushirilmoqda"
            $result = Invoke-ForcedRestart
            Log "Natija: success=$($result.success) - $($result.message)"
            $report = @{ hostname = $identity.hostname; ips = $identity.ips; macs = $identity.macs;
                         success = [bool]$result.success; message = [string]$result.message }
            try { Invoke-Api "agent_watchdog_report" $report $cfg | Out-Null }
            catch { Log "Natijani serverga yuborib bo'lmadi: $_" }
        }
    } catch {
        if (-not $errLogged) {
            Log "Server bilan bog'lanib bo'lmadi (bu normal - masalan tarmoqdan tashqarida): $_"
            $errLogged = $true
        }
    }
    if ($i -lt $Polls) { Start-Sleep -Seconds $PollIntervalSeconds }
}
