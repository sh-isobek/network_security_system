# Watchdog-NetworkSecurityAgent.ps1
#
# Foydalanuvchi so'rovi: "kompyuter perezagruzkadan so'ng agent avtomatik
# ulana olmasa, Dashboard'da qayta ulanishga urinish tugmasi bo'lishi
# kerak". Bu skript aynan shu vazifani bajaradi - har necha daqiqada
# (Scheduled Task orqali, SYSTEM, eng yuqori huquqlar bilan, ASOSIY
# agent xizmatidan MUSTAQIL - xizmat o'zi o'lik bo'lsa ham ishlaydi):
#
#   1) Agent Windows xizmati "Running" holatda emasligini (masalan
#      kompyuter qayta yoqilgandan keyin avtomatik boshlanmagan yoki
#      kutilmagan sababdan to'xtab qolgan) mahalliy tekshiradi va
#      topilsa `Start-Service` bilan qayta ishga tushiradi. Bu qism
#      TARMOQ/SERVERGA UMUMAN BOG'LIQ EMAS - internet/server ishlamasa
#      ham ishlayveradi (eng muhim, asosiy tuzatish).
#
#   2) Markaziy serverdan (best-effort, tarmoq yo'q bo'lsa jim
#      o'tkaziladi) "admin Dashboard'dan qayta ulanish so'radimi"
#      degan bayroqni so'raydi - True bo'lsa, xizmatni HOZIRGI
#      holatidan qat'iy nazar MAJBURIY qayta ishga tushiradi. Bu
#      "xizmat Windows nazarida 'Running', lekin heartbeat thread'i
#      osilib/o'lib qolgan" (zombi) holatni ham qamrab oladi - bu
#      holatni (1)-bo'lim payqay olmaydi, chunki xizmat SCM darajasida
#      hali "ishlayapti" ko'rinadi.
#
# MUHIM (xavfsizlik arxitekturasi - ATAYLAB shunday tanlangan): bu
# skript FAQAT so'rov-javob tarzida ishlaydi (BU KOMPYUTER so'raydi,
# server javob beradi) - server bu kompyuterga hech qachon o'zi
# ulanmaydi yoki buyruq yubormaydi. Shuning uchun bu markazlashtirilgan
# masofaviy buyruq ijrosi (WinRM/PsExec kabi) EMAS - agentning o'zi
# allaqachon ishlatadigan bir xil chiquvchi HTTPS so'rovining davomi,
# xuddi shu autentifikatsiya (per-agent token yoki umumiy bootstrap
# kalit) bilan.

param(
    [string]$ServiceName = "NetworkSecurityEndpointAgent",
    [string]$LogFile = "C:\ProgramData\NetworkSecurityAgent\watchdog.log",
    [string]$TokenFile = "C:\ProgramData\NetworkSecurityAgent\agent_api_token.secret"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Log([string]$m) {
    try {
        $d = Split-Path $LogFile -Parent
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m" | Out-File -FilePath $LogFile -Append -Encoding utf8
    } catch { }
}

# --- 1) Mahalliy xizmat holati tekshiruvi (server bilan aloqa shart emas) ---
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Log "Xizmat topilmadi ($ServiceName) - hech narsa qilinmadi (hali o'rnatilmagan bo'lishi mumkin)"
} elseif ($svc.Status -ne 'Running') {
    Log "Xizmat holati: $($svc.Status) - qayta ishga tushirishga urinilmoqda"
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Log "Muvaffaqiyatli ishga tushirildi"
    } catch {
        Log "Ishga tushirishda xato: $_"
    }
}

# --- 2) Serverdan majburiy-qayta-ishga-tushirish bayrog'i (best-effort) ---
try {
    $ApiServerUrl = [Environment]::GetEnvironmentVariable("API_SERVER_URL", "Machine")
    $ApiKey = [Environment]::GetEnvironmentVariable("AGENT_API_KEY", "Machine")
    if (Test-Path $TokenFile) {
        $tokenValue = (Get-Content $TokenFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($tokenValue) { $ApiKey = $tokenValue }
    }
    if ($ApiServerUrl -and $ApiKey) {
        $body = @{ hostname = $env:COMPUTERNAME } | ConvertTo-Json
        $resp = Invoke-RestMethod -Uri "$ApiServerUrl/api/v1/agent_watchdog_check" -Method Post `
            -Headers @{ "X-API-Key" = $ApiKey } -ContentType "application/json" -Body $body -TimeoutSec 10
        if ($resp.restart_requested) {
            Log "Admin Dashboard'dan qayta ulanish so'ragan - xizmat MAJBURIY qayta ishga tushirilmoqda"
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            Log "Majburiy qayta ishga tushirish bajarildi"
        }
    } else {
        Log "OGOHLANTIRISH: API_SERVER_URL/AGENT_API_KEY topilmadi - server bayrog'i tekshirilmadi (faqat mahalliy holat tekshiruvi bajarildi)"
    }
} catch {
    Log "Server bilan bog'lanib bo'lmadi (bayroq tekshiruvi o'tkazib yuborildi - bu normal, masalan tarmoqdan tashqarida): $_"
}
