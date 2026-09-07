<#
.SYNOPSIS
    NetworkSecurityAgent - PowerShell PROTOTIPI (Python/.exe/pywin32'siz).

.DESCRIPTION
    Bu - Windows Endpoint Agent'ning (agent_core/agent.py) eng muhim
    zanjirini (fayl paydo bo'lishi -> SHA256 hash -> markaziy serverga
    /api/v1/check_hash so'rovi) FAQAT native PowerShell/.NET vositalari
    bilan, Python/pywin32/PyInstaller zanjiriga umuman muhtoj bo'lmasdan
    qayta yozib ko'rish uchun PROTOTIP.

    Nega: pywin32-asosidagi Windows Service (windows_agent/service_wrapper.py)
    bilan bog'liq muammolar bu loyihada 15 martadan ko'p alohida
    tuzatilgan (SCM Control Dispatcher, ReportServiceStatus, --startup
    auto, log yo'li va h.k. - CLAUDE.md'da hujjatlashtirilgan). Sof
    PowerShell yechimi bu butun muammolar sinfini (va PyInstaller build
    zanjirini) butunlay yo'qotadi.

    HOZIRCHA BU PROTOTIPDA YO'Q (keyingi bosqich, agar prototip ma'qul
    kelsa):
      - Zararli fayl aniqlanganda uni ochiq ushlab turgan jarayonni
        topib o'ldirish (Python versiyadagi process_killer.py
        ekvivalenti - PowerShell'da bu handle.exe (Sysinternals) yoki
        .NET native API (NtQuerySystemInformation) talab qiladi, bu
        yerda ataylab qoldirilgan). Hozircha faqat ALERT log qilinadi.
      - Xavfsiz karantin (copy+verify+delete) - hozircha fayl
        O'CHIRILMAYDI, faqat log qilinadi.
      - Windows Service/Scheduled Task sifatida o'rnatish (installer)
        skripti - bu qo'lda, oldindagi PowerShell konsolida ishga
        tushiriladi (foreground).
      - Bir nechta foydalanuvchi profilini avtomatik aniqlash
        (agent_core'dagi _windows_watch_dirs() kabi) - hozircha faqat
        -WatchDirs orqali ko'rsatilgan papkalar yoki joriy
        foydalanuvchining Downloads/Desktop.
      - /api/v1/agent_heartbeat davriy yuborilishi.

    MUHIM (halol eslatma): bu skript PowerShell mavjud bo'lmagan
    (Linux) muhitda yozilgan - haqiqiy Windows'da hali ISHGA TUSHIRIB
    SINALMAGAN (Zeek/Grafana/boshqa GPO skriptlari kabi holat).
    Production'ga qo'yishdan oldin albatta bitta test kompyuterda
    qo'lda tekshiring.

.PARAMETER ApiServerUrl
    Markaziy server manzili, masalan http://172.16.1.206:8443

.PARAMETER ApiKey
    X-API-Key sarlavhasi uchun token (umumiy AGENT_API_KEY yoki
    /api/v1/agent_enroll orqali olingan shu-kompyuterga xos token).

.PARAMETER WatchDirs
    Kuzatiladigan papkalar ro'yxati. Ko'rsatilmasa, joriy
    foydalanuvchining Downloads va Desktop papkalari ishlatiladi.

.EXAMPLE
    .\Agent.ps1 -ApiServerUrl "http://172.16.1.206:8443" -ApiKey "nssk_..."
#>

param(
    [string]$ApiServerUrl = "",
    [string]$ApiKey = "",
    [string[]]$WatchDirs = @(),
    [string]$LogFile = "$env:ProgramData\NetworkSecurityAgent\agent_ps.log",
    [int]$StabilityCheckIntervalMs = 500,
    [int]$StabilityRounds = 3,
    [int]$StabilityTimeoutSec = 30
)

$ErrorActionPreference = "Stop"

# --- 0) Konfiguratsiya: parametr -> shu papkadagi '.env' -> xato ---
# MUHIM: Deploy-NetworkSecurityAgent.ps1/Install-NetworkSecurityAgent.ps1
# bilan BIR XIL '.env' formatini o'qiydi (API_SERVER_URL=... /
# AGENT_API_KEY=...) - shuning uchun bitta '.env' fayli barcha ishga
# tushirish usullari (Python .exe, PowerShell prototip) uchun ishlaydi.
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

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ApiServerUrl -or -not $ApiKey) {
    $envValues = Read-DotEnv -Path (Join-Path $ScriptDir ".env")
    if (-not $ApiServerUrl -and $envValues.ContainsKey("API_SERVER_URL")) {
        $ApiServerUrl = $envValues["API_SERVER_URL"]
    }
    if (-not $ApiKey -and $envValues.ContainsKey("AGENT_API_KEY")) {
        $ApiKey = $envValues["AGENT_API_KEY"]
    }
}

if (-not $ApiServerUrl -or -not $ApiKey) {
    Write-Error "-ApiServerUrl va -ApiKey berilmagan, va shu papkada '.env' faylida ham topilmadi (API_SERVER_URL=... / AGENT_API_KEY=...)."
    exit 1
}

$LogDir = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-AgentLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp [$Level] $Message"
    Write-Host $line
    $line | Out-File -FilePath $LogFile -Append -Encoding utf8
}

# --- 1) Tarmoq proksisi butunlay o'chiriladi ---
# MUHIM (Python agentda O'N TO'RTINCHI marta topilgan real production
# xatosi bilan BIR XIL turkum - CLAUDE.md'ga qarang): LocalSystem/SYSTEM
# konteksti tizim darajasidagi (masalan Group Policy orqali o'rnatilgan
# yoki noto'g'ri sozlangan WinHTTP) proksi sozlamalarini meros qilib
# olishi mumkin - bu ichki serverga ulanishni ConnectionReset/timeout
# bilan JIM ravishda buzishi mumkin edi. Bizning ichki server bilan
# aloqa hech qachon tashqi proksiga muhtoj emas, shuning uchun uni
# butunlay o'chirib qo'yish xavfsiz va to'g'ri.
[System.Net.WebRequest]::DefaultWebProxy = $null

# --- 2) Kuzatiladigan papkalarni aniqlash ---
if ($WatchDirs.Count -eq 0) {
    $candidates = @(
        (Join-Path $env:USERPROFILE "Downloads"),
        (Join-Path $env:USERPROFILE "Desktop")
    )
    $WatchDirs = $candidates | Where-Object { Test-Path $_ }
}

if ($WatchDirs.Count -eq 0) {
    Write-AgentLog "OGOHLANTIRISH: hech qanday kuzatiladigan papka topilmadi. Chiqilmoqda." "WARN"
    exit 1
}

Write-AgentLog "Kuzatiladigan papkalar: $($WatchDirs -join ', ')"

# --- 3) Hostname/IP (serverga yuborish uchun, faqat ko'rinish/Dashboard
#         "Fayllar" sahifasi maqsadida - tekshiruv natijasiga ta'sir
#         qilmaydi, agent_core/agent.py'dagi bilan bir xil maqsad) ---
$Hostname = $env:COMPUTERNAME
$IpAddress = (
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1 -ExpandProperty IPAddress
)
if (-not $IpAddress) { $IpAddress = "0.0.0.0" }

# --- 4) Fayl "barqarorlashishini" kutish ---
# MUHIM: agent_core/file_monitor.py'dagi _wait_until_stable() bilan
# BIR XIL mantiq (rounds-asosida, timeout-asosida) - katta fayl
# yuklanayotganda hali to'liq yozilmagan faylni hash qilib
# yubormaslik uchun.
function Wait-FileStable {
    param([string]$Path)
    $start = Get-Date
    $stableRounds = 0
    $lastSize = -1

    while (((Get-Date) - $start).TotalSeconds -lt $StabilityTimeoutSec) {
        if (-not (Test-Path $Path)) { return $false }
        try {
            $size = (Get-Item $Path -ErrorAction Stop).Length
        } catch {
            return $false
        }

        if ($size -eq $lastSize -and $size -gt 0) {
            $stableRounds++
            if ($stableRounds -ge $StabilityRounds) {
                return $true
            }
        } else {
            $stableRounds = 0
        }

        $lastSize = $size
        Start-Sleep -Milliseconds $StabilityCheckIntervalMs
    }
    return $false
}

# --- 5) Serverga tekshiruv so'rovi (POST /api/v1/check_hash) ---
function Invoke-CheckHash {
    param([string]$Path)

    if (-not (Test-Path $Path -PathType Leaf)) { return }

    $stable = Wait-FileStable -Path $Path
    if (-not $stable) {
        Write-AgentLog "Fayl barqarorlashmadi (hali yozilmoqda, band yoki o'chirildi) - o'tkazib yuborildi: $Path" "WARN"
        return
    }

    try {
        $sha256 = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    } catch {
        Write-AgentLog "Hash hisoblab bo'lmadi ($Path): $_" "WARN"
        return
    }

    $body = @{
        sha256     = $sha256
        filename   = Split-Path $Path -Leaf
        hostname   = $Hostname
        ip_address = $IpAddress
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri "$ApiServerUrl/api/v1/check_hash" -Method Post `
            -Headers @{ "X-API-Key" = $ApiKey } -ContentType "application/json" -Body $body -TimeoutSec 15
    } catch {
        Write-AgentLog "Serverga so'rov muvaffaqiyatsiz bo'ldi ($Path): $_" "WARN"
        return
    }

    if ($response.malicious) {
        # PROTOTIP CHEKLOVI (yuqoridagi .DESCRIPTION'ga qarang): hozircha
        # faqat OGOHLANTIRISH log qilinadi - jarayonni o'ldirish/faylni
        # o'chirish/karantin HALI QO'SHILMAGAN.
        Write-AgentLog "ZARARLI FAYL ANIQLANDI: $Path (tasdiqlangan=$($response.confirmed), manba=$($response.source), nom=$($response.threat_name)) - PROTOTIP: hech qanday avtomatik chora HALI QO'LLANILMAYDI" "ALERT"
    } else {
        Write-AgentLog "Toza: $Path (sha256=$sha256)"
    }
}

# --- 6) Ishga tushganda serverga ulanishni tekshirish ---
try {
    Invoke-RestMethod -Uri "$ApiServerUrl/api/v1/health" -Method Get -TimeoutSec 10 | Out-Null
    Write-AgentLog "Serverga ulanish tasdiqlandi: $ApiServerUrl"
} catch {
    Write-AgentLog "OGOHLANTIRISH: serverga ulanib bo'lmadi ($ApiServerUrl): $_ - kuzatish baribir boshlanadi" "WARN"
}

# --- 7) FileSystemWatcher'lar (Created/Changed/Deleted hodisalari) ---
# MUHIM: agent_core/file_monitor.py'dagi _NewFileHandler bilan BIR XIL
# "seen" mantig'i - Created VA Changed ikkalasi ham bir xil faylni bir
# necha marta xabar qilishi mumkin (masalan katta fayl yuklanayotganda),
# shuning uchun ConcurrentDictionary orqali "allaqachon navbatga
# qo'yilgan" fayllarni belgilaymiz. Deleted hodisasi "seen"dan olib
# tashlaydi - xuddi shu nom bilan yangi fayl yaratilsa, qayta "yangi"
# deb aniqlanishi uchun (masalan biz uni keyinchalik o'chirsak).
$Queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$Seen = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new()
$SharedState = [PSCustomObject]@{ Queue = $Queue; Seen = $Seen }
$Watchers = @()

foreach ($dir in $WatchDirs) {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $dir
    $watcher.Filter = "*.*"
    $watcher.IncludeSubdirectories = $false
    $watcher.EnableRaisingEvents = $true

    Register-ObjectEvent -InputObject $watcher -EventName Created -MessageData $SharedState -Action {
        $state = $Event.MessageData
        $path = $Event.SourceEventArgs.FullPath
        if ($state.Seen.TryAdd($path, 0)) {
            $state.Queue.Enqueue($path)
        }
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Changed -MessageData $SharedState -Action {
        $state = $Event.MessageData
        $path = $Event.SourceEventArgs.FullPath
        if ($state.Seen.TryAdd($path, 0)) {
            $state.Queue.Enqueue($path)
        }
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Deleted -MessageData $SharedState -Action {
        $state = $Event.MessageData
        $path = $Event.SourceEventArgs.FullPath
        $dummy = [byte]0
        [void]$state.Seen.TryRemove($path, [ref]$dummy)
    } | Out-Null

    $Watchers += $watcher
    Write-AgentLog "Kuzatuv boshlandi: $dir"
}

Write-AgentLog "Agent (PowerShell prototip) ishga tushdi. To'xtatish uchun Ctrl+C."

# --- 8) Asosiy tsikl: navbatdagi fayllarni ketma-ket qayta ishlash ---
try {
    while ($true) {
        $path = $null
        if ($Queue.TryDequeue([ref]$path)) {
            try {
                Invoke-CheckHash -Path $path
            } catch {
                Write-AgentLog "Kutilmagan xato ($path): $_" "WARN"
            }
        } else {
            Start-Sleep -Milliseconds 500
        }
    }
} finally {
    foreach ($w in $Watchers) {
        $w.EnableRaisingEvents = $false
        $w.Dispose()
    }
    Get-EventSubscriber | Unregister-Event
    Write-AgentLog "Agent to'xtatildi."
}
