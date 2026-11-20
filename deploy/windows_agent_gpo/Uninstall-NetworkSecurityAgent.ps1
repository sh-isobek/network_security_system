# Uninstall-NetworkSecurityAgent.ps1
#
# Bitta kompyuterdan Network Security Endpoint Agent'ni TO'LIQ olib tashlaydi.
# KOMPYUTER QAYTA YOQILMAYDI, foydalanuvchi sessiyasi uzilmaydi.
#
# Odatda qo'lda ishlatilmaydi: DC'da Start-AgentRemoval.ps1 SYSVOL'ga UNINSTALL
# belgisini qo'yadi, shundan keyin har kompyuterdagi GPO Startup skripti va
# NSA-Agent-Deploy vazifasi (har 30 daqiqa) Deploy-NetworkSecurityAgent.ps1 orqali
# shu skriptni SYSTEM huquqi bilan ishga tushiradi.
# Qo'lda (Administrator PowerShell):
#     powershell -ExecutionPolicy Bypass -File .\Uninstall-NetworkSecurityAgent.ps1
#
# Nima olib tashlanadi:
#   * NSA-Agent-Watchdog vazifasi (birinchi - xizmatni qayta yoqib yubormasin)
#   * eski "NetworkSecurityAgent Deploy" vazifasi (agar qolgan bo'lsa)
#   * NetworkSecurityEndpointAgent xizmati va uning jarayonlari
#   * C:\Program Files\NetworkSecurityAgent papkasi
#   * tizim muhit o'zgaruvchilari: API_SERVER_URL, AGENT_API_KEY, AGENT_VERSION,
#     AGENT_CA_BUNDLE_FILE
#   * shu kompyuterning API tokeni (agent_api_token.secret)
# Nima QOLADI (ataylab):
#   * C:\ProgramData\NetworkSecurityAgent\Quarantine - karantindagi fayllar; yolg'on-ijobiy
#     bo'lsa qaytarish uchun Restore-Quarantine.ps1 shu papka yoniga ko'chiriladi
#   * jurnallar (*.log) va DC'dagi GPO zaxiralari
#   * NSA-Agent-Deploy vazifasi - u GPO'ga tegishli (GPO o'chirilganda yo'qoladi)
#
# IDEMPOTENT: qayta ishga tushirilsa, o'chiriladigan narsa qolmagan bo'lsa hech narsa
# qilmaydi. Chiqish kodi: 0 - hammasi olib tashlandi, 1 - nimadir qoldi (keyingi
# ishga tushishda yana urinadi).
param(
    [string]$InstallDir = "C:\Program Files\NetworkSecurityAgent",
    [string]$ServiceName = "NetworkSecurityEndpointAgent",
    [string]$DataDir = "C:\ProgramData\NetworkSecurityAgent"
)

# Tashqi buyruqlar (sc.exe, schtasks.exe) stderr'ga yozsa PS 5.1 'Stop' rejimida to'xtab
# qolardi - har qadam natijasini o'zimiz tekshiramiz.
$ErrorActionPreference = "Continue"
$LogFile = Join-Path $DataDir "uninstall.log"
$EnvNames = @("API_SERVER_URL", "AGENT_API_KEY", "AGENT_VERSION", "AGENT_CA_BUNDLE_FILE")
$OwnTasks = @("NSA-Agent-Watchdog", "NetworkSecurityAgent Deploy")
$script:changed = $false

function Log([string]$m) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [Uninstall] $m"
    Write-Host $line
    try {
        if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1MB)) { Move-Item $LogFile "$LogFile.old" -Force }
        $line | Out-File -FilePath $LogFile -Append -Encoding utf8
    } catch { }
}

function Test-Task([string]$name) {
    $null = schtasks.exe /Query /TN $name 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Get-AgentProcesses {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($InstallDir.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) }
}

# Noto'g'ri parametr bilan begona papkani o'chirib yubormaslik uchun
foreach ($p in @($InstallDir, $DataDir)) {
    if (-not $p -or (Split-Path $p -Leaf) -notlike "*NetworkSecurityAgent*") {
        Write-Host "XATO: '$p' agent papkasiga o'xshamaydi (nomida NetworkSecurityAgent bo'lishi kerak) - hech narsa qilinmadi"
        exit 1
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "XATO: Administrator (yoki SYSTEM) huquqi kerak"
    exit 1
}
Set-Location $env:SystemRoot   # o'chiriladigan papka ichida turib qolmaslik uchun

# --- 1) Watchdog va eski vazifalar (xizmatni qayta ishga tushirib yubormasin) ---
foreach ($t in $OwnTasks) {
    if (Test-Task $t) {
        $null = schtasks.exe /End /TN $t 2>&1
        $null = schtasks.exe /Delete /TN $t /F 2>&1
        if (Test-Task $t) { Log "OGOHLANTIRISH: vazifani o'chirib bo'lmadi: $t" } else { Log "Vazifa o'chirildi: $t" }
        $script:changed = $true
    }
}

# --- 2) Xizmat ---
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    $script:changed = $true
    Log "Xizmat to'xtatilmoqda: $ServiceName (holati: $($svc.Status))"
    # Avval avto-ishga tushishni o'chiramiz: o'chirish yarim qolsa ham keyingi yoqilishda qaytmasin
    $null = sc.exe config $ServiceName start= disabled 2>&1
    if ($svc.Status -ne 'Stopped') {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        } catch { Log "Stop-Service: $_" }
    }
    $svcPid = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue).ProcessId
    if ($svcPid -and $svcPid -gt 0) {
        Stop-Process -Id $svcPid -Force -ErrorAction SilentlyContinue
        Log "Xizmat to'xtamadi - jarayon (PID $svcPid) majburan to'xtatildi"
        Start-Sleep -Seconds 2
    }
    # pywin32 xizmati: exe'ning o'z 'remove' buyrug'i (Deploy'dagi kabi), keyin zaxira sc.exe delete
    $exe = Join-Path $InstallDir "NetworkSecurityAgent.exe"
    if (Test-Path $exe) { $null = & $exe remove 2>&1 }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { $null = sc.exe delete $ServiceName 2>&1 }
    for ($i = 0; $i -lt 10 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Log "OGOHLANTIRISH: xizmat hali SCM'da ko'rinadi (o'chirishga belgilangan bo'lishi mumkin - ochiq dastur yopilganda yo'qoladi)"
    } else {
        Log "Xizmat olib tashlandi: $ServiceName"
    }
}

# --- 3) Qolgan agent jarayonlari (PyInstaller bola jarayoni va h.k.) ---
$procs = @(Get-AgentProcesses)
if ($procs.Count -gt 0) {
    $script:changed = $true
    foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
    Log "Agent jarayonlari to'xtatildi: $(($procs | ForEach-Object { "$($_.Name)#$($_.ProcessId)" }) -join ', ')"
    Start-Sleep -Seconds 2
}

# --- 4) Karantin qaytarish skriptini saqlab qolish (dastur papkasi o'chiriladi) ---
$quarantine = Join-Path $DataDir "Quarantine"
$qCount = @(Get-ChildItem -Path $quarantine -Directory -ErrorAction SilentlyContinue).Count
if ($qCount -gt 0) {
    $restoreDst = Join-Path $DataDir "Restore-Quarantine.ps1"
    if (-not (Test-Path $restoreDst)) {
        foreach ($src in @((Join-Path $InstallDir "Restore-Quarantine.ps1"), (Join-Path $PSScriptRoot "Restore-Quarantine.ps1"))) {
            if ($src -and (Test-Path $src)) {
                Copy-Item $src $restoreDst -Force -ErrorAction SilentlyContinue
                Log "Karantinda $qCount ta yozuv qoldi; qaytarish skripti: $restoreDst"
                break
            }
        }
    }
}

# --- 5) Dastur papkasi ---
if (Test-Path $InstallDir) {
    $script:changed = $true
    for ($i = 1; $i -le 5 -and (Test-Path $InstallDir); $i++) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $InstallDir) { Start-Sleep -Seconds 3 }
    }
    if (Test-Path $InstallDir) { Log "OGOHLANTIRISH: papka to'liq o'chmadi (fayl band): $InstallDir - keyingi safar yana urinadi" }
    else { Log "Papka o'chirildi: $InstallDir" }
}

# --- 6) Tizim muhit o'zgaruvchilari ---
foreach ($n in $EnvNames) {
    if ($null -ne [Environment]::GetEnvironmentVariable($n, "Machine")) {
        [Environment]::SetEnvironmentVariable($n, $null, "Machine")
        Log "Muhit o'zgaruvchisi o'chirildi: $n"
        $script:changed = $true
    }
}

# --- 7) Shu kompyuterning maxfiy tokeni ---
foreach ($f in @(Get-ChildItem -Path $DataDir -Filter "*.secret" -File -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
    Log "Maxfiy fayl o'chirildi: $($f.FullName)"
    $script:changed = $true
}

# --- 8) Yakuniy tekshiruv ---
$left = @()
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { $left += "xizmat" }
if (Test-Path $InstallDir) { $left += "papka" }
foreach ($t in $OwnTasks) { if (Test-Task $t) { $left += "vazifa '$t'" } }
foreach ($n in $EnvNames) { if ($null -ne [Environment]::GetEnvironmentVariable($n, "Machine")) { $left += $n } }
if (@(Get-AgentProcesses).Count -gt 0) { $left += "jarayon" }

if ($left.Count -gt 0) {
    Log "QISMAN: qolganlar - $($left -join ', ')"
    exit 1
}
if ($script:changed) { Log "Agent to'liq olib tashlandi ($env:COMPUTERNAME)" }
exit 0
