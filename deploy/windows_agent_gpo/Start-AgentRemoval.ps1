# Start-AgentRemoval.ps1
#
# DC'da ADMIN sifatida BIR MARTA ishga tushiriladi: domendagi BARCHA kompyuterlardan
# Network Security Endpoint Agent'ni olib tashlashni yoqadi. KOMPYUTERLAR QAYTA YOQILMAYDI.
#
# Qanday ishlaydi: SYSVOL'dagi agent paket papkasiga Uninstall-NetworkSecurityAgent.ps1,
# yangilangan Deploy-NetworkSecurityAgent.ps1 va UNINSTALL belgi faylini qo'yadi. Har
# kompyuterda allaqachon ishlab turgan NSA-Agent-Deploy vazifasi (har 30 daqiqa) va GPO
# Startup skripti Deploy'ni ishga tushiradi - Deploy belgini ko'rib, agentni O'RNATISH
# o'rniga OLIB TASHLAYDI. Onlayn kompyuterlar ~35 daqiqa ichida, o'chiq turganlari
# keyingi yoqilishida tozalanadi. Natija har kompyuterda:
#     C:\ProgramData\NetworkSecurityAgent\uninstall.log
#
# Ishlatish (DC'da, Administrator PowerShell, shu skript turgan papkada
# Uninstall-NetworkSecurityAgent.ps1 va Deploy-NetworkSecurityAgent.ps1 ham bo'lishi kerak):
#     .\Start-AgentRemoval.ps1 -DryRun     # nima qilinishini ko'rsatadi, hech narsa yozmaydi
#     .\Start-AgentRemoval.ps1             # o'chirishni yoqadi (+ shu DC'ning o'z agentini darhol o'chiradi)
#     .\Start-AgentRemoval.ps1 -Undo       # bekor qiladi: agentlar keyingi safar qayta o'rnatiladi
#
# Barcha kompyuterlar tozalangach (masalan 1-2 haftadan keyin) GPO'ni butunlay olib
# tashlash mumkin: .\Publish-AgentDeployGpoTask.ps1 -Remove, keyin GPO'dagi Startup
# skriptini o'chirish yoki GPO bog'lanishini (link) uzish.
param(
    [string]$SysvolDir = "",    # bo'sh bo'lsa ...\SYSVOL\sysvol\<domen>\scripts\NetworkSecurityAgent avto-topiladi
    [switch]$Undo,
    [switch]$SkipLocal,         # shu kompyuterning o'z agentini darhol o'chirmaslik
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$LogFile = "C:\ProgramData\NetworkSecurityAgent\agent-removal.log"
$AutoUpdateTask = "NSA-Agent-AutoUpdate"

function Log([string]$m) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"
    Write-Host $line
    try {
        $d = Split-Path $LogFile -Parent
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        $line | Out-File -FilePath $LogFile -Append -Encoding utf8
    } catch { }
}

function Set-AutoUpdateTask([bool]$enabled) {
    $ErrorActionPreference = "Continue"
    $null = schtasks.exe /Query /TN $AutoUpdateTask 2>&1
    if ($LASTEXITCODE -ne 0) { return }
    $flag = if ($enabled) { "/Enable" } else { "/Disable" }
    if ($DryRun) { Log "DRY-RUN: schtasks /Change /TN $AutoUpdateTask $flag"; return }
    $null = schtasks.exe /Change /TN $AutoUpdateTask $flag 2>&1
    if ($LASTEXITCODE -eq 0) { Log "$AutoUpdateTask vazifasi: $flag" }
    else { Log "OGOHLANTIRISH: $AutoUpdateTask vazifasini o'zgartirib bo'lmadi ($flag)" }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "XATO: PowerShell'ni 'Run as Administrator' orqali oching"
    exit 1
}

# --- 1) SYSVOL'dagi agent paket papkasi (kompyuterlar Deploy'ni aynan shu yerdan oladi) ---
if (-not $SysvolDir) {
    $hits = @(Get-ChildItem -Path (Join-Path $env:SystemRoot "SYSVOL\sysvol\*\scripts\NetworkSecurityAgent\VERSION") -ErrorAction SilentlyContinue)
    if ($hits.Count -ne 1) {
        Write-Host "XATO: SYSVOL'da agent papkasi aniq topilmadi ($($hits.Count) ta). -SysvolDir bilan ko'rsating, masalan:"
        Write-Host "  .\Start-AgentRemoval.ps1 -SysvolDir 'C:\Windows\SYSVOL\sysvol\<domen>\scripts\NetworkSecurityAgent'"
        exit 1
    }
    $SysvolDir = $hits[0].DirectoryName
}
if (-not (Test-Path (Join-Path $SysvolDir "Deploy-NetworkSecurityAgent.ps1"))) {
    Write-Host "XATO: $SysvolDir ichida Deploy-NetworkSecurityAgent.ps1 yo'q - bu agent paket papkasi emas"
    exit 1
}
$marker = Join-Path $SysvolDir "UNINSTALL"
Log "=== Start-AgentRemoval (Undo=$Undo, DryRun=$DryRun) SYSVOL papka: $SysvolDir ==="

# --- Bekor qilish ---
if ($Undo) {
    if (Test-Path $marker) {
        if ($DryRun) { Log "DRY-RUN: o'chiriladi: $marker" }
        else { Remove-Item -LiteralPath $marker -Force; Log "UNINSTALL belgisi olib tashlandi - agentlar keyingi Deploy'da (<=35 daqiqa yoki yoqilganda) qayta o'rnatiladi" }
    } else {
        Log "UNINSTALL belgisi yo'q edi - o'zgarish yo'q"
    }
    Set-AutoUpdateTask $true
    exit 0
}

# --- 2) Manba fayllar (shu skript yonida) ---
$srcUninstall = Join-Path $PSScriptRoot "Uninstall-NetworkSecurityAgent.ps1"
$srcDeploy = Join-Path $PSScriptRoot "Deploy-NetworkSecurityAgent.ps1"
foreach ($f in @($srcUninstall, $srcDeploy)) {
    if (-not (Test-Path $f)) { Write-Host "XATO: $f topilmadi (shu skript bilan bir papkada bo'lishi kerak)"; exit 1 }
}
if (-not (Select-String -Path $srcDeploy -Pattern "UNINSTALL belgisi" -SimpleMatch -Quiet)) {
    Write-Host "XATO: $srcDeploy eski versiya (UNINSTALL belgisini tekshirmaydi) - repodagi yangi faylni oling"
    exit 1
}
$sameDir = (Resolve-Path $PSScriptRoot).Path.TrimEnd('\') -eq (Resolve-Path $SysvolDir).Path.TrimEnd('\')

if ($DryRun) {
    if (-not $sameDir) { Log "DRY-RUN: nusxalanadi: $srcUninstall, $srcDeploy -> $SysvolDir (eski Deploy zaxiralanadi)" }
    Log "DRY-RUN: yaratiladi: $marker"
    Set-AutoUpdateTask $false
    if (-not $SkipLocal) { Log "DRY-RUN: shu kompyuterning agenti darhol olib tashlanadi" }
    exit 0
}

# --- 3) Fayllarni SYSVOL'ga joylash: avval skriptlar, BELGI ENG OXIRIDA ---
if (-not $sameDir) {
    $backupDir = "C:\ProgramData\NetworkSecurityAgent\removal-backup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Copy-Item (Join-Path $SysvolDir "Deploy-NetworkSecurityAgent.ps1") $backupDir -Force
    Log "Eski Deploy skripti zaxiralandi: $backupDir"
    Copy-Item $srcUninstall $SysvolDir -Force
    # karantin qaytarish skripti: Uninstall uni har kompyuterda karantin yoniga qo'yadi
    $srcRestore = Join-Path $PSScriptRoot "Restore-Quarantine.ps1"
    if (Test-Path $srcRestore) { Copy-Item $srcRestore $SysvolDir -Force }
    Copy-Item $srcDeploy $SysvolDir -Force
    Log "SYSVOL'ga joylandi: Uninstall-NetworkSecurityAgent.ps1, Restore-Quarantine.ps1, Deploy-NetworkSecurityAgent.ps1"
}
Set-Content -Path $marker -Value "Agentlarni olib tashlash yoqilgan: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($env:USERDOMAIN\$env:USERNAME). Bekor qilish: Start-AgentRemoval.ps1 -Undo" -Encoding ASCII
Log "UNINSTALL belgisi yaratildi: $marker"

# --- 4) Avto-yangilovchi SYSVOL'ga yangi agent versiyasini qo'ymasin ---
Set-AutoUpdateTask $false

# --- 5) Shu DC'ning o'z agenti ---
if (-not $SkipLocal) {
    Log "Shu kompyuterning ($env:COMPUTERNAME) agenti olib tashlanmoqda..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $SysvolDir "Uninstall-NetworkSecurityAgent.ps1")
    Log "Mahalliy uninstall: exit $LASTEXITCODE"
}

Log "Tayyor. Onlayn kompyuterlar ~35 daqiqa ichida, o'chiq turganlari keyingi yoqilishda tozalanadi."
Log "Tekshirish (istalgan kompyuterda): Get-Service NetworkSecurityEndpointAgent  -> topilmasligi kerak"
