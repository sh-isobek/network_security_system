# Sync-AgentFromGitHub.ps1
#
# AD serverda (Domain Controller) rejalashtirilgan vazifa sifatida ishlaydi:
#  1) GitHub'dagi eng so'nggi "agent-vX.Y.Z" Release'ni tekshiradi;
#  2) SYSVOL'dagi joriy VERSION'dan yangi bo'lsa - zip'ni yuklab, SHA256'ni tekshiradi;
#  3) eski SYSVOL papkasini _backup_<versiya>ga zaxiralab, yangi fayllarni joylaydi
#     (exe, VERSION, Deploy/Install skriptlari) - GPO orqali barcha kompyuterlar keyingi
#     yoqilishda yangilanadi;
#  4) shu serverning O'Z agentini ham darhol yangilaydi (Deploy skripti, idempotent).
# Xato bo'lsa SYSVOL o'zgarmaydi. Jurnal: C:\ProgramData\NetworkSecurityAgent\sync.log
param(
    [string]$Repo = "sh-isobek/network_security_system",
    [string]$SysvolDir = "",      # bo'sh bo'lsa VERSION fayli bor SYSVOL papkasi avto-topiladi
    [string]$LogFile = "C:\ProgramData\NetworkSecurityAgent\sync.log"
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Log([string]$m) {
    $d = Split-Path $LogFile -Parent
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m" | Out-File -FilePath $LogFile -Append -Encoding utf8
}
function ToVer([string]$v) { try { [version]($v.Trim()) } catch { [version]"0.0.0" } }

$stage = Join-Path $env:TEMP ("nsa_sync_" + [guid]::NewGuid().ToString("N"))
try {
    if (-not $SysvolDir) {
        $root = Join-Path $env:SystemRoot "SYSVOL\sysvol"
        $hit = Get-ChildItem -Path $root -Recurse -Filter VERSION -ErrorAction SilentlyContinue |
               Where-Object { $_.Directory.Parent.Name -eq "scripts" -or $_.FullName -match "NetworkSecurityAgent" } | Select-Object -First 1
        if (-not $hit) { throw "SYSVOL'da agent papkasi (VERSION) topilmadi - -SysvolDir bering" }
        $SysvolDir = $hit.DirectoryName
    }
    $cur = ToVer (Get-Content (Join-Path $SysvolDir "VERSION") -Raw)

    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "nsa-sync" } -TimeoutSec 30
    $latest = ToVer ($rel.tag_name -replace "^agent-v", "")
    if ($latest -le $cur) { Log "Yangilanish yo'q (SYSVOL $cur, GitHub $latest)"; }
    else {
        Log "Yangi versiya topildi: $cur -> $latest"
        $zipAsset = $rel.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
        $shaAsset = $rel.assets | Where-Object { $_.name -like "*.zip.sha256" } | Select-Object -First 1
        if (-not $zipAsset -or -not $shaAsset) { throw "Release'da zip yoki sha256 fayli yo'q" }
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        $zip = Join-Path $stage $zipAsset.name
        Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zip -UseBasicParsing -TimeoutSec 300
        $shaBody = (Invoke-WebRequest -Uri $shaAsset.browser_download_url -UseBasicParsing -TimeoutSec 60).Content
        if ($shaBody -is [byte[]]) { $shaBody = [Text.Encoding]::ASCII.GetString($shaBody) }   # PS 5.1: octet-stream bayt massivi
        $expected = ($shaBody.Trim() -split "\s+")[0].ToLower()
        $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected) { throw "SHA256 mos emas (kutilgan $expected, olingan $actual) - o'rnatilmadi" }

        Expand-Archive -Path $zip -DestinationPath $stage -Force
        $pkg = Join-Path $stage "NetworkSecurityAgent"
        foreach ($f in "NetworkSecurityAgent.exe", "VERSION", "Deploy-NetworkSecurityAgent.ps1") {
            if (-not (Test-Path (Join-Path $pkg $f))) { throw "Paketda $f yo'q" }
        }
        if ((ToVer (Get-Content (Join-Path $pkg "VERSION") -Raw)) -ne $latest) { throw "Paket VERSION'i release tegi bilan mos emas" }

        # zaxira (agar shu versiya zaxirasi hali yo'q bo'lsa) va joylash
        $backup = Join-Path (Split-Path $SysvolDir -Parent) ("_backup_" + $cur + "_" + (Split-Path $SysvolDir -Leaf))
        if (-not (Test-Path $backup)) { Copy-Item $SysvolDir $backup -Recurse -Force }
        # VERSION ENG OXIRIDA yoziladi: yarim ko'chirilgan holatda agentlar yangilanmasin
        foreach ($f in Get-ChildItem $pkg -File | Where-Object { $_.Name -ne "VERSION" }) {
            Copy-Item $f.FullName (Join-Path $SysvolDir $f.Name) -Force
        }
        Copy-Item (Join-Path $pkg "VERSION") (Join-Path $SysvolDir "VERSION") -Force
        Log "SYSVOL yangilandi: $SysvolDir ($latest); zaxira: $backup"
    }

    # Shu serverning O'Z agenti: Deploy skripti idempotent (versiya bir xil bo'lsa hech narsa qilmaydi)
    $deploy = Join-Path $SysvolDir "Deploy-NetworkSecurityAgent.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $deploy | Out-Null
    Log "Lokal Deploy skripti ishga tushirildi (exit $LASTEXITCODE)"
}
catch { Log "XATO: $_"; exit 1 }
finally { if (Test-Path $stage) { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue } }
