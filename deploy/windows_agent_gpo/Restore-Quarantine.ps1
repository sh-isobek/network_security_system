# Restore-Quarantine.ps1 - karantindagi fayllarni ASL joyiga qaytaradi (yolg'on-ijobiy holatlar uchun).
# Ishlatish (admin PowerShell):
#   .\Restore-Quarantine.ps1 -List                       # nima karantinda ekanini ko'rsatadi
#   .\Restore-Quarantine.ps1 -Name ChromeSetup.exe       # nomi bo'yicha qaytaradi
#   .\Restore-Quarantine.ps1 -All                        # hammasini qaytaradi
# SHA256 karantin nusxasi bilan qayta tekshiriladi; asl joyda fayl bo'lsa ustidan yozilmaydi.
param([switch]$List, [switch]$All, [string]$Name = "", [string]$Root = "C:\ProgramData\NetworkSecurityAgent\Quarantine")
$ErrorActionPreference = "Stop"
$items = Get-ChildItem $Root -Directory | ForEach-Object {
    $m = Join-Path $_.FullName "metadata.json"
    if (Test-Path $m) { $j = Get-Content $m -Raw | ConvertFrom-Json; [pscustomobject]@{ Dir = $_.FullName; File = $j.filename; Original = $j.original_path; Sha = $j.sha256; Threat = $j.threat_name } }
}
if ($List -or (-not $All -and -not $Name)) { $items | Format-Table File, Original -AutoSize; return }
foreach ($i in $items) {
    if (-not $All -and $i.File -ne $Name) { continue }
    $src = Join-Path $i.Dir $i.File
    if (-not (Test-Path $src)) { Write-Host "Karantin fayli topilmadi: $src"; continue }
    if ((Get-FileHash $src -Algorithm SHA256).Hash.ToLower() -ne $i.Sha.ToLower()) { Write-Host "SHA256 mos emas, o'tkazildi: $($i.File)"; continue }
    if (Test-Path $i.Original) { Write-Host "Asl joyda fayl bor, o'tkazildi: $($i.Original)"; continue }
    New-Item -ItemType Directory -Path (Split-Path $i.Original -Parent) -Force | Out-Null
    Copy-Item $src $i.Original
    Write-Host "Qaytarildi: $($i.Original)"
}
