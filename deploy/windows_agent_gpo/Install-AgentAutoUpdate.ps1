# Bir marta, AD serverda ADMIN sifatida ishga tushiriladi: Sync-AgentFromGitHub.ps1 ni
# SYSTEM huquqi bilan har 30 daqiqada (va yoqilganda) ishlaydigan vazifa qilib ro'yxatga oladi.
param([string]$Interval = 30, [string]$SysvolDir = "")
$ErrorActionPreference = "Stop"
$dest = "C:\ProgramData\NetworkSecurityAgent"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot "Sync-AgentFromGitHub.ps1") $dest -Force
$args = "-NoProfile -ExecutionPolicy Bypass -File `"$dest\Sync-AgentFromGitHub.ps1`""
if ($SysvolDir) { $args += " -SysvolDir `"$SysvolDir`"" }
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $args
$t1 = New-ScheduledTaskTrigger -AtStartup
$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Interval)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -StartWhenAvailable
Register-ScheduledTask -TaskName "NSA-Agent-AutoUpdate" -Action $action -Trigger @($t1, $t2) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "NSA-Agent-AutoUpdate"
Write-Host "Vazifa o'rnatildi va ishga tushirildi. Jurnal: $dest\sync.log"
