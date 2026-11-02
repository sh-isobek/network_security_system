# CI (windows-latest, Windows PowerShell 5.1): deploy/windows_agent_gpo/AgentTls.ps1
# ichki CA'ga faqat shu jarayonda ishonishini, begona CA va noto'g'ri nomni rad
# etishini HAQIQIY TLS ulanishlari bilan tekshiradi.
param([Parameter(Mandatory = $true)][string]$CertDir, [Parameter(Mandatory = $true)][string]$Lib)
$ErrorActionPreference = "Stop"
$failed = 0
function Check([string]$name, [bool]$cond) {
    if ($cond) { Write-Host "OK   $name" } else { Write-Host "FAIL $name"; $script:failed++ }
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
$ca = Join-Path $CertDir "ca_a.crt"

# 0) Yangi jarayonda (AgentTls'siz) server rad etilishi kerak - CA Windows do'konida yo'q
$plain = powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; try { Invoke-WebRequest -Uri https://127.0.0.1:19443/api/v1/health -UseBasicParsing -TimeoutSec 10 | Out-Null; 'connected' } catch { 'rejected' }"
Check "AgentTls'siz jarayon ichki CA'ga ishonmaydi (Trusted Root'ga qo'shilmagan)" ($plain -eq "rejected")

. $Lib

Check "ConvertTo-AgentHttpsUrl" ((ConvertTo-AgentHttpsUrl -HttpUrl "http://172.16.1.206:8443" -Port 9443) -eq "https://172.16.1.206:9443")
Check "ConvertTo-AgentHttpsUrl (yo'l/slash bilan)" ((ConvertTo-AgentHttpsUrl -HttpUrl "http://10.0.0.5:8443/" -Port 9443) -eq "https://10.0.0.5:9443")
Check "To'g'ri CA + to'g'ri IP -> qabul" (Test-AgentHttpsUrl -Url "https://127.0.0.1:19443" -CaFile $ca)
Check "Begona CA -> rad" (-not (Test-AgentHttpsUrl -Url "https://127.0.0.1:19444" -CaFile $ca))
Check "Nom (SAN) mos emas -> rad" (-not (Test-AgentHttpsUrl -Url "https://127.0.0.1:19445" -CaFile $ca))
Check "Server yo'q port -> rad (xatosiz)" (-not (Test-AgentHttpsUrl -Url "https://127.0.0.1:19446" -CaFile $ca))

# Watchdog uslubidagi POST (Invoke-RestMethod) ham ishlashi kerak
Enable-AgentCaTrust -CaFile $ca
$resp = Invoke-RestMethod -Uri "https://127.0.0.1:19443/api/v1/agent_watchdog_check" -Method Post -Headers @{ "X-API-Key" = "x" } `
    -ContentType "application/json" -Body (@{ hostname = "ci" } | ConvertTo-Json) -TimeoutSec 10
Check "Invoke-RestMethod POST (watchdog) HTTPS orqali" ($resp.status -eq "ok")

try { $null = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ca) ; $okCa = $true } catch { $okCa = $false }
Check "CA fayli o'qiladi" $okCa
try { Enable-AgentCaTrust -CaFile (Join-Path $CertDir "missing.crt"); $threw = $false } catch { $threw = $true }
Check "Yo'q CA fayli -> xato (jim ishonish yo'q)" $threw

if ($failed -gt 0) { Write-Error "$failed ta tekshiruv muvaffaqiyatsiz"; exit 1 }
Write-Host "Barcha AgentTls tekshiruvlari o'tdi"
