# Publish-AgentDeployGpoTask.ps1
#
# DC'da ADMIN sifatida bir marta ishga tushiriladi. Agentni GPO orqali barcha kompyuterlarga
# QAYTA YOQMASDAN yetkazadi: agentni o'rnatuvchi GPO'ga (Deploy-NetworkSecurityAgent.ps1
# Startup skripti turgan GPO) Group Policy Preferences "Scheduled Task" qo'shadi - har
# kompyuterda SYSTEM huquqi bilan har IntervalMinutes daqiqada (va GPO qo'llanganda darhol)
# o'sha Deploy skriptini ishga tushiradi. Deploy skripti IDEMPOTENT: versiya bir xil bo'lsa
# hech narsa qilmaydi, yangi bo'lsa faqat agent XIZMATINI almashtiradi. KOMPYUTERLAR QAYTA
# YOQILMAYDI va foydalanuvchi sessiyasi uzilmaydi (gpupdate /boot, /logoff ishlatilmaydi).
#
# Nima o'zgaradi:
#   * GPO'ning Machine\Preferences\ScheduledTasks\ScheduledTasks.xml fayli (shablon:
#     ScheduledTasks.template.xml), gPCMachineExtensionNames (Scheduled Tasks CSE ro'yxatga
#     olinadi) va GPO versiyasi (AD + GPT.INI) - shunda mijozlar o'zgarishni ko'radi.
#   * O'zgartirishdan OLDIN GPO zaxiralanadi (Backup-GPO) - qaytarish: -Remove yoki
#     Restore-GPO.
#
# Ishlatish (DC'da, Administrator PowerShell):
#     .\Publish-AgentDeployGpoTask.ps1 -DryRun            # nima qilinishini ko'rsatadi, hech narsa yozmaydi
#     .\Publish-AgentDeployGpoTask.ps1                    # nashr qiladi
#     .\Publish-AgentDeployGpoTask.ps1 -ForceRefresh      # + onlayn kompyuterlarda gpupdate (qayta yoqmasdan)
#     .\Publish-AgentDeployGpoTask.ps1 -Remove            # vazifani barcha kompyuterlardan olib tashlaydi
param(
    [string]$GpoName = "",             # bo'sh bo'lsa Deploy-NetworkSecurityAgent.ps1 Startup skripti bor GPO avto-topiladi
    [int]$IntervalMinutes = 30,
    [int]$RandomDelayMinutes = 5,      # yuzlab kompyuter bir vaqtda xizmatni almashtirmasligi uchun
    [string]$TaskName = "NSA-Agent-Deploy",
    [switch]$DryRun,
    [switch]$Remove,
    [switch]$ForceRefresh,
    [string]$LogFile = "C:\ProgramData\NetworkSecurityAgent\publish-gpo-task.log"
)

$ErrorActionPreference = "Stop"
Import-Module GroupPolicy
Import-Module ActiveDirectory

function Log([string]$m) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"
    Write-Host $line
    try {
        $d = Split-Path $LogFile -Parent
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        $line | Out-File -FilePath $LogFile -Append -Encoding utf8
    } catch { }
}

$domain = Get-ADDomain
$domainDns = $domain.DNSRoot
$sysvolPolicies = Join-Path $env:SystemRoot "SYSVOL\sysvol\$domainDns\Policies"
Log "=== Publish-AgentDeployGpoTask (DryRun=$DryRun, Remove=$Remove, ForceRefresh=$ForceRefresh) domen=$domainDns ==="

# --- 1) Agentni o'rnatuvchi GPO'ni topish (uning qamrovi/bog'lanishi allaqachon to'g'ri) ---
function Get-ScriptsIni([Guid]$Id) {
    foreach ($n in "scripts.ini", "psscripts.ini") {
        $p = Join-Path $sysvolPolicies "{$Id}\Machine\Scripts\$n"
        if (Test-Path $p) { Get-Content $p -Raw -ErrorAction SilentlyContinue }
    }
}
$candidates = @()
foreach ($g in Get-GPO -All) {
    if ($GpoName -and $g.DisplayName -ne $GpoName) { continue }
    $ini = (Get-ScriptsIni $g.Id) -join "`n"
    if ($GpoName -or $ini -match "Deploy-NetworkSecurityAgent") { $candidates += @{ Gpo = $g; Ini = $ini } }
}
if ($candidates.Count -ne 1) {
    Log "XATO: mos GPO soni $($candidates.Count). -GpoName bilan aniq ko'rsating. Topilganlar: $(($candidates | ForEach-Object { $_.Gpo.DisplayName }) -join ', ')"
    exit 1
}
$gpo = $candidates[0].Gpo
Log "GPO: '$($gpo.DisplayName)' {$($gpo.Id)}"

# Startup skripti qaysi yo'l bilan chaqirilsa - vazifa ham AYNAN SHU yo'ldan ishlaydi (u allaqachon ishlab turibdi)
$deployPath = $null
if ($candidates[0].Ini -match '(?im)^\s*\d+CmdLine\s*=\s*(.*Deploy-NetworkSecurityAgent\.ps1)\s*$') { $deployPath = $Matches[1].Trim().Trim('"') }
if ($deployPath -and $deployPath -notmatch '^(\\\\|[A-Za-z]:\\)') { $deployPath = $null }   # nisbiy fayl nomi bo'lsa - standart UNC ishlatiladi
if (-not $deployPath) { $deployPath = "\\$domainDns\SYSVOL\$domainDns\scripts\NetworkSecurityAgent\Deploy-NetworkSecurityAgent.ps1" }
Log "Deploy skripti yo'li (mijozlarda): $deployPath"

# --- 2) Qamrov (faqat ma'lumot uchun; DC'lar qamrovda bo'lmasligi kerak) ---
[xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
$links = @($report.GPO.LinksTo | ForEach-Object { $_.SOMPath })
Log "GPO bog'langan joylar: $($links -join '; ')"
if ($links | Where-Object { $_ -match "Domain Controllers" }) { Log "OGOHLANTIRISH: GPO 'Domain Controllers' OU'siga ham bog'langan!" }

# --- 3) XML tayyorlash ---
$templatePath = Join-Path $PSScriptRoot "ScheduledTasks.template.xml"
if (-not (Test-Path $templatePath)) { Log "XATO: shablon topilmadi: $templatePath"; exit 1 }
$taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$deployPath`""
$now = Get-Date
$action = if ($Remove) { "D" } else { "R" }
$xmlText = (Get-Content $templatePath -Raw -Encoding UTF8).
    Replace("{{TASK_NAME}}", $TaskName).
    Replace("{{CHANGED}}", $now.ToString("yyyy-MM-dd HH:mm:ss")).
    Replace("{{UID}}", "{$([Guid]::NewGuid().ToString().ToUpper())}").
    Replace("{{ACTION}}", $action).
    Replace("{{START}}", $now.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ss")).
    Replace("{{INTERVAL}}", "$IntervalMinutes").
    Replace("{{RANDOM}}", "$RandomDelayMinutes").
    Replace("{{ARGS}}", [Security.SecurityElement]::Escape($taskArgs))
[xml]$newDoc = $xmlText   # to'g'ri XML ekanini tekshiradi (xato bo'lsa shu yerda to'xtaydi)
$newTask = $newDoc.ScheduledTasks.TaskV2

$prefDir = Join-Path $sysvolPolicies "{$($gpo.Id)}\Machine\Preferences\ScheduledTasks"
$prefFile = Join-Path $prefDir "ScheduledTasks.xml"
if (Test-Path $prefFile) {
    [xml]$doc = Get-Content $prefFile -Raw -Encoding UTF8
    foreach ($t in @($doc.ScheduledTasks.ChildNodes | Where-Object { $_.name -eq $TaskName })) { [void]$doc.ScheduledTasks.RemoveChild($t) }
    [void]$doc.ScheduledTasks.AppendChild($doc.ImportNode($newTask, $true))
    Log "Mavjud ScheduledTasks.xml yangilanadi (boshqa vazifalar saqlanadi)"
} else {
    $doc = $newDoc
    Log "Yangi ScheduledTasks.xml yaratiladi"
}

# --- 4) AD atributlari: Scheduled Tasks CSE ro'yxatga olinishi va GPO versiyasi ---
$cse = "{AADCED64-746C-4633-A97C-D61349046527}"      # Group Policy Preferences: Scheduled Tasks
$tool = "{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}"     # Preferences MMC tool
$gpoDn = "CN={$($gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)"
$adObj = Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames, versionNumber
$current = [string]$adObj.gPCMachineExtensionNames

$map = [ordered]@{}
foreach ($m in [regex]::Matches($current, '\[((?:\{[0-9A-Fa-f-]+\})+)\]')) {
    $guids = [regex]::Matches($m.Groups[1].Value, '\{[0-9A-Fa-f-]+\}') | ForEach-Object { $_.Value.ToUpper() }
    $map[$guids[0]] = @($guids | Select-Object -Skip 1)
}
if (-not $map.Contains($cse)) { $map[$cse] = @() }
if ($map[$cse] -notcontains $tool) { $map[$cse] = @($map[$cse] + $tool) }
$newExt = (($map.Keys | Sort-Object) | ForEach-Object { "[$_" + (($map[$_] | Sort-Object) -join "") + "]" }) -join ""

$oldVer = [int]$adObj.versionNumber
$machineVer = ($oldVer -band 0xFFFF) + 1
$newVer = ($oldVer -band 0xFFFF0000) -bor $machineVer

Log "gPCMachineExtensionNames: '$current' -> '$newExt'"
Log "GPO versiyasi: $oldVer -> $newVer (kompyuter qismi $machineVer)"

if ($DryRun) {
    Log "DRY-RUN: hech narsa yozilmadi. Yozilardi: $prefFile"
    Log ($doc.OuterXml)
    exit 0
}

# --- 5) Zaxira va yozish ---
$backupDir = "C:\ProgramData\NetworkSecurityAgent\gpo-backup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
[void](Backup-GPO -Guid $gpo.Id -Path $backupDir)
Log "GPO zaxirasi: $backupDir (qaytarish: Restore-GPO -Guid {$($gpo.Id)} -Path '$backupDir')"

if (-not (Test-Path $prefDir)) { New-Item -ItemType Directory -Path $prefDir -Force | Out-Null }
$settings = New-Object Xml.XmlWriterSettings
$settings.Encoding = New-Object Text.UTF8Encoding($false)
$writer = [Xml.XmlWriter]::Create($prefFile, $settings)
$doc.Save($writer); $writer.Close()
Log "Yozildi: $prefFile"

Set-ADObject -Identity $gpoDn -Replace @{ gPCMachineExtensionNames = $newExt; versionNumber = $newVer }
$gptIni = Join-Path $sysvolPolicies "{$($gpo.Id)}\GPT.INI"
$iniText = Get-Content $gptIni -Raw
if ($iniText -match '(?im)^Version\s*=') { $iniText = [regex]::Replace($iniText, '(?im)^Version\s*=.*$', "Version=$newVer") }
else { $iniText = $iniText.TrimEnd() + "`r`nVersion=$newVer`r`n" }
Set-Content -Path $gptIni -Value $iniText -Encoding ASCII
Log "AD va GPT.INI yangilandi (versiya $newVer). Mijozlar keyingi GPO yangilanishida (odatda ~90-120 daqiqa) olishadi."

# --- 6) Ixtiyoriy: onlayn kompyuterlarda GPO'ni HOZIR qo'llash (QAYTA YOQMASDAN, sessiyani uzmasdan) ---
if ($ForceRefresh -and -not $Remove) {
    $computers = @()
    foreach ($l in $links) {
        if ($l -match "Domain Controllers") { continue }
        $parts = $l.Split("/")
        if ($parts.Count -eq 1) { $base = $domain.DistinguishedName }
        else { $base = (($parts[($parts.Count - 1)..1] | ForEach-Object { "OU=$_" }) -join ",") + "," + $domain.DistinguishedName }
        try {
            $computers += Get-ADComputer -Filter { Enabled -eq $true } -SearchBase $base -ErrorAction Stop |
                Where-Object { $_.DistinguishedName -notlike "*OU=Domain Controllers,*" } | ForEach-Object { $_.Name }
        } catch { Log "OGOHLANTIRISH: '$base' dan kompyuterlar olinmadi: $_" }
    }
    $computers = $computers | Sort-Object -Unique
    Log "gpupdate yuboriladi: $($computers.Count) ta kompyuter (faqat onlayn bo'lganlarga; /boot va /logoff ISHLATILMAYDI)"
    $ok = 0; $fail = 0; $offline = 0
    foreach ($batch in ($computers | ForEach-Object -Begin { $i = 0 } -Process { [pscustomobject]@{ N = $_; G = [math]::Floor($i++ / 20) } } | Group-Object G)) {
        $jobs = foreach ($c in $batch.Group.N) {
            Start-Job -ArgumentList $c -ScriptBlock {
                param($c)
                if (-not (Test-Connection -ComputerName $c -Count 1 -Quiet)) { return "offline:$c" }
                try { Invoke-GPUpdate -Computer $c -Target Computer -Force -RandomDelayInMinutes 0 -ErrorAction Stop; return "ok:$c" }
                catch { return "fail:$c" }
            }
        }
        $res = $jobs | Wait-Job -Timeout 120 | Receive-Job
        $jobs | Remove-Job -Force
        foreach ($r in $res) { if ($r -like "ok:*") { $ok++ } elseif ($r -like "offline:*") { $offline++ } else { $fail++ } }
    }
    Log "gpupdate natijasi: muvaffaqiyatli=$ok, oflayn=$offline, bajarilmadi=$fail (bajarilmaganlar/oflaynlar GPO'ni o'zi navbatdagi yangilanishda oladi)"
}
Log "Tayyor."
