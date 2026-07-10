<#
.SYNOPSIS
    Проверка базовой безопасности Windows-машины → HTML-чеклист с вердиктами.

.DESCRIPTION
    Быстрый аудит гигиены одной машины: проверяет типовые слабые места, которые
    чаще всего находят на пентестах и в инцидентах. По каждому пункту — вердикт
    PASS / WARN / FAIL и краткое пояснение.

    Проверки:
      * SMBv1 — включён ли устаревший уязвимый протокол (EternalBlue и др.)
      * RDP — включён ли, и требует ли NLA (Network Level Authentication)
      * Firewall — включён ли по всем профилям
      * BitLocker — зашифрован ли системный диск
      * LLMNR — выключен ли (иначе — вектор перехвата хешей)
      * UAC — включён ли контроль учётных записей
      * Windows Update — как давно ставились обновления
      * Гостевая учётка — отключена ли
      * PowerShell v2 — выключен ли устаревший движок

    Только чтение — ничего не меняет, лишь докладывает.

.PARAMETER ReportPath
    Куда сохранить HTML. По умолчанию SecurityBaseline_<имя>_<дата>.html в текущей папке.

.EXAMPLE
    .\Test-SecurityBaseline.ps1

.NOTES
    Совместимо с Windows PowerShell 5.1. Часть проверок (BitLocker, некоторые
    фичи) требует прав администратора — без них пункт помечается как «неизвестно».
#>
param(
    [string]$ReportPath
)

if (-not $ReportPath) {
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ReportPath = Join-Path $baseDir ("SecurityBaseline_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd'))
}

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name, [string]$Verdict, [string]$Detail)  # Verdict: PASS / WARN / FAIL / UNKNOWN
    $checks.Add([pscustomobject]@{ Name = $Name; Verdict = $Verdict; Detail = $Detail })
}

Write-Host "[*] Проверка $env:COMPUTERNAME ..." -ForegroundColor Cyan

# --- SMBv1 ---
try {
    $smb = Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='SMB1Protocol'" -ErrorAction Stop
    if ($smb -and $smb.InstallState -eq 1) { Add-Check 'SMBv1' 'FAIL' 'Включён устаревший SMBv1 — отключить (уязвим к EternalBlue)' }
    else { Add-Check 'SMBv1' 'PASS' 'Отключён' }
} catch {
    $srv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -ErrorAction SilentlyContinue
    if ($srv -and $srv.SMB1 -eq 0) { Add-Check 'SMBv1' 'PASS' 'Отключён (SMB1=0)' }
    else { Add-Check 'SMBv1' 'WARN' 'Не удалось определить — проверить вручную' }
}

# --- RDP + NLA ---
$rdpDeny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
if ($rdpDeny -eq 0) {
    $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    if ($nla -eq 1) { Add-Check 'RDP' 'PASS' 'Включён, требует NLA' }
    else { Add-Check 'RDP' 'FAIL' 'Включён БЕЗ NLA — включить Network Level Authentication' }
} else {
    Add-Check 'RDP' 'PASS' 'Отключён'
}

# --- Firewall ---
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $off = @($profiles | Where-Object { -not $_.Enabled })
    if ($off.Count -eq 0) { Add-Check 'Брандмауэр' 'PASS' 'Включён по всем профилям' }
    else { Add-Check 'Брандмауэр' 'FAIL' ("Выключен: " + (($off.Name) -join ', ')) }
} catch { Add-Check 'Брандмауэр' 'UNKNOWN' 'Не удалось проверить' }

# --- BitLocker системного диска ---
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($bl.ProtectionStatus -eq 'On') { Add-Check 'BitLocker' 'PASS' "Системный диск зашифрован ($($bl.VolumeStatus))" }
    else { Add-Check 'BitLocker' 'WARN' 'Системный диск не зашифрован' }
} catch { Add-Check 'BitLocker' 'UNKNOWN' 'Недоступно (нет прав или роль не установлена)' }

# --- LLMNR ---
$llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
if ($llmnr -eq 0) { Add-Check 'LLMNR' 'PASS' 'Отключён политикой' }
else { Add-Check 'LLMNR' 'WARN' 'Включён — вектор перехвата учётных данных (Responder). Отключить через GPO' }

# --- UAC ---
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($uac -eq 1) { Add-Check 'UAC' 'PASS' 'Включён' }
else { Add-Check 'UAC' 'FAIL' 'Контроль учётных записей отключён' }

# --- Последнее обновление ---
try {
    $lastHotfix = Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastHotfix) {
        $days = [int]((Get-Date) - $lastHotfix.InstalledOn).TotalDays
        if ($days -le 45) { Add-Check 'Обновления' 'PASS' "Последнее: $($lastHotfix.HotFixID), $days дн. назад" }
        else { Add-Check 'Обновления' 'WARN' "Последнее обновление $days дн. назад — давно" }
    } else { Add-Check 'Обновления' 'UNKNOWN' 'Не удалось определить дату' }
} catch { Add-Check 'Обновления' 'UNKNOWN' 'Не удалось получить список' }

# --- Гостевая учётная запись ---
try {
    $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-%-501'" -ErrorAction Stop | Select-Object -First 1
    if ($guest -and -not $guest.Disabled) { Add-Check 'Гость' 'FAIL' "Учётная запись '$($guest.Name)' включена" }
    else { Add-Check 'Гость' 'PASS' 'Отключена' }
} catch { Add-Check 'Гость' 'UNKNOWN' 'Не удалось проверить' }

# --- PowerShell v2 ---
try {
    $psv2 = Get-CimInstance Win32_OptionalFeature -Filter "Name='MicrosoftWindowsPowerShellV2'" -ErrorAction Stop
    if ($psv2 -and $psv2.InstallState -eq 1) { Add-Check 'PowerShell v2' 'WARN' 'Устаревший движок v2 включён — отключить (обход логирования)' }
    else { Add-Check 'PowerShell v2' 'PASS' 'Отключён' }
} catch { Add-Check 'PowerShell v2' 'UNKNOWN' 'Не удалось проверить' }

# ---- Консоль ----
$color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; UNKNOWN = 'DarkGray' }
foreach ($c in $checks) {
    Write-Host ("  [{0,-7}] {1,-16} {2}" -f $c.Verdict, $c.Name, $c.Detail) -ForegroundColor $color[$c.Verdict]
}

# ---- HTML ----
$style = @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f9fafb; }
  h1 { font-size: 22px; } .meta { color: #6b7280; font-size: 13px; margin-bottom: 14px; }
  table { border-collapse: collapse; width: 100%; background: #fff; }
  th, td { border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; font-size: 13px; }
  th { background: #f3f4f6; }
  .v { display: inline-block; min-width: 62px; text-align: center; padding: 2px 8px; border-radius: 8px; color: #fff; font-weight: 600; font-size: 12px; }
  .PASS { background: #10b981; } .WARN { background: #f59e0b; } .FAIL { background: #ef4444; } .UNKNOWN { background: #9ca3af; }
</style>
"@

$rowsHtml = ($checks | ForEach-Object {
    "<tr><td>$($_.Name)</td><td><span class='v $($_.Verdict)'>$($_.Verdict)</span></td><td>$($_.Detail)</td></tr>"
}) -join "`n"

$pass = @($checks | Where-Object Verdict -eq 'PASS').Count
$warn = @($checks | Where-Object Verdict -eq 'WARN').Count
$fail = @($checks | Where-Object Verdict -eq 'FAIL').Count

$body = @"
<h1>Проверка безопасности — $env:COMPUTERNAME</h1>
<div class='meta'>Сформировано: $(Get-Date -Format 'dd.MM.yyyy HH:mm') ·
<b style='color:#10b981'>PASS: $pass</b> · <b style='color:#f59e0b'>WARN: $warn</b> · <b style='color:#ef4444'>FAIL: $fail</b></div>
<table>
<tr><th>Проверка</th><th>Вердикт</th><th>Детали</th></tr>
$rowsHtml
</table>
"@

"<!DOCTYPE html><html><head><meta charset='utf-8'>$style</head><body>$body</body></html>" |
    Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "[OK] Отчёт: $ReportPath" -ForegroundColor Green
if ($fail -gt 0) { Write-Host "[!] Критичных пунктов (FAIL): $fail" -ForegroundColor Red }
