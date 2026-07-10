<#
.SYNOPSIS
    Глубокий аудит защищённости Windows по мотивам CIS Benchmark → HTML + оценка.

.DESCRIPTION
    Проверяет ~25 настроек безопасности, сгруппированных по категориям
    (учётные записи, сеть и протоколы, поверхность атаки, обновления и аудит),
    и выставляет итоговую оценку в процентах. По каждому пункту — вердикт
    PASS / WARN / FAIL, ссылка на раздел CIS и краткая рекомендация «как исправить».

    Только чтение — ничего не меняет, лишь докладывает. Это «глубокая» версия;
    для быстрого взгляда есть Test-SecurityBaseline.ps1 (9 базовых пунктов).

.PARAMETER ReportPath
    Куда сохранить HTML. По умолчанию HardeningAudit_<имя>_<дата>.html в текущей папке.

.EXAMPLE
    .\Invoke-WindowsHardeningAudit.ps1

.NOTES
    Запускать от администратора — иначе часть проверок (Defender, политики паролей,
    аудит) будут «UNKNOWN». Windows 10/11 / Server 2016+. Совместимо с PS 5.1.
    Ориентир — CIS Microsoft Windows Benchmark; это не полное соответствие,
    а быстрый практический аудит ключевых пунктов.
#>
param(
    [string]$ReportPath
)

if (-not $ReportPath) {
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ReportPath = Join-Path $baseDir ("HardeningAudit_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd'))
}

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param(
        [string]$Category, [string]$Name, [string]$CIS,
        [ValidateSet('PASS','WARN','FAIL','UNKNOWN')][string]$Verdict,
        [string]$Detail, [string]$Fix = ''
    )
    $checks.Add([pscustomobject]@{
        Category = $Category; Name = $Name; CIS = $CIS
        Verdict = $Verdict; Detail = $Detail; Fix = $Fix
    })
}

function Get-Reg {
    param([string]$Path, [string]$Name)
    (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "[*] Аудит защищённости $env:COMPUTERNAME ..." -ForegroundColor Cyan
if (-not $isAdmin) { Write-Host "[!] Не админ — часть проверок будет UNKNOWN." -ForegroundColor Yellow }

# ==================== УЧЁТНЫЕ ЗАПИСИ И АУТЕНТИФИКАЦИЯ ====================
$cat = 'Учётные записи'

# Гостевая учётка
try {
    $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-%-501'" -EA Stop | Select-Object -First 1
    if ($guest -and -not $guest.Disabled) { Add-Check $cat 'Гостевая учётная запись' '2.3.1.2' 'FAIL' "'$($guest.Name)' включена" 'Отключить: net user Гость /active:no' }
    else { Add-Check $cat 'Гостевая учётная запись' '2.3.1.2' 'PASS' 'Отключена' }
} catch { Add-Check $cat 'Гостевая учётная запись' '2.3.1.2' 'UNKNOWN' 'Не удалось проверить' }

# Встроенный Администратор (SID -500)
try {
    $admin = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-%-500'" -EA Stop | Select-Object -First 1
    if ($admin -and -not $admin.Disabled) { Add-Check $cat 'Встроенный Администратор' '2.3.1.1' 'WARN' "'$($admin.Name)' включён — цель для брутфорса" 'Отключить встроенную учётку, использовать именные админ-аккаунты' }
    else { Add-Check $cat 'Встроенный Администратор' '2.3.1.1' 'PASS' 'Отключён' }
} catch { Add-Check $cat 'Встроенный Администратор' '2.3.1.1' 'UNKNOWN' 'Не удалось проверить' }

# Политика паролей (net accounts)
try {
    $na = net accounts 2>$null
    $minLen = ($na | Select-String 'Minimum password length|Минимальная длина пароля') -replace '\D',''
    if ($minLen) {
        if ([int]$minLen -ge 14) { Add-Check $cat 'Мин. длина пароля' '1.1.4' 'PASS' "$minLen символов" }
        elseif ([int]$minLen -ge 8) { Add-Check $cat 'Мин. длина пароля' '1.1.4' 'WARN' "$minLen символов (CIS рекомендует ≥14)" 'Увеличить минимальную длину до 14' }
        else { Add-Check $cat 'Мин. длина пароля' '1.1.4' 'FAIL' "$minLen символов — слишком коротко" 'Установить минимум 14 символов' }
    } else { Add-Check $cat 'Мин. длина пароля' '1.1.4' 'UNKNOWN' 'Не удалось прочитать' }
} catch { Add-Check $cat 'Мин. длина пароля' '1.1.4' 'UNKNOWN' 'Не удалось прочитать' }

# LM-хеш не хранится
$noLM = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'
if ($noLM -eq 1) { Add-Check $cat 'Хранение LM-хеша' '2.3.11.5' 'PASS' 'LM-хеши не хранятся' }
else { Add-Check $cat 'Хранение LM-хеша' '2.3.11.5' 'FAIL' 'LM-хеши хранятся — легко ломаются' 'NoLMHash=1 в HKLM\SYSTEM\...\Lsa' }

# NTLMv2
$lm = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
if ($null -ne $lm -and $lm -ge 3) { Add-Check $cat 'Уровень NTLM' '2.3.11.7' 'PASS' "LmCompatibilityLevel=$lm (только NTLMv2)" }
elseif ($null -eq $lm) { Add-Check $cat 'Уровень NTLM' '2.3.11.7' 'WARN' 'Не задано явно — возможен NTLMv1' 'LmCompatibilityLevel=5 (только NTLMv2)' }
else { Add-Check $cat 'Уровень NTLM' '2.3.11.7' 'FAIL' "LmCompatibilityLevel=$lm — разрешён слабый NTLM" 'Установить 5' }

# Пустые пароли только консольно
$blank = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse'
if ($blank -eq 1 -or $null -eq $blank) { Add-Check $cat 'Пустые пароли по сети' '2.3.1.4' 'PASS' 'Ограничены (по умолчанию)' }
else { Add-Check $cat 'Пустые пароли по сети' '2.3.1.4' 'FAIL' 'Разрешён сетевой вход с пустым паролем' 'LimitBlankPasswordUse=1' }

# UAC
$lua = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
if ($lua -eq 1) { Add-Check $cat 'UAC (контроль учёток)' '2.3.17.1' 'PASS' 'Включён' }
else { Add-Check $cat 'UAC (контроль учёток)' '2.3.17.1' 'FAIL' 'Отключён' 'EnableLUA=1' }

# ==================== СЕТЬ И ПРОТОКОЛЫ ====================
$cat = 'Сеть и протоколы'

# SMBv1
try {
    $smb1 = Get-CimInstance Win32_OptionalFeature -Filter "Name='SMB1Protocol'" -EA Stop
    if ($smb1 -and $smb1.InstallState -eq 1) { Add-Check $cat 'SMBv1' '18.4.3' 'FAIL' 'Включён устаревший SMBv1' 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' }
    else { Add-Check $cat 'SMBv1' '18.4.3' 'PASS' 'Отключён' }
} catch { Add-Check $cat 'SMBv1' '18.4.3' 'UNKNOWN' 'Не удалось проверить' }

# SMB-подпись обязательна
$smbSign = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
if ($smbSign -eq 1) { Add-Check $cat 'Подпись SMB (сервер)' '2.3.9.2' 'PASS' 'Обязательна' }
else { Add-Check $cat 'Подпись SMB (сервер)' '2.3.9.2' 'WARN' 'Не обязательна — риск MITM/relay' 'RequireSecuritySignature=1' }

# LLMNR
$llmnr = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
if ($llmnr -eq 0) { Add-Check $cat 'LLMNR' '18.5.4.2' 'PASS' 'Отключён' }
else { Add-Check $cat 'LLMNR' '18.5.4.2' 'WARN' 'Включён — перехват хешей (Responder)' 'GPO: EnableMulticast=0' }

# RDP NLA
$rdpDeny = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
if ($rdpDeny -eq 0) {
    $nla = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($nla -eq 1) { Add-Check $cat 'RDP' '18.10.9.3.x' 'PASS' 'Включён, требует NLA' }
    else { Add-Check $cat 'RDP' '18.10.9.3.x' 'FAIL' 'Включён БЕЗ NLA' 'Включить Network Level Authentication' }
} else { Add-Check $cat 'RDP' '18.10.9.3.x' 'PASS' 'Отключён' }

# Брандмауэр
try {
    $off = @(Get-NetFirewallProfile -EA Stop | Where-Object { -not $_.Enabled })
    if ($off.Count -eq 0) { Add-Check $cat 'Брандмауэр' '9.x' 'PASS' 'Включён по всем профилям' }
    else { Add-Check $cat 'Брандмауэр' '9.x' 'FAIL' ("Выключен: " + ($off.Name -join ', ')) 'Включить Windows Firewall для всех профилей' }
} catch { Add-Check $cat 'Брандмауэр' '9.x' 'UNKNOWN' 'Не удалось проверить' }

# ==================== ПОВЕРХНОСТЬ АТАКИ ====================
$cat = 'Поверхность атаки'

# AutoRun
$autorun = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
if ($autorun -eq 255) { Add-Check $cat 'Автозапуск (AutoRun)' '18.9.8.x' 'PASS' 'Отключён для всех дисков' }
else { Add-Check $cat 'Автозапуск (AutoRun)' '18.9.8.x' 'WARN' 'Включён — риск запуска с USB' 'NoDriveTypeAutoRun=255' }

# PowerShell v2
try {
    $psv2 = Get-CimInstance Win32_OptionalFeature -Filter "Name='MicrosoftWindowsPowerShellV2'" -EA Stop
    if ($psv2 -and $psv2.InstallState -eq 1) { Add-Check $cat 'PowerShell v2' '18.x' 'WARN' 'Устаревший движок включён (обход логирования)' 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' }
    else { Add-Check $cat 'PowerShell v2' '18.x' 'PASS' 'Отключён' }
} catch { Add-Check $cat 'PowerShell v2' '18.x' 'UNKNOWN' 'Не удалось проверить' }

# Defender realtime
try {
    $mp = Get-MpComputerStatus -EA Stop
    if ($mp.RealTimeProtectionEnabled) { Add-Check $cat 'Defender: защита в реальном времени' '18.9.47.x' 'PASS' 'Включена' }
    else { Add-Check $cat 'Defender: защита в реальном времени' '18.9.47.x' 'FAIL' 'Выключена' 'Включить защиту в реальном времени' }

    $age = ($mp.AntivirusSignatureAge)
    if ($null -ne $age) {
        if ($age -le 3) { Add-Check $cat 'Defender: базы сигнатур' '—' 'PASS' "Обновлены ($age дн. назад)" }
        else { Add-Check $cat 'Defender: базы сигнатур' '—' 'WARN' "Старые базы ($age дн.)" 'Update-MpSignature' }
    }
} catch { Add-Check $cat 'Defender: защита в реальном времени' '18.9.47.x' 'UNKNOWN' 'Недоступно (нет прав или сторонний AV)' }

# BitLocker
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -EA Stop
    if ($bl.ProtectionStatus -eq 'On') { Add-Check $cat 'BitLocker (системный диск)' '18.9.11.x' 'PASS' "Зашифрован ($($bl.VolumeStatus))" }
    else { Add-Check $cat 'BitLocker (системный диск)' '18.9.11.x' 'WARN' 'Не зашифрован' 'Включить BitLocker на системном диске' }
} catch { Add-Check $cat 'BitLocker (системный диск)' '18.9.11.x' 'UNKNOWN' 'Недоступно (нет прав/роли)' }

# ==================== ОБНОВЛЕНИЯ И АУДИТ ====================
$cat = 'Обновления и аудит'

# Последнее обновление
try {
    $hf = Get-HotFix -EA Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hf) {
        $days = [int]((Get-Date) - $hf.InstalledOn).TotalDays
        if ($days -le 45) { Add-Check $cat 'Свежесть обновлений' '18.x' 'PASS' "$($hf.HotFixID), $days дн. назад" }
        else { Add-Check $cat 'Свежесть обновлений' '18.x' 'WARN' "Последнее $days дн. назад" 'Установить обновления Windows' }
    } else { Add-Check $cat 'Свежесть обновлений' '18.x' 'UNKNOWN' 'Нет данных' }
} catch { Add-Check $cat 'Свежесть обновлений' '18.x' 'UNKNOWN' 'Не удалось получить' }

# PowerShell Script Block Logging
$sbl = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
if ($sbl -eq 1) { Add-Check $cat 'PowerShell: логирование блоков' '18.9.100.x' 'PASS' 'Включено' }
else { Add-Check $cat 'PowerShell: логирование блоков' '18.9.100.x' 'WARN' 'Выключено — не видно, что выполняли злоумышленники' 'GPO: Turn on PowerShell Script Block Logging' }

# Аудит создания процессов с командной строкой
$cmdAudit = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
if ($cmdAudit -eq 1) { Add-Check $cat 'Аудит: командная строка процессов' '18.9.3.x' 'PASS' 'Включён' }
else { Add-Check $cat 'Аудит: командная строка процессов' '18.9.3.x' 'WARN' 'Выключен — в логах не видно аргументов запуска' 'GPO: Include command line in process creation events' }

# ==================== КОНСОЛЬ ====================
$color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; UNKNOWN = 'DarkGray' }
$curCat = ''
foreach ($c in $checks) {
    if ($c.Category -ne $curCat) { Write-Host "`n-- $($c.Category) --" -ForegroundColor White; $curCat = $c.Category }
    Write-Host ("  [{0,-7}] {1}" -f $c.Verdict, $c.Name) -ForegroundColor $color[$c.Verdict]
}

# ==================== ОЦЕНКА ====================
$scored = @($checks | Where-Object { $_.Verdict -ne 'UNKNOWN' })
$pass = @($scored | Where-Object Verdict -eq 'PASS').Count
$score = if ($scored.Count) { [math]::Round($pass / $scored.Count * 100) } else { 0 }
$fail = @($checks | Where-Object Verdict -eq 'FAIL').Count
$warn = @($checks | Where-Object Verdict -eq 'WARN').Count
$scoreColor = if ($score -ge 80) { '#10b981' } elseif ($score -ge 60) { '#f59e0b' } else { '#ef4444' }

# ==================== HTML ====================
$style = @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f9fafb; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  .meta { color: #6b7280; font-size: 13px; margin-bottom: 16px; }
  .score { display: inline-flex; align-items: center; gap: 14px; background: #fff; border: 1px solid #e5e7eb;
           border-radius: 12px; padding: 14px 22px; margin-bottom: 18px; }
  .score .num { font-size: 40px; font-weight: 700; color: $scoreColor; }
  .score .lbl { color: #6b7280; font-size: 13px; }
  h2 { font-size: 15px; margin-top: 22px; color: #374151; }
  table { border-collapse: collapse; width: 100%; background: #fff; margin-top: 6px; }
  th, td { border: 1px solid #e5e7eb; padding: 7px 11px; text-align: left; font-size: 13px; vertical-align: top; }
  th { background: #f3f4f6; }
  .v { display: inline-block; min-width: 58px; text-align: center; padding: 2px 8px; border-radius: 8px; color: #fff; font-weight: 600; font-size: 12px; }
  .PASS { background: #10b981; } .WARN { background: #f59e0b; } .FAIL { background: #ef4444; } .UNKNOWN { background: #9ca3af; }
  .cis { color: #9ca3af; font-size: 11px; }
  .fix { color: #2563eb; font-size: 12px; }
</style>
"@

$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append("<h1>Аудит защищённости — $env:COMPUTERNAME</h1>")
[void]$sb.Append("<div class='meta'>Сформировано: $(Get-Date -Format 'dd.MM.yyyy HH:mm') · по мотивам CIS Benchmark</div>")
[void]$sb.Append("<div class='score'><div class='num'>$score%</div><div class='lbl'>защищённость<br>PASS $pass из $($scored.Count) · <b style='color:#ef4444'>FAIL $fail</b> · <b style='color:#f59e0b'>WARN $warn</b></div></div>")

foreach ($grp in $checks | Group-Object Category) {
    [void]$sb.Append("<h2>$($grp.Name)</h2><table><tr><th>Проверка</th><th>CIS</th><th>Вердикт</th><th>Детали</th><th>Как исправить</th></tr>")
    foreach ($c in $grp.Group) {
        [void]$sb.Append("<tr><td>$($c.Name)</td><td class='cis'>$($c.CIS)</td><td><span class='v $($c.Verdict)'>$($c.Verdict)</span></td><td>$($c.Detail)</td><td class='fix'>$($c.Fix)</td></tr>")
    }
    [void]$sb.Append("</table>")
}

"<!DOCTYPE html><html><head><meta charset='utf-8'>$style</head><body>$($sb.ToString())</body></html>" |
    Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "`n=== Оценка защищённости: $score% (PASS $pass/$($scored.Count), FAIL $fail, WARN $warn) ===" -ForegroundColor Cyan
Write-Host "[OK] Отчёт: $ReportPath" -ForegroundColor Green
