<#
.SYNOPSIS
    История входов/выходов Windows из журнала безопасности → таблица / CSV / HTML.

.DESCRIPTION
    Разбирает журнал «Безопасность» (Security) и показывает, кто и когда входил:
    события 4624 (успешный вход) и, по желанию, 4634/4647 (выход). По умолчанию
    показывает только «человеческие» входы — интерактивный (консоль), RDP и
    разблокировку — а шумные сетевые входы (доступ к шарам, тип 3) пропускает.

    Отвечает на вечный вопрос «кто заходил на этот сервер и когда».

    Быстрый: фильтрует по типу входа на стороне журнала (XPath) и ограничивает
    число событий — не виснет даже на нагруженном сервере с гигантским логом.

.PARAMETER Days
    За сколько последних дней смотреть журнал. По умолчанию 7.

.PARAMETER User
    Фильтр по имени пользователя (подстрока). По умолчанию — все.

.PARAMETER IncludeNetwork
    Также показывать сетевые входы (тип 3) — на серверах их очень много (доступ
    к общим папкам). По умолчанию выключено.

.PARAMETER IncludeLogoff
    Также показывать события выхода (4634/4647). По умолчанию только входы.

.PARAMETER MaxEvents
    Ограничение на число прочитанных событий (защита от гигантских логов).
    По умолчанию 3000 (самые свежие).

.PARAMETER ComputerName
    С какой машины читать журнал. По умолчанию — локальная.

.PARAMETER Csv
    Также сохранить результат в CSV рядом со скриптом.

.PARAMETER Html
    Также сохранить HTML-отчёт.

.EXAMPLE
    .\Get-LoginHistory.ps1 -Days 3
    Консольные и RDP-входы за 3 дня.

.EXAMPLE
    .\Get-LoginHistory.ps1 -User ivanov -Days 30 -Html
    Входы пользователя ivanov за месяц + HTML-отчёт.

.NOTES
    Нужны права на чтение журнала безопасности (администратор).
    Совместимо с Windows PowerShell 5.1. Только чтение.
#>
param(
    [int]$Days = 7,
    [string]$User,
    [switch]$IncludeNetwork,
    [switch]$IncludeLogoff,
    [int]$MaxEvents = 3000,
    [string]$ComputerName = $env:COMPUTERNAME,
    [switch]$Csv,
    [switch]$Html
)

$baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$logonTypeName = @{
    2  = 'Интерактивный'; 3 = 'Сеть'; 4 = 'Пакетный'; 5 = 'Служба'
    7  = 'Разблокировка'; 8 = 'Сеть (открытый)'; 9 = 'Новые уч.данные'
    10 = 'RDP'; 11 = 'Кэш'
}

# какие типы входа показываем
$types = if ($IncludeNetwork) { 2, 3, 7, 8, 10, 11 } else { 2, 7, 10, 11 }

$isLocal = $ComputerName -in @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
$remoteParams = @{}
if (-not $isLocal) { $remoteParams.ComputerName = $ComputerName }

$ms = [long]$Days * 86400 * 1000

Write-Host "[*] Чтение журнала безопасности $ComputerName за $Days дн. (лимит $MaxEvents событий) ..." -ForegroundColor Cyan

# XPath: фильтруем тип входа на стороне журнала — иначе на сервере тянутся сотни тысяч событий
$typeClause = ($types | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or '
$xpLogon = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[$typeClause]]"

function Read-Events([string]$XPath) {
    try {
        Get-WinEvent -LogName Security -FilterXPath $XPath -MaxEvents $MaxEvents @remoteParams -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -match 'No events were found') { return @() }
        throw
    }
}

try {
    $logonEvents = @(Read-Events $xpLogon)
    $logoffEvents = @()
    if ($IncludeLogoff) {
        $xpLogoff = "*[System[(EventID=4634 or EventID=4647) and TimeCreated[timediff(@SystemTime) <= $ms]]]"
        $logoffEvents = @(Read-Events $xpLogoff)
    }
} catch {
    Write-Host "[!] Не удалось прочитать журнал: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Запустите PowerShell от администратора." -ForegroundColor Yellow
    return
}

$noise = 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', 'DWM-*', 'UMFD-*', '*$'
function Is-Noise([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $true }
    foreach ($p in $noise) { if ($name -like $p) { return $true } }
    return $false
}

# Быстрое чтение полей по индексам свойств (без разбора XML) — на порядок быстрее
$rows = foreach ($e in $logonEvents) {
    $p = $e.Properties
    if ($p.Count -lt 19) { continue }
    $name = [string]$p[5].Value           # TargetUserName
    if (Is-Noise $name) { continue }
    if ($User -and $name -notlike "*$User*") { continue }
    $lt = [int]$p[8].Value                 # LogonType
    $ip = [string]$p[18].Value             # IpAddress
    [pscustomobject]@{
        Время    = $e.TimeCreated
        Действие = 'Вход'
        Пользователь = $name
        Домен    = [string]$p[6].Value
        Тип      = if ($logonTypeName.ContainsKey($lt)) { $logonTypeName[$lt] } else { "Тип $lt" }
        Источник = if ($ip -and $ip -notin @('-', '::1', '127.0.0.1')) { $ip } else { '' }
    }
}

$rows += foreach ($e in $logoffEvents) {
    $p = $e.Properties
    if ($p.Count -lt 2) { continue }
    $name = [string]$p[1].Value            # TargetUserName
    if (Is-Noise $name) { continue }
    if ($User -and $name -notlike "*$User*") { continue }
    [pscustomobject]@{
        Время    = $e.TimeCreated
        Действие = 'Выход'
        Пользователь = $name
        Домен    = [string]$p[2].Value
        Тип      = ''
        Источник = ''
    }
}

$rows = @($rows | Sort-Object Время -Descending)

if (-not $rows.Count) {
    Write-Host "Событий входа не найдено за указанный период." -ForegroundColor Yellow
    return
}

$rows | Format-Table Время, Действие, Пользователь, Домен, Тип, Источник -AutoSize

$logins = @($rows | Where-Object Действие -eq 'Вход').Count
Write-Host ("`n[OK] Событий: {0} (входов: {1}), уникальных пользователей: {2}" -f `
    $rows.Count, $logins, @($rows.Пользователь | Sort-Object -Unique).Count) -ForegroundColor Green
if ($logonEvents.Count -eq $MaxEvents) {
    Write-Host "[i] Достигнут лимит $MaxEvents — возможно, показаны не все. Увеличьте -MaxEvents или сузьте -Days." -ForegroundColor DarkYellow
}

if ($Csv) {
    $csvPath = Join-Path $baseDir ("LoginHistory_{0}_{1}.csv" -f $ComputerName, (Get-Date -Format 'yyyyMMdd'))
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "     CSV: $csvPath" -ForegroundColor Green
}

if ($Html) {
    $style = @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f9fafb; }
  h1 { font-size: 20px; } .meta { color: #6b7280; font-size: 13px; margin-bottom: 12px; }
  table { border-collapse: collapse; width: 100%; background: #fff; }
  th, td { border: 1px solid #e5e7eb; padding: 6px 10px; text-align: left; font-size: 13px; }
  th { background: #f3f4f6; }
  tr:nth-child(even) td { background: #fafafa; }
  .in { color: #059669; font-weight: 600; } .out { color: #9ca3af; }
</style>
"@
    $rowsHtml = ($rows | ForEach-Object {
        $cls = if ($_.Действие -eq 'Вход') { 'in' } else { 'out' }
        "<tr><td>$($_.Время.ToString('dd.MM HH:mm:ss'))</td><td class='$cls'>$($_.Действие)</td><td>$($_.Пользователь)</td><td>$($_.Домен)</td><td>$($_.Тип)</td><td>$($_.Источник)</td></tr>"
    }) -join "`n"
    $body = @"
<h1>История входов — $ComputerName</h1>
<div class='meta'>За $Days дн. · событий: $($rows.Count) · входов: $logins · $(Get-Date -Format 'dd.MM.yyyy HH:mm')</div>
<table><tr><th>Время</th><th>Действие</th><th>Пользователь</th><th>Домен</th><th>Тип</th><th>Источник</th></tr>
$rowsHtml
</table>
"@
    $htmlPath = Join-Path $baseDir ("LoginHistory_{0}_{1}.html" -f $ComputerName, (Get-Date -Format 'yyyyMMdd'))
    "<!DOCTYPE html><html><head><meta charset='utf-8'>$style</head><body>$body</body></html>" |
        Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "     HTML: $htmlPath" -ForegroundColor Green
}
