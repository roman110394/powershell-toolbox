<#
.SYNOPSIS
    История входов/выходов Windows из журнала безопасности → таблица / CSV / HTML.

.DESCRIPTION
    Разбирает журнал «Безопасность» (Security) и показывает, кто и когда входил
    и выходил: события 4624 (успешный вход) и 4634/4647 (выход). Отсеивает
    системный шум (SYSTEM, LOCAL SERVICE, DWM/UMFD и т.п.), показывает тип входа
    (интерактивный, RDP, сеть) и адрес источника.

    Отвечает на вечный вопрос «кто заходил на этот сервер и когда».

.PARAMETER Days
    За сколько последних дней смотреть журнал. По умолчанию 7.

.PARAMETER User
    Фильтр по имени пользователя (подстрока). По умолчанию — все.

.PARAMETER LogonTypesOnly
    Показывать только эти типы входа. По умолчанию — интерактивный (2),
    сетевой (3), RDP (10). Например: -LogonTypesOnly 2,10 — только консоль и RDP.

.PARAMETER ComputerName
    С какой машины читать журнал. По умолчанию — локальная.

.PARAMETER Csv
    Также сохранить результат в CSV рядом со скриптом.

.PARAMETER Html
    Также сохранить HTML-отчёт.

.EXAMPLE
    .\Get-LoginHistory.ps1 -Days 3
    Кто входил за последние 3 дня.

.EXAMPLE
    .\Get-LoginHistory.ps1 -User ivanov -Days 30 -Html
    Все входы пользователя ivanov за месяц + HTML-отчёт.

.NOTES
    Нужны права на чтение журнала безопасности (обычно администратор).
    Совместимо с Windows PowerShell 5.1. Только чтение.
#>
param(
    [int]$Days = 7,
    [string]$User,
    [int[]]$LogonTypesOnly = @(2, 3, 10),
    [string]$ComputerName = $env:COMPUTERNAME,
    [switch]$Csv,
    [switch]$Html
)

$baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$start = (Get-Date).AddDays(-$Days)

$logonTypeName = @{
    2  = 'Интерактивный'; 3 = 'Сеть'; 4 = 'Пакетный'; 5 = 'Служба'
    7  = 'Разблокировка'; 8 = 'Сеть (открытый)'; 9 = 'Новые уч.данные'
    10 = 'RDP'; 11 = 'Кэш'
}

# служебные «пользователи», которые только зашумляют картину
$noise = 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', 'DWM-*', 'UMFD-*', '*$'

Write-Host "[*] Чтение журнала безопасности $ComputerName за $Days дн. ..." -ForegroundColor Cyan

$filter = @{ LogName = 'Security'; Id = 4624, 4634, 4647; StartTime = $start }
$evtParams = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
if ($ComputerName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')) { $evtParams.ComputerName = $ComputerName }

try {
    $events = Get-WinEvent @evtParams
} catch {
    Write-Host "[!] Не удалось прочитать журнал: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Нужны права администратора; убедитесь, что журнал 'Безопасность' не пуст." -ForegroundColor Yellow
    return
}

$rows = foreach ($e in $events) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    if ($e.Id -eq 4624) {
        $lt = [int]$d['LogonType']
        if ($LogonTypesOnly -and ($lt -notin $LogonTypesOnly)) { continue }
        $name = $d['TargetUserName']
        $action = 'Вход'
        $type = if ($logonTypeName.ContainsKey($lt)) { $logonTypeName[$lt] } else { "Тип $lt" }
        $src = $d['IpAddress']
    } else {
        $name = $d['TargetUserName']
        $action = 'Выход'
        $type = ''
        $src = ''
    }

    # отсев служебного шума
    $skip = $false
    foreach ($p in $noise) { if ($name -like $p) { $skip = $true; break } }
    if ($skip -or [string]::IsNullOrWhiteSpace($name)) { continue }
    if ($User -and $name -notlike "*$User*") { continue }

    [pscustomobject]@{
        Время    = $e.TimeCreated
        Действие = $action
        Пользователь = $name
        Домен    = $d['TargetDomainName']
        Тип      = $type
        Источник = if ($src -and $src -ne '-' -and $src -ne '::1' -and $src -ne '127.0.0.1') { $src } else { '' }
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
