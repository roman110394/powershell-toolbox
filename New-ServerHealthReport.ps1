<#
.SYNOPSIS
    HTML-дашборд состояния сервера/ПК: диски, память, аптайм, процессы, службы.

.DESCRIPTION
    Собирает ключевые показатели машины и складывает в самодостаточный HTML-отчёт
    (без внешних зависимостей и интернета). Диски с малым свободным местом
    подсвечиваются; показываются службы в статусе «должна работать, но остановлена».

    Работает локально или по сети (-ComputerName). Только чтение.

.PARAMETER ComputerName
    Имя целевой машины. По умолчанию — локальная (localhost).

.PARAMETER ReportPath
    Куда сохранить HTML. По умолчанию Health_<имя>_<дата>.html рядом со скриптом.

.PARAMETER DiskWarnPercent
    Порог подсветки диска (процент свободного). По умолчанию 15.

.PARAMETER TopProcesses
    Сколько процессов показать в топе по памяти. По умолчанию 10.

.EXAMPLE
    .\New-ServerHealthReport.ps1
    Отчёт по текущей машине.

.EXAMPLE
    .\New-ServerHealthReport.ps1 -ComputerName SRV-DC01 -DiskWarnPercent 20

.NOTES
    Совместимо с Windows PowerShell 5.1. Для удалённого сбора нужны права
    администратора на целевой машине (CIM/WinRM).
#>
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$ReportPath,
    [int]$DiskWarnPercent = 15,
    [int]$TopProcesses = 10
)

if (-not $ReportPath) {
    $ReportPath = Join-Path $PSScriptRoot ("Health_{0}_{1}.html" -f $ComputerName, (Get-Date -Format 'yyyyMMdd'))
}

$isLocal = $ComputerName -in @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
$cimParams = @{ ErrorAction = 'Stop' }
if (-not $isLocal) { $cimParams.ComputerName = $ComputerName }

Write-Host "[*] Сбор данных с $ComputerName ..." -ForegroundColor Cyan

$os  = Get-CimInstance Win32_OperatingSystem @cimParams
$cs  = Get-CimInstance Win32_ComputerSystem @cimParams
$cpu = Get-CimInstance Win32_Processor @cimParams | Select-Object -First 1

$uptime   = (Get-Date) - $os.LastBootUpTime
$memTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)   # значения в КБ → ГБ
$memFree  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$memUsedP = [math]::Round(($memTotal - $memFree) / $memTotal * 100)

# --- Диски ---
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" @cimParams | ForEach-Object {
    $totalGb = [math]::Round($_.Size / 1GB, 1)
    $freeGb  = [math]::Round($_.FreeSpace / 1GB, 1)
    $freeP   = if ($_.Size) { [math]::Round($_.FreeSpace / $_.Size * 100) } else { 0 }
    [pscustomobject]@{
        Диск = $_.DeviceID; 'Всего, ГБ' = $totalGb; 'Свободно, ГБ' = $freeGb
        'Свободно, %' = $freeP; Warn = ($freeP -lt $DiskWarnPercent)
    }
}

# --- Топ процессов по памяти ---
$procParams = @{ ErrorAction = 'SilentlyContinue' }
if (-not $isLocal) { $procParams.ComputerName = $ComputerName }
$topProc = Get-Process @procParams | Sort-Object WorkingSet64 -Descending | Select-Object -First $TopProcesses |
    Select-Object Name, Id, @{n='Память, МБ';e={[math]::Round($_.WorkingSet64/1MB)}}

# --- Службы: авто-запуск, но остановлены ---
$svc = Get-CimInstance Win32_Service @cimParams |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } |
    Select-Object @{n='Служба';e={$_.DisplayName}}, Name, @{n='Состояние';e={$_.State}}

# ---------- HTML ----------
$style = @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f9fafb; }
  h1 { font-size: 22px; } h2 { font-size: 16px; margin-top: 26px; }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 18px; min-width: 150px; }
  .card .label { color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  .card .value { font-size: 20px; font-weight: 600; margin-top: 4px; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; background: #fff; }
  th, td { border: 1px solid #e5e7eb; padding: 6px 10px; text-align: left; font-size: 13px; }
  th { background: #f3f4f6; }
  tr.warn td { background: #fef2f2; color: #b91c1c; font-weight: 600; }
  .empty { color: #10b981; font-size: 13px; margin-top: 8px; }
  .meta { color: #6b7280; font-size: 13px; }
</style>
"@

$diskRows = ($disks | ForEach-Object {
    $cls = if ($_.Warn) { " class='warn'" } else { "" }
    "<tr$cls><td>$($_.'Диск')</td><td>$($_.'Всего, ГБ')</td><td>$($_.'Свободно, ГБ')</td><td>$($_.'Свободно, %')%</td></tr>"
}) -join "`n"

$body = @"
<h1>Отчёт о состоянии — $ComputerName</h1>
<div class='meta'>Сформировано: $(Get-Date -Format 'dd.MM.yyyy HH:mm')</div>
<div class='cards'>
  <div class='card'><div class='label'>ОС</div><div class='value' style='font-size:14px'>$($os.Caption)</div></div>
  <div class='card'><div class='label'>Аптайм</div><div class='value'>$($uptime.Days)д $($uptime.Hours)ч</div></div>
  <div class='card'><div class='label'>Память</div><div class='value'>$memUsedP% из $memTotal ГБ</div></div>
  <div class='card'><div class='label'>CPU</div><div class='value' style='font-size:14px'>$($cpu.Name.Trim())</div></div>
  <div class='card'><div class='label'>Модель</div><div class='value' style='font-size:14px'>$($cs.Manufacturer) $($cs.Model)</div></div>
</div>

<h2>Диски</h2>
<table><tr><th>Диск</th><th>Всего, ГБ</th><th>Свободно, ГБ</th><th>Свободно, %</th></tr>
$diskRows
</table>

<h2>Топ-$TopProcesses процессов по памяти</h2>
$($topProc | ConvertTo-Html -Fragment)

<h2>Службы: автозапуск, но не работают ($(@($svc).Count))</h2>
$(if (@($svc).Count) { $svc | ConvertTo-Html -Fragment } else { "<div class='empty'>Все авто-службы работают ✓</div>" })
"@

"<!DOCTYPE html><html><head><meta charset='utf-8'>$style</head><body>$body</body></html>" |
    Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "[OK] Отчёт сохранён: $ReportPath" -ForegroundColor Green
$warnDisks = @($disks | Where-Object Warn)
if ($warnDisks.Count) {
    Write-Host ("[!] Мало места: {0}" -f (($warnDisks | ForEach-Object { "$($_.Диск) $($_.'Свободно, %')%" }) -join ', ')) -ForegroundColor Red
}
if ($isLocal) { Invoke-Item $ReportPath }
