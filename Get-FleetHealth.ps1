<#
.SYNOPSIS
    Сводка здоровья всего парка серверов одной таблицей: диски, память, аптайм, службы.

.DESCRIPTION
    Обходит серверы (список из AD автоматически или заданный руками) и собирает
    по каждому: свободное место на дисках, загрузку памяти, аптайм и число
    авто-служб в состоянии «остановлена». Результат — одна сводная HTML-таблица,
    где проблемные серверы подсвечены, плюс таблица в консоли.

    Утренний ритуал админа: один запуск — и видно, где горит, без RDP на каждый сервер.

.PARAMETER ComputerName
    Список хостов. Если не задан — берутся все включённые серверы из AD
    (OperatingSystem -like '*Server*').

.PARAMETER Credential
    Учётные данные для опроса (по умолчанию — текущая сессия).

.PARAMETER DiskWarnPercent
    Порог свободного места, ниже которого диск считается проблемой. По умолчанию 15.

.PARAMETER MemWarnPercent
    Порог загрузки памяти, выше которого — проблема. По умолчанию 90.

.PARAMETER UptimeWarnDays
    Аптайм больше этого числа дней помечается (сервер давно не видел обновлений).
    По умолчанию 60.

.PARAMETER ReportPath
    Куда сохранить HTML. По умолчанию FleetHealth_<дата>.html в текущей папке.

.EXAMPLE
    .\Get-FleetHealth.ps1
    Все серверы из AD, текущая учётка.

.EXAMPLE
    .\Get-FleetHealth.ps1 -ComputerName SRV-DC01, SRV-FS01, SRV-APP01 -UptimeWarnDays 90

.NOTES
    Для автосписка нужен модуль ActiveDirectory (RSAT); при явном -ComputerName
    AD не требуется. Опрос через CIM/DCOM — работает и там, где нет WinRM.
#>
param(
    [string[]]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$DiskWarnPercent = 15,
    [int]$MemWarnPercent = 90,
    [int]$UptimeWarnDays = 60,
    [string]$ReportPath
)

if (-not $ReportPath) {
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ReportPath = Join-Path $baseDir ("FleetHealth_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmm'))
}

# ---- Список серверов ----
if (-not $ComputerName) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ComputerName = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Server*' } `
        -Properties OperatingSystem | Select-Object -ExpandProperty Name | Sort-Object
    if (-not $ComputerName) { throw "В AD не найдено включённых серверов." }
    Write-Host "[*] Из AD получено серверов: $($ComputerName.Count)" -ForegroundColor Cyan
}

$cimOpt = New-CimSessionOption -Protocol Dcom

$results = foreach ($srv in $ComputerName) {
    Write-Host ("  {0,-20}" -f $srv) -NoNewline

    $row = [pscustomobject]@{
        Server   = $srv
        Status   = 'OK'
        OS       = ''
        UptimeD  = $null
        MemUsedP = $null
        Disks    = ''      # худшие диски текстом: "C: 6% · D: 12%"
        DeadSvc  = $null
        Problems = [System.Collections.Generic.List[string]]::new()
    }

    $session = $null
    try {
        $csParams = @{ ComputerName = $srv; SessionOption = $cimOpt; OperationTimeoutSec = 10; ErrorAction = 'Stop' }
        if ($Credential) { $csParams.Credential = $Credential }
        $session = New-CimSession @csParams

        $os = Get-CimInstance -CimSession $session Win32_OperatingSystem -ErrorAction Stop
        $row.OS      = ($os.Caption -replace 'Майкрософт |Microsoft ', '')
        $row.UptimeD = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        $row.MemUsedP = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100)

        $disks = Get-CimInstance -CimSession $session Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{ D = $_.DeviceID; FreeP = if ($_.Size) { [math]::Round($_.FreeSpace / $_.Size * 100) } else { 0 } }
            }
        $row.Disks = ($disks | ForEach-Object { "$($_.D) $($_.FreeP)%" }) -join ' · '

        $row.DeadSvc = @(Get-CimInstance -CimSession $session Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }).Count

        # ---- оценка проблем ----
        foreach ($d in $disks) {
            if ($d.FreeP -lt $DiskWarnPercent) { $row.Problems.Add("диск $($d.D) — $($d.FreeP)% свободно") }
        }
        if ($row.MemUsedP -ge $MemWarnPercent) { $row.Problems.Add("память $($row.MemUsedP)%") }
        if ($row.UptimeD -ge $UptimeWarnDays)  { $row.Problems.Add("аптайм $([int]$row.UptimeD) дн. — обновления?") }
        if ($row.DeadSvc -gt 0)                { $row.Problems.Add("$($row.DeadSvc) авто-служб остановлено") }

        if ($row.Problems.Count) { $row.Status = 'WARN' }
        Write-Host ("  {0}" -f $(if ($row.Status -eq 'OK') { 'OK' } else { $row.Problems -join '; ' })) `
            -ForegroundColor $(if ($row.Status -eq 'OK') { 'Green' } else { 'Yellow' })
    } catch {
        $row.Status = 'DOWN'
        $row.Problems.Add("недоступен: $($_.Exception.Message.Split("`n")[0])")
        Write-Host "  НЕДОСТУПЕН" -ForegroundColor Red
    } finally {
        if ($session) { Remove-CimSession $session -ErrorAction SilentlyContinue }
    }

    $row
}

# ---- Консольная сводка ----
$results | Sort-Object { switch ($_.Status) { 'DOWN' {0} 'WARN' {1} default {2} } } |
    Format-Table Server, Status, OS,
        @{n='Аптайм, дн';e={$_.UptimeD}},
        @{n='RAM, %';e={$_.MemUsedP}},
        @{n='Диски';e={$_.Disks}},
        @{n='Проблемы';e={$_.Problems -join '; '}} -AutoSize -Wrap

# ---- HTML ----
$style = @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f9fafb; }
  h1 { font-size: 22px; } .meta { color: #6b7280; font-size: 13px; margin-bottom: 14px; }
  table { border-collapse: collapse; width: 100%; background: #fff; }
  th, td { border: 1px solid #e5e7eb; padding: 7px 10px; text-align: left; font-size: 13px; }
  th { background: #f3f4f6; }
  tr.warn td { background: #fffbeb; }
  tr.down td { background: #fef2f2; }
  .badge { display: inline-block; padding: 1px 10px; border-radius: 10px; color: #fff; font-size: 12px; font-weight: 600; }
  .ok { background: #10b981; } .warn { background: #f59e0b; } .down { background: #ef4444; }
  .problems { color: #b91c1c; }
</style>
"@

$order = @{ DOWN = 0; WARN = 1; OK = 2 }
$rowsHtml = ($results | Sort-Object { $order[$_.Status] } | ForEach-Object {
    $cls = switch ($_.Status) { 'WARN' { " class='warn'" } 'DOWN' { " class='down'" } default { '' } }
    $badge = "<span class='badge $($_.Status.ToLower())'>$($_.Status)</span>"
    "<tr$cls><td>$($_.Server)</td><td>$badge</td><td>$($_.OS)</td><td>$($_.UptimeD)</td><td>$($_.MemUsedP)</td><td>$($_.Disks)</td><td>$($_.DeadSvc)</td><td class='problems'>$($_.Problems -join '; ')</td></tr>"
}) -join "`n"

$okCount = @($results | Where-Object Status -eq 'OK').Count
$warnCount = @($results | Where-Object Status -eq 'WARN').Count
$downCount = @($results | Where-Object Status -eq 'DOWN').Count

$body = @"
<h1>Здоровье парка серверов</h1>
<div class='meta'>Сформировано: $(Get-Date -Format 'dd.MM.yyyy HH:mm') ·
Всего: $(@($results).Count) · <b style='color:#10b981'>OK: $okCount</b> ·
<b style='color:#f59e0b'>Внимание: $warnCount</b> · <b style='color:#ef4444'>Недоступно: $downCount</b></div>
<table>
<tr><th>Сервер</th><th>Статус</th><th>ОС</th><th>Аптайм, дн</th><th>RAM, %</th><th>Диски (свободно)</th><th>Мёртвых служб</th><th>Проблемы</th></tr>
$rowsHtml
</table>
"@

"<!DOCTYPE html><html><head><meta charset='utf-8'>$style</head><body>$body</body></html>" |
    Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "[OK] Отчёт: $ReportPath" -ForegroundColor Green
