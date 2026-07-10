<#
.SYNOPSIS
    Аудит здоровья Active Directory одним запуском → HTML-отчёт.

.DESCRIPTION
    Собирает типовые проблемы домена и складывает в наглядный самодостаточный
    HTML-файл (без внешних зависимостей — можно открыть где угодно, отправить почтой):

      * Неактивные пользователи (нет входа N дней, но учётка включена)
      * Пароли с флагом «никогда не истекает»
      * Учётки с флагом «пароль не требуется»
      * Заблокированные учётные записи
      * Просроченные учётки
      * Состав привилегированных групп (Domain/Enterprise/Schema Admins)
      * Неактивные компьютеры (нет регистрации N дней)

    Только чтение — скрипт ничего не меняет в домене.

.PARAMETER InactiveDays
    Порог неактивности для пользователей и компьютеров. По умолчанию 90.

.PARAMETER ReportPath
    Куда сохранить HTML. По умолчанию AD-Audit_<дата>.html рядом со скриптом.

.PARAMETER SearchBase
    Ограничить аудит конкретным OU (DistinguishedName). По умолчанию — весь домен.

.PARAMETER Demo
    Сформировать пример отчёта на вымышленных данных (contoso.local), без обращения
    к AD. Удобно посмотреть, что делает скрипт, на машине без домена.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -InactiveDays 60

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Demo
    Пример отчёта на вымышленных данных.

.NOTES
    Требуется модуль ActiveDirectory (RSAT). Права обычного доменного пользователя
    достаточно для чтения. Запускать на DC или машине с RSAT.
#>
param(
    [int]$InactiveDays = 90,
    [string]$ReportPath,
    [string]$SearchBase,
    [switch]$Demo   # показать пример отчёта на вымышленных данных, без обращения к AD
)

if (-not $Demo) { Import-Module ActiveDirectory -ErrorAction Stop }

if (-not $ReportPath) {
    # $PSScriptRoot пуст при запуске из памяти (irm | iex) — тогда пишем в текущую папку
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $suffix = if ($Demo) { 'Demo' } else { Get-Date -Format 'yyyyMMdd' }
    $ReportPath = Join-Path $baseDir ("AD-Audit_{0}.html" -f $suffix)
}

if ($Demo) {
    # --- Демо-данные (вымышленный домен, никаких реальных учёток) ---
    Write-Host "[*] Демо-режим: отчёт на вымышленных данных (contoso.local)" -ForegroundColor Cyan
    $domain = 'contoso.local'
    $inactiveUsers = @(
        [pscustomobject]@{ Name='Иван Петров'; SamAccountName='i.petrov'; 'Последний вход'=(Get-Date).AddDays(-142) }
        [pscustomobject]@{ Name='Ольга Смирнова'; SamAccountName='o.smirnova'; 'Последний вход'=(Get-Date).AddDays(-201) }
        [pscustomobject]@{ Name='Сергей Волков'; SamAccountName='s.volkov'; 'Последний вход'=(Get-Date).AddDays(-97) }
    )
    $pwdNeverExpires = @(
        [pscustomobject]@{ Name='Администратор'; SamAccountName='Administrator' }
        [pscustomobject]@{ Name='Сервис Бэкапа'; SamAccountName='svc-backup' }
        [pscustomobject]@{ Name='Пётр Иванов'; SamAccountName='p.ivanov' }
    )
    $pwdNotRequired = @(
        [pscustomobject]@{ Name='Терминал Касса'; SamAccountName='pos-terminal' }
    )
    $lockedOut = @(
        [pscustomobject]@{ Name='Анна Козлова'; SamAccountName='a.kozlova' }
    )
    $expired = @(
        [pscustomobject]@{ Name='Стажёр (уволен)'; SamAccountName='intern2025'; 'Истекла'=(Get-Date).AddDays(-30) }
    )
    $privMembers = @(
        [pscustomobject]@{ 'Группа'='Domain Admins'; 'Участник'='Администратор'; 'Логин'='Administrator'; 'Класс'='user' }
        [pscustomobject]@{ 'Группа'='Domain Admins'; 'Участник'='Пётр Иванов'; 'Логин'='p.ivanov'; 'Класс'='user' }
        [pscustomobject]@{ 'Группа'='Enterprise Admins'; 'Участник'='Администратор'; 'Логин'='Administrator'; 'Класс'='user' }
    )
    $inactiveComputers = @(
        [pscustomobject]@{ Name='WKS-042'; OperatingSystem='Windows 10 Pro'; 'Последняя регистрация'=(Get-Date).AddDays(-120) }
        [pscustomobject]@{ Name='SRV-OLD01'; OperatingSystem='Windows Server 2012 R2'; 'Последняя регистрация'=(Get-Date).AddDays(-380) }
    )
} else {
    $cutoff = (Get-Date).AddDays(-$InactiveDays)
    $base   = @{}
    if ($SearchBase) { $base.SearchBase = $SearchBase }

    Write-Host "[*] Сбор данных Active Directory (порог неактивности: $InactiveDays дн.)..." -ForegroundColor Cyan

    # --- Пользователи ---
    $allUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordNeverExpires, PasswordNotRequired,
        Enabled, LockedOut, AccountExpirationDate, whenCreated @base

    $inactiveUsers = $allUsers | Where-Object {
        $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff
    } | Select-Object Name, SamAccountName, @{n='Последний вход';e={$_.LastLogonDate}}

    $pwdNeverExpires = $allUsers | Where-Object { $_.Enabled -and $_.PasswordNeverExpires } |
        Select-Object Name, SamAccountName

    $pwdNotRequired = $allUsers | Where-Object { $_.Enabled -and $_.PasswordNotRequired } |
        Select-Object Name, SamAccountName

    $lockedOut = Search-ADAccount -LockedOut @base |
        Select-Object Name, SamAccountName

    $expired = Search-ADAccount -AccountExpired @base | Where-Object { $_.ObjectClass -eq 'user' } |
        Select-Object Name, SamAccountName, @{n='Истекла';e={$_.AccountExpirationDate}}

    # --- Привилегированные группы ---
    $privGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'
    $privMembers = foreach ($g in $privGroups) {
        try {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Группа = $g; Участник = $_.Name; Логин = $_.SamAccountName; Класс = $_.ObjectClass }
            }
        } catch {}
    }

    # --- Компьютеры ---
    $inactiveComputers = Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem, Enabled @base |
        Where-Object { $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff } |
        Select-Object Name, OperatingSystem, @{n='Последняя регистрация';e={$_.LastLogonDate}}

    $domain = (Get-ADDomain).DNSRoot
}

# ---------- Формирование HTML ----------
$style = @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f9fafb; }
  h1 { font-size: 22px; }
  h2 { font-size: 17px; margin-top: 28px; padding-bottom: 6px; border-bottom: 2px solid #e5e7eb; }
  .meta { color: #6b7280; font-size: 13px; margin-bottom: 8px; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; background: #fff; }
  th, td { border: 1px solid #e5e7eb; padding: 6px 10px; text-align: left; font-size: 13px; }
  th { background: #f3f4f6; }
  tr:nth-child(even) td { background: #fafafa; }
  .count { display: inline-block; min-width: 24px; padding: 1px 8px; border-radius: 10px;
           background: #ef4444; color: #fff; font-size: 12px; margin-left: 8px; }
  .count.ok { background: #10b981; }
  .empty { color: #10b981; font-size: 13px; margin-top: 8px; }
</style>
"@

function New-Section {
    param([string]$Title, $Data, [string]$EmptyText = 'Проблем не найдено ✓')
    $arr = @($Data)
    $badge = if ($arr.Count) { "<span class='count'>$($arr.Count)</span>" } else { "<span class='count ok'>0</span>" }
    $html = "<h2>$Title$badge</h2>"
    if ($arr.Count) {
        $html += ($arr | ConvertTo-Html -Fragment)
    } else {
        $html += "<div class='empty'>$EmptyText</div>"
    }
    $html
}

$body  = "<h1>Аудит Active Directory — $domain</h1>"
$body += "<div class='meta'>Сформировано: $(Get-Date -Format 'dd.MM.yyyy HH:mm') · Порог неактивности: $InactiveDays дней</div>"
$body += New-Section "Неактивные пользователи (вход давнее $InactiveDays дн.)" $inactiveUsers
$body += New-Section "Пароль никогда не истекает" $pwdNeverExpires
$body += New-Section "Пароль не требуется (PasswordNotRequired)" $pwdNotRequired
$body += New-Section "Заблокированные учётные записи" $lockedOut
$body += New-Section "Просроченные учётные записи" $expired
$body += New-Section "Участники привилегированных групп" $privMembers "Группы пусты (?)"
$body += New-Section "Неактивные компьютеры (регистрация давнее $InactiveDays дн.)" $inactiveComputers

"<!DOCTYPE html><html><head><meta charset='utf-8'>$style</head><body>$body</body></html>" |
    Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "[OK] Отчёт сохранён: $ReportPath" -ForegroundColor Green
Write-Host ("     Неактивных юзеров: {0} · Пароль без срока: {1} · Неактивных ПК: {2}" -f `
    @($inactiveUsers).Count, @($pwdNeverExpires).Count, @($inactiveComputers).Count) -ForegroundColor Yellow

# открыть в браузере
Invoke-Item $ReportPath
