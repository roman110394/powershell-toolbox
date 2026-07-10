<#
.SYNOPSIS
    Напоминание о скором истечении пароля AD — в Telegram и/или сводкой админу.

.DESCRIPTION
    Находит доменных пользователей, у которых пароль истекает в ближайшие N дней,
    и отправляет уведомление в Telegram-чат. Удобно повесить на планировщик задач
    (раз в сутки утром) — пользователи меняют пароль заранее, а не в момент блокировки.

    Учитывает доменную политику максимального возраста пароля и игнорирует учётки
    с флагом «пароль не истекает».

    Токен бота и chat_id НЕ хранятся в скрипте — берутся из параметров или
    переменных окружения TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID.

.PARAMETER DaysBefore
    За сколько дней до истечения начинать напоминать. По умолчанию 7.

.PARAMETER BotToken
    Токен Telegram-бота. По умолчанию из $env:TELEGRAM_BOT_TOKEN.

.PARAMETER ChatId
    ID чата/канала. По умолчанию из $env:TELEGRAM_CHAT_ID.

.PARAMETER SearchBase
    Ограничить конкретным OU (DistinguishedName). По умолчанию — весь домен.

.PARAMETER WhatIf
    Ничего не отправлять — только показать, кому бы ушло напоминание.

.EXAMPLE
    $env:TELEGRAM_BOT_TOKEN = "123:ABC"
    $env:TELEGRAM_CHAT_ID   = "-1001234567890"
    .\Send-PasswordExpiryReminder.ps1 -DaysBefore 5

.NOTES
    Требуется модуль ActiveDirectory (RSAT).
#>
param(
    [int]$DaysBefore = 7,
    [string]$BotToken = $env:TELEGRAM_BOT_TOKEN,
    [string]$ChatId   = $env:TELEGRAM_CHAT_ID,
    [string]$SearchBase,
    [switch]$WhatIf
)

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $WhatIf) {
    if (-not $BotToken) { throw "Не задан токен: -BotToken или TELEGRAM_BOT_TOKEN" }
    if (-not $ChatId)   { throw "Не задан чат: -ChatId или TELEGRAM_CHAT_ID" }
}

# Максимальный возраст пароля из доменной политики
$maxAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
if ($maxAge.TotalDays -le 0) {
    throw "В домене не задан максимальный возраст пароля (пароли не истекают)."
}

$base = @{}
if ($SearchBase) { $base.SearchBase = $SearchBase }

$users = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $false } `
    -Properties PasswordLastSet, EmailAddress, DisplayName @base

$now = Get-Date
$soon = foreach ($u in $users) {
    if (-not $u.PasswordLastSet) { continue }   # пароль ни разу не менялся — пропускаем
    $expiry = $u.PasswordLastSet + $maxAge
    $daysLeft = [math]::Floor(($expiry - $now).TotalDays)
    if ($daysLeft -ge 0 -and $daysLeft -le $DaysBefore) {
        [pscustomobject]@{
            Name     = $u.DisplayName
            Login    = $u.SamAccountName
            Expiry   = $expiry
            DaysLeft = $daysLeft
        }
    }
}

$soon = @($soon | Sort-Object DaysLeft)

if (-not $soon.Count) {
    Write-Host "Нет пользователей с истекающим паролем в ближайшие $DaysBefore дн." -ForegroundColor Green
    return
}

Write-Host "Пароль истекает в ближайшие $DaysBefore дн. — $($soon.Count) чел.:" -ForegroundColor Yellow
$soon | Format-Table Name, Login, @{n='Дней';e={$_.DaysLeft}}, @{n='Истекает';e={$_.Expiry.ToString('dd.MM.yyyy')}} -AutoSize

if ($WhatIf) {
    Write-Host "`n[WhatIf] Сообщения не отправлены." -ForegroundColor Cyan
    return
}

# --- Отправка сводки в Telegram ---
$lines = $soon | ForEach-Object {
    $word = switch ($_.DaysLeft) { 0 {'сегодня'} 1 {'завтра'} default {"через $($_.DaysLeft) дн."} }
    "• $($_.Name) ($($_.Login)) — $word"
}
$text = "🔐 Пароли истекают:`n" + ($lines -join "`n")

$api = "https://api.telegram.org/bot$BotToken/sendMessage"
try {
    Invoke-RestMethod -Uri $api -Method Post -Body @{ chat_id = $ChatId; text = $text } | Out-Null
    Write-Host "`nСводка отправлена в Telegram." -ForegroundColor Green
} catch {
    Write-Host "`nНе удалось отправить в Telegram: $($_.Exception.Message)" -ForegroundColor Red
}
