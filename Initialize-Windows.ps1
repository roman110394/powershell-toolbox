<#
.SYNOPSIS
    Настройка свежей Windows одним запуском: софт, деблоат, приватность, твики.

.DESCRIPTION
    То, что админ делает руками на каждой новой машине, — собрано в один скрипт
    с понятными переключателями. Ничего не делает «молча»: по умолчанию сухой
    прогон (-WhatIf) показывает, что будет сделано, без изменений.

    Разделы (включаются флагами, или всё сразу через -All):
      -Apps     установка программ через winget (список свой или встроенный)
      -Debloat  удаление предустановленного мусора (Xbox, Bing, реклама и т.п.)
      -Privacy  отключение телеметрии, рекламного ID, «подобранного контента»
      -Tweaks   удобные мелочи: показ расширений и скрытых файлов, тёмная тема

    Все изменения — обратимые и консервативные: ничего критичного для работы
    системы не трогается.

.PARAMETER Apps
    Установить программы через winget.

.PARAMETER AppList
    Путь к txt со списком winget-ID (по одному в строке, # — комментарий).
    Если не задан — используется встроенный базовый набор.

.PARAMETER Debloat
    Удалить предустановленные приложения из встроенного списка «мусора».

.PARAMETER Privacy
    Применить настройки приватности (телеметрия, реклама, слежка).

.PARAMETER Tweaks
    Применить удобные твики Проводника и оформления.

.PARAMETER All
    Включить все разделы сразу.

.PARAMETER Apply
    Реально применить изменения. Без него скрипт работает в режиме предпросмотра
    (показывает, что сделал бы, но не меняет систему).

.EXAMPLE
    .\Initialize-Windows.ps1 -All
    Показать, что будет сделано во всех разделах (ничего не меняя).

.EXAMPLE
    .\Initialize-Windows.ps1 -All -Apply
    Применить всё: софт, деблоат, приватность, твики.

.EXAMPLE
    .\Initialize-Windows.ps1 -Apps -AppList .\my-apps.txt -Apply
    Поставить только программы из своего списка.

.NOTES
    Запускать в PowerShell от администратора. Деблоат/приватность/твики требуют
    прав администратора; установка софта — winget (App Installer из Microsoft Store).
    Windows 10/11. Совместимо с Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
    [switch]$Apps,
    [string]$AppList,
    [switch]$Debloat,
    [switch]$Privacy,
    [switch]$Tweaks,
    [switch]$All,
    [switch]$Apply
)

if ($All) { $Apps = $Debloat = $Privacy = $Tweaks = $true }
if (-not ($Apps -or $Debloat -or $Privacy -or $Tweaks)) {
    Write-Host "Не выбран ни один раздел. Укажите -Apps / -Debloat / -Privacy / -Tweaks или -All." -ForegroundColor Yellow
    Write-Host "Справка: Get-Help .\Initialize-Windows.ps1 -Full" -ForegroundColor Gray
    return
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$mode = if ($Apply) { 'ПРИМЕНЕНИЕ' } else { 'ПРЕДПРОСМОТР (изменений не будет)' }
Write-Host "=== Initialize-Windows · режим: $mode ===" -ForegroundColor Cyan
if ($Apply -and -not $isAdmin -and ($Debloat -or $Privacy -or $Tweaks)) {
    Write-Host "[!] Нужны права администратора для деблоата/приватности/твиков. Запустите PowerShell от админа." -ForegroundColor Red
    return
}

$log = [System.Collections.Generic.List[string]]::new()
function Do-Action {
    param([string]$Desc, [scriptblock]$Action)
    if ($Apply) {
        try { & $Action; Write-Host "  [OK]   $Desc" -ForegroundColor Green; $log.Add("OK   $Desc") }
        catch { Write-Host "  [FAIL] $Desc — $($_.Exception.Message)" -ForegroundColor Red; $log.Add("FAIL $Desc") }
    } else {
        Write-Host "  [ + ]  $Desc" -ForegroundColor DarkCyan; $log.Add("WOULD $Desc")
    }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# ============================ APPS ============================
if ($Apps) {
    Write-Host "`n-- Установка программ (winget) --" -ForegroundColor White

    $defaultApps = @(
        '7zip.7zip'                       # архиватор
        'Mozilla.Firefox'                 # браузер
        'Notepad++.Notepad++'             # редактор
        'VideoLAN.VLC'                    # медиаплеер
        'Microsoft.PowerToys'             # утилиты для Windows
        'Git.Git'                         # git
        'Microsoft.VisualStudioCode'      # редактор кода
        'Adobe.Acrobat.Reader.64-bit'     # PDF
        'Google.Chrome'                   # браузер
        'Microsoft.PowerShell'            # PowerShell 7
    )

    if ($AppList) {
        if (-not (Test-Path $AppList)) { Write-Host "  Файл списка не найден: $AppList" -ForegroundColor Red; return }
        $appIds = Get-Content $AppList | ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') }
    } else {
        $appIds = $defaultApps
    }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "  [!] winget не найден. Установите 'App Installer' из Microsoft Store." -ForegroundColor Red
    } else {
        foreach ($id in $appIds) {
            Do-Action "winget: $id" { winget install --id $id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null }
        }
    }
}

# ============================ DEBLOAT ============================
if ($Debloat) {
    Write-Host "`n-- Удаление предустановленного мусора --" -ForegroundColor White

    $bloat = @(
        'Microsoft.3DBuilder', 'Microsoft.BingNews', 'Microsoft.BingWeather'
        'Microsoft.GetHelp', 'Microsoft.Getstarted', 'Microsoft.MicrosoftSolitaireCollection'
        'Microsoft.People', 'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps'
        'Microsoft.Xbox.TCUI', 'Microsoft.XboxGameOverlay', 'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxIdentityProvider', 'Microsoft.XboxSpeechToTextOverlay'
        'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'Microsoft.MixedReality.Portal'
        'Microsoft.SkypeApp', 'Microsoft.Todos', 'Clipchamp.Clipchamp'
    )

    foreach ($pkg in $bloat) {
        $installed = Get-AppxPackage -Name $pkg -ErrorAction SilentlyContinue
        if ($installed) {
            Do-Action "удалить $pkg" { Get-AppxPackage -Name $pkg | Remove-AppxPackage -ErrorAction Stop }
        }
    }
}

# ============================ PRIVACY ============================
if ($Privacy) {
    Write-Host "`n-- Настройки приватности --" -ForegroundColor White

    Do-Action "Отключить телеметрию (уровень Security)" {
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0
    }
    Do-Action "Отключить рекламный ID" {
        Set-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0
    }
    Do-Action "Отключить 'подобранный контент' (реклама в системе)" {
        $p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        foreach ($n in 'SubscribedContent-338388Enabled','SubscribedContent-338389Enabled','SubscribedContent-353694Enabled','SubscribedContent-353696Enabled') {
            Set-Reg $p $n 0
        }
    }
    Do-Action "Отключить веб-поиск в меню Пуск" {
        Set-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1
    }
    Do-Action "Отключить телеметрию ввода/рукописного текста" {
        Set-Reg 'HKCU:\SOFTWARE\Microsoft\Input\TIPC' 'Enabled' 0
    }
}

# ============================ TWEAKS ============================
if ($Tweaks) {
    Write-Host "`n-- Удобные твики --" -ForegroundColor White

    Do-Action "Показывать расширения файлов" {
        Set-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt' 0
    }
    Do-Action "Показывать скрытые файлы" {
        Set-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Hidden' 1
    }
    Do-Action "Тёмная тема оформления" {
        Set-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'AppsUseLightTheme' 0
        Set-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'SystemUsesLightTheme' 0
    }
    Do-Action "Открывать Проводник на 'Этот компьютер' (а не 'Быстрый доступ')" {
        Set-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'LaunchTo' 1
    }
}

# ============================ ИТОГ ============================
Write-Host "`n=== Итог ===" -ForegroundColor Cyan
$did = @($log | Where-Object { $_ -match '^(OK|WOULD)' }).Count
if ($Apply) {
    Write-Host "Применено действий: $(@($log | Where-Object { $_ -match '^OK' }).Count), ошибок: $(@($log | Where-Object { $_ -match '^FAIL' }).Count)"
    Write-Host "Часть твиков и деблоата вступит в силу после перезахода в систему / перезапуска Проводника." -ForegroundColor Yellow
} else {
    Write-Host "Запланировано действий: $did. Для реального применения добавьте -Apply." -ForegroundColor Yellow
}
