<#
.SYNOPSIS
    Сравнение двух деревьев папок: чего где не хватает.

.DESCRIPTION
    Сравнивает структуру подпапок (и опционально файлы) двух корней — например,
    локальную копию облака и содержимое NAS перед миграцией. Показывает цветную
    сводку в консоли и может сохранить текстовый отчёт.

.PARAMETER PathA
    Первый корень (например, папка Яндекс.Диска).

.PARAMETER PathB
    Второй корень (например, смонтированная шара NAS).

.PARAMETER CompareFiles
    Сравнивать не только папки, но и файлы (медленнее на больших деревьях).

.PARAMETER ReportPath
    Куда сохранить текстовый отчёт. Если не задан — отчёт не сохраняется.

.EXAMPLE
    .\Compare-FolderTrees.ps1 -PathA "C:\CloudCopy" -PathB "S:\Archive" -CompareFiles -ReportPath .\report.txt
#>
param(
    [Parameter(Mandatory)]
    [string]$PathA,
    [Parameter(Mandatory)]
    [string]$PathB,
    [switch]$CompareFiles,
    [string]$ReportPath
)

foreach ($p in $PathA, $PathB) {
    if (-not (Test-Path $p)) { throw "Папка не найдена: $p" }
}

function Get-RelativeFolders([string]$BasePath) {
    Get-ChildItem -Path $BasePath -Directory -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName.Replace($BasePath, '').TrimStart('\') } |
        Sort-Object
}

function Get-RelativeFiles([string]$BasePath) {
    Get-ChildItem -Path $BasePath -File -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName.Replace($BasePath, '').TrimStart('\') }
}

Write-Host "Анализ структуры папок..." -ForegroundColor Yellow

$foldersA = @(Get-RelativeFolders $PathA)
$foldersB = @(Get-RelativeFolders $PathB)

# HashSet вместо -notin: на тысячах папок разница в скорости на порядки
$setA = [System.Collections.Generic.HashSet[string]]::new([string[]]$foldersA, [System.StringComparer]::OrdinalIgnoreCase)
$setB = [System.Collections.Generic.HashSet[string]]::new([string[]]$foldersB, [System.StringComparer]::OrdinalIgnoreCase)

$onlyInA = @($foldersA | Where-Object { -not $setB.Contains($_) })
$onlyInB = @($foldersB | Where-Object { -not $setA.Contains($_) })

Write-Host ""
Write-Host "================ СТАТИСТИКА ПАПОК ================" -ForegroundColor Cyan
Write-Host ("Всего в A ({0}): {1}" -f $PathA, $foldersA.Count)
Write-Host ("Всего в B ({0}): {1}" -f $PathB, $foldersB.Count)
Write-Host "Только в A: $($onlyInA.Count)" -ForegroundColor Green
Write-Host "Только в B: $($onlyInB.Count)" -ForegroundColor Red

if ($onlyInA) {
    Write-Host "`n--- Папки только в A ---" -ForegroundColor Green
    $onlyInA | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }
}
if ($onlyInB) {
    Write-Host "`n--- Папки только в B ---" -ForegroundColor Red
    $onlyInB | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

$filesOnlyInA = @(); $filesOnlyInB = @()
if ($CompareFiles) {
    Write-Host "`nАнализ файлов..." -ForegroundColor Yellow
    $filesA = @(Get-RelativeFiles $PathA)
    $filesB = @(Get-RelativeFiles $PathB)
    $fsetA = [System.Collections.Generic.HashSet[string]]::new([string[]]$filesA, [System.StringComparer]::OrdinalIgnoreCase)
    $fsetB = [System.Collections.Generic.HashSet[string]]::new([string[]]$filesB, [System.StringComparer]::OrdinalIgnoreCase)
    $filesOnlyInA = @($filesA | Where-Object { -not $fsetB.Contains($_) })
    $filesOnlyInB = @($filesB | Where-Object { -not $fsetA.Contains($_) })

    Write-Host ""
    Write-Host "================ СТАТИСТИКА ФАЙЛОВ ================" -ForegroundColor Cyan
    Write-Host "Всего в A: $($filesA.Count) · Всего в B: $($filesB.Count)"
    Write-Host "Только в A: $($filesOnlyInA.Count)" -ForegroundColor Green
    Write-Host "Только в B: $($filesOnlyInB.Count)" -ForegroundColor Red

    foreach ($pair in @(
        @{ List = $filesOnlyInA; Label = 'A'; Color = 'Green';  Sign = '+' },
        @{ List = $filesOnlyInB; Label = 'B'; Color = 'Red';    Sign = '-' })) {
        if ($pair.List) {
            Write-Host "`n--- Файлы только в $($pair.Label) (первые 100) ---" -ForegroundColor $pair.Color
            $pair.List | Select-Object -First 100 | ForEach-Object { Write-Host "  $($pair.Sign) $_" -ForegroundColor $pair.Color }
            if ($pair.List.Count -gt 100) { Write-Host "  ... и ещё $($pair.List.Count - 100)" -ForegroundColor $pair.Color }
        }
    }
}

if ($ReportPath) {
    $report = @"
==============================================================
ОТЧЁТ О СРАВНЕНИИ ДЕРЕВЬЕВ ПАПОК — $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')
A: $PathA
B: $PathB
==============================================================
Папок в A: $($foldersA.Count) · Папок в B: $($foldersB.Count)
Только в A: $($onlyInA.Count) · Только в B: $($onlyInB.Count)

--- ПАПКИ ТОЛЬКО В A ---
$($onlyInA -join "`r`n")

--- ПАПКИ ТОЛЬКО В B ---
$($onlyInB -join "`r`n")
"@
    if ($CompareFiles) {
        $report += @"


--- ФАЙЛЫ ТОЛЬКО В A ---
$($filesOnlyInA -join "`r`n")

--- ФАЙЛЫ ТОЛЬКО В B ---
$($filesOnlyInB -join "`r`n")
"@
    }
    $report | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "`nОтчёт сохранён: $ReportPath" -ForegroundColor Green
}

Write-Host "`nГотово." -ForegroundColor Cyan
