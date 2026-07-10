<#
.SYNOPSIS
    Копирование файлов по списку путей из текстового файла.

.DESCRIPTION
    Читает txt-файл со списком полных путей (по одному в строке), копирует все
    существующие файлы в целевую папку. Дубликаты имён не перезаписываются,
    а получают суффикс _1, _2 и т.д. В конце — сводка.

    Полезно, когда список файлов пришёл откуда-то снаружи: результат поиска,
    выгрузка из программы, «вот эти забери» от коллеги.

.PARAMETER ListPath
    Текстовый файл со списком путей (UTF-8).

.PARAMETER Destination
    Куда копировать (папка создастся, если её нет).

.PARAMETER Filter
    Regex-фильтр по пути, например '\.(mp4|mov)$' — брать только видео.
    По умолчанию берутся все непустые строки.

.EXAMPLE
    .\Copy-FromList.ps1 -ListPath .\paths.txt -Destination D:\Collected -Filter '\.mp4$'
#>
param(
    [Parameter(Mandatory)]
    [string]$ListPath,
    [Parameter(Mandatory)]
    [string]$Destination,
    [string]$Filter
)

if (-not (Test-Path $Destination)) {
    New-Item -Path $Destination -ItemType Directory | Out-Null
    Write-Host "Создана папка: $Destination" -ForegroundColor Green
}

$paths = Get-Content -Path $ListPath -Encoding UTF8 | Where-Object { $_.Trim() }
if ($Filter) { $paths = $paths | Where-Object { $_ -match $Filter } }

Write-Host "Файлов в списке: $($paths.Count)" -ForegroundColor Cyan

$copied = 0; $errors = 0

foreach ($src in $paths) {
    $src = $src.Trim()

    if (-not (Test-Path $src)) {
        Write-Host "Не найден: $src" -ForegroundColor Yellow
        $errors++
        continue
    }

    $fileName = [System.IO.Path]::GetFileName($src)
    $dest = Join-Path $Destination $fileName

    # Имя занято — подбираем свободное с суффиксом _N
    $counter = 1
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
    $ext = [System.IO.Path]::GetExtension($fileName)
    while (Test-Path $dest) {
        $dest = Join-Path $Destination "$baseName`_$counter$ext"
        $counter++
    }

    try {
        Copy-Item -Path $src -Destination $dest
        Write-Host "Скопировано: $fileName" -ForegroundColor Green
        $copied++
    } catch {
        Write-Host "Ошибка копирования $fileName : $_" -ForegroundColor Red
        $errors++
    }
}

Write-Host "`n===== Итог =====" -ForegroundColor Magenta
Write-Host "Скопировано: $copied"
Write-Host "Ошибок / не найдено: $errors"
Write-Host "Все файлы в: $Destination"
