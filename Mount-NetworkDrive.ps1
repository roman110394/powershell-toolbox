<#
.SYNOPSIS
    Подключение сетевого диска с автоматическим запросом учётных данных.

.DESCRIPTION
    Пробует подключить шару с сохранёнными в системе учётными данными;
    если не вышло — запрашивает логин/пароль и подключает с /persistent:yes
    (диск будет восстанавливаться при входе в систему).

    Удобно раздавать пользователям как «кликни и работает» вместо инструкции.

.PARAMETER DriveLetter
    Буква диска без двоеточия, например 'S'.

.PARAMETER UncPath
    Путь к шаре, например '\\nas.contoso.local\Share'.

.EXAMPLE
    .\Mount-NetworkDrive.ps1 -DriveLetter S -UncPath \\nas.contoso.local\Docs
#>
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[D-Zd-z]$')]
    [string]$DriveLetter,
    [Parameter(Mandatory)]
    [string]$UncPath
)

$drive = "$($DriveLetter.ToUpper()):"

# Убираем старое подключение, если было
net use $drive /delete 2>$null | Out-Null

# Сначала пробуем без ввода — вдруг учётные данные уже сохранены в системе
net use $drive $UncPath /persistent:yes 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Диск $drive подключен (учётные данные уже были сохранены)" -ForegroundColor Green
    exit 0
}

Write-Host "Автоматически подключиться не удалось — нужны учётные данные." -ForegroundColor Yellow
$cred = Get-Credential -Message "Учётные данные для $UncPath"
if (-not $cred) {
    Write-Host "Отменено пользователем." -ForegroundColor Gray
    exit 1
}

net use $drive $UncPath /user:"$($cred.UserName)" "$($cred.GetNetworkCredential().Password)" /persistent:yes

if ($LASTEXITCODE -eq 0) {
    Write-Host "Успех! Диск $drive подключен и будет восстанавливаться при входе." -ForegroundColor Green
} else {
    Write-Host "Ошибка подключения. Проверьте логин/пароль и доступность $UncPath." -ForegroundColor Red
    exit 1
}
