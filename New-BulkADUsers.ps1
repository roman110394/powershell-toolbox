<#
.SYNOPSIS
    Массовое создание пользователей Active Directory из CSV + базовая структура OU.

.DESCRIPTION
    Создаёт стандартную структуру OU (Users / Computers / Servers / Groups) внутри
    корневого OU компании и заводит пользователей из CSV-файла: UPN, e-mail,
    отображаемое имя, стартовый пароль со сменой при первом входе.

    Формат CSV (разделитель — запятая, кодировка UTF-8), см. users.sample.csv:
    SamAccountName,GivenName,Surname,MiddleName,Email,Enabled

.PARAMETER CsvPath
    Путь к CSV со списком пользователей.

.PARAMETER CompanyOU
    Имя корневого OU компании (создаётся, если нет). По умолчанию 'Company'.

.PARAMETER MailDomain
    Домен для e-mail, если в CSV колонка Email пустая (сам логин возьмётся из SamAccountName).

.PARAMETER DefaultPassword
    Стартовый пароль (SecureString). Если не указан — будет запрошен.
    Всем пользователям ставится «сменить пароль при следующем входе».

.EXAMPLE
    .\New-BulkADUsers.ps1 -CsvPath .\users.csv -CompanyOU "Contoso" -MailDomain contoso.com

.NOTES
    Требуется модуль ActiveDirectory (RSAT) и права на создание объектов в домене.
    Запускать на DC или машине с RSAT под доменным админом.
#>
param(
    [Parameter(Mandatory)]
    [string]$CsvPath,
    [string]$CompanyOU = 'Company',
    [string]$MailDomain,
    [SecureString]$DefaultPassword
)

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $DefaultPassword) {
    $DefaultPassword = Read-Host -AsSecureString "Стартовый пароль для новых пользователей"
}

$domain   = Get-ADDomain
$domainDN = $domain.DistinguishedName          # DC=contoso,DC=local
$upnSuffix = $domain.DNSRoot                   # contoso.local

# ---- Структура OU ----
$companyPath = "OU=$CompanyOU,$domainDN"
New-ADOrganizationalUnit -Name $CompanyOU -Path $domainDN -ErrorAction SilentlyContinue
foreach ($ou in 'Users', 'Computers', 'Servers', 'Groups') {
    New-ADOrganizationalUnit -Name $ou -Path $companyPath -ErrorAction SilentlyContinue
}
$usersPath = "OU=Users,$companyPath"
Write-Host "[+] Структура OU готова: $companyPath" -ForegroundColor Green

# ---- Пользователи ----
$users = Import-Csv -Path $CsvPath -Encoding UTF8
$created = 0; $skipped = 0

foreach ($u in $users) {
    if (-not $u.SamAccountName) { continue }

    if (Get-ADUser -Filter "SamAccountName -eq '$($u.SamAccountName)'" -ErrorAction SilentlyContinue) {
        Write-Host "  = $($u.SamAccountName) уже существует, пропуск" -ForegroundColor Yellow
        $skipped++
        continue
    }

    $displayName = (@($u.Surname, $u.GivenName, $u.MiddleName) -ne '') -join ' '
    $email = if ($u.Email) { $u.Email } elseif ($MailDomain) { "$($u.SamAccountName)@$MailDomain" } else { $null }
    $enabled = $u.Enabled -notin @('0', 'false', 'False', 'no')

    $params = @{
        SamAccountName        = $u.SamAccountName
        UserPrincipalName     = "$($u.SamAccountName)@$upnSuffix"
        Name                  = $displayName
        GivenName             = $u.GivenName
        Surname               = $u.Surname
        DisplayName           = $displayName
        Path                  = $usersPath
        AccountPassword       = $DefaultPassword
        Enabled               = $enabled
        ChangePasswordAtLogon = $true
    }
    if ($email) { $params.EmailAddress = $email }

    try {
        New-ADUser @params -ErrorAction Stop
        Write-Host "  + $($u.SamAccountName)  ($displayName)" -ForegroundColor Green
        $created++
    } catch {
        Write-Host "  ! $($u.SamAccountName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Импорт завершён. Создано: $created, пропущено (уже есть): $skipped" -ForegroundColor Cyan
