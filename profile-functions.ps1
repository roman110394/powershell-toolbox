# ── PowerShell Toolbox: короткие команды для запуска скриптов из GitHub ──
# Один раз добавьте это в свой профиль (см. инструкцию в README), и запускайте словом:
#   healthreport
#   scannet -Subnet 192.168.1
#   adaudit -InactiveDays 60

$ToolboxBase = 'https://raw.githubusercontent.com/roman110394/powershell-toolbox/main'

function Invoke-ToolboxScript {
    param([Parameter(Mandatory)][string]$Name)
    $rest = $args   # всё, что после имени скрипта, — пробрасываем как есть
    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
    $code = (Invoke-RestMethod "$ToolboxBase/$Name.ps1").TrimStart([char]0xFEFF)
    & ([scriptblock]::Create($code)) @rest
}

function healthreport { Invoke-ToolboxScript New-ServerHealthReport @args }
function scannet      { Invoke-ToolboxScript Scan-Network          @args }
function adaudit      { Invoke-ToolboxScript Invoke-ADAudit        @args }
function pwdexpiry    { Invoke-ToolboxScript Send-PasswordExpiryReminder @args }
function cmpfolders   { Invoke-ToolboxScript Compare-FolderTrees   @args }
function watchsite    { Invoke-ToolboxScript Watch-Site            @args }
