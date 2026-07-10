# ── PowerShell Toolbox: короткие команды для запуска скриптов из GitHub ──
# Один раз добавьте это в свой профиль (см. инструкцию в README), и запускайте словом:
#   healthreport
#   scannet -Subnet 192.168.1
#   adaudit -InactiveDays 60

$ToolboxBase = 'https://raw.githubusercontent.com/roman110394/powershell-toolbox/main'

function Invoke-ToolboxScript {
    # без param() — чтобы -ParamName аргументы уходили в целевой скрипт, а не сюда
    $name = $args[0]
    $rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }
    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
    $code = (Invoke-RestMethod "$ToolboxBase/$name.ps1").TrimStart([char]0xFEFF)
    & ([scriptblock]::Create($code)) @rest
}

function healthreport { Invoke-ToolboxScript New-ServerHealthReport @args }
function fleethealth  { Invoke-ToolboxScript Get-FleetHealth        @args }
function hardaudit    { Invoke-ToolboxScript Invoke-WindowsHardeningAudit @args }
function secbaseline  { Invoke-ToolboxScript Test-SecurityBaseline  @args }
function winsetup     { Invoke-ToolboxScript Initialize-Windows     @args }
function scannet      { Invoke-ToolboxScript Scan-Network          @args }
function adaudit      { Invoke-ToolboxScript Invoke-ADAudit        @args }
function loginhistory { Invoke-ToolboxScript Get-LoginHistory     @args }
function pwdexpiry    { Invoke-ToolboxScript Send-PasswordExpiryReminder @args }
function cmpfolders   { Invoke-ToolboxScript Compare-FolderTrees   @args }
function watchsite    { Invoke-ToolboxScript Watch-Site            @args }
