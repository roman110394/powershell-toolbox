<#
.SYNOPSIS
    Параллельный сканер подсети: живые хосты, имя, ОС, залогиненный пользователь, MAC.

.DESCRIPTION
    Сканирует подсеть /24 (ICMP + TCP-порты для устройств, не отвечающих на ping),
    затем для каждого живого хоста собирает: hostname (DNS/NetBIOS), ОС и текущего
    пользователя (через CIM/DCOM), MAC (из ARP-кэша). Результат — CSV и таблица.

    Работает на Windows PowerShell 5.1 — параллельность через runspace pool,
    без ForEach-Object -Parallel.

.PARAMETER Subnet
    Первые три октета подсети, например '192.168.1'.

.PARAMETER Credential
    Учётная запись с правами администратора на опрашиваемых Windows-хостах.
    Если не указана — будет запрошена.

.PARAMETER OutputCsv
    Путь к итоговому CSV. По умолчанию network-inventory.csv рядом со скриптом.

.EXAMPLE
    .\Scan-Network.ps1 -Subnet 192.168.1
    Просканировать 192.168.1.1-254, учётку спросит при запуске.
#>
param(
    [string]$Subnet = '192.168.1',
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputCsv
)

if (-not $OutputCsv) {
    # $PSScriptRoot пуст при запуске из памяти (irm | iex) — тогда пишем в текущую папку
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputCsv = Join-Path $baseDir 'network-inventory.csv'
}

if (-not $Credential) {
    $Credential = Get-Credential -Message "Учётная запись администратора для опроса Windows-хостов"
}

$range      = 1..254
$probePorts = 135, 445, 139, 22, 80, 443, 9100, 62078, 23, 3389

Write-Host "[*] Сканирую $Subnet.1-254 ..." -ForegroundColor Cyan

# ---- Параллельный поиск живых хостов через runspace pool (совместимо с PS 5.1) ----
$probeScript = {
    param($ip, $ports)
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) { return $ip }
    foreach ($p in $ports) {
        $c = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $c.BeginConnect($ip, $p, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(300, $false) -and $c.Connected) {
                $c.EndConnect($iar); $c.Close(); return $ip
            }
        } catch {} finally { $c.Close() }
    }
    return $null
}

$pool = [runspacefactory]::CreateRunspacePool(1, 64)
$pool.Open()
$jobs = foreach ($i in $range) {
    $ip = "$Subnet.$i"
    $ps = [powershell]::Create().AddScript($probeScript).AddArgument($ip).AddArgument($probePorts)
    $ps.RunspacePool = $pool
    [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); IP = $ip }
}
$alive = foreach ($j in $jobs) {
    $r = $j.PS.EndInvoke($j.Handle)
    $j.PS.Dispose()
    if ($r) { $r }
}
$pool.Close(); $pool.Dispose()

$alive = @($alive)
Write-Host ("[+] Живых хостов: {0}" -f $alive.Count) -ForegroundColor Green

# ---- MAC-адреса из ARP-кэша ----
$arpMap = @{}
arp -a | ForEach-Object {
    if ($_ -match '\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+') { $arpMap[$matches[1]] = $matches[2] }
}

function Test-Port {
    param($ip, $port, $timeoutMs = 400)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($timeoutMs, $false) -and $c.Connected) {
            $c.EndConnect($iar); return $true
        }
    } catch {} finally { $c.Close() }
    return $false
}

# ---- Детали по каждому хосту ----
$results = foreach ($ip in $alive) {
    $row = [pscustomobject]@{
        IP = $ip; Hostname = ''; OS = ''; LoggedUser = ''; MAC = $arpMap[$ip]; Status = ''
    }

    try { $row.Hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch {}

    if (-not $row.Hostname) {
        # DNS молчит — пробуем NetBIOS
        try {
            $nb = nbtstat -A $ip 2>$null | Select-String '<00>\s+UNIQUE'
            if ($nb) {
                $parts = ($nb[0].ToString().Trim() -split '\s+')
                if ($parts.Count -gt 0) { $row.Hostname = $parts[0] }
            }
        } catch {}
    }

    $session = $null
    try {
        # DCOM вместо WinRM: работает на хостах без настроенного PS Remoting
        $opt = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession -ComputerName $ip -Credential $Credential -SessionOption $opt -OperationTimeoutSec 6 -ErrorAction Stop

        $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop

        $row.OS         = $os.Caption
        $row.LoggedUser = $cs.UserName

        if (-not $row.LoggedUser) {
            # RDP-сессии не видны в Win32_ComputerSystem — смотрим владельца explorer.exe
            $proc = Get-CimInstance -CimSession $session -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($proc) {
                $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($owner.User) { $row.LoggedUser = "$($owner.Domain)\$($owner.User)" }
            }
        }
        $row.Status = 'OK'
    } catch {
        # CIM не ответил — определяем тип устройства по открытым портам
        if ((Test-Port $ip 445) -or (Test-Port $ip 135)) {
            $row.OS = 'Windows (auth failed)'
            $row.Status = $_.Exception.Message.Split("`n")[0]
        } elseif (Test-Port $ip 22)   { $row.OS = 'Linux/SSH' }
          elseif ((Test-Port $ip 9100) -or (Test-Port $ip 631)) { $row.OS = 'Printer' }
          elseif (Test-Port $ip 62078) { $row.OS = 'iPhone/iPad' }
          elseif ((Test-Port $ip 80) -or (Test-Port $ip 443)) { $row.OS = 'Web device (router/IoT)' }
          else { $row.OS = 'Unknown (ICMP only)' }
    } finally {
        if ($session) { Remove-CimSession $session -ErrorAction SilentlyContinue }
    }

    Write-Host ("  {0,-15} {1,-28} {2,-32} {3}" -f $row.IP, $row.Hostname, $row.OS, $row.LoggedUser)
    $row
}

$results |
    Sort-Object { [int]($_.IP.Split('.')[-1]) } |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "[OK] Сохранено: $OutputCsv" -ForegroundColor Green
$results | Sort-Object { [int]($_.IP.Split('.')[-1]) } | Format-Table -AutoSize
