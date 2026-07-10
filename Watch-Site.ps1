<#
.SYNOPSIS
    Мониторинг доступности сайта с алертами в Telegram.

.DESCRIPTION
    Раз в N секунд опрашивает URL. При падении (код != 200 или таймаут) шлёт
    сообщение в Telegram-чат; при восстановлении — сообщение об этом.
    Повторные алерты об одной и той же ошибке не дублируются.

    Токен бота НЕ хранится в скрипте — берётся из параметра или переменной
    окружения TELEGRAM_BOT_TOKEN.

.PARAMETER Url
    Проверяемый адрес.

.PARAMETER ChatId
    ID чата/канала Telegram (у групп отрицательный, вида -100xxxxxxxxxx).
    По умолчанию — из переменной окружения TELEGRAM_CHAT_ID.

.PARAMETER BotToken
    Токен бота от @BotFather. По умолчанию — из TELEGRAM_BOT_TOKEN.

.PARAMETER IntervalSeconds
    Период проверки. По умолчанию 300 (5 минут).

.EXAMPLE
    $env:TELEGRAM_BOT_TOKEN = "123456:ABC..."
    $env:TELEGRAM_CHAT_ID   = "-1001234567890"
    .\Watch-Site.ps1 -Url https://example.com

.NOTES
    Удобно запускать как задачу планировщика «при старте системы» или в screen/tmux
    на дежурной машине.
#>
param(
    [Parameter(Mandatory)]
    [string]$Url,
    [string]$ChatId  = $env:TELEGRAM_CHAT_ID,
    [string]$BotToken = $env:TELEGRAM_BOT_TOKEN,
    [int]$IntervalSeconds = 300
)

if (-not $BotToken) { throw "Не задан токен: параметр -BotToken или переменная окружения TELEGRAM_BOT_TOKEN" }
if (-not $ChatId)   { throw "Не задан чат: параметр -ChatId или переменная окружения TELEGRAM_CHAT_ID" }

$telegramApi = "https://api.telegram.org/bot$BotToken/sendMessage"

function Send-Alert([string]$Text) {
    try {
        Invoke-RestMethod -Uri "$telegramApi?chat_id=$ChatId&text=$([uri]::EscapeDataString($Text))" | Out-Null
    } catch {
        Write-Host "$(Get-Date) Не удалось отправить в Telegram: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$lastStatusOk  = $true
$lastErrorCode = $null

Send-Alert "INFO: мониторинг $Url запущен (проверка каждые $IntervalSeconds сек)"
Write-Host "Мониторинг $Url ... (каждые $IntervalSeconds сек, Ctrl+C для остановки)"

while ($true) {
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
        $statusCode = [int]$response.StatusCode

        Write-Host "$(Get-Date) Код ответа: $statusCode"

        if ($statusCode -ne 200) {
            # шлём алерт только при смене состояния или нового кода ошибки
            if ($lastStatusOk -or $lastErrorCode -ne $statusCode) {
                Send-Alert "WARNING: $Url отвечает кодом $statusCode"
                $lastStatusOk = $false
                $lastErrorCode = $statusCode
            }
        } elseif (-not $lastStatusOk) {
            Send-Alert "SUCCESS: $Url восстановлен (код 200)"
            $lastStatusOk = $true
            $lastErrorCode = $null
        }
    } catch {
        $err = $_.Exception.Message
        Write-Host "$(Get-Date) Ошибка запроса: $err" -ForegroundColor Yellow
        if ($lastStatusOk -or $lastErrorCode -ne 'Exception') {
            Send-Alert "ERROR: $Url недоступен — $err"
            $lastStatusOk = $false
            $lastErrorCode = 'Exception'
        }
    }

    Start-Sleep -Seconds $IntervalSeconds
}
