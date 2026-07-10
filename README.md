# 🧰 PowerShell Toolbox

Рабочие PowerShell-скрипты системного администратора — из реальной практики
(инвентаризация сети, миграция на NAS, массовое заведение пользователей),
причёсанные и обезличенные для публикации.

Всё совместимо с **Windows PowerShell 5.1** — работает на любой живой Windows
без установки чего-либо.

## Скрипты

| Скрипт | Что делает |
|---|---|
| [Scan-Network.ps1](Scan-Network.ps1) | ⭐ Параллельный сканер подсети на runspace pool: живые хосты, hostname, ОС, залогиненный пользователь, MAC → CSV. Определяет принтеры, Linux, iOS-устройства по портам |
| [New-BulkADUsers.ps1](New-BulkADUsers.ps1) | Массовое создание пользователей AD из CSV + стандартная структура OU. Пример данных: [users.sample.csv](users.sample.csv) |
| [Watch-Site.ps1](Watch-Site.ps1) | Мониторинг доступности сайта с алертами в Telegram (упал / восстановился, без дублей) |
| [Compare-FolderTrees.ps1](Compare-FolderTrees.ps1) | Сравнение двух деревьев папок (и файлов) — что где отсутствует; отчёт в файл. Выручает при миграциях данных |
| [Mount-NetworkDrive.ps1](Mount-NetworkDrive.ps1) | Подключение сетевого диска: сначала пробует сохранённые учётные данные, потом спрашивает. «Кликни и работает» для пользователей |
| [Copy-FromList.ps1](Copy-FromList.ps1) | Копирование файлов по списку путей из txt с авто-переименованием дублей |

## Использование

У каждого скрипта есть встроенная справка:

```powershell
Get-Help .\Scan-Network.ps1 -Full
```

Быстрые примеры:

```powershell
# Инвентаризация подсети (учётку администратора спросит сам)
.\Scan-Network.ps1 -Subnet 192.168.1

# Завести пользователей из CSV в OU "Contoso"
.\New-BulkADUsers.ps1 -CsvPath .\users.csv -CompanyOU Contoso -MailDomain contoso.com

# Мониторинг сайта с алертами в Telegram
$env:TELEGRAM_BOT_TOKEN = "токен_от_BotFather"
$env:TELEGRAM_CHAT_ID   = "-1001234567890"
.\Watch-Site.ps1 -Url https://example.com

# Что не доехало до NAS при миграции
.\Compare-FolderTrees.ps1 -PathA C:\CloudCopy -PathB S:\Archive -CompareFiles -ReportPath .\diff.txt
```

## Принципы

- **Никаких секретов в коде** — пароли и токены только через параметры,
  `Get-Credential` или переменные окружения.
- **PS 5.1 first** — никаких зависимостей от PowerShell 7, всё работает
  из коробки на Windows 10/11 и Server 2016+.
- Кодировка файлов — UTF-8 с BOM (иначе PowerShell 5.1 ломает кириллицу).

## Требования

- Windows PowerShell 5.1+
- `New-BulkADUsers.ps1` — модуль ActiveDirectory (RSAT) и права в домене
- `Scan-Network.ps1` — права администратора на опрашиваемых Windows-хостах
