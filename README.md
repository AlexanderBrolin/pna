# Process Network Analyzer (PNA)

Десктопное приложение для мониторинга сетевой активности процессов на Windows. Показывает все TCP и UDP соединения выбранного приложения с резолвом IP-адресов в доменные имена. Полезно для создания точечных маршрутов (KnockDNS, Antizapret) и анализа сетевого поведения приложений.

## Возможности

- **Мониторинг по процессу или пулу процессов** — выбираешь `chrome.exe` и автоматически отслеживаются ВСЕ процессы Chrome (вкладки, расширения, service workers). Новые процессы добавляются в пул автоматически.
- **TCP-соединения** — захват через `GetExtendedTcpTable` с поллингом 50мс. Ловит даже короткоживущие соединения (HTTP-запросы, API-вызовы).
- **UDP-соединения** — захват через raw socket (`SIO_RCVALL`) + привязка к процессу через `GetExtendedUdpTable`. Ловит VoIP-звонки (Telegram, Discord), QUIC-трафик (YouTube, Google), DNS-запросы.
- **Резолв доменов** — три источника: ETW DNS-Client (перехват DNS-запросов с привязкой к PID), кэш DNS Windows (`ipconfig /displaydns`), reverse DNS (fallback).
- **Заблокированные соединения** — видны даже соединения, заблокированные DPI/ТСПУ: DNS-запрос фиксируется до попытки соединения, TCP SYN_SENT ловится поллингом, UDP-пакеты перехватываются на уровне интерфейса.
- **Экспорт** — домены, IP-адреса (с агрегацией подсетей /24), JSON с полной метаинформацией.
- **Чёрный список** — встроенный фильтр системных доменов (Microsoft, Windows Update, OCSP и т.д.).

## Как это работает

### Архитектура

```
┌─────────────────────────────────────────────────────┐
│  Electron Frontend (HTML/JS)                        │
│  ← WebSocket →                                      │
│  Python Backend (asyncio + threads)                  │
│                                                      │
│  ┌──────────────┐  ┌───────────────┐  ┌───────────┐ │
│  │ DNS ETW      │  │ TCP Poller    │  │ UDP Raw   │ │
│  │ (domain→IP)  │  │ (50ms, ctypes)│  │ Socket    │ │
│  └──────┬───────┘  └──────┬────────┘  └─────┬─────┘ │
│         └──────────┬──────┘                  │       │
│              ┌─────▼──────┐    ┌─────────────▼─┐    │
│              │ Aggregator  │    │ UDP Table      │    │
│              │ (dedup,     │    │ (port→PID map) │    │
│              │  merge)     │    └────────────────┘    │
│              └─────┬───────┘                          │
│              ┌─────▼───────┐                          │
│              │ rDNS / DNS  │                          │
│              │ Cache       │                          │
│              └─────────────┘                          │
└─────────────────────────────────────────────────────┘
```

### Механизмы захвата

| Протокол | Метод | Привязка к PID | Интервал |
|----------|-------|----------------|----------|
| TCP | `GetExtendedTcpTable` (ctypes) | Нативно из WinAPI | 50мс |
| UDP | Raw socket `SIO_RCVALL` + `GetExtendedUdpTable` | Через local_port→PID таблицу | Real-time + 200мс |
| DNS | ETW `Microsoft-Windows-DNS-Client` | Нативно (ClientPID) | Event-driven |

### Резолв IP → Домен (приоритет)

1. **ETW DNS** — перехват DNS-запросов процесса в реальном времени (домен + IP + PID)
2. **DNS Cache Windows** — `ipconfig /displaydns` каждые 2 сек (все DNS-запросы системы)
3. **Reverse DNS** — `gethostbyaddr()` для IP без домена (8 параллельных потоков, таймаут 3 сек)

## Требования

- Windows 10/11
- Python 3.10+
- Права администратора (для ETW и raw socket)

## Установка

### Из релиза (рекомендуется)

Скачайте установщик из [Releases](https://github.com/AlexanderBrolin/pna/releases), запустите, следуйте инструкциям.

### Из исходников

```bash
# Клонировать
git clone https://github.com/AlexanderBrolin/pna.git
cd pna

# Установить зависимости
npm install
pip install -r backend/requirements.txt

# Запустить в dev-режиме
npm start

# Собрать exe
npm run build-exe
```

## Использование

1. Запустите приложение **от имени администратора**
2. В выпадающем списке выберите процесс или пул процессов (например, `chrome.exe`)
3. Нажмите **Начать захват**
4. Откройте нужные сайты / сделайте звонок — соединения появятся в таблице
5. Используйте поиск, сортировку, фильтры для анализа
6. Экспортируйте результат: домены, IP или JSON

### Применение для маршрутизации (Antizapret / KnockDNS)

1. Запустите мониторинг нужного приложения
2. Используйте все функции приложения (откройте разные разделы сайта, позвоните и т.д.)
3. Экспортируйте список доменов → добавьте в конфиг KnockDNS / Antizapret
4. Экспортируйте IP-адреса (с подсетями) → добавьте в маршруты

## Структура проекта

```
├── backend/
│   ├── server.py           # WebSocket сервер, оркестрация
│   ├── etw_tracer.py       # ETW DNS + TCP poller + UDP raw socket
│   ├── aggregator.py       # Дедупликация, IP→домен, группировка
│   ├── process_tree.py     # Отслеживание процессов и дочерних
│   ├── dns_cache.py        # Поллинг ipconfig /displaydns
│   ├── rdns_resolver.py    # Reverse DNS резолвер
│   ├── blacklist.py        # Чёрный список доменов
│   └── requirements.txt
├── src/
│   ├── main.js             # Electron main process
│   ├── preload.js          # Preload script
│   └── renderer/
│       ├── index.html
│       ├── app.js          # UI логика
│       └── styles.css
└── package.json
```

## Лицензия

MIT
