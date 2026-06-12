# Платформа управления уязвимостями

**Автор:** Тарасов Вадим Романович  
**Группа:** 221131  
**Вариант:** 4 — Платформа управления уязвимостями (Vulnerability Management)

Курсовой проект по дисциплине «Методы и технологии программирования».

**Репозиторий:** https://github.com/vadeetar/Kursach

Система сбора данных об уязвимостях (CVE, NVD), сопоставления с инвентаризацией ПО организации, приоритизации по CVSS/EPSS и веб-интерфейса для отслеживания статуса исправления.

## Стек

| Компонент | Технология |
|-----------|------------|
| Backend | Python 3.12, FastAPI, SQLAlchemy, Pydantic V2 |
| БД | PostgreSQL 15 (SQLite — локально без Docker) |
| Источники | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities), [EPSS API](https://www.first.org/epss/api) |
| Контейнеры | Docker, Docker Compose |
| Качество | pytest, Bandit (SAST), pip-audit (SCA), GitHub Actions |

## Быстрый старт (Windows, без Docker)

Из корня проекта в PowerShell:

```powershell
cd E:\курсач
.\start.ps1
```

Не закрывайте окно терминала. Откройте:

- **Веб-интерфейс:** http://127.0.0.1:8000
- **Swagger API:** http://127.0.0.1:8000/api/v1/docs

> `ERR_CONNECTION_REFUSED` — сервер не запущен. Сначала выполните `.\start.ps1`.

При первом запуске создаётся `backend\vuln_mgmt.db` и загружаются **демо-данные** (3 CVE, 3 пакета, находки).

## Быстрый старт (Docker)

Нужен [Docker Desktop](https://www.docker.com/products/docker-desktop/).

```bash
cp .env.example .env
docker compose up -d --build
```

Откройте http://localhost:8000

## Локальный запуск вручную

```powershell
cd backend
py -3 -m pip install -r requirements.txt
$env:PYTHONPATH = "."
py -3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

База SQLite создаётся автоматически в `backend\vuln_mgmt.db` (путь не зависит от текущей папки).

## Основные возможности

1. **Сбор CVE** — `POST /api/v1/tasks/sync-nvd` (NVD API)
2. **EPSS** — `POST /api/v1/tasks/update-epss`
3. **Инвентарь ПО** — `POST /api/v1/assets`
4. **Сопоставление** — `POST /api/v1/tasks/match-assets`
5. **Управление исправлением** — `PATCH /api/v1/findings/{id}`
6. **Отчёты** — `GET /api/v1/reports/executive-summary`

## Тесты и безопасность

```powershell
cd backend
py -3 -m pip install -r requirements.txt
$env:DISABLE_SEED = "1"
$env:TESTING = "1"
py -3 -m pytest --cov=app --cov-report=term-missing -v
py -3 -m ruff check app tests
py -3 -m bandit -r app -ll
```

## Структура проекта

```
├── start.ps1              # запуск на Windows
├── backend/
│   ├── app/               # FastAPI, NVD/EPSS, веб-UI
│   └── tests/             # pytest
├── docs/                  # архитектура, демо, презентация
├── docker-compose.yml
├── POYASNITELNA_ZAPISKA.md
└── .github/workflows/ci.yml
```

## Git Flow

- `main` — стабильная версия (релиз для защиты)
- `develop` — интеграция
- Коммиты: `feat:`, `fix:`, `docs:`, `test:`

## Документация

| Документ | Назначение |
|----------|------------|
| [Пояснительная записка](POYASNITELNA_ZAPISKA.md) | Текст курсовой |
| [Архитектура](docs/ARCHITECTURE.md) | Диаграммы |
| [Презентация](docs/PREZENTACIYA.md) | Слайды к защите |
| [Сценарий демо](docs/DEMO_ZASHCHITA.md) | Демонстрация |
| [Скриншоты](SCREENSHOTS_GUIDE.md) | Приложения к записке |
| [Задание](ZADANIE_KURSOVOJ.md) | Вариант 4 |

## Переменные окружения

См. [.env.example](.env.example). Опционально: `NVD_API_KEY` для увеличенных лимитов NVD API.

## AI-ассистированная разработка

Проект разработан с использованием AI-ассистента (Cursor) в соответствии с методическими указаниями 2026 г.
