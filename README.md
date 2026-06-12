# Платформа управления уязвимостями

**Автор:** Бондаренко Полина  
**Группа:** 221331  
**Вариант:** 4 — Платформа управления уязвимостями (Vulnerability Management)

Курсовой проект по дисциплине «Методы и технологии программирования».

**Репозиторий:** https://github.com/bpolina537/Kursovoiy_Proekt

Система сбора данных об уязвимостях (CVE, NVD), сопоставления с инвентаризацией ПО организации, приоритизации по CVSS и контексту актива. API позволяет вести инвентарь, добавлять уязвимости, импортировать данные из NVD и отслеживать статус исправления.

## Стек

| Компонент | Технология |
|-----------|------------|
| Backend | Python 3.12, FastAPI, SQLAlchemy, Pydantic V2 |
| БД | PostgreSQL |
| Источники | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) |
| Контейнеры | Docker, Docker Compose |
| Качество | pytest, ruff, black, Bandit, GitHub Actions |

## Быстрый старт (Windows, без Docker)

Из корня проекта в PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\activate
py -3 -m pip install -e .[dev]
$env:DATABASE_URL = "memory://local"
py -3 -m uvicorn vuln_mgmt.main:app --host 127.0.0.1 --port 8000 --reload
```

Откройте:

- **Swagger API:** http://127.0.0.1:8000/docs
- **Healthcheck:** http://127.0.0.1:8000/health

> `ERR_CONNECTION_REFUSED` — сервер не запущен. Сначала выполните команду запуска.

## Быстрый старт (Docker)

Нужен [Docker Desktop](https://www.docker.com/products/docker-desktop/).

```bash
cp .env.example .env
docker compose up -d --build
```

Откройте http://localhost:8000/docs

## Основные возможности

1. **Инвентарь ПО** — `POST /assets`
2. **Реестр уязвимостей** — `POST /vulnerabilities`
3. **Импорт CVE из NVD** — `POST /vulnerabilities/import`
4. **Оценка риска актива** — `GET /assets/{asset_id}/assessment`
5. **Управление исправлением** — `POST /remediations`, `PATCH /remediations/{id}`
6. **Проверка состояния сервиса** — `GET /health`, `GET /ready`

## Примеры запросов

Создание актива:

```powershell
curl -X POST http://127.0.0.1:8000/assets `
  -H "Content-Type: application/json" `
  -d "{\"name\":\"CRM\",\"vendor\":\"Acme\",\"product\":\"crm\",\"version\":\"1.0.0\",\"environment\":\"production\",\"owner\":\"IT\",\"criticality\":5}"
```

Создание уязвимости:

```powershell
curl -X POST http://127.0.0.1:8000/vulnerabilities `
  -H "Content-Type: application/json" `
  -d "{\"cve_id\":\"CVE-2024-11111\",\"title\":\"Remote code execution\",\"description\":\"RCE in CRM component\",\"cvss_score\":9.8,\"severity\":\"critical\",\"affected_vendor\":\"Acme\",\"affected_product\":\"crm\",\"fixed_version\":\"1.1.0\",\"published_at\":\"2024-01-10T10:00:00+00:00\",\"exploit_available\":true}"
```

Получение оценки риска:

```powershell
curl http://127.0.0.1:8000/assets/<asset_id>/assessment
```

## Тесты и безопасность

```powershell
py -3 -m pytest --cov=src --cov-report=term-missing -v
py -3 -m ruff check src tests
py -3 -m bandit -r src
```

## Структура проекта

```text
├── src/
│   └── vuln_mgmt/
│       ├── core/              # конфигурация, DI, БД, logging, telemetry
│       ├── domain/            # сущности, ошибки, расчёт риска
│       ├── infrastructure/    # SQLAlchemy, репозитории, NVD-клиент
│       ├── routers/           # FastAPI endpoints
│       ├── schemas/           # Pydantic-схемы
│       ├── services/          # бизнес-логика
│       └── ui/                # веб-интерфейс дашборда
├── tests/
│   ├── api/
│   └── unit/
├── docs/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

## Git Flow

- `main` — стабильная версия для защиты
- Коммиты: `feat:`, `fix:`, `docs:`, `test:`, `chore:`

## Переменные окружения

См. [.env.example](.env.example). Опционально можно указать `NVD_API_KEY` для увеличенных лимитов NVD API.

## AI-ассистированная разработка

Проект разработан с использованием AI-ассистента в соответствии с методическими указаниями 2026 г.
