# Курсовой проект: Платформа управления уязвимостями

**Студент:** Бондаренко Полина  
**Группа:** 221331  
**Лабораторная работа:** 14  
**Вариант:** 4  
**Тип варианта:** повышенная сложность

## Описание
Платформа управления уязвимостями собирает сведения о CVE, хранит инвентаризацию ПО организации и помогает приоритизировать исправления на основе CVSS, критичности актива и среды эксплуатации.

## Технологии
- Python 3.11+
- FastAPI
- Pydantic
- SQLAlchemy 2
- PostgreSQL
- NVD API
- Docker и Docker Compose
- pytest
- ruff, black, bandit

## Архитектура
Проект использует layered architecture:

- `src/vuln_mgmt/core` - конфигурация, DI, логирование, БД, telemetry
- `src/vuln_mgmt/domain` - доменные сущности, ошибки и расчёт риска
- `src/vuln_mgmt/infrastructure` - SQLAlchemy-модели, репозитории и NVD-клиент
- `src/vuln_mgmt/services` - бизнес-логика
- `src/vuln_mgmt/routers` - HTTP API
- `src/vuln_mgmt/schemas` - Pydantic-схемы
- `tests` - unit и API-тесты

## Сборка
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
```

Или через Docker:

```bash
copy .env.example .env
docker compose build
```

## Запуск
Локально:

```bash
uvicorn vuln_mgmt.main:app --reload
```

Через Docker:

```bash
docker compose up
```

Swagger-документация будет доступна по адресу:

```text
http://127.0.0.1:8000/docs
```

## Примеры запросов
Создание актива:

```bash
curl -X POST http://127.0.0.1:8000/assets ^
  -H "Content-Type: application/json" ^
  -d "{\"name\":\"CRM\",\"vendor\":\"Acme\",\"product\":\"crm\",\"version\":\"1.0.0\",\"environment\":\"production\",\"owner\":\"IT\",\"criticality\":5}"
```

Создание уязвимости:

```bash
curl -X POST http://127.0.0.1:8000/vulnerabilities ^
  -H "Content-Type: application/json" ^
  -d "{\"cve_id\":\"CVE-2024-11111\",\"title\":\"Remote code execution\",\"description\":\"RCE in CRM component\",\"cvss_score\":9.8,\"severity\":\"critical\",\"affected_vendor\":\"Acme\",\"affected_product\":\"crm\",\"fixed_version\":\"1.1.0\",\"published_at\":\"2024-01-10T10:00:00+00:00\",\"exploit_available\":true}"
```

Получение оценки риска:

```bash
curl http://127.0.0.1:8000/assets/<asset_id>/assessment
```

## API
- `GET /health`
- `GET /ready`
- `POST /assets`
- `GET /assets`
- `GET /assets/{asset_id}`
- `GET /assets/{asset_id}/assessment`
- `POST /vulnerabilities`
- `POST /vulnerabilities/import`
- `GET /vulnerabilities`
- `POST /remediations`
- `PATCH /remediations/{remediation_id}`

## Проверка качества
```bash
pytest
ruff check src tests
bandit -r src
```

