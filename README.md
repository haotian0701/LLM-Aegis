# Aegis Gateway

This repository currently implements **stage 1**: a Chat Completions style gateway with authentication, explicit conversation IDs, PostgreSQL audit records, and an in-process Mock provider. It does not yet detect sensitive information or enforce category-based policies. Do not send real secrets to the demo.

## Run locally (PowerShell)

Python 3.13 and Docker Desktop are required. Start Docker Desktop before running Compose. No local model or cloud model account is needed.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
docker compose up -d db

$env:AEGIS_DATABASE_URL = 'postgresql+psycopg://aegis:aegis_dev_only@127.0.0.1:54329/aegis'
$env:AEGIS_API_KEYS_JSON = '{"demo-client":"replace-with-a-long-random-client-token"}'
$env:AEGIS_HMAC_KEY = 'replace-with-an-independent-long-random-hmac-key'
$env:AEGIS_RUN_MODE = 'demo'
$env:AEGIS_DEMO_PROVIDER = 'mock'
$env:AEGIS_MODEL_ALIASES_JSON = '{"aegis-mock":"mock-v1"}'

.\.venv\Scripts\alembic upgrade head
.\.venv\Scripts\python -m aegis
```

Try a request in a second PowerShell session:

```powershell
$headers = @{ Authorization = 'Bearer replace-with-a-long-random-client-token' }
$body = @{ model = 'aegis-mock'; messages = @(@{ role = 'user'; content = 'Hello' }) } | ConvertTo-Json -Depth 5
Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/v1/chat/completions' -Method Post -Headers $headers -ContentType 'application/json' -Body $body
```

The response header `X-Aegis-Conversation-Id` can be sent on later requests to reuse the explicit conversation ID. Every authenticated valid request currently receives a fixed Mock answer in demo mode. With `AEGIS_RUN_MODE=strict` and no real local provider, valid requests return `LOCAL_UNAVAILABLE` after creating an audit event.

The stage 1 Mock rejects `temperature`, `top_p`, and `max_tokens` with `UNSUPPORTED_FEATURE`, because its fixed response cannot honor generation controls.

The `.env.example` file lists configuration keys; the application intentionally does not load `.env` itself. Keep live tokens and HMAC keys out of source control.

On Windows, use `python -m aegis` as shown above: Psycopg's async connections require the selector event loop rather than the Windows default proactor loop. The entry point selects it before starting Uvicorn.

## Check

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
.\.venv\Scripts\pyright
```

The HTTP tests use an in-memory storage test double. PostgreSQL persistence and Alembic migrations require the Docker database.

To include the PostgreSQL integration check after running migrations, set `AEGIS_TEST_DATABASE_URL` to the same database URL and rerun pytest. The integration test uses unique conversation IDs.
