# Aegis Gateway

Stage 2 implements a text-only Chat Completions gateway with local rule detection, English CPU NER, policy decisions, conversation sensitivity, and PostgreSQL audit records. It does not yet send requests to a cloud model or perform masking. Demo mode can use an external OpenAI-compatible service **only for semantic classification**; that service receives the original text, so use synthetic data only.

## Run locally (PowerShell)

Use Python 3.13 and Docker Desktop. The install includes spaCy and its small English CPU NER model; no local LLM or GPU is needed.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
docker compose up -d db

$env:AEGIS_DATABASE_URL = 'postgresql+psycopg://aegis:aegis_dev_only@127.0.0.1:54329/aegis'
$env:AEGIS_API_KEYS_JSON = '{"demo-client":"replace-with-a-long-random-client-token"}'
$env:AEGIS_HMAC_KEY = 'replace-with-an-independent-long-random-hmac-key'
$env:AEGIS_RUN_MODE = 'demo'
$env:AEGIS_DEMO_PROVIDER = 'mock'

.\.venv\Scripts\alembic upgrade head
.\.venv\Scripts\python -m aegis
```

The app does not load `.env` automatically. `.env.example` lists all configuration keys. On Windows, `python -m aegis` starts Uvicorn with the Selector event loop required by psycopg's async connections.

Without semantic service configuration, the gateway still starts. A request already blocked by local rules returns `POLICY_BLOCKED`; other demo requests needing semantic classification return `SECURITY_UNAVAILABLE` without calling Mock. To enable external semantic classification in demo mode, configure all three server-side values before starting the app:

```powershell
$env:AEGIS_SEMANTIC_URL = 'https://provider.example/v1/chat/completions'
$env:AEGIS_SEMANTIC_API_KEY = 'replace-with-provider-key'
$env:AEGIS_SEMANTIC_MODEL = 'replace-with-classifier-model'
```

Only use synthetic messages in this configuration: the classifier receives all supported message text, including history and completed tool-call arguments. The service must return a Chat Completion whose assistant `content` is JSON in the form `{"results":[{"id":"messages[0].content","label":"CLEAR"}]}`; each input text ID needs exactly one `CLEAR`, `BUSINESS_SECRET`, or `UNCERTAIN` result. An incomplete or uncertain response fails closed. Strict mode cannot configure this external detector.

Try a locally blocked synthetic request in a second PowerShell session:

```powershell
$headers = @{ Authorization = 'Bearer replace-with-a-long-random-client-token' }
$body = @{ model = 'aegis-mock'; messages = @(@{ role = 'user'; content = 'api_key=abcdefghijklmnop12345' }) } | ConvertTo-Json -Depth 5
Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/v1/chat/completions' -Method Post -Headers $headers -ContentType 'application/json' -Body $body
```

The response is `403 POLICY_BLOCKED`; PowerShell may surface it as a web exception. Successful or failed valid requests return `X-Aegis-Conversation-Id`. Send it explicitly on later requests to reuse a conversation; omitting it starts a new one.

## Current decisions

| Decision | Stage 2 behavior |
| --- | --- |
| `BLOCK` | `403 POLICY_BLOCKED`; no semantic or model call when local rules already determine the block. |
| `LOCAL` | Demo calls the fixed Mock response; strict returns `503 LOCAL_UNAVAILABLE` without a trusted local provider. |
| `CLOUD` / `MASK_CLOUD` | `503 ROUTE_UNAVAILABLE`; no cloud model call or masking occurs yet. |

The bundled YAML policy maps API keys and secrets to `BLOCK`, business secrets to `LOCAL`, and detected personal or network identifiers to `MASK_CLOUD`. A custom YAML file can be selected with `AEGIS_POLICY_PATH`; invalid or incomplete policies prevent startup. The request body limit is 128 KiB, and the extracted text limit is 32 KiB. `temperature`, `top_p`, and `max_tokens` remain unsupported by the Mock.

## Check

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
.\.venv\Scripts\ruff format --check .
.\.venv\Scripts\pyright
```

The HTTP tests use a fake store and fake semantic HTTP service. To run the PostgreSQL integration test after `alembic upgrade head`, set `AEGIS_TEST_DATABASE_URL` to the same PostgreSQL URL and rerun pytest.
