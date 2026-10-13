# Aegis Gateway

Stage 4 adds a demo-only OpenAI-compatible cloud model route and request-scoped reversible masking. The external semantic classifier still receives the original supported message text **before masking**. Use synthetic data only.

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

Only use synthetic messages in this configuration: the classifier receives all forwarded message string fields, including history, message names, tool IDs, function names and completed tool-call arguments. The service must return a Chat Completion whose assistant `content` is JSON in the form `{"results":[{"id":"messages[0].content","label":"CLEAR"}]}`; each input text ID needs exactly one `CLEAR`, `BUSINESS_SECRET`, or `UNCERTAIN` result. An incomplete or uncertain response fails closed. Strict mode cannot configure this external detector.

To send `CLOUD` and `MASK_CLOUD` model requests in demo mode, configure a separate cloud endpoint and credential. `AEGIS_CLOUD_BASE_URL` is the API root, such as `https://provider.example/v1`; Aegis appends `/chat/completions`. `AEGIS_MODEL_ALIASES_JSON` maps each client model alias to the actual cloud model ID. A partial cloud configuration prevents startup; with no cloud configuration, these routes return `ROUTE_UNAVAILABLE`.

```powershell
$env:AEGIS_CLOUD_BASE_URL = 'https://provider.example/v1'
$env:AEGIS_CLOUD_API_KEY = 'replace-with-cloud-model-key'
$env:AEGIS_MODEL_ALIASES_JSON = '{"aegis-demo":"replace-with-cloud-model-id"}'
```

The model route receives raw text for `CLOUD` and masked text for `MASK_CLOUD`. The external semantic classifier receives the original text first in both cases. Mask mappings stay in request memory and are discarded after response handling; they are never sent to the cloud or stored in PostgreSQL. A response containing an unresolved request placeholder fails with `SECURITY_UNAVAILABLE`.

Try a locally blocked synthetic request in a second PowerShell session:

```powershell
$headers = @{ Authorization = 'Bearer replace-with-a-long-random-client-token' }
$body = @{ model = 'aegis-mock'; messages = @(@{ role = 'user'; content = 'api_key=abcdefghijklmnop12345' }) } | ConvertTo-Json -Depth 5
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/v1/chat/completions' -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bodyBytes
```

Send JSON as UTF-8 bytes, especially from Windows PowerShell 5.1, so non-ASCII message text reaches Aegis unchanged. Windows PowerShell 5.1 can also decode a UTF-8 response as Latin-1; for a successful response, read `$response.RawContentStream.ToArray()` with `[System.Text.Encoding]::UTF8.GetString(...)` before `ConvertFrom-Json`. The response in the example is `403 POLICY_BLOCKED`; PowerShell may surface it as a web exception. Successful or failed valid requests return `X-Aegis-Conversation-Id`. Send it explicitly on later requests to reuse a conversation; omitting it starts a new one.

## Conversation ownership and administration

Only one request for a given API principal and conversation ID can be active at a time. Another request receives `409 CONVERSATION_BUSY`, with both request and conversation ID headers; retry with the same conversation ID after the first request finishes. It is audited and does not reach detection or a model. Different principals can use the same text ID independently.

Sensitive state never expires or downgrades automatically. An operator can close a conversation from the host after its current request finishes:

```powershell
.\.venv\Scripts\python -m aegis.admin close-conversation --principal-id demo-client --conversation-id <id> --actor <operator-id>
```

The old ID then returns `410 CONVERSATION_CLOSED` and cannot be reopened; the client must use a new ID. Closing retains prior audit records and writes an administration event. There is no public administration HTTP endpoint.

If a process dies or an audit write cannot finish, its conversation may remain occupied. After confirming the original process is stopped, the operator can mark the exact pending request abandoned and release its claim:

```powershell
.\.venv\Scripts\python -m aegis.admin recover-request --principal-id demo-client --conversation-id <id> --request-id <32-character-request-id> --actor <operator-id> --confirm-stopped
```

Recovery does not clear sensitive state. If the abandoned request has no committed policy decision, recovery conservatively marks the conversation sensitive. It records `REQUEST_ABANDONED` and an administration event. A cancelled request with no committed decision is handled the same way before its claim is released. Neither claims nor sensitive state have an automatic expiry. Both commands use `AEGIS_DATABASE_URL` and must run on the host with database access.

## Current decisions

| Decision | Current behavior |
| --- | --- |
| `BLOCK` | `403 POLICY_BLOCKED`; no semantic or model call when local rules already determine the block. |
| `LOCAL` | Demo calls the fixed Mock response; strict returns `503 LOCAL_UNAVAILABLE` without a trusted local provider. |
| `CLOUD` | Demo calls the configured cloud model after successful detection and audit; without cloud configuration, `503 ROUTE_UNAVAILABLE`. |
| `MASK_CLOUD` | Demo masks located entities across all supported text fields, verifies the request, calls the cloud model, then restores response placeholders. Unsafe masking returns `503 SECURITY_UNAVAILABLE` without a model call. |

The bundled YAML policy maps API keys and secrets to `BLOCK`, business secrets to `LOCAL`, and detected personal or network identifiers to `MASK_CLOUD`. A custom YAML file can be selected with `AEGIS_POLICY_PATH`; invalid or incomplete policies prevent startup. The request body limit is 128 KiB, and the extracted text limit is 32 KiB. Cloud requests forward `temperature`, `top_p`, and `max_tokens`; local Mock requests reject them. Strict mode continues to choose `LOCAL` because no trusted local semantic classifier is available.

## Check

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
.\.venv\Scripts\ruff format --check .
.\.venv\Scripts\pyright
```

The HTTP tests use a fake store and fake semantic HTTP service. To run the PostgreSQL integration test after `alembic upgrade head`, set `AEGIS_TEST_DATABASE_URL` to the same PostgreSQL URL and rerun pytest.
