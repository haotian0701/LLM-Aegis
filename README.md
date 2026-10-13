# Aegis Gateway

Stage 5 adds an explicit demo-only cloud simulation for `LOCAL` decisions and a loopback browser demo. Stage 6 begins with a route acceptance matrix and per-request audit details in that demo. A simulated `LOCAL` call sends the original message to an external model; it does not provide local isolation. The external semantic classifier also receives the original supported text **before masking**. Use synthetic data only.

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

To use the configured cloud model for `LOCAL` decisions, explicitly set `AEGIS_DEMO_PROVIDER=simulated_local` instead of `mock` and restart Aegis. It reuses `AEGIS_CLOUD_BASE_URL`, `AEGIS_CLOUD_API_KEY`, and `AEGIS_MODEL_ALIASES_JSON`; incomplete cloud configuration prevents startup. This route is identified as `simulated-local-openai-compatible` in the audit, with `policy_action=LOCAL`, `actual_destination=EXTERNAL`, and `simulation=true` after model egress intent commits. Security failures and model errors do not fall back to another route.

In demo mode, open **http://127.0.0.1:8000/** on the same computer for the browser demo. The page automatically uses a temporary, process-scoped token for its own audit principal; it never displays the configured long-lived client token. The page and temporary token are only available on loopback and disappear in strict mode. It provides synthetic examples for `CLOUD`, `MASK_CLOUD`, `BLOCK`, and a follow-up `LOCAL` request using the blocked conversation ID. The follow-up deliberately omits the earlier text to demonstrate persisted security state. The page sends only the current message, so a separate client must pass history when model context is needed.

After each browser request, the page reads `/demo/audit/{request_id}` and shows detected categories, detection status, masking status, and model call status. The request ID can also be pasted into the lookup field. The endpoint accepts only the current process's browser token on loopback and returns records belonging to that browser principal; it returns no prompt text, Prompt HMAC, or credentials. `masking_status=SUCCEEDED` means the gateway validated the masked request and committed model egress intent. The outbound-payload acceptance test verifies what a fake cloud model actually receives:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_stage_six.py tests/test_cloud_routing.py::test_masked_history_and_tool_arguments_reach_cloud_as_placeholders -q
```

Completed decisions include `X-Aegis-Policy-Action`, `X-Aegis-Actual-Destination`, and `X-Aegis-Simulation` response headers. Errors before a policy decision do not include these headers.

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
| `LOCAL` | Demo calls the selected Mock or explicit external simulated provider; strict returns `503 LOCAL_UNAVAILABLE` without a trusted local provider. |
| `CLOUD` | Demo calls the configured cloud model after successful detection and audit; without cloud configuration, `503 ROUTE_UNAVAILABLE`. |
| `MASK_CLOUD` | Demo masks located entities across all supported text fields, verifies the request, calls the cloud model, then restores response placeholders. Unsafe masking returns `503 SECURITY_UNAVAILABLE` without a model call. |

The bundled YAML policy maps API keys and secrets to `BLOCK`, business secrets to `LOCAL`, and detected personal or network identifiers to `MASK_CLOUD`. A custom YAML file can be selected with `AEGIS_POLICY_PATH`; invalid or incomplete policies prevent startup. The request body limit is 128 KiB, and the extracted text limit is 32 KiB. Cloud and simulated `LOCAL` requests forward `temperature`, `top_p`, and `max_tokens`; local Mock requests reject them. Strict mode continues to choose `LOCAL` because no trusted local semantic classifier is available.

## Check

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
.\.venv\Scripts\ruff format --check .
.\.venv\Scripts\pyright
```

The HTTP tests use a fake store and fake semantic HTTP service. To run the PostgreSQL integration test after `alembic upgrade head`, set `AEGIS_TEST_DATABASE_URL` to the same PostgreSQL URL and rerun pytest.
