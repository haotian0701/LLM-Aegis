# Aegis Gateway

[![CI](https://github.com/haotian0701/LLM-Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/haotian0701/LLM-Aegis/actions/workflows/ci.yml)

## Decision Console

Screenshots from the local browser fixture using **synthetic requests and fake providers**: four policy outcomes, followed by the Audit Inspect drawer with a masked request preview.

![Decision Console with four routing outcomes and audit records](assets/console-routes.png)

![Audit Inspect drawer showing the MASK_CLOUD decision and masked model messages](assets/audit-inspect.png)

Aegis is a Python gateway that checks an OpenAI-compatible chat request before dispatching it to a model. It combines local detection, a configurable policy, optional semantic classification, masking, provider routing, conversation state, and a PostgreSQL audit trail. The Decision Console is a loopback-only interface for exploring those decisions.

The console can send single-turn requests or resend successful turns in continuous chat. It exposes routing results, a filterable audit list, an Inspect drawer, and conversation state. It is available only on loopback in `demo` mode; `strict` mode exposes neither the console nor its demo APIs.

This is an engineering demo. It runs on a CPU without a local LLM; the `LOCAL` route uses Mock by default. An explicitly selected `simulated_local` route calls an **external** model. Strict mode does not load external detectors or providers and currently returns `LOCAL_UNAVAILABLE` when a trusted local model is needed.

## Request flow

```mermaid
flowchart LR
    Client["Client / local Decision Console"] --> Gateway["FastAPI: auth, limits, conversation claim"]
    Gateway --> Detection["Local rules + spaCy NER"]
    Detection -->|eligible demo request| Semantic["External semantic classifier: original text"]
    Detection --> Policy["Deterministic YAML policy"]
    Semantic --> Policy
    Policy --> Decision{"Action"}
    Decision -->|BLOCK| Block["403; no model call"]
    Decision -->|LOCAL| Local["Mock or explicit simulated external model"]
    Decision -->|CLOUD| Cloud["External model: original request"]
    Decision -->|MASK_CLOUD| Mask["Mask + validate"] --> MaskedCloud["External model: masked request"]
    Gateway -.-> Store[("PostgreSQL: audit + conversation state")]
    Policy -.-> Store
    Block -.-> Store
    Local -.-> Store
    Cloud -.-> Store
    MaskedCloud -.-> Store
```

The gateway records external egress intent before an external classifier or model call. A storage, detection, masking, or provider failure does not silently switch to another route. A conversation's sensitive state persists across requests; concurrent requests for the same principal and conversation receive `409 CONVERSATION_BUSY`.

| Decision | Default behavior in demo mode |
| --- | --- |
| `BLOCK` | Reject locally with `403 POLICY_BLOCKED`; no semantic or model call if rules already determine the block. |
| `LOCAL` | Use Mock, or an explicitly configured external `simulated_local` provider. The audit distinguishes policy action from actual destination. |
| `CLOUD` | Send the original request to the configured external model. |
| `MASK_CLOUD` | Mask detected text before the model call, then restore response placeholders locally. Unsafe or unresolved masking fails closed. |

The bundled policy maps API keys and secrets to `BLOCK`, business secrets to `LOCAL`, and personal or network identifiers to `MASK_CLOUD`. Customers can supply a validated YAML policy. The gateway records decision and provider metadata in PostgreSQL; demo-browser `MASK_CLOUD` audit details also retain the **masked** model-message preview. Unmasked portions of that preview remain readable. Reversible mask mappings are not stored in the audit.

### Where data can leave the machine

- **External semantic classifier:** In demo mode, eligible requests send their original supported message text, including history and tool-call arguments, to the configured classifier **before masking**. With no classifier configured, these requests fail with `SECURITY_UNAVAILABLE`.
- **`CLOUD` / `MASK_CLOUD`:** The external model receives original or masked text, respectively. Mask mappings remain in request memory and are discarded after response handling.
- **`LOCAL`:** Mock stays in process. `simulated_local` sends the original request to an external model and is labeled `actual_destination=EXTERNAL`, `simulation=true` in the audit. Strict mode does not allow that simulation.

Use only synthetic messages with external demo services. [`.env.example`](.env.example) lists the optional configuration keys.

## Run locally (PowerShell)

Requires Python 3.13, Node.js 24, and Docker Desktop. The included spaCy English NER model runs on a CPU. The app does not load `.env` automatically.

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
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python -m aegis
```

Open **http://127.0.0.1:8000/** on the same machine. The console obtains a temporary, process-scoped demo token. With the basic configuration above, locally blocked examples work; other requests need a semantic classifier, and external model routes need a cloud provider.

To exercise all four decisions, stop the gateway, configure the optional external classifier and model services below, and start it again. Use only synthetic requests. The semantic URL points to a chat-completions endpoint; the cloud base URL is its API root, without `/chat/completions`.

```powershell
$env:AEGIS_SEMANTIC_URL = 'https://provider.example/v1/chat/completions'
$env:AEGIS_SEMANTIC_API_KEY = 'replace-with-classifier-key'
$env:AEGIS_SEMANTIC_MODEL = 'replace-with-classifier-model'
$env:AEGIS_CLOUD_BASE_URL = 'https://provider.example/v1'
$env:AEGIS_CLOUD_API_KEY = 'replace-with-model-key'
$env:AEGIS_MODEL_ALIASES_JSON = '{"aegis-mock":"replace-with-cloud-model-id"}'
.\.venv\Scripts\python -m aegis
```

The classifier must return JSON with exactly one `CLEAR`, `BUSINESS_SECRET`, or `UNCERTAIN` label for every input text ID; missing or uncertain results fail closed. The optional `AEGIS_DEMO_PROVIDER=simulated_local` setting uses the configured cloud provider for `LOCAL` decisions and records the actual external destination. For frontend development, start the Python API, then run `npm run dev` in `frontend/`.

## Controlled task demo (Runtime Firewall stages 0–1)

In `demo` mode, the same Console workspace can run a synthetic task and show an ordered audit timeline for each model, retrieval, tool-call, and tool-result boundary. The fixed fixture accepts these three prompts: `Summarize the authorized launch notes.`, `Summarize the suspicious operations note.`, and `Show the timeout scenario.` The first returns an authorized synthetic document and source. The second causes the fake model to propose `send_email`; the independent tool policy denies it before the adapter runs. The third records an unknown result after a synthetic tool timeout. Retrieval excludes documents belonging to other principals.

The separate `POST /v1/agent/runs` endpoint is available only in `demo` mode. It accepts an API bearer token (or the loopback Console token), the existing optional `X-Aegis-Conversation-Id` header, and a JSON body such as:

```json
{"model":"aegis-mock","input":"Summarize the authorized launch notes.","engine":"fixture"}
```

`engine` defaults to `fixture`; success returns `task_id`, `answer`, and permitted document `sources`. Errors use the gateway's existing error envelope. The task ID is also the `X-Aegis-Request-Id` and can be inspected through the demo audit drawer. Step records retain metadata and digests, not raw document bodies or complete tool arguments.

Selecting `engine=cloud` accepts synthetic free-text tasks and uses the configured OpenAI-compatible model for structured tool calls. It requires the external semantic classifier; that classifier sees original task and tool-result text before model masking. Every model request uses the existing four route policy. `MASK_CLOUD` sends masked text, and `LOCAL` cannot silently use a cloud model unless the process explicitly selects `simulated_local`. Cloud tool calls still pass the same independent tool policy. Use only synthetic inputs with external services.

This stage uses a fixed document fixture and local fake tool adapter. An MCP server, a full RAG pipeline, external MCP proxying, and real write operations are outside the implemented stage.

## Verification

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
.\.venv\Scripts\ruff format --check .
.\.venv\Scripts\pyright
```

CI runs backend checks, PostgreSQL integration tests, frontend checks, and a browser smoke test with fake providers. Run `npm run browser:smoke` from `frontend/` to reproduce the four-route browser fixture locally.
