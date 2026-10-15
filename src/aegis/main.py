"""Aegis HTTP gateway with fail-closed detection and conversation coordination."""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import json
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.agent import AgentFailure, AgentService
from aegis.agent_provider import AgentModel, OpenAICompatibleAgentModel
from aegis.config import Settings
from aegis.detection import (
    NerDetector,
    RuleDetector,
    SpacyEnglishNer,
    extract_fragments,
    text_bytes,
    unique_findings,
)
from aegis.injection import InjectionDetector, OpenAICompatibleSourceDetector
from aegis.masking import MaskingError, mask_request
from aegis.policy import UPGRADE_CATEGORIES, Action, PolicyEngine
from aegis.provider import (
    MockLocalProvider,
    ModelProvider,
    OpenAICompatibleCloudProvider,
    SimulatedLocalProvider,
)
from aegis.schemas import (
    ChatCompletionChoice,
    ChatCompletionMessage,
    ChatCompletionResponse,
    ChatRequest,
)
from aegis.semantic import OpenAICompatibleSemanticDetector, SemanticDetector
from aegis.store import AuditDraft, PostgresRequestStore, RequestStore
from aegis.workspace_workflow import (
    WORKSPACE_MODEL_TOOLS,
    WorkspaceRequest,
    WorkspaceTools,
    WorkspaceWorkflow,
)

CONVERSATION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
MAX_BODY_BYTES = 128 * 1024
MAX_TEXT_BYTES = 32 * 1024
DEMO_PRINCIPAL = "__aegis_demo_browser__"
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _audit_cursor(
    secret: str, filters: dict[str, str | None], started_at: datetime, request_id: str
) -> str:
    data = json.dumps(
        {
            "principal": DEMO_PRINCIPAL,
            "filters": filters,
            "started_at": started_at.isoformat(),
            "request_id": request_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), data, sha256).digest()
    return base64.urlsafe_b64encode(data + signature).decode("ascii").rstrip("=")


def _read_audit_cursor(
    cursor: str, secret: str, filters: dict[str, str | None]
) -> tuple[datetime, str]:
    if len(cursor) > 2048:
        raise ValueError("invalid cursor")
    try:
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        data, signature = raw[:-32], raw[-32:]
        expected = hmac.new(secret.encode("utf-8"), data, sha256).digest()
        if len(signature) != 32 or not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        payload = json.loads(data)
        if payload["principal"] != DEMO_PRINCIPAL or payload["filters"] != filters:
            raise ValueError("cursor scope mismatch")
        started_at = datetime.fromisoformat(payload["started_at"])
        request_id = payload["request_id"]
        if started_at.tzinfo is None or not isinstance(request_id, str):
            raise ValueError("invalid cursor contents")
        if REQUEST_ID_PATTERN.fullmatch(request_id) is None:
            raise ValueError("invalid request ID")
        return started_at, request_id
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid cursor") from exc


def _local_demo_request(request: Request) -> bool:
    if request.client is None or request.url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return False
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _route_headers(
    response: JSONResponse, action: Action, destination: str, simulation: bool
) -> JSONResponse:
    response.headers["X-Aegis-Policy-Action"] = action.value
    response.headers["X-Aegis-Actual-Destination"] = destination
    response.headers["X-Aegis-Simulation"] = "true" if simulation else "false"
    return response


def _error(
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    conversation_id: str | None = None,
) -> JSONResponse:
    headers = {"X-Aegis-Request-Id": request_id}
    if conversation_id is not None:
        headers["X-Aegis-Conversation-Id"] = conversation_id
    return JSONResponse(
        status_code=status_code,
        headers=headers,
        content={
            "error": {
                "message": message,
                "type": "aegis_error",
                "code": code,
                "request_id": request_id,
            }
        },
    )


def _authenticate(header: str | None, api_keys: dict[str, str]) -> str | None:
    if header is None or not header.startswith("Bearer "):
        return None
    token = header[len("Bearer ") :]
    if not token:
        return None
    matched: str | None = None
    for principal, configured_token in api_keys.items():
        if hmac.compare_digest(token, configured_token):
            matched = principal
    return matched


def _prompt_hmac(request: ChatRequest, secret: str) -> str:
    canonical = json.dumps(
        [message.model_dump(exclude_none=True) for message in request.messages],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical, sha256).hexdigest()


def _rejection(request_id: str, principal_id: str | None, code: str) -> AuditDraft:
    return AuditDraft(
        request_id=request_id,
        principal_id=principal_id,
        conversation_id=None,
        status="REJECTED",
        model_alias=None,
        prompt_hmac=None,
        error_code=code,
    )


def create_app(
    settings: Settings | None = None,
    *,
    store: RequestStore | None = None,
    provider: ModelProvider | None = None,
    cloud_provider: ModelProvider | None = None,
    rule_detector: RuleDetector | None = None,
    ner_detector: NerDetector | None = None,
    semantic_detector: SemanticDetector | None = None,
    policy: PolicyEngine | None = None,
    agent_model: AgentModel | None = None,
    injection_detector: InjectionDetector | None = None,
    workspace_root: Path | None = None,
) -> FastAPI:
    """Build the gateway; tests may inject detectors, storage and providers."""
    settings = settings or Settings.from_env()
    if settings.run_mode == "strict":
        if provider is not None and (provider.simulation or provider.destination == "EXTERNAL"):
            raise ValueError("strict mode cannot use an external or simulated provider")
        if semantic_detector is not None and semantic_detector.external:
            raise ValueError("strict mode cannot use an external semantic detector")
        if cloud_provider is not None:
            raise ValueError("strict mode cannot load an external cloud provider")
    elif provider is None:
        if settings.demo_provider == "simulated_local":
            assert settings.cloud_base_url is not None
            assert settings.cloud_api_key is not None
            provider = SimulatedLocalProvider(
                base_url=settings.cloud_base_url,
                api_key=settings.cloud_api_key,
                model_aliases=settings.model_aliases,
            )
        else:
            provider = MockLocalProvider()

    policy = policy or PolicyEngine.load(settings.policy_path)
    rule_detector = rule_detector or RuleDetector()
    ner_detector = ner_detector or SpacyEnglishNer()
    if settings.run_mode == "demo" and semantic_detector is None and settings.semantic_url:
        assert settings.semantic_api_key is not None
        assert settings.semantic_model is not None
        semantic_detector = OpenAICompatibleSemanticDetector(
            url=settings.semantic_url,
            api_key=settings.semantic_api_key,
            model=settings.semantic_model,
        )
    if settings.run_mode == "demo" and cloud_provider is None and settings.cloud_base_url:
        assert settings.cloud_api_key is not None
        cloud_provider = OpenAICompatibleCloudProvider(
            base_url=settings.cloud_base_url,
            api_key=settings.cloud_api_key,
            model_aliases=settings.model_aliases,
        )

    engine = None
    sessions = None
    if store is None:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        store = PostgresRequestStore(sessions)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        if engine is not None:
            await engine.dispose()

    app = FastAPI(title="Aegis Gateway", version="0.5.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.provider = provider
    app.state.cloud_provider = cloud_provider
    app.state.policy = policy

    workspace_workflow: WorkspaceWorkflow | None = None
    if settings.run_mode == "demo" and all(
        (settings.cloud_base_url, settings.cloud_api_key, settings.semantic_url)
    ):
        assert settings.cloud_base_url is not None and settings.cloud_api_key is not None
        assert settings.semantic_url is not None
        assert settings.semantic_api_key is not None and settings.semantic_model is not None
        workspace_model = agent_model or OpenAICompatibleAgentModel(
            base_url=settings.cloud_base_url,
            api_key=settings.cloud_api_key,
            model_aliases=settings.model_aliases,
            tools=WORKSPACE_MODEL_TOOLS,
        )
        workspace_gate = AgentService(
            settings=settings,
            store=store,
            policy=policy,
            rule_detector=rule_detector,
            ner_detector=ner_detector,
            semantic_detector=semantic_detector,
            cloud_model=workspace_model,
        )
        workspace_workflow = WorkspaceWorkflow(
            settings,
            store,
            workspace_gate,
            WorkspaceTools(workspace_root or Path(__file__).resolve().parents[2]),
            injection_detector
            or OpenAICompatibleSourceDetector(
                settings.semantic_url, settings.semantic_api_key, settings.semantic_model
            ),
        )
    app.state.workspace_workflow = workspace_workflow

    demo_token: str | None = None
    demo_headers: dict[str, str] = {}
    if settings.run_mode == "demo":
        if DEMO_PRINCIPAL in settings.api_keys:
            raise ValueError("reserved demo browser principal is configured")
        demo_token = secrets.token_urlsafe(32)
        demo_headers = {
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": (
                "default-src 'none'; script-src 'self'; "
                "style-src 'self'; connect-src 'self'; img-src 'self' data:; "
                "base-uri 'none'; form-action 'none'"
            ),
        }

        @app.get("/", include_in_schema=False)
        async def demo_home(request: Request) -> HTMLResponse:
            if not _local_demo_request(request):
                return HTMLResponse("Not found", status_code=404)
            index = FRONTEND_DIST / "index.html"
            if not index.is_file():
                return HTMLResponse(
                    "<h1>Aegis frontend build required</h1><p>Run npm ci and npm run build "
                    "in the frontend directory.</p>",
                    status_code=503,
                    headers=demo_headers,
                )
            return HTMLResponse(index.read_text(encoding="utf-8"), headers=demo_headers)

        @app.get("/assets/{asset_path:path}", include_in_schema=False)
        async def demo_asset(request: Request, asset_path: str) -> Response:
            if not _local_demo_request(request):
                return JSONResponse({"detail": "Not found"}, status_code=404)
            asset_root = (FRONTEND_DIST / "assets").resolve()
            asset = (asset_root / asset_path).resolve()
            if not asset.is_relative_to(asset_root) or not asset.is_file():
                return JSONResponse({"detail": "Not found"}, status_code=404)
            return FileResponse(asset, headers=demo_headers)

        @app.get("/demo/bootstrap", include_in_schema=False)
        async def demo_bootstrap(request: Request) -> JSONResponse:
            if not _local_demo_request(request):
                return JSONResponse({"detail": "Not found"}, status_code=404)
            return JSONResponse(
                {
                    "token": demo_token,
                    "models": list(settings.model_aliases),
                    "local_mode": settings.demo_provider,
                },
                headers=demo_headers,
            )

        def demo_read_denial(request: Request) -> JSONResponse | None:
            if not _local_demo_request(request):
                return JSONResponse({"detail": "Not found"}, status_code=404, headers=demo_headers)
            authorization = request.headers.get("authorization")
            if (
                authorization is None
                or not authorization.startswith("Bearer ")
                or demo_token is None
                or not hmac.compare_digest(authorization[len("Bearer ") :], demo_token)
            ):
                return JSONResponse(
                    {"detail": "Unauthorized"}, status_code=401, headers=demo_headers
                )
            return None

        @app.get("/demo/audits", include_in_schema=False)
        async def demo_audits(request: Request) -> JSONResponse:
            denial = demo_read_denial(request)
            if denial is not None:
                return denial
            query = request.query_params
            try:
                if set(query) - {"limit", "cursor", "policy_action", "status", "conversation_id"}:
                    raise ValueError("unknown filter")
                limit = int(query.get("limit", "20"))
                if not 1 <= limit <= 100:
                    raise ValueError("invalid limit")
                action = query.get("policy_action")
                status = query.get("status")
                conversation_id = query.get("conversation_id")
                if action is not None and action not in {item.value for item in Action}:
                    raise ValueError("invalid action")
                if status is not None and status not in {
                    "PENDING",
                    "SUCCEEDED",
                    "FAILED",
                    "REJECTED",
                    "BLOCKED",
                }:
                    raise ValueError("invalid status")
                if (
                    conversation_id is not None
                    and CONVERSATION_ID_PATTERN.fullmatch(conversation_id) is None
                ):
                    raise ValueError("invalid conversation ID")
                filters = {
                    "policy_action": action,
                    "status": status,
                    "conversation_id": conversation_id,
                }
                before = (
                    _read_audit_cursor(query["cursor"], settings.hmac_key, filters)
                    if "cursor" in query
                    else None
                )
            except ValueError:
                return JSONResponse(
                    {"detail": "Invalid audit query"}, status_code=400, headers=demo_headers
                )
            try:
                items = await store.list_audits(
                    DEMO_PRINCIPAL,
                    limit=limit + 1,
                    policy_action=action,
                    status=status,
                    conversation_id=conversation_id,
                    before=before,
                )
            except Exception:
                return JSONResponse(
                    {"detail": "Audit unavailable"}, status_code=503, headers=demo_headers
                )
            page = items[:limit]
            next_cursor = None
            if len(items) > limit and page and page[-1].started_at is not None:
                next_cursor = _audit_cursor(
                    settings.hmac_key, filters, page[-1].started_at, page[-1].request_id
                )
            return JSONResponse(
                jsonable_encoder(
                    {"items": [asdict(item) for item in page], "next_cursor": next_cursor}
                ),
                headers=demo_headers,
            )

        @app.get("/demo/conversations/{conversation_id}", include_in_schema=False)
        async def demo_conversation(request: Request, conversation_id: str) -> JSONResponse:
            denial = demo_read_denial(request)
            if denial is not None:
                return denial
            if CONVERSATION_ID_PATTERN.fullmatch(conversation_id) is None:
                return JSONResponse({"detail": "Not found"}, status_code=404, headers=demo_headers)
            try:
                summary = await store.get_conversation_summary(conversation_id, DEMO_PRINCIPAL)
            except Exception:
                return JSONResponse(
                    {"detail": "Conversation unavailable"}, status_code=503, headers=demo_headers
                )
            if summary is None:
                return JSONResponse({"detail": "Not found"}, status_code=404, headers=demo_headers)
            return JSONResponse(jsonable_encoder(asdict(summary)), headers=demo_headers)

        @app.get("/demo/audit/{request_id}", include_in_schema=False)
        async def demo_audit(request: Request, request_id: str) -> JSONResponse:
            denial = demo_read_denial(request)
            if denial is not None:
                return denial
            if REQUEST_ID_PATTERN.fullmatch(request_id) is None:
                return JSONResponse({"detail": "Not found"}, status_code=404, headers=demo_headers)
            try:
                summary = await store.get_audit_summary(request_id, DEMO_PRINCIPAL)
            except Exception:
                return JSONResponse(
                    {"detail": "Audit unavailable"}, status_code=503, headers=demo_headers
                )
            if summary is None:
                return JSONResponse({"detail": "Not found"}, status_code=404, headers=demo_headers)
            return JSONResponse(jsonable_encoder(asdict(summary)), headers=demo_headers)

    if workspace_workflow is not None:
        assert demo_token is not None

        @app.get("/workspace/bootstrap", include_in_schema=False)
        async def workspace_bootstrap(request: Request) -> JSONResponse:
            if not _local_demo_request(request):
                return JSONResponse({"detail": "Not found"}, status_code=404)
            return JSONResponse(
                {
                    "token": demo_token,
                    "models": list(settings.model_aliases),
                    "root": workspace_workflow.tools.root.name,
                },
                headers=demo_headers,
            )

        @app.post("/v1/workflows/workspace")
        async def workspace_run(request: Request) -> JSONResponse:
            task_id = uuid4().hex
            if not _local_demo_request(request):
                return _error(404, "NOT_FOUND", "Workflow is local only.", task_id)
            authorization = request.headers.get("authorization", "")
            if not authorization.startswith("Bearer ") or not hmac.compare_digest(
                authorization[len("Bearer ") :], demo_token
            ):
                return _error(401, "UNAUTHORIZED", "Invalid demo token.", task_id)
            try:
                if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
                    raise ValueError("JSON required")
                raw = await request.body()
                if len(raw) > MAX_BODY_BYTES:
                    raise ValueError("body too large")
                payload = WorkspaceRequest.model_validate_json(raw)
                if payload.model not in settings.model_aliases:
                    raise ValueError("unknown model")
            except (ValueError, ValidationError):
                return _error(400, "INVALID_REQUEST", "Invalid project task.", task_id)
            conversation_id = request.headers.get("x-aegis-conversation-id") or uuid4().hex
            if CONVERSATION_ID_PATTERN.fullmatch(conversation_id) is None:
                return _error(400, "INVALID_REQUEST", "Invalid conversation ID.", task_id)
            draft = AuditDraft(
                request_id=task_id,
                principal_id=DEMO_PRINCIPAL,
                conversation_id=conversation_id,
                status="PENDING",
                model_alias=payload.model,
                prompt_hmac=hmac.new(
                    settings.hmac_key.encode(), payload.input.encode(), sha256
                ).hexdigest(),
                task_type="AGENT",
            )
            try:
                begin = await store.begin_request(draft)
            except Exception:
                return _error(503, "AUDIT_UNAVAILABLE", "Audit storage is unavailable.", task_id)
            if begin.status != "CLAIMED":
                code = "CONVERSATION_BUSY" if begin.status == "BUSY" else "CONVERSATION_CLOSED"
                return _error(409 if begin.status == "BUSY" else 410, code, code, task_id)
            started = time.perf_counter()
            result = None
            failure = None
            try:
                async with asyncio.timeout(60):
                    result = await workspace_workflow.run(
                        task_id, payload, bool(begin.was_sensitive)
                    )
            except AgentFailure as exc:
                failure = exc
            except TimeoutError:
                failure = AgentFailure(504, "TASK_TIMEOUT", "Project task timed out.")
            except Exception:
                failure = AgentFailure(502, "WORKFLOW_ERROR", "Project task failed.")
            assert failure is not None or result is not None
            if failure is not None:
                final_status = "BLOCKED" if failure.http_status == 403 else "FAILED"
                final_error = failure.code
            else:
                assert result is not None
                final_status = "BLOCKED" if result.status == "SOURCE_EXCLUDED" else "SUCCEEDED"
                final_error = "INJECTION_DETECTED" if result.status == "SOURCE_EXCLUDED" else None
            try:
                await store.finish_dispatch(
                    task_id,
                    status=final_status,
                    error_code=final_error,
                    duration_ms=round((time.perf_counter() - started) * 1000),
                )
            except Exception:
                return _error(503, "AUDIT_UNAVAILABLE", "Audit storage is unavailable.", task_id)
            if failure:
                return _error(
                    failure.http_status,
                    failure.code,
                    failure.message,
                    task_id,
                    conversation_id,
                )
            assert result is not None
            return JSONResponse(
                jsonable_encoder(
                    {
                        "task_id": task_id,
                        "status": result.status,
                        "answer": result.answer,
                        "sources": result.sources,
                    }
                ),
                headers={"X-Aegis-Request-Id": task_id, "X-Aegis-Conversation-Id": conversation_id},
            )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(http_request: Request) -> JSONResponse:
        request_id = uuid4().hex
        started = time.perf_counter()

        async def reject(
            status_code: int, code: str, message: str, principal_id: str | None
        ) -> JSONResponse:
            try:
                await store.record_rejection(_rejection(request_id, principal_id, code))
            except Exception:
                return _error(503, "AUDIT_UNAVAILABLE", "Audit storage is unavailable.", request_id)
            return _error(status_code, code, message, request_id)

        principal_id = _authenticate(http_request.headers.get("authorization"), settings.api_keys)
        if principal_id is None and demo_token is not None and _local_demo_request(http_request):
            header = http_request.headers.get("authorization")
            if header is not None and header.startswith("Bearer "):
                if hmac.compare_digest(header[len("Bearer ") :], demo_token):
                    principal_id = DEMO_PRINCIPAL
        if principal_id is None:
            return await reject(401, "UNAUTHORIZED", "Invalid API token.", None)
        if (
            http_request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            return await reject(
                400, "INVALID_REQUEST", "JSON request body is required.", principal_id
            )

        body = bytearray()
        async for chunk in http_request.stream():
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                return await reject(
                    413, "INVALID_REQUEST", "Request body is too large.", principal_id
                )
            body.extend(chunk)
        try:
            raw_body = json.loads(body.decode("utf-8"))
            chat_request = ChatRequest.model_validate(raw_body)
        except (ValueError, ValidationError, UnicodeDecodeError):
            return await reject(
                400, "INVALID_REQUEST", "Invalid or unsupported request body.", principal_id
            )
        if chat_request.model not in settings.model_aliases:
            return await reject(400, "INVALID_REQUEST", "Unknown model alias.", principal_id)
        supplied_id = http_request.headers.get("x-aegis-conversation-id")
        if supplied_id is not None and CONVERSATION_ID_PATTERN.fullmatch(supplied_id) is None:
            return await reject(400, "INVALID_REQUEST", "Invalid conversation ID.", principal_id)
        fragments = extract_fragments(chat_request)
        if text_bytes(fragments) > MAX_TEXT_BYTES:
            return await reject(413, "INVALID_REQUEST", "Message text is too large.", principal_id)
        conversation_id = supplied_id if supplied_id is not None else uuid4().hex

        draft = AuditDraft(
            request_id=request_id,
            principal_id=principal_id,
            conversation_id=conversation_id,
            status="PENDING",
            model_alias=chat_request.model,
            prompt_hmac=_prompt_hmac(chat_request, settings.hmac_key),
        )
        try:
            begin = await store.begin_request(draft)
        except Exception:
            return _error(
                503,
                "AUDIT_UNAVAILABLE",
                "Audit storage is unavailable.",
                request_id,
                conversation_id,
            )
        if begin.status == "BUSY":
            return _error(
                409,
                "CONVERSATION_BUSY",
                "Conversation has an active request; retry later.",
                request_id,
                conversation_id,
            )
        if begin.status == "CLOSED":
            return _error(
                410,
                "CONVERSATION_CLOSED",
                "Conversation is closed; use a new conversation ID.",
                request_id,
                conversation_id,
            )
        assert begin.was_sensitive is not None
        was_sensitive = begin.was_sensitive

        async def process_claimed() -> JSONResponse:
            async def finish_error(
                code: str,
                message: str,
                *,
                detection_status: str,
                semantic_call_status: str | None = None,
            ) -> JSONResponse:
                try:
                    await store.finish_dispatch(
                        request_id,
                        status="FAILED",
                        error_code=code,
                        duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
                        detection_status=detection_status,
                        semantic_call_status=semantic_call_status,
                        detected_categories=sorted(
                            {finding.category.value for finding in findings}
                        ),
                        detector_durations_ms=durations,
                    )
                except Exception:
                    return _error(
                        503,
                        "AUDIT_UNAVAILABLE",
                        "Audit storage is unavailable.",
                        request_id,
                        conversation_id,
                    )
                return _error(503, code, message, request_id, conversation_id)

            findings = []
            durations: dict[str, int] = {}
            local_failure = False
            locally_blocked = False
            try:
                detector_started = time.perf_counter()
                findings.extend(rule_detector.detect(fragments))
                durations["rules"] = max(0, round((time.perf_counter() - detector_started) * 1000))
                locally_blocked = (
                    policy.decide(
                        (finding.category for finding in findings), was_sensitive=was_sensitive
                    )
                    == Action.BLOCK
                )
                if not locally_blocked:
                    detector_started = time.perf_counter()
                    findings.extend(await ner_detector.detect(fragments))
                    durations["ner"] = max(
                        0, round((time.perf_counter() - detector_started) * 1000)
                    )
            except Exception:
                local_failure = True
            findings = unique_findings(findings)
            categories = {finding.category for finding in findings}
            if not local_failure:
                try:
                    locally_blocked = (
                        policy.decide(categories, was_sensitive=was_sensitive) == Action.BLOCK
                    )
                except Exception:
                    local_failure = True

            if local_failure and settings.run_mode == "demo":
                return await finish_error(
                    "SECURITY_UNAVAILABLE",
                    "Security detection is unavailable.",
                    detection_status="FAILED",
                )

            semantic_succeeded = False
            if (
                not local_failure
                and not locally_blocked
                and not was_sensitive
                and settings.run_mode == "demo"
                and fragments
            ):
                if semantic_detector is None:
                    return await finish_error(
                        "SECURITY_UNAVAILABLE",
                        "Semantic detection is unavailable.",
                        detection_status="UNAVAILABLE",
                    )
                try:
                    await store.record_external_intent(
                        request_id,
                        provider_name=semantic_detector.name,
                        model=semantic_detector.model,
                    )
                except Exception:
                    return _error(
                        503,
                        "AUDIT_UNAVAILABLE",
                        "Audit storage is unavailable.",
                        request_id,
                        conversation_id,
                    )
                detector_started = time.perf_counter()
                try:
                    findings.extend(await semantic_detector.detect(fragments))
                    durations["semantic"] = max(
                        0, round((time.perf_counter() - detector_started) * 1000)
                    )
                    semantic_succeeded = True
                except Exception:
                    durations["semantic"] = max(
                        0, round((time.perf_counter() - detector_started) * 1000)
                    )
                    return await finish_error(
                        "SECURITY_UNAVAILABLE",
                        "Semantic detection failed.",
                        detection_status="FAILED",
                        semantic_call_status="FAILED",
                    )

            findings = unique_findings(findings)
            categories = {finding.category for finding in findings}
            try:
                action = policy.decide(categories, was_sensitive=was_sensitive)
            except Exception:
                if settings.run_mode == "demo":
                    return await finish_error(
                        "SECURITY_UNAVAILABLE",
                        "Policy evaluation failed.",
                        detection_status="FAILED",
                    )
                action = Action.LOCAL
                local_failure = True
            if (local_failure or settings.run_mode == "strict") and action != Action.BLOCK:
                action = Action.LOCAL
            detection_status = (
                "DEGRADED" if local_failure or settings.run_mode == "strict" else "COMPLETE"
            )
            try:
                action = await store.record_decision(
                    request_id,
                    principal_id=principal_id,
                    conversation_id=conversation_id,
                    action=action,
                    categories=sorted(category.value for category in categories),
                    detection_status=detection_status,
                    detector_durations_ms=durations,
                    upgrade_sensitive=bool(categories & UPGRADE_CATEGORIES),
                    local_destination=(
                        provider.destination
                        if provider is not None and provider.destination != "EXTERNAL"
                        else "NONE"
                    ),
                    local_provider_name=provider.name if provider is not None else None,
                    local_model=settings.model_aliases[chat_request.model]
                    if provider is not None
                    else None,
                    local_simulation=provider.simulation if provider is not None else False,
                    semantic_succeeded=semantic_succeeded,
                )
            except Exception:
                return _error(
                    503,
                    "AUDIT_UNAVAILABLE",
                    "Audit storage is unavailable.",
                    request_id,
                    conversation_id,
                )

            status = "SUCCEEDED"
            error_code: str | None = None
            model_call_status: str | None = None
            masking_status: str | None = None
            response: JSONResponse | None = None
            external_local = (
                action == Action.LOCAL
                and provider is not None
                and provider.destination == "EXTERNAL"
            )
            route_destination = (
                provider.destination
                if action == Action.LOCAL and provider is not None and not external_local
                else "NONE"
            )
            route_simulation = (
                action == Action.LOCAL and provider is not None and provider.simulation
            )
            if action == Action.BLOCK:
                status = "BLOCKED"
                error_code = "POLICY_BLOCKED"
                response = _error(
                    403, error_code, "Request blocked by policy.", request_id, conversation_id
                )
            elif action in {Action.CLOUD, Action.MASK_CLOUD}:
                if cloud_provider is None:
                    status = "FAILED"
                    error_code = "ROUTE_UNAVAILABLE"
                    response = _error(
                        503,
                        error_code,
                        "Cloud provider is not configured.",
                        request_id,
                        conversation_id,
                    )
                else:
                    outbound = chat_request
                    masked_request = None
                    if action == Action.MASK_CLOUD:
                        try:
                            masked_request = mask_request(chat_request, findings)
                            outbound = masked_request.request
                        except MaskingError:
                            status = "FAILED"
                            error_code = "SECURITY_UNAVAILABLE"
                            masking_status = "FAILED"
                            response = _error(
                                503,
                                error_code,
                                "Request could not be safely masked.",
                                request_id,
                                conversation_id,
                            )
                    if error_code is None:
                        try:
                            await store.record_model_intent(
                                request_id,
                                provider_name=cloud_provider.name,
                                model=settings.model_aliases[chat_request.model],
                                masked=masked_request is not None,
                                masked_messages=(
                                    [
                                        message.model_dump(exclude_none=True)
                                        for message in outbound.messages
                                    ]
                                    if masked_request is not None and principal_id == DEMO_PRINCIPAL
                                    else None
                                ),
                            )
                        except Exception:
                            return _route_headers(
                                _error(
                                    503,
                                    "AUDIT_UNAVAILABLE",
                                    "Audit storage is unavailable.",
                                    request_id,
                                    conversation_id,
                                ),
                                action,
                                route_destination,
                                route_simulation,
                            )
                        route_destination = "EXTERNAL"
                        try:
                            result = await cloud_provider.complete(outbound)
                            model_call_status = "SUCCEEDED"
                            content = (
                                masked_request.restore(result.content)
                                if masked_request is not None
                                else result.content
                            )
                            completion = ChatCompletionResponse(
                                id=f"chatcmpl-{request_id}",
                                created=int(datetime.now(UTC).timestamp()),
                                model=chat_request.model,
                                choices=[
                                    ChatCompletionChoice(
                                        message=ChatCompletionMessage(content=content),
                                        finish_reason=result.finish_reason,
                                    )
                                ],
                            )
                            response = JSONResponse(
                                content=completion.model_dump(),
                                headers={
                                    "X-Aegis-Request-Id": request_id,
                                    "X-Aegis-Conversation-Id": conversation_id,
                                },
                            )
                        except MaskingError:
                            status = "FAILED"
                            error_code = "SECURITY_UNAVAILABLE"
                            response = _error(
                                503,
                                error_code,
                                "Provider response could not be safely restored.",
                                request_id,
                                conversation_id,
                            )
                        except TimeoutError:
                            status = "FAILED"
                            error_code = "PROVIDER_TIMEOUT"
                            model_call_status = "FAILED"
                            response = _error(
                                504,
                                error_code,
                                "Cloud provider timed out.",
                                request_id,
                                conversation_id,
                            )
                        except Exception:
                            status = "FAILED"
                            error_code = "PROVIDER_ERROR"
                            model_call_status = "FAILED"
                            response = _error(
                                502,
                                error_code,
                                "Cloud provider failed.",
                                request_id,
                                conversation_id,
                            )
            elif not external_local and any(
                value is not None
                for value in (
                    chat_request.temperature,
                    chat_request.top_p,
                    chat_request.max_tokens,
                )
            ):
                status = "FAILED"
                error_code = "UNSUPPORTED_FEATURE"
                response = _error(
                    400,
                    error_code,
                    "Generation parameters are not supported by the local provider.",
                    request_id,
                    conversation_id,
                )
            elif provider is None:
                status = "FAILED"
                error_code = "LOCAL_UNAVAILABLE"
                response = _error(
                    503,
                    error_code,
                    "No trusted local provider is configured.",
                    request_id,
                    conversation_id,
                )
            else:
                if external_local:
                    assert provider is not None
                    try:
                        await store.record_model_intent(
                            request_id,
                            provider_name=provider.name,
                            model=settings.model_aliases[chat_request.model],
                            masked=False,
                        )
                    except Exception:
                        return _route_headers(
                            _error(
                                503,
                                "AUDIT_UNAVAILABLE",
                                "Audit storage is unavailable.",
                                request_id,
                                conversation_id,
                            ),
                            action,
                            route_destination,
                            route_simulation,
                        )
                    route_destination = "EXTERNAL"
                try:
                    assert provider is not None
                    result = await provider.complete(chat_request)
                    if external_local:
                        model_call_status = "SUCCEEDED"
                    completion = ChatCompletionResponse(
                        id=f"chatcmpl-{request_id}",
                        created=int(datetime.now(UTC).timestamp()),
                        model=chat_request.model,
                        choices=[
                            ChatCompletionChoice(
                                message=ChatCompletionMessage(content=result.content),
                                finish_reason=result.finish_reason,
                            )
                        ],
                    )
                    response = JSONResponse(
                        content=completion.model_dump(),
                        headers={
                            "X-Aegis-Request-Id": request_id,
                            "X-Aegis-Conversation-Id": conversation_id,
                        },
                    )
                except TimeoutError:
                    status = "FAILED"
                    error_code = "PROVIDER_TIMEOUT"
                    if external_local:
                        model_call_status = "FAILED"
                    response = _error(
                        504, error_code, "Local provider timed out.", request_id, conversation_id
                    )
                except Exception:
                    status = "FAILED"
                    error_code = "PROVIDER_ERROR"
                    if external_local:
                        model_call_status = "FAILED"
                    response = _error(
                        502, error_code, "Local provider failed.", request_id, conversation_id
                    )

            assert response is not None
            try:
                await store.finish_dispatch(
                    request_id,
                    status=status,
                    error_code=error_code,
                    duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
                    model_call_status=model_call_status,
                    masking_status=masking_status,
                )
            except Exception:
                return _route_headers(
                    _error(
                        503,
                        "AUDIT_UNAVAILABLE",
                        "Audit storage is unavailable.",
                        request_id,
                        conversation_id,
                    ),
                    action,
                    route_destination,
                    route_simulation,
                )
            return _route_headers(response, action, route_destination, route_simulation)

        try:
            return await process_claimed()
        except asyncio.CancelledError:
            try:
                await store.finish_dispatch(
                    request_id,
                    status="FAILED",
                    error_code="REQUEST_CANCELLED",
                    duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
                    detection_status="FAILED",
                )
            except Exception:
                pass  # An uncertain database result remains claimed for explicit recovery.
            raise

    return app
