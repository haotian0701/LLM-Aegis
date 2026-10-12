"""Aegis HTTP gateway, stage 1."""

from __future__ import annotations

import hmac
import json
import re
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.config import Settings
from aegis.provider import MockLocalProvider, ModelProvider
from aegis.schemas import (
    ChatCompletionChoice,
    ChatCompletionMessage,
    ChatCompletionResponse,
    ChatRequest,
)
from aegis.store import AuditDraft, PostgresRequestStore, RequestStore

CONVERSATION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


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
        policy_action=None,
        actual_destination="NONE",
        provider_name=None,
        model_alias=None,
        provider_model=None,
        simulation=False,
        prompt_hmac=None,
        error_code=code,
    )


def create_app(
    settings: Settings | None = None,
    *,
    store: RequestStore | None = None,
    provider: ModelProvider | None = None,
) -> FastAPI:
    """Build the gateway. Tests may inject storage and a provider without a database."""
    settings = settings or Settings.from_env()
    if settings.run_mode == "strict":
        if provider is not None and provider.simulation:
            raise ValueError("strict mode cannot use a simulated provider")
    elif provider is None:
        provider = MockLocalProvider()

    engine = None
    if store is None:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        store = PostgresRequestStore(sessions)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        if engine is not None:
            await engine.dispose()

    app = FastAPI(title="Aegis Gateway", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.provider = provider

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
        if principal_id is None:
            return await reject(401, "UNAUTHORIZED", "Invalid API token.", None)

        if (
            http_request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            return await reject(
                400, "INVALID_REQUEST", "JSON request body is required.", principal_id
            )

        try:
            raw_body = await http_request.json()
            chat_request = ChatRequest.model_validate(raw_body)
        except (ValueError, ValidationError, UnicodeDecodeError):
            return await reject(
                400, "INVALID_REQUEST", "Invalid or unsupported request body.", principal_id
            )

        if chat_request.model not in settings.model_aliases:
            return await reject(400, "INVALID_REQUEST", "Unknown model alias.", principal_id)

        if any(
            value is not None
            for value in (
                chat_request.temperature,
                chat_request.top_p,
                chat_request.max_tokens,
            )
        ):
            return await reject(
                400,
                "UNSUPPORTED_FEATURE",
                "Generation parameters are not supported by the stage 1 provider.",
                principal_id,
            )

        supplied_id = http_request.headers.get("x-aegis-conversation-id")
        if supplied_id is not None and CONVERSATION_ID_PATTERN.fullmatch(supplied_id) is None:
            return await reject(400, "INVALID_REQUEST", "Invalid conversation ID.", principal_id)
        conversation_id = supplied_id if supplied_id is not None else uuid4().hex

        actual_destination = provider.destination if provider is not None else "NONE"
        draft = AuditDraft(
            request_id=request_id,
            principal_id=principal_id,
            conversation_id=conversation_id,
            status="PENDING",
            policy_action="LOCAL",
            actual_destination=actual_destination,
            provider_name=provider.name if provider is not None else None,
            model_alias=chat_request.model,
            provider_model=settings.model_aliases[chat_request.model]
            if provider is not None
            else None,
            simulation=provider.simulation if provider is not None else False,
            prompt_hmac=_prompt_hmac(chat_request, settings.hmac_key),
        )
        try:
            await store.prepare_dispatch(draft)
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
        response: JSONResponse
        if provider is None:
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
            try:
                result = await provider.complete(chat_request)
                completion = ChatCompletionResponse(
                    id=f"chatcmpl-{request_id}",
                    created=int(datetime.now(UTC).timestamp()),
                    model=chat_request.model,
                    choices=[
                        ChatCompletionChoice(message=ChatCompletionMessage(content=result.content))
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
                response = _error(
                    504, error_code, "Local provider timed out.", request_id, conversation_id
                )
            except Exception:
                status = "FAILED"
                error_code = "PROVIDER_ERROR"
                response = _error(
                    502, error_code, "Local provider failed.", request_id, conversation_id
                )

        duration_ms = max(0, round((time.perf_counter() - started) * 1000))
        try:
            await store.finish_dispatch(
                request_id, status=status, error_code=error_code, duration_ms=duration_ms
            )
        except Exception:
            return _error(
                503,
                "AUDIT_UNAVAILABLE",
                "Audit storage is unavailable.",
                request_id,
                conversation_id,
            )
        return response

    return app
