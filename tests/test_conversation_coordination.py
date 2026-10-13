"""Stage 3 coordination and administration against PostgreSQL."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.config import Settings
from aegis.detection import Finding, TextFragment
from aegis.main import create_app
from aegis.models import AuditEvent, Conversation, ConversationAdminEvent
from aegis.policy import Category
from aegis.provider import ProviderResult
from aegis.store import (
    AuditDraft,
    ConversationBusy,
    PostgresRequestStore,
    RecoveryMismatch,
)

TEST_DATABASE_URL = os.getenv("AEGIS_TEST_DATABASE_URL")


class EmptyNer:
    async def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        return []


class PausingSemantic:
    name = "fake-external"
    model = "fake-classifier"
    destination = "EXTERNAL"
    external = True

    def __init__(self) -> None:
        self.calls: list[list[TextFragment]] = []
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        self.calls.append(fragments)
        if any("merger" in item.text for item in fragments):
            self.entered.set()
            await self.release.wait()
            return [
                Finding(
                    Category.BUSINESS_SECRET,
                    "semantic_external",
                    item.text_id,
                    item.message_index,
                    item.path,
                    0,
                    len(item.text),
                    None,
                    "uncalibrated",
                )
                for item in fragments
            ]
        return []


class RecordingProvider:
    name = "recording-mock"
    destination = "MOCK"
    simulation = True

    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, request: object) -> ProviderResult:
        self.calls += 1
        return ProviderResult(content="synthetic response")


class FailingIntentStore(PostgresRequestStore):
    async def record_external_intent(
        self, request_id: str, *, provider_name: str, model: str
    ) -> None:
        raise RuntimeError("injected audit failure")


def settings() -> Settings:
    assert TEST_DATABASE_URL is not None
    return Settings(
        database_url=TEST_DATABASE_URL,
        api_keys={"alice": "alice-token", "bob": "bob-token"},
        hmac_key="integration-hmac-key-longer-than-32-bytes",
        run_mode="demo",
        demo_provider="mock",
    )


def headers(token: str, conversation_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Aegis-Conversation-Id": conversation_id,
    }


def payload(text: str) -> dict[str, object]:
    return {"model": "aegis-mock", "messages": [{"role": "user", "content": text}]}


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_concurrent_request_conflicts_until_sensitive_decision_finishes() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"coord-{uuid4().hex}"
    semantic = PausingSemantic()
    provider = RecordingProvider()
    app = create_app(
        settings(), semantic_detector=semantic, ner_detector=EmptyNer(), provider=provider
    )
    engine = create_async_engine(TEST_DATABASE_URL)
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                cloud = await client.post(
                    "/v1/chat/completions",
                    headers=headers("alice-token", conversation_id),
                    json=payload("ordinary first round"),
                )
                assert cloud.status_code == 503
                assert cloud.json()["error"]["code"] == "ROUTE_UNAVAILABLE"
                first_task = asyncio.create_task(
                    client.post(
                        "/v1/chat/completions",
                        headers=headers("alice-token", conversation_id),
                        json=payload("synthetic merger plan"),
                    )
                )
                try:
                    await asyncio.wait_for(semantic.entered.wait(), timeout=5)
                    busy = await client.post(
                        "/v1/chat/completions",
                        headers=headers("alice-token", conversation_id),
                        json=payload("ordinary follow-up"),
                    )
                    assert busy.status_code == 409
                    assert busy.json()["error"]["code"] == "CONVERSATION_BUSY"
                    assert busy.headers["x-aegis-conversation-id"] == conversation_id
                    assert len(semantic.calls) == 2
                    assert provider.calls == 0

                    other_principal = await client.post(
                        "/v1/chat/completions",
                        headers=headers("bob-token", conversation_id),
                        json=payload("ordinary independent request"),
                    )
                    assert other_principal.status_code == 503
                    assert other_principal.json()["error"]["code"] == "ROUTE_UNAVAILABLE"
                    assert len(semantic.calls) == 3
                finally:
                    semantic.release.set()
                first = await first_task
                assert first.status_code == 200
                retry = await client.post(
                    "/v1/chat/completions",
                    headers=headers("alice-token", conversation_id),
                    json=payload("ordinary follow-up"),
                )
                assert retry.status_code == 200
                assert len(semantic.calls) == 3
                assert provider.calls == 2

        sessions = async_sessionmaker(engine)
        async with sessions() as session:
            alice = await session.get(Conversation, ("alice", conversation_id))
            bob = await session.get(Conversation, ("bob", conversation_id))
            assert alice is not None and bob is not None
            assert (alice.sensitive, alice.state_version, alice.active_request_id) == (
                True,
                1,
                None,
            )
            assert (bob.sensitive, bob.state_version) == (False, 0)
            first_audit = await session.get(AuditEvent, first.headers["x-aegis-request-id"])
            cloud_audit = await session.get(AuditEvent, cloud.headers["x-aegis-request-id"])
            retry_audit = await session.get(AuditEvent, retry.headers["x-aegis-request-id"])
            busy_audit = await session.get(AuditEvent, busy.headers["x-aegis-request-id"])
            assert all(
                event is not None for event in (first_audit, cloud_audit, retry_audit, busy_audit)
            )
            assert cloud_audit is not None
            assert (
                cloud_audit.policy_action,
                cloud_audit.conversation_state_before,
                cloud_audit.conversation_state_after,
            ) == ("CLOUD", "NORMAL", "NORMAL")
            assert first_audit is not None and retry_audit is not None and busy_audit is not None
            assert (
                first_audit.conversation_state_before,
                first_audit.conversation_state_after,
                first_audit.conversation_state_version,
            ) == ("NORMAL", "SENSITIVE", 1)
            assert (retry_audit.policy_action, retry_audit.conversation_state_before) == (
                "LOCAL",
                "SENSITIVE",
            )
            assert (busy_audit.status, busy_audit.error_code, busy_audit.detection_status) == (
                "REJECTED",
                "CONVERSATION_BUSY",
                "NOT_RUN",
            )
    finally:
        await engine.dispose()


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_abandoned_request_recovery_and_terminal_close() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"admin-{uuid4().hex}"
    request_id = uuid4().hex
    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    store = PostgresRequestStore(sessions)
    semantic = PausingSemantic()
    app = create_app(settings(), store=store, semantic_detector=semantic, ner_detector=EmptyNer())
    try:
        begin = await store.begin_request(
            AuditDraft(request_id, "alice", conversation_id, "PENDING", "aegis-mock", "a" * 64)
        )
        assert begin.status == "CLAIMED"
        with pytest.raises(ConversationBusy):
            await store.close_conversation(
                principal_id="alice", conversation_id=conversation_id, actor_id="operator"
            )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            busy = await client.post(
                "/v1/chat/completions",
                headers=headers("alice-token", conversation_id),
                json=payload("ordinary request"),
            )
            assert busy.status_code == 409
            assert semantic.calls == []
            with pytest.raises(RecoveryMismatch):
                await store.recover_request(
                    principal_id="alice",
                    conversation_id=conversation_id,
                    request_id=uuid4().hex,
                    actor_id="operator",
                )
            await store.recover_request(
                principal_id="alice",
                conversation_id=conversation_id,
                request_id=request_id,
                actor_id="operator",
            )
            blocked = await client.post(
                "/v1/chat/completions",
                headers=headers("alice-token", conversation_id),
                json=payload("api_key=abcdefghijklmnop12345"),
            )
            assert blocked.status_code == 403
            assert await store.close_conversation(
                principal_id="alice", conversation_id=conversation_id, actor_id="operator"
            )
            assert not await store.close_conversation(
                principal_id="alice", conversation_id=conversation_id, actor_id="operator"
            )
            closed = await client.post(
                "/v1/chat/completions",
                headers=headers("alice-token", conversation_id),
                json=payload("ordinary request"),
            )
            assert closed.status_code == 410
            assert closed.json()["error"]["code"] == "CONVERSATION_CLOSED"
            assert closed.headers["x-aegis-conversation-id"] == conversation_id
            assert semantic.calls == []

        async with sessions() as session:
            conversation = await session.get(Conversation, ("alice", conversation_id))
            abandoned = await session.get(AuditEvent, request_id)
            closed_audit = await session.get(AuditEvent, closed.headers["x-aegis-request-id"])
            admin_events = (
                await session.scalars(
                    select(ConversationAdminEvent).where(
                        ConversationAdminEvent.conversation_id == conversation_id
                    )
                )
            ).all()
            assert conversation is not None and abandoned is not None and closed_audit is not None
            assert (conversation.closed_at is not None, conversation.active_request_id) == (
                True,
                None,
            )
            assert conversation.sensitive is True and conversation.state_version == 2
            assert (abandoned.status, abandoned.error_code) == ("FAILED", "REQUEST_ABANDONED")
            assert (closed_audit.conversation_state_before, closed_audit.error_code) == (
                "CLOSED",
                "CONVERSATION_CLOSED",
            )
            assert [event.action for event in admin_events] == ["RECOVER", "CLOSE"]
            assert all(event.actor_id == "operator" for event in admin_events)
            assert (admin_events[0].state_before, admin_events[0].state_after) == (
                "NORMAL",
                "SENSITIVE",
            )
    finally:
        await engine.dispose()


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_audit_failure_keeps_claim_and_admin_cli_closes_after_recovery() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"cli-{uuid4().hex}"
    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    failing_store = FailingIntentStore(sessions)
    semantic = PausingSemantic()
    provider = RecordingProvider()
    app = create_app(
        settings(),
        store=failing_store,
        semantic_detector=semantic,
        ner_detector=EmptyNer(),
        provider=provider,
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            failed = await client.post(
                "/v1/chat/completions",
                headers=headers("alice-token", conversation_id),
                json=payload("ordinary synthetic request"),
            )
            assert failed.status_code == 503
            assert failed.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
            assert semantic.calls == []
            assert provider.calls == 0
            request_id = failed.headers["x-aegis-request-id"]
            busy = await client.post(
                "/v1/chat/completions",
                headers=headers("alice-token", conversation_id),
                json=payload("another ordinary request"),
            )
            assert busy.status_code == 409

        env = {**os.environ, "AEGIS_DATABASE_URL": TEST_DATABASE_URL}
        missing_confirmation = subprocess.run(
            [
                sys.executable,
                "-m",
                "aegis.admin",
                "recover-request",
                "--principal-id",
                "alice",
                "--conversation-id",
                conversation_id,
                "--request-id",
                request_id,
                "--actor",
                "test-operator",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert missing_confirmation.returncode == 2
        recovered = subprocess.run(
            [
                sys.executable,
                "-m",
                "aegis.admin",
                "recover-request",
                "--principal-id",
                "alice",
                "--conversation-id",
                conversation_id,
                "--request-id",
                request_id,
                "--actor",
                "test-operator",
                "--confirm-stopped",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert recovered.returncode == 0, recovered.stderr
        closed = subprocess.run(
            [
                sys.executable,
                "-m",
                "aegis.admin",
                "close-conversation",
                "--principal-id",
                "alice",
                "--conversation-id",
                conversation_id,
                "--actor",
                "test-operator",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert closed.returncode == 0, closed.stderr
        async with sessions() as session:
            conversation = await session.get(Conversation, ("alice", conversation_id))
            audit = await session.get(AuditEvent, request_id)
            assert conversation is not None and audit is not None
            assert conversation.active_request_id is None and conversation.closed_at is not None
            assert (audit.status, audit.error_code) == ("FAILED", "REQUEST_ABANDONED")
    finally:
        await engine.dispose()


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_cancelled_request_finishes_audit_and_releases_claim() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"cancel-{uuid4().hex}"
    semantic = PausingSemantic()
    app = create_app(settings(), semantic_detector=semantic, ner_detector=EmptyNer())
    engine = create_async_engine(TEST_DATABASE_URL)
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                task = asyncio.create_task(
                    client.post(
                        "/v1/chat/completions",
                        headers=headers("alice-token", conversation_id),
                        json=payload("synthetic merger plan"),
                    )
                )
                await asyncio.wait_for(semantic.entered.wait(), timeout=5)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                retry = await client.post(
                    "/v1/chat/completions",
                    headers=headers("alice-token", conversation_id),
                    json=payload("ordinary retry"),
                )
                assert retry.status_code == 200
                assert len(semantic.calls) == 1

        sessions = async_sessionmaker(engine)
        async with sessions() as session:
            conversation = await session.get(Conversation, ("alice", conversation_id))
            assert conversation is not None and conversation.active_request_id is None
            assert (conversation.sensitive, conversation.state_version) == (True, 1)
            audits = (
                await session.scalars(
                    select(AuditEvent).where(AuditEvent.conversation_id == conversation_id)
                )
            ).all()
            assert len(audits) == 2
            cancelled = next(event for event in audits if event.error_code == "REQUEST_CANCELLED")
            assert cancelled.status == "FAILED"
    finally:
        semantic.release.set()
        await engine.dispose()
