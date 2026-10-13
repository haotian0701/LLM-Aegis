"""Host-only conversation administration; no HTTP management endpoint."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.store import (
    ConversationBusy,
    ConversationNotFound,
    PostgresRequestStore,
    RecoveryMismatch,
)

CONVERSATION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m aegis.admin")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("close-conversation", "recover-request"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--principal-id", required=True)
        subparser.add_argument("--conversation-id", required=True)
        subparser.add_argument("--actor", required=True)
        if command == "recover-request":
            subparser.add_argument("--request-id", required=True)
            subparser.add_argument("--confirm-stopped", action="store_true", required=True)
    return parser


def _valid_label(value: str) -> bool:
    return 1 <= len(value) <= 128 and all(
        char.isprintable() and char not in "\r\n" for char in value
    )


async def _execute(arguments: argparse.Namespace, database_url: str) -> str:
    engine = create_async_engine(database_url, pool_pre_ping=True)
    store = PostgresRequestStore(async_sessionmaker(engine, expire_on_commit=False))
    try:
        if arguments.command == "close-conversation":
            changed = await store.close_conversation(
                principal_id=arguments.principal_id,
                conversation_id=arguments.conversation_id,
                actor_id=arguments.actor,
            )
            return "Conversation closed." if changed else "Conversation was already closed."
        await store.recover_request(
            principal_id=arguments.principal_id,
            conversation_id=arguments.conversation_id,
            request_id=arguments.request_id,
            actor_id=arguments.actor,
        )
        return "Abandoned request marked failed; conversation released."
    finally:
        await engine.dispose()


def main() -> None:
    parser = _parser()
    arguments = parser.parse_args()
    database_url = os.environ.get("AEGIS_DATABASE_URL", "")
    if not database_url.startswith("postgresql+psycopg://"):
        parser.error("AEGIS_DATABASE_URL must use postgresql+psycopg")
    if not _valid_label(arguments.principal_id) or not _valid_label(arguments.actor):
        parser.error("principal ID and actor must be 1-128 printable characters")
    if CONVERSATION_ID_PATTERN.fullmatch(arguments.conversation_id) is None:
        parser.error("invalid conversation ID")
    if (
        arguments.command == "recover-request"
        and REQUEST_ID_PATTERN.fullmatch(arguments.request_id) is None
    ):
        parser.error("invalid request ID")
    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    try:
        result = asyncio.run(_execute(arguments, database_url), loop_factory=loop_factory)
    except (ConversationBusy, ConversationNotFound, RecoveryMismatch) as exc:
        parser.exit(2, f"{exc}\n")
    except Exception:
        parser.exit(
            1, "Database operation failed; inspect the database and audit before retrying.\n"
        )
    print(result)


if __name__ == "__main__":
    main()
