"""Credential lifecycle and delegation against real provider-managed SQLite."""

import asyncio
import base64
import json
import time
from contextlib import contextmanager

import pytest
from toolframe_sdk import PluginError, Principal, RuntimeContext, call_context
from toolframe_storage_sqlite.plugin import ADMIN_SERVICE, SQL_SERVICE, SqliteProvider

from toolframe_mcp_auth.plugin import SERVICE, McpAuthProvider, digest, plugin

CATALOG = {
    "notes.read": {"category": "business"},
    "notes.write": {"category": "business"},
    "system.auth.mcp_keys": {"category": "system"},
}


@contextmanager
def caller(actor=None, **extra):
    reference = call_context.set(
        {
            "principal": (actor or Principal(kind="local")).model_dump(),
            "scope_catalog": CATALOG,
            "deadline": time.time() + 30,
            "root_id": "test-root",
            "chain": ["mcp-auth"],
            **extra,
        }
    )
    try:
        yield
    finally:
        call_context.reset(reference)


class StoragePeer:
    def __init__(self, provider):
        self.provider = provider

    async def request(self, method, params, timeout=None):
        assert method == "service.call" and params["alias"] == "storage"
        reference = call_context.set(
            {
                "application_id": "test",
                "owner": "mcp-auth",
                "owner_generation": "one",
                "root_id": "test-root",
                "deadline": time.time() + 30,
            }
        )
        try:
            return await self.provider.invoke(
                SQL_SERVICE, params["method"], params["params"]
            )
        finally:
            call_context.reset(reference)


@pytest.fixture
async def auth(tmp_path):
    storage = SqliteProvider(
        RuntimeContext(
            None, plugin_id="storage-sqlite", generation="one", state_directory=tmp_path
        )
    )
    await storage.activate()
    with caller(management=True, application_id="test"):
        await storage.invoke(
            ADMIN_SERVICE,
            "ensure_store",
            {"owner": "mcp-auth", "schema": plugin.store.model_dump()},
        )
    instance = McpAuthProvider(
        RuntimeContext(StoragePeer(storage), plugin_id="mcp-auth", generation="one")
    )
    with caller():
        await instance.activate()
    try:
        yield instance
    finally:
        await storage.dispose()


async def create(auth, **fields):
    with caller():
        return await auth.invoke(
            SERVICE, "create", {"label": "Laptop", "scopes": ["notes.read"], **fields}
        )


async def test_generation_digest_only_and_restart(auth):
    created = await create(auth)
    token = created["token"]
    assert token.startswith("tf_mcp_") and len(token) == 50
    assert len(base64.urlsafe_b64decode(token[7:] + "=")) == 32
    with caller():
        raw = await auth.get(created["key"]["id"])
        listed = await auth.invoke(SERVICE, "list", {})
        assert raw["digest"] == digest(token)
        assert token not in json.dumps(raw) + json.dumps(listed)
        assert "digest" not in json.dumps(listed) and "token" not in json.dumps(listed)
        restarted = McpAuthProvider(auth.context)
        await restarted.activate()
        result = await restarted.invoke(SERVICE, "verify", {"token": token})
    assert result["principal"]["credential_id"] == raw["id"]
    assert result["principal"]["kind"] == "mcp_key"


async def test_concurrent_keys_revocation_and_expiry(auth):
    records = await asyncio.gather(
        *(create(auth, label=f"Client {i}") for i in range(8))
    )
    assert len({row["token"] for row in records}) == 8
    with caller():
        first, second = records[:2]
        for _ in range(2):
            await auth.invoke(SERVICE, "revoke", {"id": first["key"]["id"]})
        await auth.store.execute(
            "UPDATE mcp_keys SET expires_at=? WHERE id=?",
            [time.time() - 1, second["key"]["id"]],
        )
        for row in (first, second):
            for method, params in (
                ("verify", {"token": row["token"]}),
                ("resolve", {"id": row["key"]["id"]}),
            ):
                with pytest.raises(PluginError) as denied:
                    await auth.invoke(SERVICE, method, params)
                assert denied.value.code == "invalid_credentials"
        assert (await auth.invoke(SERVICE, "verify", {"token": records[2]["token"]}))[
            "principal"
        ]["credential_id"] == records[2]["key"]["id"]


async def test_only_successful_authorized_activity_updates_usage(auth):
    row = (await create(auth))["key"]
    with caller():
        await auth.invoke(SERVICE, "resolve", {"id": row["id"]})
        with pytest.raises(PluginError) as denied:
            await auth.invoke(
                SERVICE,
                "resolve",
                {"id": row["id"], "required_scopes": ["notes.write"], "activity": True},
            )
        assert denied.value.code == "forbidden"
        assert (await auth.get(row["id"]))["last_used"] is None
        await auth.invoke(
            SERVICE,
            "resolve",
            {"id": row["id"], "required_scopes": ["notes.read"], "activity": True},
        )
        assert (await auth.get(row["id"]))["last_used"] is not None


async def test_delegation_and_management_are_bounded(auth):
    broad = await create(auth, scopes=["notes.write"])
    expiry = time.time() + 300
    actor = Principal(
        kind="password",
        credential_id="admin",
        scopes=("system.auth.mcp_keys", "notes.read"),
        expires_at=expiry,
    )
    fields = {"label": "Delegated", "scopes": ["notes.read"], "expires_at": expiry - 1}
    with caller(actor):
        for extra in (
            {"scopes": ["notes.write"]},
            {"expires_at": None},
            {"expires_at": expiry + 1},
        ):
            with pytest.raises(PluginError) as denied:
                await auth.invoke(SERVICE, "create", {**fields, **extra})
            assert denied.value.code == "forbidden"
        issued = await auth.invoke(SERVICE, "create", fields)
        listed = await auth.invoke(SERVICE, "list", {})
        assert [r["id"] for r in listed["keys"]] == [issued["key"]["id"]]
        with pytest.raises(PluginError):
            await auth.invoke(SERVICE, "revoke", {"id": broad["key"]["id"]})
    with caller(Principal(kind="mcp_key", scopes=("notes.read",))):
        for method in ("create", "list", "revoke"):
            with pytest.raises(PluginError) as denied:
                await auth.invoke(SERVICE, method, fields)
            assert denied.value.code == "forbidden"


@pytest.mark.parametrize(
    "fields",
    [
        {"scopes": []},
        {"scopes": ["system.auth.mcp_keys"]},
        {"scopes": ["missing"]},
        {"label": []},
        {"label": "\ud800"},
        {"expires_at": True},
        {"expires_at": float("nan")},
        {"expires_at": float("inf")},
        {"expires_at": 0},
        {"token": "custom"},
    ],
)
async def test_invalid_issuance_creates_no_record(auth, fields):
    with pytest.raises(PluginError) as denied:
        await create(auth, **fields)
    assert denied.value.code == "invalid_request"
    with caller():
        assert (await auth.invoke(SERVICE, "list", {}))["keys"] == []


@pytest.mark.parametrize(
    "token",
    [None, [], "", "wrong", "tf_mcp_" + "a" * 42, "tf_mcp_" + "a" * 44, "\ud800" * 50],
)
async def test_malformed_credentials_are_typed_denials(auth, token):
    with caller(), pytest.raises(PluginError) as denied:
        await auth.invoke(SERVICE, "verify", {"token": token})
    assert denied.value.code == "invalid_credentials"
