"""Own MCP credentials; core owns HTTP admission and trusted caller context."""

import asyncio
import hashlib
import json
import math
import re
import secrets
import time
import uuid
from importlib.resources import files

from toolframe_sdk import (
    AuthorizationSpec,
    MethodSpec,
    Migration,
    Plugin,
    PluginDefinition,
    PluginError,
    Principal,
    Requirement,
    ServiceSpec,
    StoreSchema,
)

SERVICE = "toolframe.mcp-auth"
MANAGE_SCOPE = "system.auth.mcp_keys"
TOKEN = re.compile(r"tf_mcp_[A-Za-z0-9_-]{43}\Z")
SCHEMA = """
CREATE TABLE mcp_keys (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, digest TEXT NOT NULL UNIQUE,
 scopes TEXT NOT NULL, created_by TEXT NOT NULL,
 created_at REAL NOT NULL, expires_at REAL, revoked_at REAL, last_used REAL
);
"""


def digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def public_record(record):
    return {k: v for k, v in record.items() if k != "digest"} | {
        "scopes": json.loads(record["scopes"]),
        # A record identifier is sufficient for display; reveal no secret bytes.
        "masked_key": "tf_mcp_•••• (" + record["id"][:8] + ")",
    }


class McpAuthProvider(Plugin):
    def __init__(self, context):
        super().__init__(context)
        self.store = context.storage()
        self.lock = asyncio.Lock()

    async def activate(self):
        await self.store.query("SELECT id FROM mcp_keys LIMIT 1")

    def actor(self):
        value = self.context.call_info.get("principal")
        if not value:
            raise PluginError("forbidden", "A host-admitted administrator is required")
        actor = Principal.model_validate(value)
        if not actor.unrestricted and MANAGE_SCOPE not in actor.scopes:
            raise PluginError("forbidden", "MCP key management permission required")
        return actor

    def bounds(self, actor, scopes, expiry):
        if actor.unrestricted:
            return
        catalog = self.context.call_info.get("scope_catalog", {})
        if not actor.allows(scopes, catalog):
            raise PluginError(
                "forbidden", "Cannot delegate scopes beyond your own grant"
            )
        if actor.expires_at is not None and (
            expiry is None or expiry > actor.expires_at
        ):
            raise PluginError("forbidden", "Cannot delegate beyond your grant expiry")

    def fields(self, params):
        label = params.get("label")
        scopes = params.get("scopes")
        expiry = params.get("expires_at")
        catalog = self.context.call_info.get("scope_catalog", {})
        try:
            valid_label = (
                isinstance(label, str) and bool(label.strip()) and len(label) <= 120
            )
            if valid_label:
                label.encode("utf-8")
        except UnicodeError:
            valid_label = False
        if (
            not valid_label
            or not isinstance(scopes, list)
            or not scopes
            or not all(
                isinstance(s, str) and catalog.get(s, {}).get("category") == "business"
                for s in scopes
            )
            or (
                expiry is not None
                and (
                    type(expiry) not in (int, float)
                    or not math.isfinite(expiry)
                    or not time.time() < expiry < 253402300800
                )
            )
        ):
            raise PluginError(
                "invalid_request",
                "Supply a name, business scopes and a future expiry (or null)",
            )
        return label.strip(), sorted(set(scopes)), expiry

    async def get(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(
            r"[0-9a-f]{32}", identifier
        ):
            raise PluginError("invalid_request", "Supply an MCP key record ID")
        rows = await self.store.query("SELECT * FROM mcp_keys WHERE id=?", [identifier])
        if not rows:
            raise PluginError("credential_missing", "MCP key record not found")
        return rows[0]

    async def decision(self, record, params):
        now = time.time()
        if (
            record is None
            or record["revoked_at"] is not None
            or (record["expires_at"] is not None and now >= record["expires_at"])
        ):
            raise PluginError("invalid_credentials", "Invalid or expired MCP key")
        actor = Principal(
            kind="mcp_key",
            credential_id=record["id"],
            scopes=tuple(json.loads(record["scopes"])),
            expires_at=record["expires_at"],
        )
        if not actor.allows(
            params.get("required_scopes", ()),
            self.context.call_info.get("scope_catalog", {}),
        ):
            raise PluginError(
                "forbidden", "MCP key does not grant this tool's permissions"
            )
        if params.get("activity", False):
            await self.store.execute(
                "UPDATE mcp_keys SET last_used=? WHERE id=?", [now, record["id"]]
            )
        return {"principal": actor.model_dump()}

    async def invoke(self, service, method, params):
        # Optional OAuth I/O must not hold the independent key-store lock.
        if (
            method == "verify"
            and isinstance(params.get("token"), str)
            and params["token"].startswith("tf_oauth_")
        ):
            return await self.context.call("oauth", "verify", params)
        if (
            method == "resolve"
            and isinstance(params.get("id"), str)
            and params["id"].startswith("oauth:")
        ):
            return await self.context.call("oauth", "resolve", params)
        async with self.lock:
            if method == "verify":
                token = params.get("token")
                if not isinstance(token, str) or not TOKEN.fullmatch(token):
                    raise PluginError(
                        "invalid_credentials", "Invalid or expired MCP key"
                    )
                rows = await self.store.query(
                    "SELECT * FROM mcp_keys WHERE digest=?", [digest(token)]
                )
                return await self.decision(rows[0] if rows else None, {})
            if method == "resolve":
                try:
                    record = await self.get(params.get("id"))
                except PluginError:
                    raise PluginError(
                        "invalid_credentials", "Invalid or expired MCP key"
                    ) from None
                return await self.decision(record, params)
            actor = self.actor()
            if method == "create":
                if set(params) - {"label", "scopes", "expires_at"}:
                    raise PluginError(
                        "invalid_request", "MCP keys are generated by the server"
                    )
                label, scopes, expiry = self.fields(params)
                self.bounds(actor, scopes, expiry)
                token = "tf_mcp_" + secrets.token_urlsafe(32)
                identifier = uuid.uuid4().hex
                await self.store.execute(
                    "INSERT INTO mcp_keys(id,label,digest,scopes,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
                    [
                        identifier,
                        label,
                        digest(token),
                        json.dumps(scopes),
                        actor.credential_id or actor.kind,
                        time.time(),
                        expiry,
                    ],
                )
                return {
                    "key": public_record(await self.get(identifier)),
                    "token": token,
                }
            if method == "list":
                records = await self.store.query(
                    "SELECT * FROM mcp_keys ORDER BY created_at DESC"
                )
                visible = []
                for record in records:
                    try:
                        self.bounds(
                            actor, json.loads(record["scopes"]), record["expires_at"]
                        )
                    except PluginError:
                        continue
                    visible.append(public_record(record))
                return {"keys": visible}
            if method == "revoke":
                record = await self.get(params.get("id"))
                self.bounds(actor, json.loads(record["scopes"]), record["expires_at"])
                await self.store.execute(
                    "UPDATE mcp_keys SET revoked_at=COALESCE(revoked_at,?) WHERE id=?",
                    [time.time(), record["id"]],
                )
                return {"key": public_record(await self.get(record["id"]))}
            raise PluginError("invalid_request", "Unknown MCP key operation")


plugin = PluginDefinition(
    id="mcp-auth",
    kind="provider",
    provider_kind="mcp-auth",
    factory="toolframe_mcp_auth.plugin:McpAuthProvider",
    authorization=AuthorizationSpec(),
    requires={
        "storage": Requirement(service="toolframe.storage.sql"),
        "oauth": Requirement(service="toolframe.oauth.tokens", optional=True),
    },
    services={
        SERVICE: ServiceSpec(
            methods={
                name: MethodSpec(
                    audience="internal", read_only=name in {"verify", "list"}
                )
                for name in ("create", "list", "revoke", "verify", "resolve")
            }
        )
    },
    store=StoreSchema(
        revision="v1",
        migrations=(
            Migration(
                revision="v1",
                sql=SCHEMA,
                dialects={
                    "postgresql": files(__package__)
                    .joinpath("migrations", "v1.postgresql.sql")
                    .read_text()
                },
            ),
        ),
    ),
)
