# Toolframe MCP Auth

Managed, named bearer keys for MCP clients using Streamable HTTP. Each key contains
32 random bytes (256 bits), encoded as `tf_mcp_` plus 43 URL-safe characters.
The credential provider owns its managed SQLite store and retains only SHA-256
digests. Full keys are returned once, only when created.

Install this plugin with `toolframe-storage-sqlite`, the updated SDK/core and
FastMCP provider. The optional MCP keys page ships in Dashboard Auth. Operators
or grants with `system.auth.mcp_keys` can create, list and revoke keys; issuance
is bounded by the administrator's own business scopes and expiry. MCP keys carry
fixed business scopes, never system permissions. Rotation is create, switch the
client, then revoke the old key.

```toml
[mcp_access]
mode = "protected"
auth_provider = "mcp-auth"

[plugins.mcp-auth]
source = "pypi:toolframe-mcp-auth==0.1.0"
enabled = true
```

The source above describes the package release; use this checkout's absolute path
until it is published. Apply configuration changes with `toolframe apply`.
Creating a key does not change public/protected mode. Protected MCP stays closed
with no keys or when its auth provider is missing, disabled, reloading or failed.
Local MCP clients also require credentials. Dashboard access has its own policy.
Public mode permits anonymous access and ignores authorization headers; enable
protected mode to enforce key grants.

Clients use the application's `/mcp` URL and send `Authorization: Bearer <key>`
on every request. Remote connections must use HTTPS. OAuth discovery/browser
sign-in is not included. Full secrets must not be placed in URLs, checked-in
configuration, or tool arguments. Revocation/expiry is checked before each new
tool admission; already admitted calls finish. Credentials survive reload/restart.

The internal `toolframe.mcp-auth` service provides `create`, `list`, `revoke`,
`verify` and `resolve`. Core admits management callers and owns trusted request
contexts. These methods are not public business APIs. Back up the plugin's
consistent managed SQLite store using the application's normal backup procedure.

```sh
uv sync
uv run pytest -q
uv run ruff check src tests
uv build --wheel
```
