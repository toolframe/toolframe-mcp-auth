# MCP keys and OAuth verification

Managed, named bearer keys for MCP clients using Streamable HTTP. Each key contains
32 random bytes (256 bits), encoded as `tf_mcp_` plus 43 URL-safe characters.
The credential provider owns a managed SQL store and retains only SHA-256
digests. Full keys are returned once, only when created.

Install this plugin with an active SQL provider, a compatible SDK/Core pair and
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
source = "pypi:toolframe-mcp-auth==0.3.2"
enabled = true
```

Apply configuration changes with `toolframe --home APP apply`. Core downloads
the pinned package from PyPI and prepares its isolated environment.
Creating a key does not change public/protected mode. Protected MCP stays closed
with no keys or when its auth provider is missing, disabled, reloading or failed.
Local MCP clients also require credentials. Dashboard access has its own policy.
Public mode permits anonymous access and ignores authorization headers; enable
protected mode to enforce key grants.

Clients use the application's `/mcp` URL and send `Authorization: Bearer <key>`
on every request. Remote connections must use HTTPS. Full secrets must not be placed in URLs, checked-in
configuration, or tool arguments. Revocation/expiry is checked before each new
tool admission; already admitted calls finish. Credentials survive reload/restart.

For browser-based Agent authorization, install the independent
`toolframe-oidc-auth` plugin with compatible Core/Auth builds. MCP Auth declares
an optional `toolframe.oauth.tokens` dependency: `tf_oauth_` tokens and `oauth:`
credential references are delegated to its verifier with the resource and
required scopes intact. Existing keys stay local to this plugin. An absent or
unhealthy optional verifier rejects OAuth requests without disabling key
verification. OIDC login, consent, discovery and token issuance belong to the
shared OIDC plugin; MCP Auth adds no provider-specific authentication flow.

The internal `toolframe.mcp-auth` service provides `create`, `list`, `revoke`,
`verify` and `resolve`. Core admits management callers and owns trusted request
contexts. These methods are not public business APIs. Back up the plugin's
consistent managed store using its SQL provider's backup procedure.

## PostgreSQL storage

Version 0.3 requires SDK 0.4 and declares PostgreSQL migration SQL alongside the
unchanged SQLite history. Provision this plugin’s stable store owner with the
PostgreSQL provider before enabling it. The application still runs one Core;
retain its private keys and configuration with the application home. Existing
SQLite records are not imported automatically.
