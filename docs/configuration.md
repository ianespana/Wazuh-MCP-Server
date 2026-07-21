# Configuration Guide

Complete configuration reference for Wazuh MCP Server v4.2.1.

All configuration is via environment variables, loaded from (highest precedence first):

1. System environment variables (recommended for production)
2. A `.env` file in the working directory (convenient for development)
3. Built-in defaults

Only the variables listed here are read by the server. (See `.env.example` for a ready-to-copy template.)

## Required

| Variable | Description |
|----------|-------------|
| `WAZUH_HOST` | Wazuh Manager hostname or IP |
| `WAZUH_USER` | Manager API username |
| `WAZUH_PASS` | Manager API password |

The Manager API is always reached over HTTPS on `WAZUH_PORT` (it is TLS-only).

## Server

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | `production` enforces stricter startup checks (see [Production](#production)) |
| `MCP_HOST` | `0.0.0.0` | Bind address |
| `MCP_PORT` | `3000` | Listen port (plain HTTP — terminate TLS at a reverse proxy) |
| `MCP_TRANSPORT` | `http` | Transport. Only HTTP/SSE is implemented |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `MAX_MEMORY_MB` | `512` | Memory budget used for the ratio reported by `/health` and `/metrics` |

## Wazuh Manager

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_PORT` | `55000` | Manager API port |
| `WAZUH_VERIFY_SSL` | `true` | Verify the Manager's TLS certificate. Set `false` only for self-signed certs in development |

## Wazuh Indexer

Required for alert search, aggregation, and vulnerability tools (the vulnerability API was removed in Wazuh 4.8.0 and replaced by Indexer queries).

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | — | Indexer hostname/IP. An explicit `http://` prefix selects plain HTTP |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port |
| `WAZUH_INDEXER_USER` | — | Indexer username |
| `WAZUH_INDEXER_PASS` | — | Indexer password |
| `WAZUH_INDEXER_SSL` | `true` | Use HTTPS for the Indexer. Set `false` for a plain-HTTP OpenSearch node (inferred automatically from an `http://` prefix on the host) |
| `WAZUH_INDEXER_VERIFY_SSL` | `true` | Verify the Indexer's TLS certificate |

## Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `bearer` | `oidc` (recommended production), `bearer`, legacy `oauth`, or `none` (authless) |
| `AUTH_SECRET_KEY` | auto (dev only) | HMAC/JWT signing key. **Required when `ENVIRONMENT=production`** unless `AUTH_MODE=none`; the server refuses to start without it. Use the same value on every instance so tokens survive restarts and load balancing. Generate with `openssl rand -hex 32` |
| `TOKEN_LIFETIME_HOURS` | `24` | Session-token lifetime |
| `MCP_API_KEY` | auto (dev only) | A single pre-set API key in the form `wazuh_<43 chars>`. Generate with `python -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"` |
| `MCP_API_KEY_SCOPES` | `wazuh:read` | Space-separated scopes granted to `MCP_API_KEY`. Add `wazuh:write` to enable active-response/rollback tools |
| `API_KEYS` | — | JSON array for multiple keys with individual scopes |
| `AUTHLESS_ALLOW_WRITE` | `false` | In `AUTH_MODE=none`, allow write tools for unauthenticated callers (dangerous on a `0.0.0.0` bind) |

Scopes are **fail-closed**: a token with no scope claim is treated as read-only, and write is never granted implicitly.

### OAuth (only when `AUTH_MODE=oauth`)

> **Legacy/development compatibility mode.** Internal OAuth does not authenticate an
> end user and must not be used to protect a production SIEM. Use external OIDC below.

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_ISSUER_URL` | derived from request | Public issuer URL |
| `OAUTH_ENABLE_DCR` | `false` | Dynamic Client Registration. Off by default (the endpoint is unauthenticated); enable only if you need it |
| `OAUTH_ACCESS_TOKEN_TTL` | `3600` | Access-token lifetime (seconds) |
| `OAUTH_REFRESH_TOKEN_TTL` | `86400` | Refresh-token lifetime (seconds) |
| `OAUTH_AUTHORIZATION_CODE_TTL` | `600` | Authorization-code lifetime (seconds) |

OAuth requires **PKCE with `S256`**; authorization codes are single-use and refresh tokens rotate on every use.

### External OIDC (recommended production)

Set `AUTH_MODE=oidc` to make Wazuh MCP an OAuth protected resource. It does not
issue tokens, register clients, or expose `/oauth/authorize`; External OIDC provider performs
the authorization-code + PKCE login flow and this server validates its access JWTs.

| Variable | Required | Description                                                    |
| --- | --- |----------------------------------------------------------------|
| `MCP_RESOURCE_URL` | yes | Public resource URL, e.g. `https://wazuh-mcp.example.com/mcp`  |
| `OIDC_ISSUER_URL` | yes | OIDC provider issuer URL                                       |
| `OIDC_AUDIENCE` | yes | Expected access-token audience; normally `MCP_RESOURCE_URL`    |
| `OIDC_DISCOVERY_URL` | no | Defaults to `<issuer>/.well-known/openid-configuration`        |
| `OIDC_JWKS_URL` | no | Defaults to discovery's `jwks_uri`                             |
| `OIDC_ALLOWED_ALGORITHMS` | no | Comma-separated allowlist, default `RS256`; `none` is rejected |
| `OIDC_REQUIRED_SCOPES` | no | Baseline scopes, default `wazuh:read`                          |
| `OIDC_READ_GROUPS` / `OIDC_WRITE_GROUPS` | no | Optional Authentik group-to-scope mapping                      |

The server exposes `/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/mcp`. The scope catalog is supplied by
the authorization server's OIDC discovery; the MCP validates only the
`wazuh:read` and `wazuh:write` scopes it receives in access tokens. Missing credentials return a 401
with a `resource_metadata` challenge; invalid tokens return `invalid_token`.
Tokens are accepted only in the `Authorization: Bearer` header. Signature, `kid`,
expiration, issuer, audience, allowed algorithm and scopes are checked using OIDC
discovery and cached JWKS. A JWKS rotation triggers a refresh for an unknown `kid`.

## Network, CORS & rate limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_ORIGINS` | `https://claude.ai,http://localhost:3000` | Comma-separated CORS origins |
| `TRUSTED_PROXIES` | — | Comma-separated proxy IPs trusted for `X-Forwarded-For`. Set this behind a reverse proxy/load balancer so rate limiting keys on the real client IP |
| `RATE_LIMIT_REQUESTS` | `100` | Allowed requests per window, per client |
| `RATE_LIMIT_WINDOW` | `60` | Rate-limit window (seconds) |

## Sessions

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | — | Redis URL for shared session storage across instances. Without it, sessions are in-memory (single-instance) |
| `SESSION_TTL_SECONDS` | `1800` | Session inactivity timeout |

## TLS / HTTPS

The server speaks plain HTTP on `MCP_PORT`. There is **no built-in HTTPS listener** — terminate TLS at a reverse proxy (nginx, Caddy, Traefik) or a load balancer, which is also where you set HSTS, client-cert policies, and TLS versions.

## Role-Based Access Control (RBAC)

| Scope | Tools | Description |
|-------|-------|-------------|
| `wazuh:read` | 40 tools | Alerts, agents, vulnerabilities, analysis, compliance, system monitoring, verification |
| `wazuh:write` | 14 tools | Active response (block IP, isolate host, kill process, …) and rollback tools |

- **Fail-closed:** a token with no scope claim gets read-only; write is opt-in.
- **Scope enforcement:** every `tools/call` checks the token's scopes before executing.
- **Filtered tool list:** `tools/list` only returns the tools the token may call.
- **Audit logging:** every `wazuh:write` call is logged with client ID, session, timestamp, and arguments.
- Grant write to the env key with `MCP_API_KEY_SCOPES="wazuh:read wazuh:write"`, or per-key via the `API_KEYS` JSON (`"scopes": ["wazuh:read"]`).

## Authentication modes

Configure via `AUTH_MODE`:

| Mode | Value | Description                                                                       |
|------|-------|-----------------------------------------------------------------------------------|
| **Bearer** | `bearer` | API-key → JWT/session-token auth (default)                                        |
| **External OIDC** | `oidc` | External authorization server (recommended production)                            |
| **OAuth** | `oauth` | Legacy internal OAuth compatibility mode; not end-user authentication             |
| **Authless** | `none` | No authentication; read-only unless `AUTHLESS_ALLOW_WRITE=true` (development only) |

**Bearer — exchange an API key for a JWT:**
```bash
curl -X POST https://your-server/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_your-api-key"}'
```
The JWT carries the API key's own scopes (read-only unless the key was granted write).

**OAuth discovery & endpoints:** `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token` (and `/oauth/register` only when `OAUTH_ENABLE_DCR=true`).

## Environment-specific examples

### Development
```bash
ENVIRONMENT=development
WAZUH_HOST=dev-wazuh.internal
WAZUH_USER=dev-user
WAZUH_PASS=dev-password
WAZUH_VERIFY_SSL=false           # self-signed dev certs
LOG_LEVEL=DEBUG
# AUTH_SECRET_KEY / MCP_API_KEY auto-generated and printed on startup
```

### Production
```bash
ENVIRONMENT=production
WAZUH_HOST=wazuh.company.com
WAZUH_USER=mcp-service-account
WAZUH_PASS=very-secure-password
WAZUH_VERIFY_SSL=true

AUTH_MODE=bearer
AUTH_SECRET_KEY=<openssl rand -hex 32, identical on every instance>
MCP_API_KEY=wazuh_<generated>
MCP_API_KEY_SCOPES=wazuh:read              # add wazuh:write only if this key triggers active response
TRUSTED_PROXIES=10.0.0.1                    # your reverse proxy

WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=<secret>
WAZUH_INDEXER_VERIFY_SSL=true

REDIS_URL=redis://redis:6379/0             # required for multi-instance
LOG_LEVEL=INFO
```

In production the server **refuses to start** if `AUTH_SECRET_KEY` is unset (and `AUTH_MODE != none`).

## Validation & troubleshooting

```bash
# Health (no auth) — shows status + service checks
curl -s http://localhost:3000/health | jq .

# Prometheus metrics (CPU/memory gauges, request counters)
curl -s http://localhost:3000/metrics | head

# Verify the app imports with the current env
PYTHONPATH=src python -c "import wazuh_mcp_server.server; print('OK')"
```

Common checks:
```bash
# Manager reachability (TLS)
curl -k -u "$WAZUH_USER:$WAZUH_PASS" "https://$WAZUH_HOST:55000/"

# Indexer reachability
curl -k -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" "https://$WAZUH_INDEXER_HOST:9200/"
```

Configuration changes require a restart:
```bash
docker compose restart wazuh-mcp-remote-server
```

## Claude Desktop integration

> Claude Desktop connects to remote MCP servers through the **Connectors UI**, not `claude_desktop_config.json` (the JSON file only supports local stdio servers).

1. Deploy with HTTPS in front (reverse proxy).
2. Claude Desktop → **Settings → Connectors → Add custom connector**.
3. URL: `https://your-domain.com/mcp` (or `/sse` for legacy SSE).
4. Configure auth in **Advanced settings** (Bearer token, or OAuth if `AUTH_MODE=oauth`).

See [Claude Integration](CLAUDE_INTEGRATION.md) for details.

---

**Next:** [Security Guide](security/README.md) · [API Reference](api/README.md) · [Troubleshooting](TROUBLESHOOTING.md)
