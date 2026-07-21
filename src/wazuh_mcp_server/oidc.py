"""External OIDC validation for the MCP protected resource.

This module deliberately implements no authorization-server endpoints: Authentik (or
another OIDC provider) issues tokens and this application only validates them.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import InvalidTokenError

logger = logging.getLogger(__name__)

MAX_TOKEN_LENGTH = 16_384
MAX_CLAIMS = 100


class OIDCValidationError(Exception):
    """A safe, categorized token-validation failure suitable for audit logs."""

    def __init__(self, category: str, required_scope: str | None = None):
        self.category = category
        self.required_scope = required_scope
        super().__init__(category)


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    subject: str
    username: str | None
    client_id: str | None
    scopes: set[str]
    groups: set[str]
    issuer: str
    audience: set[str]
    raw_claims: dict[str, Any]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def _canonical_issuer(value: str) -> str:
    return value.rstrip("/")


class OIDCDiscoveryClient:
    def __init__(self, config):
        self.config = config
        self._metadata: dict[str, Any] | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def get(self, force: bool = False) -> dict[str, Any]:
        if not force and self._metadata and time.monotonic() < self._expires_at:
            return self._metadata
        async with self._lock:
            if not force and self._metadata and time.monotonic() < self._expires_at:
                return self._metadata
            try:
                async with httpx.AsyncClient(verify=self.config.OIDC_VERIFY_SSL, timeout=self.config.REQUEST_TIMEOUT_SECONDS) as client:
                    response = await client.get(self.config.OIDC_DISCOVERY_URL)
                    response.raise_for_status()
                    metadata = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise OIDCValidationError("discovery_unavailable") from exc
            if not isinstance(metadata, dict) or not isinstance(metadata.get("jwks_uri"), str):
                raise OIDCValidationError("invalid_discovery")
            discovered_issuer = metadata.get("issuer")
            if not isinstance(discovered_issuer, str) or _canonical_issuer(discovered_issuer) != _canonical_issuer(self.config.OIDC_ISSUER_URL):
                raise OIDCValidationError("invalid_discovery")
            self._metadata = metadata
            self._expires_at = time.monotonic() + self.config.OIDC_JWKS_CACHE_SECONDS
            return metadata


class JWKSCache:
    def __init__(self, config, discovery: OIDCDiscoveryClient):
        self.config, self.discovery = config, discovery
        self._keys: dict[str, dict[str, Any]] = {}
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> dict[str, Any]:
        if kid in self._keys and time.monotonic() < self._expires_at:
            return self._keys[kid]
        await self._refresh(force=kid not in self._keys)
        key = self._keys.get(kid)
        if not key:
            raise OIDCValidationError("unknown_kid")
        return key

    async def _refresh(self, force: bool = False) -> None:
        async with self._lock:
            # A second caller can use a cache refreshed by the first one.
            if not force and self._keys and time.monotonic() < self._expires_at:
                return
            jwks_uri = self.config.OIDC_JWKS_URL
            if not jwks_uri:
                jwks_uri = (await self.discovery.get()).get("jwks_uri")
            try:
                async with httpx.AsyncClient(verify=self.config.OIDC_VERIFY_SSL, timeout=self.config.REQUEST_TIMEOUT_SECONDS) as client:
                    response = await client.get(jwks_uri)
                    response.raise_for_status()
                    document = response.json()
            except (httpx.HTTPError, ValueError, OIDCValidationError) as exc:
                # A still-valid cache is allowed during an IdP outage; otherwise fail closed.
                if self._keys and time.monotonic() < self._expires_at:
                    return
                raise OIDCValidationError("jwks_unavailable") from exc
            keys = document.get("keys") if isinstance(document, dict) else None
            if not isinstance(keys, list):
                raise OIDCValidationError("invalid_jwks")
            parsed = {key["kid"]: key for key in keys if isinstance(key, dict) and isinstance(key.get("kid"), str)}
            if not parsed:
                raise OIDCValidationError("invalid_jwks")
            self._keys = parsed
            self._expires_at = time.monotonic() + self.config.OIDC_JWKS_CACHE_SECONDS


class OIDCTokenValidator:
    def __init__(self, config):
        self.config = config
        self.discovery = OIDCDiscoveryClient(config)
        self.jwks = JWKSCache(config, self.discovery)

    async def validate(self, token: str) -> AuthenticatedPrincipal:
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
            raise OIDCValidationError("invalid_token")
        try:
            header = jwt.get_unverified_header(token)
        except InvalidTokenError as exc:
            raise OIDCValidationError("invalid_token") from exc
        algorithm, kid = header.get("alg"), header.get("kid")
        if not isinstance(algorithm, str) or algorithm not in self.config.OIDC_ALLOWED_ALGORITHMS:
            raise OIDCValidationError("invalid_algorithm")
        if not isinstance(kid, str) or not kid:
            raise OIDCValidationError("missing_kid")
        jwk = await self.jwks.get_key(kid)
        try:
            key_factory = jwt.algorithms.get_default_algorithms().get(algorithm)
            if key_factory is None:
                raise OIDCValidationError("invalid_algorithm")
            key = key_factory.from_jwk(jwk)
            claims = jwt.decode(
                token, key=key, algorithms=list(self.config.OIDC_ALLOWED_ALGORITHMS),
                audience=self.config.OIDC_AUDIENCE,
                leeway=self.config.OIDC_CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iss", "aud", "sub"], "verify_iat": True, "verify_iss": False},
            )
        except OIDCValidationError:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise OIDCValidationError("expired_token") from exc
        except jwt.InvalidIssuerError as exc:
            raise OIDCValidationError("invalid_issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise OIDCValidationError("invalid_audience") from exc
        except InvalidTokenError as exc:
            raise OIDCValidationError("invalid_signature") from exc
        if not isinstance(claims, dict) or len(claims) > MAX_CLAIMS:
            raise OIDCValidationError("invalid_claims")
        if not isinstance(claims.get("iss"), str) or _canonical_issuer(claims["iss"]) != _canonical_issuer(self.config.OIDC_ISSUER_URL):
            raise OIDCValidationError("invalid_issuer")
        if claims.get("token_use") == "id" or claims.get("typ") == "id_token":
            raise OIDCValidationError("id_token")
        scopes = self._scopes(claims)
        groups = self._groups(claims)
        if groups.intersection(self.config.OIDC_READ_GROUPS):
            scopes.add("wazuh:read")
        if groups.intersection(self.config.OIDC_WRITE_GROUPS):
            scopes.update(("wazuh:read", "wazuh:write"))
        for scope in self.config.OIDC_REQUIRED_SCOPES:
            if scope not in scopes:
                raise OIDCValidationError("missing_scope", scope)
        audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if not all(isinstance(item, str) for item in audience):
            raise OIDCValidationError("invalid_audience")
        return AuthenticatedPrincipal(
            subject=claims["sub"], username=claims.get(self.config.OIDC_USERNAME_CLAIM) or claims.get("email"),
            client_id=claims.get("client_id") or claims.get("azp"), scopes=scopes, groups=groups,
            issuer=claims["iss"], audience=set(audience), raw_claims=claims,
        )

    def _scopes(self, claims: dict[str, Any]) -> set[str]:
        value = claims.get(self.config.OIDC_SCOPE_CLAIM, claims.get("scp", ""))
        if isinstance(value, str):
            return set(value.split())
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return set(value)
        return set()

    def _groups(self, claims: dict[str, Any]) -> set[str]:
        value = claims.get(self.config.OIDC_GROUPS_CLAIM, [])
        if isinstance(value, str):
            return {value}
        return set(value) if isinstance(value, list) and all(isinstance(item, str) for item in value) else set()
