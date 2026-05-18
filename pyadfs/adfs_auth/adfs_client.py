"""
Synchronous ADFS Token validation.

Validates and decodes ADFS-issued JWTs using OpenID configuration endpoint to
auto-discover the issuer, JWKS URI and audience.
Uses the `PyJWT` library for JWT handling and `PyJWKClient` for JWKS management.
"""

import logging
from typing import Any, Dict, Optional, Type

import requests
from jwt import PyJWKClientError
from jwt import decode as jwt_decode

from pyadfs.adfs_auth.jwks import JWKSManager
from pyadfs.config import settings
from pyadfs.consts import ADFS_AUDIENCE_PREFIX_URN, ADFS_METADATA_URL
from pyadfs.exceptions import InvalidTokenError, JWKSFetchError, TokenValidationError
from pyadfs.helpers import match_jwt_exception
from pyadfs.models import OIDCConfig, TokenModel, ValidatedToken

logger = logging.getLogger(__name__)


class ADFSClient:
    """
    Synchronous ADFS Token validator.

    Fetches the OpenID configuration on first use to auto-discover the JWKS URI and expected issuer.
    Token validation uses ``PyJWKSClient`` for key management and caching, and ``PyJWT`` for decoding/verification.
    """

    def __init__(
        self,
        adfs_base_url: Optional[str] = None,
        adfs_client_id: Optional[str] = None,
        audience: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        keys_lifespan: int = 3600,
        verify_ssl: bool = True,
        token_model: Type[TokenModel] = TokenModel,
        timeout: int = 15,
    ) -> None:
        """
        :param adfs_base_url: The base URL of the ADFS server (e.g. `"https://adfs.example.com"`).
            Defaults to `settings.adfs_base_url` if not provided.
        :param adfs_client_id: Your ADFS Application's (application group) Client ID.
            Defaults to `settings.adfs_client_id` if not provided.
        :param audience: Expected ``aud`` claim value. Defaults to ``microsoft:identityserver:{adfs_client_id}``.
        :param jwks_uri: Override the JWKS URI (e.g. `"https://adfs.example.com/adfs/discovery/keys"`).
            Should be provided - it is typically discovered from the `jwks_uri` field.
            in the openid-configuration document at `{adfs_base_url}/.well-known/openid-configuration.`
        :param keys_lifespan: Seconds to cache the signing keys before refreshing. Defaults to 3600 (1 hour).
        :param verify_ssl: Whether to verify SSL and TLS certificates. Defaults to True.
        :param token_model: Pydantic model used to parse token claims. Defaults to `TokenModel`.
            Subclass this and add extra fields to capture custom ADFS claims.
        :param timeout: Seconds to wait for the ADFS server to respond when fetching JWKS keys. Defaults to 15 seconds.
        """
        client_id = audience or adfs_client_id or settings.adfs_client_id
        base_url = adfs_base_url or settings.adfs_base_url
        self._adfs_base_url = base_url
        self._audience = (
            f"{ADFS_AUDIENCE_PREFIX_URN}:{client_id}" if audience is None and client_id is not None else audience
        )
        self._keys_lifespan = keys_lifespan
        self._verify_ssl = verify_ssl
        self._token_model = token_model
        self._timeout = timeout
        self._metadata_url = ADFS_METADATA_URL.format(base_url) if base_url else None
        self._explicit_jwks_uri = jwks_uri

        self._oidc_config: Optional[OIDCConfig] = None
        self._jwks: Optional[JWKSManager] = None
        self._validate_config()

    def _validate_config(self) -> None:
        if not self._audience:
            raise ValueError(
                "Missing Audience (`aud`) claim value, must specify audience= or set settings.adfs_client_id"
            )
        if not self._metadata_url:
            raise ValueError(
                "Missing full URL for .well-known/openid-configuration, "
                "must specify adfs_base_url or set settings.adfs_base_url"
            )

    def validate_token(
        self, token: str, claims_only: bool = True, *, custom_decode_options: Optional[Dict[str, Any]] = None
    ) -> TokenModel | ValidatedToken:
        """
        Validate an ADFS-issued JWT and return its claims.
        Uses RS256, RS384 and RS512 Algorithms as per ADFS defaults and RFC7518 recommendations.
        As specified in `https://datatracker.ietf.org/doc/html/rfc7519#section-8`.

        Performs the following checks:
            - Signature verification (key looked up from JWKS by ``kid``).
            - ``exp`` claim check (token expiration).
            - ``aud`` claim check (matches expected audience).

        :param token: The raw JWT string (access token).
        :param claims_only: If True, returns only the token claims as a Pydantic model (TokenModel).
            If False, returns a ValidatedToken containing both the raw token and the parsed claims.
            Defaults to True.
        :param custom_decode_options: Optional dictionary of custom options for the JWT decode function.
            (Recommended to leave as default, which applies secure defaults and ADFS best practice checks).
            See https://pyjwt.readthedocs.io/en/latest/usage.html#custom-claims-validation for details.
        :return: ``TokenModel`` if ``claims_only=True`` (default), otherwise ``ValidatedToken``.
        :raise InvalidTokenError: If the token is invalid in any way (signature, expiration, audience, etc).
        :raise JWKSFetchError: If there is an error fetching the JWKS keys needed for signature verification.
        """
        jwks = self._ensure_jwks()
        try:
            signing_key = jwks.get_signing_key(token)
        except JWKSFetchError:
            raise
        except Exception as exc:
            raise InvalidTokenError(f"Error retrieving signing key: {str(exc)}") from exc
        options = {
            "verify_signature": True,
            "require": ["exp", "aud", "iss"],
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": True,
        }
        options.update(custom_decode_options if custom_decode_options else {})

        try:
            raw_claims = jwt_decode(
                token,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512"],
                issuer=self.oidc_config.issuer,
                audience=self._audience,
                options=options,  # type: ignore
            )
        except PyJWKClientError as exc:
            raise InvalidTokenError(f"Decode token failed: {str(exc)}") from exc
        except Exception as exc:
            custom_exc = match_jwt_exception(exc)
            if custom_exc:
                raise custom_exc from exc
            raise TokenValidationError(f"Token validation failed: {str(exc)}") from exc

        try:
            claims = self._token_model.model_validate(raw_claims)
        except Exception as exc:
            raise InvalidTokenError(f"Error parsing token claims: {str(exc)}") from exc
        return ValidatedToken(claims, raw_claims) if not claims_only else claims

    def decode_token_unsafe(self, token: str) -> Dict[str, Any]:
        """
        Decode a JWT **without** validating its signature or claims.
        This is unsafe and should only be used for debugging or extracting claims from an
        already known valid token.

        :param token: The raw JWT string (access token).
        :return: The decoded claims as a dictionary.
        """
        jwks = self._ensure_jwks()
        signing_key = jwks.get_signing_key(token)
        return jwt_decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            options={"verify_signature": False, "verify_aud": False, "verify_exp": False, "verify_iss": False},
        )

    @property
    def oidc_config(self) -> OIDCConfig:
        """:return: Lazily fetched and cached OpenID configuration document."""
        return self._ensure_oidc_config()

    def _ensure_oidc_config(self) -> OIDCConfig:
        if self._oidc_config is None:
            self._oidc_config = self._fetch_oidc_config()
        return self._oidc_config

    def _ensure_jwks(self) -> JWKSManager:
        if self._jwks is None:
            uri = self._explicit_jwks_uri or self.oidc_config.jwks_uri
            self._jwks = JWKSManager(
                jwks_uri=uri, adfs_base_url=self._adfs_base_url, keys_lifespan=self._keys_lifespan
            )
        return self._jwks

    def _fetch_oidc_config(self) -> OIDCConfig:
        try:
            res = requests.get(url=self._metadata_url, timeout=self._timeout, verify=self._verify_ssl)  # type: ignore
            res.raise_for_status()
            data: Dict[str, Any] = res.json()
        except Exception as exc:
            raise JWKSFetchError(f"Error fetching OpenID configuration from {self._metadata_url}: {str(exc)}") from exc

        if "jwks_uri" not in data or "issuer" not in data:
            raise JWKSFetchError(
                f"OpenID configuration is missing required fields (jwks_uri and/or issuer): {list(data.keys())}"
            )
        logger.debug("Fetched OIDC config - issuer: %s, jwks_uri: %s", data["access_token_issuer"], data["jwks_uri"])
        return OIDCConfig(data)
