"""
Shared JWKS management using PyJWKClient.

Handles fetching, caching and key retrieval from the ADFS JWKS endpoint.
Used internally by both the ADFS and ADFSAsync classes for token validation.
"""

import threading
from typing import List, Optional

from jwt import PyJWK, PyJWKClient, PyJWKClientError

from pyadfs.config import settings
from pyadfs.consts import ADFS_JWKS_URI
from pyadfs.exceptions import JWKSFetchError


class JWKSManager:
    """
    Thread-safe manager for fetching and caching JWKS keys from the ADFS server backed py `PyJWKClient`.

    Fetches keys from the ADFS JWKS endpoint (discoverd via openid-configuration) and caches them
    for a configurable lifespan. Automatically refreshes keys when they expire or when a key is not found.
    """

    def __init__(
        self, jwks_uri: Optional[str] = None, adfs_base_url: Optional[str] = None, keys_lifespan: int = 3600
    ) -> None:
        """
        Initialize the JWKSManager.

        :param jwks_uri: The JWKS URI (e.g. `"https://adfs.example.com/adfs/discovery/keys"`).
            Should be provided - it is typically discovered from the `jwks_uri` field.
            in the openid-configuration document at `/.well-known/openid-configuration.`
        :param adfs_base_url: The base URL of the ADFS server (e.g. `"https://adfs.example.com"`).
            Defaults to `settings.adfs_base_url` if not provided.
            This is used as a fallback for the default endpoint if `jwks_uri` is not provided.
        :param keys_lifespan: Seconds to cache the signing keys before refreshing. Defaults to 3600 (1 hour).
        """
        base_url = adfs_base_url or settings.adfs_base_url
        self._jwks_uri = jwks_uri or ADFS_JWKS_URI.format(base_url) if base_url else None
        self._keys_lifespan = keys_lifespan
        self._client: Optional[PyJWKClient] = None
        self._lock = threading.Lock()

    @property
    def jwks_uri(self) -> Optional[str]:
        """Get the JWKS URI being used by this manager."""
        return self._jwks_uri

    def ensure_client(self) -> PyJWKClient:
        """Ensure the PyJWKClient is initialized and return it."""
        if self._jwks_uri is None:
            raise ValueError(
                "Missing `jwks_uri`. Provide a JWKS URI directly or set `adfs_base_url` to fallback to default key url."
            )
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = PyJWKClient(
                        self._jwks_uri,
                        cache_keys=True,
                        lifespan=self._keys_lifespan,
                        cache_jwk_set=True,
                    )
        return self._client

    def get_signing_key(self, token: str) -> PyJWK:
        """
        Get the signing key for a given JWT token.
        The key is automatically fetched and cached on the first call.

        :param token: A signed JWT token, the kid header is used to lookup the correct key.
        :return: The PyJWK signing key object matching the tokens `kid`.
        :raises JWKSFetchError: If there is an error fetching the JWKS keys or if the key is not found.
        """
        try:
            client = self.ensure_client()
            return client.get_signing_key_from_jwt(token)
        except PyJWKClientError as exc:
            raise JWKSFetchError(f"Error fetching JWKS keys: {str(exc)}") from exc

    def get_signing_keys(self, refresh: bool = False) -> List[PyJWK]:
        """
        Get all signing keys from the JWKS endpoint.

        :param refresh: If True, forces a refresh of the keys from the JWKS endpoint.
        :return: A list of PyJWK signing key objects (all signing keys currently published).
        :raises JWKSFetchError: If there is an error fetching the JWKS keys.
        """
        try:
            client = self.ensure_client()
            return client.get_signing_keys(refresh)
        except PyJWKClientError as exc:
            raise JWKSFetchError(f"Error fetching JWKS keys: {str(exc)}") from exc
