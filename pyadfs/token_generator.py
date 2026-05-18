"""
This module supports ADFS Token generation in sync and async for two grant types: client_credentials and password.
The generated token is a JWT which can be used to authenticate to ADFS protected resources.
1. Password grant type: The most common grant type, used for user authentication, generally this is the used grant type.
   It requires a username and password in addition to the application's client id and client secret.
2. Client credentials grant type: This grant type is used for application authentication,
   commonly used for service-to-service authentication, it does not involve a user context, therefore
   it does not require a username and password, but it requires the application's client id and client secret.

By default an application group registered in ADFS is configured to allow Password grant type,
if you want to use Client Credentials, you need to add a relying party trust for the application group.

This module provides two functions:

* `generate_token`: A synchronous (requests) function to generate a token.
* `generate_token_async`: An asynchronous (aiohttp) function to generate a token.

Both support the two OAuth2 grant types that ADFS exposes:

* **password**: user-flow that requires ``username`` and ``password``.
* **client_credentials**: application-flow (service-to-service) that requires only the client_id and client_secret.
"""

import asyncio
import logging
from json import JSONDecodeError
from typing import Dict, Optional
from warnings import warn

import aiohttp
import requests
from aiohttp.client_exceptions import ClientConnectionError, ClientError, ServerTimeoutError
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import HTTPError, Timeout

from pyadfs.config import settings
from pyadfs.consts import ADFS_TOKEN_URL
from pyadfs.exceptions import ADFSError, response_error_factory
from pyadfs.models import RawTokenModel

logger = logging.getLogger(__name__)

GRANT_TYPES = {
    "password": {"username", "password"},
    "client_credentials": set(),
}


def _build_token_req_payload(
    grant_type: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    resource: Optional[str] = None,
    scope: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """
    Assemble the form-encoded payload that will be sent to the token endpoint.
    Values that are not explicitly provided will fallback to the application settings.
    """
    resolved_client_id = client_id or settings.adfs_client_id
    resolved_client_secret = client_secret or settings.adfs_client_secret
    resolved_resource = resource or resolved_client_id

    payload = {
        "grant_type": grant_type,
        "client_id": resolved_client_id,
        "client_secret": resolved_client_secret,
        "resource": resolved_resource,
    }
    if scope:
        payload["scope"] = scope
    required_fields = GRANT_TYPES.get(grant_type, set())
    if "username" in required_fields and username:
        payload["username"] = username
    if "password" in required_fields and password:
        payload["password"] = password
    return payload


def _validate_params(grant_type: str, username: Optional[str], password: Optional[str]) -> None:
    """
    Validate that the required parameters for the specified grant type are provided.
    """
    required_fields = GRANT_TYPES.get(grant_type)
    if not required_fields:
        raise ValueError(f"Unsupported grant type: {grant_type}, supported types are: {', '.join(GRANT_TYPES.keys())}")
    if "username" in required_fields and not username:
        raise ValueError("Username is required for password grant type")
    if username and "username" in required_fields and "@" not in username:
        raise ValueError("Username must contain a domain (e.g., username@domain)")
    if "password" in required_fields and not password:
        raise ValueError("Password is required for password grant type")
    if "username" not in required_fields and (username or password):
        warn("Username and password are ignored for client_credentials grant type")


def generate_token(
    grant_type: str = "password",
    adfs_base_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    resource: Optional[str] = None,
    scope: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: int = 20,
    verify_ssl: bool = True,
) -> RawTokenModel:
    """
    Generate an ADFS token using the specified grant type and parameters synchronously.

    :param grant_type: The OAuth2 grant type to use (e.g., "password" or "client_credentials").
    :param adfs_base_url: The base URL of the ADFS server (optional, defaults to `settings.adfs_base_url`).
    :param client_id: The client ID of the application (optional, defaults to `settings.client_id`).
    :param client_secret: The client secret of the application (optional, defaults to `settings.client_secret`).
    :param resource: The resource for which the token is requested (optional, defaults to `client_id`).
    :param scope: The scope of the access request (optional).
    :param username: The username for password grant type (required for ``password`` grant).
    :param password: The password for password grant type (required for ``password`` grant).
    :param timeout: The timeout for the token request in seconds (default: 20).
    :param verify_ssl: Whether to verify SSL certificates when connecting to the ADFS server (default: True).
    :return: A RawTokenModel containing the token response (contains access_token and expires_in).
    :raise ValueError: If ``grant_type`` is unsupported or required parameters are missing.
    :raises ADFSError: If there is an error during token generation.
    """
    # pylint: disable=too-many-locals, too-many-arguments
    base_url = adfs_base_url or settings.adfs_base_url
    _validate_params(grant_type, username, password)

    payload = _build_token_req_payload(
        grant_type=grant_type,
        client_id=client_id,
        client_secret=client_secret,
        resource=resource,
        scope=scope,
        username=username,
        password=password,
    )
    try:
        response = requests.post(
            url=ADFS_TOKEN_URL.format(base_url),
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
            verify=verify_ssl,
        )
        response.raise_for_status()
        result = response.json()
        return RawTokenModel(**result)
    except (Timeout, TimeoutError) as exc:
        raise ADFSError(f"ADFS Token request timed out after {timeout}s (server={base_url})") from exc
    except RequestsConnectionError as exc:
        raise ADFSError(f"Failed to connect to ADFS server at {base_url}") from exc
    except HTTPError as exc:
        raise response_error_factory(response.status_code, response.text) from exc
    except JSONDecodeError as exc:
        raise ADFSError(f"Failed decoding and parsing token response as JSON (status={response.status_code})") from exc


async def generate_token_async(
    grant_type: str = "password",
    adfs_base_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    resource: Optional[str] = None,
    scope: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: int = 20,
    verify_ssl: bool = True,
) -> RawTokenModel:
    """
    Generate an ADFS token using the specified grant type and parameters asynchronously (using ``aiohttp``).

    :param grant_type: The OAuth2 grant type to use (e.g., "password" or "client_credentials").
    :param adfs_base_url: The base URL of the ADFS server (optional, defaults to `settings.adfs_base_url`).
    :param client_id: The client ID of the application (optional, defaults to `settings.client_id`).
    :param client_secret: The client secret of the application (optional, defaults to `settings.client_secret`).
    :param resource: The resource for which the token is requested (optional, defaults to `client_id`).
    :param scope: The scope of the access request (optional).
    :param username: The username for password grant type (required for ``password`` grant).
    :param password: The password for password grant type (required for ``password`` grant).
    :param timeout: The timeout for the token request in seconds (default: 20).
    :param verify_ssl: Whether to verify SSL certificates when connecting to the ADFS server (default: True).
    :return: A RawTokenModel containing the token response (contains access_token and expires_in).
    :raise ValueError: If ``grant_type`` is unsupported or required parameters are missing.
    :raises ADFSError: If there is an error during token generation.
    """
    # pylint: disable=too-many-locals, too-many-arguments
    base_url = adfs_base_url or settings.adfs_base_url
    _validate_params(grant_type, username, password)

    payload = _build_token_req_payload(
        grant_type=grant_type,
        client_id=client_id,
        client_secret=client_secret,
        resource=resource,
        scope=scope,
        username=username,
        password=password,
    )

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        try:
            async with session.post(
                url=ADFS_TOKEN_URL.format(base_url),
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                ssl=verify_ssl,
            ) as response:
                response.raise_for_status()
                result = await response.json()
                return RawTokenModel(**result)
        except (asyncio.TimeoutError, ServerTimeoutError) as exc:
            raise ADFSError(f"ADFS Token request timed out after {timeout}s (server={base_url})") from exc
        except ClientConnectionError as exc:
            raise ADFSError(f"Failed to connect to ADFS server at {base_url}") from exc
        except ClientError as exc:
            text = await response.text() or "No response body"
            raise response_error_factory(response.status, text) from exc
        except JSONDecodeError as exc:
            raise ADFSError(f"Failed decoding and parsing token response as JSON (status={response.status})") from exc
