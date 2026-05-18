"""
Python-ADFS
===========

A Python library for interacting with Active Directory Federation Services (ADFS) and OIDC.

Usage::

    # Generate and validate a token (sync)
    from pyadfs import ADFSClient, generate_token
    token = generate_token(grant_type="password", username="username@domain", password="secret")
    client = ADFSClient(adfs_client_id="your-adfs-client-id")
    client.validate_token(token.access_token)

    # Generate and validate a token (async)
    from pyadfs import ADFSClientAsync, generate_token_async
    token = await generate_token_async(grant_type="client_credentials")
    # You can use a context manager for ADFSClientAsync
    async with ADFSClientAsync(adfs_client_id="your-adfs-client-id") as client:
        token_model = await client.validate_token(token.access_token)
        upn = token_model.user_principal_name
        email = token_model.email_address

Authors::
    Yedidya Rosenstark
"""

from .adfs_auth import ADFSClient, ADFSClientAsync
from .models import RawTokenModel, TokenModel, ValidatedToken
from .token_generator import generate_token, generate_token_async

__all__ = [
    "ADFSClient",
    "ADFSClientAsync",
    "RawTokenModel",
    "TokenModel",
    "ValidatedToken",
    "generate_token",
    "generate_token_async",
]

__title__ = "python-adfs"
__version__ = "0.1.0"
__description__ = "ADFS client library for Python"
__author__ = "Yedidya Rosenstark"
__author_email__ = "yedidya.rosenstark@gmail.com"
__email__ = __author_email__
__url__ = "https://github.com/Didi45R/python-adfs"
