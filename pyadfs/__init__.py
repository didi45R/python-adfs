"""
Python-ADFS
===========

A Python library for interacting with Active Directory Federation Services (ADFS) and OIDC.

Usage::
    TODO

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
