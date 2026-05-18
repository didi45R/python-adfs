from typing import Optional

import jwt

from pyadfs.exceptions import (
    AudienceMismatchError,
    InvalidTokenError,
    SignatureVerificationError,
    TokenExpiredError,
)


def extract_token_exp(access_token: str) -> float:
    try:
        exp = jwt.decode(access_token, options={"verify_signature": False}).get("exp", 0)
        return float(exp) if isinstance(exp, (int, float, str)) else 0.0
    except Exception:
        return 0.0


def match_jwt_exception(exc: Exception) -> Optional[Exception]:
    exception_mapping = {
        (jwt.ExpiredSignatureError, TokenExpiredError): "The provided token has expired",
        (jwt.InvalidAudienceError, AudienceMismatchError): "The provided token has an invalid audience",
        (jwt.InvalidIssuerError, InvalidTokenError): "The provided token has an invalid issuer",
        (jwt.InvalidSignatureError, SignatureVerificationError): "The provided token has an invalid signature",
        (jwt.PyJWKClientError, InvalidTokenError): "The provided token is invalid",
    }
    for (jwt_exc, custom_exc), message in exception_mapping.items():
        if isinstance(exc, jwt_exc):
            return custom_exc(message)
    return None
