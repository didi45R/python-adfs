from typing import Optional


class ServerError(Exception):
    def __init__(self, *args) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args)


class ResponseError(ServerError):
    def __init__(self, status_code: int, response_text: str) -> None:
        super().__init__(f"Server responded with status code {status_code}: {response_text}")
        self.status_code = status_code
        self.response_text = response_text


class NotFoundError(ResponseError): ...  # noqa: E701


class ConflictError(ResponseError): ...  # noqa: E701


class BadRequestError(ResponseError): ...  # noqa: E701


class ForbiddenError(ResponseError): ...  # noqa: E701


class UnauthorizedError(ResponseError): ...  # noqa: E701


def response_error_factory(status_code: int, response_text: str) -> ResponseError:
    mapping = {
        400: BadRequestError,
        401: UnauthorizedError,
        403: ForbiddenError,
        404: NotFoundError,
        409: ConflictError,
    }
    return mapping.get(status_code, ResponseError)(status_code, response_text)


class ADFSError(Exception):
    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(message)


class AuthorizationError(ADFSError):
    def __init__(self, message: str = "User is not authorized") -> None:
        super().__init__(message)


class InvalidTokenError(ADFSError):
    def __init__(self, message: str = "The provided token is invalid") -> None:
        super().__init__(message)


class TokenExpiredError(ADFSError):
    def __init__(self, message: str = "The provided token has expired") -> None:
        super().__init__(message)


class AudienceMismatchError(ADFSError):
    def __init__(self, message: str = "The token audience does not match the expected audience") -> None:
        super().__init__(message)


class SignatureVerificationError(ADFSError):
    def __init__(self, message: str = "The token signature could not be verified") -> None:
        super().__init__(message)


class TokenValidationError(ADFSError):
    def __init__(self, message: str = "Token validation failed") -> None:
        super().__init__(message)


class ADFSUnknownError(ADFSError):
    def __init__(self, message: str = "An unknown error occurred while processing the ADFS token") -> None:
        super().__init__(message)


class JWKSFetchError(ADFSError):
    def __init__(self, message: str = "Failed to fetch JWKS from ADFS server") -> None:
        super().__init__(message)
