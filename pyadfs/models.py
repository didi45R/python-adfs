import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from pyadfs.helpers import extract_token_exp


class TokenModel(BaseModel):
    """
    Model containing the default and most used fields which are common to all ADFS tokens.
    Contains the default fields which are present in JWTs as specified in RFC7519 and common Active Directory fields.

    If you want to override any of these fields, use the `TokenModel` class as a base class.

    >>> class CustomTokenModel(TokenModel):
    >>>     my_field: str = Field(..., alias="myField")
    """

    model_config = ConfigDict(from_attributes=True, extra="allow")

    subject: Optional[str] = Field(None, alias="sub")
    sam_account_name: Optional[str] = Field(None, alias="sAMAccountName")
    email_address: Optional[str] = Field(
        None, validation_alias=AliasChoices("EmailAddress", "email"), serialization_alias="EmailAddress"
    )
    user_principal_name: Optional[str] = Field(None, alias="UPN")
    app_type: Optional[str] = Field(None, alias="apptype")
    auth_method: Optional[str] = Field(None, alias="authmethod")
    expire_time: float = Field(..., alias="exp")
    issuer: Optional[str] = Field(None, alias="iss")
    audience: Optional[str] = Field(None, alias="aud")
    issued_at: Optional[float] = Field(None, alias="iat")
    not_before: Optional[float] = Field(None, alias="nbf")
    jwt_id: Optional[str] = Field(None, alias="jti")

    @property
    def exp_readable_timestamp(self) -> str:
        """Returns exp as human-readable timestamp (time.ctime)."""
        return time.ctime(self.expire_time)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def expires_at(self) -> datetime:
        """Returns the expiration time as a datetime object in UTC."""
        return datetime.fromtimestamp(self.expire_time, tz=timezone.utc)


class TokenUser(BaseModel):
    """
    Model for Username/Password credentials. Password is excluded from serialization for security.
    """

    username: str
    password: str = Field(..., repr=False, exclude=True)

    @field_validator("username", mode="before")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not value:
            raise ValueError("Username cannot be empty")
        if "@" not in value:
            raise ValueError("Username must be FQDN (containing @realm)")
        return value


class RawTokenModel(BaseModel):
    """
    Model containing the "raw" result of generated ADFS token, these fields are not optional and
    if they are not present, the token is considered invalid.

    The required fields are:
        * access_token: The actual token string which is used for authentication.
        * token_type: The type of the token, usually "Bearer".
        * expires_in: The number of seconds until the token expires.

    To read the access_token as it was returned, simply use the `access_token` field.
    """

    model_config = ConfigDict(from_attributes=True, extra="allow")

    access_token: str
    token_type: Optional[str] = "Bearer"
    expires_in: float
    scope: Optional[str] = None
    exp: Optional[float] = None

    @model_validator(mode="after")
    def populate_exp(self) -> "RawTokenModel":
        """Populates the `exp` field based on the current time and `expires_in` if `exp` is not already set."""
        if self.exp is None:
            self.exp = extract_token_exp(self.access_token)
        return self

    @field_validator("exp", mode="before")
    @classmethod
    def validate_exp(cls, value: Optional[float]) -> Optional[float]:
        if not value:
            return None
        return value

    @property
    def is_expired(self) -> bool:
        """Returns True if the token is expired, False otherwise."""
        if self.exp is None:
            return False
        return time.time() >= self.exp

    @property
    def exp_readable_timestamp(self) -> Optional[str]:
        """Returns exp as human-readable timestamp (time.ctime) if exp is set, None otherwise."""
        if self.exp is None:
            return None
        return time.ctime(self.exp)

    @property
    def expires_at(self) -> Optional[datetime]:
        """Returns the expiration time as a datetime object in UTC if exp is set, None otherwise."""
        if self.exp is None:
            return None
        return datetime.fromtimestamp(self.exp, tz=timezone.utc)


class ValidatedToken:
    """
    Result of a successful token validation.
    This is mainly used for debugging so you can see all the claims returned.

    Attributes:
        claims (TokenModel): The parsed and validated claims extracted from the JWT.
        raw_claims (Dict[str, Any]): Raw claims dictionary, before model parsing.
    """

    __slots__ = ("claims", "raw_claims")

    def __init__(self, claims: TokenModel, raw_claims: Dict[str, Any]) -> None:
        self.claims = claims
        self.raw_claims = raw_claims


class OIDCConfig:
    """
    Cached snapshot of the ADFS OpenID Connect discovery document.

    Attributes:
        issuer (str): Value of the "issuer" field which is used for validating the "iss" claim in the tokens.
        jwks_uri (str): URL where JWKs (JSON Web Key Set) is published.
        token_endpoint (str): OAuth2 token endpoint where a token is generated.
        end_session_endpoint (Optional[str]): Logout endpoint if published by the ADFS server.
        raw (Dict[str, Any]): The raw discovery JSON document for forward-compatibility.
    """

    def __init__(self, data: Dict[str, Any]) -> None:
        self.issuer: str = data.get("access_token_issuer") or data["issuer"]
        if not self.issuer:
            raise ValueError("OIDC discovery document must include access_token_issuer or issuer")
        self.jwks_uri: str = data["jwks_uri"]
        self.token_endpoint: str = data["token_endpoint"]
        self.end_session_endpoint: Optional[str] = data.get("end_session_endpoint")
        self.raw: Dict[str, Any] = data
