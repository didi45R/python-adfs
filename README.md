# python-adfs

Python module for interacting with Microsoft ADFS and OIDC for authentication and authorization, simplified, type-safe and production-ready.

## Installation

Install the module using pip

```bash
pip install pyadfs
```

See pyproject.toml for more information and changelog.md for updates.

## Usage

It is recommended that you read the microsoft docs for foundational knowledge on ADFS authentication.
\
See microsoft docs and OWASP regarding ADFS best practices.

_all methods have matching async functions and classes for use in async environments._

```python
from pyadfs import ADFSClient, TokenModel, generate_token

raw_token = generate_token(
    grant_type="password",
    username="didi45R@example.local",
    password="top-secret",
)

client = ADFSClient() # Use env variables or pass vars directly at init (see config.py)
token_model = client.validate_token(raw_token.access_token)
upn = token_model.user_principle_name
email = token_model.email_address
print(f"{upn}'s token expires at: {token_model.exp_readable_timestamp}")
```

### Useful links

- [jwt.io](https://www.jwt.io/) (jwt playground)
- [JWT RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [microsoft example openid-configuration](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration)

\
**Created by Yedidya.R**
\
Copyright &copy; Yedidya Rosenstark. All rights reserved.
