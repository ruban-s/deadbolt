# JWT

Issue and verify short-lived, signed JWTs for stateless API access. Tokens are signed with an HKDF-derived subkey of the master secret, independent of the cookie-signing key.

## Install

`pip install "deadbolt[jwt]"`

## Setup

```python
import deadbolt as db
from deadbolt.plugins.jwt import jwt

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[jwt(expires_in=900, issuer="deadbolt")],
)
```

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `expires_in` | integer | `900` | Token lifetime in seconds (`exp` claim). Default 15 minutes. |
| `issuer` | string | `"deadbolt"` | `iss` claim written on issue and required on verify. |

## API

Error responses use the envelope `{"error": {"code": "...", "message": "..."}}` with the listed HTTP status.

#### `GET /token`

Issues a signed JWT for the current session's user. **Auth:** session required.

**Request**: no body.

The issued token carries these claims: `sub` (user id), `email`, `iss` (issuer), `iat`, `exp`.

**Response `200`**:

```json
{ "token": "<header>.<payload>.<signature>", "expires_in": 900 }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `POST /token/verify`

Verifies a token's signature, expiry, and issuer, returning its claims. **Auth:** public.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `token` | string | yes | The JWT to verify. |

**Response `200`**:

```json
{
  "valid": true,
  "user_id": "usr_1",
  "claims": {
    "sub": "usr_1",
    "email": "a@b.com",
    "iss": "deadbolt",
    "iat": 1751932800,
    "exp": 1751933700
  }
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `invalid_token` | Token is malformed, expired, wrongly issued, or signed with a different key. |

## Notes

- **HS256 with a derived key.** Tokens are signed with `HS256`. The key is `derive_key(auth.secret, b"deadbolt/jwt-hs256")` — an HKDF-derived subkey of the master secret, separate from the cookie-signing key. A token minted under a different `secret` fails verification.
- **Issuer enforced.** `verify` decodes with `issuer=<issuer>`, so a token whose `iss` does not match the configured issuer is rejected as `invalid_token`.
- **Short-lived, pair with the session.** Tokens default to a 15-minute lifetime and are not revocable on their own; pair them with the revocable session for anything sensitive. `verify` rejects expired tokens.
- **Stateless.** Verification checks only the signature and claims — no database lookup — so a JWT remains valid until it expires regardless of session state.
