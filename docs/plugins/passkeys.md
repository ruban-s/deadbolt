# Passkeys (WebAuthn)

Register and sign in with passkeys using the WebAuthn standard. Each ceremony is a two-step `options` → `verify` flow; the server-issued challenge is held server-side and referenced by a returned `challenge_token`.

## Install

`pip install "deadbolt[passkeys]"`

## Setup

```python
import deadbolt as db
from deadbolt.plugins.passkeys import passkeys

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[
        passkeys(
            rp_id="example.com",
            rp_name="Example",
            origin="https://example.com",
        ),
    ],
)
```

The plugin registers a `passkey` table (`id`, `user_id`, `name`, `credential_id`, `public_key`, `sign_count`, `created_at`).

## Configuration

The `passkeys()` plugin factory:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `rp_id` | `str` | required | Relying Party ID — the registrable domain (e.g. `"example.com"`). Must match the page origin's domain. |
| `rp_name` | `str` | required | Human-readable Relying Party name shown by the authenticator. |
| `origin` | `str` | required | Expected origin of ceremonies (e.g. `"https://example.com"`); verified on both register and authenticate. |

## API

### `POST /passkey/register-options`

Returns WebAuthn creation options for the signed-in user (excluding already-registered credentials) plus a `challenge_token`. **Auth:** session required.

**Request**: no fields required.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| _(none)_ | | | Body may be empty `{}`. |

**Response `200`**:

```json
{
  "options": {
    "rp": { "id": "example.com", "name": "Example" },
    "user": { "id": "...", "name": "a@b.com", "displayName": "..." },
    "challenge": "...",
    "pubKeyCredParams": [],
    "excludeCredentials": []
  },
  "challenge_token": "..."
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |

**Example** (browser creates the credential from the returned options):

```js
const { options, challenge_token } = await (await fetch("/api/auth/passkey/register-options", {
  method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
})).json();

const credential = await navigator.credentials.create({ publicKey: options });
```

### `POST /passkey/register-verify`

Verifies the created credential and stores the passkey for the signed-in user. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `challenge_token` | `string` | yes | Token returned by `register-options`. |
| `credential` | `object` | yes | The `PublicKeyCredential` from `navigator.credentials.create`, serialized to JSON. |
| `name` | `string` | no | Optional label for the passkey (e.g. `"MacBook"`). |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |
| `400` | `invalid_request` | `credential` missing or not an object, or `challenge_token` missing. |
| `400` | `invalid_challenge` | Challenge not found or expired (TTL 300s). |

**Example**:

```js
await fetch("/api/auth/passkey/register-verify", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ challenge_token, credential, name: "MacBook" }),
});
```

### `POST /passkey/authenticate-options`

Returns WebAuthn request options and a `challenge_token`. If an `email` is supplied and known, the response scopes `allowCredentials` to that user's passkeys; otherwise it allows any (usernameless/discoverable). **Auth:** public.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | `string` | no | If given and matching a user, restricts allowed credentials to that user. |

**Response `200`**:

```json
{
  "options": {
    "challenge": "...",
    "rpId": "example.com",
    "allowCredentials": []
  },
  "challenge_token": "..."
}
```

**Errors**: none specific (always returns options).

**Example**:

```js
const { options, challenge_token } = await (await fetch("/api/auth/passkey/authenticate-options", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "a@b.com" }),
})).json();

const assertion = await navigator.credentials.get({ publicKey: options });
```

### `POST /passkey/authenticate-verify`

Verifies the assertion against the stored passkey, updates the signature counter, and issues a session. **Auth:** public.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `challenge_token` | `string` | yes | Token returned by `authenticate-options`. |
| `credential` | `object` | yes | The assertion from `navigator.credentials.get`, serialized to JSON. Its `id` selects the stored passkey. |

**Response `200`**:

```json
{
  "user": {
    "id": "...",
    "email": "a@b.com",
    "email_verified": false,
    "name": null,
    "image": null,
    "created_at": "...",
    "updated_at": "..."
  }
}
```

A `__Host-session` cookie is set alongside the body.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | `credential` missing or not an object, or `challenge_token` missing. |
| `400` | `invalid_challenge` | Challenge not found or expired (TTL 300s). |
| `400` | `unknown_passkey` | No passkey matches the credential `id`, or its owning user is gone. |

**Example**:

```js
await fetch("/api/auth/passkey/authenticate-verify", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ challenge_token, credential: assertion }),
});
```

### `GET /passkey/list`

Lists the signed-in user's passkeys. **Auth:** session required.

**Request**: none.

**Response `200`**:

```json
{
  "passkeys": [
    { "id": "...", "name": "MacBook", "created_at": "..." }
  ]
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |

### `POST /passkey/delete`

Deletes one of the signed-in user's passkeys. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | `string` | yes | The passkey `id` (as returned by `/passkey/list`). |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |
| `400` | `invalid_request` | `id` missing or not a string. |
| `404` | `not_found` | No passkey with that `id` owned by the user. |

## Flow

1. Signed-in user `POST /passkey/register-options` → gets `options` + `challenge_token`.
2. Browser runs `navigator.credentials.create({ publicKey: options })`.
3. `POST /passkey/register-verify` with `challenge_token` and the created `credential` → passkey stored.
4. Later, to sign in: `POST /passkey/authenticate-options` (optionally with `email`) → `options` + `challenge_token`.
5. Browser runs `navigator.credentials.get({ publicKey: options })`.
6. `POST /passkey/authenticate-verify` with `challenge_token` and the assertion → session cookie set and `user` returned.

## Notes

- **Challenge token flow.** Each `options` call generates a fresh WebAuthn challenge, stores it in a `verification` row keyed by prefix + a random `challenge_token` (`passkey-reg:<user_id>:<token>` for registration, `passkey-auth:<token>` for authentication), and returns the token. The `verify` step submits the token to look the challenge back up. Challenges are single-use (deleted on lookup) with a 300-second TTL.
- **Clients use the browser WebAuthn API.** The `options` payloads are meant to be passed straight into `navigator.credentials.create` (registration) or `navigator.credentials.get` (authentication); the resulting credential/assertion is serialized and sent to the matching `verify` endpoint.
- **Origin and RP binding.** Verification enforces `expected_rp_id = rp_id` and `expected_origin = origin`, so credentials only work for the configured relying party.
- **Signature counter.** The stored `sign_count` is updated from each successful assertion, supporting cloned-authenticator detection per the WebAuthn spec.
- **Excluded credentials.** Registration options exclude the user's existing passkeys so the same authenticator is not enrolled twice.
