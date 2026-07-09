# Sign-In with Ethereum

Let users authenticate by signing a message with their Ethereum wallet — no password, no email —
following [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361). The address *is* the identity; a
wallet-backed user is created the first time an address signs in.

## Install

`pip install "deadbolt[siwe]"`  *(brings `eth-account` for signature recovery)*

## Setup

```python
import deadbolt as db
from deadbolt.plugins.siwe import siwe

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    plugins=[siwe(domain="app.example.com", chain_id=1)],
)
```

Run the schema generator (or your migration) so the `siwe_nonce` and `wallet_address` tables exist.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `domain` | string | — | **Required.** The domain the signed message must be bound to; a message for any other domain is rejected. |
| `chain_id` | integer | `1` | Advertised on the nonce response (mainnet by default). |
| `nonce_ttl` | integer | `600` | Nonce lifetime in seconds. |
| `verify` | callable | eth-account | Overrides signature recovery with `(message, signature) -> address | None`. |

## The flow

1. **`GET /siwe/nonce`** → `{ "nonce": "...", "chain_id": 1 }`. The client embeds the nonce in an
   EIP-4361 message it builds locally.
2. The wallet signs that message (EIP-191 `personal_sign`).
3. **`POST /siwe/verify`** with `{ "message": "...", "signature": "0x..." }`. The server recovers the
   signer, checks it matches the message's address, validates the nonce (single-use, unexpired) and
   domain and any expiry, then returns `{ "user": { ... }, "address": "0x..." }` plus the session
   cookie.

## Errors

| Status | Code | When |
| --- | --- | --- |
| `401` | `invalid_message` | The message is malformed or bound to a different domain. |
| `401` | `invalid_signature` | The signature does not recover to the claimed address. |
| `401` | `invalid_nonce` | The nonce is unknown, already used, or expired. |
| `401` | `expired_message` | The message's `Expiration Time` has passed. |

## Notes

- **Nonce is single-use.** It is deleted the moment it is presented, so a replayed message fails even
  within its TTL — the core defence against signature replay.
- **Address is the account.** The recovered address maps to a `wallet_address` row; the linked user is
  reused on return visits. A synthetic `<address>@siwe.local` email fills the required user field.
- **Pairs with bearer.** Wallet clients are typically non-browser; combine with the
  [bearer](bearer.md) plugin to carry the session as a header.
