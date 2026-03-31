---
name: crypto
description: Cryptographic hashing, HMAC signatures, and JWT decoding
metadata:
  act: {}
---

# Crypto Component

Cryptographic operations that LLMs cannot perform natively.

## Tools

### hash
Compute a cryptographic hash.

```
hash(input: "hello world")                      → "b94d27b9..."
hash(input: "hello world", algorithm: "sha512")  → "309ecc48..."
hash(input: "hello world", algorithm: "sha3-256") → "644bcc7e..."
```

Algorithms: `sha256` (default), `sha512`, `sha3-256`.

### hmac
Compute HMAC for message authentication (e.g. webhook signature verification).

```
hmac(message: "payload", key: "secret")                     → "5162..."
hmac(message: "payload", key: "secret", algorithm: "sha512") → "a]3f..."
```

### jwt_decode
Decode a JWT token without verifying the signature. Returns header and claims.

```
jwt_decode(token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
→ {"header": {"alg": "HS256"}, "claims": {"sub": "1234567890"}}
```

Use to inspect token claims (who, expiry) without knowing the secret.
