# HMAC-SHA256 from Scratch (C)

A from-scratch implementation of HMAC-SHA256 in C, with no external cryptographic
libraries built on top of a hand-written SHA-256 implementation
([SHA256-from-scratch-c](https://github.com/LamprosM-prog/SHA256-from-scratch-c)).

This is part of an ongoing project working toward a full password-protected folder locker
(PBKDF2-HMAC-SHA256 for key derivation, AES-CBC for encryption, encrypt-then-MAC
for integrity).

## Security Disclaimer

This is not a production-grade cryptographic library. It hasn't been audited,
isn't constant-time in places where that would matter for production use, and
shouldn't be used to protect anything sensitive as-is. It is only an educational
project made by a student.

## Structure

```
src/
├── sha256/
│   ├── sha256.c
│   └── sha256.h
├── hmac.c
└── hmac.h
tests/
└── test_hmac.c
```

`hmac.c` implements the standard nested construction:

```
HMAC(K, m) = H( (K' ⊕ opad) || H( (K' ⊕ ipad) || m ) )
```

uses the streaming `sha256_init` / `sha256_update` / `sha256_final` API from
the SHA-256 implementation, so the ipad/opad-prefixed data is never manually
concatenated into a single buffer.

## Building and testing

```
make run
```

Builds `test_hmac` and runs it directly.

## Test vectors

Verified against [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) test cases 1, 2, 3 and 6.
All four pass with exact match against the RFC's expected output.