# secure-password-reset

A small, dependency-free reference implementation of a **secure password reset
flow** in Python — the kind of thing every application needs and most get
subtly wrong.

Everything here uses only the Python standard library (`hashlib`, `hmac`,
`secrets`, `unittest`), so you can read every line and run it anywhere.

## Why this exists

Password reset is the most attacked part of most authentication systems. If an
attacker can reset a password, none of your other login security matters. This
repo implements the flow the way it should be done, and documents *why* each
decision was made.

## The threat model

| Threat | Mitigation |
| --- | --- |
| Database leak exposes passwords | Passwords stored as slow salted PBKDF2 hashes, never encrypted or plaintext |
| Database leak exposes reset tokens | Only the SHA-256 *hash* of a reset token is stored |
| Attacker guesses a reset token | 256 bits of entropy from `secrets.token_urlsafe(32)` |
| Attacker learns which emails are registered | Reset requests return the same result for known and unknown emails |
| Stolen token reused later | Tokens are single-use and expire (default 30 minutes) |
| Timing attack on comparison | All secret comparisons use `hmac.compare_digest` |
| Old sessions survive a reset | Confirming a reset invalidates every other outstanding token for that user |

## Project layout

```
password_reset/
    hashing.py   # password hashing and verification
    tokens.py    # reset token generation and storage hygiene
    store.py     # in-memory user + token storage
    service.py   # the reset flow itself
tests/
    test_*.py    # unittest suite
```

## Running it

```bash
python3 -m unittest discover -s tests -v
```

## Status

Built incrementally, one feature branch and pull request at a time. See the
[closed pull requests](../../pulls?q=is%3Apr+is%3Aclosed) for the build history.

## License

MIT — see [LICENSE](LICENSE).
