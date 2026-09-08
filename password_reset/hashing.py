"""Password hashing and verification.

Passwords are *hashed*, never encrypted. This distinction matters: encryption
is reversible, so anyone who obtains the key obtains every password. A hash is
one-way, so even a full database compromise does not hand the attacker usable
credentials.

The scheme used here is PBKDF2-HMAC-SHA256, which is available in the Python
standard library and approved by NIST SP 800-132. Three properties make it
suitable:

* **Salted** - every password gets 16 fresh random bytes, so identical
  passwords produce different hashes and precomputed rainbow tables are
  useless.
* **Slow** - the iteration count makes each guess expensive, which is the only
  real defence against offline brute force once a database has leaked.
* **Self-describing** - the algorithm, cost, and salt travel with the hash, so
  the cost can be raised later without invalidating existing hashes.

Production alternatives worth knowing: Argon2id (the current preference, via
``argon2-cffi``), scrypt (``hashlib.scrypt``), and bcrypt. They are omitted here
only to keep this project free of third-party dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

#: Identifier stored alongside each hash so the scheme can be changed later.
ALGORITHM = "pbkdf2_sha256"

#: OWASP's recommended minimum for PBKDF2-HMAC-SHA256. Raise it over time as
#: hardware gets faster; :func:`needs_rehash` will flag stored hashes that fall
#: behind.
DEFAULT_ITERATIONS = 600_000

#: 128 bits of salt. The salt is not secret, it only needs to be unique.
SALT_BYTES = 16

#: Length of the derived key, matching SHA-256's native output size.
HASH_BYTES = 32

#: Separator between fields in the encoded form. Base64 never produces "$".
_FIELD_SEPARATOR = "$"


class InvalidHashError(ValueError):
    """Raised when a stored hash cannot be parsed."""


def _b64encode(raw: bytes) -> str:
    """Encode bytes as unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(encoded: str) -> bytes:
    """Decode unpadded URL-safe base64 back to bytes."""
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    """Run PBKDF2-HMAC-SHA256 over a password."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=HASH_BYTES,
    )


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Hash a password for storage.

    Returns a self-describing string of the form::

        pbkdf2_sha256$600000$<salt>$<derived key>

    The salt is generated fresh on every call, so hashing the same password
    twice produces two different results. That is expected and correct.

    :param password: the plaintext password, which is never stored anywhere.
    :param iterations: PBKDF2 cost. Lower it only in tests.
    :raises ValueError: if the password is empty or the cost is not positive.
    """
    if not password:
        raise ValueError("password must not be empty")
    if iterations < 1:
        raise ValueError("iterations must be a positive integer")

    salt = secrets.token_bytes(SALT_BYTES)
    derived = _derive(password, salt, iterations)
    return _FIELD_SEPARATOR.join(
        [ALGORITHM, str(iterations), _b64encode(salt), _b64encode(derived)]
    )


def _parse(encoded: str) -> tuple[str, int, bytes, bytes]:
    """Split an encoded hash into its four fields.

    :raises InvalidHashError: if the string is not a well-formed hash.
    """
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = encoded.split(
            _FIELD_SEPARATOR
        )
        iterations = int(raw_iterations)
        salt = _b64decode(raw_salt)
        digest = _b64decode(raw_digest)
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidHashError("malformed password hash") from exc

    if algorithm != ALGORITHM:
        raise InvalidHashError(f"unsupported algorithm: {algorithm!r}")
    if iterations < 1:
        raise InvalidHashError("iteration count must be positive")

    return algorithm, iterations, salt, digest


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against a stored hash.

    The comparison uses :func:`hmac.compare_digest`, which takes the same
    amount of time whether the first byte differs or only the last one does.
    A naive ``==`` would leak, through response timing, how much of a guess was
    correct - enough for an attacker to recover a hash byte by byte.

    A malformed or unsupported stored hash returns ``False`` rather than
    raising, so a single corrupt database row cannot become an authentication
    bypass or a crash on the login path.
    """
    if not password or not encoded:
        return False

    try:
        _, iterations, salt, expected = _parse(encoded)
    except InvalidHashError:
        return False

    candidate = _derive(password, salt, iterations)
    return hmac.compare_digest(candidate, expected)


def needs_rehash(encoded: str, *, iterations: int = DEFAULT_ITERATIONS) -> bool:
    """Report whether a stored hash was created with an outdated cost.

    Call this after a successful login, when the plaintext password is briefly
    in hand: if it returns ``True``, re-hash and store the result. That is how
    an existing user base is migrated to a higher cost without forcing anyone
    to reset a password.
    """
    try:
        _, stored_iterations, _, _ = _parse(encoded)
    except InvalidHashError:
        return True
    return stored_iterations < iterations
