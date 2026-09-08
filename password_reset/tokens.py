"""Reset token generation, storage hygiene, and lifecycle.

A reset token is a bearer credential: whoever holds it can take over the
account it belongs to. That makes it exactly as sensitive as the password it
replaces, and it is handled with the same care.

Four rules govern the design:

1. **Unguessable.** Tokens come from :mod:`secrets`, which draws on the
   operating system's cryptographic random source. ``random`` is seeded
   predictably and must never be used for anything security-relevant.
2. **Never stored in usable form.** Only the SHA-256 hash of a token is kept.
   A leaked database therefore yields no working tokens, exactly as it yields
   no working passwords.
3. **Short-lived.** A token expires 30 minutes after issue, which bounds how
   long a leaked reset email stays dangerous.
4. **Single-use.** Once redeemed a token is spent, so an intercepted link
   cannot be replayed.

Why SHA-256 here when passwords need 600,000 rounds of PBKDF2: the slow hash
exists because humans pick guessable passwords, so each guess must be made
expensive. A token is 256 bits of machine-generated randomness with no
structure to guess, and it is verified on the request path where speed
matters. A fast hash is the right tool for a high-entropy secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

#: 32 bytes = 256 bits of entropy. token_urlsafe yields ~43 URL-safe
#: characters, so the token can be dropped straight into a reset link.
TOKEN_BYTES = 32

#: How long a freshly issued token stays valid.
DEFAULT_TTL = timedelta(minutes=30)


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime.

    Every timestamp in this module is timezone-aware. Naive datetimes compare
    incorrectly across timezones and silently raise when compared with aware
    ones, which is a poor way to discover that an expiry check is broken.
    """
    return datetime.now(timezone.utc)


def generate_token() -> str:
    """Generate a new, cryptographically random reset token.

    This is the only moment the raw token exists in usable form. It goes to
    the user, and only its hash is retained.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Hash a token for storage.

    Unlike passwords there is no per-token salt. Salts defend against
    precomputed tables for low-entropy secrets; a 256-bit random token cannot
    be tabulated, so a salt would add cost without adding protection.

    :raises ValueError: if the token is empty.
    """
    if not token:
        raise ValueError("token must not be empty")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(token: str, stored_hash: str) -> bool:
    """Compare a presented token against a stored hash in constant time.

    :func:`hmac.compare_digest` keeps the comparison time independent of how
    many leading characters happen to match, closing the same timing channel
    guarded against in password verification.
    """
    if not token or not stored_hash:
        return False
    return hmac.compare_digest(hash_token(token), stored_hash)


@dataclass
class ResetToken:
    """A single password reset grant.

    Only ``token_hash`` is persisted. The raw token is returned to the caller
    once, by :meth:`issue`, and is not recoverable afterwards.
    """

    user_id: str
    token_hash: str
    expires_at: datetime
    created_at: datetime = field(default_factory=utcnow)
    used_at: datetime | None = None

    @classmethod
    def issue(
        cls,
        user_id: str,
        *,
        ttl: timedelta = DEFAULT_TTL,
        now: datetime | None = None,
    ) -> tuple["ResetToken", str]:
        """Create a token for ``user_id``.

        Returns the storable record and the raw token, in that order. The raw
        value is deliberately awkward to ignore: it must be delivered to the
        user and then forgotten.

        :raises ValueError: if ``user_id`` is empty or ``ttl`` is not positive.
        """
        if not user_id:
            raise ValueError("user_id must not be empty")
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")

        issued_at = now or utcnow()
        raw_token = generate_token()
        record = cls(
            user_id=user_id,
            token_hash=hash_token(raw_token),
            expires_at=issued_at + ttl,
            created_at=issued_at,
        )
        return record, raw_token

    def is_expired(self, now: datetime | None = None) -> bool:
        """Whether the token's validity window has passed."""
        return (now or utcnow()) >= self.expires_at

    def is_used(self) -> bool:
        """Whether the token has already been redeemed."""
        return self.used_at is not None

    def is_usable(self, now: datetime | None = None) -> bool:
        """Whether the token may still be redeemed right now."""
        return not self.is_used() and not self.is_expired(now)

    def mark_used(self, now: datetime | None = None) -> None:
        """Spend the token.

        Raises rather than silently succeeding on a second call: redeeming an
        already-spent token is a replay attempt, and the caller must not treat
        it as success.

        :raises ValueError: if the token was already used.
        """
        if self.is_used():
            raise ValueError("token has already been used")
        self.used_at = now or utcnow()
