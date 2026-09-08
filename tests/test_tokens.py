"""Tests for :mod:`password_reset.tokens`."""

import unittest
from datetime import datetime, timedelta, timezone

from password_reset.tokens import (
    DEFAULT_TTL,
    TOKEN_BYTES,
    ResetToken,
    generate_token,
    hash_token,
    tokens_match,
    utcnow,
)

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class GenerateTokenTests(unittest.TestCase):
    def test_tokens_are_unique_across_many_draws(self):
        tokens = {generate_token() for _ in range(1000)}
        self.assertEqual(len(tokens), 1000)

    def test_token_carries_the_expected_entropy(self):
        # token_urlsafe emits roughly 4 characters per 3 bytes.
        token = generate_token()
        self.assertGreaterEqual(len(token), TOKEN_BYTES)

    def test_token_is_url_safe(self):
        # Reset tokens are embedded in links, so they must survive a URL
        # without escaping.
        allowed = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        )
        for _ in range(50):
            self.assertTrue(set(generate_token()) <= allowed)

    def test_entropy_floor_is_at_least_256_bits(self):
        self.assertGreaterEqual(TOKEN_BYTES * 8, 256)


class HashTokenTests(unittest.TestCase):
    def test_hash_is_deterministic(self):
        token = generate_token()
        self.assertEqual(hash_token(token), hash_token(token))

    def test_hash_is_a_sha256_hex_digest(self):
        self.assertEqual(len(hash_token("anything")), 64)

    def test_different_tokens_hash_differently(self):
        self.assertNotEqual(hash_token("token-a"), hash_token("token-b"))

    def test_raw_token_is_not_recoverable_from_the_hash(self):
        token = generate_token()
        self.assertNotIn(token, hash_token(token))

    def test_rejects_empty_token(self):
        with self.assertRaises(ValueError):
            hash_token("")


class TokensMatchTests(unittest.TestCase):
    def test_matches_the_issuing_token(self):
        token = generate_token()
        self.assertTrue(tokens_match(token, hash_token(token)))

    def test_rejects_a_different_token(self):
        self.assertFalse(tokens_match(generate_token(), hash_token(generate_token())))

    def test_rejects_empty_inputs(self):
        token = generate_token()
        self.assertFalse(tokens_match("", hash_token(token)))
        self.assertFalse(tokens_match(token, ""))

    def test_rejects_a_truncated_token(self):
        token = generate_token()
        self.assertFalse(tokens_match(token[:-1], hash_token(token)))


class IssueTests(unittest.TestCase):
    def test_returns_record_and_raw_token(self):
        record, raw = ResetToken.issue("user-1", now=FIXED_NOW)
        self.assertIsInstance(record, ResetToken)
        self.assertTrue(tokens_match(raw, record.token_hash))

    def test_raw_token_is_never_stored_on_the_record(self):
        record, raw = ResetToken.issue("user-1", now=FIXED_NOW)
        self.assertNotIn(raw, repr(record))

    def test_expiry_follows_the_ttl(self):
        record, _ = ResetToken.issue("user-1", ttl=timedelta(minutes=15), now=FIXED_NOW)
        self.assertEqual(record.expires_at, FIXED_NOW + timedelta(minutes=15))

    def test_default_ttl_is_thirty_minutes(self):
        self.assertEqual(DEFAULT_TTL, timedelta(minutes=30))

    def test_two_tokens_for_one_user_differ(self):
        first, raw_first = ResetToken.issue("user-1", now=FIXED_NOW)
        second, raw_second = ResetToken.issue("user-1", now=FIXED_NOW)
        self.assertNotEqual(raw_first, raw_second)
        self.assertNotEqual(first.token_hash, second.token_hash)

    def test_rejects_empty_user_id(self):
        with self.assertRaises(ValueError):
            ResetToken.issue("", now=FIXED_NOW)

    def test_rejects_non_positive_ttl(self):
        for bad_ttl in (timedelta(0), timedelta(minutes=-5)):
            with self.subTest(ttl=bad_ttl):
                with self.assertRaises(ValueError):
                    ResetToken.issue("user-1", ttl=bad_ttl, now=FIXED_NOW)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.record, self.raw = ResetToken.issue("user-1", now=FIXED_NOW)

    def test_fresh_token_is_usable(self):
        self.assertTrue(self.record.is_usable(now=FIXED_NOW))

    def test_token_is_unusable_after_expiry(self):
        just_after = FIXED_NOW + DEFAULT_TTL + timedelta(seconds=1)
        self.assertTrue(self.record.is_expired(now=just_after))
        self.assertFalse(self.record.is_usable(now=just_after))

    def test_expiry_boundary_is_exclusive(self):
        # At exactly expires_at the token is already dead, so there is no
        # one-second window where a stale token still works.
        self.assertTrue(self.record.is_expired(now=self.record.expires_at))

    def test_token_is_unusable_after_being_spent(self):
        self.record.mark_used(now=FIXED_NOW)
        self.assertTrue(self.record.is_used())
        self.assertFalse(self.record.is_usable(now=FIXED_NOW))

    def test_replay_is_rejected(self):
        self.record.mark_used(now=FIXED_NOW)
        with self.assertRaises(ValueError):
            self.record.mark_used(now=FIXED_NOW)

    def test_a_spent_token_stays_unusable_even_before_expiry(self):
        self.record.mark_used(now=FIXED_NOW)
        still_within_ttl = FIXED_NOW + timedelta(minutes=1)
        self.assertFalse(self.record.is_usable(now=still_within_ttl))


class TimezoneTests(unittest.TestCase):
    def test_utcnow_is_timezone_aware(self):
        self.assertIsNotNone(utcnow().tzinfo)

    def test_issued_timestamps_are_timezone_aware(self):
        record, _ = ResetToken.issue("user-1")
        self.assertIsNotNone(record.created_at.tzinfo)
        self.assertIsNotNone(record.expires_at.tzinfo)


if __name__ == "__main__":
    unittest.main()
