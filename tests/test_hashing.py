"""Tests for :mod:`password_reset.hashing`."""

import unittest

from password_reset.hashing import (
    ALGORITHM,
    DEFAULT_ITERATIONS,
    InvalidHashError,
    hash_password,
    needs_rehash,
    verify_password,
)

# Real hashing is deliberately slow, which is the whole point of PBKDF2. Tests
# use a low cost so the suite stays fast; production code uses the default.
TEST_ITERATIONS = 1_000


class HashPasswordTests(unittest.TestCase):
    def test_encoded_hash_has_four_fields(self):
        encoded = hash_password("hunter2-is-a-bad-password", iterations=TEST_ITERATIONS)
        fields = encoded.split("$")
        self.assertEqual(len(fields), 4)
        self.assertEqual(fields[0], ALGORITHM)
        self.assertEqual(fields[1], str(TEST_ITERATIONS))

    def test_plaintext_never_appears_in_the_hash(self):
        password = "a-very-distinctive-passphrase"
        encoded = hash_password(password, iterations=TEST_ITERATIONS)
        self.assertNotIn(password, encoded)

    def test_same_password_hashes_differently_each_time(self):
        # Distinct salts mean identical passwords produce distinct hashes,
        # which is what defeats rainbow tables.
        first = hash_password("repeated", iterations=TEST_ITERATIONS)
        second = hash_password("repeated", iterations=TEST_ITERATIONS)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("repeated", first))
        self.assertTrue(verify_password("repeated", second))

    def test_rejects_empty_password(self):
        with self.assertRaises(ValueError):
            hash_password("", iterations=TEST_ITERATIONS)

    def test_rejects_non_positive_iterations(self):
        with self.assertRaises(ValueError):
            hash_password("valid", iterations=0)

    def test_handles_unicode_passwords(self):
        password = "café-Ünïcode-密码-🔐"
        encoded = hash_password(password, iterations=TEST_ITERATIONS)
        self.assertTrue(verify_password(password, encoded))

    def test_handles_very_long_passwords(self):
        # Unlike bcrypt, PBKDF2 has no 72-byte truncation limit, so the whole
        # passphrase contributes entropy.
        long_password = "x" * 4096
        encoded = hash_password(long_password, iterations=TEST_ITERATIONS)
        self.assertTrue(verify_password(long_password, encoded))
        self.assertFalse(verify_password("x" * 4095, encoded))


class VerifyPasswordTests(unittest.TestCase):
    def setUp(self):
        self.password = "correct-horse-battery-staple"
        self.encoded = hash_password(self.password, iterations=TEST_ITERATIONS)

    def test_accepts_the_correct_password(self):
        self.assertTrue(verify_password(self.password, self.encoded))

    def test_rejects_an_incorrect_password(self):
        self.assertFalse(verify_password("not-the-password", self.encoded))

    def test_rejects_a_case_variant(self):
        self.assertFalse(verify_password(self.password.upper(), self.encoded))

    def test_rejects_empty_inputs(self):
        self.assertFalse(verify_password("", self.encoded))
        self.assertFalse(verify_password(self.password, ""))

    def test_malformed_hashes_return_false_instead_of_raising(self):
        # A corrupt row must never crash the login path or, worse, be treated
        # as a match.
        malformed = [
            "not-a-hash",
            "pbkdf2_sha256$1000$onlythreefields",
            "pbkdf2_sha256$notanumber$c2FsdA$aGFzaA",
            "pbkdf2_sha256$-5$c2FsdA$aGFzaA",
            "md5$1000$c2FsdA$aGFzaA",
            "$$$",
        ]
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                self.assertFalse(verify_password(self.password, candidate))

    def test_tampering_with_the_stored_digest_is_detected(self):
        algorithm, iterations, salt, _ = self.encoded.split("$")
        forged = "$".join([algorithm, iterations, salt, "AAAAAAAAAAAAAAAAAAAAAA"])
        self.assertFalse(verify_password(self.password, forged))


class NeedsRehashTests(unittest.TestCase):
    def test_flags_hashes_below_the_current_cost(self):
        encoded = hash_password("legacy", iterations=TEST_ITERATIONS)
        self.assertTrue(needs_rehash(encoded))

    def test_accepts_hashes_at_the_current_cost(self):
        encoded = hash_password("current", iterations=TEST_ITERATIONS)
        self.assertFalse(needs_rehash(encoded, iterations=TEST_ITERATIONS))

    def test_accepts_hashes_above_the_current_cost(self):
        encoded = hash_password("future", iterations=TEST_ITERATIONS * 2)
        self.assertFalse(needs_rehash(encoded, iterations=TEST_ITERATIONS))

    def test_unparseable_hashes_are_flagged_for_rehashing(self):
        self.assertTrue(needs_rehash("garbage"))

    def test_default_cost_meets_the_owasp_floor(self):
        self.assertGreaterEqual(DEFAULT_ITERATIONS, 600_000)


class InvalidHashErrorTests(unittest.TestCase):
    def test_is_a_value_error(self):
        # Callers that only catch ValueError still behave correctly.
        self.assertTrue(issubclass(InvalidHashError, ValueError))


if __name__ == "__main__":
    unittest.main()
