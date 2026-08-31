"""
Unit tests for TokenSmith.

These use real JWT construction and real HMAC/RSA cryptography (fast and
fully deterministic) rather than mocks — there's no network involved in
any of TokenSmith's core logic, so there's nothing to mock.

Run with:
    python3 -m unittest discover -s tests
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import tokensmith as ts  # noqa: E402


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_hs256_token(header: dict, payload: dict, secret: str) -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


class TestParsing(unittest.TestCase):

    def test_parses_valid_token(self):
        token = make_hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        parsed = ts.parse_jwt(token)
        self.assertTrue(parsed.valid_structure)
        self.assertEqual(parsed.header["alg"], "HS256")
        self.assertEqual(parsed.payload["sub"], "1")

    def test_rejects_wrong_segment_count(self):
        parsed = ts.parse_jwt("only.two")
        self.assertFalse(parsed.valid_structure)

    def test_rejects_invalid_base64_json(self):
        parsed = ts.parse_jwt("!!!.!!!.!!!")
        self.assertFalse(parsed.valid_structure)


class TestHMACVerificationAndCracking(unittest.TestCase):

    def test_verify_correct_secret(self):
        token = make_hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "correct-secret")
        parsed = ts.parse_jwt(token)
        self.assertTrue(ts.verify_hmac_secret(parsed, "correct-secret"))

    def test_verify_wrong_secret_fails(self):
        token = make_hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "correct-secret")
        parsed = ts.parse_jwt(token)
        self.assertFalse(ts.verify_hmac_secret(parsed, "wrong-secret"))

    def test_crack_finds_known_weak_secret(self):
        token = make_hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        parsed = ts.parse_jwt(token)
        found, attempts = ts.crack_hmac_secret(parsed, ts.DEFAULT_WEAK_SECRETS)
        self.assertEqual(found, "secret")
        self.assertGreater(attempts, 0)

    def test_crack_fails_for_strong_secret(self):
        token = make_hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "Xk9$mQ2!vR7&pL4@nT8#wZ1^")
        parsed = ts.parse_jwt(token)
        found, attempts = ts.crack_hmac_secret(parsed, ts.DEFAULT_WEAK_SECRETS)
        self.assertIsNone(found)
        self.assertEqual(attempts, len(ts.DEFAULT_WEAK_SECRETS))

    def test_crack_skips_non_hmac_algorithms(self):
        parsed = ts.ParsedJWT(raw="", header={"alg": "RS256"}, payload={}, header_b64="a",
                               payload_b64="b", signature=b"x", signature_b64="c")
        found, attempts = ts.crack_hmac_secret(parsed, ts.DEFAULT_WEAK_SECRETS)
        self.assertIsNone(found)
        self.assertEqual(attempts, 0)


class TestForgery(unittest.TestCase):

    def test_none_variants_have_empty_signature(self):
        token = make_hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        parsed = ts.parse_jwt(token)
        variants = ts.forge_none_variants(parsed)
        self.assertEqual(len(variants), 4)
        for alg_value, forged in variants.items():
            self.assertTrue(forged.endswith("."))
            header = json.loads(ts.b64url_decode(forged.split(".")[0]))
            self.assertEqual(header["alg"], alg_value)

    def test_none_variant_preserves_payload(self):
        token = make_hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, "secret")
        parsed = ts.parse_jwt(token)
        variants = ts.forge_none_variants(parsed)
        forged = variants["none"]
        payload = json.loads(ts.b64url_decode(forged.split(".")[1]))
        self.assertEqual(payload["sub"], "admin")

    def test_alg_confusion_forgery_is_acceptable_by_naive_verifier(self):
        """This mirrors the real vulnerability: a verifier that treats the
        RSA public key bytes as an HMAC secret when alg=HS256 will accept
        this forged token."""
        token = make_hs256_token({"alg": "RS256", "typ": "JWT"}, {"sub": "admin"}, "irrelevant")
        parsed = ts.parse_jwt(token)
        fake_public_key_bytes = b"-----BEGIN PUBLIC KEY-----\nFAKEDATA\n-----END PUBLIC KEY-----\n"
        forged = ts.forge_alg_confusion_token(parsed, fake_public_key_bytes)

        h, p, s = forged.split(".")
        expected_sig = hmac.new(fake_public_key_bytes, f"{h}.{p}".encode(), hashlib.sha256).digest()
        actual_sig = ts.b64url_decode(s)
        self.assertTrue(hmac.compare_digest(expected_sig, actual_sig))
        header = json.loads(ts.b64url_decode(h))
        self.assertEqual(header["alg"], "HS256")


class TestClaimAnalysis(unittest.TestCase):

    def test_missing_exp_flagged_high(self):
        findings = ts.analyze_payload({"sub": "1"})
        self.assertTrue(any(f.severity == "HIGH" and "exp" in f.message for f in findings))

    def test_long_lifetime_flagged_medium(self):
        now = int(time.time())
        findings = ts.analyze_payload({"sub": "1", "iat": now, "exp": now + 60 * 60 * 24 * 90})
        self.assertTrue(any(f.severity == "MEDIUM" and "long-lived" in f.message for f in findings))

    def test_reasonable_lifetime_not_flagged(self):
        now = int(time.time())
        findings = ts.analyze_payload({"sub": "1", "iat": now, "exp": now + 900, "iss": "x", "aud": "y"})
        self.assertEqual(len([f for f in findings if f.severity in ("HIGH", "MEDIUM", "CRITICAL")]), 0)

    def test_sensitive_claim_name_flagged(self):
        now = int(time.time())
        findings = ts.analyze_payload({"sub": "1", "exp": now + 900, "password": "hunter2"})
        self.assertTrue(any("password" in f.message for f in findings))

    def test_none_alg_header_flagged_critical(self):
        findings = ts.analyze_header({"alg": "none"})
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    def test_jku_header_flagged(self):
        findings = ts.analyze_header({"alg": "RS256", "jku": "https://evil.test/keys.json"})
        self.assertTrue(any("jku" in f.message for f in findings))

    def test_kid_path_traversal_flagged_high(self):
        findings = ts.analyze_header({"alg": "HS256", "kid": "../../etc/passwd"})
        self.assertTrue(any(f.severity == "HIGH" and "kid" in f.message for f in findings))

    def test_clean_header_no_findings(self):
        findings = ts.analyze_header({"alg": "HS256", "typ": "JWT"})
        self.assertEqual(findings, [])


class TestWordlistLoading(unittest.TestCase):

    def test_default_wordlist_used_when_no_path(self):
        self.assertEqual(ts.load_wordlist(None), ts.DEFAULT_WEAK_SECRETS)

    def test_custom_wordlist_loaded(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("candidate1\ncandidate2\n")
            path = f.name
        try:
            loaded = ts.load_wordlist(path)
            self.assertEqual(loaded, ["candidate1", "candidate2"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
