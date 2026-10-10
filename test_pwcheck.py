"""Run with: python3 -m unittest test_pwcheck.py"""

import unittest
from unittest import mock

import pwcheck


class EntropyTests(unittest.TestCase):
    def test_charset_size(self):
        self.assertEqual(pwcheck.charset_size("abc"), 26)
        self.assertEqual(pwcheck.charset_size("aB1!"), 26 + 26 + 10 + 32)

    def test_common_password_is_very_weak(self):
        r = pwcheck.analyze("password", use_hibp=False)
        self.assertEqual(r["rating"], "very weak")

    def test_leetspeak_common_password_detected(self):
        r = pwcheck.analyze("p@ssw0rd", use_hibp=False)
        self.assertIn("is a very common password", r["weaknesses"])

    def test_patterns_detected(self):
        w = [d for d, _ in pwcheck.find_weaknesses("Summer2024!")]
        self.assertTrue(any("year" in x for x in w))
        self.assertTrue(any("Word123" in x for x in w))
        self.assertTrue(pwcheck._has_sequence("xxqwerxx"))
        self.assertTrue(pwcheck._has_sequence("9876"))

    def test_random_password_is_strong(self):
        r = pwcheck.analyze("v7#Qm!2pLx@9Rz$Kd", use_hibp=False)
        self.assertIn(r["rating"], ("strong", "very strong"))


class HibpTests(unittest.TestCase):
    # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    PREFIX = "5BAA6"
    SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def test_sha1_split(self):
        digest = pwcheck.sha1_hex("password")
        self.assertEqual(digest[:5], self.PREFIX)
        self.assertEqual(digest[5:], self.SUFFIX)

    def test_parse_range_response(self):
        body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{self.SUFFIX}:9659365\r\nAAAA:0"
        self.assertEqual(pwcheck.parse_range_response(body, self.SUFFIX), 9659365)
        self.assertEqual(pwcheck.parse_range_response(body, "NOPE"), 0)

    def test_only_prefix_is_sent(self):
        captured = {}

        class FakeResp:
            def read(self):
                return f"{HibpTests.SUFFIX}:42".encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        def fake_urlopen(req, timeout):
            captured["url"] = req.full_url
            return FakeResp()

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(pwcheck.hibp_breach_count("password"), 42)
        self.assertTrue(captured["url"].endswith("/range/" + self.PREFIX))
        self.assertNotIn(self.SUFFIX, captured["url"])
        self.assertEqual(captured["url"].rsplit("/", 1)[1], self.PREFIX)

    def test_unreachable_returns_none(self):
        import urllib.error
        with mock.patch("urllib.request.urlopen",
                        side_effect=urllib.error.URLError("blocked")):
            self.assertIsNone(pwcheck.hibp_breach_count("password"))
            r = pwcheck.analyze("password")
            self.assertFalse(r["hibp_reachable"])


if __name__ == "__main__":
    unittest.main()
