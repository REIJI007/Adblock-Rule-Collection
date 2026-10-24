import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / ".github" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from adguard_dns_converter import (  # noqa: E402
    extract_badfilter,
    classify_and_convert,
    parse_adguard_dns_rule,
    parse_hosts_as_adguard,
    run_semantic_self_tests,
    validate_dnsrewrite_value,
)


class AdGuardDnsConversionTests(unittest.TestCase):
    def test_converter_semantic_self_tests(self):
        run_semantic_self_tests()

    def assert_rule(self, source, expected):
        actual, error = parse_adguard_dns_rule(source)
        self.assertIsNone(error, msg=f"{source!r} rejected: {error}")
        self.assertEqual(actual, expected)

    def assert_rejected(self, source):
        actual, error = parse_adguard_dns_rule(source)
        self.assertIsNone(actual)
        self.assertTrue(error, msg=f"{source!r} unexpectedly accepted")

    def test_basic_and_hostname_mask_rules(self):
        cases = [
            ("||Example.COM^", "||example.com^"),
            ("@@||Example.COM^", "@@||example.com^"),
            ("|Example.COM^", "|example.com^"),
            ("@@|Example.COM^", "@@|example.com^"),
            ("||*.Example.org^", "||*.example.org^"),
            ("||foo-*.example.org^", "||foo-*.example.org^"),
            ("example.org", "example.org"),
            # A bare IP has a documented DNS-filter meaning; an anchored IP does not.
            ("192.0.2.1", "192.0.2.1"),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assert_rule(source, expected)

    def test_dnsrewrite_shorthand_and_explicit_records(self):
        cases = [
            (
                "||EXAMPLE.org^$dnsrewrite=NOERROR;A;192.0.2.1",
                "||example.org^$dnsrewrite=NOERROR;A;192.0.2.1",
            ),
            (
                "||example.org^$dnsrewrite=example.net",
                "||example.org^$dnsrewrite=example.net",
            ),
            (
                "||_sip._tcp.example.org^$dnsrewrite=NOERROR;SRV;10 60 8080 example.org",
                "||_sip._tcp.example.org^$dnsrewrite=NOERROR;SRV;10 60 8080 example.org",
            ),
            (
                "||example.org^$dnsrewrite=NXDOMAIN;;",
                "||example.org^$dnsrewrite=NXDOMAIN;;",
            ),
            (
                "@@||example.org^$dnsrewrite",
                "@@||example.org^$dnsrewrite",
            ),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assert_rule(source, expected)

    def test_respgeo_dnstype_and_modifier_order_are_normalized(self):
        self.assert_rule(
            "||*.example.org^$respgeo=US|FR",
            "||*.example.org^$respgeo=FR|US",
        )
        self.assert_rule(
            "||example.org^$dnstype=~A|AAAA",
            "||example.org^$dnstype=AAAA",
        )
        self.assert_rule(
            "||example.org^$denyallow=example.net|example.net",
            "||example.org^$denyallow=example.net",
        )
        self.assert_rule(
            "||example.org^$important,dnstype=AAAA|A",
            "||example.org^$dnstype=A|AAAA,important",
        )

    def test_regex_end_anchor_and_modifiers(self):
        self.assert_rule("/example$/", "/example$/")
        self.assert_rule("/example$/$important", "/example$/$important")
        enabled, target = extract_badfilter("/example$/$important,badfilter")
        self.assertTrue(enabled)
        self.assertEqual(target, "/example$/$important")

    def test_unsupported_rules_are_skipped_not_weakened(self):
        for source in (
            "||example.org^$script",
            "||example.org^$ctag=device_pc",
            '||example.org^$dnsrewrite=NOERROR;CAA;0 issue "ca.example"',
            r"/example(?=\.org)/",
            "||192.0.2.1^",
            "||-invalid.example.org^",
            "||invalid-.example.org^",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_dnsrewrite_values_are_validated(self):
        self.assertEqual(
            validate_dnsrewrite_value("192.0.2.1"),
            ("192.0.2.1", None),
        )
        self.assertEqual(
            validate_dnsrewrite_value("NOERROR;A;192.0.2.1"),
            ("NOERROR;A;192.0.2.1", None),
        )
        normalized, error = validate_dnsrewrite_value("NOERROR;A;999.1.1.1")
        self.assertIsNone(normalized)
        self.assertTrue(error)

    def test_hosts_mappings_preserve_exact_hostname_scope(self):
        recognized, rules, error = parse_hosts_as_adguard("0.0.0.0 ads.example.org")
        self.assertTrue(recognized)
        self.assertEqual(rules, ["|ads.example.org^"])
        self.assertIsNone(error)

        recognized, rules, error = parse_hosts_as_adguard("192.0.2.1 example.org")
        self.assertTrue(recognized)
        self.assertIsNone(rules)
        self.assertIn("non-blocking Hosts IP mapping", error)

        recognized, rules, error = parse_hosts_as_adguard("192.0.2.1")
        self.assertFalse(recognized)
        self.assertIsNone(rules)
        self.assertIsNone(error)

        converted, kind, reason = classify_and_convert("192.0.2.1")
        self.assertEqual(converted, ["192.0.2.1"])
        self.assertEqual(kind, "adblock-style")
        self.assertIsNone(reason)

    def test_badfilter_keeps_exception_prefix_and_other_modifiers(self):
        enabled, target = extract_badfilter(
            "@@||example.org^$denyallow=sub.example.org,badfilter"
        )
        self.assertTrue(enabled)
        self.assertEqual(target, "@@||example.org^$denyallow=sub.example.org")


if __name__ == "__main__":
    unittest.main()
