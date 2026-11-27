import concurrent.futures
import unittest
from unittest.mock import patch

from dns_domain_validator import (
    DNS_PROVIDERS,
    classify_domain,
    make_dns_query,
    normalize_domain,
    parse_dns_response,
    parse_line,
    rewrite_line,
)


class InlineExecutor:
    """Execute submitted query tasks immediately for deterministic unit tests."""

    def submit(self, function, *args, **kwargs):
        future = concurrent.futures.Future()
        try:
            future.set_result(function(*args, **kwargs))
        except Exception as error:
            future.set_exception(error)
        return future


class DomainNormalizationTests(unittest.TestCase):
    def test_normalizes_ascii_and_idna(self):
        self.assertEqual(normalize_domain("Ads.Example.com."), "ads.example.com")
        self.assertEqual(
            normalize_domain("例子.测试"),
            "xn--fsqu00a.xn--0zwm56d",
        )

    def test_rejects_wildcards_ip_literals_and_single_labels(self):
        for value in ("*.example.com", "example.*", "192.0.2.1", "localhost"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_domain(value))


class FormatCoverageTests(unittest.TestCase):
    def test_all_seven_providers_are_configured(self):
        self.assertEqual(
            set(DNS_PROVIDERS),
            {"google", "cloudflare", "cisco", "quad9", "alidns", "tencent", "baidu"},
        )

    def test_adblock_anchored_rule_and_domain_modifier(self):
        line = "||ads.example.com^$script,domain=site.example|~allow.example"
        self.assertEqual(
            parse_line(line, "adblock"),
            (
                "single",
                ["ads.example.com", "allow.example", "site.example"],
            ),
        )

    def test_dns_anchored_and_bare_domain_rules(self):
        self.assertEqual(
            parse_line("@@||dead.example.com^$dnstype=A", "dns"),
            ("single", ["dead.example.com"]),
        )
        self.assertEqual(
            parse_line("dead.example.com", "dns"),
            ("single", ["dead.example.com"]),
        )

    def test_pure_domain_list(self):
        self.assertEqual(
            parse_line("dead.example.com", "domains"),
            ("single", ["dead.example.com"]),
        )

    def test_hosts_ipv4_and_ipv6_records(self):
        self.assertEqual(
            parse_line("0.0.0.0 dead.example.com keep.example.com localhost", "hosts"),
            ("hosts", ["dead.example.com", "keep.example.com"]),
        )
        self.assertEqual(
            parse_line(":: dead.example.com", "hosts"),
            ("hosts", ["dead.example.com"]),
        )

    def test_wildcards_regex_url_patterns_and_comments_are_not_candidates(self):
        examples = [
            ("||*.example.com^", "adblock"),
            ("/^https?:\\/\\/ads\\.example\\.com/", "adblock"),
            ("|https://ads.example.com/path|", "adblock"),
            ("||ads.example.com^", "adblock"),
            ("! comment", "adblock"),
            ("# comment", "domains"),
        ]
        self.assertEqual(parse_line(examples[0][0], examples[0][1]), (None, []))
        self.assertEqual(parse_line(examples[1][0], examples[1][1]), (None, []))
        self.assertEqual(parse_line(examples[2][0], examples[2][1]), (None, []))
        self.assertEqual(parse_line(examples[3][0], examples[3][1]), ("single", ["ads.example.com"]))
        self.assertEqual(parse_line(examples[4][0], examples[4][1]), (None, []))
        self.assertEqual(parse_line(examples[5][0], examples[5][1]), (None, []))


class FilteringTests(unittest.TestCase):
    def test_removes_invalid_adblock_and_dns_rules(self):
        self.assertIsNone(
            rewrite_line("||dead.example.com^$third-party\n", {"dead.example.com"}, "adblock")
        )
        self.assertIsNone(
            rewrite_line("@@||dead.example.com^$dnstype=A\n", {"dead.example.com"}, "dns")
        )

    def test_removes_bare_dns_and_pure_domain_entries(self):
        self.assertIsNone(
            rewrite_line("dead.example.com\n", {"dead.example.com"}, "dns")
        )
        self.assertIsNone(
            rewrite_line("dead.example.com\n", {"dead.example.com"}, "domains")
        )

    def test_hosts_line_only_loses_invalid_hostname(self):
        self.assertEqual(
            rewrite_line(
                "0.0.0.0 dead.example.com keep.example.com localhost # local\n",
                {"dead.example.com"},
                "hosts",
            ),
            "0.0.0.0 keep.example.com localhost # local\n",
        )

    def test_hosts_line_is_removed_when_all_public_names_are_invalid(self):
        self.assertIsNone(
            rewrite_line(
                "2001:db8::1 dead.example.com\n",
                {"dead.example.com"},
                "hosts",
            )
        )

    def test_cosmetic_scope_drops_or_rewrites_without_broadening(self):
        self.assertEqual(
            rewrite_line(
                "keep.example.com,~dead.example.com##.ad\n",
                {"dead.example.com"},
                "adblock",
            ),
            "keep.example.com##.ad\n",
        )
        self.assertIsNone(
            rewrite_line(
                "dead.example.com##.ad\n",
                {"dead.example.com"},
                "adblock",
            )
        )

    def test_domain_modifier_is_sanitized(self):
        self.assertEqual(
            rewrite_line(
                "||tracker.example.net^$script,domain=keep.example.com|~dead.example.com\n",
                {"dead.example.com"},
                "adblock",
            ),
            "||tracker.example.net^$script,domain=keep.example.com\n",
        )

    def test_comments_wildcards_and_unrecognized_rules_are_unchanged(self):
        for line, kind in [
            ("! comment\n", "adblock"),
            ("||*.example.com^\n", "adblock"),
            ("/^https?:\\/\\/dead\\.example\\.com/", "adblock"),
            ("|https://dead.example.com/path|", "adblock"),
        ]:
            self.assertEqual(rewrite_line(line, {"dead.example.com"}, kind), line)


class DnsWireFormatTests(unittest.TestCase):
    def test_query_packet_and_rcode_parser(self):
        query, query_id = make_dns_query("example.com", "A")
        self.assertEqual(int.from_bytes(query[:2], "big"), query_id)
        response = bytearray(query[:12])
        flags = 0x8183  # QR=1, RD=1, RA=1, NXDOMAIN
        response[2:4] = flags.to_bytes(2, "big")
        self.assertEqual(parse_dns_response(bytes(response), query_id), 3)

    def test_mismatched_transaction_id_is_rejected(self):
        query, query_id = make_dns_query("example.com", "AAAA")
        response = bytearray(query[:12])
        response[0:2] = ((query_id + 1) % 65536).to_bytes(2, "big")
        response[2:4] = (0x8180).to_bytes(2, "big")
        self.assertIsNone(parse_dns_response(bytes(response), query_id))


class ConsensusTests(unittest.TestCase):
    @patch("dns_domain_validator.query_public_dns")
    def test_all_seven_must_agree_on_a_and_aaaa_nxdomain(self, query):
        query.return_value = 3
        result = classify_domain("missing.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "nxdomain")
        self.assertEqual(len(result["providers"]), 7)

    @patch("dns_domain_validator.query_public_dns")
    def test_any_noerror_prevents_deletion(self, query):
        def answer(provider, domain, qtype, timeout):
            return 0 if (provider, qtype) == ("baidu", "A") else 3

        query.side_effect = answer
        result = classify_domain("existing.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "valid")

    @patch("dns_domain_validator.query_public_dns")
    def test_any_unavailable_resolver_prevents_deletion(self, query):
        def answer(provider, domain, qtype, timeout):
            return None if (provider, qtype) == ("tencent", "AAAA") else 3

        query.side_effect = answer
        result = classify_domain("uncertain.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
