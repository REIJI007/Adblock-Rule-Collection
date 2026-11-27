import concurrent.futures
import unittest
from unittest.mock import patch

from dns_domain_validator import (
    DNS_PROVIDERS,
    MANAGED_OUTPUTS,
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
    def test_exactly_five_unfiltered_providers_are_configured(self):
        self.assertEqual(
            set(DNS_PROVIDERS),
            {"google", "cloudflare", "tencent", "alidns", "adguard_unfiltered"},
        )
        self.assertIn(
            "https://unfiltered.adguard-dns.com/dns-query",
            DNS_PROVIDERS["adguard_unfiltered"]["endpoint"],
        )

    def test_only_adblock_main_and_lite_outputs_are_accepted(self):
        self.assertEqual(
            set(MANAGED_OUTPUTS),
            {"ADBLOCK_RULE_COLLECTION.txt", "ADBLOCK_RULE_COLLECTION_Lite.txt"},
        )

    def test_adblock_anchored_rule_and_domain_modifier(self):
        line = "||ads.example.com^$script,domain=site.example|~allow.example"
        self.assertEqual(
            parse_line(line, "adblock"),
            (
                "single",
                ["ads.example.com", "site.example"],
            ),
        )

    def test_compiler_generated_exact_host_regex_is_dns_validated(self):
        exact = r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"
        wrapped = r"/^https?:\/\/(?:[^\/?#@]+@)?(?:ads\.example\.com)(?::[0-9]+)?(?:[\/?#]|$)/"
        self.assertEqual(parse_line(exact, "adblock"), ("single", ["ads.example.com"]))
        self.assertEqual(parse_line(wrapped, "adblock"), ("single", ["ads.example.com"]))
        self.assertIsNone(
            rewrite_line(exact + "\n", {"ads.example.com"}, "adblock")
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
            "keep.example.com,~dead.example.com##.ad\n",
        )
        self.assertIsNone(
            rewrite_line(
                "dead.example.com##.ad\n",
                {"dead.example.com"},
                "adblock",
            )
        )

    def test_domain_modifier_removes_only_invalid_positive_scope(self):
        self.assertEqual(
            rewrite_line(
                "||tracker.example.net^$script,domain=dead.example.com|keep.example.com\n",
                {"dead.example.com"},
                "adblock",
            ),
            "||tracker.example.net^$script,domain=keep.example.com\n",
        )

    def test_domain_modifier_preserves_invalid_negative_scope(self):
        line = "||tracker.example.net^$script,domain=keep.example.com|~dead.example.com\n"
        self.assertEqual(
            rewrite_line(line, {"dead.example.com"}, "adblock"),
            line,
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

    def test_truncated_response_is_treated_as_query_failure(self):
        query, query_id = make_dns_query("example.com", "A")
        response = bytearray(query[:12])
        response[2:4] = (0x8380).to_bytes(2, "big")  # QR=1, TC=1, NOERROR
        self.assertIsNone(parse_dns_response(bytes(response), query_id))

    def test_mismatched_transaction_id_is_rejected(self):
        query, query_id = make_dns_query("example.com", "AAAA")
        response = bytearray(query[:12])
        response[0:2] = ((query_id + 1) % 65536).to_bytes(2, "big")
        response[2:4] = (0x8180).to_bytes(2, "big")
        self.assertIsNone(parse_dns_response(bytes(response), query_id))


class ConsensusTests(unittest.TestCase):
    @patch("dns_domain_validator.query_public_dns")
    def test_all_five_nxdomain_for_both_types_marks_domain_invalid(self, query):
        query.return_value = 3
        result = classify_domain("missing.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(len(result["providers"]), 5)
        self.assertEqual(query.call_count, 10)

    @patch("dns_domain_validator.query_public_dns")
    def test_all_five_query_failures_also_mark_domain_invalid(self, query):
        query.return_value = None
        result = classify_domain("offline.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(query.call_count, 10)

    @patch("dns_domain_validator.query_public_dns")
    def test_any_noerror_prevents_deletion(self, query):
        def answer(provider, domain, qtype, timeout):
            return 0 if (provider, qtype) == ("cloudflare", "A") else 3

        query.side_effect = answer
        result = classify_domain("existing.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "valid")

    @patch("dns_domain_validator.query_public_dns")
    def test_one_successful_noerror_response_is_enough_even_with_other_failures(self, query):
        def answer(provider, domain, qtype, timeout):
            if (provider, qtype) == ("adguard_unfiltered", "AAAA"):
                return 0
            if provider == "tencent":
                return None
            return 3

        query.side_effect = answer
        result = classify_domain("uncertain.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "valid")

    @patch("dns_domain_validator.query_public_dns")
    def test_noerror_nodata_is_a_successful_dns_response(self, query):
        query.return_value = 0
        result = classify_domain("nodata.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "valid")


if __name__ == "__main__":
    unittest.main()
