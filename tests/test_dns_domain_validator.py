import concurrent.futures
import ipaddress
import struct
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


def dns_answer_response(qtype, answers=(), flags=0x8180):
    """Build a minimal DNS packet with optional answer-section RRs for tests."""
    query, query_id = make_dns_query("example.com", qtype)
    packet = bytearray(
        struct.pack("!HHHHHH", query_id, flags, 1, len(answers), 0, 0)
    )
    packet.extend(query[12:])
    for rrtype, rdata in answers:
        packet.extend(b"\xc0\x0c")  # compressed owner name: example.com
        packet.extend(struct.pack("!HHIH", rrtype, 1, 60, len(rdata)))
        packet.extend(rdata)
    return bytes(packet), query_id


def dns_result(rcode, addresses=()):
    return {"rcode": rcode, "addresses": list(addresses)}


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
        self.assertTrue(all(p["transport"] == "doh" for p in DNS_PROVIDERS.values()))

    def test_only_adblock_main_and_lite_outputs_are_accepted(self):
        self.assertEqual(
            set(MANAGED_OUTPUTS),
            {"ADBLOCK_RULE_COLLECTION.txt", "ADBLOCK_RULE_COLLECTION_Lite.txt"},
        )

    def test_adblock_anchored_rule_and_domain_modifier(self):
        line = "||ads.example.com^$script,domain=site.example|~allow.example"
        self.assertEqual(
            parse_line(line, "adblock"),
            ("single", ["ads.example.com", "site.example"]),
        )

    def test_compiler_generated_exact_host_regex_is_dns_validated(self):
        exact = r"/^https?:\\/\\/(?:[^\\/?#@]+@)?ads\\.example\\.com(?::[0-9]+)?(?:[\\/?#]|$)/"
        wrapped = r"/^https?:\\/\\/(?:[^\\/?#@]+@)?(?:ads\\.example\\.com)(?::[0-9]+)?(?:[\\/?#]|$)/"
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
            (r"/^https?:\\/\\/ads\\.example\\.com/", "adblock"),
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
            (r"/^https?:\\/\\/dead\\.example\\.com/", "adblock"),
            ("|https://dead.example.com/path|", "adblock"),
        ]:
            self.assertEqual(rewrite_line(line, {"dead.example.com"}, kind), line)


class DnsWireFormatTests(unittest.TestCase):
    def test_query_packet_and_rcode_parser(self):
        query, query_id = make_dns_query("example.com", "A")
        self.assertEqual(int.from_bytes(query[:2], "big"), query_id)
        response = bytearray(query[:12])
        response[2:4] = (0x8183).to_bytes(2, "big")  # QR=1, NXDOMAIN
        response[4:6] = (0).to_bytes(2, "big")  # no echoed question section
        self.assertEqual(
            parse_dns_response(bytes(response), query_id, "A"),
            {"rcode": 3, "addresses": []},
        )

    def test_parses_ipv4_address_from_a_answer(self):
        packet, query_id = dns_answer_response(
            "A", [(1, ipaddress.ip_address("93.184.216.34").packed)]
        )
        self.assertEqual(
            parse_dns_response(packet, query_id, "A"),
            {"rcode": 0, "addresses": ["93.184.216.34"]},
        )

    def test_parses_ipv6_address_from_aaaa_answer(self):
        address = "2606:4700:4700::1111"
        packet, query_id = dns_answer_response(
            "AAAA", [(28, ipaddress.ip_address(address).packed)]
        )
        self.assertEqual(
            parse_dns_response(packet, query_id, "AAAA"),
            {"rcode": 0, "addresses": [address]},
        )

    def test_noerror_with_empty_answer_is_not_an_ip_resolution(self):
        packet, query_id = dns_answer_response("A")
        self.assertEqual(
            parse_dns_response(packet, query_id, "A"),
            {"rcode": 0, "addresses": []},
        )

    def test_cname_only_answer_is_not_an_ip_resolution(self):
        cname_target = b"\x05alias\x07example\x03com\x00"
        packet, query_id = dns_answer_response("A", [(5, cname_target)])
        self.assertEqual(
            parse_dns_response(packet, query_id, "A"),
            {"rcode": 0, "addresses": []},
        )

    def test_wrong_record_type_does_not_count(self):
        packet, query_id = dns_answer_response(
            "A", [(28, ipaddress.ip_address("2606:4700:4700::1111").packed)]
        )
        self.assertEqual(
            parse_dns_response(packet, query_id, "A"),
            {"rcode": 0, "addresses": []},
        )

    def test_sinkhole_and_non_host_addresses_do_not_count(self):
        for value in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"):
            packet, query_id = dns_answer_response(
                "A", [(1, ipaddress.ip_address(value).packed)]
            )
            with self.subTest(address=value):
                self.assertEqual(
                    parse_dns_response(packet, query_id, "A"),
                    {"rcode": 0, "addresses": []},
                )

    def test_truncated_response_is_treated_as_query_failure(self):
        response = bytearray(12)
        response[0:2] = (1234).to_bytes(2, "big")
        response[2:4] = (0x8380).to_bytes(2, "big")  # QR=1, TC=1
        self.assertIsNone(parse_dns_response(bytes(response), 1234, "A"))

    def test_mismatched_transaction_id_is_rejected(self):
        packet, query_id = dns_answer_response(
            "AAAA", [(28, ipaddress.ip_address("2606:4700:4700::1111").packed)]
        )
        self.assertIsNone(parse_dns_response(packet, (query_id + 1) % 65536, "AAAA"))


class ConsensusTests(unittest.TestCase):
    @patch("dns_domain_validator.query_public_dns")
    def test_all_five_nxdomain_for_both_types_marks_domain_invalid(self, query):
        query.return_value = dns_result(3)
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
    def test_any_provider_returning_ipv4_address_keeps_domain(self, query):
        def answer(provider, domain, qtype, timeout):
            return dns_result(0, ["8.8.8.8"]) if (provider, qtype) == ("cloudflare", "A") else dns_result(3)

        query.side_effect = answer
        result = classify_domain("existing.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["ip_returning_queries"], ["cloudflare/A"])

    @patch("dns_domain_validator.query_public_dns")
    def test_any_provider_returning_ipv6_address_keeps_domain(self, query):
        def answer(provider, domain, qtype, timeout):
            return dns_result(0, ["2606:4700:4700::1111"]) if (provider, qtype) == ("adguard_unfiltered", "AAAA") else dns_result(3)

        query.side_effect = answer
        result = classify_domain("existing.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["ip_returning_queries"], ["adguard_unfiltered/AAAA"])

    @patch("dns_domain_validator.query_public_dns")
    def test_noerror_nodata_from_all_resolvers_does_not_keep_domain(self, query):
        query.return_value = dns_result(0)
        result = classify_domain("nodata.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["ip_returning_queries"], [])

    @patch("dns_domain_validator.query_public_dns")
    def test_cname_or_other_noerror_without_ip_does_not_keep_domain(self, query):
        def answer(provider, domain, qtype, timeout):
            if provider == "tencent":
                return dns_result(0)
            return dns_result(3)

        query.side_effect = answer
        result = classify_domain("cname-only.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "invalid")

    @patch("dns_domain_validator.query_public_dns")
    def test_one_ip_answer_is_enough_even_with_other_failures(self, query):
        def answer(provider, domain, qtype, timeout):
            if (provider, qtype) == ("adguard_unfiltered", "AAAA"):
                return dns_result(0, ["2606:4700:4700::1111"])
            if provider == "tencent":
                return None
            return dns_result(3)

        query.side_effect = answer
        result = classify_domain("uncertain.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "valid")


if __name__ == "__main__":
    unittest.main()
