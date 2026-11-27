import concurrent.futures
import ipaddress
import struct
import unittest
from unittest.mock import MagicMock, patch

from dns_domain_validator import (
    CACHE_VERSION,
    DNS_PROVIDERS,
    MANAGED_OUTPUTS,
    apply_negative_confirmation,
    classify_domain,
    make_dns_query,
    normalize_domain,
    parse_dns_response,
    parse_line,
    rewrite_line,
    verify_resolver_pool,
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


def encode_dns_name(value):
    return b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in value.rstrip(".").split(".")
    ) + b"\x00"


def dns_answer_response(qtype, answers=(), flags=0x8180, domain="example.com"):
    """Build a minimal DNS packet with optional Answer RRs."""
    query, query_id = make_dns_query(domain, qtype)
    packet = bytearray(
        struct.pack("!HHHHHH", query_id, flags, 1, len(answers), 0, 0)
    )
    packet.extend(query[12:])
    for answer in answers:
        if len(answer) == 2:
            rrtype, rdata = answer
            owner = domain
        else:
            rrtype, rdata, owner = answer
        owner_wire = b"\xc0\x0c" if owner == domain else encode_dns_name(owner)
        packet.extend(owner_wire)
        packet.extend(struct.pack("!HHIH", rrtype, 1, 60, len(rdata)))
        packet.extend(rdata)
    return bytes(packet), query_id


def dns_result(rcode, addresses=(), ttl=300):
    return {
        "rcode": rcode,
        "addresses": list(addresses),
        "ttl": ttl if addresses else None,
        "cname_chain": [],
    }


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
        self.assertEqual(
            DNS_PROVIDERS["adguard_unfiltered"]["tls_server_name"],
            "unfiltered.adguard-dns.com",
        )
        self.assertEqual(DNS_PROVIDERS["adguard_unfiltered"]["path"], "/dns-query")
        self.assertTrue(all(p["transport"] == "doh" for p in DNS_PROVIDERS.values()))
        for name, provider in DNS_PROVIDERS.items():
            self.assertTrue(
                provider["bootstrap_ipv4"]
                or provider["bootstrap_ipv6"]
                or provider.get("bootstrap_hostname"),
                msg=f"{name} must have a numeric or DoH-bootstrapped endpoint",
            )
        tencent = DNS_PROVIDERS["tencent"]
        self.assertEqual(tencent["bootstrap_hostname"], "doh.pub")
        self.assertEqual(
            set(tencent["bootstrap_resolvers"]),
            {"google", "cloudflare", "alidns", "adguard_unfiltered"},
        )
        self.assertNotIn("tencent", tencent["bootstrap_resolvers"])


    def test_tencent_bootstrap_resolves_only_via_other_doh_providers(self):
        import dns_domain_validator as validator

        calls = []

        def fake_query(provider, domain, qtype, timeout):
            calls.append((provider, domain, qtype))
            return dns_result(
                0,
                ["203.0.113.53"] if qtype == "A" else ["2001:db8::53"],
                ttl=120,
            )

        validator._BOOTSTRAP_HOST_CACHE.pop("doh.pub", None)
        with patch("dns_domain_validator.query_public_dns", side_effect=fake_query):
            first = validator._resolve_bootstrap_host(
                "doh.pub",
                ["google", "cloudflare"],
                2,
            )
            second = validator._resolve_bootstrap_host(
                "doh.pub",
                ["google", "cloudflare"],
                2,
            )

        self.assertEqual(first, ["203.0.113.53", "2001:db8::53"])
        self.assertEqual(second, first)
        self.assertTrue(calls)
        self.assertNotIn("tencent", {provider for provider, _, _ in calls})
        self.assertTrue(all(domain == "doh.pub" for _, domain, _ in calls))
        self.assertEqual(len(calls), 4)

    def test_tencent_bootstrap_returns_dynamic_numeric_addresses(self):
        import dns_domain_validator as validator

        validator._BOOTSTRAP_HOST_CACHE["doh.pub"] = {
            "addresses": ["203.0.113.53", "2001:db8::53"],
            "expires_at": 9999999999,
        }
        config = validator.DNS_PROVIDERS["tencent"]
        original_v4 = config["bootstrap_ipv4"]
        original_v6 = config["bootstrap_ipv6"]
        try:
            self.assertEqual(
                validator._ordered_bootstrap_ips("tencent", 2),
                ["203.0.113.53", "2001:db8::53"],
            )
        finally:
            config["bootstrap_ipv4"] = original_v4
            config["bootstrap_ipv6"] = original_v6
            validator._BOOTSTRAP_HOST_CACHE.pop("doh.pub", None)

    def test_doh_url_uses_numeric_ip_and_brackets_ipv6(self):
        from dns_domain_validator import _doh_url

        self.assertEqual(
            _doh_url("8.8.8.8", "/dns-query", "abc"),
            "https://8.8.8.8/dns-query?dns=abc",
        )
        self.assertEqual(
            _doh_url("2001:4860:4860::8888", "/dns-query", "abc"),
            "https://[2001:4860:4860::8888]/dns-query?dns=abc",
        )

    def test_pinned_transport_keeps_tls_hostname_and_verification(self):
        import ssl
        from dns_domain_validator import _PinnedHTTPSConnection

        context = ssl.create_default_context()
        connection = _PinnedHTTPSConnection(
            "8.8.8.8",
            bootstrap_ip="8.8.8.8",
            tls_server_name="dns.google",
            context=context,
        )
        self.assertEqual(connection.tls_server_name, "dns.google")
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)

    def test_doh_request_sends_one_hostname_host_header_to_ip_connection(self):
        import base64
        import dns_domain_validator as validator

        validator._RATE_LIMITERS["google"] = validator.RateLimiter(1000)
        fake_connection = MagicMock()
        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.getheader.side_effect = lambda name, default=None: (
            "application/dns-message" if name == "Content-Type" else default
        )
        fake_response.read.return_value = b"dns-response"
        fake_connection.getresponse.return_value = fake_response

        with patch(
            "dns_domain_validator.make_dns_query",
            return_value=(b"dns-query-packet", 1234),
        ):
            with patch(
                "dns_domain_validator._PinnedHTTPSConnection",
                return_value=fake_connection,
            ) as connection_factory:
                with patch(
                    "dns_domain_validator.parse_dns_response",
                    return_value={"rcode": 0, "addresses": ["93.184.216.34"]},
                ):
                    result = validator._query_doh(
                        "google",
                        "example.com",
                        "A",
                        2,
                    )

        self.assertEqual(result["addresses"], ["93.184.216.34"])
        self.assertEqual(connection_factory.call_args.args[0], "8.8.8.8")
        self.assertEqual(
            fake_connection.putrequest.call_args.args,
            (
                "GET",
                "/dns-query?dns=" + base64.urlsafe_b64encode(b"dns-query-packet").rstrip(b"=").decode("ascii"),
            ),
        )
        self.assertEqual(
            fake_connection.putrequest.call_args.kwargs,
            {"skip_host": True, "skip_accept_encoding": True},
        )
        host_headers = [
            call.args[1]
            for call in fake_connection.putheader.call_args_list
            if call.args[0].lower() == "host"
        ]
        self.assertEqual(host_headers, ["dns.google"])
        fake_connection.close.assert_called_once()

    def test_pinned_connection_uses_numeric_socket_target_and_hostname_sni(self):
        from dns_domain_validator import _PinnedHTTPSConnection

        connection = _PinnedHTTPSConnection(
            "8.8.8.8",
            bootstrap_ip="8.8.8.8",
            tls_server_name="dns.google",
            timeout=3,
        )
        raw_socket = MagicMock()
        tls_socket = MagicMock()
        with patch(
            "dns_domain_validator.socket.create_connection",
            return_value=raw_socket,
        ) as create_connection:
            with patch.object(
                connection._context,
                "wrap_socket",
                return_value=tls_socket,
            ) as wrap_socket:
                connection.connect()

        create_connection.assert_called_once_with(
            ("8.8.8.8", 443),
            3,
            None,
        )
        wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="dns.google",
        )
        self.assertIs(connection.sock, tls_socket)

    def test_cache_schema_was_bumped_after_policy_change(self):
        self.assertEqual(CACHE_VERSION, 6)

    def test_only_adblock_main_and_lite_outputs_are_accepted(self):
        self.assertEqual(
            set(MANAGED_OUTPUTS),
            {"ADBLOCK_RULE_COLLECTION.txt", "ADBLOCK_RULE_COLLECTION_Lite.txt"},
        )

    def test_adblock_target_only_is_dns_validated(self):
        line = "||ads.example.com^$script,domain=site.example|~allow.example"
        self.assertEqual(
            parse_line(line, "adblock"),
            ("single", ["ads.example.com"]),
        )

    def test_cosmetic_scope_is_context_not_a_blocked_target(self):
        self.assertEqual(parse_line("site.example##.ad", "adblock"), (None, []))
        self.assertEqual(parse_line("site.example,shop.example#@#.ad", "adblock"), (None, []))

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
            (r"/^https?:\/\/ads\.example\.com/", "adblock"),
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
    def test_removes_invalid_adblock_and_dns_targets(self):
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

    def test_cosmetic_scope_is_never_rewritten_by_dns_target_status(self):
        line = "dead.example.com##.ad\n"
        self.assertEqual(
            rewrite_line(line, {"dead.example.com"}, "adblock"),
            line,
        )

    def test_domain_modifier_scope_is_not_removed_when_scope_host_has_no_ip(self):
        line = "||tracker.example.net^$script,domain=dead.example.com|keep.example.com\n"
        self.assertEqual(
            parse_line(line, "adblock"),
            ("single", ["tracker.example.net"]),
        )
        self.assertEqual(
            rewrite_line(line, {"dead.example.com"}, "adblock"),
            line,
        )

    def test_invalid_primary_target_removes_rule_without_mutating_scope(self):
        line = "||dead.example.com^$script,domain=keep.example.com|~allow.example\n"
        self.assertIsNone(
            rewrite_line(line, {"dead.example.com"}, "adblock")
        )

    def test_comments_wildcards_and_unrecognized_rules_are_unchanged(self):
        for line, kind in [
            ("! comment\n", "adblock"),
            ("||*.example.com^\n", "adblock"),
            (r"/^https?:\/\/dead\.example\.com/", "adblock"),
            ("|https://dead.example.com/path|", "adblock"),
        ]:
            self.assertEqual(rewrite_line(line, {"dead.example.com"}, kind), line)


class DnsWireFormatTests(unittest.TestCase):
    def test_query_packet_and_nxdomain_parser(self):
        query, query_id = make_dns_query("example.com", "A")
        self.assertEqual(int.from_bytes(query[:2], "big"), query_id)
        response = bytearray(query)
        response[2:4] = (0x8183).to_bytes(2, "big")  # QR=1, NXDOMAIN
        response[6:8] = (0).to_bytes(2, "big")  # no Answer records
        self.assertEqual(
            parse_dns_response(bytes(response), query_id, "A", "example.com"),
            {"rcode": 3, "addresses": [], "ttl": None, "cname_chain": []},
        )

    def test_parses_ipv4_address_from_a_answer(self):
        packet, query_id = dns_answer_response(
            "A", [(1, ipaddress.ip_address("93.184.216.34").packed)]
        )
        self.assertEqual(
            parse_dns_response(packet, query_id, "A", "example.com"),
            {
                "rcode": 0,
                "addresses": ["93.184.216.34"],
                "ttl": 60,
                "cname_chain": ["example.com"],
            },
        )

    def test_parses_ipv6_address_from_aaaa_answer(self):
        address = "2606:4700:4700::1111"
        packet, query_id = dns_answer_response(
            "AAAA", [(28, ipaddress.ip_address(address).packed)]
        )
        result = parse_dns_response(packet, query_id, "AAAA", "example.com")
        self.assertEqual(result["addresses"], [address])
        self.assertEqual(result["rcode"], 0)

    def test_noerror_with_empty_answer_is_not_an_ip_resolution(self):
        packet, query_id = dns_answer_response("A")
        self.assertEqual(
            parse_dns_response(packet, query_id, "A", "example.com")["addresses"],
            [],
        )

    def test_cname_only_answer_is_not_an_ip_resolution(self):
        cname_target = encode_dns_name("alias.example.com")
        packet, query_id = dns_answer_response("A", [(5, cname_target)])
        result = parse_dns_response(packet, query_id, "A", "example.com")
        self.assertEqual(result["addresses"], [])
        self.assertEqual(result["cname_chain"], ["example.com", "alias.example.com"])

    def test_cname_chain_with_final_ipv4_is_valid(self):
        target = "edge.example.net"
        answers = [
            (5, encode_dns_name(target)),
            (1, ipaddress.ip_address("93.184.216.34").packed, target),
        ]
        packet, query_id = dns_answer_response("A", answers)
        result = parse_dns_response(packet, query_id, "A", "example.com")
        self.assertEqual(result["addresses"], ["93.184.216.34"])
        self.assertEqual(result["cname_chain"], ["example.com", target])
        self.assertEqual(result["ttl"], 60)

    def test_unrelated_answer_address_is_not_counted(self):
        packet, query_id = dns_answer_response(
            "A",
            [(1, ipaddress.ip_address("93.184.216.34").packed, "unrelated.example.net")],
        )
        self.assertEqual(
            parse_dns_response(packet, query_id, "A", "example.com")["addresses"],
            [],
        )

    def test_wrong_record_type_does_not_count(self):
        packet, query_id = dns_answer_response(
            "A", [(28, ipaddress.ip_address("2606:4700:4700::1111").packed)]
        )
        self.assertEqual(
            parse_dns_response(packet, query_id, "A", "example.com")["addresses"],
            [],
        )

    def test_sinkhole_and_non_host_addresses_do_not_count(self):
        for value in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"):
            packet, query_id = dns_answer_response(
                "A", [(1, ipaddress.ip_address(value).packed)]
            )
            with self.subTest(address=value):
                self.assertEqual(
                    parse_dns_response(packet, query_id, "A", "example.com")["addresses"],
                    [],
                )

    def test_private_unicast_address_is_accepted(self):
        packet, query_id = dns_answer_response(
            "A", [(1, ipaddress.ip_address("192.168.1.10").packed)]
        )
        self.assertEqual(
            parse_dns_response(packet, query_id, "A", "example.com")["addresses"],
            ["192.168.1.10"],
        )

    def test_truncated_response_is_treated_as_query_failure(self):
        packet, query_id = dns_answer_response("A")
        response = bytearray(packet)
        response[2:4] = (0x8380).to_bytes(2, "big")  # QR=1, TC=1
        self.assertIsNone(
            parse_dns_response(bytes(response), query_id, "A", "example.com")
        )

    def test_mismatched_transaction_id_is_rejected(self):
        packet, query_id = dns_answer_response(
            "AAAA", [(28, ipaddress.ip_address("2606:4700:4700::1111").packed)]
        )
        self.assertIsNone(
            parse_dns_response(packet, (query_id + 1) % 65536, "AAAA", "example.com")
        )


class ConsensusTests(unittest.TestCase):
    @patch("dns_domain_validator.query_public_dns")
    def test_all_nxdomain_is_pending_until_repeated_confirmation(self, query):
        query.return_value = dns_result(3)
        first = classify_domain("missing.example", 2, InlineExecutor())
        self.assertEqual(first["status"], "no_address")
        self.assertEqual(len(first["providers"]), 5)
        self.assertEqual(query.call_count, 10)

        first = apply_negative_confirmation(first, None, now=1000)
        self.assertEqual(first["status"], "pending_confirmation")
        second = classify_domain("missing.example", 2, InlineExecutor())
        second = apply_negative_confirmation(second, first, now=1900)
        self.assertEqual(second["status"], "pending_confirmation")
        third = classify_domain("missing.example", 2, InlineExecutor())
        third = apply_negative_confirmation(third, second, now=2800)
        self.assertEqual(third["status"], "invalid")

    @patch("dns_domain_validator.query_public_dns")
    def test_all_query_failures_are_temporary_not_negative(self, query):
        query.return_value = None
        result = classify_domain("offline.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "temporary_failure")
        confirmed = apply_negative_confirmation(
            result,
            {"negative_observations": [1000, 1900]},
            now=2800,
        )
        self.assertEqual(confirmed["status"], "temporary_failure")
        self.assertEqual(len(confirmed["negative_observations"]), 2)
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
    def test_noerror_nodata_from_all_resolvers_is_no_address(self, query):
        query.return_value = dns_result(0)
        result = classify_domain("nodata.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "no_address")
        self.assertEqual(result["ip_returning_queries"], [])

    @patch("dns_domain_validator.query_public_dns")
    def test_any_transport_failure_prevents_negative_confirmation(self, query):
        def answer(provider, domain, qtype, timeout):
            if provider == "google" and qtype == "A":
                return None
            return dns_result(3)

        query.side_effect = answer
        result = classify_domain("incomplete.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "temporary_failure")

    @patch("dns_domain_validator.query_public_dns")
    def test_cname_or_other_noerror_without_ip_does_not_keep_domain(self, query):
        query.return_value = dns_result(0)
        result = classify_domain("cname-only.example", 2, InlineExecutor())
        self.assertEqual(result["status"], "no_address")

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

    @patch("dns_domain_validator.query_public_dns")
    def test_too_few_healthy_resolvers_prevents_negative_confirmation(self, query):
        def answer(provider, domain, qtype, timeout):
            if domain == "example.com" and provider in {"google", "cloudflare"}:
                return dns_result(0, ["93.184.216.34"])
            if domain == "missing.example" and provider in {"google", "cloudflare"}:
                return dns_result(3)
            return None

        query.side_effect = answer
        result = classify_domain(
            "missing.example",
            2,
            InlineExecutor(),
            healthy_providers={"google", "cloudflare"},
            min_healthy_resolvers=3,
        )
        self.assertEqual(result["status"], "temporary_failure")


class CanaryTests(unittest.TestCase):
    @patch("dns_domain_validator.query_public_dns")
    def test_canary_rejects_noerror_without_usable_ip(self, query):
        query.return_value = dns_result(0)
        with self.assertRaises(RuntimeError):
            verify_resolver_pool(2, InlineExecutor())

    @patch("dns_domain_validator.query_public_dns")
    def test_canary_requires_three_healthy_resolvers_by_default(self, query):
        query.side_effect = lambda provider, domain, qtype, timeout: (
            dns_result(0, ["93.184.216.34"])
            if provider in {"google", "cloudflare"}
            else dns_result(3)
        )
        with self.assertRaises(RuntimeError):
            verify_resolver_pool(2, InlineExecutor())

    @patch("dns_domain_validator.query_public_dns")
    def test_canary_returns_individually_healthy_resolvers(self, query):
        query.side_effect = lambda provider, domain, qtype, timeout: (
            dns_result(0, ["93.184.216.34"])
            if provider in {"google", "cloudflare", "tencent"}
            else dns_result(3)
        )
        self.assertEqual(
            verify_resolver_pool(2, InlineExecutor()),
            {"google", "cloudflare", "tencent"},
        )


if __name__ == "__main__":
    unittest.main()
