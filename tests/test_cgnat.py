"""Tests for transitvpn.cgnat — mocked HTTP/UPnP, all CgnatResult branches."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from transitvpn.cgnat import (
    CgnatResult,
    CgnatStatus,
    _find_wan_service,
    _get_local_ip,
    _get_public_ip,
    _get_router_external_ip,
    _ip_str_to_int,
    _is_cgnat,
    _is_private,
    _probe_upnp,
    _soap_external_ip,
    _ssdp_location,
    detect_cgnat,
)


class TestIpStrToInt:
    def test_all_zeros(self):
        assert _ip_str_to_int("0.0.0.0") == 0

    def test_all_ones(self):
        assert _ip_str_to_int("255.255.255.255") == 0xFFFFFFFF

    def test_loopback(self):
        assert _ip_str_to_int("127.0.0.1") == (127 << 24) | 1

    def test_known_value(self):
        expected = (192 << 24) | (168 << 16) | (1 << 8) | 100
        assert _ip_str_to_int("192.168.1.100") == expected

    def test_cgnat_start(self):
        expected = (100 << 24) | (64 << 16)
        assert _ip_str_to_int("100.64.0.0") == expected

    def test_each_octet_independent(self):
        # 1.2.3.4 = (1<<24)|(2<<16)|(3<<8)|4
        assert _ip_str_to_int("1.2.3.4") == (1 << 24) | (2 << 16) | (3 << 8) | 4


class TestIsCgnat:
    def test_cgnat_start_of_range(self):
        assert _is_cgnat("100.64.0.0") is True

    def test_cgnat_end_of_range(self):
        assert _is_cgnat("100.127.255.255") is True

    def test_cgnat_middle(self):
        assert _is_cgnat("100.96.0.1") is True
        assert _is_cgnat("100.100.200.100") is True

    def test_just_below_cgnat(self):
        # 100.63.255.255 is just before the range
        assert _is_cgnat("100.63.255.255") is False

    def test_just_above_cgnat(self):
        # 100.128.0.0 is just after the range
        assert _is_cgnat("100.128.0.0") is False

    def test_google_dns(self):
        assert _is_cgnat("8.8.8.8") is False

    def test_rfc1918_10(self):
        assert _is_cgnat("10.0.0.1") is False

    def test_rfc1918_192168(self):
        assert _is_cgnat("192.168.1.1") is False

    def test_malformed_returns_false(self):
        assert _is_cgnat("not.an.ip") is False
        assert _is_cgnat("") is False
        assert _is_cgnat("999.999.999.999") is False

    def test_100_0_0_0_not_cgnat(self):
        # 100.0.0.0/8 outside 100.64.0.0/10
        assert _is_cgnat("100.0.0.0") is False


class TestIsPrivate:
    @pytest.mark.parametrize("ip", ["10.0.0.0", "10.255.255.255", "10.1.2.3"])
    def test_rfc1918_class_a(self, ip):
        assert _is_private(ip) is True

    @pytest.mark.parametrize("ip", ["172.16.0.0", "172.31.255.255", "172.20.0.1"])
    def test_rfc1918_class_b(self, ip):
        assert _is_private(ip) is True

    @pytest.mark.parametrize("ip", ["192.168.0.0", "192.168.255.255", "192.168.1.1"])
    def test_rfc1918_class_c(self, ip):
        assert _is_private(ip) is True

    @pytest.mark.parametrize("ip", ["100.64.0.0", "100.127.255.255", "100.100.0.1"])
    def test_cgnat_range_is_private(self, ip):
        assert _is_private(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "172.15.255.255",  # just below 172.16/12
        "172.32.0.0",      # just above 172.31/12
        "192.169.0.0",     # just above 192.168/16
        "11.0.0.0",        # above 10/8
        "100.63.255.255",  # just below CGNAT
        "100.128.0.0",     # just above CGNAT
    ])
    def test_public_ips(self, ip):
        assert _is_private(ip) is False

    def test_malformed_returns_false(self):
        assert _is_private("not.valid") is False
        assert _is_private("") is False


class TestCgnatResultProperties:
    def test_is_behind_cgnat_true(self):
        r = CgnatResult(status=CgnatStatus.BEHIND_CGNAT)
        assert r.is_behind_cgnat is True

    def test_is_behind_cgnat_false_not_behind(self):
        r = CgnatResult(status=CgnatStatus.NOT_BEHIND_CGNAT)
        assert r.is_behind_cgnat is False

    def test_is_behind_cgnat_false_unknown(self):
        r = CgnatResult(status=CgnatStatus.UNKNOWN)
        assert r.is_behind_cgnat is False

    def test_default_fields(self):
        r = CgnatResult(status=CgnatStatus.UNKNOWN)
        assert r.public_ip is None
        assert r.local_ip is None
        assert r.upnp_available is False
        assert r.details == []

    def test_details_list_is_independent_per_instance(self):
        r1 = CgnatResult(status=CgnatStatus.UNKNOWN)
        r2 = CgnatResult(status=CgnatStatus.UNKNOWN)
        r1.details.append("x")
        assert r2.details == []

    def test_full_construction(self):
        r = CgnatResult(
            status=CgnatStatus.BEHIND_CGNAT,
            public_ip="100.64.1.1",
            local_ip="192.168.1.1",
            upnp_available=True,
            details=["msg"],
        )
        assert r.public_ip == "100.64.1.1"
        assert r.local_ip == "192.168.1.1"
        assert r.upnp_available is True
        assert r.details == ["msg"]


class TestGetPublicIp:
    def _make_mock_response(self, body: bytes) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = body
        mock_resp.__exit__.return_value = False
        return mock_resp

    def test_returns_stripped_ip_on_success(self):
        mock_resp = self._make_mock_response(b"  1.2.3.4\n")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _get_public_ip(timeout=1.0)
        assert result == "1.2.3.4"

    def test_uses_first_url_when_it_succeeds(self):
        mock_resp = self._make_mock_response(b"1.2.3.4")
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            _get_public_ip(timeout=1.0)
        assert mock_open.call_count == 1

    def test_falls_back_to_second_url_on_first_failure(self):
        mock_resp = self._make_mock_response(b"5.6.7.8")
        call_count = [0]

        def side_effect(url, timeout):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("first url failed")
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=side_effect):
            result = _get_public_ip(timeout=1.0)

        assert result == "5.6.7.8"
        assert call_count[0] == 2

    def test_returns_none_when_all_urls_fail(self):
        with patch("urllib.request.urlopen", side_effect=OSError("network error")):
            result = _get_public_ip(timeout=1.0)
        assert result is None

    def test_timeout_kwarg_forwarded(self):
        mock_resp = self._make_mock_response(b"9.9.9.9")
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            _get_public_ip(timeout=3.0)
        _, kwargs = mock_open.call_args
        assert kwargs.get("timeout") == 3.0 or mock_open.call_args[0][1] == 3.0

    def test_response_read_is_capped_at_64_bytes(self):
        """_get_public_ip must call resp.read(64) — not read() or read(big) — to cap the
        response size and avoid streaming a large body."""
        mock_resp = self._make_mock_response(b"5.5.5.5")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _get_public_ip(timeout=1.0)
        assert result == "5.5.5.5"
        inner_read = mock_resp.__enter__.return_value.read
        inner_read.assert_called_once_with(64)


class TestGetLocalIp:
    def test_returns_ip_on_success(self):
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.5", 0)
        with patch("socket.socket", return_value=mock_sock):
            result = _get_local_ip()
        assert result == "192.168.1.5"

    def test_connects_to_8888_to_determine_route(self):
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("10.0.0.1", 0)
        with patch("socket.socket", return_value=mock_sock):
            _get_local_ip()
        mock_sock.connect.assert_called_once_with(("8.8.8.8", 80))

    def test_returns_none_on_connect_error(self):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("network unreachable")
        with patch("socket.socket", return_value=mock_sock):
            result = _get_local_ip()
        assert result is None

    def test_returns_none_on_socket_creation_error(self):
        with patch("socket.socket", side_effect=OSError("permission denied")):
            result = _get_local_ip()
        assert result is None


class TestProbeUpnp:
    def test_returns_true_when_response_received(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nST: urn:...\r\n\r\n"
        with patch("socket.socket", return_value=mock_sock):
            result = _probe_upnp(timeout=1.0)
        assert result is True

    def test_sends_ssdp_discover_packet(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"ok"
        with patch("socket.socket", return_value=mock_sock):
            _probe_upnp(timeout=1.0)
        call_args = mock_sock.sendto.call_args
        payload = call_args[0][0]
        destination = call_args[0][1]
        assert b"M-SEARCH" in payload
        assert destination == ("239.255.255.250", 1900)

    def test_sets_timeout_on_socket(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"ok"
        with patch("socket.socket", return_value=mock_sock):
            _probe_upnp(timeout=2.5)
        mock_sock.settimeout.assert_called_once_with(2.5)

    def test_returns_false_on_timeout(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timed out")
        with patch("socket.socket", return_value=mock_sock):
            result = _probe_upnp(timeout=1.0)
        assert result is False

    def test_returns_false_on_oserror(self):
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = OSError("network unreachable")
        with patch("socket.socket", return_value=mock_sock):
            result = _probe_upnp(timeout=1.0)
        assert result is False

    def test_returns_false_when_socket_creation_fails(self):
        with patch("socket.socket", side_effect=OSError("cannot create socket")):
            result = _probe_upnp(timeout=1.0)
        assert result is False


class TestDetectCgnatDryRun:
    def test_dry_run_returns_unknown(self):
        result = detect_cgnat(dry_run=True)
        assert result.status == CgnatStatus.UNKNOWN

    def test_dry_run_skips_all_network_calls(self):
        with (
            patch("transitvpn.cgnat._get_local_ip") as mock_local,
            patch("transitvpn.cgnat._get_public_ip") as mock_public,
            patch("transitvpn.cgnat._probe_upnp") as mock_upnp,
        ):
            detect_cgnat(dry_run=True)
        mock_local.assert_not_called()
        mock_public.assert_not_called()
        mock_upnp.assert_not_called()

    def test_dry_run_fields_are_null(self):
        result = detect_cgnat(dry_run=True)
        assert result.public_ip is None
        assert result.local_ip is None
        assert result.upnp_available is False

    def test_dry_run_detail_mentions_skipped(self):
        result = detect_cgnat(dry_run=True)
        assert any("dry-run" in d for d in result.details)

    def test_dry_run_is_not_behind_cgnat(self):
        result = detect_cgnat(dry_run=True)
        assert result.is_behind_cgnat is False


class TestDetectCgnatBranches:
    """Exercises every status branch in detect_cgnat() with mocked helpers."""

    def _run(
        self,
        local_ip: str | None,
        public_ip: str | None,
        upnp: bool = False,
        router_ip: str | None = None,
        timeout: float = 5.0,
    ) -> CgnatResult:
        with (
            patch("transitvpn.cgnat._get_local_ip", return_value=local_ip),
            patch("transitvpn.cgnat._get_public_ip", return_value=public_ip),
            patch("transitvpn.cgnat._probe_upnp", return_value=upnp),
            patch("transitvpn.cgnat._get_router_external_ip", return_value=router_ip),
        ):
            return detect_cgnat(timeout=timeout)

    # --- UNKNOWN branch ---

    def test_unknown_when_public_ip_unreachable(self):
        result = self._run(local_ip="192.168.1.1", public_ip=None)
        assert result.status == CgnatStatus.UNKNOWN
        assert result.is_behind_cgnat is False

    def test_unknown_when_both_local_and_public_unavailable(self):
        result = self._run(local_ip=None, public_ip=None)
        assert result.status == CgnatStatus.UNKNOWN

    def test_unknown_result_public_ip_is_none(self):
        result = self._run(local_ip="192.168.1.1", public_ip=None)
        assert result.public_ip is None

    # --- BEHIND_CGNAT via RFC-1918 local + CGNAT public ---

    def test_behind_cgnat_rfc1918_local_cgnat_public(self):
        result = self._run(local_ip="192.168.1.1", public_ip="100.100.0.1")
        assert result.status == CgnatStatus.BEHIND_CGNAT
        assert result.is_behind_cgnat is True

    def test_behind_cgnat_rfc1918_local_cgnat_public_detail(self):
        result = self._run(local_ip="192.168.1.1", public_ip="100.100.0.1")
        assert any("CGNAT" in d or "double-NAT" in d for d in result.details)

    def test_behind_cgnat_rfc1918_local_rfc1918_public(self):
        # Public IP is also private (double-NAT scenario)
        result = self._run(local_ip="192.168.1.1", public_ip="10.0.0.1")
        assert result.status == CgnatStatus.BEHIND_CGNAT

    def test_behind_cgnat_10x_local_with_cgnat_public(self):
        result = self._run(local_ip="10.0.0.1", public_ip="100.80.0.1")
        assert result.status == CgnatStatus.BEHIND_CGNAT

    def test_behind_cgnat_172_16_local_with_rfc1918_public(self):
        result = self._run(local_ip="172.20.0.5", public_ip="172.16.0.1")
        assert result.status == CgnatStatus.BEHIND_CGNAT

    # --- NOT_BEHIND_CGNAT via RFC-1918 local + genuine public ---

    def test_not_behind_cgnat_rfc1918_local_public_ip(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8")
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT
        assert result.is_behind_cgnat is False

    def test_not_behind_cgnat_10x_local_public_ip(self):
        result = self._run(local_ip="10.0.0.1", public_ip="8.8.8.8")
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT

    def test_not_behind_cgnat_172_16_local_public_ip(self):
        result = self._run(local_ip="172.20.0.1", public_ip="8.8.8.8")
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT

    # --- BEHIND_CGNAT via CGNAT local IP ---

    def test_behind_cgnat_when_local_ip_is_in_cgnat_range(self):
        result = self._run(local_ip="100.64.0.1", public_ip="8.8.8.8")
        assert result.status == CgnatStatus.BEHIND_CGNAT

    def test_behind_cgnat_cgnat_local_detail_mentions_range(self):
        result = self._run(local_ip="100.64.0.1", public_ip="8.8.8.8")
        assert any("100.64.0.0/10" in d for d in result.details)

    def test_behind_cgnat_cgnat_local_at_end_of_range(self):
        result = self._run(local_ip="100.127.255.255", public_ip="8.8.8.8")
        assert result.status == CgnatStatus.BEHIND_CGNAT

    # --- NOT_BEHIND_CGNAT via public == local (no NAT) ---

    def test_not_behind_cgnat_public_matches_local(self):
        result = self._run(local_ip="1.2.3.4", public_ip="1.2.3.4")
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT

    def test_not_behind_cgnat_no_nat_detail(self):
        result = self._run(local_ip="1.2.3.4", public_ip="1.2.3.4")
        assert any("no NAT" in d for d in result.details)

    # --- NOT_BEHIND_CGNAT via else fallthrough ---

    def test_not_behind_cgnat_local_none_public_set(self):
        # local_ip is None: skips all elif branches that check local_ip
        result = self._run(local_ip=None, public_ip="8.8.8.8")
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT

    def test_not_behind_cgnat_public_local_differ_both_public(self):
        # Both IPs are public and different — else branch
        result = self._run(local_ip="1.2.3.4", public_ip="5.6.7.8")
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT

    # --- Result field population ---

    def test_result_captures_public_ip(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8")
        assert result.public_ip == "8.8.8.8"

    def test_result_captures_local_ip(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8")
        assert result.local_ip == "192.168.1.1"

    def test_upnp_available_true_propagates(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8", upnp=True)
        assert result.upnp_available is True

    def test_upnp_available_false_propagates(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8", upnp=False)
        assert result.upnp_available is False

    def test_upnp_responded_detail_when_available(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8", upnp=True)
        assert any("UPnP IGD responded" in d for d in result.details)

    def test_upnp_no_response_detail_when_unavailable(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8", upnp=False)
        assert any("UPnP IGD: no response" in d for d in result.details)

    def test_local_ip_unavailable_detail_when_none(self):
        result = self._run(local_ip=None, public_ip="8.8.8.8")
        assert any("unavailable" in d for d in result.details)

    def test_local_ip_detail_shows_ip_when_present(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8")
        assert any("192.168.1.1" in d for d in result.details)

    def test_public_ip_unreachable_detail_when_none(self):
        result = self._run(local_ip="192.168.1.1", public_ip=None)
        assert any("unreachable" in d for d in result.details)

    def test_public_ip_detail_shows_ip_when_present(self):
        result = self._run(local_ip="192.168.1.1", public_ip="8.8.8.8")
        assert any("8.8.8.8" in d for d in result.details)

    def test_upnp_does_not_change_cgnat_status(self):
        # UPnP is orthogonal to CGNAT determination
        result_upnp = self._run(local_ip="100.100.0.1", public_ip="8.8.8.8", upnp=True)
        result_no_upnp = self._run(local_ip="100.100.0.1", public_ip="8.8.8.8", upnp=False)
        assert result_upnp.status == result_no_upnp.status == CgnatStatus.BEHIND_CGNAT

    def test_timeout_forwarded_to_get_public_ip(self):
        with (
            patch("transitvpn.cgnat._get_local_ip", return_value="192.168.1.1"),
            patch("transitvpn.cgnat._get_public_ip", return_value="8.8.8.8") as mock_pub,
            patch("transitvpn.cgnat._probe_upnp", return_value=False),
            patch("transitvpn.cgnat._get_router_external_ip", return_value=None),
        ):
            detect_cgnat(timeout=7.0)
        mock_pub.assert_called_once_with(timeout=7.0)

    def test_upnp_timeout_capped_at_two(self):
        with (
            patch("transitvpn.cgnat._get_local_ip", return_value="192.168.1.1"),
            patch("transitvpn.cgnat._get_public_ip", return_value="8.8.8.8"),
            patch("transitvpn.cgnat._probe_upnp", return_value=False) as mock_upnp,
            patch("transitvpn.cgnat._get_router_external_ip", return_value=None),
        ):
            detect_cgnat(timeout=10.0)
        mock_upnp.assert_called_once_with(timeout=2.0)

    def test_upnp_timeout_equals_main_when_main_below_two(self):
        with (
            patch("transitvpn.cgnat._get_local_ip", return_value="192.168.1.1"),
            patch("transitvpn.cgnat._get_public_ip", return_value="8.8.8.8"),
            patch("transitvpn.cgnat._probe_upnp", return_value=False) as mock_upnp,
            patch("transitvpn.cgnat._get_router_external_ip", return_value=None),
        ):
            detect_cgnat(timeout=1.0)
        mock_upnp.assert_called_once_with(timeout=1.0)

    def test_router_external_ip_timeout_capped_at_two(self):
        with (
            patch("transitvpn.cgnat._get_local_ip", return_value="192.168.1.1"),
            patch("transitvpn.cgnat._get_public_ip", return_value="8.8.8.8"),
            patch("transitvpn.cgnat._probe_upnp", return_value=False),
            patch(
                "transitvpn.cgnat._get_router_external_ip", return_value=None
            ) as mock_router,
        ):
            detect_cgnat(timeout=10.0)
        mock_router.assert_called_once_with(timeout=2.0)


class TestDetectCgnatRouterWanIp:
    """The router's WAN IP (UPnP IGD) is the authoritative CGNAT signal."""

    def _run(
        self,
        local_ip: str | None,
        public_ip: str | None,
        router_ip: str | None,
    ) -> CgnatResult:
        with (
            patch("transitvpn.cgnat._get_local_ip", return_value=local_ip),
            patch("transitvpn.cgnat._get_public_ip", return_value=public_ip),
            patch("transitvpn.cgnat._probe_upnp", return_value=True),
            patch("transitvpn.cgnat._get_router_external_ip", return_value=router_ip),
        ):
            return detect_cgnat()

    def test_private_router_wan_is_cgnat_despite_routable_public_ip(self):
        # The real CGNAT case the old heuristic missed: private local IP and a
        # routable public IP (the carrier's), but the router's WAN is private.
        result = self._run(
            local_ip="192.168.1.10", public_ip="203.0.113.7", router_ip="100.96.0.1"
        )
        assert result.status == CgnatStatus.BEHIND_CGNAT
        assert result.router_external_ip == "100.96.0.1"

    def test_rfc1918_router_wan_is_cgnat(self):
        result = self._run(
            local_ip="192.168.1.10", public_ip="203.0.113.7", router_ip="10.0.0.4"
        )
        assert result.status == CgnatStatus.BEHIND_CGNAT

    def test_router_wan_differs_from_public_ip_is_cgnat(self):
        result = self._run(
            local_ip="192.168.1.10", public_ip="203.0.113.7", router_ip="198.51.100.9"
        )
        assert result.status == CgnatStatus.BEHIND_CGNAT
        assert any("differs from public IP" in d for d in result.details)

    def test_router_wan_matches_public_ip_is_not_cgnat(self):
        result = self._run(
            local_ip="192.168.1.10", public_ip="203.0.113.7", router_ip="203.0.113.7"
        )
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT
        assert any("no CGNAT" in d for d in result.details)

    def test_routable_router_wan_with_no_public_ip_is_not_cgnat(self):
        result = self._run(
            local_ip="192.168.1.10", public_ip=None, router_ip="203.0.113.7"
        )
        assert result.status == CgnatStatus.NOT_BEHIND_CGNAT

    def test_router_ip_overrides_local_heuristic(self):
        # Local-vs-public heuristic alone would say NOT_BEHIND; router says CGNAT.
        result = self._run(
            local_ip="192.168.1.10", public_ip="8.8.8.8", router_ip="100.64.0.1"
        )
        assert result.status == CgnatStatus.BEHIND_CGNAT

    def test_router_ip_recorded_in_details(self):
        result = self._run(
            local_ip="192.168.1.10", public_ip="203.0.113.7", router_ip="203.0.113.7"
        )
        assert any("router WAN IP (UPnP): 203.0.113.7" in d for d in result.details)

    def test_no_router_ip_detail_when_unavailable(self):
        result = self._run(
            local_ip="192.168.1.10", public_ip="203.0.113.7", router_ip=None
        )
        assert any("router WAN IP: unavailable" in d for d in result.details)
        assert result.router_external_ip is None


class TestSsdpLocation:
    def _mock_sock(self, recv_bytes: bytes) -> MagicMock:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = recv_bytes
        return mock_sock

    def test_extracts_location_header(self):
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n"
        )
        with patch("socket.socket", return_value=self._mock_sock(resp)):
            assert _ssdp_location(timeout=1.0) == "http://192.168.1.1:5000/rootDesc.xml"

    def test_location_header_is_case_insensitive(self):
        resp = b"HTTP/1.1 200 OK\r\nlocation: http://10.0.0.1/desc.xml\r\n\r\n"
        with patch("socket.socket", return_value=self._mock_sock(resp)):
            assert _ssdp_location(timeout=1.0) == "http://10.0.0.1/desc.xml"

    def test_returns_none_when_no_location(self):
        resp = b"HTTP/1.1 200 OK\r\nST: urn:foo\r\n\r\n"
        with patch("socket.socket", return_value=self._mock_sock(resp)):
            assert _ssdp_location(timeout=1.0) is None

    def test_returns_none_on_timeout(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timed out")
        with patch("socket.socket", return_value=mock_sock):
            assert _ssdp_location(timeout=1.0) is None


class TestFindWanService:
    _DESC = """<root>
      <device><serviceList>
        <service>
          <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
          <controlURL>/ctl/IPConn</controlURL>
        </service>
      </serviceList></device>
    </root>"""

    def test_finds_wanip_control_url_absolute(self):
        result = _find_wan_service(self._DESC, "http://192.168.1.1:5000/rootDesc.xml")
        assert result == (
            "http://192.168.1.1:5000/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
        )

    def test_finds_wanppp_service(self):
        desc = (
            "<service>"
            "<serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1"
            "</serviceType><controlURL>/ppp</controlURL></service>"
        )
        result = _find_wan_service(desc, "http://10.0.0.1:80/desc.xml")
        assert result is not None
        assert result[0] == "http://10.0.0.1:80/ppp"

    def test_returns_none_when_no_wan_service(self):
        desc = (
            "<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1"
            "</serviceType><controlURL>/x</controlURL></service>"
        )
        assert _find_wan_service(desc, "http://10.0.0.1/desc.xml") is None


class TestSoapExternalIp:
    def _mock_response(self, body: bytes) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = body
        mock_resp.__exit__.return_value = False
        return mock_resp

    def test_parses_external_ip(self):
        body = (
            b"<s:Envelope><s:Body><u:GetExternalIPAddressResponse>"
            b"<NewExternalIPAddress>100.96.0.1</NewExternalIPAddress>"
            b"</u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
        )
        with patch("urllib.request.urlopen", return_value=self._mock_response(body)):
            result = _soap_external_ip(
                "http://10.0.0.1/ctl", "urn:...:WANIPConnection:1", timeout=1.0
            )
        assert result == "100.96.0.1"

    def test_returns_none_when_tag_absent(self):
        body = b"<s:Envelope><s:Body></s:Body></s:Envelope>"
        with patch("urllib.request.urlopen", return_value=self._mock_response(body)):
            result = _soap_external_ip(
                "http://10.0.0.1/ctl", "urn:...:WANIPConnection:1", timeout=1.0
            )
        assert result is None

    def test_returns_none_on_network_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            result = _soap_external_ip(
                "http://10.0.0.1/ctl", "urn:...:WANIPConnection:1", timeout=1.0
            )
        assert result is None


class TestGetRouterExternalIp:
    def test_returns_none_when_no_igd_discovered(self):
        with patch("transitvpn.cgnat._ssdp_location", return_value=None):
            assert _get_router_external_ip(timeout=1.0) is None

    def test_returns_none_when_description_unreachable(self):
        with (
            patch("transitvpn.cgnat._ssdp_location", return_value="http://x/desc.xml"),
            patch("urllib.request.urlopen", side_effect=OSError("unreachable")),
        ):
            assert _get_router_external_ip(timeout=1.0) is None

    def test_full_happy_path(self):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = b"<root/>"
        mock_resp.__exit__.return_value = False
        with (
            patch(
                "transitvpn.cgnat._ssdp_location",
                return_value="http://192.168.1.1/desc.xml",
            ),
            patch("urllib.request.urlopen", return_value=mock_resp),
            patch(
                "transitvpn.cgnat._find_wan_service",
                return_value=("http://192.168.1.1/ctl", "urn:WANIPConnection:1"),
            ),
            patch(
                "transitvpn.cgnat._soap_external_ip", return_value="203.0.113.5"
            ) as mock_soap,
        ):
            result = _get_router_external_ip(timeout=1.0)
        assert result == "203.0.113.5"
        mock_soap.assert_called_once()
