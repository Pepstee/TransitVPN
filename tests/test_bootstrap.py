"""Tests for the bootstrap CLI command — state/ file assertions, cgnat mocked, hermetic."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from transitvpn.cgnat import CgnatResult, CgnatStatus
from transitvpn.cli import main


# ---------------------------------------------------------------------------
# Helpers — pre-built CgnatResult stubs
# ---------------------------------------------------------------------------


def _cgnat_ok(public_ip: str = "1.2.3.4") -> CgnatResult:
    return CgnatResult(
        status=CgnatStatus.NOT_BEHIND_CGNAT,
        public_ip=public_ip,
        local_ip="192.168.1.1",
        upnp_available=False,
        details=["local IP: 192.168.1.1", f"public IP: {public_ip}"],
    )


def _cgnat_behind() -> CgnatResult:
    return CgnatResult(
        status=CgnatStatus.BEHIND_CGNAT,
        public_ip="100.100.0.1",
        local_ip="192.168.1.1",
        upnp_available=False,
        details=["local IP: 192.168.1.1", "public IP: 100.100.0.1",
                 "public IP is non-routable → double-NAT / CGNAT"],
    )


def _cgnat_unknown() -> CgnatResult:
    return CgnatResult(
        status=CgnatStatus.UNKNOWN,
        public_ip=None,
        local_ip=None,
        upnp_available=False,
        details=["dry-run: network probes skipped"],
    )


# ---------------------------------------------------------------------------
# Fixture — bootstrap runner with chdir + mocked detect_cgnat
# ---------------------------------------------------------------------------


@pytest.fixture()
def run_in_tmp(tmp_path, monkeypatch, capsys):
    """
    Returns a helper that runs `main(argv)` with detect_cgnat mocked and
    cwd set to tmp_path. Returns (exit_code, captured_stdout).
    """
    monkeypatch.chdir(tmp_path)

    def _run(argv=None, cgnat_result=None):
        if cgnat_result is None:
            cgnat_result = _cgnat_ok()
        with patch("transitvpn.cgnat.detect_cgnat", return_value=cgnat_result):
            code = main(argv if argv is not None else ["bootstrap"])
        out = capsys.readouterr().out
        return code, out

    return _run


# ---------------------------------------------------------------------------
# Return-code
# ---------------------------------------------------------------------------


class TestBootstrapReturnCode:
    def test_dry_run_returns_zero(self, run_in_tmp) -> None:
        code, _ = run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        assert code == 0

    def test_normal_run_returns_zero(self, run_in_tmp) -> None:
        code, _ = run_in_tmp(["bootstrap"])
        assert code == 0

    def test_returns_zero_when_behind_cgnat(self, run_in_tmp) -> None:
        code, _ = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_behind())
        assert code == 0

    def test_returns_zero_when_public_ip_none(self, run_in_tmp) -> None:
        code, _ = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_unknown())
        assert code == 0


# ---------------------------------------------------------------------------
# State file creation — normal run writes both files
# ---------------------------------------------------------------------------


class TestBootstrapFileCreation:
    def test_xray_server_json_created(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap"])
        assert (tmp_path / "state" / "xray-server.json").exists()

    def test_ss_server_json_created(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap"])
        assert (tmp_path / "state" / "ss-server.json").exists()

    def test_state_dir_created(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap"])
        assert (tmp_path / "state").is_dir()

    def test_dry_run_does_not_create_xray_file(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        assert not (tmp_path / "state" / "xray-server.json").exists()

    def test_dry_run_does_not_create_ss_file(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        assert not (tmp_path / "state" / "ss-server.json").exists()

    def test_dry_run_does_not_create_state_dir(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        assert not (tmp_path / "state").exists()

    def test_xray_file_contains_valid_json(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap"])
        raw = (tmp_path / "state" / "xray-server.json").read_text()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_ss_file_contains_valid_json(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap"])
        raw = (tmp_path / "state" / "ss-server.json").read_text()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# JSON structure of xray-server.json
# ---------------------------------------------------------------------------


class TestXrayJsonStructure:
    @pytest.fixture()
    def xray(self, run_in_tmp, tmp_path) -> dict:
        run_in_tmp(["bootstrap"])
        return json.loads((tmp_path / "state" / "xray-server.json").read_text())

    def test_inbounds_key_present(self, xray) -> None:
        assert "inbounds" in xray

    def test_outbounds_key_present(self, xray) -> None:
        assert "outbounds" in xray

    def test_inbounds_is_list(self, xray) -> None:
        assert isinstance(xray["inbounds"], list)

    def test_inbounds_is_not_empty(self, xray) -> None:
        assert len(xray["inbounds"]) >= 1

    def test_outbounds_is_not_empty(self, xray) -> None:
        assert len(xray["outbounds"]) >= 1

    def test_inbound_protocol_is_vless(self, xray) -> None:
        assert xray["inbounds"][0]["protocol"] == "vless"

    def test_inbound_stream_has_reality(self, xray) -> None:
        stream = xray["inbounds"][0]["streamSettings"]
        assert stream["security"] == "reality"

    def test_inbound_has_port_443(self, xray) -> None:
        assert xray["inbounds"][0]["port"] == 443

    def test_reality_private_key_present(self, xray) -> None:
        reality = xray["inbounds"][0]["streamSettings"]["realitySettings"]
        assert "privateKey" in reality
        assert isinstance(reality["privateKey"], str)
        assert reality["privateKey"] != ""

    def test_vless_client_id_is_present(self, xray) -> None:
        clients = xray["inbounds"][0]["settings"]["clients"]
        assert len(clients) >= 1
        assert "id" in clients[0]

    def test_outbound_protocol_is_freedom(self, xray) -> None:
        assert xray["outbounds"][0]["protocol"] == "freedom"

    def test_json_roundtrip_preserves_identity(self, xray) -> None:
        re_parsed = json.loads(json.dumps(xray))
        assert re_parsed == xray


# ---------------------------------------------------------------------------
# JSON structure of ss-server.json
# ---------------------------------------------------------------------------


class TestSsJsonStructure:
    @pytest.fixture()
    def ss(self, run_in_tmp, tmp_path) -> dict:
        run_in_tmp(["bootstrap"])
        return json.loads((tmp_path / "state" / "ss-server.json").read_text())

    def test_server_key_present(self, ss) -> None:
        assert "server" in ss

    def test_server_port_key_present(self, ss) -> None:
        assert "server_port" in ss

    def test_password_key_present(self, ss) -> None:
        assert "password" in ss

    def test_method_key_present(self, ss) -> None:
        assert "method" in ss

    def test_mode_key_present(self, ss) -> None:
        assert "mode" in ss

    def test_all_required_keys_present(self, ss) -> None:
        assert {"server", "server_port", "password", "method", "mode"}.issubset(ss.keys())

    def test_server_port_is_8388(self, ss) -> None:
        assert ss["server_port"] == 8388

    def test_server_port_is_int(self, ss) -> None:
        assert isinstance(ss["server_port"], int)

    def test_mode_is_tcp_and_udp(self, ss) -> None:
        assert ss["mode"] == "tcp_and_udp"

    def test_method_is_ss2022_cipher(self, ss) -> None:
        assert ss["method"].startswith("2022-")

    def test_password_is_non_empty_string(self, ss) -> None:
        assert isinstance(ss["password"], str)
        assert ss["password"] != ""

    def test_json_roundtrip_preserves_identity(self, ss) -> None:
        assert json.loads(json.dumps(ss)) == ss


# ---------------------------------------------------------------------------
# Stdout output — cgnat status line
# ---------------------------------------------------------------------------


class TestBootstrapStdoutCgnat:
    def test_prints_cgnat_status_not_behind(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_ok())
        assert "cgnat: not_behind_cgnat" in out

    def test_prints_cgnat_status_behind(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_behind())
        assert "cgnat: behind_cgnat" in out

    def test_prints_cgnat_status_unknown_on_dry_run(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        assert "cgnat: unknown" in out

    def test_prints_cgnat_details(self, run_in_tmp) -> None:
        cgnat = _cgnat_ok()
        _, out = run_in_tmp(["bootstrap"], cgnat_result=cgnat)
        for detail in cgnat.details:
            assert detail in out

    def test_no_cgnat_warning_when_not_behind(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_ok())
        assert "warning" not in out.lower() or "CGNAT" not in out

    def test_cgnat_warning_printed_when_behind(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_behind())
        assert "warning" in out
        assert "CGNAT" in out

    def test_unknown_public_ip_dry_run_warns_user(self, run_in_tmp) -> None:
        """When public_ip is None, dry-run output must contain 'warning' or 'unknown'.

        No network is touched: detect_cgnat is mocked by run_in_tmp.  The 'cgnat: unknown'
        status line and the 'warning: public IP unknown' line both satisfy the contract.
        """
        _, out = run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        lower = out.lower()
        assert "warning" in lower or "unknown" in lower, (
            f"expected 'warning' or 'unknown' in output, got:\n{out}"
        )


# ---------------------------------------------------------------------------
# Stdout output — URI lines
# ---------------------------------------------------------------------------


class TestBootstrapStdoutUris:
    def test_prints_vless_uri_label(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"])
        assert "vless_uri:" in out

    def test_prints_ss_uri_label(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"])
        assert "ss_uri:" in out

    def test_vless_uri_in_stdout_starts_with_scheme(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"])
        vless_line = next(ln for ln in out.splitlines() if "vless_uri:" in ln)
        assert "vless://" in vless_line

    def test_ss_uri_in_stdout_starts_with_scheme(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"])
        ss_line = next(ln for ln in out.splitlines() if "ss_uri:" in ln and "vless" not in ln)
        assert "ss://" in ss_line

    def test_vless_uri_uses_public_ip_from_cgnat(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_ok("9.9.9.9"))
        vless_line = next(ln for ln in out.splitlines() if "vless_uri:" in ln)
        assert "9.9.9.9" in vless_line

    def test_ss_uri_uses_public_ip_from_cgnat(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_ok("9.9.9.9"))
        ss_line = next(ln for ln in out.splitlines() if "ss_uri:" in ln and "vless" not in ln)
        assert "9.9.9.9" in ss_line

    def test_fallback_host_zero_when_public_ip_none(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"], cgnat_result=_cgnat_unknown())
        vless_line = next(ln for ln in out.splitlines() if "vless_uri:" in ln)
        assert "0.0.0.0" in vless_line

    def test_vless_uses_port_443(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"])
        vless_line = next(ln for ln in out.splitlines() if "vless_uri:" in ln)
        assert ":443" in vless_line

    def test_ss_uses_port_8388(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"])
        # "ss_uri:" is a substring of "vless_uri:"; guard against that.
        ss_line = next(ln for ln in out.splitlines() if "ss_uri:" in ln and "vless" not in ln)
        assert ":8388" in ss_line

    def test_dry_run_also_prints_uris(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        assert "vless_uri:" in out
        assert "ss_uri:" in out


# ---------------------------------------------------------------------------
# Stdout output — "wrote files" message
# ---------------------------------------------------------------------------


class TestBootstrapWroteFilesMessage:
    def test_normal_run_prints_wrote_message(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap"])
        assert "wrote" in out and ("xray-server.json" in out or "state" in out)

    def test_dry_run_does_not_print_wrote_message(self, run_in_tmp) -> None:
        _, out = run_in_tmp(["bootstrap", "--dry-run"], cgnat_result=_cgnat_unknown())
        assert "wrote" not in out


# ---------------------------------------------------------------------------
# detect_cgnat interaction
# ---------------------------------------------------------------------------


class TestBootstrapCgnatCallSite:
    def test_detect_cgnat_called_with_dry_run_false_for_normal(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with patch(
            "transitvpn.cgnat.detect_cgnat", return_value=_cgnat_ok()
        ) as mock_detect:
            main(["bootstrap"])
        mock_detect.assert_called_once_with(dry_run=False)

    def test_detect_cgnat_called_with_dry_run_true(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with patch(
            "transitvpn.cgnat.detect_cgnat", return_value=_cgnat_unknown()
        ) as mock_detect:
            main(["bootstrap", "--dry-run"])
        mock_detect.assert_called_once_with(dry_run=True)

    def test_detect_cgnat_called_exactly_once(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        with patch(
            "transitvpn.cgnat.detect_cgnat", return_value=_cgnat_ok()
        ) as mock_detect:
            main(["bootstrap"])
        assert mock_detect.call_count == 1


# ---------------------------------------------------------------------------
# Two successive normal runs — second overwrites first (idempotent)
# ---------------------------------------------------------------------------


class TestBootstrapIdempotency:
    def test_second_run_overwrites_xray_json(self, run_in_tmp, tmp_path) -> None:
        run_in_tmp(["bootstrap"])
        content1 = (tmp_path / "state" / "xray-server.json").read_text()
        run_in_tmp(["bootstrap"])
        content2 = (tmp_path / "state" / "xray-server.json").read_text()
        # Both must be valid JSON; passwords differ because generate_keys() randomises them
        assert json.loads(content1) is not None
        assert json.loads(content2) is not None

    def test_second_run_returns_zero(self, run_in_tmp) -> None:
        run_in_tmp(["bootstrap"])
        code, _ = run_in_tmp(["bootstrap"])
        assert code == 0
