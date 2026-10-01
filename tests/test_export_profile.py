"""Focused coverage for private client-profile export."""

from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from transitvpn.config import XrayDeployment
from transitvpn.export_profile import ProfileExportError, build_profile_uri, export_profile
from transitvpn.keygen import generate_keys, generate_short_id
from transitvpn.server import build_client_config

_REPOSITORY = Path(__file__).resolve().parents[1]


def _generated_client(host: str = "MiXeD.Example.Test"):
    keys = generate_keys()
    deployment = XrayDeployment(
        keys=keys,
        server=host,
        target="cover.example.test:443",
        server_name="cover.example.test",
        short_id=generate_short_id(),
        target_verified=True,
    )
    return build_client_config(deployment), keys


class TestExportProfile(unittest.TestCase):
    def test_generated_client_uri_preserves_fields_and_input(self) -> None:
        config, keys = _generated_client()
        before = json.dumps(config, sort_keys=True)
        uri = build_profile_uri(config)
        parsed = urlsplit(uri)
        query = parse_qs(parsed.query, strict_parsing=True)

        self.assertTrue(parsed.scheme == "vless", "export scheme is incorrect")
        self.assertTrue(parsed.hostname == "mixed.example.test", "export host is incorrect")
        self.assertTrue(parsed.port == 443, "export port is incorrect")
        self.assertTrue(parsed.username == keys.vless_uuid, "export user ID is incorrect")
        self.assertTrue(set(query) == {
            "security", "encryption", "type", "pbk", "sni", "sid", "fp", "flow",
        }, "export query fields are incomplete or duplicated")
        self.assertTrue(all(len(values) == 1 for values in query.values()),
                        "export query contains duplicate values")
        self.assertTrue(query["pbk"][0] == config["outbounds"][0]["streamSettings"][
            "realitySettings"]["publicKey"], "export public key changed")
        self.assertTrue(json.dumps(config, sort_keys=True) == before,
                        "profile parsing changed its input config")

    def test_ipv6_and_equal_public_key_alias_are_supported(self) -> None:
        config, keys = _generated_client()
        peer = config["outbounds"][0]["settings"]["vnext"][0]
        peer["address"] = "2001:db8::1"
        reality = config["outbounds"][0]["streamSettings"]["realitySettings"]
        reality["password"] = reality["publicKey"]

        uri = build_profile_uri(config)
        parsed = urlsplit(uri)
        self.assertTrue(parsed.netloc.startswith(f"{keys.vless_uuid}@[2001:db8::1]:"),
                        "IPv6 export was not bracketed")
        self.assertTrue(parsed.hostname == "2001:db8::1", "IPv6 host changed")

    def test_conflicting_or_malformed_key_aliases_are_rejected(self) -> None:
        config, _ = _generated_client()
        original = config["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"]
        variants = []
        conflict = copy.deepcopy(config)
        conflict["outbounds"][0]["streamSettings"]["realitySettings"]["password"] = "different"
        variants.append(("conflict", conflict))
        malformed = copy.deepcopy(config)
        malformed["outbounds"][0]["streamSettings"]["realitySettings"]["password"] = 17
        variants.append(("malformed alias", malformed))
        empty = copy.deepcopy(config)
        empty["outbounds"][0]["streamSettings"]["realitySettings"]["password"] = ""
        variants.append(("empty alias", empty))
        for label, candidate in variants:
            with self.subTest(case=label), self.assertRaises(ProfileExportError):
                build_profile_uri(candidate)
        self.assertTrue(bool(original), "generated fixture key is empty")

    def test_multi_peer_and_unrepresented_transport_are_rejected(self) -> None:
        config, _ = _generated_client()
        multi_peer = copy.deepcopy(config)
        multi_peer["outbounds"][0]["settings"]["vnext"].append(
            copy.deepcopy(multi_peer["outbounds"][0]["settings"]["vnext"][0])
        )
        extra_transport = copy.deepcopy(config)
        extra_transport["outbounds"][0]["streamSettings"]["sockopt"] = {"mark": 1}
        for label, candidate in (("multi-peer", multi_peer), ("extra transport", extra_transport)):
            with self.subTest(case=label), self.assertRaises(ProfileExportError):
                build_profile_uri(candidate)

    def test_cli_writes_private_exclusive_file_without_printing_credentials(self) -> None:
        config, keys = _generated_client()
        with tempfile.TemporaryDirectory(prefix="transitvpn-profile-cli-") as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir(mode=0o700)
            config_path = state / "xray-client.json"
            original = json.dumps(config, separators=(",", ":")).encode()
            config_path.write_bytes(original)
            config_path.chmod(0o600)
            output_dir = root / "private-export"
            output = output_dir / "client.vless"
            env = {**os.environ, "PYTHONPATH": str(_REPOSITORY)}
            command = [
                sys.executable, "-m", "transitvpn", "export-profile",
                "--output", str(output),
            ]
            result = subprocess.run(
                command, cwd=root, env=env, capture_output=True, text=True,
                timeout=30, stdin=subprocess.DEVNULL, check=False,
            )
            self.assertTrue(result.returncode == 0, "export CLI failed")
            self.assertTrue(result.stdout == "export-profile: profile exported\n",
                            "export CLI success output is not credential-free")
            self.assertTrue(result.stderr == "", "export CLI wrote unexpected error output")
            output_text = output.read_text(encoding="utf-8")
            self.assertTrue(stat.S_IMODE(output.stat().st_mode) == 0o600,
                            "profile file is not mode 0600")
            self.assertTrue(stat.S_IMODE(output_dir.stat().st_mode) == 0o700,
                            "new profile directory is not mode 0700")
            self.assertTrue(config_path.read_bytes() == original, "input config changed")
            self.assertTrue(all(value not in result.stdout + result.stderr for value in (
                keys.vless_uuid, keys.reality_private_key, keys.reality_public_key,
                keys.ss_password, output_text,
            )), "export CLI exposed credential material")

            refusal = subprocess.run(
                command, cwd=root, env=env, capture_output=True, text=True,
                timeout=30, stdin=subprocess.DEVNULL, check=False,
            )
            self.assertTrue(refusal.returncode == 1, "existing profile was overwritten")
            self.assertTrue(refusal.stdout == "", "refusal wrote unexpected stdout")
            self.assertTrue(refusal.stderr ==
                            "export-profile: error: client profile could not be exported\n",
                            "refusal output is not generic")
            self.assertTrue(output.read_text(encoding="utf-8") == output_text,
                            "existing profile contents changed")
            self.assertTrue(all(value not in refusal.stdout + refusal.stderr for value in (
                keys.vless_uuid, keys.reality_private_key, keys.reality_public_key,
                keys.ss_password, output_text,
            )), "export CLI refusal exposed credential material")

    def test_symlink_input_and_nonprivate_parent_are_refused(self) -> None:
        config, _ = _generated_client()
        with tempfile.TemporaryDirectory(prefix="transitvpn-profile-io-") as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir(mode=0o700)
            input_path = state / "xray-client.json"
            input_path.write_text(json.dumps(config), encoding="utf-8")
            input_path.chmod(0o600)
            linked_input = root / "linked-client.json"
            linked_input.symlink_to(input_path)
            private_parent = root / "private"
            private_parent.mkdir(mode=0o700)
            with self.assertRaises(ProfileExportError):
                export_profile(linked_input, private_parent / "profile.vless")

            public_parent = root / "public"
            public_parent.mkdir(mode=0o755)
            public_parent.chmod(0o755)
            refused = public_parent / "profile.vless"
            with self.assertRaises(ProfileExportError):
                export_profile(input_path, refused)
            self.assertTrue(not refused.exists(), "nonprivate parent received a profile")
