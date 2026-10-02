"""Focused safety checks for private two-file Xray configuration recovery."""

from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from transitvpn.config_backup import (
    ConfigBackupError,
    backup_configs,
    restore_configs,
)


class ConfigBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="transitvpn-config-backup-")
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.private_parent = self.root / "private-backups"
        self.state.mkdir(mode=0o700)
        self.private_parent.mkdir(mode=0o700)
        self.backup = self.private_parent / "trusted-recovery"
        self.original = {
            "xray-server.json": b'{"purpose":"synthetic-server"}\n',
            "xray-client.json": b'{"purpose":"synthetic-client"}\n',
        }
        for name, data in self.original.items():
            path = self.state / name
            path.write_bytes(data)
            path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _make_backup(self) -> None:
        backup_configs(self.state, self.backup)

    def _change_current_configs(self) -> dict[str, bytes]:
        changed = {
            "xray-server.json": b'{"purpose":"changed-server"}\n',
            "xray-client.json": b'{"purpose":"changed-client"}\n',
        }
        for name, data in changed.items():
            path = self.state / name
            path.write_bytes(data)
            path.chmod(0o600)
        return changed

    def test_private_backup_and_validated_restore_round_trip(self) -> None:
        self._make_backup()
        self.assertEqual(
            sorted(path.name for path in self.backup.iterdir()),
            ["xray-client.json", "xray-server.json"],
        )
        self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o700)
        for name, data in self.original.items():
            info = (self.backup / name).stat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual((self.backup / name).read_bytes(), data)
            (self.state / name).unlink()

        with mock.patch("transitvpn.xray.validate_configs") as validate:
            restore_configs(self.state, self.backup, xray_binary="pinned-test-xray")
        self.assertEqual(validate.call_count, 1)
        for name, data in self.original.items():
            path = self.state / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_backup_refuses_lifecycle_entries_and_existing_destination(self) -> None:
        (self.state / "tunnel.pid").write_text("not-a-process", encoding="ascii")
        with self.assertRaises(ConfigBackupError):
            self._make_backup()
        self.assertFalse(self.backup.exists())
        (self.state / "tunnel.pid").unlink()
        self._make_backup()
        saved = (self.backup / "xray-server.json").read_bytes()
        with self.assertRaises(ConfigBackupError):
            self._make_backup()
        self.assertEqual((self.backup / "xray-server.json").read_bytes(), saved)

    def test_restore_refuses_existing_config_and_dangling_pid_link(self) -> None:
        self._make_backup()
        before = {
            name: (self.state / name).read_bytes() for name in self.original
        }
        identities = {
            name: (self.state / name).stat().st_ino for name in self.original
        }
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup)
        validate.assert_not_called()
        for name in self.original:
            self.assertEqual((self.state / name).read_bytes(), before[name])
            self.assertEqual((self.state / name).stat().st_ino, identities[name])

        for name in self.original:
            (self.state / name).unlink()
        (self.state / "tunnel-client.pid").symlink_to(self.state / "missing-target")
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup)
        validate.assert_not_called()
        self.assertFalse((self.state / "xray-server.json").exists())

    def test_replace_is_opt_in_and_restores_both_validated_configs(self) -> None:
        self._make_backup()
        changed = self._change_current_configs()
        before_ids = {
            name: (self.state / name).stat().st_ino for name in changed
        }
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup, xray_binary="pinned-test-xray")
        validate.assert_not_called()
        for name, data in changed.items():
            self.assertEqual((self.state / name).read_bytes(), data)
            self.assertEqual((self.state / name).stat().st_ino, before_ids[name])

        with mock.patch("transitvpn.xray.validate_configs") as validate:
            restore_configs(
                self.state,
                self.backup,
                xray_binary="pinned-test-xray",
                replace_existing=True,
            )
        validate.assert_called_once_with(
            {
                "server": json.loads(self.original["xray-server.json"]),
                "client": json.loads(self.original["xray-client.json"]),
            },
            binary="pinned-test-xray",
        )
        for name, data in self.original.items():
            restored = self.state / name
            self.assertEqual(restored.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
            self.assertEqual(restored.stat().st_nlink, 1)
            self.assertEqual((self.backup / name).read_bytes(), data)

    def test_replace_validation_refusal_preserves_both_existing_destinations(self) -> None:
        self._make_backup()
        changed = self._change_current_configs()
        before = {
            name: (
                (self.state / name).read_bytes(),
                (self.state / name).stat().st_dev,
                (self.state / name).stat().st_ino,
            )
            for name in changed
        }
        validation_observations: list[tuple[bool, bool, str]] = []

        def reject_backup_client(configs: dict[str, object], *, binary: str) -> None:
            validation_observations.append(
                (
                    configs.get("server") == json.loads(self.original["xray-server.json"]),
                    configs.get("client") == json.loads(self.original["xray-client.json"]),
                    binary,
                )
            )
            raise ValueError("synthetic backup client validation refusal")

        with mock.patch(
            "transitvpn.xray.validate_configs", side_effect=reject_backup_client
        ), self.assertRaises(ConfigBackupError):
            restore_configs(
                self.state,
                self.backup,
                xray_binary="pinned-test-xray",
                replace_existing=True,
            )

        self.assertEqual(validation_observations, [(True, True, "pinned-test-xray")])
        for name, (data, device, inode) in before.items():
            current = (self.state / name).stat()
            self.assertEqual((self.state / name).read_bytes(), data)
            self.assertEqual((current.st_dev, current.st_ino), (device, inode))
        self.assertEqual(
            [path.name for path in self.state.iterdir() if path.name.startswith(".transitvpn-")],
            [],
        )

    def test_replace_refuses_pid_entries_and_symlink_destinations(self) -> None:
        self._make_backup()
        changed = self._change_current_configs()
        before_ids = {
            name: (self.state / name).stat().st_ino for name in changed
        }
        pid_entry = self.state / "tunnel-client.pid"
        pid_entry.symlink_to(self.root / "missing-pid-target")
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup, replace_existing=True)
        validate.assert_not_called()
        pid_entry.unlink()
        for name, data in changed.items():
            self.assertEqual((self.state / name).read_bytes(), data)
            self.assertEqual((self.state / name).stat().st_ino, before_ids[name])

        server = self.state / "xray-server.json"
        outside = self.root / "outside-config"
        server.unlink()
        outside.write_bytes(changed["xray-server.json"])
        outside.chmod(0o600)
        server.symlink_to(outside)
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup, replace_existing=True)
        validate.assert_not_called()
        self.assertTrue(server.is_symlink())
        self.assertEqual(outside.read_bytes(), changed["xray-server.json"])
        self.assertEqual((self.state / "xray-client.json").read_bytes(), changed["xray-client.json"])

    def test_replace_refuses_hard_link_alias(self) -> None:
        self._make_backup()
        self._change_current_configs()
        server = self.state / "xray-server.json"
        outside = self.root / "outside-hardlink"
        os.link(server, outside)
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup, replace_existing=True)
        validate.assert_not_called()
        self.assertEqual(server.stat().st_ino, outside.stat().st_ino)
        self.assertEqual(server.stat().st_nlink, 2)

    def test_replace_rechecks_snapshots_before_commit(self) -> None:
        self._make_backup()
        changed = self._change_current_configs()
        server = self.state / "xray-server.json"
        server_identity = server.stat().st_ino
        concurrent_client = b'{"purpose":"concurrent-update"}\n'
        original_write = __import__("transitvpn.config_backup", fromlist=["_write_private_file"])._write_private_file

        def write_then_change(directory_fd: int, name: str, data: bytes) -> tuple[int, int]:
            identity = original_write(directory_fd, name, data)
            if name.endswith("xray-server.json.tmp"):
                client = self.state / "xray-client.json"
                client.write_bytes(concurrent_client)
            return identity

        with mock.patch("transitvpn.config_backup._write_private_file", side_effect=write_then_change), mock.patch(
            "transitvpn.xray.validate_configs"
        ), self.assertRaises(ConfigBackupError):
            restore_configs(self.state, self.backup, replace_existing=True)
        self.assertEqual(server.read_bytes(), changed["xray-server.json"])
        self.assertEqual(server.stat().st_ino, server_identity)
        self.assertEqual((self.state / "xray-client.json").read_bytes(), concurrent_client)
        self.assertEqual(
            [p.name for p in self.state.iterdir() if p.name.startswith(".transitvpn-")],
            [],
        )

    def test_partial_replace_failure_restores_prior_pair_and_redacts_cli_error(self) -> None:
        self._make_backup()
        changed = self._change_current_configs()
        real_replace = os.replace
        replace_calls = 0

        def fail_second_replace(*args, **kwargs):
            nonlocal replace_calls
            replace_calls += 1
            if replace_calls == 2:
                raise OSError("private synthetic sentinel")
            return real_replace(*args, **kwargs)

        with mock.patch("transitvpn.config_backup.os.replace", side_effect=fail_second_replace), mock.patch(
            "transitvpn.xray.validate_configs"
        ), self.assertRaises(ConfigBackupError) as error:
            restore_configs(self.state, self.backup, replace_existing=True)
        self.assertEqual(str(error.exception), "configuration backup or restore was refused")
        self.assertNotIn("private synthetic sentinel", str(error.exception))
        self.assertEqual(replace_calls, 3)
        for name, data in changed.items():
            path = self.state / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(
            [p.name for p in self.state.iterdir() if p.name.startswith(".transitvpn-")],
            [],
        )

        from transitvpn.cli import main
        from transitvpn.config_backup import ConfigBackupError as RestoreError

        stderr = io.StringIO()
        with mock.patch(
            "transitvpn.config_backup.restore_configs",
            side_effect=RestoreError("private synthetic sentinel"),
        ), redirect_stderr(stderr):
            code = main([
                "config-restore", "--source", str(self.backup), "--replace"
            ])
        self.assertEqual(code, 1)
        self.assertEqual(
            stderr.getvalue(),
            "config-restore: error: trusted configuration backup could not be restored\n",
        )
        self.assertNotIn("private synthetic sentinel", stderr.getvalue())

    def test_xray_validation_refusal_writes_neither_config(self) -> None:
        self._make_backup()
        for name in self.original:
            (self.state / name).unlink()
        with mock.patch(
            "transitvpn.xray.validate_configs", side_effect=RuntimeError("validation refused")
        ), self.assertRaises(ConfigBackupError):
            restore_configs(self.state, self.backup)
        self.assertFalse((self.state / "xray-server.json").exists())
        self.assertFalse((self.state / "xray-client.json").exists())

    def test_backup_refuses_symlink_configuration_source(self) -> None:
        (self.state / "xray-client.json").unlink()
        (self.state / "xray-client.json").symlink_to(self.root / "outside-config")
        (self.root / "outside-config").write_bytes(self.original["xray-client.json"])
        (self.root / "outside-config").chmod(0o600)
        with self.assertRaises(ConfigBackupError):
            self._make_backup()
        self.assertFalse(self.backup.exists())


if __name__ == "__main__":
    unittest.main()
