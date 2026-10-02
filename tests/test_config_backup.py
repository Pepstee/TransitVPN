"""Focused safety checks for private two-file Xray configuration recovery."""

from __future__ import annotations

import stat
import tempfile
import unittest
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
        original_server = (self.state / "xray-server.json").read_bytes()
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup)
        validate.assert_not_called()
        self.assertEqual((self.state / "xray-server.json").read_bytes(), original_server)

        for name in self.original:
            (self.state / name).unlink()
        (self.state / "tunnel-client.pid").symlink_to(self.state / "missing-target")
        with mock.patch("transitvpn.xray.validate_configs") as validate, self.assertRaises(
            ConfigBackupError
        ):
            restore_configs(self.state, self.backup)
        validate.assert_not_called()
        self.assertFalse((self.state / "xray-server.json").exists())

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
