"""Focused tests for offline in-place application release updates."""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from transitvpn import release
from transitvpn.cli import main


class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="transitvpn-release-data-")
        self.root = Path(self.temporary.name)
        self.destination = self.root / "install"
        self.destination.mkdir()
        self.repository = Path(__file__).resolve().parents[1]
        self.revision_b = "b" * 40
        self.revision_c = "c" * 40
        self.tree_b = {
            "app/one.txt": (0o100644, b"old one\n"),
            "app/two.txt": (0o100644, b"old two\n"),
            "keep.txt": (0o100644, b"keep\n"),
            "pyproject.toml": (0o100644, b"[project]\n"),
            "remove.txt": (0o100644, b"remove\n"),
        }
        self.tree_c = {
            "added.txt": (0o100644, b"new data\n"),
            "app/one.txt": (0o100644, b"new one\n"),
            "app/two.txt": (0o100644, b"new two\n"),
            "keep.txt": (0o100644, b"keep\n"),
            "pyproject.toml": (0o100644, b"[project]\n"),
        }
        self.object_data: dict[str, bytes] = {}
        self.trees = {
            self.revision_b: self.tree_b,
            self.revision_c: self.tree_c,
        }
        for tree in self.trees.values():
            for _mode, data in tree.values():
                self.object_data[hashlib.sha1(data).hexdigest()] = data
        self._write_tree_to_destination(self.tree_b)
        (self.destination / "local-note.txt").write_text("preserve\n", encoding="utf-8")
        self.git_patch = mock.patch("transitvpn.release._run_git", side_effect=self._fake_git)
        self.git_patch.start()
        self.addCleanup(self.git_patch.stop)
        self.addCleanup(self.temporary.cleanup)

    def _write_tree_to_destination(self, tree: dict[str, tuple[int, bytes]]) -> None:
        for relative, (_mode, data) in tree.items():
            path = self.destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)

    def _fake_git(self, repo: Path, *args: str, output_limit: int) -> bytes:
        if args == ("rev-parse", "--show-toplevel"):
            return str(self.repository).encode() + b"\n"
        if args[:2] == ("cat-file", "-e"):
            revision = args[2].removesuffix("^{commit}")
            if revision not in self.trees:
                raise release.ReleaseError("release operation was refused")
            return b""
        if args[:1] == ("ls-tree",):
            revision = args[-1]
            records = []
            for relative, (mode, data) in sorted(self.trees[revision].items()):
                oid = hashlib.sha1(data).hexdigest()
                records.append(f"{mode:06o} blob {oid}\t{relative}".encode() + b"\0")
            return b"".join(records)
        if args[:2] == ("cat-file", "-s"):
            return str(len(self.object_data[args[2]])).encode()
        if args[:2] == ("cat-file", "blob"):
            return self.object_data[args[2]]
        raise AssertionError("unexpected Git operation")

    def test_upgrade_updates_tracked_files_and_preserves_unrelated_data(self) -> None:
        original_keep = (self.destination / "keep.txt").stat().st_ino
        result = release.apply_release(
            self.repository, self.destination, self.revision_b, self.revision_c
        )
        self.assertEqual(result.changed_file_count, 4)
        self.assertFalse(result.no_op)
        self.assertEqual((self.destination / "app/one.txt").read_bytes(), b"new one\n")
        self.assertEqual((self.destination / "app/two.txt").read_bytes(), b"new two\n")
        self.assertEqual((self.destination / "added.txt").read_bytes(), b"new data\n")
        self.assertFalse((self.destination / "remove.txt").exists())
        self.assertEqual((self.destination / "keep.txt").stat().st_ino, original_keep)
        self.assertEqual((self.destination / "local-note.txt").read_text(), "preserve\n")

    def test_same_revision_is_noop_and_preserves_inodes(self) -> None:
        before = {path: (self.destination / path).stat().st_ino for path in self.tree_b}
        result = release.apply_release(
            self.repository, self.destination, self.revision_b, self.revision_b
        )
        self.assertTrue(result.no_op)
        self.assertEqual(result.changed_file_count, 0)
        self.assertEqual(
            before,
            {path: (self.destination / path).stat().st_ino for path in self.tree_b},
        )

    def test_unexpected_old_bytes_are_refused_without_mutation(self) -> None:
        target = self.destination / "app/one.txt"
        target.write_bytes(b"operator edit\n")
        before = target.stat().st_ino
        with self.assertRaises(release.ReleaseError):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.assertEqual(target.read_bytes(), b"operator edit\n")
        self.assertEqual(target.stat().st_ino, before)
        self.assertFalse((self.destination / "added.txt").exists())

    def test_untracked_candidate_collision_is_refused_and_preserved(self) -> None:
        candidate = self.destination / "added.txt"
        candidate.write_text("untracked\n", encoding="utf-8")
        before = candidate.stat().st_ino
        with self.assertRaises(release.ReleaseError):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.assertEqual(candidate.read_text(encoding="utf-8"), "untracked\n")
        self.assertEqual(candidate.stat().st_ino, before)
        self.assertEqual((self.destination / "app/one.txt").read_bytes(), b"old one\n")

    def test_symlinked_tracked_entry_is_refused(self) -> None:
        target = self.destination / "app/one.txt"
        target.unlink()
        target.symlink_to(self.destination / "keep.txt")
        with self.assertRaises(release.ReleaseError):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.assertTrue(target.is_symlink())
        self.assertEqual((self.destination / "keep.txt").read_bytes(), b"keep\n")

    def test_dependency_declaration_change_is_refused(self) -> None:
        changed = dict(self.tree_c)
        changed["pyproject.toml"] = (0o100644, b"[project]\ndependencies=[]\n")
        self.trees[self.revision_c] = changed
        for _mode, data in changed.values():
            self.object_data[hashlib.sha1(data).hexdigest()] = data
        with self.assertRaises(release.ReleaseError):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.assertEqual((self.destination / "app/one.txt").read_bytes(), b"old one\n")

    def test_unsafe_manifest_path_and_nonregular_git_mode_are_refused(self) -> None:
        unsafe = {"../outside.txt": (0o100644, b"text\n")}
        self.trees[self.revision_c] = unsafe
        self.object_data[hashlib.sha1(b"text\n").hexdigest()] = b"text\n"
        with self.assertRaises(release.ReleaseError):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.trees[self.revision_c] = {"bad-link": (0o120000, b"target\n")}
        self.object_data[hashlib.sha1(b"target\n").hexdigest()] = b"target\n"
        with self.assertRaises(release.ReleaseError):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.assertFalse((self.root / "outside.txt").exists())
        self.assertEqual((self.destination / "app/one.txt").read_bytes(), b"old one\n")

    def test_caught_write_failure_restores_prior_release(self) -> None:
        first = self.destination / "app/one.txt"
        second = self.destination / "app/two.txt"
        real_replace = os.replace
        calls = 0

        def fail_second_replace(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic failure")
            return real_replace(*args, **kwargs)

        with (
            mock.patch("transitvpn.release.os.replace", side_effect=fail_second_replace),
            self.assertRaisesRegex(release.ReleaseError, "prior release was restored"),
        ):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.assertEqual(first.read_bytes(), b"old one\n")
        self.assertEqual(second.read_bytes(), b"old two\n")
        self.assertFalse((self.destination / "added.txt").exists())
        self.assertEqual((self.destination / "local-note.txt").read_text(), "preserve\n")
        self.assertFalse(list(self.destination.rglob(".transitvpn-release-*.tmp")))

    def test_rollback_preserves_an_unexpected_concurrent_edit(self) -> None:
        first = self.destination / "app/one.txt"
        real_replace = os.replace
        calls = 0

        def race_on_second_replace(src, dst, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                first.write_bytes(b"concurrent edit\n")
                raise OSError("synthetic failure after external edit")
            return real_replace(src, dst, *args, **kwargs)

        with (
            mock.patch("transitvpn.release.os.replace", side_effect=race_on_second_replace),
            self.assertRaisesRegex(release.ReleaseError, "rollback was incomplete"),
        ):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )
        self.assertEqual(first.read_bytes(), b"concurrent edit\n")
        self.assertEqual((self.destination / "app/two.txt").read_bytes(), b"old two\n")
        self.assertFalse((self.destination / "added.txt").exists())

    def test_rollback_continues_after_a_parent_becomes_a_symlink(self) -> None:
        old_root = b"old root\n"
        new_root = b"new root\n"
        self.tree_b["a-root.txt"] = (0o100644, old_root)
        self.tree_c["a-root.txt"] = (0o100644, new_root)
        for data in (old_root, new_root):
            self.object_data[hashlib.sha1(data).hexdigest()] = data
        root_entry = self.destination / "a-root.txt"
        root_entry.write_bytes(old_root)
        root_entry.chmod(0o644)

        app = self.destination / "app"
        preserved_app = self.destination / "app-preserved"
        symlink_target = self.root / "unrelated-target"
        symlink_target.mkdir()

        def replace_parent_then_fail(*_args, **_kwargs):
            os.rename(app, preserved_app)
            app.symlink_to(symlink_target, target_is_directory=True)
            raise OSError("synthetic late failure")

        with (
            mock.patch(
                "transitvpn.release._remove_expected",
                side_effect=replace_parent_then_fail,
            ),
            self.assertRaisesRegex(release.ReleaseError, "rollback was incomplete"),
        ):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )

        self.assertEqual(root_entry.read_bytes(), old_root)
        self.assertTrue(app.is_symlink())
        self.assertEqual((preserved_app / "one.txt").read_bytes(), b"new one\n")
        self.assertEqual((preserved_app / "two.txt").read_bytes(), b"new two\n")

    def test_directory_cleanup_continues_after_a_parent_becomes_a_symlink(self) -> None:
        other_data = b"other directory data\n"
        volatile_data = b"preserve changed subtree\n"
        self.tree_c["other-dir/child.txt"] = (0o100644, other_data)
        self.tree_c["volatile/child/new.txt"] = (0o100644, volatile_data)
        for data in (other_data, volatile_data):
            self.object_data[hashlib.sha1(data).hexdigest()] = data

        volatile = self.destination / "volatile"
        preserved = self.destination / "volatile-preserved"
        symlink_target = self.root / "unrelated-target"
        symlink_target.mkdir()

        def replace_parent_then_fail(*_args, **_kwargs):
            os.rename(volatile, preserved)
            volatile.symlink_to(symlink_target, target_is_directory=True)
            raise OSError("synthetic late failure")

        with (
            mock.patch(
                "transitvpn.release._remove_expected",
                side_effect=replace_parent_then_fail,
            ),
            self.assertRaisesRegex(release.ReleaseError, "rollback was incomplete"),
        ):
            release.apply_release(
                self.repository, self.destination, self.revision_b, self.revision_c
            )

        self.assertFalse((self.destination / "other-dir").exists())
        self.assertFalse((self.destination / "added.txt").exists())
        self.assertTrue(volatile.is_symlink())
        self.assertEqual((preserved / "child" / "new.txt").read_bytes(), volatile_data)
        self.assertEqual((self.destination / "app" / "one.txt").read_bytes(), b"old one\n")


class ReleaseCliTests(unittest.TestCase):
    def test_upgrade_and_rollback_parser_and_fixed_summary(self) -> None:
        for command in ("upgrade", "rollback"):
            args = [
                command,
                "--source-repo",
                "/trusted/local/repo",
                "--destination",
                "/existing/install",
                "--expected-current",
                "b" * 40,
                "--revision",
                "c" * 40,
            ]
            stdout = io.StringIO()
            with (
                mock.patch(
                    "transitvpn.release.apply_release",
                    return_value=release.ReleaseObservation("b" * 40, "c" * 40, 2, False),
                ),
                redirect_stdout(stdout),
            ):
                self.assertEqual(main(args), 0)
            self.assertEqual(
                stdout.getvalue(),
                f"{command}: applied {'b' * 40} -> {'c' * 40}; changed files=2\n",
            )

    def test_cli_refusal_does_not_print_arguments_or_exception_details(self) -> None:
        secret_path = "/private/do-not-print/credential-state"
        stderr = io.StringIO()
        with (
            mock.patch(
                "transitvpn.release.apply_release",
                side_effect=release.ReleaseError("release operation was refused"),
            ),
            redirect_stderr(stderr),
        ):
            self.assertEqual(
                main(
                    [
                        "upgrade",
                        "--source-repo",
                        "/trusted/repo",
                        "--destination",
                        secret_path,
                        "--expected-current",
                        "b" * 40,
                        "--revision",
                        "c" * 40,
                    ]
                ),
                1,
            )
        self.assertEqual(stderr.getvalue(), "upgrade: error: release operation was refused\n")
        self.assertNotIn(secret_path, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
