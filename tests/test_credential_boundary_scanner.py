"""Adversarial negative controls for the credential-boundary scanner."""

from __future__ import annotations

from contextlib import redirect_stderr
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCANNER_PATH = PROJECT_ROOT / "scripts" / "scan-credentials.py"
SPEC = importlib.util.spec_from_file_location("credential_scanner", SCANNER_PATH)
assert SPEC is not None and SPEC.loader is not None
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


def credential_canaries() -> dict[str, str]:
    """Build credential-shaped values at runtime so fixtures hold no credential."""
    uuid = "7a51e96b" + "-2f34-4c68-9abc-" + "1234567890de"
    return {
        "private-key": "-----BEGIN PRIVATE " + "KEY-----\n" + ("Q" * 32)
        + "\n-----END PRIVATE " + "KEY-----\n",
        "client-import-uri": "ss" + "://" + ("Y" * 20),
        "uuid-credential": uuid,
        "password-token": "api_" + "key=" + "BoundaryCanary987654",
    }


class CredentialBoundaryScannerTests(unittest.TestCase):
    def run_scanner(
        self, root: Path, tracked: set[Path]
    ) -> tuple[int, str]:
        stderr = io.StringIO()
        with (
            mock.patch.object(scanner, "ROOT", root),
            mock.patch.object(scanner, "tracked_files", return_value=tracked),
            redirect_stderr(stderr),
        ):
            status = scanner.main()
        return status, stderr.getvalue()

    def assert_all_credential_classes_fail(self, generated: bool) -> None:
        for rule, canary in credential_canaries().items():
            with self.subTest(rule=rule), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                parent = root / "evidence" if generated else root / "tracked"
                parent.mkdir()
                candidate = parent / f"{rule}.txt"
                candidate.write_text(canary, encoding="utf-8")

                status, diagnostic = self.run_scanner(
                    root, set() if generated else {candidate}
                )

                self.assertEqual(1, status)
                self.assertIn(f"{candidate.relative_to(root)}: {rule}", diagnostic)
                self.assertNotIn(canary, diagnostic)
                self.assertNotIn("BoundaryCanary987654", diagnostic)

    def test_every_prohibited_class_fails_for_tracked_project_artefacts(self) -> None:
        self.assert_all_credential_classes_fail(generated=False)

    def test_every_prohibited_class_fails_in_generated_evidence(self) -> None:
        self.assert_all_credential_classes_fail(generated=True)

    def test_documented_placeholders_pass_without_diagnostics(self) -> None:
        symbolic_words = (
            "PLACEHOLDER",
            "REDACTED",
            "EXAMPLE",
            "DUMMY",
            "SENTINEL",
            "CHANGEME",
        )
        placeholder_lines = [
            "token=" + word + "_VALUE_123456" for word in symbolic_words
        ]
        placeholder_lines.extend(
            (
                "secret={INJECTED_AT_RUNTIME}",
                "00000000" + "-0000-4000-8000-" + "000000000000",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "tracked-placeholder.txt"
            candidate.write_text("\n".join(placeholder_lines), encoding="utf-8")

            status, diagnostic = self.run_scanner(root, {candidate})

        self.assertEqual(0, status)
        self.assertEqual("", diagnostic)


if __name__ == "__main__":
    unittest.main()
