"""Verify that the test runner is declared without importing that test runner."""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path


PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
DEVELOPMENT_GROUP_NAMES = {"dev", "development", "test", "tests"}


def _requirement_name(requirement: str) -> str:
    """Extract and normalize the distribution name from a PEP 508 requirement."""
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    if match is None:
        return ""
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


class DevelopmentDependencyContractTests(unittest.TestCase):
    def test_pytest_is_declared_in_a_development_or_test_group(self) -> None:
        with PYPROJECT.open("rb") as stream:
            metadata = tomllib.load(stream)

        optional_groups = metadata.get("project", {}).get("optional-dependencies", {})
        dependency_groups = metadata.get("dependency-groups", {})
        candidate_groups = {
            name: requirements
            for groups in (optional_groups, dependency_groups)
            if isinstance(groups, dict)
            for name, requirements in groups.items()
            if name.lower() in DEVELOPMENT_GROUP_NAMES
        }

        self.assertTrue(
            candidate_groups,
            "pyproject.toml must expose a development/test dependency group "
            "(dev, development, test, or tests)",
        )

        declared_names = {
            _requirement_name(requirement)
            for requirements in candidate_groups.values()
            if isinstance(requirements, list)
            for requirement in requirements
            if isinstance(requirement, str)
        }
        self.assertIn(
            "pytest",
            declared_names,
            "pyproject.toml development/test dependency group must declare pytest",
        )


if __name__ == "__main__":
    unittest.main()
