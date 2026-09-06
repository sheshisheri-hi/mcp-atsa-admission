from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_atsa_admission.models import AllowList, Policy, TrustRoot

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURES


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def trust_root() -> TrustRoot:
    return TrustRoot.from_mapping(load_fixture("trust_root.json"))


@pytest.fixture
def policy() -> Policy:
    return Policy.from_mapping(load_fixture("policy.json"))


@pytest.fixture
def allow_list() -> AllowList:
    return AllowList.from_mapping(load_fixture("allow_list.json"))


@pytest.fixture
def clearance_valid() -> dict:
    return load_fixture("clearance_valid.json")
