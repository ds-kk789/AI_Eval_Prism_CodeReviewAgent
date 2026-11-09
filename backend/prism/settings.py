"""Paths, environment and config. API keys are read here and handed only to the LLM gateway."""
from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from pathlib import Path

import yaml
from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BACKEND_DIR / "config"
DATA_DIR = BACKEND_DIR / "data"
SAMPLES_ROOT = DATA_DIR                      # request paths look like "samples/b01_user_lookup.py"
GOLDEN_FILE = DATA_DIR / "golden" / "v1.jsonl"
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
SCHEMAS_DIR = BACKEND_DIR / "schemas"
RUNS_DIR = Path(os.environ.get("PRISM_RUNS_DIR", BACKEND_DIR / "runs"))

load_dotenv(BACKEND_DIR / ".env", override=False)
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")
os.environ.setdefault("DEEPEVAL_TELEMETRY_OPT_OUT", "YES")

import logging  # noqa: E402

for _name in ("casbin", "presidio-analyzer", "presidio_analyzer", "httpx", "google_genai"):
    logging.getLogger(_name).setLevel(logging.WARNING)


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    return value if value not in ("", None) else default


@lru_cache
def load_yaml(name: str) -> dict:
    return yaml.safe_load((CONFIG_DIR / name).read_text(encoding="utf-8"))


def budgets() -> dict:
    return load_yaml("budgets.yaml")


def thresholds() -> dict:
    return load_yaml("thresholds.yaml")


def users() -> dict[str, str]:
    return load_yaml("roles.yaml")["users"]


def build() -> str:
    """v0 = flawed build with planted weaknesses, v1 = hardened build."""
    b = (env("PRISM_BUILD", "v1") or "v1").lower()
    if b not in ("v0", "v1"):
        raise ValueError(f"PRISM_BUILD must be v0 or v1, not {b!r}")
    return b


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "missing"


@lru_cache
def provenance() -> dict:
    """Hashes recorded in every audit entry (Task 1.7): golden dataset and both dependency locks."""
    return {
        "dataset_sha256": sha256_file(GOLDEN_FILE)[:16],
        "deps_sha256": sha256_file(BACKEND_DIR / "requirements.lock")[:16],
        "redteam_deps_sha256": sha256_file(BACKEND_DIR / "requirements-redteam.lock")[:16],
    }
