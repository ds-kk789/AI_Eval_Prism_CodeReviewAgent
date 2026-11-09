"""Offline test setup: runs and LLM cache go to a temp folder; no API keys are used."""
import os
import shutil
import tempfile
from pathlib import Path

os.environ["PRISM_RUNS_DIR"] = tempfile.mkdtemp(prefix="prism_test_runs_")
for k in ("GOOGLE_API_KEY", "GROQ_API_KEY", "GROQ_API_KEY_2"):
    os.environ[k] = ""                               # tests must never reach a real provider

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_cache():
    from prism import llm
    shutil.rmtree(llm.CACHE_DIR, ignore_errors=True)
    yield


@pytest.fixture
def run_id(request):
    return f"test_{request.node.name}"


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(Path(os.environ["PRISM_RUNS_DIR"]), ignore_errors=True)
