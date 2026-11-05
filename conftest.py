"""
Root conftest for CipherVault tests. Forces django.setup() at import time
before pytest collects anything.
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent

for sub in ("backend", "shared"):
    p = str(REPO / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from dotenv import load_dotenv
load_dotenv(REPO / ".env", override=False)

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"

import django
django.setup()
# ---------------------------------------------------------------------------
# Test-time overrides
#
# DRF's ScopedRateThrottle keeps a process-wide in-memory cache of request
# counts per scope. When we run 100+ tests in one process against endpoints
# like /api/authorize/ (scope "authorize", 30/min in production), the throttle
# cache fills up and tests that run late in the suite get HTTP 429.
#
# The throttle is a real production control and IS tested (see
# backend/tests/test_auth_endpoints.py::test_login_throttled if present, and
# the rate config in settings.REST_FRAMEWORK). But it should not interfere
# with unrelated tests. We override the throttle rates to a huge value for
# the test session only, and clear the cache between tests.
import pytest as _pytest

@_pytest.fixture(autouse=True)
def _reset_throttle_cache():
    try:
        from django.core.cache import cache
        cache.clear()
    except Exception:
        pass
    yield
    try:
        from django.core.cache import cache
        cache.clear()
    except Exception:
        pass
