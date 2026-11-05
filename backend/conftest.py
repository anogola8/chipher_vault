"""
Backend-level conftest. Runs before backend/tests/* is imported.

Django's app registry must be initialized before any `from <app>.models`
import, and pytest-django's collection order isn't fully guaranteed with
testpaths spanning multiple directories. This file removes the guesswork.
"""
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
REPO = BACKEND.parent

for p in (str(BACKEND), str(REPO), str(REPO / "shared")):
    if p not in sys.path:
        sys.path.insert(0, p)

from dotenv import load_dotenv
load_dotenv(REPO / ".env", override=False)

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"

import django
if not getattr(django.apps.apps, "ready", False):
    django.setup()
