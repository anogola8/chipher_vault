"""
Single import surface for the crypto layer, so backend code does not need
to know about shared/ vs backend/crypto/ layout.

Import path note: backend/ is on sys.path both under pytest (via conftest)
and under `manage.py runserver` (Django's default). The package is therefore
importable as `crypto.encryption_service`, NOT `backend.crypto.encryption_service`
— the `backend.` prefix only works when the repo root is also on sys.path,
which is not the case for a plain `manage.py` invocation.
"""
from __future__ import annotations

from crypto.encryption_service import (     # noqa: F401
    ProtectedDocument,
    protect_pdf,
    unprotect_cvault,
    peek_document_id,
    peek_policy_ref,
)
