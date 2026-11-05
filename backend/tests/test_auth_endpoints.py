"""
Phase 5 auth endpoint tests.

Uses Django's test client through DRF's APIClient, which handles session
cookies the same way a browser would. CSRF enforcement is disabled in tests
via `enforce_csrf_checks=False` (the client's default), because CSRF is
verified by Django's own test suite plus the middleware; what we care about
here is auth flow correctness.
"""
import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import User


@pytest.fixture
def client():
    return APIClient()


def _register(client, email="alice@example.com", password="a-strong-password-1", **extra):
    return client.post(
        reverse("accounts:register"),
        data={"email": email, "password": password, **extra},
        format="json",
    )


# ---------- register ----------

def test_register_creates_user(db, client):
    r = _register(client)
    assert r.status_code == 201, r.content
    assert r.json()["user"]["email"] == "alice@example.com"
    assert User.objects.filter(email="alice@example.com").exists()


def test_register_duplicate_email_rejected(db, client):
    _register(client)
    r = _register(client)
    assert r.status_code == 400
    assert "email" in r.json()


def test_register_weak_password_rejected(db, client):
    r = _register(client, password="short")
    assert r.status_code == 400
    assert "password" in r.json()


def test_register_common_password_rejected(db, client):
    r = _register(client, password="password1234")
    # Django's CommonPasswordValidator catches "password..." families.
    assert r.status_code == 400
    assert "password" in r.json()


def test_register_email_is_lowercased(db, client):
    r = _register(client, email="MiXeD@Example.COM")
    assert r.status_code == 201
    assert r.json()["user"]["email"] == "mixed@example.com"


# ---------- login ----------

def test_login_success(db, client):
    _register(client)
    r = client.post(
        reverse("accounts:login"),
        data={"email": "alice@example.com", "password": "a-strong-password-1"},
        format="json",
    )
    assert r.status_code == 200, r.content
    assert r.json()["user"]["email"] == "alice@example.com"
    assert "csrf_token" in r.json()


def test_login_wrong_password(db, client):
    _register(client)
    r = client.post(
        reverse("accounts:login"),
        data={"email": "alice@example.com", "password": "wrong-password"},
        format="json",
    )
    assert r.status_code == 401
    # Generic message — no account enumeration.
    assert "Invalid credentials" in r.json()["detail"]


def test_login_unknown_user(db, client):
    r = client.post(
        reverse("accounts:login"),
        data={"email": "nobody@example.com", "password": "whatever-long"},
        format="json",
    )
    assert r.status_code == 401
    assert "Invalid credentials" in r.json()["detail"]


def test_login_missing_fields(db, client):
    r = client.post(reverse("accounts:login"), data={}, format="json")
    assert r.status_code == 400


# ---------- me ----------

def test_me_requires_auth(db, client):
    r = client.get(reverse("accounts:me"))
    assert r.status_code in (401, 403)


def test_me_returns_user_after_login(db, client):
    _register(client)
    client.post(
        reverse("accounts:login"),
        data={"email": "alice@example.com", "password": "a-strong-password-1"},
        format="json",
    )
    r = client.get(reverse("accounts:me"))
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["is_owner"] is True
    assert body["is_recipient"] is True


# ---------- logout ----------

def test_logout_clears_session(db, client):
    _register(client)
    client.post(
        reverse("accounts:login"),
        data={"email": "alice@example.com", "password": "a-strong-password-1"},
        format="json",
    )
    r = client.post(reverse("accounts:logout"))
    assert r.status_code == 204
    r2 = client.get(reverse("accounts:me"))
    assert r2.status_code in (401, 403)
