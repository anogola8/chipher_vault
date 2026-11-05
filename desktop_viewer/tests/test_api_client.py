from __future__ import annotations

import pytest
import requests

from desktop_viewer.api.client import (
    CipherVaultClient, NetworkError, Unauthorized, Forbidden, NotFound,
    BadRequest, ServerError, ProtocolError, UserInfo,
)


BASE = "http://testserver"


@pytest.fixture
def client():
    return CipherVaultClient(BASE)


def test_register_success(client, requests_mock):
    requests_mock.post(f"{BASE}/api/auth/register/", json={
        "user": {"id": "1", "email": "a@b.co", "display_name": "",
                 "is_owner": True, "is_recipient": True}
    }, status_code=201)
    u = client.register("a@b.co", "strong-password-1")
    assert isinstance(u, UserInfo)
    assert u.email == "a@b.co"


def test_login_success_sets_csrf(client, requests_mock):
    requests_mock.post(f"{BASE}/api/auth/login/", json={
        "user": {"id": "1", "email": "a@b.co", "display_name": "",
                 "is_owner": True, "is_recipient": True},
        "csrf_token": "CSRF_FROM_SERVER",
    })
    u = client.login("a@b.co", "pw")
    assert u.email == "a@b.co"
    assert client._csrf == "CSRF_FROM_SERVER"


def test_login_401_raises_unauthorized(client, requests_mock):
    requests_mock.post(f"{BASE}/api/auth/login/",
                       json={"detail": "Invalid credentials"}, status_code=401)
    with pytest.raises(Unauthorized):
        client.login("a@b.co", "wrong")


def test_authorize_success(client, requests_mock):
    requests_mock.post(f"{BASE}/api/authorize/", json={
        "token": "tok123",
        "expires_at": "2026-01-01T00:02:00Z",
        "session_id": "sid",
        "document_id": "docid",
        "document_title": "Report",
        "remaining_total": 4,
        "remaining_recipient": 2,
        "policy_expires_at": None,
        "watermark_text": "a@b.co | 2026-01-01",
    })
    r = client.authorize("docid")
    assert r.token == "tok123"
    assert r.remaining_total == 4


def test_authorize_403_reports_reason(client, requests_mock):
    requests_mock.post(f"{BASE}/api/authorize/",
                       json={"detail": "access has been revoked"}, status_code=403)
    with pytest.raises(Forbidden) as ei:
        client.authorize("docid")
    assert "revoked" in ei.value.reason


def test_redeem_success(client, requests_mock):
    requests_mock.post(f"{BASE}/api/authorize/redeem/", json={
        "document_key_hex": "00" * 32,
        "nonce_hex": "11" * 12,
        "aad_hex": "22" * 8,
        "document_id": "docid",
        "mime": "application/pdf",
    })
    r = client.redeem("docid", "tok123")
    assert len(r.document_key_hex) == 64
    assert r.mime == "application/pdf"


def test_network_failure_is_network_error(client, requests_mock):
    requests_mock.post(f"{BASE}/api/authorize/",
                       exc=requests.exceptions.ConnectionError("refused"))
    with pytest.raises(NetworkError):
        client.authorize("docid")


def test_timeout_is_network_error(client, requests_mock):
    requests_mock.post(f"{BASE}/api/authorize/",
                       exc=requests.exceptions.Timeout("timed out"))
    with pytest.raises(NetworkError):
        client.authorize("docid")


def test_404_raises_not_found(client, requests_mock):
    requests_mock.get(f"{BASE}/api/auth/me/",
                      json={"detail": "Not found."}, status_code=404)
    with pytest.raises(NotFound):
        client.me()


def test_400_raises_bad_request_with_body(client, requests_mock):
    requests_mock.post(f"{BASE}/api/auth/register/",
                       json={"email": ["taken"]}, status_code=400)
    with pytest.raises(BadRequest) as ei:
        client.register("x@y.co", "pw-long-enough-1")
    assert "email" in ei.value.detail


def test_500_raises_server_error(client, requests_mock):
    requests_mock.post(f"{BASE}/api/authorize/",
                       json={"detail": "boom"}, status_code=500)
    with pytest.raises(ServerError):
        client.authorize("docid")


def test_bad_json_shape_raises_protocol_error(client, requests_mock):
    requests_mock.post(f"{BASE}/api/authorize/", json={"unexpected": True})
    with pytest.raises(ProtocolError):
        client.authorize("docid")


def test_csrf_header_sent_after_login(client, requests_mock):
    requests_mock.post(f"{BASE}/api/auth/login/", json={
        "user": {"id": "1", "email": "a@b.co", "display_name": "",
                 "is_owner": True, "is_recipient": True},
        "csrf_token": "CSRF123",
    })
    client.login("a@b.co", "pw")

    seen = {}
    def _capture(request, context):
        seen["X-CSRFToken"] = request.headers.get("X-CSRFToken")
        context.status_code = 200
        return {"document_key_hex": "00" * 32, "nonce_hex": "11" * 12,
                "aad_hex": "22", "document_id": "d", "mime": "application/pdf"}
    requests_mock.post(f"{BASE}/api/authorize/redeem/", json=_capture)

    client.redeem("d", "t")
    assert seen["X-CSRFToken"] == "CSRF123"
