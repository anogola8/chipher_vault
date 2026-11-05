"""
HTTP client for CipherVault backend.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import requests


DEFAULT_TIMEOUT = 15.0


class ClientError(Exception):
    pass


class NetworkError(ClientError):
    pass


class Unauthorized(ClientError):
    pass


class Forbidden(ClientError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class NotFound(ClientError):
    pass


class BadRequest(ClientError):
    def __init__(self, detail: Any):
        self.detail = detail
        super().__init__(str(detail))


class ServerError(ClientError):
    pass


class ProtocolError(ClientError):
    pass


@dataclass(frozen=True)
class UserInfo:
    id: str
    email: str
    display_name: str
    is_owner: bool
    is_recipient: bool


@dataclass(frozen=True)
class AuthorizeResult:
    token: str
    expires_at: str
    session_id: str
    document_id: str
    document_title: str
    remaining_total: int
    remaining_recipient: int
    policy_expires_at: Optional[str]
    watermark_text: str


@dataclass(frozen=True)
class ReleaseMaterial:
    document_key_hex: str
    nonce_hex: str
    aad_hex: str
    document_id: str
    mime: str


class CipherVaultClient:
    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._s = requests.Session()
        self._csrf: Optional[str] = None
        self._user: Optional[UserInfo] = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _headers(self, unsafe: bool) -> dict:
        h = {"Accept": "application/json"}
        if unsafe:
            h["Content-Type"] = "application/json"
            if self._csrf:
                h["X-CSRFToken"] = self._csrf
        return h

    def _handle_response(self, r: requests.Response) -> Any:
        c = self._s.cookies.get("csrftoken")
        if c:
            self._csrf = c

        if r.status_code == 204:
            return None

        try:
            body = r.json() if r.content else None
        except ValueError:
            body = None

        if 200 <= r.status_code < 300:
            return body

        detail = ""
        if isinstance(body, dict):
            detail = body.get("detail") or str(body)

        if r.status_code == 401:
            self._user = None
            raise Unauthorized(detail or "unauthorized")
        if r.status_code == 403:
            raise Forbidden(detail or "forbidden")
        if r.status_code == 404:
            raise NotFound(detail or "not found")
        if r.status_code == 400:
            raise BadRequest(body if body is not None else detail)
        if 500 <= r.status_code < 600:
            raise ServerError(f"{r.status_code}: {detail}")
        raise ProtocolError(f"unexpected status {r.status_code}: {detail}")

    def _post(self, path: str, json_body: Optional[dict] = None) -> Any:
        try:
            r = self._s.post(
                self._url(path),
                json=json_body or {},
                headers=self._headers(unsafe=True),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise NetworkError(str(e))
        return self._handle_response(r)

    def _get(self, path: str) -> Any:
        try:
            r = self._s.get(
                self._url(path),
                headers=self._headers(unsafe=False),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise NetworkError(str(e))
        return self._handle_response(r)

    def _delete(self, path: str) -> Any:
        try:
            r = self._s.delete(
                self._url(path),
                headers=self._headers(unsafe=True),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise NetworkError(str(e))
        return self._handle_response(r)

    def register(self, email: str, password: str, display_name: str = "") -> UserInfo:
        body = self._post("/api/auth/register/", {
            "email": email, "password": password, "display_name": display_name,
        })
        if not isinstance(body, dict) or "user" not in body:
            raise ProtocolError("register: unexpected response shape")
        self._user = self._parse_user(body["user"])
        return self._user

    def login(self, email: str, password: str) -> UserInfo:
        body = self._post("/api/auth/login/", {"email": email, "password": password})
        if not isinstance(body, dict) or "user" not in body:
            raise ProtocolError("login: unexpected response shape")
        if "csrf_token" in body and isinstance(body["csrf_token"], str):
            self._csrf = body["csrf_token"]
        self._user = self._parse_user(body["user"])
        return self._user

    def logout(self) -> None:
        self._post("/api/auth/logout/", {})
        self._user = None
        self._csrf = None

    def me(self) -> UserInfo:
        body = self._get("/api/auth/me/")
        self._user = self._parse_user(body)
        return self._user

    @property
    def current_user(self) -> Optional[UserInfo]:
        return self._user

    def authorize(self, document_id: str) -> AuthorizeResult:
        body = self._post("/api/authorize/", {"document_id": document_id})
        try:
            return AuthorizeResult(
                token=body["token"],
                expires_at=body["expires_at"],
                session_id=body["session_id"],
                document_id=body["document_id"],
                document_title=body["document_title"],
                remaining_total=int(body["remaining_total"]),
                remaining_recipient=int(body["remaining_recipient"]),
                policy_expires_at=body.get("policy_expires_at"),
                watermark_text=body["watermark_text"],
            )
        except (KeyError, TypeError) as e:
            raise ProtocolError(f"authorize: missing field {e}")

    def redeem(self, document_id: str, token: str) -> ReleaseMaterial:
        body = self._post(
            "/api/authorize/redeem/",
            {"document_id": document_id, "token": token},
        )
        try:
            return ReleaseMaterial(
                document_key_hex=body["document_key_hex"],
                nonce_hex=body["nonce_hex"],
                aad_hex=body["aad_hex"],
                document_id=body["document_id"],
                mime=body["mime"],
            )
        except (KeyError, TypeError) as e:
            raise ProtocolError(f"redeem: missing field {e}")

    def revoke(self, document_id: str, reason: str = "") -> None:
        self._post(f"/api/documents/{document_id}/revoke/", {"reason": reason})

    @staticmethod
    def _parse_user(u: dict) -> UserInfo:
        try:
            return UserInfo(
                id=str(u["id"]),
                email=u["email"],
                display_name=u.get("display_name", "") or "",
                is_owner=bool(u["is_owner"]),
                is_recipient=bool(u["is_recipient"]),
            )
        except (KeyError, TypeError) as e:
            raise ProtocolError(f"user: missing field {e}")
