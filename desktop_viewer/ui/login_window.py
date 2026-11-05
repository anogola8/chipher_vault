"""
Main GUI window.

Page 0: Login / Register.
Page 1: Document Viewer (Open .cvault, Authorize, Decrypt, Render).
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QStackedWidget, QStatusBar,
    QVBoxLayout, QWidget, QFileDialog,
)

from desktop_viewer.api.client import (
    CipherVaultClient, UserInfo, ClientError, Forbidden,
)
from desktop_viewer.crypto.decrypt import decrypt_cvault, peek_document_id
from desktop_viewer.ui.pdf_viewer import PDFViewerWidget


DEFAULT_BASE_URL = os.environ.get("CV_API_URL", "http://127.0.0.1:8000")


# --- Background Worker for Auth/Decrypt ---
class _AuthWorker(QThread):
    ok = Signal(object, object)  # (AuthorizeResult, bytes) -> pdf bytes
    fail = Signal(str)

    def __init__(self, client: CipherVaultClient, cvault_bytes: bytes, doc_id: uuid.UUID):
        super().__init__()
        self._client = client
        self._cvault_bytes = cvault_bytes
        self._doc_id_str = str(doc_id)

    def run(self):
        try:
            # 1. Authorize
            auth_res = self._client.authorize(self._doc_id_str)
            # 2. Redeem
            material = self._client.redeem(self._doc_id_str, auth_res.token)
            # 3. Decrypt
            pdf_bytes = decrypt_cvault(self._cvault_bytes, material)
            
            self.ok.emit(auth_res, pdf_bytes)
        except Forbidden as e:
            self.fail.emit(f"Access denied: {e.reason}")
        except ClientError as e:
            self.fail.emit(f"Network/Server error: {e}")
        except Exception as e:
            self.fail.emit(f"Decryption failed: {e}")


# --- Login/Register Worker ---
class _LoginWorker(QThread):
    ok = Signal(object)
    fail = Signal(str)

    def __init__(self, client, email, password):
        super().__init__()
        self._client = client
        self._email = email
        self._password = password

    def run(self):
        try:
            self.ok.emit(self._client.login(self._email, self._password))
        except Exception as e:
            self.fail.emit(str(e))


class _RegisterWorker(QThread):
    ok = Signal(object)
    fail = Signal(str)

    def __init__(self, client, email, password):
        super().__init__()
        self._client = client
        self._email = email
        self._password = password

    def run(self):
        try:
            self.ok.emit(self._client.register(self._email, self._password))
        except Exception as e:
            self.fail.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        super().__init__()
        self.setWindowTitle("CipherVault Viewer")
        self.resize(900, 700)

        self.client = CipherVaultClient(base_url)
        self._user: Optional[UserInfo] = None
        self._worker: Optional[QThread] = None

        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_login_page())
        self._stack.addWidget(self._build_viewer_page())
        self.setCentralWidget(self._stack)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage(f"Server: {base_url}")

    # --- Page: Login ---
    def _build_login_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        
        title = QLabel("Sign in to CipherVault")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        outer.addWidget(title)

        form = QFormLayout()
        self._email = QLineEdit()
        self._email.setPlaceholderText("you@example.com")
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.Password)
        form.addRow("Email", self._email)
        form.addRow("Password", self._password)
        outer.addLayout(form)

        buttons = QHBoxLayout()
        self._btn_login = QPushButton("Log in")
        self._btn_register = QPushButton("Register")
        buttons.addWidget(self._btn_login)
        buttons.addWidget(self._btn_register)
        outer.addLayout(buttons)

        self._login_error = QLabel("")
        self._login_error.setStyleSheet("color: #b00020;")
        self._login_error.setWordWrap(True)
        outer.addWidget(self._login_error)
        outer.addStretch(1)

        self._btn_login.clicked.connect(self._do_login)
        self._btn_register.clicked.connect(self._do_register)
        return page

    # --- Page: Viewer ---
    def _build_viewer_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        # Top bar
        top_bar = QHBoxLayout()
        self._user_label = QLabel("(not logged in)")
        self._user_label.setStyleSheet("font-weight: bold;")
        top_bar.addWidget(self._user_label)
        
        top_bar.addStretch(1)
        
        self._btn_open = QPushButton("Open .cvault file...")
        self._btn_open.clicked.connect(self._do_open_file)
        top_bar.addWidget(self._btn_open)

        self._btn_logout = QPushButton("Log out")
        self._btn_logout.clicked.connect(self._do_logout)
        top_bar.addWidget(self._btn_logout)

        outer.addLayout(top_bar)

        # The viewer widget
        self._pdf_viewer = PDFViewerWidget()
        outer.addWidget(self._pdf_viewer)

        # Info label (remaining opens)
        self._info_label = QLabel("")
        self._info_label.setStyleSheet("color: gray;")
        outer.addWidget(self._info_label)

        return page

    # --- Actions ---
    def _do_login(self):
        email = self._email.text().strip().lower()
        password = self._password.text()
        if not email or not password:
            self._login_error.setText("Email and password required.")
            return
        
        self._login_error.setText("")
        self._status.showMessage("Logging in...")
        self._btn_login.setEnabled(False)
        
        self._worker = _LoginWorker(self.client, email, password)
        self._worker.ok.connect(self._on_login_ok)
        self._worker.fail.connect(self._on_login_fail)
        self._worker.start()

    def _do_register(self):
        email = self._email.text().strip().lower()
        password = self._password.text()
        if not email or not password:
            self._login_error.setText("Email and password required.")
            return
        
        self._login_error.setText("")
        self._status.showMessage("Registering...")
        self._btn_login.setEnabled(False)
        self._btn_register.setEnabled(False)
        
        self._worker = _RegisterWorker(self.client, email, password)
        self._worker.ok.connect(self._on_login_ok)
        self._worker.fail.connect(self._on_login_fail)
        self._worker.start()

    def _on_login_ok(self, user: UserInfo):
        self._user = user
        self._status.showMessage(f"Logged in as {user.email}")
        self._btn_login.setEnabled(True)
        self._btn_register.setEnabled(True)
        self._user_label.setText(f"Signed in as {user.email}")
        self._stack.setCurrentIndex(1)

    def _on_login_fail(self, msg: str):
        self._status.showMessage("Login failed")
        self._btn_login.setEnabled(True)
        self._btn_register.setEnabled(True)
        self._login_error.setText(msg)

    def _do_logout(self):
        try:
            self.client.logout()
        except Exception:
            pass
        self._user = None
        self._password.clear()
        self._pdf_viewer.close_document()
        self._stack.setCurrentIndex(0)
        self._status.showMessage("Logged out")

    def _do_open_file(self):
        if not self._user:
            return

        path, _ = QFileDialog.getOpenFileName(
            self, "Open Protected Document", "", "CipherVault Files (*.cvault);;All Files (*)"
        )
        if not path:
            return

        try:
            cvault_bytes = Path(path).read_bytes()
            doc_id = peek_document_id(cvault_bytes)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not read file:\\n{e}")
            return

        self._status.showMessage("Authorizing...")
        self._btn_open.setEnabled(False)

        self._worker = _AuthWorker(self.client, cvault_bytes, doc_id)
        self._worker.ok.connect(self._on_auth_ok)
        self._worker.fail.connect(self._on_auth_fail)
        self._worker.start()

    def _on_auth_ok(self, auth_res, pdf_bytes: bytes):
        self._btn_open.setEnabled(True)
        self._status.showMessage("Document unlocked")
        
        self._pdf_viewer.load(pdf_bytes, auth_res.watermark_text)
        
        # Update info label
        exp = auth_res.policy_expires_at or "Never"
        self._info_label.setText(
            f"Document: {auth_res.document_title} | "
            f"Opens remaining: {auth_res.remaining_recipient} | "
            f"Expires: {exp}"
        )

    def _on_auth_fail(self, msg: str):
        self._btn_open.setEnabled(True)
        self._status.showMessage("Authorization failed")
        QMessageBox.warning(self, "Access Denied", msg)


def main() -> int:
    import sys
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
