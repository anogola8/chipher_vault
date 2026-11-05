import os
import sys
import uuid
import importlib

import pytest

# Make both shared/ and the repo root importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_HERE, _REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

import cv_crypto
from cv_crypto import (
    generate_document_key, generate_salt, encrypt_pdf, decrypt_pdf,
    wrap_document_key, unwrap_document_key,
    build_body_aad, build_wrap_aad,
    AuthenticationFailed, BadKeyError, KEY_SIZE, NONCE_SIZE, SALT_SIZE,
    load_master_key_from_env, MASTER_KEY_ENV,
)
from cvault_format import CvaultContainer
from backend.crypto.encryption_service import (
    protect_pdf, unprotect_cvault, peek_document_id, peek_policy_ref,
)


# ---------- helpers ----------

def _fake_pdf(n=2048):
    # A minimal valid-ish PDF header plus filler. Crypto doesn't care about
    # PDF structure; the format module treats it as opaque bytes.
    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    return header + os.urandom(n)


def _sample_args():
    return dict(
        document_id=uuid.uuid4(),
        policy_ref="pol-" + uuid.uuid4().hex[:8],
    )


# ---------- crypto primitives ----------

def test_generate_document_key_is_random():
    a = generate_document_key()
    b = generate_document_key()
    assert len(a) == KEY_SIZE
    assert a != b


def test_body_aad_is_deterministic_and_bound():
    hb = b"HEADER"
    pol = b"policy-1"
    app = b"app-metadata"
    a1 = build_body_aad(hb, pol, app)
    a2 = build_body_aad(hb, pol, app)
    assert a1 == a2
    # changing any component changes the AAD
    assert build_body_aad(b"HEADER2", pol, app) != a1
    assert build_body_aad(hb, b"policy-2", app) != a1
    assert build_body_aad(hb, pol, b"app-metadata-2") != a1
    # version prefix is there
    assert a1.startswith(b"CVAULT-BODY-AAD-v1")


def test_encrypt_decrypt_roundtrip():
    key = generate_document_key()
    pt = b"hello world"
    hb = b"\x00" * 52
    aad, nonce, ct = encrypt_pdf(pt, key, header_bytes=hb, policy_ref="p1")
    out = decrypt_pdf(ct, key, aad=aad, nonce=nonce)
    assert out == pt


def test_wrong_key_fails():
    k1 = generate_document_key()
    k2 = generate_document_key()
    aad, nonce, ct = encrypt_pdf(b"data", k1, header_bytes=b"h", policy_ref="p")
    with pytest.raises(AuthenticationFailed):
        decrypt_pdf(ct, k2, aad=aad, nonce=nonce)


def test_tampered_ciphertext_fails():
    key = generate_document_key()
    aad, nonce, ct = encrypt_pdf(b"data", key, header_bytes=b"h", policy_ref="p")
    bad = bytearray(ct)
    bad[0] ^= 0xFF
    with pytest.raises(AuthenticationFailed):
        decrypt_pdf(bytes(bad), key, aad=aad, nonce=nonce)


def test_tampered_aad_fails():
    key = generate_document_key()
    aad, nonce, ct = encrypt_pdf(b"data", key, header_bytes=b"h", policy_ref="p")
    with pytest.raises(AuthenticationFailed):
        decrypt_pdf(ct, key, aad=aad + b"x", nonce=nonce)


def test_tampered_policy_ref_fails():
    key = generate_document_key()
    aad, nonce, ct = encrypt_pdf(b"data", key, header_bytes=b"h", policy_ref="p1")
    # Re-derive AAD with different policy
    aad2 = build_body_aad(b"h", b"p2", b"")
    with pytest.raises(AuthenticationFailed):
        decrypt_pdf(ct, key, aad=aad2, nonce=nonce)


def test_non_32_byte_key_rejected():
    with pytest.raises(BadKeyError):
        encrypt_pdf(b"x", b"short", header_bytes=b"h", policy_ref="p")
    with pytest.raises(BadKeyError):
        decrypt_pdf(b"x" * 32, b"short", aad=b"a", nonce=b"\x00" * 12)


def test_bad_nonce_length_rejected():
    key = generate_document_key()
    with pytest.raises(cv_crypto.CryptoError):
        decrypt_pdf(b"x" * 32, key, aad=b"a", nonce=b"short")


# ---------- key wrapping ----------

def test_wrap_unwrap_roundtrip():
    mk = generate_document_key()
    dek = generate_document_key()
    salt = generate_salt()
    doc_hex = str(uuid.uuid4())
    wn, wc = wrap_document_key(mk, dek, document_id_hex=doc_hex, salt=salt)
    back = unwrap_document_key(mk, wn, wc, document_id_hex=doc_hex, salt=salt)
    assert back == dek


def test_unwrap_with_wrong_master_key_fails():
    mk1 = generate_document_key()
    mk2 = generate_document_key()
    dek = generate_document_key()
    salt = generate_salt()
    doc_hex = str(uuid.uuid4())
    wn, wc = wrap_document_key(mk1, dek, document_id_hex=doc_hex, salt=salt)
    with pytest.raises(AuthenticationFailed):
        unwrap_document_key(mk2, wn, wc, document_id_hex=doc_hex, salt=salt)


def test_unwrap_bound_to_document_id():
    mk = generate_document_key()
    dek = generate_document_key()
    salt = generate_salt()
    doc_a = str(uuid.uuid4())
    doc_b = str(uuid.uuid4())
    wn, wc = wrap_document_key(mk, dek, document_id_hex=doc_a, salt=salt)
    with pytest.raises(AuthenticationFailed):
        unwrap_document_key(mk, wn, wc, document_id_hex=doc_b, salt=salt)


def test_unwrap_bound_to_salt():
    mk = generate_document_key()
    dek = generate_document_key()
    s1 = generate_salt()
    s2 = generate_salt()
    doc_hex = str(uuid.uuid4())
    wn, wc = wrap_document_key(mk, dek, document_id_hex=doc_hex, salt=s1)
    with pytest.raises(AuthenticationFailed):
        unwrap_document_key(mk, wn, wc, document_id_hex=doc_hex, salt=s2)


# ---------- env loading ----------

def test_load_master_key_from_env(monkeypatch):
    raw = os.urandom(32).hex()
    monkeypatch.setenv(MASTER_KEY_ENV, raw)
    k = load_master_key_from_env()
    assert k == bytes.fromhex(raw)


def test_load_master_key_missing(monkeypatch):
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    with pytest.raises(RuntimeError):
        load_master_key_from_env()


def test_load_master_key_bad_hex(monkeypatch):
    monkeypatch.setenv(MASTER_KEY_ENV, "not-hex")
    with pytest.raises(RuntimeError):
        load_master_key_from_env()


def test_load_master_key_wrong_length(monkeypatch):
    monkeypatch.setenv(MASTER_KEY_ENV, "00" * 16)  # 16 bytes
    with pytest.raises(RuntimeError):
        load_master_key_from_env()


# ---------- end-to-end via the service ----------

def _roundtrip(pdf, **extra):
    master = generate_document_key()
    args = _sample_args()
    pd = protect_pdf(pdf, master_key=master, **args, **extra)
    out = unprotect_cvault(
        pd.cvault_bytes,
        dek_wrap_nonce=pd.dek_wrap_nonce,
        dek_wrapped=pd.dek_wrapped,
        dek_salt=pd.dek_salt,
        master_key=master,
        expected_document_id=args["document_id"],
        expected_policy_ref=args["policy_ref"],
    )
    return pd, out


def test_service_roundtrip():
    pdf = _fake_pdf()
    pd, out = _roundtrip(pdf)
    assert out == pdf
    assert pd.document_id is not None
    assert pd.policy_ref.startswith("pol-")


def test_service_container_is_not_plaintext():
    pdf = b"%PDF-1.4\nTHIS IS A CANARY STRING\n" + os.urandom(512)
    pd, _ = _roundtrip(pdf)
    assert b"CANARY STRING" not in pd.cvault_bytes


def test_service_peek_helpers():
    pdf = _fake_pdf()
    master = generate_document_key()
    args = _sample_args()
    pd = protect_pdf(pdf, master_key=master, **args)
    assert peek_document_id(pd.cvault_bytes) == args["document_id"]
    assert peek_policy_ref(pd.cvault_bytes) == args["policy_ref"]


def test_service_tampered_header_fails():
    pdf = _fake_pdf()
    master = generate_document_key()
    args = _sample_args()
    pd = protect_pdf(pdf, master_key=master, **args)
    # Flip a byte inside the container's fixed header (document_id region)
    tampered = bytearray(pd.cvault_bytes)
    tampered[10] ^= 0xFF
    with pytest.raises(Exception):
        unprotect_cvault(
            bytes(tampered),
            dek_wrap_nonce=pd.dek_wrap_nonce,
            dek_wrapped=pd.dek_wrapped,
            dek_salt=pd.dek_salt,
            master_key=master,
            expected_document_id=args["document_id"],
            expected_policy_ref=args["policy_ref"],
        )


def test_service_wrong_expected_document_id_fails():
    pdf = _fake_pdf()
    master = generate_document_key()
    args = _sample_args()
    pd = protect_pdf(pdf, master_key=master, **args)
    with pytest.raises(AuthenticationFailed):
        unprotect_cvault(
            pd.cvault_bytes,
            dek_wrap_nonce=pd.dek_wrap_nonce,
            dek_wrapped=pd.dek_wrapped,
            dek_salt=pd.dek_salt,
            master_key=master,
            expected_document_id=uuid.uuid4(),
        )


def test_service_wrong_master_key_fails():
    pdf = _fake_pdf()
    master = generate_document_key()
    wrong = generate_document_key()
    args = _sample_args()
    pd = protect_pdf(pdf, master_key=master, **args)
    with pytest.raises(AuthenticationFailed):
        unprotect_cvault(
            pd.cvault_bytes,
            dek_wrap_nonce=pd.dek_wrap_nonce,
            dek_wrapped=pd.dek_wrapped,
            dek_salt=pd.dek_salt,
            master_key=wrong,
            expected_document_id=args["document_id"],
        )


def test_service_large_pdf():
    pdf = b"%PDF-1.4\n" + os.urandom(1024 * 1024)  # ~1 MB
    pd, out = _roundtrip(pdf)
    assert out == pdf
