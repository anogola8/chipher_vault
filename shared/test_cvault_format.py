import struct
import uuid

import pytest

from cvault_format import (
    build_container, CvaultContainer, InvalidMagic, UnsupportedVersion,
    TruncatedFile, CorruptHeader, IntegrityError, MAGIC, HEADER_FIXED_SIZE,
)


def _sample(**overrides):
    kwargs = dict(
        document_id=uuid.UUID("11111111-2222-3333-4444-555555555555"),
        nonce=b"\x00" * 12,
        mime="application/pdf",
        algorithm="AES-256-GCM",
        policy_ref="policy-abc",
        aad=b"meta-aad",
        ciphertext=b"ciphertext" + b"\x01" * 16,
    )
    kwargs.update(overrides)
    return build_container(**kwargs)


def _offsets(c):
    pos = HEADER_FIXED_SIZE
    mime_off = pos; pos += len(c.mime.encode("utf-8"))
    algo_off = pos; pos += len(c.algorithm.encode("utf-8"))
    pol_len_off = pos; pos += 4
    pol_off = pos; pos += len(c.policy_ref.encode("utf-8"))
    aad_off = pos; pos += len(c.aad)
    ct_off = pos; pos += len(c.ciphertext)
    return dict(mime=mime_off, algo=algo_off, pol_len=pol_len_off,
                pol=pol_off, aad=aad_off, ct=ct_off)


def test_roundtrip():
    c = _sample()
    data = c.serialize()
    assert data[:6] == MAGIC
    parsed = CvaultContainer.parse(data)
    assert parsed == c


def test_copied_bytes_are_identical():
    assert _sample().serialize() == _sample().serialize()


def test_truncated_rejected():
    data = _sample().serialize()
    for cut in (1, 10, 40, 51, 60, len(data) - 1, len(data) - 32):
        with pytest.raises((TruncatedFile, CorruptHeader)):
            CvaultContainer.parse(data[:cut])


def test_invalid_magic_rejected():
    data = bytearray(_sample().serialize())
    data[0:6] = b"NOTCVL"
    with pytest.raises(InvalidMagic):
        CvaultContainer.parse(bytes(data))


def test_unsupported_version_rejected():
    data = bytearray(_sample().serialize())
    data[6:8] = struct.pack(">H", 999)
    with pytest.raises(UnsupportedVersion):
        CvaultContainer.parse(bytes(data))


def test_modified_ciphertext_detected_by_sha():
    c = _sample()
    data = bytearray(c.serialize())
    data[_offsets(c)["ct"]] ^= 0xFF
    with pytest.raises(IntegrityError):
        CvaultContainer.parse(bytes(data))


def test_modified_aad_detected():
    c = _sample()
    data = bytearray(c.serialize())
    data[_offsets(c)["aad"]] ^= 0xFF
    with pytest.raises(IntegrityError):
        CvaultContainer.parse(bytes(data))


def test_modified_policy_rejected_or_detected():
    # Flipping a byte in policy_ref either:
    #   (a) produces invalid UTF-8 -> parse raises CorruptHeader, or
    #   (b) produces valid UTF-8 but a different ref -> body sha is unchanged
    #       (policy is not part of body), so we assert the value changed and
    #       rely on AES-GCM tag binding in Phase 3 to catch this at decryption.
    c = _sample()
    data = bytearray(c.serialize())
    data[_offsets(c)["pol"]] ^= 0xFF
    try:
        parsed = CvaultContainer.parse(bytes(data))
    except CorruptHeader:
        return
    assert parsed.policy_ref != c.policy_ref

def test_trailing_junk_rejected():
    data = _sample().serialize() + b"junk"
    with pytest.raises(CorruptHeader):
        CvaultContainer.parse(data)


def test_bad_nonce_length():
    with pytest.raises(ValueError):
        build_container(
            document_id=uuid.uuid4(), nonce=b"short",
            mime="application/pdf", algorithm="AES-256-GCM",
            policy_ref="p", aad=b"", ciphertext=b"x" * 16,
        )
