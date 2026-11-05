"""CipherVault .cvault container - creation, serialization, parsing, integrity check."""
from __future__ import annotations

import hashlib
import io
import struct
import uuid
from dataclasses import dataclass

MAGIC = b"CVAULT"
CURRENT_VERSION = 1
NONCE_SIZE = 12
SHA256_SIZE = 32
MAX_MIME_LEN = 128
MAX_ALGO_LEN = 32
MAX_POLICY_REF_LEN = 512
MAX_CIPHERTEXT_LEN = 512 * 1024 * 1024
MAX_AAD_LEN = 64 * 1024
HEADER_FIXED_SIZE = 6 + 2 + 16 + 8 + 4 + 12 + 2 + 2


class CvaultError(Exception):
    pass


class InvalidMagic(CvaultError):
    pass


class UnsupportedVersion(CvaultError):
    pass


class TruncatedFile(CvaultError):
    pass


class CorruptHeader(CvaultError):
    pass


class IntegrityError(CvaultError):
    pass


@dataclass(frozen=True)
class CvaultContainer:
    document_id: uuid.UUID
    version: int
    nonce: bytes
    mime: str
    algorithm: str
    policy_ref: str
    aad: bytes
    ciphertext: bytes

    def header_bytes_for_aad(self) -> bytes:
        return (
            MAGIC
            + struct.pack(">H", self.version)
            + self.document_id.bytes
            + struct.pack(">Q", len(self.ciphertext))
            + struct.pack(">I", len(self.aad))
            + self.nonce
            + struct.pack(">H", len(self.mime.encode("utf-8")))
            + struct.pack(">H", len(self.algorithm.encode("utf-8")))
        )

    def serialize(self) -> bytes:
        mime_b = self.mime.encode("utf-8")
        algo_b = self.algorithm.encode("utf-8")
        pol_b = self.policy_ref.encode("utf-8")
        if len(mime_b) > MAX_MIME_LEN:
            raise CorruptHeader("mime too long")
        if len(algo_b) > MAX_ALGO_LEN:
            raise CorruptHeader("algorithm too long")
        if len(pol_b) > MAX_POLICY_REF_LEN:
            raise CorruptHeader("policy_ref too long")
        body = self.aad + self.ciphertext
        body_sha = hashlib.sha256(body).digest()
        out = io.BytesIO()
        out.write(self.header_bytes_for_aad())
        out.write(mime_b)
        out.write(algo_b)
        out.write(struct.pack(">I", len(pol_b)))
        out.write(pol_b)
        out.write(self.aad)
        out.write(self.ciphertext)
        out.write(body_sha)
        return out.getvalue()

    @classmethod
    def parse(cls, data: bytes) -> "CvaultContainer":
        if len(data) < HEADER_FIXED_SIZE:
            raise TruncatedFile("smaller than fixed header")
        if data[:6] != MAGIC:
            raise InvalidMagic("missing CVAULT magic")
        version = struct.unpack(">H", data[6:8])[0]
        if version != CURRENT_VERSION:
            raise UnsupportedVersion("version %d not supported" % version)
        document_id = uuid.UUID(bytes=data[8:24])
        ciphertext_len = struct.unpack(">Q", data[24:32])[0]
        aad_len = struct.unpack(">I", data[32:36])[0]
        nonce = data[36:48]
        if len(nonce) != NONCE_SIZE:
            raise CorruptHeader("bad nonce")
        mime_len = struct.unpack(">H", data[48:50])[0]
        algo_len = struct.unpack(">H", data[50:52])[0]
        if ciphertext_len > MAX_CIPHERTEXT_LEN:
            raise CorruptHeader("ciphertext_len exceeds hard cap")
        if aad_len > MAX_AAD_LEN:
            raise CorruptHeader("aad_len exceeds hard cap")
        if mime_len > MAX_MIME_LEN or algo_len > MAX_ALGO_LEN:
            raise CorruptHeader("mime/algo length out of bounds")
        pos = HEADER_FIXED_SIZE
        if pos + mime_len > len(data):
            raise TruncatedFile("mime")
        try:
            mime = data[pos:pos + mime_len].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise CorruptHeader("mime not valid utf-8")
        pos += mime_len
        if pos + algo_len > len(data):
            raise TruncatedFile("algorithm")
        try:
            algorithm = data[pos:pos + algo_len].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise CorruptHeader("algorithm not valid utf-8")
        pos += algo_len
        if pos + 4 > len(data):
            raise TruncatedFile("policy_ref_len")
        policy_ref_len = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        if policy_ref_len > MAX_POLICY_REF_LEN:
            raise CorruptHeader("policy_ref too long")
        if pos + policy_ref_len > len(data):
            raise TruncatedFile("policy_ref")
        try:
            policy_ref = data[pos:pos + policy_ref_len].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise CorruptHeader("policy_ref not valid utf-8")
        pos += policy_ref_len
        if pos + aad_len > len(data):
            raise TruncatedFile("aad")
        aad = data[pos:pos + aad_len]
        pos += aad_len
        if pos + ciphertext_len > len(data):
            raise TruncatedFile("ciphertext")
        ciphertext = data[pos:pos + ciphertext_len]
        pos += ciphertext_len
        if pos + SHA256_SIZE > len(data):
            raise TruncatedFile("body_sha256")
        expected_sha = data[pos:pos + SHA256_SIZE]
        pos += SHA256_SIZE
        if pos != len(data):
            raise CorruptHeader("trailing %d bytes after container" % (len(data) - pos))
        actual_sha = hashlib.sha256(aad + ciphertext).digest()
        if actual_sha != expected_sha:
            raise IntegrityError("body_sha256 mismatch")
        return cls(
            document_id=document_id,
            version=version,
            nonce=nonce,
            mime=mime,
            algorithm=algorithm,
            policy_ref=policy_ref,
            aad=aad,
            ciphertext=ciphertext,
        )


def build_container(*, document_id, nonce, mime, algorithm, policy_ref, aad, ciphertext, version=CURRENT_VERSION):
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    return CvaultContainer(
        document_id=document_id,
        version=version,
        nonce=nonce,
        mime=mime,
        algorithm=algorithm,
        policy_ref=policy_ref,
        aad=aad,
        ciphertext=ciphertext,
    )
