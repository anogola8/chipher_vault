"""
File format conversion for CipherVault.

Accepts common document formats (.docx, .xlsx, .pptx, .odt, .ods, .odp,
.txt, .rtf) and converts them to PDF using LibreOffice's headless mode.

PDFs pass through unchanged. Any other format is rejected.

Security notes:
  - File type is sniffed from magic bytes, NOT from extension. An .exe
    renamed to .docx is rejected at the magic-byte check.
  - LibreOffice runs as a subprocess with a hard timeout. Malicious files
    that hang the converter are killed.
  - The temp directory is per-call, gets cleaned up regardless of outcome.
  - In production this should run in an isolated container with resource
    limits, NOT in the Django worker process. See docs/security_model.md.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path


CONVERTIBLE_EXTENSIONS = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".txt": "text/plain",
    ".rtf": "application/rtf",
}

PDF_MIME = "application/pdf"
PDF_MAGIC = b"%PDF-"
ZIP_MAGIC = b"PK\x03\x04"
RTF_MAGIC = b"{\\rtf"

DEFAULT_TIMEOUT_SECONDS = 60


class ConversionError(Exception):
    pass


class UnsupportedFormat(ConversionError):
    pass


class ConversionFailed(ConversionError):
    pass


class ConversionTimeout(ConversionError):
    pass


class LibreOfficeNotFound(ConversionError):
    pass


@dataclass(frozen=True)
class ConversionResult:
    pdf_bytes: bytes
    source_mime: str
    was_converted: bool


def _find_soffice() -> str:
    override = os.environ.get("SOFFICE_PATH")
    if override and Path(override).is_file():
        return override

    for candidate in (
        r"C:\Program Files\LibreOffice\program\soffice.com",
        r"C:\Program Files\LibreOffice\program\soffice.exe",
        r"C:\Program Files (x86)\LibreOffice\program\soffice.com",
        r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
    ):
        if Path(candidate).is_file():
            return candidate

    on_path = shutil.which("soffice") or shutil.which("soffice.com")
    if on_path:
        return on_path

    raise LibreOfficeNotFound(
        "LibreOffice not found. Install it, set SOFFICE_PATH to the soffice "
        "binary, or put LibreOffice's program/ directory on PATH."
    )


def _validate_extension_hint(filename: str, data: bytes) -> str:
    name = (filename or "").lower()
    ext = Path(name).suffix

    if ext == ".pdf":
        if not data.startswith(PDF_MAGIC):
            raise UnsupportedFormat("file has .pdf extension but does not look like a PDF")
        return ".pdf"

    if ext not in CONVERTIBLE_EXTENSIONS:
        allowed = ", ".join([".pdf"] + sorted(CONVERTIBLE_EXTENSIONS.keys()))
        raise UnsupportedFormat(
            f"unsupported file type: {ext or '(none)'}; allowed: {allowed}"
        )

    if ext == ".txt":
        return ext

    if ext == ".rtf":
        if not data.startswith(RTF_MAGIC):
            raise UnsupportedFormat("file has .rtf extension but does not look like RTF")
        return ext

    if not data.startswith(ZIP_MAGIC):
        raise UnsupportedFormat(
            f"file has {ext} extension but is not a valid Office ZIP container"
        )
    return ext


def convert_to_pdf(
    *,
    filename: str,
    data: bytes,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ConversionResult:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if not data:
        raise UnsupportedFormat("file is empty")

    ext = _validate_extension_hint(filename, bytes(data))
    if ext == ".pdf":
        return ConversionResult(
            pdf_bytes=bytes(data),
            source_mime=PDF_MIME,
            was_converted=False,
        )

    soffice = _find_soffice()
    return _run_libreoffice(
        soffice=soffice,
        data=bytes(data),
        ext=ext,
        timeout_seconds=timeout_seconds,
    )


def _run_libreoffice(
    *,
    soffice: str,
    data: bytes,
    ext: str,
    timeout_seconds: int,
) -> ConversionResult:
    work_dir = Path(tempfile.mkdtemp(prefix=f"cv-convert-{uuid.uuid4().hex[:8]}-"))
    try:
        input_path = work_dir / f"input{ext}"
        input_path.write_bytes(data)

        profile_url = f"file:///{work_dir.as_posix()}/lo_profile"
        cmd = [
            soffice,
            "--headless",
            "--norestore",
            "--nolockcheck",
            f"-env:UserInstallation={profile_url}",
            "--convert-to", "pdf",
            "--outdir", str(work_dir),
            str(input_path),
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise ConversionTimeout(
                f"conversion exceeded {timeout_seconds}s timeout"
            )

        if proc.returncode != 0:
            raise ConversionFailed(
                f"LibreOffice exited with code {proc.returncode}: "
                f"{(proc.stderr or proc.stdout or '').strip()[:200]}"
            )

        expected_pdf = work_dir / "input.pdf"
        if not expected_pdf.exists():
            raise ConversionFailed(
                "LibreOffice did not produce a PDF; stderr: "
                f"{(proc.stderr or '').strip()[:200]}"
            )

        pdf_bytes = expected_pdf.read_bytes()
        if not pdf_bytes.startswith(PDF_MAGIC):
            raise ConversionFailed("LibreOffice output is not a valid PDF")

        return ConversionResult(
            pdf_bytes=pdf_bytes,
            source_mime=CONVERTIBLE_EXTENSIONS[ext],
            was_converted=True,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
