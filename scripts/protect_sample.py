"""
End-to-end: log in, upload sample.pdf, download .cvault, self-authorize.

Usage:
  python scripts/protect_sample.py <email> <password> [out_path]

Produces: sample.cvault at repo root (default).
"""
import io
import sys
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8000"


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: python scripts/protect_sample.py <email> <password> [out_path]")
        return 2
    email, password = sys.argv[1], sys.argv[2]
    out_path = Path(sys.argv[3] if len(sys.argv) > 3 else "sample.cvault")
    pdf_path = Path("sample.pdf")
    if not pdf_path.exists():
        print(f"sample.pdf not found. Run make_test_pdf.py first.")
        return 1

    s = requests.Session()
    s.headers["Accept"] = "application/json"

    # 1. Login
    r = s.post(f"{BASE}/api/auth/login/", json={"email": email, "password": password})
    if r.status_code != 200:
        print(f"login failed: {r.status_code} {r.text}")
        return 1
    csrf = r.json()["csrf_token"]
    user = r.json()["user"]
    print(f"logged in as {user['email']}")

    # 2. Upload (multipart)
    headers = {"X-CSRFToken": csrf}
    with open(pdf_path, "rb") as f:
        files = {"file": (pdf_path.name, f, "application/pdf")}
        data = {
            "title": "Viewer Test Document",
            "max_total_openings": "20",
            "max_openings_per_recipient": "20",
            "max_recipients": "5",
        }
        r = s.post(f"{BASE}/api/documents/", data=data, files=files, headers=headers)
    if r.status_code != 201:
        print(f"upload failed: {r.status_code} {r.text}")
        return 1
    doc = r.json()
    doc_id = doc["id"]
    print(f"uploaded document {doc_id} ({doc['title']})")

    # 3. Authorize self as recipient
    r = s.post(
        f"{BASE}/api/documents/{doc_id}/recipients/",
        json={"email": user["email"]},
        headers={**headers, "Content-Type": "application/json"},
    )
    if r.status_code not in (201, 200):
        print(f"recipient add failed: {r.status_code} {r.text}")
        return 1
    print(f"authorized {user['email']} as recipient")

    # 4. Download .cvault
    r = s.get(f"{BASE}/api/documents/{doc_id}/download/")
    if r.status_code != 200:
        print(f"download failed: {r.status_code} {r.text}")
        return 1
    out_path.write_bytes(r.content)
    print(f"saved {out_path} ({len(r.content)} bytes)")
    print(f"\nNow open this file in the viewer:")
    print(f"  Open .cvault file... -> {out_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
