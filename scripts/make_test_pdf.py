"""Generate a minimal 3-page PDF for viewer testing."""
import sys
import pymupdf

out = sys.argv[1] if len(sys.argv) > 1 else "sample.pdf"

doc = pymupdf.open()
for i, header in enumerate(["Page One", "Page Two", "Page Three"], start=1):
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text((72, 100), header, fontsize=28)
    page.insert_text((72, 160), f"This is page {i} of a CipherVault test document.",
                     fontsize=14)
    page.insert_text((72, 200), "If you can read this, decryption succeeded.",
                     fontsize=14)
    page.insert_text((72, 240), "If this page carries a red tiled watermark, the viewer works.",
                     fontsize=12)

doc.save(out)
doc.close()
print(f"Wrote {out}")
