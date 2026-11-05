"""
Usage: python manage.py verify_audit

Exits 0 if the audit chain is intact, 1 if any anomaly is detected.
Read-only.
"""
from django.core.management.base import BaseCommand

from audit.verify import verify_chain


class Command(BaseCommand):
    help = "Verify the SHA-256 hash-linked audit ledger."

    def handle(self, *args, **options):
        r = verify_chain()
        if r.ok:
            self.stdout.write(self.style.SUCCESS(
                f"Audit ledger OK ({r.total} events)"
            ))
            return
        self.stdout.write(self.style.ERROR(
            f"AUDIT LEDGER TAMPERED at seq {r.first_bad_seq}: {r.reason}"
        ))
        for k, v in r.detail.items():
            self.stdout.write(self.style.ERROR(f"  {k}: {v}"))
        raise SystemExit(1)
