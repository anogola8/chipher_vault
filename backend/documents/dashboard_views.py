from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import default_storage
from django.conf import settings
import uuid

from .models import Document, DocumentKey
from policies.models import DocumentPolicy, DocumentRecipient
from . import storage
from .converter import convert_to_pdf
from backend_crypto import service as crypto_service

@login_required
def dashboard(request):
    docs = Document.objects.filter(owner=request.user).order_by('-created_at')
    return render(request, 'dashboard.html', {'documents': docs})

@login_required
def upload_page(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        max_total = int(request.POST.get('max_total_openings', 10))
        max_per = int(request.POST.get('max_openings_per_recipient', 3))
        file = request.FILES.get('file')
        
        if not file or not title:
            messages.error(request, "Title and file are required.")
            return redirect('upload_page')

        try:
            raw = file.read()
            conv = convert_to_pdf(filename=file.name, data=raw)
            pdf_bytes = conv.pdf_bytes
        except Exception as e:
            messages.error(request, f"Conversion failed: {e}")
            return redirect('upload_page')

        document_id = uuid.uuid4()
        policy_ref = f"pol-{uuid.uuid4().hex[:20]}"

        # Encrypt
        protected = crypto_service.protect_pdf(
            pdf_bytes,
            document_id=document_id,
            policy_ref=policy_ref,
            master_key=settings.CV_MASTER_KEY,
        )

        storage_path = storage.write_blob(document_id, protected.cvault_bytes)

        # Save DB rows
        doc = Document.objects.create(
            id=document_id,
            owner=request.user,
            title=title,
            original_filename=file.name[:255],
            original_size=len(raw),
            plaintext_sha256=protected.plaintext_sha256,
            storage_path=storage_path,
            source_mime=conv.source_mime,
            converted_to_pdf=conv.was_converted,
        )
        DocumentKey.objects.create(
            document=doc,
            dek_wrap_nonce=protected.dek_wrap_nonce,
            dek_wrapped=protected.dek_wrapped,
            dek_salt=protected.dek_salt,
        )
        DocumentPolicy.objects.create(
            document=doc,
            policy_ref=policy_ref,
            max_total_openings=max_total,
            max_openings_per_recipient=max_per,
            max_recipients=5,
        )
        
        messages.success(request, f"Successfully uploaded and protected '{title}'.")
        return redirect('dashboard')

    return render(request, 'upload.html')

@login_required
def download_cvault(request, document_id):
    doc = get_object_or_404(Document, id=document_id, owner=request.user)
    try:
        blob = storage.read_blob(doc.storage_path)
    except FileNotFoundError:
        messages.error(request, "Stored file missing.")
        return redirect('dashboard')
    
    response = HttpResponse(blob, content_type="application/octet-stream")
    safe_name = (doc.title or "document").replace('"', "_")[:200]
    response["Content-Disposition"] = f'attachment; filename="{safe_name}.cvault"'
    return response

@login_required
def add_recipient(request, document_id):
    if request.method == 'POST':
        doc = get_object_or_404(Document, id=document_id, owner=request.user)
        email = request.POST.get('email')
        if email:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                user = User.objects.get(email=email.lower())
                DocumentRecipient.objects.get_or_create(
                    document=doc, user=user,
                    defaults={'added_by': request.user}
                )
                messages.success(request, f"Authorized {email} to view this document.")
            except User.DoesNotExist:
                messages.error(request, "User not found. They must register first.")
    return redirect('dashboard')
