from django.urls import path

from .views import (
    DocumentUploadView, DocumentListView, DocumentDetailView,
    DocumentDownloadView, DocumentRecipientAddView, DocumentRecipientRemoveView,
)

app_name = "documents"

urlpatterns = [
    path("", DocumentUploadView.as_view(), name="upload"),
    path("list/", DocumentListView.as_view(), name="list"),
    path("<uuid:document_id>/", DocumentDetailView.as_view(), name="detail"),
    path("<uuid:document_id>/download/", DocumentDownloadView.as_view(), name="download"),
    path("<uuid:document_id>/recipients/", DocumentRecipientAddView.as_view(), name="recipient_add"),
    path("<uuid:document_id>/recipients/<str:email>/", DocumentRecipientRemoveView.as_view(), name="recipient_remove"),
]
