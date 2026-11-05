from django.urls import path

from .views import AuthorizeView, RedeemView, RevokeView, ActivityView

app_name = "authorization"

urlpatterns = [
    path("authorize/", AuthorizeView.as_view(), name="authorize"),
    path("authorize/redeem/", RedeemView.as_view(), name="redeem"),
    path("documents/<uuid:document_id>/revoke/", RevokeView.as_view(), name="revoke"),
    path("documents/<uuid:document_id>/activity/", ActivityView.as_view(), name="activity"),
]
