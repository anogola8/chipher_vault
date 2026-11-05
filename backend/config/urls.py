from django.contrib import admin
from django.urls import include, path
from django.contrib.auth import views as auth_views
from documents import dashboard_views

urlpatterns = [
    path("admin/", admin.site.urls),
    
    # Web Dashboard
    path("", dashboard_views.dashboard, name="dashboard"),
    path("login/", auth_views.LoginView.as_view(template_name="login.html"), name="login"),
    path("register/", __import__("accounts.web_views", fromlist=["register_page"]).register_page, name="register"),
    path("logout/", auth_views.LogoutView.as_view(next_page="login"), name="logout"),
    path("upload/", dashboard_views.upload_page, name="upload_page"),
    path("download/<uuid:document_id>/", dashboard_views.download_cvault, name="download_cvault"),
    path("add-recipient/<uuid:document_id>/", dashboard_views.add_recipient, name="add_recipient"),

    # API
    path("api/auth/", include("accounts.urls")),
    path("api/documents/", include("documents.urls")),
    path("api/", include("authorization.urls")),
]
