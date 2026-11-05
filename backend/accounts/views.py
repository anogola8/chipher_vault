"""
Auth endpoints.

All endpoints use DRF's default permission classes (IsAuthenticated), so
`register` and `login` are explicitly marked AllowAny. Everything else is
authenticated by default.
"""
from __future__ import annotations

from django.contrib.auth import authenticate, login, logout, get_user_model
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from .serializers import RegisterSerializer, UserSelfSerializer

User = get_user_model()


@method_decorator(ensure_csrf_cookie, name="dispatch")
class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []     # register does not need a session

    def post(self, request):
        ser = RegisterSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = ser.save()
        return Response(
            {"user": UserSelfSerializer(user).data},
            status=status.HTTP_201_CREATED,
        )


@method_decorator(ensure_csrf_cookie, name="dispatch")
class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        password = request.data.get("password") or ""

        # Deliberately generic error message: do not reveal whether the
        # email exists (account-enumeration defence).
        if not email or not password:
            return Response(
                {"detail": "email and password are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, username=email, password=password)
        if user is None or not user.is_active:
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        login(request, user)
        # Rotate the CSRF cookie for the new session.
        csrf = get_token(request)
        return Response({
            "user": UserSelfSerializer(user).data,
            "csrf_token": csrf,
        })


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSelfSerializer(request.user).data)
