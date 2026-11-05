"""
CipherVault Django settings. Environment is loaded from <repo>/.env.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent
SHARED_DIR = REPO_ROOT / "shared"
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

load_dotenv(REPO_ROOT / ".env", override=False)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    return int(v) if v not in (None, "") else default


SECRET_KEY = _env("DJANGO_SECRET_KEY")
if not SECRET_KEY or SECRET_KEY.startswith("replace-"):
    raise RuntimeError(
        "DJANGO_SECRET_KEY is not set. Put a real value in .env before starting."
    )

DEBUG = _env_bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = [
    h.strip() for h in _env("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
    if h.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "accounts",
    "documents",
    "policies",
    "authorization",
    "audit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "config.middleware.HideServerHeaderMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BACKEND_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

_db_url = _env("DJANGO_DATABASE_URL", "sqlite:///db.sqlite3")
if _db_url.startswith("sqlite:///"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BACKEND_DIR / _db_url[len("sqlite:///"):],
            "OPTIONS": {
                "init_command": "PRAGMA foreign_keys = ON;",
                "transaction_mode": "IMMEDIATE",
                "timeout": 20,
            },
        }
    }
else:
    from urllib.parse import urlparse
    p = urlparse(_db_url)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": p.path.lstrip("/"),
            "USER": p.username,
            "PASSWORD": p.password,
            "HOST": p.hostname,
            "PORT": p.port or 5432,
        }
    }

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "authorize": "30/min",
        "login": "10/min",
    },
}

CORS_ALLOWED_ORIGINS = []
if DEBUG:
    CORS_ALLOWED_ORIGINS = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BACKEND_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = BACKEND_DIR / "media"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# CipherVault config
CV_MASTER_KEY_HEX = _env("CIPHERVAULT_MASTER_KEY")
if not CV_MASTER_KEY_HEX or CV_MASTER_KEY_HEX.startswith("replace-"):
    raise RuntimeError(
        "CIPHERVAULT_MASTER_KEY is not set. Put a 64-hex-char value in .env."
    )
try:
    CV_MASTER_KEY = bytes.fromhex(CV_MASTER_KEY_HEX.strip())
except ValueError:
    raise RuntimeError("CIPHERVAULT_MASTER_KEY is not valid hex")
if len(CV_MASTER_KEY) != 32:
    raise RuntimeError(
        f"CIPHERVAULT_MASTER_KEY must decode to 32 bytes, got {len(CV_MASTER_KEY)}"
    )

CV_MAX_UPLOAD_BYTES = _env_int("CIPHERVAULT_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)
CV_BLOB_ROOT = BACKEND_DIR / "blobs"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "std": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "std"},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}
