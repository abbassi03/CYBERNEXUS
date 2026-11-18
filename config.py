"""Application configuration for CYBERNEXUS."""
import os
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    pass


class Config:
    SECRET_KEY = os.environ.get("CYBERNEXUS_SECRET_KEY", "dev-only-change-this-secret-key")
    DATABASE_PATH = os.environ.get("CYBERNEXUS_DATABASE", str(BASE_DIR / "instance" / "cybernexus.db"))
    INGEST_API_KEY = os.environ.get("CYBERNEXUS_INGEST_KEY", "")
    BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("CYBERNEXUS_ADMIN_PASSWORD", "")
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("CYBERNEXUS_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    JSON_SORT_KEYS = False
