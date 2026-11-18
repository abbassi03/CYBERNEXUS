"""WSGI entry point for Gunicorn and other production WSGI servers."""
from app import create_app

app = create_app()
