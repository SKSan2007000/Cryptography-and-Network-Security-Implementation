import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath("."))

from backend.app.main import app
from backend.app.database import engine, Base, SessionLocal


@pytest.fixture(scope="session")
def client():
    # Ensure tables are ready in PostgreSQL
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c
