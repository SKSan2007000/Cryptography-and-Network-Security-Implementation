from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.routers import (
    auth, users, transfers, security, trust,
    digital_twin, security_lab, notifications, admin
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure storage directory exists
    storage_base = Path(settings.STORAGE_PATH).resolve()
    storage_base.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="SentinelCrypt Secure Transfer Platform",
    description="Trust-Aware Secure File Transfer Platform Using Hybrid Cryptography with Continuous Integrity Verification and Dynamic Threat Response",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3456",
        "http://127.0.0.1:3456",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
@app.get("/api/status")
def health_check():
    return {
        "status": "ONLINE",
        "service": "SentinelCrypt FastAPI Backend",
        "database": "PostgreSQL 17 (SQLAlchemy 2.x)",
        "security": "Hybrid Cryptography (AES-256-GCM / RSA-OAEP-2048 / SHA-256)",
        "version": "2.0.0"
    }


# Include Routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(transfers.router)
app.include_router(security.router)
app.include_router(trust.router)
app.include_router(digital_twin.router)
app.include_router(security_lab.router)
app.include_router(notifications.router)
app.include_router(admin.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
