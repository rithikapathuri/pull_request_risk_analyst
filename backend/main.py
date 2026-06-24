from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes import router
from backend.config import get_settings

settings = get_settings()

app = FastAPI(
    title="PR Risk Autopilot",
    description="Analyzes GitHub pull requests for security risk, blast radius, and CVE exposure.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "ok", "env": settings.app_env}