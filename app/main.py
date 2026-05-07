from fastapi import FastAPI  # type: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore
from app.routers import analyze
from app.core.config import settings

app = FastAPI(
    title="Email Maliciousness Scorer",
    description="Backend service for Gmail Add-on that scores email maliciousness",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/api/v1", tags=["analyze"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "version": "0.1.0"}