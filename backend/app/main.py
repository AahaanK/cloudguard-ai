"""
CloudGuardAI - Main Application Server & Serverless Gateway Handler
Exposes REST APIs, serves the enterprise coastal UI dashboard,
and exports the AWS Lambda / API Gateway handler via Mangum.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from mangum import Mangum
import os

from .config import settings
from .api.storage_routes import router as storage_router
from .api.scan_routes import router as scan_router
from .aws.session_manager import aws_session_manager

app = FastAPI(
    title="CloudGuardAI",
    description="Enterprise Cloud Infrastructure Risk Analysis & Security Platform",
    version="1.0.0"
)

# CORS Configuration for API Gateway and Web Clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(storage_router)
app.include_router(scan_router)

@app.get("/api/v1/health", tags=["Health & Status"])
async def health_check():
    """System health check and operational status."""
    aws_status = aws_session_manager.verify_identity()
    return {
        "status": "HEALTHY",
        "app_name": settings.app_name,
        "environment": settings.app_env,
        "storage_backend": settings.storage_backend,
        "database_backend": settings.database_backend,
        "remediation_backend": settings.remediation_backend,
        "aws": aws_status
    }

@app.get("/api/v1/aws/status", tags=["AWS Credential Diagnostics"])
@app.get("/api/aws/status", tags=["AWS Credential Diagnostics"])
async def get_aws_status(refresh: bool = False):
    """
    Returns sanitized AWS credential and identity diagnostics.
    Never exposes secret access keys or raw session tokens.
    """
    return aws_session_manager.verify_identity(force_refresh=refresh)

@app.post("/api/v1/aws/refresh", tags=["AWS Credential Diagnostics"])
@app.post("/api/aws/refresh", tags=["AWS Credential Diagnostics"])
async def refresh_aws_credentials():
    """
    Reloads .env file and environment variables, flushes cached Boto3 session,
    and re-verifies STS caller identity dynamically without server restarts.
    """
    return aws_session_manager.reset_session()

# Frontend Static Files Mount
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", tags=["UI"])
    async def serve_index():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "CloudGuardAI API Online. Frontend index.html not yet built."}

# AWS Lambda Handler for Amazon API Gateway (HTTP API v2 or REST API)
handler = Mangum(app, lifespan="off")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.host, port=settings.port, reload=True)
