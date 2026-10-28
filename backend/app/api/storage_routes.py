"""
CloudGuardAI - Storage & Template Upload REST API Endpoints
Provides authenticated upload, direct-to-S3 presigned URLs, retrieval, and status checking.
"""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query, Response, Request
from fastapi.responses import StreamingResponse
import io
from typing import Optional

from ..storage.manager import storage_manager

router = APIRouter(prefix="/api/v1/storage", tags=["Storage & Ingestion"])

@router.post("/upload-url")
async def get_direct_upload_url(
    request: Request,
    filename: Optional[str] = Form(default=None),
    analysis_id: Optional[str] = Form(default=None),
    expires_in: Optional[int] = Form(default=None)
):
    """
    Generates a presigned direct upload URL (S3 PUT or Local fallback).
    Accepts both Form data and JSON payloads to ensure maximum client compatibility.
    Bypasses API Gateway's 10 MB payload limit for large blueprint uploads.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            if isinstance(body, dict):
                filename = body.get("filename", filename)
                analysis_id = body.get("analysis_id", analysis_id)
                expires_in = body.get("expires_in", expires_in)
        except Exception:
            pass

    if not filename:
        raise HTTPException(status_code=400, detail="Missing required parameter: 'filename'.")

    try:
        url_data = storage_manager.generate_upload_url(
            filename=filename,
            analysis_id=analysis_id,
            expiration_seconds=expires_in or 900
        )
        return {
            "success": True,
            "message": "Authorized direct upload URL generated successfully.",
            "data": url_data
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate upload URL: {str(e)}")

@router.post("/upload")
async def upload_infrastructure_file(
    file: UploadFile = File(...),
    template_type: str = Form(default="auto"),
    analysis_id: Optional[str] = Form(default=None)
):
    """
    Uploads a Terraform (.tf, .tf.json) or CloudFormation (.yaml, .json) template.
    Validates extension, size, computes SHA-256, and stores in S3 (with local fallback).
    """
    try:
        content = await file.read()
        result = storage_manager.store_file(
            content=content,
            filename=file.filename or "template.tf",
            analysis_id=analysis_id,
            is_report=False
        )
        return {
            "success": True,
            "message": "Template uploaded and registered successfully.",
            "data": result
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Storage operation failed: {str(e)}")

@router.get("/file/{file_key:path}")
async def get_storage_file(file_key: str, download: bool = Query(default=False)):
    """Retrieves file content directly from active storage backend."""
    try:
        content, content_type = storage_manager.retrieve_file(file_key)
        filename = file_key.split("/")[-1]

        headers = {}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        else:
            headers["Content-Disposition"] = f'inline; filename="{filename}"'

        return Response(
            content=content,
            media_type=content_type,
            headers=headers
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Requested object '{file_key}' not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve file: {str(e)}")

@router.get("/download-url")
async def get_presigned_download_url(file_key: str = Query(...), expires_in: int = Query(default=900)):
    """Generates a secure, short-lived presigned URL or local access route."""
    try:
        url = storage_manager.get_download_url(file_key, expiration_seconds=expires_in)
        return {
            "success": True,
            "file_key": file_key,
            "download_url": url,
            "expires_in_seconds": expires_in
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status")
async def get_storage_status():
    """Returns storage system health, active backend, and bucket status."""
    return storage_manager.status()
