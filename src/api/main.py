from __future__ import annotations

import os

from fastapi import BackgroundTasks, FastAPI, HTTPException

from src.api.env_loader import has_valid_env_value, load_root_env
from src.api.jobs import create_scan_job, get_scan_job, run_scan_job

load_root_env()

from src.api.schemas import HealthResponse, ScanJobResponse, ScanRequest, ScanResponse
from src.api.service import scan_contract


app = FastAPI(
    title="Smart Contract Vulnerability Detector API",
    version="1.0.0",
)


@app.get("/api/v1/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        api="smart-contract-vuln-detector",
        rag_provider="minimax",
        minimax_configured=has_valid_env_value("MINIMAX_API_KEY"),
    )


@app.post("/api/v1/scan", response_model=ScanResponse)
def scan_endpoint(payload: ScanRequest) -> ScanResponse:
    try:
        return scan_contract(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Internal scan error. Periksa model artifacts, RAG index, dan konfigurasi MiniMax.",
        )


@app.post("/api/v1/scan/jobs", response_model=ScanJobResponse, status_code=202)
def start_scan_job(payload: ScanRequest, background_tasks: BackgroundTasks) -> ScanJobResponse:
    job = create_scan_job(payload)
    background_tasks.add_task(run_scan_job, job.job_id, payload)
    return job


@app.get("/api/v1/scan/jobs/{job_id}", response_model=ScanJobResponse)
def get_scan_job_status(job_id: str) -> ScanJobResponse:
    job = get_scan_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job tidak ditemukan.")
    return job


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "Smart Contract Vulnerability Detector API is running."}
