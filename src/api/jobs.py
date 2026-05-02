from __future__ import annotations

import threading
import uuid

from src.api.schemas import ScanJobResponse, ScanMode, ScanProgress, ScanRequest, ScanResponse
from src.api.service import scan_contract


_jobs: dict[str, ScanJobResponse] = {}
_jobs_lock = threading.Lock()


def _total_steps(include_rag: bool) -> int:
    return 4 if include_rag else 3


def _queued_progress(request: ScanRequest) -> ScanProgress:
    return ScanProgress(
        phase="queued",
        message="Scan job queued. Menunggu worker backend memulai analisis.",
        progress_percent=3,
        step_index=0,
        total_steps=_total_steps(request.options.include_rag),
        scan_mode=request.options.scan_mode,
        include_rag=request.options.include_rag,
    )


def create_scan_job(request: ScanRequest) -> ScanJobResponse:
    job_id = str(uuid.uuid4())
    job = ScanJobResponse(
        job_id=job_id,
        status="queued",
        progress=_queued_progress(request),
    )
    with _jobs_lock:
        _jobs[job_id] = job
    return job


def get_scan_job(job_id: str) -> ScanJobResponse | None:
    with _jobs_lock:
        return _jobs.get(job_id)


def _store_job(job_id: str, job: ScanJobResponse) -> None:
    with _jobs_lock:
        _jobs[job_id] = job


def update_scan_job(
    job_id: str,
    *,
    status: str,
    phase: str,
    message: str,
    progress_percent: int,
    step_index: int,
    total_steps: int,
    scan_mode: ScanMode,
    include_rag: bool,
    result: ScanResponse | None = None,
    error: str | None = None,
) -> None:
    job = ScanJobResponse(
        job_id=job_id,
        status=status,
        progress=ScanProgress(
            phase=phase,
            message=message,
            progress_percent=max(0, min(progress_percent, 100)),
            step_index=step_index,
            total_steps=total_steps,
            scan_mode=scan_mode,
            include_rag=include_rag,
        ),
        result=result,
        error=error,
    )
    _store_job(job_id, job)


def run_scan_job(job_id: str, request: ScanRequest) -> None:
    total_steps = _total_steps(request.options.include_rag)

    def report_progress(
        phase: str,
        message: str,
        progress_percent: int,
        step_index: int,
    ) -> None:
        update_scan_job(
            job_id,
            status="running",
            phase=phase,
            message=message,
            progress_percent=progress_percent,
            step_index=step_index,
            total_steps=total_steps,
            scan_mode=request.options.scan_mode,
            include_rag=request.options.include_rag,
        )

    try:
        result = scan_contract(request, progress_callback=report_progress)
    except Exception as exc:
        update_scan_job(
            job_id,
            status="failed",
            phase="failed",
            message="Scan gagal diproses di backend.",
            progress_percent=100,
            step_index=max(total_steps - 1, 0),
            total_steps=total_steps,
            scan_mode=request.options.scan_mode,
            include_rag=request.options.include_rag,
            error=str(exc),
        )
        return

    update_scan_job(
        job_id,
        status="completed",
        phase="completed",
        message="Scan complete.",
        progress_percent=100,
        step_index=max(total_steps - 1, 0),
        total_steps=total_steps,
        scan_mode=request.options.scan_mode,
        include_rag=request.options.include_rag,
        result=result,
    )
