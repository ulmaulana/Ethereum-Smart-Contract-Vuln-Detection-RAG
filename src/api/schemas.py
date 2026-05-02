from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


VulnerabilityKey = Literal[
    "reentrancy",
    "access_control",
    "arithmetic",
    "bad_randomness",
    "denial_of_service",
    "time_manipulation",
    "unchecked_low_level_calls",
]
PredictionStatus = Literal["clean", "suspected", "detected"]
ScanMode = Literal["fast", "deep"]
ScanJobStatus = Literal["queued", "running", "completed", "failed"]
ScanPhase = Literal["queued", "parse", "features", "classifiers", "rag", "completed", "failed"]


class ScanOptions(BaseModel):
    include_rag: bool = True
    rag_provider: Literal["minimax"] = "minimax"
    threshold_mode: Literal["default", "tuned", "high_recall"] = "tuned"
    scan_mode: ScanMode = "fast"


class ScanRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    source_code: str = Field(..., min_length=20, max_length=200_000)
    filename: str = Field(..., min_length=1, max_length=255)
    options: ScanOptions = Field(default_factory=ScanOptions)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        if not value.endswith(".sol"):
            raise ValueError("Filename harus berakhiran .sol")
        if "/" in value or "\\" in value:
            raise ValueError("Filename tidak boleh mengandung path separator")
        return value


class PredictionResponse(BaseModel):
    status: PredictionStatus
    detected: bool
    confidence: float
    threshold: float
    vulnerable_functions: list[str]
    decision_basis: list[str]


class ExplanationResponse(BaseModel):
    class_: VulnerabilityKey = Field(alias="class")
    swc_id: str
    title: str
    description_markdown: str
    mitigation_markdown: str
    fix_code: str
    references: list[str]

    model_config = ConfigDict(populate_by_name=True)


class ScanMetadata(BaseModel):
    model_version: str
    features_used: int
    scan_mode: ScanMode


class ScanResponse(BaseModel):
    job_id: str
    filename: str
    status: Literal["completed"]
    scan_duration_ms: int
    predictions: dict[VulnerabilityKey, PredictionResponse]
    explanations: list[ExplanationResponse]
    metadata: ScanMetadata


class ScanProgress(BaseModel):
    phase: ScanPhase
    message: str
    progress_percent: int = Field(..., ge=0, le=100)
    step_index: int = Field(..., ge=0)
    total_steps: int = Field(..., ge=1)
    scan_mode: ScanMode
    include_rag: bool


class ScanJobResponse(BaseModel):
    job_id: str
    status: ScanJobStatus
    progress: ScanProgress
    result: ScanResponse | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    api: str
    rag_provider: Literal["minimax"]
    minimax_configured: bool
