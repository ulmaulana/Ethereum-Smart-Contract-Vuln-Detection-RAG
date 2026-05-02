from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack

from src.api.env_loader import has_valid_env_value, load_root_env

load_root_env()

from src.api.schemas import (
    ExplanationResponse,
    PredictionResponse,
    ScanMode,
    ScanRequest,
    ScanResponse,
)
from src.features.handcrafted import extract_features, feature_names
from src.features.rules import extract_rule_features
from src.preprocessing.config import PROCESSED_DIR
from src.preprocessing.solidity_parser import build_header_context, parse_source_file
from src.rag.explainer import explain_with_llm
from src.rag.knowledge_base import KNOWLEDGE_BASE


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = PROJECT_ROOT / "models"
NUM_FOLDS = 5
DEFAULT_THRESHOLD = 0.5
CRITICAL_CLASSES = {
    "reentrancy",
    "access_control",
    "unchecked_low_level_calls",
    "arithmetic",
}
MODELS_BY_MODE: dict[ScanMode, tuple[Path, ...]] = {
    "fast": (MODELS_DIR / "fast", MODELS_DIR),
    "deep": (MODELS_DIR / "deep",),
}
THRESHOLD_FILES_BY_MODE: dict[ScanMode, tuple[Path, ...]] = {
    "fast": (
        PROCESSED_DIR / "threshold_tuning_fast.json",
        PROCESSED_DIR / "threshold_tuning.json",
    ),
    "deep": (
        PROCESSED_DIR / "threshold_tuning_deep.json",
        PROCESSED_DIR / "threshold_tuning.json",
    ),
}
MODEL_VERSION_BY_MODE = {
    "fast": "xgb-fast-hybrid-v2",
    "deep": "xgb-deep-hybrid-v2",
}
STRONG_RULES: dict[str, tuple[str, ...]] = {
    "reentrancy": ("rule_reentrancy_strong",),
    "access_control": (
        "rule_access_control_tx_origin",
        "rule_access_control_no_modifier",
    ),
    "unchecked_low_level_calls": ("rule_unchecked_call_value",),
    "arithmetic": ("rule_arithmetic_pre08_no_safemath",),
}
FAST_RULE_THRESHOLD_MULTIPLIER = 0.6
ML_ONLY_CRITICAL_MULTIPLIER = 2.0
ML_ONLY_CRITICAL_MIN_DELTA = 0.1
ML_ONLY_CRITICAL_FLOOR = 0.2
ProgressCallback = Callable[[str, str, int, int], None]


@dataclass(frozen=True)
class FunctionRecord:
    contract_name: str
    function_name: str
    source: str
    header: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class FeatureRecord:
    function: FunctionRecord
    handcrafted: dict[str, float]
    rules: dict[str, int]


@dataclass(frozen=True)
class FoldArtifacts:
    vectorizer: object
    models: dict[str, object]
    calibrators: dict[str, object]


@dataclass(frozen=True)
class ArtifactBundle:
    scan_mode: ScanMode
    active_classes: tuple[str, ...]
    tuned_thresholds: dict[str, float]
    folds: tuple[FoldArtifacts, ...]
    numeric_feature_names: tuple[str, ...]
    feature_count: int
    model_version: str
    artifacts_root: Path


def _load_active_classes() -> tuple[str, ...]:
    with open(PROCESSED_DIR / "active_classes.json", encoding="utf-8") as handle:
        data = json.load(handle)
    return tuple(data["active"])


def _load_thresholds_for_mode(scan_mode: ScanMode) -> dict[str, float]:
    for threshold_file in THRESHOLD_FILES_BY_MODE[scan_mode]:
        if threshold_file.exists():
            with open(threshold_file, encoding="utf-8") as handle:
                data = json.load(handle)
            return {
                cls: float(info["best_threshold"])
                for cls, info in data.items()
                if isinstance(info, dict) and "best_threshold" in info
            }
    return {}


def _load_feature_names_file(path: Path, fallback: list[str]) -> tuple[str, ...]:
    if path.exists():
        with open(path, encoding="utf-8") as handle:
            return tuple(json.load(handle))
    return tuple(fallback)


@lru_cache(maxsize=1)
def get_fast_numeric_feature_names() -> tuple[str, ...]:
    handcrafted = _load_feature_names_file(
        PROCESSED_DIR / "handcrafted_feature_names.json",
        [f"hc_{name}" for name in feature_names()],
    )
    rule_features = _load_feature_names_file(
        PROCESSED_DIR / "rule_feature_names.json",
        list(STRONG_RULES["reentrancy"])
        + [
            "rule_reentrancy_weak",
            "rule_access_control_tx_origin",
            "rule_access_control_no_modifier",
            "rule_arithmetic_pre08_no_safemath",
            "rule_unchecked_call_value",
            "rule_time_manipulation",
            "rule_bad_randomness",
            "rule_dos_loop_external_call",
            "rule_dos_unbounded_loop",
        ],
    )
    return handcrafted + rule_features


@lru_cache(maxsize=1)
def get_deep_numeric_feature_names() -> tuple[str, ...]:
    handcrafted = _load_feature_names_file(
        PROCESSED_DIR / "handcrafted_feature_names.json",
        [f"hc_{name}" for name in feature_names()],
    )
    tool_features = _load_feature_names_file(
        PROCESSED_DIR / "tool_feature_names.json",
        [],
    )
    rule_features = _load_feature_names_file(
        PROCESSED_DIR / "rule_feature_names.json",
        [],
    )
    return handcrafted + tool_features + rule_features


def get_numeric_feature_names(scan_mode: ScanMode) -> tuple[str, ...]:
    return (
        get_fast_numeric_feature_names()
        if scan_mode == "fast"
        else get_deep_numeric_feature_names()
    )


def _resolve_artifacts_root(scan_mode: ScanMode) -> Path:
    for candidate in MODELS_BY_MODE[scan_mode]:
        if candidate.exists():
            return candidate
    raise RuntimeError(
        f"Tidak ada model artifacts untuk scan mode '{scan_mode}'. "
        "Jalankan training pipeline terbaru terlebih dahulu."
    )


@lru_cache(maxsize=None)
def get_artifacts(scan_mode: ScanMode) -> ArtifactBundle:
    active_classes = _load_active_classes()
    tuned_thresholds = _load_thresholds_for_mode(scan_mode)
    artifacts_root = _resolve_artifacts_root(scan_mode)
    numeric_feature_names = (
        get_deep_numeric_feature_names()
        if scan_mode == "fast" and artifacts_root == MODELS_DIR
        else get_numeric_feature_names(scan_mode)
    )

    folds: list[FoldArtifacts] = []
    tfidf_feature_count = 0
    tfidf_root = artifacts_root / "tfidf"
    xgb_root = artifacts_root / "xgb"
    calibrator_root = artifacts_root / "calibrators"

    for fold in range(NUM_FOLDS):
        tfidf_path = tfidf_root / f"fold_{fold}.pkl"
        if not tfidf_path.exists():
            continue

        vectorizer = joblib.load(tfidf_path)
        if tfidf_feature_count == 0:
            try:
                tfidf_feature_count = len(vectorizer.get_feature_names_out())
            except Exception:
                tfidf_feature_count = 0

        models: dict[str, object] = {}
        calibrators: dict[str, object] = {}
        for vuln_class in active_classes:
            model_path = xgb_root / f"fold_{fold}_{vuln_class}.pkl"
            if model_path.exists():
                models[vuln_class] = joblib.load(model_path)

            calibrator_path = calibrator_root / f"fold_{fold}_{vuln_class}.pkl"
            if calibrator_path.exists():
                calibrators[vuln_class] = joblib.load(calibrator_path)

        if models:
            folds.append(
                FoldArtifacts(
                    vectorizer=vectorizer,
                    models=models,
                    calibrators=calibrators,
                )
            )

    if not folds:
        raise RuntimeError(
            f"Tidak ada model inference yang berhasil dimuat dari '{artifacts_root}'."
        )

    version = MODEL_VERSION_BY_MODE[scan_mode]
    if artifacts_root == MODELS_DIR:
        version = f"{version}-legacy"

    return ArtifactBundle(
        scan_mode=scan_mode,
        active_classes=active_classes,
        tuned_thresholds=tuned_thresholds,
        folds=tuple(folds),
        numeric_feature_names=numeric_feature_names,
        feature_count=len(numeric_feature_names) + tfidf_feature_count,
        model_version=version,
        artifacts_root=artifacts_root,
    )


@lru_cache(maxsize=1)
def get_knowledge_base_map() -> dict[str, dict]:
    kb_map: dict[str, dict] = {}
    for entry in KNOWLEDGE_BASE:
        kb_map.setdefault(entry["category"], entry)
    return kb_map


def parse_contract(source_code: str) -> list[FunctionRecord]:
    parsed = parse_source_file(source_code)
    functions: list[FunctionRecord] = []

    for contract in parsed["contracts"]:
        if contract["kind"] == "interface":
            continue

        header = build_header_context(parsed, contract["name"])
        for fn in contract["functions"]:
            if not (30 <= len(fn["source"]) <= 8_000):
                continue

            functions.append(
                FunctionRecord(
                    contract_name=contract["name"],
                    function_name=fn["name"],
                    source=fn["source"],
                    header=header,
                    start_line=fn["start_line"],
                    end_line=fn["end_line"],
                )
            )

    return functions


def resolve_thresholds(
    mode: str,
    active_classes: tuple[str, ...],
    tuned: dict[str, float],
) -> dict[str, float]:
    thresholds: dict[str, float] = {}
    for vuln_class in active_classes:
        if mode == "tuned":
            thresholds[vuln_class] = tuned.get(vuln_class, DEFAULT_THRESHOLD)
        elif mode == "high_recall":
            base = tuned.get(vuln_class, DEFAULT_THRESHOLD)
            thresholds[vuln_class] = max(0.05, round(base * 0.7, 4))
        else:
            thresholds[vuln_class] = DEFAULT_THRESHOLD
    return thresholds


def format_function_label(function: FunctionRecord) -> str:
    return (
        f"{function.contract_name}::{function.function_name} "
        f"[{function.start_line}-{function.end_line}]"
    )


def build_feature_records(functions: list[FunctionRecord]) -> list[FeatureRecord]:
    feature_records: list[FeatureRecord] = []
    for function in functions:
        handcrafted = {
            f"hc_{name}": float(value)
            for name, value in extract_features(function.source, function.header).items()
        }
        rules = {
            name: int(value)
            for name, value in extract_rule_features(function.source, function.header).items()
        }
        feature_records.append(
            FeatureRecord(
                function=function,
                handcrafted=handcrafted,
                rules=rules,
            )
        )
    return feature_records


def build_numeric_matrix(
    feature_records: list[FeatureRecord],
    numeric_feature_names: tuple[str, ...],
) -> csr_matrix:
    numeric_rows = []
    for record in feature_records:
        numeric_feature_map = {name: 0.0 for name in numeric_feature_names}
        numeric_feature_map.update(record.handcrafted)
        numeric_feature_map.update(record.rules)
        numeric_rows.append(
            [float(numeric_feature_map[name]) for name in numeric_feature_names]
        )
    return csr_matrix(np.array(numeric_rows, dtype=np.float32))


def _apply_calibrator(calibrator: object, scores: np.ndarray) -> np.ndarray:
    if calibrator is None:
        return scores

    if hasattr(calibrator, "predict_proba"):
        return calibrator.predict_proba(scores.reshape(-1, 1))[:, 1]
    if hasattr(calibrator, "predict"):
        calibrated = calibrator.predict(scores)
        return np.clip(np.asarray(calibrated, dtype=np.float32), 0.0, 1.0)
    return scores


def _ml_positive_functions(
    functions: list[FunctionRecord],
    confidence_scores: np.ndarray,
    threshold: float,
) -> list[str]:
    return [
        format_function_label(functions[index])
        for index, confidence in enumerate(confidence_scores)
        if float(confidence) >= threshold
    ]


def _rule_positive_functions(
    feature_records: list[FeatureRecord],
    vuln_class: str,
) -> tuple[list[str], list[str]]:
    rule_names = STRONG_RULES.get(vuln_class, ())
    matched_functions: list[str] = []
    matched_rules: set[str] = set()

    for record in feature_records:
        hits = [
            rule_name
            for rule_name in rule_names
            if int(record.rules.get(rule_name, 0)) == 1
        ]
        if hits:
            matched_functions.append(format_function_label(record.function))
            matched_rules.update(hits)

    return matched_functions, sorted(matched_rules)


def build_predictions(
    functions: list[FunctionRecord],
    threshold_mode: str,
    scan_mode: ScanMode,
    progress_callback: ProgressCallback | None = None,
    total_steps: int = 4,
) -> dict[str, PredictionResponse]:
    artifacts = get_artifacts(scan_mode)
    thresholds = resolve_thresholds(
        threshold_mode,
        artifacts.active_classes,
        artifacts.tuned_thresholds,
    )
    if progress_callback:
        progress_callback(
            "features",
            "Extracting ML and rule features from Solidity functions.",
            32,
            1,
        )
    feature_records = build_feature_records(functions)
    numeric_matrix = build_numeric_matrix(feature_records, artifacts.numeric_feature_names)
    function_sources = [function.source for function in functions]
    if progress_callback:
        progress_callback(
            "classifiers",
            f"Running {len(artifacts.active_classes)} XGBoost classifiers.",
            62 if total_steps == 4 else 72,
            2,
        )

    probability_sum = {
        vuln_class: np.zeros(len(functions), dtype=np.float32)
        for vuln_class in artifacts.active_classes
    }
    probability_count = {vuln_class: 0 for vuln_class in artifacts.active_classes}

    for fold in artifacts.folds:
        tfidf_matrix = fold.vectorizer.transform(function_sources)
        design_matrix = hstack([numeric_matrix, tfidf_matrix]).tocsr()

        for vuln_class, model in fold.models.items():
            scores = model.predict_proba(design_matrix)[:, 1]
            calibrator = fold.calibrators.get(vuln_class)
            calibrated_scores = _apply_calibrator(calibrator, scores)
            probability_sum[vuln_class] += calibrated_scores
            probability_count[vuln_class] += 1

    predictions: dict[str, PredictionResponse] = {}
    for vuln_class in artifacts.active_classes:
        count = probability_count[vuln_class]
        confidence_scores = (
            probability_sum[vuln_class] / count
            if count > 0
            else np.zeros(len(functions), dtype=np.float32)
        )
        threshold = thresholds[vuln_class]
        max_confidence = float(np.max(confidence_scores)) if len(confidence_scores) else 0.0
        ml_functions = _ml_positive_functions(functions, confidence_scores, threshold)
        rule_functions, matched_rules = _rule_positive_functions(feature_records, vuln_class)

        status = "clean"
        decision_basis: list[str] = []
        notable_functions: list[str] = []
        ml_detected = bool(ml_functions)
        strong_rule_hit = bool(rule_functions)

        if ml_detected:
            if vuln_class in CRITICAL_CLASSES and not strong_rule_hit:
                ml_only_threshold = max(
                    threshold * ML_ONLY_CRITICAL_MULTIPLIER,
                    threshold + ML_ONLY_CRITICAL_MIN_DELTA,
                    ML_ONLY_CRITICAL_FLOOR,
                )
                if max_confidence >= ml_only_threshold:
                    status = "detected"
                    decision_basis.append("ml")
                    notable_functions.extend(ml_functions)
            else:
                status = "detected"
                decision_basis.append("ml")
                notable_functions.extend(ml_functions)

        if strong_rule_hit and vuln_class in CRITICAL_CLASSES:
            decision_basis.extend(matched_rules)
            rule_trigger_threshold = max(0.05, round(threshold * FAST_RULE_THRESHOLD_MULTIPLIER, 4))
            if ml_detected or max_confidence >= rule_trigger_threshold:
                status = "detected"
                if "ml" not in decision_basis:
                    decision_basis.insert(0, "hybrid")
            else:
                status = "suspected"
            notable_functions.extend(rule_functions)

        if status == "clean":
            notable_functions = []

        deduped_functions = list(dict.fromkeys(notable_functions))[:8]
        deduped_basis = list(dict.fromkeys(decision_basis))

        predictions[vuln_class] = PredictionResponse(
            status=status,
            detected=status == "detected",
            confidence=round(max_confidence, 4),
            threshold=round(threshold, 4),
            vulnerable_functions=deduped_functions,
            decision_basis=deduped_basis,
        )

    return predictions


def build_explanations(
    request: ScanRequest,
    functions: list[FunctionRecord],
    predictions: dict[str, PredictionResponse],
    progress_callback: ProgressCallback | None = None,
    total_steps: int = 4,
) -> list[ExplanationResponse]:
    if not request.options.include_rag:
        return []
    if not has_valid_env_value("MINIMAX_API_KEY"):
        raise RuntimeError(
            "MINIMAX_API_KEY belum di-set valid di root .env atau .env.local."
        )

    kb_map = get_knowledge_base_map()
    explanations: list[ExplanationResponse] = []
    rag_candidates = [
        (vuln_class, prediction)
        for vuln_class, prediction in predictions.items()
        if prediction.status == "detected"
        or (prediction.status == "suspected" and vuln_class in CRITICAL_CLASSES)
    ]

    if progress_callback:
        candidate_count = len(rag_candidates)
        if candidate_count == 0:
            progress_callback(
                "rag",
                "No eligible findings for RAG explanation. Finalizing scan output.",
                92,
                min(3, total_steps - 1),
            )
        else:
            progress_callback(
                "rag",
                f"Generating RAG explanation for {candidate_count} finding(s).",
                82,
                min(3, total_steps - 1),
            )

    for index, (vuln_class, prediction) in enumerate(rag_candidates, start=1):
        if progress_callback:
            progress_callback(
                "rag",
                f"Generating RAG explanation {index}/{len(rag_candidates)} for {vuln_class}.",
                min(96, 82 + int((index / max(len(rag_candidates), 1)) * 12)),
                min(3, total_steps - 1),
            )

        kb_entry = kb_map.get(vuln_class)
        if not kb_entry:
            continue

        relevant_function = next(
            (
                function
                for function in functions
                if format_function_label(function) in prediction.vulnerable_functions
            ),
            functions[0],
        )

        llm_analysis = explain_with_llm(
            vuln_class,
            relevant_function.source,
            contract_id=relevant_function.contract_name,
            llm_provider=request.options.rag_provider,
        )

        mitigation_markdown = kb_entry["mitigation"]
        if prediction.status == "suspected":
            mitigation_markdown = (
                "Status saat ini **suspected** karena rule keamanan kuat aktif, "
                "tetapi confidence model belum melewati threshold final.\n\n"
                + mitigation_markdown
            )
        if kb_entry["references"]:
            mitigation_markdown = (
                f"{mitigation_markdown}\n\n### Referensi\n"
                + "\n".join(f"- {reference}" for reference in kb_entry["references"])
            )

        explanations.append(
            ExplanationResponse(
                **{
                    "class": vuln_class,
                    "swc_id": kb_entry["swc_id"],
                    "title": kb_entry["title"],
                    "description_markdown": llm_analysis,
                    "mitigation_markdown": mitigation_markdown,
                    "fix_code": kb_entry["fix_code"],
                    "references": list(kb_entry["references"]),
                }
            )
        )

    return explanations


def _validate_scan_mode(scan_mode: ScanMode) -> None:
    if scan_mode == "deep":
        raise ValueError(
            "Deep scan belum tersedia untuk kontrak upload baru karena runtime tool features "
            "belum digenerate saat request. Gunakan fast scan untuk inferensi aplikasi."
        )


def scan_contract(
    request: ScanRequest,
    progress_callback: ProgressCallback | None = None,
) -> ScanResponse:
    _validate_scan_mode(request.options.scan_mode)

    start = time.perf_counter()
    total_steps = 4 if request.options.include_rag else 3
    if progress_callback:
        progress_callback(
            "parse",
            "Parsing Solidity source and extracting function boundaries.",
            12,
            0,
        )
    functions = parse_contract(request.source_code)
    if not functions:
        raise ValueError(
            "Tidak ada function Solidity yang valid untuk dianalisis. "
            "Pastikan source contract lengkap dan bukan input acak."
        )

    predictions = build_predictions(
        functions,
        request.options.threshold_mode,
        request.options.scan_mode,
        progress_callback=progress_callback,
        total_steps=total_steps,
    )
    explanations = build_explanations(
        request,
        functions,
        predictions,
        progress_callback=progress_callback,
        total_steps=total_steps,
    )
    duration_ms = int((time.perf_counter() - start) * 1000)
    artifacts = get_artifacts(request.options.scan_mode)

    return ScanResponse(
        job_id=str(uuid.uuid4()),
        filename=request.filename,
        status="completed",
        scan_duration_ms=duration_ms,
        predictions=predictions,
        explanations=explanations,
        metadata={
            "model_version": artifacts.model_version,
            "features_used": artifacts.feature_count,
            "scan_mode": request.options.scan_mode,
        },
    )
