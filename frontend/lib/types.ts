export const vulnKeys = [
  "reentrancy",
  "access_control",
  "arithmetic",
  "bad_randomness",
  "denial_of_service",
  "time_manipulation",
  "unchecked_low_level_calls",
] as const;

export type VulnerabilityKey = (typeof vulnKeys)[number];

export type RagProvider = "minimax";
export type ThresholdMode = "default" | "tuned" | "high_recall";
export type ScanMode = "fast" | "deep";
export type PredictionStatus = "clean" | "suspected" | "detected";
export type ScanJobStatus = "queued" | "running" | "completed" | "failed";
export type ScanPhase =
  | "queued"
  | "parse"
  | "features"
  | "classifiers"
  | "rag"
  | "completed"
  | "failed";

export type ScanOptionsInput = {
  include_rag: boolean;
  rag_provider: RagProvider;
  threshold_mode: ThresholdMode;
  scan_mode: ScanMode;
};

export type ScanRequest = {
  source_code: string;
  filename: string;
  options: ScanOptionsInput;
};

export type Prediction = {
  status: PredictionStatus;
  detected: boolean;
  confidence: number;
  threshold: number;
  vulnerable_functions: string[];
  decision_basis: string[];
};

export type Explanation = {
  class: VulnerabilityKey;
  swc_id: string;
  title: string;
  description_markdown: string;
  mitigation_markdown: string;
  fix_code: string;
  references: string[];
};

export type ScanResponse = {
  job_id: string;
  filename: string;
  status: "completed";
  scan_duration_ms: number;
  predictions: Record<VulnerabilityKey, Prediction>;
  explanations: Explanation[];
  metadata: {
    model_version: string;
    features_used: number;
    scan_mode: ScanMode;
  };
  fallback?: {
    enabled: boolean;
    reason: string;
  };
};

export type ScanProgress = {
  phase: ScanPhase;
  message: string;
  progress_percent: number;
  step_index: number;
  total_steps: number;
  scan_mode: ScanMode;
  include_rag: boolean;
};

export type ScanJobResponse = {
  job_id: string;
  status: ScanJobStatus;
  progress: ScanProgress;
  result: ScanResponse | null;
  error: string | null;
};

export type ScanHistoryItem = {
  id: string;
  timestamp: string;
  request: ScanRequest;
  response: ScanResponse;
};

export type DemoContract = {
  slug: string;
  label: string;
  focus: VulnerabilityKey;
  description: string;
  filename: string;
  source: string;
};
