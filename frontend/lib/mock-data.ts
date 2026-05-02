import { VULN_CLASSES } from "@/lib/constants";
import type {
  Explanation,
  Prediction,
  ScanRequest,
  ScanResponse,
  VulnerabilityKey,
} from "@/lib/types";
import { vulnKeys } from "@/lib/types";

function clamp(value: number) {
  return Math.max(0.01, Math.min(0.99, value));
}

function hashString(value: string) {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash |= 0;
  }

  return Math.abs(hash);
}

function detectFunctions(source: string) {
  const matches = source.match(/function\s+([A-Za-z0-9_]+)/g) ?? [];
  return matches.map((item) => item.replace("function", "").trim());
}

function keywordSignal(source: string, key: VulnerabilityKey) {
  const normalized = source.toLowerCase();
  const has = (fragment: string) => normalized.includes(fragment);

  switch (key) {
    case "reentrancy":
      return has(".call{") || has(".call(") || has("delegatecall");
    case "access_control":
      return has("onlyowner") || has("owner") || has("admin");
    case "arithmetic":
      return has("++") || has("--") || has("unchecked");
    case "bad_randomness":
      return has("block.timestamp") || has("blockhash") || has("keccak256");
    case "denial_of_service":
      return has("for (") || has("while (") || has("transfer(");
    case "time_manipulation":
      return has("block.timestamp") || has("now");
    case "unchecked_low_level_calls":
      return has(".call(") || has("delegatecall") || has("send(");
    default:
      return false;
  }
}

function buildPrediction(
  key: VulnerabilityKey,
  source: string,
  hash: number,
  functions: string[],
): Prediction {
  const baseThresholds: Record<VulnerabilityKey, number> = {
    reentrancy: 0.45,
    access_control: 0.1,
    arithmetic: 0.8,
    bad_randomness: 0.15,
    denial_of_service: 0.4,
    time_manipulation: 0.1,
    unchecked_low_level_calls: 0.95,
  };

  const signal = keywordSignal(source, key);
  const jitter = ((hash % 17) + key.length) / 100;
  const confidence = clamp(signal ? 0.68 + jitter : 0.04 + jitter / 3);
  const vulnerableFunctions = signal ? functions.slice(0, 2) : [];
  const detected = confidence >= baseThresholds[key];

  return {
    status: detected ? "detected" : signal ? "suspected" : "clean",
    detected,
    confidence,
    threshold: baseThresholds[key],
    vulnerable_functions: vulnerableFunctions,
    decision_basis: signal ? ["mock-heuristic"] : [],
  };
}

function buildExplanation(key: VulnerabilityKey, prediction: Prediction): Explanation {
  const meta = VULN_CLASSES[key];

  return {
    class: key,
    swc_id: meta.swc_id,
    title: meta.label,
    description_markdown: `**${meta.label}** terdeteksi dengan confidence \`${Math.round(
      prediction.confidence * 100,
    )}%\`. Sistem menemukan pola yang relevan dengan kategori ini pada source contract yang di-scan.`,
    mitigation_markdown:
      "Gunakan validasi yang eksplisit, perketat kontrol akses, dan ubah urutan eksekusi agar state internal diperbarui sebelum external interaction dilakukan.",
    fix_code: `// ${meta.label}\nfunction patchedExample() external {\n    // apply checks-effects-interactions and strict validation here\n}`,
    references: [`https://swcregistry.io/docs/${meta.swc_id}`],
  };
}

export function createMockScanResponse(
  request: ScanRequest,
  reason = "Backend unavailable, using local mock analysis.",
): ScanResponse {
  const functions = detectFunctions(request.source_code);
  const hash = hashString(request.source_code + request.filename);

  const predictions = vulnKeys.reduce(
    (accumulator, key) => {
      accumulator[key] = buildPrediction(key, request.source_code, hash, functions);
      return accumulator;
    },
    {} as Record<VulnerabilityKey, Prediction>,
  );

  const explanations = vulnKeys
    .filter((key) => predictions[key].detected)
    .map((key) => buildExplanation(key, predictions[key]));

  return {
    job_id: `mock-${hash}`,
    filename: request.filename,
    status: "completed",
    scan_duration_ms: 220 + (hash % 180),
    predictions,
    explanations,
    metadata: {
      model_version: "mock-v1.0.0",
      features_used: 5170,
      scan_mode: request.options.scan_mode,
    },
    fallback: {
      enabled: true,
      reason,
    },
  };
}
