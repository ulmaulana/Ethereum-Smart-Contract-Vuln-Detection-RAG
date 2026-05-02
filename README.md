# Smart Contract Vulnerability Detector

Deteksi kerentanan pada smart contract Ethereum (Solidity) menggunakan Machine Learning,
dilengkapi penjelasan mitigasi via Retrieval-Augmented Generation (RAG).

## Highlight Hasil

- **Macro F1 (contract-level): 0.579** - 2.78x lebih tinggi dari tool baseline terbaik (Mythril 0.208).
- **WIN 6 dari 7 class** vs 9 SmartBugs baseline tools (Slither, Mythril, Oyente, Securify, dll.).
- Reentrancy F1 = 0.867, Unchecked low-level calls F1 = 0.933.
- **First & only model** yang mendeteksi `bad_randomness` (semua 9 baseline tools = 0.000).
- Validasi case study: detect The DAO hack ($60M) dengan confidence 0.999.

Detail lengkap di `processed/case_study_report.md`, `processed/evaluation_report.md`,
`processed/stage9_production_roadmap.md`, dan `processed/stage10_limitations_future_work.md`.

## Peran Tiga Dataset

Project ini menggunakan tiga dataset SmartBugs dengan peran yang berbeda dan saling melengkapi.

### 1. SmartBugs Curated (143 contracts) - Test Set (Gold Standard)

Dataset kecil tapi berkualitas tinggi. Setiap kontrak sudah di-label manual oleh peneliti
SmartBugs yang tahu pasti vulnerability apa di line berapa. Karena label-nya dapat dipercaya
100%, dataset ini dipakai sebagai acuan kebenaran untuk mengukur akurasi model.

Di pipeline: hanya boleh muncul di TEST side saat evaluasi. Tidak pernah dipakai sendirian
untuk train karena terlalu kecil untuk ML.

### 2. SmartBugs Wild (47,000 contracts) - Training Data (Sumber Volume)

Dataset besar dari mainnet Ethereum, tapi tidak punya label sama sekali - kita tidak tahu
kontrak mana yang vulnerable. Volumenya besar, jadi sangat bernilai untuk training ML, asal
bisa dilabel dulu.

Di pipeline: di-label dengan weak supervision (lihat peran Results) → menghasilkan ~35k
silver-labeled functions. Selalu di TRAIN side, tidak pernah dipakai untuk test karena
label-nya noisy.

### 3. SmartBugs Results (output 9 tools × kedua dataset) - Peran Ganda

Pre-computed analysis output dari 9 SmartBugs tools (Slither, Mythril, Oyente, Securify,
Manticore, MAIAN, Osiris, SmartCheck, HoneyBadger) yang sudah dijalankan ke semua kontrak
Curated dan Wild. Dataset ini punya dua fungsi sekaligus:

**Fungsi A: Label generator untuk Wild.** Untuk setiap kontrak Wild, lihat output 9 tools.
Kalau ≥2 tools setuju kontrak vulnerable di class X → beri silver label positive. Ini cara
unlock 35k training samples dari Wild yang tadinya unlabeled.

**Fungsi B: Input feature ke ML model (106 features).** Output 9 tools bukan dipakai sebagai
predictor langsung, tapi dijadikan input feature ke XGBoost. Model belajar pattern: "kalau
Slither bilang reentrancy DAN Mythril setuju, trust tinggi", atau "kalau Securify sering
false positive di class X, ignore".

### Ringkasan Peran

| Dataset  | Peran 1 Kalimat                                                 |
|----------|-----------------------------------------------------------------|
| Curated  | Acuan kebenaran (gold) untuk **mengukur akurasi** model         |
| Wild     | Sumber **volume training data** (lewat silver labeling)         |
| Results  | **Memberi label** ke Wild + jadi **input feature** ke ML model  |

**Sinergi:** Curated kasih *quality*, Wild kasih *quantity*, Results jadi *jembatan* yang
menghubungkan keduanya plus memperkaya feature.

**Aturan emas:** Test SELALU pakai Curated gold. Train boleh campur Curated + Wild silver.

## Struktur Project

```
.
├── dataset/                              # 3 dataset SmartBugs (input)
│   ├── smartbugs-curated-main/           # 143 kontrak gold-labeled
│   ├── smartbugs-wild-master/            # 47k kontrak mainnet
│   └── smartbugs-results-master/         # output 9 tools (pre-computed)
├── src/
│   ├── preprocessing/                    # Pipeline preprocessing (Stage 1-4)
│   ├── features/                         # Hand-crafted, tool, dan rule features
│   ├── training/                         # Training XGBoost + evaluasi (Stage 5-6)
│   ├── rag/                              # Knowledge base + ChromaDB + explainer (Stage 7)
│   ├── case_study/                       # Validasi 10 hack contracts terkenal (Stage 8)
│   └── api/                              # FastAPI inference backend
├── frontend/                             # Next.js UI (opsional)
├── processed/                            # Output pipeline + reports
├── models/                               # XGBoost models (fast/deep) + TF-IDF vectorizer
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
```

```bash
npm install
```

## Cara Menjalankan Aplikasi

Terminal 1 - Backend API:

```bash
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```

Terminal 2 - Frontend:

```bash
cd frontend
npm run dev
```

Backend membaca `.env` dan `.env.local`. Minimal pastikan:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
MINIMAX_API_KEY=...
```

Endpoint utama:

- `GET  /api/v1/health`
- `POST /api/v1/scan`

Kalau `include_rag=true`, backend memanggil MiniMax untuk explanation berbasis RAG.
Untuk uji inference ML murni tanpa LLM, kirim request dengan `options.include_rag=false`.

## Sumber Dataset

- SmartBugs Curated: https://github.com/smartbugs/smartbugs-curated
- SmartBugs Wild   : https://github.com/smartbugs/smartbugs-wild
- SmartBugs Results: https://github.com/smartbugs/smartbugs-results

Struktur folder lokal yang diharapkan:

- `dataset/smartbugs-curated-main/`
- `dataset/smartbugs-wild-master/`
- `dataset/smartbugs-results-master/`

## Pipeline Lengkap (Stage 1-8)

### Overview

```
+--------------------------------------------------------------------+
| CURATED (143 gold)   WILD (47k raw)        RESULTS (9 tools out)   |
|        |                  |                       |                 |
|        |                  | <-- Tool voting ------+                 |
|        |                  |     (>=2 setuju = silver)               |
|        v                  v                                          |
|  curated_labels      wild_labels (35k silver)                        |
|        |                  |                                          |
|        +--------+---------+                                          |
|                 v                                                    |
|        K-Fold split + Wild pool sampling                             |
|                 v                                                    |
|        Function-level extraction (parser Solidity)                   |
|                 v                                                    |
|        Smart sampling + 53 hand-crafted features                     |
|                 v                                                    |
|        Augment: + 106 tool features <-- (RESULTS dataset)            |
|                  + 10 expert rule features                           |
|                  + 5000 TF-IDF features                              |
|                  = 5,170 features per function                       |
|                 v                                                    |
|        XGBoost 5-Fold CV training                                    |
|        (TRAIN: Curated + Wild silver, TEST: Curated gold)            |
|                 v                                                    |
|        Aggregate to contract-level + threshold tuning                |
|                 v                                                    |
|        Evaluate vs 9 baseline tools (RESULTS)                        |
|                 v                                                    |
|        RAG explanation (ChromaDB + knowledge base)                   |
|                 v                                                    |
|        Case study di 10 famous hack contracts                        |
+--------------------------------------------------------------------+
```

### Stage 1 - Olah Curated (Gold Label)

Input: `dataset/smartbugs-curated-main/dataset/<category>/<file>.sol` +
`vulnerabilities.json`.

Langkah:

1. Parse `vulnerabilities.json` untuk mapping file → kategori → line vulnerability.
2. Untuk setiap `.sol`: baca source, parse function ranges, map vuln line ke function,
   extract header context.
3. Hasil: dataset function-level dengan label gold per function.

Output: `processed/curated_labels.parquet`, `processed/curated_functions.parquet`.

### Stage 2 - Olah Wild + Results (Silver Label via Tool Voting)

Input: kontrak Wild + `smartbugs-results-master/results/<tool>/icse20/<addr>/result.json`.

Langkah:

1. Iterasi setiap kontrak Wild, baca output 9 tools.
2. Mapping nama vulnerability per tool → kategori SmartBugs.
3. Aggregate vote per kategori per kontrak.
4. Apply threshold `>=2 tools` → label silver positive.
5. Filter: skip duplikat, kontrak yang gagal di semua tools, LOC terlalu kecil.

Output: `processed/wild_labels.parquet`, `processed/wild_functions.parquet`,
`processed/wild_pool.parquet`.

### Stage 3 - K-Fold Split

- Curated dibagi 5 fold dengan multi-label stratified split.
- Wild di-sample jadi balanced pool (~19,906 contracts) - selalu di TRAIN side.
- Aturan: TEST hanya gold (Curated), TRAIN bisa campur (Curated + Wild silver).

Output: `processed/curated_folds.parquet`, `processed/wild_pool.parquet`,
`processed/cv_split_summary.json`.

### Stage 4 - Function Extraction + Multi-Source Features

**4a. Function-level extraction** dengan custom Solidity parser
(`src/preprocessing/solidity_parser.py`). Hasil: 972 Curated functions + 591k Wild functions.

**4b. Smart sampling + 53 hand-crafted features.** Sampling per class (5k pos + 15k neg)
→ ~110k functions. Extract regex-based features (`hc_call_value_count`, `hc_has_tx_origin`,
`hc_safemath_used`, dll.).

**4c. Tool features (106 features).** Untuk setiap kontrak, lookup output 9 tools dari
RESULTS dataset → per-detector counts + per-tool totals + per-category votes.

**4d. Expert rule features (10 features).** High-precision deterministic rules
(`rule_reentrancy_strong`, `rule_arithmetic_pre08_no_safemath`, dll.).

Output: `processed/sampled_functions_v2.parquet` (110k rows × 193 columns).

### Stage 5 - Training XGBoost (Multi-Source Fusion)

Pipeline akurasi terbaru menyediakan dua mode:

- **fast**: fitur runtime-available (`hc_* + rule_* + TF-IDF`)
- **deep**: fitur benchmark (`hc_* + rule_* + tool_* + TF-IDF`) → 5,170 features total

Quick run:

```bash
python src/training/stage5_train_xgb_dual.py --mode fast --quick
python src/training/stage5_train_xgb_dual.py --mode deep --quick
python src/training/stage6_evaluate_dual.py
```

5-Fold CV training, satu binary classifier per class. `scale_pos_weight` capped at 5,
`n_estimators=300`, `max_depth=6`. Refine Wild silver labels dengan positive relevance +
safety filter.

Output:

- `models/fast/`, `models/deep/` (joblib XGBoost + TF-IDF vectorizer)
- `processed/predictions_function_level.parquet`
- `processed/metrics_aggregated.json`, `metrics_per_fold.json`

### Stage 6 - Evaluasi Contract-Level + Comparison vs 9 Tools

- Aggregate function predictions → contract level (max probability per class).
- Tuning threshold per class untuk maximize F1.
- Compare hasil dengan 9 baseline tools (lookup di RESULTS dataset).

Output:

- `processed/contract_level_metrics.json`
- `processed/threshold_tuning.json`
- `processed/baseline_comparison.json`
- `processed/evaluation_report.md`
- `processed/benchmark_metrics.json`, `product_readiness.json`

Tampilkan rekap rapi:

```bash
python src/training/show_results.py
```

### Stage 7 - RAG Knowledge Base + Explainer

```bash
python src/rag/build_index.py    # build ChromaDB index dari knowledge base
python src/rag/stage7_demo.py    # end-to-end demo: predict + explain
```

Hasil: predictions ditemani penjelasan vulnerability + mitigasi + kode fix dalam
Bahasa Indonesia, lengkap dengan referensi SWC Registry.

### Stage 8 - Case Study Real-World Hacks

Validasi model di 10 kontrak hack terkenal (The DAO, Parity Wallet, BEC Token,
SmartBillions, GovernMental, dll.) dengan total kerugian historis >$1 miliar.

```bash
python src/case_study/stage8_hack_detection.py            # full report dengan RAG
python src/case_study/stage8_hack_detection.py --no-rag   # versi cepat
```

Output:

- `processed/case_study_report.md` - detailed report per hack + honest analysis
- `processed/case_study_summary.csv`

Detection rate: 4/10 (3 FULL_MATCH + 1 PARTIAL). Honest analysis menjelaskan setiap miss
case dengan technical reason di section "Why Some Detections Failed".

## Strategi Pelabelan

| Sumber                          | Jumlah     | Tipe label | Dipakai untuk      |
|---------------------------------|-----------:|------------|--------------------|
| Curated (vulnerabilities.json)  | 143        | Gold       | Test + Train       |
| Wild + Results (tool voting ≥2) | ~35k       | Silver     | Train (bulk)       |

Test set HANYA berisi gold label - supaya evaluasi tetap valid.

## Taksonomi Vulnerability (DASP Top 10)

`access_control`, `arithmetic`, `bad_randomness`, `denial_of_service`,
`front_running`, `other`, `reentrancy`, `short_addresses`,
`time_manipulation`, `unchecked_low_level_calls`.

7 active classes (yang punya cukup sampel di Curated): semua di atas kecuali `front_running`,
`other`, dan `short_addresses`.

## Dokumentasi Pendukung

- `processed/training_report.md` - function-level metrics per fold
- `processed/evaluation_report.md` - contract-level + comparison vs 9 tools
- `processed/case_study_report.md` - validasi 10 famous hack contracts
- `processed/stage9_production_roadmap.md` - roadmap deploy ke production
- `processed/stage10_limitations_future_work.md` - limitasi + future work + threats to validity

## Lisensi & Atribusi

Project ini menggunakan dataset publik dari ekosistem SmartBugs (Durieux et al., ICSE 2020).
Tools baseline dikembangkan oleh Trail of Bits (Slither, Manticore), ConsenSys (Mythril),
NUS (Oyente, MAIAN), ETH Zurich (Securify), University of Luxembourg (Osiris, HoneyBadger),
dan SmartDec (SmartCheck). Lihat `processed/stage10_limitations_future_work.md` section
"Referensi" untuk daftar paper lengkap. Education purpose only.
