# Smart Contract Vulnerability Detector

Deteksi kerentanan pada smart contract Ethereum (Solidity) menggunakan Machine Learning,
dilengkapi penjelasan mitigasi via Retrieval-Augmented Generation (RAG).

## Struktur

```
.
├── dataset/                              # 3 dataset SmartBugs (input)
│   ├── smartbugs-curated-main/           # 143 kontrak gold-labeled
│   ├── smartbugs-wild-master/            # 47k kontrak mainnet
│   └── smartbugs-results-master/         # hasil 9 tools analisis
├── src/
│   └── preprocessing/                    # Pipeline preprocessing
│       ├── config.py                     # path & konstanta
│       ├── verify_dataset.py             # sanity check dataset
│       ├── stage1_curated.py             # gold labels dari Curated
│       ├── stage2_wild.py                # silver labels dari Wild+Results (tool voting)
│       └── stage3_split.py               # train/val/test split
├── processed/                            # output preprocessing
│   ├── curated_labels.parquet/.csv
│   ├── wild_labels.parquet/.csv
│   ├── train.parquet
│   ├── val.parquet
│   ├── test.parquet
│   └── split_summary.json
└── requirements.txt
```

## Setup

```bash
# Install dependencies (sekali saja)
pip install -r requirements.txt
```

## Sumber Dataset

Project ini menggunakan tiga dataset dari ekosistem SmartBugs:

- SmartBugs Curated: https://github.com/smartbugs/smartbugs-curated
- SmartBugs Results: https://github.com/smartbugs/smartbugs-results
- SmartBugs Wild: https://github.com/smartbugs/smartbugs-wild

Struktur folder lokal yang diharapkan:

- `dataset/smartbugs-curated-main/` dari `smartbugs-curated`
- `dataset/smartbugs-results-master/` dari `smartbugs-results`
- `dataset/smartbugs-wild-master/` dari `smartbugs-wild`

## Menjalankan Pipeline Preprocessing

Jalankan secara berurutan dari folder `src/preprocessing`:

```bash
cd src/preprocessing

# 0) Verifikasi dataset (cek semua file ada)
python verify_dataset.py

# 1) Olah Curated → gold labels
python stage1_curated.py

# 2) Olah Wild + Results → silver labels (tool voting)
python stage2_wild.py

# 3) Unifikasi dan split train/val/test
python stage3_split.py
```

Output preprocessing tersimpan di `processed/`.

## Metodologi Pengolahan Dataset dan Training

Berikut pipeline pengolahan tiga dataset secara konkret, dari data mentah sampai training dan evaluasi model.

### Overview Pipeline

```text
+--------------------------------------------------------------------+
| CURATED (gold)    WILD (raw .sol)    RESULTS (tool outputs)         |
|      |                   |                    |                     |
|      |                   +---------+----------+                     |
|      |                             |                                |
|      |                             v                                |
|      |                 Tool Voting -> Silver Labels                 |
|      |                             |                                |
|      +------------+----------------+                                |
|                   v                                                 |
|   Unified Dataset (Solidity + label per kontrak/function)          |
|                   |                                                 |
|                   v                                                 |
|         Feature Extraction (beberapa jalur)                         |
|                   |                                                 |
|                   v                                                 |
|              Train Model + Evaluasi                                 |
+--------------------------------------------------------------------+
```

### Stage 1: Olah Curated (Gold Label)

Input:

- `smartbugs-curated-main/dataset/<category>/<file>.sol`
- `smartbugs-curated-main/vulnerabilities.json`

Langkah:

1. Parse `vulnerabilities.json` untuk mendapatkan mapping file ke kategori dan line vulnerability.
2. Untuk setiap file `.sol`:
   - baca source code;
   - parse ke AST;
   - extract daftar function beserta rentang barisnya;
   - map line vulnerability ke function yang menaungi line tersebut;
   - extract konteks kontrak seperti state variables, modifiers, dan inheritance.
3. Hasil akhirnya adalah dataset function-level dengan label gold per function.

Contoh struktur output:

```text
+--------------+----------+--------------+--------------+--------+
| contract_id  | function | header_ctx   | source_code  | labels |
+--------------+----------+--------------+--------------+--------+
| Fibonacci..  | withdraw | contract...  | function...  | [AC]   |
| Fibonacci..  | deposit  | contract...  | function...  | []     |
+--------------+----------+--------------+--------------+--------+
```

Output utama:

- `processed/curated_labels.parquet`
- `processed/curated_labels.csv`
- `processed/curated_functions.parquet`

### Stage 2: Olah Wild + Results (Silver Label via Tool Voting)

Input:

- `smartbugs-wild-master/contracts/0x*.sol`
- `smartbugs-results-master/results/<tool>/icse20/0x*/result.json`

Langkah:

1. Iterasi setiap kontrak Wild.
2. Untuk setiap tool, baca `result.json` lalu ekstrak vulnerability yang terdeteksi.
3. Mapping nama vulnerability dari masing-masing tool ke kategori SmartBugs.
4. Aggregate vote per kategori per kontrak.
5. Terapkan aturan labeling berbasis voting:
   - strict: label aktif jika terdeteksi >= 3 tools;
   - moderate: label aktif jika terdeteksi >= 2 tools;
   - loose: label aktif jika terdeteksi >= 1 tool.
6. Rekomendasi yang dipakai adalah threshold `>= 2 tools` untuk menyeimbangkan precision dan recall.
7. Filter data:
   - skip kontrak duplikat;
   - skip kontrak yang gagal diproses oleh semua tools;
   - skip kontrak dengan LOC terlalu kecil.

Contoh struktur output:

```text
+--------------+--------------+------------------+----------+
| contract_id  | source_code  | labels (silver)  | vote_cnt |
+--------------+--------------+------------------+----------+
| 0xABC...     | pragma...    | [reentrancy]     | 3        |
+--------------+--------------+------------------+----------+
```

Output utama:

- `processed/wild_labels.parquet`
- `processed/wild_labels.csv`
- `processed/wild_functions.parquet`
- `processed/wild_pool.parquet`

### Stage 3: Unifikasi dan Split

Dataset gabungan terdiri dari:

- Curated functions dengan label gold berkepercayaan tinggi.
- Wild contracts/functions dengan label silver hasil consensus tools.

Strategi split:

- Training set: Wild silver + 60% Curated gold
- Validation set: 20% Curated gold
- Test set: 20% Curated gold

Catatan:

- Jangan train di Wild lalu test di Wild.
- Curated test set dipakai sebagai ground truth benchmark agar evaluasi tetap valid.

Output utama:

- `processed/train.parquet`
- `processed/val.parquet`
- `processed/test.parquet`
- `processed/cv_split_summary.json`
- `processed/cv_split_report.md`

### Stage 4: Feature Extraction

#### Path A: XGBoost

Tiga jalur fitur dapat digabungkan:

- bytecode/opcode sequence lalu diubah ke TF-IDF;
- hand-crafted features seperti `has_call_value`, `num_external_calls`, `uses_tx_origin`, `has_modifier`, `num_state_vars`, dan fitur statis lain;
- source-token TF-IDF dari kode Solidity.

Semua fitur kemudian digabung menjadi matriks fitur untuk training model gradient boosting.

Artefak yang dihasilkan pada implementasi ini meliputi:

- `processed/sampled_functions.parquet`
- `processed/sampled_functions_v2.parquet`
- `processed/handcrafted_feature_names.json`
- `processed/rule_feature_names.json`
- `processed/tool_feature_names.json`
- model TF-IDF dan XGBoost di folder `models/`

#### Path B: CodeBERT (opsional metodologis)

Untuk pendekatan function-level berbasis transformer:

1. Gabungkan `header_context + source_code`.
2. Tokenisasi hingga panjang maksimum model.
3. Jika melebihi batas token, gunakan sliding window dengan overlap.
4. Hasil akhir berupa tensor `input_ids` dan `attention_mask` untuk fine-tuning model multi-label.

Bagian ini merupakan opsi metodologis jika eksperimen ingin diperluas ke model berbasis transformer.

### Stage 5: Training dan Evaluasi

Training multi-label classification dapat dilakukan dengan dua pendekatan:

- XGBoost: satu model per kategori vulnerability.
- CodeBERT: satu model dengan banyak sigmoid output.

Evaluasi dilakukan pada Curated test set dengan metrik:

- precision, recall, dan F1 per kategori;
- macro-F1, micro-F1, dan hamming loss secara keseluruhan;
- perbandingan terhadap 9 tools individual dari dataset Results.

Output evaluasi yang tersedia di project ini:

- `processed/metrics_aggregated.json`
- `processed/metrics_per_fold.json`
- `processed/contract_level_metrics.json`
- `processed/baseline_comparison.json`
- `processed/threshold_tuning.json`
- `processed/training_report.md`
- `processed/evaluation_report.md`
- `processed/predictions_function_level.parquet`
- `processed/contract_level_predictions.parquet`

## Strategi Pelabelan

| Sumber                          | Jumlah         | Tipe label | Pakai untuk        |
|---------------------------------|----------------|------------|--------------------|
| Curated (vulnerabilities.json)  | 143            | Gold       | Test + Val + Train |
| Wild + Results (tool voting ≥2) | ~10k–25k       | Silver     | Train (bulk)       |

Test set HANYA berisi label gold — supaya evaluasi akurat.

## Taksonomi (10 Kategori DASP)

`access_control`, `arithmetic`, `bad_randomness`, `denial_of_service`,
`front_running`, `other`, `reentrancy`, `short_addresses`,
`time_manipulation`, `unchecked_low_level_calls`
