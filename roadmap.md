# Production-Grade Roadmap — Smart Contract Vulnerability Detector

Dokumen ini memetakan jalur dari versi akademik saat ini (XGBoost + handcrafted features di SmartBugs Curated) menuju detector berkelas production yang sebanding dengan tooling auditor profesional.

---

## 1. Status Saat Ini (Baseline Akademik)

| Aspek | Kondisi |
|---|---|
| Dataset | SmartBugs Curated 143 contracts (Solidity 0.4.x – 0.5.x, era 2018–2020) |
| Vuln classes | 7 (access_control, arithmetic, bad_randomness, denial_of_service, reentrancy, time_manipulation, unchecked_low_level_calls) |
| Feature engineering | Handcrafted rules (~50 features) + tool baselines |
| Model | XGBoost dual-head (function-level + contract-level) |
| Macro-F1 contract-level (tuned threshold) | **0.579** |
| Posisi vs 9 tools baseline | Win 6/7 class |
| Limitations | Distribution shift Solidity 0.4 → 0.8.34, kelas modern tidak ter-cover |

Detail metrik: lihat [show_results.py output](../src/training/show_results.py) dan [evaluation_report.md](../processed/evaluation_report.md).

---

## 2. Definisi Production-Grade

Benchmark realistis: tools yang dipakai auditor pro sekarang — **Slither, Aderyn, Mythril, Wake, Olympix, Cyfrin, Codehawks**. Kompetisi mereka di dimensi berikut:

| Dimensi | Bar Production-Grade |
|---|---|
| **Coverage** | Solidity 0.4 – 0.8.34, plus Vyper, Yul |
| **Vuln classes** | 30–80 detector (bukan 7) |
| **False positive rate** | < 15% di benchmark publik |
| **Recall di SWC Registry** | > 80% |
| **Modern attacks** | Flash loan, oracle, cross-function reentrancy, signature replay |
| **Latency** | < 30s untuk kontrak ≤ 2k LOC |
| **Reproducibility** | Deterministic output, version-pinned |
| **CI/CD integration** | GitHub Action, pre-commit hook, IDE plugin |
| **Continuous update** | Detector baru tiap kuartal mengikuti exploit terbaru |

---

## 3. Gap Analysis — Apa yang Kurang Sekarang

### 3.1 Data gap

| Issue | Dampak |
|---|---|
| Solidity version drift (0.4–0.5 → 0.8.34) | Model blind ke pola modern; over-flag bug yang sudah hilang (mis. arithmetic auto-revert di 0.8) |
| Hanya 143 gold contracts | Kelas minor (DoS=6, time_manipulation=5) tidak punya data cukup untuk F1 stabil |
| 7 class taksonomi 2018-era | Tidak meng-cover flash loan, oracle manipulation, read-only reentrancy, signature replay, proxy storage collision, governance attack, MEV — kelas yang dominan di kerugian post-2022 |
| Sumber dataset wild juga era 2019 | Wild dataset tidak menyelamatkan dari distribution shift |

### 3.2 Model gap

| Issue | Dampak |
|---|---|
| Handcrafted rules 50 features | Plateau — sulit naik tanpa representation learning |
| Function-level isolation | Cross-function dataflow vulnerabilities tidak ter-deteksi (read-only reentrancy, dll) |
| Tidak ada graph structure | AST/CFG/DFG informasi hilang |
| Tidak ada confidence calibration | Probabilitas raw, tidak reliable untuk threshold-based decision di production |

### 3.3 Pipeline gap

| Issue | Dampak |
|---|---|
| Tidak ada continuous evaluation | Model tidak tahu kalau exploit baru muncul |
| Tidak ada human-in-the-loop | False positive dari auto-label menumpuk |
| Tidak ada deployment infra | Belum ada API, CLI, atau IDE integration |

---

## 4. Distribution Shift — Risiko Utama

SmartBugs Curated era: **Solidity 0.4.x – 0.5.x**. Solidity 0.8.x mengubah landscape vulnerability secara fundamental:

| Vulnerability | Solidity 0.4–0.5 (training) | Solidity 0.8+ (production) |
|---|---|---|
| **arithmetic** | Bug umum, butuh SafeMath manual | Otomatis revert — class hampir mati |
| **bad_randomness** | `block.difficulty` | Deprecated → `block.prevrandao` |
| **access_control** | Constructor pakai nama kontrak | Keyword `constructor` wajib — bug tipe ini hilang |
| **unchecked_low_level_calls** | `.call.value()()` style lama | Syntax baru, pola masih ada |
| **DoS** | Loop unbounded klasik | Masih relevan + gas griefing variant |
| **reentrancy** | Single-function reentrancy | + Cross-function, **read-only reentrancy** |

### Vuln class baru yang dominan post-2020 (tidak ada di SmartBugs)

- Flash loan attacks
- Oracle manipulation (price oracle, TWAP)
- Cross-function & read-only reentrancy
- Signature replay (EIP-712 misuse)
- Proxy storage collision (delegatecall)
- ERC-20 approval race / front-running approve
- MEV sandwich vectors
- Governance attacks (vote manipulation)

Total kerugian dari kelas-kelas ini di 2022–2025 jauh lebih besar daripada 7 kelas SmartBugs digabung.

---

## 5. Strategi Augmentasi Data — Pilihan Pendekatan

### Pendekatan 1: Label kontrak yang sudah ada (recommended)

```
SmartBugs Wild (47k unlabeled, sudah ada)
        ↓
   Pre-filter (Slither/Mythril)
        ↓
   AI Opus baca + kasih label
        ↓
   Tambah ke Curated (jadi SB Curated v2)
```

- Sumber kontrak nyata, dari blockchain
- AI hanya bertugas labeling (distant supervision — standar paper)
- Token efisien: ~3.4k/contract
- Valid secara metodologi

### Pendekatan 2: Generate kontrak baru dari nol (NOT recommended)

- Sumber kontrak sintetis, dibuat AI
- Reviewer akan menolak — bukan real-world data
- Risk: model overfit ke gaya AI, gagal di kontrak nyata
- Token boros (~3k output/contract + verify)

### Pendekatan 3: Scrape audit reports (production track)

```
Code4rena / Sherlock / Solodit
        ↓
   Markdown parser → Structured findings
        ↓
   Map ke taksonomi modern (30+ kelas)
        ↓
   Gold-quality dataset dengan label dari auditor manusia
```

- **Gold label asli**, bukan distant supervision
- Modern Solidity (post-2021)
- Sumber gratis dan publik
- Inilah yang dipakai vendor production seperti Olympix

---

## 6. Roadmap 4 Fase

### Fase 1 — Modern Dataset Bootstrap (4–8 minggu)

Tujuan: punya dataset gold modern dari audit firm.

**Tasks:**
1. Scraper untuk audit reports (gratis, public):
   - Code4rena: ~250 audit, ~5000 findings
   - Sherlock: ~150 audit, ~3000 findings
   - Cantina, Spearbit (selective)
   - Solodit (aggregator, ~30k findings)
   - DeFiHackLabs (post-mortem PoC)
2. Normalize ke schema:
   ```json
   {
     "contract_source": "...",
     "solidity_version": "0.8.x",
     "vuln_class": "oracle_manipulation",
     "severity": "high",
     "affected_lines": [123, 145],
     "audit_firm": "code4rena",
     "audit_date": "2024-03",
     "exploit_confirmed": true
   }
   ```
3. Taksonomi baru (extend SmartBugs):
   - **Keep:** reentrancy, access_control, dos, unchecked_calls
   - **Drop/demote:** arithmetic (mostly dead di 0.8), short_addresses
   - **Add:** oracle_manipulation, flash_loan, read_only_reentrancy, signature_replay, proxy_storage_collision, governance, mev, erc20_approval_race
4. Quality control: cross-validation antar sumber audit firm

**Deliverable:** ~5000–15000 labeled contracts dengan modern vulnerabilities, gold label dari auditor profesional.

### Fase 2 — Architecture Upgrade (4–6 minggu)

| Komponen | Sekarang | Production |
|---|---|---|
| Feature representation | Handcrafted rules (~50 features) | **Transformer embeddings** (CodeBERT, GraphCodeBERT, atau Solidity-tuned) |
| Code structure | Linear text | **AST + CFG + DFG** (graph neural network) |
| Context | Function-isolated | **Cross-function dataflow** |
| Backbone | XGBoost | Hybrid: GNN encoder + transformer + classifier |
| Inference | Single-shot | **LLM-augmented:** static-detector hits → LLM untuk reasoning + filter FP |

**Stack rekomendasi:**
- Slither / Wake sebagai static analysis backbone (ekstrak AST/CFG/DFG → graph)
- GNN (PyTorch Geometric) untuk encode struktur
- Embeddings dari CodeT5+ atau StarCoder2 untuk semantik
- LLM judge layer (Claude Haiku 4.5) untuk filter false positive — auditor virtual

### Fase 3 — Evaluation & Calibration (3–4 minggu)

Multi-benchmark, bukan cuma SmartBugs:

| Benchmark | Tujuan |
|---|---|
| SmartBugs Curated | Legacy compatibility |
| **SolidiFI** | Synthetic injection (fairness check) |
| **SWC Registry** | Standar industri |
| **DeFiHackLabs** | Real exploits historis (post-mortem) |
| **Custom held-out** | Audit findings 2025–2026 yang belum public saat training |

Plus calibration layer: confidence score reliable, bukan cuma raw probability. Pakai Platt scaling atau temperature scaling dengan validation set berbeda dari training.

### Fase 4 — Productionization (4–8 minggu)

| Komponen | Tools |
|---|---|
| API serving | FastAPI + Modal / Replicate untuk GPU |
| Monitoring | Prometheus + Grafana, alert kalau drift |
| CI/CD | GitHub Action (`org/sol-vuln-scan@v1`) |
| Versioning | Model registry (Weights & Biases / DVC) |
| Continuous learning | Re-train tiap kuartal pakai audit baru |
| Public benchmark | Submit ke SmartBugs leaderboard, blog post |

---

## 7. Estimasi Resource

### Budget waktu (solo, part-time)

| Fase | Durasi |
|---|---|
| Fase 1 (data) | 4–8 minggu |
| Fase 2 (model) | 4–6 minggu |
| Fase 3 (eval) | 3–4 minggu |
| Fase 4 (deploy) | 4–8 minggu |
| **Total MVP production** | **6–9 bulan part-time** |

### Budget LLM (token)

| Aktivitas | Estimasi |
|---|---|
| Fase 1 scraping (parsing report → structured) | ~50–100M token |
| Fase 2 LLM judge training data | ~30M token |
| Fase 3 evaluation | ~20M token |
| **Total** | **~150M token** |

Optimasi biaya: pakai Claude Haiku 4.5 untuk filter, Opus 4.7 hanya untuk borderline cases.

### Budget compute

| Resource | Biaya bulanan |
|---|---|
| GPU training (A100 / RTX 4090 via RunPod) | ~$200 |
| Inference serving | ~$50 untuk traffic kecil |

### Estimasi sample complexity untuk F1 ≥ 0.95 per kelas

Berdasarkan ekstrapolasi learning curve dari data sekarang:

| Class | Positif sekarang | Target estimasi | Tambahan |
|---|---:|---:|---:|
| unchecked_low_level_calls | 52 | ~80–100 | +30–50 |
| reentrancy | 31 | ~80–120 | +50–90 |
| access_control | 18 | ~150–250 | +130–230 |
| arithmetic | 15 | ~150–250 | +135–235 |
| bad_randomness | 8 | ~150–250 | +140–240 |
| denial_of_service | 6 | ~250–400 | +245–395 |
| time_manipulation | 5 | ~250–400 | +245–395 |

**Catatan:** untuk DoS dan time_manipulation, kemungkinan butuh juga upgrade fitur (graph-based / IR-level), bukan cuma data lebih.

---

## 8. Reality Check & Trade-offs

### Apa yang BISA dicapai solo
- Fase 1 + Fase 2 + Fase 3 (MVP research-grade)
- Macro-F1 di benchmark akademik > 0.85
- Publish blog post / paper workshop

### Apa yang TIDAK BISA dicapai solo
- True production-grade tanpa human-in-the-loop auditor profesional
- False negative rate < 5% (butuh tim security engineer)
- Maintenance jangka panjang tanpa funding

### Posisi proyek vs vendor production

Vendor seperti Olympix dan Cyfrin punya:
- Tim 10–30 security engineer full-time
- Budget tahunan jutaan dollar
- Akses private audit data dari klien
- Continuous bug bounty integration

Solo project tidak akan match ini. Tapi bisa **comparable di niche tertentu** (mis. kelas modern reentrancy + flash loan) kalau fokus.

---

## 9. Milestone Konkret — Langkah Pertama

**Minggu 1–2:** Bikin scraper Code4rena.
- Output: parquet dengan ~3000 findings, sudah dipetakan ke taksonomi modern
- Lokasi: `dataset/code4rena/findings.parquet`
- Schema: lihat Fase 1

**Minggu 3–4:** Train baseline XGBoost yang sudah ada di dataset modern (drop SmartBugs sementara).
- Ukur F1 sebagai baseline production-relevant
- Bandingkan dengan F1 SmartBugs sekarang
- Identifikasi kelas yang collapse di data modern

**Minggu 5–8:** Implementasi taksonomi modern + augment dengan Sherlock + Solodit.

---

## 10. Open Questions

- Apakah scope dibatasi ke Solidity saja, atau extend ke Vyper / Move / Rust (Solana)?
- Apakah focus ke detection (binary class) atau severity prediction (regression)?
- Lisensi target: open source (MIT) atau commercial?
- Target user: auditor profesional, dev DeFi, atau both?

---

## Referensi

- SmartBugs Curated paper (ICSE 2020): https://arxiv.org/abs/1910.10601
- SWC Registry: https://swcregistry.io
- Code4rena: https://github.com/code-423n4
- Sherlock: https://github.com/sherlock-audit
- Solodit: https://solodit.cyfrin.io
- DeFiHackLabs: https://github.com/SunWeb3Sec/DeFiHackLabs
- Slither: https://github.com/crytic/slither
- Aderyn: https://github.com/Cyfrin/aderyn
- Wake: https://github.com/Ackee-Blockchain/wake
