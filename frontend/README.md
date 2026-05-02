# Smart Contract Vulnerability Detector Frontend

Frontend Next.js untuk proyek Smart Contract Vulnerability Detector. Aplikasi ini menyediakan:

- Landing page dengan positioning riset keamanan
- Scanner split-view untuk upload atau paste Solidity dan melihat hasil scan
- Demo page dengan kontrak historis yang sudah diisi otomatis
- About page berisi metodologi, stack, dan keterbatasan

## Stack

- Next.js 16 App Router
- React 19 + TypeScript strict
- Tailwind CSS v3
- shadcn-style source components di `components/ui`
- TanStack Query + Zustand persist
- React Hook Form + Zod
- Monaco Editor + Recharts + react-markdown

## Local Setup

1. Install dependency:

```bash
npm install
```

2. Copy environment file di root repo:

```bash
cp ../.env.example ../.env.local
```

3. Jalankan dev server dari folder `frontend`:

```bash
npm run dev
```

App akan aktif di `http://localhost:3000`.

Backend API harus aktif terpisah di `http://localhost:8000` atau URL lain yang di-set ke `NEXT_PUBLIC_API_URL`.

Scanner sekarang mendukung dua mode:

- `Fast Scan`: default, dipakai untuk inferensi aplikasi
- `Deep Scan`: placeholder opsional untuk mode analyzer yang lebih berat; request akan ditolak eksplisit sampai runtime analyzer tersedia

## Environment Variables

Semua environment variable sekarang disatukan di root repo, bukan di folder `frontend`.

- `NEXT_PUBLIC_API_URL`
  Default: `http://localhost:8000`
  Digunakan oleh proxy route `app/api/scan/route.ts` untuk meneruskan request ke backend FastAPI.

- `MINIMAX_API_KEY`
  Wajib untuk RAG explanation berbasis MiniMax.

- `MINIMAX_MODEL`
  Default: `MiniMax-M2.7`

- `MINIMAX_API_URL`
  Default: `https://api.minimax.io/v1/chat/completions`

- `MINIMAX_MAX_TOKENS`
  Default: `1024`

## Commands

```bash
npm run dev
npm run lint
npm run typecheck
npm run build
```

## Backend Dependency

Dari root repo, jalankan backend FastAPI:

```bash
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```

## Structure

```text
frontend/
├── app/
├── components/
├── lib/
├── public/demo-contracts/
├── scripts/run-next.mjs
├── tailwind.config.ts
├── vercel.json
└── ...
```

## Deployment Notes

1. Import folder `frontend/` ke Vercel sebagai root project.
2. Set environment variable `NEXT_PUBLIC_API_URL` ke URL backend FastAPI.
3. Set `MINIMAX_API_KEY` dan variabel MiniMax lain di environment deployment backend yang memproses RAG.

## Caveats

- Ini adalah research-grade assistant untuk triage awal, bukan pengganti audit smart contract profesional.
- Demo contracts disediakan hanya untuk demonstrasi historis, bukan reproduksi exploit penuh.
