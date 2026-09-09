# Fase 0 — Kerangka (Branching + CI/CD Skeleton)

**Status:** Selesai · **Branch:** `develop` (base untuk semua fase lain) · **Merged to main:** Belum (dijadwalkan Fase 6)

## Tujuan
Membangun kerangka kerja sebelum menyentuh logika modul apa pun: strategi
branching, skeleton CI/CD 3-tingkat, struktur folder test, dan Module
Registry (mekanisme toggle terpusat).

## Yang dikerjakan

- **Struktur branch:** `main` (protected, snapshot hackathon asli) →
  `develop` (integration branch) → 6 branch fase (`foundation/*`,
  `feature/*`, `docs/*`), semua bercabang dari `develop`.
- **CI/CD 3 tingkat** (`.github/workflows/`):
  - `branch-ci.yml` — lint + unit test cepat, jalan di branch `foundation/*`
    dan `feature/*`.
  - `develop-ci.yml` — full suite (unit + integration + benchmark), jalan
    di `develop` dan PR menuju `develop`/`main`.
  - `main-ci.yml` — semua di atas + build package + smoke test, gerbang
    terakhir sebelum `main`.
- **Struktur test:** `tests/unit/`, `tests/integration/`, `tests/benchmarks/`,
  masing-masing dengan aturan layering tertulis (`README.md` di tiap folder).
- **Module Registry** (`yomi_core/module_registry.py` + `docs/demo_mode.md`):
  satu sumber kebenaran untuk status ON/OFF semua 16 modul, dengan
  `risk_tier` (READ_ONLY/CONTAINMENT/INVASIVE). Modul invasif (Ghost,
  Mirage, ShadowNet, Sandbox, eBPF Sensor) default OFF, dengan
  `DEMO_PROFILE_ENV` buat nyalain semua sekaligus pas demo.

## Bug ditemukan & diperbaiki

| # | Temuan | Perbaikan |
|---|--------|-----------|
| 1 | `docs/dataset_documentation.md` nyuruh `export GEMINI_API_KEY`, tapi `router.py` baca `YOMI_GEMINI_API_KEY` | Diperbaiki di dokumentasi |
| 2 | `README.md` referensi `docs/system_topology.svg` (huruf kecil), file asli `System_Topology.svg` — broken link di filesystem case-sensitive | Path diperbaiki |
| 3 | `yomi_data/recovery/` (dibuat runtime oleh `shadow_net.py`) nggak punya `.gitkeep`, beda dari 6 folder lain | Ditambahkan |

## Keputusan arsitektur

- **Trunk-based + integration branch**, bukan GitFlow penuh — supaya `main`
  selalu bisa langsung dirilis kapan saja tanpa nunggu `release/*` terpisah.
- **Module Registry sebagai gerbang wajib**: setiap modul di codebase harus
  terdaftar di registry dengan keputusan eksplisit (default ON/OFF), nggak
  boleh ada modul yang "nganggur" tanpa status jelas.

## Referensi commit
`c17669f` (baseline import) → `64d9ccb` (module registry) di branch `develop`.
