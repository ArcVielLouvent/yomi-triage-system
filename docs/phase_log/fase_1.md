# Fase 1 — Lapisan 0 (Fondasi): stamp.py, os_bridge.py, yomi_data/__init__.py

**Status:** Selesai, merged ke `develop` (PR #1) · **Branch asal:** `foundation/stamp-datastore-osbridge`

## Tujuan
Modul Lapisan 0 adalah fondasi yang ditempa lawan oleh **semua** modul lain
di sistem, langsung atau tidak langsung. Diuji duluan karena kalau ada bug
di sini, itu merambat ke seluruh sistem tanpa kecuali.

## Yang dikerjakan

- **`tests/unit/test_stamp.py`** (10 test): genesis entry, hash-chaining,
  HMAC signing, deteksi tamper (hash diubah / chain diputus / field hilang),
  kontrak singleton, `get_ledger_summary()`.
- **`tests/unit/test_os_bridge.py`** (9 test): deteksi tool via mock
  `shutil.which`, penolakan binary di path nggak dipercaya, **SIGSTOP/SIGCONT
  sungguhan** ke subprocess asli (bukan mock — perilaku level OS perlu
  dibuktikan nyata, bukan diasumsikan), guard PID kritis, ghost-process
  handling.
- **`tests/unit/test_yomi_data.py`** (11 test): validasi data store,
  round-trip year-store, self-repair manifest, karantina file korup,
  penolakan symlink, edge case baca ledger, permission file aman.
- **`tests/benchmarks/test_bench_stamp.py`**: baseline throughput
  `record_action()` (~211 ops/detik di sandbox referensi, ~165 ops/detik
  di Codespaces — beda mesin, bukan regresi).
- **`run_tests.sh`**: script satu-perintah buat lint+unit+integration+bench,
  mirroring persis apa yang CI jalanin, supaya bisa dites lokal sebelum push.
- **`pyproject.toml`**: konfigurasi `ruff` yang fokus ke kelas bug serius
  (`F`, `E9`) repo-wide, style/kosmetik ditunda per-paket biar nggak ada
  commit reformat raksasa di file yang belum ada test coverage-nya.

## Bug ditemukan & diperbaiki

| # | Temuan | Tingkat | Perbaikan |
|---|--------|---------|-----------|
| 4 | `cli.py --install` selalu crash (`UnboundLocalError`) — `import sys` lokal nimpa import modul di scope fungsi yang sama | **Crash** | Import lokal redundan dihapus |
| 5 | `_run_console_loop()` manggil `_get_latest_ledger_log()` yang nggak pernah didefinisikan → `NameError` | **Crash** | Disamakan dengan pola benar di `_run_tui_loop()` |
| 6 | `query_cve()` didefinisikan 2x di `library.py`, versi aktif pakai shallow `.copy()` bukan `deepcopy()` | **Silent bug** | Duplikat dihapus, konsolidasi ke versi `deepcopy`-safe |

## Bug didokumentasikan, belum diperbaiki (di luar scope Lapisan 0)

- `weaver.py` membuang temuan MITRE dari laporan akhir meski ada di ledger.
- `write_year_store()` kehilangan data diam-diam kalau `cve_id` nggak cocok
  (sudah ada regression test yang menangkap bug ini secara sengaja).
- `ImmutableStamp` + `yomi_data` hardcode path relatif ke `__file__` +
  singleton ketat → nggak bisa multi-tenant, butuh fixture khusus buat dites.
- `mcp_server.py` whitelist path hardcoded, bukan diturunkan dari `yomi_data`.

## Coverage gap ditemukan (bukan bug, tapi titik buta)

`stamp.py` cuma 54% ke-cover. Jalur KMS/Vault/AWS-Secrets-Manager, kunci
turunan password, backup ledger korup, dan SOC checkpoint anchoring **belum
pernah dieksekusi test sekalipun**. Diprioritaskan buat fase berikutnya yang
nyentuh `stamp.py` lagi.

## Insiden CI (ditemukan & diperbaiki setelah PR dibuka)

PR #1 sempat gagal 2x di GitHub Actions meskipun lolos di lokal:
1. `pytest tests/integration` exit code 5 ("no tests collected") dianggap
   gagal oleh GitHub Actions, padahal `tests/integration/` memang masih
   kosong (jatah Fase 4). Percobaan fix pertama (`code=$?` setelah pytest)
   gagal juga karena `bash -e` (mode default GitHub Actions runner)
   langsung motong script begitu pytest exit non-zero. Fix final: cek dulu
   pakai `find` apa ada file test sebelum manggil `pytest` sama sekali —
   menghindari masalahnya sepenuhnya, bukan nangkep setelah kejadian.
2. `main-ci.yml` manggil `develop-ci.yml` lewat `uses:` (reusable workflow),
   tapi `develop-ci.yml` belum punya trigger `workflow_call` — laten,
   ketauan sebelum sempat kejadian pas PR ke `main`.

## Referensi commit
`2119914` → `9f29a13` di branch `foundation/stamp-datastore-osbridge`,
merged ke `develop` sebagai PR #1.
