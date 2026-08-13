# Fase 2 — Lapisan 1: sift_toolkit, harness, telemetry, mitre_mapper, mirage, weaver, library, remediator, ebpf_sensor, sandbox, ghost

**Status:** Sedang berjalan · **Branch:** `foundation/layer1-modules`

> Dokumen ini di-update tiap ada progress baru, bukan ditulis sekali di
> akhir fase. Urutan pengerjaan: modul dengan dependensi paling sedikit dan
> risiko paling rendah duluan.

## Cakupan modul

11 modul Lapisan 1 (semuanya cuma bergantung ke Lapisan 0):
`sift_toolkit.py`, `harness.py`, `telemetry.py`, `mitre_mapper.py`,
`mirage.py`, `weaver.py`, `library.py`, `remediator.py`, `ebpf_sensor.py`,
`sandbox.py`, `ghost.py`.

## Progress

### ✅ `telemetry.py` (9 test)
Start/stop timer lifecycle, double-stop safety, ledger sealing,
**regression guard buat bug "astronomical speed multiplier"** yang disebut
di docstring modul sendiri (dibuktikan: multiplier di-cap sesuai
`max(latency, 0.001)`, nggak pernah meledak ke jutaan x meski latency
sub-milidetik), threshold 60 detik vs Horizon3 AI, eviction
`MAX_TRACKED_INCIDENTS`, stress test 50 thread konkuren.

Nggak ada bug baru ditemukan — modul ini bersih.

### ✅ `mitre_mapper.py` (10 test)
Keyword matching, fallback `GENERIC_ANOMALY`, penanganan input invalid,
type coercion aman, dedup unique-tactic count. **3 test khusus buat
verifikasi klaim modul sendiri** ("Hardened against Substring False
Positives") — terbukti **valid**: kata "invader" nggak salah ke-match
sama keyword "vad" berkat word-boundary regex.

Konfirmasi langsung (via ledger) bug `weaver.py` yang udah ditemukan
sebelumnya: `record_action()` di sini beneran nyatet "Mapped N unique
tactics" — jadi datanya ADA di ledger, cuma ilang pas sampai ke laporan
akhir. Bug-nya di `weaver.py`, bukan di sini.

Nggak ada bug baru ditemukan di modul ini sendiri.

### ⏳ Belum dikerjakan
`weaver.py`, `harness.py`, `library.py`, `remediator.py`, `mirage.py`,
`ebpf_sensor.py`, `sandbox.py`, `sift_toolkit.py`, `ghost.py`.

## Ringkasan sejauh ini

- **19 test baru** (50/50 total termasuk Fase 1, semua lulus)
- **0 bug baru** ditemukan di 2 modul yang udah dikerjakan (keduanya
  ternyata bersih — bukan berarti nggak niat cari, tes-nya tetap sekomplit
  Fase 1, cuma emang kodenya solid)
- Lint bersih, CI hijau

## Kerjaan administratif (bukan test-writing, tapi masuk Fase 2 sesuai arahan)

`scripts/create_known_issues.sh` — migrasi 13 temuan bug dari Fase 0-1 ke
GitHub Issues tab (bukan cuma di `docs/known_issues.md`), termasuk
hackathon-era findings. Issue yang udah fix langsung dibuka-tutup dengan
referensi commit; issue yang masih open tetap kebuka.

## Referensi commit
`e03358a` → (berlanjut) di branch `foundation/layer1-modules`.
