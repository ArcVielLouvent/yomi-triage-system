# Fase 4 — Integration/Crucible Tests + Benchmark Harness Sungguhan

**Status:** Selesai · **Branch:** `feature/integration-benchmarks`

## Tujuan

Sampai Fase 3, semua test mengisolasi satu modul (mock semua yang
dia bergantung). Fase 4 membuktikan modul-modul itu beneran **bekerja
sama** saat digabung — dan bikin benchmark regression checker yang tadinya
cuma stub jadi beneran jalan.

## Yang dikerjakan

### Integration/crucible test (5 test, `tests/integration/`)

**`test_chain_sentinel_router_harness.py`** (3 test) — rantai
`Sentinel → Swarm/Hunter → MitreMapper → Router → Harness` pakai objek
modul **nyata** (bukan mock berlapis), cuma boundary LLM API yang di-mock:
- Pembuktian nyata desain **"shoot first, ask AI later"**: skenario CRITICAL
  bikin proses beneran ke-`SIGSTOP` **sebelum** LLM sempat dipanggil sama
  sekali, lewat subprocess asli yang dipantau statusnya di `/proc`.
- Skenario non-CRITICAL kebukti nggak lewat jalur instant-freeze, tapi
  tetap jalan penuh lewat rantai LLM cascade sampai Harness.
- Kontrak `_score_threat` diverifikasi terhadap bentuk output **asli**
  `SwarmOrchestrator.deploy_swarm()`, bukan fixture buatan tangan — biar
  ketauan kalau ada drift struktur data di masa depan.

**`test_chain_swarm_hunter_dossier.py`** (2 test) — rantai
`Swarm → Hunter → (ledger) → Weaver → Dossier`:
- Buktikan temuan dari scan modul analisis nyata beneran nyampe utuh ke
  laporan akhir yang bisa dibaca manusia (bukan ilang di tengah jalan).
- Verifikasi tanda tangan kriptografi laporan **nyata** cocok sama isi
  file yang beneran di-generate (bukan cek bentuk data doang).

Dua bug ditemukan waktu nulis test ini — **keduanya di test saya sendiri**,
bukan di kode Yomi: asumsi salah soal `generate_pdf_dossier()` (ternyata
nggak ada return statement sama sekali — API-nya emang caller harus glob
folder), dan asumsi salah soal nama field signature (`signature`, bukan
`sha256`, dan tipenya bisa HMAC atau SHA256 polos tergantung `hmac_key`).

### Benchmark regression checker sungguhan

`scripts/check_benchmark_regression.py` — dari stub (`exit 0` selalu)
jadi beneran ngukur dan bandingin. **Prinsip desain penting** (hasil
diskusi eksplisit soal beda mesin): script ini **nggak pernah**
membandingkan lintas mesin (laptop kamu vs Codespaces vs sandbox saya) —
tiap environment punya baseline sendiri-sendiri, dibandingkan cuma ke
dirinya sendiri di run berikutnya. Threshold default 50% (sengaja longgar,
CI runner sering noisy/shared CPU, ketat sedikit aja banyak false positive).

**Diverifikasi 3 skenario nyata** (bukan cuma ditulis, tapi dijalankan
dan dibuktikan exit code-nya benar):
1. Kondisi normal → `PASS`, exit 0
2. Regresi dipaksa (baseline dimanipulasi jadi sangat cepat) → `FAIL`,
   **exit 1** (dibuktikan lewat `$?` asli, bukan ketipu exit code `grep`
   di pipe — pelajaran dari insiden CI Fase 1)
3. Baseline belum ada → `PASS` (nggak fail), kasih pesan buat generate
   baseline dulu

### Dokumen baru

`docs/roadmap/dfir-depth.md` — visi resmi "sedalam Palung Mariana":
cakupan DFIR lengkap (memory, disk, timeline, network, malware/binary,
registry forensics + cross-artifact correlation yang sekarang **belum ada
sama sekali**), 3 tolok ukur konkret dari analisis kompetitif SANS
(validasi ground-truth, skala data tanpa collapse context LLM, provenance
yang menolak klaim palsu). Dijadwalkan setelah Fase 6, bukan bagian dari
roadmap Fase 0-6 yang sedang berjalan.

## Ringkasan
- **6 item baru**: 5 integration test + 1 benchmark checker yang beneran fungsional
- **408/408 test lulus** (402 unit + 5 integration + 1 benchmark), stabil 3x run
- **0 bug baru di kode Yomi** — dua "bug" yang ketemu ternyata di asumsi test saya sendiri, sudah diperbaiki
- Lint bersih

## Referensi commit
Branch `feature/integration-benchmarks`, dari `develop` (setelah sync Fase 1-3).
