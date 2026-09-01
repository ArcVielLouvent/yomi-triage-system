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

### ✅ `weaver.py` (11 test)
Include, filter noise action types, sanitasi ANSI escape, tanda `[LF]`/`[CR]`
buat newline tersembunyi, `_secure_tail_logs` (limit, ledger hilang).

**Konfirmasi akar bug MITRE-dropping** (lihat `known_issues.md` #7) — bukan
soal bias frekuensi seperti dugaan awal, tapi **data-shape mismatch**:
`mitre_regex` di `weaver.py` nyari pola `T1XXX` di teks `description`, tapi
`mitre_mapper.py` nulis `"Mapped 2 unique tactics across 5 anomalies"` —
nggak ada literal MITRE ID di teks itu sama sekali. Regex-nya sendiri
**benar** (dibuktikan dengan test terpisah: kalau modul lain nulis literal
`T1055` di description, itu KE-DETECT), tapi struktur datanya nggak pernah
ketemu buat entry `MITRE_MAPPER` secara spesifik.

### ✅ `harness.py` (20 test)
Veto logic lengkap (schema invalid, PID kritis ≤100, kernel thread tanpa
exe path, symlink masquerade defeat via `realpath()`, binary bernama sama
tapi di folder nggak dipercaya, AccessDenied/NoSuchProcess fail-safe),
routing ke `os_bridge`, **1 test end-to-end nyata** (bukan mock) yang
beneran nge-freeze subprocess via seluruh rantai `harness → os_bridge →
SIGSTOP`.

Nggak ada bug baru — modul veto ini justru paling defensif dari semua yang
udah dites, klaim "symlink hijacking defeated" di docstring **terbukti
valid**.

### ✅ `ghost.py` (11 test)
Camouflage (dengan/tanpa `setproctitle` — dipaksa deterministik lewat
`sys.modules`, bukan gantung ke lingkungan), fallback Windows/Linux,
1 test **real** `prctl()` yang beneran ubah `/proc/self/comm` lalu di-restore,
anti-tamper watchdog (SIGTERM/SIGHUP) dengan **snapshot+restore handler**
biar nggak bocor ke proses test itu sendiri, `_tamper_handler` nyegel ke
ledger sebelum exit.

Nggak ada bug baru ditemukan.

### Ringkasan Batch 1
**42 test baru, 0 bug baru** (3 dari 3 modul ternyata bersih — bagus buat
`harness.py` khususnya, itu guardrail keamanan paling kritis). Konfirmasi
1 akar bug lama (`weaver.py`/MITRE) secara presisi.

### ✅ `remediator.py` (20 test)
Validasi payload, generate script (urutan STOP→dump→KILL, permission 0o750,
proteksi injeksi lewat newline stripping), rantai fallback signing
(GPG → HMAC-SHA256 → SHA256 polos), orkestrasi penuh
`generate_rollback_script()`.

**2 gap validasi ditemukan** (bukan crash, tapi celah desain nyata):
- **Nggak ada proteksi PID kritis sama sekali** — beda dari `harness.py`
  yang hardblock PID ≤100, `remediator.py` bakal dengan senang hati generate
  script yang isinya `kill -STOP 1` / `kill -9 1` (target PID 1/init) tanpa
  penolakan apa pun. Script-nya emang nggak auto-execute, tapi tetap
  berbahaya kalau dipercaya buta sama analis.
- **Pengecekan "critical system path" cuma exact-match**, bukan prefix —
  `/bin/bash` atau `/etc/passwd` lolos validasi (nggak dianggap "critical"),
  padahal jelas file sistem kritis. Dampak praktisnya terbatas karena script
  yang di-generate cuma pakai `pid`, bukan `file_path`, di command yang
  dieksekusi — tapi klaim di komentar kodenya ("Never execute kill commands
  targeting core OS paths") lebih kuat dari yang sebenarnya diimplementasi.

Dua-duanya ditulis sebagai regression test eksplisit (`test_KNOWN_GAP_*`),
bukan didiamkan.

### ✅ `mirage.py` (17 test)
Gate env var (pola sama kayak Module Registry), generate decoy Linux
(fake `/etc/shadow` + SSH key, permission 0o600 diverifikasi) dan Windows
(fake SAM hive + dokumen umpan), teardown dengan boundary check, **self-healing
orphan sweeper** (dites nyata pakai subprocess asli buat kasus "PID masih
hidup" vs "PID udah mati" — bukan cuma mock).

**1 kelemahan teoretis dicatat** (bukan bug yang bisa dieksploitasi lewat
API publik sekarang): boundary check di `teardown_hallucination` pakai
`.startswith()` string biasa, bukan proper path-containment check — pola
klasik yang rawan kalau ada folder "sibling" bernama mirip (misal
`mirage_env_EVIL`). Nggak bisa dipicu lewat API publik saat ini (PID selalu
di-cast ke integer, prefix folder cuma 2 pilihan tetap), tapi dicatat biar
kalau kode ini di-refactor nanti, pola berbahayanya nggak ke-copy paste ke
tempat yang beneran rawan.

### Ringkasan Batch 2
**37 test baru, 0 bug crash, 3 gap desain ditemukan & terdokumentasi**
(2 di remediator, 1 di mirage — dua-duanya defense-in-depth issue, bukan
lubang yang langsung bisa dieksploitasi lewat jalur normal).

### ✅ `library.py` (32 test)
Setup toko data (izin file 0o700/0o600, self-repair manifest korup), round-trip
year-file + invalidasi cache LRU, migrasi format lama (list→dict), ekstraksi
tahun dari CVE ID/tanggal publish, hash entry (buat dedup, ngecualiin field
volatile), logika merge (added vs updated count), `query_cve` (deepcopy
isolation), `analyze_artifact`, pipeline `_fetch_nvd_recent` end-to-end
(HTTP+LZMA di-mock), hygiene thread background.

**2 bug fungsional serius ditemukan, dua-duanya diperbaiki:**
- **`lzma.LZMAFile(fileobj=...)`** — nama parameter itu **nggak ada** di API
  `lzma` Python (yang bener `filename`, meski nerima file-like object juga).
  Muncul di 2 lokasi. Akibatnya **sinkronisasi CVE dari NVD gagal total sejak
  awal proyek**, diam-diam ketangkep `except Exception`. Diperbaiki di
  keduanya.
- **`analyze_artifact()` arah pengecekan substring kebalik** — nama artifact
  (panjang) dicek sebagai substring DI DALAM teks deskripsi (pendek), bukan
  sebaliknya. Cuma jalan kalau nama artifact persis CVE ID doang. Diperbaiki
  dengan desain baru: exact-match CVE ID lewat regex (fast path, presisi),
  `context_hints` tetap arah lama (memang udah benar), dan fallback
  containment yang arahnya dibalik jadi benar.

### ✅ `sift_toolkit.py` (25 test)
Chokepoint bersama (`_validate_target_path`, `_validate_tool`, `_run_subprocess`,
`_run_pipe`) dites pakai **subprocess sungguhan** (`echo`, `false`, `sleep`,
binary nggak ada) — bukan mock, karena inti modul ini ya soal nanganin
subprocess dengan aman. Plus sampel wrapper representatif (Volatility pslist
end-to-end pakai fake binary di PATH, YARA "--" injection barrier, TSK icat
binary-integrity, Scalpel flag ordering).

**2 bug nyata ditemukan lewat testing berulang (bukan cuma sekali run), dua-duanya diperbaiki:**
- **Pesan "timed out" nyaris nggak pernah muncul** — `_run_subprocess` nebak
  timeout dari `returncode is None`, tapi `_stream_process_output` udah
  nge-*reap* proses duluan sebelum balik, jadi `returncode` udah keisi -9.
  Diperbaiki dengan flag `timed_out` eksplisit.
- **Race condition nyata** (baru ketauan setelah run test 5x berulang —
  gagal di test yang beda-beda tiap run, ciri khas race condition):
  `process.poll()` dicek duluan sebelum baca pipe, jadi command cepat kayak
  `echo` bisa kehilangan output-nya kalau proses udah selesai sebelum loop
  sempat baca. Diperbaiki: loop nggak pernah keluar berdasar `poll()` lagi,
  tapi berdasar EOF beneran di pipe. **Diverifikasi stabil 5x run berturut-turut
  setelah fix**, dulu flaky.

### ✅ `ebpf_sensor.py` (12 test)
Kontrak singleton, fallback `bcc` nggak ke-install (beneran nggak ada di
sandbox, jadi ini natural real test bukan simulasi), short-circuit "udah
armed". **Logika deteksi ancaman** (bagian paling kritis) dites dengan cara
nangkep callback `print_event` dari closure lewat mock `open_perf_buffer`,
lalu panggil langsung pakai event palsu — akses `/etc/shadow` → SIGSTOP +
2 ledger entry, shell kritis via execve → alert, filter false-positive
(cmdline sendiri/`volatility`/`python`, path `sans_hackathon`), kegagalan
SIGSTOP tetap ke-log meski containment gagal.

Nggak ada bug baru — logika deteksinya solid.

### ✅ `sandbox.py` (23 test)
Validasi binary, containment read-only 0o400, **overlay mount OverlayFS
beneran** (bukan mock — sandbox ini punya CAP_SYS_ADMIN, dibuktikan lewat
probe manual dulu sebelum nulis test, dengan cleanup ketat di `finally`
supaya nggak ada mount ketinggalan), guard root/OS buat mini-container,
verifikasi command `unshare` nggak ada `-r` (klaim "prevent UID map escape"
di docstring — **terbukti valid**), orkestrasi penuh `execute_resurrection`
dan `_monitor_awakened_threat` (deploy decoy → timeout/kill → teardown →
kunci evidence 0o500 → profiling → cleanup paksa).

Nggak ada bug baru — modul ini defensif dan sesuai klaim dokumentasinya.

### Ringkasan Batch 3
**92 test baru, 4 bug fungsional nyata ditemukan & diperbaiki** (2 di
`library.py` — satu di antaranya bikin fitur inti "auto-update CVE" nggak
pernah jalan sejak awal proyek, dan satu bug desain matching yang saya putuskan
sendiri arah perbaikannya sesuai instruksi; 2 di `sift_toolkit.py` — satu di
antaranya race condition asli yang cuma ketauan lewat testing berulang).

## Ringkasan Fase 2 total
- **190 test baru** (221/221 total termasuk Fase 1, stabil 3x run berturut-turut)
- **4 bug fungsional diperbaiki** (2 crash-adjacent, 1 fitur mati total sejak
  awal proyek, 1 race condition), **3 gap desain terdokumentasi** (Batch 2)
- Lint bersih, CI hijau
- Semua 11 modul Lapisan 1 selesai diuji

## Ringkasan sejauh ini

- **98 test baru** (129/129 total termasuk Fase 1, semua lulus)
- **0 bug crash baru**, **3 gap desain ditemukan & terdokumentasi** (2 di
  `remediator.py`, 1 di `mirage.py`) — defense-in-depth, bukan lubang yang
  langsung bisa dieksploitasi lewat jalur normal
- Lint bersih, CI hijau

## Kerjaan administratif (bukan test-writing, tapi masuk Fase 2 sesuai arahan)

`scripts/create_known_issues.sh` — migrasi 13 temuan bug dari Fase 0-1 ke
GitHub Issues tab (bukan cuma di `docs/known_issues.md`), termasuk
hackathon-era findings. Issue yang udah fix langsung dibuka-tutup dengan
referensi commit; issue yang masih open tetap kebuka.

## Referensi commit
`e03358a` → (berlanjut) di branch `foundation/layer1-modules`.
