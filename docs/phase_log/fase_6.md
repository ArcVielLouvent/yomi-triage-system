# Fase 6 — Guardian Orchestrator, Release, Landing Page

**Status:** Tahap 1 SELESAI · Tahap 2-3 belum mulai · **Branch:** kerja
lokal, belum di-push (Codespaces kehabisan kredit, diperbarui 1
September)

Fase 6 dibagi 3 tahap (keputusan eksplisit dari Arcia, bukan asumsi):

1. **Tahap 1** — perbaikan issue tersisa + integrasi SEMUA kode dan
   fitur tanpa satupun lepas, sesuai rencana arsitektur.
2. **Tahap 2** — GitHub Release lengkap dengan deskripsi, dokumentasi
   saat ini, dan versioning.
3. **Tahap 3** — landing page KuroTech.

Tahap 2 dan 3 direncanakan konkret setelah Tahap 1 benar-benar solid,
bukan sekarang.

---

## Tahap 1 — Guardian Orchestrator ("Great Integration")

### Verifikasi awal: branch lama tidak berguna

Sebelum mulai, dua branch yang sudah ada (`feature/guardian-orchestrator`,
`feature/module-registry`) diverifikasi dulu terhadap `develop` --
`diff -rq` membuktikan keduanya masih versi hackathon-era (tidak punya
`docs/`, `tests/unit/` lengkap, dsb dari Fase 0-5), dan
`yomi_core/module_registry.py` + `yomi_core/sentinel.py` di kedua
branch itu **identik byte-per-byte** dengan yang ada di `develop`. Tidak
ada kerjaan tersembunyi untuk di-merge; integrasi dimulai murni dari
`develop`.

### Yang dibangun: `yomi_core/guardian.py`

`GuardianOrchestrator` adalah satu-satunya tempat yang memutuskan modul
deep-dive mana yang jalan, berdasarkan `yomi_core/module_registry.py`
-- bukan env var ad-hoc yang tersebar di berbagai tempat. Ini menutup
**known_issues.md #11**.

**Batasan desain (didokumentasikan eksplisit di docstring modul, wajib
dibaca sebelum mengubah file ini):**

1. **Single investigation per process** -- konsisten dengan asumsi
   `ImmutableStamp` singleton yang sudah ada. #9 (multi-tenant) tetap
   keputusan arsitektur terpisah yang sengaja **tidak** diselesaikan di
   sini (sesuai instruksi eksplisit sebelumnya bahwa #9 butuh keputusan
   tersendiri dari Arcia).
2. **`shadow_net.deploy_micro_hook()` itu fire-and-forget** -- spawn
   thread, langsung return. `kill_chain()`-nya sendiri (sudah ada,
   sudah teruji) yang menangani containment lanjutan. Guardian **tidak**
   mencoba merantai MindReader/Sandbox/Remediator dari sini secara
   sinkron karena hasilnya belum diketahui saat itu -- itu race
   condition. Modul deep-dive hanya dipicu dari containment SINKRON:
   jalur instant CRITICAL SIGSTOP, atau hasil harness
   `status=="SUCCESS"` + `action=="FROZEN"`.
3. Setiap dispatch dibungkus try/except, gagal dicatat ke ledger
   (`<MODULE>_DISPATCH_ERROR`), tidak pernah di-raise -- satu modul
   rewel (Radare2 hilang, mount sandbox gagal) tidak boleh mematikan
   observation loop atau modul setelahnya.
4. **Dua modul (Ghost, Mirage) punya gating env var ad-hoc sendiri**
   di luar skema `module_registry` -- lihat #25/#26 di bawah.

### Dispatch flow

- `handle_post_containment(target_pid)` -- dipanggil dari 2 titik di
  `sentinel.py`: setelah instant CRITICAL SIGSTOP berhasil, dan setelah
  hasil router `SUCCESS`/`FROZEN` (dengan guard `post_containment_dispatched`
  supaya tidak dobel kalau kedua jalur itu kena PID yang sama). Resolve
  `/proc/<pid>/exe` (best-effort, `""` kalau proses sudah exit/fileless),
  lalu dispatch `MIND_READER` -> `REMEDIATOR` -> `SANDBOX` -> `MIRAGE`
  (urutan ini penting: `MIRAGE` cuma jalan kalau `SANDBOX` juga jalan).
- `handle_escalation(target_pid, reason)` -- dipanggil saat router
  balikin `ESCALATED_TO_SHADOW_NET`. Fire-and-forget dispatch
  `SHADOW_NET`.
- `generate_incident_dossier()` -- dipanggil tanpa syarat di akhir tiap
  siklus `_zero_prompt_trigger`, kalau `DOSSIER` enabled (default: ya).
- `periodic_maintenance()` -- dipanggil tiap siklus `start()` loop,
  internal cuma benar-benar sweep `MIRAGE` decoy tiap 20 siklus.
- `bootstrap_startup_daemons()` -- static method, dipanggil sekali dari
  `cli.py` saat startup, ganti wiring `Ghost`+`eBPF Sensor` yang lama.

### Wiring ke `sentinel.py` dan `cli.py`

- `SentinelDaemon.__init__` sekarang bikin `self.guardian = GuardianOrchestrator()`.
- `_zero_prompt_trigger` dipatch guardian di 3 titik (instant freeze,
  hasil router, akhir siklus untuk dossier) -- lihat kode untuk detail
  persis, semua ditambahkan tanpa mengubah perilaku lama yang sudah ada
  (test lama tetap lulus tanpa modifikasi assertion, cuma ditambah
  assertion baru).
- `cli.py`: blok besar hardcoded Ghost Protocol (gated
  `YOMI_ENABLE_GHOST_PROTOCOL`) + eBPF Sensor (**tidak ada gating sama
  sekali**) diganti 1 baris:
  `GuardianOrchestrator.bootstrap_startup_daemons(audit)`.

### Temuan baru selama integrasi (known_issues.md #25, #26)

**#25 -- dua mekanisme toggle paralel untuk keputusan yang sama.**
`mirage.py`'s `deploy_hallucination()` punya pengecekan env var sendiri
(`YOMI_ENABLE_MIRAGE_MODE`) di luar skema `YOMI_MODULE_MIRAGE`.
**Diakali** (bukan dihapus): Guardian panggil dengan `force_enable=True`
untuk bypass pengecekan internal itu -- keputusan enable/disable sudah
diambil di level registry sebelum Guardian manggil. Env var lama tetap
ada untuk kompatibilitas manual invocation, sengaja tidak dihapus
karena berisiko merusak assertion `test_mirage.py` yang sudah ada.

**#26 -- Ghost Protocol dan eBPF Sensor bypass `module_registry` total.**
Ghost Protocol digerbang env var terpisah (`YOMI_ENABLE_GHOST_PROTOCOL`,
bukan `YOMI_MODULE_GHOST`). eBPF Sensor **lebih parah -- tidak digerbang
sama sekali**: `cli.py` selalu `subprocess.Popen` eBPF Sensor di setiap
`--auto` startup, mengabaikan total `EBPF_SENSOR`'s `default_enabled=False`
di registry. **FIXED** -- keduanya sekarang lewat
`bootstrap_startup_daemons()`. **Breaking change**: operator yang
biasa pakai `YOMI_ENABLE_GHOST_PROTOCOL=true` sekarang harus pakai
`YOMI_MODULE_GHOST=true`. Didokumentasikan di `docs/usage.md`.

### Bug ditemukan & diperbaiki di test saya sendiri (bukan kode Yomi), 3 total

1. **Kebocoran file ke `yomi_data/` asli repo (paling serius).** Waktu
   pertama kali jalanin integration test setelah wiring guardian, file
   dossier PDF/TXT/sig **beneran ditulis** ke `yomi_data/reports/` asli
   (bukan `tmp_path` terisolasi) -- karena `remediator.py`, `dossier.py`,
   dan `library.py` (dipakai transitif oleh `mind_reader.py`) semua
   pakai pola `__file__`-relative yang sama seperti `swarm.py`, tapi
   fixture `sentinel` di `test_chain_sentinel_router_harness.py` cuma
   monkeypatch `swarm_module.__file__`. Ketahuan karena `git status`
   dicek manual SETELAH test hijau, bukan diasumsikan aman cuma karena
   "PASSED". Fixture diperbaiki: tambah monkeypatch `__file__` untuk
   `remediator_module`, `dossier_module`, `library_module`. Verifikasi
   ulang: `git status --short` bersih setelah run.
2. **2 test `test_guardian.py` sendiri lupa minta fixture `isolated_stamp`**
   (`test_mirage_enabled_without_sandbox_dependency_fails_loud_at_construction`,
   `test_periodic_maintenance_sweeps_mirage_only_every_n_cycles`) --
   keduanya construct `GuardianOrchestrator()` manual di dalam body test
   (bukan lewat fixture `guardian` yang sudah isolated), jadi
   `ImmutableStamp()` di dalamnya kena singleton real yang belum
   ter-reset. Ketahuan dengan cara scan otomatis: jalankan setiap test
   satu-per-satu, cek `git diff yomi_data/` sesudahnya, `git checkout`
   ulang kalau berubah. Diperbaiki dengan menambah `isolated_stamp` ke
   signature kedua test itu. Re-scan penuh setelah fix: nol kebocoran.
3. Assertion pertama saya untuk `REMEDIATOR` di integration test asumsi
   sembarang isi pesan penolakan -- diperbaiki jadi cek isi persis
   ("critical system path") setelah verifikasi manual pesan asli dari
   fix #15.

### Verifikasi

- **482/482 test lulus** (unit + integration, root), stabil.
- **481 passed + 1 skipped sebagai non-root, 5x run berturut-turut.**
- Coverage `yomi_core/guardian.py`: **93%** (25 test baru di
  `test_guardian.py`). Sisa 7% adalah baris pesan cetak/log di jalur
  error yang jarang dan tidak esensial untuk dites lebih lanjut.
- Lint bersih.
- `git status` dicek manual setelah setiap run test integration untuk
  memastikan tidak ada file bocor ke `yomi_data/` asli -- bukan cuma
  mengandalkan "test PASSED".
- Integration test membuktikan dispatch nyata (bukan mock) terhadap
  PID subprocess sungguhan: `REMEDIATOR` menolak `python3` interpreter
  path (di `/usr`) sesuai fix #15, `DOSSIER` generate laporan
  bertanda tangan sungguhan -- dikonfirmasi lewat entry ledger, bukan
  diasumsikan.

### Sisa Tahap 1

Tidak ada -- semua modul (13/13) sekarang tersambung, gated oleh
registry, teruji. #11 FIXED, #25 diakali (didokumentasikan), #26 FIXED.

## Dokumentasi lengkap & smoke test (lanjutan Tahap 1)

Setelah wiring inti selesai, Arcia minta dokumentasi cara pakai yang benar-benar
lengkap (level "seperti apply jurnal Q1") -- ketauan beberapa hal yang saya
sebutkan di chat sebelumnya (instalasi daemon, cara verifikasi, demo
containment) **belum pernah ditulis ke dokumentasi resmi**. Diperbaiki total:

### `scripts/smoke_test_cli.py` -- dari stub jadi implementasi nyata

File ini sebelumnya stub yang sengaja nunggu Guardian Orchestrator ada dulu.
Sekarang diimplementasikan penuh: boot `SentinelDaemon` sungguhan, feed
anomali CRITICAL sintetis ke subprocess sungguhan (harmless), dan verifikasi
lewat 4 assertion konkret (proses beneran SIGSTOP via `/proc`, entry ledger
`AUTONOMOUS_CONTAINMENT`, `REPORT_SIGNED`, dan `ABORTED` dengan alasan
"critical system path"). Diisolasi penuh ke temp dir (tidak pernah sentuh
`yomi_data/` asli), satu-satunya boundary yang di-mock adalah panggilan LLM.
Diwire ke `run_tests.sh smoke` dan masuk ke `run_tests.sh` (mode `all`).

Dijalankan 5x berturut-turut untuk stabilitas -- lulus semua, exit code 0
tiap kali. `git status` dicek manual tiap run -- bersih.

### Temuan baru saat capture demo penuh (#29, #30)

Sambil menjalankan skenario `DEMO_PROFILE_ENV` penuh (semua modul invasive
aktif) untuk dapat output nyata buat dokumentasi, ketauan 2 hal:

**#29 (FIXED):** `sandbox.py`'s `_monitor_awakened_threat` (dipanggil dari
thread monitoring post-detonation) manggil `MindReaderDecompiler()` dan
`MirageProtocol()` **tanpa cek `module_registry` sama sekali** -- bug class
persis sama dengan #26, tapi di call site yang berbeda dari
`GuardianOrchestrator`'s dispatch. Diperbaiki: kedua panggilan sekarang cek
`resolve_active_modules()` dulu. Test baru:
`test_monitor_awakened_threat_respects_disabled_mirage_and_mind_reader`, plus
2 test lama diupdate (perlu eksplisit `YOMI_MODULE_MIRAGE=true` sekarang,
karena default-nya OFF dan sebelumnya kode lama nggak pernah cek itu).

**#30 (OPEN, dicatat bukan diperbaiki):** Mirage decoy punya lifecycle
asimetris kalau `SANDBOX` aktif -- 1 PID insiden bisa punya 2 decoy Mirage
independen (satu dari Guardian's pre-detonation dispatch, satu dari
Sandbox's sendiri post-detonation dispatch). Sandbox teardown punyanya
sendiri segera; punya Guardian nggak pernah di-teardown eksplisit, cuma
nunggu periodic sweep. Bukan lubang keamanan, bukan data loss, tapi kalau
nggak didokumentasikan bisa disalahartikan sebagai ledger yang aneh (2x
`HALLUCINATION_DEPLOYED`, cuma 1x `HALLUCINATION_TEARDOWN`).

### Dokumentasi yang ditulis/diperluas

- **`docs/usage.md`**: 2 section baru (~200 baris) -- "Installing as a
  Persistent Daemon (Linux)" (penjelasan lengkap `install_yomi_linux.sh`:
  apa yang dilakukan, cara pakai, cara kelola, kenapa venv+`--system-site-packages`,
  kenapa warning kunci HMAC) dan "Verifying and Observing Yomi" (cara baca
  ledger + tabel `action_type`, cara jalanin smoke test dengan output asli
  yang di-capture, cara memicu skenario containment manual dengan aman).
- **`docs/demo_mode.md`**: ditulis ulang jadi 4 section -- walkthrough
  demo penuh dengan **output ledger asli yang di-capture**, penjelasan
  eksplisit soal MindReader/Mirage muncul 2x (referensi #29/#30 biar nggak
  disalahartikan bug), dan section baru "Testing with real forensic
  datasets" (NIST CFReDS, Digital Corpora, Volatility Foundation's Memory
  Samples wiki -- 3 sumber gratis terverifikasi lewat web search, bukan
  hafalan, plus contoh command persis pakai `SiftArsenal`/`YomiMCPServer`).
- **`README.md`** dan `docs/accuracy_report.md`: update kecil (anchor link
  yang berubah nomor, `run_tests.sh smoke` ditambahkan ke tabel).
- **`run_tests.sh`**: tambah mode `smoke`, masuk ke `run_tests.sh` (`all`).

### Verifikasi

- **483/483 total** (unit+integration+bench, plus smoke test terpisah) lulus.
- Smoke test 5x run berturut-turut, stabil, exit code 0.
- Setiap klaim konkret di dokumentasi baru (isi ledger, path resolusi,
  nama fungsi `SiftArsenal`, URL dataset) diverifikasi langsung -- bukan
  ditulis dari ingatan/asumsi.

## Tahap 2 & 3

Belum dimulai. Direncanakan konkret setelah Tahap 1 dikonfirmasi solid
oleh Arcia (termasuk setelah bisa dijalankan/dicoba langsung di
Codespaces, yang kredit-nya baru diperbarui 1 September).
