# Fase 5 — README Split + 3 Gerbang Wajib Pra-Fase 6 (#12, #13, #21)

**Status:** SELESAI · **Branch:** `docs/readme-split`

> Living document sesi ini dikerjakan ulang dari nol berdasarkan kode
> `develop` yang sudah di-merge (Fase 4 selesai), karena sesi sebelumnya
> terlalu panjang dan terputus sebelum sempat commit/push. Semua isi di
> bawah ini diverifikasi langsung terhadap kode nyata di repo, bukan
> disalin mentah dari ringkasan sesi sebelumnya.

## Cakupan

1. **README split** (tujuan asli Fase 5): pisahkan `README.md` lama
   (539 baris, campur pitch hackathon + dokumentasi teknis) jadi README
   ramping + `docs/` terstruktur.
2. **Issue #13** (checkpoint mismatch message menyesatkan) — dibarengin
   sama beres-beres dokumentasi, sesuai keputusan triase.
3. Dua dari empat gerbang wajib sebelum Fase 6: **#21** (router.py no
   OS-level feedback) dan **#12** (stamp.py coverage 54%). *(#14 dan #15,
   remediator.py, belum dikerjakan sesi ini — lihat "Sisa pekerjaan" di
   bawah.)*

## 1. README Split

README lama dipecah jadi:
- **`README.md`** (56 baris) — pitch singkat, kenapa Yomi beda dari
  finalis SANS, quickstart, tabel link ke semua dokumentasi.
- **`docs/architecture.md`** (206 baris) — arsitektur sistem, 3 diagram
  Mermaid, referensi modul inti, catatan status wiring `sentinel.py`
  (5/13 modul, dicatat sebagai konteks untuk gap arsitektural yang
  sudah ada).
- **`docs/security.md`** (126 baris) — framework keamanan/compliance,
  tabel hardening MCP Vault, threat model, arsitektur keamanan lanjutan.
- **`docs/installation.md`** (60 baris) — prasyarat, instalasi, konfigurasi
  env var.
- **`docs/usage.md`** (95 baris) — perintah operasional, skenario
  taktis, metrik performa.
- **`docs/hackathon/sans_submission.md`** (58 baris) — konten spesifik
  hackathon **diarsipkan**, dipisah total dari README utama, dengan
  catatan arsip di bagian atas.

Tidak ada konten yang hilang -- setiap bagian dari README lama dipetakan
ke salah satu file baru, atau diarsipkan secara eksplisit ke
`docs/hackathon/`.

## 2. Issue #13 — Checkpoint mismatch message

`_create_or_verify_checkpoint()` di `stamp.py` mencetak "Checkpoint
mismatch detected. Updating..." setiap kali ledger sudah maju sejak
checkpoint terakhir ditulis — ini kondisi **normal setiap restart**
(bukan sinyal tamper), tapi kalimatnya kebaca kayak alert keamanan.

**Fix:** pesan diganti jadi "Checkpoint routine update: ledger has new
entries since the last checkpoint (expected on normal restart).
Re-anchoring checkpoint to the current ledger state." Deteksi tamper
sungguhan tidak disentuh — itu sepenuhnya di `verify_soc_checkpoint()`
lewat verifikasi HMAC attestation, fungsi yang berbeda.

Regression test:
`tests/unit/test_stamp_coverage.py::test_checkpoint_routine_update_on_ledger_advance`.

## 3. Issue #21 — router.py: tidak ada feedback untuk kegagalan OS-level

`execute_autonomous_triage`'s ReAct loop punya cabang eksplisit buat
`REJECTED`, `SELF_CORRECTION_REQUIRED`, `SUCCESS`-non-vetoed, dan
`VETOED` — tapi kalau aksi `freeze`/`thaw` lolos veto lalu gagal di
level OS (`os_bridge` balikin `GHOST_PROCESS` atau `ERROR` generik),
tidak ada cabang yang cocok. Loop diam-diam lanjut iterasi berikutnya
tanpa `[SYSTEM FEEDBACK]` apa pun ke LLM.

**Fix:** ditambahkan cabang fallback eksplisit setelah pengecekan
`VETOED` — status apa pun yang bukan salah satu dari 4 kondisi di atas
sekarang menambahkan `[SYSTEM FEEDBACK]` berisi status + alasan
(cek key `message` maupun `reason`, karena `os_bridge` pakai `reason`
sementara pesan veto internal harness pakai `message`), lalu
`continue` supaya LLM dapat kesempatan retry dengan info itu.

Dua test baru:
- `test_triage_os_level_failure_gets_system_feedback_and_can_recover` —
  memverifikasi feedback muncul dan retry berhasil kalau kondisi hilang.
- `test_triage_persistent_os_level_failure_eventually_escalates` —
  memverifikasi tetap eskalasi ke Shadow Net (bukan infinite loop) kalau
  kondisi gagal terus menerus.

Test lama yang dulu sengaja menangkap perilaku buggy
(`test_triage_KNOWN_GAP_...`) sudah diganti total, bukan cuma di-skip.

## 4. Issue #12 — stamp.py coverage 54% → 89%

File test baru: `tests/unit/test_stamp_coverage.py` (45 test). Menyasar
jalur yang sebelumnya 0% tersentuh:

- **KMS dispatch**: tidak ada provider, provider tidak dikenal, dispatch
  ke Vault, dispatch ke AWS Secrets Manager.
- **Vault**: config tidak lengkap, sukses (bentuk data flat & nested
  KV-v2), nama field custom, request gagal (exception), field hilang
  dari respons.
- **AWS Secrets Manager**: `secret_id` hilang, `boto3` tidak terpasang
  (`ImportError`), sukses lewat `SecretString`, sukses lewat
  `SecretBinary`, client exception.
- **Kunci ephemeral (PBKDF2)**: password dari env var, tanpa password
  non-interaktif, password kosong ditolak, salt persisten & bisa dibaca
  ulang, deterministik untuk password+salt yang sama.
- **`_backup_corrupted_ledger`**: bikin backup + metadata, no-op kalau
  ledger tidak ada, gagal copy ditangani (tidak crash).
- **`cleanup_corrupt_backups`**: retensi sesuai `retain_last`, retensi 0
  hapus semua, gagal hapus file ditangani, trigger via env flag.
- **`_create_or_verify_checkpoint`**: dibuat pertama kali, update rutin
  (verifikasi wording baru dari Issue #13), gagal tulis ditangani.
- **`verify_soc_checkpoint`**: belum ada checkpoint (True), attestation
  valid (True), signature hilang (False), termodifikasi/tamper (False),
  error baca file (False).
- **Round-trip pemulihan korupsi ledger**: corrupt di tengah jalan →
  backup otomatis → re-init → entry `LEDGER_RECOVERY` tercatat.
- **`_atomic_write` mode biner**, **fallback legacy hash** di
  `_verify_ledger` (format JSON lama tanpa compact separator).

Semua panggilan eksternal (`requests`, `boto3`) di-mock — tidak ada
network call sungguhan ke Vault/AWS mana pun.

**Hasil:** `yomi_audit/stamp.py` naik dari **54% → 89%** coverage.
Sisa 11% nyaris seluruhnya blok defensif `except OSError: pass` di
sekitar panggilan `os.chmod` yang butuh mocking OS call gagal tanpa
alasan fungsional untuk dipicu — tidak dianggap sepadan untuk dikejar
lebih jauh saat ini.

### Bug ditemukan di test saya sendiri (bukan kode Yomi), 4 total

1. String test buat jalur fallback base64→UTF-8 (`"x" * 40`) ternyata
   valid base64 (panjang 40 habis dibagi 4 dan cuma pakai karakter
   alfabet base64) — jadi malah tidak pernah masuk jalur fallback yang
   dimaksud. Diganti string yang benar-benar mengandung karakter di
   luar alfabet base64.
2. Asumsi salah soal file checkpoint notary "belum ada" saat fixture
   baru dibuat — ternyata `_anchor_soc_checkpoint` jalan di **setiap**
   `_append_entry`, termasuk entry genesis, jadi file itu sudah ada
   sejak inisialisasi pertama. Test yang butuh kondisi "belum ada"
   diperbaiki dengan menghapus file itu dulu secara eksplisit.
3. Kalkulasi jumlah file backup yang salah di test `retain_last` —
   awalnya cuma menghitung file `.jsonl`, padahal
   `cleanup_corrupt_backups` menghitung `.jsonl` DAN `.metadata.json`
   sebagai entry terpisah dalam list yang sama. Ini bukan cuma bug di
   test saya — ini mengarah ke **temuan desain nyata** di bawah.
4. **Ditemukan setelah run pertama di Codespaces (bukan di sandbox
   sesi ini)**: dua test simulasi tamper
   (`test_verify_soc_checkpoint_false_when_signature_missing` dan
   `test_verify_soc_checkpoint_false_when_tampered`) menulis ulang
   `notary_checkpoint_file` langsung dengan `open(..., "w")` tanpa
   chmod dulu. Di sandbox root, ini lolos karena root membypass
   permission check OS. Tapi `_anchor_soc_checkpoint` sengaja
   men-set file itu ke **`0o400` (read-only, proteksi gaya WORM)**
   setelah ditulis — jadi di lingkungan non-root sungguhan (Codespaces,
   `whoami` = `codespace`), `open("w")` kena `PermissionError` sebelum
   sempat menguji assertion yang dituju. Diperbaiki dengan
   `os.chmod(..., 0o600)` sebelum menulis ulang, meniru langkah yang
   memang harus dilakukan penyerang sungguhan sebelum bisa mengubah
   file itu — jadi hasilnya malah lebih realistis dari sebelumnya, bukan
   cuma tambal test. **Diverifikasi ulang dengan menjalankan test suite
   sebagai user non-root (`nobody`) di sandbox, bukan cuma diyakini
   benar** — 447 passed + 1 skipped, stabil 5x run berturut-turut,
   sebelum dipaketkan ulang.

### Temuan desain nyata: known_issues.md #24 (baru, OPEN)

Selagi menulis test `retain_last`, ketemu bahwa `cleanup_corrupt_backups`
menghitung **file individual**, bukan **insiden**. Setiap backup
menghasilkan 2 file (`.jsonl` + `.metadata.json`) yang masuk list
gabungan yang di-sort by mtime lalu dipotong di `retain_last`. Jadi
`retain_last=1` bisa nyisain cuma `.metadata.json` doang tanpa
`.jsonl` pasangannya — bukan "1 insiden lengkap yang utuh" seperti nama
parameternya menyiratkan.

Bukan kehilangan data ledger utama, bukan bisa dieksploitasi lewat API
publik, tapi janji retensi dari nama parameternya tidak benar-benar
terpenuhi. Dicatat sebagai entry #24 di `docs/known_issues.md`, status
OPEN — ditemukan sambil nulis test coverage untuk #12, bukan tugas
tersendiri sesi ini, jadi tidak diperbaiki sekarang.

## Verifikasi

- `./run_tests.sh` (via `pytest tests/unit`) hijau **5x run berturut-turut**
  — **448/448 test lulus**, termasuk 45 test baru di
  `test_stamp_coverage.py` dan 2 test router.py yang diperbarui.
- **Diverifikasi ulang sebagai user non-root** (bukan cuma sebagai root
  di sandbox) setelah bug #4 di atas ketahuan dari run pertama di
  Codespaces — 447 passed + 1 skipped, stabil 5x run berturut-turut.
  Perbedaan hasil root-vs-non-root murni soal permission file
  (`0o400` WORM lock beneran ditegakkan sebagai non-root, dibypass
  sebagai root), bukan perbedaan logika.
- Coverage `yomi_audit/stamp.py`: **54% → 89%**. (Your first Codespaces
  run showed 88% with lines 652-655/672-675 missing -- that's not a
  different environment quirk, it's simply because the 2 failing tests
  errored out with `PermissionError` before ever reaching the
  tamper-comparison code those lines cover. With the fix above, those
  tests pass and those lines get exercised, back to 89%.)
- Tidak ada regresi di `test_stamp.py` maupun `test_router.py` yang sudah
  ada.

## Sisa pekerjaan (belum di sesi ini)

1. Issue **#14** — `remediator.py` tidak ada proteksi PID kritis.
2. Issue **#15** — `remediator.py` path-check exact-match, bukan prefix.
3. Jalankan `scripts/create_known_issues_fase5.sh` (buat issue GitHub
   baru #24, tutup #14/#15/#23 lama — *catatan: nomor GitHub #14/#15 di
   sini adalah untuk stamp-coverage & checkpoint-message, JANGAN
   tertukar sama rencana remediator.py #14/#15 di known_issues.md
   penomoran lokal, yang beda skema*).
4. Setelah #14 dan #15 (remediator.py) beres, baru declare 4-issue-
   prioritas pra-Fase-6 selesai semua, lanjut ke **Fase 6** (Release +
   landing page KuroTech).

## Ringkasan angka

- Total temuan di `docs/known_issues.md`: **24** (#1-24), naik dari 23.
- 3 temuan lama (#12, #13, #21) berubah status jadi **FIXED**.
- 1 temuan baru (#24) ditambahkan, status **OPEN**.
- Total test suite: **448/448** hijau, stabil 5x run berturut-turut.
