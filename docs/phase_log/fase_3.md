# Fase 3 — Lapisan 2: router, mcp_server, hunter, swarm, dossier, mind_reader, shadow_net, dashboard

**Status:** Sedang berjalan · **Branch:** `foundation/layer2-modules`

> Living document, di-update tiap ada progress baru.

## Cakupan modul

8 modul Lapisan 2 (bergantung ke Lapisan 1): `router.py`, `mcp_server.py`,
`hunter.py`, `swarm.py`, `dossier.py`, `mind_reader.py`, `shadow_net.py`,
`dashboard.py`.

## Progress

### ✅ Batch 1 — `dossier.py` (12 test), `dashboard.py` (22 test)

**`dossier.py`**: pembuatan PDF+TXT dual-artifact, penandatanganan
GPG→HMAC→SHA256 (pola sama kayak `remediator.py`), integritas hash raw,
penanganan karakter non-Latin-1 (TXT annex harus tetap simpan Unicode asli
meski PDF-nya transliterasi — sesuai klaim "Prevents Evidence Spoliation").
Butuh install `fpdf==1.7.2` di sandbox (sudah ada di `requirements.txt`,
cuma belum ter-install sesi ini). **Nggak ada bug baru.**

**`dashboard.py`**: sanitasi log (ANSI escape, RTL override `\u202E`,
truncation 2000 karakter, eviction 100 entry), klasifikasi warna log
(prioritas threat > deception > warning > success), refresh telemetry dari
file JSONL (termasuk skip baris korup), refresh metrics library & sistem
(psutil beneran), lifecycle thread background (start/stop bersih). Butuh
install `rich==13.7.1`. **Nggak ada bug baru** — dua-duanya modul yang
solid.

2 bug di test saya sendiri ketemu & diperbaiki selama nulis (bukan di
kode Yomi): path assertion nggak di-normpath (dossier), off-by-one di
ekspektasi eviction log (dashboard).

### Ringkasan Batch 1
**34 test baru, 0 bug baru di kode Yomi.**

### ✅ Batch 2 — `hunter.py` (23 test), `swarm.py` (34 test)

**`hunter.py`**: resolusi sumber forensik (env var override, fallback root
POSIX), parsing timeline Plaso (word-boundary PID matching — dibuktikan
`234` nggak salah match di dalam `812345`, kategorisasi event: logon,
shell, credential access, persistence, keyword `MALICIOUS` universal,
sorting kronologis, cap 5 event, truncation 500 char), parsing TSK
(deteksi file dihapus/carved, dedup+cap), orkestrasi penuh
`hunt_root_cause` (PID invalid, sumber forensik nggak ada, tool nggak
tersedia). **Nggak ada bug baru.**

**`swarm.py`**: sanitasi log (masking password/API key/Bearer token),
klasifikasi IP eksternal vs private/loopback/multicast/link-local,
ekstraksi IP & PID dari teks (dedup+sort), penguncian inode fisik
(hardlink → fallback read-only kalau disk penuh → fallback copy kalau
disk cukup — tiga jalur dites nyata pakai file asli), live network scan
(mock `psutil.net_connections`), agent memory & network (orkestrasi
Volatility/TShark), **verifikasi klaim "false positive immune C2
detection"** — dibuktikan valid: string `http.host` polos (misal dari
path file) TIDAK memicu alert, tapi `http.host == evil.com` (sintaks
query asli) MEMICU. **Nggak ada bug baru.**

1 bug di test saya sendiri ditemukan & diperbaiki (bukan di kode Yomi):
assertion urutan kronologis ketipu header ringkasan yang nyebut tanggal
duluan sebelum daftar event.

### Ringkasan Batch 2
**57 test baru, 0 bug baru di kode Yomi.**

### 🔄 Batch 3 (sedang berjalan) — `router.py` (30 test), `mcp_server.py` (22 test)

**`router.py`** (`OpenClawGateway` + `YomiRouter`): kaskade LLM (Gemini →
lokal, urutan model, fallback penuh), ekstraksi teks respons (Gemini
string/list-fragment, local message.content/text), `_extract_json_payload`
brace-depth matching (bukan regex — terbukti bener nangani nested braces
dan markdown fencing), estimasi token metrics, loop ReAct penuh
(`_evaluate_intent`: type-confusion defense buat `epistemic_doubt`/
`target_pid`, self-correction, veto retry dengan feedback, eskalasi Shadow
Net setelah `max_iterations`).

**Temuan penting**: awalnya saya duga ada gap di penanganan `action:
"unknown"` — ternyata analisis awal saya salah (harness punya whitelist
sendiri `["freeze","thaw"]` yang lebih ketat dari router, jadi `"unknown"`
kena VETO duluan, bukan lolos). Tapi investigasi itu nemuin dua hal nyata:
1. **Dead code terkonfirmasi** di `harness.py`: baris fallback `"Action
   valid but no OS routing defined"` **nggak mungkin ke-reach** — cuma
   `freeze`/`thaw` yang bisa lolos veto, dan keduanya selalu ke-dispatch.
   Ditambahkan regression test yang enumerate semua `allowed_actions`.
2. **Gap nyata ditemukan**: kalau `freeze`/`thaw` lolos veto TAPI gagal di
   level OS (`os_bridge` balikin `GHOST_PROCESS` atau `ERROR` — misal PID
   udah mati), loop `execute_autonomous_triage` **nggak punya cabang buat
   status itu** — diam-diam lanjut iterasi tanpa kasih feedback ke LLM,
   beda dari semua jalur penolakan lain (REJECTED/SELF_CORRECTION/VETOED
   semuanya kasih feedback). Didokumentasikan sebagai regression test,
   belum diperbaiki (perlu keputusan: cabang baru atau treat as VETOED).

**`mcp_server.py`**: validasi argumen dinamis (PID numerik, path traversal
`..`, boundary vault, operator shell `$() \` | ; && || >`), rute VVIP
freeze/thaw yang bypass thread pool, load shedding (reject instan kalau
worker penuh), akuntansi `active_tasks` yang tetap benar meski tool
exception atau timeout (`finally` di wrapper), truncation output 100KB.
Konfirmasi ulang gap vault hardcoded (`known_issues.md` #12) — bukan bug
baru, cuma reverifikasi.

3 bug di test saya sendiri ditemukan & diperbaiki selama nulis (bukan di
kode Yomi): analisis awal yang salah soal action "unknown" (diperbaiki
jadi skenario yang benar), signature lambda `submit()` yang salah jumlah
argumen.

### Ringkasan Batch 3 sejauh ini
**52 test baru, 0 bug crash baru, 1 gap logika nyata + 1 dead code
terkonfirmasi.**

### ✅ Batch 3 (selesai) — `router.py` (30), `mcp_server.py` (22), `mind_reader.py` (17), `shadow_net.py` (20)

**`mind_reader.py`**: ekstraksi string fallback native (regex ASCII 4+
karakter, cap baca 1MB), orkestrasi penuh `decompile_and_profile`
(binary hilang, fallback dari Radare2 ke native extractor, truncation
4000 karakter, **schema mimicry** — CVE palsu format `CVE-YYYY-YOMIxxxx`
buat nyuntik profil ke `OmniLibrary` biar bisa di-query O(1)), profiling
via LLM (`_derive_profile_from_assembly`: sukses pakai respons LLM,
fallback heuristik kalau field wajib nggak lengkap atau LLM error,
klasifikasi skill level berdasarkan pola assembly). **Nggak ada bug baru.**

**`shadow_net.py`**: resolusi `/proc/[pid]/stat`+`/proc/[pid]/exe` (dites
nyata pakai proses sendiri), `deploy_micro_hook` (PID invalid, eBPF nggak
ada, hook udah aktif, binary nggak keresolve → cleanup hook entry),
`_monitor_syscalls_safe` (isolasi exception, cleanup di `finally`),
`_monitor_syscalls_logic` (nggak ada ancaman, freeze gagal → stop awal,
**deteksi PID recycling** via start-time mismatch → thaw + fallback
`SIGCONT` mentah kalau thaw gagal, ancaman terkonfirmasi → kill chain),
`_execute_kill_chain` (orkestrasi `remediator`+`sandbox` yang di-mock,
**pemulihan ELF nyata dari `/proc/pid/exe`** pakai subprocess asli —
bukan mock — buat kasus fileless, quarantine escalation kalau recovery
gagal). **Nggak ada bug baru.**

2 bug di test saya sendiri (bukan kode Yomi): perbandingan path terlalu
ketat (`sys.executable` vs resolusi `/proc/self/exe` yang beda level
symlink).

### Ringkasan Batch 3 (final)
**89 test baru, 0 bug crash baru, 1 gap logika + 1 dead code
terkonfirmasi** (keduanya dari `router.py`/`harness.py`).

## FASE 3 SELESAI — Ringkasan total
- **232 test baru** (402/402 total, stabil 3x run berturut-turut)
- **1 gap logika ditemukan** (router.py, belum diperbaiki — butuh
  keputusan produk), **1 dead code terkonfirmasi** (harness.py, dijaga
  regression test)
- Lint bersih, nggak ada residu (mount/thread/signal handler) setelah run
- Semua 8 modul Lapisan 2 selesai diuji
