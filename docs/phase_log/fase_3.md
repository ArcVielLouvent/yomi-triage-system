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

### ⏳ Belum dikerjakan
`mind_reader.py`, `shadow_net.py`

## Ringkasan Fase 3 sejauh ini
- **143 test baru** (365/365 total, stabil 3x run)
- **1 gap logika ditemukan** (router.py, `known_issues.md` #21), **1 dead
  code terkonfirmasi** (harness.py)
- Lint bersih
