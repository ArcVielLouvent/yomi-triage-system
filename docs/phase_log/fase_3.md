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

### ⏳ Belum dikerjakan
Batch 3 (paling berat): `router.py`, `mcp_server.py`, `mind_reader.py`, `shadow_net.py`

## Ringkasan Fase 3 sejauh ini
- **91 test baru** (312/312 total, stabil 3x run)
- **0 bug baru**
- Lint bersih
