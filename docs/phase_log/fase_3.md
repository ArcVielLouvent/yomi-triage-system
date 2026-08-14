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

### ⏳ Belum dikerjakan
Batch 2: `hunter.py`, `swarm.py`
Batch 3 (paling berat): `router.py`, `mcp_server.py`, `mind_reader.py`, `shadow_net.py`

## Ringkasan Fase 3 sejauh ini
- **34 test baru** (255/255 total, stabil 3x run)
- **0 bug baru**
- Lint bersih
