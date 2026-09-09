# Roadmap: Kedalaman DFIR ("Sedalam Palung Mariana")

**Status:** Visi resmi, belum mulai dikerjakan. Ditulis Fase 4, dieksekusi
setelah Fase 6 (Guardian Orchestrator + Module Registry, lalu Release +
KuroTech landing page) selesai.

## Latar belakang

Setelah hackathon SANS "FIND EVIL!", analisis kompetitif terhadap 3 dari 5
finalis (FindEvil, Mulder, Camel — dibaca langsung dari repo GitHub publik
mereka, bukan cuma blurb Devpost) menemukan pola konsisten: ketiganya
beroperasi murni sebagai **post-incident forensic investigator terhadap
bukti statis** (memory dump, disk image, PCAP yang sudah dikumpulkan).
FindEvil bahkan eksplisit menulis sebagai prinsip desain inti: *"examined
on a clean workstation (SIFT) — never the live, untrusted host."*

Yomi, dengan `ebpf_sensor.py` (intersepsi syscall kernel real-time) dan
`sentinel.py` (jalur "shoot first, ask AI later" — `SIGSTOP` sebelum LLM
dipanggil), beroperasi di kategori berbeda: **live EDR + active defense**.

**Kesimpulan strategis:** Yomi kalah di SANS bukan karena live-response-nya
tidak berharga, tapi karena kompetisi menilai kedalaman forensik
post-mortem — dan Yomi terlalu lebar (EDR + honeypot + sandbox + forensik
sekaligus, masing-masing setengah teruji) dibanding bar yang ditetapkan
tiga finalis itu.

## Keputusan

**Dalami DFIR/post-mortem dulu sampai benar-benar berat**, baru rambat ke
EDR live-response. Bukan cuma "bisa handle memory dump besar" — itu cuma
satu titik data pembanding ke Mulder (120GB, NIST-validated). Definisi
"dalam" yang dipakai proyek ini mencakup **seluruh permukaan DFIR**, bukan
satu jenis artefak saja.

## Cakupan "Sedalam Palung Mariana" — per kategori artefak forensik

| Kategori | Tool wrapper di Yomi | Status kedalaman saat ini |
|---|---|---|
| Memory forensics | Volatility (`pslist`, `netscan`, `yarascan`, `malfind`) | Wrapper ada, belum divalidasi terhadap ground-truth publik |
| Disk/filesystem | TSK (`fls`, `icat`, `mftparser`), Scalpel carving | Wrapper ada, belum diuji skala besar |
| Timeline analysis | Plaso `log2timeline` | Wrapper ada, tapi parsing di `hunter.py` cuma keyword+PID sederhana — belum ada *super timeline* correlation sungguhan |
| Network forensics | tshark/PCAP | Wrapper ada, deteksi C2 udah presisi (dibuktikan Fase 3) tapi belum diuji PCAP besar |
| Malware/binary analysis | Radare2 + `mind_reader.py` | Ada, fallback ke string-extraction kalau r2 gagal — belum ada disassembly correlation lintas sample |
| Registry forensics | `reglookup` | Wrapper ada, **belum pernah diuji integrasinya sama sekali** |
| **Cross-artifact correlation** | **Tidak ada** | **Gap terbesar** — ini yang bikin Mulder kuat: bukan cuma "bisa parsing tiap tipe data", tapi menyatukan timeline+YARA+network+registry jadi satu narasi investigasi koheren |

## Tiga tolok ukur dari kompetitor (jadi acuan, bukan ditiru mentah)

1. **Validasi ground-truth**, bukan cuma "tidak crash". Mulder pakai NIST
   answer key resmi. Rujukan publik yang relevan: NIST CFReDS, Digital
   Corpora, DFIR challenge dataset Ali Hadi.
2. **Skala data besar tanpa collapse context LLM.** Mulder pakai SQLite+FTS5
   sebagai buffer, bukan nge-dump output tool mentah ke context window.
   **Temuan konkret dari kode Yomi sendiri:** `hunter.py`/`sift_toolkit.py`
   masih truncate 100KB langsung — ini akan jadi bottleneck nyata begitu
   dump >2GB masuk. Keputusan arsitektur ini perlu diambil sebelum
   "kedalaman" bisa tercapai, bukan sekadar bug fix.
3. **Provenance yang menolak klaim palsu**, bukan cuma mencatat. Mulder
   menolak finding kalau `evidence_refs` tidak match `tool_call_id` asli di
   audit log. FindEvil punya `verify_finding` sebagai gate wajib sebelum
   `finalize_report`. Yomi punya ledger yang mencatat semua (`stamp.py`),
   tapi belum punya mekanisme yang **aktif menolak** klaim yang tidak bisa
   ditelusuri balik ke tool call asli.
4. **Skenario uji yang saling bertentangan secara sengaja** (seperti 29
   skenario FindEvil: false-flag APT, sanctioned pentest, dormant
   compromise, insider threat) — supaya sistem terbukti tidak overfit ke
   satu pola serangan.

## Visi jangka panjang

Satu sistem, dua mode yang saling melengkapi — bukan ditempel jadi satu:
- **Pre-mortem** (EDR real-time) — melindungi hardware saat kejadian berlangsung
- **Post-mortem** (DFIR mendalam) — melacak pelaku setelah kejadian, dengan bukti yang defensible

Kombinasi ini genuinely tidak ada di kelima finalis SANS manapun.

## Urutan eksekusi (belum mulai)

Ini **bukan** bagian dari Fase 0-6 yang sedang berjalan. Dijadwalkan
sebagai program kerja terpisah (sebut saja Fase 7+) setelah Release + landing
page KuroTech selesai, dengan branch dan roadmap detail sendiri —
kemungkinan dimulai dari cross-artifact correlation layer (gap terbesar),
lalu validasi ground-truth per kategori artefak satu-satu, baru terakhir
provenance-rejection gate.
