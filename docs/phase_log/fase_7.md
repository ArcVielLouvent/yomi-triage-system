# Fase 7 — Cross-Artifact Correlation Layer (Tahap 1: Desain)

**Status:** Sedang berjalan (Tahap 1 inti selesai, terverifikasi end-to-end) · **Branch:** `feature/cross-artifact-correlation`

> Bagian dari roadmap [`docs/roadmap/dfir-depth.md`](../roadmap/dfir-depth.md)
> ("Sedalam Palung Mariana"). Dijadwalkan setelah landing page KuroTech di
> roadmap aslinya, tapi dieksekusi lebih dulu (keputusan Arcia: landing page
> nunggu budget hosting, nggak ada dependency teknis ke correlation layer).
> Cross-artifact correlation adalah gap terbesar dibanding tiga finalis SANS
> yang dianalisis (FindEvil, Mulder, Camel) — lihat roadmap untuk detail
> analisis kompetitif.

## Kenapa mulai dari sini

Yomi punya wrapper buat tiap kategori artefak forensik (memory, disk,
timeline, network, malware/binary, registry) tapi masing-masing beroperasi
**terisolasi**. Nggak ada yang menyatukan temuan mereka jadi satu narasi
investigasi koheren. Ini persis yang bikin Mulder (finalis SANS) kuat:
bukan cuma "bisa parsing tiap tipe data", tapi korelasi timeline+YARA+
network+registry jadi satu cerita.

## Temuan arsitektur (dari baca kode sebelum desain)

**Cikal-bakal correlation sudah ada, tapi ad-hoc dan sekali pakai.**
`sentinel.py::_build_forensic_context()` sudah manual gabungin hasil
`Hunter.hunt_root_cause()` + `MitreMapper.map_anomalies()` + anomaly list
jadi satu JSON string — tapi cuma buat dikirim ke LLM router sekali,
langsung dibuang, nggak pernah disimpan sebagai artefak sendiri.

**Correlator TIDAK BOLEH baca ulang ledger, harus nangkep data live.**
`weaver.py` (pembuat laporan akhir) baca ulang `stamp.py`'s ledger buat
bikin narasi — tapi `ImmutableStamp.record_action()` cuma nyimpen
`description` sebagai *string bebas*, bukan struktur asli. Hasil kaya dari
Hunter (`temporal_vector`/`spatial_vector` sebagai field terpisah) dan
MitreMapper (`matched_tactics` per anomaly) hilang strukturnya begitu masuk
ledger — cuma jadi kalimat generik ("PID X Hunt Completed"). Ini akar
masalah dari bug yang sudah terdokumentasi di test suite:
`test_mitre_mapper_entries_are_NOT_detected_by_weaver_KNOWN_BUG`. Correlator
Fase 7 harus konsumsi return value modul-modul itu **selagi masih live di
memory**, sebelum dipipihkan jadi string log.

**Registry (`reglookup`) belum siap dikorelasikan, dua potongan hilang:**
1. Nggak ada parser. Bandingkan dengan `hunter.py`'s
   `_parse_plaso_output`/`_parse_tsk_output` — `run_reglookup()` di
   `sift_toolkit.py` cuma jalankan subprocess mentah, output-nya text
   polos, nggak ada ekstraksi run-key/persistence/autostart.
2. Nggak ada path resolver. Hunter punya `_resolve_forensic_source()`
   buat nemuin target (env var → root filesystem → fallback). Nggak ada
   yang setara buat nemuin file hive registry (`SYSTEM`, `SOFTWARE`,
   `NTUSER.DAT`) yang biasanya berupa artefak yang di-carve dari image
   disk yang diperiksa, bukan ada di live host SIFT.

## Keputusan desain (dikonfirmasi bareng Arcia)

1. **Titik integrasi:** modul baru terpisah, di-dispatch `guardian.py`
   setelah containment — pola yang sama dengan `mind_reader`/`remediator`/
   `sandbox`/`mirage` di `handle_post_containment()`. Bukan nimpa logika
   `_build_forensic_context` di `sentinel.py` (itu tetap jalan buat LLM
   real-time, terpisah dari correlator yang post-containment).
2. **Bentuk output:** objek data terstruktur baru, `CorrelatedCaseFile` —
   **aditif**, jadi input tambahan buat `dossier.py`/`weaver.py`, bukan
   gantiin apa pun yang sudah ada.
3. **Scope v1:** termasuk registry, meski wrapper-nya belum pernah
   divalidasi — artinya sebagian kerja Fase 7 Tahap 1 adalah **membangun
   parser + path resolver registry itu sendiri**, bukan asumsi siap pakai.

## Arsitektur yang diusulkan

### Modul baru: `yomi_engine/correlator.py`

```
class CrossArtifactCorrelator:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()   # buat reglookup langsung, bukan lewat modul lain

    def correlate(
        self,
        target_pid: int,
        hunt_result: dict,        # dari OmniVectorHunter.hunt_root_cause()
        mapped_tactics: list,     # dari MitreMapper.map_anomalies()
        swarm_reports: list,      # dari SwarmOrchestrator.deploy_swarm()["reports"]
        cve_matches: list | None = None,   # dari OmniLibrary.analyze_artifact(), kalau MindReader udah jalan
        registry_hive_path: str | None = None,  # opsional, lewat env var
    ) -> "CorrelatedCaseFile":
        ...
```

Bukan modul yang manggil Hunter/Swarm/MitreMapper/Library sendiri —
`guardian.py` yang udah punya hasil mereka (atau bisa akses) yang oper ke
`correlate()`. Correlator murni fungsi penggabung + penilai konsistensi,
nggak duplikat kerja modul lain.

### Struktur data: `CorrelatedCaseFile`

Bukan cuma nge-merge jadi satu dict — bagian pentingnya adalah **flag
kontradiksi**, bukan cuma gabung diam-diam (ini nyambung ke prinsip #3
roadmap: provenance yang menolak klaim palsu). Contoh: MitreMapper bilang
`T1071` (C2 beacon) terdeteksi dari kata kunci di anomaly text, tapi
Swarm's network agent nggak nemu external IP apa pun — itu kontradiksi
yang harus kelihatan di laporan, bukan ke-silent-merge jadi "confirmed C2".

```python
@dataclass
class CorrelatedCaseFile:
    target_pid: int
    incident_id: str

    # per-artefak, evidence_ref nunjuk balik ke record_id ledger asli
    # (bukan re-parse ledger -- dicatat langsung pas correlate() dipanggil)
    timeline_events: list[dict]      # dari hunt_result.temporal_vector
    filesystem_artifacts: list[dict] # dari hunt_result.spatial_vector
    network_findings: list[dict]     # dari swarm_reports (Network_Agent)
    memory_findings: list[dict]      # dari swarm_reports (Memory_Agent)
    registry_findings: list[dict]    # dari reglookup parser baru
    mitre_tactics: list[dict]        # dari mapped_tactics
    cve_correlations: list[dict]     # dari cve_matches

    corroborated_tactics: list[str]  # MITRE ID yang didukung >=2 sumber independen
    contradictions: list[dict]       # klaim yang TIDAK didukung sumber lain
    coverage_gaps: list[str]         # kategori artefak yang unavailable/gagal
```

`corroborated_tactics` vs `contradictions` ini yang jadi nilai tambah
utama dibanding modul yang udah ada — MitreMapper sendiri cuma keyword
match satu sumber, nggak pernah cross-check ke sumber lain.

### Registry: kerja prasyarat sebelum correlator bisa pakai dia

1. `yomi_mcp/sift_toolkit.py::run_reglookup()` — sudah ada, dipakai
   apa adanya.
2. **Baru:** parser di `hunter.py` atau `correlator.py` sendiri (masih
   perlu diputuskan) — ekstrak run-key/service/autostart entries dari
   output reglookup, mirip pola `_parse_plaso_output`.
3. **Baru:** resolver path hive, lewat env var (`YOMI_REGISTRY_HIVE_PATH`),
   nggak ada default otomatis kayak `_resolve_forensic_source()` karena
   hive registry biasanya artefak yang di-carve manual, bukan langsung
   ada di root filesystem SIFT.
4. **Baru:** test unit buat parser + resolver ini (nol test sekarang).

### Integrasi ke `guardian.py`

Nambah 1 accessor lazy (`_get_correlator`) + 1 pemanggilan di
`handle_post_containment()`, **setelah** `mind_reader`/`remediator`/
`sandbox`/`mirage` (karena correlator butuh `cve_correlations` yang
tergantung `mind_reader` udah jalan duluan buat nemuin binary path/CVE
mimicry). Hasilnya disimpan di `summary["correlated_case_file"]`, dikirim
ke `generate_incident_dossier()` sebagai argumen tambahan (perlu ubah
signature `dossier.py::generate_pdf_dossier()` buat terima ini sebagai
parameter opsional).

### `module_registry.py`

```python
"CORRELATOR": ModuleSpec(
    "CORRELATOR", "yomi_engine.correlator", RiskTier.READ_ONLY, True,
    requires=("HUNTER", "MITRE_MAPPER", "SWARM"),
),
```
READ_ONLY karena murni sintesis, nggak ada OS-level side effect.
`LIBRARY` sengaja **tidak** masuk `requires` (correlator jalan tanpa CVE
correlation kalau Library nonaktif, cuma `cve_correlations` kosong).

## Isu skala yang perlu diputuskan (bukan blocker v1, tapi dicatat)

Roadmap sudah nyatet ini duluan: `hunter.py`/`sift_toolkit.py` masih
truncate 100KB/2MB langsung sebelum masuk context LLM. Kompetitor
(Mulder) pakai SQLite+FTS5 sebagai buffer buat data besar. Correlator v1
beroperasi di atas hasil yang **sudah** ditruncate modul sumbernya —
nggak nyelesain masalah skala ini, cuma mewarisi batasannya. Keputusan
arsitektur SQLite+FTS5 (atau setara) itu dijadwalkan terpisah, bukan
bagian Fase 7 Tahap 1.

## Rencana kerja bertahap

1. ✅ **Registry hardening** (prasyarat) — `_resolve_registry_hive_path()`
   (env var `YOMI_REGISTRY_HIVE_PATH`, tanpa fallback otomatis, sengaja)
   + `_parse_reglookup_output()` (filter keyword persistence: Run/
   RunOnce/Services/Winlogon Shell/AppInit_DLLs/IFEO) + method publik
   `hunt_registry_persistence()`, semua di `hunter.py`.
2. ✅ **`correlator.py` inti** — `CorrelatedCaseFile` dataclass +
   `CrossArtifactCorrelator.correlate()`. Dua fungsi corroboration
   diimplementasi: T1071 (C2) dicek silang ke temuan Swarm's network
   agent, T1055 (Process Injection) dicek silang ke timeline Plaso.
   **Bug ditemukan & diperbaiki selama development**: cek regex awal
   buat T1071 (`external|c2`) ternyata ke-match di kalimat "bersih"
   swarm.py sendiri ("...without obvious external C2 anomalies") —
   diperbaiki jadi match 4 frasa spesifik yang cuma muncul saat swarm.py
   beneran nemu sesuatu. Rencana awal ada `_check_credential_access_
   corroboration` tapi ternyata **dead code** — nggak ada satu pun dari
   5 IoE signature di `mitre_mapper.py` yang tactical_desc-nya
   menyebut "credential" — diganti jadi cek T1055 yang beneran eksis.
3. ✅ **Integrasi guardian.py + module_registry.py** — method baru
   `finalize_correlation()`, **sengaja dipisah** dari
   `handle_post_containment()`: pada jalur CRITICAL (instant SIGSTOP),
   `handle_post_containment()` kepanggil SEBELUM `hunt_result`/
   `mapped_tactics` selesai dihitung di `sentinel.py` — jadi data yang
   dibutuhkan correlator belum eksis di titik itu. `finalize_correlation()`
   dipanggil terpisah, setelah data itu tersedia, terlepas dari jalur
   containment mana yang kepicu. Entry `CORRELATOR` ditambahkan ke
   `module_registry.py` (READ_ONLY, default ON, requires HUNTER+
   MITRE_MAPPER+SWARM, LIBRARY sengaja bukan hard dependency).
4. ✅ **Integrasi dossier.py** — `generate_pdf_dossier()` terima
   `correlated_case_file=None` opsional, section-nya di-append ke
   narrative Weaver sebelum PDF/TXT ditulis & di-hash (backward
   compatible, semua caller lama nggak perlu berubah).
5. ✅ **Test** — `tests/unit/test_correlator.py` (baru, ~20 test,
   termasuk regression guard buat bug T1071 di atas),
   `tests/unit/test_hunter.py` (+14 test registry), `test_guardian.py`
   (+5 test finalize_correlation/dossier wiring), `test_dossier.py`
   (+2 test backward-compat & section append). Full suite 483→518 test,
   dijalankan 3x berturut-turut, semua PASS. `ruff check .` bersih.
   **Diverifikasi end-to-end lewat `scripts/smoke_test_cli.py`** (bukan
   cuma unit test terisolasi) — urutan asli kelihatan di output:
   Registry Persistence Hunt → REGISTRY_HUNT_SKIPPED → CASE_FILE_COMPILED
   by CORRELATOR, tersambung ke rantai Sentinel→Guardian→Harness nyata.
6. ✅ **`docs/known_issues.md` + `scripts/create_known_issues_fase7.sh`**
   sesuai `PHASE_CHECKLIST.md`. Entri #33: MitreMapper's signature set
   nggak divalidasi terhadap asumsi tactic ID yang dipakai correlator's
   corroboration checks (dead-code credential-access function + regex
   T1071 yang ke-false-positive, keduanya ditemukan & diperbaiki
   sebelum commit, tapi gap desainnya sendiri masih OPEN — nggak ada
   mekanisme test/CI yang nyambungin tactic ID yang diasumsikan
   correlator ke tactic ID yang beneran ada di MitreMapper).
7. ✅ **Bonus: `known_issues.md` #7 FIXED** (di luar rencana kerja awal,
   dikerjakan karena Arcia minta cek issue lama yang belum diperbaiki,
   dan ini langsung nyambung ke `weaver.py`+`dossier.py` yang lagi
   disentuh). Root cause: `mitre_mapper.py`'s `MAPPED` ledger entry
   nggak pernah nyebut MITRE ID literal di `description`-nya, jadi
   regex scan `weaver.py` nggak pernah nemu apa pun — bukan bug di
   regex-nya, datanya emang nggak pernah ada. Fix: `mitre_mapper.py`
   sekarang embed ID ke `description` DAN ke `metadata.mitre_ids`
   terstruktur; `weaver.py` baca `metadata` langsung, bukan cuma
   regex-atas-teks-bebas. Test lama yang nge-assert perilaku buggy
   (`..._NOT_detected_..._KNOWN_BUG`) di-rename & di-flip jadi
   `..._ARE_detected_...`, plus test baru buat backward-compat ledger
   lama tanpa field `metadata`. Verified end-to-end lewat
   `scripts/smoke_test_cli.py`.

## Belum diputuskan / perlu dibahas lagi

- Parser reglookup taruh di mana: `hunter.py` (biar konsisten sama
  Plaso/TSK) atau `correlator.py` sendiri (biar hunter tetap fokus PID
  correlation doang)?
- `dossier.py::generate_pdf_dossier()` signature berubah — perlu cek
  dampaknya ke test yang udah ada (`test_dossier.py`,
  `test_chain_swarm_hunter_dossier.py`).
- Belum ada keputusan soal ground-truth validation dataset (NIST CFReDS/
  Digital Corpora/Ali Hadi) — itu Tahap 2 roadmap, di luar scope dokumen
  ini.

## Sisa known_issues.md yang masih OPEN (per pengecekan Sesi ini)

Dicek atas permintaan Arcia ("issue/bug lainnya yang dulu belum
diperbaiki?"). #7 sudah diperbaiki di atas. Sisanya yang masih OPEN,
dari `docs/known_issues.md`:

- **#8** — `write_year_store()` nggak validasi shape saat nulis (yomi_data
  layer, nggak nyambung ke Fase 7).
- **#9** — `ImmutableStamp` singleton + hardcoded data dir, blokir
  multi-tenant. Sengaja OPEN, keputusan arsitektur besar, di luar scope
  fase mana pun sampai diputuskan eksplisit.
- **#10** — `mcp_server.py` READ_VAULTS/WRITE_VAULTS hardcoded absolute
  path list, isu portabilitas deployment.
- **#16** — `mirage.py` teardown boundary check pakai `startswith()`,
  bukan path containment asli (defense-in-depth, "not urgent").
- **#24** — `cleanup_corrupt_backups` ngitung file, bukan incident
  (nggak nyambung ke Fase 7).
- **#27** — `pip install .` masukin `yomi_data/` kayak modul biasa
  (worked around lewat instalasi/warning, root cause belum di-fix).
- **#30** — asymmetric Mirage decoy lifecycle pas SANDBOX enabled.
- **#33** — (baru, sesi ini) MitreMapper signature set nggak
  divalidasi ke asumsi correlator.

Nggak ada satupun dari sisa ini yang bersinggungan langsung sama kode
yang disentuh Fase 7 Tahap 1 (`hunter.py`, `correlator.py`,
`guardian.py`, `dossier.py`, `sentinel.py`, `mitre_mapper.py`,
`weaver.py`) selain #7 yang udah dikerjain. Sisanya independen —
perlu sesi/keputusan terpisah, bukan sesuatu yang "kebetulan" bisa
ikut sekalian.
