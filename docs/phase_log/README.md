# Phase Log

Ringkasan per-fase: apa yang dikerjakan, bug ditemukan, perubahan dibuat,
keputusan arsitektur. Ditulis untuk dibaca tanpa perlu gali `git log` atau
`docs/known_issues.md`.

| Fase | Status | Ringkasan |
|------|--------|-----------|
| [Fase 0](fase_0.md) | ✅ Selesai | Branching, CI/CD skeleton, struktur test, Module Registry |
| [Fase 1](fase_1.md) | ✅ Selesai (merged, PR #1) | Unit test + benchmark Lapisan 0 (stamp, os_bridge, yomi_data) — 31 test, 3 crash bug diperbaiki |
| [Fase 2](fase_2.md) | ✅ Selesai (merged) | Unit test Lapisan 1 (11 modul), 190 test, 4 bug fungsional diperbaiki |
| [Fase 3](fase_3.md) | ✅ Selesai (belum merge) | Unit test Lapisan 2 (8 modul), 232 test, 1 gap logika + 1 dead code ditemukan |
| [Fase 4](fase_4.md) | ✅ Selesai (belum merge) | Integration/crucible test (5) + benchmark regression checker sungguhan |
| [Fase 5](fase_5.md) | ✅ Selesai (belum merge) | README split + 4 gerbang wajib pra-Fase 6 (#12, #13, #14, #15, #21) diperbaiki; #24 baru ditemukan |
| [Fase 6](fase_6.md) | 🔄 Tahap 1 selesai, Tahap 2-3 belum mulai | Guardian Orchestrator (semua 13 modul tersambung, #11/#26 FIXED, #25 diakali); Release + landing page KuroTech menyusul |

Untuk daftar bug lengkap (fixed + open), lihat
[`docs/known_issues.md`](../known_issues.md) atau tab **Issues** di GitHub
(setelah `scripts/create_known_issues.sh` dijalankan).
