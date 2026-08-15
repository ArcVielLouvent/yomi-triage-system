# Checklist Wajib Setiap Fase

Sebelum fase dianggap "selesai" dan dipaket buat di-pull ke Codespaces,
semua ini harus sudah beres — bukan opsional, bukan nyusul belakangan:

1. **Test ditulis dan lulus** — `./run_tests.sh` hijau, diverifikasi
   minimal 3x run berturut-turut (bukan sekali doang, buat nangkep race
   condition/flaky test).
2. **Lint bersih** — `ruff check .` lolos ruleset blocking.
3. **`docs/phase_log/fase_N.md` di-update** — ringkasan apa yang
   dikerjakan, bug ditemukan/diperbaiki, keputusan arsitektur.
4. **`docs/known_issues.md` di-update** — setiap temuan baru (bug, gap
   desain, dead code) dapat nomor urut lanjutan, status FIXED/OPEN jelas.
5. **`scripts/create_known_issues_fase{N}.sh` dibuat** — SATU script per
   fase yang isinya PERSIS temuan baru fase itu (bukan gabung ulang sama
   fase sebelumnya). Ini WAJIB dibuat bersamaan dengan poin 3-4 di atas,
   di respons yang sama saat fase itu selesai — bukan menunggu ditanya
   belakangan.
6. **Residu dicek bersih** — nggak ada mount/thread/signal handler/proses
   yang ketinggalan dari test (khususnya modul yang nyentuh OS-level
   state kayak `ghost.py`, `sandbox.py`, `ebpf_sensor.py`).

## Riwayat script issues per fase

| Fase | Script | Jumlah temuan |
|------|--------|----------------|
| 0-1 | `scripts/create_known_issues.sh` | 13 (#1-13) |
| 2 | `scripts/create_known_issues_batch2_3.sh` | 7 (#14-20) |
| 3 | `scripts/create_known_issues_fase3.sh` | 2 (#21-22) |

Total sampai Fase 3: **22 temuan** tercatat di GitHub Issues.
