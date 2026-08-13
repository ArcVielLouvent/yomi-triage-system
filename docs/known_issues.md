# Known Issues Log

Running log of every real bug/inconsistency found during the Yomi evolution
effort, in the order discovered. Purpose: nothing found gets lost between
sessions or phases, and each entry says whether it's fixed yet.

## Fixed

1. **`docs/dataset_documentation.md` told judges to `export GEMINI_API_KEY`,
   but `router.py` reads `YOMI_GEMINI_API_KEY`.** Following the doc literally
   = LLM cascade silently never activates. Fixed on `foundation/stamp-datastore-osbridge` (not yet merged to `develop`).

2. **`README.md` referenced `docs/system_topology.svg` (lowercase), actual
   file is `docs/System_Topology.svg`.** Broken image link on any
   case-sensitive filesystem (Linux, GitHub raw). Fixed on `foundation/stamp-datastore-osbridge` (not yet merged to `develop`).

3. **`yomi_data/recovery/` created at runtime by `shadow_net.py` (ELF
   recovery from RAM) had no `.gitkeep`,** unlike the other 6 data
   subfolders -- inconsistent repo structure on fresh clone. Fixed on
   `develop`.

4. **`yomi_core/cli.py` `--install` flag crashes 100% of the time**
   (`UnboundLocalError` on `sys.exit(0)`), caused by a redundant local
   `import sys` later in the same `main()` function shadowing the
   module-level import for the whole function scope. Fixed on `foundation/stamp-datastore-osbridge` (not yet merged to `develop`)
   (removed the redundant local import).

5. **`_run_console_loop()` in `cli.py` called `_get_latest_ledger_log()`,
   a function that doesn't exist anywhere in the codebase** -- `NameError`
   on first ledger-size change in console/headless fallback mode. The
   sibling `_run_tui_loop()` had already been correctly updated to call the
   real helper (`_get_new_ledger_logs(last_hash)`); console mode was never
   brought in sync. Fixed on `foundation/stamp-datastore-osbridge` (not yet merged to `develop`) (console loop now matches TUI loop's
   correct pattern).

6. **`query_cve()` was defined twice in `yomi_engine/library.py`.** The
   second (silently active) definition used a shallow `.copy()` instead of
   `deepcopy()`, meaning callers could mutate nested fields of the
   in-memory CVE cache through the object they were handed back. Fixed on
   `develop` (consolidated to one deepcopy-safe definition).

## Documented, not yet fixed (behavioral/design issues, need a decision)

7. **`weaver.py` narrative generator drops MITRE tactic findings from the
   human-readable dossier even when the underlying ledger clearly logged
   them** ("Dossier Generation Bias" -- confirmed empirically against a real
   report file in the original submission, not just from the docs'
   self-reported warning). Needs a fix in `weaver.py`'s event-selection
   logic; scheduled for whichever phase touches `yomi_engine/weaver.py` +
   `dossier.py`.

8. **`write_year_store()` (yomi_data) performs no shape validation at write
   time.** An entry missing a matching `cve_id` field writes successfully
   with zero error, then silently vanishes (quarantined as corrupt) on the
   next read/scan. Captured as a regression test
   (`test_write_year_store_silently_drops_entries_missing_cve_id` in
   `tests/unit/test_yomi_data.py`) so the bug can't regress further, but
   the actual fix (validate on write, raise instead of silently accepting)
   is not yet implemented.

9. **`ImmutableStamp` (stamp.py) and `yomi_data/__init__.py` both hardcode
   their data directory relative to `__file__`,** with `ImmutableStamp`
   additionally being a strict process-wide singleton. This makes true
   multi-tenant / concurrent-investigation use impossible within one
   process, and required a `__file__`-monkeypatch fixture just to unit-test
   safely (see `tests/unit/conftest.py`). Flagged as a design smell for
   discussion -- not changed, since it's a behavior change beyond "add
   tests," and affects every module built on top of it.

10. **`yomi_mcp/mcp_server.py`'s `READ_VAULTS`/`WRITE_VAULTS` are hardcoded
    absolute path prefixes** (`/tmp`, `/var/tmp`, `/mnt`, `/home`,
    `/workspace`, `/data`, `/media`, `/opt/yomi`), not derived from
    `yomi_data`'s actual location. A deployment outside those trees will
    have every MCP tool call VETOed as "outside vault boundaries" even when
    legitimate. Portability concern for enterprise deployment; not yet
    addressed.

## Architectural gaps (not bugs, but the reason Guardian/Module Registry exist)

11. As of the hackathon snapshot, `sentinel.py`'s autonomous loop only
    wired in `swarm`, `hunter`, `router`, `mitre_mapper`, `telemetry`.
    Eight real modules (`mind_reader`, `shadow_net`, `remediator`,
    `dossier`, `mirage`, `sandbox`, `ghost`, `ebpf_sensor`) existed but were
    never called automatically -- only reachable via each file's own
    `if __name__ == "__main__"`. This is what `yomi_core/module_registry.py`
    (Fase 4-5, Guardian orchestrator) is being built to fix.

## Style/lint backlog (not blocking, tracked for later per-package cleanup)

- 19x `S110` (try/except/pass without logging) across
  `stamp.py`, `cli.py`, `dashboard.py`, `sentinel.py`, `dossier.py`,
  `ebpf_sensor.py`, `library.py`, `sandbox.py`, `shadow_net.py`, `swarm.py`,
  `sift_toolkit.py`. Many are legitimate "best effort" cleanup patterns
  (unmount, chmod, temp-file removal) -- needs per-instance review, not a
  blanket "add logging" pass. Deferred to whichever `foundation/*` or
  `feature/*` branch actually touches each file.
- 1x `E722` bare `except:` in `ebpf_sensor.py`.
- ~30 import-sort / f-string-cosmetic findings across the repo (ruff
  `--fix`-able), deferred for the same reason.

## Coverage gaps found during pre-merge review (not bugs, but blind spots)

12. **`yomi_audit/stamp.py` is only 54% covered by Fase 1 tests.** The
    untested 46% includes security-relevant paths that have never been
    executed by any test: KMS/Vault/AWS-Secrets-Manager HMAC key retrieval,
    password-derived ephemeral key generation, corrupted-ledger backup +
    cleanup, and SOC checkpoint anchoring/verification. CI passing does not
    mean these paths are correct -- it means they've never been exercised
    at all. Flagged as the top coverage priority for whichever phase next
    touches `stamp.py`.

13. **`_create_or_verify_checkpoint()` prints "Checkpoint mismatch
    detected. Updating..." on every normal ledger write since the last
    checkpoint** -- this is expected behavior (checkpoint just needs to
    catch up), not a tamper signal, but the wording reads like a security
    alert. Risk: operators habituate to seeing this message and start
    ignoring it, which defeats its purpose on the rare occasion a mismatch
    *is* real tampering. Consider distinguishing "routine update" from
    "verification failure" in the log wording. Not fixed here (behavior
    change, not test-writing); flagged for whoever next touches this
    function.
