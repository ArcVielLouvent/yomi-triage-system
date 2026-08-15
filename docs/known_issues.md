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

## Fase 2 Batch 2 findings (remediator.py, mirage.py)

14. **`remediator.py`'s `_validate_payload` has no critical-PID protection**
    (unlike `harness.py`'s PID<=100 hardblock). A payload targeting PID 1
    (init) generates a rollback script successfully. The script isn't
    auto-executed, but nothing stops one from being generated. Captured as
    a regression test (`test_KNOWN_GAP_no_critical_pid_protection` in
    `tests/unit/test_remediator.py`).

    Status: OPEN.

15. **`remediator.py`'s "critical system path" check is an exact match, not
    a prefix check.** `/bin/bash` and `/etc/passwd` pass validation despite
    being core system files, because the check only compares against the
    bare directory strings ("/bin", "/etc") themselves. Practical impact
    is limited since the generated script's kill commands only reference
    `pid`, never `file_path` -- but the check's own comment claims broader
    protection than it actually provides. Captured as
    `test_KNOWN_GAP_critical_path_check_is_exact_match_not_prefix`.

    Status: OPEN.

16. **`mirage.py`'s `teardown_hallucination` boundary check uses string
    `.startswith()`, not proper path containment** -- theoretically
    vulnerable to sibling-directory prefix matching (e.g. a folder named
    `mirage_env_EVIL` also "starts with" `mirage_env`). Not exploitable
    through the current public API (target_path is always built from an
    int-cast pid + a 2-value-constrained prefix), but flagged as a pattern
    to avoid if this code is ever refactored to accept more flexible
    input. Captured as
    `test_teardown_boundary_check_documented_prefix_weakness`.

    Status: OPEN (defense-in-depth hardening, not urgent).

## Fase 2 Batch 3 findings (library.py, sift_toolkit.py) — FIXED

17. **`library.py`: `lzma.LZMAFile(fileobj=...)` uses a non-existent
    keyword argument.** Python's `lzma.LZMAFile` API names this parameter
    `filename` (which also accepts file-like objects) -- `fileobj` doesn't
    exist. Present in 2 call sites (`_fetch_nvd_recent`,
    `seed_full_nvd_archive`). This meant NVD CVE database sync has
    silently failed with `TypeError` (caught by a broad
    `except Exception`) on every single invocation since project
    inception -- the core "auto-updating threat intelligence" feature has
    never actually worked.

    Status: **FIXED**. Both occurrences now pass the BytesIO object
    positionally instead of via `fileobj=`.

18. **`library.py`: `analyze_artifact()`'s keyword matching checked
    substring containment backwards.** The full (often long, decorated)
    `artifact_name` was checked as a substring INSIDE the short
    "cve_id + description" text, which only succeeds when `artifact_name`
    IS almost exactly the bare CVE ID. Any realistic filename (e.g.
    `"suspicious_cve-2026-0006_dropper.exe"`) never matched, despite the
    CVE-year regex correctly narrowing the search first.

    Status: **FIXED**. Redesigned with two correctly-directed checks: (a)
    a full CVE-ID pattern extracted from `artifact_name` gets a direct
    O(1) dict lookup as a fast/precise path, (b) `context_hints` (short,
    curated keywords) keep the original correct direction
    (hint-in-description), (c) the extracted CVE ID is checked for
    containment WITHIN `artifact_name`/hints as a fallback. Deduped via
    `matched_cve_ids` to avoid double-counting.

19. **`sift_toolkit.py`: `_run_subprocess`'s "timed out" error message was
    effectively dead code.** It inferred a timeout from
    `process.returncode is None`, but `_stream_process_output` already
    reaps the just-killed process via `process.wait()` before returning
    -- so `returncode` is essentially never still `None` by the time the
    caller checks it. Callers got a generic `"tool returned -9"` message
    instead of the intended `"execution timed out after Xs"` message.

    Status: **FIXED**. `_stream_process_output` now returns an explicit
    `timed_out` flag (3-tuple return) instead of inferring it from
    `returncode`. Applied to both call sites (`_run_subprocess`,
    `_run_pipe`).

20. **`sift_toolkit.py`: genuine race condition in
    `_stream_process_output`'s main loop.** `process.poll() is not None`
    was checked FIRST every iteration, breaking immediately if the
    process had already exited -- for fast commands (e.g. `echo`), the
    child could finish before the loop ever attempted a single read,
    discarding output still sitting unread in the OS pipe buffer.
    Confirmed via 5x repeated local test runs: intermittent, different
    tests failed each run (classic race-condition signature).

    Status: **FIXED**. The loop no longer uses `poll()` as an exit
    signal at all -- pipes are tracked in a set and only dropped on an
    actual EOF (empty read), so buffered output is always drained
    regardless of whether the process has already exited. Verified
    stable across 5 consecutive full-suite runs post-fix.

## Fase 3 Batch 3 findings (router.py, harness.py)

21. **`router.py`: `execute_autonomous_triage`'s ReAct loop has no branch
    for OS-level execution failures.** If an LLM-proposed `freeze`/`thaw`
    action passes veto (target PID isn't protected) but fails at the OS
    level (e.g. `os_bridge` returns `GHOST_PROCESS` for a PID that no
    longer exists, or a generic `ERROR`), `_evaluate_intent`'s result
    doesn't match any of the loop's explicit status checks (`REJECTED`,
    `SELF_CORRECTION_REQUIRED`, `SUCCESS`-and-not-vetoed, `VETOED`). The
    loop silently proceeds to the next iteration without appending any
    `[SYSTEM FEEDBACK]` to `current_context` -- unlike every other
    rejection path, which explains to the LLM what went wrong. The LLM
    has no signal that its action failed and may repeat an identical
    response, burning iterations until `max_iterations` triggers Shadow
    Net escalation with no useful diagnostic trail.

    Captured as: `tests/unit/test_router.py::test_triage_KNOWN_GAP_os_level_failure_gets_no_feedback_and_silently_retries`

    Status: OPEN. Needs a product decision: should this be its own
    handled branch (e.g. feed the OS-level failure reason back to the
    LLM, similar to VETOED), or is silent retry-then-escalate the
    intended fail-safe behavior? Not fixed here.

22. **`harness.py`: `process_intent`'s trailing "no OS routing defined"
    branch is dead code.** `self.allowed_actions` is exactly
    `["freeze", "thaw"]`; `_veto_check` rejects any action outside that
    list before the dispatch logic runs, and the dispatch logic
    explicitly handles both remaining actions. No input can reach the
    trailing `{"status": "ERROR", "message": "Action valid but no OS
    routing defined..."}` branch.

    Status: **Confirmed via regression test**
    (`tests/unit/test_harness.py::test_no_action_value_can_reach_the_trailing_no_routing_branch`),
    not removed (harmless dead code, low priority cleanup -- would only
    matter if `allowed_actions` grows without a matching dispatch branch,
    which the new test now guards against).
