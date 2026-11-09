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

   Root cause (confirmed by reading both files together): `weaver.py`
   only ever regex-scans each ledger entry's `description` string for a
   literal `T1XXX`-shaped substring. `mitre_mapper.py`'s own `MAPPED`
   ledger entry never contained one -- its description was always just
   `f"Mapped {n} unique tactics across {m} anomalies."`, no IDs. The
   MITRE_MAPPER event WAS visible in the narrative's timeline section
   (agent name + action type render fine), but the dedicated "[MITRE
   ATT&CK MAPPING CONFIRMED]" section below it always claimed nothing
   was found, regardless of how much real mapping happened.

   Status: **FIXED (Fase 7).** `mitre_mapper.py`'s `MAPPED` entry now
   embeds the actual matched MITRE IDs directly in `description` (e.g.
   `"Mapped 2 unique tactics across 5 anomalies: T1055, T1486."`) AND
   in a structured `metadata.mitre_ids` list. `weaver.py` now reads
   `metadata.mitre_ids` directly in addition to its existing regex scan
   -- more robust than relying on prose always containing a literal
   T-code, and it degrades safely (no crash) on older ledger entries
   with no `metadata` field at all. Regression test renamed from
   `test_mitre_mapper_entries_are_NOT_detected_by_weaver_KNOWN_BUG` to
   `test_mitre_mapper_entries_ARE_detected_by_weaver` in
   `tests/unit/test_weaver.py`, now asserting the fixed behavior;
   `test_weaver_ignores_missing_or_malformed_metadata_field` added for
   the backward-compatibility case. Verified end-to-end via
   `scripts/smoke_test_cli.py`, not just the unit tests.

8. **`write_year_store()` (yomi_data) performs no shape validation at write
   time.** An entry missing a matching `cve_id` field writes successfully
   with zero error, then silently vanishes (quarantined as corrupt) on the
   next read/scan.

   Status: **FIXED (known-issues cleanup).** `write_year_store()` now
   validates the same invariants as the read path (`dict[str, dict]`, each
   entry's `cve_id` equal to its key) and raises `ValueError` before
   writing anything, leaving any existing year file untouched. It had no
   non-test callers. Covered by
   `test_write_year_store_rejects_entries_missing_cve_id`,
   `test_write_year_store_rejects_other_malformed_shapes` and
   `test_rejected_write_leaves_existing_year_file_untouched` in
   `tests/unit/test_yomi_data.py`.

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
    legitimate. Portability concern for enterprise deployment.

    Status: **FIXED (known-issues cleanup).** The built-in lists are now
    `DEFAULT_READ_VAULTS` / `DEFAULT_WRITE_VAULTS` and operators can ADD
    roots with `YOMI_MCP_READ_VAULTS` / `YOMI_MCP_WRITE_VAULTS`
    (`os.pathsep`-separated absolute paths; they never remove a built-in
    root). A relative entry or `/` raises `ValueError` at construction,
    since a vault is a security allowlist and must not be skipped
    silently. The data directory is deliberately NOT added automatically:
    it holds the HMAC key. Covered in `tests/unit/test_mcp_server.py`.

## Architectural gaps (not bugs, but the reason Guardian/Module Registry exist)

11. As of the hackathon snapshot, `sentinel.py`'s autonomous loop only
    wired in `swarm`, `hunter`, `router`, `mitre_mapper`, `telemetry`.
    Eight real modules (`mind_reader`, `shadow_net`, `remediator`,
    `dossier`, `mirage`, `sandbox`, `ghost`, `ebpf_sensor`) existed but were
    never called automatically -- only reachable via each file's own
    `if __name__ == "__main__"`. This is what `yomi_core/module_registry.py`
    (Fase 4-5, Guardian orchestrator) is being built to fix.

    Status: **FIXED (Fase 6, Tahap 1).** `yomi_core/guardian.py`'s
    `GuardianOrchestrator` now wires all 8 modules into
    `sentinel.py`'s autonomous loop, gated entirely by
    `module_registry.resolve_active_modules()`:
    - `handle_post_containment(target_pid)` fires after a SYNCHRONOUS
      containment success (the instant CRITICAL SIGSTOP path, or a
      harness `status=="SUCCESS"`/`action=="FROZEN"` result) and
      dispatches `MIND_READER`, `REMEDIATOR`, `SANDBOX`, and `MIRAGE` (in
      that order, each independently try/except-guarded).
    - `handle_escalation(target_pid, reason)` fires on
      `ESCALATED_TO_SHADOW_NET` and fire-and-forget dispatches
      `SHADOW_NET` -- deliberately does NOT chain further modules off of
      it, since `deploy_micro_hook()` spawns its own monitoring thread
      and its outcome isn't known synchronously (see the module
      docstring's constraint #2 for the full reasoning).
    - `generate_incident_dossier()` fires unconditionally at the end of
      every `_zero_prompt_trigger` cycle if `DOSSIER` is enabled.
    - `periodic_maintenance()` sweeps orphaned `MIRAGE` decoys every 20
      sentinel cycles (not per-incident).
    - `bootstrap_startup_daemons()` wires `GHOST` and `EBPF_SENSOR` at
      CLI startup (see #26 below -- this replaces two previously
      ungated/mis-gated call sites in `cli.py`).

    Every dispatch is wrapped in try/except and logged to the ledger on
    failure (`<MODULE>_DISPATCH_ERROR`) rather than raised, so one
    misbehaving module (e.g. Radare2 missing, a sandbox mount failing)
    can never take down the observation loop or block modules after it.

    Tests: `tests/unit/test_guardian.py` (25 tests, 93% coverage of
    `guardian.py`), plus new end-to-end assertions in
    `tests/integration/test_chain_sentinel_router_harness.py` proving
    real dispatch against a REAL subprocess PID (not mocked) -- the
    real containment path resolves `/proc/<pid>/exe` to the actual
    python3 interpreter, `REMEDIATOR` correctly refuses it via the #15
    path-containment fix (python3 lives under `/usr`), and `DOSSIER`
    generates a real signed report, all verified via ledger entries.

    **Explicitly NOT touched by this fix:** #9 (ImmutableStamp
    singleton / single-tenant architecture) -- multi-tenant concurrent
    investigation remains a separate, deferred architectural decision.
    Guardian assumes the same single-investigation-per-process model
    `sentinel.py` already used.

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

    Status: **FIXED (Fase 5).** Coverage raised from 54% to 89% via
    `tests/unit/test_stamp_coverage.py` (45 new tests): all KMS provider
    dispatch paths, Vault (flat + KV-v2 nested response shapes, custom
    field name, request failure), AWS Secrets Manager (`SecretString` and
    `SecretBinary`, missing `boto3`, client failure), ephemeral
    PBKDF2 key derivation (env-var password, missing password, empty
    password, salt persistence), `_backup_corrupted_ledger` +
    `cleanup_corrupt_backups` (including the env-flag-triggered path),
    `_create_or_verify_checkpoint`, `verify_soc_checkpoint` (valid,
    missing signature, tampered, read-error), the ledger-corruption ->
    backup -> reinit round trip, and the legacy (non-compact JSON) hash
    fallback in `_verify_ledger`. All external calls (`requests`,
    `boto3`) are mocked; nothing here makes a real network call. The
    remaining 11% is almost entirely defensive `except OSError: pass`
    blocks around `os.chmod` calls that are impractical to trigger
    without mocking the OS call to fail for no functional reason -- not
    considered worth chasing further. See also #24 below, a real design
    nuance this test-writing surfaced in `cleanup_corrupt_backups`.

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

    Status: **FIXED (Fase 5).** Message changed to "Checkpoint routine
    update: ledger has new entries since the last checkpoint (expected on
    normal restart). Re-anchoring checkpoint to the current ledger
    state." Genuine tamper detection is unchanged -- it lives entirely in
    `verify_soc_checkpoint()`'s HMAC attestation check, which this
    function does not touch. Regression test:
    `tests/unit/test_stamp_coverage.py::test_checkpoint_routine_update_on_ledger_advance`.

## Fase 2 Batch 2 findings (remediator.py, mirage.py)

14. **`remediator.py`'s `_validate_payload` has no critical-PID protection**
    (unlike `harness.py`'s PID<=100 hardblock). A payload targeting PID 1
    (init) generates a rollback script successfully. The script isn't
    auto-executed, but nothing stops one from being generated. Captured as
    a regression test (`test_KNOWN_GAP_no_critical_pid_protection` in
    `tests/unit/test_remediator.py`).

    Status: **FIXED (Fase 6 prep).** `_validate_payload` now rejects any
    `pid <= 100` before proceeding, mirroring `harness.py`'s hardblock.
    Deliberately does NOT add `harness.py`'s deeper psutil-based
    "protect on `NoSuchProcess`" check -- `remediator.py`'s whole design
    intent is to keep generating rollback scripts when the PID/file is
    already gone (fileless malware self-deletes), so failing safe on a
    missing PID would defeat that purpose. Regression tests:
    `tests/unit/test_remediator.py::test_low_numbered_pid_is_now_protected`,
    `::test_pid_exactly_100_is_still_protected`,
    `::test_pid_101_is_not_blocked_by_the_low_pid_rule`.

15. **`remediator.py`'s "critical system path" check is an exact match, not
    a prefix check.** `/bin/bash` and `/etc/passwd` pass validation despite
    being core system files, because the check only compares against the
    bare directory strings ("/bin", "/etc") themselves. Practical impact
    is limited since the generated script's kill commands only reference
    `pid`, never `file_path` -- but the check's own comment claims broader
    protection than it actually provides. Captured as
    `test_KNOWN_GAP_critical_path_check_is_exact_match_not_prefix`.

    Status: **FIXED (Fase 6 prep).** Switched to real path containment
    via `pathlib` (resolved path equals the critical dir, or the
    critical dir appears in `resolved.parents`) instead of an exact
    string match -- deliberately NOT implemented as `.startswith()`,
    which would repeat the exact class of bug flagged in #16/#18 below
    for `mirage.py` (`.startswith("/etc")` also wrongly matches
    `/etcetera/file`). `/` is kept as an EXACT match only, not
    containment -- every absolute path is technically "under" `/`, so
    treating it as a containment boundary would reject everything.
    Regression tests:
    `tests/unit/test_remediator.py::test_critical_path_containment_now_blocks_files_inside_protected_dirs`,
    `::test_critical_path_containment_does_not_repeat_mirage_startswith_bug`,
    `::test_root_path_is_still_exact_match_only_not_containment`.

16. **`mirage.py`'s `teardown_hallucination` boundary check uses string
    `.startswith()`, not proper path containment** -- theoretically
    vulnerable to sibling-directory prefix matching (e.g. a folder named
    `mirage_env_EVIL` also "starts with" `mirage_env`). Not exploitable
    through the current public API (target_path is always built from an
    int-cast pid + a 2-value-constrained prefix), but flagged as a pattern
    to avoid if this code is ever refactored to accept more flexible
    input.

    Status: **FIXED (known-issues cleanup).** The check is now
    `MirageProtocol._is_inside_mirage_dir()`: real path containment
    (`os.path.realpath` + `os.path.commonpath`), strictly inside
    `mirage_dir` (the root itself does not count), so a string-prefix
    sibling or a symlink pointing outside is refused. Covered by
    `test_boundary_check_rejects_string_prefix_sibling`,
    `test_boundary_check_accepts_real_children_only` and
    `test_teardown_refuses_symlink_that_escapes_mirage_dir` in
    `tests/unit/test_mirage.py`.

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

    Captured as: `tests/unit/test_router.py::test_triage_os_level_failure_gets_system_feedback_and_can_recover`

    Status: **FIXED (Fase 5).** Added an explicit fallback branch after
    the `VETOED` check: any status that isn't `REJECTED`,
    `SELF_CORRECTION_REQUIRED`, `SUCCESS`-and-not-vetoed, or `VETOED` now
    appends a `[SYSTEM FEEDBACK]` entry to `current_context` with the
    status and reason (checking both `message` and `reason` keys, since
    `os_bridge` uses `reason` while the harness's own veto message uses
    `message`), then `continue`s to let the LLM retry with that
    information. Two tests cover this: one confirms recovery when the
    condition clears on the next iteration
    (`test_triage_os_level_failure_gets_system_feedback_and_can_recover`),
    and one confirms it still escalates to Shadow Net rather than looping
    forever if the condition never clears
    (`test_triage_persistent_os_level_failure_eventually_escalates`).

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

## Real bug found via cross-environment testing (Codespaces), now fixed

23. **`shadow_net.py`'s `__init__` relied solely on `os.umask(0o077)` to
    secure `recovery_dir`'s permissions — insufficient on filesystems with
    default POSIX ACLs.** Reported from a GitHub Codespaces devcontainer:
    mode came out **`0o756` (world-writable, `S_IWOTH` set)**,
    deterministically reproducible (same value across multiple runs, not
    a race) — impossible to reach via `umask(0o077)` math alone (umask can
    only clear bits, never introduce `rw-` for other). Root cause: per
    POSIX, when a directory has a default ACL, new children inherit
    permissions from that ACL and **umask is bypassed entirely** — some
    Codespaces devcontainer filesystems apparently have such a default ACL
    on the relevant mount.

    **Verified real** (not environment noise) by reproducing the exact
    failure mode locally: mocking `os.makedirs` to simulate an
    ACL-override to `0o756`, confirming the *original* code would produce
    a world-writable recovery vault under that condition.

    Status: **FIXED.** `__init__` now calls `os.chmod(recovery_dir, 0o700)`
    explicitly right after `os.makedirs()`, which is guaranteed to set the
    exact permission regardless of umask/ACL interactions on any
    filesystem — `chmod` doesn't go through umask calculation at all.
    Verified the fix defeats the exact simulated ACL-override scenario
    that reproduces the original bug. Test restored to an exact
    `mode == 0o700` assertion (previously loosened to "not
    group/other-writable" as a stop-gap before the real fix was
    identified — that loosening is no longer needed now that the
    permission is explicitly guaranteed).

## Fase 5 findings (stamp.py coverage work)

24. **`yomi_audit/stamp.py`'s `cleanup_corrupt_backups(retain_last=N)`
    counts individual files, not incidents.** Each call to
    `_backup_corrupted_ledger` writes *two* files -- the `.jsonl` copy of
    the corrupted ledger, and a `.metadata.json` sidecar written
    immediately after it. `cleanup_corrupt_backups` lists every file
    whose name starts with the backup prefix, sorts that flat list by
    mtime, and retains the first `retain_last` entries -- treating the
    `.jsonl` and its `.metadata.json` as two independent, unrelated
    files rather than one paired incident. So `retain_last=1` does not
    mean "keep the most recent full incident"; it means "keep the single
    most-recently-modified file on disk", which in practice is always
    the `.metadata.json` (written after its `.jsonl` pair). The result:
    `retain_last=1` can leave a lone `.metadata.json` on disk with no
    matching `.jsonl` backup beside it.

    This is not data loss of the *ledger itself* (the live ledger and
    its HMAC chain are untouched -- this only affects retention of
    corruption-recovery backups) and not exploitable by an attacker, but
    it means the retention guarantee implied by the parameter name
    doesn't hold, and an operator relying on `retain_last=1` "for safety"
    could end up with less than they expect if they ever need to inspect
    a backup after a corruption event.

    Status: **FIXED (known-issues cleanup).** Files are grouped by
    incident (the `.jsonl` name, with the `.metadata.json` suffix
    stripped), incidents are ranked by their newest file, and
    `retain_last=N` keeps the N newest incidents, so a `.jsonl` and its
    sidecar are always kept or deleted together. The return value is still
    the number of files deleted. Covered by
    `test_cleanup_corrupt_backups_retain_last_keeps_whole_incident`,
    `test_cleanup_corrupt_backups_keeps_newest_incidents_as_pairs` and
    `test_cleanup_corrupt_backups_orphan_sidecar_counts_as_own_incident`
    in `tests/unit/test_stamp_coverage.py`.

## Fase 6 findings (Guardian Orchestrator integration work)

25. **Two parallel env-var gating mechanisms for the same decision.**
    `mirage.py`'s `deploy_hallucination()` checks its OWN internal env
    var (`YOMI_ENABLE_MIRAGE_MODE`) in addition to whatever
    `module_registry`'s `YOMI_MODULE_MIRAGE` decided -- two separate
    toggles an operator could set inconsistently (e.g.
    `YOMI_MODULE_MIRAGE=true` but forgetting `YOMI_ENABLE_MIRAGE_MODE`,
    silently getting no deception behavior despite the registry saying
    it's on).

    Status: **WORKED AROUND, not removed.** `GuardianOrchestrator` calls
    `deploy_hallucination(..., force_enable=True)`, deliberately
    bypassing `mirage.py`'s own env check -- the enable/disable decision
    is made once, at the registry level, before Guardian ever calls it.
    `mirage.py`'s own env var is left in place for backward
    compatibility with direct/manual invocation (e.g. someone running
    `python3 yomi_engine/mirage.py` directly, or a future CLI flag).
    Genuinely removing the duplicate mechanism (making
    `YOMI_ENABLE_MIRAGE_MODE` simply not exist) would be a larger,
    separate cleanup -- not done here since it risks breaking existing
    `tests/unit/test_mirage.py` assertions that specifically test that
    env var's behavior.

26. **Ghost Protocol and the eBPF Sensor bypassed `module_registry`
    entirely in `cli.py`.** Ghost Protocol was gated by its own ad-hoc
    `YOMI_ENABLE_GHOST_PROTOCOL` env var, never by
    `module_registry`'s `YOMI_MODULE_GHOST`. Worse: the eBPF Sensor
    had **no gating at all** -- `cli.py` unconditionally
    `subprocess.Popen`'d it on every `--auto` startup, completely
    ignoring `EBPF_SENSOR`'s `default_enabled=False` in the registry.

    Status: **FIXED (Fase 6, Tahap 1).** Both now go through
    `GuardianOrchestrator.bootstrap_startup_daemons()`, which consults
    `module_registry.resolve_active_modules()` exclusively. Operators
    who previously relied on `YOMI_ENABLE_GHOST_PROTOCOL=true` must
    switch to `YOMI_MODULE_GHOST=true` -- this is a deliberate breaking
    change to the env var name, made now (Fase 6) rather than carrying
    the inconsistency into the public release. Documented in
    `docs/usage.md` and the Fase 6 release notes. Tests:
    `tests/unit/test_guardian.py::test_bootstrap_ghost_*` and
    `::test_bootstrap_ebpf_sensor_*` (6 tests total).

27. **`pip install .` packages `yomi_data/` like any other Python
    module, so the evidence ledger/notary checkpoint/CVE store/HMAC key
    for a `pip`-installed daemon end up inside the venv's
    `site-packages/yomi_data/`, not anywhere an operator would
    intuitively look.** Not a bug in the sense of broken functionality
    -- `ImmutableStamp`/`OmniLibrary`'s `__file__`-relative path
    resolution finds it fine -- but for a DFIR tool, the evidence
    store's location needs to be predictable and documented, not
    implicit inside a venv's package directory.

    Status: **FIXED (known-issues cleanup), with one deliberate
    omission.** `yomi_data.resolve_data_dir()` is now the single resolver:
    when `YOMI_DATA_DIR` is set to an absolute path, `ImmutableStamp`,
    `OmniLibrary`, dossier, remediator, swarm, sandbox, shadow_net,
    mirage, the dashboard and `yomi_data` itself all keep their data
    there; a relative value raises `ValueError`. With the variable unset
    the default is unchanged (`yomi_data/` next to the package), and
    `scripts/install_yomi_linux.sh` still prints the resolved path. NOT
    done: defaulting `pip`-installed daemons to an FHS location such as
    `/var/lib/yomi-triage` -- that changes where existing installs look
    for their evidence, so it needs an explicit decision (the install
    script or service unit can export `YOMI_DATA_DIR` meanwhile).
    Covered by `tests/unit/test_data_dir_override.py`.

28. **A dev/test `yomi_data/audit_hmac.key` already present in the
    checkout gets silently copied into a "production" install via
    `pip install .`.** If someone ran the test suite or `cli.py --auto`
    locally before running the installer, that HMAC key -- not a fresh
    production key -- would end up signing the real evidence ledger.

    Status: **MITIGATED (Fase 6, Tahap 1).**
    `scripts/install_yomi_linux.sh` detects a pre-existing
    `yomi_data/audit_hmac.key` before installing and requires explicit
    interactive confirmation (`Continue anyway and reuse this key?
    [y/N]`) before proceeding, rather than silently continuing or
    silently deleting a key an operator might have a legitimate reason
    to keep. Not a full fix -- `setup.py`'s packaging behavior itself
    (including data files it shouldn't) is the root cause, same as #27
    above, and a real fix likely means addressing both together.

29. **`sandbox.py`'s `_monitor_awakened_threat` bypassed `module_registry`
    entirely when re-invoking `MindReaderDecompiler` and `MirageProtocol`
    after the post-detonation observation window** -- the same bug class
    as #26, found while actually running a full `DEMO_PROFILE_ENV`
    scenario end-to-end (not from reading the code). This is a SEPARATE
    call site from `GuardianOrchestrator`'s own pre-detonation dispatch,
    which already respected the registry -- so disabling `MIND_READER` or
    `MIRAGE` via env var had no effect on this specific post-detonation
    re-analysis pass.

    Status: **FIXED (Fase 6, Tahap 1).** Both calls now check
    `module_registry.resolve_active_modules()` first, matching every
    other dispatch site. Regression tests:
    `tests/unit/test_sandbox.py::test_monitor_awakened_threat_respects_disabled_mirage_and_mind_reader`
    (proves both stay uncalled when disabled), plus the two pre-existing
    tests updated to explicitly enable `MIRAGE` (previously they passed
    without needing to, since the old code never checked).

30. **Asymmetric Mirage decoy lifecycle when `SANDBOX` is enabled.** A
    single incident against one PID can end up with TWO independent
    Mirage decoys deployed for it: one from
    `GuardianOrchestrator.handle_post_containment` (pre-detonation
    dispatch), one from `sandbox.py`'s own `_monitor_awakened_threat`
    (post-detonation re-analysis, see #29 above). `sandbox.py` tears
    down its OWN decoy immediately after the observation window closes --
    but `guardian.py` never calls `teardown_hallucination()` for the one
    it deployed, leaving it to be cleaned up later (if at all before the
    process genuinely dies) by `periodic_maintenance()`'s
    `sweep_orphaned_hallucinations()` sweep. Not a security hole (the
    decoy is inert once the underlying process is gone) and not silent
    data loss, but the ledger will show two `HALLUCINATION_DEPLOYED`
    entries and only one `HALLUCINATION_TEARDOWN` for the same PID during
    a `SANDBOX`-enabled run -- worth knowing so it doesn't read as a
    ledger inconsistency. Found while capturing real demo output for
    `docs/demo_mode.md`.

    Status: **FIXED (known-issues cleanup).** `GuardianOrchestrator`
    records each decoy it deploys successfully and
    `teardown_incident_decoys()` removes them; `sentinel.py` calls it at
    end of incident, after the dossier. Failures are logged as
    `MIRAGE_TEARDOWN_DISPATCH_ERROR` and never raised. Decoys that
    `sandbox.py` deploys for itself are still torn down by `sandbox.py`.
    The periodic orphan sweep remains as the backstop. Covered in
    `tests/unit/test_guardian.py`.

31. **Telemetry benchmark named after and printed unverified "win"
    claims against a specific competitor's trademarked product.**
    `telemetry.py`'s `stop_timer()` computed a boolean field
    `beat_horizon3_ai` (`latency < 60.0`) and, when true, printed
    `"[✓] TACTICAL WIN : Defeated Horizon3 AI 60-second breakout time."`
    -- `dashboard.py` surfaced the same field as `"Beat Horizon3: ..."`.
    Horizon3.ai's NodeZero® is a real, currently active, well-funded,
    actively marketed commercial product (confirmed via web search, not
    assumed) -- and this field never reflected an actual head-to-head
    benchmark against it. It only ever compared Yomi's own latency
    against a publicly-stated industry breakout-time figure. Printing
    "Defeated Horizon3 AI" as if a real comparative test had been run is
    an unsubstantiated comparative claim tied to a real competitor's
    name, which is a materially different (and higher) risk than simply
    mentioning a competitor's product factually in prose.

    Status: **FIXED (Fase 6, Tahap 1).** Field renamed to
    `sub_60s_containment` (still `latency < 60.0`, same underlying
    industry benchmark figure, just no longer tied to one company's
    trademarked product name); log message changed to
    `"[✓] TACTICAL WIN : Sub-60s containment achieved."`. Updated
    `dashboard.py` and all tests (`test_dashboard.py`, `test_telemetry.py`)
    to match. `docs/hackathon/sans_submission.md` (the archived original
    hackathon pitch, which does name Horizon3/NodeZero) got an added
    naming-note disclaimer rather than being rewritten, since it's
    preserved verbatim for historical accuracy of what was actually
    submitted.

32. **Integration test / smoke test assumed a non-portable binary
    location.** `test_critical_threat_chain_freezes_real_process_end_to_end`
    and `scripts/smoke_test_cli.py` both spawned `[sys.executable, "-c", ...]`
    as the "target process," and asserted REMEDIATOR's #15
    path-containment fix refuses to generate a rollback script for it --
    on the assumption that the interpreter's own binary lives under a
    protected directory (`/bin`, `/sbin`, `/usr`, `/etc`). That held by
    coincidence in some environments but is NOT universal: GitHub
    Actions' `actions/setup-python` installs Python under
    `/opt/hostedtoolcache/`, which isn't protected, so CI got
    `PLAYBOOK_GENERATED` instead of the expected `ABORTED` -- a real CI
    failure, not a local sandbox artifact.

    Status: **FIXED (Fase 6, Tahap 1).** Both spawn `sleep` (a coreutils
    binary) instead of `sys.executable` -- `sleep` reliably resolves
    under `/bin` or `/usr/bin` on every mainstream Linux distribution,
    including usrmerge-based systems where `/bin` is a symlink into
    `/usr` (since `/proc/<pid>/exe` resolves through symlinks to the
    final real path), making the assertion portable rather than
    environment-dependent. Re-verified: integration suite and smoke test
    both pass; `docs/demo_mode.md` and `docs/usage.md`'s quoted real
    ledger output (previously showing `/usr/bin/python3`) re-captured to
    show `/usr/bin/sleep`.

## Fase 7 findings (cross-artifact correlation work)

33. **`MitreMapper`'s signature set is small, hardcoded, and nothing
    validates that assumed tactic IDs actually exist in it.** While
    building `correlator.py`'s cross-source corroboration logic (Fase 7),
    a `_check_credential_access_corroboration` function was written
    assuming a "credential access" MITRE tactic existed in
    `mitre_mapper.py`'s signature dictionary. It doesn't -- the module
    only has 5 fixed IoE signatures (`PE_INJECT`/T1055,
    `YR_RANSOMWARE`/T1486, `PROC_BAD_DTB`/T1014, `PEB_MASQ`/T1036.004,
    `C2_BEACON`/T1071), none with "credential" in their `tactical_desc`.
    The function would have been silent dead code -- it checks
    `mitre_tactics` entries that never contain the string it searches
    for, so its `if not claims_cred_access: return` guard would always
    fire and its actual logic would never run. Nothing (no import error,
    no test failure, no lint warning) would have flagged this; it was
    only caught by manually re-reading `mitre_mapper.py`'s signature
    table before committing.

    A related, real (not hypothetical) bug was caught the same way: the
    first draft of `_check_c2_corroboration`'s network-finding match
    (`external|c2` substring) false-positived against `swarm.py`'s own
    CLEAN finding wording (`"...without obvious external C2
    anomalies"`), which would have marked an uncorroborated MitreMapper
    keyword hit as "corroborated" -- the exact failure mode the
    correlator exists to prevent. Fixed by narrowing to the 4 specific
    positive-signal phrases `swarm.py` emits when it actually flags
    something; a regression test
    (`test_t1071_is_a_contradiction_when_network_agent_finds_nothing`)
    guards this specific case going forward.

    Status: **FIXED.** Both specific instances were fixed in Fase 7
    (dead credential-access check replaced with a real
    T1055/Process-Injection check; C2 corroboration regex narrowed and
    regression-tested). The broader design gap was fixed in the
    known-issues cleanup: `mitre_mapper.py` now exposes `RAW_SIGNATURES`,
    `GENERIC_ANOMALY_MITRE_ID` and a `KNOWN_MITRE_IDS` frozenset
    (importable without instantiating `MitreMapper`), and
    `correlator.py` declares the IDs its checks depend on as
    `C2_TACTIC_ID` / `PROCESS_INJECTION_TACTIC_ID` /
    `CORROBORATED_TACTIC_IDS`. Two tests in
    `tests/unit/test_correlator.py` assert those IDs, and every
    ATT&CK-shaped string literal in `correlator.py`, are in
    `KNOWN_MITRE_IDS`, so a check written against a tactic the mapper
    never emits is now a test failure instead of a silent no-op.

## TUI polish findings (dashboard.py / cli.py)

34. **The dashboard's latency/speed rows showed a permanent red `[TAMPERED] FILE MISSING` / `AUDIT LOG COMPROMISED` on every normal install.** `dashboard.py` read `telemetry_benchmarks.jsonl`, but `TelemetryEngine` has only ever recorded benchmarks in the audit ledger (`BENCHMARK_RECORDED`, with the report in `metadata`); nothing creates that file. A missing file was reported as tampering, so the alarm was always on and the real latency was never displayed.

    Status: **FIXED.** The dashboard reads the latest `BENCHMARK_RECORDED` entry from the ledger tail. `[TAMPERED]` is shown only when a telemetry file existed during the session and then disappeared. A test that had locked in the old behavior was rewritten
    (`test_refresh_telemetry_missing_file_on_fresh_install_is_not_an_alarm`); new tests cover the ledger source, the vanished-file alarm and `YOMI_DATA_DIR`.

35. **The TUI froze between ledger events and was slow to appear.** `Live(tui.render_layout(), ...)` rendered a layout built once per event, so CPU/RAM and the other metrics that the background thread kept updating were not redrawn until the next event. `YomiDashboard()` also built `OmniLibrary()` synchronously, whose network probe retries for several seconds on an air-gapped host, leaving raw `[YOMI-AUDIT]` lines on screen instead of the UI. Only the newest ledger entry was shown at startup, and the `DEPLOYED` noise filter also hid Shadow Net deployments.

    Status: **FIXED.** `Live(get_renderable=tui.render_layout)` rebuilds the layout on every refresh; the library is created on its own thread (`YomiDashboard(lazy_library=True)`); the last 60 events are replayed at startup with their original timestamps; `DEPLOYED` is hidden only for the SWARM agent. Tests in `tests/unit/test_dashboard.py` and the new `tests/unit/test_cli_tui.py` (the TUI loop had no tests before).

36. **Stray `print()`/stderr output could land on the TUI screen.** `Live` was created with its default `redirect_stdout=True`, which routes any print into the live display above the layout and pushes the layout down until the next redraw (reproduced in a pty with a thread calling `record_action`). In `--auto` mode this was only masked because `_run_sentinel_daemon`'s worker uses `contextlib.redirect_stdout`, which is process-wide and therefore silences every thread once Sentinel has started; anything printed before that point depended on start order.

    Status: **FIXED.** The TUI now owns this explicitly: for its lifetime stdout/stderr are replaced by a null sink (`_quiet_stdio`) and `Live` runs with `redirect_stdout=False`; the dashboard's own console keeps writing to the original stdout. Everything shown is derived from the ledger, which already records those events.

37. **Several tests failed intermittently depending on the PID the run happened to get.** `harness.py` and `os_bridge.py` deliberately refuse any PID <= 100 as core OS/kernel. Tests that assert on a real process break when that process (or pytest itself) has such a PID: `test_os_bridge.py::test_cryogenic_freeze_refuses_self` (preempted by the PID <= 100 block before the "current or parent process" check), `::test_cryogenic_freeze_and_thaw_real_process`, `::test_freeze_dead_pid_reports_ghost_process`, and `tests/integration/test_chain_sentinel_router_harness.py::test_critical_threat_chain_freezes_real_process_end_to_end`. It happens when a container's PID counter has just wrapped or in a fresh PID namespace (reproduced with `unshare --pid --fork --mount-proc`: 4 failures on the previous code), and is why the first of them was already noted as flaky in a container. Only the tests were affected: the protection in `harness.py`/`os_bridge.py` behaves as designed.

    Status: **FIXED (tests only).** The three tests that spawn a child (two in `test_os_bridge.py` via `_spawn_above_reserved_pids`, one integration test inline) now spawn and reap throwaway children until the target's PID is above the protected range (up to 300 attempts, then skip with a reason), so they keep running instead of failing. The self-refusal test cannot change its own PID, so it is skipped with an explicit reason when pytest's PID is <= 100. In a PID namespace that starts at 1 the suite now gives only that one skip.
