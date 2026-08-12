import json
import os
import re
import stat
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
CVE_STORE_DIR = DATA_DIR / "cve_store"
MANIFEST_FILE = CVE_STORE_DIR / "manifest.json"
LEDGER_FILE = DATA_DIR / "yomi_chain_of_custody.jsonl"
MIGRATED_FILE = DATA_DIR / "cve_database.json.migrated"
CORRUPT_SUFFIX = ".corrupt"
DEFAULT_MANIFEST = {
    "years": {},
    "total_count": 0,
    "last_updated": None,
    "source": "LOCAL",
}
YEAR_FILE_PATTERN = re.compile(r"^\d{4}\.json$")
DEFAULT_DIRECTORY_MODE = 0o700
DEFAULT_FILE_MODE = 0o600


def _secure_path(path: Path, mode: int) -> None:
    try:
        if path.exists():
            path.chmod(mode)
    except OSError:
        pass


def _atomic_write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as temp_file:
        json.dump(payload, temp_file, indent=2, sort_keys=True)
    os.replace(tmp_path, path)
    _secure_path(path, 0o600)


def _mark_corrupt_file(path: Path, reason: str, raw_content: str | None = None) -> None:
    backup_path = path.with_name(
        path.name + CORRUPT_SUFFIX + f".{int(time.time())}.json"
    )
    try:
        payload = {
            "_corrupt_reason": reason,
            "_source_file": str(path.name),
            "_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "raw_data": raw_content,
        }
        with open(backup_path.with_suffix(backup_path.suffix + ".tmp"), "w", encoding="utf-8") as backup_file:
            json.dump(payload, backup_file, indent=2, sort_keys=True)
        os.replace(str(backup_path.with_suffix(backup_path.suffix + ".tmp")), str(backup_path))
        _secure_path(backup_path, 0o600)
    except OSError:
        pass


def _ensure_directory(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _secure_path(path, mode)


def _ensure_ledger_file() -> None:
    _ensure_directory(DATA_DIR, mode=0o700)
    if not LEDGER_FILE.exists():
        LEDGER_FILE.write_text("", encoding="utf-8")
    _secure_path(LEDGER_FILE, 0o600)


def _ensure_manifest() -> None:
    _ensure_directory(CVE_STORE_DIR, mode=0o700)
    if not MANIFEST_FILE.exists():
        _atomic_write_json(MANIFEST_FILE, DEFAULT_MANIFEST)
    _secure_path(MANIFEST_FILE, 0o600)


def _assert_not_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Security violation: '{path}' must not be a symlink.")
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError(f"Security violation: ancestor '{parent}' of '{path}' is a symlink.")


def _assert_path_ownership(path: Path) -> None:
    if os.name != "posix" or not path.exists():
        return
    owner_uid = path.stat().st_uid
    safe_owner_ids = {0, os.getuid()}
    if owner_uid not in safe_owner_ids:
        raise ValueError(
            f"Security violation: '{path}' is owned by UID {owner_uid}, expected {safe_owner_ids}."
        )


def _assert_file_permissions(path: Path, expected_mode: int) -> None:
    if os.name != "posix" or not path.exists():
        return
    actual_mode = stat.S_IMODE(path.stat().st_mode)
    if actual_mode != expected_mode:
        raise ValueError(
            f"Permission violation: '{path}' mode {oct(actual_mode)} does not match expected {oct(expected_mode)}."
        )


def _assert_data_store_integrity() -> None:
    _assert_not_symlink(DATA_DIR)
    _assert_not_symlink(CVE_STORE_DIR)
    _assert_not_symlink(MANIFEST_FILE)
    _assert_not_symlink(LEDGER_FILE)
    _assert_path_ownership(DATA_DIR)
    _assert_path_ownership(CVE_STORE_DIR)
    _assert_path_ownership(MANIFEST_FILE)
    _assert_path_ownership(LEDGER_FILE)
    if MIGRATED_FILE.exists():
        _assert_not_symlink(MIGRATED_FILE)
        _assert_path_ownership(MIGRATED_FILE)


def _load_json_file(path: Path) -> object:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_year_file(path: Path) -> dict[str, dict]:
    raw_content = path.read_text(encoding="utf-8")
    payload = json.loads(raw_content)
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list):
        normalized: dict[str, dict] = {}
        for item in payload:
            if isinstance(item, dict) and item.get("cve_id"):
                normalized[str(item["cve_id"])] = item
        return normalized
    raise ValueError("Year file JSON is not a dictionary or list.")


def _validate_year_file(year_file: Path) -> tuple[int, bool]:
    _assert_not_symlink(year_file)
    _assert_path_ownership(year_file)
    _assert_file_permissions(year_file, DEFAULT_FILE_MODE)

    try:
        entries = _load_year_file(year_file)
    except Exception as exc:
        raw_content = None
        try:
            raw_content = year_file.read_text(encoding="utf-8")
        except Exception:
            pass
        _mark_corrupt_file(
            year_file,
            f"Invalid year file content: {exc}",
            raw_content,
        )
        return 0, False

    valid_count = 0
    for key, value in entries.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            _mark_corrupt_file(
                year_file,
                "Year file contains invalid entry types.",
                year_file.read_text(encoding="utf-8"),
            )
            return 0, False
        if str(value.get("cve_id", "")) != key:
            _mark_corrupt_file(
                year_file,
                "Year file entry key does not match cve_id field.",
                year_file.read_text(encoding="utf-8"),
            )
            return 0, False
        valid_count += 1

    return valid_count, True


def _scan_cve_store() -> tuple[dict[int, int], list[str], list[str], bool]:
    _ensure_directory(CVE_STORE_DIR, mode=DEFAULT_DIRECTORY_MODE)
    entries_by_year: dict[int, int] = {}
    corrupt_files: list[str] = []
    invalid_candidates: list[str] = []
    encountered_invalid = False

    for candidate in sorted(CVE_STORE_DIR.iterdir()):
        if not candidate.is_file():
            continue
        if candidate.name == MANIFEST_FILE.name:
            continue
        if not YEAR_FILE_PATTERN.match(candidate.name):
            invalid_candidates.append(str(candidate))
            encountered_invalid = True
            continue

        try:
            count, valid = _validate_year_file(candidate)
            if valid:
                year = int(candidate.stem)
                entries_by_year[year] = count
            else:
                corrupt_files.append(str(candidate))
                encountered_invalid = True
        except Exception:
            corrupt_files.append(str(candidate))
            encountered_invalid = True

    return entries_by_year, corrupt_files, invalid_candidates, encountered_invalid


def _repair_manifest_if_needed(manifest: dict, entries_by_year: dict[int, int]) -> dict:
    actual_total = sum(entries_by_year.values())
    expected_total = int(manifest.get("total_count", 0))
    canonical_year_summary = {str(year): count for year, count in sorted(entries_by_year.items())}

    if manifest.get("years", {}) != canonical_year_summary:
        manifest["years"] = canonical_year_summary
        manifest["total_count"] = actual_total
        manifest["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    elif expected_total != actual_total:
        manifest["total_count"] = actual_total
        manifest["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    manifest["source"] = manifest.get("source", "LOCAL")
    _atomic_write_json(MANIFEST_FILE, manifest)
    return manifest


def validate_manifest() -> dict:
    _ensure_manifest()
    _assert_not_symlink(MANIFEST_FILE)
    _assert_path_ownership(MANIFEST_FILE)
    _assert_file_permissions(MANIFEST_FILE, DEFAULT_FILE_MODE)

    try:
        manifest = _load_json_file(MANIFEST_FILE)
        if not isinstance(manifest, dict):
            raise ValueError("Manifest content must be a JSON object.")
        return manifest
    except (json.JSONDecodeError, ValueError) as exc:
        raw_manifest = None
        try:
            raw_manifest = MANIFEST_FILE.read_text(encoding="utf-8")
        except Exception:
            pass
        _mark_corrupt_file(
            MANIFEST_FILE,
            f"Invalid manifest file: {exc}",
            raw_manifest,
        )
        try:
            MANIFEST_FILE.unlink()
        except OSError:
            pass
        _atomic_write_json(MANIFEST_FILE, DEFAULT_MANIFEST)
        return DEFAULT_MANIFEST.copy()


def validate_data_store() -> dict:
    _assert_data_store_integrity()
    _ensure_ledger_file()
    manifest = validate_manifest()
    if MIGRATED_FILE.exists():
        _secure_path(MIGRATED_FILE, DEFAULT_FILE_MODE)

    entries_by_year, corrupt_files, invalid_candidates, store_invalid = _scan_cve_store()
    manifest = _repair_manifest_if_needed(manifest, entries_by_year)

    total_count = sum(entries_by_year.values())
    manifest_total = int(manifest.get("total_count", 0))
    counts_match = total_count == manifest_total

    return {
        "data_dir": str(DATA_DIR),
        "ledger_file": str(LEDGER_FILE),
        "manifest_file": str(MANIFEST_FILE),
        "migrated_archive": str(MIGRATED_FILE) if MIGRATED_FILE.exists() else "",
        "actual_total_count": total_count,
        "manifest_total_count": manifest_total,
        "counts_match": counts_match,
        "year_files": sorted(entries_by_year.keys()),
        "year_file_count": len(entries_by_year),
        "corrupt_year_files": corrupt_files,
        "invalid_year_candidates": invalid_candidates,
        "manifest_needs_repair": store_invalid or not counts_match,
    }


def read_latest_ledger_entry() -> dict | None:
    _assert_not_symlink(LEDGER_FILE)
    if not LEDGER_FILE.exists():
        return None
    try:
        with open(LEDGER_FILE, "r", encoding="utf-8") as ledger_handle:
            lines = [line.strip() for line in ledger_handle if line.strip()]
        if not lines:
            return None
        return json.loads(lines[-1])
    except (json.JSONDecodeError, OSError):
        return None


def load_year_store(year: int) -> dict[str, dict]:
    path = CVE_STORE_DIR / f"{year}.json"
    if not path.exists():
        return {}
    count, valid = _validate_year_file(path)
    if not valid:
        return {}
    return _load_year_file(path)


def write_year_store(year: int, year_store: dict[str, dict]) -> None:
    _ensure_directory(CVE_STORE_DIR, mode=DEFAULT_DIRECTORY_MODE)
    path = CVE_STORE_DIR / f"{year}.json"
    _atomic_write_json(path, year_store)
    _secure_path(path, DEFAULT_FILE_MODE)
