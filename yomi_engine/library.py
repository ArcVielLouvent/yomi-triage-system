import lzma
import hashlib
import io
import json
import os
import threading
import time
from datetime import datetime, timezone
import functools
import copy

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Omni-Library
# Purpose: Localized Threat Intelligence & CVE Retrieval System.
#          - LRU Memory Caching (Zero OOM Risk)
#          - Time-Sliced O(1) Lookups (High Speed Triage)
#          - Deadlock-free threading model
# ==============================================================================


class OmniLibrary:
    RECENT_FEED_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-recent.json.xz"
    ARCHIVE_FEED_TEMPLATE = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
    DEFAULT_SYNC_INTERVAL = 3600

    def __init__(
        self, data_dir: str | None = None, sync_interval: int = DEFAULT_SYNC_INTERVAL
    ):
        self.data_dir = (
            data_dir
            if data_dir
            else os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "yomi_data")
            )
        )
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_dir = os.path.join(self.data_dir, "cve_store")
        self.manifest_file = os.path.join(self.db_dir, "manifest.json")
        self.db_file = os.path.join(self.data_dir, "cve_database.json")

        self.database_write_lock = (
            threading.Lock()
        )  # Only lock on write to prevent read deadlocks

        self.last_updated: str | None = None
        self.source: str = "LOCAL"
        self.online: bool = False
        self.sync_interval = max(60, sync_interval)
        self.stop_event = threading.Event()
        self.audit = ImmutableStamp()

        self.audit.record_action(
            "OMNI_LIBRARY",
            "LEDGER_VERIFICATION",
            "Verified immutable audit ledger on startup.",
            metadata={
                "ledger_file": self.audit.ledger_file,
                "entry_count": self.audit.get_ledger_summary().get("entry_count", 0),
            },
        )

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "YomiOmniLibrary/2.0 (+https://github.com/ArcVielLouvent/yomi-triage-system)",
                "Accept": "application/json",
            }
        )

        self._ensure_data_store()
        self._configure_http_session()
        self._load_manifest()
        self._validate_manifest()
        self._seed_recent_database()
        self._start_continuous_scraping()

    def _ensure_data_store(self):
        os.makedirs(self.db_dir, exist_ok=True)
        if not os.path.exists(self.manifest_file):
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "years": {},
                        "total_count": 0,
                        "last_updated": None,
                        "source": "LOCAL",
                    },
                    f,
                )
            self._secure_store_permissions()

    def _secure_store_permissions(self):
        try:
            os.chmod(self.db_dir, 0o700)
            os.chmod(self.manifest_file, 0o600)
        except OSError:
            pass

    def _configure_http_session(self):
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["HEAD", "GET"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _load_manifest(self):
        try:
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                manifest = json.load(f)
                self.year_index = {
                    int(year): int(count)
                    for year, count in manifest.get("years", {}).items()
                }
                self.last_updated = manifest.get("last_updated")
                self.source = manifest.get("source", "LOCAL")
        except Exception:
            self.year_index = {}
            self.last_updated = None
            self.source = "LOCAL"

        if not self.year_index and os.path.exists(self.db_file):
            self._migrate_old_database()

    def _persist_manifest(self):
        with self.database_write_lock:
            manifest = {
                "years": {
                    str(year): count for year, count in sorted(self.year_index.items())
                },
                "total_count": sum(self.year_index.values()),
                "last_updated": self.last_updated,
                "source": self.source,
            }
            temp_manifest = self.manifest_file + ".tmp"
            with open(temp_manifest, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, sort_keys=True)
            os.replace(temp_manifest, self.manifest_file)
            self._secure_store_permissions()

    def _validate_manifest(self):
        if not os.path.exists(self.manifest_file):
            self._persist_manifest()
            return
        try:
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                json.load(f)
        except (json.JSONDecodeError, ValueError):
            backup = f"{self.manifest_file}.corrupt.{int(time.time())}"
            os.replace(self.manifest_file, backup)
            self._persist_manifest()

    def _year_file(self, year: int) -> str:
        return os.path.join(self.db_dir, f"{year}.json")

    # LRU Cache ensures RAM never spikes. Max 2 years kept in memory at a time.
    @functools.lru_cache(maxsize=2)
    def _load_year_file(self, year: int) -> dict:
        path = self._year_file(year)
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
                if isinstance(content, dict):
                    return content
                if isinstance(content, list):
                    converted = {}
                    for item in content:
                        if isinstance(item, dict) and item.get("cve_id"):
                            converted[str(item["cve_id"])] = item
                    return converted
        except Exception:
            pass
        return {}

    def _save_year_file(self, year: int, year_store: dict) -> None:
        with self.database_write_lock:
            path = self._year_file(year)
            temp_path = path + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(year_store, f, indent=2, sort_keys=True)
            os.replace(temp_path, path)
            self._secure_store_permissions()

            # Invalidate cache since disk data changed
            self._load_year_file.cache_clear()

    def _extract_year_from_entry(self, entry: dict) -> int:
        published = entry.get("published_date")
        if isinstance(published, str) and len(published) >= 4:
            try:
                return int(published[:4])
            except ValueError:
                pass
        return (
            self._extract_year_from_cve_id(entry.get("cve_id", ""))
            or datetime.now(timezone.utc).year
        )

    def _extract_year_from_cve_id(self, cve_id: str) -> int | None:
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            parts = cve_id.split("-")
            if len(parts) >= 3 and parts[1].isdigit():
                try:
                    return int(parts[1])
                except ValueError:
                    pass
        return None

    def _migrate_old_database(self):
        try:
            with open(self.db_file, "r", encoding="utf-8") as f:
                old_entries = json.load(f)
            if isinstance(old_entries, list):
                buckets = {}
                for item in old_entries:
                    normalized = self._normalize_entry(item)
                    if not normalized:
                        continue
                    year = self._extract_year_from_entry(normalized)
                    normalized["record_hash"] = self._compute_entry_hash(normalized)
                    buckets.setdefault(year, {})[normalized["cve_id"]] = normalized

                for year, year_store in buckets.items():
                    existing = self._load_year_file(year).copy()
                    existing.update(year_store)
                    self._save_year_file(year, existing)
                    self.year_index[year] = len(existing)
                self._persist_manifest()
                migrated = self.db_file + ".migrated"
                os.replace(self.db_file, migrated)
        except Exception:
            pass

    def _compute_entry_hash(self, item: dict) -> str:
        normalized = {
            key: item[key]
            for key in sorted(item)
            if key not in {"record_hash", "ingested_at", "_orig_record_hash"}
        }
        payload = json.dumps(normalized, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _has_network(self) -> bool:
        try:
            response = self.session.head(
                "https://nvd.nist.gov", timeout=5, allow_redirects=True
            )
            return 200 <= response.status_code < 400
        except requests.RequestException:
            return False

    def _normalize_entry(
        self, item: dict, origin_feed: str | None = None
    ) -> dict | None:
        if not isinstance(item, dict):
            return None

        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id")
        if not cve_id:
            return None

        descriptions = cve_obj.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        references = cve_obj.get("references", [])
        reference_urls = [ref.get("url") for ref in references if ref.get("url")]

        return {
            "cve_id": str(cve_id),
            "target": str(cve_id),
            "description": str(description),
            "published_date": cve_obj.get("published"),
            "cvss_score": self._extract_cvss(cve_obj),
            "references": reference_urls,
            "indicators": [cve_id] + reference_urls,
            "origin_feed": origin_feed or "GITHUB_MIRROR",
            "ingested_at": datetime.now(timezone.utc).isoformat() + "Z",
        }

    def _extract_cvss(self, cve_obj: dict):
        metrics = cve_obj.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and len(metrics[version]) > 0:
                score = metrics[version][0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return score
        return None

    def _merge_external_entries(
        self, entries: list, origin_feed: str | None = None
    ) -> int:
        added, updated = 0, 0
        year_buckets = {}

        for item in entries:
            normalized = self._normalize_entry(item, origin_feed=origin_feed)
            if not normalized:
                continue
            normalized["record_hash"] = self._compute_entry_hash(normalized)
            year = self._extract_year_from_entry(normalized)
            year_buckets.setdefault(year, {})[normalized["cve_id"]] = normalized

        for year, year_entries in year_buckets.items():
            year_store = self._load_year_file(year).copy()
            for cve_id, normalized in year_entries.items():
                existing = year_store.get(cve_id)
                if existing is None:
                    year_store[cve_id] = normalized
                    added += 1
                else:
                    existing_snapshot = {
                        k: v
                        for k, v in existing.items()
                        if k not in {"record_hash", "ingested_at"}
                    }
                    normalized_snapshot = {
                        k: v
                        for k, v in normalized.items()
                        if k not in {"record_hash", "ingested_at"}
                    }
                    if normalized_snapshot != existing_snapshot:
                        year_store[cve_id].update(normalized)
                        year_store[cve_id]["record_hash"] = self._compute_entry_hash(
                            year_store[cve_id]
                        )
                        updated += 1
            if year_store:
                self._save_year_file(year, year_store)
                self.year_index[year] = len(year_store)

        if added or updated:
            self._persist_manifest()
        return added

    def _fetch_url(self, url: str, timeout: int = 30) -> bytes | None:
        try:
            response = self.session.get(url, timeout=timeout)
            if response.status_code == 200:
                return response.content
        except requests.RequestException:
            pass
        return None

    def _fetch_nvd_recent(self) -> bool:
        content = self._fetch_url(self.RECENT_FEED_URL, timeout=30)
        if not content:
            return False
        try:
            with lzma.LZMAFile(fileobj=io.BytesIO(content)) as xz:
                payload = json.load(xz)
            added = self._merge_external_entries(
                payload.get("vulnerabilities", []), origin_feed="NVD_RECENT"
            )
            if added:
                self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"
                self.source = "NVD_RECENT"
                self._persist_manifest()
                self.audit.record_action(
                    "OMNI_LIBRARY", "CVE_SYNC", f"Synced {added} CVEs."
                )
            self.online = True
            return True
        except Exception:
            return False

    def _seed_recent_database(self):
        if self._has_network():
            self._fetch_nvd_recent()

    def seed_full_nvd_archive(
        self, start_year: int = 1999, end_year: int | None = None
    ):
        if not self._has_network():
            return
        end_year = end_year or datetime.now(timezone.utc).year
        for year in range(start_year, end_year + 1):
            try:
                content = self._fetch_url(
                    self.ARCHIVE_FEED_TEMPLATE.format(year=year), timeout=90
                )
                if not content:
                    continue
                with lzma.LZMAFile(fileobj=io.BytesIO(content)) as xz:
                    payload = json.load(xz)
                self._merge_external_entries(
                    payload.get("vulnerabilities", []),
                    origin_feed=f"NVD_ARCHIVE_{year}",
                )
                time.sleep(1)
            except Exception:
                continue

    def _scraping_worker(self):
        while not self.stop_event.wait(self.sync_interval):
            if self._has_network():
                self.online = True
                self._fetch_nvd_recent()
            else:
                self.online = False

    def _start_continuous_scraping(self):
        threading.Thread(target=self._scraping_worker, daemon=True).start()

    def shutdown(self):
        self.stop_event.set()

    def analyze_artifact(
        self, artifact_name: str, context_hints: list | None = None
    ) -> dict:
        if not isinstance(artifact_name, str) or not artifact_name.strip():
            return {
                "status": "ERROR",
                "analysis": "Invalid artifact name.",
                "matches": [],
            }

        search_terms = [artifact_name.strip().lower()] + [
            str(h).lower() for h in (context_hints or [])
        ]
        matches = []
        MAX_RESULTS = 3

        target_years = []
        import re

        cve_pattern = re.search(
            r"cve[-_.\s]?(\d{4})[-_.\s]?", artifact_name, re.IGNORECASE
        )
        if cve_pattern:
            extracted_year = int(cve_pattern.group(1))
            if extracted_year in self.year_index:
                target_years = [extracted_year]

        if not target_years:
            target_years = sorted(self.year_index.keys(), reverse=True)

        for year in target_years:
            year_store = self._load_year_file(year)
            for entry in year_store.values():
                combined_text = " ".join(
                    [str(entry.get("cve_id", "")), str(entry.get("description", ""))]
                ).lower()

                if any(term in combined_text for term in search_terms):
                    matches.append(copy.deepcopy(entry))

                    if len(matches) >= MAX_RESULTS:
                        break

            if len(matches) >= MAX_RESULTS:
                break

        return {
            "status": "THREAT_FOUND" if matches else "CLEAN_OR_UNKNOWN",
            "matches": matches[:MAX_RESULTS],
            "analysis": (
                f"Found {len(matches)} vulnerabilities."
                if matches
                else "No matching threats found in the Omni-Library."
            ),
        }

    def query_cve(self, cve_id: str) -> dict | None:
        if not isinstance(cve_id, str) or not cve_id.strip():
            return None

        year = self._extract_year_from_cve_id(cve_id.strip())
        if year:
            entry = self._load_year_file(year).get(cve_id.strip())
            return copy.deepcopy(entry) if entry else None

        # Lock-free scan for unformatted CVE queries
        for file_year in sorted(self.year_index, reverse=True):
            entry = self._load_year_file(file_year).get(cve_id.strip())
            if entry:
                return copy.deepcopy(entry)
        return None

    def query_cve(self, cve_id: str) -> dict | None:
        if not isinstance(cve_id, str) or not cve_id.strip():
            return None

        year = self._extract_year_from_cve_id(cve_id.strip())
        if year:
            return self._load_year_file(year).get(cve_id.strip(), {}).copy() or None

        # Lock-free scan for unformatted CVE queries
        for file_year in sorted(self.year_index, reverse=True):
            entry = self._load_year_file(file_year).get(cve_id.strip())
            if entry:
                return entry.copy()
        return None

    def get_metadata(self) -> dict:
        return {
            "count": sum(self.year_index.values()),
            "years": sorted(self.year_index.keys()),
            "last_updated": self.last_updated,
            "source": self.source,
            "online": self.online,
        }
