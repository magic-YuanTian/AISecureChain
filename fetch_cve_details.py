"""
Fetch CVE details from the CVE.org API for all AI-related CVEs.
Uses concurrent requests for speed. Saves progress incrementally.
"""

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

OUTPUT_FILE = "output/cve_details.json"
CVE_IDS_FILE = "output/cve_ids.json"
API_BASE = "https://cveawg.mitre.org/api/cve"
MAX_WORKERS = 15


def fetch_one_cve(cve_id):
    """Fetch a single CVE record from the CVE.org API."""
    try:
        r = requests.get(f"{API_BASE}/{cve_id}", timeout=15)
        if r.status_code == 200:
            return cve_id, r.json()
        else:
            return cve_id, {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return cve_id, {"error": str(e)}


def main():
    with open(CVE_IDS_FILE) as f:
        cve_ids = json.load(f)
    print(f"Total CVEs to fetch: {len(cve_ids)}")

    existing = {}
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE) as f:
            existing = json.load(f)
        print(f"Already fetched: {len(existing)}")

    remaining = [c for c in cve_ids if c not in existing]
    print(f"Remaining to fetch: {len(remaining)}")

    if not remaining:
        print("All CVEs already fetched!")
        return

    results = dict(existing)
    fetched = 0
    errors = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_one_cve, cve_id): cve_id for cve_id in remaining}

        for future in as_completed(futures):
            cve_id, data = future.result()
            results[cve_id] = data
            fetched += 1

            if "error" in data:
                errors += 1

            if fetched % 100 == 0:
                elapsed = time.time() - start_time
                rate = fetched / elapsed
                eta = (len(remaining) - fetched) / rate if rate > 0 else 0
                print(f"  [{fetched}/{len(remaining)}] {rate:.1f} req/s, ETA: {eta:.0f}s, errors: {errors}")

                with open(OUTPUT_FILE, "w") as f:
                    json.dump(results, f, ensure_ascii=False)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, ensure_ascii=False)

    elapsed = time.time() - start_time
    print(f"\nDone! Fetched {fetched} CVEs in {elapsed:.1f}s ({fetched/elapsed:.1f} req/s)")
    print(f"Errors: {errors}")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
