"""Resolve CWE id(s) from a CVE (NVD) and/or GHSA (GitHub Advisories).

Used by the extract validator cascade and by ``scripts/lookup_advisory_cwe.py``.

  CVE  → NVD CVE API 2.0
  GHSA → GitHub Security Advisories API
         (if the GHSA lists a CVE and follow_cve=True, also query NVD)

Env (optional, raises rate limits)
---------------------------------
  NVD_API_KEY     header apiKey for services.nvd.nist.gov
  GITHUB_TOKEN    Authorization: Bearer … for api.github.com
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

QE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = QE_ROOT.parent
_ENV_PATH = REPO_ROOT / ".env"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


def _load_env_file(path: Path = _ENV_PATH) -> None:
    if not path.exists():
        return
    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key and key not in os.environ:
                    os.environ[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass


_load_env_file()


def is_advisory_id(vuln_id: str | None) -> bool:
    """True when ``vuln_id`` is a CVE or GHSA (not AISC/AVID/etc.)."""
    if not vuln_id:
        return False
    s = str(vuln_id).strip()
    return bool(CVE_RE.match(s) or GHSA_RE.match(s))


def _normalize_cwe(raw: str) -> str | None:
    s = (raw or "").strip().upper().replace("_", "-")
    if not s:
        return None
    if s.startswith("CWE-"):
        num = s[4:]
    elif s.isdigit():
        num = s
    else:
        return None
    if not num.isdigit():
        return None
    return f"CWE-{int(num)}"


def _http_get(url: str, headers: dict[str, str], timeout: float = 30.0) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"HTTP {e.code} for {url}: {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"request failed for {url}: {e}") from e
    return json.loads(body) if body else {}


def lookup_cve_nvd(cve_id: str, *, api_key: str | None = None) -> dict[str, Any]:
    """Return {id, source, cwes, cves, title, error?} from NVD."""
    cve_id = cve_id.strip().upper()
    if not CVE_RE.match(cve_id):
        return {"id": cve_id, "source": "nvd", "cwes": [], "cves": [cve_id], "error": "invalid CVE id"}

    key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "").strip()
    headers = {"Accept": "application/json", "User-Agent": "AISecureChain-advisory_cwe"}
    if key:
        headers["apiKey"] = key

    url = f"{NVD_CVE_URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
    try:
        data = _http_get(url, headers)
    except RuntimeError as e:
        return {"id": cve_id, "source": "nvd", "cwes": [], "cves": [cve_id], "error": str(e)}

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return {
            "id": cve_id,
            "source": "nvd",
            "cwes": [],
            "cves": [cve_id],
            "title": None,
            "error": "CVE not found in NVD (or empty response)",
        }

    cve = (vulns[0].get("cve") or {})
    title = None
    for d in cve.get("descriptions") or []:
        if (d.get("lang") or "").lower() == "en" and d.get("value"):
            title = d["value"]
            break
    if not title and (cve.get("descriptions") or []):
        title = (cve["descriptions"][0] or {}).get("value")

    cwes: list[str] = []
    for block in cve.get("weaknesses") or []:
        for desc in block.get("description") or []:
            cwe = _normalize_cwe(str(desc.get("value") or ""))
            if not cwe or cwe in {"CWE-0"}:
                continue
            raw = str(desc.get("value") or "").upper()
            if "NVD-CWE-NOINFO" in raw or "NVD-CWE-OTHER" in raw or raw.startswith("NVD-CWE"):
                continue
            if cwe not in cwes:
                cwes.append(cwe)

    return {
        "id": cve_id,
        "source": "nvd",
        "cwes": cwes,
        "cves": [cve_id],
        "title": title,
        "error": None if cwes else "NVD returned no usable CWE (noinfo/other/empty)",
    }


def lookup_ghsa(
    ghsa_id: str,
    *,
    token: str | None = None,
    follow_cve: bool = False,
    nvd_api_key: str | None = None,
) -> dict[str, Any]:
    """Return {id, source, cwes, cves, title, nvd?, error?} from GitHub Advisories."""
    ghsa_id = ghsa_id.strip().upper()
    ghsa_path = ghsa_id.lower()
    if not GHSA_RE.match(ghsa_id):
        return {"id": ghsa_id, "source": "github", "cwes": [], "cves": [], "error": "invalid GHSA id"}

    tok = token if token is not None else os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AISecureChain-advisory_cwe",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if tok:
        headers["Authorization"] = f"Bearer {tok}"

    url = f"{GITHUB_ADVISORY_URL}/{ghsa_path}"
    try:
        data = _http_get(url, headers)
    except RuntimeError as e:
        return {"id": ghsa_id, "source": "github", "cwes": [], "cves": [], "error": str(e)}

    cwes: list[str] = []
    for item in data.get("cwes") or []:
        cwe = _normalize_cwe(str(item.get("cwe_id") or item.get("cweId") or ""))
        if cwe and cwe not in cwes:
            cwes.append(cwe)

    cves: list[str] = []
    for ident in data.get("identifiers") or []:
        if str(ident.get("type") or "").upper() == "CVE":
            cid = str(ident.get("value") or "").strip().upper()
            if CVE_RE.match(cid) and cid not in cves:
                cves.append(cid)
    for cid in data.get("cve_id") or [] if isinstance(data.get("cve_id"), list) else []:
        cid_u = str(cid).strip().upper()
        if CVE_RE.match(cid_u) and cid_u not in cves:
            cves.append(cid_u)

    out: dict[str, Any] = {
        "id": ghsa_id,
        "source": "github",
        "cwes": cwes,
        "cves": cves,
        "title": data.get("summary") or data.get("description"),
        "error": None if cwes else "GitHub advisory returned no CWE",
    }

    if follow_cve and cves and not cwes:
        nvd = lookup_cve_nvd(cves[0], api_key=nvd_api_key)
        out["nvd"] = nvd
        for cwe in nvd.get("cwes") or []:
            if cwe not in out["cwes"]:
                out["cwes"].append(cwe)
        if out["cwes"]:
            out["error"] = None
        elif nvd.get("error"):
            out["error"] = f"GHSA had no CWE; NVD follow-up: {nvd['error']}"

    return out


def lookup(id_str: str, *, follow_cve: bool = False) -> dict[str, Any]:
    """Dispatch on id shape."""
    s = id_str.strip()
    if CVE_RE.match(s):
        return lookup_cve_nvd(s)
    if GHSA_RE.match(s):
        return lookup_ghsa(s, follow_cve=follow_cve)
    return {
        "id": s,
        "source": None,
        "cwes": [],
        "cves": [],
        "error": "id must look like CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx",
    }


def pick_cwe_for_registry(
    cwes: list[str],
    registry: dict[str, Any] | None = None,
) -> str | None:
    """Prefer a CWE already in the ontology registry; else first advisory CWE."""
    if not cwes:
        return None
    if registry:
        for cwe in cwes:
            if cwe in registry:
                return cwe
    return cwes[0]
