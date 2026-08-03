"""
Push a regression benchmark report to the shared Google Sheet.

Writes the same flat table the team sheet already uses:

    task | link | precision | recall | f1
    ...one row per doc...
    OVERALL row, then an info row (model / n_docs / generated_at).

Google requires OAuth for ALL sheet writes (public "anyone with link" sharing
only covers reads), so a one-time setup is needed. Either auth path works;
they are tried in this order:

1) Apps Script Web App  (simplest — no GCP project, ~2 minutes)
   - Open the sheet -> Extensions -> Apps Script, paste:

        function doPost(e) {
          var p = JSON.parse(e.postData.contents);
          var sh = SpreadsheetApp.openById(p.spreadsheet_id)
                     .getSheets().filter(function(s){ return String(s.getSheetId()) === String(p.gid); })[0];
          sh.clearContents();
          sh.getRange(1, 1, p.values.length, p.values[0].length).setValues(p.values);
          return ContentService.createTextOutput(JSON.stringify({ok: true, rows: p.values.length}))
                               .setMimeType(ContentService.MimeType.JSON);
        }

   - Deploy -> New deployment -> Web app, "Execute as: Me",
     "Who has access: Anyone", copy the /exec URL.
   - export AISC_SHEET_WEBAPP_URL="https://script.google.com/macros/s/.../exec"

2) Service account  (Sheets API)
   - Create a GCP service account + JSON key, share the sheet with the
     service account's email as Editor.
   - export AISC_GSA_FILE=/path/to/key.json
     (GOOGLE_APPLICATION_CREDENTIALS is honored too.)

Usage:
    python -m extract_eval.regression.push_sheet report.json
    python -m extract_eval.regression.evaluate_regression --out report.json --sheet
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests

# The target sheet is private to whoever runs this, so it is configuration,
# not a constant: set AISC_SHEET_ID / AISC_SHEET_GID (or pass --sheet-id/--gid).
DEFAULT_SPREADSHEET_ID = os.environ.get("AISC_SHEET_ID", "")
DEFAULT_GID = os.environ.get("AISC_SHEET_GID", "0")

SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"


def _round(x):
    return "" if x is None else round(x, 4)


def build_rows(report: dict) -> list[list]:
    """Flatten a report into the sheet's task/link/precision/recall/f1 table."""
    rows = [["task", "link", "precision", "recall", "f1"]]
    for doc_id, d in report["per_doc"].items():
        m = d.get("metrics") or {}
        url = (d.get("meta") or {}).get("url", "")
        rows.append([doc_id, url, _round(m.get("precision")), _round(m.get("recall")),
                     _round(m.get("f1"))])
    o = report["overall"]
    rows.append(["OVERALL", "", _round(o["precision"]), _round(o["recall"]), _round(o["f1"])])
    cfg = report.get("config", {})
    rows.append([f"model={cfg.get('model')} n_docs={cfg.get('n_docs')} "
                 f"generated_at={cfg.get('generated_at')}", "", "", "", ""])
    return rows


# ── path 1: Apps Script web app ──────────────────────────────────────────────

def push_via_webapp(url: str, rows: list[list], spreadsheet_id: str, gid: str) -> str:
    resp = requests.post(url, json={"spreadsheet_id": spreadsheet_id, "gid": gid,
                                    "values": rows}, timeout=60)
    resp.raise_for_status()
    return f"webapp: {resp.text.strip()[:200]}"


# ── path 2: service account + Sheets API ────────────────────────────────────

def _sa_session(key_file: str):
    from google.oauth2 import service_account
    import google.auth.transport.requests as gtr

    creds = service_account.Credentials.from_service_account_file(
        key_file, scopes=[SHEETS_SCOPE])
    creds.refresh(gtr.Request())
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {creds.token}"
    return s


def _sheet_title_for_gid(session, spreadsheet_id: str, gid: str) -> str:
    r = session.get(f"{SHEETS_API}/{spreadsheet_id}", params={"fields": "sheets.properties"},
                    timeout=30)
    r.raise_for_status()
    for sh in r.json().get("sheets", []):
        p = sh["properties"]
        if str(p.get("sheetId")) == str(gid):
            return p["title"]
    raise KeyError(f"no sheet tab with gid={gid} in spreadsheet {spreadsheet_id}")


def push_via_service_account(key_file: str, rows: list[list],
                             spreadsheet_id: str, gid: str) -> str:
    session = _sa_session(key_file)
    title = _sheet_title_for_gid(session, spreadsheet_id, gid)
    session.post(f"{SHEETS_API}/{spreadsheet_id}/values/{title}!A1:Z1000:clear",
                 timeout=30).raise_for_status()
    r = session.put(f"{SHEETS_API}/{spreadsheet_id}/values/{title}!A1",
                    params={"valueInputOption": "USER_ENTERED"},
                    json={"values": rows}, timeout=60)
    r.raise_for_status()
    return f"service account: updated {r.json().get('updatedCells')} cells in '{title}'"


# ── entry points ─────────────────────────────────────────────────────────────

def push_report(report: dict, spreadsheet_id: str | None = None,
                gid: str | None = None) -> str:
    """Push a report dict to the sheet. Raises RuntimeError if no auth is configured."""
    spreadsheet_id = spreadsheet_id or os.environ.get("AISC_SHEET_ID", DEFAULT_SPREADSHEET_ID)
    gid = gid or os.environ.get("AISC_SHEET_GID", DEFAULT_GID)
    rows = build_rows(report)

    webapp = os.environ.get("AISC_SHEET_WEBAPP_URL")
    if webapp:
        return push_via_webapp(webapp, rows, spreadsheet_id, gid)

    key_file = os.environ.get("AISC_GSA_FILE") or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if key_file and os.path.exists(key_file):
        return push_via_service_account(key_file, rows, spreadsheet_id, gid)

    raise RuntimeError(
        "no sheet credentials: set AISC_SHEET_WEBAPP_URL (Apps Script web app) or "
        "AISC_GSA_FILE / GOOGLE_APPLICATION_CREDENTIALS (service-account key shared "
        "on the sheet). See extract_eval/regression/push_sheet.py docstring for setup.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Push a regression report to the Google Sheet.")
    ap.add_argument("report", help="report.json produced by evaluate_regression --out")
    ap.add_argument("--sheet-id", default=None, help="Spreadsheet id (default: team sheet)")
    ap.add_argument("--gid", default=None, help="Tab gid (default: results tab)")
    ap.add_argument("--dry-run", action="store_true", help="Print the rows, don't upload")
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as f:
        report = json.load(f)

    if args.dry_run:
        for row in build_rows(report):
            print(",".join(str(c) for c in row))
        return
    try:
        print(push_report(report, args.sheet_id, args.gid))
    except RuntimeError as e:
        print(f"upload skipped: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
