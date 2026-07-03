#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KIMDIS (ΚΗΜΔΗΣ) harvester for TenderDesk — phase 1: tender notices.

Queries the official KIMDIS Open Data API (launched 2025) for cyber-relevant
tender notices (προκηρύξεις/διακηρύξεις/προσκλήσεις), filters them, writes a
JSON debug file AND (when SUPABASE_URL/SUPABASE_SERVICE_KEY are set) upserts
into the `tenders` table (on_conflict=ada, source='kimdis'). New open tenders
raise alerts via the trg_tender_alert DB trigger — nothing to do here.

Strategy per date window (<=170 days, API clamps at 180):
  1. POST /notice with STRICT cyber CPVs  -> auto-pass
  2. POST /notice with BROAD IT CPVs      -> pass only on keyword match (title)
  3. POST /notice with title=<keyword>    -> auto-pass (keyword by construction)
Dedup across passes by ΑΔΑΜ (referenceNumber).

Env: KIMDIS_LOOKBACK_DAYS (default 35), SUPABASE_URL, SUPABASE_SERVICE_KEY.
Only third-party dependency: requests. Reuses helpers from diavgeia_harvest.
"""

import json
import os
import re
import sys
import time
from datetime import date, datetime, timedelta, timezone

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from diavgeia_harvest import (  # noqa: E402
    REPO, strip_accents, matches_keywords, derive_category,
    load_config, save_json, sb_enabled, sb_upsert, load_client_map,
)

KIMDIS_BASE = "https://cerpp.eprocurement.gov.gr/khmdhs-opendata"
OUT_DIR = os.path.join(REPO, "kimdis")

# All CPV codes below validated live against the API (200 + non-null counts).
# NOTE: the `title` full-text filter is intentionally NOT used. It returns 404
# when called from GitHub's runner (Azure IP) while CPV-index queries succeed —
# the GSIS gateway filters the heavier search path from foreign/datacenter IPs.
# Run title-search enrichment from a Greek egress if fuller recall is needed.
#
# STRICT = unambiguously security -> no keyword gate needed.
CPV_STRICT = [
    "48730000-4",  # Security software package
    "48731000-1",  # Data security software
    "48732000-8",  # Data protection software
    "48761000-0",  # Anti-virus software
    "72212730-5",  # Security software development
    "72225000-8",  # System security evaluation & analysis
    "79417000-0",  # Safety/security consultancy
]
# BROAD = generic IT/network where cyber work often hides -> keyword-gated on the
# returned title (matches_keywords) before a record is kept.
CPV_BROAD = [
    "72611000-6",  # Technical computer support
    "72700000-7",  # Computer network services
    "72222300-0",  # IT services
    "32420000-3",  # Network equipment
]
# API accepts multiple CPVs per request (OR semantics). Bundling collapses many
# calls into a few, cutting 429 exposure and intermittent-404 risk.
CPV_BUNDLE_SIZE = 4

MAX_WINDOW_DAYS = 170          # API hard-clamps date ranges at 180 days
REQUEST_DELAY = 3.0            # polite pacing; observed rate limit is strict
MAX_PAGES = 40                 # 50/page -> 2000 records per query, plenty


# --------------------------------------------------------------------------- #
# API access with 429 backoff
# --------------------------------------------------------------------------- #
# The eprocurement platform sits behind an F5 BIG-IP load balancer that routes
# by the ROUTEID persistence cookie. A cookieless first request (as from a CI
# runner) can be misrouted to a pool that 404s the API path. We therefore use a
# persistent Session with a browser-like UA and PRIME it with a GET to the docs
# so the F5 issues ROUTEID/f5_cspm cookies, which the Session then reuses.
_SESSION = None
_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def _get_session(force_new=False):
    global _SESSION
    if _SESSION is not None and not force_new:
        return _SESSION
    s = requests.Session()
    s.headers.update({
        "User-Agent": _BROWSER_UA,
        "Accept": "application/json",
        "Accept-Language": "el-GR,el;q=0.9,en;q=0.8",
        "Origin": "https://cerpp.eprocurement.gov.gr",
        "Referer": f"{KIMDIS_BASE}/swagger-ui/index.html",
    })
    # Prime the F5 routing cookie with a harmless GET before any POST.
    try:
        s.get(f"{KIMDIS_BASE}/swagger-ui/index.html", timeout=60)
        s.get(f"{KIMDIS_BASE}/v3/api-docs", timeout=60)
        got = ",".join(sorted(s.cookies.keys())) or "(none)"
        print(f"[kimdis] session primed; cookies: {got}")
    except requests.RequestException as e:
        print(f"[kimdis] session prime failed ({e}); continuing without cookies")
    _SESSION = s
    return s


def kimdis_post(path, body, page=0, retries=5):
    url = f"{KIMDIS_BASE}{path}"
    backoff = 20
    for attempt in range(retries):
        s = _get_session()
        try:
            r = s.post(url, params={"page": page}, json=body,
                       headers={"Content-Type": "application/json"}, timeout=60)
        except requests.RequestException as e:
            print(f"[kimdis] network error ({e}); retry in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)
            continue
        if r.status_code == 429:
            print(f"[kimdis] 429 rate-limited; backing off {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)
            continue
        if r.status_code == 404 and attempt < retries - 1:
            # Likely F5 misroute on a stale/absent ROUTEID: rebuild the session
            # (fresh cookies) and retry rather than treating as a hard failure.
            print(f"[kimdis] 404 on {path} (attempt {attempt+1}); "
                  f"re-priming session and retrying")
            _get_session(force_new=True)
            time.sleep(5)
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError(f"KIMDIS request kept failing: {path} page={page}")


def iter_notices(body):
    """Yield all notices for a filter body, across pages."""
    page = 0
    while page < MAX_PAGES:
        data = kimdis_post("/notice", body, page=page)
        content = data.get("content") or []
        for item in content:
            yield item
        if data.get("last", True) or not content:
            return
        page += 1
        time.sleep(REQUEST_DELAY)


def date_windows(lookback_days):
    """Chunk [today-lookback, today] into <=MAX_WINDOW_DAYS windows."""
    end = date.today()
    start = end - timedelta(days=lookback_days)
    windows = []
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=MAX_WINDOW_DAYS), end)
        windows.append((cur.isoformat(), nxt.isoformat()))
        cur = nxt + timedelta(days=1)
    return windows or [(start.isoformat(), end.isoformat())]


# --------------------------------------------------------------------------- #
# normalisation
# --------------------------------------------------------------------------- #
def _kv(obj, default=None):
    """KIMDIS lookup objects are {'key': .., 'value': ..}."""
    if isinstance(obj, dict):
        return obj.get("value") or default
    return obj or default


def _date_part(v):
    if not v:
        return None
    return str(v)[:10]


def extract_cpvs(notice):
    """objectDetails structure varies; pull anything shaped like a CPV."""
    blob = json.dumps(notice.get("objectDetails") or [], ensure_ascii=False)
    found = re.findall(r"\d{8}-\d", blob)
    return sorted(set(found))


def normalize(n, provenance):
    ada = n.get("referenceNumber")
    cpvs = extract_cpvs(n)
    return {
        "ada": ada,
        "subject": (n.get("title") or "").strip(),
        "org": _kv(n.get("organization"), ""),
        "org_vat": n.get("organizationVatNumber") or n.get("greekOrganizationVatNumber"),
        "nuts": _kv(n.get("nutsCode")),
        "notice_type": _kv(n.get("noticeType")),
        "procedure_type": _kv(n.get("typeOfProcedure")),
        "issue_date": _date_part(n.get("signedDate") or n.get("submissionDate")),
        "deadline": _date_part(n.get("finalSubmissionDate")),
        "amount": n.get("totalCostWithoutVAT"),
        "cancelled": bool(n.get("cancelled")),
        "cpv": cpvs,
        "req_adams": [x.get("code") for x in (n.get("approvedRequests") or [])
                      if isinstance(x, dict) and x.get("code")],
        "url": f"{KIMDIS_BASE}/notice/attachment/{ada}" if ada else "",
        "provenance": provenance,
        "harvested_at": datetime.now(timezone.utc).isoformat(),
    }


def tender_row(rec, client_id):
    return {
        "ada": rec["ada"],
        "client_id": client_id,
        "org": rec["org"] or None,
        "subject": rec["subject"][:500],
        "decision_type": rec["notice_type"] or None,
        "category": derive_category(rec.get("matched", []), rec["subject"]),
        "matched": rec.get("matched") or None,
        "cpv": rec["cpv"] or None,
        "issue_date": rec["issue_date"],
        "amount": rec["amount"],
        "currency": "EUR" if rec["amount"] is not None else None,
        "url": rec["url"] or None,
        "status": "new",
        "source": "kimdis",
        "deadline": rec["deadline"],
        "procedure_type": rec["procedure_type"],
        "org_vat": rec["org_vat"],
        "nuts": rec["nuts"],
    }


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main():
    lookback = int(os.environ.get("KIMDIS_LOOKBACK_DAYS", "35"))
    cfg = load_config()
    kws = cfg["keywords"] + cfg.get("keywords_broad", [])

    seen, records = {}, []

    def take(n, provenance, require_keyword):
        ada = n.get("referenceNumber")
        if not ada or ada in seen:
            return
        if n.get("cancelled"):
            seen[ada] = "cancelled"
            return
        rec = normalize(n, provenance)
        hits = matches_keywords(rec["subject"], kws)
        if require_keyword and not hits:
            seen[ada] = "no-keyword"
            return
        rec["matched"] = hits
        seen[ada] = provenance
        records.append(rec)

    def _chunks(seq, size):
        for i in range(0, len(seq), size):
            yield seq[i:i + size]

    for w_from, w_to in date_windows(lookback):
        print(f"[kimdis] window {w_from} -> {w_to}")

        for bundle in _chunks(CPV_STRICT, CPV_BUNDLE_SIZE):
            print(f"[kimdis]  strict CPV bundle {bundle}")
            for n in iter_notices({"cpvItems": bundle,
                                   "dateFrom": w_from, "dateTo": w_to}):
                take(n, "cpv_strict", require_keyword=False)
            time.sleep(REQUEST_DELAY)

        for bundle in _chunks(CPV_BROAD, CPV_BUNDLE_SIZE):
            print(f"[kimdis]  broad CPV bundle {bundle} (keyword-gated)")
            for n in iter_notices({"cpvItems": bundle,
                                   "dateFrom": w_from, "dateTo": w_to}):
                take(n, "cpv_broad", require_keyword=True)
            time.sleep(REQUEST_DELAY)

    records.sort(key=lambda r: (r.get("deadline") or "9999",
                                r.get("issue_date") or ""), )
    print(f"[kimdis] {len(records)} relevant notice(s) "
          f"({sum(1 for r in records if r.get('deadline') and r['deadline'] >= date.today().isoformat())} with open deadline)")

    save_json(os.path.join(OUT_DIR, "notices.json"), {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lookback_days": lookback,
        "count": len(records),
        "records": records,
    })

    if sb_enabled() and records:
        _, by_nameel = load_client_map()
        rows = [tender_row(r, by_nameel.get(strip_accents(r["org"])))
                for r in records if r.get("ada")]
        n = sb_upsert("tenders", rows, on_conflict="ada")
        print(f"[supabase] upserted {n} tender(s) from KIMDIS.")
    elif not sb_enabled():
        print("[supabase] secrets not set - JSON debug output only.")


if __name__ == "__main__":
    main()
