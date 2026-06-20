#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diavgeia harvester for TenderDesk.

Pulls public procurement decisions from the Diavgeia OpenData API, filters them
for cyber-security relevance, and writes results into JSON files that TenderDesk
can read. It NEVER writes into clients.json / proposals.json — harvested data is
kept in separate files so it can't collide with or overwrite live app data. A
human promotes a signal into an actual client from inside the app.

Dedup key is the ADA (Διαδικτυακή Ανάρτηση Απόφασης) — globally unique, so there
is no ID-collision problem here.

Modes
-----
  alerts    New tender NOTICES (διακηρύξεις/προκηρύξεις) for target orgs in the
            last `alerts_lookback_days`. Appends new hits to diavgeia/alerts.json
            and writes diavgeia/_new_today.md (used by the workflow to notify).
  harvest   AWARDS / contracts (αναθέσεις/συμβάσεις) for target orgs over
            `harvest_lookback_days`. Fetches full decisions for matches to pull
            CPV / amount / vendor, and writes diavgeia/signals.json — the
            "actively buying cyber" client-harvest list.
  discover  National keyword sweep (no org filter) to surface NEW organisations
            seeking cyber, beyond your current target list -> diavgeia/discover.json
  resolve   Resolve an org name to its organizationUid (helper).
  selftest  Hit the API once and dump the raw JSON shape of one decision, so you
            can confirm/adjust field names on first run.

Runs anywhere with open internet (e.g. a GitHub Actions runner). Only depends on
`requests`.
"""

import argparse
import json
import os
import re
import sys
import time
import unicodedata
from datetime import date, datetime, timedelta

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONFIG_PATH = os.path.join(REPO, "diavgeia", "config.json")
OUT_DIR = os.path.join(REPO, "diavgeia")

# Labels we use to auto-discover decision-type uids from /types, so we don't
# hardcode codes that may change. Matched case/accent-insensitively on label.
TENDER_NOTICE_LABELS = ["ΔΙΑΚΗΡΥΞ", "ΠΡΟΚΗΡΥΞ", "ΠΕΡΙΛΗΨΗ ΔΙΑΚΗΡΥΞ"]
AWARD_LABELS = ["ΑΝΑΘΕΣ", "ΚΑΤΑΚΥΡΩΣ", "ΣΥΜΒΑΣ"]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def strip_accents(s):
    if not s:
        return ""
    s = unicodedata.normalize("NFD", s)
    return "".join(c for c in s if unicodedata.category(c) != "Mn").lower()


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def api_get(base, path, params=None, retries=3):
    url = base.rstrip("/") + path
    headers = {"Accept": "application/json", "Connection": "keep-alive"}
    for attempt in range(retries):
        try:
            r = requests.get(url, params=params or {}, headers=headers, timeout=60)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 500, 502, 503):
                time.sleep(2 * (attempt + 1))
                continue
            r.raise_for_status()
        except requests.RequestException as e:
            if attempt == retries - 1:
                raise
            time.sleep(2 * (attempt + 1))
    return {}


# --------------------------------------------------------------------------- #
# organization resolution (accept numeric uid OR Greek name)
# --------------------------------------------------------------------------- #
_ORG_INDEX = None       # (orgs_list, {accent_stripped_label: uid})
UNRESOLVED = []         # target names we could not map to a uid


def _load_org_index(base):
    global _ORG_INDEX
    if _ORG_INDEX is not None:
        return _ORG_INDEX
    data = api_get(base, "/organizations", {"status": "all"})
    orgs = data.get("organizations") or []
    idx = {}
    for o in orgs:
        lab = strip_accents(o.get("label", ""))
        if lab:
            idx.setdefault(lab, o.get("uid"))
    _ORG_INDEX = (orgs, idx)
    return _ORG_INDEX


def resolve_org(base, org):
    """Return a Diavgeia organizationUid for `org`, which may be a numeric uid
    or a Greek name. Returns None (and records it) when it can't be resolved."""
    if org is None:
        return None
    s = str(org).strip()
    if s.isdigit():
        return s
    orgs, idx = _load_org_index(base)
    key = strip_accents(s)
    if key in idx:
        return idx[key]
    cands = [o.get("uid") for o in orgs if key and key in strip_accents(o.get("label", ""))]
    if len(cands) == 1:
        return cands[0]
    UNRESOLVED.append(s)
    return None


def flush_unresolved():
    if UNRESOLVED:
        save_json(os.path.join(OUT_DIR, "unresolved.json"), sorted(set(UNRESOLVED)))
        print(f"[resolve] {len(set(UNRESOLVED))} target(s) unresolved "
              f"-> diavgeia/unresolved.json")


# --------------------------------------------------------------------------- #
# decision-type resolution
# --------------------------------------------------------------------------- #
def resolve_type_uids(base):
    """Return {'notice': [uids...], 'award': [uids...]} discovered from /types."""
    data = api_get(base, "/types")
    types = data.get("decisionTypes") or data.get("types") or []
    notice, award = [], []
    for t in types:
        label = strip_accents(t.get("label", ""))
        uid = t.get("uid")
        if not uid:
            continue
        if any(strip_accents(p) in label for p in TENDER_NOTICE_LABELS):
            notice.append(uid)
        if any(strip_accents(p) in label for p in AWARD_LABELS):
            award.append(uid)
    return {"notice": notice, "award": award}


# --------------------------------------------------------------------------- #
# search
# --------------------------------------------------------------------------- #
def search_page(base, org=None, type_uid=None, from_date=None, to_date=None,
                page=0, size=100):
    params = {"status": "published", "sort": "recent", "page": page, "size": size}
    if org:
        params["org"] = org
    if type_uid:
        params["type"] = type_uid
    if from_date:
        params["from_date"] = from_date
    if to_date:
        params["to_date"] = to_date
    return api_get(base, "/search", params)


def iter_decisions(base, cfg, org=None, type_uid=None, from_date=None, to_date=None):
    size = cfg.get("page_size", 100)
    max_pages = cfg.get("max_pages_per_query", 20)
    delay = cfg.get("request_delay_seconds", 0.3)
    for page in range(max_pages):
        data = search_page(base, org=org, type_uid=type_uid,
                            from_date=from_date, to_date=to_date,
                            page=page, size=size)
        decisions = data.get("decisions") or data.get("docs") or []
        if not decisions:
            break
        for d in decisions:
            yield d
        if len(decisions) < size:
            break
        time.sleep(delay)


# --------------------------------------------------------------------------- #
# matching + normalisation
# --------------------------------------------------------------------------- #
def subject_of(d):
    return d.get("subject") or d.get("title") or d.get("decisionSubject") or ""


def ada_of(d):
    return d.get("ada") or d.get("ADA") or d.get("id") or ""


_WORD_RE = re.compile(r'\w+', re.UNICODE)


def _tokens(text):
    return _WORD_RE.findall(strip_accents(text))


def _stem(token):
    # Trim ~2 trailing inflectional chars (Greek ος/ας/ων/ου/ες/η), keep >=4.
    return token[: max(4, len(token) - 2)]


def matches_keywords(text, keywords):
    """Token/stem-aware match that survives Greek inflection.

    A keyword matches when EVERY one of its tokens has a stem that is a prefix
    of some token in the text. Multi-word keywords therefore require all parts
    present (in any order), so 'τείχος προστασίας' matches 'τείχους προστασίας'
    but plain 'πυροπροστασία' does not.
    """
    text_tokens = _tokens(text)
    hits = []
    for kw in keywords:
        parts = _tokens(kw)
        if parts and all(
            any(tt.startswith(_stem(p)) for tt in text_tokens) for p in parts
        ):
            hits.append(kw)
    return hits


def extract_extra_fields(full_decision):
    """Defensively pull CPV / amount / vendor from a full decision's extra fields.
    Field shapes vary by decision type, so we scan generously."""
    ef = (full_decision.get("extraFieldValues")
          or full_decision.get("extraFields")
          or {})
    flat = json.dumps(ef, ensure_ascii=False)

    cpv = re.findall(r'\b(\d{8})(?:-\d)?\b', flat)
    amounts = re.findall(r'(\d[\d.\s]*[,]\d{2})\s*(?:€|ευρ)', flat)
    vendor = ""
    for key in ("awardedToName", "contractorName", "supplier", "ανάδοχος",
                "name", "fullName"):
        if isinstance(ef, dict) and ef.get(key):
            vendor = ef.get(key)
            break

    return {
        "cpv": sorted(set(cpv)),
        "amount": amounts[0] if amounts else "",
        "vendor": vendor,
    }


def normalize(d, target=None, full=None):
    ada = ada_of(d)
    rec = {
        "ada": ada,
        "subject": subject_of(d),
        "org": d.get("organizationId") or d.get("organizationUid")
               or (target or {}).get("name", ""),
        "type": d.get("decisionTypeId") or d.get("decisionType") or "",
        "issue_date": d.get("issueDate") or d.get("submissionTimestamp") or "",
        "url": "https://diavgeia.gov.gr/doc/" + ada if ada else "",
        "tier": (target or {}).get("tier", ""),
        "harvested_at": datetime.utcnow().isoformat() + "Z",
    }
    if full is not None:
        rec.update(extract_extra_fields(full))
    return rec


def cpv_passes(rec, cfg):
    if not cfg.get("cpv_gate_enabled"):
        return True
    prefixes = cfg.get("cpv_prefixes", [])
    return any(c.startswith(p[:8]) for c in rec.get("cpv", []) for p in prefixes)


# --------------------------------------------------------------------------- #
# modes
# --------------------------------------------------------------------------- #
def mode_alerts(base, cfg):
    kws = cfg["keywords"]
    types = resolve_type_uids(base)["notice"] or [None]
    frm = (date.today() - timedelta(days=cfg["alerts_lookback_days"])).isoformat()
    out_path = os.path.join(OUT_DIR, "alerts.json")
    existing = load_json(out_path, [])
    seen = {r["ada"] for r in existing}
    new = []

    for target in cfg["targets"]:
        org_uid = resolve_org(base, target["org"])
        if not org_uid:
            continue
        for type_uid in types:
            for d in iter_decisions(base, cfg, org=org_uid,
                                    type_uid=type_uid, from_date=frm):
                ada = ada_of(d)
                if not ada or ada in seen:
                    continue
                hits = matches_keywords(subject_of(d), kws)
                if not hits:
                    continue
                rec = normalize(d, target)
                rec["matched"] = hits
                seen.add(ada)
                new.append(rec)

    if new:
        save_json(out_path, new + existing)
        write_notify_markdown(new)
    else:
        write_notify_markdown([])
    flush_unresolved()
    print(f"[alerts] {len(new)} new tender notice(s).")
    return new


def mode_harvest(base, cfg):
    kws = cfg["keywords"] + cfg.get("keywords_broad", [])
    types = resolve_type_uids(base)["award"] or [None]
    frm = (date.today() - timedelta(days=cfg["harvest_lookback_days"])).isoformat()
    out_path = os.path.join(OUT_DIR, "signals.json")
    existing = load_json(out_path, [])
    by_ada = {r["ada"]: r for r in existing}
    delay = cfg.get("request_delay_seconds", 0.3)
    added = 0

    for target in cfg["targets"]:
        org_uid = resolve_org(base, target["org"])
        if not org_uid:
            continue
        for type_uid in types:
            for d in iter_decisions(base, cfg, org=org_uid,
                                    type_uid=type_uid, from_date=frm):
                ada = ada_of(d)
                if not ada or ada in by_ada:
                    continue
                hits = matches_keywords(subject_of(d), kws)
                if not hits:
                    continue
                full = api_get(base, f"/decisions/{ada}/")
                time.sleep(delay)
                rec = normalize(d, target, full=full.get("decision", full))
                if not cpv_passes(rec, cfg):
                    continue
                rec["matched"] = hits
                by_ada[ada] = rec
                added += 1

    save_json(out_path, list(by_ada.values()))
    flush_unresolved()
    print(f"[harvest] {added} new cyber award signal(s); total {len(by_ada)}.")
    return added


def mode_discover(base, cfg):
    """National keyword sweep (no org filter) over the alert window."""
    kws = cfg["keywords"]
    types = resolve_type_uids(base)["notice"] or [None]
    frm = (date.today() - timedelta(days=cfg["alerts_lookback_days"])).isoformat()
    out_path = os.path.join(OUT_DIR, "discover.json")
    existing = load_json(out_path, [])
    seen = {r["ada"] for r in existing}
    known_orgs = {t["org"] for t in cfg["targets"]}
    new = []

    for type_uid in types:
        for d in iter_decisions(base, cfg, type_uid=type_uid, from_date=frm):
            ada = ada_of(d)
            if not ada or ada in seen:
                continue
            hits = matches_keywords(subject_of(d), kws)
            if not hits:
                continue
            rec = normalize(d, {"tier": "discovered"})
            rec["matched"] = hits
            rec["already_target"] = str(d.get("organizationId")) in known_orgs
            seen.add(ada)
            new.append(rec)

    if new:
        save_json(out_path, new + existing)
    print(f"[discover] {len(new)} new cyber-related decision(s) nationwide.")
    return new


def mode_resolve(base, name):
    data = api_get(base, "/organizations", {"status": "all"})
    orgs = data.get("organizations") or []
    needle = strip_accents(name)
    hits = [o for o in orgs if needle in strip_accents(o.get("label", ""))]
    for o in hits[:25]:
        print(f"{o.get('uid'):>12}  {o.get('label')}")
    if not hits:
        print("No match. Try a shorter / differently-spelled fragment.")


def mode_selftest(base, cfg):
    print("api_base:", base)
    types = resolve_type_uids(base)
    print("notice type uids:", types["notice"][:10])
    print("award  type uids:", types["award"][:10])
    target = cfg["targets"][0]
    print("probing org:", target)
    sample = None
    for d in iter_decisions(base, cfg, org=target["org"],
                            from_date=(date.today() - timedelta(days=30)).isoformat()):
        sample = d
        break
    if not sample:
        print("No decisions returned in the last 30 days for this org.")
        return
    print("\n--- raw decision keys ---")
    print(list(sample.keys()))
    print("\n--- raw decision (truncated) ---")
    print(json.dumps(sample, ensure_ascii=False, indent=2)[:2500])
    ada = ada_of(sample)
    if ada:
        full = api_get(base, f"/decisions/{ada}/")
        print("\n--- full decision extra-field block (truncated) ---")
        block = full.get("decision", full)
        ef = block.get("extraFieldValues") or block.get("extraFields") or {}
        print(json.dumps(ef, ensure_ascii=False, indent=2)[:2000])


# --------------------------------------------------------------------------- #
# notification markdown (consumed by the workflow)
# --------------------------------------------------------------------------- #
def write_notify_markdown(new_records):
    path = os.path.join(OUT_DIR, "_new_today.md")
    if not new_records:
        save_text(path, "")  # empty => workflow skips the notification
        return
    lines = [f"### {len(new_records)} new Diavgeia tender(s) of interest "
             f"— {date.today().isoformat()}\n"]
    for r in new_records:
        kw = ", ".join(r.get("matched", []))
        lines.append(f"- **{r['org']}** — {r['subject']}")
        lines.append(f"  - matched: _{kw}_ · [{r['ada']}]({r['url']})")
    save_text(path, "\n".join(lines) + "\n")


def save_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    choices=["alerts", "harvest", "discover", "resolve", "selftest"])
    ap.add_argument("--name", help="org name fragment (for --mode resolve)")
    args = ap.parse_args()

    cfg = load_config()
    base = cfg["api_base"]

    if args.mode == "alerts":
        mode_alerts(base, cfg)
    elif args.mode == "harvest":
        mode_harvest(base, cfg)
    elif args.mode == "discover":
        mode_discover(base, cfg)
    elif args.mode == "resolve":
        if not args.name:
            sys.exit("--name is required for resolve")
        mode_resolve(base, args.name)
    elif args.mode == "selftest":
        mode_selftest(base, cfg)


if __name__ == "__main__":
    main()
