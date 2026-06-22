#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diavgeia harvester for TenderDesk.

Queries the Diavgeia OpenData API, filters for cyber-security relevance, writes
JSON debug files AND (when SUPABASE_URL/SUPABASE_SERVICE_KEY are set) upserts the
results straight into Supabase: award/contract signals -> `assets`, new tender
notices -> `tenders`. Dedup key is the ADA.

Modes: alerts | harvest | discover | resolve | selftest
Only third-party dependency: requests.
"""

import argparse
import json
import os
import re
import sys
import time
import unicodedata
from datetime import date, datetime, timedelta, timezone

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONFIG_PATH = os.path.join(REPO, "diavgeia", "config.json")
OUT_DIR = os.path.join(REPO, "diavgeia")

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


def save_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def iso_date(v):
    """Normalise an issueDate (epoch-ms int or ISO string) to YYYY-MM-DD."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(v / 1000, timezone.utc).date().isoformat()
        except Exception:
            return None
    s = str(v)
    return s[:10] if len(s) >= 10 else None


def add_months(iso, months):
    if not iso or not months:
        return None
    try:
        y, m, d = (int(x) for x in iso[:10].split("-"))
    except Exception:
        return None
    m0 = (m - 1) + int(months)
    y += m0 // 12
    m = m0 % 12 + 1
    for dd in (d, 28, 29, 30, 31):
        try:
            return date(y, m, min(dd, d)).isoformat()
        except ValueError:
            continue
    return date(y, m, 28).isoformat()


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
        except requests.RequestException:
            if attempt == retries - 1:
                raise
            time.sleep(2 * (attempt + 1))
    return {}


# --------------------------------------------------------------------------- #
# organization resolution (numeric uid OR Greek name)
# --------------------------------------------------------------------------- #
_ORG_INDEX = None
UNRESOLVED = []


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


_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _tokens(text):
    return _WORD_RE.findall(strip_accents(text))


def _stem(token):
    return token[: max(4, len(token) - 2)]


def matches_keywords(text, keywords):
    text_tokens = _tokens(text)
    hits = []
    for kw in keywords:
        parts = _tokens(kw)
        if parts and all(
            any(tt.startswith(_stem(p)) for tt in text_tokens) for p in parts
        ):
            hits.append(kw)
    return hits


# matched-keyword -> clean asset category
CATEGORY_MAP = [
    (("firewall", "τειχος προστασιας", "ngfw"), "Firewall"),
    (("siem",), "SIEM"),
    (("edr", "xdr", "endpoint"), "Endpoint/EDR"),
    (("antivirus", "anti-virus", "κακοβουλο λογισμικο"), "Antivirus"),
    (("backup", "αντιγραφα ασφαλειας", "disaster recovery", "ανακαμψη"), "Backup/DR"),
    (("vpn",), "VPN"),
    (("waf",), "WAF"),
    (("ddos",), "DDoS"),
    (("penetration", "διεισδυσης", "τρωτοτητας", "αξιολογηση ευπαθειων"), "VA/Pen-test"),
    (("iso 27001", "συστημα διαχειρισης ασφαλειας", "σδαπ"), "ISMS/ISO27001"),
    (("nis2", "nis 2"), "NIS2"),
    (("gdpr", "dpo", "προστασια δεδομενων", "υπευθυνος προστασιας"), "Data protection"),
    (("κυβερνοασφ", "ασφαλεια πληροφ", "cyber"), "Cybersecurity (general)"),
]


def derive_category(matched, subject=""):
    hay = strip_accents(" ".join(matched) + " " + subject)
    for needles, label in CATEGORY_MAP:
        if any(strip_accents(n) in hay for n in needles):
            return label
    return "Cybersecurity (general)"


# Greek number words -> int (for duration parsing)
_GR_NUM = {
    "ενα": 1, "ενος": 1, "μια": 1, "μιας": 1, "δυο": 2, "τρια": 3, "τριων": 3,
    "τεσσερα": 4, "τεσσαρων": 4, "πεντε": 5, "εξι": 6, "επτα": 7, "εφτα": 7,
    "οκτω": 8, "οχτω": 8, "εννεα": 9, "εννια": 9, "δεκα": 10, "δωδεκα": 12,
    "εικοσι": 20, "εικοσιτεσσερα": 24, "τριαντα": 30, "τριανταεξι": 36,
    "σαραντα": 40, "σαρανταοκτω": 48, "εξηντα": 60,
}


def _to_int(tok):
    tok = strip_accents(tok)
    if tok.isdigit():
        return int(tok)
    return _GR_NUM.get(tok)


# compound duration adjectives (stems), value in months
_DUR_ADJ = [("δωδεκαμην", 12), ("δεκαμην", 10), ("εννεαμην", 9), ("οκταμην", 8),
            ("επταμην", 7), ("εξαμην", 6), ("πενταμην", 5), ("τετραμην", 4),
            ("τριμην", 3), ("διμην", 2),
            ("πενταετ", 60), ("τετραετ", 48), ("τριετ", 36), ("διετ", 24),
            ("ετησι", 12)]


def _cap(m):
    return m if (m and m <= 120) else None


def parse_duration_months(text, ef=None):
    """Return (months|None, source). Prefer the structured `duration` field
    (ΣΥΜΒΑΣΗ type), else parse Greek duration phrases from the text."""
    if isinstance(ef, dict):
        dv = ef.get("duration")
        if isinstance(dv, dict):
            m = dv.get("months") or dv.get("value")
            if m:
                try:
                    return _cap(int(m)), "field"
                except Exception:
                    pass
        elif isinstance(dv, (int, float)) and dv:
            return _cap(int(dv)), "field"
    t = strip_accents(text or "")
    # compound adjectives: τριετης, δωδεκαμηνη, εξαμηνη, ετησια ...
    for stem, mo in _DUR_ADJ:
        if stem in t:
            return _cap(mo), "parsed"
    # digit (possibly in parens) immediately before a μην/ετ token
    m = re.search(r"(\d{1,3})[\s)\-–.]{0,4}μην", t)
    if m:
        return _cap(int(m.group(1))), "parsed"
    m = re.search(r"(\d{1,2})[\s)\-–.]{0,4}(?:ετ|χρον)", t)
    if m:
        return _cap(int(m.group(1)) * 12), "parsed"
    # spelled-out number, optionally followed by a (digit), before the unit
    m = re.search(r"([α-ω]+)\s*\(?\d{0,3}\)?\s*μην", t)
    if m and _to_int(m.group(1)):
        return _cap(_to_int(m.group(1))), "parsed"
    m = re.search(r"([α-ω]+)\s*\(?\d{0,2}\)?\s*(?:ετ|χρον)", t)
    if m and _to_int(m.group(1)):
        return _cap(_to_int(m.group(1)) * 12), "parsed"
    return None, ""


def extract_extra_fields(full_decision):
    """Pull vendor / amount / cpv / duration from a full decision.
    Handles both award shapes: person[]+awardAmount and sponsor[]+expenseAmount."""
    ef = (full_decision.get("extraFieldValues")
          or full_decision.get("extraFields") or {})
    if not isinstance(ef, dict):
        ef = {}
    vendor = vendor_afm = amount = currency = ""

    persons = ef.get("person") or []
    if isinstance(persons, list) and persons and isinstance(persons[0], dict):
        vendor = persons[0].get("name", "") or ""
        vendor_afm = persons[0].get("afm", "") or ""
    aa = ef.get("awardAmount") or ef.get("contractAmount") or {}
    if isinstance(aa, dict) and aa:
        amount = aa.get("amount", "")
        currency = aa.get("currency", "") or currency
    if not vendor:
        for sp in (ef.get("sponsor") or []):
            sn = sp.get("sponsorAFMName") or {}
            if sn.get("name"):
                vendor = sn.get("name", "")
                vendor_afm = sn.get("afm", "")
                ea = sp.get("expenseAmount") or {}
                amount = ea.get("amount", amount)
                currency = ea.get("currency", currency)
                break

    cpv = ef.get("cpv") or []
    if isinstance(cpv, str):
        cpv = [cpv]
    cpv = [str(c).split("-")[0] for c in cpv if c]
    if not cpv:
        cpv = sorted(set(re.findall(r"\b(\d{8})(?:-\d)?\b",
                                    json.dumps(ef, ensure_ascii=False))))

    org = ef.get("org") or {}
    months, dsrc = parse_duration_months(subject_of(full_decision), ef)
    return {
        "cpv": cpv,
        "amount": amount if amount not in (None, "") else "",
        "currency": currency or "EUR",
        "vendor": vendor,
        "vendor_afm": vendor_afm,
        "assignment_type": ef.get("assignmentType", ""),
        "buyer": (org or {}).get("name", "") if isinstance(org, dict) else "",
        "buyer_afm": (org or {}).get("afm", "") if isinstance(org, dict) else "",
        "duration_months": months,
        "duration_source": dsrc,
    }


def normalize(d, target=None, full=None):
    ada = ada_of(d)
    rec = {
        "ada": ada,
        "subject": subject_of(d),
        "org": d.get("organizationId") or d.get("organizationUid")
               or (target or {}).get("org", ""),
        "type": d.get("decisionTypeId") or d.get("decisionType") or "",
        "issue_date": iso_date(d.get("issueDate") or d.get("submissionTimestamp")),
        "url": "https://diavgeia.gov.gr/doc/" + ada if ada else "",
        "tier": (target or {}).get("tier", ""),
        "legacy_id": (target or {}).get("legacy_id", ""),
        "harvested_at": datetime.now(timezone.utc).isoformat(),
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
# Supabase upsert (assets + tenders)
# --------------------------------------------------------------------------- #
SB_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SB_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")


def sb_enabled():
    return bool(SB_URL and SB_KEY)


def _sb_headers(extra=None):
    h = {"apikey": SB_KEY, "Authorization": "Bearer " + SB_KEY,
         "Content-Type": "application/json"}
    if extra:
        h.update(extra)
    return h


def sb_get(path, params=None):
    r = requests.get(SB_URL + "/rest/v1/" + path, headers=_sb_headers(),
                     params=params or {}, timeout=60)
    r.raise_for_status()
    return r.json()


def sb_upsert(table, rows, on_conflict):
    if not rows:
        return 0
    done = 0
    for i in range(0, len(rows), 500):
        chunk = rows[i:i + 500]
        r = requests.post(
            SB_URL + "/rest/v1/" + table,
            headers=_sb_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}),
            params={"on_conflict": on_conflict},
            data=json.dumps(chunk, ensure_ascii=False).encode("utf-8"),
            timeout=120)
        if r.status_code >= 300:
            print(f"[supabase] upsert {table} failed {r.status_code}: {r.text[:300]}")
            r.raise_for_status()
        done += len(chunk)
    return done


def load_client_map():
    by_legacy, by_nameel = {}, {}
    rows = sb_get("clients", {"select": "id,legacy_id,name_el"})
    for c in rows:
        if c.get("legacy_id"):
            by_legacy[c["legacy_id"]] = c["id"]
        if c.get("name_el"):
            by_nameel[strip_accents(c["name_el"])] = c["id"]
    return by_legacy, by_nameel


def load_targets(cfg):
    """Harvest/alert targets: pulled live from the Supabase clients table
    (name_el) when configured, else the small fallback list in config.json."""
    if sb_enabled():
        try:
            rows = sb_get("clients", {"select": "legacy_id,name_el",
                                      "name_el": "not.is.null"})
            t = [{"org": r["name_el"], "legacy_id": r["legacy_id"], "tier": "client"}
                 for r in rows if r.get("name_el")]
            if t:
                print(f"[targets] {len(t)} loaded from Supabase clients.")
                return t
        except Exception as e:
            print(f"[targets] Supabase load failed ({e}); using config targets.")
    return cfg.get("targets", [])


def asset_row(rec, client_id):
    award_date = rec.get("issue_date")
    months = rec.get("duration_months")
    dsrc = rec.get("duration_source") or ""
    renewal = add_months(award_date, months) if (award_date and months) else None
    notes_bits = []
    if rec.get("amount"):
        notes_bits.append(f"{rec['amount']} {rec.get('currency','')}".strip())
    if rec.get("assignment_type"):
        notes_bits.append(rec["assignment_type"])
    if rec.get("cpv"):
        notes_bits.append("CPV " + ",".join(rec["cpv"][:3]))
    return {
        "client_id": client_id,
        "category": derive_category(rec.get("matched", []), rec.get("subject", "")),
        "vendor": rec.get("vendor") or None,
        "vendor_afm": rec.get("vendor_afm") or None,
        "product": (rec.get("subject") or "")[:500],
        "source": rec.get("url") or None,
        "source_ada": rec.get("ada") or None,
        "amount": rec.get("amount") or None,
        "currency": rec.get("currency") or None,
        "award_date": award_date,
        "duration_months": months,
        "duration_source": dsrc or None,
        "renewal_date": renewal,
        "cpv": rec.get("cpv") or None,
        "status": "harvested",
        "notes": " · ".join(notes_bits) or None,
    }


def tender_row(rec, client_id):
    return {
        "ada": rec.get("ada"),
        "client_id": client_id,
        "org": rec.get("org") or None,
        "subject": (rec.get("subject") or "")[:500],
        "decision_type": rec.get("type") or None,
        "category": derive_category(rec.get("matched", []), rec.get("subject", "")),
        "matched": rec.get("matched") or None,
        "cpv": rec.get("cpv") or None,
        "issue_date": rec.get("issue_date"),
        "amount": rec.get("amount") or None,
        "currency": rec.get("currency") or None,
        "url": rec.get("url") or None,
        "status": "new",
    }


def push_assets(records, by_legacy=None):
    if not sb_enabled() or not records:
        return
    if by_legacy is None:
        by_legacy, _ = load_client_map()
    rows = [asset_row(r, by_legacy.get(r.get("legacy_id", "")))
            for r in records if r.get("ada")]
    n = sb_upsert("assets", rows, on_conflict="source_ada")
    print(f"[supabase] upserted {n} asset(s).")


def push_tenders(records):
    if not sb_enabled() or not records:
        return
    by_legacy, by_nameel = load_client_map()
    rows = []
    for r in records:
        if not r.get("ada"):
            continue
        cid = by_legacy.get(r.get("legacy_id", "")) \
            or by_nameel.get(strip_accents(r.get("org", "")))
        rows.append(tender_row(r, cid))
    n = sb_upsert("tenders", rows, on_conflict="ada")
    print(f"[supabase] upserted {n} tender(s).")


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
    targets = load_targets(cfg)
    new = []

    for target in targets:
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
    push_tenders(new)
    print(f"[alerts] {len(new)} new tender notice(s).")
    return new


def mode_harvest(base, cfg):
    kws = cfg["keywords"] + cfg.get("keywords_broad", [])
    types = resolve_type_uids(base)["award"] or [None]
    lookback = int(os.environ.get("HARVEST_LOOKBACK_DAYS") or cfg["harvest_lookback_days"])
    frm = (date.today() - timedelta(days=lookback)).isoformat()
    out_path = os.path.join(OUT_DIR, "signals.json")
    existing = load_json(out_path, [])
    by_ada = {r["ada"]: r for r in existing}
    delay = cfg.get("request_delay_seconds", 0.3)
    client_map = load_client_map()[0] if sb_enabled() else {}
    targets = load_targets(cfg)
    total_new = 0

    for target in targets:
        org_uid = resolve_org(base, target["org"])
        if not org_uid:
            continue
        org_fresh = []
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
                org_fresh.append(rec)
        if org_fresh:
            save_json(out_path, list(by_ada.values()))   # persist progress
            push_assets(org_fresh, client_map)            # incremental upsert
            total_new += len(org_fresh)

    save_json(out_path, list(by_ada.values()))
    flush_unresolved()
    print(f"[harvest] {total_new} new cyber award signal(s); total {len(by_ada)}.")
    return total_new


def mode_discover(base, cfg):
    """National keyword sweep (no org filter) over the alert window."""
    kws = cfg["keywords"]
    types = resolve_type_uids(base)["notice"] or [None]
    frm = (date.today() - timedelta(days=cfg["alerts_lookback_days"])).isoformat()
    out_path = os.path.join(OUT_DIR, "discover.json")
    existing = load_json(out_path, [])
    seen = {r["ada"] for r in existing}
    known_orgs = {t["org"] for t in load_targets(cfg)}
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
    push_tenders(new)
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
    print("api_base:", base, "| supabase:", "on" if sb_enabled() else "off")
    types = resolve_type_uids(base)
    print("notice type uids:", types["notice"][:10])
    print("award  type uids:", types["award"][:10])
    target = load_targets(cfg)[0]
    print("probing org:", target)
    sample = None
    for d in iter_decisions(base, cfg, org=resolve_org(base, target["org"]),
                            from_date=(date.today() - timedelta(days=30)).isoformat()):
        sample = d
        break
    if not sample:
        print("No decisions returned in the last 30 days for this org.")
        return
    ada = ada_of(sample)
    full = api_get(base, f"/decisions/{ada}/")
    print("\n--- extracted ---")
    print(json.dumps(extract_extra_fields(full.get("decision", full)),
                     ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------- #
# notification markdown (consumed by the workflow / future email step)
# --------------------------------------------------------------------------- #
def write_notify_markdown(new_records):
    path = os.path.join(OUT_DIR, "_new_today.md")
    if not new_records:
        save_text(path, "")
        return
    lines = [f"### {len(new_records)} new Diavgeia tender(s) of interest "
             f"— {date.today().isoformat()}\n"]
    for r in new_records:
        kw = ", ".join(r.get("matched", []))
        lines.append(f"- **{r['org']}** — {r['subject']}")
        lines.append(f"  - matched: _{kw}_ · [{r['ada']}]({r['url']})")
    save_text(path, "\n".join(lines) + "\n")


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
