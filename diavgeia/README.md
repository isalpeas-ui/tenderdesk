# Diavgeia harvester

Daily pull of public procurement decisions from the Diavgeia OpenData API,
filtered for cyber-security relevance, written into JSON that TenderDesk reads.

## What it produces (all in `diavgeia/`)
- `alerts.json` — new tender **notices** (διακηρύξεις/προκηρύξεις) from your target
  orgs that match the cyber keywords. Each entry keyed by ΑΔΑ.
- `signals.json` — **awards/contracts** (αναθέσεις/συμβάσεις) that match cyber
  keywords, with CPV / amount / vendor pulled from the full decision. This is the
  "actively buying cyber" client-harvest list.
- `discover.json` — nationwide keyword sweep: orgs *outside* your target list that
  just published something cyber-related (prospect discovery).
- `_new_today.md` — the day's new notices, used by the workflow to open an issue.

It never touches `clients.json` / `proposals.json`, so it can't collide with or
overwrite live app data. Promote a signal to a real client from inside the app.

## Setup (3 steps)
1. **Drop the files in the repo** at these paths:
   `scripts/diavgeia_harvest.py`, `diavgeia/config.json`,
   `.github/workflows/diavgeia-daily.yml`.
2. **Fill `config.json` → `targets`** with the municipalities you've opened plus any
   org you want to watch. Each needs a Diavgeia `org` id. To find one:
   ```
   python scripts/diavgeia_harvest.py --mode resolve --name "ΔΗΜΟΣ ΧΑΛΑΝΔΡΙΟΥ"
   ```
3. **Confirm the API field shapes once** (the API response keys vary slightly by
   decision type — selftest dumps the raw JSON so you can adjust if needed):
   ```
   pip install requests
   python scripts/diavgeia_harvest.py --mode selftest
   ```
   This must be run somewhere with open internet (your laptop or the Action) — the
   Claude sandbox can't reach diavgeia.gov.gr.

## How it runs
The workflow runs daily at 04:00 UTC (~07:00 Athens): alerts + discovery every day,
the heavier award harvest on Mondays (or on-demand via "Run workflow"). It commits
updated JSON with the Action's built-in `GITHUB_TOKEN` — no personal token needed —
and opens an issue when new tenders match.

Optional: create a `diavgeia` issue label so alert issues are filterable.

## Notes
- Dedup is by ΑΔΑ (globally unique) — no ID-collision concerns.
- Keyword matching is accent/case-insensitive and stem-aware, so Greek inflection
  (e.g. «τείχ**ους** προστασίας») still matches «τείχος προστασίας».
- When you migrate to Supabase, point the three writers at tables instead of files;
  the filtering logic stays identical.
