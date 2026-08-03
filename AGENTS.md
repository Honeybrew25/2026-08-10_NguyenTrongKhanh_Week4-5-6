# Repository guide

## Scope

This is one evolving project repository, not one source tree per week. Keep
current Python code in `src/`, tests in `tests/`, durable technical documents
in `docs/`, and weekly progress snapshots in `reports/`.

## Invariants

- Treat an existing `reports/week-N.md` as immutable. Create the next weekly
  report instead of rewriting project history.
- Keep each new weekly report short and separate `Quá trình` from `Kết quả`.
- Put curated machine inputs in `data/`, raw/derived scanner artifacts in
  `security-results/`, and verification logs in `evidence/`.
- Do not place generated JSON, CSV, HTML or log files in `docs/` or `reports/`.
- Keep secrets in the ignored `.env`; commit placeholders only in
  `.env.example`.
- Prefer topic-based names for new durable docs. The existing `docs/week1.md`
  and `docs/week2.md` paths remain for historical report links.

## Checks

Run these from the repository root after changing code or paths:

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pytest -q -m "not integration"
python -m security_pipeline search "SQL Injection" --limit 1
python -m security_pipeline analyze security-results/normalized-findings.json `
  --knowledge-base data/vulnerabilities.json --provider deterministic `
  --output "$env:TEMP\security-analysis-check.jsonl"
docker compose config --quiet
```

Use `python scripts/run_all_tests.py` when Docker integration coverage is
required. Do not add or split `DEBT.md` until there is an actionable technical
debt backlog that no longer fits normal issue tracking.
