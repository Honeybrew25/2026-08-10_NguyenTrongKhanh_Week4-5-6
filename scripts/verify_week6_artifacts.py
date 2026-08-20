from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
UNSAFE_PATTERNS = {
    "email": re.compile(
        r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])",
        re.I,
    ),
    "phone": re.compile(r"(?<!\w)(?:\+?84|0)(?:[ .-]?\d){9,10}(?!\w)"),
    "bearer": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.I),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "raw_fixture": re.compile(
        r"eval\.person@example\.test|fixture-(?:token|api-key|password)-value|PID: EVAL123456"
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _schema(name: str) -> dict[str, object]:
    value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def _validate_json(path: Path, schema_name: str) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator(_schema(schema_name)).validate(document)
    return document


def _validate_jsonl(path: Path, schema_name: str) -> list[dict[str, object]]:
    validator = Draft202012Validator(_schema(schema_name))
    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for record in records:
        validator.validate(record)
    return records


def _verify_manifest(run_directory: Path, manifest: dict[str, object]) -> None:
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise RuntimeError("manifest_files_invalid")
    for relative, expected in files.items():
        path = run_directory / str(relative)
        if not path.is_file() or _sha256(path) != expected:
            raise RuntimeError("manifest_hash_mismatch")


def _sentinel(paths: list[Path]) -> None:
    combined = ""
    for path in paths:
        if path.suffix in {".json", ".jsonl", ".log", ".txt"}:
            combined += path.read_text(encoding="utf-8", errors="replace")
    matches = [name for name, pattern in UNSAFE_PATTERNS.items() if pattern.search(combined)]
    if matches:
        raise RuntimeError("secret_pii_sentinel_failed:" + ",".join(matches))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate sanitized Week 6 release artifacts.")
    parser.add_argument("--run-directory", required=True, type=Path)
    parser.add_argument("--evaluation-directory", required=True, type=Path)
    parser.add_argument("--verification-log", required=True, type=Path)
    arguments = parser.parse_args()
    run_directory = arguments.run_directory.resolve()
    evaluation_directory = arguments.evaluation_directory.resolve()

    final = _validate_json(
        run_directory / "final-report.json", "project-sentinel-final-report.schema.json"
    )
    events = _validate_jsonl(
        run_directory / "pipeline-events.jsonl", "project-sentinel-event.schema.json"
    )
    evaluation = _validate_json(
        evaluation_directory / "evaluation-summary.json",
        "project-sentinel-evaluation.schema.json",
    )
    manifest = json.loads((run_directory / "manifest.json").read_text(encoding="utf-8"))
    _verify_manifest(run_directory, manifest)

    run_id = final["run_id"]
    if any(event.get("run_id") != run_id for event in events):
        raise RuntimeError("event_run_id_mismatch")
    if final.get("status") not in {"dry_run", "completed", "completed_no_findings"}:
        raise RuntimeError("release_run_not_successful")
    if final.get("metrics", {}).get("requests_sent") != 0:
        raise RuntimeError("ci_dry_run_sent_network_request")
    if not (
        evaluation.get("case_count") == 10
        and evaluation.get("failed") == 0
        and evaluation.get("schema_valid_rate") == 1.0
        and evaluation.get("source_coverage_rate") == 1.0
        and evaluation.get("hallucination_count") == 0
        and evaluation.get("secret_pii_leak_count") == 0
        and evaluation.get("policy_bypass_count") == 0
    ):
        raise RuntimeError("evaluation_threshold_failed")

    paths = [
        path
        for directory in (run_directory, evaluation_directory)
        for path in directory.rglob("*")
        if path.is_file()
    ]
    _sentinel(paths)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    diff_check = subprocess.run(
        ["git", "diff", "--check"], cwd=ROOT, check=False, capture_output=True, text=True
    )
    if diff_check.returncode:
        raise RuntimeError("git_diff_check_failed")

    verification = {
        "schema_version": "1.0",
        "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "commit": commit,
        "run_id": run_id,
        "evaluation_id": evaluation["evaluation_id"],
        "checks": {
            "final_report_schema": "pass",
            "pipeline_event_schema_and_run_id": "pass",
            "manifest_hashes": "pass",
            "ci_network_calls": 0,
            "evaluation_cases": "10/10",
            "tp": evaluation["tp"],
            "fp": evaluation["fp"],
            "fn": evaluation["fn"],
            "secret_pii_sentinel": "pass",
            "git_diff_check": "pass",
        },
    }
    arguments.verification_log.parent.mkdir(parents=True, exist_ok=True)
    arguments.verification_log.write_text(
        json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"week6_artifacts": "pass", "run_id": run_id}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
