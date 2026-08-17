from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence

from security_pipeline.analysis.agent import AnalysisInputError, run_analysis
from security_pipeline.analysis.providers import (
    DeterministicNarrativeProvider,
    GeminiNarrativeProvider,
    NarrativeProvider,
    ProviderError,
)
from security_pipeline.knowledge import SearchResult, search_knowledge
from security_pipeline.pipeline import normalize_files, write_normalized_report
from sentinel_guardrails.redaction import sanitize_text


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KNOWLEDGE_BASE = ROOT / "data" / "vulnerabilities.json"
DEFAULT_NORMALIZED_OUTPUT = ROOT / "security-results" / "normalized-findings.json"
DEFAULT_ANALYSIS_OUTPUT = ROOT / "security-results" / "security-analysis.jsonl"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"
DEFAULT_GEMINI_FALLBACK_MODEL = "gemini-3.6-flash"
DEFAULT_GEMINI_THINKING_LEVEL = "minimal"
DEFAULT_GEMINI_FALLBACK_THINKING_LEVEL = "low"
GEMINI_THINKING_LEVELS = ("minimal", "low", "medium", "high")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m security_pipeline",
        description=(
            "Normalize scanner JSON, search security knowledge, and generate "
            "grounded JSONL analysis."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Normalize and aggregate Bandit/ZAP JSON reports.",
    )
    normalize_parser.add_argument("inputs", nargs="+", type=Path)
    normalize_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=DEFAULT_NORMALIZED_OUTPUT,
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Group and explain normalized findings as grounded JSONL.",
    )
    analyze_parser.add_argument("input", type=Path)
    analyze_parser.add_argument(
        "--knowledge-base",
        type=Path,
        default=DEFAULT_KNOWLEDGE_BASE,
    )
    analyze_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=DEFAULT_ANALYSIS_OUTPUT,
    )
    analyze_parser.add_argument(
        "--provider",
        choices=("deterministic", "gemini"),
        default="deterministic",
        help="Use deterministic for reproducible local/CI output or gemini for LLM analysis.",
    )
    analyze_parser.add_argument(
        "--model",
        help=f"Gemini model (default: GEMINI_MODEL or {DEFAULT_GEMINI_MODEL}).",
    )
    analyze_parser.add_argument(
        "--fallback-model",
        help=(
            "Gemini fallback model used once for invalid output "
            f"(default: GEMINI_FALLBACK_MODEL or {DEFAULT_GEMINI_FALLBACK_MODEL})."
        ),
    )
    analyze_parser.add_argument(
        "--thinking-level",
        choices=GEMINI_THINKING_LEVELS,
        help=(
            "Primary Gemini thinking level "
            f"(default: GEMINI_THINKING_LEVEL or {DEFAULT_GEMINI_THINKING_LEVEL})."
        ),
    )
    analyze_parser.add_argument(
        "--fallback-thinking-level",
        choices=GEMINI_THINKING_LEVELS,
        help=(
            "Fallback Gemini thinking level (default: "
            "GEMINI_FALLBACK_THINKING_LEVEL or "
            f"{DEFAULT_GEMINI_FALLBACK_THINKING_LEVEL})."
        ),
    )

    search_parser = subparsers.add_parser(
        "search",
        help="Search knowledge by vulnerability name or keyword.",
    )
    search_parser.add_argument("query")
    search_parser.add_argument("--limit", type=int, default=5)
    search_parser.add_argument(
        "--knowledge-base",
        type=Path,
        default=DEFAULT_KNOWLEDGE_BASE,
    )
    search_parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON.",
    )
    return parser


def _configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def _local_env_value(name: str) -> str | None:
    value = os.getenv(name)
    if value and value.strip():
        return value.strip()
    env_path = ROOT / ".env"
    if not env_path.is_file():
        return None
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        if key.strip() == name:
            candidate = raw_value.strip().strip("\"'")
            if candidate and not candidate.startswith("replace-with-"):
                return candidate
    return None


def _print_search_results(query: str, results: list[SearchResult]) -> None:
    if not results:
        print(f'No knowledge found for "{query}".')
        return
    for index, result in enumerate(results, start=1):
        document = result.document
        print(f"{index}. {document['title']} (score: {result.score:.1f})")
        print(f"   OWASP: {document['owasp_top_10']}")
        print(f"   {document['summary']}")
        print(f"   Remediation: {document['remediation'][0]}")
        print(f"   Reference: {document['references'][0]}")


def main(arguments: Sequence[str] | None = None) -> int:
    _configure_output()
    args = _parser().parse_args(arguments)
    try:
        if args.command == "normalize":
            document = normalize_files(args.inputs)
            output = write_normalized_report(document, args.output)
            print(
                f"Normalized {document['summary']['total']} findings "
                f"from {len(document['sources'])} reports: {output}"
            )
            return 0

        if args.command == "analyze":
            provider: NarrativeProvider
            if args.provider == "gemini":
                provider = GeminiNarrativeProvider(
                    model=(
                        args.model
                        or _local_env_value("GEMINI_MODEL")
                        or DEFAULT_GEMINI_MODEL
                    ),
                    fallback_model=(
                        args.fallback_model
                        or _local_env_value("GEMINI_FALLBACK_MODEL")
                        or DEFAULT_GEMINI_FALLBACK_MODEL
                    ),
                    thinking_level=(
                        args.thinking_level
                        or _local_env_value("GEMINI_THINKING_LEVEL")
                        or DEFAULT_GEMINI_THINKING_LEVEL
                    ),
                    fallback_thinking_level=(
                        args.fallback_thinking_level
                        or _local_env_value("GEMINI_FALLBACK_THINKING_LEVEL")
                        or DEFAULT_GEMINI_FALLBACK_THINKING_LEVEL
                    ),
                    api_key=_local_env_value("GEMINI_API_KEY"),
                )
            else:
                provider = DeterministicNarrativeProvider()
            summary = run_analysis(
                input_path=args.input,
                knowledge_base=args.knowledge_base,
                output_path=args.output,
                provider=provider,
            )
            print(
                f"Analyzed {summary.input_findings} findings into "
                f"{summary.output_groups} grounded JSONL records "
                f"with {summary.analysis_method}: {summary.output_path}"
            )
            return 0

        results = search_knowledge(
            args.query,
            knowledge_base=args.knowledge_base,
            limit=args.limit,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "query": args.query,
                        "count": len(results),
                        "results": [result.to_dict() for result in results],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            _print_search_results(args.query, results)
        return 0
    except ProviderError as error:
        print(f"provider error: {sanitize_text(str(error)).value}", file=sys.stderr)
        return 3
    except (AnalysisInputError, FileNotFoundError, ValueError) as error:
        print(f"error: {sanitize_text(str(error)).value}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
