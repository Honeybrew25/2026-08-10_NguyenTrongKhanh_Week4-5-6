from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from security_pipeline.knowledge import SearchResult, search_knowledge
from security_pipeline.pipeline import normalize_files, write_normalized_report


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KNOWLEDGE_BASE = ROOT / "knowledge-base" / "vulnerabilities.json"
DEFAULT_NORMALIZED_OUTPUT = ROOT / "security-results" / "normalized-findings.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize scanner JSON and search the Week 2 knowledge base."
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
    except (FileNotFoundError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
