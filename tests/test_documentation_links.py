from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def test_documentation_hub_links_resolve_to_root_readme() -> None:
    stale = "[documentation hub](README.md)"
    corrected = "[documentation hub](../README.md)"
    documents = list(DOCS.glob("*.md"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in documents)

    assert stale not in combined
    assert combined.count(corrected) >= 4
    assert (DOCS / "../README.md").resolve().is_file()
