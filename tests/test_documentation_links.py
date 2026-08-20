from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def test_documentation_hub_links_resolve_to_root_readme() -> None:
    documents = list(DOCS.glob("*.md"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in documents)
    stale_links = re.findall(r"\[[^\]]+\]\(README\.md(?:#[^)]+)?\)", combined)
    root_links = re.findall(r"\[[^\]]+\]\(\.\./README\.md(?:#[^)]+)?\)", combined)

    assert stale_links == []
    assert len(root_links) >= 4
    assert (DOCS / "../README.md").resolve().is_file()
