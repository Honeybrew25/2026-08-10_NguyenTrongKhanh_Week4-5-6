from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import unicodedata
from typing import Any


TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
REQUIRED_FIELDS = {
    "id",
    "title",
    "aliases",
    "owasp_top_10",
    "summary",
    "example",
    "indicators",
    "remediation",
    "tags",
    "references",
}


@dataclass(frozen=True)
class SearchResult:
    score: float
    document: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"score": round(self.score, 3), "document": self.document}


def _normalized_text(value: object) -> str:
    text = unicodedata.normalize("NFKD", str(value or "").casefold())
    return "".join(character for character in text if not unicodedata.combining(character))


def _tokens(value: object) -> set[str]:
    return set(TOKEN_PATTERN.findall(_normalized_text(value)))


def load_knowledge_base(path: str | Path) -> dict[str, Any]:
    knowledge_path = Path(path)
    try:
        data = json.loads(knowledge_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid knowledge base JSON in {knowledge_path}") from error
    if not isinstance(data, dict) or not isinstance(data.get("documents"), list):
        raise ValueError("Knowledge base must contain a documents array")

    seen_ids: set[str] = set()
    for index, document in enumerate(data["documents"]):
        if not isinstance(document, dict):
            raise ValueError(f"Knowledge document {index} must be an object")
        missing = REQUIRED_FIELDS - document.keys()
        if missing:
            raise ValueError(
                f"Knowledge document {index} is missing: {', '.join(sorted(missing))}"
            )
        document_id = str(document["id"])
        if document_id in seen_ids:
            raise ValueError(f"Duplicate knowledge document id: {document_id}")
        seen_ids.add(document_id)
    return data


def _score_document(query: str, document: dict[str, Any]) -> float:
    normalized_query = _normalized_text(query).strip()
    query_tokens = _tokens(query)
    if not query_tokens:
        return 0.0

    title = _normalized_text(document["title"])
    aliases = [_normalized_text(alias) for alias in document["aliases"]]
    category = _normalized_text(document["owasp_top_10"])
    tags = {_normalized_text(tag) for tag in document["tags"]}
    title_tokens = _tokens(title)
    alias_tokens = set().union(*(_tokens(alias) for alias in aliases)) if aliases else set()
    category_tokens = _tokens(category)
    tag_tokens = set().union(*(_tokens(tag) for tag in tags)) if tags else set()
    content_tokens = _tokens(
        " ".join(
            [
                document["summary"],
                document["example"],
                *document["indicators"],
                *document["remediation"],
            ]
        )
    )

    score = 0.0
    if normalized_query == title or normalized_query in aliases:
        score += 20.0
    elif normalized_query in title:
        score += 12.0
    elif any(normalized_query in alias for alias in aliases):
        score += 10.0
    if normalized_query in category:
        score += 5.0

    score += 6.0 * len(query_tokens & title_tokens)
    score += 5.0 * len(query_tokens & alias_tokens)
    score += 3.0 * len(query_tokens & tag_tokens)
    score += 2.0 * len(query_tokens & category_tokens)
    score += 1.0 * len(query_tokens & content_tokens)

    matched = query_tokens & (
        title_tokens | alias_tokens | tag_tokens | category_tokens | content_tokens
    )
    score += 4.0 * (len(matched) / len(query_tokens))
    return score


def search_knowledge(
    query: str,
    *,
    knowledge_base: str | Path,
    limit: int = 5,
) -> list[SearchResult]:
    """Return ranked knowledge documents for a vulnerability name or keyword."""
    if limit < 1:
        raise ValueError("limit must be at least 1")
    data = load_knowledge_base(knowledge_base)
    results = [
        SearchResult(score=_score_document(query, document), document=document)
        for document in data["documents"]
    ]
    return sorted(
        (result for result in results if result.score > 0),
        key=lambda result: (-result.score, result.document["title"]),
    )[:limit]
