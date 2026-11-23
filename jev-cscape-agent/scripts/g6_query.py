#!/usr/bin/env python3
"""Gate G6 Free-Text Knowledge Corpus Query CLI.

Work Package: GATE_G6_OFFLINE_ACCEPTANCE
Classification: PRODUCTION_READY [Knowledge Base Query Interface]

Usage:
  python scripts/g6_query.py "<free-text query>"
  python scripts/g6_query.py --query "<free-text query>"

Output:
  Prints the top 3 sources with section heading and a ~200-character snippet,
  or prints 'NOT FOUND' if the query is out of scope or below confidence threshold.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

# Force UTF-8 encoding on standard output for Windows console compatibility
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure repository root and scripts directory are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

from g6_corpus import KnowledgeCorpus, SearchResult


def query_corpus(
    query_text: str,
    top_k: int = 3,
    min_score: float = 14.0,
    min_coverage: float = 0.40,
    max_unseen_ratio: float = 0.25,
    corpus: Optional[KnowledgeCorpus] = None,
) -> Optional[List[SearchResult]]:
    """Query the knowledge corpus and return top_k search results, or None if NOT FOUND."""
    if corpus is None:
        corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    return corpus.search(
        query=query_text,
        top_k=top_k,
        min_score=min_score,
        min_coverage=min_coverage,
        max_unseen_ratio=max_unseen_ratio,
    )


def format_results(results: Optional[List[SearchResult]], json_mode: bool = False, query: str = "") -> str:
    """Format search results for terminal display or JSON output."""
    if not results:
        if json_mode:
            return json.dumps({
                "query": query,
                "status": "not_found",
                "results_count": 0,
                "results": [],
            }, indent=2)
        return "NOT FOUND"

    if json_mode:
        return json.dumps({
            "query": query,
            "status": "found",
            "results_count": len(results),
            "results": [r.to_dict() for r in results],
        }, indent=2)

    output_lines: List[str] = []
    for r in results:
        output_lines.append(f"[{r.rank}] Source: {r.source_path}")
        output_lines.append(f"    Section: {r.section}")
        output_lines.append(f"    Snippet: {r.snippet}\n")

    return "\n".join(output_lines).rstrip()


def main() -> None:
    """CLI entrypoint for g6_query.py."""
    parser = argparse.ArgumentParser(
        description="Query the Gate G6 authentic technical knowledge corpus."
    )
    parser.add_argument(
        "query_pos",
        nargs="?",
        default=None,
        help="Free-text query string (positional argument)",
    )
    parser.add_argument(
        "--query",
        "-q",
        type=str,
        default=None,
        help="Free-text query string (named option)",
    )
    parser.add_argument(
        "--top-k",
        "-k",
        type=int,
        default=3,
        help="Maximum number of sources to return (default: 3)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON response",
    )

    args = parser.parse_args()

    # Resolve query text from positional or named argument
    query_str = args.query if args.query is not None else args.query_pos
    if not query_str or not query_str.strip():
        if args.json:
            print(json.dumps({"error": "Missing required query argument", "status": "error"}))
        else:
            print("NOT FOUND")
        sys.exit(0)

    query_clean = query_str.strip()
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    results = query_corpus(query_clean, top_k=args.top_k, corpus=corpus)

    output = format_results(results, json_mode=args.json, query=query_clean)
    print(output)
    sys.exit(0)


if __name__ == "__main__":
    main()
