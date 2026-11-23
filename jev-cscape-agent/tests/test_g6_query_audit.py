"""Tests for Gate G6 Knowledge Corpus Manifest, Anti-Contamination Audit, and Query Engine.

Work Package: GATE_G6_OFFLINE_ACCEPTANCE
Classification: UNIT_TEST [Gate G6 Knowledge Base Verification]
"""

from pathlib import Path
import json
import pytest
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

from g6_corpus import KnowledgeCorpus, SearchResult
from g6_audit import run_g6_audit
from g6_query import query_corpus, format_results
from g6_acceptance import G6_QUERY_CASES


def test_corpus_manifest_structure():
    """Verify that official Cscape help manuals and system profiles are indexed with non-trivial metrics."""
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    manifest = corpus.get_manifest()

    assert manifest["total_documents"] >= 300, f"Expected >= 300 authentic documents, got {manifest['total_documents']}"
    assert manifest["total_estimated_pages"] >= 500, "Expected >= 500 estimated pages across corpus"
    assert manifest["total_indexed_chunks"] >= 2000, "Expected >= 2000 semantic chunks"

    categories = manifest.get("categories_breakdown", {})
    assert "Advanced Ladder Logic" in categories, "Advanced Ladder Logic missing from categories"
    assert "Tools and Help" in categories, "Tools and Help missing from categories"
    assert "User Interface" in categories, "User Interface missing from categories"

    for doc in manifest["documents"]:
        assert doc["line_count"] > 0, f"Document {doc['source_path']} has 0 lines"
        assert doc["char_count"] > 0, f"Document {doc['source_path']} has 0 characters"
        assert doc["estimated_pages"] >= 1, f"Document {doc['source_path']} has 0 pages"
        assert doc["chunks_count"] >= 1, f"Document {doc['source_path']} has 0 chunks"


def test_anti_contamination_zero_leakage():
    """Verify that ZERO test suite expected answers were indexed in any corpus chunk."""
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    expected_answers = [case.ground_truth for case in G6_QUERY_CASES]

    audit = corpus.audit_anti_contamination(expected_answers)

    assert audit["total_checked"] == 30, "Expected 30 queries audited"
    assert audit["leaks_found"] == 0, f"Data leakage detected! Leaks: {audit['leaks']}"
    assert audit["leak_free"] is True, "Audit must be 100% leak free"
    assert audit["status"] == "PASS", "Audit status must be PASS"


def test_query_engine_factual_retrieval():
    """Verify that authentic factual queries return top sources with section and snippet."""
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()

    test_queries = [
        ("What is the exact Win32 command ID for Error Check in Horner Cscape 10.2?", ["32826"]),
        ("What companion DLL in Cscape 10.2 handles Structured Text editing and exports K5ExecuteCommand?", ["w5editst", "k5executecommand"]),
        ("What range of physical communication ports is permanently blocked by the SecurityGuard?", ["com1", "com256"]),
        ("What is the exact Horner APG Cscape build version targeted?", ["10.2.751.4"]),
    ]

    for query, expected_terms in test_queries:
        results = query_corpus(query, top_k=3, corpus=corpus)
        assert results is not None, f"Query '{query}' failed to retrieve results"
        assert 1 <= len(results) <= 3, f"Expected 1-3 results for query '{query}', got {len(results)}"

        for r in results:
            assert isinstance(r, SearchResult)
            assert len(r.snippet) <= 250, f"Snippet exceeded length constraint: {len(r.snippet)} chars"
            assert len(r.source_path) > 0
            assert len(r.section) > 0

        formatted = format_results(results)
        assert "[1] Source:" in formatted
        assert "NOT FOUND" not in formatted


@pytest.mark.parametrize("query", ["S008", "S8", "%S8", "%S0008"])
def test_query_s8_normalization_rank_one(query: str):
    """Verify S008, S8, %S8, and %S0008 all resolve to %S8 Always OFF table row at rank 1."""
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    results = query_corpus(query, top_k=3, corpus=corpus)

    assert results is not None, f"Query '{query}' failed to retrieve results"
    assert len(results) >= 1, f"Expected at least 1 result for '{query}'"

    top = results[0]
    assert top.rank == 1, f"Top result rank must be 1, got {top.rank}"
    assert "Tools-System-Register-Tables.htm" in top.source_path, (
        f"Expected Tools-System-Register-Tables.htm, got: {top.source_path}"
    )
    assert "System Registers" in top.section, (
        f"Expected 'System Registers' in section, got: {top.section}"
    )
    assert "%S8" in top.snippet, f"Snippet missing '%S8': {top.snippet}"
    assert "Always OFF" in top.snippet or "ALW_OFF" in top.snippet, (
        f"Snippet missing 'Always OFF' or 'ALW_OFF': {top.snippet}"
    )

    formatted = format_results(results, query=query)
    assert "[1] Source:" in formatted
    assert "Tools-System-Register-Tables.htm" in formatted
    assert "NOT FOUND" not in formatted


@pytest.mark.parametrize("query", [
    "backup a project",
    "backup project",
    "how to backup a project in cscape",
])
def test_query_backup_project_ranks_manage_backups_first(query: str):
    """Verify 'backup a project' and variants return 'Manage Backups' manual at rank 1."""
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    results = query_corpus(query, top_k=3, corpus=corpus)

    assert results is not None, f"Query '{query}' returned None (NOT FOUND)"
    assert len(results) >= 1, f"Expected at least 1 result for '{query}'"

    top = results[0]
    assert top.rank == 1, f"Top result rank must be 1, got {top.rank}"
    assert "Manage Backups.htm" in top.source_path, (
        f"Expected Manage Backups.htm at rank 1, got: {top.source_path}"
    )
    assert "Manage Backups" in top.section or "Manage Backups" in top.doc_title, (
        f"Expected 'Manage Backups' in section/title, got section='{top.section}', title='{top.doc_title}'"
    )

    snippet_lower = top.snippet.lower()
    assert any(term in snippet_lower for term in ["backup", "backups", "manage backup", "allow backup"]), (
        f"Snippet missing backup terminology: {top.snippet}"
    )

    formatted = format_results(results, query=query)
    assert "[1] Source:" in formatted
    assert "Manage Backups.htm" in formatted


def test_query_ladder_rung_ranks_advanced_ladder_first():
    """Verify 'rung' query returns official Advanced Ladder Logic manuals without ST forbidden notes."""
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    results = query_corpus("rung", top_k=3, corpus=corpus)

    assert results is not None, "Query 'rung' must return results"
    assert len(results) >= 1
    top_rung = results[0]
    assert "Advanced Ladder Logic" in top_rung.category or "Advanced Ladder Logic" in top_rung.source_path
    for r in results:
        assert "ERR_LADDER_FORBIDDEN" not in r.snippet, f"Ladder query returned ST forbidden notice: {r.snippet}"


@pytest.mark.parametrize("query", [
    "Mars",
    "mars rover mission to phobos",
    "What is the secret baking recipe for chocolate cookies?",
    "How do I invest in Bitcoin cryptocurrency on Horner Cscape?",
    "quantum gravity string theory propulsion",
    "weather forecast in Paris tomorrow",
    "What API endpoint allows direct cloud upload of .csp project files to Horner Remote Cloud?",
    "",
    "   ",
])
def test_query_mars_and_off_topic_not_found(query: str):
    """Verify off-topic, unindexed vocabulary, and empty queries strictly return NOT FOUND."""
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()
    results = query_corpus(query, corpus=corpus)

    assert results is None, f"Query '{query}' unexpectedly returned results: {results}"

    text_out = format_results(results, json_mode=False, query=query)
    assert text_out == "NOT FOUND", f"Expected 'NOT FOUND', got '{text_out}'"

    json_out = format_results(results, json_mode=True, query=query)
    assert '"status": "not_found"' in json_out
    assert '"results_count": 0' in json_out


def test_g6_audit_runner(tmp_path):
    """Verify that run_g6_audit generates a valid manifest JSON file."""
    manifest_file = tmp_path / "g6_manifest_test.json"
    evidence = run_g6_audit(manifest_path=manifest_file, quiet=True)

    assert evidence["audit_status"] == "PASS"
    assert evidence["anti_contamination"]["leaks_found"] == 0
    assert evidence["corpus_manifest"]["total_documents"] >= 300
    assert manifest_file.exists()

    with open(manifest_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["audit_status"] == "PASS"
    assert len(data["corpus_manifest"]["documents"]) >= 300
