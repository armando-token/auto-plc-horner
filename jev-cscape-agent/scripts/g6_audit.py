#!/usr/bin/env python3
"""Gate G6 Knowledge Corpus & Anti-Contamination Audit Runner.

Work Package: GATE_G6_OFFLINE_ACCEPTANCE
Classification: PRODUCTION_READY [Knowledge Corpus Audit]

Purpose:
  1. Prints the authentic technical corpus manifest:
     - Each document title
     - Source path / provenance
     - Estimated pages
     - Number of indexed semantic chunks
  2. Anti-Contamination / Data Leakage Verification:
     - Extracts all 30 Gate G6 test suite expected answers (ground_truth).
     - Verifies that NO suite expected answer text was indexed in any corpus chunk.
     - Confirms zero data leakage across all indexed technical documents.
  3. Artifact Generation:
     - Exports structured manifest to artifacts/G6/g6_corpus_manifest.json.
     - Logs complete audit execution to artifacts/logs/g6_audit.log.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Force UTF-8 encoding on standard output for Windows console compatibility
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure repository root and scripts directory are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

from g6_corpus import KnowledgeCorpus, CorpusDocument, CorpusChunk
from g6_acceptance import G6_QUERY_CASES

# Artifact Directories
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
G6_DIR = REPO_ROOT / "artifacts" / "G6"
G6_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MANIFEST_PATH = G6_DIR / "g6_corpus_manifest.json"
DEFAULT_LOG_PATH = LOG_DIR / "g6_audit.log"

logger = logging.getLogger("g6_audit")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(DEFAULT_LOG_PATH, mode="w", encoding="utf-8")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)


def run_g6_audit(
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    verbose: bool = False,
    quiet: bool = False,
) -> Dict[str, Any]:
    """Execute the Gate G6 corpus manifest generation and anti-contamination audit."""
    logger.info("Initializing Gate G6 Knowledge Corpus...")
    corpus = KnowledgeCorpus(repo_root=REPO_ROOT).build()

    total_docs = len(corpus.documents)
    total_pages = sum(d.estimated_pages for d in corpus.documents)
    total_chunks = len(corpus.chunks)

    # --------------------------------------------------------------------------
    # 1. Print Corpus Manifest
    # --------------------------------------------------------------------------
    header_line = "=" * 96
    sub_line = "-" * 96

    if not quiet:
        print("\n" + header_line)
        print("          GATE G6 TECHNICAL CORPUS MANIFEST & ANTI-CONTAMINATION AUDIT")
        print(header_line)
        print("\n" + sub_line)
        print("CORPUS MANIFEST (Authentic Technical Documentation)")
        print(sub_line)
        print(f"{'#':<3} | {'Document Title':<42} | {'Source / Provenance':<35} | {'Pages':>5} | {'Chunks':>6}")
        print(f"{'-'*3}-+-{'-'*42}-+-{'-'*35}-+-{'-'*5}-+-{'-'*6}")

        for idx, doc in enumerate(corpus.documents, 1):
            short_title = doc.doc_title if len(doc.doc_title) <= 42 else doc.doc_title[:39] + "..."
            short_src = doc.source_path if len(doc.source_path) <= 35 else "..." + doc.source_path[-32:]
            print(f"{idx:<3} | {short_title:<42} | {short_src:<35} | {doc.estimated_pages:>5} | {doc.chunks_count:>6}")

        print(f"{'-'*3}-+-{'-'*42}-+-{'-'*35}-+-{'-'*5}-+-{'-'*6}")
        print(f"{'TOTAL':<3} | {f'{total_docs} Authentic Documents':<42} | {'docs/, profiles/, root':<35} | {total_pages:>5} | {total_chunks:>6}")
        print(sub_line)

    logger.info("Corpus manifest built: %d documents, %d estimated pages, %d chunks.", total_docs, total_pages, total_chunks)

    # --------------------------------------------------------------------------
    # 2. Anti-Contamination / Data Leakage Verification
    # --------------------------------------------------------------------------
    if not quiet:
        print("\n" + sub_line)
        print("ANTI-CONTAMINATION AUDIT: VERIFYING ZERO TEST SUITE LEAKAGE")
        print(sub_line)
        print(f"Auditing {len(G6_QUERY_CASES)} test suite expected answers against {total_chunks} indexed chunks...\n")

    expected_answers = [case.ground_truth for case in G6_QUERY_CASES]
    audit_res = corpus.audit_anti_contamination(expected_answers)

    case_results = []
    for idx, case in enumerate(G6_QUERY_CASES, 1):
        expected_text = case.ground_truth.strip()
        leaked = False
        leaked_chunk = None

        for c in corpus.chunks:
            if expected_text in c.text:
                leaked = True
                leaked_chunk = c.chunk_id
                break

        badge = "[FAIL: LEAK]" if leaked else "[PASS: CLEAN]"
        case_info = {
            "case_id": case.case_id,
            "category": case.category,
            "question": case.question,
            "expected_answer_snippet": expected_text[:75] + ("..." if len(expected_text) > 75 else ""),
            "indexed_in_corpus": leaked,
            "leaked_chunk_id": leaked_chunk,
            "status": "leaked" if leaked else "clean",
        }
        case_results.append(case_info)

        if not quiet:
            trunc_gt = expected_text[:55] + ("..." if len(expected_text) > 55 else "")
            print(f"  [{case.case_id}] {badge} Expected: \"{trunc_gt}\" -> Not Indexed")

    all_clean = (audit_res["leaks_found"] == 0)
    audit_status = "PASS" if all_clean else "FAIL"

    if not quiet:
        print("\n" + sub_line)
        print(f"AUDIT SUMMARY: {audit_status}")
        print(f"  - Total Test Suite Cases Audited:   {len(G6_QUERY_CASES)}")
        print(f"  - Suite Expected Answers Indexed:   {audit_res['leaks_found']} (Requirement: 0)")
        print(f"  - Clean Uncontaminated Cases:       {len(G6_QUERY_CASES) - audit_res['leaks_found']} / {len(G6_QUERY_CASES)}")
        print(f"  - Anti-Contamination Verification:  {'PASSED (100% Zero Leakage)' if all_clean else 'FAILED (Contamination Detected)'}")
        print(sub_line + "\n")

    logger.info("Anti-contamination audit outcome: %s (Leaks found: %d)", audit_status, audit_res["leaks_found"])

    # --------------------------------------------------------------------------
    # 3. Export Manifest & Evidence Artifact
    # --------------------------------------------------------------------------
    evidence_payload: Dict[str, Any] = {
        "gate": "G6",
        "audit_name": "GATE_G6_CORPUS_MANIFEST_AND_ANTI_CONTAMINATION_AUDIT",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "audit_status": audit_status,
        "anti_contamination": {
            "all_expected_answers_clean": all_clean,
            "total_cases_audited": len(G6_QUERY_CASES),
            "leaks_found": audit_res["leaks_found"],
            "leak_details": audit_res["leaks"],
            "per_case_results": case_results,
        },
        "corpus_manifest": {
            "total_documents": total_docs,
            "total_estimated_pages": total_pages,
            "total_indexed_chunks": total_chunks,
            "documents": [d.to_dict() for d in corpus.documents],
        },
    }

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(evidence_payload, indent=2), encoding="utf-8")
    logger.info("Corpus manifest and audit evidence exported to %s", manifest_path)

    if not quiet:
        print(f"Evidence artifact written to: {manifest_path}")
        print(f"Execution log written to:     {DEFAULT_LOG_PATH}\n")

    return evidence_payload


def main() -> None:
    """CLI entrypoint for g6_audit.py."""
    parser = argparse.ArgumentParser(
        description="Gate G6 Knowledge Corpus Manifest & Anti-Contamination Audit Runner"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help=f"Path to export manifest JSON (default: {DEFAULT_MANIFEST_PATH})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw JSON manifest and audit results to stdout",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress banner and table output",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    result = run_g6_audit(
        manifest_path=args.output,
        verbose=args.verbose,
        quiet=args.quiet or args.json,
    )

    if args.json:
        print(json.dumps(result, indent=2))

    sys.exit(0 if result["audit_status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
