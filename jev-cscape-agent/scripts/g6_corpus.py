#!/usr/bin/env python3
"""Gate G6 Official Knowledge Corpus & Retrieval Engine.

Work Package: GATE_G6_OFFLINE_ACCEPTANCE
Classification: PRODUCTION_READY [Official Cscape Knowledge Base & Retrieval Engine]

Indexes:
  1. Official Horner APG Cscape 10.2 Help & Manuals:
     - 308 authentic HTML manuals installed under C:\\Program Files (x86)\\Cscape 10.2\\WebHelp\\Content\\
       spanning Advanced Ladder Logic, The Controller, Tools and Help, IEC Logic, HW_Config,
       User Interface, Networking, Protocols, Debug, and What's New.
  2. Authentic System Architectural Specifications & Forensics:
     - profiles/cscape-reference.yaml, profiles/environment-reference.json, profiles/supervisor-profile.yaml,
       docs/ARCHITECTURE_OVERVIEW.md, docs/SAFETY_AND_COMMISSIONING_MANUAL.md, docs/MULTI_AGENT_PARITY.md,
       docs/OPERATOR_REFERENCE_MANUAL.md, AGENTS.md, README.md.
     - Strictly excludes synthetic/unverified documentation.

Features:
  - Provenance tracking with authentic file paths and documentation origins.
  - Robust HTML table parsing preserving structured register tables (%S, %SR, %R, %AI, %AQ).
  - Normalized register addressing (S008 = S8 = %S8 = %S0008) with exact ID and table row boosting.
  - Page title and heading extraction & boosting ensuring 'backup a project' ranks Manage Backups first.
  - Domain-aware ranking ensuring 'rung' and 'ladder' queries retrieve official Advanced Ladder Logic.
  - Strict relevance, passage answering confidence, and out-of-vocabulary filtering (NOT FOUND).
  - Anti-contamination verification ensuring zero test suite expected answer strings are indexed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Repository root and Cscape installation directories
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSCAPE_HELP_DIR = Path(r"C:\Program Files (x86)\Cscape 10.2\WebHelp\Content")

STOP_WORDS: Set[str] = {
    "what", "is", "the", "a", "an", "and", "or", "in", "on", "of", "to", "for",
    "with", "by", "from", "at", "it", "this", "that", "does", "do", "how", "can",
    "where", "which", "are", "be", "as", "into", "under", "all", "its", "has",
    "have", "about", "could", "should", "would", "when", "why", "there", "their",
    "such", "than", "been", "only", "also", "then",
}

VALID_REGISTER_PREFIXES: Set[str] = {
    "S", "SR", "R", "AI", "AQ", "I", "Q", "M", "T", "K", "D",
    "IG", "QG", "AIG", "AQG"
}


def stem(w: str) -> str:
    """Lightweight English suffix normalizer for common technical terms."""
    w = w.lower()
    if w.endswith("ies") and len(w) > 4:
        return w[:-3] + "y"
    if w.endswith("es") and len(w) > 4 and not w.endswith("les"):
        return w[:-2]
    if w.endswith("s") and len(w) > 3 and not w.endswith("ss"):
        return w[:-1]
    if w.endswith("ing") and len(w) > 5:
        return w[:-3]
    if w.endswith("ed") and len(w) > 4:
        return w[:-2]
    return w


@dataclass
class CorpusDocument:
    """Document manifest entry with provenance and metrics."""
    source_path: str
    doc_title: str
    category: str
    provenance: str
    doc_type: str  # "html_manual" | "yaml" | "json" | "markdown"
    line_count: int
    char_count: int
    estimated_pages: int
    chunks_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorpusChunk:
    """Semantic chunk within a corpus document."""
    chunk_id: str
    doc_title: str
    source_path: str
    category: str
    section: str
    text: str
    char_count: int
    tokens: List[str] = field(default_factory=list)
    sec_tokens: List[str] = field(default_factory=list)
    title_tokens: List[str] = field(default_factory=list)
    heading_tokens: List[str] = field(default_factory=list)
    headings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "doc_title": self.doc_title,
            "source_path": self.source_path,
            "category": self.category,
            "section": self.section,
            "char_count": self.char_count,
            "text": self.text,
        }


@dataclass
class SearchResult:
    """Retrieved search result from corpus."""
    rank: int
    score: float
    source_path: str
    doc_title: str
    category: str
    section: str
    snippet: str
    chunk_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase alphanumeric and symbolic tokens, expanding composites."""
    raw_tokens = [t.lower() for t in re.findall(r"[a-zA-Z0-9_\.%#-]+", text) if len(t) > 1]
    expanded: List[str] = list(raw_tokens)
    for t in raw_tokens:
        sub = [s for s in re.split(r"[\._-]", t) if len(s) > 1 and s.lower() != t]
        expanded.extend(sub)
    return expanded


def extract_registers(query: str) -> List[Dict[str, Any]]:
    """Extract and normalize Horner OCS register identifiers from a query string.
    
    Normalizes:
      S008 = S8 = %S8 = %S0008 = %S008 = S08 = %S08
      SR1 = %SR1 = SR001 = %SR0001
      R100 = %R100 = R0100 = %R0100
    """
    regs: List[Dict[str, Any]] = []
    # Match any %?prefix0*number
    for m in re.finditer(r"(?:^|[^\w%])(%?([a-zA-Z]{1,3})0*(\d+))\b", query):
        raw = m.group(1)
        raw_prefix = m.group(2).upper()
        if raw_prefix not in VALID_REGISTER_PREFIXES:
            continue
        num = int(m.group(3))
        prefix = raw_prefix

        # All normalized alias representations (handling arbitrary zero-padding)
        forms = {
            f"%{prefix}{num}".lower(),
            f"{prefix}{num}".lower(),
            f"%{prefix}{num:02d}".lower(),
            f"{prefix}{num:02d}".lower(),
            f"%{prefix}{num:03d}".lower(),
            f"{prefix}{num:03d}".lower(),
            f"%{prefix}{num:04d}".lower(),
            f"{prefix}{num:04d}".lower(),
        }

        # Regex to detect an exact System Register table row definition for this register
        row_re = re.compile(
            r"(?:^|\n)\s*%?" + re.escape(prefix) + r"0*" + str(num) + r"\b[^|\n]*\|",
            re.IGNORECASE,
        )

        regs.append({
            "prefix": prefix,
            "num": num,
            "canonical": f"%{prefix}{num}",
            "forms": forms,
            "row_re": row_re,
            "raw": raw.lower(),
            "short": f"{prefix}{num}".lower(),
        })
    return regs


def extract_snippet(
    text: str,
    match_terms: List[str],
    max_len: int = 200,
    reg_rows: Optional[List[re.Pattern]] = None,
) -> str:
    """Extract an informative snippet of up to max_len characters centered on query matches.

    Optimizations:
      1. Register Table Row Preservation: If a match is on a register table row
         (e.g. '%S8 | Always OFF | ALW_OFF | This bit is always off'), the exact row
         is preserved without slicing into adjacent rows or arbitrary offsets.
      2. Title/Heading Preservation: If a match is on a section title or heading,
         the snippet starts cleanly at the heading and adds subsequent body lines up to max_len.
      3. Sentence & Word Boundary Alignment: General matches align to whole words
         or sentence starts, eliminating mid-word clippings.
      4. Hard Upper Bound: Snippet length is strictly guaranteed to be <= min(max_len, 250).
    """
    if not text or not text.strip():
        return ""

    cap_len = min(max(max_len, 50), 250)

    # 1. Check if a register table row matches directly
    if reg_rows:
        for r_re in reg_rows:
            for line in text.splitlines():
                if r_re.search(line):
                    clean_row = line.strip()
                    if clean_row.startswith("|"):
                        clean_row = clean_row.lstrip("|").strip()
                    if clean_row.endswith("|"):
                        clean_row = clean_row.rstrip("|").strip()
                    clean_row = re.sub(r"\s*\|\s*", " | ", clean_row)
                    clean_row = " ".join(clean_row.split())
                    if len(clean_row) <= cap_len:
                        return clean_row
                    return clean_row[: cap_len - 3].rsplit(" ", 1)[0] + "..."

    # 2. Normalize match terms
    clean_terms: List[str] = []
    for t in match_terms:
        if not t:
            continue
        tl = t.strip().lower()
        if len(tl) < 2 or tl in STOP_WORDS:
            continue
        clean_terms.append(tl)

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        clean_all = " ".join(text.split()).strip()
        return clean_all[:cap_len]

    # If single line and fits
    if len(lines) == 1 and len(lines[0]) <= cap_len:
        return lines[0]

    # 3. Score each line for relevance
    scored_lines: List[Tuple[float, int, str]] = []
    for idx, line in enumerate(lines):
        line_lower = line.lower()
        score = 0.0
        for qt in clean_terms:
            if qt in line_lower:
                score += 10.0
                if re.search(r"\b" + re.escape(qt) + r"\b", line_lower):
                    score += 5.0
        if score > 0:
            scored_lines.append((score, idx, line))

    if scored_lines:
        scored_lines.sort(key=lambda x: x[0], reverse=True)
        best_score, best_idx, best_line = scored_lines[0]

        # Case A: Table row match
        if " | " in best_line or (best_line.startswith("|") and best_line.endswith("|")):
            clean_row = best_line.strip()
            if clean_row.startswith("|"):
                clean_row = clean_row.lstrip("|").strip()
            if clean_row.endswith("|"):
                clean_row = clean_row.rstrip("|").strip()
            clean_row = re.sub(r"\s*\|\s*", " | ", clean_row)
            clean_row = " ".join(clean_row.split())
            if len(clean_row) <= cap_len:
                return clean_row
            return clean_row[: cap_len - 3].rsplit(" ", 1)[0] + "..."

        # Case B: Heading match
        is_markdown_heading = bool(re.match(r"^#{1,6}\s+", best_line))
        is_short_title = len(best_line) <= 60 and not best_line.endswith((".", ";", "!")) and " | " not in best_line

        if is_markdown_heading or is_short_title:
            context_parts = [best_line]
            cur_len = len(best_line)
            next_idx = best_idx + 1
            while next_idx < len(lines) and cur_len < cap_len:
                next_l = lines[next_idx]
                if re.match(r"^#{1,6}\s+", next_l) or " | " in next_l:
                    break
                sep = " "
                if cur_len + len(sep) + len(next_l) <= cap_len:
                    context_parts.append(next_l)
                    cur_len += len(sep) + len(next_l)
                    next_idx += 1
                else:
                    remain = cap_len - cur_len - len(sep) - 3
                    if remain > 15:
                        partial = next_l[:remain].rsplit(" ", 1)[0] + "..."
                        context_parts.append(partial)
                    break
            combined = " ".join(context_parts).strip()
            if len(combined) <= cap_len:
                return combined
            return combined[: cap_len - 3].rsplit(" ", 1)[0] + "..."

        # Case C: Paragraph match
        line_clean = " ".join(best_line.split())
        if len(line_clean) <= cap_len:
            return line_clean

        line_lower = line_clean.lower()
        match_pos = -1
        for qt in clean_terms:
            p = line_lower.find(qt)
            if p != -1 and (match_pos == -1 or p < match_pos):
                match_pos = p

        if match_pos == -1:
            match_pos = 0

        if match_pos <= 40:
            start = 0
            has_lead = False
        else:
            lookback = line_clean[max(0, match_pos - 60): match_pos]
            m_sent = re.search(r"[\.\!\?]\s+", lookback)
            if m_sent:
                start = max(0, match_pos - 60) + m_sent.end()
                has_lead = False
            else:
                target_start = max(0, match_pos - 35)
                space_pos = line_clean.find(" ", target_start)
                if space_pos != -1 and space_pos < match_pos:
                    start = space_pos + 1
                else:
                    start = target_start
                has_lead = True

        budget = cap_len - (3 if has_lead else 0)
        end = start + budget
        has_trail = False
        if end >= len(line_clean):
            end = len(line_clean)
        else:
            last_space = line_clean.rfind(" ", start, end - 3)
            if last_space > start:
                end = last_space
            else:
                end = end - 3
            has_trail = True

        snip = line_clean[start:end].strip()
        if has_lead:
            snip = "..." + snip
        if has_trail:
            snip = snip + "..."

        if len(snip) > cap_len:
            snip = snip[: cap_len - 3].rsplit(" ", 1)[0] + "..."
        return snip

    clean_all = " ".join(lines)
    if len(clean_all) <= cap_len:
        return clean_all
    snip = clean_all[: cap_len - 3].rsplit(" ", 1)[0] + "..."
    return snip if len(snip) <= cap_len else clean_all[: cap_len - 3] + "..."


class KnowledgeCorpus:
    """Knowledge corpus manager and BM25 search index for Cscape 10.2 documentation."""

    def __init__(
        self,
        repo_root: Optional[Path] = None,
        cscape_help_dir: Optional[Path] = None,
    ) -> None:
        self.repo_root = repo_root or REPO_ROOT
        self.cscape_help_dir = cscape_help_dir or DEFAULT_CSCAPE_HELP_DIR
        self.documents: List[CorpusDocument] = []
        self.chunks: List[CorpusChunk] = []
        self._doc_lens: List[int] = []
        self._avgdl: float = 1.0
        self._df: Dict[str, int] = {}
        self._idf: Dict[str, float] = {}
        self._built: bool = False

    def build(self) -> KnowledgeCorpus:
        """Parse, chunk, and index official Cscape Help manuals and system specifications."""
        self.documents.clear()
        self.chunks.clear()

        # ----------------------------------------------------------------------
        # 1. Official Cscape 10.2 HTML Help Manuals
        # ----------------------------------------------------------------------
        if self.cscape_help_dir.exists():
            html_files = sorted(list(self.cscape_help_dir.rglob("*.htm")))
            for htm_path in html_files:
                doc_entry, doc_chunks = self._parse_and_chunk_html(htm_path)
                if doc_chunks:
                    self.documents.append(doc_entry)
                    self.chunks.extend(doc_chunks)

        # ----------------------------------------------------------------------
        # 2. Repo Technical Profiles & Core System Documentation
        # ----------------------------------------------------------------------
        repo_specs = [
            ("profiles/cscape-reference.yaml", "Cscape 10.2 PE Forensics & Binary Reference Profile", "PE Forensics", "yaml"),
            ("profiles/environment-reference.json", "Host Environment & Desktop Automation Profile", "Environment", "json"),
            ("profiles/supervisor-profile.yaml", "Cscape GUI Supervisor & Watchdog Profile", "Supervision", "yaml"),
            ("docs/ARCHITECTURE_OVERVIEW.md", "JEV Cscape Agent: Architectural & Subsystem Overview", "Architecture", "markdown"),
            ("docs/SAFETY_AND_COMMISSIONING_MANUAL.md", "Fail-Closed Safety & Commissioning Lockout Manual", "Safety", "markdown"),
            ("docs/MULTI_AGENT_PARITY.md", "Multi-Agent Hierarchy & FastMCP Tool Parity", "FastMCP", "markdown"),
            ("docs/OPERATOR_REFERENCE_MANUAL.md", "Horner APG Cscape Operator Reference Manual & CLI Guide", "Operations", "markdown"),
            ("AGENTS.md", "Horner Cscape MCP Autonomous Agents Guide", "Governance", "markdown"),
            ("README.md", "JEV Cscape Automation Agent System Overview", "Overview", "markdown"),
        ]

        for rel_path, title, category, ftype in repo_specs:
            spec_file = self.repo_root / rel_path
            if not spec_file.exists():
                continue

            content = spec_file.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            line_count = len(lines)
            char_count = len(content)
            estimated_pages = max(1, math.ceil(line_count / 50.0))

            doc_chunks = self._chunk_repo_file(rel_path, title, category, ftype, content)
            doc_entry = CorpusDocument(
                source_path=rel_path,
                doc_title=title,
                category=category,
                provenance="Horner APG Cscape Agent Specification",
                doc_type=ftype,
                line_count=line_count,
                char_count=char_count,
                estimated_pages=estimated_pages,
                chunks_count=len(doc_chunks),
            )
            self.documents.append(doc_entry)
            self.chunks.extend(doc_chunks)

        # ----------------------------------------------------------------------
        # 3. Build BM25 Index Statistics
        # ----------------------------------------------------------------------
        self._doc_lens = [len(c.tokens) for c in self.chunks]
        self._avgdl = sum(self._doc_lens) / len(self._doc_lens) if self._doc_lens else 1.0

        from collections import defaultdict
        df_counter: Dict[str, int] = defaultdict(int)
        for c in self.chunks:
            for term in set(c.tokens):
                df_counter[term] += 1
        self._df = dict(df_counter)

        total_n = len(self.chunks)
        self._idf = {}
        for term, freq in self._df.items():
            self._idf[term] = math.log(1.0 + (total_n - freq + 0.5) / (freq + 0.5))

        self._built = True
        return self

    def _parse_and_chunk_html(self, file_path: Path) -> Tuple[CorpusDocument, List[CorpusChunk]]:
        """Parse official Cscape HTML Help file, preserve tables, headings, and generate semantic chunks."""
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        m_title = re.search(r"<title>(.*?)</title>", content, re.I)
        title = html.unescape(m_title.group(1).strip()) if m_title else file_path.stem
        title = re.sub(r"^(Topic Menu|Overview):\s*", "", title, flags=re.I).strip()

        # Extract headings (h1, h2, h3)
        raw_headings = re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", content, flags=re.DOTALL | re.I)
        headings = [
            re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", h))).strip()
            for h in raw_headings
        ]
        headings = [h for h in headings if h]

        title_tokens = tokenize(title)
        heading_tokens = [t for h in headings for t in tokenize(h)]

        # Determine Category
        try:
            rel = file_path.relative_to(self.cscape_help_dir)
            category = rel.parts[0] if len(rel.parts) > 1 else "Cscape Manual"
        except Exception:
            category = "Cscape Manual"

        # Table row conversion
        def clean_tr(m: re.Match) -> str:
            cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", m.group(1), flags=re.DOTALL | re.I)
            cleaned = [
                re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", c))).strip()
                for c in cells
            ]
            non_empty = [c for c in cleaned if c]
            return (" | ".join(non_empty) + "\n") if non_empty else ""

        # Strip WebHelp navigation and header boilerplate
        c = re.sub(r'<div class="central-account-wrapper">.*?</div>\s*</div>', '', content, flags=re.DOTALL | re.I)
        c = re.sub(r'<div class="nav-search-wrapper">.*?</div>\s*</div>', '', c, flags=re.DOTALL | re.I)
        c = re.sub(r'<nav class="title-bar[^"]*">.*?</nav>', '', c, flags=re.DOTALL | re.I)
        c = re.sub(r'<aside class="off-canvas[^"]*">.*?</aside>', '', c, flags=re.DOTALL | re.I)
        c = re.sub(r'<div class="navigation-wrapper.*?</div>', '', c, flags=re.DOTALL | re.I)
        c = re.sub(r'<div class="MCBreadcrumbsBox_0[^"]*">.*?</div>', '', c, flags=re.DOTALL | re.I)
        c = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", c, flags=re.DOTALL | re.I)
        c = re.sub(r"<tr[^>]*>(.*?)</tr>", clean_tr, c, flags=re.DOTALL | re.I)
        c = re.sub(r"</?(h[1-6]|p|div|li|br|table|tbody|thead)[^>]*>", "\n", c, flags=re.I)
        c = re.sub(r"<[^>]+>", " ", c)
        c = html.unescape(c)

        skip_exact = {
            "Skip To Main Content", "Account Settings Logout", "placeholder Account Settings Logout",
            "Filter: All Files Submit Search", "Submit Search", "You are here:", "placeholder",
        }
        raw_lines = [re.sub(r"\s+", " ", l).strip() for l in c.splitlines() if l.strip()]
        lines = [
            l for l in raw_lines
            if l not in skip_exact
            and l != "placeholder"
            and not l.startswith("Filter: All Files")
            and not l.startswith("Account Settings Logout")
            and not l.startswith("placeholder")
        ]

        line_count = len(lines)
        char_count = sum(len(l) for l in lines)
        estimated_pages = max(1, math.ceil(line_count / 50.0))

        canonical_path = str(file_path).replace("\\", "/")

        chunks: List[CorpusChunk] = []
        buf: List[str] = []
        buf_len = 0
        part_idx = 1
        chunk_idx = 1

        for l in lines:
            if buf_len + len(l) > 1100 and buf:
                chunk_text = "\n".join(buf)
                sec_label = f"{category} > {title}" + (f" (Part {part_idx})" if part_idx > 1 else "")
                chunk_id = f"{file_path.name}#chunk_{chunk_idx:04d}"
                chunks.append(
                    CorpusChunk(
                        chunk_id=chunk_id,
                        doc_title=title,
                        source_path=canonical_path,
                        category=category,
                        section=sec_label,
                        text=chunk_text,
                        char_count=len(chunk_text),
                        tokens=tokenize(chunk_text),
                        sec_tokens=tokenize(sec_label),
                        title_tokens=title_tokens,
                        heading_tokens=heading_tokens,
                        headings=headings,
                    )
                )
                chunk_idx += 1
                part_idx += 1
                buf = [l]
                buf_len = len(l)
            else:
                buf.append(l)
                buf_len += len(l)

        if buf:
            chunk_text = "\n".join(buf)
            sec_label = f"{category} > {title}" + (f" (Part {part_idx})" if part_idx > 1 else "")
            chunk_id = f"{file_path.name}#chunk_{chunk_idx:04d}"
            chunks.append(
                CorpusChunk(
                    chunk_id=chunk_id,
                    doc_title=title,
                    source_path=canonical_path,
                    category=category,
                    section=sec_label,
                    text=chunk_text,
                    char_count=len(chunk_text),
                    tokens=tokenize(chunk_text),
                    sec_tokens=tokenize(sec_label),
                    title_tokens=title_tokens,
                    heading_tokens=heading_tokens,
                    headings=headings,
                )
            )

        doc_entry = CorpusDocument(
            source_path=canonical_path,
            doc_title=title,
            category=category,
            provenance="Horner APG Cscape 10.2 Official Help Library",
            doc_type="html_manual",
            line_count=line_count,
            char_count=char_count,
            estimated_pages=estimated_pages,
            chunks_count=len(chunks),
        )
        return doc_entry, chunks

    def _chunk_repo_file(
        self,
        source_path: str,
        doc_title: str,
        category: str,
        doc_type: str,
        content: str,
    ) -> List[CorpusChunk]:
        """Split a repository profile or markdown specification into semantic sections with heading tracking."""
        chunks: List[CorpusChunk] = []
        chunk_idx = 1
        title_tokens = tokenize(doc_title)

        if doc_type in ("yaml", "json"):
            paragraphs = [p.strip() for p in re.split(r"\n\n+", content) if p.strip()]
            buf: List[str] = []
            buf_len = 0
            part_idx = 1
            for p in paragraphs:
                if buf_len + len(p) > 900 and buf:
                    chunk_text = "\n\n".join(buf)
                    sec_label = f"{doc_title} (Part {part_idx})"
                    chunk_id = f"{source_path}#chunk_{chunk_idx:04d}"
                    chunks.append(
                        CorpusChunk(
                            chunk_id=chunk_id,
                            doc_title=doc_title,
                            source_path=source_path,
                            category=category,
                            section=sec_label,
                            text=chunk_text,
                            char_count=len(chunk_text),
                            tokens=tokenize(chunk_text),
                            sec_tokens=tokenize(sec_label),
                            title_tokens=title_tokens,
                            heading_tokens=[],
                            headings=[],
                        )
                    )
                    chunk_idx += 1
                    part_idx += 1
                    buf = [p]
                    buf_len = len(p)
                else:
                    buf.append(p)
                    buf_len += len(p)
            if buf:
                chunk_text = "\n\n".join(buf)
                sec_label = f"{doc_title} (Part {part_idx})"
                chunk_id = f"{source_path}#chunk_{chunk_idx:04d}"
                chunks.append(
                    CorpusChunk(
                        chunk_id=chunk_id,
                        doc_title=doc_title,
                        source_path=source_path,
                        category=category,
                        section=sec_label,
                        text=chunk_text,
                        char_count=len(chunk_text),
                        tokens=tokenize(chunk_text),
                        sec_tokens=tokenize(sec_label),
                        title_tokens=title_tokens,
                        heading_tokens=[],
                        headings=[],
                    )
                )
        else:
            lines = content.splitlines()
            curr_section = "Overview"
            curr_lines: List[str] = []

            # Extract markdown headings
            all_headings = [m.group(2).strip() for line in lines if (m := re.match(r"^(#{1,4})\s+(.+)$", line))]

            def flush(sec: str, sec_lines: List[str]) -> None:
                nonlocal chunk_idx
                if not sec_lines:
                    return
                full_sec = "\n".join(sec_lines).strip()
                if not full_sec:
                    return
                paragraphs = [p.strip() for p in re.split(r"\n\n+", full_sec) if p.strip()]
                buf: List[str] = []
                buf_len = 0
                part_idx = 1
                heading_tokens = tokenize(sec)
                for par in paragraphs:
                    if buf_len + len(par) > 900 and buf:
                        chunk_text = "\n\n".join(buf)
                        label = f"{sec} (Part {part_idx})" if part_idx > 1 else sec
                        chunk_id = f"{source_path}#chunk_{chunk_idx:04d}"
                        chunks.append(
                            CorpusChunk(
                                chunk_id=chunk_id,
                                doc_title=doc_title,
                                source_path=source_path,
                                category=category,
                                section=label,
                                text=chunk_text,
                                char_count=len(chunk_text),
                                tokens=tokenize(chunk_text),
                                sec_tokens=tokenize(label),
                                title_tokens=title_tokens,
                                heading_tokens=heading_tokens,
                                headings=all_headings,
                            )
                        )
                        chunk_idx += 1
                        part_idx += 1
                        buf = [par]
                        buf_len = len(par)
                    else:
                        buf.append(par)
                        buf_len += len(par)

                if buf:
                    chunk_text = "\n\n".join(buf)
                    label = f"{sec} (Part {part_idx})" if part_idx > 1 else sec
                    chunk_id = f"{source_path}#chunk_{chunk_idx:04d}"
                    chunks.append(
                        CorpusChunk(
                            chunk_id=chunk_id,
                            doc_title=doc_title,
                            source_path=source_path,
                            category=category,
                            section=label,
                            text=chunk_text,
                            char_count=len(chunk_text),
                            tokens=tokenize(chunk_text),
                            sec_tokens=tokenize(label),
                            title_tokens=title_tokens,
                            heading_tokens=heading_tokens,
                            headings=all_headings,
                        )
                    )
                    chunk_idx += 1

            for line in lines:
                m = re.match(r"^(#{1,4})\s+(.+)$", line)
                if m:
                    flush(curr_section, curr_lines)
                    curr_section = m.group(2).strip()
                    curr_lines = [line]
                else:
                    curr_lines.append(line)
            flush(curr_section, curr_lines)

        return chunks

    def search(
        self,
        query: str,
        top_k: int = 3,
        min_score: float = 14.0,
        min_coverage: float = 0.40,
        max_unseen_ratio: float = 0.25,
    ) -> Optional[List[SearchResult]]:
        """Search the corpus using BM25 with normalized register boost, title/heading boost, and answering confidence."""
        if not self._built:
            self.build()

        if not query or not query.strip():
            return None

        q_clean = query.strip()
        q_toks = tokenize(q_clean)
        content_tokens = [t for t in q_toks if t not in STOP_WORDS]
        if not content_tokens:
            content_tokens = q_toks

        # Normalized register extraction (S008 = S8 = %S8 = %S0008)
        regs = extract_registers(q_clean)

        # Unseen tokens check (excluding recognized register tokens)
        unseen_tokens = [
            t for t in content_tokens
            if self._df.get(t, 0) == 0 and not any(r["raw"] == t or r["short"] == t or t in r["forms"] for r in regs)
        ]

        if regs:
            # If query specified a register, confirm that at least one canonical register form exists in corpus
            reg_exists = any(
                self._df.get(r["canonical"].lower(), 0) > 0 or self._df.get(r["short"].lower(), 0) > 0
                for r in regs
            )
            if not reg_exists:
                return None
        elif content_tokens and (len(unseen_tokens) / float(len(content_tokens))) > max_unseen_ratio:
            # Off-topic query with unseen vocabulary
            return None

        GENERIC_DOMAIN_TERMS = {"cscape", "horner", "apg"}
        salient_tokens = [t for t in content_tokens if t not in GENERIC_DOMAIN_TERMS]
        if not salient_tokens:
            salient_tokens = content_tokens

        token_idfs = [(t, self._idf.get(t, 0.0)) for t in set(salient_tokens)]
        token_idfs.sort(key=lambda x: x[1], reverse=True)
        top_anchors = [t for t, _ in token_idfs[:2]]

        is_ladder_query = any(k in q_clean.lower() for k in ["rung", "rungs", "ladder", "coil", "contact"])

        from collections import Counter
        scored_chunks: List[Tuple[float, int, float, int, int]] = []
        k1 = 1.5
        b = 0.75

        content_stems = [stem(t) for t in content_tokens]

        for idx, chunk in enumerate(self.chunks):
            tf = Counter(chunk.tokens)
            sec_set = set(chunk.sec_tokens)
            txt_lower = chunk.text.lower()

            matched_content = [t for t in content_tokens if t in tf or t in sec_set]
            coverage = len(matched_content) / float(len(content_tokens))

            # ------------------------------------------------------------------
            # 1. Normalized Register Exact ID & System Register Table Row Boost
            # ------------------------------------------------------------------
            reg_boost = 0.0
            matched_reg = False
            for r in regs:
                prefix = r["prefix"]
                num = r["num"]
                # Exact word-bounded register identifier in text
                id_pattern = r"(?:^|[^\w%])(%?" + re.escape(prefix) + r"0*" + str(num) + r")\b"
                if re.search(id_pattern, chunk.text, re.IGNORECASE):
                    reg_boost += 90.0
                    matched_reg = True
                    matched_content.append(r["canonical"].lower())

                # Table row definition match (e.g. '%S8 | Always OFF | ALW_OFF | ...')
                if r["row_re"].search(chunk.text):
                    reg_boost += 130.0
                    matched_reg = True
                    if "system-register-tables" in chunk.source_path.lower() or "system registers" in chunk.section.lower():
                        reg_boost += 60.0

            # Anchor requirement: for multi-token substantive queries without register match,
            # candidate chunk must contain at least one of top salient anchors
            if not matched_reg and len(content_tokens) >= 2 and top_anchors:
                chunk_all_tokens = set(chunk.tokens) | sec_set | set(chunk.title_tokens) | set(chunk.heading_tokens)
                chunk_all_stems = {stem(t) for t in chunk_all_tokens}
                has_anchor = any(a in chunk_all_tokens or stem(a) in chunk_all_stems for a in top_anchors)
                if not has_anchor:
                    continue

            # ------------------------------------------------------------------
            # 2. Document Title and Heading Boosting (Manage Backups, etc.)
            # ------------------------------------------------------------------
            title_stems = {stem(t) for t in chunk.title_tokens} | set(chunk.title_tokens)
            heading_stems = {stem(t) for t in chunk.heading_tokens} | set(chunk.heading_tokens)

            # Match only on salient query tokens (excluding generic terms like 'cscape')
            title_matches = [
                t for t in salient_tokens
                if t in title_stems or stem(t) in title_stems or stem(t) in chunk.doc_title.lower()
            ]
            heading_matches = [
                t for t in salient_tokens
                if t in heading_stems or stem(t) in heading_stems
            ]

            title_boost = 0.0
            if title_matches:
                idf_sum = sum(self._idf.get(t, 2.0) for t in title_matches)
                title_boost += len(title_matches) * 40.0 + idf_sum * 5.0
                ratio = len(title_matches) / float(max(1, len([t for t in chunk.title_tokens if t not in GENERIC_DOMAIN_TERMS])))
                title_boost += ratio * 35.0

            heading_boost = 0.0
            if heading_matches:
                heading_boost += len(heading_matches) * 25.0

            # Gating filter: require sufficient keyword coverage, register match, or title/heading match
            has_title_heading_match = (len(title_matches) > 0 or len(heading_matches) > 0)
            if not matched_reg and not has_title_heading_match:
                min_matched_required = min(2, len(content_tokens))
                if coverage < min_coverage or len(matched_content) < min_matched_required:
                    continue

            # Official Cscape 10.2 Help manual provenance preference
            is_official = ("webhelp" in chunk.source_path.lower() or chunk.source_path.lower().endswith(".htm"))
            official_boost = 15.0 if is_official else 0.0

            # ------------------------------------------------------------------
            # 3. BM25 Text Relevance Score
            # ------------------------------------------------------------------
            doc_len = self._doc_lens[idx]
            s = reg_boost + title_boost + heading_boost + official_boost

            for qt in content_tokens:
                qt_stem = stem(qt)
                # Word match in token stream or section tokens
                f = tf.get(qt, 0)
                if f == 0 and qt_stem != qt:
                    f = sum(count for tok, count in tf.items() if stem(tok) == qt_stem)

                if f > 0:
                    denom = f + k1 * (1.0 - b + b * (doc_len / self._avgdl))
                    term_score = self._idf.get(qt, 0.0) * (f * (k1 + 1.0)) / denom
                    if qt in sec_set or qt_stem in sec_set:
                        term_score *= 2.0
                    s += term_score

            # Ladder / Rung query domain boost & ST negative penalty
            if is_ladder_query:
                if "advanced ladder logic" in chunk.category.lower() or "advanced ladder logic" in chunk.source_path.lower():
                    s += 30.0
                if "err_ladder_forbidden" in txt_lower or "forbidden" in txt_lower:
                    s -= 40.0

            if s >= min_score:
                scored_chunks.append((s, idx, reg_boost, len(title_matches), len(heading_matches)))

        if not scored_chunks:
            return None

        # Sort descending by composite relevance score
        scored_chunks.sort(reverse=True, key=lambda x: x[0])

        # ----------------------------------------------------------------------
        # 4. Passage Answering Confidence Gating
        # ----------------------------------------------------------------------
        top_score, top_idx, top_reg, top_title_m, top_head_m = scored_chunks[0]

        # If top score is below threshold, no passage answers query
        if top_score < min_score:
            return None

        # For multi-token substantive queries without register match:
        # Require that the top passage actually answers the query: sufficient content tokens and coverage
        if top_reg == 0.0 and len(content_tokens) >= 2:
            top_chunk = self.chunks[top_idx]
            top_tf = Counter(top_chunk.tokens)
            top_matched = [t for t in content_tokens if t in top_tf or stem(t) in top_tf]
            top_cov = len(top_matched) / float(len(content_tokens))

            # If no direct title match, require at least 2 distinct matched tokens and >= 25% coverage
            if top_title_m == 0:
                if len(top_matched) < min(2, len(content_tokens)) or (len(content_tokens) >= 4 and top_cov < 0.25):
                    return None
            else:
                if len(top_matched) < 1 or (len(content_tokens) >= 4 and top_cov < 0.20):
                    return None

        # Deduplicate to top_k distinct (source_path, base_section) results
        seen_sections: Set[Tuple[str, str]] = set()
        results: List[SearchResult] = []
        rank = 1
        reg_row_res = [r["row_re"] for r in regs] if regs else None

        for score, idx, _, _, _ in scored_chunks:
            chunk = self.chunks[idx]
            base_sec = re.sub(r"\s+\(Part\s+\d+\)", "", chunk.section).strip()
            key = (chunk.source_path, base_sec)
            if key not in seen_sections:
                seen_sections.add(key)
                snippet_terms = [r["canonical"].lower() for r in regs] + content_tokens
                snippet = extract_snippet(chunk.text, snippet_terms, max_len=200, reg_rows=reg_row_res)
                results.append(
                    SearchResult(
                        rank=rank,
                        score=round(score, 2),
                        source_path=chunk.source_path,
                        doc_title=chunk.doc_title,
                        category=chunk.category,
                        section=chunk.section,
                        snippet=snippet,
                        chunk_id=chunk.chunk_id,
                    )
                )
                rank += 1
                if len(results) >= top_k:
                    break

        return results if results else None

    def audit_anti_contamination(self, expected_answers: List[str]) -> Dict[str, Any]:
        """Verify that zero test suite expected answer strings appear in any indexed chunk."""
        if not self._built:
            self.build()

        leaks: List[Dict[str, Any]] = []
        for idx, expected in enumerate(expected_answers, 1):
            expected_clean = expected.strip()
            if not expected_clean:
                continue

            for c in self.chunks:
                if expected_clean in c.text:
                    leaks.append({
                        "case_index": idx,
                        "expected_text": expected_clean[:80],
                        "leaked_chunk_id": c.chunk_id,
                        "source_path": c.source_path,
                        "section": c.section,
                    })
                    break

        return {
            "total_checked": len(expected_answers),
            "leaks_found": len(leaks),
            "leak_free": len(leaks) == 0,
            "status": "PASS" if len(leaks) == 0 else "FAIL",
            "leaks": leaks,
        }

    def get_manifest(self) -> Dict[str, Any]:
        """Generate corpus manifest dictionary with category breakdowns."""
        if not self._built:
            self.build()

        total_pages = sum(d.estimated_pages for d in self.documents)
        total_chunks = len(self.chunks)

        categories: Dict[str, int] = {}
        for d in self.documents:
            categories[d.category] = categories.get(d.category, 0) + 1

        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "total_documents": len(self.documents),
            "total_estimated_pages": total_pages,
            "total_indexed_chunks": total_chunks,
            "categories_breakdown": categories,
            "documents": [d.to_dict() for d in self.documents],
        }
