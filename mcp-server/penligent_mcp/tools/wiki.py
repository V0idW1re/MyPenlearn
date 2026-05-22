"""
Wiki / Second Brain tools.
Manages a persistent hacking knowledge base at ~/.local/share/penligent-local/wiki/.
Raw sources are immutable; Claude owns the pages/ layer.
"""
import hashlib
import json
import re
import time
from datetime import date
from pathlib import Path

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s
from ._cache import cached, invalidate as cache_invalidate

WIKI_DIR = Path.home() / ".local" / "share" / "penligent-local" / "wiki"
RAW_DIR = WIKI_DIR / "raw"
PAGES_DIR = WIKI_DIR / "pages"
INDEX_FILE = WIKI_DIR / "index.md"
LOG_FILE = WIKI_DIR / "log.md"
MANIFEST_FILE = WIKI_DIR / "manifest.json"
SCHEMA_FILE = WIKI_DIR / "SCHEMA.md"

_RAW_SUFFIXES = {".md", ".txt", ".rst"}


def _ensure_dirs() -> None:
    for d in (RAW_DIR, PAGES_DIR, WIKI_DIR):
        d.mkdir(parents=True, exist_ok=True)


def _load_manifest() -> dict:
    if not MANIFEST_FILE.exists():
        return {}
    try:
        return json.loads(MANIFEST_FILE.read_text())
    except Exception:
        return {}


def _save_manifest(m: dict) -> None:
    MANIFEST_FILE.write_text(json.dumps(m, indent=2))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _all_raw_files() -> list[Path]:
    if not RAW_DIR.exists():
        return []
    return [p for p in RAW_DIR.rglob("*") if p.is_file() and p.suffix in _RAW_SUFFIXES]


# ---------------------------------------------------------------------------
# wiki_status
# ---------------------------------------------------------------------------

@cached("wiki", ttl=30)
async def _wiki_status(_args: dict) -> list[TextContent]:
    _ensure_dirs()
    manifest = _load_manifest()
    raw_files = _all_raw_files()

    pending, stale, ingested = [], [], []
    for f in raw_files:
        key = str(f.relative_to(WIKI_DIR))
        if key not in manifest:
            pending.append(key)
        else:
            current_sha = _sha256(f)
            if manifest[key].get("sha256") != current_sha:
                stale.append(key)
            else:
                ingested.append(key)

    pages = list(PAGES_DIR.rglob("*.md")) if PAGES_DIR.exists() else []

    lines = [
        "## Wiki Status",
        f"Raw files total : {len(raw_files)}",
        f"Ingested        : {len(ingested)}",
        f"Pending         : {len(pending)}",
        f"Stale (modified): {len(stale)}",
        f"Wiki pages      : {len(pages)}",
        "",
    ]
    if pending:
        lines.append("### Pending (not yet ingested)")
        lines.extend(f"  {p}" for p in pending[:20])
        if len(pending) > 20:
            lines.append(f"  ... and {len(pending) - 20} more")
        lines.append("")
    if stale:
        lines.append("### Stale (file changed since last ingest)")
        lines.extend(f"  {s}" for s in stale[:20])
        lines.append("")
    if not pending and not stale:
        lines.append("All raw files are ingested and up to date.")

    return _ok("\n".join(lines))


register(
    Tool(
        name="wiki_status",
        description=(
            "Show the ingest status of the knowledge base: how many raw files are ingested, "
            "pending, or stale (modified since last ingest). Run this to see what needs processing."
        ),
        inputSchema=_s(),
    ),
    _wiki_status,
)


# ---------------------------------------------------------------------------
# wiki_read_raw
# ---------------------------------------------------------------------------

@cached("wiki")
async def _wiki_read_raw(args: dict) -> list[TextContent]:
    raw_path = args.get("path", "").strip()
    if not raw_path:
        return _ok("[wiki_read_raw] path is required")

    # Accept relative (to wiki/ or raw/) or absolute
    candidates = [
        WIKI_DIR / raw_path,
        RAW_DIR / raw_path,
        Path(raw_path),
    ]
    target = next((p for p in candidates if p.exists() and p.is_file()), None)
    if target is None:
        return _ok(f"[wiki_read_raw] File not found: {raw_path}")

    # Ensure it's inside wiki/raw/
    try:
        target.resolve().relative_to(RAW_DIR.resolve())
    except ValueError:
        return _ok(f"[wiki_read_raw] Path must be inside wiki/raw/: {raw_path}")

    content = target.read_text(errors="replace")
    rel = str(target.relative_to(WIKI_DIR))
    header = f"## Raw source: {rel}\n\n"
    return _ok(header + content)


register(
    Tool(
        name="wiki_read_raw",
        description=(
            "Read a raw source file from wiki/raw/ in preparation for ingesting it into the wiki. "
            "Pass the path relative to wiki/ (e.g. 'raw/books/chapter3.md') or relative to raw/ "
            "(e.g. 'books/chapter3.md')."
        ),
        inputSchema=_s(["path"], path=("string", "Path to raw file, relative to wiki/ or raw/")),
    ),
    _wiki_read_raw,
)


# ---------------------------------------------------------------------------
# wiki_read_page
# ---------------------------------------------------------------------------

@cached("wiki")
async def _wiki_read_page(args: dict) -> list[TextContent]:
    page_path = args.get("page_path", "").strip()
    if not page_path:
        return _ok("[wiki_read_page] page_path is required")

    candidates = [
        PAGES_DIR / page_path,
        WIKI_DIR / page_path,
        Path(page_path),
    ]
    target = next((p for p in candidates if p.exists() and p.is_file()), None)
    if target is None:
        return _ok(f"[wiki_read_page] Page not found: {page_path}")

    content = target.read_text(errors="replace")
    rel = str(target.relative_to(WIKI_DIR))
    return _ok(f"## Wiki page: {rel}\n\n{content}")


register(
    Tool(
        name="wiki_read_page",
        description=(
            "Read a synthesized wiki page. Pass path relative to pages/ "
            "(e.g. 'tools/sqlmap.md') or relative to wiki/ (e.g. 'pages/tools/sqlmap.md')."
        ),
        inputSchema=_s(["page_path"], page_path=("string", "Path to wiki page, relative to pages/ or wiki/")),
    ),
    _wiki_read_page,
)


# ---------------------------------------------------------------------------
# wiki_write_page
# ---------------------------------------------------------------------------

async def _wiki_write_page(args: dict) -> list[TextContent]:
    page_path = args.get("page_path", "").strip()
    content = args.get("content", "")
    if not page_path:
        return _ok("[wiki_write_page] page_path is required")
    if not content:
        return _ok("[wiki_write_page] content is required")
    cache_invalidate("wiki")

    target = PAGES_DIR / page_path
    # Safety: must stay inside pages/
    try:
        target.resolve().relative_to(PAGES_DIR.resolve())
    except ValueError:
        return _ok(f"[wiki_write_page] Path escapes pages/: {page_path}")

    target.parent.mkdir(parents=True, exist_ok=True)
    existed = target.exists()
    target.write_text(content)
    action = "updated" if existed else "created"
    return _ok(f"[wiki_write_page] {action}: pages/{page_path}")


register(
    Tool(
        name="wiki_write_page",
        description=(
            "Write or update a synthesized wiki page. page_path is relative to pages/ "
            "(e.g. 'tools/sqlmap.md'). Creates parent directories automatically. "
            "Use this to create new pages or merge new knowledge into existing ones."
        ),
        inputSchema=_s(
            ["page_path", "content"],
            page_path=("string", "Destination path relative to pages/ (e.g. 'techniques/sqli.md')"),
            content=("string", "Full markdown content of the page including YAML frontmatter"),
        ),
    ),
    _wiki_write_page,
)


# ---------------------------------------------------------------------------
# wiki_mark_ingested
# ---------------------------------------------------------------------------

async def _wiki_mark_ingested(args: dict) -> list[TextContent]:
    raw_path = args.get("raw_path", "").strip()
    pages_created = args.get("pages_created", [])
    if not raw_path:
        return _ok("[wiki_mark_ingested] raw_path is required")
    cache_invalidate("wiki")

    candidates = [WIKI_DIR / raw_path, RAW_DIR / raw_path, Path(raw_path)]
    target = next((p for p in candidates if p.exists() and p.is_file()), None)
    if target is None:
        return _ok(f"[wiki_mark_ingested] File not found: {raw_path}")

    # Normalise key to be relative to wiki/
    try:
        key = str(target.resolve().relative_to(WIKI_DIR.resolve()))
    except ValueError:
        key = raw_path

    manifest = _load_manifest()
    manifest[key] = {
        "ingested_at": date.today().isoformat(),
        "sha256": _sha256(target),
        "pages_created": pages_created if isinstance(pages_created, list) else [],
    }
    _save_manifest(manifest)
    return _ok(f"[wiki_mark_ingested] Recorded: {key} ({len(pages_created)} pages)")


register(
    Tool(
        name="wiki_mark_ingested",
        description=(
            "Mark a raw file as fully ingested in the manifest. Call this after all wiki pages "
            "have been written for a source. Records sha256 and today's date so stale detection works."
        ),
        inputSchema=_s(
            ["raw_path"],
            raw_path=("string", "Path to raw file relative to wiki/ or raw/"),
            pages_created={
                "type": "array",
                "items": {"type": "string"},
                "description": "List of page paths created or updated during this ingest (relative to pages/)",
            },
        ),
    ),
    _wiki_mark_ingested,
)


# ---------------------------------------------------------------------------
# wiki_query
# ---------------------------------------------------------------------------

@cached("wiki")
async def _wiki_query(args: dict) -> list[TextContent]:
    keywords = args.get("keywords", "").strip()
    top_k = int(args.get("top_k", 8))
    if not keywords:
        return _ok("[wiki_query] keywords is required")

    if not PAGES_DIR.exists():
        return _ok("[wiki_query] No wiki pages exist yet. Drop files into wiki/raw/ and run wiki_ingest_all.")

    terms = [t.lower() for t in keywords.split()]
    results: list[tuple[int, str, str]] = []  # (score, rel_path, excerpt)

    for md_file in PAGES_DIR.rglob("*.md"):
        try:
            text = md_file.read_text(errors="replace")
        except Exception:
            continue
        text_lower = text.lower()
        score = sum(text_lower.count(t) for t in terms)
        if score == 0:
            continue

        lines = text.splitlines()
        excerpts = []
        for i, line in enumerate(lines):
            if any(t in line.lower() for t in terms):
                start = max(0, i - 1)
                end = min(len(lines), i + 4)
                excerpts.append("\n".join(lines[start:end]))
                if len(excerpts) >= 2:
                    break

        rel = str(md_file.relative_to(PAGES_DIR))
        excerpt_text = "\n---\n".join(excerpts) if excerpts else lines[0] if lines else ""
        results.append((score, rel, excerpt_text))

    results.sort(key=lambda x: -x[0])
    results = results[:top_k]

    if not results:
        return _ok(
            f"[wiki_query] No pages match: {keywords}\n"
            "The wiki may not have knowledge on this topic yet. "
            "Check wiki_status for pending raw files to ingest."
        )

    parts = [f"## Wiki Query: '{keywords}' — {len(results)} result(s)\n"]
    for _score, rel, excerpt in results:
        parts.append(f"### [{rel}](pages/{rel})\n```\n{excerpt}\n```")

    parts.append(
        "\nTo read a full page: call wiki_read_page with the path shown above (e.g. 'tools/nmap.md')."
    )
    return _ok("\n\n".join(parts))


register(
    Tool(
        name="wiki_query",
        description=(
            "Search the wiki knowledge base by keywords. Returns ranked page excerpts. "
            "Call this BEFORE starting any task to retrieve relevant techniques, tool preferences, "
            "and methodology from your accumulated knowledge."
        ),
        inputSchema=_s(
            ["keywords"],
            keywords=("string", "Space-separated keywords to search (e.g. 'sqlmap injection bypass')"),
            top_k=("integer", "Maximum number of results to return (default 8)"),
        ),
    ),
    _wiki_query,
)


# ---------------------------------------------------------------------------
# wiki_ingest_all
# ---------------------------------------------------------------------------

@cached("wiki", ttl=15)
async def _wiki_ingest_all(_args: dict) -> list[TextContent]:
    """Return a manifest of all pending/stale files for Claude to process one by one."""
    _ensure_dirs()
    manifest = _load_manifest()
    raw_files = _all_raw_files()

    pending, stale = [], []
    for f in raw_files:
        key = str(f.relative_to(WIKI_DIR))
        if key not in manifest:
            pending.append(str(f.relative_to(WIKI_DIR)))
        elif manifest[key].get("sha256") != _sha256(f):
            stale.append(str(f.relative_to(WIKI_DIR)))

    queue = pending + stale
    if not queue:
        return _ok("All raw files are already ingested and up to date. Nothing to do.")

    lines = [
        f"## Ingest Queue — {len(queue)} file(s) to process",
        "",
        "Process each file below by:",
        "1. Calling wiki_read_raw(path) to read the source",
        "2. Extracting all techniques, tools, CVEs, and methodology",
        "3. Calling wiki_write_page() for each synthesized page",
        "4. Calling wiki_mark_ingested(path, pages_created=[...])",
        "5. Updating index.md via wiki_write_page('index.md', ...)",  # not pages-relative but handled
        "6. Calling wiki_log() with the ingest summary",
        "",
        "### Pending (never ingested)",
    ]
    for p in pending:
        lines.append(f"  - {p}")
    if stale:
        lines.append("\n### Stale (file changed since last ingest)")
        for s in stale:
            lines.append(f"  - {s}")
    lines.append(f"\nTotal: {len(queue)} files. Start with the first one.")
    return _ok("\n".join(lines))


register(
    Tool(
        name="wiki_ingest_all",
        description=(
            "List all raw files that are pending or stale (modified since last ingest). "
            "Returns the ordered queue to process. Claude then works through each file: "
            "read raw → write pages → mark ingested → update index → log."
        ),
        inputSchema=_s(),
    ),
    _wiki_ingest_all,
)


# ---------------------------------------------------------------------------
# wiki_log
# ---------------------------------------------------------------------------

async def _wiki_log(args: dict) -> list[TextContent]:
    entry = args.get("entry", "").strip()
    if not entry:
        return _ok("[wiki_log] entry is required")
    cache_invalidate("wiki")
    _ensure_dirs()
    today = date.today().isoformat()
    if not entry.startswith("## ["):
        entry = f"## [{today}] {entry}"

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_FILE.exists():
        LOG_FILE.write_text("# Wiki Log\n\n---\n\n")

    with LOG_FILE.open("a") as f:
        f.write(f"\n{entry}\n")

    return _ok(f"[wiki_log] Appended to log.md")


register(
    Tool(
        name="wiki_log",
        description=(
            "Append an entry to wiki/log.md. Use after each ingest, lint, or significant query. "
            "Format: 'ingest | source-name — N pages created' or 'lint | N issues found'."
        ),
        inputSchema=_s(
            ["entry"],
            entry=("string", "Log entry text. Prefix with '## [YYYY-MM-DD] type | ' or it will be auto-prefixed."),
        ),
    ),
    _wiki_log,
)


# ---------------------------------------------------------------------------
# wiki_lint
# ---------------------------------------------------------------------------

@cached("wiki", ttl=30)
async def _wiki_lint(_args: dict) -> list[TextContent]:
    _ensure_dirs()
    manifest = _load_manifest()
    issues: list[str] = []

    # 1. Pages in index.md that don't exist on disk
    if INDEX_FILE.exists():
        index_text = INDEX_FILE.read_text()
        linked = re.findall(r'\[.*?\]\((pages/[^\)]+)\)', index_text)
        for link in linked:
            target = WIKI_DIR / link
            if not target.exists():
                issues.append(f"BROKEN_LINK index.md → {link} (file missing)")

    # 2. Pages on disk not listed in index.md
    index_text = INDEX_FILE.read_text() if INDEX_FILE.exists() else ""
    orphan_pages = []
    if PAGES_DIR.exists():
        for md in PAGES_DIR.rglob("*.md"):
            rel = "pages/" + str(md.relative_to(PAGES_DIR))
            if rel not in index_text:
                orphan_pages.append(str(md.relative_to(PAGES_DIR)))
    if orphan_pages:
        issues.append(f"ORPHAN_PAGES {len(orphan_pages)} page(s) not listed in index.md:")
        for p in orphan_pages[:10]:
            issues.append(f"  - {p}")

    # 3. Stale raw files
    stale = []
    for f in _all_raw_files():
        key = str(f.relative_to(WIKI_DIR))
        if key in manifest and manifest[key].get("sha256") != _sha256(f):
            stale.append(key)
    if stale:
        issues.append(f"STALE_RAW {len(stale)} raw file(s) changed since ingest:")
        for s in stale[:10]:
            issues.append(f"  - {s}")

    # 4. Pending raw files
    pending_count = sum(
        1 for f in _all_raw_files()
        if str(f.relative_to(WIKI_DIR)) not in manifest
    )
    if pending_count:
        issues.append(f"PENDING_RAW {pending_count} raw file(s) never ingested — run wiki_ingest_all")

    # 5. Pages with no outbound cross-links
    no_links = []
    if PAGES_DIR.exists():
        for md in PAGES_DIR.rglob("*.md"):
            content = md.read_text(errors="replace")
            if not re.search(r'\[\[.+?\]\]', content):
                no_links.append(str(md.relative_to(PAGES_DIR)))
    if no_links:
        issues.append(f"NO_CROSSLINKS {len(no_links)} page(s) have no [[wiki links]]:")
        for p in no_links[:10]:
            issues.append(f"  - {p}")

    if not issues:
        return _ok("Wiki lint: no issues found. Knowledge base is healthy.")

    return _ok("## Wiki Lint Report\n\n" + "\n".join(issues))


register(
    Tool(
        name="wiki_lint",
        description=(
            "Health-check the wiki: find broken index links, orphan pages not in index, "
            "stale raw files, pending raw files, and pages with no cross-links. "
            "Run periodically to keep the knowledge base clean."
        ),
        inputSchema=_s(),
    ),
    _wiki_lint,
)
