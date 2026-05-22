#!/usr/bin/env python3
"""
Ingest all raw/machines/*.md files into wiki pages/machines/.
Creates one wiki page per source file with SCHEMA-compliant frontmatter,
updates manifest.json, index.md, and log.md.
"""
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

WIKI_DIR = Path.home() / ".local" / "share" / "penligent-local" / "wiki"
RAW_DIR = WIKI_DIR / "raw" / "machines"
PAGES_DIR = WIKI_DIR / "pages" / "machines"
MANIFEST_FILE = WIKI_DIR / "manifest.json"
INDEX_FILE = WIKI_DIR / "index.md"
LOG_FILE = WIKI_DIR / "log.md"

TODAY = date.today().isoformat()

TOOL_PATTERNS = re.compile(
    r'\b(nmap|gobuster|ffuf|feroxbuster|wfuzz|dirsearch|nikto|sqlmap|burpsuite|'
    r'hydra|hashcat|john|crackmapexec|evil-winrm|impacket|bloodhound|sharphound|'
    r'mimikatz|rubeus|kerbrute|chisel|socat|ligolo|metasploit|msfvenom|msfconsole|'
    r'nc|netcat|pwncat|linpeas|winpeas|linenum|pspy|ltrace|strace|gdb|pwndbg|'
    r'ghidra|ida|radare2|r2|binwalk|strings|file|objdump|readelf|ltrace|'
    r'wireshark|tcpdump|tshark|aircrack|hashid|haiti|cyberchef|openssl|'
    r'smbclient|smbmap|rpcclient|enum4linux|ldapsearch|dnsenum|dnsrecon|'
    r'curl|wget|python|python3|php|ruby|perl|bash|powershell|cmd|'
    r'docker|kubectl|aws|azure|gcloud|terraform)\b',
    re.IGNORECASE,
)

TECHNIQUE_PATTERNS = re.compile(
    r'\b(sql injection|sqli|xss|cross-site scripting|csrf|ssrf|xxe|ssti|'
    r'command injection|rce|remote code execution|lfi|rfi|path traversal|'
    r'directory traversal|file inclusion|buffer overflow|bof|rop|ret2libc|'
    r'heap overflow|use after free|uaf|format string|race condition|'
    r'privilege escalation|privesc|lateral movement|pass the hash|pth|'
    r'pass the ticket|ptt|kerberoasting|asreproasting|dcsync|golden ticket|'
    r'silver ticket|applocker bypass|amsi bypass|av bypass|antivirus bypass|'
    r'dll injection|dll hijacking|process injection|token impersonation|'
    r'port forwarding|tunneling|pivoting|credential dumping|lsass dump|'
    r'brute force|password spray|phishing|social engineering|'
    r'deserialization|insecure deserialization|prototype pollution|'
    r'open redirect|clickjacking|cors misconfiguration)\b',
    re.IGNORECASE,
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def load_manifest() -> dict:
    if not MANIFEST_FILE.exists():
        return {}
    try:
        return json.loads(MANIFEST_FILE.read_text())
    except Exception:
        return {}


def save_manifest(m: dict) -> None:
    MANIFEST_FILE.write_text(json.dumps(m, indent=2))


def slugify(name: str) -> str:
    s = re.sub(r'[^\w\s-]', '', name)
    s = re.sub(r'[\s_]+', '-', s).strip('-')
    return s[:120]


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter_dict, body) from a markdown file."""
    if not text.startswith('---'):
        return {}, text
    end = text.find('\n---', 3)
    if end == -1:
        return {}, text
    fm_block = text[3:end].strip()
    body = text[end + 4:].lstrip('\n')
    fm = {}
    for line in fm_block.splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and v and not v.startswith('-'):
                fm[k] = v
    # parse tags list
    tags_match = re.search(r'^tags:\s*\n((?:\s+-[^\n]+\n?)+)', fm_block, re.MULTILINE)
    if tags_match:
        tags = re.findall(r'-\s+"?([^"\n]+)"?', tags_match.group(1))
        fm['tags'] = [t.strip() for t in tags if t.strip()]
    return fm, body


def extract_info(body: str, title: str) -> dict:
    """Extract tools, techniques, and a one-line description from body text."""
    tools = sorted({m.lower() for m in TOOL_PATTERNS.findall(body)})
    techniques = sorted({m.lower() for m in TECHNIQUE_PATTERNS.findall(body)})

    # Grab first non-empty paragraph as description
    desc = ""
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('!') and not line.startswith('`'):
            desc = line[:200]
            break

    return {"tools": tools[:20], "techniques": techniques[:15], "description": desc}


def build_wiki_page(raw_path: Path, fm: dict, body: str, info: dict) -> str:
    title = fm.get('title') or raw_path.stem
    source = fm.get('source', '')
    author = fm.get('author', '')
    published = fm.get('published', '')
    raw_tags = fm.get('tags', [])
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]

    all_tags = list({t.lower() for t in raw_tags if t and t != 'clippings'})
    for tool in info['tools']:
        all_tags.append(tool)
    for tech in info['techniques'][:5]:
        all_tags.append(tech.replace(' ', '-'))
    all_tags = sorted(set(all_tags))[:20]

    tools_section = ""
    if info['tools']:
        tools_section = "\n## Tools Used\n\n" + "\n".join(f"- [[{t}]]" for t in info['tools']) + "\n"

    techniques_section = ""
    if info['techniques']:
        techniques_section = "\n## Techniques Used\n\n" + "\n".join(f"- [[{t}]]" for t in info['techniques']) + "\n"

    source_line = f"\n**Source:** {source}" if source else ""
    author_line = f"\n**Author:** {author}" if author else ""
    published_line = f"\n**Published:** {published}" if published else ""

    tags_yaml = "[" + ", ".join(all_tags[:15]) + "]" if all_tags else "[]"

    page = f"""---
title: {title}
category: machine
tags: {tags_yaml}
sources: [raw/machines/{raw_path.name}]
related: []
created: {TODAY}
updated: {TODAY}
---

# {title}
{source_line}{author_line}{published_line}

{body.strip()}
{tools_section}{techniques_section}"""

    return page


def append_to_index(title: str, slug: str, description: str) -> None:
    entry = f"- [{title}](pages/machines/{slug}.md) — {description[:120]}\n"
    if not INDEX_FILE.exists():
        INDEX_FILE.write_text("# Wiki Index\n\n## Machines\n\n")

    content = INDEX_FILE.read_text()

    if "## Machines" not in content:
        content += "\n## Machines\n\n"

    if f"pages/machines/{slug}.md" not in content:
        # Insert after the ## Machines header
        content = re.sub(
            r'(## Machines\n\n)',
            r'\1' + entry,
            content,
            count=1,
        )
        INDEX_FILE.write_text(content)


def log_summary(count: int, skipped: int) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_FILE.exists():
        LOG_FILE.write_text("# Wiki Log\n\n---\n\n")
    with LOG_FILE.open('a') as f:
        f.write(f"\n## [{TODAY}] ingest | machines — {count} pages created, {skipped} skipped (already up to date)\n")


def main() -> None:
    force = '--force' in sys.argv

    PAGES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()

    raw_files = sorted(RAW_DIR.glob("*.md"))
    total = len(raw_files)
    print(f"Found {total} raw machine files")

    created = 0
    skipped = 0
    errors = 0

    for i, raw_path in enumerate(raw_files, 1):
        key = str(raw_path.relative_to(WIKI_DIR))
        current_sha = sha256(raw_path)

        # Skip if already ingested and unchanged
        if not force and key in manifest and manifest[key].get('sha256') == current_sha:
            skipped += 1
            continue

        try:
            text = raw_path.read_text(errors='replace')
            fm, body = parse_frontmatter(text)
            info = extract_info(text, raw_path.stem)

            page_content = build_wiki_page(raw_path, fm, body, info)
            slug = slugify(raw_path.stem)
            out_path = PAGES_DIR / f"{slug}.md"

            out_path.write_text(page_content)

            title = fm.get('title') or raw_path.stem
            append_to_index(title, slug, info['description'])

            manifest[key] = {
                'ingested_at': TODAY,
                'sha256': current_sha,
                'pages_created': [f"machines/{slug}.md"],
            }
            created += 1

            if i % 50 == 0 or i == total:
                print(f"  [{i}/{total}] {created} created, {skipped} skipped, {errors} errors")

        except Exception as e:
            errors += 1
            print(f"  ERROR {raw_path.name}: {e}", file=sys.stderr)

    save_manifest(manifest)
    log_summary(created, skipped)
    print(f"\nDone. Created: {created}  Skipped: {skipped}  Errors: {errors}")
    print(f"Pages written to: {PAGES_DIR}")
    print(f"Manifest updated: {MANIFEST_FILE}")


if __name__ == '__main__':
    main()
