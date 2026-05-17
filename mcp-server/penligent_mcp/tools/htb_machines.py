import json
import os
from pathlib import Path

import httpx

from .register_all import register
from mcp.types import Tool
from ..db import get_db

HTB_API = "https://labs.hackthebox.com/api/v4"


def _token() -> str:
    t = os.environ.get("HTB_APP_TOKEN", "")
    if not t:
        raise RuntimeError(
            "HTB_APP_TOKEN env var not set. "
            "Export it before starting the MCP server."
        )
    return t


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {_token()}",
        "Accept": "application/json",
        "User-Agent": "penligent-local/0.1",
    }


async def _htb_get(path: str, params: dict | None = None) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{HTB_API}{path}", headers=_headers(), params=params)
        r.raise_for_status()
        return r.json()


async def _htb_post(path: str, body: dict) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(f"{HTB_API}{path}", headers=_headers(), json=body)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# htb_machines_list
# ---------------------------------------------------------------------------

async def _search_paginated(endpoint: str, name_filter: str, max_pages: int = 10) -> list:
    """Walk a paginated machine endpoint, returning name-filtered results."""
    matches = []
    for page in range(1, max_pages + 1):
        data = await _htb_get(endpoint, {"per_page": 25, "page": page})
        machines = data.get("data", [])
        if not machines:
            break
        if name_filter:
            matches.extend(m for m in machines if name_filter in m.get("name", "").lower())
            if matches:
                break
        else:
            return machines  # no filter: just first page of active machines
        meta = data.get("meta", {})
        if page >= meta.get("last_page", 1):
            break
    return matches


async def _htb_machines_list(args: dict) -> str:
    name_filter = (args.get("name") or "").strip().lower()

    if name_filter:
        # Search active machines first, then retired
        matches = await _search_paginated("/machine/paginated", name_filter)
        if not matches:
            matches = await _search_paginated("/machine/list/retired/paginated", name_filter)
    else:
        matches = await _search_paginated("/machine/paginated", "")

    if not matches:
        return "No machines found matching that filter."

    rows = []
    for m in matches:
        retired = m.get("retired", not m.get("active", True))
        rows.append(
            f"id={m['id']} name={m['name']} os={m.get('os','?')} "
            f"difficulty={m.get('difficultyText', m.get('difficulty','?'))} "
            f"points={m.get('points','?')} retired={retired} free={m.get('free', False)}"
        )
    return "\n".join(rows)


register(
    Tool(
        name="htb_machines_list",
        description=(
            "List HackTheBox machines. Optionally filter by name substring. "
            "Returns id, name, OS, difficulty, points, and retired status."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Optional case-insensitive name filter (e.g. 'cap', 'lame')",
                }
            },
        },
    ),
    _htb_machines_list,
)


# ---------------------------------------------------------------------------
# htb_machines_get_active
# ---------------------------------------------------------------------------

async def _htb_machines_get_active(args: dict) -> str:
    data = await _htb_get("/machine/active")
    machine = data.get("info")
    if not machine:
        return "No machine currently active."
    return json.dumps(machine, indent=2)


register(
    Tool(
        name="htb_machines_get_active",
        description="Return the currently active (spawned) HTB machine for your account.",
        inputSchema={"type": "object", "properties": {}},
    ),
    _htb_machines_get_active,
)


# ---------------------------------------------------------------------------
# htb_machines_spawn
# ---------------------------------------------------------------------------

async def _htb_machines_spawn(args: dict) -> str:
    machine_id = args.get("machine_id")
    project_id = args.get("project_id")

    if not machine_id:
        return "Error: machine_id is required."

    data = await _htb_post("/vm/spawn", {"id": int(machine_id)})

    ip = data.get("ip") or data.get("message", "")
    container_id = str(data.get("id", ""))

    # Persist IP + container ref into the project row
    if project_id:
        async with get_db() as db:
            await db.execute(
                "UPDATE projects SET htb_machine_id=?, htb_container_id=?, updated_at=strftime('%s','now') WHERE id=?",
                (int(machine_id), container_id, int(project_id)),
            )
            proj = await (
                await db.execute(
                    "SELECT name FROM projects WHERE id=?", (int(project_id),)
                )
            ).fetchone()
            await db.commit()

        # Write machine.md into the workspace
        if proj:
            workspace = (
                Path.home()
                / "penligent"
                / "projects"
                / proj["name"]
                / "workspace"
            )
            workspace.mkdir(parents=True, exist_ok=True)
            machine_info = await _htb_get(f"/machine/profile/{machine_id}")
            m = machine_info.get("info", {})
            # ip may come from the spawn response or from the profile after spawn
            resolved_ip = ip or m.get("ip", "unknown")
            md = (
                f"# {m.get('name', 'Machine')}\n\n"
                f"- **IP:** {resolved_ip}\n"
                f"- **OS:** {m.get('os', '?')}\n"
                f"- **Difficulty:** {m.get('difficultyText', '?')}\n"
                f"- **Points:** {m.get('points', '?')}\n"
                f"- **HTB ID:** {machine_id}\n"
                f"- **Container ID:** {container_id}\n"
            )
            (workspace / "machine.md").write_text(md)

    return json.dumps({"spawned": True, "ip": ip, "container_id": container_id})


register(
    Tool(
        name="htb_machines_spawn",
        description=(
            "Spawn an HTB machine by its numeric ID. "
            "Pass project_id to auto-update the project record and write workspace/machine.md."
        ),
        inputSchema={
            "type": "object",
            "required": ["machine_id"],
            "properties": {
                "machine_id": {
                    "type": "integer",
                    "description": "HTB machine ID (from htb_machines_list)",
                },
                "project_id": {
                    "type": "integer",
                    "description": "Local project ID to update (optional)",
                },
            },
        },
    ),
    _htb_machines_spawn,
)


# ---------------------------------------------------------------------------
# htb_machines_stop
# ---------------------------------------------------------------------------

async def _htb_machines_stop(args: dict) -> str:
    machine_id = args.get("machine_id")
    if not machine_id:
        return "Error: machine_id is required."
    data = await _htb_post("/vm/terminate", {"id": int(machine_id)})
    return json.dumps({"stopped": True, "response": data})


register(
    Tool(
        name="htb_machines_stop",
        description="Terminate the currently running HTB machine.",
        inputSchema={
            "type": "object",
            "required": ["machine_id"],
            "properties": {
                "machine_id": {"type": "integer", "description": "HTB machine ID"}
            },
        },
    ),
    _htb_machines_stop,
)


# ---------------------------------------------------------------------------
# htb_machines_submit_flag
# ---------------------------------------------------------------------------

async def _htb_machines_submit_flag(args: dict) -> str:
    machine_id = args.get("machine_id")
    flag = args.get("flag")
    flag_type = args.get("flag_type", "user")  # "user" or "root"

    if not machine_id or not flag:
        return "Error: machine_id and flag are required."

    data = await _htb_post(
        "/machine/own",
        {"id": int(machine_id), "flag": flag, "difficulty": 50, "type": flag_type},
    )
    return json.dumps(data)


register(
    Tool(
        name="htb_machines_submit_flag",
        description='Submit a user or root flag for an HTB machine. flag_type must be "user" or "root".',
        inputSchema={
            "type": "object",
            "required": ["machine_id", "flag"],
            "properties": {
                "machine_id": {"type": "integer"},
                "flag": {"type": "string", "description": "The flag hash to submit"},
                "flag_type": {
                    "type": "string",
                    "enum": ["user", "root"],
                    "description": "Which flag — user or root",
                },
            },
        },
    ),
    _htb_machines_submit_flag,
)


# ---------------------------------------------------------------------------
# htb_machines_search
# ---------------------------------------------------------------------------

async def _htb_machines_search(args: dict) -> str:
    name = (args.get("name") or "").strip().lower()
    os_filter = (args.get("os") or "").strip().lower()
    difficulty = (args.get("difficulty") or "").strip().lower()
    retired = args.get("retired", None)  # None = both, True = retired only, False = active only

    endpoints = ["/machine/paginated"]
    if retired is True or retired is None:
        endpoints.append("/machine/list/retired/paginated")

    all_matches = []
    seen_ids = set()
    for ep in endpoints:
        for page in range(1, 20):
            data = await _htb_get(ep, {"per_page": 25, "page": page})
            machines = data.get("data", [])
            if not machines:
                break
            for m in machines:
                if m["id"] in seen_ids:
                    continue
                seen_ids.add(m["id"])
                if name and name not in m.get("name", "").lower():
                    continue
                if os_filter and os_filter not in (m.get("os") or "").lower():
                    continue
                if difficulty and difficulty not in (m.get("difficultyText") or m.get("difficulty") or "").lower():
                    continue
                all_matches.append(m)
            meta = data.get("meta", {})
            if page >= meta.get("last_page", 1):
                break
        if len(all_matches) >= 50:
            break

    if not all_matches:
        return "No machines found matching the given filters."

    rows = []
    for m in all_matches[:50]:
        is_retired = m.get("retired", not m.get("active", True))
        rows.append(
            f"id={m['id']} name={m['name']} os={m.get('os','?')} "
            f"difficulty={m.get('difficultyText', m.get('difficulty','?'))} "
            f"points={m.get('points','?')} retired={is_retired} free={m.get('free', False)}"
        )
    return "\n".join(rows)


register(
    Tool(
        name="htb_machines_search",
        description="Search HTB machines with optional filters for name, OS, difficulty, and retired status.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name substring filter (case-insensitive)"},
                "os": {"type": "string", "description": "OS filter: Linux, Windows, FreeBSD, etc."},
                "difficulty": {"type": "string", "description": "Difficulty filter: easy, medium, hard, insane"},
                "retired": {"type": "boolean", "description": "True=retired only, False=active only, omit=both"},
            },
        },
    ),
    _htb_machines_search,
)


# ---------------------------------------------------------------------------
# htb_machine_info
# ---------------------------------------------------------------------------

async def _htb_machine_info(args: dict) -> str:
    machine_id = args.get("machine_id")
    if not machine_id:
        return "Error: machine_id is required."
    data = await _htb_get(f"/machine/profile/{machine_id}")
    m = data.get("info", data)
    return json.dumps(m, indent=2)


register(
    Tool(
        name="htb_machine_info",
        description="Get detailed information about a specific HTB machine by ID.",
        inputSchema={
            "type": "object",
            "required": ["machine_id"],
            "properties": {
                "machine_id": {"type": "integer", "description": "HTB machine numeric ID"},
            },
        },
    ),
    _htb_machine_info,
)


# ---------------------------------------------------------------------------
# htb_profile
# ---------------------------------------------------------------------------

async def _htb_profile(args: dict) -> str:
    data = await _htb_get("/user/info")
    user = data.get("info", data)
    lines = []
    for k in ("id", "name", "email", "rank", "points", "owns", "bloods", "country", "level", "pro_labs_count"):
        if k in user:
            lines.append(f"  {k}: {user[k]}")
    return "HTB Profile:\n" + "\n".join(lines)


register(
    Tool(
        name="htb_profile",
        description="Retrieve your HTB account profile (name, rank, points, owns).",
        inputSchema={"type": "object", "properties": {}},
    ),
    _htb_profile,
)


# ---------------------------------------------------------------------------
# htb_challenges_list
# ---------------------------------------------------------------------------

async def _htb_challenges_list(args: dict) -> str:
    category = (args.get("category") or "").strip().lower()
    difficulty = (args.get("difficulty") or "").strip().lower()
    data = await _htb_get("/challenge/list")
    challenges = data.get("challenges", data) if isinstance(data, dict) else data
    if not isinstance(challenges, list):
        return f"Unexpected response: {json.dumps(data)[:500]}"
    filtered = []
    for c in challenges:
        if category and category not in (c.get("category_name") or "").lower():
            continue
        if difficulty and difficulty not in (c.get("difficulty") or "").lower():
            continue
        filtered.append(c)
    if not filtered:
        return "No challenges found matching the filters."
    rows = []
    for c in filtered[:50]:
        rows.append(
            f"id={c.get('id','?')} name={c.get('name','?')} "
            f"category={c.get('category_name','?')} difficulty={c.get('difficulty','?')} "
            f"points={c.get('points','?')} solves={c.get('solves','?')}"
        )
    return f"HTB Challenges ({len(filtered)} matching):\n" + "\n".join(rows)


register(
    Tool(
        name="htb_challenges_list",
        description="List HTB challenges with optional category and difficulty filters.",
        inputSchema={
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Category filter: web, pwn, crypto, forensics, misc, reversing, etc."},
                "difficulty": {"type": "string", "description": "Difficulty filter: easy, medium, hard, insane"},
            },
        },
    ),
    _htb_challenges_list,
)


# ---------------------------------------------------------------------------
# htb_activity
# ---------------------------------------------------------------------------

async def _htb_activity(args: dict) -> str:
    limit = int(args.get("limit", 20))
    data = await _htb_get("/user/activity")
    activity = data.get("profile", {}).get("activity", []) if isinstance(data, dict) else []
    if not activity:
        # Fallback: try direct activity endpoint
        data2 = await _htb_get("/user/info")
        uid = data2.get("info", {}).get("id")
        if uid:
            data3 = await _htb_get(f"/user/profile/activity/{uid}")
            activity = data3.get("profile", {}).get("activity", [])
    if not activity:
        return "No activity data returned."
    lines = ["HTB Activity (most recent first):"]
    for a in activity[:limit]:
        obj_type = a.get("object_type", "?")
        name = a.get("name", "?")
        type_ = a.get("type", "?")
        date = a.get("date", "?")
        blood = " [BLOOD]" if a.get("first_blood") else ""
        lines.append(f"  {date}  {type_:12s} {obj_type:12s} {name}{blood}")
    return "\n".join(lines)


register(
    Tool(
        name="htb_activity",
        description="Show recent HTB activity for your account (solved machines, challenges, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max activity entries to return (default: 20)"},
            },
        },
    ),
    _htb_activity,
)
