"""
Central tool registry. Each tool module calls register() to add its
definitions and handlers. __main__.py queries this at startup.
"""
from mcp.types import Tool

_definitions: list[Tool] = []
_handlers: dict[str, any] = {}


def register(tool: Tool, handler) -> None:
    _definitions.append(tool)
    _handlers[tool.name] = handler


def get_tool_definitions() -> list[Tool]:
    return list(_definitions)


def get_handler(name: str):
    return _handlers.get(name)


# Import tool modules so they self-register via register() calls at import time.
# Add new modules here as they are created.
from . import htb_machines   # noqa: E402, F401
from . import recon          # noqa: E402, F401
from . import scanner        # noqa: E402, F401
from . import findings       # noqa: E402, F401
from . import web            # noqa: E402, F401
from . import network        # noqa: E402, F401
from . import exploit        # noqa: E402, F401
from . import post_exploit   # noqa: E402, F401
from . import passwords      # noqa: E402, F401
from . import crypto         # noqa: E402, F401
from . import osint          # noqa: E402, F401
from . import workspace      # noqa: E402, F401
from . import report         # noqa: E402, F401
from . import guardrails     # noqa: E402, F401
from . import plan           # noqa: E402, F401
from . import utils          # noqa: E402, F401
