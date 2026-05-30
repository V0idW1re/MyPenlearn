"""
Lightweight in-process LRU + TTL cache for idempotent MCP tool reads.

The MCP server runs as a stdio subprocess that lives for the duration of a
Claude turn. Within one turn the agent often calls the same read tool
repeatedly (e.g. `workspace_ls` / `workspace_read` from several sub-tools
during a continuity check). Without caching each call re-runs file I/O, manifest
parsing, and / or full content search.

Cache state is per-process, so it never outlives a single turn — fresh state
every turn keeps stale-data risk bounded. Mutating tools call
`invalidate(namespace)` to drop their related entries within the same turn.
"""
from __future__ import annotations

import functools
import json
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable

DEFAULT_TTL = 60.0    # seconds; longer than a typical turn but bounded
DEFAULT_CAP = 64      # entries per namespace

_caches: dict[str, "_LRU"] = {}


class _LRU:
    __slots__ = ("cap", "ttl", "store")

    def __init__(self, cap: int, ttl: float):
        self.cap = cap
        self.ttl = ttl
        self.store: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()

    def get(self, key: str) -> Any | None:
        item = self.store.get(key)
        if item is None:
            return None
        ts, value = item
        if time.time() - ts > self.ttl:
            del self.store[key]
            return None
        self.store.move_to_end(key)
        return value

    def put(self, key: str, value: Any) -> None:
        if key in self.store:
            self.store.move_to_end(key)
        self.store[key] = (time.time(), value)
        if len(self.store) > self.cap:
            self.store.popitem(last=False)

    def clear(self) -> None:
        self.store.clear()


def _get_cache(namespace: str, ttl: float, cap: int) -> _LRU:
    c = _caches.get(namespace)
    if c is None:
        c = _LRU(cap, ttl)
        _caches[namespace] = c
    return c


def invalidate(namespace: str) -> None:
    """Drop all entries for a namespace. Mutating tool handlers call this."""
    c = _caches.get(namespace)
    if c is not None:
        c.clear()


def invalidate_all() -> None:
    """Drop every cache entry across all namespaces."""
    for c in _caches.values():
        c.clear()


def cached(
    namespace: str,
    ttl: float = DEFAULT_TTL,
    cap: int = DEFAULT_CAP,
) -> Callable[[Callable[[dict], Awaitable[Any]]], Callable[[dict], Awaitable[Any]]]:
    """
    Decorator for async MCP tool handlers `(args: dict) -> list[TextContent]`.
    The args dict is canonicalised to a JSON key. Un-serialisable args fall
    through to the underlying handler with no caching.
    """
    def decorator(fn: Callable[[dict], Awaitable[Any]]) -> Callable[[dict], Awaitable[Any]]:
        store = _get_cache(namespace, ttl, cap)

        @functools.wraps(fn)
        async def wrapper(args: dict) -> Any:
            try:
                key = json.dumps(args or {}, sort_keys=True, default=str)
            except TypeError:
                return await fn(args)
            hit = store.get(key)
            if hit is not None:
                return hit
            result = await fn(args)
            store.put(key, result)
            return result

        return wrapper

    return decorator
