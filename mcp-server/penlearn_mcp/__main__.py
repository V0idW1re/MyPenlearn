import asyncio
import logging

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .db import init_db
from .tools import register_all

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("penlearn-mcp")

app = Server("penlearn-local")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return register_all.get_tool_definitions()


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    handler = register_all.get_handler(name)
    if handler is None:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    try:
        result = await handler(arguments)
        if isinstance(result, list) and result and isinstance(result[0], TextContent):
            return result
        return [TextContent(type="text", text=str(result))]
    except Exception as exc:
        log.exception("Tool %s raised an error", name)
        return [TextContent(type="text", text=f"Error: {exc}")]


async def _serve() -> None:
    await init_db()
    log.info("penlearn-local MCP server starting (stdio)")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
