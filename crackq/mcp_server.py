"""CRACKQ MCP server — exposes scan as an MCP tool for Cognis.Studio."""
from cognis_core.mcp import build_mcp_server
from crackq.core import scan, TOOL_NAME

_DESC = (
    "Self-hosted password cracking queue"
    " — multi-user hashcat with audit log"
)
run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description=_DESC,
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()
