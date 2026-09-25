"""MCP surface is balance, quote_payment, pay, history, channels, xbt402_pay."""

from __future__ import annotations

import unittest

from agentwallet.mcp_server import (
    FORBIDDEN_MCP_TOOLS,
    MCP_TOOL_NAMES,
    _build_server,
    registered_tool_names,
)


class McpToolListTests(unittest.TestCase):
    def test_published_name_set(self):
        self.assertEqual(
            MCP_TOOL_NAMES,
            {"balance", "quote_payment", "pay", "history", "channels", "xbt402_pay"},
        )
        self.assertTrue(FORBIDDEN_MCP_TOOLS.isdisjoint(MCP_TOOL_NAMES))

    def test_registered_tools_match_exactly(self):
        names = registered_tool_names()
        self.assertEqual(names, MCP_TOOL_NAMES)
        self.assertNotIn("approve", names)
        self.assertNotIn("recover_vault", names)
        self.assertNotIn("recover_treasury", names)

    def test_fresh_server_has_no_approve(self):
        mcp = _build_server()
        names = registered_tool_names(mcp)
        self.assertEqual(
            names, {"balance", "quote_payment", "pay", "history", "channels", "xbt402_pay"}
        )


if __name__ == "__main__":
    unittest.main()
