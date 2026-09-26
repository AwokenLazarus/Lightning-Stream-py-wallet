"""MCP surface is balance, quote_payment, pay, history, channels, xbt402_pay, close_channel,
xbt402_refund, forward_status, forward_recover (AGP-013)."""

from __future__ import annotations

import unittest

from agentwallet.mcp_server import (
    FORBIDDEN_MCP_TOOLS,
    MCP_TOOL_NAMES,
    _build_server,
    registered_tool_names,
)

EXACT = {"balance", "quote_payment", "pay", "history", "channels", "xbt402_pay", "close_channel",
         "xbt402_refund", "forward_status", "forward_recover"}  # AGP-013 adds the last three


class McpToolListTests(unittest.TestCase):
    def test_published_name_set(self):
        self.assertEqual(MCP_TOOL_NAMES, EXACT)
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
        self.assertEqual(names, EXACT)


if __name__ == "__main__":
    unittest.main()
