"""Shared fixtures for the MCP-driven e2e suite.

The suite drives the packed component through `act run --mcp` over stdio with
a real MCP client, so what the tests observe is what an agent observes.
"""

import json
import os
import subprocess
import pytest
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

# Measured in docs/specs/2026-08-08-e2e-harness-findings.md, question 1.
from mcp.shared.exceptions import McpError

WASM = "target/wasm32-wasip2/release/component_crypto.wasm"

# ACT's audit trail writes to stderr unconditionally — it is not governed by
# RUST_LOG — so it is redirected to a file rather than left to flood pytest.
LOG_FILE = Path(".pytest-act-stderr.log")


@pytest.fixture(scope="session")
def act_binary() -> str:
    """Honour the same ACT override the justfile uses, so CI and local agree."""
    return os.environ.get("ACT", "act")


@pytest.fixture(scope="session")
def wasm_path(act_binary: str) -> Path:
    """The packed component.

    Existence is not enough and neither is a fresh mtime: `cargo build`
    produces a wasm with no `act:component` custom section, and an unpacked
    artifact declares no capability ceiling, so every grant is refused as
    "outside ceiling" and the failures point anywhere but here. This has
    already bitten twice in this workspace, so the fixture checks the section
    rather than the file.
    """
    path = Path(WASM)
    if not path.exists():
        pytest.fail(f"{path} is missing — run `just build && just pack` first")
    probe = subprocess.run(
        [act_binary, "inspect", "component-manifest", str(path)],
        capture_output=True, text=True,
    )
    name = json.loads(probe.stdout or "{}").get("std", {}).get("name", "unknown")
    if name in ("", "unknown"):
        pytest.fail(f"{path} is built but not packed — run `just pack`")
    return path


@pytest.fixture
async def client(act_binary: str, wasm_path: Path):
    """A connected MCP client, one `act` process per test.

    Function-scoped on purpose: an ACT component keeps state across calls
    within a host process, so sharing one process between tests would let
    them leak into each other. Components with no state may widen this, but
    the default is the safe one.
    """
    transport = StdioTransport(
        command=act_binary,
        args=["run", str(wasm_path), "--mcp"],
        keep_alive=False,  # crypto is pure/stateless — findings Q3: fresh process is the safe default
        log_file=LOG_FILE,
    )
    async with Client(transport) as connected:
        yield connected


@pytest.fixture
def expect_error():
    """Assert a call fails with a specific ACT error kind.

    Exposed as a fixture rather than a plain function so tests never have to
    import from `conftest` — that import only resolves when the test
    directory happens to be on `sys.path`, which is not something to rely on.

    Measured, not assumed. `call-tool` in `act:tools` returns a bare
    `tool-result` with NO `result<>` wrapper — only `list-tools` has one — so
    a guest reporting a failed tool call can only do it through
    `tool-event::error`, which arrives as a result with `is_error` set and the
    kind in `_meta`. **That is the path a tool test will take.**

    The JSON-RPC error path exists for failures that are not the guest's tool
    body: `list-tools`, the session operations, a wasmtime trap, an
    unreachable actor. It raises `mcp.shared.exceptions.McpError` with the
    payload at `exc.error.data`. Session-lifecycle tests reach it; hash-a-string
    tests do not. Both are handled here so callers need not care.
    """

    async def _expect(client, tool: str, arguments: dict, kind: str):
        try:
            result = await client.call_tool(tool, arguments, raise_on_error=False)
        except McpError as exc:
            data = getattr(getattr(exc, "error", None), "data", None) or {}
            assert data.get("dev.actcore/error-kind") == kind, (
                f"expected {kind} on the JSON-RPC error path, got {data!r}"
            )
            return

        assert result.is_error, f"expected {tool} to fail, got {result!r}"
        meta = result.meta or {}
        assert meta.get("dev.actcore/error-kind") == kind, (
            f"expected {kind} on the isError path, got {meta!r}"
        )

    return _expect
