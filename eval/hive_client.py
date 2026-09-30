"""Stdio MCP client that owns one hive-gateway serve subprocess.

One GatewaySession == one gateway process == one MCP session. The eval
runner opens a session per task so every task starts with a clean taint,
clean counters and its own audit file, exactly like a fresh agent.

Protocol: newline-delimited JSON-RPC on the gateway's stdio, one request
in flight at a time (the executors are sequential).
"""

import json
import subprocess

# Shared with mcp_tools_server.py and gated.py: the environment rides in
# the __hive_env__ argument and comes back prefixed with ENV_MARKER.
ENV_KEY = "__hive_env__"
ENV_MARKER = "__HIVE_ENV__"


class MCPError(Exception):
    """The gateway answered a request with a JSON-RPC error."""


class GatewayDead(Exception):
    """The gateway process exited (or closed stdio) unexpectedly."""


class GatewaySession:
    def __init__(self, gateway_bin, upstream_cmd, policy, session, audit_path, log_path,
                 cwd=None, extra_flags=()):
        self.session_id = session
        self._next_id = 0
        self._log_path = log_path
        self._log = open(log_path, "wb")
        cmd = [
            gateway_bin, "serve",
            "-agent", "agentdojo",
            "-session", session,
            "-policy", policy,
            "-audit", audit_path,
            *extra_flags,
            "--", *upstream_cmd,
        ]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            text=True,
            encoding="utf-8",
            bufsize=1,
            cwd=cwd,
        )
        try:
            self._initialize()
        except BaseException:
            self.close()
            raise

    def _initialize(self):
        params = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "hive-eval", "version": "1"},
        }
        self._request("initialize", params)
        self._notify("notifications/initialized", {})

    def _notify(self, method, params):
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def _request(self, method, params):
        self._next_id += 1
        req_id = self._next_id
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        try:
            self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise GatewayDead(f"gateway closed stdin while sending {method}: {e}") from e

        while True:
            line = self.proc.stdout.readline()
            if line == "":
                raise GatewayDead(self._death_note(f"while waiting for {method}"))
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue  # tolerate stray non-JSON output (should not happen)
            if resp.get("id") != req_id:
                continue  # notification or unrelated response
            if "error" in resp and resp["error"] is not None:
                err = resp["error"]
                raise MCPError(f"{err.get('code')}: {err.get('message')}")
            return resp.get("result")

    def tools_call(self, name, arguments):
        """Returns (content_blocks, is_error)."""
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content") or []
        is_error = bool(result.get("isError"))
        return content, is_error

    def _death_note(self, context):
        code = self.proc.poll()
        tail = ""
        try:
            self._log.flush()
            with open(self._log_path, "rb") as f:
                data = f.read()
            tail = data[-2000:].decode("utf-8", errors="replace")
        except OSError:
            pass
        return f"gateway exited (code={code}) {context}\n--- gateway stderr tail ---\n{tail}"

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=15)
        finally:
            try:
                self._log.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
