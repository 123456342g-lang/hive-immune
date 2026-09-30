#!/usr/bin/env python
"""Stateless MCP upstream for hive-gateway.

AgentDojo tools are stateful (they mutate a typed environment), but the
gateway expects an ordinary MCP server, so the environment travels with
every tools/call in the __hive_env__ argument and comes back as a second
text block prefixed with ENV_MARKER. The process keeps nothing between
calls: two calls in a row with the same environment behave identically.

Only what MCP needs is implemented: initialize, ping, tools/list,
tools/call, and JSON-RPC notifications are ignored.
"""

import argparse
import json
import sys

from pydantic import ValidationError

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from hive_client import ENV_KEY, ENV_MARKER

PROTOCOL_VERSION = "2025-06-18"


def send(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def sync_initial(env):
    """Mirror live collections into the suite's initial_* snapshots.

    Calendar/Inbox/CloudDrive rebuild `events`/`emails`/`files` from
    `initial_events`/`initial_emails`/`initial_files` in an
    `@model_validator(mode="after")` on *every* pydantic validation, so a
    plain JSON roundtrip would silently revert every write. Copying the
    live state into the snapshot makes the roundtrip lossless; the
    workspace judge's WorkspaceDeepDiff explicitly excludes initial_*
    paths, so this is invisible to scoring.
    """
    if (cal := getattr(env, "calendar", None)) is not None:
        cal.initial_events = list(cal.events.values())
    if (inbox := getattr(env, "inbox", None)) is not None:
        inbox.initial_emails = list(inbox.emails.values())
    if (drive := getattr(env, "cloud_drive", None)) is not None:
        drive.initial_files = list(drive.files.values())


def reply_result(msg_id, result):
    send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def reply_error(msg_id, code, message):
    send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, help="AgentDojo suite name, e.g. workspace")
    parser.add_argument("--version", default="v1.2.2", help="AgentDojo suite version")
    args = parser.parse_args()

    suite = get_suite(args.version, args.suite)
    runtime = FunctionsRuntime(suite.tools)
    env_type = suite.environment_type

    tools = [
        {
            "name": f.name,
            "description": f.description,
            "inputSchema": f.parameters.model_json_schema(),
        }
        for f in suite.tools
    ]

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method = msg.get("method")
        if msg_id is None:  # notification (initialized, cancelled, ...)
            continue

        if method == "initialize":
            requested = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL_VERSION
            reply_result(msg_id, {
                "protocolVersion": requested,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "agentdojo-hive", "version": "1.0.0"},
            })
        elif method == "ping":
            reply_result(msg_id, {})
        elif method == "tools/list":
            reply_result(msg_id, {"tools": tools})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            call_args = dict(params.get("arguments") or {})
            env_json = call_args.pop(ENV_KEY, None)

            if name not in runtime.functions:
                reply_error(msg_id, -32602, f"Unknown tool: {name}")
                continue
            if env_json is None:
                reply_error(msg_id, -32602, f"missing {ENV_KEY} argument")
                continue
            try:
                env = env_type.model_validate_json(env_json)
            except ValidationError as e:
                reply_error(msg_id, -32602, f"invalid {ENV_KEY}: {e}")
                continue

            result, error = runtime.run_function(env, name, call_args)
            sync_initial(env)
            text = error if error else tool_result_to_str(result)
            content = [
                {"type": "text", "text": text},
                {"type": "text", "text": ENV_MARKER + env.model_dump_json()},
            ]
            reply_result(msg_id, {"content": content, "isError": error is not None})
        else:
            reply_error(msg_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
