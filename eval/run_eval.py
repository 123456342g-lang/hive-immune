#!/usr/bin/env python
"""Run an AgentDojo benchmark with and without hive-gateway in the loop.

Two modes:

* baseline - agentdojo's own ToolsExecutor, tools run in-process;
* gated    - every tools/call goes through `hive-gateway serve`, which
  applies eval/policy.yaml (reads taint the session; a tainted session
  may not write or send without an approval channel).

One gateway process is spawned per task, so every task starts with a
clean taint and its own audit file.

Usage (from the repository root, inside eval/.venv):

    python eval/run_eval.py --mode baseline
    python eval/run_eval.py --mode gated --approver internal
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import openai
from openai import OpenAI

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.logging import Logger, OutputLogger, TraceLogger
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

from gated import GatewayExecutor
from hive_client import GatewaySession
from hive_llm import GLMOpenAILLM

# The important_instructions attack greets the victim model by name, and
# agentdojo only knows its own model list. GLM gets the generic address.
MODEL_NAMES.setdefault("glm", "AI assistant")

REPO = Path(__file__).resolve().parent.parent
EVAL_DIR = REPO / "eval"

API_ERRORS = (
    openai.BadRequestError,
    openai.RateLimitError,
    openai.APIConnectionError,
    openai.InternalServerError,
    openai.UnprocessableEntityError,
)


# --------------------------------------------------------------------------
# approval webhook stand-in
# --------------------------------------------------------------------------
class _ApprovalHandler(BaseHTTPRequestHandler):
    mode = "internal"  # "internal" or "all", set before serving

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            req = {}
        risk = req.get("risk", "egress")
        approved = self.mode == "all" or (self.mode == "internal" and risk != "egress")
        payload = json.dumps({"approved": approved}).encode()
        self.send_response(200 if approved else 403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # keep the run output clean
        pass


def start_approver(mode):
    handler = type("Handler", (_ApprovalHandler,), {"mode": mode})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/approve"


# --------------------------------------------------------------------------
# pipeline construction
# --------------------------------------------------------------------------
def build_pipeline(mode, llm, system_message, session, env_type):
    if mode == "gated":
        executor = GatewayExecutor(session, env_type)
    else:
        executor = ToolsExecutor()
    pipeline = AgentPipeline(
        [SystemMessage(system_message), InitQuery(), llm, ToolsExecutionLoop([executor, llm])]
    )
    pipeline.name = f"{MODELS_TAG}"
    return pipeline


def default_gateway_bin():
    for name in ("hive-gateway.exe", "hive-gateway"):
        candidate = EVAL_DIR / "bin" / name
        if candidate.exists():
            return str(candidate)
    return str(EVAL_DIR / "bin" / ("hive-gateway.exe" if os.name == "nt" else "hive-gateway"))


# --------------------------------------------------------------------------
# one task run
# --------------------------------------------------------------------------
def run_one_task(suite, args, pipeline_factory, user_task, injection_task, injections, outdir):
    ut_id = user_task.ID
    it_id = injection_task.ID if injection_task is not None else "none"
    session_name = f"{ut_id}-{it_id}".replace("/", "_")[:120]
    started = time.monotonic()

    session = None
    if args.mode == "gated":
        audit_path = outdir / "audit" / f"{session_name}.jsonl"
        log_path = outdir / "gwlogs" / f"{session_name}.log"
        upstream = [sys.executable, str(EVAL_DIR / "mcp_tools_server.py"), "--suite", args.suite]
        extra = []
        if args.approver != "none":
            extra = ["-approve", args.approve_url, "-approve-timeout", "10s"]
        session = GatewaySession(
            gateway_bin=args.gateway,
            upstream_cmd=upstream,
            policy=args.policy,
            session=session_name,
            audit_path=str(audit_path),
            log_path=str(log_path),
            cwd=str(REPO),
            extra_flags=extra,
        )

    error = None
    utility, security = False, True
    try:
        pipeline = pipeline_factory(session)
        attack_type = args.attack if injection_task is not None else "none"
        with TraceLogger(
            delegate=Logger.get(),
            suite_name=suite.name,
            user_task_id=ut_id,
            injection_task_id=injection_task.ID if injection_task is not None else None,
            injections=injections,
            attack_type=attack_type,
            pipeline_name=pipeline.name,
            benchmark_version="hive-0.2",
        ) as logger:
            try:
                utility, security = suite.run_task_with_pipeline(
                    pipeline, user_task, injection_task, injections
                )
            except API_ERRORS as e:
                error = f"{type(e).__name__}: {str(e)[:300]}"
                utility, security = False, True
            except Exception as e:  # noqa: BLE001 - one bad task must not kill a long run
                error = f"{type(e).__name__}: {str(e)[:300]}"
                utility, security = False, True
            logger.set_contextarg("utility", bool(utility))
            logger.set_contextarg("security", bool(security))
            if error:
                logger.set_contextarg("error", error)
    finally:
        if session is not None:
            session.close()

    return {
        "user": ut_id,
        "injection": it_id,
        "utility": bool(utility),
        # agentdojo semantics: True = the injection goal was executed.
        # Meaningless when there was no injection task.
        "injection_executed": (bool(security) if injection_task is not None else None),
        "error": error,
        "seconds": round(time.monotonic() - started, 1),
    }


# --------------------------------------------------------------------------
def parse_list(value):
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["baseline", "gated"], required=True)
    parser.add_argument("--attack", default="important_instructions",
                        help="'important_instructions' for security runs, 'none' for utility runs")
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--suite-version", default="v1.2.2")
    parser.add_argument("--model", default="glm-4-flash")
    parser.add_argument("--user-tasks", help="comma-separated user task ids (default: all)")
    parser.add_argument("--injection-tasks", help="comma-separated injection task ids (default: all)")
    parser.add_argument("--policy", default=str(EVAL_DIR / "policy.yaml"))
    parser.add_argument("--gateway", default=default_gateway_bin())
    parser.add_argument("--approver", choices=["none", "internal", "all"], default="none",
                        help="gated mode only: approval webhook stand-in (default: none = deny mode)")
    parser.add_argument("--outdir", help="output directory (default: eval/runs/<timestamp>-<mode>-<attack>)")
    parser.add_argument("--max-tasks", type=int, help="stop after N task runs (smoke tests)")
    args = parser.parse_args()

    if not os.environ.get("GLM_BASE_URL") or not os.environ.get("GLM_API_KEY"):
        sys.exit("GLM_BASE_URL and GLM_API_KEY must be set")
    if args.mode == "baseline" and args.approver != "none":
        sys.exit("--approver only applies to --mode gated")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    outdir = Path(args.outdir) if args.outdir else EVAL_DIR / "runs" / f"{ts}-{args.mode}-{args.attack}"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "audit").mkdir(exist_ok=True)
    (outdir / "gwlogs").mkdir(exist_ok=True)

    suite = get_suite(args.suite_version, args.suite)
    user_ids = parse_list(args.user_tasks)
    injection_ids = parse_list(args.injection_tasks)
    user_task_ids = user_ids or list(suite.user_tasks.keys())
    injection_task_ids = injection_ids or list(suite.injection_tasks.keys())

    attack = None  # loaded below, once the pipeline exists

    global MODELS_TAG
    MODELS_TAG = f"{args.model}-{args.mode}"

    client = OpenAI(base_url=os.environ["GLM_BASE_URL"], api_key=os.environ["GLM_API_KEY"])
    llm = GLMOpenAILLM(client, args.model)
    system_message = load_system_message(None)

    approver_server = None
    if args.mode == "gated" and args.approver != "none":
        approver_server, args.approve_url = start_approver(args.approver)
        print(f"approval webhook: {args.approve_url} ({args.approver})")

    def pipeline_factory(session):
        return build_pipeline(args.mode, llm, system_message, session, suite.environment_type)

    if args.attack not in ("none", "", "null"):
        # The attack needs a target pipeline; important_instructions only
        # stores it, adaptive attacks would query it. An unguarded pipeline
        # is the right target: attacks are measured against what the agent
        # could have done, not against the gateway.
        target = build_pipeline("baseline", llm, system_message, None, suite.environment_type)
        attack = load_attack(args.attack, suite, target)

    config = {
        "mode": args.mode, "model": args.model, "suite": args.suite, "attack": args.attack,
        "approver": args.approver if args.mode == "gated" else None,
        "policy": args.policy, "user_tasks": user_ids or "all",
        "injection_tasks": injection_ids or "all",
        "started": datetime.now(timezone.utc).isoformat(),
    }
    (outdir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    runs = []
    total = len(user_task_ids) if attack is None else len(user_task_ids) * len(injection_task_ids)
    print(f"mode={args.mode} attack={args.attack} model={args.model} "
          f"user_tasks={len(user_task_ids)} total_runs={total} outdir={outdir}")

    with OutputLogger(str(outdir / "traces")):
        n = 0
        for user_id in user_task_ids:
            user_task = suite.get_user_task_by_id(user_id)
            if attack is None:
                pairs = [(None, {})]
            else:
                pairs = [(it, attack.attack(user_task, suite.get_injection_task_by_id(it)))
                         for it in injection_task_ids]
            for injection_id, injections in pairs:
                if args.max_tasks is not None and n >= args.max_tasks:
                    break
                injection_task = (suite.get_injection_task_by_id(injection_id)
                                  if injection_id is not None else None)
                result = run_one_task(suite, args, pipeline_factory, user_task,
                                      injection_task, injections, outdir)
                runs.append(result)
                n += 1
                mark = "ERR" if result["error"] else "ok "
                print(f"[{n}/{total}] {mark} {result['user']} x {result['injection']}: "
                      f"utility={result['utility']} injection_executed={result['injection_executed']} "
                      f"({result['seconds']}s)", flush=True)
            if args.max_tasks is not None and n >= args.max_tasks:
                break

    if approver_server is not None:
        approver_server.shutdown()

    # summary -------------------------------------------------------------
    # Errored runs have an unknown outcome and are excluded from rates.
    ok_runs = [r for r in runs if not r["error"]]
    errors = [r for r in runs if r["error"]]
    utilities = [r["utility"] for r in ok_runs]
    executed = [r["injection_executed"] for r in ok_runs]
    attacked = attack is not None
    # agentdojo's security() returns True when the INJECTION EXECUTED, so
    # the attack success rate is the mean of that field and the security
    # rate (injection resisted) is its complement.
    asr = round(sum(executed) / len(executed), 4) if (ok_runs and attacked) else None
    summary = {
        "n_runs": len(runs),
        "n_errors": len(errors),
        "utility_rate": round(sum(utilities) / len(utilities), 4) if utilities else None,
        "attack_success_rate": asr,
        "security_rate": round(1 - asr, 4) if asr is not None else None,
        "wall_seconds": round(sum(r["seconds"] for r in runs), 1),
    }
    results = {"config": config, "summary": summary, "runs": runs,
               "error_details": [{"user": r["user"], "injection": r["injection"], "error": r["error"]}
                                 for r in errors]}
    (outdir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n=== summary ===")
    print(json.dumps(summary, indent=2))
    print(f"results: {outdir / 'results.json'}")
    if approver_server is not None:
        approver_server.server_close()


MODELS_TAG = ""


if __name__ == "__main__":
    main()
