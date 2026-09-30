"""Pipeline element that routes AgentDojo tool calls through hive-gateway.

Mirrors agentdojo's ToolsExecutor signature and behaviour, with two
differences:

* every call carries the current typed environment as the __hive_env__
  argument and adopts the environment that comes back;
* a refusal arrives as an MCP tool result with isError=true (the default
  deny-style), which is handed to the model as the tool's error text,
  environment untouched - exactly what a denied call should look like
  from the agent's point of view.
"""

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from hive_client import ENV_KEY, ENV_MARKER, GatewayDead, MCPError
from ast import literal_eval
from collections.abc import Sequence


class GatewayExecutor(BasePipelineElement):
    name = "GatewayExecutor"

    def __init__(self, session, env_type):
        self.session = session
        self.env_type = env_type
        # Snapshot of inbox.contact_list taken before the first tool call.
        # agentdojo never revalidates an environment in-process, so the
        # contact list stays frozen for the whole task; every JSON
        # roundtrip here, however, re-runs Inbox._create_contact_list,
        # which appends contacts derived from *new* emails. The judge
        # (WorkspaceDeepDiff) does not exclude contact_list, so those
        # appended entries would show up as diff noise and fail utility
        # checks that passed in baseline. Restore the snapshot after each
        # revalidation to keep the two modes comparable.
        self._contact_list0 = None

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                results.append(self._error_result(tool_call, "Empty function name provided. Provide a valid function name."))
                continue
            if tool_call.function not in runtime.functions:
                results.append(self._error_result(tool_call, f"Invalid tool {tool_call.function} provided."))
                continue

            args = tool_call.args
            for arg_k, arg_v in args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    args[arg_k] = literal_eval(arg_v)

            if self._contact_list0 is None:
                if (inbox0 := getattr(env, "inbox", None)) is not None:
                    self._contact_list0 = list(inbox0.contact_list)

            call_args = {**args, ENV_KEY: env.model_dump_json()}
            try:
                content, is_error = self.session.tools_call(tool_call.function, call_args)
            except (MCPError, GatewayDead) as e:
                results.append(self._error_result(tool_call, f"hive-gateway unavailable: {e}"))
                continue

            env_block = None
            text_parts = []
            for block in content:
                text = block.get("text", "")
                if text.startswith(ENV_MARKER):
                    env_block = text[len(ENV_MARKER):]
                else:
                    text_parts.append(text)
            text = "\n".join(text_parts)

            if env_block is not None:
                try:
                    env = self.env_type.model_validate_json(env_block)
                except Exception as e:  # noqa: BLE001 - a corrupt env must not kill the task
                    results.append(self._error_result(tool_call, f"hive-gateway returned an unreadable environment: {e}"))
                    continue
                if self._contact_list0 is not None and (inbox := getattr(env, "inbox", None)) is not None:
                    inbox.contact_list = list(self._contact_list0)

            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(text)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=text if is_error else None,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args

    @staticmethod
    def _error_result(tool_call, error: str) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string("")],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=error,
        )
