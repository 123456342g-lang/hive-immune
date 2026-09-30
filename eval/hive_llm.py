"""OpenAILLM variant that speaks GLM's dialect of the chat API.

Two incompatibilities with agentdojo's stock OpenAILLM on GLM:

* tool messages with block-array content are silently ignored by GLM
  (the model sees an empty tool result and answers from memory);
* the OpenAI-only "developer" role is rejected by newer GLM models.

The fix is to flatten every content array to a string and downgrade
"developer" to "system" before the request goes out.
"""

from collections.abc import Sequence

from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM,
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage


def _flatten_content(msg: dict) -> dict:
    if msg.get("role") == "developer":
        msg["role"] = "system"
    content = msg.get("content")
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        msg["content"] = "".join(parts)
    if msg.get("role") == "assistant" and msg.get("tool_calls") and msg.get("content") == "":
        msg["content"] = None
    return msg


class GLMOpenAILLM(OpenAILLM):
    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ):
        openai_messages = [_flatten_content(_message_to_openai(m, self.model)) for m in messages]
        openai_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        # agentdojo's chat_completion_request drops temperature=0.0
        # (0.0 is falsy), leaving sampling to the server default; GLM is
        # noticeably steadier with an explicit zero.
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            tools=openai_tools or None,
            tool_choice="auto" if openai_tools else None,
            temperature=self.temperature if self.temperature is not None else 0.0,
        )
        output = _openai_to_assistant_message(completion.choices[0].message)
        return query, runtime, env, [*messages, output], extra_args
