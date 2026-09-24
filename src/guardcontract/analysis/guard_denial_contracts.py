"""Thin framework mapping from SDK guard slots to denial-signal contracts."""


CONTRACTS = {
    ("google-adk", "before_tool_callback"): "pre_short_circuit",
    ("google-adk", "after_tool_callback"): "post_explicit_boolean",
    ("pydantic-ai", "output_validator"): "retry_exception",
    ("crewai", "guardrail"): "boolean_result",
    ("crewai", "register_before_tool_call_hook"): "before_hook_boolean",
    ("crewai", "before_tool_call"): "before_hook_boolean",
    ("openai-agents", "openai-input"): "tripwire_result",
    ("openai-agents", "openai-output"): "tripwire_result",
    ("openai-agents", "openai-tool-input"): "tripwire_result",
    ("openai-agents", "openai-tool-output"): "tripwire_result",
    ("langchain", "guard"): "around_handler",
}


def denial_contract(framework: str, parameter: str) -> str:
    return CONTRACTS.get((framework, parameter),
                         CONTRACTS.get((framework, parameter.rsplit(".", 1)[-1]), "unknown"))
