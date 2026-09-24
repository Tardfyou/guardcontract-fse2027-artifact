from __future__ import annotations


def classify_guard_lifecycle(framework: str, marker: str) -> tuple[str, str]:
    value = marker.lower()
    if any(token in value for token in ("tool_input_guardrail", "input_guardrail", "before_tool_callback", "before_tool_call", "needs_approval", "request_confirmation", "wrap_tool_call")):
        return "pre_effect_decidable", "guard contract executes before protected tool dispatch"
    if any(token in value for token in ("tool_output_guardrail", "output_guardrail", "after_tool_callback", "after_tool_call", "output_validator")):
        return "post_effect_dependent", "guard contract executes after protected tool or model output"
    if framework == "crewai" and ("guardrail" in value or "guardrails" in value):
        return "post_effect_dependent", "CrewAI task guardrail validates task output after task execution"
    if "before_model_callback" in value:
        return "pre_effect_decidable", "callback executes before model-driven tool selection"
    if "after_model_callback" in value:
        return "unknown_dynamic", "after-model position alone does not establish ordering relative to tool effects"
    return "unknown_dynamic", "no pinned lifecycle contract matched the guard marker"
