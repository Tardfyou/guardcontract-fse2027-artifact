"""Versioned lifecycle vocabulary shared by structural coverage adapters."""


PROFILES = {
    "langchain": {
        "distribution": "langchain", "version": "1.4.0",
        "roles": {"middleware": "around_tool"},
        "controlled_pair": ["after_agent_post_effect", "deferred_commit_after_agent"],
    },
    "google_adk": {
        "distribution": "google-adk", "version": "2.7.0",
        "roles": {"before_tool_callback": "pre_tool", "after_tool_callback": "post_tool",
                  "before_model_callback": "pre_model", "after_model_callback": "post_model"},
        "controlled_pair": ["after_tool_callback", "before_tool_callback"],
    },
    "pydantic_ai": {
        "distribution": "pydantic-ai-slim", "version": "2.40.0",
        "roles": {"output_validator": "post_output", "result_validator": "post_output"},
        "controlled_pair": ["output_validator_post_effect", "deferred_effect_commit_in_validator"],
    },
    "openai_agents": {
        "distribution": "openai-agents", "version": "0.22.0",
        "roles": {"input_guardrails": "input_guard", "output_guardrails": "post_output",
                  "tool_input_guardrails": "pre_tool"},
        "controlled_pair": ["parallel_input_guard_race", "tool_input_guard"],
    },
    "crewai": {
        "distribution": "crewai", "version": "1.15.18",
        "roles": {"guardrail": "post_task", "guardrails": "post_task",
                  "before_tool_call": "pre_tool"},
        "controlled_pair": ["task_output_guardrail", "before_tool_hook"],
    },
}


def lifecycle(framework, source_role):
    profile = PROFILES.get(framework)
    return profile["roles"].get(source_role, "unknown") if profile else "unknown"


def validate_owned_matrix(value):
    rows = value.get("framework_rows") if isinstance(value, dict) else None
    if not isinstance(rows, list) or len(rows) != len(PROFILES):
        raise ValueError("lifecycle_matrix_inventory")
    normalized = {row["framework"].replace("-", "_"): row for row in rows}
    if set(normalized) != set(PROFILES):
        raise ValueError("lifecycle_matrix_frameworks")
    for framework, profile in PROFILES.items():
        row = normalized[framework]
        if row.get("distribution") != profile["distribution"] or row.get("version") != profile["version"]:
            raise ValueError("lifecycle_matrix_version")
        if [row.get("vulnerable_lifecycle"), row.get("repaired_lifecycle")] != profile["controlled_pair"]:
            raise ValueError("lifecycle_matrix_pair")
        if row.get("paired_behavior_verified") is not True or len(row.get("cells", [])) != 4:
            raise ValueError("lifecycle_matrix_cells")
    return {"frameworks": len(rows), "lifecycle_pairs": len(rows), "cells": sum(len(row["cells"]) for row in rows)}
