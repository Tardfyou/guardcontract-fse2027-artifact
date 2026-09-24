"""Thin framework declarations consumed by shared registration recovery."""

MIDDLEWARE_AGENT_CONSTRUCTORS = {
    "langchain.agents.create_agent": {"framework": "langchain"},
}

DECLARATIVE_MIDDLEWARE_POLICIES = {
    "langchain.agents.middleware.HumanInTheLoopMiddleware": {
        "framework": "langchain",
        "parameter": "human_in_the_loop",
        "policy_keyword": "interrupt_on",
        "symbol": "langchain.agents.middleware.HumanInTheLoopMiddleware.interrupt_on",
    },
}

DECLARATIVE_TOOL_POLICIES = {
    "google.adk.tools.FunctionTool": {
        "framework": "google-adk", "parameter": "require_confirmation",
        "policy_keyword": "require_confirmation",
        "symbol": "google.adk.tools.FunctionTool.require_confirmation"},
    "google.adk.tools.function_tool.FunctionTool": {
        "framework": "google-adk", "parameter": "require_confirmation",
        "policy_keyword": "require_confirmation",
        "symbol": "google.adk.tools.FunctionTool.require_confirmation"},
}

RUNTIME_PLUGIN_CONSTRUCTORS = {
    "google.adk.runners.Runner": {"framework": "google-adk", "agent_keywords": ["agent"]},
    "google.adk.runners.InMemoryRunner": {"framework": "google-adk", "agent_keywords": ["agent"]},
    "google.adk.runners.runner.Runner": {"framework": "google-adk", "agent_keywords": ["agent"]},
    "google.adk.apps.App": {"framework": "google-adk", "agent_keywords": ["root_agent"]},
}

PLUGIN_BASES = {"google.adk.plugins.BasePlugin", "google.adk.plugins.base_plugin.BasePlugin"}
PLUGIN_GUARD_METHODS = {"before_tool_callback", "after_tool_callback"}

# Pydantic AI renamed this post-tool lifecycle decorator.  The shared analysis
# normalizes both public spellings to the output-validator contract role.
PYDANTIC_OUTPUT_VALIDATOR_DECORATORS = {"output_validator", "result_validator"}

# Framework-supplied tool parameters are omitted from model-authored arguments
# in inert replays.  This is an API declaration only; shared mapping still owns
# parameter discovery and fails closed on every undeclared annotation.
LANGCHAIN_INJECTED_TOOL_PARAMETER_ANNOTATIONS = {
    "ToolRuntime",
    "langchain.tools.ToolRuntime",
    "RunnableConfig",
    "langchain_core.runnables.RunnableConfig",
}

PRE_EFFECT_POLICY_FACTS = {
    ("langchain", "human_in_the_loop"): "human_reject_removes_selected_tool_before_execution",
    ("google-adk", "require_confirmation"): "require_confirmation_reject_skips_function_invocation",
}

DECORATED_GLOBAL_HOOKS = {
    "crewai.hooks.before_tool_call": {"framework": "crewai", "parameter": "before_tool_call"},
    "crewai.hooks.after_tool_call": {"framework": "crewai", "parameter": "after_tool_call"},
}

EVENT_HOOK_DECORATORS = {
    "crewai.hooks.on": {
        "crewai.hooks.InterceptionPoint.PRE_TOOL_CALL": "before_tool_call",
        "crewai.hooks.InterceptionPoint.POST_TOOL_CALL": "after_tool_call",
    },
}
