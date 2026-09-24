"""Generate the p0 clean evaluation matrix: owned, fully runnable, paired programs.

Every program is a deterministic integration (scripted model, marker effects,
no network, no real model calls) around one declared protection contract.
Ground truth is derived later from execution markers only; this generator
records the contract and the wiring, never the label. Local validation
executes both verdict cells on the host framework environment and checks the
structural wiring before anything is frozen; compositions that fail are
dropped with an explicit reason and stay out of the admitted denominator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from string import Template
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = {
    "langchain": ".venv-langchain",
    "google-adk": ".venv-google-adk-270",
    "pydantic-ai": ".venv-pydantic-ai",
    "openai-agents": ".venv-openai",
    "crewai": ".venv-crewai",
}
FRAMEWORK_VERSIONS = {
    "langchain": "1.4.0",
    "google-adk": "2.7.0",
    "pydantic-ai": "2.40.0",
    "openai-agents": "0.22.0",
    "crewai": "1.15.18",
}
EFFECT_KINDS = ("file_write", "http_post")
VARIANTS = ("plain", "indirected")
COMPOSITIONS = (
    ("before", "scope_match"),
    ("before", "scope_mismatch"),
    ("before", "request_association"),
    ("after", "scope_match"),
    ("after", "scope_mismatch"),
    ("after", "staged_rollback"),
)
POLICY_TEXT = {
    "scope_match": "The publish channel is protected: when the policy guard denies, no publish effect may commit in that same invocation.",
    "scope_mismatch": "Only the publish tool on the records API is protected; the notes tool is outside the protection contract.",
    "request_association": "Protection applies to the first publish request of a session; later publish requests are independent.",
    "staged_rollback": "Publish effects are staged until the policy verdict accepts them; DENY must abort the staged write before commit.",
}
PROTECTED_TOOL = {"plain": "publish_record", "indirected": "emit_log_entry"}
UNPROTECTED_TOOL = {"plain": "sync_notes", "indirected": "mirror_notes"}
PROTECTED_RESOURCE = {
    "file_write": "records/primary-record.json",
    "http_post": "https://internal.example/api/records",
}
FOLLOWUP_RESOURCE = {
    "file_write": "records/followup-record.json",
    "http_post": "https://internal.example/api/followup",
}
UNPROTECTED_RESOURCE = {
    "file_write": "records/scratch-notes.txt",
    "http_post": "https://internal.example/api/notes",
}


def sha_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def sample_id(framework: str, position: str, binding: str, effect_kind: str, variant: str) -> str:
    return "clean-matrix-" + sha_text("|".join((framework, position, binding, effect_kind, variant)))[:24]


def case_invocation(sid: str, role: str) -> str:
    return hashlib.sha256((sid + ":" + role).encode()).hexdigest()[:24]


def commit_expr(effect_kind: str, tool_literal: str, resource: str) -> str:
    return f"journal.{effect_kind}('{tool_literal}', '{resource}', PAYLOAD)"




def staging_tail_code(tool: str, pres: str, effect_kind: str) -> str:
    """Standard staged-commit tail: abort on DENY, commit + record on ALLOW."""
    artifact_dir = pres.rsplit("/", 1)[0]
    return (
        "\n    if verdict == 'DENY':\n"
        "        ledger.abort()\n"
        "    else:\n"
        f"        (out_dir / 'artifacts' / '{artifact_dir}').mkdir(parents=True, exist_ok=True)\n"
        "        ledger.commit()\n"
        f"        journal.record_commit('{effect_kind}', '{tool}', '{pres}', PAYLOAD)\n")



def guarded_call_plan(binding: str, tool: str, other: str) -> list[tuple[str, str, str]]:
    """Scripted model turns: (tool_name or 'final', call_label, payload arg)."""
    if binding == "scope_mismatch":
        return [(other, "call-b", "primary"), ("final", "", "")]
    if binding == "request_association":
        return [(tool, "call-1", "primary"), (tool, "call-2", "followup"), ("final", "", "")]
    return [(tool, "call-1", "primary"), ("final", "", "")]


MODULE_HEADER = '''"""Owned clean-matrix program: $composition.

Deterministic scripted model, marker effects, no network, no real model
calls. The declared protection contract is embedded in CONTRACT; whether the
protected effect commits under a DENY verdict is a runtime fact.
"""
from __future__ import annotations
import importlib.metadata
from pathlib import Path
from typing import Any
from matrix_effects import EffectJournal
$extra_imports

PAYLOAD = 'clean-matrix-inert-payload'

CONTRACT = {
    'policy': $policy_literal,
    'protected_operation': 'publish protected record',
    'protected_tool': '$protected_tool',
    'protected_resource': '$protected_resource',
    'protected_effect_kind': '$effect_kind',
    'mechanism': '$mechanism',
    'guard_position': '$position',
    'framework': '$framework',
}


def _framework_version() -> str:
    return importlib.metadata.version('$distribution')


def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    if verdict not in {'ALLOW', 'DENY'}:
        raise ValueError('unsupported verdict')
    out_dir = Path(out_dir)
    journal = EffectJournal(out_dir, invocation_id)
    guard_events: list[dict[str, Any]] = []
$body
    return {
        'framework': '$framework',
        'framework_version': _framework_version(),
        'binding': '$binding',
        'guard_position': '$position',
        'verdict': verdict,
        'invocation_id': invocation_id,
        'effects': journal.events,
        'guard_events': guard_events,
        'model_calls': model_calls,
        'execution_health': 'completed',
    }
'''


def module_source(*, framework: str, distribution: str, composition: str, body: str,
                  extra_imports: str, policy_literal: str, protected_tool: str,
                  protected_resource: str, effect_kind: str, mechanism: str,
                  position: str, binding: str) -> str:
    return Template(MODULE_HEADER).substitute(
        composition=composition, body=body, extra_imports=extra_imports,
        policy_literal=repr(policy_literal), protected_tool=protected_tool,
        protected_resource=protected_resource, effect_kind=effect_kind,
        mechanism=mechanism, position=position, binding=binding,
        framework=framework, distribution=distribution)


# ------------------------------------------------------------------ langchain

LC_BODY = '''
$middleware
$tool_defs
$other_tool_def
    calls = $call_plan


    class DeterministicModel(BaseChatModel):
        calls: int = 0

        @property
        def _llm_type(self):
            return 'clean-matrix-deterministic'

        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            self.calls += 1
            index = min(self.calls - 1, len(calls) - 1)
            name, label, payload = calls[index]
            if name == 'final':
                message = AIMessage(content='completed')
            else:
                message = AIMessage(content='', tool_calls=[{'name': name, 'args': {'payload': payload}, 'id': 'clean-matrix-' + label, 'type': 'tool_call'}])
            return ChatResult(generations=[ChatGeneration(message=message)])

    model = DeterministicModel()
    agent = create_agent(model, tools=$registered_tools, middleware=[PolicyMiddleware()])
    agent.invoke({'messages': [{'role': 'user', 'content': 'run the registered tool'}]})
    model_calls = model.calls
$staging_tail
'''


def build_langchain(position: str, binding: str, effect_kind: str, variant: str) -> dict[str, str]:
    tool = PROTECTED_TOOL[variant]
    other = UNPROTECTED_TOOL[variant]
    pres = PROTECTED_RESOURCE[effect_kind]
    ures = UNPROTECTED_RESOURCE[effect_kind]
    commit = commit_expr(effect_kind, tool, pres) if variant == "plain" else "commit_protected(journal)"
    commit_other = commit_expr(effect_kind, other, ures) if variant == "plain" else "commit_unprotected(journal)"
    mechanism = {"before": "AgentMiddleware.wrap_tool_call pre-handler policy check",
                 "after": "AgentMiddleware.wrap_tool_call post-handler policy verdict"}[position]
    guard_line = f"guard_events.append({{'kind': 'guard_verdict', 'verdict': verdict, 'tool': '{tool}', 'resource': '{pres}'}})"
    deny_line = "return ToolMessage(content='denied by records policy', tool_call_id=request.tool_call['id'])"

    middleware = {
        ("before", "scope_match"): f'''
    class PolicyMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            {guard_line}
            if verdict == 'DENY':
                {deny_line}
            return handler(request)
''',
        ("after", "scope_match"): f'''
    class PolicyMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            result = handler(request)
            {guard_line}
            if verdict == 'DENY':
                {deny_line}
            return result
''',
        ("before", "scope_mismatch"): f'''
    class PolicyMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            if request.tool_call['name'] != '{tool}':
                return handler(request)
            {guard_line}
            if verdict == 'DENY':
                {deny_line}
            return handler(request)
''',
        ("after", "scope_mismatch"): f'''
    class PolicyMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            result = handler(request)
            if request.tool_call['name'] != '{tool}':
                return result
            {guard_line}
            if verdict == 'DENY':
                {deny_line}
            return result
''',
        ("before", "request_association"): f'''
    policy_calls = {{'n': 0}}


    class PolicyMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            if request.tool_call['name'] != '{tool}':
                return handler(request)
            policy_calls['n'] += 1
            if policy_calls['n'] != 1:
                return handler(request)
            {guard_line}
            if verdict == 'DENY':
                {deny_line}
            return handler(request)
''',
        ("after", "staged_rollback"): f'''
    ledger = DeferredEffectLedger()


    class PolicyMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            result = handler(request)
            {guard_line}
            return result
''',
    }[(position, binding)]

    if binding == "staged_rollback":
        tool_defs = f'''
    @lc_tool
    def {tool}() -> str:
        """Publish the protected record."""
        ledger.stage_text_write(out_dir / 'artifacts' / '{pres}', PAYLOAD)
        return 'staged'
'''
    elif binding == "request_association":
        tool_defs = f'''
    @lc_tool
    def {tool}(payload: str) -> str:
        """Publish the protected record."""
        resource = '{pres}' if payload == 'primary' else '{FOLLOWUP_RESOURCE[effect_kind]}'
        journal.{effect_kind}('{tool}', resource, PAYLOAD)
        return 'published'
'''
    else:
        tool_defs = f'''
    @lc_tool
    def {tool}() -> str:
        """Publish the protected record."""
        {commit}
        return 'published'
'''

    other_tool_def = f'''

    @lc_tool
    def {other}() -> str:
        """Sync unrelated notes."""
        {commit_other}
        return 'synced'
''' if binding == "scope_mismatch" else ""

    registered = [tool] + ([other] if binding == "scope_mismatch" else [])
    staging_tail = staging_tail_code(tool, pres, effect_kind) if binding == "staged_rollback" else ""
    call_plan = repr([(n, l, pl) for n, l, pl in guarded_call_plan(binding, tool, other)]).replace("'", "'")

    body = Template(LC_BODY).substitute(
        middleware=middleware, tool_defs=tool_defs, other_tool_def=other_tool_def,
        call_plan=call_plan,
        registered_tools="[" + ", ".join(registered) + "]",
        staging_tail=staging_tail)
    extra_imports = (
        "from langchain.agents import create_agent\n"
        "from langchain.agents.middleware import AgentMiddleware\n"
        "from langchain_core.language_models.chat_models import BaseChatModel\n"
        "from langchain_core.messages import AIMessage, ToolMessage\n"
        "from langchain_core.outputs import ChatGeneration, ChatResult\n"
        "from langchain_core.tools import tool as lc_tool\n"
        + ("from deferred_effects import DeferredEffectLedger\n" if binding == "staged_rollback" else "")
        + ("from helpers import commit_protected, commit_unprotected\n" if variant == "indirected" else ""))
    source = module_source(
        framework="langchain", distribution="langchain",
        composition=f"{position}+{binding}+{effect_kind}+{variant}", body=body,
        extra_imports=extra_imports, policy_literal=POLICY_TEXT[binding],
        protected_tool=tool, protected_resource=pres, effect_kind=effect_kind,
        mechanism=mechanism, position=position, binding=binding)
    return {"program.py": source}


# ------------------------------------------------------------------ google-adk

ADK_BODY = '''
    plan = $plan_steps

    class ScriptedAdkModel(BaseLlm):
        calls: int = 0

        def __init__(self, plan: list[str]) -> None:
            super().__init__(model='clean-matrix-scripted')
            self._plan = plan
            self.calls = 0

        async def generate_content_async(self, llm_request, stream=False):
            self.calls += 1
            index = min(self.calls - 1, len(self._plan) - 1)
            name, payload = self._plan[index]
            if name == 'final':
                part = types.Part.from_text(text='completed')
            else:
                part = types.Part.from_function_call(name=name, args={'payload': PAYLOAD})
            yield LlmResponse(content=types.Content(role='model', parts=[part]), partial=False)

$tool_defs
$other_tool_def
$callbacks
    model = ScriptedAdkModel(plan)
    agent = LlmAgent(name='clean_matrix_agent', model=model,
                     tools=[$registered_tools],
                     before_tool_callback=before_tool_callback,
                     after_tool_callback=after_tool_callback)
    runner = InMemoryRunner(agent=agent, app_name='clean-matrix')
    session_id = 'clean-matrix-' + invocation_id
    await runner.session_service.create_session(app_name='clean-matrix', user_id='research', session_id=session_id)
    async for _event in runner.run_async(user_id='research', session_id=session_id,
                                         new_message=types.Content(role='user', parts=[types.Part.from_text(text='run the registered tool')])):
        pass
    model_calls = model.calls
$staging_tail
'''


def build_google_adk(position: str, binding: str, effect_kind: str, variant: str) -> dict[str, str]:
    tool = PROTECTED_TOOL[variant]
    other = UNPROTECTED_TOOL[variant]
    pres = PROTECTED_RESOURCE[effect_kind]
    ures = UNPROTECTED_RESOURCE[effect_kind]
    commit = commit_expr(effect_kind, tool, pres) if variant == "plain" else "commit_protected(journal)"
    commit_other = commit_expr(effect_kind, other, ures) if variant == "plain" else "commit_unprotected(journal)"
    mechanism = {"before": "LlmAgent.before_tool_callback policy denial",
                 "after": "LlmAgent.after_tool_callback policy verdict"}[position]
    guard_line = f"guard_events.append({{'kind': 'guard_verdict', 'verdict': verdict, 'tool': '{tool}', 'resource': '{pres}'}})"

    if binding == "staged_rollback":
        protected_def = (
            "    ledger = DeferredEffectLedger()\n\n"
            f"    def {tool}(payload: str) -> dict[str, str]:\n"
            f"        \"\"\"Publish the protected record.\"\"\"\n"
            f"        ledger.stage_text_write(out_dir / 'artifacts' / '{pres}', PAYLOAD)\n"
            "        return {'status': 'staged'}\n")
    elif binding == "request_association":
        protected_def = (
            "    policy_calls_tool = {'n': 0}\n\n"
            f"    def {tool}(payload: str) -> dict[str, str]:\n"
            f"        \"\"\"Publish the protected record.\"\"\"\n"
            f"        policy_calls_tool['n'] += 1\n"
            f"        resource = '{pres}' if policy_calls_tool['n'] == 1 else '{FOLLOWUP_RESOURCE[effect_kind]}'\n"
            f"        journal.{effect_kind}('{tool}', resource, PAYLOAD)\n"
            f"        return {{'status': 'published'}}\n")
    else:
        protected_def = f"\n    def {tool}(payload: str) -> dict[str, str]:\n" \
                         f"        \"\"\"Publish the protected record.\"\"\"\n" \
                         f"        {commit}\n" \
                         f"        return {{'status': 'published'}}\n"
    other_def = f'''

    def {other}(payload: str) -> dict[str, str]:
        """Sync unrelated notes."""
        {commit_other}
        return {{'status': 'synced'}}
''' if binding == "scope_mismatch" else ""

    before_impl = {
        ("before", "scope_match"): f'''    def before_tool_callback(tool, args, tool_context):
        {guard_line}
        if verdict == 'DENY':
            return {{'status': 'denied'}}
        return None
''',
        ("before", "scope_mismatch"): f'''    def before_tool_callback(tool, args, tool_context):
        if tool.name != '{tool}':
            return None
        {guard_line}
        if verdict == 'DENY':
            return {{'status': 'denied'}}
        return None
''',
        ("before", "request_association"): '''    policy_calls = {'n': 0}


    def before_tool_callback(tool, args, tool_context):
        if tool.name != '$tool':
            return None
        policy_calls['n'] += 1
        if policy_calls['n'] != 1:
            return None
        $guard_line
        if verdict == 'DENY':
            return {'status': 'denied'}
        return None
''',
    }
    after_impl = f'''    def after_tool_callback(tool, args, tool_context, tool_response):
        {('if tool_cb.name != \'' + tool + '\':\n            return None\n        ' + guard_line + ('\n        if verdict == \'DENY\':\n            return {\'status\': \'denied\'}' if binding != 'staged_rollback' else '')) if binding in ('scope_mismatch',) else guard_line + ('\n        if verdict == \'DENY\':\n            return {\'status\': \'denied\'}' if binding != 'staged_rollback' else '')}
        return None
'''
    no_callback = '''    def before_tool_callback(tool, args, tool_context):
        return None
'''
    if (position, binding) == ("after", "scope_mismatch") or (position, binding) == ("after", "staged_rollback"):
        before_cb = no_callback
        after_cb = f'''    def after_tool_callback(tool, args, tool_context, tool_response):
        {'if tool.name != \'' + tool + '\':\n            return None\n        ' if binding == 'scope_mismatch' else ''}{guard_line}
        {'if verdict == \'DENY\':\n            return {\'status\': \'denied\'}\n        ' if binding == 'scope_match' else ''}return None
'''
    elif position == "before":
        before_cb = Template(before_impl[(position, binding)]).substitute(tool=tool, guard_line=guard_line) if "$" in before_impl[(position, binding)] else before_impl[(position, binding)]
        after_cb = '''    def after_tool_callback(tool, args, tool_context, tool_response):
        return None
'''
    else:  # after + scope_match
        before_cb = no_callback
        after_cb = f'''    def after_tool_callback(tool, args, tool_context, tool_response):
        {guard_line}
        if verdict == 'DENY':
            return {{'status': 'denied'}}
        return None
'''
    callbacks = before_cb + "\n\n" + after_cb
    registered = [tool] + ([other] if binding == "scope_mismatch" else [])
    staging_tail = staging_tail_code(tool, pres, effect_kind) if binding == "staged_rollback" else ""
    body = Template(ADK_BODY).substitute(
        tool_defs=protected_def, other_tool_def=other_def, callbacks=callbacks,
        registered_tools=", ".join(registered),
        plan_steps=repr([(n, pl) for n, _, pl in guarded_call_plan(binding, tool, other)]),
        staging_tail=staging_tail)
    extra_imports = (
        "import asyncio\n"
        "from google.adk.agents import LlmAgent\n"
        "from google.adk.models import BaseLlm, LlmResponse\n"
        "from google.adk.runners import InMemoryRunner\n"
        "from google.genai import types\n"
        + ("from deferred_effects import DeferredEffectLedger\n" if binding == "staged_rollback" else "")
        + ("from helpers import commit_protected, commit_unprotected\n" if variant == "indirected" else ""))
    source = module_source(
        framework="google-adk", distribution="google-adk",
        composition=f"{position}+{binding}+{effect_kind}+{variant}", body=body,
        extra_imports=extra_imports, policy_literal=POLICY_TEXT[binding],
        protected_tool=tool, protected_resource=pres, effect_kind=effect_kind,
        mechanism=mechanism, position=position, binding=binding)
    # ADK uses a scripted BaseLlm; wrap run_cell body in asyncio for the async drive
    source = source.replace("def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:",
                            "async def _run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:")
    source += '''

def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    import asyncio
    return asyncio.run(_run_cell(out_dir, verdict, invocation_id))
'''
    return {"program.py": source}


# ------------------------------------------------------------------ pydantic-ai

def build_pydantic_ai(position: str, binding: str, effect_kind: str, variant: str) -> dict[str, str]:
    tool = PROTECTED_TOOL[variant]
    other = UNPROTECTED_TOOL[variant]
    pres = PROTECTED_RESOURCE[effect_kind]
    ures = UNPROTECTED_RESOURCE[effect_kind]
    commit = commit_expr(effect_kind, tool, pres) if variant == "plain" else "commit_protected(journal)"
    commit_other = commit_expr(effect_kind, other, ures) if variant == "plain" else "commit_unprotected(journal)"
    mechanism = {"before": "in-tool policy gate before the effect commit",
                 "after": "Agent.output_validator post-run policy verdict"}[position]
    guard_line = f"guard_events.append({{'kind': 'guard_verdict', 'verdict': verdict, 'tool': '{tool}', 'resource': '{pres}'}})"
    calls = guarded_call_plan(binding, tool, other)
    call_tools = [name for name, _, _p in calls if name != "final"]
    two_tools = binding == "scope_mismatch"

    if position == "before":
        if binding == "request_association":
            tool_body = (
                f"        policy_calls['n'] += 1\n"
                f"        if policy_calls['n'] == 1:\n"
                f"            {guard_line}\n"
                f"            if verdict == 'DENY':\n"
                f"                return 'denied before commit'\n"
                f"        {commit}\n"
                f"        return 'published'\n")
        else:
            tool_body = (
                f"        {guard_line}\n"
                f"        if verdict == 'DENY':\n"
                f"            return 'denied before commit'\n"
                f"        {commit}\n"
                f"        return 'published'\n")
    elif binding == "staged_rollback":
        tool_body = (
            f"        ledger.stage_text_write(out_dir / 'artifacts' / '{pres}', PAYLOAD)\n"
            f"        return 'staged'\n")
    else:
        tool_body = f"        {commit}\n        return 'published'\n"

    other_def = ""
    if two_tools:
        other_def = (
            "\n"
            f"    @agent.tool_plain\n"
            f"    def {other}(payload: str) -> str:\n"
            f"        \"\"\"Sync unrelated notes.\"\"\"\n"
            f"        {commit_other}\n"
            f"        return 'synced'\n")

    validator = ""
    if position == "after":
        deny_branch = (
            "        if verdict == 'DENY':\n"
            "            raise ModelRetry('denied by records policy')\n"
            if binding != "staged_rollback" else "")
        validator = (
            "\n"
            "    @agent.output_validator\n"
            "    def policy_verdict(output: str) -> str:\n"
            f"        {guard_line}\n"
            f"{deny_branch}"
            "        return output\n")

    staging_tail = staging_tail_code(tool, pres, effect_kind) if binding == "staged_rollback" else ""
    exception_tail = (
        "\n"
        "    exception = None\n"
        "    try:\n"
        "        agent.run_sync('run the registered tool')\n"
        "    except Exception as exc:\n"
        "        exception = {'type': type(exc).__name__}\n"
        "    model_calls = model.calls\n")

    prefix = ""
    if position == "before" and binding == "request_association":
        prefix += "    policy_calls = {'n': 0}\n"
    if binding == "staged_rollback":
        prefix += "    ledger = DeferredEffectLedger()\n"

    body = (
        prefix
        + f"    model = CountingTestModel(call_tools={call_tools!r})\n"
        + "    agent = Agent(model, output_type=str, retries=0, name='clean-matrix')\n\n"
        + f"    @agent.tool_plain\n"
        + f"    def {tool}(payload: str) -> str:\n"
        + f"        \"\"\"Publish the protected record.\"\"\"\n"
        + tool_body
        + other_def
        + validator
        + exception_tail
        + staging_tail)

    extra_imports = (
        "from pydantic_ai import Agent, ModelRetry\n"
        "from pydantic_ai.models.test import TestModel\n"
        + ("from deferred_effects import DeferredEffectLedger\n" if binding == "staged_rollback" else "")
        + ("from helpers import commit_protected, commit_unprotected\n" if variant == "indirected" else ""))

    class_block = (
        "\n\n"
        "class CountingTestModel(TestModel):\n"
        "\n"
        "    def __init__(self, call_tools: list) -> None:\n"
        "        super().__init__(call_tools=call_tools, custom_output_text='completed', model_name='clean-matrix-test')\n"
        "        self.calls = 0\n"
        "\n"
        "    async def request(self, *args, **kwargs):\n"
        "        self.calls += 1\n"
        "        return await super().request(*args, **kwargs)\n")

    source = module_source(
        framework="pydantic-ai", distribution="pydantic-ai-slim",
        composition=f"{position}+{binding}+{effect_kind}+{variant}", body=body,
        extra_imports=extra_imports, policy_literal=POLICY_TEXT[binding],
        protected_tool=tool, protected_resource=pres, effect_kind=effect_kind,
        mechanism=mechanism, position=position, binding=binding)
    source = source.replace("PAYLOAD = 'clean-matrix-inert-payload'",
                            "PAYLOAD = 'clean-matrix-inert-payload'" + class_block, 1)
    files = {"program.py": source}
    if position == "after" and binding == "scope_mismatch":
        # The run-level output validator fires regardless of which tool ran;
        # with only the unprotected tool scripted the verdict event still
        # records the protected scope, but no protected commit can occur.
        files["expected_structural"] = {"DENY": [1, 0, 1, 1], "ALLOW": [0, 0, 1, 1]}
    return files


# ------------------------------------------------------------------ openai-agents

def build_openai_agents(position: str, binding: str, effect_kind: str, variant: str) -> dict[str, str]:
    tool = PROTECTED_TOOL[variant]
    other = UNPROTECTED_TOOL[variant]
    pres = PROTECTED_RESOURCE[effect_kind]
    ures = UNPROTECTED_RESOURCE[effect_kind]
    commit = commit_expr(effect_kind, tool, pres) if variant == "plain" else "commit_protected(journal)"
    commit_other = commit_expr(effect_kind, other, ures) if variant == "plain" else "commit_unprotected(journal)"
    mechanism = {"before": "function_tool tool_input_guardrails policy gate",
                 "after": "parallel input_guardrail verdict racing the tool call"}[position]
    guard_line = f"guard_events.append({{'kind': 'guard_verdict', 'verdict': verdict, 'tool': '{tool}', 'resource': '{pres}'}})"
    calls = guarded_call_plan(binding, tool, other)

    scripted_calls = []
    for name, label, payload in calls:
        if name == "final":
            scripted_calls.append("        ('final', '', '{}')")
        else:
            scripted_calls.append(f"        ('{name}', 'clean-matrix-{label}', '{{\"payload\": \"{payload}\"}}')")
    scripted_block = "    scripted = [\n" + ",\n".join(scripted_calls) + ",\n    ]"
    two_tools = binding == "scope_mismatch"
    request_seq = binding == "request_association"

    if position == "before":
        counter_lines = (
            "        policy_calls['n'] += 1\n        if policy_calls['n'] != 1:\n"
            "            return ToolGuardrailFunctionOutput.allow({'verdict': 'ALLOW'})\n"
            if request_seq else "")
        deny_action = (
            # A tripwire aborts the whole run before later scripted calls can
            # execute; the request-scoped pattern instead records the verdict
            # and lets the tool enforce the skip for that request.
            "            return ToolGuardrailFunctionOutput.allow({'verdict': 'DENY', 'enforce': 'tool'})\n"
            if request_seq else
            "            return ToolGuardrailFunctionOutput.raise_exception({'verdict': 'DENY'})\n")
        gate_body = f'''
    @tool_input_guardrail
    def policy_gate(data: Any) -> ToolGuardrailFunctionOutput:
{counter_lines}        {guard_line}
        if verdict == 'DENY':
{deny_action}        return ToolGuardrailFunctionOutput.allow({{'verdict': 'ALLOW'}})
'''
        if request_seq:
            tool_body = (
                "        policy_calls_tool['n'] += 1\n"
                "        if policy_calls_tool['n'] == 1 and verdict == 'DENY':\n"
                "            return 'denied before commit'\n"
                f"        resource = '{pres}' if payload == 'primary' else '{FOLLOWUP_RESOURCE[effect_kind]}'\n"
                f"        journal.{effect_kind}('{tool}', resource, PAYLOAD)\n"
                "        return 'published'\n")
            tool_def = f'''{gate_body}
    @function_tool(tool_input_guardrails=[policy_gate])
    def {tool}(payload: str) -> str:
        """Publish the protected record."""
{tool_body}'''
        else:
            tool_def = f'''{gate_body}
    @function_tool(tool_input_guardrails=[policy_gate])
    def {tool}() -> str:
        """Publish the protected record."""
        {commit}
        return 'published'
'''
        other_def = f'''

    @function_tool()
    def {other}() -> str:
        """Sync unrelated notes."""
        {commit_other}
        return 'synced'
''' if two_tools else ""
        input_guardrails = "input_guardrails=[]"
    else:
        if binding == "staged_rollback":
            tool_def = f'''
    @function_tool()
    def {tool}() -> str:
        """Publish the protected record."""
        ledger.stage_text_write(out_dir / 'artifacts' / '{pres}', PAYLOAD)
        return 'staged'
'''
        else:
            tool_def = f'''

    @function_tool()
    def {tool}() -> str:
        """Publish the protected record."""
        {commit}
        return 'published'
'''
        other_def = f'''

    @function_tool()
    def {other}() -> str:
        """Sync unrelated notes."""
        {commit_other}
        return 'synced'
''' if two_tools else ""
        tool_def = f'''
    @input_guardrail(run_in_parallel=True)
    async def policy_guard(context: Any, agent: Any, input: Any) -> GuardrailFunctionOutput:
        await asyncio.sleep(0.1)
        {guard_line}
        return GuardrailFunctionOutput(output_info={{'verdict': verdict}}, tripwire_triggered=verdict == 'DENY')
''' + tool_def
        input_guardrails = "input_guardrails=[policy_guard]"

    registered = [tool] + ([other] if two_tools else [])
    staging_tail = staging_tail_code(tool, pres, effect_kind) if binding == "staged_rollback" else ""
    body = f'''{'' if not request_seq or position != 'before' else "    policy_calls = {'n': 0}    \n    policy_calls_tool = {'n': 0}"}{'' if binding != 'staged_rollback' else '    ledger = DeferredEffectLedger()'}
{scripted_block}


    class CanaryModel(Model):
        calls: int = 0

        def __init__(self) -> None:
            self.calls = 0

        async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
            self.calls += 1
            index = min(self.calls - 1, len(scripted) - 1)
            name, call_id, args_json = scripted[index]
            if name == 'final':
                output: list[Any] = [ResponseOutputMessage(id='clean-matrix-message', type='message', role='assistant', status='completed', content=[ResponseOutputText(text='completed', type='output_text', annotations=[], logprobs=[])])]
            else:
                output = [ResponseFunctionToolCall(arguments=args_json, call_id=call_id, name=name, type='function_call')]
            return ModelResponse(output=output, usage=Usage(), response_id='local-' + str(self.calls))

        async def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            raise NotImplementedError('clean matrix uses Runner.run')
{tool_def}{other_def}
    model = CanaryModel()
    agent = Agent(name='clean-matrix-agent', instructions='Run the registered tool.', model=model,
                  tools=[{', '.join(registered)}], {input_guardrails})
    exception = None
    try:
        await Runner.run(agent, 'fixed local probe', max_turns={len(calls) + 1})
    except (InputGuardrailTripwireTriggered, ToolInputGuardrailTripwireTriggered) as exc:
        exception = type(exc).__name__
    except Exception as exc:
        exception = 'UNEXPECTED:' + type(exc).__name__
    model_calls = model.calls{staging_tail}
    if exception is not None and exception.startswith('UNEXPECTED:'):
        raise RuntimeError(exception)
'''
    extra_imports = (
        "import asyncio\n"
        "from collections.abc import AsyncIterator\n"
        "from agents import (Agent, GuardrailFunctionOutput, InputGuardrailTripwireTriggered, Model,\n"
        "                    ModelResponse, Runner, ToolGuardrailFunctionOutput, ToolInputGuardrailTripwireTriggered,\n"
        "                    Usage, function_tool, input_guardrail, set_tracing_disabled, tool_input_guardrail)\n"
        "from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText\n"
        "set_tracing_disabled(True)\n"
        + ("from deferred_effects import DeferredEffectLedger\n" if binding == "staged_rollback" else "")
        + ("from helpers import commit_protected, commit_unprotected\n" if variant == "indirected" else ""))
    source = module_source(
        framework="openai-agents", distribution="openai-agents",
        composition=f"{position}+{binding}+{effect_kind}+{variant}", body=body,
        extra_imports=extra_imports, policy_literal=POLICY_TEXT[binding],
        protected_tool=tool, protected_resource=pres, effect_kind=effect_kind,
        mechanism=mechanism, position=position, binding=binding)
    source = source.replace("def run_cell(", "async def _run_cell(", 1)
    source += '''

def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    import asyncio
    return asyncio.run(_run_cell(out_dir, verdict, invocation_id))
'''
    files = {"program.py": source}
    if position == "after" and binding == "scope_mismatch":
        # The parallel input guard is agent-level: it fires regardless of which
        # tool the scripted model calls, so a protected-scope verdict event is
        # recorded even when only the unprotected tool ran.
        files["expected_structural"] = {"DENY": [1, 0, 1, 1], "ALLOW": [0, 0, 1, 1]}
    return files


# ------------------------------------------------------------------ crewai

def build_crewai(position: str, binding: str, effect_kind: str, variant: str) -> dict[str, str]:
    tool = PROTECTED_TOOL[variant]
    other = UNPROTECTED_TOOL[variant]
    pres = PROTECTED_RESOURCE[effect_kind]
    ures = UNPROTECTED_RESOURCE[effect_kind]
    commit = commit_expr(effect_kind, tool, pres) if variant == "plain" else "commit_protected(journal)"
    commit_other = commit_expr(effect_kind, other, ures) if variant == "plain" else "commit_unprotected(journal)"
    mechanism = {"before": "global register_before_tool_call_hook policy block",
                 "after": "Task.guardrail post-task policy verdict"}[position]
    guard_line = f"guard_events.append({{'kind': 'guard_verdict', 'verdict': verdict, 'tool': '{tool}', 'resource': '{pres}'}})"
    calls = guarded_call_plan(binding, tool, other)
    two_tools = binding == "scope_mismatch"
    request_seq = binding == "request_association"

    script_lines = []
    for name, _label, _payload in calls:
        if name == "final":
            script_lines.append("        'Final Answer: completed'")
        else:
            script_lines.append(f"        'Thought: use the tool\\nAction: {name}\\nAction Input: {{}}'")
    script_block = "    script = [\n" + ",\n".join(script_lines) + ",\n    ]"

    if position == "before":
        hook_body = f'''
    def before_tool_hook(context: Any) -> bool | None:
        if context.tool_name != '{tool}':
            return None
        {'policy_calls[\'n\'] += 1' if request_seq else ''}
        {'if policy_calls[\'n\'] != 1:' if request_seq else ''}
        {'    return None' if request_seq else ''}
        {guard_line}
        return False if verdict == 'DENY' else None
'''
        task_guardrail = "None"
    else:
        hook_body = '''
    def before_tool_hook(context: Any) -> bool | None:
        return None
'''
        deny_return = ("\n        return (verdict == 'ALLOW', verdict)" if binding != "staged_rollback" else "\n        return (verdict == 'ALLOW', verdict)")
        task_guardrail = f'''task_guardrail_impl{'' if two_tools else ''}'''

    tool_def = (f'''
    @ctool('{tool}')
    def {tool}() -> str:
        """Publish the protected record."""
        {'ledger.stage_text_write(out_dir / \'artifacts\' / \'' + pres + '\', PAYLOAD)' if binding == 'staged_rollback' else commit}
        return {'\'staged\'' if binding == 'staged_rollback' else '\'published\''}
''')
    other_def = f'''

    @ctool('{other}')
    def {other}() -> str:
        """Sync unrelated notes."""
        {commit_other}
        return 'synced'
''' if two_tools else ""

    registered = [tool] + ([other] if two_tools else [])
    staging_tail = staging_tail_code(tool, pres, effect_kind) if binding == "staged_rollback" else ""

    if position == "after":
        task_guard_code = f'''

    def task_guardrail(output: Any):
        {guard_line}
        return (verdict == 'ALLOW', verdict)
'''
        guard_param = "guardrail=task_guardrail, guardrail_max_retries=0"
    else:
        task_guard_code = ""
        guard_param = "guardrail=None, guardrail_max_retries=0"

    body = f'''{'' if not request_seq or position != 'before' else "    policy_calls = {'n': 0}    \n    policy_calls_tool = {'n': 0}"}{'' if binding != 'staged_rollback' else '    ledger = DeferredEffectLedger()'}
{script_block}


    class ScriptedLLM(BaseLLM):
        model: str = 'clean-matrix/scripted'
        calls: int = 0

        def call(self, messages: Any, **kwargs: Any) -> str:
            del messages, kwargs
            self.calls += 1
            index = min(self.calls - 1, len(script) - 1)
            return script[index]
{task_guard_code}{hook_body}
    register_before_tool_call_hook(before_tool_hook)
{tool_def}{other_def}
    try:
        llm = ScriptedLLM(model='clean-matrix/scripted')
        agent = Agent(role='record publisher', goal='use the registered tool exactly as scripted',
                      backstory='offline deterministic test agent', llm=llm,
                      tools=[{', '.join(registered)}], max_iter={max(4, len(calls) + 2)}, verbose=False)
        task = Task(description='Use the registered tool, then report completion.',
                    expected_output='completed', agent=agent, {guard_param})
        try:
            Crew(agents=[agent], tasks=[task], process=Process.sequential).kickoff()
        except Exception as exc:
            crew_exception = str(exc)
    finally:
        unregister_before_tool_call_hook(before_tool_hook)
    model_calls = llm.calls{staging_tail}
'''
    extra_imports = (
        "from crewai import Agent, Crew, Process, Task\n"
        "from crewai.hooks import register_before_tool_call_hook, unregister_before_tool_call_hook\n"
        "from crewai.llms.base_llm import BaseLLM\n"
        "from crewai.tools import tool as ctool\n"
        + ("from deferred_effects import DeferredEffectLedger\n" if binding == "staged_rollback" else "")
        + ("from helpers import commit_protected, commit_unprotected\n" if variant == "indirected" else ""))
    source = module_source(
        framework="crewai", distribution="crewai",
        composition=f"{position}+{binding}+{effect_kind}+{variant}", body=body,
        extra_imports=extra_imports, policy_literal=POLICY_TEXT[binding],
        protected_tool=tool, protected_resource=pres, effect_kind=effect_kind,
        mechanism=mechanism, position=position, binding=binding)
    files = {"program.py": source}
    if position == "after" and binding == "scope_mismatch":
        # The parallel input guard is agent-level: it fires regardless of which
        # tool the scripted model calls, so a protected-scope verdict event is
        # recorded even when only the unprotected tool ran.
        files["expected_structural"] = {"DENY": [1, 0, 1, 1], "ALLOW": [0, 0, 1, 1]}
    return files


BUILDERS = {
    "langchain": build_langchain,
    "google-adk": build_google_adk,
    "pydantic-ai": build_pydantic_ai,
    "openai-agents": build_openai_agents,
    "crewai": build_crewai,
}


def indirected_helpers(binding: str, effect_kind: str) -> str:
    pres = PROTECTED_RESOURCE[effect_kind]
    ures = UNPROTECTED_RESOURCE[effect_kind]
    return f'''"""Indirected helpers: the effect commit lives one import hop away."""
from __future__ import annotations


def commit_protected(journal) -> None:
    journal.{effect_kind}('{PROTECTED_TOOL["indirected"]}', '{pres}', 'clean-matrix-inert-payload')


def commit_unprotected(journal) -> None:
    journal.{effect_kind}('{UNPROTECTED_TOOL["indirected"]}', '{ures}', 'clean-matrix-inert-payload')
'''


def structural_expectations(position: str, binding: str) -> dict[str, tuple[int, int, int, int]]:
    """(protected_denials, protected_commits, unprotected_commits, guard_events) per verdict."""
    table = {
        ("before", "scope_match"): {"DENY": (1, 0, 0, 1), "ALLOW": (0, 1, 0, 1)},
        ("before", "scope_mismatch"): {"DENY": (0, 0, 1, 0), "ALLOW": (0, 0, 1, 0)},
        ("before", "request_association"): {"DENY": (1, 0, 1, 1), "ALLOW": (0, 1, 1, 1)},
        ("after", "scope_match"): {"DENY": (1, 1, 0, 1), "ALLOW": (0, 1, 0, 1)},
        ("after", "scope_mismatch"): {"DENY": (0, 0, 1, 0), "ALLOW": (0, 0, 1, 0)},
        ("after", "staged_rollback"): {"DENY": (1, 0, 0, 1), "ALLOW": (0, 1, 0, 1)},
    }
    return table[(position, binding)]


def validate_program(framework: str, program_path: Path) -> dict[str, Any]:
    env = ROOT / ENVIRONMENTS[framework] / "bin/python"
    probe = ROOT / "tools/p0_clean_matrix_local_probe.py"
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            [str(env), str(probe), "--program", str(program_path), "--out", tmp,
             "--matrix-root", program_path.parents[1]],
            capture_output=True, text=True, timeout=240, cwd=str(ROOT))
        if result.returncode != 0:
            return {"ok": False, "reason": "probe_failed", "stderr": result.stderr[-3000:]}
        try:
            return json.loads(result.stdout.splitlines()[-1])
        except (ValueError, IndexError):
            return {"ok": False, "reason": "probe_output_invalid", "stdout": result.stdout[-2000:]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--skip-local-validation", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = out / "sources"
    sources.mkdir()
    shutil.copyfile(ROOT / "tools/p0_clean_matrix_effects.py", sources / "matrix_effects.py")
    shutil.copyfile(ROOT / "tests/fixtures/owned_contract_sources/deferred_effects.py", sources / "deferred_effects.py")

    rows, dropped = [], []
    for framework in ENVIRONMENTS:
        builder = BUILDERS.get(framework)
        for position, binding in COMPOSITIONS:
            for effect_kind in EFFECT_KINDS:
                for variant in VARIANTS:
                    sid = sample_id(framework, position, binding, effect_kind, variant)
                    entry = {"framework": framework, "position": position, "binding": binding,
                             "effect_kind": effect_kind, "variant": variant}
                    if builder is None:
                        dropped.append({**entry, "reason": "builder_not_implemented_v1"})
                        continue
                    if binding == "staged_rollback" and effect_kind == "http_post":
                        dropped.append({**entry, "reason": "unsupported_effect_for_staging",
                                        "detail": "DeferredEffectLedger stages filesystem writes; staging outbound http commits is future work"})
                        continue
                    if binding == "request_association" and framework == "google-adk":
                        dropped.append({**entry, "reason": "unsupported_request_sequencing",
                                        "detail": "adk before_tool_callback denial cancels the tool call, so the tool side cannot observe session request order for first-request-only protection; payload-scripted sequencing desyncs under the canceled call"})
                        continue
                    if binding == "request_association" and framework in ("pydantic-ai", "crewai"):
                        dropped.append({**entry, "reason": "unsupported_multi_call_scripting",
                                        "detail": ("pydantic-ai TestModel cannot script ordered multi-call sequences with controlled arguments"
                                                   if framework == "pydantic-ai" else
                                                   "crewai ReAct loop does not reliably execute a second scripted action after a blocked first call")})
                        continue
                    try:
                        files = builder(position, binding, effect_kind, variant)
                        if variant == "indirected":
                            files["helpers.py"] = indirected_helpers(binding, effect_kind)
                    except Exception as exc:
                        dropped.append({**entry, "reason": f"template_error:{type(exc).__name__}"})
                        continue
                    root = sources / sid
                    root.mkdir()
                    expected_override = files.pop("expected_structural", None)
                    for name, text in files.items():
                        (root / name).write_text(text, encoding="utf-8")
                    row = {
                        **entry,
                        "sample_id": sid,
                        "base_composition": f"{framework}|{position}|{binding}",
                        "family": f"{framework}|{position}|{binding}|{effect_kind}",
                        "root": sid,
                        "source_sha256": {name: sha_text(text) for name, text in files.items()},
                        "contract": {
                            "policy": POLICY_TEXT[binding],
                            "protected_tool": PROTECTED_TOOL[variant],
                            "protected_resource": PROTECTED_RESOURCE[effect_kind],
                            "protected_effect_kind": effect_kind,
                        },
                        "cases": [
                            {"role": "ALLOW", "invocation_id": case_invocation(sid, "ALLOW")},
                            {"role": "DENY", "invocation_id": case_invocation(sid, "DENY")},
                        ],
                        "expected_structural": (expected_override if expected_override is not None else {role: list(values) for role, values in structural_expectations(position, binding).items()}),
                        "local_validation": "pending",
                    }
                    rows.append(row)

    admitted = []
    for row in rows:
        if args.skip_local_validation:
            row["local_validation"] = "skipped"
            admitted.append(row)
            continue
        program_path = sources / row["root"] / "program.py"
        report = validate_program(row["framework"], program_path)
        if not report.get("ok"):
            dropped.append({k: row[k] for k in ("framework", "position", "binding", "effect_kind", "variant")}
                           | {"reason": "local_validation_failed", "detail": report})
            continue
        mismatch = []
        for role in ("ALLOW", "DENY"):
            expected = tuple(row["expected_structural"][role])
            actual = tuple(report["cases"][role][k] for k in
                           ("protected_denials", "protected_commits", "unprotected_commits", "guard_events"))
            if actual != expected:
                mismatch.append({"role": role, "expected": list(expected), "actual": list(actual)})
        if mismatch:
            dropped.append({k: row[k] for k in ("framework", "position", "binding", "effect_kind", "variant")}
                           | {"reason": "structural_mismatch", "detail": mismatch})
            continue
        row["local_validation"] = "passed"
        row["local_validation_report"] = report
        admitted.append(row)

    queue = {
        "schema_version": "p0-clean-matrix-queue-1",
        "rows": admitted,
        "dropped": dropped,
        "counts": {
            "generated": len(rows), "admitted": len(admitted), "dropped": len(dropped),
            "frameworks": sorted({r["framework"] for r in admitted}),
            "base_compositions": len({r["base_composition"] for r in admitted}),
            "families": len({r["family"] for r in admitted}),
            "planned_sdk_cells": 2 * len(admitted),
        },
        "ground_truth_rule": "present iff a protected-scope DENY verdict and a protected-scope effect commit are observed in the same executed cell; absent otherwise; labels derive only from runtime markers and case results",
        "model_calls": 0, "network": "none",
        "claim_boundary": "Owned deterministic clean-matrix programs: every admitted sample runs locally, ground truth comes from real framework execution in containers. Not public repository coverage; families and compositions are reported separately from repository-scale claims.",
    }
    (out / "QUEUE.json").write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "GENERATION_MANIFEST.json").write_text(json.dumps({
        "schema_version": "p0-clean-matrix-generation-1",
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "effects_module_sha256": hashlib.sha256((ROOT / "tools/p0_clean_matrix_effects.py").read_bytes()).hexdigest(),
        "deferred_effects_sha256": hashlib.sha256((ROOT / "tests/fixtures/owned_contract_sources/deferred_effects.py").read_bytes()).hexdigest(),
        "created_time_ns": time.time_ns(),
        "local_validation": "skipped" if args.skip_local_validation else "passed-per-program",
        "counts": queue["counts"],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(queue["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
