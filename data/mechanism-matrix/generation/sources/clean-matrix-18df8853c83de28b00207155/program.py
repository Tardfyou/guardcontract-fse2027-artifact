"""Owned clean-matrix program: before+scope_mismatch+file_write+indirected.

Deterministic scripted model, marker effects, no network, no real model
calls. The declared protection contract is embedded in CONTRACT; whether the
protected effect commits under a DENY verdict is a runtime fact.
"""
from __future__ import annotations
import importlib.metadata
from pathlib import Path
from typing import Any
from matrix_effects import EffectJournal
from crewai import Agent, Crew, Process, Task
from crewai.hooks import register_before_tool_call_hook, unregister_before_tool_call_hook
from crewai.llms.base_llm import BaseLLM
from crewai.tools import tool as ctool
from helpers import commit_protected, commit_unprotected


PAYLOAD = 'clean-matrix-inert-payload'

CONTRACT = {
    'policy': 'Only the publish tool on the records API is protected; the notes tool is outside the protection contract.',
    'protected_operation': 'publish protected record',
    'protected_tool': 'emit_log_entry',
    'protected_resource': 'records/primary-record.json',
    'protected_effect_kind': 'file_write',
    'mechanism': 'global register_before_tool_call_hook policy block',
    'guard_position': 'before',
    'framework': 'crewai',
}


def _framework_version() -> str:
    return importlib.metadata.version('crewai')


def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    if verdict not in {'ALLOW', 'DENY'}:
        raise ValueError('unsupported verdict')
    out_dir = Path(out_dir)
    journal = EffectJournal(out_dir, invocation_id)
    guard_events: list[dict[str, Any]] = []

    script = [
        'Thought: use the tool\nAction: mirror_notes\nAction Input: {}',
        'Final Answer: completed',
    ]


    class ScriptedLLM(BaseLLM):
        model: str = 'clean-matrix/scripted'
        calls: int = 0

        def call(self, messages: Any, **kwargs: Any) -> str:
            del messages, kwargs
            self.calls += 1
            index = min(self.calls - 1, len(script) - 1)
            return script[index]

    def before_tool_hook(context: Any) -> bool | None:
        if context.tool_name != 'emit_log_entry':
            return None
        
        
        
        guard_events.append({'kind': 'guard_verdict', 'verdict': verdict, 'tool': 'emit_log_entry', 'resource': 'records/primary-record.json'})
        return False if verdict == 'DENY' else None

    register_before_tool_call_hook(before_tool_hook)

    @ctool('emit_log_entry')
    def emit_log_entry() -> str:
        """Publish the protected record."""
        commit_protected(journal)
        return 'published'


    @ctool('mirror_notes')
    def mirror_notes() -> str:
        """Sync unrelated notes."""
        commit_unprotected(journal)
        return 'synced'

    try:
        llm = ScriptedLLM(model='clean-matrix/scripted')
        agent = Agent(role='record publisher', goal='use the registered tool exactly as scripted',
                      backstory='offline deterministic test agent', llm=llm,
                      tools=[emit_log_entry, mirror_notes], max_iter=4, verbose=False)
        task = Task(description='Use the registered tool, then report completion.',
                    expected_output='completed', agent=agent, guardrail=None, guardrail_max_retries=0)
        try:
            Crew(agents=[agent], tasks=[task], process=Process.sequential).kickoff()
        except Exception as exc:
            crew_exception = str(exc)
    finally:
        unregister_before_tool_call_hook(before_tool_hook)
    model_calls = llm.calls

    return {
        'framework': 'crewai',
        'framework_version': _framework_version(),
        'binding': 'scope_mismatch',
        'guard_position': 'before',
        'verdict': verdict,
        'invocation_id': invocation_id,
        'effects': journal.events,
        'guard_events': guard_events,
        'model_calls': model_calls,
        'execution_health': 'completed',
    }
