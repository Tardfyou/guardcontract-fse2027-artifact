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
from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool as lc_tool
from helpers import commit_protected, commit_unprotected


PAYLOAD = 'clean-matrix-inert-payload'

CONTRACT = {
    'policy': 'Only the publish tool on the records API is protected; the notes tool is outside the protection contract.',
    'protected_operation': 'publish protected record',
    'protected_tool': 'emit_log_entry',
    'protected_resource': 'records/primary-record.json',
    'protected_effect_kind': 'file_write',
    'mechanism': 'AgentMiddleware.wrap_tool_call pre-handler policy check',
    'guard_position': 'before',
    'framework': 'langchain',
}


def _framework_version() -> str:
    return importlib.metadata.version('langchain')


def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    if verdict not in {'ALLOW', 'DENY'}:
        raise ValueError('unsupported verdict')
    out_dir = Path(out_dir)
    journal = EffectJournal(out_dir, invocation_id)
    guard_events: list[dict[str, Any]] = []


    class PolicyMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            if request.tool_call['name'] != 'emit_log_entry':
                return handler(request)
            guard_events.append({'kind': 'guard_verdict', 'verdict': verdict, 'tool': 'emit_log_entry', 'resource': 'records/primary-record.json'})
            if verdict == 'DENY':
                return ToolMessage(content='denied by records policy', tool_call_id=request.tool_call['id'])
            return handler(request)


    @lc_tool
    def emit_log_entry() -> str:
        """Publish the protected record."""
        commit_protected(journal)
        return 'published'



    @lc_tool
    def mirror_notes() -> str:
        """Sync unrelated notes."""
        commit_unprotected(journal)
        return 'synced'

    calls = [('mirror_notes', 'call-b', 'primary'), ('final', '', '')]


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
    agent = create_agent(model, tools=[emit_log_entry, mirror_notes], middleware=[PolicyMiddleware()])
    agent.invoke({'messages': [{'role': 'user', 'content': 'run the registered tool'}]})
    model_calls = model.calls


    return {
        'framework': 'langchain',
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
