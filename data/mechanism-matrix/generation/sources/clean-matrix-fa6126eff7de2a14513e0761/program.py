"""Owned clean-matrix program: after+scope_match+http_post+plain.

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


PAYLOAD = 'clean-matrix-inert-payload'

CONTRACT = {
    'policy': 'The publish channel is protected: when the policy guard denies, no publish effect may commit in that same invocation.',
    'protected_operation': 'publish protected record',
    'protected_tool': 'publish_record',
    'protected_resource': 'https://internal.example/api/records',
    'protected_effect_kind': 'http_post',
    'mechanism': 'AgentMiddleware.wrap_tool_call post-handler policy verdict',
    'guard_position': 'after',
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
            result = handler(request)
            guard_events.append({'kind': 'guard_verdict', 'verdict': verdict, 'tool': 'publish_record', 'resource': 'https://internal.example/api/records'})
            if verdict == 'DENY':
                return ToolMessage(content='denied by records policy', tool_call_id=request.tool_call['id'])
            return result


    @lc_tool
    def publish_record() -> str:
        """Publish the protected record."""
        journal.http_post('publish_record', 'https://internal.example/api/records', PAYLOAD)
        return 'published'


    calls = [('publish_record', 'call-1', 'primary'), ('final', '', '')]


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
    agent = create_agent(model, tools=[publish_record], middleware=[PolicyMiddleware()])
    agent.invoke({'messages': [{'role': 'user', 'content': 'run the registered tool'}]})
    model_calls = model.calls


    return {
        'framework': 'langchain',
        'framework_version': _framework_version(),
        'binding': 'scope_match',
        'guard_position': 'after',
        'verdict': verdict,
        'invocation_id': invocation_id,
        'effects': journal.events,
        'guard_events': guard_events,
        'model_calls': model_calls,
        'execution_health': 'completed',
    }
