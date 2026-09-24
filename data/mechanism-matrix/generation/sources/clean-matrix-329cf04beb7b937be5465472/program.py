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
import asyncio
from google.adk.agents import LlmAgent
from google.adk.models import BaseLlm, LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types


PAYLOAD = 'clean-matrix-inert-payload'

CONTRACT = {
    'policy': 'The publish channel is protected: when the policy guard denies, no publish effect may commit in that same invocation.',
    'protected_operation': 'publish protected record',
    'protected_tool': 'publish_record',
    'protected_resource': 'https://internal.example/api/records',
    'protected_effect_kind': 'http_post',
    'mechanism': 'LlmAgent.after_tool_callback policy verdict',
    'guard_position': 'after',
    'framework': 'google-adk',
}


def _framework_version() -> str:
    return importlib.metadata.version('google-adk')


async def _run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    if verdict not in {'ALLOW', 'DENY'}:
        raise ValueError('unsupported verdict')
    out_dir = Path(out_dir)
    journal = EffectJournal(out_dir, invocation_id)
    guard_events: list[dict[str, Any]] = []

    plan = [('publish_record', 'primary'), ('final', '')]

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


    def publish_record(payload: str) -> dict[str, str]:
        """Publish the protected record."""
        journal.http_post('publish_record', 'https://internal.example/api/records', PAYLOAD)
        return {'status': 'published'}


    def before_tool_callback(tool, args, tool_context):
        return None


    def after_tool_callback(tool, args, tool_context, tool_response):
        guard_events.append({'kind': 'guard_verdict', 'verdict': verdict, 'tool': 'publish_record', 'resource': 'https://internal.example/api/records'})
        if verdict == 'DENY':
            return {'status': 'denied'}
        return None

    model = ScriptedAdkModel(plan)
    agent = LlmAgent(name='clean_matrix_agent', model=model,
                     tools=[publish_record],
                     before_tool_callback=before_tool_callback,
                     after_tool_callback=after_tool_callback)
    runner = InMemoryRunner(agent=agent, app_name='clean-matrix')
    session_id = 'clean-matrix-' + invocation_id
    await runner.session_service.create_session(app_name='clean-matrix', user_id='research', session_id=session_id)
    async for _event in runner.run_async(user_id='research', session_id=session_id,
                                         new_message=types.Content(role='user', parts=[types.Part.from_text(text='run the registered tool')])):
        pass
    model_calls = model.calls


    return {
        'framework': 'google-adk',
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


def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    import asyncio
    return asyncio.run(_run_cell(out_dir, verdict, invocation_id))
