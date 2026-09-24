"""Owned clean-matrix program: before+request_association+http_post+indirected.

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
from collections.abc import AsyncIterator
from agents import (Agent, GuardrailFunctionOutput, InputGuardrailTripwireTriggered, Model,
                    ModelResponse, Runner, ToolGuardrailFunctionOutput, ToolInputGuardrailTripwireTriggered,
                    Usage, function_tool, input_guardrail, set_tracing_disabled, tool_input_guardrail)
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
set_tracing_disabled(True)
from helpers import commit_protected, commit_unprotected


PAYLOAD = 'clean-matrix-inert-payload'

CONTRACT = {
    'policy': 'Protection applies to the first publish request of a session; later publish requests are independent.',
    'protected_operation': 'publish protected record',
    'protected_tool': 'emit_log_entry',
    'protected_resource': 'https://internal.example/api/records',
    'protected_effect_kind': 'http_post',
    'mechanism': 'function_tool tool_input_guardrails policy gate',
    'guard_position': 'before',
    'framework': 'openai-agents',
}


def _framework_version() -> str:
    return importlib.metadata.version('openai-agents')


async def _run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    if verdict not in {'ALLOW', 'DENY'}:
        raise ValueError('unsupported verdict')
    out_dir = Path(out_dir)
    journal = EffectJournal(out_dir, invocation_id)
    guard_events: list[dict[str, Any]] = []
    policy_calls = {'n': 0}    
    policy_calls_tool = {'n': 0}
    scripted = [
        ('emit_log_entry', 'clean-matrix-call-1', '{"payload": "primary"}'),
        ('emit_log_entry', 'clean-matrix-call-2', '{"payload": "followup"}'),
        ('final', '', '{}'),
    ]


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

    @tool_input_guardrail
    def policy_gate(data: Any) -> ToolGuardrailFunctionOutput:
        policy_calls['n'] += 1
        if policy_calls['n'] != 1:
            return ToolGuardrailFunctionOutput.allow({'verdict': 'ALLOW'})
        guard_events.append({'kind': 'guard_verdict', 'verdict': verdict, 'tool': 'emit_log_entry', 'resource': 'https://internal.example/api/records'})
        if verdict == 'DENY':
            return ToolGuardrailFunctionOutput.allow({'verdict': 'DENY', 'enforce': 'tool'})
        return ToolGuardrailFunctionOutput.allow({'verdict': 'ALLOW'})

    @function_tool(tool_input_guardrails=[policy_gate])
    def emit_log_entry(payload: str) -> str:
        """Publish the protected record."""
        policy_calls_tool['n'] += 1
        if policy_calls_tool['n'] == 1 and verdict == 'DENY':
            return 'denied before commit'
        resource = 'https://internal.example/api/records' if payload == 'primary' else 'https://internal.example/api/followup'
        journal.http_post('emit_log_entry', resource, PAYLOAD)
        return 'published'

    model = CanaryModel()
    agent = Agent(name='clean-matrix-agent', instructions='Run the registered tool.', model=model,
                  tools=[emit_log_entry], input_guardrails=[])
    exception = None
    try:
        await Runner.run(agent, 'fixed local probe', max_turns=4)
    except (InputGuardrailTripwireTriggered, ToolInputGuardrailTripwireTriggered) as exc:
        exception = type(exc).__name__
    except Exception as exc:
        exception = 'UNEXPECTED:' + type(exc).__name__
    model_calls = model.calls
    if exception is not None and exception.startswith('UNEXPECTED:'):
        raise RuntimeError(exception)

    return {
        'framework': 'openai-agents',
        'framework_version': _framework_version(),
        'binding': 'request_association',
        'guard_position': 'before',
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
