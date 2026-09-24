"""Owned clean-matrix program: after+staged_rollback+file_write+plain.

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
from deferred_effects import DeferredEffectLedger


PAYLOAD = 'clean-matrix-inert-payload'

CONTRACT = {
    'policy': 'Publish effects are staged until the policy verdict accepts them; DENY must abort the staged write before commit.',
    'protected_operation': 'publish protected record',
    'protected_tool': 'publish_record',
    'protected_resource': 'records/primary-record.json',
    'protected_effect_kind': 'file_write',
    'mechanism': 'parallel input_guardrail verdict racing the tool call',
    'guard_position': 'after',
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
    ledger = DeferredEffectLedger()
    scripted = [
        ('publish_record', 'clean-matrix-call-1', '{"payload": "primary"}'),
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

    @input_guardrail(run_in_parallel=True)
    async def policy_guard(context: Any, agent: Any, input: Any) -> GuardrailFunctionOutput:
        await asyncio.sleep(0.1)
        guard_events.append({'kind': 'guard_verdict', 'verdict': verdict, 'tool': 'publish_record', 'resource': 'records/primary-record.json'})
        return GuardrailFunctionOutput(output_info={'verdict': verdict}, tripwire_triggered=verdict == 'DENY')

    @function_tool()
    def publish_record() -> str:
        """Publish the protected record."""
        ledger.stage_text_write(out_dir / 'artifacts' / 'records/primary-record.json', PAYLOAD)
        return 'staged'

    model = CanaryModel()
    agent = Agent(name='clean-matrix-agent', instructions='Run the registered tool.', model=model,
                  tools=[publish_record], input_guardrails=[policy_guard])
    exception = None
    try:
        await Runner.run(agent, 'fixed local probe', max_turns=3)
    except (InputGuardrailTripwireTriggered, ToolInputGuardrailTripwireTriggered) as exc:
        exception = type(exc).__name__
    except Exception as exc:
        exception = 'UNEXPECTED:' + type(exc).__name__
    model_calls = model.calls
    if verdict == 'DENY':
        ledger.abort()
    else:
        (out_dir / 'artifacts' / 'records').mkdir(parents=True, exist_ok=True)
        ledger.commit()
        journal.record_commit('file_write', 'publish_record', 'records/primary-record.json', PAYLOAD)

    if exception is not None and exception.startswith('UNEXPECTED:'):
        raise RuntimeError(exception)

    return {
        'framework': 'openai-agents',
        'framework_version': _framework_version(),
        'binding': 'staged_rollback',
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
