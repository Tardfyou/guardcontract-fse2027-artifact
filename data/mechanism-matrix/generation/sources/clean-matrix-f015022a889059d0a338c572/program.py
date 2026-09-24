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
from pydantic_ai import Agent, ModelRetry
from pydantic_ai.models.test import TestModel
from deferred_effects import DeferredEffectLedger


PAYLOAD = 'clean-matrix-inert-payload'

class CountingTestModel(TestModel):

    def __init__(self, call_tools: list) -> None:
        super().__init__(call_tools=call_tools, custom_output_text='completed', model_name='clean-matrix-test')
        self.calls = 0

    async def request(self, *args, **kwargs):
        self.calls += 1
        return await super().request(*args, **kwargs)


CONTRACT = {
    'policy': 'Publish effects are staged until the policy verdict accepts them; DENY must abort the staged write before commit.',
    'protected_operation': 'publish protected record',
    'protected_tool': 'publish_record',
    'protected_resource': 'records/primary-record.json',
    'protected_effect_kind': 'file_write',
    'mechanism': 'Agent.output_validator post-run policy verdict',
    'guard_position': 'after',
    'framework': 'pydantic-ai',
}


def _framework_version() -> str:
    return importlib.metadata.version('pydantic-ai-slim')


def run_cell(out_dir: Path, verdict: str, invocation_id: str) -> dict[str, Any]:
    if verdict not in {'ALLOW', 'DENY'}:
        raise ValueError('unsupported verdict')
    out_dir = Path(out_dir)
    journal = EffectJournal(out_dir, invocation_id)
    guard_events: list[dict[str, Any]] = []
    ledger = DeferredEffectLedger()
    model = CountingTestModel(call_tools=['publish_record'])
    agent = Agent(model, output_type=str, retries=0, name='clean-matrix')

    @agent.tool_plain
    def publish_record(payload: str) -> str:
        """Publish the protected record."""
        ledger.stage_text_write(out_dir / 'artifacts' / 'records/primary-record.json', PAYLOAD)
        return 'staged'

    @agent.output_validator
    def policy_verdict(output: str) -> str:
        guard_events.append({'kind': 'guard_verdict', 'verdict': verdict, 'tool': 'publish_record', 'resource': 'records/primary-record.json'})
        return output

    exception = None
    try:
        agent.run_sync('run the registered tool')
    except Exception as exc:
        exception = {'type': type(exc).__name__}
    model_calls = model.calls

    if verdict == 'DENY':
        ledger.abort()
    else:
        (out_dir / 'artifacts' / 'records').mkdir(parents=True, exist_ok=True)
        ledger.commit()
        journal.record_commit('file_write', 'publish_record', 'records/primary-record.json', PAYLOAD)

    return {
        'framework': 'pydantic-ai',
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
