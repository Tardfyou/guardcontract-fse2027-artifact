"""Freeze paper-oriented supplemental framework candidates."""
import json
from pathlib import Path

def build():
    return {"schema_version":"representative-frameworks-1","core_frameworks":["langchain","google-adk","pydantic-ai","openai-agents","crewai"],"supplemental_candidates":[
        {"framework":"langgraph","language":"Python","reason":"stateful graph nodes, conditional edges, persistence and durable execution","paper_role":"nonlinear control-flow and checkpoint boundary","official_reference":"https://docs.langchain.com/oss/python/langgraph/graph-api"},
        {"framework":"microsoft-agent-framework","language":"Python/C#","reason":"agent-run, function-calling and chat-client middleware layers","paper_role":"cross-layer middleware ordering and scope","official_reference":"https://learn.microsoft.com/en-us/agent-framework/agents/middleware/"},
        {"framework":"vercel-ai-sdk","language":"TypeScript","reason":"typed tool calls and multi-step tool loop in a non-Python SDK","paper_role":"cross-language transfer and tool-loop lifecycle","official_reference":"https://vercel.com/ai-sdk"}],"deferred_candidates":["litellm","agno","mastra","nemo-guardrails","guardrails-ai","strands-agents"],"selection_rule":"Add only when static direct samples and a distinct lifecycle experiment are available; do not expand repair code before the selection gate passes.","claim_boundary":"Representativeness hypothesis and implementation plan, not adoption ranking or completed framework support."}

if __name__=="__main__":
    out=Path("experiments/representative-frameworks-n325"); out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(build(),indent=2,sort_keys=True)+"\n"); print(json.dumps({"core":5,"supplemental":3,"deferred":6}))
