"""Single source of truth for the external chat-completions endpoint.

2026-09-16: provider switched from Paratera (llmapi.paratera.com, unavailable)
to the official Zhipu open platform per user direction; model policy remains
GLM-5.3-Flash only (config/research-model-policy.json). The pay-as-you-go
paas/v4 endpoint bills account balance (exhausted, code 1113); the coding-plan
endpoint below bills the user's GLM Max plan quota and speaks the same
chat-completions dialect, so it is the active endpoint. All call sites and the
RecordedTransport endpoint allowlist must reference this constant so provider
identity stays auditable from one place.
"""

CHAT_COMPLETIONS_ENDPOINT = "https://open.bigmodel.cn/api/coding/paas/v4/chat/completions"

# Official platform contract: glm-5.3-flash always reasons and rejects
# thinking.type "disabled" (HTTP 400, code 1210). The frozen wire profile
# therefore pins the lowest reasoning budget explicitly instead; the value
# stays part of each recorded request, preserving the original n1892 lesson
# (unbounded hidden reasoning must not consume the completion budget).
REQUIRED_THINKING = {"type": "enabled", "budget_capacity": "low"}

# The platform echoes model ids lower-cased regardless of the requested
# casing; identity checks must compare case-insensitively.
def model_identity_matches(requested, provider_reported):
    return isinstance(provider_reported, str) and requested.lower() == provider_reported.lower()

