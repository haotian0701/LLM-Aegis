"""The server-owned tool allowlist does not trust model descriptions or arguments."""

from aegis.runtime_policy import RuntimePolicy


def test_runtime_tool_policy_denies_unknown_writes_and_invalid_arguments() -> None:
    policy = RuntimePolicy()
    assert policy.decide_tool("search_docs", '{"query":"launch"}', "alice").action == "ALLOW"
    assert policy.decide_tool("search_docs", '{"query":4}', "alice").rule == "invalid_arguments"
    assert policy.decide_tool("search_docs", "not-json", "alice").rule == "invalid_arguments"
    unknown = policy.decide_tool("api_key=secret-value", "{}", "alice")
    assert unknown.action == "DENY" and unknown.target == "unregistered-tool"
    email = policy.decide_tool(
        "send_email",
        '{"to":"person@outside.example","subject":"demo","body":"synthetic"}',
        "alice",
    )
    assert email.action == "DENY" and email.rule == "write_tool_disabled"
    assert email.target == "outside.example"
