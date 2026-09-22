"""Optional shared OAuth verification must preserve existing bearer keys."""

# ruff: noqa: F811 -- shared pytest fixture.
import pytest
from test_keys import SERVICE, auth, caller, create  # noqa: F401
from toolframe_sdk import PluginError


async def test_oauth_dispatch_and_unavailable_provider_do_not_affect_keys(
    auth, monkeypatch
):
    key = await create(auth)
    original = auth.context.call
    seen = []

    async def dispatch(alias, method, params):
        if alias != "oauth":
            return await original(alias, method, params)
        seen.append((method, params))
        raise PluginError("dependency_unavailable", "OAuth unavailable")

    monkeypatch.setattr(auth.context, "call", dispatch)
    with caller():
        for method, params in [
            (
                "verify",
                {
                    "token": "tf_oauth_" + "x" * 43,
                    "resource": "https://app.example/mcp",
                },
            ),
            ("resolve", {"id": "oauth:" + "a" * 32, "required_scopes": ["notes.read"]}),
        ]:
            with pytest.raises(PluginError, match="OAuth unavailable"):
                await auth.invoke(SERVICE, method, params)
            assert seen[-1] == (method, params)
        assert (await auth.invoke(SERVICE, "verify", {"token": key["token"]}))[
            "principal"
        ]["kind"] == "mcp_key"
        assert (await auth.invoke(SERVICE, "resolve", {"id": key["key"]["id"]}))[
            "principal"
        ]["kind"] == "mcp_key"


async def test_waiting_oauth_request_does_not_hold_key_store_lock(auth, monkeypatch):
    import asyncio

    key = await create(auth)
    original = auth.context.call
    waiting, release = asyncio.Event(), asyncio.Event()

    async def dispatch(alias, method, params):
        if alias != "oauth":
            return await original(alias, method, params)
        waiting.set()
        await release.wait()
        raise PluginError("dependency_unavailable", "OAuth unavailable")

    monkeypatch.setattr(auth.context, "call", dispatch)
    with caller():
        task = asyncio.create_task(
            auth.invoke(SERVICE, "verify", {"token": "tf_oauth_" + "x" * 43})
        )
        try:
            await asyncio.wait_for(waiting.wait(), 1)
            result = await asyncio.wait_for(
                auth.invoke(SERVICE, "verify", {"token": key["token"]}), 1
            )
            assert result["principal"]["kind"] == "mcp_key"
        finally:
            release.set()
            with pytest.raises(PluginError):
                await task
