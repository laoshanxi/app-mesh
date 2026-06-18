"""Tool catalog: only tool-tagged Apps are advertised, and per-session context
(session_id/workdir) is injected into tool args — but never overrides a value the
model set itself. The injection is what isolates a file-writing tool's side effects,
so getting "model wins" wrong would silently cross sessions' workdirs.
"""
import json
import unittest

from llm_agent.tools import ToolCatalog, _with_injected
from llm_agent.types import ToolCall


class FakeApp:
    def __init__(self, name, metadata=None, description=""):
        self.name = name
        self.metadata = metadata
        self.description = description


class FakeClient:
    def __init__(self, apps):
        self._apps = apps
        self.calls = []

    def list_apps(self):
        return self._apps

    def run_task(self, name, args, timeout):
        self.calls.append((name, args, timeout))
        return json.dumps({"ran": name, "args": json.loads(args)})


class CatalogTest(unittest.TestCase):
    def test_only_tool_tagged_apps_are_specs(self):
        client = FakeClient([
            FakeApp("echo", {"tool": {"description": "echo", "parameters": {"type": "object"}}}),
            FakeApp("plain-app", {"type": "service"}),
            FakeApp("no-meta", None),
        ])
        specs = ToolCatalog(client, timeout=30).specs()
        self.assertEqual([s.name for s in specs], ["echo"])
        self.assertEqual(specs[0].description, "echo")

    def test_spec_falls_back_to_app_description(self):
        client = FakeClient([FakeApp("echo", {"tool": {}}, description="the echo app")])
        specs = ToolCatalog(client, timeout=30).specs()
        self.assertEqual(specs[0].description, "the echo app")
        self.assertEqual(specs[0].parameters, {"type": "object", "properties": {}})

    def test_invoke_rejects_app_not_in_catalog(self):
        # A prompt-injected model must not run_task an App that wasn't advertised, even
        # if the caller's RBAC would allow it.
        client = FakeClient([
            FakeApp("echo", {"tool": {"description": "echo", "parameters": {"type": "object"}}}),
            FakeApp("delete-everything", {"type": "service"}),  # not a tool
        ])
        cat = ToolCatalog(client, timeout=30)
        cat.specs()  # populate the allowlist
        with self.assertRaises(ValueError):
            cat.invoke(ToolCall("c1", "delete-everything", "{}"))
        self.assertEqual(client.calls, [])  # never reached run_task

    def test_invoke_injects_session_context(self):
        client = FakeClient([])
        cat = ToolCatalog(client, timeout=30, session_id="S1", workdir="/w/S1")
        cat.invoke(ToolCall("c1", "echo", '{"message": "hi"}'))
        _, args, _ = client.calls[0]
        sent = json.loads(args)
        self.assertEqual(sent["session_id"], "S1")
        self.assertEqual(sent["workdir"], "/w/S1")
        self.assertEqual(sent["message"], "hi")


class InjectTest(unittest.TestCase):
    def test_adds_missing_keys(self):
        out = json.loads(_with_injected('{"a": 1}', {"session_id": "S1"}))
        self.assertEqual(out, {"a": 1, "session_id": "S1"})

    def test_model_value_wins(self):
        out = json.loads(_with_injected('{"session_id": "mine"}', {"session_id": "S1"}))
        self.assertEqual(out["session_id"], "mine")

    def test_non_object_passes_through(self):
        self.assertEqual(_with_injected("[1,2,3]", {"session_id": "S1"}), "[1,2,3]")

    def test_empty_args_become_object(self):
        out = json.loads(_with_injected("", {"session_id": "S1"}))
        self.assertEqual(out, {"session_id": "S1"})

    def test_no_inject_is_passthrough(self):
        self.assertEqual(_with_injected('{"a":1}', {}), '{"a":1}')


if __name__ == "__main__":
    unittest.main()
