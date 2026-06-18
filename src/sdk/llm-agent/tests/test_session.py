"""Session store: ownership enforcement, persistence/resume, and idle reaping.

Ownership is the L2 authz boundary (only the owner or an admin may touch a session),
so a non-owner read MUST raise Forbidden — not return another user's history.
"""
import tempfile
import time
import unittest

from llm_agent.session import Session, Store
from llm_agent.types import Forbidden, Message, NotFound, ROLE_ASSISTANT, ROLE_USER, ToolCall


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_open_get_roundtrip(self):
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        got = st.get(s.id, "alice", is_admin=False)
        self.assertIs(got, s)

    def test_non_owner_is_forbidden_admin_allowed(self):
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        with self.assertRaises(Forbidden):
            st.get(s.id, "bob", is_admin=False)
        self.assertIsNotNone(st.get(s.id, "bob", is_admin=True))  # admin override

    def test_missing_session_raises_notfound(self):
        st = Store(self.dir, ttl_seconds=0)
        with self.assertRaises(NotFound):
            st.get("nope", "alice", is_admin=False)

    def test_tenant_guard_hides_other_tenants_session(self):
        # Two tenant Apps sharing one session dir both load every session (by id). The
        # tenant guard must make a foreign-tenant session look not-found, even to its
        # owner / an admin, so a shared dir can't cross tenants.
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "tenantA")
        self.assertIs(st.get(s.id, "alice", is_admin=False, tenant="tenantA"), s)
        with self.assertRaises(NotFound):
            st.get(s.id, "alice", is_admin=False, tenant="tenantB")
        with self.assertRaises(NotFound):
            st.get(s.id, "alice", is_admin=True, tenant="tenantB")  # admin doesn't bypass tenant

    def test_closed_session_persist_does_not_resurrect(self):
        # close() sets closed under the session lock; a late persist from an in-flight
        # turn must no-op rather than recreate the just-removed file.
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        st.close(s.id, "alice", is_admin=False)
        st.persist(s)  # simulates the tail of a racing turn
        st2 = Store(self.dir, ttl_seconds=0)
        with self.assertRaises(NotFound):
            st2.get(s.id, "alice", is_admin=False)

    def test_persisted_history_resumes_in_fresh_store(self):
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        s.messages.append(Message(role=ROLE_USER, content="remember 7"))
        s.cost_tokens = 42
        st.persist(s)
        # A new Store (as a restarted process) loads the session from disk.
        st2 = Store(self.dir, ttl_seconds=0)
        got = st2.get(s.id, "alice", is_admin=False)
        self.assertEqual(got.cost_tokens, 42)
        self.assertEqual(got.messages[0].content, "remember 7")

    def test_resume_session_with_tool_calls_rebuilds_typed(self):
        # Regression: a persisted assistant turn carrying tool_calls must come back as
        # ToolCall objects (not dicts) so the next turn's provider conversion works.
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        s.messages.append(Message(role=ROLE_ASSISTANT, content="",
                                  tool_calls=[ToolCall(id="c1", name="echo", arguments='{"a":1}')]))
        st.persist(s)
        st2 = Store(self.dir, ttl_seconds=0)              # fresh process: load from disk
        got = st2.get(s.id, "alice", is_admin=False)
        tc = got.messages[0].tool_calls[0]
        self.assertIsInstance(tc, ToolCall)
        self.assertEqual((tc.id, tc.name, tc.arguments), ("c1", "echo", '{"a":1}'))

    def test_delete_closes_session_so_late_persist_cannot_resurrect(self):
        # delete() (worker reaper path) must set closed under s.lock so a racing
        # in-flight turn's persist() no-ops instead of recreating the file.
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        st.delete(s.id)
        st.persist(s)  # simulates the tail of a racing turn after delete
        st2 = Store(self.dir, ttl_seconds=0)
        with self.assertRaises(NotFound):
            st2.get(s.id, "alice", is_admin=False)

    def test_close_removes_session_and_file(self):
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        st.close(s.id, "alice", is_admin=False)
        with self.assertRaises(NotFound):
            st.get(s.id, "alice", is_admin=False)

    def test_reap_drops_only_idle_sessions(self):
        st = Store(self.dir, ttl_seconds=0.01)
        s = st.open("alice", "default")
        s.updated_at = time.time() - 10  # force stale
        st.persist(s)
        s.updated_at = time.time() - 10  # persist refreshed it; force stale again
        self.assertEqual(st.reap(), 1)
        with self.assertRaises(NotFound):
            st.get(s.id, "alice", is_admin=False)

    def test_reap_disabled_when_ttl_zero(self):
        st = Store(self.dir, ttl_seconds=0)
        s = st.open("alice", "default")
        s.updated_at = time.time() - 10_000
        self.assertEqual(st.reap(), 0)
        self.assertIsNotNone(st.get(s.id, "alice", is_admin=False))


if __name__ == "__main__":
    unittest.main()
