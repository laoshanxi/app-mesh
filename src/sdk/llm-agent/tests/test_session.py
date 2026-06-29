"""Session utils — a session is just a workdir under the workspace. No network."""
import os
import tempfile
import time
import unittest

from llm_agent import session


class SessionUtilsTest(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp()

    def test_workdir_is_stable_and_sanitized(self):
        self.assertEqual(session.workdir(self.ws, "s1"), os.path.join(self.ws, "s1"))
        # path-unsafe characters are sanitized so a session id can't escape the workspace
        self.assertEqual(session.workdir(self.ws, "../etc"), os.path.join(self.ws, "---etc"))
        self.assertEqual(session.workdir("", "s1"), "")  # no workspace → no cwd

    def test_remove_drops_the_workdir(self):
        d = session.workdir(self.ws, "s1")
        os.makedirs(d)
        session.remove(self.ws, "s1")
        self.assertFalse(os.path.exists(d))

    def test_reap_drops_only_idle_workdirs(self):
        fresh = session.workdir(self.ws, "fresh")
        stale = session.workdir(self.ws, "stale")
        os.makedirs(fresh)
        os.makedirs(stale)
        old = time.time() - 1000
        os.utime(stale, (old, old))
        self.assertEqual(session.reap_workdirs(self.ws, ttl_seconds=100), 1)
        self.assertTrue(os.path.isdir(fresh))     # kept
        self.assertFalse(os.path.isdir(stale))    # reaped

    def test_reap_disabled_when_ttl_zero(self):
        d = session.workdir(self.ws, "s")
        os.makedirs(d)
        os.utime(d, (0, 0))
        self.assertEqual(session.reap_workdirs(self.ws, ttl_seconds=0), 0)  # disabled


if __name__ == "__main__":
    unittest.main()
