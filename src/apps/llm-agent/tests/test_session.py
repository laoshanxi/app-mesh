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
        self.assertTrue(session.workdir(self.ws, "../etc").startswith(os.path.join(self.ws, "---etc")))
        self.assertEqual(session.workdir("", "s1"), "")  # no workspace → no cwd

    def test_distinct_ids_never_collide(self):
        # these three all sanitized to "a-b" before; each must now own a directory
        dirs = {session.workdir(self.ws, s) for s in ("a/b", "a-b", "a b")}
        self.assertEqual(len(dirs), 3)
        # an id already inside the safe alphabet is used as-is (stable across upgrades)
        self.assertEqual(session.workdir(self.ws, "a-b"), os.path.join(self.ws, "a-b"))

    def test_remove_drops_the_workdir(self):
        d = session.workdir(self.ws, "s1")
        os.makedirs(d)
        session.remove(self.ws, "s1")
        self.assertFalse(os.path.exists(d))

    def test_remove_also_drops_the_transcript(self):
        cwd = session.workdir(self.ws, "s1")
        os.makedirs(cwd)
        hist = os.path.join(self.ws, "projects")
        # the fixture uses the CLI's own encoding (project_dir_name): one definition,
        # so a tmpdir containing "_" can never desynchronize test and implementation
        encoded = session.project_dir_name(cwd)
        os.makedirs(os.path.join(hist, encoded))
        session.remove(self.ws, "s1", history_root=hist)
        self.assertFalse(os.path.exists(cwd))
        self.assertFalse(os.path.exists(os.path.join(hist, encoded)))
        # a missing/unknown encoding variant must not raise
        session.remove(self.ws, "s2", history_root=hist)

    def test_remove_folds_underscore_like_the_cli(self):
        # a session id keeping "_" (allowed by _safe) must still have its transcript
        # dropped: the CLI encodes "<workspace>/team_a" and "<workspace>/team-a" alike
        cwd = session.workdir(self.ws, "team_a")
        os.makedirs(cwd)
        hist = os.path.join(self.ws, "projects")
        os.makedirs(os.path.join(hist, session.project_dir_name(cwd)))
        session.remove(self.ws, "team_a", history_root=hist)
        self.assertFalse(os.path.exists(os.path.join(hist, session.project_dir_name(cwd))))

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

    def test_reap_never_drops_runtime_dirs(self):
        # the CLI config dir (all conversation history) lives inside the workspace;
        # the reaper must not treat it as an abandoned session however idle it is
        cfg = os.path.join(self.ws, ".claude")
        os.makedirs(os.path.join(cfg, "projects", "encoded"))
        os.makedirs(os.path.join(self.ws, ".llmagent"))
        old = time.time() - 10_000_000
        os.utime(cfg, (old, old))
        os.utime(os.path.join(self.ws, ".llmagent"), (old, old))
        self.assertEqual(session.reap_workdirs(self.ws, ttl_seconds=100), 0)
        self.assertTrue(os.path.isdir(os.path.join(cfg, "projects", "encoded")))

    def test_reap_disabled_when_ttl_zero(self):
        d = session.workdir(self.ws, "s")
        os.makedirs(d)
        os.utime(d, (0, 0))
        self.assertEqual(session.reap_workdirs(self.ws, ttl_seconds=0), 0)  # disabled


if __name__ == "__main__":
    unittest.main()
