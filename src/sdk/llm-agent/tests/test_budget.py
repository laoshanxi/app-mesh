"""Per-tenant ledger: shared-on-disk accounting and the clamp contract.

The clamp test guards a regression where a per-call ceiling was silently ignored once
the operator ceiling was 0/unlimited — a request must always be allowed to *tighten*,
and may never *loosen* a finite operator ceiling.
"""
import tempfile
import unittest

from llm_agent.budget import Ledger
from llm_agent.types import BudgetExceeded, TurnLimits


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_no_quota_means_unlimited(self):
        led = Ledger(self.dir, {})
        led.add("acme", 10_000)
        led.check("acme")  # must not raise

    def test_accumulates_and_blocks_at_quota(self):
        led = Ledger(self.dir, {"acme": 100})
        led.check("acme")
        self.assertEqual(led.add("acme", 60), 60)
        led.check("acme")  # 60 < 100 still ok
        self.assertEqual(led.add("acme", 60), 120)
        with self.assertRaises(BudgetExceeded):
            led.check("acme")  # 120 >= 100

    def test_same_tenant_same_dir_shares_one_counter(self):
        # Two Ledger instances (as two processes would have) over one dir share spend.
        a = Ledger(self.dir, {"acme": 100})
        b = Ledger(self.dir, {"acme": 100})
        a.add("acme", 70)
        self.assertEqual(b.used("acme"), 70)
        b.add("acme", 40)
        with self.assertRaises(BudgetExceeded):
            a.check("acme")

    def test_tenants_are_isolated(self):
        led = Ledger(self.dir, {"acme": 100, "globex": 100})
        led.add("acme", 100)
        with self.assertRaises(BudgetExceeded):
            led.check("acme")
        led.check("globex")  # untouched


class ClampTest(unittest.TestCase):
    def test_request_may_tighten_even_against_unlimited_ceiling(self):
        ceiling = TurnLimits(max_iterations=0, max_tokens=0)  # unlimited
        out = ceiling.clamp(TurnLimits(max_iterations=3, max_tokens=500))
        self.assertEqual(out.max_iterations, 3)
        self.assertEqual(out.max_tokens, 500)

    def test_request_may_not_loosen_finite_ceiling(self):
        ceiling = TurnLimits(max_iterations=5, max_tokens=1000)
        out = ceiling.clamp(TurnLimits(max_iterations=99, max_tokens=99_999))
        self.assertEqual(out.max_iterations, 5)
        self.assertEqual(out.max_tokens, 1000)

    def test_request_tightens_finite_ceiling(self):
        ceiling = TurnLimits(max_iterations=5, max_tokens=1000)
        out = ceiling.clamp(TurnLimits(max_iterations=2, max_tokens=400))
        self.assertEqual(out.max_iterations, 2)
        self.assertEqual(out.max_tokens, 400)

    def test_unset_request_inherits_ceiling(self):
        ceiling = TurnLimits(max_iterations=5, max_tokens=1000)
        out = ceiling.clamp(TurnLimits())
        self.assertEqual(out.max_iterations, 5)
        self.assertEqual(out.max_tokens, 1000)


if __name__ == "__main__":
    unittest.main()
