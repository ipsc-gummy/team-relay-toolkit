"""Isolated tests: synthetic credits, a temporary DB and no network."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest

from pilot_budget import (
    MAX_CREDITS,
    BudgetBlocked,
    BudgetError,
    DuplicateReservation,
    InsufficientCredits,
    LedgerUnavailable,
    PilotBudget,
    SettlementConflict,
    SettlementOverrun,
    UnknownMember,
    UnknownReservation,
)


class PilotBudgetTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "pilots.db"
        self.ledger = PilotBudget.create(self.path)
        self.ledger.add_member("test-a", 60)
        self.ledger.add_member("test-b", 10)

    def test_parallel_reservations_cannot_exceed_member_cap(self):
        workers = 8
        barrier = Barrier(workers)

        def reserve(index):
            barrier.wait(timeout=5)
            try:
                PilotBudget(self.path).reserve("test-a", f"test-request-{index}", 20)
            except InsufficientCredits:
                return False
            return True

        with ThreadPoolExecutor(workers) as pool:
            self.assertEqual(sum(pool.map(reserve, range(workers))), 3)
        self.assertEqual(self.ledger.balance("test-a").available, 0)

    def test_same_request_id_is_unique_under_concurrency(self):
        barrier = Barrier(2)

        def reserve():
            barrier.wait(timeout=5)
            try:
                PilotBudget(self.path).reserve("test-a", "same-id", 1)
            except DuplicateReservation:
                return False
            return True

        with ThreadPoolExecutor(2) as pool:
            results = [pool.submit(reserve) for _ in range(2)]
            self.assertEqual(sum(x.result() for x in results), 1)
        self.assertEqual(self.ledger.balance("test-a").available, 59)

    def test_unknown_final_retains_hold_across_restarts(self):
        self.ledger.reserve("test-a", "absent-usage", 45)
        for _ in range(2):
            PilotBudget(self.path).settle("test-a", "absent-usage", None)
        restarted = PilotBudget(self.path)
        self.assertEqual(restarted.balance("test-a").available, 15)
        with self.assertRaises(InsufficientCredits):
            restarted.reserve("test-a", "new-request", 16)
        with self.assertRaises(DuplicateReservation):
            restarted.reserve("test-a", "absent-usage", 1)

    def test_settlement_is_idempotent_and_conflicts_do_not_refund(self):
        self.ledger.reserve("test-a", "result", 40)
        for _ in range(2):
            self.ledger.settle("test-a", "result", 9)
        self.assertEqual(self.ledger.balance("test-a").available, 51)
        for contrary in (None, 8, 10):
            with self.subTest(contrary=contrary):
                with self.assertRaises(SettlementConflict):
                    self.ledger.settle("test-a", "result", contrary)
        self.assertEqual(self.ledger.balance("test-a").available, 51)

    def test_member_cannot_charge_or_settle_another_members_request(self):
        self.ledger.reserve("test-a", "request-a", 59)
        with self.assertRaises(UnknownReservation):
            self.ledger.settle("test-b", "request-a", 0)
        with self.assertRaises(DuplicateReservation):
            self.ledger.reserve("test-b", "request-a", 3)
        self.ledger.reserve("test-b", "request-b", 10)
        self.ledger.settle("test-b", "request-b", 0)
        self.assertEqual(self.ledger.balance("test-b").available, 10)
        self.assertEqual(self.ledger.balance("test-a").available, 1)

    def test_overrun_is_recorded_and_blocks_only_affected_member(self):
        self.ledger.reserve("test-a", "overrun", 5)
        for _ in range(2):
            with self.assertRaises(SettlementOverrun):
                self.ledger.settle("test-a", "overrun", MAX_CREDITS)
        restarted = PilotBudget(self.path)
        self.assertTrue(restarted.balance("test-a").blocked)
        self.assertEqual(restarted.balance("test-a").available, 0)
        with self.assertRaises(BudgetBlocked):
            restarted.reserve("test-a", "blocked", 1)
        with self.assertRaises(SettlementConflict):
            restarted.settle("test-a", "overrun", 5)
        restarted.reserve("test-b", "unaffected", 1)

    def test_bad_credit_values_and_ids_are_rejected(self):
        for value in (True, False, 2.0, "2", -1, MAX_CREDITS + 1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.ledger.add_member("new-test-member", value)
                with self.assertRaises(ValueError):
                    self.ledger.reserve("test-a", "malformed", value)
        with self.assertRaises(ValueError):
            self.ledger.reserve("test-a", "zero", 0)
        with self.assertRaises(ValueError):
            self.ledger.reserve("test-a", "not a valid id", 1)
        with self.assertRaises(UnknownMember):
            self.ledger.reserve("no-member", "valid-id", 1)
        self.ledger.reserve("test-a", "valid-request", 10)
        for value in (False, -1, 2.0, MAX_CREDITS + 1):
            with self.assertRaises(ValueError):
                self.ledger.settle("test-a", "valid-request", value)
        self.assertEqual(self.ledger.balance("test-a").available, 50)

    def test_initialization_cannot_replace_existing_ledger_or_cap(self):
        self.ledger.reserve("test-a", "existing", 20)
        with self.assertRaises(LedgerUnavailable):
            PilotBudget.create(self.path)
        with self.assertRaises(BudgetError):
            self.ledger.add_member("test-a", 60)
        self.assertEqual(self.ledger.balance("test-a").available, 40)

    def test_unverifiable_ledger_fails_closed(self):
        missing = self.path.with_name("missing.db")
        with self.assertRaises(LedgerUnavailable):
            PilotBudget(missing).reserve("test-a", "valid-id", 1)
        self.assertFalse(missing.exists())
        with sqlite3.connect(self.path) as con:
            con.execute("DROP TABLE reservations")
        with self.assertRaises(LedgerUnavailable):
            self.ledger.reserve("test-a", "valid-id", 1)


if __name__ == "__main__":
    unittest.main()
