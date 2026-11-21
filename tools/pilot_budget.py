"""Offline pilot ledger for synthetic integer credits, independent of any API.

Reserve a proven upper bound before dispatch. A duplicate request ID is never a
second authorization to dispatch. A missing final charge retains the whole hold
across restarts. Only a known final charge can release unused credits; any charge
above its hold blocks new work for that member. This does not determine request
costs, prove an upstream bound or enforce a production dollar limit.
"""

from contextlib import closing, contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import sqlite3


MAX_CREDITS = (1 << 63) - 1
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


class BudgetError(Exception):
    pass


class LedgerUnavailable(BudgetError):
    pass


class UnknownMember(BudgetError):
    pass


class UnknownReservation(BudgetError):
    pass


class DuplicateReservation(BudgetError):
    pass


class InsufficientCredits(BudgetError):
    pass


class BudgetBlocked(BudgetError):
    pass


class SettlementConflict(BudgetError):
    pass


class SettlementOverrun(BudgetError):
    pass


@dataclass(frozen=True)
class Balance:
    limit: int
    committed: int
    blocked: bool

    @property
    def available(self):
        return 0 if self.blocked else self.limit - self.committed


def _id(value):
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ValueError("expected a synthetic identifier (1–128 ASCII characters)")
    return value


def _credits(value, minimum=0):
    if type(value) is not int or not minimum <= value <= MAX_CREDITS:
        raise ValueError("expected an in-range integer credit amount")
    return value


class PilotBudget:
    def __init__(self, path):
        self.path = Path(path).absolute()

    @classmethod
    def create(cls, path):
        """Explicitly initialize an empty ledger; refuse to replace any file."""
        ledger = cls(path)
        try:
            with os.fdopen(os.open(ledger.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)):
                pass
        except OSError as exc:
            raise LedgerUnavailable("cannot create a new ledger") from exc
        with ledger._transaction() as db:
            db.execute("CREATE TABLE members (id TEXT PRIMARY KEY, cap INTEGER NOT NULL)")
            db.execute("""CREATE TABLE reservations (
                id TEXT PRIMARY KEY,
                member_id TEXT NOT NULL REFERENCES members(id),
                held INTEGER NOT NULL,
                final INTEGER
            )""")
            db.execute("CREATE INDEX reservations_member ON reservations(member_id)")
        return ledger

    @contextmanager
    def _transaction(self, *, write=True):
        try:
            # Never silently recreate a missing or lost ledger on a request path.
            uri = self.path.as_uri() + ("?mode=rw" if write else "?mode=ro")
            with closing(sqlite3.connect(uri, uri=True, timeout=3, isolation_level=None)) as db:
                db.execute("PRAGMA foreign_keys = ON")
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield db
                db.commit()
        except sqlite3.Error as exc:
            raise LedgerUnavailable("could not verify or update ledger") from exc

    def add_member(self, member_id, cap):
        """Set one fixed cap per member ID; do not reset an existing balance."""
        with self._transaction() as db:
            try:
                db.execute("INSERT INTO members VALUES (?, ?)", (_id(member_id), _credits(cap)))
            except sqlite3.IntegrityError as exc:
                raise BudgetError("member already exists") from exc

    @staticmethod
    def _balance(db, member_id):
        member = db.execute("SELECT cap FROM members WHERE id = ?", (member_id,)).fetchone()
        if member is None:
            raise UnknownMember("member is not registered")
        committed, blocked = db.execute("""
            SELECT COALESCE(SUM(CASE WHEN final <= held THEN final ELSE held END), 0),
                   COALESCE(MAX(final > held), 0)
            FROM reservations WHERE member_id = ?
        """, (member_id,)).fetchone()
        # Use the original hold for an overrun in this sum to avoid integer
        # overflow; the recorded actual remains in the row and blocks all work.
        return Balance(member[0], committed, bool(blocked))

    def balance(self, member_id):
        with self._transaction(write=False) as db:
            return self._balance(db, _id(member_id))

    def reserve(self, member_id, request_id, upper_bound):
        member_id, request_id = _id(member_id), _id(request_id)
        upper_bound = _credits(upper_bound, minimum=1)
        with self._transaction() as db:
            state = self._balance(db, member_id)
            if state.blocked:
                raise BudgetBlocked("past charge exceeded its reservation")
            if db.execute("SELECT 1 FROM reservations WHERE id = ?", (request_id,)).fetchone():
                raise DuplicateReservation("request ID already used")
            if upper_bound > state.available:
                raise InsufficientCredits("request exceeds remaining credits")
            db.execute("INSERT INTO reservations VALUES (?, ?, ?, NULL)",
                       (request_id, member_id, upper_bound))

    def settle(self, member_id, request_id, final_credits):
        """Record a known charge once; None keeps a pending hold unchanged."""
        member_id, request_id = _id(member_id), _id(request_id)
        if final_credits is not None:
            final_credits = _credits(final_credits)
        with self._transaction() as db:
            row = db.execute("SELECT held, final FROM reservations WHERE id = ? AND member_id = ?",
                             (request_id, member_id)).fetchone()
            if row is None:
                raise UnknownReservation("request is not reserved for this member")
            held, previous = row
            if previous is not None and previous != final_credits:
                raise SettlementConflict("final charge was already recorded")
            if previous is None and final_credits is not None:
                db.execute("UPDATE reservations SET final = ? WHERE id = ?", (final_credits, request_id))
        # Commit the evidence and block before reporting the overrun.
        if final_credits is not None and final_credits > held:
            raise SettlementOverrun("final charge exceeded its reserved upper bound")
