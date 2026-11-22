#!/usr/bin/env python3
"""Test budget relay installation with temporary files and a stub systemd only."""

from contextlib import ExitStack
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install_budget_relay as relay
from pilot_budget import PilotBudget


FIRST, NEXT = "a" * 40, "b" * 40


def fixtures(code):
    return {name: code + b"\n" for name in relay.FILES}


class InstallerTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(TemporaryDirectory(prefix="budget-installer-fixture-")))
        self.app, self.state, self.unit = root / "opt", root / "state", root / relay.UNIT
        for field, value in (("BASE", self.app), ("STATE", self.state), ("UNIT_PATH", self.unit)):
            stack.enter_context(patch.object(relay, field, value))
        self.commands = []
        self.active = False
        self.fake_pid = 0
        self.port_conflict = False
        self.drop_config = False
        self.fail_new = False
        fake = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
        stack.enter_context(patch.object(relay, "identity", return_value=fake))
        stack.enter_context(patch.object(relay, "status", side_effect=self.status))
        stack.enter_context(patch.object(relay, "listeners", side_effect=lambda _: ["other"] if self.port_conflict else []))
        stack.enter_context(patch.object(relay, "health", side_effect=self.health))
        stack.enter_context(patch.object(relay, "run", side_effect=lambda *args: self.commands.append(args)))
        self.files = fixtures(b"# synthetically audited revision")

    def status(self):
        if self.unit.is_file():
            return {"ActiveState": "active" if self.active else "inactive", "MainPID": str(self.fake_pid),
                    "LoadState": "loaded", "UnitFileState": "enabled" if self.active else "disabled",
                    "FragmentPath": str(self.unit), "DropInPaths": ""}
        return {"ActiveState": "inactive", "MainPID": "0", "LoadState": "not-found", "UnitFileState": "",
                "FragmentPath": "", "DropInPaths": ""}

    def health(self, port, expected=None):
        self.assertEqual(port, relay.PORT)
        if self.fail_new and expected is not None and relay.current() == NEXT:
            raise relay.Stop("synthetic health failure")

    def initial(self):
        relay.install(FIRST, self.files, relay.PORT)

    def test_install_stages_disabled_unit_only(self):
        self.initial()
        self.assertEqual(relay.current(), FIRST)
        self.assertEqual(self.unit.read_bytes(), relay.unit(relay.PORT))
        self.assertEqual((self.state / "members.json").read_bytes(), b"{}\n")
        self.assertEqual((self.state / "budget.sqlite").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.state / "upstream.key").exists())
        self.assertEqual([c[2:] for c in self.commands if c[0] == relay.SERVICECTL], [("daemon-reload",)])

    def test_preexisting_port_collision_writes_nothing(self):
        self.port_conflict = True
        with self.assertRaisesRegex(relay.Stop, "conflict"):
            self.initial()
        self.assertFalse(self.app.exists() or self.state.exists() or self.unit.exists())
        self.assertEqual(self.commands, [])

    def test_inactive_switches_and_rolls_back_without_restarting_or_resetting_ledger(self):
        self.initial()
        ledger = PilotBudget(self.state / "budget.sqlite")
        ledger.add_member("fake", 100_000_000_000)
        ledger.reserve("fake", "held", 1234)
        before = {path.name: path.read_bytes() for path in self.state.iterdir()}
        self.commands.clear()
        relay.switch(NEXT, relay.PORT, False, fixtures(b"# newer"))
        self.assertEqual(relay.current(), NEXT)
        relay.switch(FIRST, relay.PORT, False)
        self.assertEqual(relay.current(), FIRST)
        self.assertEqual({path.name: path.read_bytes() for path in self.state.iterdir()}, before)
        self.assertEqual(ledger.balance("fake").committed, 1234)
        self.assertEqual(self.commands, [])

    def test_active_restart_needs_explicit_permission_and_failure_restores_old_release(self):
        self.initial()
        self.active, self.fake_pid = True, 12345
        self.commands.clear()
        with self.assertRaisesRegex(relay.Stop, "explicit restart"):
            relay.switch(NEXT, relay.PORT, False, fixtures(b"# blocked"))
        self.assertEqual(self.commands, [])
        self.assertEqual(relay.current(), FIRST)
        self.fail_new = True
        with self.assertRaisesRegex(relay.Stop, "previous release restored"):
            relay.switch(NEXT, relay.PORT, True, fixtures(b"# unhealthy"))
        self.assertEqual(relay.current(), FIRST)
        self.assertEqual([c[2:] for c in self.commands], [("restart", relay.UNIT)] * 2)

    def test_untested_or_tampered_state_is_not_reused(self):
        self.initial()
        relay.stage(NEXT, fixtures(b"# candidate"))
        (self.app / "releases" / NEXT / relay.FILES[0]).write_bytes(b"# changed")
        with self.assertRaisesRegex(relay.Stop, "manifest mismatch"):
            relay.switch(NEXT, relay.PORT, False)
        self.assertEqual(relay.current(), FIRST)
        (self.state / "budget.sqlite").unlink()
        with self.assertRaises(FileNotFoundError):
            relay.switch(NEXT, relay.PORT, False)
        self.assertFalse((self.state / "budget.sqlite").exists())


class SourceTests(unittest.TestCase):
    def test_pinned_git_source_only_and_syntax(self):
        with patch.object(relay, "run", side_effect=[b"commit\n", *fixtures(b"pass").values()]) as call:
            result = relay.source(Path("/tmp/local-fixture"), FIRST)
        self.assertEqual(set(result), set(relay.FILES))
        self.assertTrue(all(call.args[-1] == f"{FIRST}:{name}" for call, name in zip(call.call_args_list[1:], relay.FILES)))
        with patch.object(relay, "run") as command, self.assertRaises(relay.Stop):
            relay.source(Path("/tmp/local-fixture"), "HEAD")
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
