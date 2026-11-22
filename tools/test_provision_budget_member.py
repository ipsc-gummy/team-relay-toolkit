#!/usr/bin/env python3
"""Exercise the root staging tool against only throwaway local SSH/ledger fixtures."""

from hashlib import sha256
import json
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from member_dollar_cap import CAP, MEMBER_TOKEN
from pilot_budget import PilotBudget, UnknownMember
from provision_budget_member import prepare


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(prefix="provision-member-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.active = self.state / "members.json"
        self.active.write_bytes(b"{}\n")
        self.active.chmod(0o600)
        self.database = self.state / "budget.sqlite"
        self.ledger = PilotBudget.create(self.database)
        self.pub = self.root / "fixture.pub"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.pub.with_suffix(""))],
                       check=True, capture_output=True, timeout=15)
        self.fp = subprocess.check_output(["ssh-keygen", "-lf", str(self.pub)], text=True).split()[1]
        self.args = {"user": "fixture-user", "public_key": self.pub, "fingerprint": self.fp, "gateway_port": 18329,
                     "state_dir": self.state, "ledger_name": self.database.name, "members_name": self.active.name,
                     "stage_name": "fixture-stage"}

    def stage(self, **kwargs):
        return prepare(**(self.args | kwargs))

    def test_stages_validated_ssh_policy_and_fixed_cap_without_touching_active_state(self):
        before = self.active.read_bytes(), self.database.read_bytes()
        stage = self.stage()
        self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
        self.assertEqual({p.name for p in stage.iterdir()},
                         {"sshd.conf", "authorized_keys", "member.token", "members.json", "plan.json"})
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in stage.iterdir()))
        policy = (stage / "sshd.conf").read_text()
        for rule in ("Match User fixture-user", "AuthenticationMethods publickey", "PasswordAuthentication no",
                     "KbdInteractiveAuthentication no", "AllowTcpForwarding local", "PermitOpen 127.0.0.1:18329",
                     "PermitListen none", "AllowStreamLocalForwarding no", "MaxSessions 0", "PermitTTY no",
                     "AuthorizedKeysCommand none", "TrustedUserCAKeys none", "Match all"):
            self.assertIn(rule + "\n", policy)
        key_line = (stage / "authorized_keys").read_text()
        self.assertTrue(key_line.startswith('restrict,port-forwarding,permitopen="127.0.0.1:18329" '))
        self.assertEqual(key_line.split()[-2:], self.pub.read_text().split()[:2])
        token = (stage / "member.token").read_text().strip()
        self.assertTrue(token.startswith("cpa-fixture-user-") and MEMBER_TOKEN.fullmatch(token))
        candidate = (stage / "members.json").read_bytes()
        self.assertEqual(json.loads(candidate), {sha256(token.encode()).hexdigest(): "fixture-user"})
        plan = json.loads((stage / "plan.json").read_bytes())
        self.assertEqual(plan["ledger"], {"file": "budget.sqlite", "action": "add_member_if_absent",
                                          "cap_nano_usd": CAP})
        self.assertEqual(plan["map"]["baseline_sha256"], sha256(before[0]).hexdigest())
        self.assertEqual(plan["map"]["candidate_sha256"], sha256(candidate).hexdigest())
        self.assertNotIn(token.encode(), (stage / "plan.json").read_bytes())
        self.assertEqual((self.active.read_bytes(), self.database.read_bytes()), before)
        with self.assertRaises(UnknownMember):
            self.ledger.balance("fixture-user")

    def test_duplicate_stage_is_not_overwritten(self):
        stage = self.stage()
        before = {p.name: p.read_bytes() for p in stage.iterdir()}
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual({p.name: p.read_bytes() for p in stage.iterdir()}, before)

    def test_existing_members_and_holds_remain_in_place(self):
        self.ledger.add_member("existing", CAP)
        self.ledger.reserve("existing", "ongoing", 123)
        existing = {"a" * 64: "existing"}
        self.active.write_text(json.dumps(existing))
        candidate = json.loads((self.stage() / "members.json").read_bytes())
        self.assertEqual({key: candidate[key] for key in existing}, existing)
        self.assertEqual(self.ledger.balance("existing").committed, 123)
        with self.assertRaisesRegex(ValueError, "already mapped"):
            self.stage(user="existing", stage_name="other")
        self.active.write_bytes(b"{}")  # An accidental removal cannot reset the stable member balance.
        with self.assertRaisesRegex(ValueError, "existing ledger identity"):
            self.stage(user="existing", stage_name="other")
        self.assertEqual(self.ledger.balance("existing").committed, 123)

    def test_rejects_invalid_public_key_identity_and_paths_before_staging(self):
        link = self.root / "link.pub"
        link.symlink_to(self.pub)
        for overrides in ({"fingerprint": "SHA256:" + "z" * 43}, {"public_key": link}, {"gateway_port": 22},
                          {"user": "root"}, {"stage_name": "../unsafe"}, {"ledger_name": self.active.name}):
            with self.subTest(overrides=overrides), self.assertRaises((ValueError, OSError)):
                self.stage(**overrides)
        self.assertFalse((self.state / self.args["stage_name"]).exists())

    def test_refuses_missing_or_exposed_active_state_without_initializing_it(self):
        self.active.chmod(0o644)
        with self.assertRaises(ValueError):
            self.stage()
        self.active.chmod(0o600)
        self.database.unlink()
        with self.assertRaises(FileNotFoundError):
            self.stage()
        self.assertFalse(self.database.exists())
        self.assertFalse((self.state / self.args["stage_name"]).exists())

    def test_refuses_unmapped_ledger_id_and_token_collision(self):
        self.active.write_text(json.dumps({"a" * 64: "absent"}))
        with self.assertRaises(UnknownMember):
            self.stage()
        self.ledger.add_member("existing", CAP)
        token = "cpa-fixture-user-" + "b" * 64
        self.active.write_text(json.dumps({sha256(token.encode()).hexdigest(): "existing"}))
        with patch("provision_budget_member.secrets.token_hex", return_value="b" * 64):
            with self.assertRaisesRegex(ValueError, "collides"):
                self.stage()
        self.assertFalse((self.state / self.args["stage_name"]).exists())


if __name__ == "__main__":
    unittest.main()
