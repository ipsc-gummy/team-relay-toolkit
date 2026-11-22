#!/usr/bin/env python3
"""Enrollment tests: real temporary ledger and package, fake Linux service/SSH effects."""

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import enroll_budget_member as enroll
from member_dollar_cap import CAP, MODEL
from pilot_budget import PilotBudget, UnknownMember
from provision_budget_member import prepare


def create(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="enroll-fixture-"))).resolve()
        self.state, self.ssh, self.homes = (self.root / name for name in ("state", "ssh", "homes"))
        for item in (self.state, self.ssh, self.homes):
            item.mkdir(mode=0o700)
        self.active = self.state / "members.json"
        create(self.active, b"{}\n")
        self.ledger = PilotBudget.create(self.state / "budget.sqlite")
        self.stage = self.state / "alpha"
        member_key = self.root / "fixture-user"
        for key in (member_key, self.root / "fixture-host"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        self.public_key = member_key.with_suffix(".pub")
        self.host_key = self.root / "fixture-host.pub"
        self.fingerprint = subprocess.check_output(["ssh-keygen", "-lf", str(self.public_key)], text=True).split()[1]
        self.host_fingerprint = subprocess.check_output(["ssh-keygen", "-lf", str(self.host_key)], text=True).split()[1]
        self.service = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.enterContext(patch.multiple(enroll, STATE=self.state, SSH_INCLUDE=self.ssh, HOMES=self.homes,
                                        HOST_KEY=self.host_key))
        self.enterContext(patch.object(enroll, "as_user", side_effect=lambda service, op: op()))

    def write_stage(self):
        prepare(user="alice", public_key=self.public_key, fingerprint=self.fingerprint, gateway_port=enroll.PORT,
                state_dir=self.state, ledger_name="budget.sqlite", members_name="members.json", stage_name="alpha")
        create(self.stage / "member.pub", self.public_key.read_bytes())
        create(self.stage / "STAGED", b"budget-mac-v1\n")
        return self.stage

    def test_private_packaging_stages_without_activation(self):
        spec = SimpleNamespace(user="alice", server_ip="127.0.0.1", public_key=self.public_key,
                               fingerprint=self.fingerprint, host_fingerprint=self.host_fingerprint)
        enroll.stage_member(spec, self.service, self.stage)
        import zipfile
        archive = self.stage / "member-mac.zip"
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.active.read_bytes(), b"{}\n")
        self.assertEqual(list(self.ssh.iterdir()), [])
        self.assertEqual(list(self.homes.iterdir()), [])
        with self.assertRaises(UnknownMember):
            self.ledger.balance("alice")
        with zipfile.ZipFile(archive) as payload:
            manifest = json.loads(payload.read("Codex团队接入/个人参数.json"))
            self.assertEqual(manifest["user"], "alice")
            self.assertEqual(manifest["gateway_port"], enroll.PORT)
            self.assertEqual(manifest["profile"], "budget-mac")
            self.assertEqual(payload.read("Codex团队接入/中转访问密钥.txt"), (self.stage / "member.token").read_bytes())

    def test_plan_associates_exact_key_and_keeps_prior_members(self):
        self.ledger.add_member("prior", CAP)
        self.active.write_bytes(json.dumps({"a" * 64: "prior"}).encode())
        self.write_stage()
        user, members, candidate, token, *_ = enroll.validate_plan(self.stage, self.active.read_bytes(), root_uid=os.getuid())
        self.assertEqual(user, "alice")
        self.assertEqual(json.loads(candidate), members | {sha256(token).hexdigest(): "alice"})
        self.active.write_bytes(b"{}\n")
        with self.assertRaisesRegex(enroll.Stopped, "stale"):
            enroll.validate_plan(self.stage, self.active.read_bytes(), root_uid=os.getuid())

    def test_tampered_ssh_stage_refused(self):
        self.write_stage()
        (self.stage / "sshd.conf").write_bytes(b"Match all\n")
        with self.assertRaisesRegex(enroll.Stopped, "SSH staged policy changed"):
            enroll.validate_plan(self.stage, self.active.read_bytes(), root_uid=os.getuid())

    def test_only_exact_dedicated_project_key_receipt_accepted(self):
        token = b"sk-proj-" + b"W" * 48
        create(self.state / "upstream.key", token + b"\n")
        rec = self.state / "upstream-verified.json"
        create(rec, json.dumps({"schema": 1, "model": MODEL, "key_sha256": sha256(token).hexdigest(),
                                "verified_at": datetime.now(timezone.utc).isoformat()}).encode())
        enroll.key_accepted(self.state, os.getuid())
        create(self.state / "upstream.key", token + b"x\n")
        with self.assertRaisesRegex(enroll.Stopped, "unaccepted upstream key"):
            enroll.key_accepted(self.state, os.getuid())

    def test_atomic_map_refuses_stale_content(self):
        enroll.atomic_map(self.active, b"{}\n", b'{"fixture":"ready"}\n', self.service)
        with self.assertRaisesRegex(enroll.Stopped, "changed since"):
            enroll.atomic_map(self.active, b"{}\n", b"{}\n", self.service)
        self.assertEqual(self.active.read_bytes(), b'{"fixture":"ready"}\n')

    def simulate_activation(self, fail_after_map):
        self.write_stage()
        check_plan = enroll.validate_plan
        commands = []
        statuses = {enroll.UNIT: "inactive", enroll.SSH_UNIT: "active"}
        actual = dict()

        def validate(stage, active):
            actual["value"] = check_plan(stage, active, root_uid=os.getuid())
            return actual["value"]

        def effective(name):
            # Effective config for unrelated accounts MUST never change.
            return name + ":unchanged"

        def run(*args, allow=False):
            commands.append(args)
            cmd, action = Path(args[0]).name, args[1]
            if cmd == "getent":
                return SimpleNamespace(returncode=2)
            if cmd == "id":
                return SimpleNamespace(stdout="alice\n")
            if cmd == "systemctl":
                if action == "start":
                    statuses[enroll.UNIT] = "active"
                if action == "stop":
                    statuses[enroll.UNIT] = "inactive"
                if action == "is-enabled":
                    return SimpleNamespace(stdout="disabled\n")
                if action == "show":
                    cmdline = (f"path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -B "
                        f"/opt/sg-budget-relay/current/tools/member_dollar_cap.py --ledger {self.state / 'budget.sqlite'} "
                        f"--members {self.active} --key-file {self.state / 'upstream.key'} --port {enroll.PORT} "
                        "--allow-official-billing")
                    return SimpleNamespace(stdout=f"FragmentPath=/etc/systemd/system/{enroll.UNIT}\n"
                                           f"User={enroll.SERVICE}\nDropInPaths=\nExecStart={{ {cmdline} }}\n")
            return SimpleNamespace(stdout="", returncode=0)

        with patch.multiple(enroll, validate_plan=validate, key_accepted=lambda *_: None, ssh_effective=effective,
                            check_effective=lambda _: None, run=run, state_of=lambda unit: statuses[unit],
                            health=lambda token: not (fail_after_map and token)):
            if fail_after_map:
                with self.assertRaisesRegex(enroll.Stopped, "health check failed"):
                    enroll.activate(self.stage, self.service, "root")
            else:
                enroll.activate(self.stage, self.service, "root")
        return commands, actual["value"]

    def test_first_activation_only_mutates_member_and_dedicated_unit(self):
        commands, (_, _, candidate, _, _, key) = self.simulate_activation(False)
        self.assertEqual(self.active.read_bytes(), candidate)
        self.assertEqual(self.ledger.balance("alice").limit, CAP)
        self.assertEqual((self.homes / "alice/.ssh/authorized_keys").read_bytes(), key)
        self.assertEqual({path.name for path in self.ssh.iterdir()}, {"92-sg-budget-alice.conf"})
        self.assertTrue((self.stage / "ACTIVATED").exists())
        controls = {cmd[1:3] for cmd in commands if cmd[0] == "/usr/bin/systemctl"}
        self.assertTrue({("start", enroll.UNIT), ("enable", enroll.UNIT), ("reload", enroll.SSH_UNIT)} <= controls)
        self.assertFalse(any("cliproxyapi" in arg for cmd in commands for arg in cmd))

    def test_failed_activation_restores_only_map_and_keeps_stable_ledger(self):
        commands, _ = self.simulate_activation(True)
        self.assertEqual(self.active.read_bytes(), b"{}\n")
        self.assertEqual(self.ledger.balance("alice").limit, CAP)
        self.assertEqual(list(self.homes.iterdir()), [])
        self.assertEqual(list(self.ssh.iterdir()), [])
        self.assertFalse((self.stage / "ACTIVATED").exists())
        self.assertIn(("/usr/bin/systemctl", "stop", enroll.UNIT), commands)
        self.assertNotIn(("/usr/bin/systemctl", "reload", enroll.SSH_UNIT), commands)


if __name__ == "__main__":
    unittest.main()
