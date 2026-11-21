#!/usr/bin/env python3
"""Offline tests of stage_release.sh against a disposable local Git origin."""
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('stage_release.sh').resolve()
ORIGIN = 'https://github.com/ipsc-gummy/team-relay-toolkit.git'
GIT = shutil.which('git')


@unittest.skipUnless(GIT and shutil.which('bash'), 'requires Git and Bash')
class StageReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='stage-release-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.origin = self.root / 'test origin'
        self.origin.mkdir()
        self.git(self.origin, 'init', '--quiet', '--object-format=sha1', '--template=')
        (self.origin / 'README.md').write_text('pinned version\n')
        self.commit = self.make_commit('initial')
        (self.origin / 'README.md').write_text('later version\n')
        self.tip = self.make_commit('later')
        (self.origin / 'untracked.txt').write_text('not in a commit\n')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.calls = self.root / 'fetch-called'
        self.offline_git(self.origin.as_uri())
        self.destination = self.root / 'output directory'

    def git(self, directory, *args):
        result = subprocess.run(
            [GIT, '-c', 'core.hooksPath=/dev/null', '-c', 'user.email=test@example.invalid',
             '-c', 'user.name=Fixture', '-c', 'commit.gpgSign=false', '-C', str(directory), *args],
            env={'PATH': os.environ['PATH'], 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'},
            check=True, text=True, capture_output=True, timeout=10,
        )
        return result.stdout.strip()

    def make_commit(self, message):
        self.git(self.origin, 'add', 'README.md')
        self.git(self.origin, 'commit', '--quiet', '-m', message)
        return self.git(self.origin, 'rev-parse', 'HEAD')

    def offline_git(self, local_origin, *, replace_requested_sha=None):
        # Intercept only the real script's network fetch. Everything else runs real Git.
        quote = shlex.quote
        replacement = (
            f'if [[ $arg == {quote(self.commit)} ]]; then arg={quote(replace_requested_sha)}; fi\n'
            if replace_requested_sha else ''
        )
        wrapper = self.bin / 'git'
        wrapper.write_text(
            '#!/usr/bin/env bash\nset -euo pipefail\nargs=()\n'
            'for arg; do\n'
            f'if [[ $arg == {quote(ORIGIN)} ]]; then\n'
            f'  : > {quote(str(self.calls))}\n'
            f'  arg={quote(local_origin)}\n'
            'fi\n'
            + replacement +
            'args+=("$arg")\ndone\n'
            f'exec {quote(GIT)} -c protocol.file.allow=always "${{args[@]}}"\n'
        )
        wrapper.chmod(0o700)

    def stage(self, *arguments, **overrides):
        environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'], **overrides)
        return subprocess.run(['bash', str(SCRIPT), *map(str, arguments)], cwd=self.root,
                              env=environment, capture_output=True, text=True, timeout=20)

    def test_pins_exact_historical_commit_in_private_checkout(self):
        result = self.stage(self.commit.upper(), self.destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'STAGED_COMMIT={self.commit}\n')
        self.assertEqual(result.stderr, '')
        self.assertTrue(self.calls.exists())
        self.assertEqual(self.git(self.destination, 'rev-parse', 'HEAD'), self.commit)
        self.assertEqual(self.git(self.destination, 'rev-parse', '--abbrev-ref', 'HEAD'), 'HEAD')
        self.assertEqual((self.destination / 'README.md').read_text(), 'pinned version\n')
        self.assertFalse((self.destination / 'untracked.txt').exists())
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)

    def test_never_reuses_an_existing_destination(self):
        self.destination.mkdir()
        existing = self.destination / 'existing.txt'
        existing.write_text('keep me\n')
        result = self.stage(self.commit, self.destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(existing.read_text(), 'keep me\n')
        self.assertFalse(self.calls.exists())

    def test_rejects_symlink_destination_and_missing_parent(self):
        self.destination.symlink_to(self.origin, target_is_directory=True)
        self.assertNotEqual(self.stage(self.commit, self.destination).returncode, 0)
        self.assertTrue(self.destination.is_symlink())
        self.assertNotEqual(self.stage(self.commit, self.root / 'missing' / 'checkout').returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_bad_commit_is_rejected_without_creating_paths(self):
        for value in ('main', self.commit[:12], 'g' * 40, 'a' * 41):
            with self.subTest(value=value):
                self.assertEqual(self.stage(value, self.destination).returncode, 2)
                self.assertFalse(self.destination.exists())
        self.assertFalse(self.calls.exists())

    def test_failed_fetch_has_no_success_marker_and_is_not_reused(self):
        result = self.stage('0' * 40, self.destination)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('could not fetch the pinned commit', result.stderr)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        self.assertFalse((self.destination / 'README.md').exists())
        self.assertNotEqual(self.stage(self.commit, self.destination).returncode, 0)

    def test_rejects_a_different_fetched_commit(self):
        self.offline_git(self.origin.as_uri(), replace_requested_sha=self.tip)
        result = self.stage(self.commit, self.destination)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('differs from the requested SHA', result.stderr)
        self.assertFalse((self.destination / 'README.md').exists())

    def test_does_not_inherit_git_repository_or_config_overrides(self):
        result = self.stage(self.commit, self.destination, GIT_DIR=str(self.origin / '.git'),
                            GIT_WORK_TREE=str(self.origin), GIT_CONFIG_COUNT='1',
                            GIT_CONFIG_KEY_0='protocol.file.allow', GIT_CONFIG_VALUE_0='never')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git(self.origin, 'rev-parse', 'HEAD'), self.tip)
        self.assertEqual(self.git(self.destination, 'rev-parse', 'HEAD'), self.commit)

    def test_help_has_no_side_effects(self):
        result = self.stage('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('NEW_DIRECTORY', result.stdout)
        self.assertFalse(self.calls.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
