import contextlib
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from accept_budget_upstream import KEY_NAME, RECEIPT_NAME, verified, verify_and_store


FAKE_KEY = "sk-proj-" + "s" * 40


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        root = self.enterContext(TemporaryDirectory())
        self.state = Path(root)
        self.log = self.enterContext(contextlib.redirect_stdout(StringIO()))
        self.enterContext(contextlib.redirect_stderr(StringIO()))

    def test_success_is_private_and_does_not_repeat(self):
        run = Mock(return_value=0)
        self.assertEqual(verify_and_store(self.state, lambda: FAKE_KEY, run), 0)
        for name in (KEY_NAME, RECEIPT_NAME):
            self.assertEqual((self.state / name).stat().st_mode & 0o777, 0o600)
        self.assertTrue(verified(self.state))
        self.assertEqual(verify_and_store(self.state, Mock(side_effect=AssertionError), run), 0)
        run.assert_called_once_with(FAKE_KEY)
        self.assertNotIn(FAKE_KEY, self.log.getvalue())

    def test_failed_acceptance_has_no_key_or_receipt(self):
        run = Mock(return_value=1)
        self.assertEqual(verify_and_store(self.state, lambda: FAKE_KEY, run), 1)
        run.assert_called_once_with(FAKE_KEY)
        self.assertFalse((self.state / KEY_NAME).exists())
        self.assertFalse((self.state / RECEIPT_NAME).exists())

    def test_partial_state_and_invalid_input_do_not_bill(self):
        run = Mock(side_effect=AssertionError)
        with self.assertRaises(ValueError):
            verify_and_store(self.state, lambda: "not-a-project-key", run)
        (self.state / KEY_NAME).write_text(FAKE_KEY)
        with self.assertRaises((OSError, ValueError)):
            verify_and_store(self.state, Mock(side_effect=AssertionError), run)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
