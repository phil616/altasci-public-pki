"""Behavior checks for crash/retry state and credential separation of the CLI."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("signing_client", Path(__file__).with_name("signing-client.py"))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class ClientStateTests(unittest.TestCase):
    def test_identical_retry_keeps_key_and_binds_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "operation.json"
            key = client.request_key(state, "https://example/signing/id/issue", b"original-csr", "credential-a")
            self.assertEqual(key, client.request_key(state, "https://example/signing/id/issue", b"original-csr", "credential-a"))
            for endpoint, body, credential in [
                ("https://example/signing/id/issue", b"new-csr", "credential-a"),
                ("https://other/signing/id/issue", b"original-csr", "credential-a"),
                ("https://example/signing/id/issue", b"original-csr", "credential-b"),
            ]:
                with self.assertRaises(ValueError):
                    client.request_key(state, endpoint, body, credential)
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_interrupted_or_invalid_state_never_mints_a_new_key(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "operation.json"
            for value in ["{", "null", "[]", "{}"]:
                state.write_text(value)
                with self.assertRaises(ValueError):
                    client.request_key(state, "https://example/issue", b"csr", "credential")
                self.assertEqual(state.read_text(), value)

    def test_state_and_outputs_cannot_alias_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "credential.txt"
            source.write_text("secret")
            alias = directory / "hardlink.txt"
            os.link(source, alias)
            for paths in [
                {"token file": source, "output": source},
                {"token file": source, "output": alias},
                {"state": directory / "operation", "output": directory / "operation"},
                {"CSR": source, "output": directory / "subdir" / ".." / source.name},
            ]:
                with self.assertRaises(ValueError):
                    client.validate_files(paths)
            client.validate_files({"token file": source, "state": directory / "state", "output": directory / "chain"})
            self.assertEqual(source.read_text(), "secret")

    def test_output_replacement_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "original"
            target.write_bytes(b"keep")
            output = Path(directory) / "output"
            output.symlink_to(target)
            client.atomic_write(output, b"certificate")
            self.assertEqual(output.read_bytes(), b"certificate")
            self.assertEqual(target.read_bytes(), b"keep")
            self.assertFalse(output.is_symlink())


if __name__ == "__main__":
    unittest.main()
