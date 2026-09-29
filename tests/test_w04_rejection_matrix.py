"""Offline checks for the W4 seven-row rejection matrix runner."""
import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
service_spec = importlib.util.spec_from_file_location("w04_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(service_spec)
service_spec.loader.exec_module(service)
matrix_spec = importlib.util.spec_from_file_location(
    "w04_rejection_matrix", ROOT / "tests/w04_rejection_matrix.py"
)
matrix = importlib.util.module_from_spec(matrix_spec)
matrix_spec.loader.exec_module(matrix)
REPORTER = "synthetic-reporter-token"
OPERATOR = "synthetic-operator-token"


class RejectionMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        version_file = Path(self.temp_dir.name) / "version"
        version_file.write_text("b" * 40, encoding="utf-8")
        self.environment = patch.dict(os.environ, {
            "REPORTER_TOKEN": REPORTER,
            "OPERATOR_TOKEN": OPERATOR,
        })
        self.environment.start()
        self.server = service.make_server(version_file, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base_url = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.environment.stop()
        self.temp_dir.cleanup()

    def test_matrix_runs_all_seven_rows_and_lists_created_event(self):
        event_id = "group7-1-matrix-test"
        version, rows = matrix.run_matrix(self.base_url, REPORTER, OPERATOR, event_id)
        self.assertEqual(version, "b" * 40)
        self.assertEqual([row["status"] for row in rows], [201, 401, 403, 400, 409, 403, 200])
        self.assertEqual(rows[3]["body"]["field"], "observed_at")
        self.assertTrue(any(item.get("event_id") == event_id for item in rows[6]["body"]))

    def test_report_includes_version_and_redacts_tokens(self):
        version, rows = matrix.run_matrix(
            self.base_url, REPORTER, OPERATOR, "group7-1-redaction-test"
        )
        report = matrix.render_report(version, rows, (REPORTER, OPERATOR))
        self.assertIn("version=" + version, report)
        self.assertIn("1 201 ", report)
        self.assertIn("7 200 ", report)
        self.assertNotIn(REPORTER, report)
        self.assertNotIn(OPERATOR, report)

    def test_token_file_requires_private_permissions_and_distinct_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            token_file = Path(temp_dir) / "app.env"
            token_file.write_text(
                f"REPORTER_TOKEN={REPORTER}\nOPERATOR_TOKEN={OPERATOR}\n",
                encoding="utf-8",
            )
            token_file.chmod(0o600)
            self.assertEqual(matrix.load_tokens(token_file), (REPORTER, OPERATOR))
            token_file.chmod(0o644)
            with self.assertRaises(matrix.MatrixError):
                matrix.load_tokens(token_file)

    def test_token_file_rejects_duplicate_or_unknown_keys(self):
        invalid_contents = (
            f"REPORTER_TOKEN={REPORTER}\nREPORTER_TOKEN=other\nOPERATOR_TOKEN={OPERATOR}\n",
            f"REPORTER_TOKEN={REPORTER}\nOPERATOR_TOKEN={OPERATOR}\nEXTRA=value\n",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            token_file = Path(temp_dir) / "app.env"
            for content in invalid_contents:
                token_file.write_text(content, encoding="utf-8")
                token_file.chmod(0o600)
                with self.assertRaises(matrix.MatrixError):
                    matrix.load_tokens(token_file)

    def test_matrix_parses_full_latest_50_response(self):
        from pathlib import Path
        import json

        valid = json.loads((ROOT / "tests/fixtures/event-valid.json").read_text(encoding="utf-8"))
        valid["note"] = "é" * 200
        for index in range(50):
            event = dict(valid, event_id=f"group7-1-large-{index:04d}")
            status, _ = matrix.request(
                self.base_url, "POST", "/events", REPORTER, event
            )
            self.assertEqual(status, 201)

        _, rows = matrix.run_matrix(
            self.base_url, REPORTER, OPERATOR, "group7-1-matrix-large"
        )
        self.assertEqual(len(rows[6]["body"]), 50)
        self.assertTrue(any(item["event_id"] == "group7-1-matrix-large" for item in rows[6]["body"]))


if __name__ == "__main__":
    unittest.main()
