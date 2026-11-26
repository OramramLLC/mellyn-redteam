"""The conformance recorder reads audit events from both ledger shapes the core has written."""

from __future__ import annotations

import json
import unittest

from tests.conformance.recorder import audit_event_rows

EVENT = {"audit_id": "aud_1", "decision": "allow", "args_sha256": "0" * 64}


class TestAuditEventRows(unittest.TestCase):
    def test_v2_envelopes_are_unwrapped(self) -> None:
        line = json.dumps(
            {
                "schema_version": 2,
                "seq": 0,
                "prev_hash": "0" * 64,
                "entry_hash": "1" * 64,
                "source": "gateway",
                "event": EVENT,
            }
        )
        # Before the fix the recorder read `decision` from the envelope, found none, and every audit case failed.
        self.assertEqual(audit_event_rows(line + "\n"), [EVENT])

    def test_v1_rows_and_blank_lines_pass_through(self) -> None:
        v1 = {**EVENT, "seq": 0, "prev_hash": "0" * 64, "entry_hash": "1" * 64}
        self.assertEqual(audit_event_rows(json.dumps(v1) + "\n\n"), [v1])

    def test_an_envelope_without_an_event_object_is_left_alone(self) -> None:
        odd = {"schema_version": 2, "event": "not-an-object"}
        self.assertEqual(audit_event_rows(json.dumps(odd)), [odd])


if __name__ == "__main__":
    unittest.main()
