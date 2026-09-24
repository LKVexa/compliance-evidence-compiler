import concurrent.futures
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cec.core import CecError, EvidenceLedger, compile_report, judge_applicability, parse_policy_corpus
from cec.evidence import MAX_EVIDENCE_BYTES
from cec.records import make_execution_record, load_schema
from cec.vendor.condition_evaluator import ExpressionError, evaluate_condition

def control(**changes):
    c = {"control_id": "C1", "title": "Control", "evidence_types": ["log"],
         "applicability": "{{enabled}} == 'true'"}
    c.update(changes)
    return c

class ReportBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = EvidenceLedger(self.temp.name)
        self.controls = [control()]
        self.judgments = judge_applicability(self.controls, {"enabled": True})

    def report(self, approval=None):
        return compile_report(self.controls, self.judgments, self.ledger, approval)

    def test_boolean_fact_cannot_bypass_applicability(self):
        self.assertEqual(self.judgments[0]["status"], "APPLICABLE")

    def test_missing_fact_requires_human_input(self):
        self.judgments = judge_applicability(self.controls, {})
        rep = self.report()
        self.assertEqual(rep["controls"][0]["status"], "NEEDS_EVIDENCE")
        self.assertTrue(rep["human_input_required"])

    def test_invalid_short_circuit_tail_and_quoted_operator(self):
        with self.assertRaises(ExpressionError):
            evaluate_condition("true or nonsense", {})
        self.assertTrue(evaluate_condition("'a or b' == 'a or b'", {}))

    def test_duplicate_ids_empty_fields_and_decision_types_rejected(self):
        for cs in ([control(), control()], [control(title=" ")],
                   [control(evidence_types=[""])], [control(evidence_types=["log", "log"])],
                   [control(needs_decision={})], [control(applicability="")]):
            with self.assertRaises(CecError):
                parse_policy_corpus({"controls": cs})
        with self.assertRaises(CecError):
            parse_policy_corpus({"controls": [], "unknown": True})

    def test_missing_duplicate_and_unknown_judgments_rejected(self):
        for judgments in ([], self.judgments * 2,
                          [dict(self.judgments[0], control_id="other")],
                          [dict(self.judgments[0], status="COMPLIANT")]):
            with self.assertRaises(CecError):
                compile_report(self.controls, judgments, self.ledger)

    def test_judgment_bound_to_current_control(self):
        self.controls[0]["evidence_types"] = ["other"]
        with self.assertRaises(CecError):
            self.report()

    def test_unrelated_or_empty_approval_rejected(self):
        for target, approver in (("C1", "person"), ("sha256:"+"0"*64, "person"),
                                 (self.report()["report_digest"], "")):
            with self.assertRaises(CecError):
                self.report({"record_type": "Approval", "role": "human",
                             "approves_report_of": target, "approver": approver})

    def test_report_digest_stable_and_approval_detached(self):
        digest = self.report()["report_digest"]
        self.assertEqual(digest, self.report()["report_digest"])
        approval = {"record_type": "Approval", "role": "human",
                    "approves_report_of": digest, "approver": "reviewer"}
        report = self.report(approval)
        approval["approver"] = "mutated"
        self.assertEqual(report["attestation"]["by_human_approval"]["approver"], "reviewer")
        self.assertFalse(report["attestation"]["identity_verified"])

    def test_new_evidence_invalidates_old_approval(self):
        digest = self.report()["report_digest"]
        self.ledger.harvest(b"clean log", evidence_type="log", source="ci://1", allowed_types={"log"})
        with self.assertRaises(CecError):
            self.report({"record_type": "Approval", "role": "human",
                         "approves_report_of": digest, "approver": "reviewer"})

    def test_invalid_scoping_facts_are_domain_errors(self):
        for facts in ([], {1: "x"}, {"enabled": float("nan")}):
            with self.assertRaises(CecError):
                judge_applicability(self.controls, facts)

class LedgerBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = EvidenceLedger(self.temp.name)

    def harvest(self, data=b"clean log", **changes):
        kw = dict(evidence_type="log", source="ci://1", allowed_types={"log"})
        kw.update(changes)
        return self.ledger.harvest(data, **kw)

    def test_missing_or_tampered_object_blocks_compilation(self):
        record = self.harvest()
        obj = Path(self.temp.name)/"objects"/record["digest"][7:]
        obj.write_bytes(b"tampered")
        with self.assertRaises(CecError):
            self.ledger.entries()
        self.harvest()  # A fresh screened harvest can repair the object.
        obj.unlink()
        with self.assertRaises(CecError):
            self.ledger.entries()

    def test_complete_corrupt_final_row_is_not_ignored(self):
        self.harvest()
        with open(self.ledger.index_path, "ab") as fh:
            fh.write(b'{"broken"\n')
        with self.assertRaises(CecError):
            self.ledger.entries()

    def test_partial_tail_recovery_allows_next_append(self):
        self.harvest()
        with open(self.ledger.index_path, "ab") as fh:
            fh.write(b'{"entry":')
        self.harvest(b"second")
        self.assertEqual(len(self.ledger.entries()), 2)

    def test_valid_unterminated_row_preserved_before_append(self):
        self.harvest()
        path = Path(self.ledger.index_path)
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        self.harvest(b"second")
        self.assertEqual(len(self.ledger.entries()), 2)

    def test_merkle_content_and_sequence_checked(self):
        self.harvest()
        path = Path(self.ledger.index_path)
        original = path.read_text()
        for mutation in ("source", "seq"):
            row = json.loads(original)
            if mutation == "source":
                row["entry"]["source"] = "forged"
            else:
                row["seq"] = True
            path.write_text(json.dumps(row)+"\n")
            with self.assertRaises(CecError):
                self.ledger.entries()
        path.write_text(original)

    def test_sensitive_metadata_not_logged(self):
        for source in ("https://user:pw@host/x", "ci://x?token=secret",
                       "alice@example.com", "customer_id=123"):
            with self.assertRaises(CecError):
                self.harvest(source=source)
        self.assertEqual(self.ledger.entries(), [])

    def test_binary_and_credential_evidence_refused(self):
        for data, action in ((b"\x00raw", "REFUSED_FORMAT"), (b"\xff", "REFUSED_FORMAT"),
                             (b"api_key=regression-placeholder", "REFUSED_SENSITIVE")):
            self.assertEqual(self.harvest(data)["action"], action)
        self.assertEqual(list((Path(self.temp.name)/"objects").iterdir()), [])

    def test_evidence_input_bounds(self):
        for data in ("text", b"x"*(MAX_EVIDENCE_BYTES+1)):
            with self.assertRaises(CecError):
                self.harvest(data)
        for kwargs in ({"allowed_types": "log"}, {"evidence_type": "../x"}, {"source": None}):
            with self.assertRaises(CecError):
                self.harvest(**kwargs)

    def test_multiple_ledger_instances_serialize_harvest(self):
        def write(i):
            led = EvidenceLedger(self.temp.name)
            return led.harvest(f"log {i}".encode(), evidence_type="log",
                               source=f"ci://{i}", allowed_types={"log"})
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            records = list(pool.map(write, range(12)))
        self.assertEqual(len(self.ledger.entries()), len(records))
        self.assertFalse(list((Path(self.temp.name)/"objects").glob("*.tmp")))

    def test_failed_ledger_fsync_does_not_commit_in_memory(self):
        record = self.harvest()
        with patch("cec.ledger.os.fsync", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                self.ledger._ledger.settle(record)
        self.assertEqual(len(self.ledger.entries()), 1)

    def test_legacy_unframed_ledger_requires_migration(self):
        record = self.harvest()
        Path(self.ledger.index_path).write_text(json.dumps(record)+"\n")
        with self.assertRaises(CecError):
            EvidenceLedger(self.temp.name)

    def test_invalid_evidence_record_schema_is_domain_error(self):
        self.ledger._ledger.settle({"action": []})
        with self.assertRaises(CecError):
            self.ledger.entries()

class InstalledRecords(unittest.TestCase):
    def test_schema_available_as_package_resource(self):
        self.assertEqual(load_schema()["title"], "Compliance Evidence Compiler Execution Record")

    def test_execution_record_detached_from_caller(self):
        work = [{"step": "review"}]
        record = make_execution_record("X", "IN_PROGRESS", work=work, artifacts=[],
            verification=[], evidence=[], guardrail_checks=[], blockers=[])
        work[0]["step"] = "changed"
        self.assertEqual(record["work_performed"][0]["step"], "review")
