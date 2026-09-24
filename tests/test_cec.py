import json
import os
import tempfile
import unittest

from cec.core import (CecError, EvidenceLedger, compile_report,
                      judge_applicability, parse_policy_corpus,
                      screen_for_sensitive_data)
from cec.records import make_execution_record

CORPUS = {"controls": [
    {"control_id": "AC-01", "title": "Access reviews",
     "evidence_types": ["access-review-export"],
     "applicability": "{{handles_auth}} == 'true'"},
    {"control_id": "SC-02", "title": "Dependency scanning",
     "evidence_types": ["sbom", "scan-report"],
     "applicability": "{{ships_software}} == 'true'"},
    {"control_id": "DR-03", "title": "Backup restore test",
     "evidence_types": ["restore-log"],
     "applicability": "{{stores_data}} == 'true'",
     "not_applicable_when": "{{stateless}} == 'true'"},
    {"control_id": "RT-04", "title": "Log retention",
     "evidence_types": ["retention-config"],
     "applicability": "{{ships_software}} == 'true'",
     "needs_decision": "DEC-03 (retention period unspecified by source)"},
]}

FACTS = {"handles_auth": "true", "ships_software": "true",
         "stores_data": "true", "stateless": "true"}


class PolicyParser(unittest.TestCase):
    def test_parse_ok(self):
        controls = parse_policy_corpus(CORPUS)
        self.assertEqual(len(controls), 4)

    def test_missing_fields_error(self):
        with self.assertRaises(CecError):
            parse_policy_corpus({"controls": [{"control_id": "X"}]})

    def test_unknown_fields_error(self):
        with self.assertRaises(CecError):
            parse_policy_corpus({"controls": [dict(CORPUS["controls"][0],
                                                   surprise=1)]})


class Applicability(unittest.TestCase):
    def setUp(self):
        self.j = {x["control_id"]: x for x in
                  judge_applicability(parse_policy_corpus(CORPUS), FACTS)}

    def test_judgments(self):
        self.assertEqual(self.j["AC-01"]["status"], "APPLICABLE")
        self.assertEqual(self.j["SC-02"]["status"], "APPLICABLE")
        # exclusion rule wins: stateless system needs no restore test
        self.assertEqual(self.j["DR-03"]["status"], "NOT_APPLICABLE")

    def test_reasoning_recorded(self):
        for j in self.j.values():
            self.assertIn("rule", j)
            self.assertTrue(j["reasoning"])
            self.assertIn("facts_consulted", j)

    def test_missing_fact_needs_evidence_not_guess(self):
        j = judge_applicability(parse_policy_corpus(CORPUS), {})[0]
        self.assertEqual(j["status"], "NEEDS_EVIDENCE")


class Guardrails(unittest.TestCase):
    def setUp(self):
        self.led = EvidenceLedger(tempfile.mkdtemp())
        self.allowed = {"sbom", "scan-report", "access-review-export"}

    def test_grd01_sensitive_data_refused(self):
        pii = b"customer_email: alice@example.com\ncustomer_id: 42"
        rec = self.led.harvest(pii, evidence_type="sbom", source="s3://x",
                               allowed_types=self.allowed)
        self.assertEqual(rec["action"], "REFUSED_SENSITIVE")
        self.assertNotIn("digest", rec)          # bytes not stored
        self.assertFalse(os.listdir(os.path.join(self.led.root, "objects")))

    def test_grd04_out_of_scope_refused(self):
        rec = self.led.harvest(b"data", evidence_type="hr-records",
                               source="x", allowed_types=self.allowed)
        self.assertEqual(rec["action"], "REFUSED_OUT_OF_SCOPE")

    def test_harvest_content_addressed(self):
        rec = self.led.harvest(b"sbom-content", evidence_type="sbom",
                               source="ci://run/1", allowed_types=self.allowed)
        self.assertEqual(rec["action"], "HARVESTED")
        self.assertTrue(rec["digest"].startswith("sha256:"))

    def test_detector_patterns(self):
        self.assertIn("card-number",
                      screen_for_sensitive_data(b"4111 1111 1111 1111"))
        self.assertIn("ssn-like", screen_for_sensitive_data(b"123-45-6789"))
        self.assertEqual(screen_for_sensitive_data(b"clean build log"), [])

    def test_grd03_no_production_change_api(self):
        import cec.core as m
        for name in dir(m):
            low = name.lower()
            for bad in ("deploy", "apply_change", "remediate", "push"):
                self.assertNotIn(bad, low)


class Report(unittest.TestCase):
    def build(self, approval=None):
        controls = parse_policy_corpus(CORPUS)
        judgments = judge_applicability(controls, FACTS)
        led = EvidenceLedger(tempfile.mkdtemp())
        allowed = {"sbom", "scan-report", "access-review-export"}
        led.harvest(b"cyclonedx...", evidence_type="sbom", source="ci://sbom",
                    allowed_types=allowed)
        led.harvest(b"scan clean", evidence_type="scan-report",
                    source="ci://scan", allowed_types=allowed)
        if approval == "valid":
            approval = {"record_type": "Approval", "role": "human",
                        "approves_report_of": compile_report(controls, judgments, led)["report_digest"],
                        "approver": "qa-lead"}
        return compile_report(controls, judgments, led, approval)

    def test_gaps_explicit(self):
        rep = self.build()
        ac = next(r for r in rep["controls"] if r["control_id"] == "AC-01")
        self.assertEqual(ac["status"], "NEEDS_EVIDENCE")
        self.assertEqual(ac["gaps"], ["access-review-export"])
        sc = next(r for r in rep["controls"] if r["control_id"] == "SC-02")
        self.assertEqual(sc["status"], "EVIDENCE_COMPILED")
        self.assertEqual(len(sc["evidence"]), 2)
        self.assertTrue(rep["human_input_required"])     # PAPER-CAP-06

    def test_needs_decision_never_invented(self):
        rep = self.build()
        rt = next(r for r in rep["controls"] if r["control_id"] == "RT-04")
        self.assertEqual(rt["status"], "NEEDS_DECISION")
        self.assertIn("DEC-03", rt["blocking_decision"])

    def test_grd02_no_attestation_without_human_approval(self):
        rep = self.build()
        self.assertNotIn("attestation", rep)
        from cec.core import CecError
        with self.assertRaises(CecError):
            self.build({"record_type": "Approval", "role": "compiler"})
        ok = self.build("valid")
        self.assertIn("attestation", ok)
        self.assertEqual(ok["attestation"]["by_human_approval"]["approver"],
                         "qa-lead")


class ExecutionRecords(unittest.TestCase):
    def test_record_validates_against_source_schema(self):
        rec = make_execution_record(
            "COMP-03", "IN_PROGRESS",
            work=[{"step": "implemented applicability engine slice"}],
            artifacts=[{"path": "cec/core.py"}],
            verification=[{"check": "unit tests", "result": "pass"}],
            evidence=[{"kind": "test-run", "ref": "docs/CHECK_RUNS.json"}],
            guardrail_checks=[{"guardrail": "GRD-01", "result": "enforced"}],
            blockers=[{"id": "DEC-03", "reason": "retention period unspecified"}])
        self.assertEqual(rec["status"], "IN_PROGRESS")

    def test_invalid_status_rejected(self):
        import jsonschema
        with self.assertRaises(jsonschema.ValidationError):
            make_execution_record("X", "TOTALLY_DONE", work=[], artifacts=[],
                                  verification=[], evidence=[],
                                  guardrail_checks=[], blockers=[])


if __name__ == "__main__":
    unittest.main()
