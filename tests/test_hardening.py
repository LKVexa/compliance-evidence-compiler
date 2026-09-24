"""Regression tests for 0.1.1-partial hardening fixes (findings A005-F1..F6)."""
import json
import os
import tempfile
import unittest

from cec.core import (CecError, EvidenceLedger, compile_report,
                      judge_applicability, parse_policy_corpus, sha256)
from cec.vendor.condition_evaluator import ExpressionError, evaluate_condition


def _ctrl(**kw):
    c = {"control_id": "C1", "title": "t", "evidence_types": ["log"],
         "applicability": "true"}
    c.update(kw)
    return c


class TestLedgerCrashRecovery(unittest.TestCase):  # A005-F1
    def test_torn_final_line_is_recovered(self):
        d = tempfile.mkdtemp()
        led = EvidenceLedger(d)
        led.harvest(b"clean data", evidence_type="log", source="s",
                    allowed_types={"log"})
        with open(led.index_path, "a") as fh:
            fh.write('{"action": "HARV')  # simulated crash mid-append
        ents = led.entries()
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0]["action"], "HARVESTED")

    def test_corrupt_interior_line_is_tamper(self):
        d = tempfile.mkdtemp()
        led = EvidenceLedger(d)
        led.harvest(b"one", evidence_type="log", source="s", allowed_types={"log"})
        led.harvest(b"two", evidence_type="log", source="s", allowed_types={"log"})
        with open(led.index_path) as fh:
            lines = fh.read().splitlines()
        lines[0] = lines[0][:-4] + "XXX"
        with open(led.index_path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        with self.assertRaises(CecError):
            led.entries()


class TestInjection(unittest.TestCase):  # A005-F2
    def test_quote_splice_cannot_flip_judgment(self):
        controls = [_ctrl(applicability="{{env}} == 'prod'")]
        j = judge_applicability(controls, {"env": "a' == 'a' or 'b"})
        self.assertEqual(j[0]["status"], "NOT_APPLICABLE")

    def test_operator_text_in_value_is_data(self):
        # Values containing operator words / quotes stay opaque data.
        self.assertFalse(evaluate_condition("{{v}} == 'prod'",
                                            {"v": "x or true"}))
        self.assertTrue(evaluate_condition("{{v}} != 'prod'",
                                           {"v": "not prod == prod"}))

    def test_legit_comparisons_still_work(self):
        self.assertTrue(evaluate_condition("{{env}} == 'prod'", {"env": "prod"}))
        self.assertTrue(evaluate_condition("{{a}} == 'x' or {{b}} == 'y'",
                                           {"a": "z", "b": "y"}))


class TestAttestationContract(unittest.TestCase):  # A005-F3
    def _report(self, approval):
        return compile_report([], [], EvidenceLedger(tempfile.mkdtemp()),
                              human_approval=approval)

    def test_missing_required_key_rejected(self):
        # Baseline's proper-subset check wrongly accepted this record
        # (missing approves_report_of but carrying an extra key); the
        # strengthened contract requires ALL required keys (GRD-02).
        with self.assertRaises(CecError):
            self._report({"record_type": "Approval", "role": "human",
                          "approver": "x", "extra": 1})

    def test_well_formed_approval_accepted(self):
        r = self._report({"record_type": "Approval", "role": "human",
                          "approver": "x", "approves_report_of": self._report(None)["report_digest"]})
        self.assertIn("attestation", r)


class TestParseIsolationAndTypes(unittest.TestCase):  # A005-F4/F5
    def test_parsed_controls_isolated_from_corpus(self):
        corpus = {"controls": [_ctrl()]}
        cs = parse_policy_corpus(corpus)
        corpus["controls"][0]["evidence_types"].append("rogue")
        self.assertEqual(cs[0]["evidence_types"], ["log"])

    def test_non_dict_control_is_cec_error(self):
        with self.assertRaises(CecError):
            parse_policy_corpus({"controls": [42]})

    def test_non_list_controls_is_cec_error(self):
        with self.assertRaises(CecError):
            parse_policy_corpus({"controls": "nope"})

    def test_non_string_rule_is_cec_error_at_parse(self):
        with self.assertRaises(CecError):
            parse_policy_corpus({"controls": [_ctrl(applicability=123)]})

    def test_non_string_rule_at_judge_is_needs_evidence(self):
        j = judge_applicability([_ctrl(applicability=123)], {})
        self.assertEqual(j[0]["status"], "NEEDS_EVIDENCE")


class TestObjectStoreIntegrity(unittest.TestCase):  # A005-F6
    def test_torn_preexisting_object_is_repaired(self):
        d = tempfile.mkdtemp()
        led = EvidenceLedger(d)
        data = b"good evidence bytes"
        obj = os.path.join(d, "objects", sha256(data).split(":", 1)[1])
        with open(obj, "wb") as fh:
            fh.write(b"TORN")
        rec = led.harvest(data, evidence_type="log", source="s",
                          allowed_types={"log"})
        self.assertEqual(rec["action"], "HARVESTED")
        with open(obj, "rb") as fh:
            self.assertEqual(fh.read(), data)

    def test_no_tmp_left_behind(self):
        d = tempfile.mkdtemp()
        led = EvidenceLedger(d)
        led.harvest(b"abc", evidence_type="log", source="s", allowed_types={"log"})
        self.assertFalse([f for f in os.listdir(os.path.join(d, "objects"))
                          if f.endswith(".tmp")])


if __name__ == "__main__":
    unittest.main()
