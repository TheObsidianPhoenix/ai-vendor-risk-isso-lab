"""Tests for the AWS control checks, with fake AWS clients (no network, no account).

What must hold: a compliant account passes; each kind of gap fails; a check
that can't run is an error, never a pass; accepted exceptions stay visible
and expire; the account number never appears in saved evidence.
"""

from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from compliance import checks
from compliance.run import report, summary_text

ROOT = Path(__file__).resolve().parent.parent
ACCOUNT = "123456789012"
NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
POLICY = '{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
REPORT = ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
          "access_key_2_active,access_key_2_last_rotated\n"
          f"<root_account>,arn:aws:iam::{ACCOUNT}:root,false,false,false,N/A,false,N/A\n")

GOOD = {
    "sts": {"get_caller_identity": {"Account": ACCOUNT}},
    "cloudtrail": {"describe_trails": {"trailList": [{"Name": "trail", "TrailARN": f"arn:aws:cloudtrail:us-east-2:{ACCOUNT}:trail/t",
                                                      "IsMultiRegionTrail": True, "LogFileValidationEnabled": True,
                                                      "KmsKeyId": "k"}]},
                   "get_trail_status": {"IsLogging": True}},
    "events": {"list_rules": {"Rules": [{"Name": "counterpart-dev-cloudtrail-tampering", "State": "ENABLED"}]}},
    "sns": {"list_subscriptions": {"Subscriptions": [{"SubscriptionArn": f"arn:aws:sns:us-east-2:{ACCOUNT}:alerts:1",
                                                      "Protocol": "email"}]}},
    "guardduty": {"list_detectors": {"DetectorIds": ["d1"]}},
    "iam": {"generate_credential_report": {"State": "COMPLETE"}, "get_credential_report": {"Content": REPORT.encode()},
            "get_account_summary": {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 0}},
            "list_entities_for_policy": {"PolicyRoles": [], "PolicyUsers": [], "PolicyGroups": []}},
    "s3control": {"get_public_access_block": {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}},
    "s3": {"list_buckets": {"Buckets": [{"Name": "counterpart-dev-audit"}]},
           "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
               {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}},
           "get_public_access_block": {"PublicAccessBlockConfiguration": {
               "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
           "get_bucket_policy": {"Policy": POLICY}, "get_bucket_versioning": {"Status": "Enabled"}},
    "kms": {"list_keys": {"Keys": [{"KeyId": "1234abcd-0000-0000-0000-00000000beef"}]},
            "describe_key": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}},
            "get_key_rotation_status": {"KeyRotationEnabled": True}},
    "dynamodb": {"list_tables": {"TableNames": ["counterpart-dev-vendors"]},
                 "describe_continuous_backups": {"ContinuousBackupsDescription": {
                     "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}}},
                 "describe_table": {"Table": {"SSEDescription": {"SSEType": "KMS", "Status": "ENABLED"}}}},
    "budgets": {"describe_budgets": {"Budgets": [{"BudgetName": "counterpart-dev-monthly"}]}},
}


class FakeClient:
    def __init__(self, answers, calls):
        self.answers, self.calls = answers, calls

    def __getattr__(self, method):
        def call(**kwargs):
            self.calls.append(method)
            answer = self.answers[method]
            if isinstance(answer, Exception):
                raise answer
            return copy.deepcopy(answer)
        return call


class FakeAWS:
    def __init__(self, data):
        self.data, self.calls = data, []

    def client(self, name):
        return FakeClient(self.data[name], self.calls)

    def sleep(self, _):
        pass


def account(**changes):
    data = copy.deepcopy(GOOD)
    for path, value in changes.items():
        service, method, *keys = path.split("__")
        target = data[service]
        if not keys:
            target[method] = value
            continue
        target = target[method]
        for k in keys[:-1]:
            target = target[k]
        target[keys[-1]] = value
    return data


def results(data, exceptions=None, now=NOW):
    return {r.id: r for r in checks.run_all(FakeAWS(data), exceptions or {}, now)[1]}


class Checks(unittest.TestCase):
    def test_a_compliant_account_passes_every_check(self):
        got = results(GOOD)
        self.assertEqual(sorted(got), [f"C-{n:02d}" for n in range(1, 12)])
        self.assertEqual({r.status for r in got.values()}, {"pass"}, {k: r.detail for k, r in got.items() if r.status != "pass"})

    def test_each_gap_fails_its_check(self):
        cases = {
            "C-01": account(cloudtrail__get_trail_status={"IsLogging": False}),
            "C-02": account(sns__list_subscriptions={"Subscriptions": [{"SubscriptionArn": "PendingConfirmation"}]}),
            "C-03": account(guardduty__list_detectors={"DetectorIds": []}),
            "C-04": account(iam__get_account_summary={"SummaryMap": {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 1}}),
            "C-06": account(iam__list_entities_for_policy={"PolicyRoles": [{"RoleName": "AccountFullAccessRole"}],
                                                           "PolicyUsers": [], "PolicyGroups": []}),
            "C-07": account(s3control__get_public_access_block__PublicAccessBlockConfiguration__BlockPublicPolicy=False),
            "C-08": account(s3__get_bucket_versioning={"Status": "Suspended"}),
            "C-09": account(kms__get_key_rotation_status={"KeyRotationEnabled": False}),
            "C-10": account(dynamodb__describe_table={"Table": {"SSEDescription": {}}}),
            "C-11": account(budgets__describe_budgets={"Budgets": []}),
        }
        for check_id, data in cases.items():
            with self.subTest(check=check_id):
                got = results(data)
                self.assertEqual(got[check_id].status, "fail", got[check_id].detail)
                others = {k for k, r in got.items() if r.status != "pass"}
                self.assertEqual(others, {check_id})

    def test_root_with_a_password_but_no_mfa_fails(self):
        data = account(iam__get_credential_report={"Content": REPORT.replace(",false,false,false,N/A", ",true,false,false,N/A").encode()})
        self.assertEqual(results(data)["C-04"].status, "fail")

    def test_iam_users_without_mfa_or_with_old_keys_fail(self):
        extra = ("alice,arn,true,false,false,N/A,false,N/A\n"
                 "bob,arn,false,false,true,2026-01-01T00:00:00+00:00,false,N/A\n")
        data = account(iam__get_credential_report={"Content": (REPORT + extra).encode()})
        got = results(data)["C-05"]
        self.assertEqual(got.status, "fail")
        self.assertEqual((got.evidence["users_without_mfa"], got.evidence["users_with_old_keys"]), (["alice"], ["bob"]))

    def test_an_unencrypted_bucket_is_named_in_the_gap(self):
        class NotFound(Exception):
            response = {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}
        got = results(account(s3__get_bucket_encryption=NotFound()))["C-08"]
        self.assertEqual(got.status, "fail")
        self.assertIn("counterpart-dev-audit: encryption", got.detail)

    def test_a_check_that_cannot_run_is_an_error_not_a_pass(self):
        class AccessDenied(Exception):
            response = {"Error": {"Code": "AccessDenied", "Message": "secret detail"}}
        got = results(account(kms__list_keys=AccessDenied()))["C-09"]
        self.assertEqual(got.status, "error")
        self.assertIn("AccessDenied", got.detail)
        self.assertNotIn("secret detail", got.detail)

    def test_the_checks_only_read(self):
        aws = FakeAWS(GOOD)
        checks.run_all(aws, {}, NOW)
        writes = [c for c in aws.calls if not c.startswith(("get_", "list_", "describe_", "generate_credential_report"))]
        self.assertEqual(writes, [])


class Exceptions(unittest.TestCase):
    EXC = {"C-06": {"risk": "R-02", "reason": "admin role", "review_by": "2026-11-30"}}
    ADMIN = {"iam__list_entities_for_policy": {"PolicyRoles": [{"RoleName": "AccountFullAccessRole"}],
                                               "PolicyUsers": [], "PolicyGroups": []}}

    def test_an_accepted_risk_is_reported_as_accepted_with_its_risk_id(self):
        got = results(account(**self.ADMIN), self.EXC)["C-06"]
        self.assertEqual((got.status, got.exception["risk"]), ("accepted", "R-02"))

    def test_an_expired_exception_fails_again(self):
        got = results(account(**self.ADMIN), self.EXC, now=datetime(2026, 12, 1, tzinfo=timezone.utc))["C-06"]
        self.assertEqual(got.status, "fail")
        self.assertIn("expired", got.detail)

    def test_an_exception_never_hides_a_passing_or_broken_check(self):
        self.assertEqual(results(GOOD, self.EXC)["C-06"].status, "pass")

    def test_the_repository_exceptions_point_at_real_risks(self):
        data = json.loads((ROOT / "compliance" / "exceptions.json").read_text())["exceptions"]
        register = (ROOT / "docs" / "risk-management" / "risk-register.md").read_text()
        for check_id, exc in data.items():
            with self.subTest(check=check_id):
                self.assertIn(f"| {exc['risk']} |", register)
                datetime.fromisoformat(exc["review_by"])


class Evidence(unittest.TestCase):
    def test_the_account_number_is_masked_everywhere(self):
        account_id, got = checks.run_all(FakeAWS(GOOD), {}, NOW)
        data = report(account_id, got, NOW)
        text = json.dumps(data) + summary_text(data)
        self.assertNotIn(ACCOUNT, text)
        self.assertIn("********9012", text)

    def test_the_summary_counts_every_outcome(self):
        account_id, got = checks.run_all(FakeAWS(account(guardduty__list_detectors={"DetectorIds": []})), {}, NOW)
        data = report(account_id, got, NOW)
        self.assertEqual(data["summary"], {"pass": 10, "fail": 1, "error": 0, "accepted": 0})


if __name__ == "__main__":
    unittest.main()
