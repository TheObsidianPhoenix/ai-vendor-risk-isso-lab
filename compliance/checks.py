"""Control checks that read evidence directly from AWS (read-only).

Each check asks one question an auditor would ask ("is every bucket
encrypted?"), answers it from the AWS APIs instead of a screenshot, and maps
the answer to SOC 2, ISO/IEC 27001:2022 Annex A and NIST SP 800-53 Rev. 5.
Mappings are marked preliminary until the Phase 10 control matrix validates
them.

Design rules:
- READ-ONLY. Only Describe/Get/List calls, plus generating the IAM credential
  report. Nothing is created, changed or deleted.
- NO SECRETS IN EVIDENCE. Results hold settings and names, never keys,
  policies' full text or tokens; AWS account numbers are masked (run.py).
- A CHECK THAT CAN'T RUN IS AN ERROR, NOT A PASS. Missing permission or an
  API failure is reported as "error", which fails the run, just like a failed
  control.
- KNOWN, ACCEPTED GAPS STAY VISIBLE. A failure covered by a risk-register
  entry is reported as "accepted" with the risk ID and a review date; once
  the review date passes it counts as a failure again.
"""

from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
KEY_MAX_AGE_DAYS = 90


@dataclass
class Result:
    id: str
    title: str
    status: str                      # pass | fail | error | accepted
    detail: str
    controls: dict
    evidence: dict = field(default_factory=dict)
    exception: dict | None = None


def _controls(soc2, iso, nist):
    return {"soc2": soc2, "iso27001_2022": iso, "nist_800_53": nist, "mapping": "preliminary"}


# ----- logging and monitoring ------------------------------------------------------

def cloudtrail(aws) -> Result:
    ct = aws.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    rows = []
    for t in trails:
        status = ct.get_trail_status(Name=t["TrailARN"])
        rows.append({"name": t["Name"], "multi_region": t.get("IsMultiRegionTrail", False),
                     "log_file_validation": t.get("LogFileValidationEnabled", False),
                     "kms_encrypted": bool(t.get("KmsKeyId")), "logging": status.get("IsLogging", False)})
    good = [r for r in rows if r["multi_region"] and r["log_file_validation"] and r["logging"]]
    return Result("C-01", "CloudTrail records activity in every region, with tamper-evident log files",
                  "pass" if good else "fail",
                  f"{len(good)} of {len(rows)} trails are multi-region, logging, with log file validation",
                  _controls(["CC7.2"], ["A.8.15", "A.8.16"], ["AU-2", "AU-9", "AU-12"]), {"trails": rows})


def security_alerts(aws) -> Result:
    events = aws.client("events")
    rules = events.list_rules(NamePrefix="counterpart-").get("Rules", [])
    enabled = [r["Name"] for r in rules if r.get("State") == "ENABLED"]
    sns = aws.client("sns")
    subs = sns.list_subscriptions().get("Subscriptions", [])
    confirmed = [s for s in subs if s.get("SubscriptionArn", "").startswith("arn:")]
    ok = len(enabled) >= 1 and len(confirmed) >= 1
    return Result("C-02", "Security alert rules are on and deliver to a confirmed recipient",
                  "pass" if ok else "fail",
                  f"{len(enabled)} enabled alert rules; {len(confirmed)} confirmed alert subscriptions",
                  _controls(["CC7.2", "CC7.3"], ["A.8.16"], ["SI-4", "IR-6"]),
                  {"enabled_rules": enabled, "confirmed_subscriptions": len(confirmed),
                   "protocols": sorted({s.get("Protocol", "") for s in confirmed})})


def guardduty(aws) -> Result:
    detectors = aws.client("guardduty").list_detectors().get("DetectorIds", [])
    return Result("C-03", "Threat detection (GuardDuty) is enabled",
                  "pass" if detectors else "fail",
                  f"{len(detectors)} GuardDuty detectors in this region",
                  _controls(["CC7.2"], ["A.8.16"], ["SI-4"]), {"detectors": len(detectors)})


# ----- identity and access ------------------------------------------------------------

def _credential_report(aws) -> list[dict]:
    iam = aws.client("iam")
    for _ in range(10):
        if iam.generate_credential_report().get("State") == "COMPLETE":
            break
        aws.sleep(2)
    content = iam.get_credential_report()["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return list(csv.DictReader(io.StringIO(text)))


def root_account(aws, report) -> Result:
    summary = aws.client("iam").get_account_summary()["SummaryMap"]
    root = next((r for r in report if r.get("user") == "<root_account>"), {})
    has_password = root.get("password_enabled", "false") == "true"
    keys = summary.get("AccountAccessKeysPresent", 0)
    mfa = summary.get("AccountMFAEnabled", 0) == 1
    # Root is safe if it has MFA, or if it has no password at all (centrally managed root in AWS Organizations)
    ok = keys == 0 and (mfa or not has_password)
    why = "no access keys; " + ("MFA on" if mfa else "no password (root sign-in not possible)" if not has_password
                                else "password set WITHOUT MFA")
    return Result("C-04", "The root user has no access keys and can't sign in without MFA",
                  "pass" if ok else "fail", why if keys == 0 else f"{keys} root access key(s) present",
                  _controls(["CC6.1"], ["A.8.2", "A.8.5"], ["IA-2(1)", "AC-6(5)"]),
                  {"root_access_keys": keys, "root_mfa": mfa, "root_password": has_password})


def user_mfa_and_keys(aws, report, now: datetime) -> Result:
    users = [r for r in report if r.get("user") != "<root_account>"]
    no_mfa = [r["user"] for r in users if r.get("password_enabled") == "true" and r.get("mfa_active") != "true"]
    old_keys = []
    for r in users:
        for n in ("1", "2"):
            if r.get(f"access_key_{n}_active") == "true":
                rotated = r.get(f"access_key_{n}_last_rotated", "N/A")
                if rotated not in ("N/A", "") and (now - datetime.fromisoformat(rotated.replace("Z", "+00:00"))).days > KEY_MAX_AGE_DAYS:
                    old_keys.append(r["user"])
    ok = not no_mfa and not old_keys
    return Result("C-05", f"IAM users with a password use MFA, and no access key is older than {KEY_MAX_AGE_DAYS} days",
                  "pass" if ok else "fail",
                  f"{len(users)} IAM users; {len(no_mfa)} without MFA; {len(old_keys)} with old access keys",
                  _controls(["CC6.1", "CC6.2"], ["A.5.17", "A.8.5"], ["IA-2(1)", "IA-5(1)"]),
                  {"iam_users": len(users), "users_without_mfa": no_mfa, "users_with_old_keys": old_keys})


def admin_principals(aws) -> Result:
    found = aws.client("iam").list_entities_for_policy(PolicyArn=ADMIN_POLICY)
    names = ([f"role:{r['RoleName']}" for r in found.get("PolicyRoles", [])]
             + [f"user:{u['UserName']}" for u in found.get("PolicyUsers", [])]
             + [f"group:{g['GroupName']}" for g in found.get("PolicyGroups", [])])
    return Result("C-06", "No principal holds full administrator access (least privilege)",
                  "pass" if not names else "fail",
                  f"{len(names)} principal(s) have AdministratorAccess",
                  _controls(["CC6.3"], ["A.5.15", "A.8.2"], ["AC-6", "AC-6(5)"]), {"admin_principals": names})


# ----- data protection ------------------------------------------------------------------

def s3_account_block(aws, account_id) -> Result:
    try:
        cfg = aws.client("s3control").get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except Exception as error:
        if "NoSuchPublicAccessBlockConfiguration" in type(error).__name__ + str(getattr(error, "response", "")):
            cfg = {}
        else:
            raise
    settings = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    ok = all(cfg.get(k) for k in settings)
    return Result("C-07", "S3 Block Public Access is on for the whole account",
                  "pass" if ok else "fail", "all four settings on" if ok else "one or more settings off",
                  _controls(["CC6.1"], ["A.8.3"], ["AC-3", "SC-7"]), {k: bool(cfg.get(k)) for k in settings})


def _error_code(error) -> str:
    return (getattr(error, "response", {}) or {}).get("Error", {}).get("Code", type(error).__name__)


def s3_buckets(aws) -> Result:
    s3 = aws.client("s3")
    rows, problems = [], []
    for b in s3.list_buckets().get("Buckets", []):
        name, row = b["Name"], {"bucket": b["Name"]}
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
            row["encryption"] = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except Exception as error:
            row["encryption"] = "none" if "ServerSideEncryptionConfigurationNotFound" in _error_code(error) else f"error:{_error_code(error)}"
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            row["public_access_blocked"] = all(cfg.values())
        except Exception:
            row["public_access_blocked"] = False
        try:
            policy = s3.get_bucket_policy(Bucket=name)["Policy"]
            row["https_only"] = '"aws:SecureTransport"' in policy and '"Deny"' in policy
        except Exception:
            row["https_only"] = False
        row["versioning"] = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        missing = [k for k in ("public_access_blocked", "https_only", "versioning") if not row[k]]
        if row["encryption"] not in ("aws:kms", "aws:kms:dsse", "AES256"):
            missing.insert(0, "encryption")
        if missing:
            problems.append(f"{name}: {', '.join(missing)}")
        rows.append(row)
    return Result("C-08", "Every S3 bucket is encrypted, private, HTTPS-only and versioned",
                  "pass" if rows and not problems else "fail",
                  f"{len(rows) - len(problems)} of {len(rows)} buckets meet all four" + (f"; gaps: {'; '.join(problems)}" if problems else ""),
                  _controls(["CC6.1", "CC6.7"], ["A.8.24", "A.8.13"], ["SC-28", "SC-8", "CP-9"]), {"buckets": rows})


def kms_rotation(aws) -> Result:
    kms = aws.client("kms")
    rows = []
    for k in kms.list_keys().get("Keys", []):
        meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
            continue
        rotation = kms.get_key_rotation_status(KeyId=k["KeyId"]).get("KeyRotationEnabled", False)
        rows.append({"key": k["KeyId"][-8:], "rotation": rotation})
    bad = [r for r in rows if not r["rotation"]]
    return Result("C-09", "Customer-managed encryption keys rotate automatically",
                  "pass" if rows and not bad else "fail",
                  f"{len(rows) - len(bad)} of {len(rows)} customer-managed keys rotate",
                  _controls(["CC6.1"], ["A.8.24"], ["SC-12"]), {"keys": rows})


def dynamodb(aws) -> Result:
    ddb = aws.client("dynamodb")
    rows = []
    for name in ddb.list_tables().get("TableNames", []):
        pitr = ddb.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]
        sse = ddb.describe_table(TableName=name)["Table"].get("SSEDescription", {})
        rows.append({"table": name,
                     "point_in_time_recovery": pitr.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") == "ENABLED",
                     "customer_key": sse.get("SSEType") == "KMS" and sse.get("Status") == "ENABLED"})
    bad = [r["table"] for r in rows if not (r["point_in_time_recovery"] and r["customer_key"])]
    return Result("C-10", "Database tables have point-in-time recovery and KMS encryption",
                  "pass" if rows and not bad else "fail",
                  f"{len(rows) - len(bad)} of {len(rows)} tables meet both" + (f"; gaps: {', '.join(bad)}" if bad else ""),
                  _controls(["CC6.1", "A1.2"], ["A.8.13", "A.8.24"], ["CP-9", "SC-28"]), {"tables": rows})


def budget_alerts(aws, account_id) -> Result:
    budgets = aws.client("budgets").describe_budgets(AccountId=account_id).get("Budgets", [])
    return Result("C-11", "A spending budget with alerts exists",
                  "pass" if budgets else "fail", f"{len(budgets)} budget(s)",
                  _controls([], [], []) | {"note": "Cost guardrail (decision D-11); no direct framework control"},
                  {"budgets": [b["BudgetName"] for b in budgets]})


# ----- runner ------------------------------------------------------------------------------

def run_all(aws, exceptions: dict, now: datetime | None = None) -> tuple[str, list[Result]]:
    now = now or datetime.now(timezone.utc)
    account_id = aws.client("sts").get_caller_identity()["Account"]
    results: list[Result] = []

    def attempt(check_id, title, fn, *args):
        try:
            results.append(fn(aws, *args))
        except Exception as error:   # Missing permission, throttling, network: never a pass
            results.append(Result(check_id, title, "error", f"check couldn't run ({_error_code(error)})", {}))

    attempt("C-01", "CloudTrail", cloudtrail)
    attempt("C-02", "Security alerts", security_alerts)
    attempt("C-03", "GuardDuty", guardduty)
    try:
        report = _credential_report(aws)
    except Exception as error:
        report = None
        results.append(Result("C-04", "Root account", "error", f"credential report unavailable ({_error_code(error)})", {}))
        results.append(Result("C-05", "IAM users", "error", f"credential report unavailable ({_error_code(error)})", {}))
    if report is not None:
        attempt("C-04", "Root account", root_account, report)
        attempt("C-05", "IAM users", user_mfa_and_keys, report, now)
    attempt("C-06", "Administrator access", admin_principals)
    attempt("C-07", "S3 account public access block", s3_account_block, account_id)
    attempt("C-08", "S3 buckets", s3_buckets)
    attempt("C-09", "KMS key rotation", kms_rotation)
    attempt("C-10", "DynamoDB", dynamodb)
    attempt("C-11", "Budget alerts", budget_alerts, account_id)

    for r in results:
        apply_exception(r, exceptions.get(r.id), now)
    results.sort(key=lambda r: r.id)
    return account_id, results


def apply_exception(result: Result, exception: dict | None, now: datetime) -> None:
    """A failure covered by an unexpired risk-register exception becomes 'accepted'."""
    if result.status != "fail" or not exception:
        return
    review_by = datetime.fromisoformat(exception["review_by"]).replace(tzinfo=timezone.utc)
    result.exception = dict(exception)
    if now <= review_by:
        result.status = "accepted"
    else:
        result.exception["expired"] = True
        result.detail += f" (exception {exception['risk']} expired {exception['review_by']}; review it)"


class AWS:
    """Thin wrapper so tests can swap in fake clients."""

    def __init__(self, region: str):
        import boto3  # Only needed for real runs
        self._session = boto3.session.Session(region_name=region)
        self._clients = {}

    def client(self, name):
        if name not in self._clients:
            self._clients[name] = self._session.client(name)
        return self._clients[name]

    @staticmethod
    def sleep(seconds):
        time.sleep(seconds)
