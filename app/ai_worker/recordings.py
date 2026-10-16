"""Recorded model answers for the three fictional sample vendors.

These stand in for Amazon Bedrock until Phase 5. They're what a well-behaved
model should say about each vendor, written by hand from the sample
documents, with every quote copied exactly so the citation checker can find it.
Each recording is selected by the canary reference printed in that vendor's
documents. A real model never sees these.
"""

from __future__ import annotations

Q = "vendor-questionnaire.xlsx"
SOC2 = "soc2-type2-summary.pdf"
POLICY = "security-policy-packet.pdf"


def f(category, state, interpretation, confidence, *citations):
    return {
        "category": category,
        "evidence_state": state,
        "citations": [{"document": d, "location": loc, "quote": quote} for d, loc, quote in citations],
        "interpretation": interpretation,
        "confidence": confidence,
    }


NIMBUS = {
    "findings": [
        f("identity_access", "verified", "Phishing-resistant MFA for all administrative access, confirmed by the SOC 2 auditor with no exceptions.", "high",
          (SOC2, "page 4", "All administrative access requires single sign-on with phishing-resistant MFA"),
          (Q, "IAM-01", "SSO with phishing-resistant MFA for all admin access.")),
        f("encryption", "verified", "AES-256 at rest and TLS 1.2+ in transit, tested by the auditor.", "high",
          (SOC2, "page 5", "Customer data is encrypted at rest with AES-256 and in transit with TLS 1.2 or higher.")),
        f("incident_response", "conflict", "The questionnaire says customers are told within 30 days; the policy packet says 72 hours. The reviewer needs to find out which is true.", "high",
          (Q, "IR-03", "Customer notification: within 30 days."),
          (POLICY, "page 6", "Affected customers are notified within 72 hours of a confirmed breach.")),
        f("vulnerability_management", "absent", "All four vulnerability questions are blank, and the SOC 2 report says vulnerability management was out of scope.", "high",
          (Q, "VM-01", "How often do you scan for vulnerabilities?"),
          (SOC2, "page 5", "Out of scope: vulnerability management")),
        f("data_retention", "absent", "No retention limit: recordings are kept for the life of the account and deleted only at closure.", "medium",
          (POLICY, "page 4", "Recordings are retained for the life of the customer account.")),
        f("logging_monitoring", "unverified", "Centralized logging is claimed, but log retention is blank and the auditor didn't examine it.", "medium",
          (Q, "LM-01", "We maintain centralized security logging.")),
        f("business_continuity", "unverified", "A 4-hour recovery time objective is stated, but continuity testing was out of the audit's scope.", "medium",
          (Q, "BC-02", "Recovery time objective: 4 hours."),
          (POLICY, "page 8", "We maintain a business continuity plan with a recovery time objective of 4 hours.")),
        f("security_awareness", "verified", "Annual training for all staff, confirmed by the auditor.", "high",
          (SOC2, "page 4", "All staff complete security awareness training annually.")),
        f("secure_development", "verified", "Peer review on every code change, confirmed by the auditor.", "high",
          (SOC2, "page 4", "Every code change requires peer review before release.")),
        f("third_party", "verified", "Subprocessors are listed and assessed annually, confirmed by the auditor.", "high",
          (SOC2, "page 5", "A subprocessor list is maintained and each subprocessor is assessed annually.")),
        f("privacy", "verified", "A privacy notice and tracked data subject requests, confirmed by the auditor.", "high",
          (SOC2, "page 5", "A privacy notice is published and data subject requests are tracked to completion.")),
        f("ai_governance", "contradicted", "Customer audio is used to train the vendor's models by default. Customers have to opt out in writing.", "high",
          (POLICY, "page 3", "Customer audio may be used to improve our transcription models unless the customer opts out"),
          (Q, "AI-01", "Customer audio may be used to improve our models unless the customer opts out in writing.")),
    ],
    "follow_up_questions": [
        "Which breach notification time is correct: 30 days or 72 hours? Please share the current incident response plan.",
        "How often do you scan for vulnerabilities, and when was your last independent penetration test?",
        "Can we contractually opt out of our data being used for model training before any data is shared?",
        "What is the maximum retention period for recordings, and can it be shortened?",
    ],
    "summary": "Strong audited controls for access, encryption and development. Concerns: customer audio is used for model training by default, vulnerability management is undocumented, and the two breach notification times disagree. Hidden text on page 9 of the policy packet looks like an instruction to an AI and was treated as data.",
}

COPPERLINE = {
    "findings": [
        f("identity_access", "unverified", "MFA for administrators is claimed with no supporting evidence.", "medium",
          (Q, "IAM-01", "Yes, MFA is required for administrators.")),
        f("encryption", "unverified", "Encryption is claimed, but no algorithm or TLS version is named and no evidence is provided.", "medium",
          (Q, "ENC-01", "All backups are encrypted using industry-standard encryption."),
          (Q, "ENC-02", "Name the minimum TLS version.")),
        f("incident_response", "unverified", "A plan is claimed, but it has never been tested and the notification time is just 'Promptly'.", "medium",
          (Q, "IR-01", "Yes, we have an incident response plan.")),
        f("vulnerability_management", "absent", "All four vulnerability questions are blank.", "high",
          (Q, "VM-01", "How often do you scan for vulnerabilities?")),
        f("data_retention", "conflict", "Data is said to be deleted within 30 days, but backups are kept for 7 years.", "high",
          (Q, "DR-01", "Customer data is deleted within 30 days of contract end."),
          (Q, "DR-02", "Backups are retained for 7 years for compliance purposes.")),
        f("logging_monitoring", "unverified", "Logging is claimed with a one-word answer and no retention period.", "medium",
          (Q, "LM-01", "Do you maintain centralized security logging?")),
        f("business_continuity", "unverified", "A 1-hour recovery objective is claimed with no test evidence.", "medium",
          (Q, "BC-01", "Yes, as a backup provider this is core to our service."),
          (Q, "BC-02", "1 hour.")),
        f("security_awareness", "unverified", "Training is claimed with a one-word answer.", "low",
          (Q, "SA-01", "Do all staff complete security awareness training annually?")),
        f("secure_development", "absent", "The secure development question is blank.", "high",
          (Q, "SD-01", "Do you follow a secure development lifecycle, including code review?")),
        f("third_party", "unverified", "Subprocessors aren't named or assessed: 'a small number of trusted partners'.", "medium",
          (Q, "TP-01", "We use a small number of trusted partners.")),
        f("privacy", "unverified", "Privacy practices are claimed with a one-word answer.", "low",
          (Q, "PR-01", "Do you publish a privacy notice and support data subject requests?")),
    ],
    "follow_up_questions": [
        "Can you provide a SOC 2 Type II report or ISO 27001 certificate?",
        "Which encryption algorithm and minimum TLS version do you use?",
        "Customer data is deleted in 30 days but backups are kept 7 years. Which applies to our data?",
        "Please complete the vulnerability management and secure development sections.",
    ],
    "summary": "Every answer is self-attested, with no audit report or other evidence. Vulnerability management and secure development are blank, and the retention answers contradict each other.",
}

KESTREL = {
    "findings": [
        f("identity_access", "verified", "Hardware-key MFA and quarterly access reviews, audited with no exceptions.", "high",
          (SOC2, "page 3", "Hardware-key MFA is required for all administrative access; access is reviewed quarterly.")),
        f("encryption", "verified", "AES-256 at rest and TLS 1.2+ in transit, audited.", "high",
          (SOC2, "page 3", "Data is encrypted at rest with AES-256 and in transit with TLS 1.2 or higher.")),
        f("incident_response", "verified", "Plan tested May 2026; 72-hour customer notification.", "high",
          (SOC2, "page 4", "The incident response plan was tested in May 2026; customers are notified within 72 hours.")),
        f("vulnerability_management", "verified", "Weekly scans, annual penetration test, 15-day fix target for critical findings.", "high",
          (SOC2, "page 4", "Weekly authenticated vulnerability scans; annual independent penetration test (April 2026);")),
        f("data_retention", "verified", "Documented retention schedule; deletion within 30 days of request.", "high",
          (SOC2, "page 5", "Retention follows a documented schedule; deletion requests are completed within 30 days.")),
        f("logging_monitoring", "verified", "Centralized, alerted logs kept for one year.", "high",
          (SOC2, "page 5", "Security logs are centralized, alerted on and kept for one year.")),
        f("business_continuity", "verified", "Failover tested February 2026 and met the 4-hour objective.", "high",
          (SOC2, "page 5", "the last failover test (February 2026) met the 4-hour RTO")),
        f("security_awareness", "verified", "Annual training plus quarterly phishing exercises.", "high",
          (SOC2, "page 3", "Staff complete annual security training and quarterly phishing exercises.")),
        f("secure_development", "verified", "Code review and automated security scanning on every change.", "high",
          (SOC2, "page 3", "Every change requires code review and passes automated security scanning.")),
        f("third_party", "verified", "Subprocessors assessed annually.", "high",
          (SOC2, "page 5", "Subprocessors are assessed annually.")),
        f("privacy", "verified", "Published privacy notice; requests tracked.", "high",
          (SOC2, "page 5", "A privacy notice is published")),
    ],
    "follow_up_questions": [
        "Please confirm the SOC 2 bridge letter covers the period since 31 May 2026.",
    ],
    "summary": "All twelve areas are backed by an independent SOC 2 Type II report with no exceptions. The vendor states it does not use AI on customer data.",
}

BY_CANARY = {
    "CANARY-NIMBUS-7Q2F": NIMBUS,
    "CANARY-COPPER-3K8M": COPPERLINE,
    "CANARY-KESTREL-9P4D": KESTREL,
}
