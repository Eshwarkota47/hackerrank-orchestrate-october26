"""
Configuration and domain definitions for Ghost Data Still Exists.
Defines operation precedence, systems, phases, and mapping rules.
"""

# System IDs
SYSTEM_ACCOUNT = "account_service"
SYSTEM_SEARCH = "search_service"
SYSTEM_ANALYTICS = "analytics_platform"
SYSTEM_SUPPORT = "support_platform"
SYSTEM_INTEGRATION = "integration_service"
SYSTEM_BACKUP = "backup_service"
SYSTEM_SECURITY = "security_service"
SYSTEM_IDENTITY = "identity_service"
SYSTEM_EXPORT = "export_service"

# Phases
PHASE_FINDING = "FINDING"
PHASE_REMEDIATION = "REMEDIATION"
PHASE_VERIFICATION = "VERIFICATION"

# Deletion Statuses
STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

# Operation rankings within phases according to problem_statement.md
FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
}

REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
}

VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}

PHASE_ORDER = {
    PHASE_FINDING: 1,
    PHASE_REMEDIATION: 2,
    PHASE_VERIFICATION: 3,
}

def get_op_rank(phase: str, op: str) -> int:
    if phase == PHASE_FINDING:
        return FINDING_ORDER.get(op, 99)
    elif phase == PHASE_REMEDIATION:
        return REMEDIATION_ORDER.get(op, 99)
    elif phase == PHASE_VERIFICATION:
        return VERIFICATION_ORDER.get(op, 99)
    return 99
