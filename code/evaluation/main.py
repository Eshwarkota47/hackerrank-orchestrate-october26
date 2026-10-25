"""
Evaluation workflow and benchmarking runner for Ghost Data Still Exists.
Evaluates agent predictions against ground-truth sample data and executes
participant-created custom benchmark scenarios to measure case, step, field, and sequence accuracy.
"""

import csv
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Any, Tuple

# Add directories to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
sys.stdout.reconfigure(encoding="utf-8")

try:
    from auditor import DeletionAuditor
except (ImportError, ModuleNotFoundError):
    from code.auditor import DeletionAuditor

CUSTOM_SCENARIOS = [
    {
        "case_id": "case_custom_01",
        "email": "leila.haddad@yahoo.com",
        "requested_at": "2026-08-25T08:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-08-28T09:03:00Z",
        "audit_at": "2026-09-03T12:00:00Z",
        "request_text": "I submitted an account deletion request previously. Please audit all primary and failover database replicas to ensure my account is deleted.",
        "description": "Secondary replica desynchronization and orphaned failover record after primary account deletion.",
        "expected_status": "INCOMPLETE",
        "expected_min_findings": 1
    },
    {
        "case_id": "case_custom_02",
        "email": "minjun.kim@gmail.com",
        "requested_at": "2026-08-24T12:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-08-25T12:00:00Z",
        "audit_at": "2026-09-15T12:00:00Z",
        "request_text": "I changed the email on this account before deleting it. Please check that nothing tied to the old address was left behind, even in systems that do not display the email.",
        "description": "Cryptographic email hash correlation across audit logs and distributed connector sync streams.",
        "expected_status": "INCOMPLETE",
        "expected_min_findings": 1
    },
    {
        "case_id": "case_custom_03",
        "email": "nadia.ionescu@yahoo.com",
        "requested_at": "2026-09-05T14:30:00Z",
        "reported_status": "NOT_APPLICABLE",
        "reported_at": "2026-09-05T15:00:00Z",
        "audit_at": "2026-09-20T14:30:00Z",
        "request_text": "Under GDPR Article 15, I request a copy of all my personal data and past purchases. Do not close or delete my account.",
        "description": "Disambiguation of Subject Access Request (SAR) from deletion request with empty remediation plan.",
        "expected_status": "NOT_APPLICABLE",
        "expected_steps_cnt": 0
    }
]

def evaluate_samples(sample_requests_path: str = "dataset/sample_deletion_requests.csv",
                     sample_output_path: str = "dataset/sample_output.csv") -> Dict[str, Any]:
    print(f"Loading evaluation dataset: {sample_requests_path}")
    auditor = DeletionAuditor()

    with open(sample_requests_path, mode="r", encoding="utf-8") as f:
        requests = list(csv.DictReader(f))

    with open(sample_output_path, mode="r", encoding="utf-8") as f:
        ground_truth = {row["case_id"]: (row["deletion_status"], json.loads(row["steps_json"])) for row in csv.DictReader(f)}

    total_cases = len(requests)
    status_matches = 0
    exact_sequence_matches = 0
    total_truth_steps = 0
    total_pred_steps = 0
    matched_steps = 0

    field_correct = defaultdict(int)
    field_total = defaultdict(int)

    results_by_case = []

    for req in requests:
        cid = req["case_id"]
        pred_status, pred_steps = auditor.audit_request(req)
        truth_status, truth_steps = ground_truth.get(cid, ("UNKNOWN", []))

        # 1. Case-level status match
        status_match = (pred_status == truth_status)
        if status_match:
            status_matches += 1

        # 2. Sequence-level exact match
        seq_match = (status_match and pred_steps == truth_steps)
        if seq_match:
            exact_sequence_matches += 1

        total_truth_steps += len(truth_steps)
        total_pred_steps += len(pred_steps)

        # 3. Step & field matching
        min_len = min(len(pred_steps), len(truth_steps))
        for i in range(min_len):
            ps = pred_steps[i]
            ts = truth_steps[i]
            all_fields_match = True
            for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total[field] += 1
                if ps.get(field) == ts.get(field):
                    field_correct[field] += 1
                else:
                    all_fields_match = False
            if all_fields_match:
                matched_steps += 1

        # Excess truth or pred fields
        if len(truth_steps) > min_len:
            for i in range(min_len, len(truth_steps)):
                for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                    field_total[field] += 1
        elif len(pred_steps) > min_len:
            for i in range(min_len, len(pred_steps)):
                for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                    field_total[field] += 1

        results_by_case.append({
            "case_id": cid,
            "status_match": status_match,
            "seq_match": seq_match,
            "truth_status": truth_status,
            "pred_status": pred_status,
            "truth_steps_cnt": len(truth_steps),
            "pred_steps_cnt": len(pred_steps),
        })

    case_acc = (status_matches / total_cases) * 100 if total_cases else 0.0
    seq_acc = (exact_sequence_matches / total_cases) * 100 if total_cases else 0.0

    step_precision = (matched_steps / total_pred_steps) * 100 if total_pred_steps else 0.0
    step_recall = (matched_steps / total_truth_steps) * 100 if total_truth_steps else 0.0
    step_f1 = (2 * step_precision * step_recall / (step_precision + step_recall)) if (step_precision + step_recall) else 0.0

    field_accuracies = {
        k: (field_correct[k] / field_total[k] * 100) if field_total[k] else 0.0
        for k in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")
    }

    # Custom Scenarios Evaluation
    custom_results = []
    for sc in CUSTOM_SCENARIOS:
        pred_st, pred_stps = auditor.audit_request(sc)
        matched_sc = (pred_st == sc["expected_status"])
        custom_results.append({
            "case_id": sc["case_id"],
            "description": sc["description"],
            "expected_status": sc["expected_status"],
            "predicted_status": pred_st,
            "matched": matched_sc,
            "steps_count": len(pred_stps)
        })

    return {
        "total_cases": total_cases,
        "status_matches": status_matches,
        "case_acc": case_acc,
        "exact_sequence_matches": exact_sequence_matches,
        "seq_acc": seq_acc,
        "step_precision": step_precision,
        "step_recall": step_recall,
        "step_f1": step_f1,
        "field_accuracies": field_accuracies,
        "field_correct": dict(field_correct),
        "field_total": dict(field_total),
        "results_by_case": results_by_case,
        "custom_results": custom_results
    }

def print_evaluation_summary(metrics: Dict[str, Any]):
    print("\n" + "=" * 60)
    print("           DELETION AUDIT EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Total Cases Evaluated:       {metrics['total_cases']}")
    print(f"Case Classification Accuracy: {metrics['case_acc']:.2f}% ({metrics['status_matches']}/{metrics['total_cases']})")
    print(f"Exact Sequence Accuracy:      {metrics['seq_acc']:.2f}% ({metrics['exact_sequence_matches']}/{metrics['total_cases']})")
    print(f"Step Precision:               {metrics['step_precision']:.2f}%")
    print(f"Step Recall:                  {metrics['step_recall']:.2f}%")
    print(f"Step F1 Score:                {metrics['step_f1']:.2f}%")
    print("-" * 60)
    print("Field-Level Accuracies:")
    for fld, acc in metrics["field_accuracies"].items():
        corr = metrics['field_correct'].get(fld, 0)
        tot = metrics['field_total'].get(fld, 0)
        print(f"  {fld:15}: {acc:6.2f}% ({corr}/{tot})")
    print("-" * 60)
    print("Custom Evaluation Scenarios:")
    for sc in metrics["custom_results"]:
        status_str = "PASS" if sc["matched"] else "FAIL"
        print(f"  [{status_str}] {sc['case_id']}: {sc['predicted_status']} (Expected: {sc['expected_status']}) - {sc['description'][:45]}...")
    print("=" * 60 + "\n")

def main():
    metrics = evaluate_samples()
    print_evaluation_summary(metrics)

if __name__ == "__main__":
    main()
