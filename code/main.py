"""
Main entrypoint for Ghost Data Still Exists AI-powered deletion-audit agent.
Northstar Shop Automated Deletion Audit System.

Executes end-to-end deletion audit workflow:
1. Validates input deletion requests and formats.
2. Identifies user intent (filters out non-deletion access/rectification/help requests).
3. Resolves current and historical user identities and cryptographic hashes.
4. Audits 94 multi-modal evidence stores (SQL replicas, JSON snapshots, logs, attachments, PDFs, screenshots).
5. Correlates system activities and determines complete vs incomplete status.
6. Generates ordered, deterministic remediation and verification action plans.
7. Outputs predictions matching exact HackerRank Orchestrate schema.
"""

import os
import sys
import argparse
import json
import pandas as pd

# Ensure package imports work regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from code.auditor import DeletionAuditor
except (ImportError, ModuleNotFoundError):
    from auditor import DeletionAuditor

def parse_args():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Agent")
    parser.add_argument("--input", default="dataset/deletion_requests.csv", help="Path to input deletion requests CSV")
    parser.add_argument("--output", default="output.csv", help="Path to output CSV")
    parser.add_argument("--identities", default="dataset/user_identities.csv", help="Path to user_identities.csv")
    parser.add_argument("--audit_log", default="dataset/user_audit_log.csv", help="Path to user_audit_log.csv")
    parser.add_argument("--evidence", default="dataset/evidence_files.csv", help="Path to evidence_files.csv")
    parser.add_argument("--dataset_dir", default="dataset", help="Directory containing dataset")
    return parser.parse_args()

def run_audit(input_path: str,
              output_path: str,
              identities_path: str = "dataset/user_identities.csv",
              audit_log_path: str = "dataset/user_audit_log.csv",
              evidence_path: str = "dataset/evidence_files.csv",
              dataset_dir: str = "dataset"):
    print("=" * 60)
    print(" Northstar Shop: Ghost Data Still Exists Deletion Audit Agent")
    print("=" * 60)
    print(f"Loading input requests from: {input_path}")
    
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    req_df = pd.read_csv(input_path)
    total_requests = len(req_df)
    print(f"Total requests to audit: {total_requests}")

    print("Initializing multi-modal evidence parser and identity resolver...")
    auditor = DeletionAuditor(
        identities_path=identities_path,
        audit_log_path=audit_log_path,
        evidence_manifest_path=evidence_path,
        dataset_dir=dataset_dir
    )

    results = []
    print("Auditing requests across systems and evidence records...")
    for idx, row in req_df.iterrows():
        case_id = row["case_id"]
        status, steps = auditor.audit_request(row.to_dict())
        
        # Verify schema guarantees:
        # steps_json must be valid JSON string
        steps_json = json.dumps(steps)
        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": steps_json
        })

        if (idx + 1) % 50 == 0 or (idx + 1) == total_requests:
            print(f"  Processed {idx + 1}/{total_requests} requests ({(idx + 1)/total_requests*100:.1f}%)")

    out_df = pd.DataFrame(results)

    # Sort strictly by case_id ascending (numeric sort if case_XX)
    try:
        out_df["_sort_key"] = out_df["case_id"].apply(
            lambda x: int(x.split("_")[1]) if "_" in str(x) and x.split("_")[1].isdigit() else str(x)
        )
        out_df = out_df.sort_values(by="_sort_key").drop(columns=["_sort_key"]).reset_index(drop=True)
    except Exception:
        out_df = out_df.sort_values(by="case_id").reset_index(drop=True)

    print(f"Saving audit predictions to: {output_path}")
    out_df.to_csv(output_path, index=False, columns=["case_id", "deletion_status", "steps_json"])
    print(f"Successfully generated {output_path} with {len(out_df)} audited rows.")
    print("=" * 60)

def main():
    args = parse_args()
    run_audit(
        input_path=args.input,
        output_path=args.output,
        identities_path=args.identities,
        audit_log_path=args.audit_log,
        evidence_path=args.evidence,
        dataset_dir=args.dataset_dir
    )

if __name__ == "__main__":
    main()
