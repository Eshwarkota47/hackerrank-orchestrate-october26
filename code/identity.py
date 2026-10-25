"""
Identity resolution module for Ghost Data Still Exists.
Resolves canonical user_id, current and historical emails, phone numbers,
full names, and email hashes across primary identities and audit logs.
"""

import csv
import os
from collections import defaultdict
from typing import Dict, Set, Optional, Any

class IdentityResolver:
    def __init__(self, identities_path: str = "dataset/user_identities.csv", audit_log_path: str = "dataset/user_audit_log.csv"):
        self.identities_path = identities_path
        self.audit_log_path = audit_log_path
        self.user_by_id: Dict[str, Dict[str, Any]] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.uid_to_emails: Dict[str, Set[str]] = defaultdict(set)
        self.hash_to_uid: Dict[str, str] = {}
        self.uid_to_hashes: Dict[str, Set[str]] = defaultdict(set)
        self.phone_to_uid: Dict[str, str] = {}
        self.name_to_uid: Dict[str, str] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.identities_path):
            with open(self.identities_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"]
                    self.user_by_id[uid] = row
                    email = row["email"].lower().strip()
                    self.email_to_uid[email] = uid
                    self.uid_to_emails[uid].add(email)
                    
                    ehash = row.get("email_hash")
                    if ehash:
                        ehash_clean = ehash.lower().strip()
                        self.hash_to_uid[ehash_clean] = uid
                        self.uid_to_hashes[uid].add(ehash_clean)
                        
                    phone = row.get("phone")
                    if phone:
                        self.phone_to_uid[phone.strip()] = uid
                    name = row.get("name")
                    if name:
                        self.name_to_uid[name.strip().lower()] = uid

        if os.path.exists(self.audit_log_path):
            with open(self.audit_log_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"]
                    field = row["field_name"]
                    old_val = row["old_value"]
                    if field == "email" and old_val:
                        old_email = old_val.lower().strip()
                        self.email_to_uid[old_email] = uid
                        self.uid_to_emails[uid].add(old_email)
                    elif field == "email_hash" and old_val:
                        old_hash = old_val.lower().strip()
                        self.hash_to_uid[old_hash] = uid
                        self.uid_to_hashes[uid].add(old_hash)

    def resolve(self, email: str) -> Dict[str, Any]:
        """
        Resolves a user profile given any known email (current or historical).
        """
        email_clean = email.lower().strip()
        uid = self.email_to_uid.get(email_clean)
        all_emails = self.uid_to_emails.get(uid, {email_clean}) if uid else {email_clean}
        all_hashes = self.uid_to_hashes.get(uid, set()) if uid else set()
        user_meta = self.user_by_id.get(uid, {}) if uid else {}

        return {
            "user_id": uid,
            "primary_email": user_meta.get("email", email_clean),
            "all_emails": all_emails,
            "all_hashes": all_hashes,
            "full_name": user_meta.get("name"),
            "phone": user_meta.get("phone"),
            "email_hash": user_meta.get("email_hash"),
        }
