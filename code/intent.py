"""
Intent classification for user privacy requests.
Distinguishes between valid deletion requests and other privacy requests
(e.g., access, download, rectification, marketing opt-out, login support)
which must be classified as NOT_APPLICABLE.
"""

import re

NON_DELETION_PATTERNS = [
    r"leave the account active",
    r"not asking for deletion",
    r"keep the account as it is",
    r"do not close (?:or delete )?(?:the|my) account",
    r"don't close (?:or delete )?(?:the|my) account",
    r"do not delete (?:the|my) account",
    r"article 15",
    r"request a copy of (?:all )?my (?:personal )?data",
    r"without removing any of my records",
    r"marketing lists only",
    r"not a request to erase",
    r"leave my profile .* in place",
    r"continue using the service",
    r"don't delete or change anything",
    r"portable format",
    r"download my account information",
    r"(?:send|need|provide|give)\s+me\s+a\s+copy",
    r"what personal information you hold",
    r"resetting the login",
    r"stop the promotional emails",
    r"change the email address used",
    r"replace it with the new one",
    r"surname is misspelled",
]

NON_DELETION_REGEX = re.compile("|".join(NON_DELETION_PATTERNS), re.IGNORECASE)

def is_deletion_request(text: str) -> bool:
    """
    Returns True if the request is a legitimate account/personal data deletion request.
    Returns False if it is an access request, rectification, marketing opt-out, or support request.
    """
    if not text or not text.strip():
        return False
    
    # Check for explicit non-deletion intent
    if NON_DELETION_REGEX.search(text):
        return False
        
    return True
