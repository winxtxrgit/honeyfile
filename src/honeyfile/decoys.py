"""Decoy file templates: tempting names and inert, obviously-fake contents.

A decoy is bait. It must look worth stealing or encrypting, yet contain nothing
real: every value here is a documented example or a clearly fake placeholder, so
a decoy that leaks or is opened reveals an intruder without exposing a secret.
Each file also carries a per-deployment token (see ``plant``) so the same string
can be watched for in logs, email or egress traffic.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decoy:
    name: str  # file name as it will appear on disk
    body: str  # contents, with "{token}" replaced when planted


# AKIAIOSFODNN7EXAMPLE and its secret are AWS's own documented example key, which
# is inert; the rest are placeholder strings that match no real account.
_OFFICE = [
    Decoy(
        "Payroll_2026_Q4.csv",
        "employee_id,name,salary,bank_account\n"
        "# {token}\n"
        "1001,[REDACTED SAMPLE],[REDACTED SAMPLE],[REDACTED SAMPLE]\n",
    ),
    Decoy(
        "passwords.txt",
        "# personal password notes -- {token}\n"
        "mail: example / change-me-EXAMPLE\n"
        "vpn: example / change-me-EXAMPLE\n",
    ),
    Decoy(
        "Board_Meeting_Confidential.docx",
        "Confidential board minutes (decoy document). {token}\n",
    ),
]

_DEV = [
    Decoy(
        ".env",
        "# {token}\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "DATABASE_URL=postgres://user:EXAMPLE@db.internal.invalid:5432/app\n",
    ),
    Decoy(
        "id_rsa",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "{token}\n"
        "THIS IS A DECOY KEY. IT IS NOT A VALID PRIVATE KEY.\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
    ),
    Decoy(
        "deploy_keys.json",
        '{{\n  "comment": "{token}",\n  "token": "EXAMPLE-not-a-real-token"\n}}\n',
    ),
]

_DB = [
    Decoy(
        "backup.sql",
        "-- MySQL dump (decoy) -- {token}\n"
        "-- No real rows: this file exists only to detect tampering.\n",
    ),
    Decoy(
        "customers_export.csv",
        "id,email,card_last4\n# {token}\n1,[REDACTED SAMPLE],0000\n",
    ),
    Decoy(
        "dump.sql.gz",
        "decoy archive placeholder -- {token}\n",
    ),
]

PROFILES: dict[str, list[Decoy]] = {"office": _OFFICE, "dev": _DEV, "db": _DB}


def decoys_for(profile: str) -> list[Decoy]:
    try:
        return PROFILES[profile]
    except KeyError:
        raise ValueError(
            f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}"
        ) from None
