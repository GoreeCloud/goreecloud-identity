"""Minimized producer-authoritative evidence for GoreeCloud Identity.

The evidence model deliberately contains only opaque identifiers and bounded
Identity outcomes. Reusable credentials, raw profile attributes, and private
user content are not representable by this API.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Final

IDENTITY_EVIDENCE_CONTRACT: Final = "goreecloud.identity-evidence.v1"
IDENTITY_EVIDENCE_SCHEMA_PATH: Final = "contracts/identity.evidence.schema.json"
MESH_ENVELOPE_VERSION: Final = "goreecloud.evidence-envelope.v1"
IDENTITY_REPOSITORY: Final = "GoreeCloud/goreecloud-identity"

ASSERTION_AUTHORITIES: Final[dict[str, str]] = {
    "service-identity-verification": "identity",
    "authentication-result": "authentication",
    "authorization-decision": "authorization",
    "account-state": "accounts",
    "device-identity-state": "devices",
    "credential-state": "credentials",
    "session-state": "sessions",
    "delegated-authority-state": "delegated-authority",
}

ALLOWED_DATA_CLASSES: Final = frozenset({"public", "operational", "derived"})
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _utc(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso8601(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class IdentityEvidence:
    """A minimized Identity-domain assertion before Mesh transport."""

    assertion: str
    outcome: str
    subject_kind: str
    subject_id: str
    source: str
    observed_at: datetime
    valid_until: datetime
    subject_scope: str = ""
    data_class: str = "derived"
    summary: str = ""
    payload_digest: str = ""

    def __post_init__(self) -> None:
        authority = ASSERTION_AUTHORITIES.get(self.assertion)
        if authority is None:
            raise ValueError("unsupported GoreeCloud Identity assertion")
        if not self.outcome or len(self.outcome) > 128:
            raise ValueError("outcome is required and must be at most 128 characters")
        if not self.subject_kind or len(self.subject_kind) > 64:
            raise ValueError("subject_kind is required and must be at most 64 characters")
        if not self.subject_id or len(self.subject_id) > 256:
            raise ValueError("subject_id is required and must be at most 256 characters")
        if len(self.subject_scope) > 256:
            raise ValueError("subject_scope must be at most 256 characters")
        if not self.source or len(self.source) > 512:
            raise ValueError("source is required and must be at most 512 characters")
        if self.data_class not in ALLOWED_DATA_CLASSES:
            raise ValueError("unsupported evidence data class")
        if len(self.summary) > 512:
            raise ValueError("summary must be at most 512 characters")
        if self.payload_digest and not _DIGEST_RE.fullmatch(self.payload_digest):
            raise ValueError("payload_digest must use sha256:<64 lowercase hex characters>")

        observed_at = _utc(self.observed_at, "observed_at")
        valid_until = _utc(self.valid_until, "valid_until")
        if valid_until <= observed_at:
            raise ValueError("valid_until must be after observed_at")

        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(self, "valid_until", valid_until)

    @property
    def authority_domain(self) -> str:
        return ASSERTION_AUTHORITIES[self.assertion]

    def to_contract_record(self) -> dict[str, object]:
        subject: dict[str, str] = {
            "kind": self.subject_kind,
            "id": self.subject_id,
        }
        if self.subject_scope:
            subject["scope"] = self.subject_scope

        record: dict[str, object] = {
            "contract": IDENTITY_EVIDENCE_CONTRACT,
            "authority_domain": self.authority_domain,
            "assertion": self.assertion,
            "outcome": self.outcome,
            "subject": subject,
            "source": self.source,
            "observed_at": _iso8601(self.observed_at),
            "valid_until": _iso8601(self.valid_until),
            "data_class": self.data_class,
            "contains_user_content": False,
            "contains_secret_material": False,
            "contains_reusable_credentials": False,
            "contains_raw_profile_attributes": False,
        }
        if self.summary:
            record["summary"] = self.summary
        if self.payload_digest:
            record["payload_digest"] = self.payload_digest
        return record


def build_mesh_envelope(
    evidence: IdentityEvidence,
    *,
    envelope_id: str,
    producer_revision: str,
) -> dict[str, object]:
    """Build a v1 Mesh envelope without embedding credential or profile data."""

    if not envelope_id or len(envelope_id) > 128:
        raise ValueError("envelope_id is required and must be at most 128 characters")
    if not _REVISION_RE.fullmatch(producer_revision):
        raise ValueError("producer_revision must be an exact lowercase 40-character Git revision")

    subject: dict[str, str] = {
        "kind": evidence.subject_kind,
        "id": evidence.subject_id,
    }
    if evidence.subject_scope:
        subject["scope"] = evidence.subject_scope

    envelope: dict[str, object] = {
        "version": MESH_ENVELOPE_VERSION,
        "id": envelope_id,
        "producer": {
            "system": "goreecloud-identity",
            "repository": IDENTITY_REPOSITORY,
            "revision": producer_revision,
            "contract": IDENTITY_EVIDENCE_SCHEMA_PATH,
        },
        "authority_domain": evidence.authority_domain,
        "subject": subject,
        "assertion": evidence.assertion,
        "outcome": evidence.outcome,
        "source": evidence.source,
        "observed_at": _iso8601(evidence.observed_at),
        "valid_until": _iso8601(evidence.valid_until),
        "data_class": evidence.data_class,
        "contains_user_content": False,
        "contains_secret_material": False,
    }
    if evidence.summary:
        envelope["summary"] = evidence.summary
    if evidence.payload_digest:
        envelope["payload_digest"] = evidence.payload_digest
    return envelope
