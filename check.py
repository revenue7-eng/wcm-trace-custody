"""Relying-party check: does a TRACE record's authorized-intent reference to a WCM
custody decision hold up? Independent of WCM: only rfc8785 and cryptography.

Section 3.1.2 rule 3: whatever this finds, the record itself still verifies. This
answers a different question, what the referenced authorization establishes.

The record's iat is when the record was issued and is never taken as the execution
time. An event time is an explicit input from the relying party, evidenced
separately; without one the verdict is authorized-execution-time-unestablished.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DECISION_KIND = "wcm-renewal/v1"


def strip_none(obj):
    if isinstance(obj, dict):
        return {k: strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [strip_none(v) for v in obj]
    return obj


def canonical(obj) -> bytes:
    """WCM's canonical form: RFC 8785 with null members omitted at every depth."""
    return rfc8785.dumps(strip_none(obj))


def sha256(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def signature_valid(decision: dict) -> bool:
    payload = {k: v for k, v in decision.items() if k != "signature_b64url"}
    try:
        Ed25519PublicKey.from_public_bytes(_b64url(decision["public_key_b64url"])).verify(
            _b64url(decision["signature_b64url"]), canonical(payload))
    except (InvalidSignature, ValueError, KeyError):
        return False
    return True


def assess(record: dict, store: dict, pinned_keys: set[str], evidence: dict | None = None,
           *, event_time: str | None = None) -> dict:
    refs = [r for r in record.get("references", []) if r.get("rel") == "authorized-intent"]
    if len(refs) != 1:
        return {"verdict": "no-authorization-reference"}
    ref = refs[0]
    decision = store.get("decisions", {}).get(ref["id"])
    out = {"reference_resolves": decision is not None}
    if decision is None:
        return {**out, "verdict": "release-unconfirmed"}

    payload = {k: v for k, v in decision.items() if k != "signature_b64url"}
    out["digest_matches"] = sha256(decision) == ref.get("digest")
    out["id_matches"] = sha256(payload) == ref["id"]
    out["signature_valid"] = signature_valid(decision)
    out["authorizer_pinned"] = decision.get("public_key_b64url") in pinned_keys
    out["is_release"] = decision.get("kind") == DECISION_KIND and decision.get("renewed") is True
    out["weights_match"] = record.get("model", {}).get("weights_digest") == decision.get("weights_hash")
    if event_time is not None:
        t = datetime.fromisoformat(event_time.replace("Z", "+00:00")).astimezone(timezone.utc)
        out["within_window"] = _dt(decision["issued_at"]) <= t < _dt(decision["expires_at"])
    if evidence is not None and ref["id"] in evidence:
        out["evidence_matches"] = sha256(evidence[ref["id"]]) == decision.get("evidence_hash")

    if not (out["digest_matches"] and out["id_matches"] and out["signature_valid"]):
        verdict = "release-contradicted"
    elif not out["authorizer_pinned"]:
        verdict = "untrusted-authorizer"
    elif not out["is_release"]:
        verdict = "not-a-release"
    elif not out["weights_match"]:
        verdict = "different-weights"
    elif out.get("evidence_matches") is False:
        verdict = "different-evidence"
    elif event_time is None:
        verdict = "authorized-execution-time-unestablished"
    elif not out["within_window"]:
        verdict = "outside-window"
    else:
        verdict = "release-confirmed"
    return {**out, "verdict": verdict}
