"""Relying-party check: does a TRACE record's authorized-intent reference to a
Custodian-format release receipt hold up? Independent of WCM and of Custodian's
own verifier: only the standard library and cryptography.

The rules follow the receipt format custodian-release-receipt-v1 with
custodian-release-grant-v1 grants. Holder keys come from the relying party's
trust pins, never from the receipt. Section 3.1.2 rule 3 of TRACE still holds:
whatever this finds, the record itself verifies or not on its own signature.

Two questions are kept apart. Authorization: are the grants valid, within their
own signed limits? Local policy: does the relying party accept an authorization
of that length under its own execution cap (pinned max_seconds)? A shorter local
cap does not make a valid grant or its signed lifetime invalid; it ends in its own
result, exceeds-local-cap.

What this does not do: reappraise the hardware quote, recompute the manifest
identity from an embedded manifest (that needs WCM), verify the manifest's
attestation cadence, or establish when the execution happened. An event time is an explicit input from the relying party,
evidenced separately. The record's iat is when the record was issued and is never
used as the execution time here.

Every input problem ends in a verdict, never in an exception.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECEIPT_VERSION = "custodian-release-receipt-v1"
GRANT_VERSION = "custodian-release-grant-v1"
AUDIT_VERSION = "custodian-holder-audit-v1"
GRANT_DOMAIN = b"custodian:release-grant:v1\x00"
ID_MAPPING = "wcm-trace-custody/authorization-id/v1"
ENVELOPE_MEMBERS = frozenset({"payload", "signature_hex"})
PAYLOAD_STRINGS = ("version", "holder_id", "manifest_id", "weights_hash", "nonce",
                   "transport_public_key", "serving_measurement", "sealed_sha256",
                   "issued_at", "expires_at")
TOLERANCE = 1e-6
MAX_SAFE_INTEGER = 2 ** 53 - 1
AUTHORIZATION_FAILURES = frozenset({
    "release-contradicted", "untrusted-authorizer", "quorum-not-met", "repeated-grant-binding",
    "not-a-release", "exceeds-signed-limit", "different-weights", "different-manifest",
    "different-evidence", "different-runtime", "no-overlap"})


class Malformed(ValueError):
    """The input does not have the structure the rules are defined over."""


def ascii_json(obj) -> bytes:
    """Sorted keys, compact, ASCII, nulls retained."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def hex256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def grant_preimage(payload: dict) -> bytes:
    return GRANT_DOMAIN + ascii_json(payload)


def grant_envelope_digest(grant: dict) -> str:
    """Digest of one signed grant: exactly {payload, signature_hex}, no prefix.
    Any other member is ignored here and refused by assess()."""
    return "sha256:" + hex256(ascii_json({"payload": grant["payload"],
                                          "signature_hex": grant["signature_hex"]}))


def authorization_id(receipt: dict) -> str:
    """Identity of the authorization, mapping version ID_MAPPING.

    SHA-256 over {"mapping": ID_MAPPING, "grant_envelopes": [...]}, where the list
    is the sorted envelope digests. Holder order, unsigned row members and unsigned
    receipt metadata do not enter it.
    """
    envelopes = sorted(grant_envelope_digest(h["grant"]) for h in receipt["holders"])
    return "sha256:" + hex256(ascii_json({"mapping": ID_MAPPING, "grant_envelopes": envelopes}))


def receipt_file_digest(raw: bytes) -> str:
    """Digest of the receipt as stored: SHA-256 of the exact file bytes."""
    return "sha256:" + hex256(raw)


def _ts(s) -> datetime:
    if not isinstance(s, str):
        raise Malformed("timestamp is not a string")
    try:
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Malformed("unparseable timestamp") from exc
    if t.tzinfo is None:
        raise Malformed("timestamp without a time zone")
    return t.astimezone(timezone.utc)


def _number(v) -> bool:
    """An interoperable JSON number (I-JSON, RFC 7493 section 2.2): a finite double,
    or an integer in [-(2**53 - 1), 2**53 - 1]. No integer is converted to float."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return -MAX_SAFE_INTEGER <= v <= MAX_SAFE_INTEGER
    return isinstance(v, float) and math.isfinite(v)


def _positive(v) -> bool:
    return _number(v) and v > 0


def _ed25519_hex(v) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(v))
    except (TypeError, ValueError):
        return False
    return True


def validate_pins(pins) -> None:
    """The relying party's trust configuration: distinct valid holder keys, a quorum
    of at least two and at most the number of holders, the model scope and a
    positive local execution cap."""
    if not isinstance(pins, dict):
        raise Malformed("pins are not an object")
    holders, threshold = pins.get("holders"), pins.get("threshold")
    if not isinstance(holders, dict) or not holders:
        raise Malformed("no pinned holders")
    if not all(isinstance(h, str) and h and _ed25519_hex(k) for h, k in holders.items()):
        raise Malformed("a pinned holder key is not a valid Ed25519 public key")
    if len({bytes.fromhex(k) for k in holders.values()}) != len(holders):
        raise Malformed("two pinned holders share one key")
    if not isinstance(threshold, int) or not 2 <= threshold <= len(holders):
        raise Malformed("threshold must be an integer from 2 to the number of holders")
    for name in ("weights_hash", "manifest_id"):
        if not isinstance(pins.get(name), str) or not pins[name]:
            raise Malformed(f"{name} is not pinned")
    if not _positive(pins.get("max_seconds")):
        raise Malformed("max_seconds (local execution cap) must be a finite positive number")


def validate_receipt(receipt) -> None:
    """Structure only: types and members the rules read. Values are judged later."""
    if not isinstance(receipt, dict):
        raise Malformed("receipt is not an object")
    rows = receipt.get("holders")
    if not isinstance(rows, list) or not rows:
        raise Malformed("holders must be a non-empty list")
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("holder_id"), str):
            raise Malformed("holder row without a holder_id")
        grant = row.get("grant")
        if not isinstance(grant, dict) or set(grant) != ENVELOPE_MEMBERS:
            raise Malformed("grant envelope must hold exactly payload and signature_hex")
        sig = grant["signature_hex"]
        if not isinstance(sig, str) or len(sig) != 128:
            raise Malformed("signature_hex is not a 64-byte hex string")
        try:
            bytes.fromhex(sig)
        except ValueError as exc:
            raise Malformed("signature_hex is not hex") from exc
        p = grant["payload"]
        if not isinstance(p, dict):
            raise Malformed("grant payload is not an object")
        for name in PAYLOAD_STRINGS:
            if not isinstance(p.get(name), str):
                raise Malformed(f"grant payload member {name} is missing or not a string")
        if not _number(p.get("max_seconds")):
            raise Malformed("grant payload max_seconds is missing or not an interoperable number")
        audit = p.get("audit")
        if not isinstance(audit, dict):
            raise Malformed("grant payload audit is not an object")
        hp = audit.get("holder_policy")
        if hp is not None and not isinstance(hp, dict):
            raise Malformed("holder_policy is not an object")
        if hp and hp.get("grant_max_seconds") is not None and not _number(hp["grant_max_seconds"]):
            raise Malformed("grant_max_seconds is not an interoperable number")
        _ts(p["issued_at"]), _ts(p["expires_at"])
        ev = row.get("evidence")
        if not isinstance(ev, dict) or not isinstance(ev.get("cpu"), dict):
            raise Malformed("evidence without a cpu object")
        for name in ("checks", "wcm_checks"):
            gates = row.get(name)
            if not isinstance(gates, list) or not all(isinstance(c, dict) for c in gates):
                raise Malformed(f"{name} is not a list of objects")
    if not isinstance(receipt.get("utc_interval"), dict):
        raise Malformed("utc_interval is not an object")


def _signature_valid(grant: dict, key_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
            bytes.fromhex(grant["signature_hex"]), grant_preimage(grant["payload"]))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True


def _evidence_matches(row: dict) -> bool:
    """Signed audit digests against the evidence and gate results carried in the row."""
    try:
        payload, audit, evidence = row["grant"]["payload"], row["grant"]["payload"]["audit"], row["evidence"]
        cpu = evidence["cpu"]
        quote = cpu.get("quote_b64")
        if not quote:
            return False
        return (audit.get("version") == AUDIT_VERSION
                and audit.get("evidence_sha256") == hex256(ascii_json(evidence))
                and audit.get("cpu_quote_sha256") == hex256(base64.b64decode(quote, validate=True))
                and audit.get("checks_sha256") == hex256(ascii_json(row["checks"]))
                and audit.get("wcm_checks_sha256") == hex256(ascii_json(row["wcm_checks"]))
                and payload["nonce"] == cpu.get("nonce_echo")
                and payload["transport_public_key"] == cpu.get("transport_public_key")
                and payload["serving_measurement"] == cpu.get("serving_image_measurement"))
    except (KeyError, TypeError, ValueError, binascii.Error):
        return False


def _grant_seconds(payload: dict) -> float:
    return (_ts(payload["expires_at"]) - _ts(payload["issued_at"])).total_seconds()


def _within_signed_limits(payload: dict) -> bool:
    """Positive, and no longer than the grant's signed max_seconds and the holder's
    signed grant_max_seconds when present. Signed values only."""
    d = _grant_seconds(payload)
    limits = [payload["max_seconds"]]
    hp = payload["audit"].get("holder_policy") or {}
    if hp.get("grant_max_seconds") is not None:
        limits.append(hp["grant_max_seconds"])
    if not all(_positive(x) for x in limits):
        return False
    return d > 0 and d <= min(limits) + TOLERANCE


def _within_local_cap(payload: dict, pins: dict) -> bool:
    """Relying-party policy, not authorization validity."""
    return _grant_seconds(payload) <= pins["max_seconds"] + TOLERANCE


def assess(record: dict, store: dict[str, bytes], pins: dict, *,
           event_time: str | None = None, expected_runtime: str | None = None) -> dict:
    """store maps a reference id to the raw receipt bytes the resolver returned."""
    for name, value in (("event_time", event_time), ("expected_runtime", expected_runtime)):
        if value is not None and not isinstance(value, str):
            return {"verdict": "invalid-arguments", "error": f"{name} must be a string"}
    try:
        validate_pins(pins)
    except (Malformed, ValueError, TypeError, OverflowError) as exc:
        return {"verdict": "invalid-trust-configuration", "error": str(exc) or type(exc).__name__}
    refs = record.get("references") if isinstance(record, dict) else None
    refs = [r for r in refs if isinstance(r, dict) and r.get("rel") == "authorized-intent"] \
        if isinstance(refs, list) else []
    if len(refs) != 1:
        return {"verdict": "no-authorization-reference"}
    ref = refs[0]
    if not all(isinstance(ref.get(k), str) and ref[k] for k in ("id", "digest")):
        return {"verdict": "malformed-reference", "error": "reference id and digest must be non-empty strings"}
    if not isinstance(store, dict):
        return {"verdict": "release-unconfirmed"}
    raw = store.get(ref["id"])
    out = {"reference_resolves": isinstance(raw, (bytes, bytearray))}
    if not out["reference_resolves"]:
        return {**out, "verdict": "release-unconfirmed"}
    try:
        return _assess(record, ref, raw, pins, out, event_time, expected_runtime)
    except (Malformed, ValueError, KeyError, TypeError, AttributeError,
            OverflowError, RecursionError) as exc:
        return {**out, "verdict": "malformed-receipt", "error": str(exc) or type(exc).__name__}


def _assess(record, ref, raw, pins, out, event_time, expected_runtime) -> dict:
    out["digest_matches"] = receipt_file_digest(raw) == ref.get("digest")
    try:
        receipt = json.loads(raw)
    except ValueError as exc:
        raise Malformed("receipt is not JSON") from exc
    validate_receipt(receipt)
    rows = receipt["holders"]
    payloads = [row["grant"]["payload"] for row in rows]
    holder_ids = [p["holder_id"] for p in payloads]
    out["id_matches"] = authorization_id(receipt) == ref.get("id")

    pinned = pins["holders"]
    out["holders_pinned"] = all(h in pinned for h in holder_ids)
    out["signatures_valid"] = all(
        _signature_valid(row["grant"], pinned[p["holder_id"]])
        for row, p in zip(rows, payloads) if p["holder_id"] in pinned)
    out["row_ids_consistent"] = all(row["holder_id"] == p["holder_id"] for row, p in zip(rows, payloads))
    distinct = set(holder_ids)
    out["duplicate_holder"] = len(distinct) != len(holder_ids)
    out["quorum_met"] = (not out["duplicate_holder"]
                         and len(distinct & set(pinned)) >= pins["threshold"])
    sealed = [p["sealed_sha256"] for p in payloads]
    nonces = [p["nonce"] for p in payloads]
    out["bindings_unique"] = len(set(sealed)) == len(sealed) and len(set(nonces)) == len(nonces)
    out["is_release"] = (receipt.get("version") == RECEIPT_VERSION
                         and all(p["version"] == GRANT_VERSION for p in payloads)
                         and all(row["checks"] and row["wcm_checks"] for row in rows)
                         and all(c.get("passed") is True
                                 for row in rows for c in row["checks"] + row["wcm_checks"]))
    out["durations_within_limits"] = all(_within_signed_limits(p) for p in payloads)
    model = record.get("model")
    out["weights_match"] = all(p["weights_hash"] == pins["weights_hash"] for p in payloads) and \
        isinstance(model, dict) and model.get("weights_digest") == pins["weights_hash"]
    out["manifest_match"] = all(p["manifest_id"] == pins["manifest_id"] for p in payloads)
    out["evidence_matches"] = all(_evidence_matches(row) for row in rows)

    runtimes = {p["serving_measurement"] for p in payloads}
    transports = {p["transport_public_key"] for p in payloads}
    out["one_runtime"] = len(runtimes) == 1 and len(transports) == 1
    if expected_runtime is not None:
        out["runtime_matches_pin"] = runtimes == {expected_runtime}

    start = max(_ts(p["issued_at"]) for p in payloads)
    end = min(_ts(p["expires_at"]) for p in payloads)
    out["windows_overlap"] = start < end
    out["window"] = {"not_before": start.isoformat(), "not_after": end.isoformat()}
    stated = receipt["utc_interval"]
    try:
        out["stated_interval_matches"] = (_ts(stated.get("not_before")) == start
                                          and _ts(stated.get("not_after")) == end)
    except Malformed:
        out["stated_interval_matches"] = False
    out["within_local_cap"] = all(_within_local_cap(p, pins) for p in payloads)
    if event_time is not None:
        t = _ts(event_time)
        out["within_window"] = start <= t < end

    if not (out["digest_matches"] and out["id_matches"] and out["signatures_valid"]
            and out["row_ids_consistent"] and out["stated_interval_matches"]):
        verdict = "release-contradicted"
    elif not out["holders_pinned"]:
        verdict = "untrusted-authorizer"
    elif not out["quorum_met"]:
        verdict = "quorum-not-met"
    elif not out["bindings_unique"]:
        verdict = "repeated-grant-binding"
    elif not out["is_release"]:
        verdict = "not-a-release"
    elif not out["durations_within_limits"]:
        verdict = "exceeds-signed-limit"
    elif not out["weights_match"]:
        verdict = "different-weights"
    elif not out["manifest_match"]:
        verdict = "different-manifest"
    elif not out["evidence_matches"]:
        verdict = "different-evidence"
    elif not out["one_runtime"] or out.get("runtime_matches_pin") is False:
        verdict = "different-runtime"
    elif not out["windows_overlap"]:
        verdict = "no-overlap"
    elif not out["within_local_cap"]:
        verdict = "exceeds-local-cap"
    elif event_time is None:
        verdict = "authorized-execution-time-unestablished"
    elif not out["within_window"]:
        verdict = "outside-window"
    else:
        verdict = "release-confirmed"
    out["authorization_valid"] = verdict not in AUTHORIZATION_FAILURES
    out["local_policy_accepted"] = out["authorization_valid"] and out["within_local_cap"]
    return {**out, "verdict": verdict}
