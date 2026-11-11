"""Generate the synthetic Custodian-format fixtures: one release receipt built from
scratch with published test keys, receipts derived from it for the refusal cases,
and TRACE records that reference them.

Nothing here comes from a real deployment. The holder keys, quotes, measurements,
manifest identity and weights digest are made up and labelled synthetic. The keys
are derived from fixed bytes so that anyone can regenerate the same files; never
pin them anywhere real.

Because the holder keys are test keys, every derived receipt that needs a valid
holder signature is signed properly. A refusal is then caused by the rule under
test, not by a broken signature.

Needs agentrust-trace and cryptography. Does not import WCM or Custodian code.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import sign_record
from agentrust_trace.sign import key_to_jwk
from custodian_check import (AUDIT_VERSION, GRANT_VERSION, RECEIPT_VERSION, ascii_json,
                             authorization_id, grant_preimage, hex256, receipt_file_digest)

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures/custodian")
RESOLVER = "https://custody.example.org/receipts"
ISSUED = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

HOLDER_KEYS = {"model-builder-lab": Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128))),
               "deploying-customer-lab": Ed25519PrivateKey.from_private_bytes(bytes(range(128, 160)))}
ROGUE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
TRACE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))


def label_digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(("synthetic:" + label).encode()).hexdigest()


WEIGHTS = label_digest("weights")
MANIFEST = label_digest("manifest")
SERVING = label_digest("serving-image")
TRANSPORT = hashlib.sha256(b"synthetic:transport-key").hexdigest()
MAX_SECONDS = 60.0
T0 = datetime(2026, 1, 15, 10, 0, 0, 250000, tzinfo=timezone.utc)


def iso(t: datetime) -> str:
    return t.isoformat()


def dump(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def gate(name: str) -> dict:
    return {"name": name, "passed": True}


def make_row(holder: str, issued: datetime, *, seconds: float = MAX_SECONDS) -> dict:
    nonce = hashlib.sha256(("synthetic:nonce:" + holder).encode()).hexdigest()
    quote = b"synthetic quote, not hardware evidence: " + holder.encode()
    evidence = {"cpu": {"platform": "synthetic", "nonce_echo": nonce,
                        "transport_public_key": TRANSPORT,
                        "serving_image_measurement": SERVING,
                        "quote_b64": base64.b64encode(quote).decode()}}
    checks = [gate("synthetic_gate_a"), gate("synthetic_gate_b")]
    wcm_checks = [gate("synthetic_wcm_gate")]
    payload = {
        "version": GRANT_VERSION,
        "holder_id": holder,
        "manifest_id": MANIFEST,
        "weights_hash": WEIGHTS,
        "nonce": nonce,
        "transport_public_key": TRANSPORT,
        "serving_measurement": SERVING,
        "sealed_sha256": hashlib.sha256(("synthetic:sealed:" + holder).encode()).hexdigest(),
        "issued_at": iso(issued),
        "expires_at": iso(issued + timedelta(seconds=seconds)),
        "max_seconds": MAX_SECONDS,
        "audit": {"version": AUDIT_VERSION, "holder_policy": {"grant_max_seconds": MAX_SECONDS}},
    }
    row = {"holder_id": holder, "grant": {"payload": payload, "signature_hex": ""},
           "evidence": evidence, "checks": checks, "wcm_checks": wcm_checks}
    return sign_row(row)


def sign_row(row: dict, key: Ed25519PrivateKey | None = None) -> dict:
    """Restate the signed audit digests over the row's evidence and gates, then sign."""
    p = row["grant"]["payload"]
    cpu = row["evidence"]["cpu"]
    p["audit"]["evidence_sha256"] = hex256(ascii_json(row["evidence"]))
    p["audit"]["cpu_quote_sha256"] = hex256(base64.b64decode(cpu["quote_b64"]))
    p["audit"]["checks_sha256"] = hex256(ascii_json(row["checks"]))
    p["audit"]["wcm_checks_sha256"] = hex256(ascii_json(row["wcm_checks"]))
    key = key or HOLDER_KEYS[p["holder_id"]]
    row["grant"]["signature_hex"] = key.sign(grant_preimage(p)).hex()
    return row


def restate_interval(receipt: dict) -> dict:
    ps = [row["grant"]["payload"] for row in receipt["holders"]]
    start = max(datetime.fromisoformat(p["issued_at"]) for p in ps)
    end = min(datetime.fromisoformat(p["expires_at"]) for p in ps)
    receipt["utc_interval"] = {"not_before": iso(start), "not_after": iso(end),
                               "basis": "latest grant start to earliest grant expiry"}
    return receipt


def make_receipt(rows: list[dict]) -> dict:
    return restate_interval({
        "version": RECEIPT_VERSION,
        "holders": rows,
        "event_reference": {"seq": 1, "at": iso(T0 + timedelta(seconds=1.4)),
                            "source": "synthetic journal metadata, unsigned"},
        "scope": "Synthetic fixture. Holder authorization only; not proof of inference.",
    })


def pins() -> dict:
    return {"holders": {h: k.public_key().public_bytes_raw().hex() for h, k in HOLDER_KEYS.items()},
            "threshold": 2, "manifest_id": MANIFEST, "weights_hash": WEIGHTS,
            "max_seconds": MAX_SECONDS}


def base_receipt() -> dict:
    return make_receipt([make_row("model-builder-lab", T0),
                         make_row("deploying-customer-lab", T0 + timedelta(seconds=1.25))])


def derived_receipts(base: dict) -> dict[str, dict]:
    owner, customer = base["holders"]
    d = {}

    # After issue, someone stretches the customer grant's expiry in the stored copy.
    r = copy.deepcopy(base)
    r["holders"][1]["grant"]["payload"]["expires_at"] = iso(T0 + timedelta(days=30))
    d["receipt-grant-altered.json"] = r

    # One holder only: the 2-of-2 rule cannot be met.
    d["receipt-one-holder.json"] = restate_interval({**copy.deepcopy(base), "holders": [copy.deepcopy(owner)]})

    # The same holder twice: two signatures, one authorizer.
    d["receipt-duplicate-holder.json"] = restate_interval(
        {**copy.deepcopy(base), "holders": [copy.deepcopy(owner), copy.deepcopy(owner)]})

    # A grant from a holder no pin trusts, validly signed by that holder's own key.
    rogue = copy.deepcopy(owner)
    rogue["holder_id"] = rogue["grant"]["payload"]["holder_id"] = "unpinned-holder"
    d["receipt-unpinned-holder.json"] = {**copy.deepcopy(base),
                                         "holders": [sign_row(rogue, ROGUE_KEY), copy.deepcopy(customer)]}

    # Evidence carried in the receipt no longer matches what the holder signed.
    r = copy.deepcopy(base)
    r["holders"][0]["evidence"]["cpu"]["platform"] = "synthetic-altered"
    d["receipt-evidence-altered.json"] = r

    # Only unsigned journal metadata changes.
    r = copy.deepcopy(base)
    r["event_reference"]["seq"] = 2
    d["receipt-label-changed.json"] = r

    # Both grants signed for 660 s while their signed max_seconds stays 60.
    r = make_receipt([make_row("model-builder-lab", T0, seconds=660),
                      make_row("deploying-customer-lab", T0 + timedelta(seconds=1.25), seconds=660)])
    d["receipt-exceeds-signed-limit.json"] = r

    # Two distinct holders sign the same sealed ciphertext digest.
    r = copy.deepcopy(base)
    r["holders"][1]["grant"]["payload"]["sealed_sha256"] = owner["grant"]["payload"]["sealed_sha256"]
    sign_row(r["holders"][1])
    d["receipt-repeated-sealed.json"] = r

    # Two distinct holders answer the same challenge.
    r = copy.deepcopy(base)
    n = owner["grant"]["payload"]["nonce"]
    r["holders"][1]["grant"]["payload"]["nonce"] = n
    r["holders"][1]["evidence"]["cpu"]["nonce_echo"] = n
    sign_row(r["holders"][1])
    d["receipt-repeated-challenge.json"] = r

    # An unsigned member added to a grant envelope; the signatures still verify.
    r = copy.deepcopy(base)
    r["holders"][0]["grant"]["note"] = "unsigned"
    d["receipt-extra-envelope-member.json"] = r

    # No holders at all.
    d["receipt-empty-holders.json"] = {**copy.deepcopy(base), "holders": []}
    return d


def record(ref_id: str, digest: str, *, weights: str) -> dict:
    r = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": int(ISSUED.timestamp()),
        "subject": "spiffe://custody.example.org/deployment/synthetic",
        "model": {"provider": "example", "model_id": "synthetic-model", "weights_digest": weights},
        "runtime": {"platform": "software-only", "measurement": SERVING},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "confidential",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "origin": {"kind": "log-import", "producer": "synthetic-receipt-generator",
                   "source_event_id": "1", "ingested_at": int(ISSUED.timestamp())},
        "cnf": {"jwk": key_to_jwk(TRACE_KEY)},
        "references": [{"rel": "authorized-intent", "id": ref_id, "resolver": RESOLVER,
                        "digest": digest, "retention": "P1Y"}],
    }
    return sign_record(r, TRACE_KEY)


# name: (reference taken from, store returned, weights, verdict)
CASES = {
    "08-custodian-authorized.json": ("receipt.json", "receipt.json", WEIGHTS,
                                     "authorized-execution-time-unestablished"),
    "09-custodian-grant-altered-after-issue.json": ("receipt.json", "receipt-grant-altered.json", WEIGHTS,
                                                    "release-contradicted"),
    "10-custodian-missing-holder.json": ("receipt-one-holder.json", None, WEIGHTS, "quorum-not-met"),
    "11-custodian-duplicate-holder.json": ("receipt-duplicate-holder.json", None, WEIGHTS, "quorum-not-met"),
    "12-custodian-unpinned-holder.json": ("receipt-unpinned-holder.json", None, WEIGHTS, "untrusted-authorizer"),
    "13-custodian-different-weights.json": ("receipt.json", None, "sha256:" + "c" * 64, "different-weights"),
    "14-custodian-evidence-altered.json": ("receipt-evidence-altered.json", None, WEIGHTS, "different-evidence"),
    "15-custodian-label-changed.json": ("receipt-label-changed.json", None, WEIGHTS,
                                        "authorized-execution-time-unestablished"),
    "16-custodian-exceeds-signed-limit.json": ("receipt-exceeds-signed-limit.json", None, WEIGHTS,
                                               "exceeds-signed-limit"),
    "17-custodian-repeated-sealed.json": ("receipt-repeated-sealed.json", None, WEIGHTS, "repeated-grant-binding"),
    "18-custodian-repeated-challenge.json": ("receipt-repeated-challenge.json", None, WEIGHTS,
                                             "repeated-grant-binding"),
    "19-custodian-extra-envelope-member.json": ("receipt-extra-envelope-member.json", None, WEIGHTS,
                                                "malformed-receipt"),
    "20-custodian-empty-holders.json": ("receipt-empty-holders.json", None, WEIGHTS, "malformed-receipt"),
}


def ref_for(obj: dict, raw: bytes) -> tuple[str, str]:
    """Reference to a stored receipt. A receipt with no grants has no authorization
    identity; its record names the file digest as id so the resolver still answers."""
    digest = receipt_file_digest(raw)
    try:
        rid = authorization_id(obj) if obj.get("holders") else digest
    except (KeyError, TypeError):
        rid = digest
    return rid, digest


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    base = base_receipt()
    stores = {"receipt.json": dump(base)}
    for name, obj in derived_receipts(base).items():
        stores[name] = dump(obj)
    for name, raw in stores.items():
        (OUT / name).write_bytes(raw)
    (OUT / "trust-pins.json").write_bytes(dump(pins()))

    expected = {"trace_signer_jwk": key_to_jwk(TRACE_KEY), "resolver": RESOLVER,
                "expected_runtime": SERVING, "synthetic": True, "cases": {}}
    for name, (ref_src, store, weights, verdict) in CASES.items():
        rid, dig = ref_for(json.loads(stores[ref_src]), stores[ref_src])
        (OUT / name).write_bytes(dump(record(rid, dig, weights=weights)))
        expected["cases"][name] = {"store": store or ref_src, "verdict": verdict}
    (OUT / "expected.json").write_bytes(dump(expected))
    print("wrote", len(CASES), "records and", len(stores), "receipts to", OUT)


if __name__ == "__main__":
    main()
