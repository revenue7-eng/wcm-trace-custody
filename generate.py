"""Generate fixtures: TRACE records that reference WCM custody decisions.

A WCM key broker re-runs its release gate and signs a keyless decision
(``wcm-renewal/v1``). A TRACE record for the execution that followed points at
that decision with ``rel: "authorized-intent"``. This script produces both with
the real libraries (WCM SDK and agentrust-trace), then writes ``expected.json``.
``test_fixtures.py`` re-checks everything without importing WCM.

Mock evidence only (WCM's SoftwareProvider): no hardware root of trust. The point
is the reference, not the attestation.

Not byte-for-byte reproducible: the WCM SDK draws fresh keys and nonces on every
run. A new run gives different bytes and the same verdicts.

Usage: python generate.py OUT_DIR MANIFEST, where MANIFEST is
python/examples/manifest.example.json from the WCM repository at tag v0.33.1.
Its SHA-256 is checked before use.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import sign_record
from agentrust_trace.sign import key_to_jwk
from wcm import WeightCustodyManifest
from wcm.kbs import KeyBrokerService
from wcm.providers import SoftwareProvider
from wcm.renewal import evidence_identity, manifest_identity
from wcm._seal import generate_transport_keypair

if len(sys.argv) != 3:
    sys.exit("usage: python generate.py OUT_DIR MANIFEST "
             "(python/examples/manifest.example.json from WCM at tag v0.33.1)")
OUT = Path(sys.argv[1])
WCM_MANIFEST = Path(sys.argv[2])
MANIFEST_SHA256 = "999e9cc807d0fa0d67b88971538a31ec7bad82654306433e458addc74ee203d9"
if hashlib.sha256(WCM_MANIFEST.read_bytes()).hexdigest() != MANIFEST_SHA256:
    sys.exit(f"{WCM_MANIFEST} is not the v0.33.1 manifest example (SHA-256 mismatch)")
RESOLVER = "https://custody.example.org/broker"
KEY = b"a-released-decryption-key-32bytes"
T0 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


def strip_none(obj):
    if isinstance(obj, dict):
        return {k: strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [strip_none(v) for v in obj]
    return obj


def jcs_sha256(obj) -> str:
    """Digest of the WCM canonical form: RFC 8785 with null members omitted."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(strip_none(obj))).hexdigest()


def write(name: str, obj) -> None:
    (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def waive(manifest: WeightCustodyManifest) -> WeightCustodyManifest:
    """Mock evidence cannot meet verification requirements; say so in the manifest."""
    policy = manifest.release_policy
    update = {"require_evidence_verification": False}
    if policy.required_gpu_measurement is not None:
        update["required_gpu_measurement"] = policy.required_gpu_measurement.model_copy(
            update={"require_cc_mode": False})
    return manifest.model_copy(update={"release_policy": policy.model_copy(update=update)})


class Clock:
    def __init__(self, t): self.t = t
    def __call__(self): return self.t


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = waive(WeightCustodyManifest.model_validate(
        json.loads(WCM_MANIFEST.read_text(encoding="utf-8"))))
    broker_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    rogue_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    trace_key = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    _, transport_pub = generate_transport_keypair()

    def broker(signing_key):
        return KeyBrokerService(
            {manifest.weights_hash: KEY}, now=Clock(T0),
            renewal_decision_ttl_seconds=300, renewal_signing_key=signing_key,
            trusted_manifest_identities={manifest_identity(manifest)})

    rp = manifest.release_policy
    current = next(m.measurement for m in rp.required_serving_image.accepted_measurements
                   if m.status.value == "current")
    rim = rp.required_gpu_measurement.rim_pin if rp.required_gpu_measurement else None

    def decide(kbs, serving):
        ev = SoftwareProvider().produce(kbs.issue_challenge(), serving_image_measurement=serving,
                                        gpu_measurement=rim, transport_public_key=transport_pub)
        d = kbs.verify_for_renewal(manifest, ev)
        # JSON round trip: the stored decision is JSON, so digest what is stored.
        return json.loads(json.dumps(asdict(d))), d.renewal_id, ev.model_dump(mode="json", exclude_none=True)

    granted, granted_id, granted_ev = decide(broker(broker_key), current)
    denied, denied_id, denied_ev = decide(broker(broker_key), "sha256:" + "ab" * 32)
    rogue, rogue_id, rogue_ev = decide(broker(rogue_key), current)
    assert granted["renewed"] and not denied["renewed"] and rogue["renewed"]

    store = {granted_id: granted, denied_id: denied, rogue_id: rogue}
    altered = copy.deepcopy(store)
    # After issue, someone stretches the window in the stored copy.
    altered[granted_id]["expires_at"] = (T0 + timedelta(days=30)).isoformat().replace("+00:00", "Z")
    write("custody-store.json", {"resolver": RESOLVER, "decisions": store})
    write("custody-store-altered.json", {"resolver": RESOLVER, "decisions": altered})
    write("evidence.json", {granted_id: granted_ev, denied_id: denied_ev, rogue_id: rogue_ev})

    def record(ref_id, digest, *, iat, weights):
        r = {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": int(iat.timestamp()),
            "subject": "spiffe://trust.example.org/workload/inference",
            "model": {"provider": "example", "model_id": "example-model", "weights_digest": weights},
            "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
            "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
            "data_class": "confidential",
            "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
            "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
            "cnf": {"jwk": key_to_jwk(trace_key)},
            "references": [{"rel": "authorized-intent", "id": ref_id, "resolver": RESOLVER,
                            "digest": digest, "retention": "P1Y"}],
        }
        return sign_record(r, trace_key)

    inside = T0 + timedelta(seconds=60)
    after = T0 + timedelta(seconds=900)
    w = str(manifest.weights_hash)
    other_w = "sha256:" + "c" * 64
    cases = {
        "01-release-confirmed.json": (granted_id, jcs_sha256(granted), inside, w, "custody-store.json"),
        "02-decision-altered-after-issue.json": (granted_id, jcs_sha256(granted), inside, w, "custody-store-altered.json"),
        "03-decision-is-a-denial.json": (denied_id, jcs_sha256(denied), inside, w, "custody-store.json"),
        "04-reference-unresolvable.json": ("sha256:" + "f" * 64, "sha256:" + "f" * 64, inside, w, "custody-store.json"),
        "05-execution-after-window.json": (granted_id, jcs_sha256(granted), after, w, "custody-store.json"),
        "06-different-weights.json": (granted_id, jcs_sha256(granted), inside, other_w, "custody-store.json"),
        "07-unpinned-authorizer.json": (rogue_id, jcs_sha256(rogue), inside, w, "custody-store.json"),
    }
    expected = {"trace_signer_jwk": key_to_jwk(trace_key),
                "pinned_broker_keys": [granted["public_key_b64url"]],
                "resolver": RESOLVER, "cases": {}}
    verdicts = {"01": "release-confirmed", "02": "release-contradicted", "03": "not-a-release",
                "04": "release-unconfirmed", "05": "outside-window", "06": "different-weights",
                "07": "untrusted-authorizer"}
    issued = T0 + timedelta(days=1)   # records issued after the fact; iat is never the event time
    for name, (rid, dig, event, weights, st) in cases.items():
        write(name, record(rid, dig, iat=issued, weights=weights))
        expected["cases"][name] = {"store": st, "verdict": verdicts[name[:2]],
                                   "event_time": event.isoformat()}
    write("expected.json", expected)
    print("wrote", len(cases), "records to", OUT)


if __name__ == "__main__":
    main()
