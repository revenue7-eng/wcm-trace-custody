"""Re-check the synthetic Custodian-format fixtures without importing WCM or
Custodian code. Verdicts are recomputed from the committed bytes and compared with
expected.json, never read from it.

All keys, quotes and digests here are synthetic (see generate_custodian.py).
"""

from __future__ import annotations

import copy
import json
from datetime import timedelta
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import generate_custodian as gen
from agentrust_trace import verify_record
from custodian_check import (GRANT_DOMAIN, ID_MAPPING, ascii_json, assess, authorization_id,
                             grant_envelope_digest, grant_preimage, hex256, receipt_file_digest)

DIR = Path(__file__).resolve().parent / "fixtures" / "custodian"
EXPECTED = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
PINS = json.loads((DIR / "trust-pins.json").read_text(encoding="utf-8"))
RAW = (DIR / "receipt.json").read_bytes()
BASE = json.loads(RAW)
RUNTIME = EXPECTED["expected_runtime"]
WINDOW_START = BASE["utc_interval"]["not_before"]
WINDOW_END = BASE["utc_interval"]["not_after"]


def load(name):
    return json.loads((DIR / name).read_text(encoding="utf-8"))


def store_for(record, name):
    return {record["references"][0]["id"]: (DIR / name).read_bytes()}


def base_case(**kw):
    rec = load("08-custodian-authorized.json")
    return assess(rec, store_for(rec, "receipt.json"), PINS, **kw)


def consistent(receipt, *, ref_id=None, pins=PINS, **kw):
    """Assess a record that points at exactly this receipt."""
    raw = ascii_json(receipt)
    rec = copy.deepcopy(load("08-custodian-authorized.json"))
    try:
        rid = ref_id or authorization_id(receipt)
    except (KeyError, TypeError, AttributeError):
        rid = receipt_file_digest(raw)
    rec["references"][0].update(id=rid, digest=receipt_file_digest(raw))
    return assess(rec, {rid: raw}, pins, **kw)


def resigned(receipt):
    for row in receipt["holders"]:
        gen.sign_row(row)
    return gen.restate_interval(receipt)


# Fixtures as committed

def test_fixtures_regenerate_byte_for_byte(tmp_path, monkeypatch):
    monkeypatch.setattr(gen, "OUT", tmp_path)
    gen.main()
    committed = {p.name: p.read_bytes() for p in DIR.glob("*.json")}
    regenerated = {p.name: p.read_bytes() for p in tmp_path.glob("*.json")}
    assert committed == regenerated


def test_fixtures_are_marked_synthetic():
    assert EXPECTED["synthetic"] is True
    for row in BASE["holders"]:
        assert row["evidence"]["cpu"]["platform"] == "synthetic"


def test_committed_records_are_exactly_the_declared_cases():
    assert {p.name for p in DIR.glob("[0-9]*.json")} == set(CASES)


@pytest.mark.parametrize("name", CASES)
def test_every_record_verifies_whatever_the_reference_says(name):
    verify_record(load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)


@pytest.mark.parametrize("name", CASES)
def test_records_are_labelled_as_imports(name):
    rec = load(name)
    assert rec["origin"]["kind"] == "log-import" and rec["runtime"]["platform"] == "software-only"


@pytest.mark.parametrize("name", CASES)
def test_verdict_recomputed(name):
    case = EXPECTED["cases"][name]
    rec = load(name)
    got = assess(rec, store_for(rec, case["store"]), PINS)
    assert got["verdict"] == case["verdict"], got


def test_record_signature_covers_the_reference():
    r = copy.deepcopy(load("08-custodian-authorized.json"))
    d = r["references"][0]["digest"]
    r["references"][0]["digest"] = d[:-1] + ("0" if d[-1] != "0" else "1")
    with pytest.raises(InvalidSignature):
        verify_record(r, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_unresolvable_reference():
    rec = load("08-custodian-authorized.json")
    assert assess(rec, {}, PINS)["verdict"] == "release-unconfirmed"


# The base authorization, every join

def test_base_receipt_confirms_with_a_supplied_event_time():
    got = base_case(event_time=WINDOW_START, expected_runtime=RUNTIME)
    flags = {k: v for k, v in got.items() if isinstance(v, bool)}
    assert got["verdict"] == "release-confirmed"
    assert flags == {"reference_resolves": True, "digest_matches": True, "id_matches": True,
                     "holders_pinned": True, "signatures_valid": True, "row_ids_consistent": True,
                     "duplicate_holder": False, "quorum_met": True, "bindings_unique": True,
                     "is_release": True, "durations_within_limits": True, "weights_match": True,
                     "manifest_match": True, "evidence_matches": True, "one_runtime": True,
                     "runtime_matches_pin": True, "windows_overlap": True,
                     "stated_interval_matches": True, "within_local_cap": True,
                     "within_window": True, "authorization_valid": True,
                     "local_policy_accepted": True}


def test_record_iat_is_not_used_as_execution_time():
    """The record was issued long after the window closed. Without a separately
    evidenced event time the check must not conclude the execution was authorized."""
    assert base_case()["verdict"] == "authorized-execution-time-unestablished"


def _shift(ts, us):
    from datetime import datetime
    return (datetime.fromisoformat(ts) + timedelta(microseconds=us)).isoformat()


@pytest.mark.parametrize("t,ok", [
    (WINDOW_START, True),                 # at the start: accepted
    (_shift(WINDOW_END, -1), True),       # one microsecond before expiry
    (_shift(WINDOW_START, -1), False),    # one microsecond before the start
    (WINDOW_END, False),                  # exact expiry: rejected
    (_shift(WINDOW_END, 600_000_000), False),
])
def test_window_boundaries_at_full_precision(t, ok):
    assert base_case(event_time=t)["verdict"] == ("release-confirmed" if ok else "outside-window")


def test_a_time_truncated_to_the_second_is_not_an_execution_time():
    """The window opens at a fractional second. A timestamp cut to whole seconds
    lands before it and is refused; it cannot stand in for execution time."""
    truncated = WINDOW_START.split(".")[0] + "+00:00"
    assert base_case(event_time=truncated)["verdict"] == "outside-window"


def test_unsigned_journal_time_is_never_read():
    assert BASE["event_reference"]["source"].endswith("unsigned")
    assert base_case()["verdict"] == "authorized-execution-time-unestablished"


def test_wrong_expected_runtime():
    got = base_case(event_time=WINDOW_START, expected_runtime="sha256:" + "d" * 64)
    assert got["verdict"] == "different-runtime"


def test_different_manifest_pin():
    rec = load("08-custodian-authorized.json")
    pins = {**PINS, "manifest_id": "sha256:" + "d" * 64}
    assert assess(rec, store_for(rec, "receipt.json"), pins)["verdict"] == "different-manifest"


def test_stated_interval_extended_is_refused():
    r = copy.deepcopy(BASE)
    r["utc_interval"]["not_after"] = _shift(WINDOW_END, 3_600_000_000)
    got = consistent(r)
    assert got["stated_interval_matches"] is False and got["verdict"] == "release-contradicted"


def test_altered_grant_breaks_digest_and_signature():
    rec = load("09-custodian-grant-altered-after-issue.json")
    got = assess(rec, store_for(rec, "receipt-grant-altered.json"), PINS)
    assert got["digest_matches"] is False and got["signatures_valid"] is False


def test_wrong_pinned_key_for_a_known_holder():
    """Both keys valid and distinct, but swapped between the holders."""
    h = PINS["holders"]
    swapped = _pins(holders={"model-builder-lab": h["deploying-customer-lab"], "deploying-customer-lab": h["model-builder-lab"]})
    got = consistent(BASE, pins=swapped)
    assert got["signatures_valid"] is False and got["verdict"] == "release-contradicted"


def test_altered_grant_with_a_record_that_points_at_it():
    """Digest and id are restated over the altered file, so only the holder
    signature can refuse it."""
    r = copy.deepcopy(BASE)
    r["holders"][1]["grant"]["payload"]["sealed_sha256"] = "f" * 64
    got = consistent(r)
    assert got["digest_matches"] and got["id_matches"]
    assert got["signatures_valid"] is False and got["verdict"] == "release-contradicted"


def test_reference_id_that_is_not_the_authorization():
    got = consistent(BASE, ref_id="sha256:" + "a" * 64)
    assert got["digest_matches"] is True and got["id_matches"] is False
    assert got["verdict"] == "release-contradicted"


def test_row_label_disagrees_with_signed_holder():
    r = copy.deepcopy(BASE)
    a, b = r["holders"]
    a["holder_id"], b["holder_id"] = b["holder_id"], a["holder_id"]
    got = consistent(r)
    assert got["row_ids_consistent"] is False and got["verdict"] == "release-contradicted"


def test_repeated_holder_with_quorum_otherwise_met():
    r = copy.deepcopy(BASE)
    r["holders"].append(copy.deepcopy(r["holders"][0]))
    got = consistent(r)
    assert got["duplicate_holder"] is True and got["verdict"] == "quorum-not-met"


def test_failed_gate():
    r = copy.deepcopy(BASE)
    r["holders"][1]["checks"][0]["passed"] = False
    assert consistent(resigned(r))["verdict"] == "not-a-release"


def test_windows_do_not_overlap():
    r = copy.deepcopy(BASE)
    p = r["holders"][1]["grant"]["payload"]
    p["issued_at"] = _shift(p["issued_at"], 120_000_000)
    p["expires_at"] = _shift(p["expires_at"], 120_000_000)
    assert consistent(resigned(r))["verdict"] == "no-overlap"


def test_two_runtimes():
    r = copy.deepcopy(BASE)
    row = r["holders"][1]
    row["grant"]["payload"]["serving_measurement"] = "sha256:" + "d" * 64
    row["evidence"]["cpu"]["serving_image_measurement"] = "sha256:" + "d" * 64
    assert consistent(resigned(r))["verdict"] == "different-runtime"


def test_quote_bytes_differ_from_signed_quote_digest():
    """Evidence digest restated over the new quote, quote digest left as signed:
    only the separate quote digest catches the swap."""
    r = copy.deepcopy(BASE)
    row = r["holders"][1]
    old = row["grant"]["payload"]["audit"]["cpu_quote_sha256"]
    row["evidence"]["cpu"]["quote_b64"] = "AAAA"
    gen.sign_row(row)
    row["grant"]["payload"]["audit"]["cpu_quote_sha256"] = old
    row["grant"]["signature_hex"] = gen.HOLDER_KEYS["deploying-customer-lab"].sign(
        grant_preimage(row["grant"]["payload"])).hex()
    assert consistent(r)["verdict"] == "different-evidence"


def test_missing_quote():
    r = copy.deepcopy(BASE)
    r["holders"][1]["evidence"]["cpu"]["quote_b64"] = None
    row = r["holders"][1]
    p = row["grant"]["payload"]
    p["audit"]["evidence_sha256"] = hex256(ascii_json(row["evidence"]))
    row["grant"]["signature_hex"] = gen.HOLDER_KEYS["deploying-customer-lab"].sign(grant_preimage(p)).hex()
    assert consistent(r)["verdict"] == "different-evidence"


# 1. Signed duration limits

def _with_duration(seconds, *, holder_limit=gen.MAX_SECONDS, signed_max=gen.MAX_SECONDS):
    r = copy.deepcopy(BASE)
    for row in r["holders"]:
        p = row["grant"]["payload"]
        p["expires_at"] = _shift(p["issued_at"], int(seconds * 1_000_000))
        p["max_seconds"] = signed_max
        p["audit"]["holder_policy"] = {"grant_max_seconds": holder_limit}
    return resigned(r)


def test_duration_at_the_signed_limit_is_accepted():
    assert consistent(_with_duration(60))["verdict"] == "authorized-execution-time-unestablished"


def test_duration_over_the_signed_limit_by_a_millisecond():
    assert consistent(_with_duration(60.001))["verdict"] == "exceeds-signed-limit"


def test_duration_660_seconds_with_signed_max_60():
    got = consistent(_with_duration(660))
    assert got["durations_within_limits"] is False and got["verdict"] == "exceeds-signed-limit"


def test_holder_limit_is_stricter_than_the_grant():
    assert consistent(_with_duration(45, holder_limit=30))["verdict"] == "exceeds-signed-limit"


# Local execution cap: relying-party policy, kept apart from authorization validity

def test_valid_60_second_grant_under_a_30_second_local_cap():
    """The case from the review: the authorization is valid, the local cap is shorter."""
    rec = load("08-custodian-authorized.json")
    got = assess(rec, store_for(rec, "receipt.json"), _pins(max_seconds=30))
    assert got["durations_within_limits"] is True and got["signatures_valid"] is True
    assert got["within_local_cap"] is False
    assert got["authorization_valid"] is True and got["local_policy_accepted"] is False
    assert got["verdict"] == "exceeds-local-cap"


def test_local_cap_equal_to_the_grant_is_accepted():
    got = consistent(BASE, pins=_pins(max_seconds=60))
    assert got["within_local_cap"] is True and got["verdict"] == "authorized-execution-time-unestablished"


def test_signed_limit_violation_is_not_reported_as_local_cap():
    got = consistent(_with_duration(660), pins=_pins(max_seconds=30))
    assert got["verdict"] == "exceeds-signed-limit" and got["authorization_valid"] is False
    assert got["local_policy_accepted"] is False


def test_local_cap_longer_than_the_grant_does_not_extend_the_signed_limit():
    got = consistent(_with_duration(90), pins=_pins(max_seconds=3600))
    assert got["verdict"] == "exceeds-signed-limit"


def test_a_valid_authorization_under_the_cap_still_needs_an_event_time():
    got = consistent(BASE, pins=_pins(max_seconds=30), event_time=WINDOW_START)
    assert got["verdict"] == "exceeds-local-cap"


def test_grant_without_holder_policy_still_bounded_by_signed_max():
    r = _with_duration(90, signed_max=60)
    for row in r["holders"]:
        del row["grant"]["payload"]["audit"]["holder_policy"]
    assert consistent(resigned(r))["verdict"] == "exceeds-signed-limit"


@pytest.mark.parametrize("seconds", [0, -5])
def test_non_positive_grant_duration(seconds):
    """A grant that expires at or before it is issued is refused by the duration
    rule itself, before the window intersection is looked at."""
    r = copy.deepcopy(BASE)
    p = r["holders"][1]["grant"]["payload"]
    p["expires_at"] = _shift(p["issued_at"], seconds * 1_000_000)
    got = consistent(resigned(r))
    assert got["durations_within_limits"] is False and got["verdict"] == "exceeds-signed-limit"


@pytest.mark.parametrize("bad", [0, -1])
def test_non_positive_signed_max(bad):
    r = copy.deepcopy(BASE)
    for row in r["holders"]:
        row["grant"]["payload"]["max_seconds"] = bad
    assert consistent(resigned(r))["verdict"] == "exceeds-signed-limit"


@pytest.mark.parametrize("token", [b"Infinity", b"NaN"])
def test_non_finite_signed_max_in_the_file_is_refused(token):
    """Python's json accepts Infinity and NaN; the signed form cannot carry them."""
    raw = RAW.replace(b'"max_seconds": 60.0', b'"max_seconds": ' + token, 1)
    assert raw != RAW
    rec = copy.deepcopy(load("08-custodian-authorized.json"))
    rid = rec["references"][0]["id"]
    rec["references"][0]["digest"] = receipt_file_digest(raw)
    got = assess(rec, {rid: raw}, PINS)
    assert got["verdict"] in {"malformed-receipt", "release-contradicted"}, got


# 2. Holder trust configuration

def _pins(**changes):
    p = copy.deepcopy(PINS)
    p.update(changes)
    return p


@pytest.mark.parametrize("pins,reason", [
    (_pins(threshold=1), "threshold of one"),
    (_pins(threshold=3), "threshold above the number of holders"),
    (_pins(threshold=True), "boolean threshold"),
    (_pins(threshold=2.0), "float threshold"),
    (_pins(holders={}), "no holders"),
    (_pins(holders={"model-builder-lab": PINS["holders"]["model-builder-lab"],
                    "deploying-customer-lab": PINS["holders"]["model-builder-lab"]}), "two names, one key"),
    (_pins(holders={**PINS["holders"], "deploying-customer-lab": "00" * 31}), "short key"),
    (_pins(holders={**PINS["holders"], "deploying-customer-lab": "zz" * 32}), "not hex"),
    (_pins(max_seconds=0), "zero ceiling"),
    ({k: v for k, v in PINS.items() if k != "max_seconds"}, "no ceiling"),
    ({k: v for k, v in PINS.items() if k != "manifest_id"}, "no manifest pin"),
    ("not an object", "pins not an object"),
])
def test_invalid_trust_configuration_is_refused(pins, reason):
    rec = load("08-custodian-authorized.json")
    got = assess(rec, store_for(rec, "receipt.json"), pins)
    assert got["verdict"] == "invalid-trust-configuration", reason


def test_shared_key_under_two_names_cannot_authorize_alone():
    """The case from the review: one key signs as both holders."""
    key = gen.HOLDER_KEYS["model-builder-lab"]
    shared = _pins(holders={"model-builder-lab": PINS["holders"]["model-builder-lab"],
                            "deploying-customer-lab": PINS["holders"]["model-builder-lab"]})
    r = copy.deepcopy(BASE)
    for row in r["holders"]:
        row["grant"]["signature_hex"] = key.sign(grant_preimage(row["grant"]["payload"])).hex()
    assert consistent(r, pins=shared)["verdict"] == "invalid-trust-configuration"


# 3. Repeated sealed-grant bindings and challenges

def test_repeated_sealed_digest():
    rec = load("17-custodian-repeated-sealed.json")
    got = assess(rec, store_for(rec, "receipt-repeated-sealed.json"), PINS)
    assert got["signatures_valid"] is True and got["bindings_unique"] is False
    assert got["verdict"] == "repeated-grant-binding"


def test_repeated_challenge():
    rec = load("18-custodian-repeated-challenge.json")
    got = assess(rec, store_for(rec, "receipt-repeated-challenge.json"), PINS)
    assert got["signatures_valid"] is True and got["evidence_matches"] is True
    assert got["bindings_unique"] is False and got["verdict"] == "repeated-grant-binding"


# 4. Malformed input ends in a refusal, never an exception

def _mutate(fn):
    r = copy.deepcopy(BASE)
    fn(r)
    return r


@pytest.mark.parametrize("receipt", [
    _mutate(lambda r: r.update(holders=[])),
    _mutate(lambda r: r.update(holders={"a": 1})),
    _mutate(lambda r: r.update(holders=None)),
    _mutate(lambda r: r["holders"].append("not a row")),
    _mutate(lambda r: r["holders"][0].pop("grant")),
    _mutate(lambda r: r["holders"][0]["grant"].pop("signature_hex")),
    _mutate(lambda r: r["holders"][0]["grant"].update(signature_hex="zz" * 64)),
    _mutate(lambda r: r["holders"][0]["grant"].update(signature_hex="00" * 10)),
    _mutate(lambda r: r["holders"][0]["grant"].update(payload=[])),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"].pop("sealed_sha256")),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"].update(nonce=7)),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"].update(max_seconds="60")),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"].update(max_seconds=True)),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"].update(audit=None)),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"]["audit"].update(holder_policy=[])),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"].update(issued_at="2026-01-15T10:00:00")),
    _mutate(lambda r: r["holders"][0]["grant"]["payload"].update(expires_at="yesterday")),
    _mutate(lambda r: r["holders"][0].update(evidence={})),
    _mutate(lambda r: r["holders"][0].update(checks="all good")),
    _mutate(lambda r: r.pop("utc_interval")),
], ids=lambda r: "case")
def test_malformed_receipt_is_a_refusal(receipt):
    got = consistent(receipt)
    assert got["verdict"] == "malformed-receipt", got


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"null", b'{"holders": []}'])
def test_malformed_bytes_are_a_refusal(raw):
    rec = copy.deepcopy(load("08-custodian-authorized.json"))
    rid = rec["references"][0]["id"]
    rec["references"][0]["digest"] = receipt_file_digest(raw)
    assert assess(rec, {rid: raw}, PINS)["verdict"] == "malformed-receipt"


def test_malformed_event_time_is_a_refusal():
    assert base_case(event_time="2026-01-15T10:00:01")["verdict"] == "malformed-receipt"


@pytest.mark.parametrize("record", [{}, {"references": None}, {"references": ["x"]},
                                    {"references": {"rel": "authorized-intent"}}, [], None, "x"])
def test_record_without_a_usable_reference(record):
    assert assess(record, {}, PINS)["verdict"] == "no-authorization-reference"


@pytest.mark.parametrize("ref_id", [["x"], {"a": 1}, None, 7, "", True])
def test_malformed_reference_id_is_refused_before_lookup(ref_id):
    rec = copy.deepcopy(load("08-custodian-authorized.json"))
    rec["references"][0]["id"] = ref_id
    got = assess(rec, store_for(load("08-custodian-authorized.json"), "receipt.json"), PINS)
    assert got["verdict"] == "malformed-reference"


@pytest.mark.parametrize("digest", [["x"], None, 0, ""])
def test_malformed_reference_digest_is_refused(digest):
    rec = copy.deepcopy(load("08-custodian-authorized.json"))
    rec["references"][0]["digest"] = digest
    got = assess(rec, store_for(rec, "receipt.json"), PINS)
    assert got["verdict"] == "malformed-reference"


@pytest.mark.parametrize("store", [None, [], "x"])
def test_store_that_is_not_a_mapping(store):
    rec = load("08-custodian-authorized.json")
    assert assess(rec, store, PINS)["verdict"] == "release-unconfirmed"


def test_stored_value_that_is_not_bytes():
    rec = load("08-custodian-authorized.json")
    got = assess(rec, {rec["references"][0]["id"]: BASE}, PINS)
    assert got["verdict"] == "release-unconfirmed"


@pytest.mark.parametrize("kw", [{"event_time": 1}, {"event_time": ["x"]},
                                {"expected_runtime": ["x"]}, {"expected_runtime": {}}])
def test_argument_of_the_wrong_type(kw):
    assert base_case(**kw)["verdict"] == "invalid-arguments"


@pytest.mark.parametrize("bad", [10 ** 400, 2 ** 53, -(2 ** 53), -(10 ** 400)])
def test_oversized_pinned_cap_is_an_invalid_configuration(bad):
    assert consistent(BASE, pins=_pins(max_seconds=bad))["verdict"] == "invalid-trust-configuration"


def test_largest_interoperable_integer_cap_is_accepted():
    got = consistent(BASE, pins=_pins(max_seconds=2 ** 53 - 1))
    assert got["verdict"] == "authorized-execution-time-unestablished"


@pytest.mark.parametrize("bad", [10 ** 400, 2 ** 53])
def test_oversized_threshold_is_an_invalid_configuration(bad):
    assert consistent(BASE, pins=_pins(threshold=bad))["verdict"] == "invalid-trust-configuration"


@pytest.mark.parametrize("member", ["max_seconds", "grant_max_seconds"])
def test_oversized_signed_limit_is_malformed(member):
    r = copy.deepcopy(BASE)
    for row in r["holders"]:
        p = row["grant"]["payload"]
        if member == "max_seconds":
            p["max_seconds"] = 10 ** 400
        else:
            p["audit"]["holder_policy"]["grant_max_seconds"] = 10 ** 400
    assert consistent(resigned(r))["verdict"] == "malformed-receipt"


# Exhaustive-ish: no input shape raises

FUZZ_VALUES = [None, True, False, 0, -1, 1, 2 ** 53, 10 ** 400, 1e308, -0.0, "", "x",
               "2026-01-15T10:00:00", "zz", [], [None], {}, {"a": {}}, [[{}]], "sha256:" + "0" * 64]


def _paths(obj, prefix=()):
    yield prefix
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, prefix + (i,))


def _set(obj, path, value):
    if not path:
        return value
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return obj


def _drop(obj, path):
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    del cur[path[-1]]
    return obj


def _fuzz_inputs(n, seed):
    import random
    rng = random.Random(seed)
    rec0 = load("08-custodian-authorized.json")
    targets = {"record": rec0, "pins": PINS, "receipt": BASE}
    paths = {name: list(_paths(obj)) for name, obj in targets.items()}
    for _ in range(n):
        objs = {k: copy.deepcopy(v) for k, v in targets.items()}
        for _ in range(rng.randint(1, 3)):
            name = rng.choice(list(objs))
            path = rng.choice(paths[name])
            try:
                if path and rng.random() < 0.25:
                    objs[name] = _drop(objs[name], path)
                else:
                    objs[name] = _set(objs[name], path, copy.deepcopy(rng.choice(FUZZ_VALUES)))
            except (KeyError, IndexError, TypeError):
                pass
        try:
            raw = ascii_json(objs["receipt"])
        except (ValueError, TypeError, OverflowError):
            raw = RAW
        if rng.random() < 0.1:
            raw = raw[: rng.randint(0, len(raw))]
        kw = {}
        if rng.random() < 0.3:
            kw["event_time"] = rng.choice([WINDOW_START, "x", 5, None])
        yield objs["record"], raw, objs["pins"], kw


@pytest.mark.parametrize("seed", range(8))
def test_no_input_raises(seed):
    rid = load("08-custodian-authorized.json")["references"][0]["id"]
    for record, raw, pins, kw in _fuzz_inputs(500, seed):
        ref = (record.get("references") or [{}])[0] if isinstance(record, dict) and \
            isinstance(record.get("references"), list) else {}
        key = ref.get("id") if isinstance(ref, dict) and isinstance(ref.get("id"), str) else rid
        got = assess(record, {key: raw}, pins, **kw)
        assert isinstance(got, dict) and isinstance(got.get("verdict"), str)


# 5. Authorization identity

def test_empty_holders_names_the_reason():
    rec = load("20-custodian-empty-holders.json")
    got = assess(rec, store_for(rec, "receipt-empty-holders.json"), PINS)
    assert got["verdict"] == "malformed-receipt" and "non-empty" in got["error"]


def test_extra_envelope_member_is_refused():
    rec = load("19-custodian-extra-envelope-member.json")
    got = assess(rec, store_for(rec, "receipt-extra-envelope-member.json"), PINS)
    assert got["verdict"] == "malformed-receipt"


def test_extra_envelope_member_does_not_change_the_identity():
    r = copy.deepcopy(BASE)
    r["holders"][0]["grant"]["note"] = "unsigned"
    assert authorization_id(r) == authorization_id(BASE)


def test_identity_ignores_holder_order_row_members_and_metadata():
    r = copy.deepcopy(BASE)
    r["holders"].reverse()
    r["holders"][0]["unsigned_row_note"] = "x"
    r["event_reference"]["seq"] = 99
    r["scope"] = "changed"
    assert authorization_id(r) == authorization_id(BASE)


def test_identity_changes_with_any_signed_byte():
    r = copy.deepcopy(BASE)
    r["holders"][0]["grant"]["signature_hex"] = "00" * 64
    assert authorization_id(r) != authorization_id(BASE)


def test_identity_encoding_is_pinned():
    """The exact preimage: mapping version plus the sorted envelope digests."""
    envelopes = sorted("sha256:" + hex256(ascii_json({"payload": row["grant"]["payload"],
                                                      "signature_hex": row["grant"]["signature_hex"]}))
                       for row in BASE["holders"])
    pre = ascii_json({"mapping": ID_MAPPING, "grant_envelopes": envelopes})
    assert pre.startswith(b'{"grant_envelopes":["sha256:')
    assert authorization_id(BASE) == "sha256:" + hex256(pre)
    assert ID_MAPPING == "wcm-trace-custody/authorization-id/v1"


def test_envelope_digest_is_over_exactly_payload_and_signature():
    row = BASE["holders"][0]
    assert grant_envelope_digest(row["grant"]) == "sha256:" + hex256(ascii_json(row["grant"]))


def test_reference_digest_is_the_exact_file():
    rec = load("08-custodian-authorized.json")
    assert rec["references"][0]["digest"] == receipt_file_digest(RAW)
    assert receipt_file_digest(RAW + b" ") != receipt_file_digest(RAW)


# Signature format

def _verify(preimage, row):
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(PINS["holders"][row["holder_id"]])).verify(
        bytes.fromhex(row["grant"]["signature_hex"]), preimage)


@pytest.mark.parametrize("row", BASE["holders"], ids=lambda r: r["holder_id"])
def test_signature_format(row):
    payload = row["grant"]["payload"]
    _verify(grant_preimage(payload), row)
    wrong = {
        "no domain prefix": ascii_json(payload),
        "non-compact JSON": GRANT_DOMAIN + json.dumps(payload, sort_keys=True, ensure_ascii=True).encode(),
        "RFC 8785": GRANT_DOMAIN + rfc8785.dumps(payload),
    }
    for label, preimage in wrong.items():
        if preimage == grant_preimage(payload):
            continue
        with pytest.raises(InvalidSignature):
            _verify(preimage, row)
