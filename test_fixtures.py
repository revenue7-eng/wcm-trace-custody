"""Re-check the fixtures without importing WCM. Outcomes are recomputed from the
committed bytes and compared with expected.json, never read from it."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from agentrust_trace import verify_record
from datetime import timedelta

from check import _dt, assess, sha256

DIR = Path(__file__).resolve().parent / "fixtures"
EXPECTED = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
PINNED = set(EXPECTED["pinned_broker_keys"])
EVIDENCE = json.loads((DIR / "evidence.json").read_text(encoding="utf-8"))


def load(name):
    return json.loads((DIR / name).read_text(encoding="utf-8"))


def test_committed_records_are_exactly_the_declared_cases():
    assert {p.name for p in DIR.glob("0*.json")} == set(CASES)


@pytest.mark.parametrize("name", CASES)
def test_every_record_verifies_whatever_the_reference_says(name):
    verify_record(load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def confirmed(**kw):
    return assess(load("01-release-confirmed.json"), load("custody-store.json"), PINNED, EVIDENCE,
                  event_time=EXPECTED["cases"]["01-release-confirmed.json"]["event_time"], **kw)


@pytest.mark.parametrize("name", CASES)
def test_verdict_recomputed(name):
    case = EXPECTED["cases"][name]
    got = assess(load(name), load(case["store"]), PINNED, EVIDENCE, event_time=case["event_time"])
    assert got["verdict"] == case["verdict"], got


def test_without_an_event_time_the_execution_time_is_unestablished():
    got = assess(load("01-release-confirmed.json"), load("custody-store.json"), PINNED, EVIDENCE)
    assert got["verdict"] == "authorized-execution-time-unestablished"


def test_record_iat_is_never_the_event_time():
    """The records are issued after the window closed. Moving iat into the window,
    or anywhere, changes nothing: only the supplied event time is compared."""
    store = load("custody-store.json")
    decision = next(iter(store["decisions"].values()))
    rec = load("05-execution-after-window.json")
    for iat in (int(_dt(decision["issued_at"]).timestamp()) + 1, 0, rec["iat"]):
        r = {**rec, "iat": iat}
        assert assess(r, store, PINNED, EVIDENCE)["verdict"] == "authorized-execution-time-unestablished"
        got = assess(r, store, PINNED, EVIDENCE,
                     event_time=EXPECTED["cases"]["05-execution-after-window.json"]["event_time"])
        assert got["verdict"] == "outside-window"


def test_window_boundaries():
    store = load("custody-store.json")
    rid = load("01-release-confirmed.json")["references"][0]["id"]
    d = store["decisions"][rid]
    rec = load("01-release-confirmed.json")
    start, end = _dt(d["issued_at"]), _dt(d["expires_at"])
    def v(t):
        return assess(rec, store, PINNED, EVIDENCE, event_time=t.isoformat())["verdict"]
    assert v(start) == "release-confirmed"
    assert v(end - timedelta(microseconds=1)) == "release-confirmed"
    assert v(start - timedelta(microseconds=1)) == "outside-window"
    assert v(end) == "outside-window"


def test_confirmed_case_checks_every_join():
    got = confirmed()
    assert got == {"reference_resolves": True, "digest_matches": True, "id_matches": True,
                   "signature_valid": True, "authorizer_pinned": True, "is_release": True,
                   "weights_match": True, "within_window": True, "evidence_matches": True,
                   "verdict": "release-confirmed"}


def test_altered_store_breaks_both_digest_and_signature():
    got = assess(load("02-decision-altered-after-issue.json"), load("custody-store-altered.json"),
                 PINNED, EVIDENCE)
    assert got["digest_matches"] is False and got["signature_valid"] is False


def test_record_signature_covers_the_reference():
    r = copy.deepcopy(load("01-release-confirmed.json"))
    d = r["references"][0]["digest"]
    r["references"][0]["digest"] = d[:-1] + ("0" if d[-1] != "0" else "1")
    with pytest.raises(InvalidSignature):
        verify_record(r, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_swapped_evidence_is_caught():
    store = load("custody-store.json")
    rid = load("01-release-confirmed.json")["references"][0]["id"]
    other = next(v for k, v in EVIDENCE.items() if k != rid)
    got = assess(load("01-release-confirmed.json"), store, PINNED, {rid: other})
    assert got["verdict"] == "different-evidence"


def test_digest_needs_null_members_omitted():
    """WCM canonicalizes with nulls omitted. A verifier using plain RFC 8785 over the
    stored object, nulls included, gets a different digest when any member is null."""
    import hashlib, rfc8785
    decision = next(iter(load("custody-store.json")["decisions"].values()))
    if not any(v is None for v in decision.values()):
        pytest.skip("no null member in this decision")
    plain = "sha256:" + hashlib.sha256(rfc8785.dumps(decision)).hexdigest()
    assert plain != sha256(decision)
