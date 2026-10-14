"""
GenLayer Direct Mode tests (gltest `direct_vm` / `direct_deploy` fixtures).

STATUS: WRITTEN FROM DOCUMENTATION, NOT EXECUTED.
The author's sandbox could not install genlayer-test (package registry blocked by
egress policy), so these have never run. Fixture names and call shapes follow
docs.genlayer.com/api-references/genlayer-test (Direct Mode section). Expect to
adjust details (e.g. how expect_revert matches, how mock_llm treats
response_format="json") on first real run.

Direct Mode mocks the LLM with regex-matched canned responses. It does NOT run
validator consensus, so these tests do not demonstrate real consensus behaviour.

Run:  gltest tests/direct -v          (or: pytest tests/direct -v)
"""
import json

DIGEST = "ab" * 32
CONTRACT = "contracts/trustguard.py"


def _verdict(score, classification, confidence="HIGH"):
    return json.dumps({
        "classification": classification, "score": score, "confidence": confidence,
        "explanation": "Mocked evaluation.", "warning_indicators": [], "missing_information": [],
        "mitigations": ["pin exact version"], "evidence_considered": [0, 1],
        "reassessment_recommended": False,
    })


def _register(c, name="left-pad"):
    return c.register_artifact("NPM_PACKAGE", name, "npm", "https://registry.npmjs.org/left-pad", "1.3.0", DIGEST)


def _evidence(c, aid, n):
    return c.submit_evidence(aid, "SECURITY_ADVISORY", "https://example.org/a/1", "",
                             f"Observation number {n} about the release.", "2026-09-01", [])


def test_register_and_read(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    aid = _register(c)
    art = c.get_artifact(aid)
    assert art["current_classification"] == "UNASSESSED"
    assert art["owner"].lower() == art["submitter"].lower()
    assert c.get_artifact_count() == 1


def test_duplicate_registration_reverts(direct_vm, direct_deploy, direct_alice, direct_bob):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    _register(c)
    with direct_vm.expect_revert("TG_DUPLICATE"):
        direct_vm.sender = direct_bob
        _register(c)


def test_invalid_digest_and_version_revert(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("TG_INPUT"):
        c.register_artifact("NPM_PACKAGE", "x", "npm", "https://r.org/x", "1.0.0", "zz")
    with direct_vm.expect_revert("TG_INPUT"):
        c.register_artifact("NPM_PACKAGE", "x", "npm", "https://r.org/x", "latest", DIGEST)


def test_assess_with_mocked_llm_and_history(direct_vm, direct_deploy, direct_alice, direct_bob):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    aid = _register(c)
    _evidence(c, aid, 1)
    direct_vm.sender = direct_bob
    _evidence(c, aid, 2)

    direct_vm.mock_llm(r".*risk signal.*", _verdict(30, "MEDIUM_RISK"))
    c.assess_artifact(aid, "initial assessment")
    assert c.get_risk(aid)["classification"] == "MEDIUM_RISK"

    _evidence(c, aid, 3)
    direct_vm.mock_llm(r".*risk signal.*", _verdict(90, "CRITICAL_RISK"))
    c.assess_artifact(aid, "new advisory")
    hist = c.get_assessment_history(aid, 0, 10)["items"]
    assert [h["classification"] for h in hist] == ["MEDIUM_RISK", "CRITICAL_RISK"]
    assert hist[1]["previous_classification"] == "MEDIUM_RISK"


def test_no_evidence_is_insufficient_without_llm(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    aid = _register(c)
    c.assess_artifact(aid, "nothing submitted yet")
    assert c.get_risk(aid)["classification"] == "INSUFFICIENT_EVIDENCE"


def test_unauthorized_metadata_change_reverts(direct_vm, direct_deploy, direct_alice, direct_bob):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    aid = _register(c)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("TG_UNAUTHORIZED"):
        c.update_source_ref(aid, "https://evil.example/x")


def test_malformed_llm_output_reverts(direct_vm, direct_deploy, direct_alice, direct_bob):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    aid = _register(c)
    _evidence(c, aid, 1)
    direct_vm.sender = direct_bob
    _evidence(c, aid, 2)
    direct_vm.mock_llm(r".*risk signal.*", json.dumps({"classification": "SAFE", "score": 0}))
    with direct_vm.expect_revert():
        c.assess_artifact(aid, "should fail closed")
    assert c.get_artifact(aid)["assessment_count"] == 0


def test_pagination_bounds(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    aid = _register(c)
    assert c.get_assessment_history(aid, 0, 10)["items"] == []
    with direct_vm.expect_revert("TG_PAGE"):
        c.get_assessment_history(aid, 0, 0)
