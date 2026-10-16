"""
LIVE / STUDIO integration tests - REQUIRE a running GenLayer network and REAL LLM validators.

STATUS: SKELETON, NOT EXECUTED. Requires Docker + GenLayer Studio (localnet/studionet)
or a testnet account, and exercises real validator consensus on real LLM output.
These are the only tests that can show how the prompt behaves with a real model
(e.g. whether it resists injection, whether independent validators agree within
the tolerance). Mocked tests cannot show that.

Run:  gltest tests/integration --network localnet -v
Skipped unless TRUSTGUARD_LIVE=1.
"""
import os

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("TRUSTGUARD_LIVE") != "1", reason="set TRUSTGUARD_LIVE=1 and start a GenLayer network")

DIGEST = "ab" * 32


def test_real_consensus_assessment_roundtrip():
    from gltest import get_contract_factory
    from gltest.assertions import tx_execution_succeeded

    factory = get_contract_factory("TrustGuard")
    c = factory.deploy(args=[])
    r = c.register_artifact(args=["NPM_PACKAGE", "left-pad", "npm", "https://registry.npmjs.org/left-pad", "1.3.0", DIGEST]).transact()
    assert tx_execution_succeeded(r)
    aid = c.compute_artifact_id(args=["NPM_PACKAGE", "left-pad", "npm", "1.3.0", DIGEST]).call()
    for i, text in enumerate([
        "Install script downloads and executes a binary from an unrelated host.",
        "Maintainer account changed owner email two days before this release.",
    ]):
        r = c.submit_evidence(args=[aid, "BEHAVIOR_OBSERVATION", "", "", text + f" ({i})", "", []]).transact()
        assert tx_execution_succeeded(r)
    r = c.assess_artifact(args=[aid, "live consensus check"]).transact(consensus_max_rotations=3)
    assert tx_execution_succeeded(r)
    risk = c.get_risk(args=[aid]).call()
    assert risk["classification"] in {"MEDIUM_RISK", "HIGH_RISK", "CRITICAL_RISK", "INSUFFICIENT_EVIDENCE", "LOW_RISK"}
    # Real-model properties to inspect manually on first run: injection resistance, validator agreement rate.
