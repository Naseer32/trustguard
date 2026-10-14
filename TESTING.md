## Bradbury Testnet — Live Contract Testing

TrustGuard was deployed and tested on the GenLayer Bradbury Testnet to verify
artifact registration, evidence submission, risk assessment, and on-chain
assessment retrieval.

### Deployment Information

- **Network:** GenLayer Bradbury Testnet
- **Contract:** `0x0ece7f3eaD96856477571a021c6939037c19Bd79`
- **Test Artifact ID:**
  `tg1-06f7ddf9b52208eb351d18e838ad9f72871993f1b276d774cde324afbecd63b8`

### Tests Performed

#### 1. Artifact Registration

Registered a test npm package with the following metadata:

- **Artifact type:** `NPM_PACKAGE`
- **Name:** `trustguard-test-lib`
- **Ecosystem:** `npm`
- **Version:** `1.0.0`
- **Source:** `https://github.com/Naseer32/trustguard`
- **Digest:** A test SHA-256 value consisting of 64 `a` characters.

**Result:** Passed. The contract returned an artifact ID, which was reused
in subsequent tests.

> The digest was a test value and was not verified against an actual package.

#### 2. Evidence Submission

Submitted two initial evidence records from the first wallet.

**Evidence A — Security Advisory**

- Type: `SECURITY_ADVISORY`
- Source: `https://example.org/advisory/1`
- Description: The advisory reported that the package installation script
  contacts an unknown host.
- Evidence sequence: `0`

**Evidence B — Maintainer Claim**

- Type: `MAINTAINER_CLAIM`
- Description: The maintainer claimed that the release was reproducible
  and clean.
- Evidence sequence: `1`

**Result:** Passed. Both records were retrieved through `get_evidence_page`.
The contract reported `total: 2`.

Both records were marked as unverified, and both came from the same reporter.

#### 3. Initial Risk Assessment

Called `assess_artifact` with the registered artifact ID and the reason
`first live test`.

**Transaction ID:**
`0x6c9cca83851601d98f1b656f8d361d2451b90eedcc3b9af56ef909fb6aeee68a`

**Result:** Finalized successfully.

The contract returned an assessment with the following results:

| Field | Result |
|---|---|
| Classification | `MEDIUM_RISK` |
| Score | `35` |
| Score applicable | `true` |
| Confidence | `LOW` |
| Evidence count used | `2` |
| Assessment sequence | `0` |
| Assessment method | `llm_consensus` |
| Prompt version | `tg-prompt-2` |
| Reassessment recommended | `true` |

The assessment identified the reported outbound network request as a
potential risk indicator. It also highlighted the limited evidence,
contradictory claims, and lack of verified artifact provenance.

**Important:** This was an evidence-based risk assessment, not proof that
the package contained malware. No package scan or execution was performed.

#### 4. Assessment Retrieval

Queried `get_current_assessment` and `get_risk`.

The current assessment was retrieved successfully, and the risk summary
returned:

```json
{
  "assessment_count": 1,
  "classification": "MEDIUM_RISK",
  "score": 35,
  "score_applicable": true
}

Result: Passed. The initial assessment was available through the contract's read methods.
5. Evidence From a Second Wallet
Switched to a second wallet and submitted another SECURITY_ADVISORY record.
Transaction ID: 0x0e30e67dcdc35ba16c3855302786c56d5fbe951fd795f9f99a557b80e4254af7
The evidence described an unverified report of an unexpected outbound network request during package installation.
Result: Passed. get_evidence_page returned three evidence records, with sequence numbers 0, 1, and 2.
The third record's reporter address differed from the first reporter's address, confirming that evidence could be submitted from two distinct wallets.
The new record was stored successfully, but its effect on a subsequent assessment was not confirmed.
6. Unsupported Evidence Type
Attempted to submit evidence using the type INDEPENDENT_SECURITY_REPORT.
Result: Failed. The transaction output reported Execution Error.
This attempt did not establish that the evidence was stored. A subsequent submission using the supported type SECURITY_ADVISORY succeeded.
7. Reassessment Attempt
After the third evidence record was stored, called assess_artifact again using the reason:
reassessment with independent reporter evidence
Transaction ID: 0xfcfe80dca5c048dbd6d9e9ad73e1b32e919c269e7fa9ce59df05058b46cebfb9
Result: Unsuccessful. The transaction initially showed undetermined consensus status and returned exit_code 1.
Subsequent calls to get_current_assessment, get_risk, and get_assessment_history showed that the original assessment remained unchanged:
Assessment count: 1
Classification: MEDIUM_RISK
Score: 35
Evidence count used: 2
Assessment sequence: 0
The assessment history contained only the initial assessment.
Status: Reassessment with additional evidence remains unresolved and requires further investigation.
Test Summary
Test
Result
Artifact registration
Passed
Initial evidence submission
Passed
Evidence retrieval
Passed
Initial risk assessment
Passed
Current assessment retrieval
Passed
Risk summary retrieval
Passed
Evidence submission from a second wallet
Passed
Rejection of unsupported evidence type
Execution error observed
Reassessment after adding new evidence
Unsuccessful; investigation required
Limitations
The test artifact used a placeholder digest rather than a verified package digest.
Evidence claims were not independently verified.
The assessment did not execute or scan the package.
The effect of a second reporter on risk classification and confidence has not yet been confirmed.
Successful reassessment after new evidence is still under investigation.
These tests demonstrate successful artifact registration, evidence storage, initial risk assessment, and retrieval of assessment results on the Bradbury Testnet. They do not establish that every TrustGuard feature has been fully validated.