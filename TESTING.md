# Bradbury Testnet: Live Contract Testing

TrustGuard was tested by hand on the GenLayer Bradbury testnet through the network explorer. This file records what was observed. It is not an exhaustive test and does not show that every feature works.

## Contracts tested

| Contract | Version | Result |
|---|---|---|
| `0x0ece7f3eaD96856477571a021c6939037c19Bd79` | Earlier version (leader calls the LLM once) | Registration, evidence and first assessment worked. Reassessment failed (see below). |
| `0xCa07AFeCa830987c572f2fE3A0802044433B153e` | Current version (leader retries once on invalid model output) | Registration, evidence, assessment and reassessment all worked on one test artifact. |

Test artifact (same on both, because the id is derived from type, ecosystem, name, version and digest, not from the contract address):

- Id: `tg1-06f7ddf9b52208eb351d18e838ad9f72871993f1b276d774cde324afbecd63b8`
- Type `NPM_PACKAGE`, name `trustguard-test-lib`, ecosystem `npm`, version `1.0.0`
- Digest: a placeholder of 64 `a` characters. It was not checked against a real package.

## Earlier contract (0x0ece...Bd79)

1. Registration, evidence submission from one wallet, and the first assessment succeeded (MEDIUM_RISK, score 35, confidence LOW, 2 evidence items, `llm_consensus`).
2. A second wallet added a third evidence item.
3. `assess_artifact` again was **unsuccessful**: the transaction showed an undetermined consensus status and `exit_code 1`. The stored assessment stayed unchanged (count 1). The exact cause was not identified. A likely explanation is that the leader raised an error on a model reply that failed validation, but this was never confirmed.
4. After this, the leader was changed to retry once with a corrective note when the model reply is invalid, and the contract was redeployed.

## Current contract (0xCa07...153e)

| Step | What was done | Observed |
|---|---|---|
| 1 | Registered the test artifact from wallet 1 | Succeeded |
| 2 | Submitted one `SECURITY_ADVISORY` from wallet 1 | Stored, `evidence_count` 1 |
| 3 | `assess_artifact`, reason `first live test` | Assessment 0: HIGH_RISK, score 45, confidence LOW, 1 evidence item, `previous_classification` UNASSESSED, `llm_consensus` |
| 4 | Wallet 2 submitted evidence with the type `INDEPENDENT_SECURITY_REPORT` | `Execution Error`. The type is not supported, so the contract rejected it. This is intended behaviour. |
| 5 | Wallet 2 called `assess_artifact` | `Execution Error`. Most likely rejected for having no new evidence (the previous step stored nothing). This cause is inferred, not read from an error message. |
| 6 | Wallet 2 submitted a `SECURITY_ADVISORY` | Succeeded. The count read 1 until the transaction was finalized, then 2. |
| 7 | `assess_artifact`, reason `reassessment with independent reporter evidence`, requested by wallet 2 | Assessment 1: HIGH_RISK, score 65, confidence MEDIUM, 2 evidence items, `previous_classification` HIGH_RISK, `llm_consensus` |
| 8 | `get_assessment_history` (offset 0, limit 10) | `total` 2. Assessment 0 was unchanged and still readable. Each record carries a different evidence digest. |

Observations:

- Reads reflect finalized state. A transaction shown as `accepted` was not visible to `get_artifact` until finalization, roughly 30 minutes later.
- The assessment explanations cited the missing digest linkage and the lack of verified provenance, and said the result is a risk signal and not proof of malware. No package was scanned or executed.
- The phrase "independent reports" in the second explanation is the model's wording. The contract cannot verify independence and stores all reporter claims as unverified.

## Limitations

- One artifact, one run per step, small evidence set. This says nothing about validator agreement rates or behaviour at scale.
- Whether the leader retry was needed in the successful reassessment is unknown. The earlier failure happened on a version without the retry, and its cause was not confirmed.
- No attempt was made on the live network to inject instructions through evidence text, so injection resistance with a real model is untested.
- The digest was a placeholder and no digest comparison was performed.
- `LOW_RISK` and `CRITICAL_RISK` outcomes, the 16-assessment cap and the 40-evidence cap were not exercised on the network.
