# Bradbury Testnet: Live Contract Testing

TrustGuard was tested by hand on the GenLayer Bradbury testnet through the network explorer. This file records what was observed. It is not an exhaustive test and does not show that every feature works.

## Contracts tested

| Contract | Version | Status |
|---|---|---|
| `0x0ece7f3eaD96856477571a021c6939037c19Bd79` | Leader calls the LLM once. Validators accept adjacent categories within 15 points. | Superseded. A reassessment failed on it. |
| `0xCa07AFeCa830987c572f2fE3A0802044433B153e` | Adds one leader retry on invalid model output. Validators still accept adjacent categories. | Superseded. Reassessment worked. |
| `0xE3Bf28739F5C32908E131359d24254bb96C99e0e` | **Current.** Validators compare the final persisted result: category must be identical, score within 5 points in the same category. | Assessment and reassessment worked on one artifact. |

The test artifact id is the same on all three, because it is derived from type, ecosystem, name, version and digest, not from the contract address:

- Id: `tg1-06f7ddf9b52208eb351d18e838ad9f72871993f1b276d774cde324afbecd63b8`
- Type `NPM_PACKAGE`, name `trustguard-test-lib`, ecosystem `npm`, version `1.0.0`
- Digest: a placeholder of 64 `a` characters. It was not checked against a real package.

## Current contract (0xE3Bf...9e0e)

Plan followed: register the artifact, submit one `SECURITY_ADVISORY`, assess, wait for finalization, submit a second `SECURITY_ADVISORY` from a second wallet, wait for finalization, assess again, then read `get_assessment_history`. Only the final history output was captured for this record. The reporter addresses of the evidence items were not re-read in this run, so "two wallets" is the plan followed, not something this file proves.

`get_assessment_history` (offset 0, limit 10) returned `total: 2`:

| Field | Assessment 0 | Assessment 1 |
|---|---|---|
| Classification | MEDIUM_RISK | HIGH_RISK |
| Score | 35 | 65 |
| Confidence | MEDIUM | MEDIUM |
| `previous_classification` | UNASSESSED | MEDIUM_RISK |
| Evidence items used | 1 | 2 |
| Evidence digest | `e5ed1868...ca3c` | `37414b65...906f` |
| Requested by | `0xbd6d84fc...aa01` | `0x58e9e85f...bf82` |
| Method | `llm_consensus` | `llm_consensus` |
| Prompt version | `tg-prompt-2` | `tg-prompt-2` |

Observations:

- Assessment 0 stayed readable and unchanged after assessment 1 was added. Each record carries the evidence digest it was based on.
- Both explanations state that the evidence is unverified and that no digest comparison exists. The disclaimer "not a guarantee of safety, no scan or execution was performed" is present in both records.
- The second explanation cites the evidence ages as 18 and 5 days, which matches the observation dates supplied (2026-10-01 and 2026-10-14 against an assessment date of 2026-10-19). Those ages are computed by the contract and passed to the model.
- The same single piece of evidence produced HIGH_RISK, score 45, confidence LOW on the earlier contract and MEDIUM_RISK, score 35, confidence MEDIUM on this one. This is ordinary model variability, and it is the reason validators must agree on the stored result rather than approximately on it.
- The phrase "independent reporters" in the second explanation is the model's wording. The contract cannot verify independence and stores all reporter claims as unverified.

## Earlier contracts

On `0x0ece...Bd79`, the first assessment succeeded (MEDIUM_RISK, 35, confidence LOW, 2 items). After a further evidence item was added, a second `assess_artifact` was unsuccessful: the transaction showed an undetermined consensus status and `exit_code 1`, and the stored assessment stayed unchanged. The cause was not identified. A likely explanation is that the leader raised an error on a model reply that failed validation, but this was never confirmed. The leader was then changed to retry once with a corrective note, and a new contract was deployed.

On `0xCa07...153e`, registration, evidence and assessment worked and a reassessment after new evidence succeeded (HIGH_RISK 45, then HIGH_RISK 65). Two input mistakes were also observed there and are intended behaviour: an unsupported evidence type was rejected with `Execution Error`, and a reassessment call with no new evidence was rejected. Reads reflect finalized state; an `accepted` transaction was not visible to `get_artifact` until it finalized.

That version was then changed because validators accepted adjacent risk categories while the leader's exact category and score were stored. The current contract closes this.

## Limitations

- One artifact and one run per step. This says nothing about how often validators agree, and the stricter agreement rule may produce more undetermined transactions under load.
- Whether the leader retry was needed in any successful run is unknown.
- No instruction-injection attempt was made through evidence text on the live network, so injection resistance with a real model is untested.
- The digest was a placeholder and no digest comparison was performed.
- `LOW_RISK`, `CRITICAL_RISK`, `INSUFFICIENT_EVIDENCE` outcomes, the 16-assessment cap and the 40-evidence cap were not exercised on the network.
- The deployer reports that the deployed file is this repo's `contracts/trustguard.py`. This was not independently checked.
