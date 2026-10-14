# TrustGuard (lite)

A GenLayer Intelligent Contract that keeps an **auditable, evidence-based registry of software-supply-chain risk assessments** (npm/Python packages, Git repos, smart-contract dependencies, AI models, datasets, build artifacts).

> **An assessment is a risk signal from submitted evidence, not a guarantee of safety.** TrustGuard never downloads, executes or malware-scans anything. `LOW_RISK` means "the submitted evidence does not indicate meaningful risk", never "safe".

## Two versions

| File | Size | Use |
|---|---|---|
| `contracts/trustguard.py` | ~18.5 KB | **Deploy this.** Sized to fit Bradbury's ~20 KB limit. |
| `archive/trustguard_full.py` | ~44 KB | Reference only (typed storage, ownership transfer, more views). Too big for Bradbury. Not maintained. |

Check size any time: `wc -c contracts/trustguard.py`. The "~20 KB" limit is as reported by the project owner; **how Bradbury measures it (bytes, KiB, after processing) is unverified**, so keep a safety margin. Do not add features without re-measuring.

Features removed to fit: ownership transfer, `get_contract_info`, `get_owner_info`, `is_registered`, single-item `get_evidence`/`get_assessment` (use the paged views with `limit=1`), typed storage dataclasses (records are now JSON strings). Ownership is fixed to the registrant.

## Verification status (read first)

| Item | Status |
|---|---|
| Contract logic | **Executed**: 74 `unittest` tests pass against a **fake** SDK (`tests/_fake_sdk`). |
| Real GenLayer runtime (GenVM, storage typing, `hashlib`/`re`, decorators) | **NOT verified.** The SDK/`gltest` could not be installed where this was written. |
| `tests/direct` (Direct Mode) | Written from docs, **never run**. |
| `tests/integration` (real LLM validators) | Skeleton, **never run**. |
| Deployment (Bradbury) | Deployed by the owner (see Deployment). Not independently verified. |
| Real consensus, injection resistance, validator agreement | **Unknown** until live tests run. |

Confirm on first real run: the `# { "Depends": ... }` pin (update to current); `gl.vm.UserError` (docs use two spellings); `Address.as_hex`; `hashlib`/`re`/`datetime.date` inside GenVM; public params `list[int]` and returns `dict`/`list[dict]`; `str.removeprefix` (Python 3.9+).

## How it works

**Identity.** `artifact_id = "tg1-" + SHA-256(length-prefixed(type, ecosystem, name, exact version, digest))`. Submitter and URL are not part of identity, so the same release cannot be registered twice. Python names are PEP 503-normalised; names are ASCII-only. Registering the same release with vs. without a digest gives two different artifacts. The id is **not returned reliably by a write transaction**, so get it from `compute_artifact_id(...)`.

**Evidence.** Bounded fields, control characters stripped, reporter-independent fingerprint (replay/duplicate blocked), rolling `evidence_digest` recorded in every assessment. Limits: 40 per artifact, 8 per reporter per artifact.

**Assessment** (`assess_artifact`): requires new evidence since the last assessment (first one always allowed); max 16 per artifact. No evidence -> deterministic `INSUFFICIENT_EVIDENCE`, no LLM call. Otherwise the leader calls `gl.nondet.exec_prompt(..., response_format="json")`; each validator re-runs it and accepts if both are `INSUFFICIENT_EVIDENCE`, or risk classes are within one band and scores within 15 points. Output is strictly validated (JSON object, score int 0-100 matching its band, bounded lists) or the transaction fails with no state change. A deterministic guard turns `LOW_RISK` into `INSUFFICIENT_EVIDENCE` unless there are 2+ items from 2+ reporters and confidence is not `LOW`. Higher-risk verdicts are never softened.

**Enforced by code:** validation, identity, duplicates, limits, access control, append-only history, band consistency, the LOW_RISK guard, staleness/digest-match facts. **Depends on the LLM:** score, class, explanation, mitigations, judging reliability and contradictions.

**Prompt injection.** Rules come first and say evidence cannot change them; evidence is JSON-encoded inside a digest-derived boundary (stripped from the text), never spliced as plain text; model output must pass schema checks; LOW_RISK needs corroboration. Residual risk: coordinated multi-reporter manipulation or a model steered toward a higher class. Only live tests can measure real resistance.

## Score bands

| Class | Score |
|---|---|
| LOW_RISK | 0-19 |
| MEDIUM_RISK | 20-39 |
| HIGH_RISK | 40-69 |
| CRITICAL_RISK | 70-100 |
| INSUFFICIENT_EVIDENCE | n/a (stored 0, `score_applicable=false`), a separate state |
| UNASSESSED | registry status before any assessment |

## Public methods

Writes (all `@gl.public.write`)
| Method | Who |
|---|---|
| `register_artifact(artifact_type, name, ecosystem, source_ref, version, digest_sha256)` | anyone (`digest_sha256=""` allowed) |
| `submit_evidence(artifact_id, evidence_type, source_ref, content_digest_sha256, description, observed_at, assessment_refs)` | anyone |
| `assess_artifact(artifact_id, reason)` | anyone (needs new evidence) |
| `update_source_ref(artifact_id, new_source_ref)` | owner only |

Views: `compute_artifact_id(type, name, ecosystem, version, digest)`, `get_artifact_count()`, `list_artifact_ids(offset, limit)` (returns `{"total", "items"}`), `get_artifact(id)`, `get_risk(id)`, `get_current_assessment(id)`, `get_assessment_history(id, offset, limit)`, `get_evidence_page(id, offset, limit)` (paged views return `{"total": n, "items": [...]}`). `limit` is 1-20; `offset` 0..total.

Artifact types: `NPM_PACKAGE, PYTHON_PACKAGE, GIT_REPOSITORY, SMART_CONTRACT_DEPENDENCY, AI_MODEL, MODEL_DATASET, BUILD_ARTIFACT`.
Evidence types: `SECURITY_ADVISORY, SOURCE_REVIEW, SCAN_REPORT, PROVENANCE_ATTESTATION, DIGEST_COMPARISON, MAINTAINER_CLAIM, BEHAVIOR_OBSERVATION, MODEL_CARD, OTHER`. `source_ref` must be `https://`, `git+https://`, `ipfs://`, `ar://` or `npm:`/`pypi:`/`cargo:`/`oci:`/`hf:`; no embedded credentials. `observed_at` is ISO-8601 and not in the future.

Errors are `gl.vm.UserError` starting with: `[TG_INPUT]`, `[TG_DUPLICATE]`, `[TG_NOT_FOUND]`, `[TG_UNAUTHORIZED]`, `[TG_NO_NEW_EVIDENCE]`, `[TG_LIMIT]`, `[TG_PAGE]`.

Records (JSON, returned as dicts). **Artifact:** `artifact_id, artifact_type, name, ecosystem, source_ref, version, digest_sha256, digest_status (SUPPLIED_UNVERIFIED|NOT_SUPPLIED), submitter, owner, registered_at, evidence_count, evidence_digest, assessment_count, current_classification, current_score, current_score_applicable, metadata_revision`. **Evidence:** `artifact_id, sequence, evidence_type, source_ref, content_digest_sha256, description, observed_at, reporter, submitted_at, assessment_refs, fingerprint, claims_unverified`. **Assessment:** `classification, previous_classification, score, score_applicable, confidence, explanation, warning_indicators, missing_information, mitigations, evidence_considered, reassessment_recommended, evidence_count_used, evidence_digest, requested_by, reason, assessed_at, method, prompt_version, disclaimer, sequence, artifact_id`.

No administrator, override, delete or upgrade path exists, so no fake owner address is hard-coded.

## Install and test

```bash
python3 -I tests/logic/test_trustguard_logic.py   # no GenLayer needed; fake SDK; logic only
python3 -I -m py_compile contracts/trustguard.py  # syntax check
wc -c contracts/trustguard.py                     # size check (must stay well under 20 KB)

pip install -r requirements.txt                   # genlayer-test, pytest (Python >= 3.12)
gltest tests/direct -v                            # Direct Mode, mocked LLM   (never run yet)
TRUSTGUARD_LIVE=1 gltest tests/integration --network localnet -v   # real validators (never run yet)
```

| Group | Real LLM | Live network | Proves consensus? |
|---|---|---|---|
| `tests/logic` | no | no | **no** |
| `tests/direct` | no (mocked) | no | **no** |
| `tests/integration` | yes | yes | partly |

No official lint command was confirmed; check your `genlayer` CLI for one.

## Example (genlayer-test client style)
```python
c = get_contract_factory("TrustGuard").deploy(args=[])
c.register_artifact(args=["NPM_PACKAGE","left-pad","npm","https://registry.npmjs.org/left-pad","1.3.0",SHA256]).transact()
aid = c.compute_artifact_id(args=["NPM_PACKAGE","left-pad","npm","1.3.0",SHA256]).call()
c.submit_evidence(args=[aid,"SECURITY_ADVISORY","https://example.org/adv/1","",
                        "Advisory reports install-script network access.","2026-09-01",[]]).transact()
c.assess_artifact(args=[aid,"initial assessment"]).transact()
c.get_current_assessment(args=[aid]).call()
```
**New evidence + reassess:** `submit_evidence(...)` (optionally `assessment_refs=[n]`), then `assess_artifact(aid, "why")`. Earlier assessments stay readable through `get_assessment_history`.

## Deployment
- **Network:** GenLayer Bradbury testnet (as reported by the deployer)
- **Contract address:** `0x0ece7f3eaD96856477571a021c6939037c19Bd79`
- **Deployed file:** `contracts/trustguard.py` (constructor takes no arguments, ~18.5 KB)

Deployment succeeded according to the deployer. The author of this repo did **not** independently verify the deployment, and a full on-chain `register -> submit_evidence -> assess_artifact` run with real validators has **not** been recorded here yet. Treat real-LLM behaviour as untested until it is.

To redeploy, use the current GenLayer docs for the network selector, faucet/test tokens and CLI flags. Re-run `wc -c contracts/trustguard.py` after any change; Bradbury has a size limit near 20 KB.

## Verifying digests independently
A SHA-256 only proves bytes match a *trusted expected* digest, not safety. Get the expected digest from an independent trusted channel, hash your download yourself (`sha256sum f`, `shasum -a 256 f`, or `Get-FileHash -Algorithm SHA256 f`) and compare. The digest stored here is **user-supplied and unverified**.

## Limitations
- No external fetching; URLs are references only; reporter claims are unverified unless corroborated.
- Anyone can fill the 40-item evidence cap (5 accounts x 8); mitigation is registering a new version.
- After 16 assessments an artifact cannot be reassessed.
- Staleness (365 days) is a heuristic; vulnerability data may be outdated. Time is the transaction datetime.
- First registrant owns the record permanently (ownership affects only `source_ref`).
- Validators may differ near band edges (tolerance: adjacent band, 15 points); the leader's value is recorded.
- Records as JSON strings are less strictly typed than the archived full version.
- Real-runtime compatibility is unverified (see above).
