# TrustGuard v2

TrustGuard is an evidence-based supply-chain risk registry on GenLayer. This repository holds the Intelligent Contract and the web app that reads and writes it.

- Contract: [`contracts/trustguard.py`](contracts/trustguard.py), deployed on GenLayer Bradbury at `0xC571C9cbd33ABFF7AD1dB044a027c51E42fCC88c`.
- Web app: [`frontend/`](frontend/), a React + Vite interface for the same contract and address.

## How the two fit together

The web app calls the deployed contract through `genlayer-js`. It reads artifacts, evidence and assessments with the contract's view methods (`list_artifact_ids`, `get_artifact`, `get_current_assessment`, `get_assessment_history`, `get_evidence_page`, `compute_artifact_id`). With a browser wallet it calls the write methods (`register_artifact`, `submit_evidence`, `assess_artifact`). The contract address is set in `frontend/src/config.js` and can be overridden with `VITE_CONTRACT_ADDRESS`. The app changes no contract logic.

## What the contract does

- Registers artifacts (packages, repositories, AI models, build artifacts) under a deterministic id.
- Stores evidence as unverified claims, with a replay block and per-reporter limits.
- Produces LLM risk assessments through GenLayer validators. Every validator re-runs the assessment and accepts only if the persisted category and the persisted score are identical to its own. The stored score is a fixed value per category, so it is bound exactly.
- Keeps an append-only assessment history. There is no admin or override.

The explanation and list fields of an assessment are written by the leader validator. They are bounded and sanitised, but validators do not bind them. This is stated in the app and in the documents below.

## Repository layout

| Path | Content |
|---|---|
| `contracts/trustguard.py` | The Intelligent Contract |
| `frontend/` | Web app (React + Vite) |
| `tests/` | Logic tests (fake SDK), Direct Mode tests, integration skeleton |
| `CONTRACT.md` | Detailed contract documentation and verification status |
| `THREAT_MODEL.md` | Threats and how each is handled |
| `TESTING.md` | What was observed on Bradbury, and its limits |

## Run the web app

```
cd frontend
npm install
npm run dev
```

`npm test` runs the web app's unit tests. `npm run build` creates a static build.

## Run the contract tests

```
python3 -I tests/logic/test_trustguard_logic.py
```

This runs against a fake SDK, so it shows the contract logic behaves as designed, not that it behaves the same on-chain. Direct Mode tests need `genlayer-test` (`gltest tests/direct -v`).

## Honest status

- The contract was assessed and reassessed on Bradbury on one test artifact. This says nothing about how often validators agree. See `TESTING.md`.
- Evidence is never verified, digests are never checked, and nothing is scanned or executed. A risk result is a signal, not a guarantee of safety.
- The web app reads finalized state only, so a new transaction can take a while to appear. Writes need a browser wallet.
- The web app's write paths were built to the `genlayer-js` documented API; the contract's reads through the app were confirmed working.
