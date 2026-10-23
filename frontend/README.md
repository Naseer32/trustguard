# TrustGuard frontend

React + Vite interface for the TrustGuard contract on GenLayer Bradbury.

Contract: `0xC571C9cbd33ABFF7AD1dB044a027c51E42fCC88c`. It can be changed with `VITE_CONTRACT_ADDRESS` (see `.env.example`). The contract, ABI and network settings are not modified by this app.

## Run

```
npm install
npm run dev
```

Build for hosting: `npm run build` (output in `dist/`). Routes use the URL hash, so the build works on static hosting such as GitHub Pages.

Checks: `npm test` runs the unit tests for validation, aggregation and routing (`node --test`, no extra packages).

## What it does

- Dashboard: artifact count, risk distribution, assessed and waiting counts, assessments and evidence recorded, confidence of current assessments, artifacts rated high or critical, artifacts with evidence added since their last assessment, and latest activity. Every figure is computed from contract reads. Nothing is estimated.
- Registry: search, filter by risk and type, sort, deep links to each artifact.
- Register artifact: live validation that mirrors the contract's rules, and a preview of the artifact id before sending.
- Case file: risk verdict on a four-band gauge, assessment history, evidence ledger, evidence submission and assessment request.
- Wallet: connect, reconnect without a prompt, follows account changes. Each write shows its steps (wallet, validators, accepted).
- Light and dark themes, mobile tab bar, skeleton loading, empty and error states.

## Limits to know

- Reads show finalized state only. A transaction that was accepted may take a while to appear.
- The dashboard loads at most 100 artifacts and shows a note if the contract holds more.
- "Latest activity" shows the most recent registration, evidence item and assessment of each artifact, not a full event log, because the contract has no event feed.
- Writes need a browser wallet (MetaMask). They do not work inside Termux.
- Client-side checks give early feedback only. The contract decides what is accepted.
- The UI was previewed in Chromium against stand-in data. Contract reads and writes through `genlayer-js` were checked by build and by the earlier read test only. Writes have not been exercised from this app.
