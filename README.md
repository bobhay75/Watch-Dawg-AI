# Watch-Dawg AI

Watch-Dawg AI is the audit and intelligence layer for transaction systems. It verifies allocation rules, reconciles balances, flags anomalies, and explains money movement.

The initial build is a deterministic audit engine and browser demo designed to integrate with Grow Vault.

## MVP features

- Transaction allocation audit for gross, vault rate, vaulted amount, and spendable amount.
- Ledger reconciliation for deposits, purchases, and vault withdrawals.
- DAW health score, anomaly review queue, audit trail table, and plain-English report.
- Built-in verified, ledger, and anomaly scenarios for fast testing.

## Run locally

Open `index.html` in a browser, or serve this folder with any static file server. Example:

```bash
python3 -m http.server 3000
```

Then visit `http://localhost:3000`.

## Test

```bash
node test.mjs
```
