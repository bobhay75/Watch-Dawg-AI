# Watch-Dawg AI audit — 2026-08-19

Verified defects addressed in this branch:

- Transaction type matching was case-sensitive, while Grow Vault emits `Deposit` and `Purchase`.
- Grow Vault purchase records use `gross`/`amount`; Watch-Dawg expected only `amount`.
- Invalid numeric values, negative amounts, and out-of-range allocation rates were insufficiently validated.
- Unknown transaction types could pass through without a clear review finding.
- No CI workflow ran the regression tests automatically.

The engine now normalizes the Grow Vault contract, validates transaction fields, audits purchase-side vaulting, and runs its regression suite in GitHub Actions.