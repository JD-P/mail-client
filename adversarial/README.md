# Mail-client adversarial findings

This directory is the independent adversarial record for the Lizard mail
client. It borrows the review discipline and fixed family ontology used by
httpd-rs, but its searches, finding IDs, durations, scores and trend lines are
mail-client-only. They must never be combined with the httpd-rs yield index.

## Current snapshot

The index currently covers **three passes**. Pass 1 reviewed commit
`4d04393b2fcd9f8cee25029279cc2fe3bd4a3b5c`; Pass 2's malicious-mail-server
review covered commit `47eb6b29fde5807dd9204aee2c4049eb7dd0ddb2`; Pass 3
reviewed commit `7c1a6683fbb7cd24e8779fc9b2c9c9b711e1e525`. Together they
contain two high denial-of-service findings, one low integrity finding and one
medium availability defect in a fail-closed security control, contributing
**211 adjusted points**. The Pass-1 findings were remediated by
`562aea7d3b29ec64c6e65851137caf557b01750b`; P2-A was remediated by
`4d1ab6614bfcb103edb2d8cd721f63fdef0e96a4`. P3-A was confirmed at its
reviewed commit and was not remediated there. Confirmed historical findings
remain in the yield total.

| Primary family | Confirmed findings | Adjusted points |
|---|---:|---:|
| `denial_of_service` | 2 | 200.0 |
| `integrity_violation` | 1 | 1.0 |
| `unclassified` | 1 | 10.0 |
| all other fixed families | 0 | 0.0 |

The scoring model is impact weight low `1`, medium `10`, high `100`, critical
`1000`, catastrophic `10000`, multiplied by `2^(1-b)` where `b` is the number
of independently wrong behaviors required for the exploit. Only confirmed,
unique findings contribute points. Every completed search, including a
zero-finding search, contributes its active duration.

## Layout

| Path | Purpose |
|---|---|
| `findings_p1.md` | Pass-1 analysis, impact, reproduction, remediation and negative observations |
| `findings_p2.md` | Pass-2 malicious-server/RCE analysis and confirmed IMAP resource finding |
| `findings_p3.md` | Pass-3 isolated-worker Landlock misclassification, default worker-discovery observation and negative evidence |
| `p1/openpgp-compression-bomb/` | End-to-end received-message OpenPGP expansion harness |
| `p1/tui-bidi-queue/` | Real Ratatui/Crossterm queue-output harness |
| `p1/results_openpgp.txt`, `p1/results_tui_bidi.txt` | Retained measurements from the reviewed commit |
| `p1/results_remediation.txt` | Post-fix regression and resource measurements |
| `p1/negative-results.txt` | Rejected hypotheses and scoped negative evidence |
| `p2/imap-response-flood/` | Real async-imap LIST flood plus IMAP/MIME mutation harness |
| `p2/results_imap_flood.txt`, `p2/negative-results.txt` | Pass-2 measurements and scoped negative RCE evidence |
| `p2/results_remediation.txt` | Post-fix command-budget, resource and compatibility results |
| `p3/imap-worker-landlock/` | Isolated IMAP worker Landlock reproduction, bisection and corrected-policy verification |
| `p3/worker-discovery/` | Retained cargo-layout worker-discovery failure and explicit-path contrast |
| `vulnerability-families.md` | Fixed classification/scoring contract and mail-client yield table |
| `yield-index/searches.jsonl` | Mail-client logical searches and active segments |
| `yield-index/findings.jsonl` | Mail-client claims, evidence, severity and composition |
| `yield-index/validate_index.py` | Local schema/referential-integrity validator |
| `yield-index/yield-summary.md` | Deterministic per-pass and cumulative score/rate calculation |

Validate the independent index from the repository root:

```sh
python3 adversarial/yield-index/validate_index.py
```

