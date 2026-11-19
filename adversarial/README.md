# Mail-client adversarial findings

This directory is the independent adversarial record for the Lizard mail
client. It borrows the review discipline and fixed family ontology used by
httpd-rs, but its searches, finding IDs, durations, scores and trend lines are
mail-client-only. They must never be combined with the httpd-rs yield index.

## Current snapshot

The index currently covers **Pass 1** against commit
`4d04393b2fcd9f8cee25029279cc2fe3bd4a3b5c`: one high denial-of-service
finding and one low integrity finding, contributing **101 adjusted points**.
Both were remediated by
`562aea7d3b29ec64c6e65851137caf557b01750b`; confirmed historical findings
remain in the yield total.

| Primary family | Confirmed findings | Adjusted points |
|---|---:|---:|
| `denial_of_service` | 1 | 100.0 |
| `integrity_violation` | 1 | 1.0 |
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
| `p1/openpgp-compression-bomb/` | End-to-end received-message OpenPGP expansion harness |
| `p1/tui-bidi-queue/` | Real Ratatui/Crossterm queue-output harness |
| `p1/results_openpgp.txt`, `p1/results_tui_bidi.txt` | Retained measurements from the reviewed commit |
| `p1/results_remediation.txt` | Post-fix regression and resource measurements |
| `p1/negative-results.txt` | Rejected hypotheses and scoped negative evidence |
| `vulnerability-families.md` | Fixed classification/scoring contract and mail-client yield table |
| `yield-index/searches.jsonl` | Mail-client logical searches and active segments |
| `yield-index/findings.jsonl` | Mail-client claims, evidence, severity and composition |
| `yield-index/validate_index.py` | Local schema/referential-integrity validator |
| `yield-index/yield-summary.md` | Deterministic Pass-1 score and rate calculation |

Validate the independent index from the repository root:

```sh
python3 adversarial/yield-index/validate_index.py
```

