# Mail-client adversarial yield — Passes 1–2

This summary covers only the Lizard mail-client index. No httpd-rs search,
finding, duration or point total is included.

Both confirmed Pass-1 findings were remediated by
`562aea7d3b29ec64c6e65851137caf557b01750b`. The yield calculation is a
historical measure of confirmed defects and therefore does not remove fixed
findings. Pass-2 P2-A was remediated by
`4d1ab6614bfcb103edb2d8cd721f63fdef0e96a4`.

## Formula

For each confirmed unique finding:

```text
adjusted points = impact weight × 2^(1 - unintended behavior count)
```

Impact weights are low `1`, medium `10`, high `100`, critical `1000` and
catastrophic `10000`. Search yield divides totals by all completed active
search time, including zero-finding searches.

## Pass-1 calculation

The retained segment runs from `2026-11-19T07:39:20.289Z` (first recoverable
local task action; the UI prompt was earlier but unavailable) through
`2026-11-19T08:12:57.796Z`, or 2,017.507 seconds / **0.560419 hours**.

| Claim | Severity | Behaviors | Factor | Adjusted points |
|---|---:|---:|---:|---:|
| P1-A | high (100) | 1 | 1.0 | 100.0 |
| P1-B | low (1) | 1 | 1.0 | 1.0 |
| **Total** |  |  |  | **101.0** |

- Confirmed findings per search-hour: **3.57**
- Adjusted points per search-hour: **180.22**

Pass 1 alone was not a trend. These rates are retained for reproducible
comparison, not as an estimate of vulnerabilities remaining.

## Pass-2 calculation

The recoverable Pass-2 segment runs from `2026-11-19T17:17:29.000Z` through
`2026-11-19T17:27:49.724Z`, or 620.724 seconds / **0.172423 hours**. The user
prompt and initial static analysis preceded the first timestamp by an
unavailable interval after context compaction, so this duration is a lower
bound and its per-hour rate is correspondingly an upper bound.

| Claim | Severity | Behaviors | Factor | Adjusted points |
|---|---:|---:|---:|---:|
| P2-A | high (100) | 1 | 1.0 | 100.0 |
| **Pass-2 total** |  |  |  | **100.0** |

- Confirmed findings per recoverable search-hour: **5.80**
- Adjusted points per recoverable search-hour: **579.97**

## Cumulative calculation

The two retained segments total 2,638.231 seconds / **0.732842 hours**.

| Pass | Confirmed findings | Adjusted points |
|---|---:|---:|
| Pass 1 | 2 | 101.0 |
| Pass 2 | 1 | 100.0 |
| **Total** | **3** | **201.0** |

- Confirmed findings per recoverable search-hour: **4.09**
- Adjusted points per recoverable search-hour: **274.27**

Two searches are still not a trend. In particular, Pass 2's unavailable
pre-timestamp interval prevents its rate from being compared naively with
Pass 1.
