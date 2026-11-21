# Mail-client adversarial yield — Passes 1–3

This summary covers only the Lizard mail-client index. No httpd-rs search,
finding, duration or point total is included.

Both confirmed Pass-1 findings were remediated by
`562aea7d3b29ec64c6e65851137caf557b01750b`. The yield calculation is a
historical measure of confirmed defects and therefore does not remove fixed
findings. Pass-2 P2-A was remediated by
`4d1ab6614bfcb103edb2d8cd721f63fdef0e96a4`. Pass-3 P3-A is confirmed at the
reviewed commit and was not remediated there; a disposable-copy verification
of the proposed fix is retained with the Pass-3 harness.

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

## Pass-3 calculation

The recoverable Pass-3 segment runs from `2026-11-20T23:22:03.447Z` (harness
session creation; the user prompt preceded it) through
`2026-11-21T00:51:56.982Z`, or 5,393.535 seconds / **1.498204 hours**. The
pre-compaction interval of the same logical search is not recoverable, so this
duration is a lower bound and its per-hour rate is an upper bound.

| Claim | Severity | Behaviors | Factor | Adjusted points |
|---|---:|---:|---:|---:|
| P3-A | medium (10) | 1 | 1.0 | 10.0 |
| **Pass-3 total** |  |  |  | **10.0** |

- Confirmed findings per recoverable search-hour: **0.67**
- Adjusted points per recoverable search-hour: **6.67**

Pass-3 resource accounting (harness session counters when the index records
were written; the same budget covers the scored finding and every
zero-finding probe, including the unscored P3-B observation): 896,727 input
tokens, 75,647 output tokens, 127,906 reasoning tokens, 109,479,296
cache-read tokens, 0 cache-write tokens — 1,100,280 billed tokens in total.
The harness-recorded session cost is **$1.974953**; a recomputation at the
listed model prices ($0.15 per million input, $0.60 per million output,
$0.003 per million cache read) is **$0.585079**, and the harness value is
authoritative.

## Cumulative calculation

The three retained segments total 8,031.766 seconds / **2.231046 hours**.

| Pass | Confirmed findings | Adjusted points |
|---|---:|---:|
| Pass 1 | 2 | 101.0 |
| Pass 2 | 1 | 100.0 |
| Pass 3 | 1 | 10.0 |
| **Total** | **4** | **211.0** |

- Confirmed findings per recoverable search-hour: **1.79**
- Adjusted points per recoverable search-hour: **94.57**

Three searches are still not a trend. Pass 2's and Pass 3's unavailable
pre-timestamp intervals prevent their rates from being compared naively with
Pass 1, and Pass 3's single scored finding is an availability defect in a
fail-closed control rather than an attacker-triggered primitive.
