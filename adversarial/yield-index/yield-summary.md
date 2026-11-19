# Mail-client adversarial yield — Pass 1

This summary covers only the Lizard mail-client index. No httpd-rs search,
finding, duration or point total is included.

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

One search is not a trend. These rates are retained for future reproducible
comparisons, not as an estimate of vulnerabilities remaining.
