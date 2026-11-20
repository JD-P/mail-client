# Mail-client CVE root-cause matrix

This directory contains a reproducible historical comparison of public CVEs
assigned to twelve mail-client families and the current Lizard design and
implementation boundary. It follows the artifact shape and conservative
language of `httpd-rs/docs/cve`: a source snapshot, a complete per-CVE ledger,
machine-readable outputs and a short review-oriented summary.

It is **not a product-security ranking**. Raw CVE totals measure disclosure and
product taxonomy as much as engineering quality. Thunderbird is assigned many
shared Gecko CVEs; Apple and Google often publish client fixes under operating-
system components; commercial clients may disclose defects without requesting
a CVE. “No record found” therefore means only that this selection found no NVD
record under the documented aliases.

## Files

- `mail-client-nvd.json` — the filtered NVD source records, product-match
  evidence, source URL and compressed-feed SHA-256.
- `mail-client-cve-matrix.json` — complete per-CVE root cause, classification,
  Lizard comparison, implementation evidence, CPEs and advisory links.
- `mail-client-cve-matrix.csv` — the same ledger for spreadsheet review.
- `mail-client-cve-matrix.md` — product counts, classification totals and the
  high/critical review set.
- `tests/mail_client_cve_matrix.py` — source selection, classification,
  generation and deterministic validation.

## Product scope

The current snapshot covers Microsoft Outlook, Mozilla Thunderbird, Apple Mail,
Gmail for Android, eM Client, Mailbird, Mutt/NeoMutt, Alpine/Pine, GNOME
Evolution, KMail/Kontact, K-9 Mail and Claws Mail. Exact scope notes and match
evidence are embedded in the source snapshot.

Selection uses structured vulnerable CPEs and CNA affected-product data first,
then narrow description patterns for products—especially Apple Mail and Gmail—
whose historical records are commonly attached to an OS rather than an
application CPE. A description-only match is retained with its regex evidence
so false positives remain auditable. Exchange Server/Outlook Web Access-only,
Alpine Linux and similarly named non-client products are explicitly excluded.

## Classification

| status | meaning |
|---|---|
| `prevented` | the disclosed primitive is removed or bounded by a concrete current property |
| `fail_closed` | unsupported active input is rejected or remains inert |
| `not_applicable` | the affected platform, integration or feature is absent |
| `partial` | a relevant mitigation exists, but an equivalent failure is not ruled out completely |
| `not_covered` | Lizard implements the relevant behavior without a sufficient invariant or comparison |
| `needs_review` | the public record is too vague for a conservative mapping |
| `rejected` | the source record has been rejected |

Only explicit advisory/root-cause overrides receive `manual_override`.
Remaining rows are marked `conservative_rule`; they are not represented as
individual PoC replays. In particular, safe Rust removes native use-after-free
and buffer-corruption primitives from maintained code, but external parsers,
codecs, cryptography and small unsafe adapters remain trusted boundaries, so
generic memory-safety rows are `partial` rather than blanket-prevented.

## Sources and blind spots

The source is the NVD data reconstructed by
[`fkie-cad/nvd-json-data-feeds`](https://github.com/fkie-cad/nvd-json-data-feeds),
which synchronizes from the NVD API and publishes timestamped xz feeds. NVD
explains that its applicability statements associate CPEs with CVEs, while the
CVE records and vendor advisories remain the underlying disclosure evidence:
[NVD product API documentation](https://nvd.nist.gov/developers/products) and
[NVD CVE FAQ](https://nvd.nist.gov/general/FAQ-Sections/CVE-FAQs).

Vendor records remain important when interpreting the normalized data:

- [Mozilla Thunderbird advisories](https://www.mozilla.org/security/known-vulnerabilities/thunderbird/)
  explicitly warn that many Thunderbird-tagged browser-engine flaws cannot be
  triggered through ordinary email because scripting is disabled.
- [Microsoft's Security Update Guide](https://msrc.microsoft.com/update-guide/)
  is authoritative for Outlook's affected editions and exploit prerequisites.
- [Apple security releases](https://support.apple.com/en-us/100100) often list
  fixes under the `Mail` component of an OS release rather than an Apple Mail
  application CPE.
- [Android security bulletins](https://source.android.com/docs/security/bulletin)
  cover platform components but do not constitute a complete Gmail-app advisory
  archive.

Advisories without CVE IDs, bugs kept private, ecosystem dependencies not named
in an application's affected set and defects in hosted mail services are out of
scope. The matrix also does not infer that a browser-engine CVE is mail-triggered
merely because NVD lists Thunderbird.

## Regeneration

Ordinary validation is offline and uses the checked-in filtered snapshot:

```sh
python3 tests/mail_client_cve_matrix.py
python3 tests/mail_client_cve_matrix.py --check
```

Refresh from the current reconstructed NVD feed:

```sh
python3 tests/mail_client_cve_matrix.py --fetch
```

For an independently downloaded and `xz -t`-validated feed:

```sh
python3 tests/mail_client_cve_matrix.py --fetch --feed /path/to/CVE-All.json.xz
```

`--fetch` records the compressed SHA-256, retrieval time and upstream URL. A
refresh may legitimately change historical descriptions, CPEs, scores and
counts because NVD records are mutable.
