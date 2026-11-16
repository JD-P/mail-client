# Vendored mail-auth

This directory is derived from `mail-auth` 0.15.1, published from upstream
commit `eb78c85582b24f8e8e3e4137fc02c0e5c5eb9ff0`.

Lizard distributes this fork under Apache-2.0, one of upstream's offered
licenses. The upstream license texts and copyright notices are retained in
`LICENSES/` and in source-file SPDX headers.

The fork hardens DKIM1 verification for use as an email-client security
boundary. Local changes reject ambiguous tag lists and obsolete algorithms,
enforce DNS key restrictions and RFC 8301 key sizes, return one ordered result
per physical signature header, disable unsolicited report and ATPS lookups by
default, and impose configurable parser, signature and DNS-work limits. It also
upgrades the pure-Rust RSA implementation from 0.9 to 0.10, adds a Ring-backed
DNS-over-TLS/DNSSEC feature, and exposes raw ordered verification evidence for
callers that must explain malformed signatures.

Regression tests cover each local parser and policy change. Run them with:

```sh
cargo test -p mail-auth --no-default-features \
  --features dns-hickory,dns-tls-ring,rust-crypto-sign
```
