#!/usr/bin/env python3
"""Build the historical mail-client CVE comparison ledger.

The checked-in source snapshot is deliberately filtered to records which match
one of PRODUCT_SPECS.  ``--fetch`` streams the complete xz-compressed NVD
reconstruction without materializing the multi-gigabyte JSON feed on disk.
Ordinary runs are offline and deterministic.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import lzma
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "cve"
SNAPSHOT = DOCS / "mail-client-nvd.json"
MATRIX_JSON = DOCS / "mail-client-cve-matrix.json"
MATRIX_CSV = DOCS / "mail-client-cve-matrix.csv"
SUMMARY_MD = DOCS / "mail-client-cve-matrix.md"
DEFAULT_FEED = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
    "CVE-All.json.xz"
)


PRODUCT_SPECS = (
    {
        "slug": "outlook",
        "name": "Microsoft Outlook",
        "scope": "Desktop and native mobile Outlook; excludes Exchange Server and Outlook Web Access-only defects.",
        "cpes": (":microsoft:outlook:", ":microsoft:office_outlook:"),
        "affected": (r"^Microsoft .*Outlook$", r"^Outlook$"),
        "description": (
            r"\bMicrosoft (?:Office )?Outlook\b",
            r"\bOutlook for (?:Android|iOS)\b",
        ),
    },
    {
        "slug": "thunderbird",
        "name": "Mozilla Thunderbird",
        "scope": "Desktop Thunderbird, including CVEs shared with Gecko when NVD marks Thunderbird affected.",
        "cpes": (":mozilla:thunderbird:",),
        "affected": (r"^Thunderbird$", r"^Mozilla Thunderbird$"),
        "description": (r"\bMozilla Thunderbird\b", r"\bThunderbird (?:before|through|ESR|[0-9])"),
    },
    {
        "slug": "apple-mail",
        "name": "Apple Mail",
        "scope": "Mail on macOS and iOS/iPadOS; excludes unrelated OS vulnerabilities merely delivered by email.",
        "cpes": (":apple:mail:",),
        "affected": (r"^(?:Apple )?Mail$",),
        "description": (
            r"\bApple Mail\b",
            r"\bMail\.app\b",
            r"\bMail in (?:Apple )?(?:Mac OS X|macOS|iOS|iPhone OS|iPadOS)\b",
            r"\bMail component (?:in|of) (?:Apple )?(?:macOS|iOS|iPhone OS|iPadOS)\b",
            r"issue involves the \"Mail(?: Drafts)?\" component",
        ),
    },
    {
        "slug": "gmail-android",
        "name": "Gmail for Android",
        "scope": "The native Gmail Android client, not Gmail's web service or unrelated Gmail integrations.",
        "cpes": (":google:gmail:",),
        "affected": (r"^Gmail(?: for Android)?$",),
        "description": (
            r"\bGmail (?:app|application|for Android)\b",
            r"\b(?:In|in) Gmail, .{0,100}\bAndroid\b",
            r"\bgmail account name on the device\b",
        ),
    },
    {
        "slug": "em-client",
        "name": "eM Client",
        "scope": "The eM Client desktop application.",
        "cpes": (":emclient:em_client:", ":em_client:em_client:"),
        "affected": (r"^eM Client$",),
        "description": (r"\beM Client (?:before|through|[0-9])",),
    },
    {
        "slug": "mailbird",
        "name": "Mailbird",
        "scope": "The Mailbird desktop application.",
        "cpes": (":mailbird:mailbird:",),
        "affected": (r"^Mailbird$",),
        "description": (r"\bMailbird (?:before|through|[0-9])",),
    },
    {
        "slug": "mutt-neomutt",
        "name": "Mutt / NeoMutt",
        "scope": "Mutt and NeoMutt, including records that affect both forks.",
        "cpes": (":mutt:mutt:", ":neomutt:neomutt:", ":neomutt_project:neomutt:"),
        "affected": (r"^(?:Mutt|NeoMutt)$",),
        "description": (r"\bMutt (?:before|through|[0-9])", r"\bNeoMutt\b"),
    },
    {
        "slug": "alpine-pine",
        "name": "Alpine / Pine",
        "scope": "The University of Washington Alpine/Pine mail-client family; never Alpine Linux.",
        "cpes": (
            ":washington.edu:alpine:",
            ":university_of_washington:alpine:",
            ":washington.edu:pine:",
        ),
        "affected": (r"^(?:Alpine|Pine)(?: Mail)?$",),
        "description": (
            r"\bAlpine (?:mail|email|IMAP|client|before|through|[0-9])",
            r"\bPine (?:mail|email|IMAP|client|before|through|[0-9])",
        ),
    },
    {
        "slug": "evolution",
        "name": "GNOME Evolution",
        "scope": "Evolution and mail-relevant Evolution Data Server defects.",
        "cpes": (":gnome:evolution:", ":gnome:evolution_data_server:"),
        "affected": (r"^(?:GNOME |Ximian )?Evolution(?: Data Server)?$",),
        "description": (
            r"\b(?:GNOME|Ximian) Evolution\b",
            r"\bEvolution (?:Data Server|mail|email|before|through|[0-9])",
            r"\bevolution-data-server\b",
        ),
    },
    {
        "slug": "kmail-kontact",
        "name": "KMail / Kontact",
        "scope": "KMail and mail-relevant Kontact/Akonadi integration defects.",
        "cpes": (":kde:kmail:", ":kde:kontact:"),
        "affected": (r"^(?:KMail|Kontact)$",),
        "description": (r"\bKMail\b", r"\bKontact (?:mail|email|before|through|[0-9])"),
    },
    {
        "slug": "k9-mail",
        "name": "K-9 Mail",
        "scope": "K-9 Mail/Thunderbird for Android before and after Mozilla stewardship.",
        "cpes": (":k9mail:k-9_mail:", ":k-9_mail_project:k-9_mail:"),
        "affected": (r"^K-9 Mail$",),
        "description": (r"\bK-9 Mail\b",),
    },
    {
        "slug": "claws-mail",
        "name": "Claws Mail",
        "scope": "The Claws Mail desktop application and its bundled mail parsers.",
        "cpes": (":claws-mail:claws_mail:", ":claws_mail:claws_mail:"),
        "affected": (r"^Claws Mail$",),
        "description": (r"\bClaws Mail\b",),
    },
)


MANUAL = {
    "CVE-2003-0140": {
        "surface": "mail-protocol",
        "root_cause": "an attacker-controlled IMAP folder name overflowed a native buffer",
        "status": "prevented",
        "confidence": "high",
        "mapping": "the IMAP parser and client are safe Rust, aggregate responses are bounded, and synchronization is process-isolated",
        "evidence": "vendor/async-imap/src/imap_stream.rs; crates/mail-backend/src/imap_engine.rs; spec/imap-sync-isolation.md",
    },
    "CVE-2003-0299": {
        "surface": "mail-protocol",
        "root_cause": "mailbox-size arithmetic crossed signed/native integer bounds in an IMAP client",
        "status": "prevented",
        "confidence": "high",
        "mapping": "verified exact resource charging rejects overflow and the isolated IMAP worker enforces aggregate limits",
        "evidence": "crates/verified-kernel/src/lib.rs::charge_usize; crates/mail-backend/src/imap_engine.rs; spec/imap-sync-isolation.md",
    },
    "CVE-2008-0039": {
        "surface": "external-handler",
        "root_cause": "a file URL in mail reached an external command-capable handler",
        "status": "not_applicable",
        "confidence": "high",
        "mapping": "file and other non-web schemes are rendered as blocked references and the renderer has no process or filesystem authority",
        "evidence": "crates/mail-tui/src/render.rs; spec/tui-render-isolation.md",
    },
    "CVE-2008-4491": {
        "surface": "message-crypto",
        "root_cause": "S/MIME drafts were copied to a remote server before encryption protected their content",
        "status": "not_applicable",
        "confidence": "high",
        "mapping": "Lizard does not implement S/MIME",
        "evidence": "spec/mail-backend.md; crates/mail-backend/src/openpgp.rs",
    },
    "CVE-2011-1429": {
        "surface": "transport-security",
        "root_cause": "SMTP TLS accepted a certificate without matching the requested server hostname",
        "status": "prevented",
        "confidence": "high",
        "mapping": "SMTP uses rustls with the configured DNS name and WebPKI verification",
        "evidence": "crates/mail-backend/src/smtp.rs",
    },
    "CVE-2015-3710": {
        "surface": "remote-content",
        "root_cause": "sender HTML could trigger an unsolicited network refresh",
        "status": "prevented",
        "confidence": "high",
        "mapping": "render workers have no network authority and sender HTML cannot authorize resource loading",
        "evidence": "README.md; spec/tui-render-isolation.md; spec/security-ui.md",
    },
    "CVE-2015-5857": {
        "surface": "identity-ui",
        "root_cause": "contact-derived identity presentation allowed a sender-address spoof",
        "status": "partial",
        "confidence": "medium",
        "mapping": "the backend records contact provenance and the UI specification makes the address book authoritative, but the complete identity UI is not yet an invariant-proved implementation",
        "evidence": "spec/security-ui.md; crates/mail-backend/src/identity.rs",
    },
    "CVE-2017-17688": {
        "surface": "message-crypto",
        "root_cause": "OpenPGP plaintext could be exfiltrated by combining malleable legacy ciphertext with an active HTML backchannel",
        "status": "prevented",
        "confidence": "high",
        "mapping": "encrypted OpenPGP mail is exposed only as plain text, cannot load remote content, and cannot be spliced into unencrypted sibling HTML",
        "evidence": "crates/mail-backend/src/openpgp.rs; crates/mail-backend/src/types.rs; spec/security-ui.md",
    },
    "CVE-2018-5184": {
        "surface": "message-crypto",
        "root_cause": "remote content in an encrypted message created a plaintext exfiltration channel",
        "status": "prevented",
        "confidence": "high",
        "mapping": "decrypted OpenPGP content is plain-text-only and render workers have no network authority",
        "evidence": "crates/mail-backend/src/openpgp.rs; crates/mail-backend/src/types.rs; spec/security-ui.md",
    },
    "CVE-2019-10732": {
        "surface": "message-crypto",
        "root_cause": "hidden encrypted MIME subparts were quoted into a reply and disclosed plaintext",
        "status": "prevented",
        "confidence": "high",
        "mapping": "decrypted content cannot establish HTML context or merge with unencrypted siblings, and replies are constructed from the typed message model",
        "evidence": "crates/mail-backend/src/openpgp.rs; crates/mail-backend/src/sending.rs; spec/security-ui.md",
    },
    "CVE-2019-10735": {
        "surface": "message-crypto",
        "root_cause": "hidden encrypted MIME subparts were quoted into a reply and disclosed plaintext",
        "status": "prevented",
        "confidence": "high",
        "mapping": "decrypted content cannot establish HTML context or merge with unencrypted siblings, and replies are constructed from the typed message model",
        "evidence": "crates/mail-backend/src/openpgp.rs; crates/mail-backend/src/sending.rs; spec/security-ui.md",
    },
    "CVE-2020-12618": {
        "surface": "message-crypto",
        "root_cause": "an S/MIME certificate from mail silently replaced an established correspondent certificate",
        "status": "not_applicable",
        "confidence": "high",
        "mapping": "Lizard does not implement S/MIME; OpenPGP key acceptance is explicit and supports multiple accepted keys",
        "evidence": "spec/mail-backend.md; crates/mail-backend/src/openpgp.rs",
    },
    "CVE-2020-14928": {
        "surface": "transport-security",
        "root_cause": "pre-STARTTLS SMTP state could be injected or interpreted before the authenticated channel existed",
        "status": "prevented",
        "confidence": "high",
        "mapping": "STARTTLS is mandatory when configured, capability state is discarded across the upgrade, and authentication occurs only after rustls completes",
        "evidence": "crates/mail-backend/src/smtp.rs",
    },
    "CVE-2020-14954": {
        "surface": "transport-security",
        "root_cause": "pre-STARTTLS IMAP state could survive into the authenticated session",
        "status": "prevented",
        "confidence": "high",
        "mapping": "the client requires STARTTLS, upgrades before authentication, and obtains fresh post-TLS capabilities",
        "evidence": "crates/mail-backend/src/imap_engine.rs; vendor/async-imap/src/client.rs",
    },
    "CVE-2020-14929": {
        "surface": "transport-security",
        "root_cause": "a requested TLS policy silently fell back to a plaintext IMAP session after PREAUTH",
        "status": "prevented",
        "confidence": "high",
        "mapping": "STARTTLS is mandatory when configured; absent or failed TLS terminates synchronization before authentication or mail access",
        "evidence": "crates/mail-backend/src/imap_engine.rs",
    },
    "CVE-2020-9941": {
        "surface": "transport-security",
        "root_cause": "mail transport could be downgraded or pre-TLS protocol input could affect the protected session",
        "status": "prevented",
        "confidence": "high",
        "mapping": "configured TLS is mandatory and pre-upgrade capability state is not trusted for authentication",
        "evidence": "crates/mail-backend/src/imap_engine.rs; crates/mail-backend/src/smtp.rs",
    },
    "CVE-2021-29969": {
        "surface": "transport-security",
        "root_cause": "Thunderbird processed IMAP server responses before STARTTLS and retained attacker influence",
        "status": "prevented",
        "confidence": "high",
        "mapping": "Lizard performs STARTTLS before authentication and re-queries capabilities on the encrypted transport",
        "evidence": "crates/mail-backend/src/imap_engine.rs; vendor/async-imap/src/client.rs",
    },
    "CVE-2021-30696": {
        "surface": "transport-security",
        "root_cause": "mail transport accepted unsafe pre-TLS state during a STARTTLS upgrade",
        "status": "prevented",
        "confidence": "medium",
        "mapping": "Lizard treats STARTTLS as a required state transition and rebuilds trust decisions after rustls completes",
        "evidence": "crates/mail-backend/src/imap_engine.rs; crates/mail-backend/src/smtp.rs",
    },
    "CVE-2021-3181": {
        "surface": "mail-parser",
        "root_cause": "pathological RFC 822 address syntax made a mailbox unavailable",
        "status": "partial",
        "confidence": "medium",
        "mapping": "message sizes and worker resources are bounded, but the external MIME/address parser remains a trusted boundary without a proof of linear work",
        "evidence": "crates/mail-backend/src/mime.rs; docs/verification.md; spec/imap-sync-isolation.md",
    },
    "CVE-2021-46853": {
        "surface": "transport-security",
        "root_cause": "unsolicited IMAP responses before STARTTLS reached an invalid client state",
        "status": "prevented",
        "confidence": "high",
        "mapping": "the isolated safe-Rust IMAP client bounds response count/bytes and completes a strict STARTTLS transition before authenticated use",
        "evidence": "vendor/async-imap/src/imap_stream.rs; crates/mail-backend/src/imap_engine.rs",
    },
    "CVE-2023-23397": {
        "surface": "external-handler",
        "root_cause": "an Outlook reminder sound path caused automatic SMB/NTLM credential disclosure",
        "status": "not_applicable",
        "confidence": "high",
        "mapping": "Lizard has no reminder-sound, SMB, UNC or NTLM handler and render workers have no network authority",
        "evidence": "spec/tui-render-isolation.md; crates/mail-tui/src/render.rs",
    },
    "CVE-2024-21413": {
        "surface": "external-handler",
        "root_cause": "a crafted link escaped Outlook's protected view and reached a Windows file/credential handler",
        "status": "not_applicable",
        "confidence": "high",
        "mapping": "only HTTP(S) and mailto links are actionable metadata; file and other schemes are blocked text and the renderer cannot open handlers",
        "evidence": "crates/mail-tui/src/render.rs; spec/tui-html-profile.md; spec/tui-render-isolation.md",
    },
    "CVE-2024-11159": {
        "surface": "message-crypto",
        "root_cause": "remote content in an OpenPGP-encrypted message disclosed plaintext",
        "status": "prevented",
        "confidence": "high",
        "mapping": "decrypted OpenPGP content is plain-text-only and render workers have no network authority",
        "evidence": "crates/mail-backend/src/openpgp.rs; crates/mail-backend/src/types.rs; spec/security-ui.md",
    },
    "CVE-2024-49393": {
        "surface": "message-crypto",
        "root_cause": "recipient headers outside the signed/encrypted protected-header set could be rewritten",
        "status": "partial",
        "confidence": "medium",
        "mapping": "outgoing OpenPGP uses protected headers and a conversation-level no-downgrade policy, but full interoperability coverage for every recipient/header layout remains incomplete",
        "evidence": "crates/mail-backend/src/sending.rs; crates/mail-backend/src/openpgp.rs; spec/mail-backend.md",
    },
}


STATUS_ORDER = (
    "prevented",
    "fail_closed",
    "not_applicable",
    "partial",
    "not_covered",
    "needs_review",
    "rejected",
)

EXPECTED_MATCHES = {
    "CVE-2024-21413": "outlook",
    "CVE-2021-29969": "thunderbird",
    "CVE-2017-13874": "apple-mail",
    "CVE-2022-20270": "gmail-android",
    "CVE-2020-12618": "em-client",
    "CVE-2015-4657": "mailbird",
    "CVE-2024-49393": "mutt-neomutt",
    "CVE-2021-46853": "alpine-pine",
    "CVE-2020-14928": "evolution",
    "CVE-2021-38373": "kmail-kontact",
    "CVE-2019-10741": "k9-mail",
    "CVE-2020-15917": "claws-mail",
}

EXPECTED_EXCLUDED = {
    "CVE-2002-2249",  # News Evolution PHP application
    "CVE-2006-2104",  # Kamgaing webmail named kmail
    "CVE-2006-7062",  # Kamgaing webmail named kmail
    "CVE-2006-7111",  # CGI Cafe KMail CGI
    "CVE-2022-26336",  # Apache POI parser merely mentions Outlook's TNEF format
    "CVE-2025-5963",  # Postbox; description only names eM Client as acquirer
}


class HashingReader(io.RawIOBase):
    def __init__(self, raw: BinaryIO) -> None:
        self.raw = raw
        self.sha256 = hashlib.sha256()
        self.bytes = 0

    def read(self, size: int = -1) -> bytes:
        data = self.raw.read(size)
        self.sha256.update(data)
        self.bytes += len(data)
        return data

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False


def iter_top_level_array(
    stream: io.TextIOBase,
    key: str,
    metadata: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Incrementally decode objects from one named top-level JSON array."""

    decoder = json.JSONDecoder()
    marker = json.dumps(key)
    buffer = ""
    while True:
        chunk = stream.read(1_048_576)
        if not chunk:
            raise ValueError(f"feed has no complete {key!r} array")
        buffer += chunk
        marker_at = buffer.find(marker)
        if marker_at < 0:
            buffer = buffer[-len(marker) :]
            continue
        array_at = buffer.find("[", marker_at + len(marker))
        if array_at < 0:
            buffer = buffer[marker_at:]
            continue
        if metadata is not None:
            header = buffer[:marker_at]
            for name in ("timestamp", "feed_name"):
                match = re.search(rf'"{name}"\s*:\s*"([^"]+)"', header)
                if match:
                    metadata[name] = match.group(1)
            count_match = re.search(r'"cve_count"\s*:\s*(\d+)', header)
            if count_match:
                metadata["cve_count"] = int(count_match.group(1))
        buffer = buffer[array_at + 1 :]
        break

    while True:
        buffer = buffer.lstrip(" \t\r\n,")
        if buffer.startswith("]"):
            return
        if not buffer:
            chunk = stream.read(1_048_576)
            if not chunk:
                raise ValueError(f"feed ended inside {key!r} array")
            buffer += chunk
            continue
        try:
            value, end = decoder.raw_decode(buffer)
        except json.JSONDecodeError:
            chunk = stream.read(1_048_576)
            if not chunk:
                raise ValueError(f"feed ended inside an object in {key!r} array")
            buffer += chunk
            continue
        if not isinstance(value, dict):
            raise ValueError(f"{key!r} contains a non-object value")
        yield value
        buffer = buffer[end:]


def english_description(record: dict[str, Any]) -> str:
    descriptions = record.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en" and isinstance(item.get("value"), str):
            return item["value"]
    return ""


def strings_below(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings_below(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings_below(child)


def record_cpes(record: dict[str, Any]) -> list[str]:
    return sorted({value for value in strings_below(record.get("configurations", [])) if value.startswith("cpe:2.3:")})


def affected_products(record: dict[str, Any]) -> list[str]:
    products: set[str] = set()
    for group in record.get("affected") or []:
        for item in group.get("affectedData") or []:
            vendor = str(item.get("vendor") or "").strip()
            product = str(item.get("product") or "").strip()
            if product and product.lower() != "n/a":
                products.add(f"{vendor} {product}".strip())
    return sorted(products)


def match_products(record: dict[str, Any]) -> tuple[list[str], list[str]]:
    description = english_description(record)
    cpes = record_cpes(record)
    affected = affected_products(record)
    matches: list[str] = []
    evidence: list[str] = []
    for spec in PRODUCT_SPECS:
        found: list[str] = []
        for fragment in spec["cpes"]:
            if any(fragment.lower() in cpe.lower() for cpe in cpes):
                found.append(f"CPE {fragment}")
        for pattern in spec["affected"]:
            if any(re.search(pattern, product, re.IGNORECASE) for product in affected):
                found.append(f"affected-product /{pattern}/")
        for pattern in spec["description"]:
            if re.search(pattern, description, re.IGNORECASE | re.DOTALL):
                found.append(f"description /{pattern}/")
        structured = any(item.startswith(("CPE ", "affected-product ")) for item in found)
        if not structured:
            if spec["slug"] == "outlook" and (
                ("Outlook Web Access" in description and not re.search(r"Microsoft Outlook (?!Web)", description))
                or "Apache POI" in description
                or "poi-scratchpad" in description
            ):
                found.clear()
            elif spec["slug"] == "evolution" and "News Evolution" in description:
                found.clear()
            elif spec["slug"] == "kmail-kontact" and any(
                name in description for name in ("Kamgaing Email System", "CGI Cafe KMail")
            ):
                found.clear()
        if found:
            matches.append(spec["slug"])
            evidence.extend(f"{spec['slug']}: {item}" for item in found)
    return matches, evidence


def fetch_snapshot(url: str) -> dict[str, Any]:
    local_feed = Path(url)
    if local_feed.is_file():
        source: BinaryIO = local_feed.open("rb")
        provenance_url = DEFAULT_FEED
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "lizard-mail-client-cve-matrix/1.0"})
        source = urllib.request.urlopen(request, timeout=120)
        provenance_url = url
    selected: list[dict[str, Any]] = []
    feed_metadata: dict[str, Any] = {}
    with source as response:
        hashing = HashingReader(response)
        with lzma.open(hashing, mode="rt", encoding="utf-8") as stream:
            for index, record in enumerate(
                iter_top_level_array(stream, "cve_items", feed_metadata), start=1
            ):
                products, evidence = match_products(record)
                if products:
                    selected.append(
                        {
                            "products": products,
                            "match_evidence": evidence,
                            "record": record,
                        }
                    )
                if index % 25_000 == 0:
                    print(f"scanned {index:,} NVD records; retained {len(selected):,}", file=sys.stderr)
    selected.sort(key=lambda item: item["record"].get("id", ""))
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    return {
        "schema_version": 1,
        "source": {
            "authority": "National Vulnerability Database",
            "transport": "fkie-cad/nvd-json-data-feeds NVD reconstruction",
            "url": provenance_url,
            "retrieved_at": timestamp,
            "compressed_sha256": hashing.sha256.hexdigest(),
            "compressed_bytes": hashing.bytes,
            "feed_timestamp": feed_metadata.get("timestamp"),
            "feed_name": feed_metadata.get("feed_name"),
            "feed_cve_count": feed_metadata.get("cve_count"),
            "selection": "structured CPE/CNA affected-product aliases plus narrow product-name description patterns",
        },
        "products": [
            {key: spec[key] for key in ("slug", "name", "scope")} for spec in PRODUCT_SPECS
        ],
        "vulnerabilities": selected,
    }


def metric(record: dict[str, Any]) -> tuple[str, float | None, str]:
    metrics = record.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        primary = next((item for item in values if item.get("type") == "Primary"), values[0])
        data = primary.get("cvssData") or {}
        severity = str(data.get("baseSeverity") or primary.get("baseSeverity") or "unknown").lower()
        score = data.get("baseScore")
        vector = str(data.get("vectorString") or "")
        return severity, float(score) if isinstance(score, (int, float)) else None, vector
    return "unknown", None, ""


def cwes(record: dict[str, Any]) -> list[str]:
    found = {
        item.get("value")
        for weakness in record.get("weaknesses") or []
        for item in weakness.get("description") or []
        if isinstance(item.get("value"), str) and item["value"].startswith("CWE-")
    }
    return sorted(found)


def references(record: dict[str, Any]) -> list[str]:
    return sorted(
        {
            item.get("url")
            for item in record.get("references") or []
            if isinstance(item.get("url"), str)
        }
    )


def classify_generic(record: dict[str, Any], products: list[str]) -> dict[str, str]:
    description = english_description(record)
    lower = description.lower()
    cwe_set = set(cwes(record))

    if str(record.get("vulnStatus", "")).lower() == "rejected":
        return result("other", "the source record was rejected", "rejected", "high", "NVD rejects the record; no Lizard prevention claim is made", "NVD record")

    browser_only = "thunderbird" in products and any(
        term in lower
        for term in (
            "javascript engine", "javascript jit", "spidermonkey", "webassembly", "web assembly",
            "webrtc", "webextensions", "webextension", "xul", "xpinstall", "service worker",
            "serviceworker", "webgl", "web audio", "mediastream", "media stream", "pdf viewer",
            "browser chrome", "browser ui", "url bar", "address bar", "browsing history",
            "private browsing", "same-origin policy", "cross-origin", "cookie jar", "browser tab",
            "developer tools", "devtools", "fullscreen api", "pointer lock", "web authentication",
            "webauthn", "websocket", "web socket", "http/2", "http3", "http/3",
            "web content", "web page", "remote web site", "browser context",
        )
    )
    if browser_only:
        return result(
            "browser-engine",
            "a browser-only Gecko/SpiderMonkey/media/extension surface tagged as affecting Thunderbird exposed the defect",
            "not_applicable",
            "medium",
            "Lizard has no JavaScript/JIT, WebExtension, XUL, WebRTC, browser-navigation or browser-storage runtime",
            "README.md; src/dom.rs; spec/tui-html-profile.md",
        )

    windows_only = any(
        term in lower
        for term in (
            "activex", "component object model", "com object", "ole object", "windows registry",
            "ntlm", "unc path", "preview pane", "rich text format", "rtf message", "pst file",
            "microsoft word", "office document", "exchange web services", "mapi",
        )
    )
    if windows_only:
        return result(
            "platform-integration",
            "a Windows/Office-specific parser, handler or authentication integration exposed the defect",
            "not_applicable",
            "medium",
            "Lizard has no COM/OLE/ActiveX/RTF/PST/MAPI/NTLM or Office preview-handler surface",
            "Cargo.toml; crates/mail-tui/src; spec/tui-render-isolation.md",
        )

    if "s/mime" in lower or "smime" in lower:
        return result(
            "message-crypto",
            "the affected behavior is specific to S/MIME certificate or content processing",
            "not_applicable",
            "high",
            "Lizard currently implements OpenPGP, not S/MIME",
            "crates/mail-backend/src/openpgp.rs; spec/mail-backend.md",
        )

    if any(term in lower for term in ("javascript", "cross-site scripting", "script execution", "xss")) or cwe_set & {"CWE-79", "CWE-80", "CWE-83"}:
        return result(
            "active-content",
            "sender-controlled active content reached an executable browser or UI context",
            "fail_closed",
            "high",
            "Lizard's mail HTML profile has no script execution, forms or browser navigation context",
            "src/dom.rs; src/style.rs; spec/tui-html-profile.md",
        )

    if any(term in lower for term in ("remote image", "remote content", "tracking pixel", "refresh operation", "external resource", "loads a url")):
        return result(
            "remote-content",
            "sender content caused an unsolicited external request or disclosed message-open state",
            "prevented",
            "high",
            "render workers have no network authority; remote URLs remain inert evidence until a separate user-authorized policy acts",
            "README.md; spec/tui-render-isolation.md; spec/security-ui.md",
        )

    if any(term in lower for term in ("starttls", "certificate hostname", "certificate validation", "ssl certificate", "tls certificate")):
        return result(
            "transport-security",
            "TLS upgrade or peer-identity state was not bound to the authenticated mail transport",
            "prevented",
            "medium",
            "IMAP and SMTP require the configured TLS mode, use rustls hostname verification, and do not authenticate from pre-STARTTLS capabilities",
            "crates/mail-backend/src/imap_engine.rs; crates/mail-backend/src/smtp.rs; vendor/async-imap/src/client.rs",
        )

    if any(term in lower for term in ("buffer overflow", "use-after-free", "use after free", "out-of-bounds", "out of bounds", "double free", "memory corruption", "heap overflow", "stack overflow")) or cwe_set & {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126", "CWE-787", "CWE-416", "CWE-415"}:
        return result(
            "memory-safety",
            "attacker-controlled mail or server data violated a native memory/lifetime boundary",
            "partial",
            "medium",
            "safe Rust removes the same native corruption primitive in maintained code and workers are isolated, but external parsers/codecs and small unsafe adapters remain trusted",
            "docs/verification.md; spec/imap-sync-isolation.md; spec/tui-render-isolation.md",
        )

    if any(term in lower for term in ("integer overflow", "integer underflow", "signedness")) or cwe_set & {"CWE-190", "CWE-191", "CWE-681"}:
        return result(
            "integer-boundary",
            "attacker-controlled arithmetic crossed a machine-sized integer boundary",
            "partial",
            "medium",
            "critical resource counters use checked or Verus-verified arithmetic, but this is not a whole-program arithmetic proof",
            "crates/verified-kernel/src/lib.rs; docs/verification.md",
        )

    if any(term in lower for term in ("denial of service", "resource exhaustion", "infinite loop", "excessive", "hang", "crash", "memory consumption", "cpu consumption")) or cwe_set & {"CWE-400", "CWE-770", "CWE-835", "CWE-1333"}:
        return result(
            "resource-exhaustion",
            "attacker-controlled parsing, allocation or work lacked a complete resource bound",
            "partial",
            "medium",
            "Lizard has message, response, storage, renderer and process budgets, but does not yet prove a global linear work/allocation bound",
            "crates/verified-kernel/src/lib.rs; docs/verification.md; spec/imap-sync-isolation.md; spec/tui-render-isolation.md",
        )

    if any(term in lower for term in ("spoof", "homograph", "display name", "sender address", "address book", "wrong origin", "incorrect origin")):
        return result(
            "identity-ui",
            "attacker-controlled identity or origin metadata was presented as application-authored fact",
            "partial",
            "medium",
            "Lizard records authentication/contact evidence and specifies claim-aware identity UI, but the complete graphical presentation is not implemented or verified",
            "spec/security-ui.md; crates/mail-backend/src/identity.rs; crates/mail-backend/src/security.rs",
        )

    if any(term in lower for term in ("openpgp", "pgp", "encrypted message", "encrypted email", "signature verification")):
        return result(
            "message-crypto",
            "OpenPGP message construction, verification or presentation admitted an unsafe state",
            "partial",
            "medium",
            "Lizard uses bounded rPGP processing, protected headers and a conversation no-downgrade policy, but rPGP and interoperability remain trusted boundaries",
            "crates/mail-backend/src/openpgp.rs; crates/mail-backend/src/sending.rs; docs/verification.md",
        )

    if any(term in lower for term in ("imap", "pop3", "smtp server", "mail server")):
        return result(
            "mail-protocol",
            "a malicious or confused mail-server protocol state reached unsafe client behavior",
            "partial",
            "medium",
            "IMAP/SMTP use bounded safe-Rust state machines and IMAP is process-isolated, but the entire protocol parser and transaction composition are not formally verified",
            "vendor/async-imap/src; crates/mail-backend/src/imap_engine.rs; crates/mail-backend/src/smtp.rs; spec/imap-sync-isolation.md",
        )

    if any(term in lower for term in ("mime", "rfc 822", "rfc822", "mail header", "email header", "message header", "attachment name", "content-type")):
        return result(
            "mail-parser",
            "malformed message structure or metadata escaped parser assumptions",
            "partial",
            "medium",
            "raw messages, MIME trees and attachments are bounded and treated as untrusted, but mail-parser and archive/codec internals remain trusted boundaries",
            "crates/mail-backend/src/mime.rs; crates/mail-backend/src/security.rs; docs/verification.md",
        )

    if any(term in lower for term in ("temporary file", "symlink", "directory traversal", "path traversal", "arbitrary file", "file overwrite")) or cwe_set & {"CWE-22", "CWE-59", "CWE-73"}:
        return result(
            "filesystem",
            "attacker-controlled names or filesystem races escaped the intended profile/blob boundary",
            "partial",
            "medium",
            "blob writes use private profile paths and atomic creation, while workers have restricted filesystem authority; complete export/import path reasoning is not formally verified",
            "crates/mail-backend/src/blob.rs; crates/mail-backend/src/lifecycle.rs; spec/imap-sync-isolation.md",
        )

    if any(term in lower for term in ("command injection", "execute arbitrary command", "shell command", "argument injection")) or cwe_set & {"CWE-77", "CWE-78", "CWE-88"}:
        return result(
            "external-handler",
            "message data reached a command or external-handler boundary without a safe typed interface",
            "not_applicable",
            "medium",
            "the current client does not execute message-supplied commands or launch attachment handlers, and render workers cannot execute processes",
            "spec/tui-render-isolation.md; crates/mail-tui/src",
        )

    if any(term in lower for term in ("password", "credential", "authentication", "oauth", "access token")):
        return result(
            "authentication",
            "credential or authentication state was exposed or bound to the wrong principal",
            "not_covered",
            "low",
            "credentials are opaque references and isolated from workers, but the disclosed product-specific flow needs individual comparison before claiming prevention",
            "crates/mail-backend/src/credential.rs; spec/imap-sync-isolation.md",
        )

    if any(term in lower for term in ("permission bypass", "permissions bypass", "privilege escalation", "sandbox escape", "application sandbox", "local malicious application")) or cwe_set & {"CWE-269", "CWE-276", "CWE-284", "CWE-862", "CWE-863"}:
        return result(
            "platform-isolation",
            "local application permissions or a platform sandbox failed to preserve the intended authority boundary",
            "partial",
            "low",
            "mail/render workers are isolated from credentials and unrelated profile data on supported Linux hosts, but the whole application and other platforms are not covered by one authority proof",
            "spec/imap-sync-isolation.md; spec/tui-render-isolation.md; docs/verification.md",
        )

    if "thunderbird" in products and any(term in lower for term in ("web content", "browser", "web page", "webextension")):
        return result(
            "browser-engine",
            "a browser/XUL/web-extension surface shared with Thunderbird exposed the defect",
            "not_applicable",
            "medium",
            "Lizard is not a browser and has no JavaScript, XUL or WebExtension runtime",
            "README.md; src/dom.rs; spec/tui-html-profile.md",
        )

    return result(
        "other",
        "the public record does not identify a root cause that can be mapped conservatively by the current rules",
        "needs_review",
        "low",
        "no Lizard prevention claim is made without advisory or patch-level review",
        "NVD/CNA description",
    )


def result(surface: str, root_cause: str, status: str, confidence: str, mapping: str, evidence: str) -> dict[str, str]:
    return {
        "surface": surface,
        "root_cause": root_cause,
        "status": status,
        "confidence": confidence,
        "mapping": mapping,
        "evidence": evidence,
    }


def matrix_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in snapshot["vulnerabilities"]:
        record = item["record"]
        cve_id = record["id"]
        products = item["products"]
        severity, score, vector = metric(record)
        if cve_id in MANUAL:
            analysis = MANUAL[cve_id]
            method = "manual_override"
            basis = "advisory/root-cause review and Lizard implementation comparison"
        else:
            analysis = classify_generic(record, products)
            method = "conservative_rule"
            basis = "NVD/CNA description, CWE and Lizard feature-boundary comparison"
        status = analysis["status"]
        rows.append(
            {
                "id": cve_id,
                "year": int(cve_id.split("-")[1]),
                "published": record.get("published", ""),
                "last_modified": record.get("lastModified", ""),
                "vuln_status": record.get("vulnStatus", ""),
                "products": products,
                "severity": severity,
                "score": score,
                "vector": vector,
                "cwes": cwes(record),
                "status": status,
                "lizard_prevents": "yes" if status in {"prevented", "fail_closed", "not_applicable"} else "partial" if status == "partial" else "no",
                "surface": analysis["surface"],
                "root_cause": analysis["root_cause"],
                "confidence": analysis["confidence"],
                "classification_method": method,
                "analysis_basis": basis,
                "lizard_mapping": analysis["mapping"],
                "implementation_evidence": analysis["evidence"],
                "description": english_description(record),
                "vulnerable_cpes": record_cpes(record),
                "references": references(record),
                "match_evidence": item["match_evidence"],
            }
        )
    return rows


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = list(rows[0]) if rows else ["id"]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "; ".join(value) if isinstance(value, list) else value for key, value in row.items()})


def render_summary(snapshot: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    product_names = {item["slug"]: item["name"] for item in snapshot["products"]}
    product_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        for product in row["products"]:
            product_rows[product].append(row)
    status_counts = Counter(row["status"] for row in rows)
    manual_count = sum(row["classification_method"] == "manual_override" for row in rows)
    high_open = [
        row
        for row in rows
        if row["severity"] in {"high", "critical"}
        and row["status"] in {"partial", "not_covered", "needs_review"}
    ]
    high_open.sort(
        key=lambda row: (
            0 if row["severity"] == "critical" else 1,
            -row["year"],
            row["id"],
        )
    )
    open_surfaces = Counter(row["surface"] for row in high_open)
    priority_rows: list[dict[str, Any]] = []
    priority_ids: set[str] = set()
    for spec in PRODUCT_SPECS:
        added = 0
        for row in high_open:
            if spec["slug"] not in row["products"] or row["id"] in priority_ids:
                continue
            priority_rows.append(row)
            priority_ids.add(row["id"])
            added += 1
            if added == 10:
                break
    lines = [
        "# Mail-client CVE root-cause matrix",
        "",
        f"NVD feed timestamp: `{snapshot['source'].get('feed_timestamp')}`; filtered on",
        f"`{snapshot['source']['retrieved_at']}` from the NVD reconstruction at",
        f"`{snapshot['source']['url']}`. The filtered source records, exact match evidence and",
        "compressed-feed SHA-256 are retained in `mail-client-nvd.json`.",
        "",
        "This is a static root-cause/design comparison, not a PoC replay result and not a",
        "ranking of product security. Public CVE counts are strongly affected by product age,",
        "shared-engine tagging, vendor CNA practice and disclosure transparency. In particular,",
        "a zero or low count is **not** evidence that a proprietary or mobile client is safer.",
        "",
        f"Rows: **{len(rows)}** distinct CVEs; explicit overrides: **{manual_count}**;",
        f"conservative rules: **{len(rows) - manual_count}**.",
        "",
        "## Product coverage",
        "",
        "| product | records | high/critical open | needs review |",
        "|---|---:|---:|---:|",
    ]
    for spec in PRODUCT_SPECS:
        selected = product_rows.get(spec["slug"], [])
        open_count = sum(
            row["severity"] in {"high", "critical"}
            and row["status"] in {"partial", "not_covered", "needs_review"}
            for row in selected
        )
        review_count = sum(row["status"] == "needs_review" for row in selected)
        lines.append(f"| {spec['name']} | {len(selected)} | {open_count} | {review_count} |")
    lines += [
        "",
        "Rows can name more than one product, so product counts do not sum to the distinct total.",
        "",
        "## Lizard comparison",
        "",
        "| classification | count |",
        "|---|---:|",
    ]
    for status in STATUS_ORDER:
        lines.append(f"| `{status}` | {status_counts[status]} |")
    lines += [
        "",
        "`prevented`, `fail_closed` and `not_applicable` describe the disclosed primitive or",
        "feature boundary only. They do not mean Lizard is vulnerability-free in that subsystem.",
        "A `partial` row is deliberately not counted as prevented.",
        "",
        f"## High/critical open review set ({len(high_open)})",
        "",
        "| surface | rows |",
        "|---|---:|",
    ]
    for surface, count in sorted(open_surfaces.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| `{surface}` | {count} |")
    lines += [
        "",
        f"### Cross-product priority sample ({len(priority_rows)} of {len(high_open)})",
        "",
        "For each product family, this shows up to ten newest critical rows followed by newest",
        "high rows. Shared rows are shown once. The complete open set remains in the JSON and",
        "CSV ledgers.",
        "",
        "| CVE | products | severity | surface | root cause | Lizard comparison |",
        "|---|---|---|---|---|---|",
    ]
    for row in priority_rows:
        products = ", ".join(product_names.get(item, item) for item in row["products"])
        cells = [row["id"], products, row["severity"], row["surface"], row["root_cause"], row["lizard_mapping"]]
        cells = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells]
        lines.append("| " + " | ".join(cells) + " |")
    lines += [
        "",
        "The complete per-CVE ledger, vulnerable CPEs, match evidence, implementation evidence",
        "and advisory links are in `mail-client-cve-matrix.json` and `.csv`.",
        "",
    ]
    return "\n".join(lines)


def build(snapshot: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    selected = {
        item["record"]["id"]: set(item["products"])
        for item in snapshot["vulnerabilities"]
    }
    for cve_id, product in EXPECTED_MATCHES.items():
        if product not in selected.get(cve_id, set()):
            raise ValueError(f"selection regression: {cve_id} must match {product}")
    leaked = sorted(EXPECTED_EXCLUDED & selected.keys())
    if leaked:
        raise ValueError("description-only false positives returned: " + ", ".join(leaked))
    rows = matrix_rows(snapshot)
    ids = [row["id"] for row in rows]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("snapshot must contain unique CVEs in lexical order")
    return rows, render_summary(snapshot, rows)


def generated_bytes(snapshot: dict[str, Any]) -> dict[Path, bytes]:
    rows, summary = build(snapshot)
    matrix_json = (json.dumps(rows, indent=2, ensure_ascii=False) + "\n").encode()
    csv_buffer = io.StringIO(newline="")
    fields = list(rows[0]) if rows else ["id"]
    writer = csv.DictWriter(csv_buffer, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: "; ".join(value) if isinstance(value, list) else value for key, value in row.items()})
    return {
        MATRIX_JSON: matrix_json,
        MATRIX_CSV: csv_buffer.getvalue().encode(),
        SUMMARY_MD: summary.encode(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true", help="refresh the filtered NVD snapshot")
    parser.add_argument("--feed", default=DEFAULT_FEED, help="xz feed URL used with --fetch")
    parser.add_argument("--check", action="store_true", help="verify generated outputs are current")
    args = parser.parse_args()

    DOCS.mkdir(parents=True, exist_ok=True)
    if args.fetch:
        snapshot = fetch_snapshot(args.feed)
        if args.check:
            raise SystemExit("--fetch and --check are mutually exclusive")
        write_json(SNAPSHOT, snapshot)
    else:
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))

    outputs = generated_bytes(snapshot)
    if args.check:
        stale = [str(path.relative_to(ROOT)) for path, data in outputs.items() if not path.exists() or path.read_bytes() != data]
        if stale:
            print("stale generated files: " + ", ".join(stale), file=sys.stderr)
            return 1
        print(f"valid: {len(snapshot['vulnerabilities'])} CVEs across {len(PRODUCT_SPECS)} product families")
        return 0

    for path, data in outputs.items():
        path.write_bytes(data)
    rows, _ = build(snapshot)
    counts = Counter(row["status"] for row in rows)
    print(f"wrote {len(rows)} rows: " + ", ".join(f"{key}={counts[key]}" for key in STATUS_ORDER))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
