#!/usr/bin/env python3
"""Validate the independent mail-client adversarial JSONL index."""

from datetime import datetime
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
INDEX = Path(__file__).resolve().parent
FAMILIES = {
    "code_execution",
    "authority_bypass",
    "information_disclosure",
    "integrity_violation",
    "server_request_abuse",
    "protocol_confusion",
    "cryptographic_trust_failure",
    "denial_of_service",
    "memory_safety",
    "unclassified",
}
IMPACTS = {"low": 1, "medium": 10, "high": 100, "critical": 1000, "catastrophic": 10000}


def load(name):
    records = []
    for number, line in enumerate((INDEX / name).read_text().splitlines(), 1):
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise AssertionError(f"{name}:{number}: {error}") from error
    return records


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    search_records = load("searches.jsonl")
    findings = load("findings.jsonl")
    searches = {item["search_id"]: item for item in search_records if item["record_type"] == "search"}
    segments = {item["segment_id"]: item for item in search_records if item["record_type"] == "segment"}
    engagements = {item["engagement_id"]: item for item in search_records if item["record_type"] == "engagement"}
    assert len(searches) == sum(item["record_type"] == "search" for item in search_records), "duplicate search ID"
    assert len(segments) == sum(item["record_type"] == "segment" for item in search_records), "duplicate segment ID"
    assert len(engagements) == sum(item["record_type"] == "engagement" for item in search_records), "duplicate engagement ID"

    claims = set()
    adjusted = 0.0
    for finding in findings:
        assert finding["record_type"] == "finding"
        claim = finding["claim_id"]
        assert claim not in claims, f"duplicate claim {claim}"
        claims.add(claim)
        assert finding["search_id"] in searches, f"{claim}: missing search"
        assert finding["engagement_id"] in engagements, f"{claim}: missing engagement"
        assert finding["primary_family"] in FAMILIES, f"{claim}: invalid family"
        assert set(finding["secondary_families"]) <= FAMILIES
        assert finding["impact_tier"] in IMPACTS
        composition = finding["composition"]
        count = composition["unintended_behavior_count"]
        assert count >= 1 and count == len(composition["unintended_behaviors"])
        assert composition["remediation_component_count"] == len(composition["remediation_components"])
        if finding["disposition"] == "confirmed":
            adjusted += IMPACTS[finding["impact_tier"]] * 2 ** (1 - count)
        for reference in finding["source_refs"]:
            path = reference.get("path")
            if path:
                assert (ROOT / path).exists(), f"{claim}: missing source ref {path}"

    for search_id, search in searches.items():
        assert search["engagement_id"] in engagements
        assert set(search["segment_ids"]) <= segments.keys()
        assert set(search["finding_ids"]) <= claims
        assert set(search["confirmed_finding_ids"]) <= claims
        for segment_id in search["segment_ids"]:
            segment = segments[segment_id]
            assert segment["search_id"] == search_id
            if segment["ended_at"] is not None:
                assert timestamp(segment["ended_at"]) >= timestamp(segment["started_at"])
        if search["completed"]:
            assert all(segments[item]["termination_status"] == "completed" for item in search["segment_ids"])
            assert all(segments[item]["ended_at"] is not None for item in search["segment_ids"])

    print(
        f"valid: {len(searches)} search(es), {len(segments)} segment(s), "
        f"{len(findings)} finding(s), {adjusted:.1f} adjusted point(s)"
    )


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError) as error:
        print(f"invalid: {error}", file=sys.stderr)
        raise SystemExit(1)

