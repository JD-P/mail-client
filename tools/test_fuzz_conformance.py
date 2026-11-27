import hashlib
import base64
import io
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import fuzz_conformance as fuzz
import fuzz_cases
from PIL import Image


class GeneratorTests(unittest.TestCase):
    def test_generation_is_replayable_and_shard_independent(self):
        first = fuzz.generate_case(1234, 27)
        second = fuzz.generate_case(1234, 27)
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first.source).digest(), hashlib.sha256(second.source).digest())
        self.assertNotEqual(first.source, fuzz.generate_case(1234, 35).source)

    def test_legacy_campaign_bytes_remain_replayable(self):
        case = fuzz.generate_case(
            0x4C495A41,
            0,
            fuzz.LEGACY_FAMILIES,
            ((360, 260),),
        )
        self.assertEqual(
            hashlib.sha256(case.source).hexdigest(),
            "73c0ee2c42c6b671e92f5e434f58471256285366fbf8319b64e6ba24caba1f75",
        )

    def test_every_family_stays_inside_inert_local_profile(self):
        for index, family in enumerate(fuzz.FAMILIES):
            case = fuzz.generate_case(99, index)
            self.assertEqual(case.family, family)
            source = case.source.lower()
            self.assertNotIn(b"<script", source)
            self.assertNotIn(b"javascript:", source)
            self.assertNotIn(b"http://", source)
            self.assertNotIn(b"https://", source)
            self.assertIn(b"<!doctype html>", source)

    def test_composition_recursively_combines_email_structures(self):
        cases = [
            fuzz.generate_case(77, index)
            for index in range(8, len(fuzz.FAMILIES) * 8, len(fuzz.FAMILIES))
        ]
        source = b"\n".join(case.source.lower() for case in cases)
        for token in (b"<table", b"<ul", b"<a ", b"<img", b"dir=", b"float:"):
            self.assertIn(token, source)
        self.assertIn(b"<!--fuzz-node:", source)
        self.assertIn(b"scrollbar-width:none", source)
        self.assertTrue(all(case.family == "composition" for case in cases))

    def test_sanitized_seed_cases_are_local_and_use_each_template(self):
        seen = set()
        for ordinal in range(len(fuzz_cases.PAIRWISE_PLANS["seed"])):
            index = 9 + ordinal * len(fuzz.FAMILIES)
            case = fuzz.generate_case(91, index)
            self.assertEqual(case.family, "seed")
            fuzz_cases.validate_inert_source(case.source)
            seen.add(dict(case.factors)["template"])
            self.assertNotIn(b"FUZZ_SLOT", case.source)
        self.assertEqual(seen, set(fuzz_cases.SEED_NAMES))

    def test_viewports_rotate_by_complete_family_block(self):
        viewports = ((111, 222), (333, 444))
        first = fuzz.generate_case(1, 0, fuzz.FAMILIES, viewports)
        same_block = fuzz.generate_case(1, len(fuzz.FAMILIES) - 1, fuzz.FAMILIES, viewports)
        next_block = fuzz.generate_case(1, len(fuzz.FAMILIES), fuzz.FAMILIES, viewports)
        self.assertEqual((first.width, first.height), viewports[0])
        self.assertEqual((same_block.width, same_block.height), viewports[0])
        self.assertEqual((next_block.width, next_block.height), viewports[1])

    def test_pairwise_plans_cover_every_declared_target(self):
        for family, domains in fuzz_cases.PAIRWISE_DOMAINS.items():
            observed = set()
            for packed in fuzz_cases.PAIRWISE_PLANS[family]:
                observed.update(fuzz_cases.config_pairs(dict(packed)))
            self.assertEqual(observed, fuzz_cases.pair_targets(domains), family)

    def test_200_case_campaign_reaches_declared_pairwise_coverage(self):
        rows = []
        for index in range(200):
            case = fuzz.generate_case(123, index)
            rows.append(
                {
                    "family": case.family,
                    "viewport": f"{case.width}x{case.height}",
                    "factors": dict(case.factors),
                    "features": list(case.features),
                }
            )
        coverage = fuzz_cases.coverage_report(rows, fuzz.FAMILIES, fuzz.DEFAULT_VIEWPORTS)
        self.assertEqual(coverage["percent"], 100.0)

    def test_structural_reducer_removes_complete_marked_subtree(self):
        source = b"<div>A<!--fuzz-node:7:start--><table><tr><td>X</td></tr></table><!--fuzz-node:7:end-->B</div>"
        candidates = list(fuzz_cases.marked_node_reductions(source))
        self.assertEqual(candidates, [b"<div>AB</div>"])

    def test_css_rule_reducer_preserves_document_prefix(self):
        source = b'<!doctype html><style>html,body{margin:0}.x{color:red}</style><div class="x">X</div>'
        candidates = list(fuzz_cases.rule_reductions(source))
        self.assertEqual(
            candidates,
            [b'<!doctype html><style>html,body{margin:0}</style><div class="x">X</div>'],
        )

    def test_embedded_fuzz_image_is_valid(self):
        image = Image.open(io.BytesIO(base64.b64decode(fuzz.PNG_DATA)))
        image.load()
        self.assertEqual(image.size, (8, 4))

    def test_declaration_reduction_does_not_rewrite_remaining_bytes(self):
        source = b"<style>.a{width:20px;height:30px;background:red}</style>"
        candidates = list(fuzz.declaration_reductions(source))
        self.assertTrue(candidates)
        self.assertIn(b"width:20px", candidates[0])
        self.assertNotIn(b"background:red", candidates[0])

    def test_declaration_reduction_stops_at_inline_style_quote(self):
        source = b'<div style="width:20px;height:30px">Body</div>'
        candidates = list(fuzz.declaration_reductions(source))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0], b'<div style="width:20px;">Body</div>')


class ClassificationTests(unittest.TestCase):
    def test_failure_precedence(self):
        self.assertEqual(fuzz.failure_kind({"timed_out": True}), "timeout")
        self.assertEqual(fuzz.failure_kind({"exit_code": 9}), "crash")
        self.assertEqual(fuzz.failure_kind({"exit_code": 0, "dom_match": False}), "dom")
        self.assertEqual(
            fuzz.failure_kind({"exit_code": 0, "dom_match": True, "geometry_match": False}),
            "geometry",
        )
        self.assertEqual(
            fuzz.failure_kind({"exit_code": 0, "dom_match": True, "geometry_match": True, "different_pixels": 1}),
            "pixels",
        )

    def test_pixel_failures_are_minimizable(self):
        self.assertTrue(
            fuzz.minimizable_failure(
                {"exit_code": 0, "dom_match": True, "geometry_match": True, "different_pixels": 1}
            )
        )
        self.assertFalse(fuzz.minimizable_failure({"oracle_error": "unavailable"}))

    def test_failure_buckets_keep_viewports_distinct(self):
        base = {
            "family": "composition",
            "exit_code": 0,
            "dom_match": True,
            "geometry_match": True,
            "different_pixels": 4,
            "max_difference": 2,
        }
        narrow = fuzz.failure_signature({**base, "viewport": "320x240"})
        wide = fuzz.failure_signature({**base, "viewport": "800x600"})
        self.assertNotEqual(narrow, wide)

    def test_kind_scope_allows_structural_signature_to_change(self):
        row = {"failure_kind": "geometry", "signature": "geometry:new"}
        self.assertFalse(fuzz.minimization_match(row, "geometry:old", "geometry", "signature"))
        self.assertTrue(fuzz.minimization_match(row, "geometry:old", "geometry", "kind"))


if __name__ == "__main__":
    unittest.main()
