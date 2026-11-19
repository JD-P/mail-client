import hashlib
import base64
import io
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import fuzz_conformance as fuzz
from PIL import Image


class GeneratorTests(unittest.TestCase):
    def test_generation_is_replayable_and_shard_independent(self):
        first = fuzz.generate_case(1234, 27)
        second = fuzz.generate_case(1234, 27)
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first.source).digest(), hashlib.sha256(second.source).digest())
        self.assertNotEqual(first.source, fuzz.generate_case(1234, 35).source)

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


if __name__ == "__main__":
    unittest.main()
