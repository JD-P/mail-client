"""Ensure image allowances cannot hide layout, clipping or document regressions."""
import copy
import unittest
from PIL import Image, ImageDraw, ImageChops
from pixel_compare import compare, acceptance


class ImageAllowanceTests(unittest.TestCase):
    def setUp(self):
        self.reference = Image.new('RGBA', (16, 16), 'white')
        draw = ImageDraw.Draw(self.reference)
        draw.rectangle((4, 4, 7, 7), fill='red')
        draw.rectangle((8, 4, 11, 7), fill='green')
        draw.rectangle((4, 8, 11, 11), fill='blue')
        self.policy = {'regions': [[4, 4, 8, 8]], 'max_channel_delta': 32, 'max_mean_channel_delta': 3.0, 'reason': 'Isolated synthetic raster; surrounding document remains strict.'}

    def test_exact_is_still_reported_as_exact(self):
        metrics, _ = compare(self.reference, self.reference, self.policy)
        self.assertEqual(acceptance(metrics, True, True), {'strict_pass': True, 'policy_pass': True, 'accepted_with_image_tolerance': False})

    def test_small_raster_change_is_explicitly_tolerated(self):
        candidate = self.reference.copy()
        candidate.putpixel((4, 4), (235, 0, 0, 255))
        metrics, _ = compare(candidate, self.reference, self.policy)
        self.assertEqual(acceptance(metrics, True, True), {'strict_pass': False, 'policy_pass': True, 'accepted_with_image_tolerance': True})
        self.assertEqual(metrics['different_pixels'], 1)
        self.assertEqual(metrics['image_tolerance']['outside_different_pixels'], 0)
        strict, _ = compare(candidate, self.reference)
        self.assertFalse(acceptance(strict, True, True)['policy_pass'])

    def test_one_changed_non_image_pixel_fails(self):
        candidate = self.reference.copy()
        candidate.putpixel((0, 0), (254, 255, 255, 255))
        metrics, _ = compare(candidate, self.reference, self.policy)
        self.assertFalse(metrics['image_tolerance_pass'])
        self.assertEqual(metrics['image_tolerance']['outside_different_pixels'], 1)

    def test_alpha_is_exact_even_inside_an_image(self):
        candidate = self.reference.copy()
        candidate.putpixel((4, 4), (255, 0, 0, 254))
        metrics, _ = compare(candidate, self.reference, self.policy)
        self.assertFalse(metrics['image_tolerance']['alpha_exact'])
        self.assertFalse(metrics['image_tolerance_pass'])

    def test_large_missing_shifted_and_overpainted_images_fail(self):
        missing = Image.new('RGBA', (16, 16), 'white')
        shifted = ImageChops.offset(self.reference, 1, 0)
        wrong_crop = self.reference.copy()
        wrong_crop.paste(self.reference.crop((4, 4, 12, 12)).transpose(Image.Transpose.FLIP_LEFT_RIGHT), (4, 4))
        text = self.reference.copy()
        ImageDraw.Draw(text).line((4, 4, 11, 4), fill='black')
        for candidate in [missing, shifted, wrong_crop, text]:
            with self.subTest(candidate=candidate):
                metrics, _ = compare(candidate, self.reference, self.policy)
                self.assertFalse(acceptance(metrics, True, True)['policy_pass'])

    def test_maximum_and_mean_limits_are_both_enforced(self):
        candidate = self.reference.copy()
        candidate.putpixel((4, 4), (222, 0, 0, 255))
        metrics, _ = compare(candidate, self.reference, self.policy)
        self.assertFalse(metrics['image_tolerance_pass'])
        candidate = self.reference.copy()
        for y in range(4, 12):
            for x in range(4, 12):
                r, g, b, a = candidate.getpixel((x, y))
                candidate.putpixel((x, y), (r - 10 if r >= 10 else r + 10, g, b, a))
        metrics, _ = compare(candidate, self.reference, self.policy)
        region = metrics['image_tolerance']['regions'][0]
        self.assertLessEqual(region['max_rgb_delta'], 32)
        self.assertGreater(region['mean_rgb_delta'][0], 3)
        self.assertFalse(metrics['image_tolerance_pass'])

    def test_dom_geometry_and_viewport_cannot_be_waived(self):
        metrics, _ = compare(self.reference, self.reference, self.policy)
        for dom, geometry in [(False, True), (True, False), (False, False)]:
            self.assertFalse(acceptance(metrics, dom, geometry)['policy_pass'])
        different_size = Image.new('RGBA', (17, 16), 'white')
        metrics, _ = compare(different_size, self.reference, self.policy)
        self.assertFalse(acceptance(metrics, True, True)['policy_pass'])

    def test_invalid_annotations_fail_closed(self):
        policies = []
        for regions in [[], [[4, 4, 100, 8]], [[4, 4, 8, 8], [5, 5, 1, 1]], [[4.0, 4, 8, 8]]]:
            bad = copy.deepcopy(self.policy)
            bad['regions'] = regions
            policies.append(bad)
        bad = copy.deepcopy(self.policy)
        bad['max_channel_delta'] = float('nan')
        policies.append(bad)
        for bad in policies:
            with self.assertRaises(ValueError):
                compare(self.reference, self.reference, bad)


if __name__ == '__main__':
    unittest.main()
