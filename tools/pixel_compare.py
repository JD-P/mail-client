"""Exact document pixels with explicit, bounded raster-only exceptions."""
import math
from PIL import Image, ImageChops, ImageStat


def rgba(source):
    return source.convert('RGBA') if isinstance(source, Image.Image) else Image.open(source).convert('RGBA')


def changed(image):
    return sum(any(pixel) for pixel in image.get_flattened_data())


def validate_tolerance(policy, size):
    required = {'regions', 'max_channel_delta', 'max_mean_channel_delta', 'reason'}
    if set(policy) != required or not isinstance(policy['reason'], str) or not policy['reason'].strip():
        raise ValueError('Image tolerance needs explicit regions, limits and a reason')
    for key in ('max_channel_delta', 'max_mean_channel_delta'):
        value = policy[key]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 255:
            raise ValueError('Invalid image tolerance limit')
    regions = policy['regions']
    if not isinstance(regions, list) or not 1 <= len(regions) <= 32:
        raise ValueError('Image tolerance needs 1..32 fixture-authored regions')
    boxes = []
    for region in regions:
        if not isinstance(region, list) or len(region) != 4 or any(type(n) is not int for n in region):
            raise ValueError('Image region must be integer x,y,width,height')
        x, y, w, h = region
        if min(x, y) < 0 or min(w, h) <= 0 or x + w > size[0] or y + h > size[1]:
            raise ValueError('Image region outside the reference viewport')
        box = (x, y, x + w, y + h)
        if any(max(x, a) < min(x + w, c) and max(y, b) < min(y + h, d) for a, b, c, d in boxes):
            raise ValueError('Image tolerance regions must not overlap')
        boxes.append(box)
    return boxes


def compare(a, b, image_tolerance=None):
    a, b = rgba(a), rgba(b)
    if a.size != b.size:
        return {'size_mismatch': [a.size, b.size], 'passed': False, 'image_tolerance_pass': False}, None
    diff = ImageChops.difference(a, b)
    alpha = diff.getchannel('A')
    visual = Image.merge('RGB', tuple(ImageChops.lighter(diff.getchannel(c), alpha) for c in 'RGB'))
    metrics = {
        'different_pixels': changed(diff),
        'max_difference': max(high for low, high in diff.getextrema()),
        'mean_rgb_error': ImageStat.Stat(diff.convert('RGB')).mean,
        'passed': not diff.getbbox(alpha_only=False),
        'image_tolerance_pass': False,
    }
    if image_tolerance is not None:
        boxes = validate_tolerance(image_tolerance, a.size)
        outside = diff.copy()
        measured = []
        for region, box in zip(image_tolerance['regions'], boxes):
            crop = diff.crop(box)
            rgb = crop.convert('RGB')
            maximum = max(high for low, high in rgb.getextrema())
            means = ImageStat.Stat(rgb).mean
            measured.append({
                'region': region,
                'different_pixels': changed(crop),
                'max_rgb_delta': maximum,
                'mean_rgb_delta': means,
                'within_limits': maximum <= image_tolerance['max_channel_delta'] and all(n <= image_tolerance['max_mean_channel_delta'] for n in means),
            })
            outside.paste((0, 0, 0, 0), box)
        details = {
            'reason': image_tolerance['reason'],
            'max_channel_delta': image_tolerance['max_channel_delta'],
            'max_mean_channel_delta': image_tolerance['max_mean_channel_delta'],
            'regions': measured,
            'outside_different_pixels': changed(outside),
            'alpha_exact': alpha.getbbox() is None,
        }
        metrics['image_tolerance'] = details
        metrics['image_tolerance_pass'] = details['outside_different_pixels'] == 0 and details['alpha_exact'] and all(r['within_limits'] for r in measured)
    return metrics, visual


def acceptance(metrics, dom_match, geometry_match):
    strict = bool(metrics.get('passed') and dom_match and geometry_match)
    accepted = bool((metrics.get('passed') or metrics.get('image_tolerance_pass')) and dom_match and geometry_match)
    return {'strict_pass': strict, 'policy_pass': accepted, 'accepted_with_image_tolerance': accepted and not strict}
