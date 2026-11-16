#!/usr/bin/env python3
"""Independent Gecko regression runner; exact metrics survive image allowances."""
import argparse
import datetime
import hashlib
import html
import json
import pathlib
import platform
import subprocess
from oracle import Gecko, ORACLE_CODE_SHA256, ORACLE_ENVIRONMENT
from pixel_compare import compare, acceptance

ROOT = pathlib.Path(__file__).resolve().parents[1]


def canon(node):
    kinds = {'Document': 9, 'Element': 1, 'Text': 3, 'Comment': 8}
    return (kinds.get(node['kind'], node['kind']), node['tag'], node['text'], sorted(node['attrs']), node['parent'], tuple(node['children']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--firefox', required=True)
    parser.add_argument('--geckodriver', required=True)
    parser.add_argument('--filter', default='')
    parser.add_argument('--reuse-oracle', action='store_true')
    parser.add_argument('--strict-images', action='store_true', help='Disable fixture-authored image RGB allowances')
    parser.add_argument('--output', default='results/conformance')
    args = parser.parse_args()
    out = ROOT / args.output
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'tests/fixtures/manifest.json').read_text())
    cases = [c for c in manifest['cases'] if args.filter in c['name']]
    oracle, rows = None, []
    try:
        for case in cases:
            name = case['name']
            path = ROOT / case['file']
            source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            prefix = out / (name + '-gecko')
            cached = json.loads(prefix.with_suffix('.json').read_text()) if args.reuse_oracle and prefix.with_suffix('.json').exists() else None
            valid_cache = cached and cached.get('source_sha256') == source_hash and cached.get('width') == case['width'] and cached.get('height') == case['height'] and cached.get('oracle_code_sha256') == ORACLE_CODE_SHA256 and cached.get('environment_fingerprint') == ORACLE_ENVIRONMENT
            if not valid_cache:
                if oracle is None:
                    oracle = Gecko(args.firefox, args.geckodriver, out)
                oracle.capture(path, case['width'], case['height'], prefix)
            reference = json.loads(prefix.with_suffix('.json').read_text())
            assert reference['source_sha256'] == source_hash, ('stale oracle', name)
            run = subprocess.run([str(pathlib.Path(args.binary).resolve()), 'render', str(path), str(out / (name + '-lizard.png')), str(case['width']), str(case['height']), str(out / (name + '-lizard.json'))], capture_output=True, text=True, timeout=15)
            row = {'name': name, 'features': case['features'], 'source_sha256': source_hash, 'exit_code': run.returncode, 'stderr': run.stderr[-4000:]}
            if run.returncode == 0:
                allowance = None if args.strict_images else case.get('image_raster_tolerance')
                metrics, diff = compare(out / (name + '-lizard.png'), prefix.with_suffix('.png'), allowance)
                row.update(metrics)
                if diff is not None:
                    diff.save(out / (name + '-diff.png'))
                ours = json.loads((out / (name + '-lizard.json')).read_text())
                row['dom_match'] = [canon(n) for n in ours['document']['nodes']] == [canon(n) for n in reference['nodes']]
                differences, compared = [], 0
                if row['dom_match']:
                    for i, (node, box) in enumerate(zip(ours['document']['nodes'], ours['scene']['boxes'])):
                        if not node['tag'] or box is None:
                            continue
                        expected = reference['nodes'][i].get('rect')
                        if expected is None:
                            continue
                        compared += 1
                        delta = {k: box['border'][k] - round(expected[k] * 60) for k in ['x', 'y', 'w', 'h']}
                        if any(delta.values()):
                            differences.append({'node': i, 'tag': node['tag'], 'delta_app_units': delta})
                row.update(box_probes_compared=compared, box_differences=differences, geometry_match=row['dom_match'] and not differences)
                row.update(acceptance(metrics, row['dom_match'], row['geometry_match']))
            else:
                row.update(passed=False, strict_pass=False, policy_pass=False, accepted_with_image_tolerance=False)
            rows.append(row)
            label = 'EXACT' if row['strict_pass'] else 'IMAGE TOLERANCE' if row['policy_pass'] else 'FAIL'
            print(name, label, row.get('different_pixels', 'crash'), flush=True)
    finally:
        if oracle:
            oracle.close()
    result = {
        'cases': len(rows),
        'strict_passes': sum(r['strict_pass'] for r in rows),
        'strict_failures': sum(not r['strict_pass'] for r in rows),
        'policy_passes': sum(r['policy_pass'] for r in rows),
        'tolerated_image_cases': sum(r['accepted_with_image_tolerance'] for r in rows),
        'failures': sum(not r['policy_pass'] for r in rows),
        'policy': 'Exact DOM, emitted-box app-unit geometry, alpha, and pixels outside annotated image regions; bounded per-fixture RGB allowances inside those regions. Exact metrics are retained.',
        'strict_images': args.strict_images,
        'results': rows,
        'environment': {
            'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'platform': platform.platform(),
            'lizard_binary_sha256': hashlib.sha256(pathlib.Path(args.binary).read_bytes()).hexdigest(),
            'cargo_lock_sha256': hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest(),
            'manifest_sha256': hashlib.sha256((ROOT / 'tests/fixtures/manifest.json').read_bytes()).hexdigest(),
            'runner_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            'pixel_compare_sha256': hashlib.sha256((ROOT / 'tools/pixel_compare.py').read_bytes()).hexdigest(),
            'oracle_code_sha256': ORACLE_CODE_SHA256,
            'font_freetype_fingerprint': ORACLE_ENVIRONMENT,
        },
    }
    (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    esc = lambda text: html.escape(str(text))
    body = []
    for row in rows:
        label = 'EXACT' if row['strict_pass'] else 'IMAGE TOLERANCE' if row['policy_pass'] else 'FAIL'
        allowance = row.get('image_tolerance')
        note = ('Outside: ' + str(allowance['outside_different_pixels']) + '; RGB limits ' + str(allowance['max_channel_delta']) + ' max / ' + str(allowance['max_mean_channel_delta']) + ' mean per channel. ' + allowance['reason']) if allowance else 'Exact pixels required.'
        links = ''.join('<a href="' + row['name'] + suffix + '.png">' + label + '</a> ' for suffix, label in [('-gecko', 'Gecko'), ('-lizard', 'Lizard'), ('-diff', 'Diff')]) if row['exit_code'] == 0 else esc(row['stderr'])
        body.append('<tr><td>' + esc(row['name']) + '</td><td>' + label + '</td><td>' + esc(row.get('different_pixels', 'error')) + '</td><td>' + esc(row.get('max_difference', '')) + '</td><td>' + esc(str(row.get('dom_match', '')) + ' / ' + str(row.get('geometry_match', ''))) + '</td><td>' + esc(note) + '</td><td>' + links + '</td></tr>')
    description = f"{result['policy_passes']} / {len(rows)} pass the configured policy: {result['strict_passes']} exact and {result['tolerated_image_cases']} with an explicit image allowance. {result['failures']} failures remain."
    (out / 'report.html').write_text('<!doctype html><meta charset="utf-8"><title>Lizard conformance</title><style>body{font:16px/1.5 system-ui;margin:35px}table{border-collapse:collapse}td,th{padding:8px 14px;border:1px solid #ddd}th{background:#e8eef4}</style><h1>Lizard / Gecko 160 differential results</h1><p>' + esc(description) + '</p><p>DOM, alpha, emitted-box geometry and non-image pixels remain exact. Only fixture-authored image regions permit bounded RGB differences. Missing element boxes are outside geometry probe coverage. Exact differences and failed cases are retained.</p><table><tr><th>Case</th><th>Result</th><th>Changed pixels</th><th>Max delta</th><th>DOM / geometry</th><th>Image allowance</th><th>Images</th></tr>' + ''.join(body) + '</table>')
    print(json.dumps({k: v for k, v in result.items() if k != 'results'}))
    return 0 if result['failures'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
