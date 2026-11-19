# Retained Gecko differential failures

These are minimized, deterministic failures from seed `0x4c495a41` of
`tools/fuzz_conformance.py`. They remain outside the passing fixture manifest
until Lizard matches Gecko exactly. Re-run the seeded campaign after changing
layout or text shaping; the fuzzer records the exact failure signatures and
preserves the original source bytes independently for each renderer.

- `empty-inline-super.html`: an empty vertically aligned inline still enlarges
  Gecko's line box.
- `mixed-bidi-spacing-wrap.html`: mixed Arabic, Latin and Hebrew with negative
  letter spacing wraps one line earlier in Gecko.
- `rowspan-table-min-width.html`: the auto table algorithm over-constrains a
  definite-width rowspan cell.
- `inside-disc-marker.html`: geometry agrees, but the shaped inside marker does
  not yet reproduce Gecko's graphical marker pixels.
- `inside-square-marker.html`: the same remaining raster issue for square
  inside markers.
- `inline-vertical-metrics.html`: tall `middle`-aligned inline blocks now have
  matching box geometry, but retain a paint-level mismatch.
- `long-break-word.html`: deprecated `word-break: break-word` now wraps with
  matching geometry, while its transformed/decorated text still differs in
  strict pixels.
