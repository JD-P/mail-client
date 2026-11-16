# Lizard development

Preserve the requested feature profile; track actual implementation separately.
The original fixture bytes must reach Gecko and Lizard independently. Never
normalize a fixture using Lizard before supplying it to Gecko. Exact pixels
are the default; annotate and justify any future per-test raster tolerance.

Prefer indexed owned arenas, explicit budgets and integer/rational geometry in
the core. Keep parsing/font/codec/OS adapters identifiable. Keep the executable
Verus kernel single-source; do not replace checked functions with merely
similar Rust implementations or prove duplicated model functions instead.
Never label the whole engine verified after checking only kernel contracts.

Validate child output even if its producer is written in Rust or verified.
Keep render workers disposable, without filesystem/network/display authority.
Do not add capabilities or automatic resource fetching to fix a rendering test.

Run relevant tests and the strict independent Gecko comparison after behavior
changes. Retain failing cases and report the limits of coverage honestly.

Image raster allowances are permitted only in explicit fixture-authored media
rectangles with stated per-pixel and mean RGB limits and a reason. Do not derive
these rectangles from Lizard's reported geometry or observed difference pixels.
Keep DOM, emitted-box geometry, alpha and all surrounding document pixels exact.
Retain both strict and policy pass counts; --strict-images must restore exact
comparison. Never describe an image-tolerated case as a pixel-perfect match.
