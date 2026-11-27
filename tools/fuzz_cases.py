"""Compositional cases, seed mutation, coverage and shrinking for renderer fuzzing.

This module is intentionally independent of Lizard.  It creates inert HTML
bytes which are handed unchanged to both Gecko and Lizard by the differential
runner.  All resources are local literals and every generator has hard bounds.
"""

from __future__ import annotations

import dataclasses
import hashlib
import html
import itertools
import pathlib
import random
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
SEED_DIRECTORY = ROOT / "tests" / "fuzz-seeds"
EXTENDED_FAMILIES = ("composition", "seed")
DEFAULT_VIEWPORTS = ((320, 240), (360, 260), (600, 480), (800, 600))
PNG_DATA = (
    "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAECAYAAACzzX7wAAAAI0lEQVR4nGP8z8Dw"
    "nwEJMDYwoAAmBgKAkYHh/380IUaSTAAAurEEhuaPW40AAAAASUVORK5CYII="
)
RESET = (
    "html,body{margin:0;padding:0;background:white}"
    'body{font:16px/24px "DejaVu Sans";color:#111}'
    "p{margin:0}"
)


@dataclasses.dataclass(frozen=True)
class CaseParts:
    source: bytes
    features: tuple[str, ...]
    factors: tuple[tuple[str, str], ...]


def choice(rng: random.Random, values):
    return values[rng.randrange(len(values))]


def document(style: str, body: str) -> bytes:
    return (
        '<!doctype html><meta charset="utf-8"><style>'
        + RESET
        + style
        + "</style>"
        + body
    ).encode("utf-8")


def validate_inert_source(source: bytes) -> None:
    """Reject authority-bearing or unexpectedly large generated documents."""

    if len(source) > 256 * 1024:
        raise ValueError("fuzz source exceeds 256 KiB")
    lower = source.lower()
    if b"<!doctype html" not in lower:
        raise ValueError("fuzz source lacks an HTML doctype")
    forbidden = (
        b"<script",
        b"<iframe",
        b"<object",
        b"<embed",
        b"<form",
        b"<link",
        b"javascript:",
        b"http://",
        b"https://",
        b"@import",
        b"url(",
        b"http-equiv=\"refresh",
        b"http-equiv='refresh",
    )
    found = next((token for token in forbidden if token in lower), None)
    if found is not None:
        raise ValueError(f"fuzz source contains forbidden token {found!r}")
    if re.search(rb"\son[a-z0-9_-]+\s*=", lower):
        raise ValueError("fuzz source contains an event handler")


COMPOSITION_DOMAINS = {
    "shell": ("div", "table"),
    "max_depth": ("2", "3", "4"),
    "direction": ("ltr", "rtl", "mixed"),
    "float": ("none", "left", "right"),
    "table_layout": ("auto", "fixed"),
    "list_style": ("disc", "square", "decimal", "lower-roman"),
    "image_fit": ("contain", "cover", "fill", "none"),
    "link_style": ("inline", "button", "image"),
    "columns": ("stacked", "two-cell"),
}

SEED_NAMES = ("mailgun-action", "mailgun-basic", "cerberus-hybrid")
SEED_DOMAINS = {
    "template": SEED_NAMES,
    "container_width": ("320", "480", "600"),
    "direction": ("ltr", "rtl", "mixed"),
    "placement": ("top", "main", "bottom"),
    "slot_depth": ("1", "2", "3"),
    "table_layout": ("auto", "fixed"),
    "image_fit": ("contain", "cover"),
    "density": ("compact", "normal", "roomy"),
}

PAIRWISE_DOMAINS = {
    "composition": COMPOSITION_DOMAINS,
    "seed": SEED_DOMAINS,
}


def _pair(left_axis: str, left_value: str, right_axis: str, right_value: str):
    left = (left_axis, str(left_value))
    right = (right_axis, str(right_value))
    return (left, right) if left_axis < right_axis else (right, left)


def pair_targets(domains: dict[str, tuple[str, ...]]) -> set[tuple[tuple[str, str], tuple[str, str]]]:
    axes = sorted(domains)
    return {
        _pair(left, left_value, right, right_value)
        for left, right in itertools.combinations(axes, 2)
        for left_value in domains[left]
        for right_value in domains[right]
    }


def config_pairs(config: dict[str, str]) -> set[tuple[tuple[str, str], tuple[str, str]]]:
    return {
        _pair(left, config[left], right, config[right])
        for left, right in itertools.combinations(sorted(config), 2)
    }


def pairwise_plan(domains: dict[str, tuple[str, ...]]) -> tuple[tuple[tuple[str, str], ...], ...]:
    """Build a deterministic greedy all-pairs plan for independent factors."""

    uncovered = pair_targets(domains)
    axes = sorted(domains)
    plan: list[tuple[tuple[str, str], ...]] = []
    while uncovered:
        first = min(uncovered)
        config = {first[0][0]: first[0][1], first[1][0]: first[1][1]}
        for axis in axes:
            if axis in config:
                continue
            candidates = []
            for value in domains[axis]:
                added = sum(
                    _pair(axis, value, other_axis, other_value) in uncovered
                    for other_axis, other_value in config.items()
                )
                candidates.append((added, value))
            config[axis] = max(candidates, key=lambda item: (item[0], item[1]))[1]
        uncovered.difference_update(config_pairs(config))
        plan.append(tuple(sorted(config.items())))
    return tuple(plan)


PAIRWISE_PLANS = {family: pairwise_plan(domains) for family, domains in PAIRWISE_DOMAINS.items()}


def planned_factors(family: str, seed: int, ordinal: int) -> dict[str, str]:
    plan = PAIRWISE_PLANS[family]
    digest = hashlib.sha256(f"{seed}:{family}:pairwise".encode()).digest()
    offset = int.from_bytes(digest[:4], "big") % len(plan)
    return dict(plan[(ordinal + offset) % len(plan)])


class Composer:
    """Bounded recursive email-fragment generator with removable node markers."""

    def __init__(self, rng: random.Random, config: dict[str, str], budget: int = 64):
        self.rng = rng
        self.config = config
        self.budget = budget
        self.serial = 0
        self.structures: set[str] = set()

    def marker(self, markup: str) -> str:
        self.serial += 1
        ident = self.serial
        return f"<!--fuzz-node:{ident}:start-->{markup}<!--fuzz-node:{ident}:end-->"

    def text(self, value: str) -> str:
        self.serial += 1
        ident = self.serial
        return f"<!--fuzz-text:{ident}:start-->{html.escape(value)}<!--fuzz-text:{ident}:end-->"

    def consume(self, structure: str) -> bool:
        self.structures.add(structure)
        if self.budget <= 0:
            return False
        self.budget -= 1
        return True

    def inline(self, force_bidi: bool = False) -> str:
        self.consume("inline")
        phrases = (
            "Your receipt is ready for review.",
            "Alpha beta gamma-delta needs attention.",
            "The project update includes three changes.",
            "Invoice 42 is available in your account.",
        )
        base = self.text(choice(self.rng, phrases))
        direction = self.config["direction"]
        if force_bidi or direction == "mixed":
            self.structures.add("bidi")
            base += ' <span dir="rtl">' + self.text("مرحبا אבגדה") + "</span>"
        elif direction == "rtl":
            self.structures.add("bidi")
            base = '<span dir="rtl">' + self.text("مرحبا بالعالم sample") + "</span>"
        link_style = self.config.get("link_style", "inline")
        self.structures.add("link")
        if link_style == "button":
            link = (
                '<a href="#account" style="display:inline-block;padding:6px 10px;'
                'border:1px solid #246;background:#def;color:#123">Open account</a>'
            )
        elif link_style == "image":
            link = (
                f'<a href="#details"><img alt="Details" width="16" height="8" '
                f'src="data:image/png;base64,{PNG_DATA}"></a>'
            )
        else:
            link = '<a href="#details" style="color:#246;text-decoration:underline">details</a>'
        return base + " " + link

    def image(self, floated: str | None = None) -> str:
        if not self.consume("image"):
            return self.marker('<span style="background:#def">image</span>')
        side = floated if floated is not None else "none"
        float_css = "" if side == "none" else f"float:{side};margin:0 8px 4px 0;"
        markup = (
            f'<img alt="Color sample" width="48" height="28" '
            f'style="{float_css}width:48px;height:28px;object-fit:{self.config["image_fit"]};'
            'border:2px solid #345;padding:2px;background:#eef" '
            f'src="data:image/png;base64,{PNG_DATA}">'
        )
        return self.marker(markup)

    def paragraph(self, force_bidi: bool = False) -> str:
        if not self.consume("text"):
            return self.text("x")
        return self.marker(
            '<p style="margin:3px 0;overflow-wrap:anywhere">'
            + self.inline(force_bidi=force_bidi)
            + "</p>"
        )

    def listing(self, depth: int) -> str:
        if not self.consume("list"):
            return self.paragraph()
        items = [self.inline(), self.inline(force_bidi=depth % 2 == 0)]
        if depth < int(self.config["max_depth"]) and self.budget > 5:
            items.append(self.block(depth + 1))
        markup = (
            f'<ul style="margin:4px 0;padding-left:28px;list-style-type:{self.config["list_style"]}">'
            + "".join(f"<li>{item}</li>" for item in items)
            + "</ul>"
        )
        return self.marker(markup)

    def table(self, depth: int) -> str:
        if not self.consume("table"):
            return self.paragraph()
        nested = self.paragraph(force_bidi=True)
        if depth < int(self.config["max_depth"]) and self.budget > 8:
            nested = self.block(depth + 1)
        markup = (
            f'<table role="presentation" style="width:100%;table-layout:{self.config["table_layout"]};'
            'border-collapse:collapse;background:#f6f7f8"><tbody>'
            '<tr><td rowspan="2" style="width:34%;padding:5px;border:1px solid #789">'
            + nested
            + '</td><td style="padding:5px;border:1px solid #789">'
            + self.inline()
            + '</td></tr><tr><td style="padding:5px;border:1px solid #789">'
            + self.inline(force_bidi=True)
            + "</td></tr></tbody></table>"
        )
        return self.marker(markup)

    def floating(self) -> str:
        if not self.consume("float"):
            return self.paragraph()
        side = self.config["float"]
        markup = '<div style="display:block;min-height:38px;background:#fff8df;padding:4px">'
        markup += self.image(floated=side)
        markup += self.inline(force_bidi=True)
        if side != "none":
            markup += '<div style="clear:both;height:1px"></div>'
        markup += "</div>"
        return self.marker(markup)

    def container(self, depth: int) -> str:
        if not self.consume("container"):
            return self.paragraph()
        children = [self.block(depth + 1), self.block(depth + 1)]
        if self.config["columns"] == "two-cell":
            markup = (
                '<table role="presentation" style="width:100%;border-spacing:4px"><tr>'
                + "".join(f'<td style="width:50%;vertical-align:top">{child}</td>' for child in children)
                + "</tr></table>"
            )
        else:
            markup = '<div style="padding:4px;border-left:3px solid #79a">' + "".join(children) + "</div>"
        return self.marker(markup)

    def block(self, depth: int = 0) -> str:
        maximum = int(self.config["max_depth"])
        if depth >= maximum or self.budget < 5:
            return self.paragraph(force_bidi=depth % 2 == 1)
        kind = choice(self.rng, ("text", "list", "table", "image", "container", "float"))
        if kind == "list":
            return self.listing(depth)
        if kind == "table":
            return self.table(depth)
        if kind == "image":
            return self.marker('<div style="padding:3px">' + self.image() + self.inline() + "</div>")
        if kind == "container":
            return self.container(depth)
        if kind == "float":
            return self.floating()
        return self.paragraph(force_bidi=depth % 2 == 1)

    def body(self, compact: bool = False) -> str:
        """Guarantee all important email structures, plus a recursive subtree."""

        gap = "2px" if compact else "6px"
        required = [
            self.paragraph(force_bidi=True),
            self.table(0),
            self.listing(0),
            self.floating(),
            self.marker('<div style="padding:3px">' + self.image() + self.inline() + "</div>"),
            self.container(0),
        ]
        self.rng.shuffle(required)
        return f'<div class="fuzz-root" style="padding:{gap}">' + "".join(required) + "</div>"


def composition_case(rng: random.Random, config: dict[str, str]) -> CaseParts:
    composer = Composer(rng, config)
    direction = "ltr" if config["direction"] == "mixed" else config["direction"]
    body = composer.body()
    if config["shell"] == "table":
        body = (
            f'<table dir="{direction}" role="presentation" style="width:100%;border-collapse:collapse">'
            f'<tr><td style="vertical-align:top">{body}</td></tr></table>'
        )
    else:
        body = f'<div dir="{direction}" style="max-width:580px">{body}</div>'
    source = document(
        "html{scrollbar-width:none}"
        ".fuzz-root a{color:#245;text-decoration:underline}"
        ".fuzz-root img{max-width:100%}"
        "@media (max-width:360px){.fuzz-root{font-size:14px}}",
        body,
    )
    validate_inert_source(source)
    features = (
        "composition-recursive",
        "html-table",
        "html-list",
        "html-anchor-links",
        "html-img",
        "css-float",
        "css-direction",
        "css-inline-formatting",
    )
    return CaseParts(source, features, tuple(sorted(config.items())))


def seed_paths() -> dict[str, pathlib.Path]:
    return {name: SEED_DIRECTORY / f"{name}.html" for name in SEED_NAMES}


def seed_corpus_sha256() -> str:
    digest = hashlib.sha256()
    for name, path in sorted(seed_paths().items()):
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _seed_fragment(rng: random.Random, config: dict[str, str]) -> str:
    composition_config = {
        "shell": "div",
        "max_depth": config["slot_depth"],
        "direction": config["direction"],
        "float": choice(rng, ("none", "left", "right")),
        "table_layout": config["table_layout"],
        "list_style": choice(rng, COMPOSITION_DOMAINS["list_style"]),
        "image_fit": config["image_fit"],
        "link_style": choice(rng, COMPOSITION_DOMAINS["link_style"]),
        "columns": choice(rng, COMPOSITION_DOMAINS["columns"]),
    }
    return Composer(rng, composition_config, budget=38).body(compact=config["density"] == "compact")


def seed_case(rng: random.Random, config: dict[str, str]) -> CaseParts:
    path = seed_paths()[config["template"]]
    source = path.read_text(encoding="utf-8")
    # Lizard renders into a fixed canvas and has no browser scrollbar chrome.
    # Keep Gecko's reference viewport equivalent when a realistic seed grows
    # taller than the selected fuzz viewport.  Composition cases already carry
    # this reset through `document()`; seed templates need it injected here.
    source, style_count = re.subn(
        r"(<style(?:\s[^>]*)?>)",
        r"\1html{scrollbar-width:none}",
        source,
        count=1,
        flags=re.I,
    )
    if style_count != 1:
        raise ValueError(f"seed template {path.name} lacks a style element")
    fragment = _seed_fragment(rng, config)
    for placement in ("top", "main", "bottom"):
        marker = f"<!--FUZZ_SLOT_{placement.upper()}-->"
        source = source.replace(marker, fragment if placement == config["placement"] else "")
    source = source.replace("max-width:600px", f'max-width:{config["container_width"]}px')
    source = source.replace("table-layout:auto", f'table-layout:{config["table_layout"]}')
    source = source.replace("object-fit:contain", f'object-fit:{config["image_fit"]}')
    source = source.replace('dir="ltr"', f'dir="{config["direction"] if config["direction"] != "mixed" else "ltr"}"')
    padding = {"compact": "8px", "normal": "16px", "roomy": "24px"}[config["density"]]
    source = source.replace("padding:16px", f"padding:{padding}")
    encoded = source.encode("utf-8")
    validate_inert_source(encoded)
    features = (
        "seed-real-email-template",
        "composition-recursive",
        "html-table",
        "html-anchor-links",
        "html-img",
        "css-at-media",
    )
    return CaseParts(encoded, features, tuple(sorted(config.items())))


def extended_case(family: str, seed: int, ordinal: int, rng: random.Random) -> CaseParts:
    config = planned_factors(family, seed, ordinal)
    if family == "composition":
        return composition_case(rng, config)
    if family == "seed":
        return seed_case(rng, config)
    raise KeyError(family)


def parse_viewport(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"([1-9][0-9]{1,3})x([1-9][0-9]{1,3})", value.lower())
    if not match:
        raise ValueError("viewport must be WIDTHxHEIGHT using values from 10 through 9999")
    return int(match.group(1)), int(match.group(2))


def viewport_for(index: int, family_count: int, viewports: tuple[tuple[int, int], ...]) -> tuple[int, int]:
    # A complete family block advances the viewport.  F*V consecutive cases
    # therefore cover every selected family at every selected viewport.
    return viewports[(index // family_count) % len(viewports)]


def coverage_report(rows, families: tuple[str, ...], viewports: tuple[tuple[int, int], ...]):
    global_targets = {
        (family, f"{width}x{height}") for family in families for width, height in viewports
    }
    global_observed = {
        (row["family"], row["viewport"])
        for row in rows
        if row.get("family") in families and row.get("viewport")
    }
    sections = []
    missing_records = []
    covered_total = len(global_targets & global_observed)
    target_total = len(global_targets)
    sections.append(
        {
            "name": "family-by-viewport",
            "covered": covered_total,
            "total": target_total,
            "percent": round(100 * covered_total / target_total, 2) if target_total else 100.0,
        }
    )
    for family, domains in PAIRWISE_DOMAINS.items():
        if family not in families:
            continue
        targets = pair_targets(domains)
        observed = set()
        for row in rows:
            if row.get("family") != family:
                continue
            factors = {str(key): str(value) for key, value in row.get("factors", {}).items()}
            if set(factors) == set(domains):
                observed.update(config_pairs(factors))
        covered = targets & observed
        covered_total += len(covered)
        target_total += len(targets)
        missing = sorted(targets - observed)
        sections.append(
            {
                "name": family,
                "covered": len(covered),
                "total": len(targets),
                "percent": round(100 * len(covered) / len(targets), 2),
            }
        )
        for left, right in missing[:20]:
            missing_records.append(
                {"family": family, "left": list(left), "right": list(right)}
            )
    feature_pairs = set()
    for row in rows:
        features = sorted(set(row.get("features", ())))
        feature_pairs.update(itertools.combinations(features, 2))
    return {
        "covered": covered_total,
        "total": target_total,
        "percent": round(100 * covered_total / target_total, 2) if target_total else 100.0,
        "sections": sections,
        "missing_sample": missing_records[:40],
        "observed_feature_pairs": len(feature_pairs),
    }


NODE_START = re.compile(rb"<!--fuzz-node:([0-9]+):start-->")
TEXT_START = re.compile(rb"<!--fuzz-text:([0-9]+):start-->")
STYLE_BLOCK = re.compile(rb"<style(?:\s[^>]*)?>(?P<body>.*?)</style\s*>", re.I | re.S)
RULE = re.compile(rb"(?P<selector>[^{}]+)\{(?P<body>[^{}]*)\}")
ATTRIBUTE = re.compile(
    rb"\s(?:style|class|dir|width|height|rowspan|colspan|align|valign)=(?:\"[^\"]*\"|'[^']*')",
    re.I,
)


def marked_node_reductions(source: bytes):
    """Remove one complete generated subtree while leaving other bytes exact."""

    for match in reversed(list(NODE_START.finditer(source))):
        end_token = f"<!--fuzz-node:{match.group(1).decode()}:end-->".encode()
        end = source.find(end_token, match.end())
        if end >= 0:
            yield source[: match.start()] + source[end + len(end_token) :]


def marked_text_reductions(source: bytes):
    for match in reversed(list(TEXT_START.finditer(source))):
        end_token = f"<!--fuzz-text:{match.group(1).decode()}:end-->".encode()
        end = source.find(end_token, match.end())
        if end >= 0 and source[match.end() : end] != b"x":
            yield source[: match.end()] + b"x" + source[end:]


def rule_reductions(source: bytes):
    reductions = []
    for style in STYLE_BLOCK.finditer(source):
        body_start = style.start("body")
        for match in RULE.finditer(style.group("body")):
            selector = match.group("selector").strip().lower()
            if (
                selector in (b"html,body", b"body", b"p")
                or b"@media" in selector
                or b"scrollbar-width:none" in match.group("body").replace(b" ", b"").lower()
            ):
                continue
            reductions.append((body_start + match.start(), body_start + match.end()))
    for start, end in reversed(reductions):
        yield source[:start] + source[end:]


def attribute_reductions(source: bytes):
    for match in reversed(list(ATTRIBUTE.finditer(source))):
        yield source[: match.start()] + source[match.end() :]


def structural_reductions(source: bytes):
    """Yield bounded, byte-preserving structural simplifications."""

    seen = set()
    for reducer in (marked_node_reductions, marked_text_reductions, rule_reductions, attribute_reductions):
        for candidate in reducer(source):
            digest = hashlib.sha256(candidate).digest()
            if digest not in seen:
                seen.add(digest)
                yield candidate
