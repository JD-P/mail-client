#![forbid(unsafe_code)]
use crate::{core::*, css, dom::*};
use serde::Serialize;
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum Unit {
    #[default]
    Px,
    Percent,
    Em,
    Rem,
    Ex,
    Ch,
    Vw,
    Vh,
}
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Length {
    pub n: i64,
    pub unit: Unit,
    pub extra: [i64; 8],
}
impl Length {
    pub fn px(n: i64) -> Self {
        Self {
            n: n * PX,
            unit: Unit::Px,
            extra: [0; 8],
        }
    }
    pub fn eval(self, basis: Au, font: Au, root: Au, vw: Au, vh: Au) -> Au {
        let scales = [0, basis, font, root, font / 2, font / 2, vw, vh];
        let index = unit_index(self.unit);
        let relative = |coefficient: i64, scale: Au, round: bool| {
            let numerator = coefficient as i128 * scale as i128;
            if round && numerator >= 0 {
                (numerator + 5000) / 10000
            } else if round {
                (numerator - 5000) / 10000
            } else {
                numerator / 10000
            }
        };
        let mut result = if index == 0 {
            self.n as i128
        } else {
            // Gecko rounds em lengths to the nearest app unit. Percentage
            // table tracks, by contrast, retain their floor allocation, so
            // rounding every relative unit regresses fixed table geometry.
            relative(self.n, scales[index], index == 2)
        };
        for (i, n) in self.extra.iter().enumerate() {
            result += if i == 0 {
                *n as i128
            } else {
                relative(*n, scales[i], i == 2)
            };
        }
        result.clamp(-(MAX_COORD as i128), MAX_COORD as i128) as Au
    }
}
fn unit_index(unit: Unit) -> usize {
    match unit {
        Unit::Px => 0,
        Unit::Percent => 1,
        Unit::Em => 2,
        Unit::Rem => 3,
        Unit::Ex => 4,
        Unit::Ch => 5,
        Unit::Vw => 6,
        Unit::Vh => 7,
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum Size {
    #[default]
    Auto,
    Length(Length),
    None,
}
impl Size {
    pub fn eval(self, basis: Au, font: Au, root: Au, vw: Au, vh: Au) -> Option<Au> {
        match self {
            Self::Length(l) => Some(l.eval(basis, font, root, vw, vh)),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum Display {
    None,
    #[default]
    Inline,
    Block,
    InlineBlock,
    Table,
    RowGroup,
    Row,
    Cell,
    Caption,
    ListItem,
}
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum Family {
    #[default]
    Serif,
    Sans,
    Mono,
    Arial,
    Times,
    Courier,
}
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum WhiteSpace {
    #[default]
    Normal,
    Nowrap,
    Pre,
    PreWrap,
    PreLine,
}
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum Align {
    #[default]
    Start,
    End,
    Left,
    Right,
    Center,
    Justify,
}
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum Float {
    #[default]
    None,
    Left,
    Right,
}
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum BorderStyle {
    #[default]
    None,
    Solid,
    Dotted,
    Dashed,
    Double,
    Groove,
    Ridge,
    Inset,
    Outset,
    Hidden,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Border {
    pub width: Au,
    pub color: u32,
    pub style: BorderStyle,
}
impl Default for Border {
    fn default() -> Self {
        Self {
            width: 3 * PX,
            color: 0,
            style: BorderStyle::None,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ColorStop {
    pub color: Option<u32>,
    pub position: Option<Length>,
}
#[derive(Clone, Debug, Serialize)]
pub struct LinearGradient {
    pub angle_mdeg: i32,
    pub stops: Vec<ColorStop>,
}
#[derive(Clone, Debug, Serialize)]
pub enum Background {
    Image(String),
    Linear(LinearGradient),
}
#[derive(Clone, Debug, Serialize)]
pub struct Style {
    pub display: Display,
    pub color: u32,
    pub background_color: u32,
    pub backgrounds: Vec<Background>,
    pub font: Family,
    pub font_size: Au,
    pub weight: u16,
    pub italic: bool,
    pub line_height: Au,
    pub line_height_factor: i64,
    pub normal_line_height: bool,
    pub kerning: bool,
    pub margin: Edges<Size>,
    pub padding: Edges<Length>,
    pub border: Edges<Border>,
    pub outline: Border,
    pub outline_offset: Au,
    pub radius: Au,
    pub radius_percent: Option<i64>,
    pub border_box: bool,
    pub width: Size,
    pub height: Size,
    pub min_width: Size,
    pub max_width: Size,
    pub min_height: Size,
    pub max_height: Size,
    pub whitespace: WhiteSpace,
    pub align: Align,
    pub direction_rtl: bool,
    pub visible: bool,
    pub opacity: u16,
    pub decoration: u8,
    pub decoration_color: u32,
    pub decoration_style: String,
    pub transform: String,
    pub vertical_align: String,
    pub indent: Length,
    pub letter_spacing: Au,
    pub word_spacing: Au,
    pub word_break: String,
    pub overflow_wrap: bool,
    pub overflow_hidden: bool,
    pub text_overflow: String,
    pub float: Float,
    pub clear: String,
    pub border_collapse: bool,
    pub border_spacing: (Au, Au),
    pub table_fixed: bool,
    pub empty_cells: bool,
    pub caption_bottom: bool,
    pub list_type: String,
    pub list_inside: bool,
    pub object_fit: String,
    pub object_position: String,
    pub background_size: String,
    pub background_position: String,
    pub background_repeat: String,
    pub background_clip: String,
    pub background_origin: String,
}
impl Default for Style {
    fn default() -> Self {
        Self {
            display: Display::Inline,
            color: 0x000000ff,
            background_color: 0,
            backgrounds: vec![],
            font: Family::Serif,
            font_size: 16 * PX,
            weight: 400,
            italic: false,
            line_height: 0,
            line_height_factor: 0,
            normal_line_height: true,
            kerning: true,
            margin: Edges {
                top: Size::Length(Length::default()),
                right: Size::Length(Length::default()),
                bottom: Size::Length(Length::default()),
                left: Size::Length(Length::default()),
            },
            padding: Edges::default(),
            border: Edges::default(),
            outline: Border {
                width: 3 * PX,
                color: 0x000000ff,
                style: BorderStyle::None,
            },
            outline_offset: 0,
            radius: 0,
            radius_percent: None,
            border_box: false,
            width: Size::Auto,
            height: Size::Auto,
            min_width: Size::Auto,
            max_width: Size::None,
            min_height: Size::Auto,
            max_height: Size::None,
            whitespace: WhiteSpace::Normal,
            align: Align::Start,
            direction_rtl: false,
            visible: true,
            opacity: 1000,
            decoration: 0,
            decoration_color: 0,
            decoration_style: "solid".into(),
            transform: "none".into(),
            vertical_align: "baseline".into(),
            indent: Length::default(),
            letter_spacing: 0,
            word_spacing: 0,
            word_break: "normal".into(),
            overflow_wrap: false,
            overflow_hidden: false,
            text_overflow: "clip".into(),
            float: Float::None,
            clear: "none".into(),
            border_collapse: false,
            border_spacing: (2 * PX, 2 * PX),
            table_fixed: false,
            empty_cells: true,
            caption_bottom: false,
            list_type: "disc".into(),
            list_inside: false,
            object_fit: "fill".into(),
            object_position: "50% 50%".into(),
            background_size: "auto".into(),
            background_position: "0% 0%".into(),
            background_repeat: "repeat".into(),
            background_clip: "border-box".into(),
            background_origin: "padding-box".into(),
        }
    }
}
fn inherited(parent: &Style) -> Style {
    Style {
        color: parent.color,
        font: parent.font,
        font_size: parent.font_size,
        weight: parent.weight,
        italic: parent.italic,
        line_height: parent.line_height,
        line_height_factor: parent.line_height_factor,
        normal_line_height: parent.normal_line_height,
        kerning: parent.kerning,
        whitespace: parent.whitespace,
        align: parent.align,
        direction_rtl: parent.direction_rtl,
        visible: parent.visible,
        decoration: parent.decoration,
        decoration_color: parent.decoration_color,
        decoration_style: parent.decoration_style.clone(),
        transform: parent.transform.clone(),
        letter_spacing: parent.letter_spacing,
        word_spacing: parent.word_spacing,
        word_break: parent.word_break.clone(),
        overflow_wrap: parent.overflow_wrap,
        border_collapse: parent.border_collapse,
        border_spacing: parent.border_spacing,
        empty_cells: parent.empty_cells,
        caption_bottom: parent.caption_bottom,
        indent: parent.indent,
        list_type: parent.list_type.clone(),
        list_inside: parent.list_inside,
        ..Style::default()
    }
}
fn simple_length(s: &str) -> Option<Length> {
    let mut p = cssparser::Parser::new(s.trim());
    let t = p.next().ok()?.clone();
    let (n, u) = match t {
        cssparser::Token::Number { value, .. } if value == 0.0 => (0.0, String::new()),
        cssparser::Token::Dimension { value, unit, .. } => (value, unit.to_ascii_lowercase()),
        cssparser::Token::Percentage { unit_value, .. } => (unit_value * 100.0, "%".into()),
        _ => return None,
    };
    p.expect_exhausted().ok()?;
    if !n.is_finite() || n.abs() > 1_000_000.0 {
        return None;
    }
    let n = n as f64;
    let (unit, value) = match u.as_str() {
        "" | "px" => (Unit::Px, n * 60.0),
        "pt" => (Unit::Px, n * 80.0),
        "pc" => (Unit::Px, n * 960.0),
        "in" => (Unit::Px, n * 5760.0),
        "cm" => (Unit::Px, n * 5760.0 / 2.54),
        "mm" => (Unit::Px, n * 5760.0 / 25.4),
        "%" => (Unit::Percent, n * 100.0),
        "em" => (Unit::Em, n * 10000.0),
        "rem" => (Unit::Rem, n * 10000.0),
        "ex" => (Unit::Ex, n * 10000.0),
        "ch" => (Unit::Ch, n * 10000.0),
        "vw" => (Unit::Vw, n * 100.0),
        "vh" => (Unit::Vh, n * 100.0),
        _ => return None,
    };
    Some(Length {
        n: value.round() as i64,
        unit,
        extra: [0; 8],
    })
}
pub fn size(s: &str) -> Option<Size> {
    match s.trim() {
        "auto" => Some(Size::Auto),
        "none" => Some(Size::None),
        _ => length(s).map(Size::Length),
    }
}
#[derive(Clone)]
enum Calc {
    Scalar(i64),
    Length([i64; 8]),
}
fn calc_scale(a: Calc, b: Calc, divide: bool) -> Option<Calc> {
    let scale = |v: i64, n: i64, d: i64| -> Option<i64> {
        if d == 0 {
            return None;
        }
        let r = v as i128 * n as i128 / d as i128;
        if r.abs() > 1_000_000_000_000 {
            return None;
        }
        Some(r as i64)
    };
    match (a, b) {
        (Calc::Scalar(a), Calc::Scalar(b)) => scale(
            a,
            if divide { 10000 } else { b },
            if divide { b } else { 10000 },
        )
        .map(Calc::Scalar),
        (Calc::Length(mut a), Calc::Scalar(b)) => {
            for v in &mut a {
                *v = scale(
                    *v,
                    if divide { 10000 } else { b },
                    if divide { b } else { 10000 },
                )?;
            }
            Some(Calc::Length(a))
        }
        (Calc::Scalar(a), Calc::Length(mut b)) if !divide => {
            for v in &mut b {
                *v = scale(*v, a, 10000)?;
            }
            Some(Calc::Length(b))
        }
        _ => None,
    }
}
fn calc_atom(p: &mut cssparser::Parser<'_>, nodes: &mut u32, depth: u32) -> Option<Calc> {
    *nodes += 1;
    if *nodes > 64 || depth > 16 {
        return None;
    }
    let token = p.next().ok()?.clone();
    match token {
        cssparser::Token::Number { value, .. }
            if value.is_finite() && value.abs() <= 1_000_000.0 =>
        {
            Some(Calc::Scalar((value as f64 * 10000.0).round() as i64))
        }
        cssparser::Token::Dimension { .. } | cssparser::Token::Percentage { .. } => {
            use cssparser::ToCss;
            let text = token.to_css_string();
            let l = simple_length(&text)?;
            let mut coefficients = [0; 8];
            coefficients[unit_index(l.unit)] = l.n;
            Some(Calc::Length(coefficients))
        }
        cssparser::Token::Function(name) if name.eq_ignore_ascii_case("calc") => p
            .parse_nested_block(|p| {
                calc_sum(p, nodes, depth + 1).ok_or_else(|| cssparser::ParseError::<()>::custom(()))
            })
            .ok(),
        cssparser::Token::ParenthesisBlock => p
            .parse_nested_block(|p| {
                calc_sum(p, nodes, depth + 1).ok_or_else(|| cssparser::ParseError::<()>::custom(()))
            })
            .ok(),
        cssparser::Token::Delim('-') => {
            calc_scale(calc_atom(p, nodes, depth + 1)?, Calc::Scalar(-10000), false)
        }
        cssparser::Token::Delim('+') => calc_atom(p, nodes, depth + 1),
        _ => None,
    }
}
fn calc_product(p: &mut cssparser::Parser<'_>, nodes: &mut u32, depth: u32) -> Option<Calc> {
    let mut result = calc_atom(p, nodes, depth)?;
    loop {
        let state = p.state();
        let token = p.next().ok().cloned();
        match token {
            Some(cssparser::Token::Delim(op)) if op == '*' || op == '/' => {
                result = calc_scale(result, calc_atom(p, nodes, depth + 1)?, op == '/')?;
            }
            _ => {
                p.reset(&state);
                break;
            }
        }
    }
    Some(result)
}
fn calc_sum(p: &mut cssparser::Parser<'_>, nodes: &mut u32, depth: u32) -> Option<Calc> {
    let mut result = calc_product(p, nodes, depth)?;
    loop {
        let state = p.state();
        let token = p.next().ok().cloned();
        match token {
            Some(cssparser::Token::Delim(op)) if op == '+' || op == '-' => {
                let b = calc_product(p, nodes, depth + 1)?;
                let b = if op == '-' {
                    calc_scale(b, Calc::Scalar(-10000), false)?
                } else {
                    b
                };
                result = match (result, b) {
                    (Calc::Length(mut a), Calc::Length(b)) => {
                        for i in 0..8 {
                            a[i] = a[i].checked_add(b[i])?;
                            if a[i].abs() > 1_000_000_000_000 {
                                return None;
                            }
                        }
                        Calc::Length(a)
                    }
                    (Calc::Scalar(a), Calc::Scalar(b)) => Calc::Scalar(a.checked_add(b)?),
                    _ => return None,
                };
            }
            _ => {
                p.reset(&state);
                break;
            }
        }
    }
    Some(result)
}
pub fn length(s: &str) -> Option<Length> {
    if let Some(l) = simple_length(s) {
        return Some(l);
    }
    let mut parser = cssparser::Parser::new(s);
    let token = parser.next().ok()?.clone();
    if !matches!(token,cssparser::Token::Function(ref name)if name.eq_ignore_ascii_case("calc")) {
        return None;
    }
    let mut nodes = 0;
    let result = parser
        .parse_nested_block(|p| {
            let v = calc_sum(p, &mut nodes, 0)
                .ok_or_else(|| cssparser::ParseError::<()>::custom(()))?;
            p.expect_exhausted()?;
            Ok::<_, cssparser::ParseError<()>>(v)
        })
        .ok()?;
    parser.expect_exhausted().ok()?;
    let coefficients = match result {
        Calc::Length(a) => a,
        Calc::Scalar(0) => [0; 8],
        _ => return None,
    };
    Some(Length {
        n: 0,
        unit: Unit::Px,
        extra: coefficients,
    })
}
pub fn color(s: &str) -> Option<u32> {
    if s.trim().eq_ignore_ascii_case("transparent") {
        return Some(0);
    }
    let c = s.trim().parse::<csscolorparser::Color>().ok()?.to_rgba8();
    Some(u32::from_be_bytes(c))
}
pub fn linear_gradient(value: &str) -> Option<LinearGradient> {
    let body = value
        .trim()
        .strip_prefix("linear-gradient(")?
        .strip_suffix(')')?;
    let parts = css::split_top(body, ',');
    if parts.len() < 2 || parts.len() > 65 {
        return None;
    }
    let mut angle_mdeg = 180000;
    let mut first = 0;
    let direction = parts[0].trim().to_ascii_lowercase();
    if direction.starts_with("to ") {
        angle_mdeg = match direction.as_str() {
            "to top" => 0,
            "to right" => 90000,
            "to bottom" => 180000,
            "to left" => 270000,
            "to top right" | "to right top" => 45000,
            "to bottom right" | "to right bottom" => 135000,
            "to bottom left" | "to left bottom" => 225000,
            "to top left" | "to left top" => 315000,
            _ => return None,
        };
        first = 1;
    } else {
        for (unit, scale) in [
            ("deg", 1000.0),
            ("turn", 360000.0),
            ("grad", 900.0),
            ("rad", 180000.0 / std::f64::consts::PI),
        ] {
            if let Some(n) = direction
                .strip_suffix(unit)
                .and_then(|n| n.trim().parse::<f64>().ok())
            {
                if !n.is_finite() || n.abs() > 1_000_000.0 {
                    return None;
                }
                angle_mdeg = (n * scale).rem_euclid(360000.0).round() as i32;
                first = 1;
                break;
            }
        }
    }
    let mut stops = vec![];
    for part in &parts[first..] {
        let words = simple_words(part);
        if words.is_empty() || words.len() > 2 {
            return None;
        }
        let c = if words[0].eq_ignore_ascii_case("currentcolor") {
            None
        } else {
            Some(color(&words[0])?)
        };
        let position = if words.len() == 2 {
            Some(length(&words[1])?)
        } else {
            None
        };
        stops.push(ColorStop { color: c, position });
    }
    if stops.len() < 2 || stops.len() > 64 {
        return None;
    }
    Some(LinearGradient { angle_mdeg, stops })
}
fn four<T: Clone>(v: Vec<T>) -> Option<[T; 4]> {
    match v.len() {
        1 => Some([v[0].clone(), v[0].clone(), v[0].clone(), v[0].clone()]),
        2 => Some([v[0].clone(), v[1].clone(), v[0].clone(), v[1].clone()]),
        3 => Some([v[0].clone(), v[1].clone(), v[2].clone(), v[1].clone()]),
        4 => Some([v[0].clone(), v[1].clone(), v[2].clone(), v[3].clone()]),
        _ => None,
    }
}
pub fn simple_words(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut p = cssparser::Parser::new(s);
    while !p.is_exhausted() {
        let start = p.position();
        let Ok(token) = p.next().cloned() else {
            break;
        };
        if matches!(
            token,
            cssparser::Token::Function(_) | cssparser::Token::ParenthesisBlock
        ) {
            let _ = p.parse_nested_block(|q| {
                while q.next_including_whitespace_and_comments().is_ok() {}
                Ok::<_, cssparser::ParseError<()>>(())
            });
        }
        out.push(p.slice_from(start).trim().to_string());
    }
    out
}
fn expand(name: &str, value: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let sides = ["top", "right", "bottom", "left"];
    if matches!(value.trim(), "inherit" | "initial" | "unset") {
        let names: Vec<String> = match name {
            "font" => [
                "font-family",
                "font-size",
                "font-weight",
                "font-style",
                "line-height",
            ]
            .iter()
            .map(|x| x.to_string())
            .collect(),
            "background" => [
                "background-color",
                "background-image",
                "background-size",
                "background-position",
                "background-repeat",
                "background-clip",
                "background-origin",
            ]
            .iter()
            .map(|x| x.to_string())
            .collect(),
            "text-decoration" => [
                "text-decoration-line",
                "text-decoration-color",
                "text-decoration-style",
            ]
            .iter()
            .map(|x| x.to_string())
            .collect(),
            "list-style" => ["list-style-type", "list-style-position"]
                .iter()
                .map(|x| x.to_string())
                .collect(),
            "border" | "border-top" | "border-right" | "border-bottom" | "border-left" => {
                let mut names = vec![];
                for side in sides {
                    if name == "border" || name == format!("border-{side}") {
                        for attr in ["width", "style", "color"] {
                            names.push(format!("border-{side}-{attr}"));
                        }
                    }
                }
                names
            }
            _ => vec![],
        };
        if !names.is_empty() {
            return names
                .into_iter()
                .map(|n| (n, value.trim().into()))
                .collect();
        }
    }

    if matches!(
        name,
        "margin" | "padding" | "border-width" | "border-color" | "border-style"
    ) {
        if let Some(vals) = four(simple_words(value)) {
            for (i, side) in sides.iter().enumerate() {
                let n = if let Some(suffix) = name.strip_prefix("border-") {
                    format!("border-{side}-{suffix}")
                } else {
                    format!("{name}-{side}")
                };
                out.push((n, vals[i].clone()));
            }
        }
        return out;
    }
    if name == "border" || sides.iter().any(|side| name == format!("border-{side}")) {
        let values = simple_words(value);
        let mut width = "medium".to_string();
        let mut style = "none".to_string();
        let mut col = "currentcolor".to_string();
        for v in values {
            if border_style(&v).is_some() {
                style = v;
            } else if length(&v).is_some() || matches!(v.as_str(), "thin" | "medium" | "thick") {
                width = v;
            } else if color(&v).is_some() || v == "currentcolor" {
                col = v;
            }
        }
        for side in sides {
            if name == "border" || name == format!("border-{side}") {
                for (k, v) in [("width", &width), ("style", &style), ("color", &col)] {
                    out.push((format!("border-{side}-{k}"), v.clone()));
                }
            }
        }
        return out;
    }
    if name == "outline" {
        return expand("border-top", value)
            .into_iter()
            .map(|(k, v)| (k.replace("border-top-", "outline-"), v))
            .collect();
    }
    if name == "background" {
        out.push(("background-color".into(), "transparent".into()));
        out.push(("background-image".into(), "none".into()));
        for word in simple_words(value) {
            if color(&word).is_some() {
                out.push(("background-color".into(), word));
            } else if word.starts_with("url(") || word.starts_with("linear-gradient(") {
                out.push(("background-image".into(), word));
            } else if matches!(
                word.as_str(),
                "repeat" | "no-repeat" | "repeat-x" | "repeat-y"
            ) {
                out.push(("background-repeat".into(), word));
            }
        }
        return out;
    }
    if name == "font" {
        let words = simple_words(value);
        out.extend([
            ("font-style".into(), "normal".into()),
            ("font-weight".into(), "normal".into()),
            ("line-height".into(), "normal".into()),
        ]);
        let mut found = false;
        for (i, v) in words.iter().enumerate() {
            let pair: Vec<_> = v.split('/').collect();
            if length(pair[0]).is_some() || matches!(pair[0], "small" | "medium" | "large") {
                out.push(("font-size".into(), pair[0].into()));
                if pair.len() > 1 {
                    out.push(("line-height".into(), pair[1].into()));
                }
                let mut family = i + 1;
                if words.get(i + 1).map(|x| x.as_str()) == Some("/") && words.len() > i + 2 {
                    out.push(("line-height".into(), words[i + 2].clone()));
                    family = i + 3;
                }
                out.push(("font-family".into(), words[family..].join(" ")));
                found = true;
                break;
            }
            if v == "italic" || v == "oblique" {
                out.push(("font-style".into(), v.clone()));
            }
            if v == "bold" || v.parse::<u16>().is_ok() {
                out.push(("font-weight".into(), v.clone()));
            }
        }
        if !found {
            return vec![];
        }
        return out;
    }
    if name == "text-decoration" {
        for v in simple_words(value) {
            if matches!(
                v.as_str(),
                "none" | "underline" | "overline" | "line-through"
            ) {
                out.push(("text-decoration-line".into(), v));
            } else if color(&v).is_some() {
                out.push(("text-decoration-color".into(), v));
            } else if matches!(
                v.as_str(),
                "solid" | "dotted" | "dashed" | "double" | "wavy"
            ) {
                out.push(("text-decoration-style".into(), v));
            }
        }
        return out;
    }
    if name == "list-style" {
        for v in simple_words(value) {
            if v == "inside" || v == "outside" {
                out.push(("list-style-position".into(), v));
            } else if !v.contains("url(") {
                out.push(("list-style-type".into(), v));
            }
        }
        return out;
    }
    if name == "margin-block"
        || name == "padding-block"
        || name == "margin-inline"
        || name == "padding-inline"
    {
        let v = simple_words(value);
        if v.len() == 1 || v.len() == 2 {
            let prefix = name.split('-').next().unwrap();
            let dir = name.split('-').nth(1).unwrap();
            out.push((format!("{prefix}-{dir}-start"), v[0].clone()));
            out.push((format!("{prefix}-{dir}-end"), v[v.len() - 1].clone()));
        }
        return out;
    }
    out.push((name.to_string(), value.to_string()));
    out
}
fn border_style(v: &str) -> Option<BorderStyle> {
    Some(match v {
        "none" => BorderStyle::None,
        "solid" => BorderStyle::Solid,
        "dotted" => BorderStyle::Dotted,
        "dashed" => BorderStyle::Dashed,
        "double" => BorderStyle::Double,
        "groove" => BorderStyle::Groove,
        "ridge" => BorderStyle::Ridge,
        "inset" => BorderStyle::Inset,
        "outset" => BorderStyle::Outset,
        "hidden" => BorderStyle::Hidden,
        _ => return None,
    })
}
fn accepted(name: &str, value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    let v = v.as_str();
    if v == "inherit" || v == "initial" || v == "unset" {
        return true;
    }
    match name {
        "width" | "height" | "min-width" | "max-width" | "min-height" | "max-height"
        | "inline-size" | "block-size" | "min-inline-size" | "max-inline-size"
        | "min-block-size" | "max-block-size" => {
            size(v).is_some_and(|z| !matches!(z,Size::Length(l)if l.n<0))
        }
        "margin-top"
        | "margin-right"
        | "margin-bottom"
        | "margin-left"
        | "margin-inline-start"
        | "margin-inline-end"
        | "margin-block-start"
        | "margin-block-end" => size(v).is_some(),
        "padding-top"
        | "padding-right"
        | "padding-bottom"
        | "padding-left"
        | "padding-inline-start"
        | "padding-inline-end"
        | "padding-block-start"
        | "padding-block-end" => length(v).is_some_and(|l| l.n >= 0),
        "color" | "background-color" | "text-decoration-color" => {
            v == "currentcolor" || color(value).is_some()
        }
        "display" => matches!(
            v,
            "none"
                | "block"
                | "inline"
                | "inline-block"
                | "table"
                | "inline-table"
                | "table-row"
                | "table-cell"
                | "table-row-group"
                | "table-header-group"
                | "table-footer-group"
                | "table-caption"
                | "list-item"
        ),
        "font-size" => {
            length(v).is_some_and(|l| l.n >= 0)
                || matches!(
                    v,
                    "xx-small"
                        | "x-small"
                        | "small"
                        | "medium"
                        | "large"
                        | "x-large"
                        | "xx-large"
                        | "smaller"
                        | "larger"
                )
        }
        "font-weight" => {
            matches!(v, "normal" | "bold" | "bolder" | "lighter")
                || v.parse::<u16>().is_ok_and(|n| n >= 1 && n <= 1000)
        }
        "font-style" => matches!(v, "normal" | "italic" | "oblique"),
        "line-height" => {
            v == "normal"
                || length(v).is_some_and(|l| l.n >= 0)
                || v.parse::<f64>()
                    .is_ok_and(|x| x.is_finite() && x >= 0.0 && x < 100.0)
        }
        "font-family" => !v.is_empty() && !v.contains("url("),
        "box-sizing" => matches!(v, "border-box" | "content-box"),
        "direction" => matches!(v, "ltr" | "rtl"),
        "visibility" => matches!(v, "visible" | "hidden" | "collapse"),
        "opacity" => v.parse::<f64>().is_ok_and(|x| x.is_finite()),
        "white-space" => matches!(v, "normal" | "nowrap" | "pre" | "pre-wrap" | "pre-line"),
        "text-align" => matches!(v, "start" | "end" | "left" | "right" | "center" | "justify"),
        "float" => matches!(v, "none" | "left" | "right"),
        "clear" => matches!(v, "none" | "left" | "right" | "both"),
        "outline-width" => {
            matches!(v, "thin" | "medium" | "thick")
                || length(v).is_some_and(|l| l.n >= 0 && l.unit != Unit::Percent)
        }
        "outline-style" => border_style(v).is_some() && v != "hidden",
        "outline-color" => v == "currentcolor" || color(value).is_some(),
        "outline-offset" => length(v).is_some_and(|l| l.unit != Unit::Percent),
        "font-kerning" => matches!(v, "auto" | "normal" | "none"),
        "background-image" => css::split_top(value, ',').iter().all(|x| {
            let x = x.trim();
            x == "none"
                || (x.starts_with("url(") && x.ends_with(')'))
                || linear_gradient(x).is_some()
        }),
        "background-size" => {
            matches!(v, "cover" | "contain") || {
                let w = simple_words(value);
                !w.is_empty()
                    && w.len() <= 2
                    && w.iter()
                        .all(|x| x == "auto" || length(x).is_some_and(|l| l.n >= 0))
            }
        }
        "background-repeat" => matches!(v, "repeat" | "no-repeat" | "repeat-x" | "repeat-y"),
        "background-clip" | "background-origin" => {
            matches!(v, "border-box" | "padding-box" | "content-box")
        }
        "background-position" | "object-position" => {
            let w = simple_words(value);
            !w.is_empty()
                && w.len() <= 4
                && w.iter().all(|x| {
                    matches!(x.as_str(), "left" | "right" | "top" | "bottom" | "center")
                        || length(x).is_some()
                })
        }
        "border-collapse" => matches!(v, "collapse" | "separate"),
        "border-spacing" => {
            let w = simple_words(value);
            !w.is_empty()
                && w.len() <= 2
                && w.iter()
                    .all(|x| length(x).is_some_and(|l| l.unit != Unit::Percent && l.n >= 0))
        }
        "table-layout" => matches!(v, "auto" | "fixed"),
        "empty-cells" => matches!(v, "show" | "hide"),
        "caption-side" => matches!(v, "top" | "bottom"),
        "text-decoration-line" => {
            let w = simple_words(value);
            !w.is_empty()
                && w.iter().all(|x| {
                    matches!(
                        x.as_str(),
                        "none" | "underline" | "overline" | "line-through"
                    )
                })
        }
        "text-decoration-style" => matches!(v, "solid" | "double" | "dotted" | "dashed" | "wavy"),
        "text-transform" => matches!(v, "none" | "uppercase" | "lowercase" | "capitalize"),
        "text-indent" => length(value).is_some(),
        "vertical-align" => {
            matches!(
                v,
                "baseline"
                    | "top"
                    | "bottom"
                    | "middle"
                    | "text-top"
                    | "text-bottom"
                    | "sub"
                    | "super"
            ) || length(value).is_some()
        }
        "letter-spacing" | "word-spacing" => v == "normal" || length(value).is_some(),
        "word-break" => matches!(v, "normal" | "break-all" | "keep-all" | "break-word"),
        "overflow-wrap" | "word-wrap" => matches!(v, "normal" | "break-word" | "anywhere"),
        "overflow" | "overflow-x" | "overflow-y" => matches!(v, "visible" | "hidden" | "clip"),
        "text-overflow" => matches!(v, "clip" | "ellipsis"),
        "list-style-type" => matches!(
            v,
            "none"
                | "disc"
                | "circle"
                | "square"
                | "decimal"
                | "decimal-leading-zero"
                | "lower-alpha"
                | "upper-alpha"
                | "lower-latin"
                | "upper-latin"
                | "lower-roman"
                | "upper-roman"
        ),
        "list-style-position" => matches!(v, "inside" | "outside"),
        "object-fit" => matches!(v, "fill" | "contain" | "cover" | "none" | "scale-down"),
        _ if name.starts_with("border-") && name.ends_with("-width") => {
            matches!(v, "thin" | "medium" | "thick") || length(v).is_some_and(|l| l.n >= 0)
        }
        _ if name.starts_with("border-") && name.ends_with("-style") => border_style(v).is_some(),
        _ if name.starts_with("border-") && name.ends_with("-color") => {
            v == "currentcolor" || color(value).is_some()
        }
        _ => {
            matches!(
                name,
                "background-image"
                    | "background-size"
                    | "background-position"
                    | "background-repeat"
                    | "background-clip"
                    | "background-origin"
                    | "border-radius"
                    | "border-collapse"
                    | "border-spacing"
                    | "table-layout"
                    | "empty-cells"
                    | "caption-side"
                    | "text-decoration-line"
                    | "text-decoration-style"
                    | "text-transform"
                    | "text-indent"
                    | "vertical-align"
                    | "letter-spacing"
                    | "word-spacing"
                    | "word-break"
                    | "overflow-wrap"
                    | "word-wrap"
                    | "overflow"
                    | "overflow-x"
                    | "overflow-y"
                    | "text-overflow"
                    | "list-style-type"
                    | "list-style-position"
                    | "object-fit"
                    | "object-position"
                    | "font-kerning"
            ) && !v.contains("var(")
                && !v.contains("expression(")
        }
    }
}
fn ua(n: &Node, s: &mut Style) {
    let em = |hundredths: i64| {
        Size::Length(Length {
            n: hundredths * 100,
            unit: Unit::Em,
            extra: [0; 8],
        })
    };
    match n.tag.as_str() {
        "html" | "body" | "div" | "p" | "pre" | "blockquote" | "address" | "section"
        | "article" | "header" | "footer" | "main" | "nav" | "aside" | "figure" | "figcaption"
        | "center" | "ul" | "ol" | "dl" | "dt" | "dd" | "hr" => s.display = Display::Block,
        "head" | "style" | "title" | "meta" | "link" | "script" | "base" => {
            s.display = Display::None
        }
        "table" => {
            s.display = Display::Table;
            // Gecko's UA table rule supplies the initial separate-border
            // model on every table. Although these properties inherit, a
            // nested table does not inherit an outer author-level `collapse`
            // unless the author explicitly targets the nested table too.
            s.border_collapse = false;
            s.border_spacing = (2 * PX, 2 * PX);
        }
        "tr" => s.display = Display::Row,
        "tbody" | "thead" | "tfoot" => s.display = Display::RowGroup,
        "td" | "th" => {
            s.display = Display::Cell;
            s.padding = Edges {
                top: Length::px(1),
                right: Length::px(1),
                bottom: Length::px(1),
                left: Length::px(1),
            };
            s.vertical_align = "middle".into();
        }
        "caption" => {
            s.display = Display::Caption;
            s.align = Align::Center;
        }
        "li" => s.display = Display::ListItem,
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            s.display = Display::Block;
            s.weight = 700;
            let factor = match n.tag.as_str() {
                "h1" => 200,
                "h2" => 150,
                "h3" => 117,
                "h4" => 100,
                "h5" => 83,
                _ => 67,
            };
            s.font_size = s.font_size * factor / 100;
            // Gecko's heading margins are relative to each heading's own
            // computed font size, and grow as the heading size decreases.
            // A single `.67em` rule happens to fit h1 but compresses h2-h6.
            s.margin.top = em(match n.tag.as_str() {
                "h1" => 67,
                "h2" => 83,
                "h3" => 100,
                "h4" => 133,
                "h5" => 167,
                _ => 233,
            });
            s.margin.bottom = s.margin.top;
        }
        _ => {}
    }
    if n.tag == "body" {
        s.margin = Edges {
            top: Size::Length(Length::px(8)),
            right: Size::Length(Length::px(8)),
            bottom: Size::Length(Length::px(8)),
            left: Size::Length(Length::px(8)),
        };
    }
    if matches!(
        n.tag.as_str(),
        "p" | "pre" | "blockquote" | "ul" | "ol" | "dl"
    ) {
        // These UA margins are `1em`, not a fixed 16px. This matters inside
        // email templates that set a smaller body font.
        s.margin.top = em(100);
        s.margin.bottom = em(100);
    }
    if n.tag == "blockquote" {
        s.margin.left = Size::Length(Length::px(40));
        s.margin.right = s.margin.left;
    }
    if matches!(n.tag.as_str(), "ul" | "ol") {
        if n.tag == "ol" {
            s.list_type = "decimal".into();
        }
    }
    if matches!(n.tag.as_str(), "b" | "strong" | "th") {
        s.weight = 700;
    }
    if n.tag == "th" {
        s.align = Align::Center;
    }
    if matches!(n.tag.as_str(), "i" | "em" | "dfn" | "cite" | "address") {
        s.italic = true;
    }
    if matches!(n.tag.as_str(), "code" | "pre" | "kbd" | "samp" | "tt") {
        s.font = Family::Mono;
    }
    if n.tag == "pre" {
        s.whitespace = WhiteSpace::Pre;
    }
    if n.tag == "small" {
        s.font_size = s.font_size * 5 / 6;
    }
    if n.tag == "big" {
        s.font_size = s.font_size * 6 / 5;
    }
    if matches!(n.tag.as_str(), "sub" | "sup") {
        s.font_size = s.font_size * 5 / 6;
        s.vertical_align = n.tag.clone();
    }
    if matches!(n.tag.as_str(), "s" | "strike" | "del") {
        s.decoration |= 4;
    }
    if matches!(n.tag.as_str(), "u" | "ins") {
        s.decoration |= 1;
    }
    if n.tag == "a" && n.attr("href").is_some() {
        s.color = 0x0000eeff;
        s.decoration |= 1;
    }
    if n.tag == "center" {
        s.align = Align::Center;
    }
    if n.tag == "hr" {
        s.margin.top = Size::Length(Length::px(8));
        s.margin.bottom = s.margin.top;
        s.border.top = Border {
            width: PX,
            color: 0x808080ff,
            style: BorderStyle::Solid,
        };
    }
    if n.attr("hidden").is_some() || n.disabled {
        s.display = Display::None;
    }
}
fn hints(n: &Node) -> Vec<(String, String)> {
    let mut v = vec![];
    for (k, a) in &n.attrs {
        match k.as_str() {
            "width" | "height" => {
                let value = if a.trim().parse::<i64>().is_ok() {
                    format!("{}px", a.trim())
                } else {
                    a.clone()
                };
                v.push((k.clone(), value));
            }
            "bgcolor" => v.push(("background-color".into(), a.clone())),
            "color" if n.tag == "font" => v.push(("color".into(), a.clone())),
            "face" if n.tag == "font" => v.push(("font-family".into(), a.clone())),
            "size" if n.tag == "font" => {
                if let Ok(mut n) = a.trim().parse::<i64>() {
                    if a.starts_with('+') || a.starts_with('-') {
                        n += 3;
                    }
                    let px = match n.clamp(1, 7) {
                        1 => 10,
                        2 => 13,
                        3 => 16,
                        4 => 18,
                        5 => 24,
                        6 => 32,
                        _ => 48,
                    };
                    v.push(("font-size".into(), format!("{px}px")));
                }
            }
            "align" => {
                if n.tag == "table" && a == "center" {
                    v.push(("margin-left".into(), "auto".into()));
                    v.push(("margin-right".into(), "auto".into()));
                } else {
                    v.push(("text-align".into(), a.clone()));
                }
            }
            "valign" => v.push(("vertical-align".into(), a.clone())),
            "dir" if a == "rtl" || a == "ltr" => v.push(("direction".into(), a.clone())),
            "cellspacing" if n.tag == "table" => {
                v.push(("border-spacing".into(), format!("{}px", a)))
            }
            "background" => v.push((
                "background-image".into(),
                format!("url(\"{}\")", a.replace('"', "%22")),
            )),
            "border" if n.tag == "table" => {
                v.push(("border".into(), format!("{}px outset gray", a)))
            }
            _ => {}
        }
    }
    v
}

pub fn compute(
    doc: &Document,
    width: Au,
    height: Au,
    limits: &Limits,
    budget: &mut Budget,
    states: &[(NodeId, String)],
) -> Result<Vec<Style>> {
    let mut order = 0;
    let mut rules = vec![];
    for text in &doc.stylesheets {
        rules.extend(css::stylesheet(text, width, height, limits, budget, &mut order)?.rules);
    }
    let mut styles: Vec<Style> = vec![];
    let mut root_font = 16 * PX;
    for (id, n) in doc.nodes.iter().enumerate() {
        budget.charge(1)?;
        let initial_parent = Style::default();
        let parent = n.parent.map(|p| &styles[p]).unwrap_or(&initial_parent);
        let mut s = inherited(&parent);
        ua(n, &mut s);
        if s.display == Display::Cell {
            let mut ancestor = n.parent;
            while let Some(i) = ancestor {
                if doc.nodes[i].tag == "table" {
                    if let Some(pad) = doc.nodes[i]
                        .attr("cellpadding")
                        .and_then(|x| x.trim().parse::<i64>().ok())
                        .filter(|x| *x >= 0 && *x <= 10000)
                    {
                        let p = Length::px(pad);
                        s.padding = Edges {
                            top: p,
                            right: p,
                            bottom: p,
                            left: p,
                        };
                    }
                    break;
                }
                ancestor = doc.nodes[i].parent;
            }
        }

        let mut winners: Vec<(String, String, u64)> = vec![];
        let mut add = |name: &str, value: &str, rank: u64| {
            for (k, v) in expand(name, value) {
                if !accepted(&k, &v) {
                    continue;
                }
                if let Some(e) = winners.iter_mut().find(|(n, _, _)| n == &k) {
                    if rank >= e.2 {
                        *e = (k, v, rank);
                    }
                } else {
                    winners.push((k, v, rank));
                }
            }
        };
        for (k, v) in hints(n) {
            add(&k, &v, 0);
        }
        if n.element() {
            for rule in &rules {
                let mut specificity = None;
                for sel in &rule.selectors {
                    if css::matches(sel, id, doc, states, budget)? {
                        specificity = Some(specificity.unwrap_or(0u32).max(sel.specificity));
                    }
                }
                if let Some(sp) = specificity {
                    for d in &rule.declarations {
                        budget.charge((d.name.len() + d.value.len() + 1) as u64)?;
                        let rank = (d.important as u64) << 63 | (sp as u64) << 24 | d.order as u64;
                        add(&d.name, &d.value, rank + 1);
                    }
                }
            }
            if let Some(inline) = n.attr("style") {
                for d in css::declarations(inline, &mut order, limits, budget)? {
                    let rank = (d.important as u64) << 63 | 1u64 << 62 | d.order as u64;
                    add(&d.name, &d.value, rank);
                }
            }
        }
        // Relative font sizing is resolved before em-valued geometry.
        for (k, v, _) in &winners {
            if k == "font-size" {
                if v == "inherit" || v == "unset" {
                    s.font_size = parent.font_size;
                } else if v == "initial" {
                    s.font_size = 16 * PX;
                } else if let Some(l) = length(v) {
                    let f = l.eval(parent.font_size, parent.font_size, root_font, width, height);
                    if f >= 0 && f <= 1024 * PX {
                        s.font_size = f;
                    }
                } else {
                    s.font_size = match v.as_str() {
                        "xx-small" => 9 * PX,
                        "x-small" => 10 * PX,
                        "small" => 13 * PX,
                        "medium" => 16 * PX,
                        "large" => 18 * PX,
                        "x-large" => 24 * PX,
                        "xx-large" => 32 * PX,
                        "smaller" => parent.font_size * 5 / 6,
                        "larger" => parent.font_size * 6 / 5,
                        _ => s.font_size,
                    };
                }
            }
        }
        if n.tag == "html" {
            root_font = s.font_size;
        }
        if s.line_height_factor > 0 {
            s.line_height = s.font_size * s.line_height_factor / 10000;
        }
        for (k, v, _) in &winners {
            if k == "direction" {
                apply(&mut s, k, v, &parent, root_font, width, height);
            }
        }
        if matches!(n.tag.as_str(), "ul" | "ol") {
            // Gecko's UA rule is `padding-inline-start: 40px`, not a
            // physical left padding. Establish it after direction resolves
            // but before author declarations, so e.g. an RTL list with an
            // author `padding-left` keeps the UA padding on its right edge.
            if s.direction_rtl {
                s.padding.right = Length::px(40);
            } else {
                s.padding.left = Length::px(40);
            }
        }
        for (k, v, _) in &winners {
            apply(&mut s, k, v, &parent, root_font, width, height);
        }
        if n.attr("hidden").is_some() || n.disabled {
            s.display = Display::None;
        }
        for side in ["top", "right", "bottom", "left"] {
            let key = format!("border-{side}-color");
            let current = winners
                .iter()
                .find(|(k, _, _)| k == &key)
                .map(|(_, v, _)| v.eq_ignore_ascii_case("currentcolor"))
                .unwrap_or(true);
            if current {
                let b = match side {
                    "top" => &mut s.border.top,
                    "right" => &mut s.border.right,
                    "bottom" => &mut s.border.bottom,
                    _ => &mut s.border.left,
                };
                b.color = s.color;
            }
        }
        if !winners.iter().any(|(k, _, _)| k == "outline-color") {
            s.outline.color = s.color;
        }
        styles.push(s);
    }
    Ok(styles)
}
fn property_inherits(name: &str) -> bool {
    matches!(
        name,
        "color"
            | "font-family"
            | "font-size"
            | "font-weight"
            | "font-style"
            | "font-kerning"
            | "line-height"
            | "text-align"
            | "direction"
            | "white-space"
            | "visibility"
            | "text-transform"
            | "text-indent"
            | "letter-spacing"
            | "word-spacing"
            | "word-break"
            | "overflow-wrap"
            | "word-wrap"
            | "border-collapse"
            | "border-spacing"
            | "empty-cells"
            | "list-style-type"
            | "list-style-position"
    )
}
fn copy_property(to: &mut Style, from: &Style, name: &str) {
    match name {
        "display" => to.display = from.display.clone(),
        "color" => to.color = from.color.clone(),
        "background-color" => to.background_color = from.background_color.clone(),
        "background-image" => to.backgrounds = from.backgrounds.clone(),
        "background-size" => to.background_size = from.background_size.clone(),
        "background-position" => to.background_position = from.background_position.clone(),
        "background-repeat" => to.background_repeat = from.background_repeat.clone(),
        "background-clip" => to.background_clip = from.background_clip.clone(),
        "background-origin" => to.background_origin = from.background_origin.clone(),
        "font-family" => to.font = from.font.clone(),
        "font-size" => to.font_size = from.font_size.clone(),
        "font-weight" => to.weight = from.weight.clone(),
        "font-style" => to.italic = from.italic.clone(),
        "font-kerning" => to.kerning = from.kerning.clone(),
        "width" => to.width = from.width.clone(),
        "height" => to.height = from.height.clone(),
        "min-width" => to.min_width = from.min_width.clone(),
        "max-width" => to.max_width = from.max_width.clone(),
        "min-height" => to.min_height = from.min_height.clone(),
        "max-height" => to.max_height = from.max_height.clone(),
        "box-sizing" => to.border_box = from.border_box.clone(),
        "border-collapse" => to.border_collapse = from.border_collapse.clone(),
        "border-spacing" => to.border_spacing = from.border_spacing.clone(),
        "table-layout" => to.table_fixed = from.table_fixed.clone(),
        "empty-cells" => to.empty_cells = from.empty_cells.clone(),
        "caption-side" => to.caption_bottom = from.caption_bottom.clone(),
        "text-align" => to.align = from.align.clone(),
        "direction" => to.direction_rtl = from.direction_rtl.clone(),
        "white-space" => to.whitespace = from.whitespace.clone(),
        "visibility" => to.visible = from.visible.clone(),
        "opacity" => to.opacity = from.opacity.clone(),
        "text-decoration-line" => to.decoration = from.decoration.clone(),
        "text-decoration-color" => to.decoration_color = from.decoration_color.clone(),
        "text-decoration-style" => to.decoration_style = from.decoration_style.clone(),
        "text-transform" => to.transform = from.transform.clone(),
        "text-indent" => to.indent = from.indent.clone(),
        "vertical-align" => to.vertical_align = from.vertical_align.clone(),
        "letter-spacing" => to.letter_spacing = from.letter_spacing.clone(),
        "word-spacing" => to.word_spacing = from.word_spacing.clone(),
        "word-break" => to.word_break = from.word_break.clone(),
        "overflow-wrap" => to.overflow_wrap = from.overflow_wrap.clone(),
        "word-wrap" => to.overflow_wrap = from.overflow_wrap.clone(),
        "overflow" => to.overflow_hidden = from.overflow_hidden.clone(),
        "overflow-x" => to.overflow_hidden = from.overflow_hidden.clone(),
        "overflow-y" => to.overflow_hidden = from.overflow_hidden.clone(),
        "text-overflow" => to.text_overflow = from.text_overflow.clone(),
        "float" => to.float = from.float.clone(),
        "clear" => to.clear = from.clear.clone(),
        "list-style-type" => to.list_type = from.list_type.clone(),
        "list-style-position" => to.list_inside = from.list_inside.clone(),
        "object-fit" => to.object_fit = from.object_fit.clone(),
        "object-position" => to.object_position = from.object_position.clone(),
        "outline-width" => to.outline.width = from.outline.width,
        "outline-style" => to.outline.style = from.outline.style,
        "outline-color" => to.outline.color = from.outline.color,
        "outline-offset" => to.outline_offset = from.outline_offset,
        "line-height" => {
            to.line_height = from.line_height;
            to.line_height_factor = from.line_height_factor;
            to.normal_line_height = from.normal_line_height;
        }
        "border-radius" => {
            to.radius = from.radius;
            to.radius_percent = from.radius_percent;
        }
        "margin-top" => to.margin.top = from.margin.top,
        "margin-right" => to.margin.right = from.margin.right,
        "margin-bottom" => to.margin.bottom = from.margin.bottom,
        "margin-left" => to.margin.left = from.margin.left,
        "padding-top" => to.padding.top = from.padding.top,
        "padding-right" => to.padding.right = from.padding.right,
        "padding-bottom" => to.padding.bottom = from.padding.bottom,
        "padding-left" => to.padding.left = from.padding.left,
        "border-top-width" => to.border.top.width = from.border.top.width,
        "border-top-style" => to.border.top.style = from.border.top.style,
        "border-top-color" => to.border.top.color = from.border.top.color,
        "border-right-width" => to.border.right.width = from.border.right.width,
        "border-right-style" => to.border.right.style = from.border.right.style,
        "border-right-color" => to.border.right.color = from.border.right.color,
        "border-bottom-width" => to.border.bottom.width = from.border.bottom.width,
        "border-bottom-style" => to.border.bottom.style = from.border.bottom.style,
        "border-bottom-color" => to.border.bottom.color = from.border.bottom.color,
        "border-left-width" => to.border.left.width = from.border.left.width,
        "border-left-style" => to.border.left.style = from.border.left.style,
        "border-left-color" => to.border.left.color = from.border.left.color,
        _ => {}
    }
}
fn apply(s: &mut Style, name: &str, value: &str, parent: &Style, root: Au, vw: Au, vh: Au) {
    let lower = value.trim().to_ascii_lowercase();
    let initial_value = match name {
        "width" | "height" | "min-width" | "min-height" => "auto",
        "max-width" | "max-height" => "none",
        "margin-top" | "margin-right" | "margin-bottom" | "margin-left" | "padding-top"
        | "padding-right" | "padding-bottom" | "padding-left" => "0",
        "display" => "inline",
        "box-sizing" => "content-box",
        "font-size" => "medium",
        "font-weight" => "normal",
        "font-style" => "normal",
        "line-height" => "normal",
        "background-color" => "transparent",
        "background-image" => "none",
        "border-radius" => "0",
        "opacity" => "1",
        "float" | "clear" => "none",
        "overflow" => "visible",
        _ => lower.as_str(),
    };
    let v = if lower == "initial" {
        initial_value
    } else {
        lower.as_str()
    };
    let logical = match name {
        "inline-size" => "width",
        "block-size" => "height",
        "min-inline-size" => "min-width",
        "max-inline-size" => "max-width",
        "min-block-size" => "min-height",
        "max-block-size" => "max-height",
        "margin-block-start" => "margin-top",
        "margin-block-end" => "margin-bottom",
        "padding-block-start" => "padding-top",
        "padding-block-end" => "padding-bottom",
        "margin-inline-start" => {
            if s.direction_rtl {
                "margin-right"
            } else {
                "margin-left"
            }
        }
        "margin-inline-end" => {
            if s.direction_rtl {
                "margin-left"
            } else {
                "margin-right"
            }
        }
        "padding-inline-start" => {
            if s.direction_rtl {
                "padding-right"
            } else {
                "padding-left"
            }
        }
        "padding-inline-end" => {
            if s.direction_rtl {
                "padding-left"
            } else {
                "padding-right"
            }
        }
        _ => name,
    };
    let inherit = lower == "inherit" || lower == "unset" && property_inherits(logical);
    let initial = lower == "initial" || lower == "unset" && !property_inherits(logical);
    if inherit || initial {
        let defaults = Style::default();
        copy_property(s, if inherit { parent } else { &defaults }, logical);
        return;
    }
    let fallback = parent;
    match logical {
        "outline-width" => {
            s.outline.width = match v {
                "thin" => PX,
                "medium" => 3 * PX,
                "thick" => 5 * PX,
                _ => length(v)
                    .map(|l| l.eval(0, s.font_size, root, vw, vh))
                    .unwrap_or(s.outline.width),
            };
        }
        "outline-style" => {
            if let Some(style) = border_style(v) {
                s.outline.style = style;
            }
        }
        "outline-color" => {
            s.outline.color = if v == "currentcolor" {
                s.color
            } else {
                color(value).unwrap_or(s.outline.color)
            };
        }
        "outline-offset" => {
            if let Some(l) = length(v) {
                s.outline_offset = l.eval(0, s.font_size, root, vw, vh);
            }
        }
        "box-sizing" => s.border_box = v == "border-box",
        "display" => {
            if let Some(x) = match v {
                "none" => Some(Display::None),
                "block" => Some(Display::Block),
                "inline" => Some(Display::Inline),
                "inline-block" => Some(Display::InlineBlock),
                "table" | "inline-table" => Some(Display::Table),
                "table-row" => Some(Display::Row),
                "table-cell" => Some(Display::Cell),
                "table-row-group" | "table-header-group" | "table-footer-group" => {
                    Some(Display::RowGroup)
                }
                "table-caption" => Some(Display::Caption),
                "list-item" => Some(Display::ListItem),
                _ => None,
            } {
                s.display = x;
            }
        }
        "color" => {
            if inherit || initial {
                s.color = fallback.color;
            } else if let Some(c) = color(value) {
                s.color = c;
            }
        }
        "background-color" => {
            if let Some(c) = color(value) {
                s.background_color = c;
            } else if v == "currentcolor" {
                s.background_color = s.color;
            }
        }
        "background-image" => {
            s.backgrounds.clear();
            for layer in css::split_top(value, ',') {
                let l = layer.trim();
                if l.starts_with("url(") {
                    s.backgrounds.push(Background::Image(
                        l[4..]
                            .trim_end_matches(')')
                            .trim()
                            .trim_matches(['\'', '"'])
                            .into(),
                    ));
                } else if l.starts_with("linear-gradient(") {
                    if let Some(gradient) = linear_gradient(l) {
                        s.backgrounds.push(Background::Linear(gradient));
                    }
                }
            }
        }
        "background-size" => s.background_size = value.into(),
        "background-position" => s.background_position = value.into(),
        "background-repeat" => s.background_repeat = v.into(),
        "background-clip" => s.background_clip = v.into(),
        "background-origin" => s.background_origin = v.into(),
        "font-kerning" => s.kerning = v != "none",
        "font-family" => {
            s.font = if inherit || initial {
                fallback.font
            } else if v.contains("courier") {
                Family::Courier
            } else if v.contains("arial") || v.contains("helvetica") {
                Family::Arial
            } else if v.contains("times new roman") || v.contains("times,") {
                Family::Times
            } else if v.contains("mono") {
                Family::Mono
            } else if v.contains("sans")
                || v.contains("system-ui")
                || v.contains("verdana")
                || v.contains("tahoma")
            {
                Family::Sans
            } else {
                Family::Serif
            };
        }
        "font-weight" => {
            s.weight = if inherit || initial {
                fallback.weight
            } else {
                match v {
                    "bold" | "bolder" => 700,
                    "normal" | "lighter" => 400,
                    _ => v
                        .parse::<u16>()
                        .ok()
                        .filter(|x| *x >= 1 && *x <= 1000)
                        .unwrap_or(s.weight),
                }
            };
        }
        "font-style" => {
            s.italic = if inherit || initial {
                fallback.italic
            } else {
                v == "italic" || v.starts_with("oblique")
            };
        }
        "line-height" => {
            if inherit || initial {
                s.line_height = fallback.line_height;
                s.line_height_factor = fallback.line_height_factor;
                s.normal_line_height = fallback.normal_line_height;
            } else if v == "normal" {
                s.line_height = 0;
                s.line_height_factor = 0;
                s.normal_line_height = true;
            } else if let Ok(n) = v.parse::<f64>() {
                if n.is_finite() && n >= 0.0 && n < 100.0 {
                    s.normal_line_height = false;
                    s.line_height_factor = (n * 10000.0).round() as i64;
                    s.line_height = s.font_size * s.line_height_factor / 10000;
                }
            } else if let Some(l) = length(v) {
                s.normal_line_height = false;
                s.line_height_factor = 0;
                s.line_height = l.eval(s.font_size, s.font_size, root, vw, vh).max(0);
            }
        }
        "width" | "height" | "min-width" | "max-width" | "min-height" | "max-height" => {
            if let Some(z) = size(v) {
                if matches!(z,Size::Length(l)if l.n<0) {
                    return;
                }
                match logical {
                    "width" => s.width = z,
                    "height" => s.height = z,
                    "min-width" => s.min_width = z,
                    "max-width" => s.max_width = z,
                    "min-height" => s.min_height = z,
                    _ => s.max_height = z,
                }
            }
        }
        "margin-top" | "margin-right" | "margin-bottom" | "margin-left" => {
            if let Some(z) = size(v) {
                match logical {
                    "margin-top" => s.margin.top = z,
                    "margin-right" => s.margin.right = z,
                    "margin-bottom" => s.margin.bottom = z,
                    _ => s.margin.left = z,
                }
            }
        }
        "padding-top" | "padding-right" | "padding-bottom" | "padding-left" => {
            if let Some(z) = length(v) {
                if z.n >= 0 {
                    match logical {
                        "padding-top" => s.padding.top = z,
                        "padding-right" => s.padding.right = z,
                        "padding-bottom" => s.padding.bottom = z,
                        _ => s.padding.left = z,
                    }
                }
            }
        }
        "border-radius" => {
            if let Some(l) = value.split_ascii_whitespace().next().and_then(length) {
                if l.unit == Unit::Percent {
                    s.radius_percent = Some(l.n.max(0));
                    s.radius = 0;
                } else {
                    s.radius_percent = None;
                    s.radius = l.eval(s.font_size, s.font_size, root, vw, vh).max(0);
                }
            }
        }
        "border-collapse" => s.border_collapse = v == "collapse",
        "border-spacing" => {
            let a: Vec<_> = value.split_ascii_whitespace().filter_map(length).collect();
            if !a.is_empty() {
                s.border_spacing = (
                    a[0].eval(0, s.font_size, root, vw, vh).max(0),
                    a[a.len() - 1].eval(0, s.font_size, root, vw, vh).max(0),
                );
            }
        }
        "table-layout" => s.table_fixed = v == "fixed",
        "empty-cells" => s.empty_cells = v != "hide",
        "caption-side" => s.caption_bottom = v == "bottom",
        "text-align" => {
            s.align = match v {
                "left" => Align::Left,
                "right" => Align::Right,
                "center" => Align::Center,
                "justify" => Align::Justify,
                "start" => Align::Start,
                "end" => Align::End,
                _ => s.align,
            }
        }
        "direction" => {
            if v == "rtl" || v == "ltr" {
                s.direction_rtl = v == "rtl";
            }
        }
        "white-space" => {
            s.whitespace = match v {
                "normal" => WhiteSpace::Normal,
                "nowrap" => WhiteSpace::Nowrap,
                "pre" => WhiteSpace::Pre,
                "pre-wrap" => WhiteSpace::PreWrap,
                "pre-line" => WhiteSpace::PreLine,
                _ => s.whitespace,
            }
        }
        "visibility" => {
            if v == "visible" || v == "hidden" || v == "collapse" {
                s.visible = v == "visible";
            }
        }
        "opacity" => {
            if let Ok(n) = v.parse::<f64>() {
                if n.is_finite() {
                    s.opacity = (n.clamp(0.0, 1.0) * 1000.0).round() as u16;
                }
            }
        }
        "text-decoration-line" => {
            s.decoration = 0;
            for x in v.split_ascii_whitespace() {
                s.decoration |= match x {
                    "underline" => 1,
                    "overline" => 2,
                    "line-through" => 4,
                    _ => 0,
                };
            }
        }
        "text-decoration-color" => {
            if let Some(c) = color(value) {
                s.decoration_color = c;
            }
        }
        "text-decoration-style" => s.decoration_style = v.into(),
        "text-transform" => s.transform = v.into(),
        "text-indent" => {
            if let Some(l) = length(v) {
                s.indent = l;
            }
        }
        "vertical-align" => s.vertical_align = v.into(),
        "letter-spacing" | "word-spacing" => {
            let val = if v == "normal" {
                Some(0)
            } else {
                length(v).map(|l| l.eval(0, s.font_size, root, vw, vh))
            };
            if let Some(n) = val {
                if logical == "letter-spacing" {
                    s.letter_spacing = n;
                } else {
                    s.word_spacing = n;
                }
            }
        }
        "word-break" => s.word_break = v.into(),
        "overflow-wrap" | "word-wrap" => s.overflow_wrap = v == "break-word" || v == "anywhere",
        "overflow" | "overflow-x" | "overflow-y" => {
            if matches!(v, "hidden" | "visible" | "clip") {
                s.overflow_hidden = v != "visible";
            }
        }
        "text-overflow" => s.text_overflow = v.into(),
        "float" => {
            s.float = match v {
                "left" => Float::Left,
                "right" => Float::Right,
                _ => Float::None,
            }
        }
        "clear" => s.clear = v.into(),
        "list-style-type" => s.list_type = v.into(),
        "list-style-position" => s.list_inside = v == "inside",
        "object-fit" => s.object_fit = v.into(),
        "object-position" => s.object_position = value.into(),
        _ => {
            if let Some(rest) = logical.strip_prefix("border-") {
                let a: Vec<_> = rest.split('-').collect();
                if a.len() == 2 {
                    let col = s.color;
                    let b = match a[0] {
                        "top" => &mut s.border.top,
                        "right" => &mut s.border.right,
                        "bottom" => &mut s.border.bottom,
                        "left" => &mut s.border.left,
                        _ => return,
                    };
                    match a[1] {
                        "width" => {
                            let w = match v {
                                "thin" => Some(PX),
                                "medium" => Some(3 * PX),
                                "thick" => Some(5 * PX),
                                _ => length(v).map(|l| l.eval(0, s.font_size, root, vw, vh)),
                            };
                            if let Some(w) = w {
                                b.width = w.max(0);
                            }
                        }
                        "style" => {
                            if let Some(z) = border_style(v) {
                                b.style = z;
                            }
                        }
                        "color" => {
                            if v == "currentcolor" {
                                b.color = col;
                            } else if let Some(c) = color(value) {
                                b.color = c;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
