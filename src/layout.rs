#![forbid(unsafe_code)]
//! Bounded layout over an indexed document. Fixed-point geometry is kept out of
//! the native renderer. Dependency shaping and decoding are explicit adapters.
use crate::{core::*, dom::*, style::*, text::*};
use serde::{Deserialize, Serialize};
use unicode_segmentation::UnicodeSegmentation;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageResource {
    pub key: String,
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}
#[derive(Clone, Debug, Serialize)]
pub enum Draw {
    BeginOpacity {
        opacity: u16,
    },
    EndOpacity,
    Rect {
        rect: Rect,
        color: u32,
        radius: Au,
    },
    DiscMarker {
        rect: Rect,
        color: u32,
    },
    Text {
        node: NodeId,
        x: Au,
        baseline: Au,
        run: Run,
        color: u32,
    },
    Image {
        rect: Rect,
        resource: usize,
    },
    TiledImage {
        rect: Rect,
        resource: usize,
        tile: (Au, Au),
    },
    Gradient {
        rect: Rect,
        gradient: LinearGradient,
        color: u32,
    },
    Border {
        rect: Rect,
        widths: [Au; 4],
        colors: [u32; 4],
        styles: [String; 4],
        radius: Au,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct Primitive {
    pub clip: Rect,
    pub fixed_clip: Option<Rect>,
    pub clip_radius: Au,
    pub opacity: u16,
    pub draw: Draw,
}
#[derive(Clone, Debug, Serialize)]
pub struct LayoutBox {
    pub node: NodeId,
    pub border: Rect,
    pub content: Rect,
    pub baseline: Au,
}
#[derive(Clone, Debug, Serialize)]
pub struct LineBox {
    pub parent: NodeId,
    pub rect: Rect,
    pub baseline: Au,
}
#[derive(Clone, Debug, Serialize)]
pub struct Link {
    pub node: NodeId,
    pub target: String,
    pub rectangles: Vec<Rect>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AccessibleNode {
    pub node: NodeId,
    pub role: String,
    pub name: String,
    pub lang: Option<String>,
    pub description: String,
    pub hidden: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Scene {
    pub width: Au,
    pub height: Au,
    pub primitives: Vec<Primitive>,
    pub boxes: Vec<Option<LayoutBox>>,
    pub lines: Vec<LineBox>,
    pub links: Vec<Link>,
    pub accessible: Vec<AccessibleNode>,
    pub readable_text: String,
    pub work_remaining: u64,
}
#[derive(Clone)]
enum Item {
    Text { node: NodeId, run: Run, space: bool },
    Break(NodeId),
    Opportunity(NodeId),
    Box(NodeId),
    Block(NodeId),
}
#[derive(Clone)]
enum Placed {
    Text {
        node: NodeId,
        run: Run,
        x: Au,
        level: unicode_bidi::Level,
    },
    Box {
        id: NodeId,
        first: usize,
        last: usize,
        lines: (usize, usize),
        x: Au,
        rect: Rect,
        margins: Edges<Au>,
        advance: Au,
        level: unicode_bidi::Level,
    },
}
#[derive(Clone)]
struct Cell {
    id: NodeId,
    row: usize,
    col: usize,
    rs: usize,
    cs: usize,
}
#[derive(Clone)]
struct Grid {
    rows: Vec<NodeId>,
    captions: Vec<NodeId>,
    cells: Vec<Cell>,
    cols: usize,
}
#[derive(Clone, Copy, Default)]
struct SharedEdge {
    border: Border,
    source: u8,
}
impl SharedEdge {
    fn offer(&mut self, border: Border, source: u8) {
        let rank = |b: Border, source: u8| {
            let style = match b.style {
                BorderStyle::Hidden => 10,
                BorderStyle::Double => 9,
                BorderStyle::Solid => 8,
                BorderStyle::Dashed => 7,
                BorderStyle::Dotted => 6,
                BorderStyle::Ridge => 5,
                BorderStyle::Outset => 4,
                BorderStyle::Groove => 3,
                BorderStyle::Inset => 2,
                BorderStyle::None => 0,
            };
            (
                b.style == BorderStyle::Hidden,
                if style == 0 { 0 } else { b.width },
                style,
                source,
            )
        };
        if rank(border, source) > rank(self.border, self.source) {
            *self = Self { border, source };
        }
    }
    fn width(self) -> Au {
        if matches!(self.border.style, BorderStyle::None | BorderStyle::Hidden) {
            0
        } else {
            self.border.width
        }
    }
}
struct CollapsedGrid {
    horizontal: Vec<SharedEdge>,
    vertical: Vec<SharedEdge>,
    outer: Edges<Au>,
}
#[derive(Clone, Copy)]
struct Floating {
    rect: Rect,
    side: Float,
}
pub struct Engine<'a> {
    pub doc: &'a Document,
    pub styles: &'a [Style],
    pub fonts: &'a Fonts,
    pub images: &'a [ImageResource],
    pub limits: &'a Limits,
    pub budget: &'a mut Budget,
    pub scene: Scene,
    root_font: Au,
    fixed_clip: Option<Rect>,
    inherited_floats: Vec<Floating>,
    intrinsic: Vec<Option<(Au, Au)>>,
    glyphs: usize,
    collapsed: Vec<Option<Edges<Border>>>,
}
impl Scene {
    pub fn validate(&self, fonts: &Fonts, images: &[ImageResource]) -> Result<()> {
        let coordinate = |v: Au| (-MAX_COORD..=MAX_COORD).contains(&v);
        let rectangle = |r: Rect| {
            coordinate(r.x)
                && coordinate(r.y)
                && r.w >= 0
                && r.h >= 0
                && r.w <= MAX_COORD
                && r.h <= MAX_COORD
                && coordinate(r.right())
                && coordinate(r.bottom())
        };
        if self.primitives.len() > 200_000
            || self.width <= 0
            || self.width > MAX_COORD
            || self.height < 0
            || self.height > MAX_COORD
        {
            return Err(Error::Budget("scene"));
        }
        let mut groups = 0usize;
        let mut glyphs = 0usize;
        for p in &self.primitives {
            if p.fixed_clip.is_some_and(|r| !rectangle(r))
                || !rectangle(p.clip)
                || p.clip_radius < 0
                || p.clip_radius > MAX_COORD
                || p.opacity > 1000
            {
                return Err(Error::Invalid("paint clip"));
            }
            match &p.draw {
                Draw::BeginOpacity { opacity } => {
                    if *opacity > 1000 || groups >= 128 {
                        return Err(Error::Invalid("opacity nesting"));
                    }
                    groups += 1;
                }
                Draw::EndOpacity => {
                    if groups == 0 {
                        return Err(Error::Invalid("opacity stack underflow"));
                    }
                    groups -= 1;
                }
                Draw::Rect {
                    rect,
                    color: _,
                    radius,
                } => {
                    if !rectangle(*rect) || *radius < 0 || *radius > MAX_COORD {
                        return Err(Error::Invalid("paint rectangle"));
                    }
                }
                Draw::DiscMarker { rect, .. } => {
                    if !rectangle(*rect) {
                        return Err(Error::Invalid("paint marker"));
                    }
                }
                Draw::Border {
                    rect,
                    widths,
                    radius,
                    ..
                } => {
                    if !rectangle(*rect)
                        || *radius < 0
                        || *radius > MAX_COORD
                        || widths.iter().any(|v| *v < 0 || *v > MAX_COORD)
                    {
                        return Err(Error::Invalid("paint border"));
                    }
                }
                Draw::TiledImage {
                    rect,
                    resource,
                    tile,
                } => {
                    if !rectangle(*rect)
                        || *resource >= images.len()
                        || tile.0 <= 0
                        || tile.1 <= 0
                        || tile.0 > MAX_COORD
                        || tile.1 > MAX_COORD
                    {
                        return Err(Error::Invalid("paint tiled image"));
                    }
                }
                Draw::Image { rect, resource } => {
                    if !rectangle(*rect) || *resource >= images.len() {
                        return Err(Error::Invalid("paint image"));
                    }
                }
                Draw::Gradient { rect, gradient, .. } => {
                    if !rectangle(*rect)
                        || gradient.stops.len() < 2
                        || gradient.stops.len() > 64
                        || gradient.angle_mdeg < 0
                        || gradient.angle_mdeg > 360000
                    {
                        return Err(Error::Invalid("paint gradient"));
                    }
                }
                Draw::Text {
                    x, baseline, run, ..
                } => {
                    if !coordinate(*x)
                        || !coordinate(*baseline)
                        || run.size <= 0
                        || run.size > 1024 * PX
                        || run.font >= fonts.fonts.len()
                    {
                        return Err(Error::Invalid("paint text"));
                    }
                    glyphs = glyphs
                        .checked_add(run.glyphs.len())
                        .ok_or(Error::Budget("glyphs"))?;
                    if glyphs > 500_000 {
                        return Err(Error::Budget("glyphs"));
                    }
                    let font = &fonts.fonts[run.font];
                    let face = rustybuzz::Face::from_slice(&font.bytes, font.index)
                        .ok_or(Error::Invalid("font"))?;
                    for g in &run.glyphs {
                        if g.index >= face.number_of_glyphs() as u32
                            || !coordinate(g.x)
                            || !coordinate(g.y)
                            || checked_add(*x, g.x).is_err()
                            || checked_add(*baseline, g.y).is_err()
                        {
                            return Err(Error::Invalid("paint glyph"));
                        }
                    }
                }
            }
        }
        if groups != 0 {
            return Err(Error::Invalid("unclosed opacity stack"));
        }
        Ok(())
    }
}

fn alphabetic_counter(mut value: i64, uppercase: bool) -> Option<String> {
    if value < 1 || value > 1_000_000 {
        return None;
    }
    let base = if uppercase { b'A' } else { b'a' };
    let mut result = Vec::new();
    while value > 0 {
        value -= 1;
        result.push((base + (value % 26) as u8) as char);
        value /= 26;
    }
    result.reverse();
    Some(result.into_iter().collect())
}

fn roman_counter(mut value: i64, uppercase: bool) -> Option<String> {
    if !(1..=3999).contains(&value) {
        return None;
    }
    let mut result = String::new();
    for (number, digits) in [
        (1000, "M"),
        (900, "CM"),
        (500, "D"),
        (400, "CD"),
        (100, "C"),
        (90, "XC"),
        (50, "L"),
        (40, "XL"),
        (10, "X"),
        (9, "IX"),
        (5, "V"),
        (4, "IV"),
        (1, "I"),
    ] {
        while value >= number {
            result.push_str(digits);
            value -= number;
        }
    }
    Some(if uppercase {
        result
    } else {
        result.to_ascii_lowercase()
    })
}

impl<'a> Engine<'a> {
    pub fn new(
        doc: &'a Document,
        styles: &'a [Style],
        fonts: &'a Fonts,
        images: &'a [ImageResource],
        limits: &'a Limits,
        budget: &'a mut Budget,
        width: Au,
        height: Au,
    ) -> Self {
        let root_font = doc
            .nodes
            .iter()
            .position(|n| n.tag == "html")
            .map(|i| styles[i].font_size)
            .unwrap_or(16 * PX);
        Self {
            doc,
            styles,
            fonts,
            images,
            limits,
            budget,
            scene: Scene {
                width,
                height,
                primitives: vec![],
                boxes: vec![None; doc.nodes.len()],
                lines: vec![],
                links: vec![],
                accessible: vec![],
                readable_text: doc.readable_text(),
                work_remaining: 0,
            },
            root_font,
            fixed_clip: None,
            inherited_floats: vec![],
            intrinsic: vec![None; doc.nodes.len()],
            glyphs: 0,
            collapsed: vec![None; doc.nodes.len()],
        }
    }
    pub fn run(mut self) -> Result<Scene> {
        let clip = Rect::new(0, 0, self.scene.width, MAX_COORD);
        let root = self
            .doc
            .nodes
            .iter()
            .position(|n| n.tag == "html")
            .unwrap_or(0);
        let r = self.block(root, 0, 0, self.scene.width, None, clip, 0)?;
        self.scene.height = self.scene.height.max(r.bottom()).min(MAX_COORD);
        self.semantics()?;
        self.scene.work_remaining = self.budget.remaining();
        Ok(self.scene)
    }
    fn eval(&self, l: Length, basis: Au, s: &Style) -> Au {
        l.eval(
            basis,
            s.font_size,
            self.root_font,
            self.scene.width,
            self.scene.height,
        )
    }
    fn val(&self, z: Size, basis: Au, s: &Style) -> Option<Au> {
        z.eval(
            basis,
            s.font_size,
            self.root_font,
            self.scene.width,
            self.scene.height,
        )
    }
    fn corner(&self, s: &Style, r: Rect) -> Au {
        s.radius_percent
            .map(|n| ((r.w.min(r.h) as i128 * n as i128) / 10000).clamp(0, MAX_COORD as i128) as Au)
            .unwrap_or(s.radius)
    }
    fn margins(&self, s: &Style, basis: Au) -> Edges<Au> {
        Edges {
            top: self.val(s.margin.top, basis, s).unwrap_or(0),
            right: self.val(s.margin.right, basis, s).unwrap_or(0),
            bottom: self.val(s.margin.bottom, basis, s).unwrap_or(0),
            left: self.val(s.margin.left, basis, s).unwrap_or(0),
        }
    }
    fn vertical_shift(&self, s: &Style) -> Au {
        match s.vertical_align.as_str() {
            "super" => s.font_size / 3,
            "sub" => -s.font_size / 5,
            _ => length(&s.vertical_align)
                .map(|value| self.eval(value, s.line_height, s))
                .unwrap_or(0),
        }
    }
    fn insets(&self, s: &Style, basis: Au) -> Edges<Au> {
        let bw = |b: Border| {
            if matches!(b.style, BorderStyle::None | BorderStyle::Hidden) {
                0
            } else {
                b.width
            }
        };
        Edges {
            top: self.eval(s.padding.top, basis, s) + bw(s.border.top),
            right: self.eval(s.padding.right, basis, s) + bw(s.border.right),
            bottom: self.eval(s.padding.bottom, basis, s) + bw(s.border.bottom),
            left: self.eval(s.padding.left, basis, s) + bw(s.border.left),
        }
    }
    fn emit(&mut self, draw: Draw, clip: Rect, _s: &Style) -> Result<usize> {
        self.budget.charge(1)?;
        if self.scene.primitives.len() >= self.limits.primitives {
            return Err(Error::Budget("primitives"));
        }
        let id = self.scene.primitives.len();
        self.scene.primitives.push(Primitive {
            clip,
            fixed_clip: self.fixed_clip,
            clip_radius: 0,
            opacity: 1000,
            draw,
        });
        Ok(id)
    }
    fn rect(&mut self, r: Rect, c: u32, radius: Au, clip: Rect, s: &Style) -> Result<()> {
        if c & 255 != 0 && r.w > 0 && r.h > 0 && s.visible && s.opacity > 0 {
            self.emit(
                Draw::Rect {
                    rect: r,
                    color: c,
                    radius,
                },
                clip,
                s,
            )?;
        }
        Ok(())
    }
    fn top_margin(&mut self, id: NodeId, basis: Au, depth: usize) -> Result<Au> {
        self.budget.charge(1)?;
        if depth > self.limits.depth {
            return Err(Error::Budget("margin depth"));
        }
        let s = &self.styles[id];
        let mut m = self.margins(s, basis).top;
        let e = self.insets(s, basis);
        if s.display == Display::Block
            && e.top == 0
            && !matches!(self.doc.nodes[id].tag.as_str(), "html")
        {
            for c in &self.doc.nodes[id].children {
                let n = &self.doc.nodes[*c];
                if self.styles[*c].display == Display::None
                    || matches!(n.kind, Kind::Comment)
                    || matches!(n.kind, Kind::Text) && n.text.trim().is_empty()
                {
                    continue;
                }
                if self.styles[*c].float != Float::None {
                    continue;
                }
                if self.styles[*c].clear == "none"
                    && matches!(self.styles[*c].display, Display::Block | Display::ListItem)
                {
                    m = collapse_margin(m, self.top_margin(*c, basis, depth + 1)?);
                }
                break;
            }
        }
        Ok(m)
    }
    fn bottom_margin(&mut self, id: NodeId, basis: Au, depth: usize) -> Result<Au> {
        self.budget.charge(1)?;
        if depth > self.limits.depth {
            return Err(Error::Budget("margin depth"));
        }
        let s = &self.styles[id];
        let mut m = self.margins(s, basis).bottom;
        let e = self.insets(s, basis);
        if s.display == Display::Block && e.bottom == 0 && s.height == Size::Auto {
            for c in self.doc.nodes[id].children.iter().rev() {
                let n = &self.doc.nodes[*c];
                if self.styles[*c].display == Display::None
                    || matches!(n.kind, Kind::Comment)
                    || matches!(n.kind, Kind::Text) && n.text.trim().is_empty()
                {
                    continue;
                }
                if self.styles[*c].float != Float::None {
                    continue;
                }
                if matches!(self.styles[*c].display, Display::Block | Display::ListItem) {
                    m = collapse_margin(m, self.bottom_margin(*c, basis, depth + 1)?);
                }
                break;
            }
        }
        Ok(m)
    }
    fn block(
        &mut self,
        id: NodeId,
        x: Au,
        y: Au,
        available: Au,
        forced: Option<Au>,
        clip: Rect,
        depth: usize,
    ) -> Result<Rect> {
        self.budget.charge(1)?;
        if depth > self.limits.depth {
            return Err(Error::Budget("layout depth"));
        }
        let mut s = self.effective(id);
        let empty_cell = s.display == Display::Cell && !s.empty_cells && self.cell_empty(id)?;
        if empty_cell {
            s.background_color = 0;
            s.backgrounds.clear();
        }
        if s.display == Display::None || self.doc.nodes[id].disabled {
            return Ok(Rect::new(x, y, 0, 0));
        }
        if s.display == Display::Table {
            return self.table(id, x, y, available, forced, clip, depth + 1);
        }
        if self.doc.nodes[id].tag == "img" {
            let (w, _, _) = self.image_size(id, available);
            let e = self.insets(&s, available);
            let m = self.margins(&s, available);
            let free = (available - w - e.left - e.right - m.left - m.right).max(0);
            let offset = m.left
                + if s.margin.left == Size::Auto && s.margin.right == Size::Auto {
                    free / 2
                } else if s.margin.left == Size::Auto {
                    free
                } else {
                    0
                };
            return self.image_box(id, x + offset, y, available, clip);
        }
        let m = self.margins(&s, available);
        let edges = self.insets(&s, available);
        let pad = edges.left + edges.right;
        let mut w = forced.unwrap_or_else(|| {
            self.val(s.width, available, &s)
                .map(|n| if s.border_box { n } else { n + pad })
                .unwrap_or((available - m.left - m.right).max(pad))
        });
        if let Some(max) = self.val(s.max_width, available, &s) {
            w = w.min(if s.border_box { max } else { max + pad });
        }
        if let Some(min) = self.val(s.min_width, available, &s) {
            w = w.max(if s.border_box { min } else { min + pad });
        }
        w = w.max(pad).min(MAX_COORD);
        let free = (available - w - m.left - m.right).max(0);
        let containing_rtl = self.doc.nodes[id]
            .parent
            .map(|parent| self.styles[parent].direction_rtl)
            .unwrap_or(false);
        let left = m.left
            + if s.float != Float::None {
                0
            } else {
                match (s.margin.left, s.margin.right) {
                    (Size::Auto, Size::Auto) => free / 2,
                    (Size::Auto, _) => free,
                    (_, _) if containing_rtl && s.width != Size::Auto => free,
                    _ => 0,
                }
            };
        let bx = x + left;
        let cx = bx + edges.left;
        let raw_cy = y + edges.top;
        let cy = if s.display == Display::ListItem {
            ((raw_cy + PX - 1) / PX) * PX
        } else {
            raw_cy
        };
        let cw = (w - pad).max(0);
        if s.opacity < 1000 {
            self.emit(Draw::BeginOpacity { opacity: s.opacity }, clip, &s)?;
        }
        let first = self.scene.primitives.len();
        let bg = self.emit(
            Draw::Rect {
                rect: Rect::new(bx, y, w, 0),
                color: if s.visible { s.background_color } else { 0 },
                radius: s.radius,
            },
            clip,
            &s,
        )?;
        let previous_fixed_clip = self.fixed_clip;
        let mut content_clip = clip;
        if s.overflow_hidden {
            let own = Rect::new(
                bx,
                y,
                w,
                self.val(s.height, self.scene.height, &s)
                    .unwrap_or(MAX_COORD - y - edges.top - edges.bottom)
                    + edges.top
                    + edges.bottom,
            );
            if self.fixed_clip.is_some() {
                content_clip = content_clip.intersect(own);
            } else {
                self.fixed_clip = Some(clip);
                content_clip = own;
            }
        }
        let child_ids = self.doc.nodes[id].children.clone();
        let mut cursor = cy;
        let mut previous_margin = 0;
        let mut inline = vec![];
        let mut floats: Vec<Floating> = self.inherited_floats.clone();
        let mut first_content = true;
        for child in child_ids {
            let cs = self.styles[child].clone();
            if cs.display == Display::None
                || self.doc.nodes[child].disabled
                || matches!(self.doc.nodes[child].kind, Kind::Comment)
            {
                continue;
            }
            if cs.float != Float::None {
                if !inline.is_empty() {
                    cursor = self.inline(
                        id,
                        &inline,
                        cx,
                        cursor,
                        cw,
                        content_clip,
                        &floats,
                        depth + 1,
                    )?;
                    inline.clear();
                    first_content = false;
                }
                let (_, max) = self.measure(child, depth + 1)?;
                let margins = self.margins(&cs, cw);
                let edges = self.insets(&cs, cw);
                let available = (cw - margins.left - margins.right).max(PX);
                let desired = self
                    .val(cs.width, cw, &cs)
                    .map(|value| {
                        if cs.border_box {
                            value
                        } else {
                            value + edges.left + edges.right
                        }
                    })
                    .unwrap_or(max)
                    .min(available)
                    .max(PX);
                let mut fy = checked_add(cursor, margins.top)?;
                let (mut fx, mut fw) = self.line_space(cx, fy, cw, cs.font_size, &floats);
                while fw < desired {
                    if let Some(bottom) = floats
                        .iter()
                        .filter(|f| f.rect.bottom() > fy)
                        .map(|f| f.rect.bottom())
                        .min()
                    {
                        fy = bottom;
                        (fx, fw) = self.line_space(cx, fy, cw, cs.font_size, &floats);
                        self.budget.charge(1)?;
                    } else {
                        break;
                    }
                }
                if cs.float == Float::Right {
                    // `fx` is the margin-box origin passed to `block`, which
                    // adds the left margin before placing the border box. Keep
                    // the entire margin box inside the available line space.
                    fx += fw - desired - margins.left - margins.right;
                }
                let r = self.block(child, fx, fy, cw, Some(desired), content_clip, depth + 1)?;
                floats.push(Floating {
                    rect: Rect::new(
                        r.x - margins.left,
                        r.y - margins.top,
                        r.w + margins.left + margins.right,
                        r.h + margins.top + margins.bottom,
                    ),
                    side: cs.float,
                });
                continue;
            }
            if matches!(
                cs.display,
                Display::Block
                    | Display::ListItem
                    | Display::Table
                    | Display::RowGroup
                    | Display::Row
                    | Display::Caption
            ) {
                if !inline.is_empty() {
                    cursor = self.inline(
                        id,
                        &inline,
                        cx,
                        cursor,
                        cw,
                        content_clip,
                        &floats,
                        depth + 1,
                    )?;
                    inline.clear();
                    previous_margin = 0;
                    first_content = false;
                }
                let mut cleared = false;
                if cs.clear != "none" {
                    for f in &floats {
                        if cs.clear == "both"
                            || cs.clear == "left" && f.side == Float::Left
                            || cs.clear == "right" && f.side == Float::Right
                        {
                            let next = cursor.max(f.rect.bottom());
                            cleared |= next != cursor;
                            cursor = next;
                        }
                    }
                }
                let top = if cleared {
                    0
                } else {
                    self.top_margin(child, cw, 0)?
                };
                let collapse_first = first_content
                    && edges.top == 0
                    && s.display == Display::Block
                    && self.doc.nodes[id].tag != "html";
                if !collapse_first {
                    cursor = checked_add(cursor, collapse_margin(previous_margin, top))?;
                }
                let saved = self.inherited_floats.clone();
                self.inherited_floats = floats.clone();
                let r = self.block(child, cx, cursor, cw, None, content_clip, depth + 1)?;
                self.inherited_floats = saved;
                cursor = r.bottom();
                previous_margin = self.bottom_margin(child, cw, 0)?;
                first_content = false;
            } else {
                inline.push(child);
            }
        }
        if !inline.is_empty() {
            cursor = checked_add(cursor, previous_margin)?;
            cursor = self.inline(
                id,
                &inline,
                cx,
                cursor,
                cw,
                content_clip,
                &floats,
                depth + 1,
            )?;
            previous_margin = 0;
        }
        let collapse_bottom = edges.bottom == 0
            && s.height == Size::Auto
            && s.display == Display::Block
            && self.doc.nodes[id].tag != "html";
        if !collapse_bottom {
            cursor = checked_add(cursor, previous_margin)?;
        }
        let contains_descendant_floats = self.doc.nodes[id].tag == "html"
            || s.display == Display::Cell
            || s.display == Display::InlineBlock
            || s.float != Float::None
            || s.overflow_hidden;
        if contains_descendant_floats && s.height == Size::Auto {
            for (node, b) in self.scene.boxes.iter().enumerate() {
                self.budget.charge(1)?;
                if self.styles[node].float != Float::None {
                    let mut in_context = self.doc.nodes[id].tag == "html";
                    let mut ancestor = self.doc.nodes[node].parent;
                    while !in_context {
                        self.budget.charge(1)?;
                        let Some(current) = ancestor else { break };
                        if current == id {
                            in_context = true;
                            break;
                        }
                        ancestor = self.doc.nodes[current].parent;
                    }
                    if !in_context {
                        continue;
                    }
                    if let Some(b) = b {
                        let bottom = self.margins(&self.styles[node], cw).bottom;
                        cursor = cursor.max(checked_add(b.border.bottom(), bottom)?);
                    }
                }
            }
        }
        let mut h = (cursor - cy).max(0);
        if s.height == Size::Auto
            && s.display == Display::ListItem
            && matches!(s.list_type.as_str(), "disc" | "circle" | "square")
            && s.line_height > 0
            && h % s.line_height == 0
        {
            // Gecko's graphical marker contributes its half-pixel overflow
            // when ordinary text struts determine the item height. A taller
            // replaced box already determines the principal height.
            h = checked_add(h, PX / 2)?;
        }
        if let Some(value) = self.val(s.height, self.scene.height, &s) {
            let specified = if s.border_box {
                (value - edges.top - edges.bottom).max(0)
            } else {
                value.max(0)
            };
            // CSS table-cell height contributes a minimum to the row. Cell
            // contents are not clipped down to the declared height.
            h = if s.display == Display::Cell {
                h.max(specified)
            } else {
                specified
            };
        }
        if let Some(max) = self.val(s.max_height, self.scene.height, &s) {
            h = h.min(max);
        }
        if let Some(min) = self.val(s.min_height, self.scene.height, &s) {
            h = h.max(min);
        }
        let r = Rect::new(bx, y, w, checked_add(h, edges.top + edges.bottom)?);
        if r.right().abs() > MAX_COORD || r.bottom().abs() > MAX_COORD {
            return Err(Error::Budget("document geometry"));
        }
        let actual_radius = self.corner(&s, r);
        let borders = [s.border.top, s.border.right, s.border.bottom, s.border.left];
        let opaque_uniform_rounded_border = actual_radius > 0
            && s.background_clip == "border-box"
            && borders.iter().all(|border| {
                border.style == BorderStyle::Solid
                    && border.width == borders[0].width
                    && border.color & 255 == 255
            });
        let color_area = self.area(&s, r, Rect::new(cx, cy, cw, h), &s.background_clip);
        if let Draw::Rect { rect, radius, .. } = &mut self.scene.primitives[bg].draw {
            if opaque_uniform_rounded_border {
                // Gecko leaves a one-device-pixel overlap between an opaque
                // rounded border and its background to avoid an AA seam.
                let inset = (borders[0].width - PX).max(0);
                *rect = Rect::new(r.x + inset, r.y + inset, r.w - 2 * inset, r.h - 2 * inset);
                *radius = (actual_radius - inset).max(0);
            } else {
                *rect = color_area;
                *radius = actual_radius;
            }
        }
        self.fixed_clip = previous_fixed_clip;
        let baseline = self
            .scene
            .lines
            .iter()
            .rev()
            .find(|l| l.parent >= id)
            .map(|l| l.baseline)
            .unwrap_or(r.bottom());
        self.scene.boxes[id] = Some(LayoutBox {
            node: id,
            border: r,
            content: Rect::new(cx, cy, cw, h),
            baseline,
        });
        if !s.backgrounds.is_empty() {
            let after = self.scene.primitives.split_off(first + 1);
            self.backgrounds(&s, r, Rect::new(cx, cy, cw, h), content_clip)?;
            self.scene.primitives.extend(after);
        }
        if self.collapsed[id].is_none() && !empty_cell {
            self.borders(&s, r, clip)?;
        }
        if s.display == Display::ListItem && !s.list_inside && s.list_type != "none" {
            if s.list_type == "disc" {
                // Gecko paints the default outside disc as marker geometry,
                // not as the font's asymmetrical U+2022 outline.
                self.emit(
                    Draw::DiscMarker {
                        rect: Rect::new(bx - 14 * PX, baseline - 7 * PX - PX / 2, 6 * PX, 6 * PX),
                        color: s.color,
                    },
                    clip,
                    &s,
                )?;
            } else {
                let marker = self.marker(id);
                let run = self.fonts.shape(&marker, &s, self.budget)?;
                let mx = bx - run.width - self.fonts.shape(" ", &s, self.budget)?.width;
                self.text(id, mx, baseline, run, clip, &s)?;
            }
        }
        if s.opacity < 1000 {
            self.emit(Draw::EndOpacity, clip, &s)?;
        }
        Ok(r)
    }
    fn cell_empty(&mut self, id: NodeId) -> Result<bool> {
        let mut stack = self.doc.nodes[id].children.clone();
        while let Some(i) = stack.pop() {
            self.budget.charge(1)?;
            let n = &self.doc.nodes[i];
            if n.disabled || self.styles[i].display == Display::None {
                continue;
            }
            if matches!(n.kind, Kind::Text)
                && !n
                    .text
                    .chars()
                    .all(|c| matches!(c, ' ' | '\t' | '\r' | '\n' | '\x0c'))
            {
                return Ok(false);
            }
            if matches!(n.tag.as_str(), "img" | "br" | "hr") {
                return Ok(false);
            }
            stack.extend(&n.children);
        }
        Ok(true)
    }
    fn line_space(&self, x: Au, y: Au, w: Au, h: Au, floats: &[Floating]) -> (Au, Au) {
        let mut left = x;
        let mut right = x + w;
        for f in floats {
            if f.rect.y < y + h && f.rect.bottom() > y {
                if f.side == Float::Left {
                    left = left.max(f.rect.right());
                } else {
                    right = right.min(f.rect.x);
                }
            }
        }
        (left, (right - left).max(0))
    }
    fn marker(&self, id: NodeId) -> String {
        let s = &self.styles[id];
        if matches!(s.list_type.as_str(), "disc" | "circle" | "square") {
            return match s.list_type.as_str() {
                "circle" => "◦",
                "square" => "▪",
                _ => "•",
            }
            .into();
        }
        let mut n = 1i64;
        if let Some(p) = self.doc.nodes[id].parent {
            n = self.doc.nodes[p]
                .attr("start")
                .and_then(|x| x.parse::<i64>().ok())
                .unwrap_or(1);
            for c in &self.doc.nodes[p].children {
                if *c == id {
                    break;
                }
                if self.doc.nodes[*c].tag == "li" {
                    n = n.saturating_add(1);
                }
            }
        }
        if let Some(v) = self.doc.nodes[id]
            .attr("value")
            .and_then(|x| x.parse::<i64>().ok())
        {
            n = v;
        }
        match s.list_type.as_str() {
            "lower-alpha" | "lower-latin" => alphabetic_counter(n, false)
                .map(|value| format!("{value}."))
                .unwrap_or_else(|| format!("{n}.")),
            "upper-alpha" | "upper-latin" => alphabetic_counter(n, true)
                .map(|value| format!("{value}."))
                .unwrap_or_else(|| format!("{n}.")),
            "lower-roman" => roman_counter(n, false)
                .map(|value| format!("{value}."))
                .unwrap_or_else(|| format!("{n}.")),
            "upper-roman" => roman_counter(n, true)
                .map(|value| format!("{value}."))
                .unwrap_or_else(|| format!("{n}.")),
            _ => format!("{n}."),
        }
    }
    fn text_items(
        &mut self,
        id: NodeId,
        text: &str,
        s: &Style,
        space: bool,
        items: &mut Vec<Item>,
    ) -> Result<()> {
        if !space
            && !matches!(s.whitespace, WhiteSpace::Pre | WhiteSpace::Nowrap)
            && s.word_break != "keep-all"
        {
            let mut from = 0;
            for (to, _) in unicode_linebreak::linebreaks(text) {
                if to > from {
                    let run = self.fonts.shape(&text[from..to], s, self.budget)?;
                    items.push(Item::Text {
                        node: id,
                        run,
                        space: false,
                    });
                    from = to;
                }
            }
        } else {
            let run = self.fonts.shape(text, s, self.budget)?;
            items.push(Item::Text {
                node: id,
                run,
                space,
            });
        }
        Ok(())
    }
    fn collect(&mut self, id: NodeId, items: &mut Vec<Item>, depth: usize) -> Result<()> {
        self.budget.charge(1)?;
        if depth > self.limits.depth {
            return Err(Error::Budget("inline depth"));
        }
        let node = &self.doc.nodes[id];
        let s = self.styles[id].clone();
        if s.display == Display::None || node.disabled {
            return Ok(());
        }
        if node.tag == "br" {
            items.push(Item::Break(id));
            return Ok(());
        }
        if node.tag == "wbr" {
            items.push(Item::Opportunity(id));
            return Ok(());
        }
        if matches!(
            s.display,
            Display::Block
                | Display::ListItem
                | Display::Table
                | Display::RowGroup
                | Display::Row
                | Display::Caption
        ) {
            items.push(Item::Block(id));
            return Ok(());
        }
        if node.tag == "img" || s.display == Display::InlineBlock {
            items.push(Item::Box(id));
            return Ok(());
        }
        if matches!(node.kind, Kind::Text) {
            let text = node.text.clone();
            let preserve = matches!(s.whitespace, WhiteSpace::Pre | WhiteSpace::PreWrap);
            let mut part = String::new();
            let mut is_space = None;
            for c in text.chars() {
                if c == '\n' && (preserve || s.whitespace == WhiteSpace::PreLine) {
                    if !part.is_empty() {
                        self.text_items(id, &part, &s, is_space == Some(true), items)?;
                        part.clear();
                    }
                    items.push(Item::Break(id));
                    is_space = None;
                    continue;
                }
                let whitespace = matches!(c, ' ' | '\n' | '\r' | '\t' | '\x0c');
                if is_space.is_some() && is_space != Some(whitespace) {
                    self.text_items(id, &part, &s, is_space == Some(true), items)?;
                    part.clear();
                }
                is_space = Some(whitespace);
                if whitespace && !preserve {
                    if part.is_empty() {
                        part.push(' ');
                    }
                } else if c == '\t' {
                    part.push_str("        ");
                } else {
                    part.push(c);
                }
            }
            if !part.is_empty() {
                self.text_items(id, &part, &s, is_space == Some(true), items)?;
            }
            return Ok(());
        }
        for child in node.children.clone() {
            self.collect(child, items, depth + 1)?;
        }
        Ok(())
    }
    fn bidi_levels(&mut self, parent: NodeId, items: &[Item]) -> Result<Vec<unicode_bidi::Level>> {
        let mut paragraph = String::new();
        let mut starts = Vec::with_capacity(items.len());
        let mut active_isolates: Vec<(NodeId, bool)> = vec![];
        for item in items {
            let node = match item {
                Item::Text { node, .. }
                | Item::Break(node)
                | Item::Opportunity(node)
                | Item::Box(node)
                | Item::Block(node) => *node,
            };
            let mut isolates = vec![];
            let mut ancestor = Some(node);
            while let Some(id) = ancestor {
                self.budget.charge(1)?;
                if id == parent {
                    break;
                }
                if let Some(value) = self.doc.nodes[id].attr("dir") {
                    if value.eq_ignore_ascii_case("ltr") || value.eq_ignore_ascii_case("rtl") {
                        isolates.push((id, value.eq_ignore_ascii_case("rtl")));
                    }
                }
                ancestor = self.doc.nodes[id].parent;
            }
            isolates.reverse();
            let shared = active_isolates
                .iter()
                .zip(&isolates)
                .take_while(|(left, right)| left == right)
                .count();
            for _ in shared..active_isolates.len() {
                paragraph.push('\u{2069}'); // PDI
            }
            for (_, rtl) in &isolates[shared..] {
                paragraph.push(if *rtl { '\u{2067}' } else { '\u{2066}' }); // RLI/LRI
            }
            active_isolates = isolates;
            starts.push(paragraph.len());
            match item {
                Item::Text { run, .. } => paragraph.push_str(&run.text),
                Item::Break(_) => paragraph.push('\n'),
                Item::Opportunity(_) => paragraph.push('\u{200b}'),
                Item::Box(_) => paragraph.push('\u{fffc}'),
                Item::Block(_) => paragraph.push('\u{2029}'),
            }
        }
        for _ in 0..active_isolates.len() {
            paragraph.push('\u{2069}'); // PDI
        }
        let base = if self.styles[parent].direction_rtl {
            unicode_bidi::Level::rtl()
        } else {
            unicode_bidi::Level::ltr()
        };
        let bidi = unicode_bidi::BidiInfo::new(&paragraph, Some(base));
        Ok(starts
            .into_iter()
            .map(|start| bidi.levels.get(start).copied().unwrap_or(base))
            .collect())
    }
    fn inline(
        &mut self,
        parent: NodeId,
        nodes: &[NodeId],
        x: Au,
        start: Au,
        width: Au,
        clip: Rect,
        floats: &[Floating],
        depth: usize,
    ) -> Result<Au> {
        let mut items = vec![];
        for id in nodes {
            self.collect(*id, &mut items, depth + 1)?;
        }
        if self.styles[parent].display == Display::ListItem && self.styles[parent].list_inside {
            let s = &self.styles[parent];
            let mut run = self
                .fonts
                .shape(&(self.marker(parent) + " "), s, self.budget)?;
            match s.list_type.as_str() {
                "disc" | "circle" => {
                    // Gecko's round inside markers reserve a small marker-side
                    // gap beyond the shaped glyph plus ordinary word space.
                    run.width += s.font_size * 17 / 320;
                }
                "square" => {
                    // The square marker's typographic advance is slightly
                    // narrower than the font glyph plus an ordinary space.
                    run.width -= s.font_size * 17 / 480;
                }
                _ => {}
            }
            items.insert(
                0,
                Item::Text {
                    node: parent,
                    run,
                    space: false,
                },
            );
        }
        // Resolve the Unicode bidi paragraph before wrapping. Recomputing it
        // for each visual line loses the context that determines neutral and
        // isolate levels, so a wrapped `dir` subtree can otherwise jump to the
        // opposite side of its following text.
        let item_levels = self.bidi_levels(parent, &items)?;
        let ps = self.styles[parent].clone();
        let (_, _, normal) = self.fonts.metrics(&ps);
        let default_height = if !ps.normal_line_height {
            ps.line_height
        } else {
            normal
        };
        let mut y = start;
        let (mut lx, mut lw) = self.line_space(x, y, width, default_height, floats);
        let mut pen = 0;
        let mut line: Vec<Placed> = vec![];
        let mut line_height = default_height;
        let (strut_a, strut_d, _) = self.fonts.metrics(&ps);
        let strut_above = strut_a + (default_height - strut_a - strut_d) / 2;
        let mut line_ascent = strut_above;
        let mut pending_space: Option<(NodeId, Run, unicode_bidi::Level)> = None;
        let mut first = true;
        for (item, bidi_level) in items.into_iter().zip(item_levels) {
            self.budget.charge(1)?;
            match item {
                Item::Break(_) => {
                    self.finish_line(
                        parent,
                        &line,
                        lx,
                        y,
                        lw,
                        pen,
                        line_height,
                        line_ascent,
                        clip,
                    )?;
                    y = checked_add(y, line_height)?;
                    line.clear();
                    pen = 0;
                    line_height = default_height;
                    line_ascent = strut_above;
                    pending_space = None;
                    first = false;
                    (lx, lw) = self.line_space(x, y, width, default_height, floats);
                }
                Item::Opportunity(_) => {}
                Item::Text { node, run, space } => {
                    let s = self.styles[node].clone();
                    let preserve = matches!(s.whitespace, WhiteSpace::Pre | WhiteSpace::PreWrap);
                    if space && !preserve {
                        if !line.is_empty() {
                            pending_space = Some((node, run, bidi_level));
                        }
                        continue;
                    }
                    let sw = pending_space.as_ref().map(|(_, r, _)| r.width).unwrap_or(0);
                    let wrapping = !matches!(s.whitespace, WhiteSpace::Pre | WhiteSpace::Nowrap);
                    let split_run = wrapping
                        && (s.word_break == "break-all"
                            || ((s.word_break == "break-word" || s.overflow_wrap)
                                && run.width > lw));
                    if wrapping
                        && s.word_break != "break-all"
                        && pen + sw + run.width > lw
                        && !line.is_empty()
                    {
                        self.finish_line(
                            parent,
                            &line,
                            lx,
                            y,
                            lw,
                            pen,
                            line_height,
                            line_ascent,
                            clip,
                        )?;
                        y = checked_add(y, line_height)?;
                        line.clear();
                        pen = 0;
                        line_height = default_height;
                        line_ascent = strut_above;
                        pending_space = None;
                        first = false;
                        (lx, lw) = self.line_space(x, y, width, default_height, floats);
                    }
                    if let Some((n, r, level)) = pending_space.take() {
                        line.push(Placed::Text {
                            node: n,
                            run: r.clone(),
                            x: pen,
                            level,
                        });
                        pen += r.width;
                    }
                    if first && line.is_empty() {
                        pen += self.eval(ps.indent, width, &ps);
                    }
                    if split_run {
                        let mut shaping_style = s.clone();
                        shaping_style.transform = "none".into();
                        let mut offset = 0;
                        while offset < run.text.len() {
                            let ends: Vec<_> = run.text[offset..]
                                .grapheme_indices(true)
                                .map(|(index, grapheme)| offset + index + grapheme.len())
                                .collect();
                            let room = (lw - pen).max(0);
                            let (mut lo, mut hi) = (0usize, ends.len());
                            while lo < hi {
                                self.budget.charge(1)?;
                                let mid = lo + (hi - lo).div_ceil(2);
                                let candidate = self.fonts.shape(
                                    &run.text[offset..ends[mid - 1]],
                                    &shaping_style,
                                    self.budget,
                                )?;
                                if candidate.width <= room {
                                    lo = mid;
                                } else {
                                    hi = mid - 1;
                                }
                            }
                            if lo == 0 && !line.is_empty() {
                                self.finish_line(
                                    parent,
                                    &line,
                                    lx,
                                    y,
                                    lw,
                                    pen,
                                    line_height,
                                    line_ascent,
                                    clip,
                                )?;
                                y = checked_add(y, line_height)?;
                                line.clear();
                                pen = 0;
                                line_height = default_height;
                                line_ascent = strut_above;
                                first = false;
                                (lx, lw) = self.line_space(x, y, width, default_height, floats);
                                continue;
                            }
                            let end = ends[lo.saturating_sub(1)];
                            let end = if lo == 0 { ends[0] } else { end };
                            let piece = self.fonts.shape(
                                &run.text[offset..end],
                                &shaping_style,
                                self.budget,
                            )?;
                            let (_, _, font_height) = self.fonts.metrics(&s);
                            let used = if !s.normal_line_height {
                                s.line_height
                            } else {
                                font_height
                            };
                            let leading = (used - piece.ascent - piece.descent) / 2;
                            let below = (line_height - line_ascent).max(piece.descent + leading);
                            line_ascent = line_ascent.max(piece.ascent + leading);
                            line_height = line_ascent + below;
                            line.push(Placed::Text {
                                node,
                                run: piece.clone(),
                                x: pen,
                                level: bidi_level,
                            });
                            pen = checked_add(pen, piece.width)?;
                            offset = end;
                            if offset < run.text.len() {
                                self.finish_line(
                                    parent,
                                    &line,
                                    lx,
                                    y,
                                    lw,
                                    pen,
                                    line_height,
                                    line_ascent,
                                    clip,
                                )?;
                                y = checked_add(y, line_height)?;
                                line.clear();
                                pen = 0;
                                line_height = default_height;
                                line_ascent = strut_above;
                                first = false;
                                (lx, lw) = self.line_space(x, y, width, default_height, floats);
                            }
                        }
                    } else {
                        let (_, _, h) = self.fonts.metrics(&s);
                        let used = if !s.normal_line_height {
                            s.line_height
                        } else {
                            h
                        };
                        let leading = (used - run.ascent - run.descent) / 2;
                        let vertical_shift = self.vertical_shift(&s);
                        let below =
                            (line_height - line_ascent).max(run.descent + leading - vertical_shift);
                        line_ascent = line_ascent.max(run.ascent + leading + vertical_shift);
                        line_height = line_ascent + below;
                        pen = checked_add(pen, run.width)?;
                        let xx = pen - run.width;
                        line.push(Placed::Text {
                            node,
                            run,
                            x: xx,
                            level: bidi_level,
                        });
                    }
                }
                Item::Block(id) => {
                    if !line.is_empty() {
                        self.finish_line(
                            parent,
                            &line,
                            lx,
                            y,
                            lw,
                            pen,
                            line_height,
                            line_ascent,
                            clip,
                        )?;
                        y = checked_add(y, line_height)?;
                        line.clear();
                    }
                    let s = self.styles[id].clone();
                    let margins = self.margins(&s, width);
                    y = checked_add(y, margins.top)?;
                    let r = self.block(id, x, y, width, None, clip, depth + 1)?;
                    y = checked_add(r.bottom(), margins.bottom)?;
                    pending_space = None;
                    pen = 0;
                    line_height = default_height;
                    line_ascent = strut_above;
                    first = false;
                    (lx, lw) = self.line_space(x, y, width, default_height, floats);
                }
                Item::Box(id) => {
                    let s = self.styles[id].clone();
                    let margins = self.margins(&s, width);
                    let a = self.scene.primitives.len();
                    let ln = self.scene.lines.len();
                    let r = if self.doc.nodes[id].tag == "img" {
                        self.image_box(id, 0, 0, width, clip)?
                    } else {
                        let (min, max) = self.measure(id, depth + 1)?;
                        let e = self.insets(&s, width);
                        let shrink_available = (width - margins.left - margins.right).max(0);
                        let w = self
                            .val(s.width, width, &s)
                            .map(|n| {
                                if s.border_box {
                                    n
                                } else {
                                    n + e.left + e.right
                                }
                            })
                            .unwrap_or(max.min(shrink_available).max(min));
                        // Percentage padding and min/max constraints remain
                        // relative to the containing block, not the resolved
                        // shrink-to-fit width passed through `forced`.
                        self.block(id, 0, 0, width, Some(w), clip, depth + 1)?
                    };
                    let b = self.scene.primitives.len();
                    let advance = margins.left + r.w + margins.right;
                    let sw = pending_space.as_ref().map(|(_, r, _)| r.width).unwrap_or(0);
                    if pen + sw + advance > lw
                        && !line.is_empty()
                        && !matches!(ps.whitespace, WhiteSpace::Nowrap | WhiteSpace::Pre)
                    {
                        self.finish_line(
                            parent,
                            &line,
                            lx,
                            y,
                            lw,
                            pen,
                            line_height,
                            line_ascent,
                            clip,
                        )?;
                        y = checked_add(y, line_height)?;
                        line.clear();
                        pen = 0;
                        pending_space = None;
                        (lx, lw) = self.line_space(x, y, width, default_height, floats);
                    }
                    if let Some((n, run, level)) = pending_space.take() {
                        pen += run.width;
                        line.push(Placed::Text {
                            node: n,
                            x: pen - run.width,
                            run,
                            level,
                        });
                    }
                    let below = (line_height - line_ascent).max(0);
                    match s.vertical_align.as_str() {
                        "top" | "text-top" | "bottom" | "text-bottom" => {
                            // These alignments position the margin box against
                            // the completed line. A box shorter than the strut
                            // does not enlarge that line merely because its
                            // top would sit above the text baseline.
                            line_height = line_height.max(margins.top + r.h + margins.bottom);
                        }
                        "middle" => {
                            // The margin-box midpoint sits one half x-height
                            // above the parent baseline. Account for both
                            // extents while constructing the line box; merely
                            // increasing its total height leaves a tall middle
                            // box protruding above the line in Gecko.
                            let margin_height = margins.top + r.h + margins.bottom;
                            let above = margin_height / 2 + self.fonts.x_height(&ps) / 2;
                            let below_box = margin_height - above;
                            line_ascent = line_ascent.max(above);
                            line_height = line_ascent + below.max(below_box);
                        }
                        _ => {
                            // An inline-block participates with the baseline
                            // of its last in-flow line. Replaced elements use
                            // their bottom edge, as recorded by image_box.
                            let box_baseline = self.scene.boxes[id]
                                .as_ref()
                                .map(|layout| (layout.baseline - r.y).clamp(0, r.h))
                                .unwrap_or(r.h);
                            let shift = self.vertical_shift(&s);
                            line_ascent = line_ascent.max(margins.top + box_baseline + shift);
                            line_height = line_ascent
                                + below.max(margins.bottom + r.h - box_baseline - shift);
                        }
                    }
                    line.push(Placed::Box {
                        id,
                        first: a,
                        last: b,
                        lines: (ln, self.scene.lines.len()),
                        x: pen,
                        rect: r,
                        margins,
                        advance,
                        level: bidi_level,
                    });
                    pen = checked_add(pen, advance)?;
                }
            }
        }
        if !line.is_empty() {
            self.finish_line(
                parent,
                &line,
                lx,
                y,
                lw,
                pen,
                line_height,
                line_ascent,
                clip,
            )?;
            y = checked_add(y, line_height)?;
        }
        Ok(y)
    }
    fn finish_line(
        &mut self,
        parent: NodeId,
        line: &[Placed],
        x: Au,
        y: Au,
        width: Au,
        used: Au,
        h: Au,
        ascent: Au,
        clip: Rect,
    ) -> Result<()> {
        let ps = self.styles[parent].clone();
        let mut shortened = vec![];
        let ellipsis = ps.overflow_hidden
            && ps.text_overflow == "ellipsis"
            && used > width
            && !ps.direction_rtl
            && matches!(ps.align, Align::Start | Align::Left);
        if ellipsis {
            let mark = self.fonts.shape("…", &ps, self.budget)?;
            let room = (width - mark.width).max(0);
            for item in line {
                match item {
                    Placed::Text {
                        node,
                        run,
                        x: xx,
                        level,
                    } => {
                        if *xx >= room {
                            continue;
                        }
                        if *xx + run.width <= room {
                            shortened.push(item.clone());
                            continue;
                        }
                        let mut boundaries: Vec<_> =
                            run.text.grapheme_indices(true).map(|(i, _)| i).collect();
                        boundaries.push(run.text.len());
                        let (mut lo, mut hi) = (0, boundaries.len());
                        while lo + 1 < hi {
                            self.budget.charge(1)?;
                            let mid = lo + (hi - lo) / 2;
                            let candidate = self.fonts.shape(
                                &run.text[..boundaries[mid]],
                                &self.styles[*node],
                                self.budget,
                            )?;
                            if candidate.width <= room - *xx {
                                lo = mid;
                            } else {
                                hi = mid;
                            }
                        }
                        if boundaries[lo] > 0 {
                            let prefix = self.fonts.shape(
                                &run.text[..boundaries[lo]],
                                &self.styles[*node],
                                self.budget,
                            )?;
                            shortened.push(Placed::Text {
                                node: *node,
                                run: prefix,
                                x: *xx,
                                level: *level,
                            });
                        }
                    }
                    Placed::Box {
                        first,
                        last,
                        x: xx,
                        advance,
                        ..
                    } => {
                        if *xx + advance <= room {
                            shortened.push(item.clone());
                        } else {
                            for p in &mut self.scene.primitives[*first..*last] {
                                p.clip = Rect::default();
                            }
                        }
                    }
                }
            }
            let end = shortened
                .iter()
                .map(|p| match p {
                    Placed::Text { x, run, .. } => x + run.width,
                    Placed::Box { x, advance, .. } => x + advance,
                })
                .max()
                .unwrap_or(0);
            shortened.push(Placed::Text {
                node: parent,
                // Gecko rasterizes the marker at the zero subpixel phase for
                // this trailing half-pixel advance.
                x: (end - PX / 2).max(0),
                run: mark,
                level: unicode_bidi::Level::ltr(),
            });
        }
        let line = if ellipsis { shortened.as_slice() } else { line };
        let offset = match ps.align {
            Align::Center => (width - used) / 2,
            Align::Right => width - used,
            Align::Start if ps.direction_rtl => width - used,
            Align::End if !ps.direction_rtl => width - used,
            _ => 0,
        };
        let baseline = y + ascent;
        self.scene.lines.push(LineBox {
            parent,
            rect: Rect::new(x, y, width, h),
            baseline,
        });
        let levels: Vec<_> = line
            .iter()
            .map(|item| match item {
                Placed::Text { level, .. } | Placed::Box { level, .. } => *level,
            })
            .collect();
        let visual = unicode_bidi::BidiInfo::reorder_visual(&levels);
        let mut positions = vec![0i64; line.len()];
        let mut advance = 0;
        let reorder = visual.iter().enumerate().any(|(i, j)| i != *j);
        for index in visual {
            positions[index] = advance;
            advance += match &line[index] {
                Placed::Text { run, .. } => run.width,
                Placed::Box { advance, .. } => *advance,
            };
        }
        let mut inline_backgrounds: Vec<(NodeId, Rect)> = vec![];
        for (index, p) in line.iter().enumerate() {
            if let Placed::Text {
                node, run, x: xx, ..
            } = p
            {
                let xx = if reorder { positions[index] } else { *xx };
                let r = Rect::new(
                    x + offset + xx,
                    baseline - run.ascent,
                    run.width,
                    run.ascent + run.descent,
                );
                let mut ancestor = self.doc.nodes[*node].parent;
                while let Some(id) = ancestor {
                    self.budget.charge(1)?;
                    if self.styles[id].display != Display::Inline {
                        break;
                    }
                    if self.styles[id].background_color & 255 != 0 {
                        if let Some((_, bounds)) =
                            inline_backgrounds.iter_mut().find(|(i, _)| *i == id)
                        {
                            let left = bounds.x.min(r.x);
                            let top = bounds.y.min(r.y);
                            *bounds = Rect::new(
                                left,
                                top,
                                bounds.right().max(r.right()) - left,
                                bounds.bottom().max(r.bottom()) - top,
                            );
                        } else {
                            inline_backgrounds.push((id, r));
                        }
                    }
                    ancestor = self.doc.nodes[id].parent;
                }
            }
        }
        inline_backgrounds.sort_by_key(|(id, _)| self.doc.nodes[*id].depth);
        for (id, r) in inline_backgrounds {
            let s = self.styles[id].clone();
            self.rect(r, s.background_color, self.corner(&s, r), clip, &s)?;
        }
        for (index, p) in line.iter().enumerate() {
            let bidi_x = positions[index];
            match p {
                Placed::Text {
                    node,
                    run,
                    x: original_x,
                    ..
                } => {
                    let xx = if reorder { &bidi_x } else { original_x };
                    let s = self.styles[*node].clone();
                    let yy = baseline - self.vertical_shift(&s);
                    let r = Rect::new(
                        x + offset + xx,
                        yy - run.ascent,
                        run.width,
                        run.ascent + run.descent,
                    );
                    self.rect(r, s.background_color, s.radius, clip, &s)?;
                    self.text(*node, x + offset + xx, yy, run.clone(), clip, &s)?;
                    self.extend_box(*node, r, yy);
                }
                Placed::Box {
                    id,
                    first,
                    last,
                    lines,
                    x: original_x,
                    rect: r,
                    margins,
                    ..
                } => {
                    let xx = if reorder { &bidi_x } else { original_x };
                    let box_baseline = self.scene.boxes[*id]
                        .as_ref()
                        .map(|layout| (layout.baseline - r.y).clamp(0, r.h))
                        .unwrap_or(r.h);
                    let dy = match self.styles[*id].vertical_align.as_str() {
                        "top" | "text-top" => y + margins.top,
                        "bottom" => y + h - margins.bottom - r.h,
                        "middle" => {
                            baseline
                                - (margins.top + r.h + margins.bottom) / 2
                                - self.fonts.x_height(&ps) / 2
                                + margins.top
                        }
                        _ => {
                            let aligned =
                                baseline - box_baseline - self.vertical_shift(&self.styles[*id]);
                            if r.h == 0
                                && self.styles[parent].display == Display::ListItem
                                && matches!(
                                    self.styles[parent].list_type.as_str(),
                                    "disc" | "circle" | "square"
                                )
                            {
                                // Gecko snaps the baseline edge of an empty
                                // inline-block in a graphical-marker line to a
                                // device-pixel boundary.
                                aligned.div_euclid(PX) * PX
                                    + if aligned.rem_euclid(PX) == 0 { 0 } else { PX }
                            } else {
                                aligned
                            }
                        }
                    };
                    let dy = if r.h == 0
                        && self.styles[parent].display == Display::ListItem
                        && matches!(
                            self.styles[parent].list_type.as_str(),
                            "disc" | "circle" | "square"
                        )
                        && matches!(self.styles[*id].vertical_align.as_str(), "bottom")
                    {
                        dy + PX / 2
                    } else {
                        dy
                    };
                    self.translate(
                        *id,
                        *first,
                        *last,
                        *lines,
                        x + offset + xx + margins.left - r.x,
                        dy - r.y,
                    );
                }
            }
        }
        Ok(())
    }
    fn text(
        &mut self,
        node: NodeId,
        x: Au,
        baseline: Au,
        run: Run,
        clip: Rect,
        s: &Style,
    ) -> Result<()> {
        self.glyphs += run.glyphs.len();
        if self.glyphs > self.limits.glyphs {
            return Err(Error::Budget("glyphs"));
        }
        if !s.visible || s.opacity == 0 || s.font_size == 0 {
            return Ok(());
        }
        let w = run.width;
        self.emit(
            Draw::Text {
                node,
                x,
                baseline,
                run,
                color: s.color,
            },
            clip,
            s,
        )?;
        let c = if s.decoration_color == 0 {
            s.color
        } else {
            s.decoration_color
        };
        let t = (s.font_size / 16).max(PX);
        if s.decoration & 1 != 0 {
            self.rect(
                Rect::new(x, baseline + s.font_size / 10, w, t),
                c,
                0,
                clip,
                s,
            )?;
        }
        if s.decoration & 2 != 0 {
            self.rect(
                Rect::new(x, baseline - s.font_size * 4 / 5, w, t),
                c,
                0,
                clip,
                s,
            )?;
        }
        if s.decoration & 4 != 0 {
            let font = &self.fonts.fonts[self.fonts.id(s)];
            let face = rustybuzz::Face::from_slice(&font.bytes, font.index)
                .ok_or(Error::Invalid("font metrics"))?;
            let offset = face
                .strikeout_metrics()
                .map(|m| m.position as Au * s.font_size / face.units_per_em() as Au)
                .unwrap_or(s.font_size / 3);
            self.rect(
                Rect::new(
                    x,
                    ((baseline + PX / 2) / PX) * PX - ((offset + PX / 2) / PX) * PX,
                    w,
                    t,
                ),
                c,
                0,
                clip,
                s,
            )?;
        }
        Ok(())
    }
    fn extend_box(&mut self, id: NodeId, r: Rect, baseline: Au) {
        let mut n = Some(id);
        while let Some(i) = n {
            if !matches!(self.styles[i].display, Display::Inline) {
                break;
            }
            if let Some(b) = self.scene.boxes[i].as_mut() {
                let x = b.border.x.min(r.x);
                let y = b.border.y.min(r.y);
                b.border = Rect::new(
                    x,
                    y,
                    b.border.right().max(r.right()) - x,
                    b.border.bottom().max(r.bottom()) - y,
                );
                b.content = b.border;
            } else {
                self.scene.boxes[i] = Some(LayoutBox {
                    node: i,
                    border: r,
                    content: r,
                    baseline,
                });
            }
            n = self.doc.nodes[i].parent;
        }
    }
    fn translate(
        &mut self,
        id: NodeId,
        first: usize,
        last: usize,
        lines: (usize, usize),
        dx: Au,
        dy: Au,
    ) {
        for p in &mut self.scene.primitives[first..last] {
            if p.fixed_clip.is_some() {
                p.clip.x += dx;
                p.clip.y += dy;
            }
            match &mut p.draw {
                Draw::BeginOpacity { .. } | Draw::EndOpacity => {}
                Draw::Rect { rect, .. }
                | Draw::DiscMarker { rect, .. }
                | Draw::Image { rect, .. }
                | Draw::TiledImage { rect, .. }
                | Draw::Gradient { rect, .. }
                | Draw::Border { rect, .. } => {
                    rect.x += dx;
                    rect.y += dy;
                }
                Draw::Text { x, baseline, .. } => {
                    *x += dx;
                    *baseline += dy;
                }
            }
        }
        for i in id..self.doc.nodes.len() {
            if i > id && self.doc.nodes[i].depth <= self.doc.nodes[id].depth {
                break;
            }
            if let Some(b) = self.scene.boxes[i].as_mut() {
                b.border.x += dx;
                b.border.y += dy;
                b.content.x += dx;
                b.content.y += dy;
                b.baseline += dy;
            }
        }
        for l in &mut self.scene.lines[lines.0..lines.1] {
            l.rect.x += dx;
            l.rect.y += dy;
            l.baseline += dy;
        }
    }
    fn image_size(&self, id: NodeId, width: Au) -> (Au, Au, Option<usize>) {
        let n = &self.doc.nodes[id];
        let s = &self.styles[id];
        let edges = self.insets(s, width);
        let horizontal_edges = edges.left + edges.right;
        let vertical_edges = edges.top + edges.bottom;
        let content_dimension = |value: Au, edges: Au| {
            if s.border_box {
                (value - edges).max(0)
            } else {
                value
            }
        };
        let image = n
            .attr("src")
            .and_then(|key| self.images.iter().position(|i| i.key == key));
        let (iw, ih) = image
            .map(|i| {
                (
                    self.images[i].width as Au * PX,
                    self.images[i].height as Au * PX,
                )
            })
            .unwrap_or((16 * PX, 16 * PX));
        let w = self
            .val(s.width, width, s)
            .map(|value| content_dimension(value, horizontal_edges));
        let h = self
            .val(s.height, self.scene.height, s)
            .map(|value| content_dimension(value, vertical_edges));
        let (mut w, mut h) = match (w, h) {
            (Some(w), Some(h)) => (w, h),
            (Some(w), None) => (w, if iw > 0 { ih * w / iw } else { 0 }),
            (None, Some(h)) => (if ih > 0 { iw * h / ih } else { 0 }, h),
            _ => (iw, ih),
        };
        if let Some(max) = self
            .val(s.max_width, width, s)
            .map(|value| content_dimension(value, horizontal_edges))
        {
            if w > max && w > 0 {
                h = h * max / w;
                w = max;
            }
        }
        if let Some(min) = self
            .val(s.min_width, width, s)
            .map(|value| content_dimension(value, horizontal_edges))
        {
            if w < min && w > 0 {
                h = h * min / w;
                w = min;
            }
        }
        (w.max(0), h.max(0), image)
    }
    fn image_box(&mut self, id: NodeId, x: Au, y: Au, width: Au, clip: Rect) -> Result<Rect> {
        let s = self.styles[id].clone();
        if s.opacity < 1000 {
            self.emit(Draw::BeginOpacity { opacity: s.opacity }, clip, &s)?;
        }
        let (w, h, image) = self.image_size(id, width);
        let e = self.insets(&s, width);
        let r = Rect::new(x, y, w + e.left + e.right, h + e.top + e.bottom);
        let content = Rect::new(x + e.left, y + e.top, w, h);
        self.rect(r, s.background_color, self.corner(&s, r), clip, &s)?;
        if let Some(resource) = image {
            if s.visible {
                let image = &self.images[resource];
                let (iw, ih) = (image.width as Au * PX, image.height as Au * PX);
                let (dw, dh) = self.fitted(&s.object_fit, iw, ih, w, h);
                let (dx, dy) = self.position_pair(&s.object_position, w - dw, h - dh, &s);
                let p = self.emit(
                    Draw::Image {
                        rect: Rect::new(content.x + dx, content.y + dy, dw, dh),
                        resource,
                    },
                    if self.fixed_clip.is_some() {
                        clip.intersect(content)
                    } else {
                        content
                    },
                    &s,
                )?;
                self.scene.primitives[p].fixed_clip = self.fixed_clip.or(Some(clip));
                self.scene.primitives[p].clip_radius =
                    (self.corner(&s, r) - e.left.min(e.top)).max(0);
            }
        } else {
            self.rect(content, 0xeeeeeeff, 0, clip, &s)?;
            if let Some(alt) = self.doc.nodes[id].attr("alt") {
                let run = self.fonts.shape(alt, &s, self.budget)?;
                self.text(
                    id,
                    content.x,
                    content.y + run.ascent,
                    run,
                    clip.intersect(content),
                    &s,
                )?;
            }
        }
        self.borders(&s, r, clip)?;
        self.scene.boxes[id] = Some(LayoutBox {
            node: id,
            border: r,
            content,
            baseline: r.bottom(),
        });
        if s.opacity < 1000 {
            self.emit(Draw::EndOpacity, clip, &s)?;
        }
        Ok(r)
    }

    fn measure(&mut self, id: NodeId, depth: usize) -> Result<(Au, Au)> {
        self.budget.charge(1)?;
        if depth > self.limits.depth {
            return Err(Error::Budget("intrinsic depth"));
        }
        if let Some(v) = self.intrinsic[id] {
            return Ok(v);
        }
        let owned = self.effective(id);
        let s = &owned;
        let n = &self.doc.nodes[id];
        if s.display == Display::None {
            return Ok((0, 0));
        }
        let mut min = 0;
        let mut max = 0;
        let mut inline = 0;
        if s.display == Display::Table {
            let grid = self.grid(id)?;
            let mut a = vec![0; grid.cols];
            let mut b = vec![0; grid.cols];
            for cell in &grid.cells {
                let (c, d) = self.measure(cell.id, depth + 1)?;
                if cell.cs == 1 {
                    a[cell.col] = a[cell.col].max(c);
                    b[cell.col] = b[cell.col].max(d);
                }
            }
            for cell in &grid.cells {
                if cell.cs > 1 {
                    let (c, d) = self.measure(cell.id, depth + 1)?;
                    let have_a: Au = a[cell.col..cell.col + cell.cs].iter().sum();
                    let have_b: Au = b[cell.col..cell.col + cell.cs].iter().sum();
                    for i in cell.col..cell.col + cell.cs {
                        a[i] += (c - have_a).max(0) / cell.cs as i64;
                        b[i] += (d - have_b).max(0) / cell.cs as i64;
                    }
                }
            }
            let spacing = if s.border_collapse {
                0
            } else {
                s.border_spacing.0 * (grid.cols as i64 + 1)
            };
            min = a.iter().sum::<Au>() + spacing;
            max = b.iter().sum::<Au>() + spacing;
        } else if matches!(n.kind, Kind::Text) {
            let run = self
                .fonts
                .shape(&n.text.replace(['\n', '\t', '\r'], " "), s, self.budget)?;
            max = run.width;
            for word in n.text.split_whitespace() {
                min = min.max(self.fonts.shape(word, s, self.budget)?.width);
            }
        } else if n.tag == "img" {
            let (w, _, _) = self.image_size(id, self.scene.width);
            min = w;
            max = w;
        } else {
            for child in n.children.clone() {
                let (mut a, mut b) = self.measure(child, depth + 1)?;
                if self.styles[child].float != Float::None {
                    // A float's margin box contributes to its containing
                    // block's shrink-to-fit width. Omitting these margins can
                    // make an auto-width email table narrower than the float
                    // it contains, even though final float placement already
                    // reserves the same space.
                    let margins = self.margins(&self.styles[child], self.scene.width);
                    let horizontal = margins.left + margins.right;
                    a = checked_add(a, horizontal)?;
                    b = checked_add(b, horizontal)?;
                }
                min = min.max(a);
                if matches!(
                    self.styles[child].display,
                    Display::Inline | Display::InlineBlock
                ) {
                    inline += b;
                    max = max.max(inline);
                } else {
                    max = max.max(b);
                    inline = 0;
                }
            }
        }
        let e = self.insets(s, self.scene.width);
        min += e.left + e.right;
        max += e.left + e.right;
        if let Size::Length(l) = s.width {
            if l.unit != Unit::Percent && l.extra[1] == 0 {
                let value = self.eval(l, self.scene.width, s);
                let w = if s.border_box {
                    value
                } else {
                    value + e.left + e.right
                };
                min = min.max(w);
                max = max.max(w);
            }
        }
        let result = (min.min(MAX_COORD), max.max(min).min(MAX_COORD));
        self.intrinsic[id] = Some(result);
        Ok(result)
    }
    fn borders(&mut self, s: &Style, r: Rect, clip: Rect) -> Result<()> {
        let b = [s.border.top, s.border.right, s.border.bottom, s.border.left];
        let has_border = b
            .iter()
            .any(|b| b.width > 0 && !matches!(b.style, BorderStyle::None | BorderStyle::Hidden));
        let widths = b.map(|b| {
            if matches!(b.style, BorderStyle::None | BorderStyle::Hidden) {
                0
            } else {
                b.width
            }
        });
        let colors = b.map(|b| b.color);
        let styles = b.map(|b| format!("{:?}", b.style));
        if has_border {
            self.emit(
                Draw::Border {
                    rect: r,
                    widths,
                    colors,
                    styles,
                    radius: self.corner(s, r),
                },
                clip,
                s,
            )?;
        }
        if s.outline.width > 0
            && !matches!(s.outline.style, BorderStyle::None | BorderStyle::Hidden)
        {
            let edge = s.outline.width + s.outline_offset;
            let outline = Rect::new(r.x - edge, r.y - edge, r.w + 2 * edge, r.h + 2 * edge);
            self.emit(
                Draw::Border {
                    rect: outline,
                    widths: [s.outline.width; 4],
                    colors: [s.outline.color; 4],
                    styles: std::array::from_fn(|_| format!("{:?}", s.outline.style)),
                    radius: 0,
                },
                clip,
                s,
            )?;
        }
        Ok(())
    }

    fn area(&self, s: &Style, r: Rect, content: Rect, which: &str) -> Rect {
        if which == "content-box" {
            return content;
        }
        if which == "padding-box" {
            let bw = |b: Border| {
                if matches!(b.style, BorderStyle::None | BorderStyle::Hidden) {
                    0
                } else {
                    b.width
                }
            };
            let l = bw(s.border.left);
            let t = bw(s.border.top);
            return Rect::new(
                r.x + l,
                r.y + t,
                r.w - l - bw(s.border.right),
                r.h - t - bw(s.border.bottom),
            );
        }
        r
    }
    fn position(&self, value: &str, free: Au, axis: bool, s: &Style) -> Au {
        match value {
            "left" | "top" => 0,
            "center" => free / 2,
            "right" | "bottom" => free,
            _ => length(value)
                .map(|l| self.eval(l, free, s))
                .unwrap_or(if axis { 0 } else { free / 2 }),
        }
    }
    fn position_pair(&self, value: &str, free_x: Au, free_y: Au, s: &Style) -> (Au, Au) {
        let mut words = simple_words(value);
        if words.is_empty() {
            words.push("0%".into());
        }
        if words.len() == 1 {
            if words[0] == "top" || words[0] == "bottom" {
                words.insert(0, "center".into());
            } else {
                words.push("center".into());
            }
        }
        if words[0] == "top" || words[0] == "bottom" {
            words.swap(0, 1);
        }
        (
            self.position(&words[0], free_x, true, s),
            self.position(&words[1], free_y, false, s),
        )
    }
    fn fitted(&self, value: &str, iw: Au, ih: Au, w: Au, h: Au) -> (Au, Au) {
        if iw <= 0 || ih <= 0 {
            return (0, 0);
        }
        match value {
            "contain" | "cover" | "scale-down" => {
                let use_width = if value == "cover" {
                    w * ih >= h * iw
                } else {
                    w * ih <= h * iw
                };
                let (mut a, mut b) = if use_width {
                    (w, ih * w / iw)
                } else {
                    (iw * h / ih, h)
                };
                if value == "scale-down" && a > iw {
                    a = iw;
                    b = ih;
                }
                (a, b)
            }
            "none" => (iw, ih),
            _ => (w, h),
        }
    }
    fn backgrounds(&mut self, s: &Style, r: Rect, content: Rect, clip: Rect) -> Result<()> {
        let area = self.area(s, r, content, &s.background_origin);
        let own_clip = self.area(s, r, content, &s.background_clip);
        let paint_clip = if self.fixed_clip.is_some() {
            clip.intersect(own_clip)
        } else {
            own_clip
        };
        for background in s.backgrounds.iter().rev() {
            match background {
                Background::Linear(gradient) => {
                    self.emit(
                        Draw::Gradient {
                            rect: area,
                            gradient: gradient.clone(),
                            color: s.color,
                        },
                        paint_clip,
                        s,
                    )?;
                }
                Background::Image(key) => {
                    if let Some(i) = self.images.iter().position(|x| &x.key == key) {
                        let iw = self.images[i].width as Au * PX;
                        let ih = self.images[i].height as Au * PX;
                        let mut size = simple_words(&s.background_size);
                        let (tw, th) = if matches!(s.background_size.as_str(), "contain" | "cover")
                        {
                            self.fitted(&s.background_size, iw, ih, area.w, area.h)
                        } else {
                            if size.is_empty() {
                                size.push("auto".into());
                            }
                            let w = size
                                .first()
                                .and_then(|v| length(v))
                                .map(|l| self.eval(l, area.w, s));
                            let h = size
                                .get(1)
                                .and_then(|v| length(v))
                                .map(|l| self.eval(l, area.h, s));
                            match (w, h) {
                                (Some(w), Some(h)) => (w, h),
                                (Some(w), None) => (w, if iw > 0 { ih * w / iw } else { 0 }),
                                (None, Some(h)) => (if ih > 0 { iw * h / ih } else { 0 }, h),
                                _ => (iw, ih),
                            }
                        };
                        if tw <= 0 || th <= 0 {
                            continue;
                        }
                        let (dx, dy) =
                            self.position_pair(&s.background_position, area.w - tw, area.h - th, s);
                        let repeat_x =
                            s.background_repeat == "repeat" || s.background_repeat == "repeat-x";
                        let repeat_y =
                            s.background_repeat == "repeat" || s.background_repeat == "repeat-y";
                        let bx = area.x + if repeat_x { dx.rem_euclid(tw) - tw } else { dx };
                        let by = area.y + if repeat_y { dy.rem_euclid(th) - th } else { dy };
                        let bounds = Rect::new(
                            bx,
                            by,
                            if repeat_x {
                                paint_clip.right() - bx
                            } else {
                                tw
                            },
                            if repeat_y {
                                paint_clip.bottom() - by
                            } else {
                                th
                            },
                        );
                        let id = self.emit(
                            Draw::TiledImage {
                                rect: bounds,
                                resource: i,
                                tile: (tw, th),
                            },
                            paint_clip,
                            s,
                        )?;
                        self.scene.primitives[id].fixed_clip = self.fixed_clip.or(Some(clip));
                        self.scene.primitives[id].clip_radius = self.corner(s, r);
                    }
                }
            }
        }
        Ok(())
    }

    fn grid(&mut self, id: NodeId) -> Result<Grid> {
        let mut rows = vec![];
        let mut captions = vec![];
        let mut pending: Vec<_> = self.doc.nodes[id].children.iter().rev().copied().collect();
        while let Some(node) = pending.pop() {
            self.budget.charge(1)?;
            match self.styles[node].display {
                Display::Row => rows.push(node),
                Display::RowGroup => {
                    for child in self.doc.nodes[node].children.iter().rev() {
                        pending.push(*child);
                    }
                }
                Display::Caption => captions.push(node),
                _ => {}
            }
        }
        let mut cells = vec![];
        let mut occupied: Vec<u64> = vec![0; 256];
        let mut cols = 0usize;
        for (row, node) in rows.iter().enumerate() {
            let mut col = 0;
            for cell in &self.doc.nodes[*node].children {
                if self.styles[*cell].display != Display::Cell {
                    continue;
                }
                while col < occupied.len() && occupied[col] > row as u64 {
                    col += 1;
                    self.budget.charge(1)?;
                }
                let cs = self.doc.nodes[*cell]
                    .attr("colspan")
                    .and_then(|x| x.parse::<usize>().ok())
                    .unwrap_or(1)
                    .clamp(1, 256);
                let raw_rs = self.doc.nodes[*cell]
                    .attr("rowspan")
                    .and_then(|x| x.parse::<usize>().ok())
                    .unwrap_or(1);
                let rs = if raw_rs == 0 {
                    rows.len() - row
                } else {
                    raw_rs.min(rows.len() - row).max(1)
                };
                if col + cs > 256 || cells.len() >= self.limits.table_cells {
                    return Err(Error::Budget("table grid"));
                }
                self.budget.charge(cs as u64)?;
                if !crate::verified::mark_columns(&mut occupied, col, cs, (row + rs) as u64) {
                    return Err(Error::Budget("table grid"));
                }
                cells.push(Cell {
                    id: *cell,
                    row,
                    col,
                    rs,
                    cs,
                });
                cols = cols.max(col + cs);
                col += cs;
            }
        }
        Ok(Grid {
            rows,
            captions,
            cells,
            cols,
        })
    }
    fn effective(&self, id: NodeId) -> Style {
        let mut s = self.styles[id].clone();
        if let Some(border) = self.collapsed[id] {
            s.border = border;
        }
        s
    }
    fn collapsed_grid(&mut self, id: NodeId, grid: &Grid) -> Result<CollapsedGrid> {
        let (nr, nc) = (grid.rows.len(), grid.cols);
        let slots = (nr + 1)
            .checked_mul(nc + 1)
            .ok_or(Error::Budget("collapsed grid"))?;
        if slots > self.limits.table_cells {
            return Err(Error::Budget("collapsed grid"));
        }
        self.budget.charge((slots as u64) * 4)?;
        let mut h = vec![SharedEdge::default(); (nr + 1) * nc];
        let mut v = vec![SharedEdge::default(); nr * (nc + 1)];
        let table = &self.styles[id];
        for c in 0..nc {
            h[c].offer(table.border.top, 1);
            h[nr * nc + c].offer(table.border.bottom, 1);
        }
        for r in 0..nr {
            v[r * (nc + 1)].offer(table.border.left, 1);
            v[r * (nc + 1) + nc].offer(table.border.right, 1);
        }
        for (r, node) in grid.rows.iter().enumerate() {
            let row = &self.styles[*node];
            for c in 0..nc {
                h[r * nc + c].offer(row.border.top, 2);
                h[(r + 1) * nc + c].offer(row.border.bottom, 2);
            }
            v[r * (nc + 1)].offer(row.border.left, 2);
            v[r * (nc + 1) + nc].offer(row.border.right, 2);
        }
        for cell in &grid.cells {
            let b = self.styles[cell.id].border;
            self.budget.charge((cell.cs as u64 + cell.rs as u64) * 2)?;
            for c in cell.col..cell.col + cell.cs {
                h[cell.row * nc + c].offer(b.top, 3);
                h[(cell.row + cell.rs) * nc + c].offer(b.bottom, 3);
            }
            for r in cell.row..cell.row + cell.rs {
                v[r * (nc + 1) + cell.col].offer(b.left, 3);
                v[r * (nc + 1) + cell.col + cell.cs].offer(b.right, 3);
            }
        }
        for cell in &grid.cells {
            for r in cell.row + 1..cell.row + cell.rs {
                for c in cell.col..cell.col + cell.cs {
                    self.budget.charge(1)?;
                    h[r * nc + c] = SharedEdge::default();
                }
            }
            for r in cell.row..cell.row + cell.rs {
                for c in cell.col + 1..cell.col + cell.cs {
                    self.budget.charge(1)?;
                    v[r * (nc + 1) + c] = SharedEdge::default();
                }
            }
            let half = |width: Au| Border {
                width: width / 2,
                color: 0,
                style: BorderStyle::Solid,
            };
            self.collapsed[cell.id] = Some(Edges {
                top: half(
                    (cell.col..cell.col + cell.cs)
                        .map(|c| h[cell.row * nc + c].width())
                        .max()
                        .unwrap_or(0),
                ),
                bottom: half(
                    (cell.col..cell.col + cell.cs)
                        .map(|c| h[(cell.row + cell.rs) * nc + c].width())
                        .max()
                        .unwrap_or(0),
                ),
                left: half(
                    (cell.row..cell.row + cell.rs)
                        .map(|r| v[r * (nc + 1) + cell.col].width())
                        .max()
                        .unwrap_or(0),
                ),
                right: half(
                    (cell.row..cell.row + cell.rs)
                        .map(|r| v[r * (nc + 1) + cell.col + cell.cs].width())
                        .max()
                        .unwrap_or(0),
                ),
            });
            self.intrinsic[cell.id] = None;
        }
        let outer = Edges {
            top: (0..nc).map(|c| h[c].width() / 2).max().unwrap_or(0),
            bottom: (0..nc)
                .map(|c| h[nr * nc + c].width() / 2)
                .max()
                .unwrap_or(0),
            left: (0..nr)
                .map(|r| v[r * (nc + 1)].width() / 2)
                .max()
                .unwrap_or(0),
            right: (0..nr)
                .map(|r| v[r * (nc + 1) + nc].width() / 2)
                .max()
                .unwrap_or(0),
        };
        Ok(CollapsedGrid {
            horizontal: h,
            vertical: v,
            outer,
        })
    }
    fn table(
        &mut self,
        id: NodeId,
        x: Au,
        y: Au,
        available: Au,
        forced: Option<Au>,
        clip: Rect,
        depth: usize,
    ) -> Result<Rect> {
        self.budget.charge(1)?;
        if depth > self.limits.depth {
            return Err(Error::Budget("table depth"));
        }
        let s = self.styles[id].clone();
        let margins = self.margins(&s, available);
        let grid = self.grid(id)?;
        let collapsed = if s.border_collapse {
            Some(self.collapsed_grid(id, &grid)?)
        } else {
            None
        };
        let e = collapsed
            .as_ref()
            .map(|c| c.outer)
            .unwrap_or_else(|| self.insets(&s, available));
        let Grid {
            rows,
            captions,
            cells,
            cols,
        } = grid;
        let fixed =
            s.table_fixed && (forced.is_some() || self.val(s.width, available, &s).is_some());
        let mut mins = vec![0i64; cols];
        let mut maxs = vec![0i64; cols];
        let (sx, sy) = if s.border_collapse {
            (0, 0)
        } else {
            s.border_spacing
        };
        for cell in &cells {
            if fixed {
                continue;
            }
            let (a, b) = self.measure(cell.id, depth + 1)?;
            if cell.cs == 1 {
                mins[cell.col] = mins[cell.col].max(a);
                maxs[cell.col] = maxs[cell.col].max(b);
            }
        }
        for cell in &cells {
            if !fixed && cell.cs > 1 {
                let (a, b) = self.measure(cell.id, depth + 1)?;
                let amin: Au = mins[cell.col..cell.col + cell.cs].iter().sum();
                let bmax: Au = maxs[cell.col..cell.col + cell.cs].iter().sum();
                for i in cell.col..cell.col + cell.cs {
                    mins[i] += (a - amin - sx * (cell.cs - 1) as i64).max(0) / cell.cs as i64;
                    maxs[i] += (b - bmax - sx * (cell.cs - 1) as i64).max(0) / cell.cs as i64;
                }
            }
        }
        let spacing = sx * (cols as i64 + 1);
        let min: Au = mins.iter().sum::<Au>() + spacing + e.left + e.right;
        let max: Au = maxs.iter().sum::<Au>() + spacing + e.left + e.right;
        let mut caption_max = 0;
        for caption in &captions {
            let (_, measured_max) = self.measure(*caption, depth + 1)?;
            caption_max = caption_max.max(measured_max);
        }
        let desired = forced
            .or_else(|| self.val(s.width, available, &s))
            .unwrap_or(max.min(available - margins.left - margins.right));
        let mut grid_width = desired.max(min);
        if let Some(max) = self.val(s.max_width, available, &s) {
            grid_width = grid_width.min(max).max(min);
        }
        let w = grid_width.max(caption_max);
        let inner = (grid_width - e.left - e.right - spacing).max(0);
        let sum_min: Au = mins.iter().sum();
        let sum_max: Au = maxs.iter().sum();
        let extra = (inner - sum_min).max(0);
        let grow = (sum_max - sum_min).max(0);
        let mut widths = mins.clone();
        let mut specified = vec![false; cols];
        for cell in &cells {
            if (cell.cs == 1 && !fixed) || (fixed && cell.row == 0) {
                if let Some(value) =
                    self.val(self.styles[cell.id].width, inner, &self.styles[cell.id])
                {
                    let edge = self.insets(&self.effective(cell.id), inner);
                    let target = (value + edge.left + edge.right) / cell.cs as Au;
                    for c in cell.col..cell.col + cell.cs {
                        widths[c] = widths[c].max(target);
                        specified[c] = true;
                    }
                }
            }
        }
        let flexible: Vec<_> = (0..cols).filter(|i| !specified[*i]).collect();
        let assigned: Au = widths.iter().sum();
        let residual = (inner - assigned).max(0);
        let targets: Vec<_> = if flexible.is_empty() {
            (0..cols).collect()
        } else {
            flexible
        };
        let growth: Au = targets.iter().map(|i| (maxs[*i] - widths[*i]).max(0)).sum();
        let preferred: Au = targets.iter().map(|i| maxs[*i]).sum();
        for i in &targets {
            let g = (maxs[*i] - widths[*i]).max(0);
            widths[*i] += if residual <= growth && growth > 0 {
                (residual * g + growth / 2) / growth
            } else {
                g + if preferred > 0 {
                    ((residual - growth).max(0) * maxs[*i] + preferred / 2) / preferred
                } else if !targets.is_empty() {
                    residual / targets.len() as i64
                } else {
                    0
                }
            };
        }
        let _ = (extra, grow);

        // Definite cell widths participate before distributing residual free width.
        if cols > 0 {
            let assigned: Au = widths.iter().sum();
            widths[cols - 1] += (inner - assigned).max(0);
        }
        let free = (available - w - margins.left - margins.right).max(0);
        let containing_rtl = self.doc.nodes[id]
            .parent
            .map(|parent| self.styles[parent].direction_rtl)
            .unwrap_or(false);
        let bx = x
            + margins.left
            + if s.margin.left == Size::Auto && s.margin.right == Size::Auto {
                free / 2
            } else if s.margin.left == Size::Auto {
                free
            } else if containing_rtl {
                free
            } else {
                0
            };
        let mut top = y;
        for cap in &captions {
            if !self.styles[*cap].caption_bottom {
                let r = self.block(*cap, bx, top, w, Some(w), clip, depth + 1)?;
                top = r.bottom();
            }
        }
        let bg = self.emit(
            Draw::Rect {
                rect: Rect::new(bx, top, grid_width, 0),
                color: s.background_color,
                radius: s.radius,
            },
            clip,
            &s,
        )?;
        let mut row_heights = vec![0i64; rows.len()];
        let mut placements = vec![];
        for cell in &cells {
            let cell_width =
                widths[cell.col..cell.col + cell.cs].iter().sum::<Au>() + sx * (cell.cs - 1) as i64;
            let first = self.scene.primitives.len();
            let lines = self.scene.lines.len();
            let r = self.block(cell.id, 0, 0, cell_width, Some(cell_width), clip, depth + 1)?;
            let last = self.scene.primitives.len();
            if cell.rs == 1 {
                row_heights[cell.row] = row_heights[cell.row].max(r.h);
            }
            placements.push((first, last, (lines, self.scene.lines.len()), r));
        }
        for (cell, (_, _, _, r)) in cells.iter().zip(&placements) {
            let have: Au = row_heights[cell.row..cell.row + cell.rs].iter().sum::<Au>()
                + sy * (cell.rs - 1) as i64;
            if r.h > have {
                let missing = r.h - have;
                for i in cell.row..cell.row + cell.rs {
                    row_heights[i] += missing / cell.rs as i64;
                }
                row_heights[cell.row + cell.rs - 1] += missing % cell.rs as i64;
            }
        }
        let mut row_y = vec![];
        let mut yy = top + e.top + sy;
        for h in &row_heights {
            row_y.push(yy);
            yy = checked_add(yy, *h + sy)?;
        }
        for (cell, (first, last, lines, r)) in cells.iter().zip(placements) {
            let xx = if s.direction_rtl {
                let after = cell.col + cell.cs;
                bx + e.left + sx + widths[after..].iter().sum::<Au>() + sx * (cols - after) as i64
            } else {
                bx + e.left + sx + widths[..cell.col].iter().sum::<Au>() + sx * cell.col as i64
            };
            let cell_h = row_heights[cell.row..cell.row + cell.rs].iter().sum::<Au>()
                + sy * (cell.rs - 1) as i64;
            let extra = cell_h - r.h;
            let delta = match self.styles[cell.id].vertical_align.as_str() {
                "middle" => extra / 2,
                "bottom" => extra,
                _ => 0,
            };
            self.translate(
                cell.id,
                first,
                last,
                lines,
                xx - r.x,
                row_y[cell.row] - r.y + delta,
            );
            let before = Rect::new(xx, row_y[cell.row] + delta, r.w, r.h);
            for primitive in &mut self.scene.primitives[first..last] {
                if let Draw::Border { rect, .. } = &mut primitive.draw {
                    if *rect == before {
                        *rect = Rect::new(xx, row_y[cell.row], r.w, cell_h);
                    }
                }
            }
            if let Some(b) = self.scene.boxes[cell.id].as_mut() {
                b.border.y = row_y[cell.row];
                b.border.h = cell_h;
            }
            if let Some(Primitive {
                draw: Draw::Rect { rect, .. },
                ..
            }) = self.scene.primitives.get_mut(first)
            {
                rect.y = row_y[cell.row];
                rect.h = cell_h;
            }
        }
        let r = Rect::new(bx, top, grid_width, (yy - top + e.bottom).max(0));
        if let Draw::Rect { rect, .. } = &mut self.scene.primitives[bg].draw {
            *rect = r;
        }
        if let Some(shared) = &collapsed {
            let mut xs = vec![bx + e.left];
            for width in &widths {
                xs.push(xs.last().unwrap() + width);
            }
            let mut ys = row_y.clone();
            ys.push(yy);
            for row in 0..rows.len() {
                for c in 0..=cols {
                    let edge = shared.vertical[row * (cols + 1) + c];
                    let width = edge.width();
                    if width > 0 {
                        self.rect(
                            Rect::new(
                                xs[c] - width / 2,
                                ys[row] - e.top,
                                width,
                                row_heights[row] + e.top + e.bottom,
                            ),
                            edge.border.color,
                            0,
                            clip,
                            &s,
                        )?;
                    }
                }
            }
            for row in 0..=rows.len() {
                for c in 0..cols {
                    let edge = shared.horizontal[row * cols + c];
                    let width = edge.width();
                    if width > 0 {
                        self.rect(
                            Rect::new(
                                xs[c] - e.left,
                                ys[row] - width / 2,
                                widths[c] + e.left + e.right,
                                width,
                            ),
                            edge.border.color,
                            0,
                            clip,
                            &s,
                        )?;
                    }
                }
            }
        } else {
            self.borders(&s, r, clip)?;
        }
        for (i, node) in rows.iter().enumerate() {
            self.scene.boxes[*node] = Some(LayoutBox {
                node: *node,
                border: Rect::new(
                    bx + e.left + sx,
                    row_y[i],
                    inner + sx * cols.saturating_sub(1) as Au,
                    row_heights[i],
                ),
                content: Rect::new(
                    bx + e.left + sx,
                    row_y[i],
                    inner + sx * cols.saturating_sub(1) as Au,
                    row_heights[i],
                ),
                baseline: row_y[i] + row_heights[i],
            });
        }
        let mut bottom = r.bottom();
        for cap in &captions {
            if self.styles[*cap].caption_bottom {
                bottom = self
                    .block(*cap, bx, bottom, w, Some(w), clip, depth + 1)?
                    .bottom();
            }
        }
        let wrapper = Rect::new(bx, y, w, bottom - y);
        self.scene.boxes[id] = Some(LayoutBox {
            node: id,
            border: wrapper,
            content: wrapper,
            baseline: wrapper.bottom(),
        });
        Ok(wrapper)
    }
    fn semantics(&mut self) -> Result<()> {
        let mut fragments: Vec<Vec<Rect>> = vec![vec![]; self.doc.nodes.len()];
        for primitive in &self.scene.primitives {
            if let Draw::Text {
                node,
                x,
                baseline,
                run,
                ..
            } = &primitive.draw
            {
                let mut r = Rect::new(
                    *x,
                    *baseline - run.ascent,
                    run.width,
                    run.ascent + run.descent,
                )
                .intersect(primitive.clip);
                if let Some(clip) = primitive.fixed_clip {
                    r = r.intersect(clip);
                }
                if r.w == 0 || r.h == 0 {
                    continue;
                }
                let mut ancestor = Some(*node);
                while let Some(id) = ancestor {
                    self.budget.charge(1)?;
                    if self.doc.nodes[id].tag == "a" {
                        if let Some(previous) = fragments[id].last_mut().filter(|p| {
                            p.y == r.y && p.h == r.h && r.x <= p.right() + 1 && r.right() >= p.x
                        }) {
                            let left = previous.x.min(r.x);
                            *previous =
                                Rect::new(left, r.y, previous.right().max(r.right()) - left, r.h);
                        } else {
                            fragments[id].push(r);
                        }
                    }
                    ancestor = self.doc.nodes[id].parent;
                }
            }
        }
        for (id, n) in self.doc.nodes.iter().enumerate() {
            if n.tag != "img" {
                continue;
            }
            if let Some(b) = &self.scene.boxes[id] {
                let mut ancestor = n.parent;
                while let Some(i) = ancestor {
                    self.budget.charge(1)?;
                    if self.doc.nodes[i].tag == "a" {
                        fragments[i].push(b.border);
                    }
                    ancestor = self.doc.nodes[i].parent;
                }
            }
        }
        let mut ids: Vec<(String, usize)> = self
            .doc
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.attr("id").map(|key| (key.to_string(), i)))
            .collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        for (id, n) in self.doc.nodes.iter().enumerate() {
            self.budget.charge(1)?;
            if !n.element() || n.disabled {
                continue;
            }
            let s = &self.styles[id];
            if n.tag == "a" {
                if let Some(target) = n.attr("href") {
                    let rectangles = if s.display == Display::Inline {
                        std::mem::take(&mut fragments[id])
                    } else {
                        self.scene.boxes[id]
                            .as_ref()
                            .map(|b| vec![b.border])
                            .unwrap_or_default()
                    };
                    self.scene.links.push(Link {
                        node: id,
                        target: target.to_string(),
                        rectangles,
                    });
                }
            }
            let implicit = match n.tag.as_str() {
                "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => "heading",
                "a" => "link",
                "ul" | "ol" => "list",
                "li" => "listitem",
                "table" => "table",
                "tr" => "row",
                "td" => "cell",
                "th" => "columnheader",
                "img" => "img",
                "p" => "paragraph",
                _ => "generic",
            };
            let role = n
                .attr("role")
                .filter(|x| {
                    matches!(
                        *x,
                        "presentation"
                            | "none"
                            | "table"
                            | "row"
                            | "cell"
                            | "list"
                            | "listitem"
                            | "heading"
                            | "link"
                            | "img"
                            | "document"
                            | "paragraph"
                    )
                })
                .unwrap_or(implicit)
                .to_string();
            let mut label = String::new();
            let mut description = String::new();
            for (attr, target) in [
                ("aria-labelledby", &mut label),
                ("aria-describedby", &mut description),
            ] {
                if let Some(refs) = n.attr(attr) {
                    for key in refs.split_ascii_whitespace().take(32) {
                        self.budget.charge(32)?;
                        let pos = ids.partition_point(|(s, _)| s.as_str() < key);
                        if let Some((s, i)) = ids.get(pos) {
                            if s == key {
                                let text = self.doc.text_content(*i);
                                self.budget.charge(text.len() as u64)?;
                                if !target.is_empty() {
                                    target.push(' ');
                                }
                                target.push_str(&text);
                            }
                        }
                    }
                }
            }
            if label.is_empty() {
                label = n
                    .attr("aria-label")
                    .or_else(|| n.attr("alt"))
                    .map(String::from)
                    .unwrap_or_else(|| {
                        if matches!(implicit, "link" | "heading" | "listitem") {
                            self.doc.text_content(id)
                        } else {
                            String::new()
                        }
                    });
            }
            let mut hidden =
                s.display == Display::None || !s.visible || n.attr("aria-hidden") == Some("true");
            let mut lang = n.attr("lang").map(String::from);
            let mut ancestor = n.parent;
            while let Some(i) = ancestor {
                self.budget.charge(1)?;
                let a = &self.doc.nodes[i];
                hidden |= self.styles[i].display == Display::None
                    || a.disabled
                    || a.attr("aria-hidden") == Some("true");
                if lang.is_none() {
                    lang = a.attr("lang").map(String::from);
                }
                ancestor = a.parent;
            }
            self.scene.accessible.push(AccessibleNode {
                node: id,
                role,
                name: label,
                lang,
                description,
                hidden,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_list_counters_match_css_sequences() {
        assert_eq!(alphabetic_counter(1, false).as_deref(), Some("a"));
        assert_eq!(alphabetic_counter(27, true).as_deref(), Some("AA"));
        assert_eq!(roman_counter(4, false).as_deref(), Some("iv"));
        assert_eq!(roman_counter(1999, true).as_deref(), Some("MCMXCIX"));
        assert_eq!(roman_counter(4000, false), None);
    }
}
