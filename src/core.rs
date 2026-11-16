#![forbid(unsafe_code)]
//! Proof-oriented kernel: integer geometry, bounded work, no I/O or unsafe code.
//! One app unit is 1/60 CSS pixel. Native conversion occurs only in paint.rs.
use serde::{Deserialize, Serialize};
pub type Au = i64;
pub const PX: Au = 60;
pub const MAX_COORD: Au = 1_000_000 * PX;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    pub html_bytes: usize,
    pub nodes: usize,
    pub depth: usize,
    pub css_bytes: usize,
    pub declarations: usize,
    pub selectors: usize,
    pub selector_parts: usize,
    pub media_depth: usize,
    pub steps: u64,
    pub image_pixels: u64,
    pub image_bytes: usize,
    pub decoded_bytes: usize,
    pub glyphs: usize,
    pub primitives: usize,
    pub table_cells: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            html_bytes: 4_194_304,
            nodes: 100_000,
            depth: 128,
            css_bytes: 1_048_576,
            declarations: 25_000,
            selectors: 5_000,
            selector_parts: 32,
            media_depth: 16,
            steps: 20_000_000,
            image_pixels: 16_777_216,
            image_bytes: 10_485_760,
            decoded_bytes: 67_108_864,
            glyphs: 500_000,
            primitives: 200_000,
            table_cells: 65_536,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Error {
    Budget(&'static str),
    Invalid(&'static str),
    Resource(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug)]
pub struct Budget {
    remaining: u64,
}
impl Budget {
    pub fn new(n: u64) -> Self {
        Self { remaining: n }
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn charge(&mut self, n: u64) -> Result<()> {
        match crate::verified::debit(self.remaining, n) {
            Some(left) => {
                self.remaining = left;
                Ok(())
            }
            None => Err(Error::Budget("work")),
        }
    }
}
pub fn checked_add(a: Au, b: Au) -> Result<Au> {
    crate::verified::add_coord(a, b).ok_or(Error::Budget("coordinate"))
}
pub fn mul_div(a: Au, b: Au, d: Au) -> Result<Au> {
    if d == 0 {
        return Err(Error::Invalid("zero divisor"));
    }
    let v = (a as i128) * (b as i128) / (d as i128);
    if v < -(MAX_COORD as i128) || v > MAX_COORD as i128 {
        Err(Error::Budget("coordinate"))
    } else {
        Ok(v as Au)
    }
}
pub fn px(n: Au) -> Au {
    n.saturating_mul(PX).clamp(-MAX_COORD, MAX_COORD)
}
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rect {
    pub x: Au,
    pub y: Au,
    pub w: Au,
    pub h: Au,
}
impl Rect {
    pub fn new(x: Au, y: Au, w: Au, h: Au) -> Self {
        Self {
            x,
            y,
            w: w.max(0),
            h: h.max(0),
        }
    }
    pub fn right(self) -> Au {
        self.x.saturating_add(self.w)
    }
    pub fn bottom(self) -> Au {
        self.y.saturating_add(self.h)
    }
    pub fn intersect(self, b: Self) -> Self {
        let x = self.x.max(b.x);
        let y = self.y.max(b.y);
        Self::new(
            x,
            y,
            self.right().min(b.right()).saturating_sub(x),
            self.bottom().min(b.bottom()).saturating_sub(y),
        )
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Edges<T: Copy + Default> {
    pub top: T,
    pub right: T,
    pub bottom: T,
    pub left: T,
}
pub fn collapse_margin(a: Au, b: Au) -> Au {
    a.max(0).max(b.max(0)) + a.min(0).min(b.min(0))
}
pub fn image_len(w: u32, h: u32, stride: u32, max: u64) -> Result<usize> {
    let n = crate::verified::rgba_length(w, h, stride, max)
        .ok_or(Error::Invalid("image geometry or budget"))?;
    usize::try_from(n).map_err(|_| Error::Budget("image address space"))
}
