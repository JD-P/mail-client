#![forbid(unsafe_code)]
//! Font loading and shaping are unverified adapters, outside the integer kernel.
use crate::{core::*, style::*};
use serde::Serialize;
#[derive(Clone)]
pub struct FontData {
    pub bytes: Vec<u8>,
    pub path: String,
    pub index: u32,
}
pub struct Fonts {
    pub fonts: Vec<FontData>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Glyph {
    pub index: u32,
    pub x: Au,
    pub y: Au,
    pub cluster: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct Run {
    pub font: usize,
    pub size: Au,
    pub glyphs: Vec<Glyph>,
    pub width: Au,
    pub ascent: Au,
    pub descent: Au,
    pub text: String,
}
impl Fonts {
    pub fn system() -> Result<Self> {
        let mut fonts = vec![];
        for family in ["DejaVuSerif", "DejaVuSans", "DejaVuSansMono"] {
            for suffix in ["", "-Bold", "-Italic", "-BoldItalic"] {
                let suffix = if family != "DejaVuSerif" {
                    suffix.replace("Italic", "Oblique")
                } else {
                    suffix.into()
                };
                let path = format!("/usr/share/fonts/truetype/dejavu/{family}{suffix}.ttf");
                let bytes = std::fs::read(&path).map_err(|_| Error::Resource(path.clone()))?;
                fonts.push(FontData {
                    bytes,
                    path,
                    index: 0,
                });
            }
        }
        for (family_no, family) in ["LiberationSans", "LiberationSerif", "LiberationMono"]
            .iter()
            .enumerate()
        {
            for (style_no, suffix) in ["Regular", "Bold", "Italic", "BoldItalic"]
                .iter()
                .enumerate()
            {
                let a = format!("/usr/share/fonts/truetype/liberation2/{family}-{suffix}.ttf");
                let b = format!("/usr/share/fonts/truetype/liberation/{family}-{suffix}.ttf");
                let path = if std::path::Path::new(&a).is_file() {
                    a
                } else {
                    b
                };
                match std::fs::read(&path) {
                    Ok(bytes) => fonts.push(FontData {
                        bytes,
                        path,
                        index: 0,
                    }),
                    Err(_) => {
                        let base = match family_no {
                            0 => 1,
                            1 => 0,
                            _ => 2,
                        };
                        fonts.push(fonts[base * 4 + style_no].clone());
                    }
                }
            }
        }
        Ok(Self { fonts })
    }
    pub fn id(&self, s: &Style) -> usize {
        let family = match s.font {
            Family::Serif => 0,
            Family::Sans => 1,
            Family::Mono => 2,
            Family::Arial => 3,
            Family::Times => 4,
            Family::Courier => 5,
        };
        family * 4 + if s.italic { 2 } else { 0 } + if s.weight >= 600 { 1 } else { 0 }
    }
    pub fn metrics(&self, s: &Style) -> (Au, Au, Au) {
        let face = rustybuzz::Face::from_slice(&self.fonts[self.id(s)].bytes, 0).unwrap();
        let u = face.units_per_em() as i64;
        let scale = |v: i64| ((v as i128 * s.font_size as i128 + u as i128 / 2) / u as i128) as Au;
        let a = ((scale(face.ascender() as i64) + PX - 1) / PX) * PX;
        let d = ((scale(-(face.descender() as i64)) + PX - 1) / PX) * PX;
        let gap = scale(face.line_gap() as i64);
        let h = ((a + d + gap + PX - 1) / PX) * PX;
        (a, d, h)
    }
    pub fn shape(&self, text: &str, s: &Style, budget: &mut Budget) -> Result<Run> {
        budget.charge(text.len() as u64 + 1)?;
        let id = self.id(s);
        let face = rustybuzz::Face::from_slice(&self.fonts[id].bytes, self.fonts[id].index)
            .ok_or(Error::Invalid("system font"))?;
        let text = match s.transform.as_str() {
            "uppercase" => text.to_uppercase(),
            "lowercase" => text.to_lowercase(),
            "capitalize" => {
                let mut first = true;
                text.chars()
                    .flat_map(|c| {
                        let upper = first;
                        first = c.is_whitespace();
                        if upper {
                            c.to_uppercase().collect::<Vec<_>>()
                        } else {
                            vec![c]
                        }
                    })
                    .collect()
            }
            _ => text.to_string(),
        };
        let bidi = unicode_bidi::BidiInfo::new(
            &text,
            Some(if s.direction_rtl {
                unicode_bidi::Level::rtl()
            } else {
                unicode_bidi::Level::ltr()
            }),
        );
        let mut glyphs = vec![];
        let mut pen = 0i64;
        let upem = face.units_per_em() as i64;
        for para in &bidi.paragraphs {
            let (_, runs) = bidi.visual_runs(para, para.range.clone());
            for range in runs {
                let mut buffer = rustybuzz::UnicodeBuffer::new();
                buffer.push_str(&text[range.clone()]);
                buffer.set_direction(if bidi.levels[range.start].is_rtl() {
                    rustybuzz::Direction::RightToLeft
                } else {
                    rustybuzz::Direction::LeftToRight
                });
                buffer.guess_segment_properties();
                let no_kern = "kern=0".parse::<rustybuzz::Feature>().unwrap();
                let features = if s.kerning { vec![] } else { vec![no_kern] };
                let shaped = rustybuzz::shape(&face, &features, buffer);
                for (info, pos) in shaped.glyph_infos().iter().zip(shaped.glyph_positions()) {
                    let scale = |n: i32| {
                        ((n as i128 * s.font_size as i128
                            + if n >= 0 {
                                upem as i128 / 2
                            } else {
                                -upem as i128 / 2
                            })
                            / upem as i128) as Au
                    };
                    glyphs.push(Glyph {
                        index: info.glyph_id,
                        x: pen + scale(pos.x_offset),
                        y: -scale(pos.y_offset),
                        cluster: info.cluster + range.start as u32,
                    });
                    pen = checked_add(pen, scale(pos.x_advance) + s.letter_spacing)?;
                }
            }
        }
        if text == " " {
            pen = checked_add(pen, s.word_spacing)?;
        }
        let (ascent, descent, _) = self.metrics(s);
        Ok(Run {
            font: id,
            size: s.font_size,
            glyphs,
            width: pen,
            ascent,
            descent,
            text,
        })
    }
}
