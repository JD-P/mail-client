#![forbid(unsafe_code)]
//! No I/O: decode only explicit raster bytes or literal data:image values.
use crate::{
    core::*,
    dom::*,
    layout::ImageResource,
    style::{Background, Style},
};
use base64::Engine;
pub fn decode(
    key: String,
    bytes: &[u8],
    limits: &Limits,
    budget: &mut Budget,
) -> Result<ImageResource> {
    if bytes.len() > limits.image_bytes {
        return Err(Error::Budget("encoded image"));
    }
    budget.charge(bytes.len() as u64)?;
    let format = image::guess_format(bytes).map_err(|_| Error::Invalid("raster format"))?;
    if !matches!(
        format,
        image::ImageFormat::Png
            | image::ImageFormat::Jpeg
            | image::ImageFormat::Gif
            | image::ImageFormat::WebP
    ) {
        return Err(Error::Invalid("non-approved image format"));
    }
    let mut reader = image::ImageReader::with_format(std::io::Cursor::new(bytes), format);
    let mut decode_limits = image::Limits::default();
    decode_limits.max_image_width = Some(16384);
    decode_limits.max_image_height = Some(16384);
    decode_limits.max_alloc = Some(limits.decoded_bytes as u64);
    reader.limits(decode_limits);
    let decoded = reader
        .decode()
        .map_err(|_| Error::Invalid("raster decode"))?
        .into_rgba8();
    let (w, h) = decoded.dimensions();
    let pixels = w as u64 * h as u64;
    if pixels > limits.image_pixels {
        return Err(Error::Budget("image pixels"));
    }
    budget.charge(pixels)?;
    let rgba = decoded.into_raw();
    image_len(
        w,
        h,
        w.checked_mul(4).ok_or(Error::Budget("image stride"))?,
        limits.decoded_bytes as u64,
    )?;
    Ok(ImageResource {
        key,
        width: w,
        height: h,
        rgba,
    })
}
pub fn data_uri(
    value: &str,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<Option<ImageResource>> {
    if !value.starts_with("data:") {
        return Ok(None);
    }
    let (header, data) = value.split_once(',').ok_or(Error::Invalid("data URL"))?;
    let header = header.to_ascii_lowercase();
    let typ = header
        .trim_start_matches("data:")
        .split(';')
        .next()
        .unwrap_or("");
    if !matches!(typ, "image/png" | "image/jpeg" | "image/gif" | "image/webp") {
        return Err(Error::Invalid("data image type"));
    }
    if data.len() > limits.image_bytes.saturating_mul(2) {
        return Err(Error::Budget("data image"));
    }
    let bytes = if header.ends_with(";base64") {
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| Error::Invalid("base64 image"))?
    } else {
        let b = data.as_bytes();
        let mut out = vec![];
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                if i + 2 >= b.len() {
                    return Err(Error::Invalid("percent image"));
                }
                let text = std::str::from_utf8(&b[i + 1..i + 3])
                    .map_err(|_| Error::Invalid("percent image"))?;
                out.push(
                    u8::from_str_radix(text, 16).map_err(|_| Error::Invalid("percent image"))?,
                );
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    };
    decode(value.to_string(), &bytes, limits, budget).map(Some)
}
pub fn collect_data(
    doc: &Document,
    styles: &[Style],
    images: &mut Vec<ImageResource>,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<()> {
    let mut candidates = vec![];
    for (id, n) in doc.nodes.iter().enumerate() {
        if n.disabled {
            continue;
        }
        if n.tag == "img" {
            if let Some(src) = n.attr("src") {
                candidates.push(src.to_string());
            }
        }
        for bg in &styles[id].backgrounds {
            if let Background::Image(src) = bg {
                candidates.push(src.clone());
            }
        }
    }
    let mut bytes = images.iter().map(|i| i.rgba.len()).sum::<usize>();
    for key in candidates {
        budget.charge(1)?;
        if images.iter().any(|i| i.key == key) {
            continue;
        }
        if images.len() >= 256 {
            return Err(Error::Budget("image capabilities"));
        }
        match data_uri(&key, limits, budget) {
            Ok(Some(image)) => {
                bytes = bytes
                    .checked_add(image.rgba.len())
                    .ok_or(Error::Budget("decoded image total"))?;
                if bytes > limits.decoded_bytes {
                    return Err(Error::Budget("decoded image total"));
                }
                images.push(image);
            }
            Ok(None) => {}
            Err(Error::Budget(s)) => return Err(Error::Budget(s)),
            Err(_) => { /* Invalid image becomes the normal blocked/alt-text placeholder. */ }
        }
    }
    Ok(())
}
