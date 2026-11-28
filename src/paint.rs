//! The explicit native boundary: WebRender's Rust API and SWGL's C++ rasterizer.
use crate::core::Au;
use crate::{core::*, layout::*, text::Fonts};
use gleam::gl;
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    ptr,
    rc::Rc,
    sync::{mpsc, Arc},
    time::Duration,
};
use webrender::{api::units::*, api::*, render_api::*, *};

struct Notify(mpsc::Sender<()>);
impl RenderNotifier for Notify {
    fn clone(&self) -> Box<dyn RenderNotifier> {
        Box::new(Self(self.0.clone()))
    }
    fn wake_up(&self, _: bool) {}
    fn new_frame_ready(&self, _: DocumentId, _: FramePublishId, _: &FrameReadyParams) {
        let _ = self.0.send(());
    }
}

unsafe extern "C" fn allocation_size(p: *const c_void) -> usize {
    if p.is_null() {
        0
    } else {
        libc::malloc_usable_size(p as *mut c_void)
    }
}

fn rect(r: Rect, scroll: Au) -> LayoutRect {
    LayoutRect::from_origin_and_size(
        LayoutPoint::new(r.x as f32 / 60.0, (r.y - scroll) as f32 / 60.0),
        LayoutSize::new(r.w as f32 / 60.0, r.h as f32 / 60.0),
    )
}
fn color(c: u32, opacity: u16) -> ColorF {
    let a = c.to_be_bytes();
    ColorF::new(
        a[0] as f32 / 255.0,
        a[1] as f32 / 255.0,
        a[2] as f32 / 255.0,
        a[3] as f32 / 255.0 * opacity as f32 / 1000.0,
    )
}

#[derive(Clone)]
struct UploadImage {
    width: u32,
    height: u32,
    premultiplied_rgba: Vec<u8>,
}

fn premultiplied(image: &ImageResource) -> UploadImage {
    UploadImage {
        width: image.width,
        height: image.height,
        premultiplied_rgba: image
            .rgba
            .chunks_exact(4)
            .flat_map(|pixel| {
                [
                    crate::verified::premultiply_channel(pixel[0], pixel[3]),
                    crate::verified::premultiply_channel(pixel[1], pixel[3]),
                    crate::verified::premultiply_channel(pixel[2], pixel[3]),
                    pixel[3],
                ]
            })
            .collect(),
    }
}

fn raster_mask(mask: Vec<u8>, width: u32, height: u32, value: u32, opacity: u16) -> UploadImage {
    let color = value.to_be_bytes();
    let color_alpha = ((u32::from(color[3]) * u32::from(opacity) + 500) / 1000) as u8;
    let mut pixels = Vec::with_capacity(mask.len() * 4);
    for coverage in mask {
        let alpha = ((u16::from(color_alpha) * u16::from(coverage) + 127) / 255) as u8;
        pixels.extend_from_slice(&[
            ((u16::from(color[0]) * u16::from(alpha)) / 255) as u8,
            ((u16::from(color[1]) * u16::from(alpha)) / 255) as u8,
            ((u16::from(color[2]) * u16::from(alpha)) / 255) as u8,
            alpha,
        ]);
    }
    UploadImage {
        width,
        height,
        premultiplied_rgba: pixels,
    }
}

fn paint_solid_opaque(
    pixels: &mut [u8],
    width: u32,
    mask: &[u8],
    mask_width: u32,
    mask_height: u32,
    offset_x: u32,
    offset_y: u32,
    value: u32,
    fast_two_pixel: Option<&[bool]>,
    vertical_single_pixel: Option<&[bool]>,
) {
    let source = value.to_be_bytes();
    for y in 0..mask_height {
        for x in 0..mask_width {
            let coverage = mask[(y * mask_width + x) as usize];
            if coverage == 0 {
                continue;
            }
            let base = (((y + offset_y) * width + x + offset_x) * 4) as usize;
            if coverage == 255 {
                pixels[base..base + 3].copy_from_slice(&source[..3]);
            } else if fast_two_pixel.is_some_and(|fast| {
                fast.get((y * mask_width + x) as usize)
                    .copied()
                    .unwrap_or(false)
            }) {
                let scale = u16::from(coverage) + (u16::from(coverage) >> 7);
                for channel in 0..3 {
                    pixels[base + channel] = ((u16::from(source[channel]) * scale
                        + u16::from(pixels[base + channel]) * (256 - scale))
                        >> 8) as u8;
                }
            } else if vertical_single_pixel.is_some_and(|vertical| {
                vertical
                    .get((y * mask_width + x) as usize)
                    .copied()
                    .unwrap_or(false)
            }) {
                // Skia's one-pixel vertical shortcut first premultiplies the
                // opaque source by coverage, then derives the destination
                // scale from the quantized source alpha.
                let source_scale = u16::from(coverage) + (u16::from(coverage) >> 7);
                let source_alpha = (255 * source_scale) >> 8;
                let inverse = 255 - source_alpha;
                let destination_scale = inverse + (inverse >> 7);
                for channel in 0..3 {
                    pixels[base + channel] = (((u16::from(source[channel]) * source_scale) >> 8)
                        + ((u16::from(pixels[base + channel]) * destination_scale) >> 8))
                        as u8;
                }
            } else {
                for channel in 0..3 {
                    let foreground = (u16::from(source[channel]) * (u16::from(coverage) + 1)) >> 8;
                    let background =
                        (u16::from(pixels[base + channel]) * (256 - u16::from(coverage))) >> 8;
                    pixels[base + channel] = (foreground + background) as u8;
                }
            }
        }
    }
}

fn opaque_image(width: u32, height: u32, value: u32) -> UploadImage {
    let color = value.to_be_bytes();
    let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
    for _ in 0..width as usize * height as usize {
        pixels.extend_from_slice(&[color[0], color[1], color[2], 255]);
    }
    UploadImage {
        width,
        height,
        premultiplied_rgba: pixels,
    }
}

fn pixel_aligned_rect(rectangle: Rect) -> Option<(u32, u32)> {
    if rectangle.x % PX != 0 || rectangle.y % PX != 0 {
        return None;
    }
    image_pixels(rectangle.w).zip(image_pixels(rectangle.h))
}

fn paint_polygons_opaque(
    image: &mut UploadImage,
    polygons: &[Vec<(f32, f32)>],
    offset_x: u32,
    offset_y: u32,
    mask_width: u32,
    mask_height: u32,
    color: u32,
    through_aa_clip: bool,
) {
    let (mask, mut fast) =
        crate::software_raster::polygons_raster(mask_width, mask_height, polygons);
    if through_aa_clip {
        // Gecko clips each mismatched square corner before painting its side.
        // The clip forces Skia through its general mask compositor rather
        // than the two-pixel edge shortcut used by a directly filled path.
        fast.fill(false);
    }
    paint_solid_opaque(
        &mut image.premultiplied_rgba,
        image.width,
        &mask,
        mask_width,
        mask_height,
        offset_x,
        offset_y,
        color,
        Some(&fast),
        None,
    );
}

fn gecko_mixed_border_image(
    width: u32,
    height: u32,
    widths: &[Au; 4],
    colors: &[u32; 4],
    styles: &[String; 4],
    backing_color: u32,
) -> Option<UploadImage> {
    if styles.each_ref().map(String::as_str) != ["Solid", "Dashed", "Dotted", "Double"]
        || colors.iter().any(|color| color & 255 != 255)
    {
        return None;
    }
    let [top, right, bottom, left] = widths.map(image_pixels);
    let (top, right, bottom, left) = (top?, right?, bottom?, left?);
    if top == 0
        || right == 0
        || bottom == 0
        || left < 2
        || left >= width
        || right >= width
        || top >= height
        || bottom >= height
    {
        return None;
    }

    let mut image = opaque_image(width, height, backing_color);
    let top_f = top as f32;
    let right_f = right as f32;
    let bottom_f = bottom as f32;
    let left_f = left as f32;

    // Gecko paints dissimilar square corners one side at a time through a
    // diagonal clip. Keep each corner local so Skia's small-mask path (rather
    // than its wide RLE path) determines the edge coverage.
    paint_polygons_opaque(
        &mut image,
        &[vec![(0.0, 0.0), (left_f, 0.0), (left_f, top_f)]],
        0,
        0,
        left,
        top,
        colors[0],
        true,
    );
    let third = left / 3;
    let remainder = left % 3;
    let outer = third + u32::from(remainder == 2);
    let gap = third + u32::from(remainder == 1);
    let inner = left - outer - gap;
    let top_third = top / 3;
    let top_remainder = top % 3;
    let top_outer = top_third + u32::from(top_remainder == 2);
    let top_gap = top_third + u32::from(top_remainder == 1);
    let inner_start_y = top_outer + top_gap;
    let (mut left_corner_mask, _) = crate::software_raster::polygons_raster(
        left,
        top,
        &[vec![(0.0, 0.0), (left_f, top_f), (0.0, top_f)]],
    );
    for y in 0..top {
        for x in 0..left {
            let in_stripe =
                x < outer || (y >= inner_start_y && x >= outer + gap && x < outer + gap + inner);
            if !in_stripe {
                left_corner_mask[(y * left + x) as usize] = 0;
            }
        }
    }
    paint_solid_opaque(
        &mut image.premultiplied_rgba,
        image.width,
        &left_corner_mask,
        left,
        top,
        0,
        0,
        colors[3],
        None,
        None,
    );
    paint_polygons_opaque(
        &mut image,
        &[vec![(right_f, 0.0), (right_f, top_f), (0.0, top_f)]],
        width - right,
        0,
        right,
        top,
        colors[1],
        true,
    );
    paint_polygons_opaque(
        &mut image,
        &[vec![(0.0, 0.0), (right_f, 0.0), (0.0, top_f)]],
        width - right,
        0,
        right,
        top,
        colors[0],
        true,
    );

    // A dotted neighbor cedes its square corner to the non-dotted side.
    paint_polygons_opaque(
        &mut image,
        &[vec![
            (0.0, 0.0),
            (right_f, 0.0),
            (right_f, bottom_f),
            (0.0, bottom_f),
        ]],
        width - right,
        height - bottom,
        right,
        bottom,
        colors[1],
        false,
    );
    for (stripe_start, stripe_end) in [(0, outer), (outer + gap, outer + gap + inner)] {
        if stripe_end <= stripe_start {
            continue;
        }
        paint_polygons_opaque(
            &mut image,
            &[vec![
                (stripe_start as f32, 0.0),
                (stripe_end as f32, 0.0),
                (stripe_end as f32, bottom_f),
                (stripe_start as f32, bottom_f),
            ]],
            0,
            height - bottom,
            left,
            bottom,
            colors[3],
            false,
        );
    }

    // Straight top and double-left portions exclude the corners painted above.
    paint_polygons_opaque(
        &mut image,
        &[vec![
            (0.0, 0.0),
            ((width - left - right) as f32, 0.0),
            ((width - left - right) as f32, top_f),
            (0.0, top_f),
        ]],
        left,
        0,
        width - left - right,
        top,
        colors[0],
        false,
    );
    for (stripe_start, stripe_end) in [(0, outer), (outer + gap, outer + gap + inner)] {
        if stripe_end <= stripe_start {
            continue;
        }
        paint_polygons_opaque(
            &mut image,
            &[vec![
                (stripe_start as f32, 0.0),
                (stripe_end as f32, 0.0),
                (stripe_end as f32, (height - top - bottom) as f32),
                (stripe_start as f32, (height - top - bottom) as f32),
            ]],
            0,
            top,
            left,
            height - top - bottom,
            colors[3],
            false,
        );
    }

    // Gecko extends a dashed side to an adjacent dotted corner. The dash
    // setup then chooses an odd number of half-segments, yielding symmetric
    // half-dashes at the exposed ends.
    let dash_start = top_f;
    let dash_end = height as f32;
    let dash_length = dash_end - dash_start;
    let nominal_half_dash = right_f * 1.5;
    let mut half_count = (dash_length / nominal_half_dash).floor() as i32;
    match half_count.rem_euclid(4) {
        0 => half_count += 1,
        2 => half_count += 3,
        3 => half_count += 2,
        _ => {}
    }
    let half_dash = dash_length / half_count.max(1) as f32;
    let full_dash = half_dash * 2.0;
    let mut dashed_rects = Vec::new();
    let mut start = dash_start;
    let mut on = half_dash;
    while start < dash_end {
        let end = (start + on).min(dash_end);
        if end > start {
            dashed_rects.push(vec![
                (0.0, start),
                (right_f, start),
                (right_f, end),
                (0.0, end),
            ]);
        }
        start = end + full_dash;
        on = full_dash;
    }
    paint_polygons_opaque(
        &mut image,
        &dashed_rects,
        width - right,
        0,
        right,
        height,
        colors[1],
        false,
    );

    let center_y = height as f32 - bottom_f / 2.0;
    let dotted_start = width as f32 - right_f - bottom_f / 2.0;
    let dotted_end = left_f + bottom_f / 2.0;
    let dotted_length = dotted_start - dotted_end;
    let mut dot_count = (dotted_length / bottom_f).round() as u32;
    if dot_count % 2 == 1 {
        dot_count += 1;
    }
    let circles: Vec<_> = (1..=dot_count)
        .step_by(2)
        .map(|index| {
            let ratio = index as f32 / dot_count as f32;
            (
                dotted_start * (1.0 - ratio) + dotted_end * ratio,
                center_y,
                bottom_f / 2.0,
            )
        })
        .collect();
    let (circle_mask, circle_fast) =
        crate::software_raster::circles_raster(width, height, &circles);
    paint_solid_opaque(
        &mut image.premultiplied_rgba,
        width,
        &circle_mask,
        width,
        height,
        0,
        0,
        colors[2],
        Some(&circle_fast),
        None,
    );

    Some(image)
}

fn image_pixels(value: Au) -> Option<u32> {
    if value <= 0 || value % PX != 0 {
        return None;
    }
    u32::try_from(value / PX)
        .ok()
        .filter(|value| *value <= 16_384)
}

fn software_image_len(width: u32, height: u32) -> Option<usize> {
    image_len(width, height, width.checked_mul(4)?, 67_108_864).ok()
}

fn quantized_sample_with_ties(
    position: u32,
    source: u32,
    destination: u32,
    preceding_tie: bool,
) -> (u32, u32, i32) {
    let denominator = i64::from(destination) * 2;
    let numerator = (i64::from(position) * 2 + 1) * i64::from(source) - i64::from(destination);
    let base = numerator.div_euclid(denominator);
    let remainder = numerator.rem_euclid(denominator);
    let scaled_remainder = remainder * 16;
    let fraction = if preceding_tie && scaled_remainder == denominator * 12 {
        ((scaled_remainder - 1) / denominator) as i32
    } else {
        (scaled_remainder / denominator) as i32
    };
    let first = base.clamp(0, i64::from(source - 1)) as u32;
    let second = (base + 1).clamp(0, i64::from(source - 1)) as u32;
    (first, second, fraction)
}

#[cfg(test)]
fn quantized_sample(position: u32, source: u32, destination: u32) -> (u32, u32, i32) {
    quantized_sample_with_ties(position, source, destination, false)
}

/// Gecko's decoded-image scaling surfaces retain four fractional bits. Build
/// that bounded surface explicitly so disposable SWGL texture precision is not
/// part of the media-decoding contract.
fn resample_image_with_ties(
    source: &UploadImage,
    width: u32,
    height: u32,
    preceding_tie: bool,
) -> Vec<u8> {
    let mut output = vec![0; width as usize * height as usize * 4];
    for y in 0..height {
        let (y0, y1, fy) = quantized_sample_with_ties(y, source.height, height, preceding_tie);
        for x in 0..width {
            let (x0, x1, fx) = quantized_sample_with_ties(x, source.width, width, preceding_tie);
            for channel in 0..4usize {
                let sample = |sx: u32, sy: u32| -> i32 {
                    source.premultiplied_rgba[((sy * source.width + sx) * 4) as usize + channel]
                        .into()
                };
                let top = sample(x0, y0) + ((sample(x1, y0) - sample(x0, y0)) * fx >> 4);
                let bottom = sample(x0, y1) + ((sample(x1, y1) - sample(x0, y1)) * fx >> 4);
                output[((y * width + x) * 4) as usize + channel] =
                    (top + ((bottom - top) * fy >> 4)).clamp(0, 255) as u8;
            }
        }
    }
    output
}

fn resample_image(source: &UploadImage, width: u32, height: u32) -> Vec<u8> {
    resample_image_with_ties(source, width, height, false)
}

#[derive(Clone)]
struct ConvolutionFilter {
    offset: usize,
    values: Vec<i16>,
}

fn lanczos3(distance: f32) -> f32 {
    if !(-3.0..3.0).contains(&distance) {
        return 0.0;
    }
    if distance.abs() < f32::EPSILON {
        return 1.0;
    }
    let radians = distance * std::f32::consts::PI;
    (radians.sin() / radians) * ((radians / 3.0).sin() / (radians / 3.0))
}

/// Construct the same normalized 14-bit Lanczos-3 kernels used by Gecko's
/// raster-image decoder. Keeping this here, rather than delegating to an image
/// crate, also keeps malformed-message image work inside our existing budgets.
fn convolution_filters(source: u32, destination: u32) -> Vec<ConvolutionFilter> {
    let scale = destination as f32 / source as f32;
    let clamped_scale = scale.min(1.0);
    let support = 3.0 / clamped_scale;
    let inverse_scale = 1.0 / scale;
    let mut filters = Vec::with_capacity(destination as usize);
    for output in 0..destination {
        let source_pixel = (output as f32 + 0.5) * inverse_scale;
        let begin = (source_pixel - support)
            .floor()
            .clamp(0.0, source.saturating_sub(1) as f32) as usize;
        let end = (source_pixel + support)
            .ceil()
            .clamp(0.0, source.saturating_sub(1) as f32) as usize;
        let mut distance = (begin as f32 + 0.5 - source_pixel) * clamped_scale;
        let mut floating = Vec::with_capacity(end - begin + 1);
        let mut sum = 0.0f32;
        for _ in begin..=end {
            let value = lanczos3(distance);
            floating.push(value);
            sum += value;
            distance += clamped_scale;
        }
        let inverse_sum = 1.0 / sum;
        let mut values: Vec<i16> = floating
            .into_iter()
            .map(|value| (value * inverse_sum * 16_384.0) as i16)
            .collect();
        let fixed_sum: i32 = values.iter().map(|value| i32::from(*value)).sum();
        let middle = values.len() / 2;
        values[middle] = (i32::from(values[middle]) + 16_384 - fixed_sum) as i16;
        let leading_zeroes = values.iter().take_while(|value| **value == 0).count();
        let offset = begin + leading_zeroes;
        values.drain(..leading_zeroes);
        while values.last() == Some(&0) {
            values.pop();
        }
        filters.push(ConvolutionFilter { offset, values });
    }
    filters
}

fn convolve_channel(samples: impl Iterator<Item = (i16, u8)>) -> u8 {
    let accumulated: i32 = samples
        .map(|(filter, sample)| i32::from(filter) * i32::from(sample))
        .sum();
    ((accumulated + 8_192) >> 14).clamp(0, 255) as u8
}

/// Downscale a decoded premultiplied raster exactly as Gecko's
/// `DownscalingFilter` does: horizontal and vertical Lanczos-3 convolution,
/// with normalized 14-bit kernels and alpha repaired after the final pass.
fn downscale_image(source: &UploadImage, width: u32, height: u32) -> Vec<u8> {
    let horizontal_filters = convolution_filters(source.width, width);
    let vertical_filters = convolution_filters(source.height, height);
    let mut horizontal = vec![0; width as usize * source.height as usize * 4];
    for y in 0..source.height as usize {
        for (x, filter) in horizontal_filters.iter().enumerate() {
            for channel in 0..4usize {
                let samples = filter.values.iter().enumerate().map(|(index, value)| {
                    let source_index =
                        ((y * source.width as usize + filter.offset + index) * 4) + channel;
                    (*value, source.premultiplied_rgba[source_index])
                });
                horizontal[(y * width as usize + x) * 4 + channel] = convolve_channel(samples);
            }
        }
    }
    let mut output = vec![0; width as usize * height as usize * 4];
    for (y, filter) in vertical_filters.iter().enumerate() {
        for x in 0..width as usize {
            for channel in 0..4usize {
                let samples = filter.values.iter().enumerate().map(|(index, value)| {
                    let source_index =
                        (((filter.offset + index) * width as usize + x) * 4) + channel;
                    (*value, horizontal[source_index])
                });
                output[(y * width as usize + x) * 4 + channel] = convolve_channel(samples);
            }
            let pixel = &mut output[(y * width as usize + x) * 4..][..4];
            pixel[3] = pixel[3].max(pixel[0].max(pixel[1]).max(pixel[2]));
        }
    }
    output
}

fn rounded_app_unit(value: Au) -> i64 {
    (value as f64 / PX as f64).round() as i64
}

fn snapped_image_size(rectangle: Rect) -> Option<(u32, u32)> {
    let width =
        (rounded_app_unit(rectangle.x + rectangle.w) - rounded_app_unit(rectangle.x)).max(1);
    let height =
        (rounded_app_unit(rectangle.y + rectangle.h) - rounded_app_unit(rectangle.y)).max(1);
    let width = u32::try_from(width).ok()?;
    let height = u32::try_from(height).ok()?;
    (width <= 16_384 && height <= 16_384).then_some((width, height))
}

fn fractional_raster_size(rectangle: Rect) -> Option<(u32, u32)> {
    if rectangle.w <= 0 || rectangle.h <= 0 || (rectangle.w % PX == 0 && rectangle.h % PX == 0) {
        return None;
    }
    let width = u32::try_from(rectangle.w.div_euclid(PX) + 1).ok()?;
    let height = u32::try_from(rectangle.h.div_euclid(PX)).ok()?;
    (width <= 16_384 && (1..=16_384).contains(&height)).then_some((width, height))
}

fn raster_gradient(
    gradient: &crate::style::LinearGradient,
    current: u32,
    opacity: u16,
    rectangle: Rect,
    scene: &Scene,
    max_len: usize,
) -> Option<UploadImage> {
    let width = image_pixels(rectangle.w)?;
    let height = image_pixels(rectangle.h)?;
    let len = usize::try_from(width)
        .ok()?
        .checked_mul(usize::try_from(height).ok()?)?
        .checked_mul(4)?;
    if len > max_len {
        return None;
    }
    let w = f64::from(width);
    let h = f64::from(height);
    let angle = (gradient.angle_mdeg as f64 / 1000.0).to_radians();
    let (dx, dy) = (angle.sin(), -angle.cos());
    let extent = (w * dx).abs() + (h * dy).abs();
    if extent <= 0.0 {
        return None;
    }
    let start = (w / 2.0 - dx * extent / 2.0, h / 2.0 - dy * extent / 2.0);
    let end = (w / 2.0 + dx * extent / 2.0, h / 2.0 + dy * extent / 2.0);
    let n = gradient.stops.len();
    let mut offsets: Vec<Option<f64>> = gradient
        .stops
        .iter()
        .map(|stop| {
            stop.position.map(|length| {
                length.eval(
                    (extent * 60.0).round() as Au,
                    16 * PX,
                    16 * PX,
                    scene.width,
                    scene.height,
                ) as f64
                    / (extent * 60.0)
            })
        })
        .collect();
    if offsets.first()?.is_none() {
        offsets[0] = Some(0.0);
    }
    if offsets.last()?.is_none() {
        offsets[n - 1] = Some(1.0);
    }
    let mut previous = offsets[0]?.clamp(0.0, 1.0);
    offsets[0] = Some(previous);
    for value in offsets.iter_mut().skip(1) {
        if let Some(position) = value {
            *position = position.clamp(0.0, 1.0).max(previous);
            previous = *position;
        }
    }
    let mut from = 0usize;
    while from + 1 < n {
        let mut to = from + 1;
        while offsets[to].is_none() {
            to += 1;
        }
        let a = offsets[from]?;
        let b = offsets[to]?;
        for (index, slot) in offsets.iter_mut().enumerate().take(to).skip(from + 1) {
            *slot = Some(a + (b - a) * (index - from) as f64 / (to - from) as f64);
        }
        from = to;
    }
    let stops: Vec<_> = gradient
        .stops
        .iter()
        .enumerate()
        .map(|(index, stop)| {
            let bytes = stop.color.unwrap_or(current).to_be_bytes();
            let alpha = ((u32::from(bytes[3]) * u32::from(opacity) + 500) / 1000) as u8;
            (
                offsets[index].unwrap_or(0.0),
                [
                    crate::verified::premultiply_channel(bytes[0], alpha),
                    crate::verified::premultiply_channel(bytes[1], alpha),
                    crate::verified::premultiply_channel(bytes[2], alpha),
                    alpha,
                ],
            )
        })
        .collect();
    let vx = end.0 - start.0;
    let vy = end.1 - start.1;
    let denominator = vx * vx + vy * vy;
    let mut pixels = vec![0; len];
    for y in 0..height {
        for x in 0..width {
            let px = f64::from(x) + 0.5;
            let py = f64::from(y) + 0.5;
            let position =
                (((px - start.0) * vx + (py - start.1) * vy) / denominator).clamp(0.0, 1.0);
            let upper = stops
                .iter()
                .position(|(offset, _)| *offset >= position)
                .unwrap_or(stops.len() - 1);
            let lower = upper.saturating_sub(1);
            let span = stops[upper].0 - stops[lower].0;
            let amount = if span > 0.0 {
                ((position - stops[lower].0) / span).clamp(0.0, 1.0)
            } else {
                1.0
            };
            let base = ((y * width + x) * 4) as usize;
            for channel in 0..4 {
                pixels[base + channel] = (f64::from(stops[lower].1[channel])
                    + (f64::from(stops[upper].1[channel]) - f64::from(stops[lower].1[channel]))
                        * amount)
                    .round()
                    .clamp(0.0, 255.0) as u8;
            }
        }
    }
    Some(UploadImage {
        width,
        height,
        premultiplied_rgba: pixels,
    })
}

fn raster_disc_marker(color: u32, opacity: u16, rectangle: Rect, rtl: bool) -> Option<UploadImage> {
    let width = image_pixels(rectangle.w)?;
    let height = image_pixels(rectangle.h)?;
    if (width, height) != (6, 6) {
        return None;
    }
    // Gecko's six-pixel CSS disc uses its path rasterizer's asymmetric edge
    // coverage. Retaining that coverage avoids substituting a font bullet or
    // WebRender rounded rectangle, both of which have visibly different ink.
    const LTR_COVERAGE: [[u8; 6]; 6] = [
        [0, 1, 72, 95, 26, 0],
        [1, 178, 255, 255, 241, 55],
        [74, 255, 255, 255, 255, 187],
        [100, 255, 255, 255, 255, 214],
        [30, 244, 255, 255, 255, 133],
        [0, 62, 196, 219, 138, 7],
    ];
    const RTL_COVERAGE: [[u8; 6]; 6] = [
        [0, 13, 87, 85, 10, 0],
        [22, 221, 255, 255, 216, 16],
        [138, 255, 255, 255, 255, 123],
        [164, 255, 255, 255, 255, 150],
        [83, 255, 255, 255, 255, 69],
        [0, 104, 211, 210, 97, 0],
    ];
    let bytes = color.to_be_bytes();
    let color_alpha = ((u32::from(bytes[3]) * u32::from(opacity) + 500) / 1000) as u8;
    let mut pixels = Vec::with_capacity(6 * 6 * 4);
    for row in if rtl { RTL_COVERAGE } else { LTR_COVERAGE } {
        for coverage in row {
            let alpha = ((u16::from(color_alpha) * u16::from(coverage) + 127) / 255) as u8;
            pixels.extend_from_slice(&[
                crate::verified::premultiply_channel(bytes[0], alpha),
                crate::verified::premultiply_channel(bytes[1], alpha),
                crate::verified::premultiply_channel(bytes[2], alpha),
                alpha,
            ]);
        }
    }
    Some(UploadImage {
        width,
        height,
        premultiplied_rgba: pixels,
    })
}
struct ContextOwner(swgl::Context);
impl Drop for ContextOwner {
    fn drop(&mut self) {
        self.0.destroy();
    }
}

/// Retain this object for a message's lifetime. Scrolling reuses its display
/// list, scene, glyphs and picture caches; it does not repeat HTML layout.
pub struct Painter<'a> {
    fonts: &'a Fonts,
    renderer: Option<Renderer>,
    api: RenderApi,
    doc: DocumentId,
    pipe: PipelineId,
    font_keys: Vec<FontKey>,
    image_keys: Vec<ImageKey>,
    instances: Vec<(usize, Au, FontInstanceKey)>,
    rx: mpsc::Receiver<()>,
    gl: Rc<dyn gl::Gl>,
    width: u32,
    height: u32,
    document_height: Au,
    epoch: u32,
    frame_id: u64,
    context: ContextOwner,
}
impl<'a> Painter<'a> {
    pub fn new(fonts: &'a Fonts, width: u32, height: u32) -> Result<Self> {
        if width == 0 || height == 0 || width > 4096 || height > 4096 {
            return Err(Error::Budget("surface size"));
        }
        let context = ContextOwner(swgl::Context::create());
        let ctx = context.0;
        ctx.make_current();
        ctx.init_default_framebuffer(0, 0, width as i32, height as i32, 0, ptr::null_mut());
        let gl: Rc<dyn gl::Gl> = Rc::new(ctx);
        let mut options = WebRenderOptions::default();
        options.enable_debugger = false;
        options.size_of_op = Some(allocation_size);
        options.enable_gpu_markers = false;
        options.enable_subpixel_aa = true;
        options.clear_color = ColorF::WHITE;
        options.surface_origin_is_top_left = true;
        options.clear_caches_with_quads = false;
        options.allow_advanced_blend_equation = true;
        options.picture_tile_size = Some(DeviceIntSize::new(
            if cfg!(target_os = "windows") {
                512
            } else {
                1024
            },
            512,
        ));
        options.enable_shared_instance_buffer = !cfg!(target_os = "windows");
        options.workers = Some(Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .map_err(|_| Error::Resource("worker pool".into()))?,
        ));
        let (tx, rx) = mpsc::channel();
        let (renderer, sender) = create_webrender_instance(
            GpuBackendConfig::Gl(GlBackendConfig::new(gl.clone())),
            Box::new(Notify(tx)),
            options,
            None,
        )
        .map_err(|e| Error::Resource(format!("WebRender init: {e:?}")))?;

        let mut api = sender.create_api();
        let doc = api.add_document(DeviceIntSize::new(width as i32, height as i32));
        let pipe = PipelineId(0, 0);
        let mut txn = Transaction::new();
        let mut font_keys = vec![];
        for f in &fonts.fonts {
            let key = api.generate_font_key();
            txn.add_raw_font(key, f.bytes.clone(), f.index);
            font_keys.push(key);
        }
        api.send_transaction(doc, txn);
        Ok(Self {
            fonts,
            renderer: Some(renderer),
            api,
            doc,
            pipe,
            font_keys,
            image_keys: vec![],
            instances: vec![],
            rx,
            gl,
            width,
            height,
            document_height: height as Au * PX,
            epoch: 0,
            frame_id: 0,
            context,
        })
    }
    pub fn set_scene(&mut self, scene: &Scene, images: &[ImageResource]) -> Result<()> {
        self.context.0.make_current();
        if images.len() > 256 {
            return Err(Error::Budget("image capabilities"));
        }
        scene.validate(self.fonts, images)?;
        if scene.height < 0 || scene.height > MAX_COORD {
            return Err(Error::Budget("scene height"));
        }
        let mut total = 0usize;
        for im in images {
            if im.width > 16384 || im.height > 16384 {
                return Err(Error::Budget("image dimensions"));
            }
            let len = image_len(
                im.width,
                im.height,
                im.width.checked_mul(4).ok_or(Error::Budget("stride"))?,
                67_108_864,
            )?;
            total = total
                .checked_add(len)
                .ok_or(Error::Budget("decoded image total"))?;
            if total > 67_108_864 {
                return Err(Error::Budget("decoded image total"));
            }
            if im.rgba.len() != len {
                return Err(Error::Invalid("RGBA byte length"));
            }
        }
        let mut uploads: Vec<_> = images.iter().map(premultiplied).collect();
        let mut derived_images = HashMap::<(usize, u32, u32), usize>::new();
        let mut rasterized_images = HashMap::<(usize, u32, u32), usize>::new();
        for primitive in &scene.primitives {
            if let Draw::Image { rect, resource } = &primitive.draw {
                let source = &uploads[*resource];
                let decoded_size = snapped_image_size(*rect)
                    .filter(|(width, height)| *width < source.width && *height < source.height);
                if let Some((width, height)) = decoded_size {
                    let key = (*resource, width, height);
                    if !rasterized_images.contains_key(&key) {
                        let len = image_len(
                            width,
                            height,
                            width.checked_mul(4).ok_or(Error::Budget("stride"))?,
                            67_108_864,
                        )?;
                        if uploads.len() < 512 && total.saturating_add(len) <= 67_108_864 {
                            let derived = UploadImage {
                                width,
                                height,
                                premultiplied_rgba: downscale_image(source, width, height),
                            };
                            total += len;
                            let index = uploads.len();
                            uploads.push(derived);
                            rasterized_images.insert(key, index);
                        }
                    }
                    continue;
                }
                if let Some((width, height)) = fractional_raster_size(*rect) {
                    let key = (*resource, width, height);
                    if !rasterized_images.contains_key(&key) {
                        let len = image_len(
                            width,
                            height,
                            width.checked_mul(4).ok_or(Error::Budget("stride"))?,
                            67_108_864,
                        )?;
                        if uploads.len() < 512 && total.saturating_add(len) <= 67_108_864 {
                            let derived = UploadImage {
                                width,
                                height,
                                premultiplied_rgba: resample_image_with_ties(
                                    source, width, height, true,
                                ),
                            };
                            total += len;
                            let index = uploads.len();
                            uploads.push(derived);
                            rasterized_images.insert(key, index);
                        }
                    }
                    continue;
                }
            }
            let candidate = match &primitive.draw {
                Draw::Image { rect, resource } => Some((*resource, rect.w, rect.h)),
                Draw::TiledImage { resource, tile, .. } => Some((*resource, tile.0, tile.1)),
                _ => None,
            };
            let Some((resource, width, height)) = candidate else {
                continue;
            };
            let Some((width, height)) = image_pixels(width).zip(image_pixels(height)) else {
                continue;
            };
            let source = &uploads[resource];
            if (width, height) == (source.width, source.height)
                || derived_images.contains_key(&(resource, width, height))
            {
                continue;
            }
            let len = image_len(
                width,
                height,
                width.checked_mul(4).ok_or(Error::Budget("stride"))?,
                67_108_864,
            )?;
            if uploads.len() >= 512 || total.saturating_add(len) > 67_108_864 {
                continue;
            }
            let derived = UploadImage {
                width,
                height,
                premultiplied_rgba: resample_image(source, width, height),
            };
            total += len;
            let index = uploads.len();
            uploads.push(derived);
            derived_images.insert((resource, width, height), index);
        }
        let mut gradient_images = HashMap::<usize, usize>::new();
        for (primitive_index, primitive) in scene.primitives.iter().enumerate() {
            let Draw::Gradient {
                rect,
                gradient,
                color,
            } = &primitive.draw
            else {
                continue;
            };
            let Some(image) = raster_gradient(
                gradient,
                *color,
                primitive.opacity,
                *rect,
                scene,
                67_108_864usize.saturating_sub(total),
            ) else {
                continue;
            };
            let len = image.premultiplied_rgba.len();
            if uploads.len() >= 512 || total.saturating_add(len) > 67_108_864 {
                continue;
            }
            total += len;
            let index = uploads.len();
            uploads.push(image);
            gradient_images.insert(primitive_index, index);
        }
        let mut marker_images = HashMap::<usize, usize>::new();
        for (primitive_index, primitive) in scene.primitives.iter().enumerate() {
            let Draw::DiscMarker { rect, color, rtl } = &primitive.draw else {
                continue;
            };
            let Some(image) = raster_disc_marker(*color, primitive.opacity, *rect, *rtl) else {
                continue;
            };
            let len = image.premultiplied_rgba.len();
            if uploads.len() >= 512 || total.saturating_add(len) > 67_108_864 {
                continue;
            }
            total += len;
            let index = uploads.len();
            uploads.push(image);
            marker_images.insert(primitive_index, index);
        }
        let mut software_images = HashMap::<usize, usize>::new();
        for (primitive_index, primitive) in scene.primitives.iter().enumerate() {
            if uploads.len() >= 512 {
                break;
            }
            let remaining = 67_108_864usize.saturating_sub(total);
            let image = match &primitive.draw {
                Draw::Rect {
                    rect,
                    color,
                    radius,
                } if *radius > 0 && *radius % PX == 0 => pixel_aligned_rect(*rect)
                    .filter(|(width, height)| {
                        software_image_len(*width, *height).is_some_and(|len| len <= remaining)
                    })
                    .map(|(width, height)| {
                        raster_mask(
                            crate::software_raster::rounded_rect_mask(
                                width,
                                height,
                                *radius as f32 / PX as f32,
                            ),
                            width,
                            height,
                            *color,
                            primitive.opacity,
                        )
                    }),
                Draw::Border {
                    rect,
                    widths,
                    colors,
                    styles,
                    radius,
                } if *radius == 0 && primitive.opacity == 1000 => {
                    let backing_color =
                        scene.primitives[..primitive_index]
                            .iter()
                            .rev()
                            .find_map(|candidate| {
                                let Draw::Rect {
                                    rect: backing_rect,
                                    color,
                                    radius,
                                } = candidate.draw
                                else {
                                    return None;
                                };
                                (candidate.opacity == 1000
                                    && color & 255 == 255
                                    && radius == 0
                                    && backing_rect.x <= rect.x
                                    && backing_rect.y <= rect.y
                                    && backing_rect.x + backing_rect.w >= rect.x + rect.w
                                    && backing_rect.y + backing_rect.h >= rect.y + rect.h)
                                    .then_some(color)
                            });
                    pixel_aligned_rect(*rect)
                        .filter(|(width, height)| {
                            software_image_len(*width, *height).is_some_and(|len| len <= remaining)
                        })
                        .zip(backing_color)
                        .and_then(|((width, height), backing_color)| {
                            gecko_mixed_border_image(
                                width,
                                height,
                                widths,
                                colors,
                                styles,
                                backing_color,
                            )
                        })
                }
                Draw::Border {
                    rect,
                    widths,
                    colors,
                    styles,
                    radius,
                } if *radius > 0
                    && *radius % PX == 0
                    && widths.iter().all(|width| *width == widths[0])
                    && widths[0] > 0
                    && widths[0] % PX == 0
                    && colors.iter().all(|color| *color == colors[0])
                    && styles.iter().all(|style| style == "Solid") =>
                {
                    pixel_aligned_rect(*rect)
                        .filter(|(width, height)| {
                            software_image_len(*width, *height).is_some_and(|len| len <= remaining)
                        })
                        .map(|(width, height)| {
                            raster_mask(
                                crate::software_raster::rounded_border_mask(
                                    width,
                                    height,
                                    *radius as f32 / PX as f32,
                                    widths[0] as f32 / PX as f32,
                                ),
                                width,
                                height,
                                colors[0],
                                primitive.opacity,
                            )
                        })
                }
                _ => None,
            };
            let Some(image) = image else {
                continue;
            };
            let len = image.premultiplied_rgba.len();
            if uploads.len() >= 512 || total.saturating_add(len) > 67_108_864 {
                continue;
            }
            total += len;
            let index = uploads.len();
            uploads.push(image);
            software_images.insert(primitive_index, index);
        }
        let mut software_skips = HashSet::<usize>::new();
        for (border_index, border_primitive) in scene.primitives.iter().enumerate() {
            let Draw::Border {
                rect: border_rect,
                widths,
                colors,
                styles,
                radius: border_radius,
            } = &border_primitive.draw
            else {
                continue;
            };
            if border_primitive.opacity != 1000
                || colors[0] & 255 != 255
                || *border_radius <= 0
                || *border_radius % PX != 0
                || !widths.iter().all(|width| *width == widths[0])
                || widths[0] <= 0
                || widths[0] % PX != 0
                || !colors.iter().all(|value| *value == colors[0])
                || !styles.iter().all(|style| style == "Solid")
            {
                continue;
            }
            let Some((width, height)) = pixel_aligned_rect(*border_rect) else {
                continue;
            };
            let rounded_background = scene.primitives[..border_index]
                .iter()
                .enumerate()
                .rev()
                .find_map(|(index, primitive)| {
                    let Draw::Rect {
                        rect,
                        color,
                        radius,
                    } = primitive.draw
                    else {
                        return None;
                    };
                    (primitive.opacity == 1000
                        && color & 255 == 255
                        && radius > 0
                        && radius % PX == 0
                        && rect.x >= border_rect.x
                        && rect.y >= border_rect.y
                        && rect.x + rect.w <= border_rect.x + border_rect.w
                        && rect.y + rect.h <= border_rect.y + border_rect.h
                        && rect.x * 2 + rect.w == border_rect.x * 2 + border_rect.w
                        && rect.y * 2 + rect.h == border_rect.y * 2 + border_rect.h
                        && pixel_aligned_rect(rect).is_some())
                    .then_some((index, rect, color, radius))
                });
            let Some((background_index, background_rect, background_color, background_radius)) =
                rounded_background
            else {
                continue;
            };
            let backing_color =
                scene.primitives[..background_index]
                    .iter()
                    .rev()
                    .find_map(|primitive| {
                        let Draw::Rect {
                            rect,
                            color,
                            radius,
                        } = primitive.draw
                        else {
                            return None;
                        };
                        (primitive.opacity == 1000
                            && color & 255 == 255
                            && radius == 0
                            && rect.x <= border_rect.x
                            && rect.y <= border_rect.y
                            && rect.x + rect.w >= border_rect.x + border_rect.w
                            && rect.y + rect.h >= border_rect.y + border_rect.h)
                            .then_some(color)
                    });
            let Some(backing_color) = backing_color else {
                continue;
            };
            let Some((background_width, background_height)) = pixel_aligned_rect(background_rect)
            else {
                continue;
            };
            let Some(len) = software_image_len(width, height) else {
                continue;
            };
            if uploads.len() >= 512 || total.saturating_add(len) > 67_108_864 {
                continue;
            }
            let offset_x = ((background_rect.x - border_rect.x) / PX) as u32;
            let offset_y = ((background_rect.y - border_rect.y) / PX) as u32;
            let mut image = opaque_image(width, height, backing_color);
            let background_mask = crate::software_raster::rounded_rect_mask(
                background_width,
                background_height,
                background_radius as f32 / PX as f32,
            );
            paint_solid_opaque(
                &mut image.premultiplied_rgba,
                width,
                &background_mask,
                background_width,
                background_height,
                offset_x,
                offset_y,
                background_color,
                None,
                None,
            );
            let (border_mask, border_fast, _border_vertical) =
                crate::software_raster::rounded_border_raster(
                    width,
                    height,
                    *border_radius as f32 / PX as f32,
                    widths[0] as f32 / PX as f32,
                );
            paint_solid_opaque(
                &mut image.premultiplied_rgba,
                width,
                &border_mask,
                width,
                height,
                0,
                0,
                colors[0],
                Some(&border_fast),
                None,
            );
            debug_assert_eq!(len, image.premultiplied_rgba.len());
            total += len;
            let image_index = uploads.len();
            uploads.push(image);
            software_images.insert(border_index, image_index);
            software_skips.insert(background_index);
        }
        self.document_height = scene.height;
        let api = &mut self.api;
        let mut txn = Transaction::new();
        for key in self.image_keys.drain(..) {
            txn.delete_image(key);
        }
        let mut image_keys = vec![];
        for im in &uploads {
            let key = api.generate_image_key();
            txn.add_image(
                key,
                ImageDescriptor::new(
                    im.width as i32,
                    im.height as i32,
                    ImageFormat::RGBA8,
                    ImageDescriptorFlags::empty(),
                ),
                ImageData::new(im.premultiplied_rgba.clone()),
                None,
            );
            image_keys.push(key);
        }
        let instances = &mut self.instances;
        let font_keys = &self.font_keys;
        let pipe = self.pipe;
        let scroll = 0;
        let mut builder = DisplayListBuilder::new(pipe);
        builder.begin(60.0);
        let original = SpaceAndClipInfo::root_scroll(pipe);
        let sid = builder.define_scroll_frame(
            original.spatial_id,
            ExternalScrollId(1, pipe),
            rect(
                Rect::new(
                    0,
                    0,
                    self.width as Au * PX,
                    scene.height.max(self.height as Au * PX),
                ),
                0,
            ),
            rect(
                Rect::new(0, 0, self.width as Au * PX, self.height as Au * PX),
                0,
            ),
            LayoutVector2D::zero(),
            APZScrollGeneration::default(),
            HasScrollLinkedEffect::No,
        );
        let root = SpaceAndClipInfo {
            spatial_id: sid,
            clip_chain_id: original.clip_chain_id,
        };
        builder.push_simple_stacking_context(root.spatial_id, PrimitiveFlags::IS_BACKFACE_VISIBLE);
        for (primitive_index, p) in scene.primitives.iter().enumerate() {
            let clip = rect(p.clip, scroll);
            let clip_id = if p.clip_radius > 0 {
                builder.define_clip_rounded_rect(
                    root.spatial_id,
                    ComplexClipRegion::new(
                        clip,
                        BorderRadius::uniform(p.clip_radius as f32 / 60.0),
                        LayoutSideOffsets::zero(),
                        ClipMode::Clip,
                    ),
                )
            } else {
                builder.define_clip_rect(root.spatial_id, clip)
            };
            let mut clip_ids = vec![clip_id];
            if let Some(fixed) = p.fixed_clip {
                clip_ids.push(builder.define_clip_rect(root.spatial_id, rect(fixed, scroll)));
            }
            let chain = builder.define_clip_chain(None, clip_ids);
            let space = SpaceAndClipInfo {
                spatial_id: root.spatial_id,
                clip_chain_id: chain,
            };
            let common = |r| CommonItemProperties::new(r, space);
            match &p.draw {
                Draw::BeginOpacity { opacity } => {
                    // Gecko hands WebRender an 8-bit display opacity. Preserve
                    // that quantization before SWGL composites the isolated
                    // group; feeding the decimal CSS value directly changes
                    // half-opacity channels by one level.
                    let quantized = if *opacity == 0 {
                        0
                    } else {
                        ((u32::from(*opacity) * 255 + 500) / 1000 + 1).min(255)
                    };
                    let value = quantized as f32 / 255.0;
                    builder.push_stacking_context(
                        root.spatial_id,
                        PrimitiveFlags::IS_BACKFACE_VISIBLE,
                        None,
                        TransformStyle::Flat,
                        MixBlendMode::Normal,
                        &[FilterOp::Opacity(PropertyBinding::Value(value), value)],
                        &[],
                        RasterSpace::Screen,
                        StackingContextFlags::empty(),
                        None,
                    );
                }
                Draw::EndOpacity => builder.pop_stacking_context(),
                Draw::Rect {
                    rect: r,
                    color: c,
                    radius,
                } => {
                    if *c & 255 == 0 || r.w == 0 || r.h == 0 {
                        continue;
                    }
                    if software_skips.contains(&primitive_index) {
                        continue;
                    }
                    let b = rect(*r, scroll);
                    if let Some(image) = software_images.get(&primitive_index) {
                        builder.push_image(
                            &common(b),
                            b,
                            ImageRendering::Pixelated,
                            AlphaType::PremultipliedAlpha,
                            image_keys[*image],
                            color(0xffffffff, 1000),
                        );
                        continue;
                    }
                    let mut sc = space;
                    if *radius > 0 {
                        let id = builder.define_clip_rounded_rect(
                            root.spatial_id,
                            ComplexClipRegion::new(
                                b,
                                BorderRadius::uniform(*radius as f32 / 60.0),
                                LayoutSideOffsets::zero(),
                                ClipMode::Clip,
                            ),
                        );
                        let chain = builder.define_clip_chain(Some(chain), [id]);
                        sc.clip_chain_id = chain;
                    }
                    builder.push_rect(&CommonItemProperties::new(b, sc), b, color(*c, p.opacity));
                }
                Draw::Text {
                    x,
                    baseline,
                    run,
                    color: c,
                    ..
                } => {
                    let key = if let Some((_, _, k)) = instances
                        .iter()
                        .find(|(f, s, _)| *f == run.font && *s == run.size)
                    {
                        *k
                    } else {
                        if instances.len() >= 512 {
                            return Err(Error::Budget("font instances"));
                        }
                        let key = api.generate_font_instance_key();
                        txn.add_font_instance(
                            key,
                            font_keys[run.font],
                            run.size as f32 / 60.0,
                            Some(FontInstanceOptions {
                                render_mode: FontRenderMode::Alpha,
                                flags: FontInstanceFlags::SUBPIXEL_POSITION
                                    | FontInstanceFlags::EMBEDDED_BITMAPS,
                                ..Default::default()
                            }),
                            Some(FontInstancePlatformOptions {
                                hinting: FontHinting::Light,
                                ..Default::default()
                            }),
                            vec![],
                        );
                        instances.push((run.font, run.size, key));
                        key
                    };
                    let mut glyphs: Vec<_> = run
                        .glyphs
                        .iter()
                        .map(|g| GlyphInstance {
                            index: g.index,
                            point: LayoutPoint::new(
                                (x + g.x) as f32 / 60.0,
                                (baseline - scroll + g.y) as f32 / 60.0,
                            ),
                        })
                        .collect();
                    // Gecko preserves logical glyph order when it submits an
                    // RTL run to WebRender. HarfBuzz returns those glyphs in
                    // visual order, recognizable by descending source
                    // clusters, so reverse the submitted instances without
                    // changing their already-positioned coordinates. Joined
                    // scripts have overlapping glyph masks; matching Gecko's
                    // order also matches SWGL's byte-quantized composition at
                    // those overlaps.
                    let (has_distinct_clusters, clusters_descend) = run
                        .glyphs
                        .windows(2)
                        .filter(|pair| pair[0].cluster != pair[1].cluster)
                        .fold((false, true), |(_, descending), pair| {
                            (true, descending && pair[0].cluster > pair[1].cluster)
                        });
                    if has_distinct_clusters && clusters_descend {
                        glyphs.reverse();
                    }
                    let bounds = rect(
                        Rect::new(
                            *x - PX,
                            *baseline - run.ascent - PX,
                            run.width.max(PX) + PX * 2,
                            run.ascent + run.descent + PX * 2,
                        ),
                        scroll,
                    );
                    let clip_bounds = bounds.inflate(1.0, 1.0);
                    builder.push_text(
                        &common(clip_bounds),
                        bounds,
                        &glyphs,
                        key,
                        color(*c, p.opacity),
                        None,
                    );
                }
                Draw::DiscMarker {
                    rect: r, color: c, ..
                } => {
                    let b = rect(*r, scroll);
                    if let Some(image) = marker_images.get(&primitive_index) {
                        builder.push_image(
                            &common(b),
                            b,
                            ImageRendering::Pixelated,
                            AlphaType::PremultipliedAlpha,
                            image_keys[*image],
                            color(0xffffffff, 1000),
                        );
                    } else {
                        let id = builder.define_clip_rounded_rect(
                            root.spatial_id,
                            ComplexClipRegion::new(
                                b,
                                BorderRadius::uniform(r.w.min(r.h) as f32 / 120.0),
                                LayoutSideOffsets::zero(),
                                ClipMode::Clip,
                            ),
                        );
                        let chain = builder.define_clip_chain(Some(chain), [id]);
                        let marker_space = SpaceAndClipInfo {
                            spatial_id: root.spatial_id,
                            clip_chain_id: chain,
                        };
                        builder.push_rect(
                            &CommonItemProperties::new(b, marker_space),
                            b,
                            color(*c, p.opacity),
                        );
                    }
                }
                Draw::TiledImage {
                    rect: r,
                    resource,
                    tile,
                } => {
                    let b = rect(*r, scroll);
                    let derived = image_pixels(tile.0).zip(image_pixels(tile.1)).and_then(
                        |(width, height)| derived_images.get(&(*resource, width, height)).copied(),
                    );
                    let image = derived.unwrap_or(*resource);
                    builder.push_repeating_image(
                        &common(b),
                        b,
                        LayoutSize::new(tile.0 as f32 / 60.0, tile.1 as f32 / 60.0),
                        LayoutSize::zero(),
                        if derived.is_some() {
                            ImageRendering::Pixelated
                        } else {
                            ImageRendering::Auto
                        },
                        AlphaType::PremultipliedAlpha,
                        image_keys[image],
                        color(0xffffffff, p.opacity),
                    );
                }
                Draw::Image { rect: r, resource } => {
                    let source = &uploads[*resource];
                    let decoded_rasterized = snapped_image_size(*r)
                        .filter(|(width, height)| *width < source.width && *height < source.height)
                        .and_then(|(width, height)| {
                            rasterized_images.get(&(*resource, width, height)).copied()
                        });
                    let fractional_size = decoded_rasterized
                        .is_none()
                        .then(|| fractional_raster_size(*r))
                        .flatten();
                    let fractional_rasterized = fractional_size.and_then(|(width, height)| {
                        rasterized_images.get(&(*resource, width, height)).copied()
                    });
                    let paint_rect = if let Some((width, height)) = fractional_size {
                        Rect::new(
                            (r.x + PX - 1).div_euclid(PX) * PX,
                            (r.y + PX - 1).div_euclid(PX) * PX,
                            width as Au * PX,
                            height as Au * PX,
                        )
                    } else {
                        *r
                    };
                    let b = rect(paint_rect, scroll);
                    let rasterized = decoded_rasterized.or(fractional_rasterized);
                    let derived =
                        image_pixels(r.w)
                            .zip(image_pixels(r.h))
                            .and_then(|(width, height)| {
                                derived_images.get(&(*resource, width, height)).copied()
                            });
                    let image = rasterized.or(derived).unwrap_or(*resource);
                    let mut properties = common(b);
                    if decoded_rasterized.is_some() {
                        properties.flags |= PrimitiveFlags::RASTERIZED_FOR_RECT;
                    }
                    builder.push_image(
                        &properties,
                        b,
                        if fractional_rasterized.is_some()
                            || (derived.is_some() && rasterized.is_none())
                        {
                            ImageRendering::Pixelated
                        } else {
                            ImageRendering::Auto
                        },
                        AlphaType::PremultipliedAlpha,
                        image_keys[image],
                        color(0xffffffff, p.opacity),
                    );
                }
                Draw::Border {
                    rect: r,
                    widths,
                    colors,
                    styles,
                    radius,
                } => {
                    let b = rect(*r, scroll);
                    if let Some(image) = software_images.get(&primitive_index) {
                        builder.push_image(
                            &common(b),
                            b,
                            ImageRendering::Pixelated,
                            AlphaType::PremultipliedAlpha,
                            image_keys[*image],
                            color(0xffffffff, 1000),
                        );
                        continue;
                    }
                    let side = |i: usize| BorderSide {
                        color: color(colors[i], p.opacity),
                        style: match styles[i].as_str() {
                            "Solid" => BorderStyle::Solid,
                            "Dotted" => BorderStyle::Dotted,
                            "Dashed" => BorderStyle::Dashed,
                            "Double" => BorderStyle::Double,
                            "Groove" => BorderStyle::Groove,
                            "Ridge" => BorderStyle::Ridge,
                            "Inset" => BorderStyle::Inset,
                            "Outset" => BorderStyle::Outset,
                            _ => BorderStyle::None,
                        },
                    };
                    builder.push_border(
                        &common(b),
                        b,
                        LayoutSideOffsets::new(
                            widths[0] as f32 / 60.0,
                            widths[1] as f32 / 60.0,
                            widths[2] as f32 / 60.0,
                            widths[3] as f32 / 60.0,
                        ),
                        BorderDetails::Normal(NormalBorder {
                            top: side(0),
                            right: side(1),
                            bottom: side(2),
                            left: side(3),
                            radius: BorderRadius::uniform(*radius as f32 / 60.0),
                            inset: LayoutSideOffsets::zero(),
                            do_aa: true,
                        }),
                        &[],
                    );
                }
                Draw::Gradient {
                    rect: r,
                    gradient,
                    color: current,
                } => {
                    let b = rect(*r, scroll);
                    if let Some(image) = gradient_images.get(&primitive_index) {
                        builder.push_image(
                            &common(b),
                            b,
                            ImageRendering::Pixelated,
                            AlphaType::PremultipliedAlpha,
                            image_keys[*image],
                            color(0xffffffff, 1000),
                        );
                        continue;
                    }
                    let w = r.w as f64 / 60.0;
                    let h = r.h as f64 / 60.0;
                    let angle = (gradient.angle_mdeg as f64 / 1000.0).to_radians();
                    let (dx, dy) = (angle.sin(), -angle.cos());
                    let extent = (w * dx).abs() + (h * dy).abs();
                    let start = LayoutVector2D::new(
                        (w / 2.0 - dx * extent / 2.0) as f32,
                        (h / 2.0 - dy * extent / 2.0) as f32,
                    );
                    let end = LayoutVector2D::new(
                        (w / 2.0 + dx * extent / 2.0) as f32,
                        (h / 2.0 + dy * extent / 2.0) as f32,
                    );
                    let n = gradient.stops.len();
                    let mut offsets: Vec<Option<f32>> = gradient
                        .stops
                        .iter()
                        .map(|s| {
                            s.position.map(|l| {
                                if extent > 0.0 {
                                    (l.eval(
                                        (extent * 60.0).round() as Au,
                                        16 * PX,
                                        16 * PX,
                                        scene.width,
                                        scene.height,
                                    ) as f64
                                        / (extent * 60.0))
                                        as f32
                                } else {
                                    0.0
                                }
                            })
                        })
                        .collect();
                    if offsets[0].is_none() {
                        offsets[0] = Some(0.0);
                    }
                    if offsets[n - 1].is_none() {
                        offsets[n - 1] = Some(1.0);
                    }
                    let mut previous = offsets[0].unwrap().clamp(0.0, 1.0);
                    offsets[0] = Some(previous);
                    for value in offsets.iter_mut().skip(1) {
                        if let Some(v) = value {
                            *v = v.clamp(0.0, 1.0).max(previous);
                            previous = *v;
                        }
                    }
                    let mut i = 0;
                    while i < n - 1 {
                        let mut j = i + 1;
                        while offsets[j].is_none() {
                            j += 1;
                        }
                        let a = offsets[i].unwrap();
                        let z = offsets[j].unwrap();
                        for k in i + 1..j {
                            offsets[k] = Some(a + (z - a) * (k - i) as f32 / (j - i) as f32);
                        }
                        i = j;
                    }
                    let stops: Vec<_> = gradient
                        .stops
                        .iter()
                        .enumerate()
                        .map(|(i, s)| GradientStop {
                            offset: offsets[i].unwrap(),
                            color: color(s.color.unwrap_or(*current), p.opacity),
                        })
                        .collect();
                    builder.push_gradient(
                        &common(b),
                        b,
                        Gradient {
                            start,
                            end,
                            extend_mode: ExtendMode::Clamp,
                            alpha_mode: AlphaMode::Premultiplied,
                        },
                        b.size(),
                        LayoutSize::zero(),
                        &stops,
                    );
                }
            }
        }
        builder.pop_stacking_context();
        txn.set_display_list(Epoch(self.epoch), api.get_namespace_id(), builder.end());
        txn.set_root_pipeline(pipe);
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or(Error::Budget("scene epochs"))?;
        api.send_transaction(self.doc, txn);
        self.image_keys = image_keys;
        Ok(())
    }
    pub fn frame(&mut self, scroll: Au) -> Result<Vec<u8>> {
        if scroll < 0 || scroll > MAX_COORD {
            return Err(Error::Invalid("scroll offset"));
        }
        self.context.0.make_current();
        let scroll = scroll.min((self.document_height - self.height as Au * PX).max(0));
        let mut txn = Transaction::new();
        txn.set_scroll_offsets(
            ExternalScrollId(1, self.pipe),
            vec![SampledScrollOffset {
                offset: LayoutVector2D::new(0.0, scroll as f32 / 60.0),
                generation: APZScrollGeneration::default(),
            }],
        );
        txn.generate_frame(self.frame_id, true, false, RenderReasons::empty());
        self.frame_id = self
            .frame_id
            .checked_add(1)
            .ok_or(Error::Budget("frame IDs"))?;
        self.api.send_transaction(self.doc, txn);
        self.rx
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| Error::Budget("render deadline"))?;
        let renderer = self
            .renderer
            .as_mut()
            .ok_or(Error::Invalid("renderer closed"))?;
        renderer.update();
        renderer
            .render(DeviceIntSize::new(self.width as i32, self.height as i32), 0)
            .map_err(|e| Error::Resource(format!("WebRender draw: {e:?}")))?;
        self.gl.finish();
        let _ = renderer.flush_pipeline_info();
        Ok(self.gl.read_pixels(
            0,
            0,
            self.width as i32,
            self.height as i32,
            gl::RGBA,
            gl::UNSIGNED_BYTE,
        ))
    }
}
impl Drop for Painter<'_> {
    fn drop(&mut self) {
        self.context.0.make_current();
        if let Some(renderer) = self.renderer.take() {
            renderer.deinit();
        }
    }
}
pub fn render(
    scene: &Scene,
    fonts: &Fonts,
    images: &[ImageResource],
    width: u32,
    height: u32,
    scroll: Au,
) -> Result<Vec<u8>> {
    let mut painter = Painter::new(fonts, width, height)?;
    painter.set_scene(scene, images)?;
    painter.frame(scroll)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_rasters_are_budgeted_before_allocation() {
        assert_eq!(software_image_len(4_096, 4_096), Some(67_108_864));
        assert_eq!(software_image_len(4_097, 4_096), None);
        assert_eq!(software_image_len(16_384, 16_384), None);
    }

    #[test]
    fn decoded_image_sampling_uses_four_fractional_bits() {
        assert_eq!(quantized_sample(0, 2, 3), (0, 0, 13));
        assert_eq!(quantized_sample(1, 2, 3), (0, 1, 8));
        assert_eq!(quantized_sample(2, 2, 3), (1, 1, 2));
    }

    #[test]
    fn decoded_image_resampling_interpolates_premultiplied_bytes() {
        let source = UploadImage {
            width: 2,
            height: 1,
            premultiplied_rgba: vec![0, 0, 0, 255, 240, 120, 0, 255],
        };
        assert_eq!(
            resample_image(&source, 3, 1),
            vec![0, 0, 0, 255, 120, 60, 0, 255, 240, 120, 0, 255]
        );
    }

    #[test]
    fn decoded_image_downscaling_matches_gecko_lanczos_surface() {
        let mut pixels = Vec::new();
        for y in 0..4 {
            for x in 0..8 {
                pixels.extend_from_slice(match (x < 4, y < 2) {
                    (true, true) => &[255, 0, 0, 255],
                    (false, true) => &[0, 128, 0, 255],
                    (true, false) => &[0, 0, 255, 255],
                    (false, false) => &[0, 0, 0, 0],
                });
            }
        }
        let source = UploadImage {
            width: 8,
            height: 4,
            premultiplied_rgba: pixels,
        };
        assert_eq!(
            downscale_image(&source, 3, 2),
            vec![
                237, 0, 18, 255, 118, 59, 9, 246, 0, 129, 0, 237, 18, 0, 237, 255, 9, 5, 118, 136,
                0, 10, 0, 18,
            ]
        );
    }

    #[test]
    fn fractional_image_rect_uses_snapped_device_extent() {
        assert_eq!(
            snapped_image_size(Rect::new(5 * PX, 5 * PX, 3 * PX, 3 * PX / 2)),
            Some((3, 2))
        );
    }

    #[test]
    fn default_disc_marker_retains_gecko_edge_coverage() {
        let marker =
            raster_disc_marker(0x000000ff, 1000, Rect::new(0, 0, 6 * PX, 6 * PX), false).unwrap();
        let alpha: Vec<_> = marker
            .premultiplied_rgba
            .chunks_exact(4)
            .map(|pixel| pixel[3])
            .collect();
        assert_eq!(&alpha[..6], &[0, 1, 72, 95, 26, 0]);
        assert_eq!(&alpha[30..], &[0, 62, 196, 219, 138, 7]);
    }

    #[test]
    fn rtl_disc_marker_retains_gecko_edge_coverage() {
        let marker =
            raster_disc_marker(0x000000ff, 1000, Rect::new(0, 0, 6 * PX, 6 * PX), true).unwrap();
        let alpha: Vec<_> = marker
            .premultiplied_rgba
            .chunks_exact(4)
            .map(|pixel| pixel[3])
            .collect();
        assert_eq!(&alpha[..6], &[0, 13, 87, 85, 10, 0]);
        assert_eq!(&alpha[30..], &[0, 104, 211, 210, 97, 0]);
    }
}
