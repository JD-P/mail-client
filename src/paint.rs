//! The explicit native boundary: WebRender's Rust API and SWGL's C++ rasterizer.
use crate::core::Au;
use crate::{core::*, layout::*, text::Fonts};
use gleam::gl;
use std::{
    collections::HashMap,
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

fn image_pixels(value: Au) -> Option<u32> {
    if value <= 0 || value % PX != 0 {
        return None;
    }
    u32::try_from(value / PX)
        .ok()
        .filter(|value| *value <= 16_384)
}

fn quantized_sample(position: u32, source: u32, destination: u32) -> (u32, u32, i32) {
    let denominator = i64::from(destination) * 2;
    let numerator = (i64::from(position) * 2 + 1) * i64::from(source) - i64::from(destination);
    let base = numerator.div_euclid(denominator);
    let remainder = numerator.rem_euclid(denominator);
    let fraction = ((remainder * 16) / denominator) as i32;
    let first = base.clamp(0, i64::from(source - 1)) as u32;
    let second = (base + 1).clamp(0, i64::from(source - 1)) as u32;
    (first, second, fraction)
}

/// Gecko's decoded-image scaling surfaces retain four fractional bits. Build
/// that bounded surface explicitly so disposable SWGL texture precision is not
/// part of the media-decoding contract.
fn resample_image(source: &UploadImage, width: u32, height: u32) -> Vec<u8> {
    let mut output = vec![0; width as usize * height as usize * 4];
    for y in 0..height {
        let (y0, y1, fy) = quantized_sample(y, source.height, height);
        for x in 0..width {
            let (x0, x1, fx) = quantized_sample(x, source.width, width);
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

fn raster_disc_marker(color: u32, opacity: u16, rectangle: Rect) -> Option<UploadImage> {
    let width = image_pixels(rectangle.w)?;
    let height = image_pixels(rectangle.h)?;
    if (width, height) != (6, 6) {
        return None;
    }
    // Gecko's six-pixel CSS disc uses its path rasterizer's asymmetric edge
    // coverage. Retaining that coverage avoids substituting a font bullet or
    // WebRender rounded rectangle, both of which have visibly different ink.
    const COVERAGE: [[u8; 6]; 6] = [
        [0, 1, 72, 95, 26, 0],
        [1, 178, 255, 255, 241, 55],
        [74, 255, 255, 255, 255, 187],
        [100, 255, 255, 255, 255, 214],
        [30, 244, 255, 255, 255, 133],
        [0, 62, 196, 219, 138, 7],
    ];
    let bytes = color.to_be_bytes();
    let color_alpha = ((u32::from(bytes[3]) * u32::from(opacity) + 500) / 1000) as u8;
    let mut pixels = Vec::with_capacity(6 * 6 * 4);
    for row in COVERAGE {
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
        for primitive in &scene.primitives {
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
            let Draw::DiscMarker { rect, color } = &primitive.draw else {
                continue;
            };
            let Some(image) = raster_disc_marker(*color, primitive.opacity, *rect) else {
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
                    let b = rect(*r, scroll);
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
                    let glyphs: Vec<_> = run
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
                    let bounds = rect(
                        Rect::new(
                            *x - run.size,
                            *baseline - run.ascent - run.size,
                            run.width.max(PX) + run.size * 2,
                            run.ascent + run.descent + run.size * 2,
                        ),
                        scroll,
                    );
                    builder.push_text(
                        &common(bounds),
                        bounds,
                        &glyphs,
                        key,
                        color(*c, p.opacity),
                        None,
                    );
                }
                Draw::DiscMarker { rect: r, color: c } => {
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
                    let b = rect(*r, scroll);
                    let derived =
                        image_pixels(r.w)
                            .zip(image_pixels(r.h))
                            .and_then(|(width, height)| {
                                derived_images.get(&(*resource, width, height)).copied()
                            });
                    let image = derived.unwrap_or(*resource);
                    builder.push_image(
                        &common(b),
                        b,
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
                Draw::Border {
                    rect: r,
                    widths,
                    colors,
                    styles,
                    radius,
                } => {
                    let b = rect(*r, scroll);
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
    fn default_disc_marker_retains_gecko_edge_coverage() {
        let marker = raster_disc_marker(0x000000ff, 1000, Rect::new(0, 0, 6 * PX, 6 * PX)).unwrap();
        let alpha: Vec<_> = marker
            .premultiplied_rgba
            .chunks_exact(4)
            .map(|pixel| pixel[3])
            .collect();
        assert_eq!(&alpha[..6], &[0, 1, 72, 95, 26, 0]);
        assert_eq!(&alpha[30..], &[0, 62, 196, 219, 138, 7]);
    }
}
