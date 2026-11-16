//! The explicit native boundary: WebRender's Rust API and SWGL's C++ rasterizer.
use crate::core::Au;
use crate::{core::*, layout::*, text::Fonts};
use gleam::gl;
use std::{
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
        options.enable_subpixel_aa = false;
        options.clear_color = ColorF::WHITE;
        options.surface_origin_is_top_left = true;
        options.clear_caches_with_quads = false;
        options.allow_advanced_blend_equation = true;
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
        self.document_height = scene.height;
        let api = &mut self.api;
        let mut txn = Transaction::new();
        for key in self.image_keys.drain(..) {
            txn.delete_image(key);
        }
        let mut image_keys = vec![];
        for im in images {
            let key = api.generate_image_key();
            txn.add_image(
                key,
                ImageDescriptor::new(
                    im.width as i32,
                    im.height as i32,
                    ImageFormat::RGBA8,
                    ImageDescriptorFlags::empty(),
                ),
                ImageData::new(
                    im.rgba
                        .chunks_exact(4)
                        .flat_map(|p| {
                            [
                                crate::verified::premultiply_channel(p[0], p[3]),
                                crate::verified::premultiply_channel(p[1], p[3]),
                                crate::verified::premultiply_channel(p[2], p[3]),
                                p[3],
                            ]
                        })
                        .collect(),
                ),
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
        for p in &scene.primitives {
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
                    let value = *opacity as f32 / 1000.0;
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
                Draw::TiledImage {
                    rect: r,
                    resource,
                    tile,
                } => {
                    let b = rect(*r, scroll);
                    builder.push_repeating_image(
                        &common(b),
                        b,
                        LayoutSize::new(tile.0 as f32 / 60.0, tile.1 as f32 / 60.0),
                        LayoutSize::zero(),
                        ImageRendering::Auto,
                        AlphaType::PremultipliedAlpha,
                        image_keys[*resource],
                        color(0xffffffff, p.opacity),
                    );
                }
                Draw::Image { rect: r, resource } => {
                    let b = rect(*r, scroll);
                    builder.push_image(
                        &common(b),
                        b,
                        ImageRendering::Auto,
                        AlphaType::PremultipliedAlpha,
                        image_keys[*resource],
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
