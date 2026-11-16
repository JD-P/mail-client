use lizard::{
    core::*,
    dom::Document,
    layout::{Engine, ImageResource},
    text::Fonts,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
#[derive(Deserialize, Serialize)]
struct Job {
    html: String,
    #[serde(default = "width")]
    width: u32,
    #[serde(default = "height")]
    height: u32,
    #[serde(default)]
    scroll: i64,
    #[serde(default)]
    resources: Vec<ImageResource>,
    #[serde(default)]
    diagnostic_trace: bool,
}
fn width() -> u32 {
    800
}
fn height() -> u32 {
    600
}
fn run(mut job: Job, preloaded: Option<Fonts>) -> Result<(Vec<u8>, serde_json::Value)> {
    let limits = Limits::default();
    if job.width == 0 || job.height == 0 || job.width > 4096 || job.height > 4096 {
        return Err(Error::Budget("viewport"));
    }
    if job.resources.len() > 256 {
        return Err(Error::Budget("image capabilities"));
    }
    let mut total = 0usize;
    for im in &job.resources {
        if im.width > 16384
            || im.height > 16384
            || im.width as u64 * im.height as u64 > limits.image_pixels
        {
            return Err(Error::Budget("image dimensions"));
        }
        let len = image_len(
            im.width,
            im.height,
            im.width.checked_mul(4).ok_or(Error::Budget("stride"))?,
            limits.decoded_bytes as u64,
        )?;
        if len != im.rgba.len() {
            return Err(Error::Invalid("image length"));
        }
        total = total.checked_add(len).ok_or(Error::Budget("images"))?;
        if total > limits.decoded_bytes {
            return Err(Error::Budget("images"));
        }
    }
    let mut budget = Budget::new(limits.steps);
    let doc = Document::parse(job.html.as_bytes(), &limits, &mut budget)?;
    let styles = lizard::style::compute(
        &doc,
        px(job.width as i64),
        px(job.height as i64),
        &limits,
        &mut budget,
        &[],
    )?;
    lizard::resources::collect_data(&doc, &styles, &mut job.resources, &limits, &mut budget)?;
    let fonts = match preloaded {
        Some(f) => f,
        None => Fonts::system()?,
    };
    let scene = Engine::new(
        &doc,
        &styles,
        &fonts,
        &job.resources,
        &limits,
        &mut budget,
        px(job.width as i64),
        px(job.height as i64),
    )
    .run()?;
    let rgba = lizard::paint::render(
        &scene,
        &fonts,
        &job.resources,
        job.width,
        job.height,
        px(job.scroll),
    )?;
    let trace = if job.diagnostic_trace {
        serde_json::json!({"document":doc,"styles":styles,"scene":scene,"limits":limits,"verified":false})
    } else {
        serde_json::json!({"width":scene.width,"height":scene.height,"links":scene.links,"accessible":scene.accessible,"readable_text":scene.readable_text,"work_remaining":scene.work_remaining,"verified":false})
    };
    Ok((rgba, trace))
}
fn png(
    path: &Path,
    rgba: &[u8],
    w: u32,
    h: u32,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let file = fs::File::create(path)?;
    let mut encoder = png::Encoder::new(file, w, h);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(rgba)?;
    Ok(())
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|x| x.as_str()) == Some("sandbox-self-test") {
        let fonts = Fonts::system()?;
        lizard::sandbox::enter()?;
        let file = fs::File::open("/etc/passwd");
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let ok = file.is_err() && sock < 0;
        println!(
            "{}",
            serde_json::json!({"filesystem_denied":file.is_err(),"network_denied":sock<0,"fonts_preloaded":fonts.fonts.len()})
        );
        if !ok {
            std::process::exit(1);
        }
        return Ok(());
    }
    if args.get(1).map(|x| x.as_str()) == Some("worker-stdio") {
        lizard::sandbox::set_limits()?;
        let mut n = [0u8; 8];
        std::io::stdin().read_exact(&mut n)?;
        let size = u64::from_le_bytes(n);
        if size > 20_000_000 {
            return Err("job too large".into());
        }
        let mut data = vec![0; size as usize];
        std::io::stdin().read_exact(&mut data)?;
        let job: Job = serde_json::from_slice(&data)?;
        let fonts = Fonts::system()?;
        lizard::sandbox::enter()?;
        let (rgba, trace) = run(job, Some(fonts))?;
        let trace = serde_json::to_vec(&trace)?;
        if trace.len() > 16_777_216 {
            return Err("trace too large".into());
        }
        let mut out = std::io::stdout().lock();
        out.write_all(&(rgba.len() as u64).to_le_bytes())?;
        out.write_all(&rgba)?;
        out.write_all(&(trace.len() as u64).to_le_bytes())?;
        out.write_all(&trace)?;
        out.flush()?;
        return Ok(());
    }
    if args.get(1).map(|x| x.as_str()) == Some("worker") {
        let mut s = String::new();
        std::io::stdin().take(20_000_000).read_to_string(&mut s)?;
        let job: Job = serde_json::from_str(&s)?;
        let (w, h) = (job.width, job.height);
        let (rgba, trace) = run(job, None)?;
        let out = args
            .get(2)
            .ok_or("worker requires output PNG path in development mode")?;
        png(Path::new(out), &rgba, w, h)?;
        if let Some(path) = args.get(3) {
            fs::write(path, serde_json::to_vec_pretty(&trace)?)?;
        }
        println!("{}", serde_json::json!({"ok":true,"width":w,"height":h}));
        return Ok(());
    }
    if args.len() < 4 || args[1] != "render" {
        eprintln!("usage: lizard render INPUT.html OUTPUT.png [WIDTH HEIGHT TRACE.json SCROLL]\n       lizard worker OUTPUT.png [TRACE.json] < job.json\nDevelopment renderer: not a complete client or sandbox supervisor.");
        std::process::exit(2);
    }
    let w = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(800);
    let h = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(600);
    let job = Job {
        html: fs::read_to_string(&args[2])?,
        width: w,
        height: h,
        scroll: args.get(7).and_then(|s| s.parse().ok()).unwrap_or(0),
        resources: vec![],
        diagnostic_trace: args.get(6).is_some(),
    };
    let started = std::time::Instant::now();
    let packet = serde_json::to_vec(&job)?;
    let (rgba, trace_bytes) = lizard::worker::render(&packet, w, h)?;
    let trace: serde_json::Value = serde_json::from_slice(&trace_bytes)?;
    png(Path::new(&args[3]), &rgba, w, h)?;
    if let Some(path) = args.get(6) {
        fs::write(path, serde_json::to_vec_pretty(&trace)?)?;
    }
    println!(
        "{}",
        serde_json::json!({"ok":true,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0,"output":args[3]})
    );
    std::io::stdout().flush()?;
    Ok(())
}
