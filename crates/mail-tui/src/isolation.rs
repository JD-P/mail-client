//! Disposable Linux process boundary for terminal HTML parsing and layout.
//!
//! The child never receives a terminal, profile, credential, network or
//! display handle. It returns a bounded semantic page; the parent validates
//! that page and remains the only process allowed to emit terminal controls.

use crate::{
    HtmlRenderer, ImageReference, ImageSource, Limits, LinkKind, LinkReference, RenderOptions,
    RenderedPage,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ratatui::{
    layout::Alignment,
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};
use unicode_width::UnicodeWidthStr;
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL_VERSION: u32 = 1;
const MAX_REQUEST_BYTES: usize = 6 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ERROR_CHARS: usize = 4 * 1024;
const MAX_OUTPUT_SPANS: usize = 250_000;
const MAX_OUTPUT_TEXT_BYTES: usize = 20 * 1024 * 1024;
const MAX_REFERENCE_BYTES: usize = 16 * 1024;
const MAX_WARNINGS: usize = 1_024;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[derive(Clone, Debug)]
pub struct HtmlRenderIsolationConfig {
    pub worker_path: PathBuf,
    pub wall_timeout: Duration,
}

impl Default for HtmlRenderIsolationConfig {
    fn default() -> Self {
        Self {
            worker_path: default_worker_path(),
            wall_timeout: Duration::from_secs(5),
        }
    }
}

fn default_worker_path() -> PathBuf {
    let name = if cfg!(windows) {
        "lizard-mail-tui-render-worker.exe"
    } else {
        "lizard-mail-tui-render-worker"
    };
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_owned))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(name)
}

#[derive(Clone, Debug)]
pub struct IsolatedHtmlRenderer {
    limits: Limits,
    isolation: HtmlRenderIsolationConfig,
}

impl Default for IsolatedHtmlRenderer {
    fn default() -> Self {
        Self::new(Limits::default(), HtmlRenderIsolationConfig::default())
    }
}

impl IsolatedHtmlRenderer {
    pub fn new(limits: Limits, isolation: HtmlRenderIsolationConfig) -> Self {
        Self { limits, isolation }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub async fn render(
        &self,
        html: &[u8],
        width: u16,
    ) -> Result<RenderedPage, IsolatedRenderError> {
        if width == 0 {
            return Err(IsolatedRenderError::InvalidInput(
                "terminal rendering width must be at least one cell".into(),
            ));
        }
        if html.len() > self.limits.max_input_bytes {
            return Err(IsolatedRenderError::InvalidInput(format!(
                "HTML input is {} bytes; limit is {}",
                html.len(),
                self.limits.max_input_bytes
            )));
        }
        validate_limits(&self.limits).map_err(IsolatedRenderError::InvalidInput)?;
        if self.isolation.wall_timeout.is_zero() {
            return Err(IsolatedRenderError::InvalidInput(
                "renderer wall timeout must not be zero".into(),
            ));
        }
        let worker_path = std::fs::canonicalize(&self.isolation.worker_path).map_err(|error| {
            IsolatedRenderError::Unavailable(format!("renderer worker is unavailable: {error}"))
        })?;
        let request = WorkerRequest {
            protocol: PROTOCOL_VERSION,
            width,
            limits: self.limits.clone(),
            html_base64: BASE64.encode(html),
        };
        let mut payload = Zeroizing::new(
            serde_json::to_vec(&request)
                .map_err(|error| IsolatedRenderError::Protocol(error.to_string()))?,
        );
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(IsolatedRenderError::InvalidInput(
                "renderer request exceeds its protocol limit".into(),
            ));
        }
        let request_length = u32::try_from(payload.len()).map_err(|_| {
            IsolatedRenderError::InvalidInput("renderer request length overflow".into())
        })?;
        let mut command = Command::new(worker_path);
        command
            .arg("--worker-v1")
            .env_clear()
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        prepare_worker_command(&mut command).map_err(IsolatedRenderError::Unavailable)?;
        let mut child = command.spawn().map_err(|error| {
            IsolatedRenderError::Unavailable(format!("could not start renderer worker: {error}"))
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            IsolatedRenderError::Protocol("renderer worker stdin was unavailable".into())
        })?;
        let mut stdout = child.stdout.take().ok_or_else(|| {
            IsolatedRenderError::Protocol("renderer worker stdout was unavailable".into())
        })?;
        let exchange = async {
            stdin.write_all(&request_length.to_be_bytes()).await?;
            stdin.write_all(payload.as_slice()).await?;
            stdin.shutdown().await?;
            payload.zeroize();

            let mut length = [0_u8; 4];
            stdout.read_exact(&mut length).await?;
            let length = u32::from_be_bytes(length) as usize;
            if length > MAX_RESPONSE_BYTES {
                return Err(std::io::Error::other(
                    "renderer response exceeds its protocol limit",
                ));
            }
            let mut response = vec![0_u8; length];
            stdout.read_exact(&mut response).await?;
            let status = child.wait().await?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "renderer worker exited unsuccessfully: {status}"
                )));
            }
            Ok::<_, std::io::Error>(response)
        };
        let response = match timeout(self.isolation.wall_timeout, exchange).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(IsolatedRenderError::Protocol(bounded_error(&format!(
                    "renderer worker protocol failed: {error}"
                ))));
            }
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(IsolatedRenderError::Timeout);
            }
        };
        let response: WorkerResponse = serde_json::from_slice(&response).map_err(|error| {
            IsolatedRenderError::Protocol(format!("invalid renderer response: {error}"))
        })?;
        if response.protocol != PROTOCOL_VERSION {
            return Err(IsolatedRenderError::Protocol(
                "renderer protocol version mismatch".into(),
            ));
        }
        let page = response
            .result
            .map_err(|detail| IsolatedRenderError::Render(bounded_error(&detail)))?;
        page.validate_and_convert(width, &self.limits)
    }
}

#[cfg(target_os = "linux")]
fn prepare_worker_command(command: &mut Command) -> Result<(), String> {
    // Landlock does not revoke authority carried by a file descriptor opened
    // before sandboxing. CLOSE_RANGE_CLOEXEC preserves Rust's exec-error pipe
    // until a successful exec while guaranteeing that a dependency's
    // accidentally inheritable profile/database descriptor cannot cross the
    // worker exec boundary. Landlock ABI 6 kernels necessarily support this
    // older close_range operation; failure aborts the worker launch.
    //
    // SAFETY: the closure runs after fork and before exec and performs one
    // async-signal-safe syscall using only constant scalar arguments.
    unsafe {
        command.pre_exec(|| {
            let result = libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn prepare_worker_command(_command: &mut Command) -> Result<(), String> {
    Err("isolated terminal rendering is not implemented on this platform".into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IsolatedRenderError {
    InvalidInput(String),
    Unavailable(String),
    Protocol(String),
    Render(String),
    Timeout,
}

impl fmt::Display for IsolatedRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(detail) => write!(formatter, "invalid render request: {detail}"),
            Self::Unavailable(detail) => formatter.write_str(detail),
            Self::Protocol(detail) => write!(formatter, "renderer boundary failed: {detail}"),
            Self::Render(detail) => write!(formatter, "message rendering failed: {detail}"),
            Self::Timeout => formatter.write_str("message rendering exceeded its time limit"),
        }
    }
}

impl std::error::Error for IsolatedRenderError {}

#[derive(Serialize, Deserialize)]
struct WorkerRequest {
    protocol: u32,
    width: u16,
    limits: Limits,
    html_base64: String,
}

#[derive(Serialize, Deserialize)]
struct WorkerResponse {
    protocol: u32,
    result: Result<WirePage, String>,
}

#[derive(Serialize, Deserialize)]
struct WirePage {
    lines: Vec<WireLine>,
    links: Vec<WireLink>,
    images: Vec<WireImage>,
    warnings: Vec<String>,
    truncated: bool,
}

#[derive(Serialize, Deserialize)]
struct WireLine {
    alignment: Option<WireAlignment>,
    spans: Vec<WireSpan>,
}

#[derive(Serialize, Deserialize)]
struct WireSpan {
    text: String,
    style: WireStyle,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct WireStyle {
    foreground: Option<WireColor>,
    bold: bool,
    dim: bool,
    italic: bool,
    underlined: bool,
    crossed_out: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireColor {
    Blue,
    Cyan,
    DarkGray,
    Yellow,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireAlignment {
    Left,
    Center,
    Right,
}

#[derive(Serialize, Deserialize)]
struct WireLink {
    number: usize,
    destination: Option<String>,
    kind: WireLinkKind,
    blocked_scheme: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireLinkKind {
    Web,
    Mail,
    ContentId,
    Fragment,
    Relative,
    Blocked,
}

#[derive(Serialize, Deserialize)]
struct WireImage {
    number: usize,
    alt: Option<String>,
    source: WireImageSource,
    location: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireImageSource {
    Remote,
    ContentId,
    Embedded,
    Relative,
    Blocked,
    Missing,
}

impl WirePage {
    fn from_page(page: RenderedPage) -> Result<Self, String> {
        let lines = page
            .lines
            .into_iter()
            .map(WireLine::from_line)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            lines,
            links: page.links.into_iter().map(WireLink::from).collect(),
            images: page.images.into_iter().map(WireImage::from).collect(),
            warnings: page.warnings,
            truncated: page.truncated,
        })
    }

    fn validate_and_convert(
        self,
        width: u16,
        limits: &Limits,
    ) -> Result<RenderedPage, IsolatedRenderError> {
        if self.lines.len() > limits.max_output_lines
            || self.links.len() > limits.max_links
            || self.images.len() > limits.max_images
            || self.warnings.len() > MAX_WARNINGS
        {
            return Err(protocol_error(
                "renderer output exceeded a collection limit",
            ));
        }
        let mut total_spans = 0usize;
        let mut total_text_bytes = 0usize;
        let mut total_cells = 0usize;
        let mut lines = Vec::with_capacity(self.lines.len());
        for line in self.lines {
            total_spans = total_spans.saturating_add(line.spans.len());
            if total_spans > MAX_OUTPUT_SPANS {
                return Err(protocol_error("renderer output contains too many spans"));
            }
            let mut line_cells = 0usize;
            let mut spans = Vec::with_capacity(line.spans.len());
            for span in line.spans {
                validate_display_text(&span.text)?;
                total_text_bytes = total_text_bytes.saturating_add(span.text.len());
                if total_text_bytes > MAX_OUTPUT_TEXT_BYTES {
                    return Err(protocol_error("renderer output text is too large"));
                }
                let cells = span.text.width();
                line_cells = line_cells.saturating_add(cells);
                total_cells = total_cells.saturating_add(cells);
                spans.push(Span::styled(span.text, span.style.to_style()));
            }
            if line_cells > usize::from(width) || total_cells > limits.max_output_cells {
                return Err(protocol_error("renderer output exceeds its cell budget"));
            }
            let mut rendered = Line::from(spans);
            rendered.alignment = line.alignment.map(WireAlignment::into_alignment);
            lines.push(rendered);
        }
        let links = self
            .links
            .into_iter()
            .enumerate()
            .map(|(index, link)| link.validate_and_convert(index + 1))
            .collect::<Result<Vec<_>, _>>()?;
        let images = self
            .images
            .into_iter()
            .enumerate()
            .map(|(index, image)| image.validate_and_convert(index + 1))
            .collect::<Result<Vec<_>, _>>()?;
        for warning in &self.warnings {
            if warning.len() > MAX_REFERENCE_BYTES {
                return Err(protocol_error("renderer warning is too large"));
            }
            validate_display_text(warning)?;
        }
        Ok(RenderedPage {
            lines,
            links,
            images,
            warnings: self.warnings,
            truncated: self.truncated,
        })
    }
}

impl WireLine {
    fn from_line(line: Line<'static>) -> Result<Self, String> {
        if line.style != Style::default() {
            return Err("renderer produced an unsupported line-level style".into());
        }
        Ok(Self {
            alignment: line.alignment.map(WireAlignment::from_alignment),
            spans: line
                .spans
                .into_iter()
                .map(|span| {
                    Ok(WireSpan {
                        text: span.content.into_owned(),
                        style: WireStyle::from_style(span.style)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        })
    }
}

impl WireStyle {
    fn from_style(style: Style) -> Result<Self, String> {
        let allowed = Modifier::BOLD
            | Modifier::DIM
            | Modifier::ITALIC
            | Modifier::UNDERLINED
            | Modifier::CROSSED_OUT;
        if style.bg.is_some()
            || style.underline_color.is_some()
            || !style.sub_modifier.is_empty()
            || !(style.add_modifier & !allowed).is_empty()
        {
            return Err("renderer produced an unsupported terminal style".into());
        }
        let foreground = match style.fg {
            None => None,
            Some(Color::Blue) => Some(WireColor::Blue),
            Some(Color::Cyan) => Some(WireColor::Cyan),
            Some(Color::DarkGray) => Some(WireColor::DarkGray),
            Some(Color::Yellow) => Some(WireColor::Yellow),
            Some(_) => return Err("renderer produced a color outside its semantic palette".into()),
        };
        Ok(Self {
            foreground,
            bold: style.add_modifier.contains(Modifier::BOLD),
            dim: style.add_modifier.contains(Modifier::DIM),
            italic: style.add_modifier.contains(Modifier::ITALIC),
            underlined: style.add_modifier.contains(Modifier::UNDERLINED),
            crossed_out: style.add_modifier.contains(Modifier::CROSSED_OUT),
        })
    }

    fn to_style(self) -> Style {
        let mut style = Style::default();
        if let Some(color) = self.foreground {
            style = style.fg(color.into_color());
        }
        for (enabled, modifier) in [
            (self.bold, Modifier::BOLD),
            (self.dim, Modifier::DIM),
            (self.italic, Modifier::ITALIC),
            (self.underlined, Modifier::UNDERLINED),
            (self.crossed_out, Modifier::CROSSED_OUT),
        ] {
            if enabled {
                style = style.add_modifier(modifier);
            }
        }
        style
    }
}

impl WireColor {
    fn into_color(self) -> Color {
        match self {
            Self::Blue => Color::Blue,
            Self::Cyan => Color::Cyan,
            Self::DarkGray => Color::DarkGray,
            Self::Yellow => Color::Yellow,
        }
    }
}

impl WireAlignment {
    fn from_alignment(alignment: Alignment) -> Self {
        match alignment {
            Alignment::Left => Self::Left,
            Alignment::Center => Self::Center,
            Alignment::Right => Self::Right,
        }
    }

    fn into_alignment(self) -> Alignment {
        match self {
            Self::Left => Alignment::Left,
            Self::Center => Alignment::Center,
            Self::Right => Alignment::Right,
        }
    }
}

impl From<LinkReference> for WireLink {
    fn from(link: LinkReference) -> Self {
        Self {
            number: link.number,
            destination: link.destination,
            kind: match link.kind {
                LinkKind::Web => WireLinkKind::Web,
                LinkKind::Mail => WireLinkKind::Mail,
                LinkKind::ContentId => WireLinkKind::ContentId,
                LinkKind::Fragment => WireLinkKind::Fragment,
                LinkKind::Relative => WireLinkKind::Relative,
                LinkKind::Blocked => WireLinkKind::Blocked,
            },
            blocked_scheme: link.blocked_scheme,
        }
    }
}

impl WireLink {
    fn validate_and_convert(
        self,
        expected_number: usize,
    ) -> Result<LinkReference, IsolatedRenderError> {
        if self.number != expected_number {
            return Err(protocol_error("renderer link numbering is invalid"));
        }
        validate_reference(self.destination.as_deref())?;
        validate_reference(self.blocked_scheme.as_deref())?;
        Ok(LinkReference {
            number: self.number,
            destination: self.destination,
            kind: match self.kind {
                WireLinkKind::Web => LinkKind::Web,
                WireLinkKind::Mail => LinkKind::Mail,
                WireLinkKind::ContentId => LinkKind::ContentId,
                WireLinkKind::Fragment => LinkKind::Fragment,
                WireLinkKind::Relative => LinkKind::Relative,
                WireLinkKind::Blocked => LinkKind::Blocked,
            },
            blocked_scheme: self.blocked_scheme,
        })
    }
}

impl From<ImageReference> for WireImage {
    fn from(image: ImageReference) -> Self {
        Self {
            number: image.number,
            alt: image.alt,
            source: match image.source {
                ImageSource::Remote => WireImageSource::Remote,
                ImageSource::ContentId => WireImageSource::ContentId,
                ImageSource::Embedded => WireImageSource::Embedded,
                ImageSource::Relative => WireImageSource::Relative,
                ImageSource::Blocked => WireImageSource::Blocked,
                ImageSource::Missing => WireImageSource::Missing,
            },
            location: image.location,
        }
    }
}

impl WireImage {
    fn validate_and_convert(
        self,
        expected_number: usize,
    ) -> Result<ImageReference, IsolatedRenderError> {
        if self.number != expected_number {
            return Err(protocol_error("renderer image numbering is invalid"));
        }
        validate_reference(self.alt.as_deref())?;
        validate_reference(self.location.as_deref())?;
        Ok(ImageReference {
            number: self.number,
            alt: self.alt,
            source: match self.source {
                WireImageSource::Remote => ImageSource::Remote,
                WireImageSource::ContentId => ImageSource::ContentId,
                WireImageSource::Embedded => ImageSource::Embedded,
                WireImageSource::Relative => ImageSource::Relative,
                WireImageSource::Blocked => ImageSource::Blocked,
                WireImageSource::Missing => ImageSource::Missing,
            },
            location: self.location,
        })
    }
}

fn validate_reference(value: Option<&str>) -> Result<(), IsolatedRenderError> {
    if let Some(value) = value {
        if value.len() > MAX_REFERENCE_BYTES {
            return Err(protocol_error("renderer reference is too large"));
        }
        validate_display_text(value)?;
    }
    Ok(())
}

fn validate_display_text(value: &str) -> Result<(), IsolatedRenderError> {
    if value.chars().any(is_forbidden_display_character) {
        return Err(protocol_error(
            "renderer output contains a terminal control or bidi control",
        ));
    }
    Ok(())
}

fn protocol_error(detail: impl Into<String>) -> IsolatedRenderError {
    IsolatedRenderError::Protocol(detail.into())
}

fn validate_limits(limits: &Limits) -> Result<(), String> {
    let maximum = Limits::default();
    let valid = limits.max_input_bytes <= maximum.max_input_bytes
        && limits.max_markup_tokens <= maximum.max_markup_tokens
        && limits.max_nodes <= maximum.max_nodes
        && limits.max_depth <= maximum.max_depth
        && limits.max_attributes_per_element <= maximum.max_attributes_per_element
        && limits.max_attribute_bytes <= maximum.max_attribute_bytes
        && limits.max_text_bytes <= maximum.max_text_bytes
        && limits.max_links <= maximum.max_links
        && limits.max_images <= maximum.max_images
        && limits.max_table_cells <= maximum.max_table_cells
        && limits.max_output_lines <= maximum.max_output_lines
        && limits.max_output_cells <= maximum.max_output_cells;
    if !valid {
        return Err("isolated renderer limits exceed the hard worker profile".into());
    }
    Ok(())
}

fn bounded_error(detail: &str) -> String {
    detail
        .chars()
        .take(MAX_ERROR_CHARS)
        .map(|character| {
            if is_forbidden_display_character(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn is_forbidden_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
        )
}

pub(crate) fn run_worker_process() -> Result<(), String> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next();
    if mode.as_deref() == Some(std::ffi::OsStr::new("--sandbox-self-test")) {
        return sandbox_self_test();
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new("--seccomp-self-test")) {
        return seccomp_self_test();
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new("--seccomp-x32-self-test")) {
        return seccomp_x32_self_test();
    }
    if mode.as_deref() != Some(std::ffi::OsStr::new("--worker-v1")) {
        return Err("this executable is an internal isolated renderer".into());
    }
    install_worker_sandbox()?;

    let mut length = [0_u8; 4];
    std::io::stdin()
        .read_exact(&mut length)
        .map_err(|error| format!("reading request length: {error}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_REQUEST_BYTES {
        return Err("renderer request exceeds its protocol limit".into());
    }
    let mut payload = vec![0_u8; length];
    std::io::stdin()
        .read_exact(&mut payload)
        .map_err(|error| format!("reading request: {error}"))?;
    let request: WorkerRequest =
        serde_json::from_slice(&payload).map_err(|error| format!("parsing request: {error}"))?;
    payload.zeroize();
    if request.protocol != PROTOCOL_VERSION {
        return Err("renderer protocol version mismatch".into());
    }
    validate_limits(&request.limits)?;
    if request.width == 0 {
        return Err("renderer request has an invalid width".into());
    }
    let html = Zeroizing::new(
        BASE64
            .decode(request.html_base64)
            .map_err(|error| format!("decoding renderer input: {error}"))?,
    );
    if html.len() > request.limits.max_input_bytes {
        return Err("decoded renderer input exceeds its limit".into());
    }
    let result = HtmlRenderer::new(request.limits)
        .render(&html, request.width, &RenderOptions::default())
        .map_err(|error| bounded_error(&error.to_string()))
        .and_then(WirePage::from_page);
    let response = WorkerResponse {
        protocol: PROTOCOL_VERSION,
        result,
    };
    let bytes = serde_json::to_vec(&response)
        .map_err(|error| format!("serializing renderer response: {error}"))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err("renderer response exceeds its protocol limit".into());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "renderer response length overflow")?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&length.to_be_bytes())
        .and_then(|()| stdout.write_all(&bytes))
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("writing renderer response: {error}"))
}

#[cfg(target_os = "linux")]
fn install_worker_sandbox() -> Result<(), String> {
    set_worker_limits()?;
    enter_landlock()?;
    enter_seccomp()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_worker_sandbox() -> Result<(), String> {
    Err("isolated terminal rendering is not implemented on this platform".into())
}

#[cfg(target_os = "linux")]
fn set_worker_limits() -> Result<(), String> {
    fn set(resource: libc::__rlimit_resource_t, current: u64, maximum: u64) -> Result<(), String> {
        let value = libc::rlimit {
            rlim_cur: current,
            rlim_max: maximum,
        };
        // SAFETY: setrlimit only reads the initialized rlimit structure.
        if unsafe { libc::setrlimit(resource, &value) } != 0 {
            return Err(format!(
                "could not set renderer resource limit: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    set(libc::RLIMIT_AS, 512 * 1024 * 1024, 512 * 1024 * 1024)?;
    set(libc::RLIMIT_CPU, 2, 3)?;
    set(libc::RLIMIT_FSIZE, 0, 0)?;
    set(libc::RLIMIT_CORE, 0, 0)?;
    set(libc::RLIMIT_NOFILE, 16, 16)?;
    // SAFETY: PR_SET_DUMPABLE takes an integer flag and no pointer.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!(
            "could not disable renderer ptrace access: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_landlock() -> Result<(), String> {
    use landlock::{Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetStatus, Scope, ABI};
    let abi = ABI::V6;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(abi)))
        .and_then(|ruleset| ruleset.scope(Scope::AbstractUnixSocket))
        .and_then(|ruleset| ruleset.scope(Scope::Signal))
        .map_err(|error| format!("could not configure renderer Landlock: {error}"))?
        .create()
        .map_err(|error| format!("could not create renderer Landlock ruleset: {error}"))?
        .restrict_self()
        .map_err(|error| format!("could not enter renderer Landlock sandbox: {error}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(format!(
            "renderer Landlock sandbox was not fully enforced: {status:?}"
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn enter_seccomp() -> Result<(), String> {
    // SAFETY: this initialized classic-BPF program is consumed synchronously
    // by prctl. The filter is installed only after Landlock set no_new_privs.
    unsafe {
        const LD: u16 = 0x20;
        const JEQ: u16 = 0x15;
        const JSET: u16 = 0x45;
        const RET: u16 = 0x06;
        const ALLOW: u32 = 0x7fff0000;
        const KILL: u32 = 0x80000000;
        const ERRNO: u32 = 0x00050000;
        let stmt = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
        let mut code = vec![
            stmt(LD, 4),
            jump(JEQ, 0xc000003e, 1, 0),
            stmt(RET, KILL),
            stmt(LD, 0),
            jump(JSET, X32_SYSCALL_BIT, 0, 1),
            stmt(RET, KILL),
        ];
        for syscall in [
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_kcmp,
            libc::SYS_bpf,
            libc::SYS_userfaultfd,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_openat2,
            libc::SYS_creat,
            libc::SYS_name_to_handle_at,
            libc::SYS_open_by_handle_at,
            libc::SYS_chdir,
            libc::SYS_fchdir,
            libc::SYS_chmod,
            libc::SYS_fchmod,
            libc::SYS_fchmodat,
            libc::SYS_fchmodat2,
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_lchown,
            libc::SYS_fchownat,
            libc::SYS_setxattr,
            libc::SYS_lsetxattr,
            libc::SYS_fsetxattr,
            libc::SYS_removexattr,
            libc::SYS_lremovexattr,
            libc::SYS_fremovexattr,
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
            libc::SYS_pidfd_send_signal,
            libc::SYS_process_madvise,
            libc::SYS_process_mrelease,
            libc::SYS_shmget,
            libc::SYS_shmat,
            libc::SYS_shmdt,
            libc::SYS_shmctl,
            libc::SYS_msgget,
            libc::SYS_msgsnd,
            libc::SYS_msgrcv,
            libc::SYS_msgctl,
            libc::SYS_semget,
            libc::SYS_semop,
            libc::SYS_semctl,
            libc::SYS_semtimedop,
            libc::SYS_pipe,
            libc::SYS_pipe2,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_move_mount,
            libc::SYS_open_tree,
            libc::SYS_mount_setattr,
            libc::SYS_fanotify_init,
            libc::SYS_fanotify_mark,
            libc::SYS_inotify_init,
            libc::SYS_inotify_init1,
            libc::SYS_inotify_add_watch,
            libc::SYS_inotify_rm_watch,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_prctl,
            libc::SYS_seccomp,
            libc::SYS_setrlimit,
            libc::SYS_prlimit64,
        ] {
            code.push(jump(JEQ, syscall as u32, 0, 1));
            code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        }
        code.push(stmt(RET, ALLOW));
        let program = libc::sock_fprog {
            len: u16::try_from(code.len()).map_err(|_| "renderer seccomp program is too large")?,
            filter: code.as_mut_ptr(),
        };
        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
            return Err(format!(
                "could not enter renderer seccomp sandbox: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn enter_seccomp() -> Result<(), String> {
    Err("isolated terminal renderer seccomp is not implemented for this architecture".into())
}

#[cfg(target_os = "linux")]
fn sandbox_self_test() -> Result<(), String> {
    install_worker_sandbox()?;
    report_sandbox_evidence()
}

#[cfg(not(target_os = "linux"))]
fn sandbox_self_test() -> Result<(), String> {
    Err("renderer sandbox self-test is unavailable on this platform".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn seccomp_self_test() -> Result<(), String> {
    set_worker_limits()?;
    enable_no_new_privs_for_self_test()?;
    enter_seccomp()?;
    report_sandbox_evidence()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn seccomp_self_test() -> Result<(), String> {
    Err("renderer seccomp self-test is unavailable on this platform".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn seccomp_x32_self_test() -> Result<(), String> {
    enable_no_new_privs_for_self_test()?;
    enter_seccomp()?;
    // The filter must kill this disposable process before the kernel can
    // interpret the x32 syscall number, even when the x32 ABI is disabled.
    // SAFETY: this deliberately issues a no-argument getpid-shaped syscall in
    // a child used only by the regression test.
    unsafe {
        libc::syscall((libc::SYS_getpid as u32 | X32_SYSCALL_BIT) as libc::c_long);
    }
    Err("renderer seccomp accepted an x32-numbered syscall".into())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn seccomp_x32_self_test() -> Result<(), String> {
    Err("renderer x32 seccomp self-test is unavailable on this platform".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn enable_no_new_privs_for_self_test() -> Result<(), String> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes an integer flag and no pointer. The
    // production path gets this property from Landlock; test paths set it
    // directly so seccomp can be exercised on Landlock-less CI.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "could not set no_new_privs for seccomp self-test: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn report_sandbox_evidence() -> Result<(), String> {
    #[derive(Serialize)]
    struct Evidence {
        filesystem_denied: bool,
        network_denied: bool,
        execution_denied: bool,
        sysv_ipc_denied: bool,
        pidfd_access_denied: bool,
    }
    // Invalid arguments distinguish a filter EPERM from the kernel's ordinary
    // EINVAL/EBADF without creating an IPC object or touching another process.
    // SAFETY: both probes pass scalar invalid arguments to disposable-test
    // syscalls and inspect only their return value and errno.
    let (sysv_ipc_denied, pidfd_access_denied) = unsafe {
        let result = libc::syscall(libc::SYS_shmget, libc::IPC_PRIVATE, 0_usize, 0);
        let sysv_ipc_denied =
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        let result = libc::syscall(libc::SYS_pidfd_getfd, -1_i32, -1_i32, 0_u32);
        let pidfd_access_denied =
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        (sysv_ipc_denied, pidfd_access_denied)
    };
    let evidence = Evidence {
        filesystem_denied: std::fs::read("/etc/passwd").is_err(),
        network_denied: std::net::UdpSocket::bind("127.0.0.1:0").is_err(),
        execution_denied: std::process::Command::new("/bin/true").status().is_err(),
        sysv_ipc_denied,
        pidfd_access_denied,
    };
    if !evidence.filesystem_denied
        || !evidence.network_denied
        || !evidence.execution_denied
        || !evidence.sysv_ipc_denied
        || !evidence.pidfd_access_denied
    {
        return Err(format!(
            "renderer sandbox self-test failed: {}",
            serde_json::to_string(&evidence).map_err(|error| error.to_string())?
        ));
    }
    println!(
        "{}",
        serde_json::to_string(&evidence).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_page_round_trip_rejects_terminal_controls() {
        let page = HtmlRenderer::default()
            .render(
                b"<h1>Hello</h1><p><a href='https://example.com'>world</a></p>",
                40,
                &RenderOptions::default(),
            )
            .unwrap();
        let wire = WirePage::from_page(page).unwrap();
        let page = wire.validate_and_convert(40, &Limits::default()).unwrap();
        assert!(page.lines.iter().all(|line| line.width() <= 40));

        let wire = WirePage {
            lines: vec![WireLine {
                alignment: None,
                spans: vec![WireSpan {
                    text: "unsafe\u{1b}[2J".into(),
                    style: WireStyle {
                        foreground: None,
                        bold: false,
                        dim: false,
                        italic: false,
                        underlined: false,
                        crossed_out: false,
                    },
                }],
            }],
            links: Vec::new(),
            images: Vec::new(),
            warnings: Vec::new(),
            truncated: false,
        };
        assert!(wire.validate_and_convert(40, &Limits::default()).is_err());
    }
}
