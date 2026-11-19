use std::collections::HashMap;

use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use url::Url;

use crate::parser::{Element, HtmlDocument, Node, ParseWarning, RenderError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkKind {
    Web,
    Mail,
    ContentId,
    Fragment,
    Relative,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkReference {
    pub number: usize,
    pub destination: Option<String>,
    pub kind: LinkKind,
    pub blocked_scheme: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    Remote,
    ContentId,
    Embedded,
    Relative,
    Blocked,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub number: usize,
    pub alt: Option<String>,
    pub source: ImageSource,
    /// A bounded, display-safe reference. No resource is fetched by this crate.
    pub location: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub body: Style,
    pub heading: Style,
    pub link: Style,
    pub code: Style,
    pub quote_prefix: Style,
    pub image: Style,
    pub warning: Style,
    pub table_border: Style,
    pub link_target: Style,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            body: Style::default(),
            heading: Style::default().add_modifier(Modifier::BOLD),
            link: Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::UNDERLINED),
            code: Style::default().fg(Color::Cyan),
            quote_prefix: Style::default().fg(Color::DarkGray),
            image: Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
            warning: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            table_border: Style::default().fg(Color::DarkGray),
            link_target: Style::default().fg(Color::DarkGray),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RenderOptions {
    pub theme: Theme,
    /// Append a numbered destination list. Enabled by default because hiding a
    /// link destination is especially dangerous in a mail client.
    pub show_link_targets: bool,
    /// Include a bounded image source in image metadata. It is never fetched.
    pub retain_image_locations: bool,
    pub unicode_borders: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            theme: Theme::default(),
            show_link_targets: true,
            retain_image_locations: true,
            unicode_borders: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RenderedPage {
    pub lines: Vec<Line<'static>>,
    pub links: Vec<LinkReference>,
    pub images: Vec<ImageReference>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

impl RenderedPage {
    pub fn widget(&self) -> HtmlView<'_> {
        HtmlView {
            page: self,
            scroll: 0,
        }
    }
}

/// A lightweight Ratatui widget over an already rendered page.
#[derive(Debug, Clone, Copy)]
pub struct HtmlView<'a> {
    page: &'a RenderedPage,
    scroll: u16,
}

impl<'a> HtmlView<'a> {
    pub fn scroll(mut self, rows: u16) -> Self {
        self.scroll = rows;
        self
    }
}

impl Widget for HtmlView<'_> {
    fn render(self, area: Rect, buffer: &mut Buffer) {
        let start = usize::from(self.scroll).min(self.page.lines.len());
        let end = start
            .saturating_add(usize::from(area.height))
            .min(self.page.lines.len());
        Paragraph::new(self.page.lines[start..end].to_vec()).render(area, buffer);
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct TextStyle {
    bold: bool,
    italic: bool,
    underline: bool,
    crossed: bool,
    code: bool,
    dim: bool,
    heading: bool,
    link: bool,
    image: bool,
    warning: bool,
    border: bool,
    target: bool,
}

impl TextStyle {
    fn ratatui(self, theme: &Theme) -> Style {
        let mut style = theme.body;
        if self.heading {
            style = style.patch(theme.heading);
        }
        if self.code {
            style = style.patch(theme.code);
        }
        if self.link {
            style = style.patch(theme.link);
        }
        if self.image {
            style = style.patch(theme.image);
        }
        if self.warning {
            style = style.patch(theme.warning);
        }
        if self.border {
            style = style.patch(theme.table_border);
        }
        if self.target {
            style = style.patch(theme.link_target);
        }
        if self.bold {
            style = style.add_modifier(Modifier::BOLD);
        }
        if self.italic {
            style = style.add_modifier(Modifier::ITALIC);
        }
        if self.underline {
            style = style.add_modifier(Modifier::UNDERLINED);
        }
        if self.crossed {
            style = style.add_modifier(Modifier::CROSSED_OUT);
        }
        if self.dim {
            style = style.add_modifier(Modifier::DIM);
        }
        style
    }
}

#[derive(Debug, Clone, Copy, Default)]
enum Transform {
    #[default]
    None,
    Uppercase,
    Lowercase,
    Capitalize,
}

#[derive(Debug, Clone)]
struct Context {
    style: TextStyle,
    prefix: String,
    alignment: Alignment,
    preserve: bool,
    transform: Transform,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            style: TextStyle::default(),
            prefix: String::new(),
            alignment: Alignment::Left,
            preserve: false,
            transform: Transform::None,
        }
    }
}

#[derive(Debug, Clone)]
struct Piece {
    text: String,
    style: TextStyle,
}

#[derive(Debug, Clone)]
struct Flow {
    pieces: Vec<Piece>,
    first_prefix: String,
    rest_prefix: String,
    alignment: Alignment,
    preserve: bool,
    blank_after: bool,
}

impl Flow {
    fn is_empty(&self) -> bool {
        self.pieces.iter().all(|piece| piece.text.is_empty())
    }
}

struct Composer<'a> {
    document: &'a HtmlDocument,
    options: &'a RenderOptions,
    width: usize,
    flows: Vec<Flow>,
    current: Option<Flow>,
    pending_space: bool,
    links: Vec<LinkReference>,
    link_numbers: HashMap<(LinkKind, Option<String>, Option<String>), usize>,
    images: Vec<ImageReference>,
    warnings: Vec<String>,
    table_cells: usize,
}

impl<'a> Composer<'a> {
    fn new(document: &'a HtmlDocument, width: usize, options: &'a RenderOptions) -> Self {
        let warnings = document
            .warnings()
            .iter()
            .map(|warning| match warning {
                ParseWarning::ActiveContentRemoved => "Active content was removed.".to_owned(),
                ParseWarning::StylesheetIgnored => "Author stylesheet was ignored.".to_owned(),
                ParseWarning::UnsupportedElement(tag) => {
                    format!("Unsupported <{tag}> element was reduced to its text.")
                }
            })
            .collect();
        Self {
            document,
            options,
            width,
            flows: Vec::new(),
            current: None,
            pending_space: false,
            links: Vec::new(),
            link_numbers: HashMap::new(),
            images: Vec::new(),
            warnings,
            table_cells: 0,
        }
    }

    fn begin(&mut self, context: &Context, blank_after: bool) {
        self.finish(false);
        self.current = Some(Flow {
            pieces: Vec::new(),
            first_prefix: context.prefix.clone(),
            rest_prefix: context.prefix.clone(),
            alignment: context.alignment,
            preserve: context.preserve,
            blank_after,
        });
        self.pending_space = false;
    }

    fn begin_prefixed(
        &mut self,
        context: &Context,
        first_prefix: String,
        rest_prefix: String,
        blank_after: bool,
    ) {
        self.finish(false);
        self.current = Some(Flow {
            pieces: Vec::new(),
            first_prefix,
            rest_prefix,
            alignment: context.alignment,
            preserve: context.preserve,
            blank_after,
        });
        self.pending_space = false;
    }

    fn ensure(&mut self, context: &Context) {
        if self.current.is_none() {
            self.begin(context, false);
        }
    }

    fn finish(&mut self, force_blank_after: bool) {
        if let Some(mut flow) = self.current.take() {
            flow.blank_after |= force_blank_after;
            if !flow.is_empty() {
                self.flows.push(flow);
            }
        }
        self.pending_space = false;
    }

    fn append(&mut self, raw: &str, context: &Context) {
        self.ensure(context);
        let text = sanitize_text(raw, context.transform);
        if context.preserve {
            self.push_piece(expand_tabs(&text), context.style);
            return;
        }

        let mut output = String::new();
        for character in text.chars() {
            if character.is_whitespace() {
                self.pending_space = true;
            } else {
                if self.pending_space && (!output.is_empty() || self.has_content()) {
                    output.push(' ');
                }
                self.pending_space = false;
                output.push(character);
            }
        }
        self.push_piece(output, context.style);
    }

    fn append_literal(&mut self, text: impl Into<String>, style: TextStyle, context: &Context) {
        self.ensure(context);
        self.pending_space = false;
        self.push_piece(text.into(), style);
    }

    fn push_piece(&mut self, text: String, style: TextStyle) {
        if text.is_empty() {
            return;
        }
        let Some(flow) = self.current.as_mut() else {
            debug_assert!(false, "piece appended without an active flow");
            return;
        };
        if let Some(last) = flow.pieces.last_mut() {
            if same_style(last.style, style) {
                last.text.push_str(&text);
                return;
            }
        }
        flow.pieces.push(Piece { text, style });
    }

    fn has_content(&self) -> bool {
        self.current
            .as_ref()
            .is_some_and(|flow| flow.pieces.iter().any(|piece| !piece.text.is_empty()))
    }

    fn hard_break(&mut self, context: &Context) {
        self.ensure(context);
        self.pending_space = false;
        self.push_piece("\n".to_owned(), context.style);
    }

    fn raw_line(&mut self, text: String, style: TextStyle, context: &Context) {
        self.finish(false);
        let mut raw_context = context.clone();
        raw_context.preserve = true;
        raw_context.alignment = Alignment::Left;
        self.begin(&raw_context, false);
        self.append_literal(text, style, &raw_context);
        self.finish(false);
    }

    fn link(&mut self, href: &str) -> Option<usize> {
        if self.links.len() >= self.document.limits.max_links {
            if !self
                .warnings
                .iter()
                .any(|warning| warning == "Additional links were omitted.")
            {
                self.warnings
                    .push("Additional links were omitted.".to_owned());
            }
            return None;
        }
        let classified = classify_link(href);
        let key = (
            classified.kind.clone(),
            classified.destination.clone(),
            classified.blocked_scheme.clone(),
        );
        if let Some(number) = self.link_numbers.get(&key) {
            return Some(*number);
        }
        let number = self.links.len() + 1;
        self.links.push(LinkReference {
            number,
            destination: classified.destination.clone(),
            kind: classified.kind.clone(),
            blocked_scheme: classified.blocked_scheme,
        });
        self.link_numbers.insert(key, number);
        Some(number)
    }

    fn image(&mut self, element: &Element, context: &Context) {
        let label = self.register_image(element);
        self.append_literal(
            label,
            TextStyle {
                image: true,
                ..context.style
            },
            context,
        );
    }

    fn register_image(&mut self, element: &Element) -> String {
        if self.images.len() >= self.document.limits.max_images {
            if !self
                .warnings
                .iter()
                .any(|warning| warning == "Additional images were omitted.")
            {
                self.warnings
                    .push("Additional images were omitted.".to_owned());
            }
            return "[Additional images omitted]".to_owned();
        }
        let alt = element
            .attr("alt")
            .or_else(|| element.attr("aria-label"))
            .map(|value| bounded_display(value, 512))
            .filter(|value| !value.trim().is_empty());
        let (source, location) = classify_image(element.attr("src"));
        let number = self.images.len() + 1;
        self.images.push(ImageReference {
            number,
            alt: alt.clone(),
            source,
            location: self
                .options
                .retain_image_locations
                .then_some(location)
                .flatten(),
        });
        let label = alt
            .as_deref()
            .map(|alt| format!("[Image: {alt}]"))
            .unwrap_or_else(|| "[Image omitted]".to_owned());
        label
    }
}

fn same_style(left: TextStyle, right: TextStyle) -> bool {
    left.bold == right.bold
        && left.italic == right.italic
        && left.underline == right.underline
        && left.crossed == right.crossed
        && left.code == right.code
        && left.dim == right.dim
        && left.heading == right.heading
        && left.link == right.link
        && left.image == right.image
        && left.warning == right.warning
        && left.border == right.border
        && left.target == right.target
}

struct ClassifiedLink {
    destination: Option<String>,
    kind: LinkKind,
    blocked_scheme: Option<String>,
}

fn classify_link(raw: &str) -> ClassifiedLink {
    let display = bounded_display(raw.trim(), 8_192);
    if display.is_empty() {
        return ClassifiedLink {
            destination: None,
            kind: LinkKind::Blocked,
            blocked_scheme: None,
        };
    }
    if display.starts_with('#') {
        return ClassifiedLink {
            destination: Some(display),
            kind: LinkKind::Fragment,
            blocked_scheme: None,
        };
    }
    match Url::parse(&display) {
        Ok(url) => {
            let scheme = url.scheme().to_ascii_lowercase();
            let kind = match scheme.as_str() {
                "http" | "https" => LinkKind::Web,
                "mailto" => LinkKind::Mail,
                "cid" => LinkKind::ContentId,
                _ => LinkKind::Blocked,
            };
            if kind == LinkKind::Blocked {
                ClassifiedLink {
                    destination: None,
                    kind,
                    blocked_scheme: Some(bounded_display(&scheme, 32)),
                }
            } else {
                ClassifiedLink {
                    destination: Some(bounded_display(url.as_str(), 8_192)),
                    kind,
                    blocked_scheme: None,
                }
            }
        }
        Err(url::ParseError::RelativeUrlWithoutBase) => ClassifiedLink {
            destination: Some(display),
            kind: LinkKind::Relative,
            blocked_scheme: None,
        },
        Err(_) => ClassifiedLink {
            destination: None,
            kind: LinkKind::Blocked,
            blocked_scheme: None,
        },
    }
}

fn classify_image(raw: Option<&str>) -> (ImageSource, Option<String>) {
    let Some(raw) = raw else {
        return (ImageSource::Missing, None);
    };
    let display = bounded_display(raw.trim(), 8_192);
    if display.is_empty() {
        return (ImageSource::Missing, None);
    }
    if display.to_ascii_lowercase().starts_with("cid:") {
        return (ImageSource::ContentId, Some(display));
    }
    if display.to_ascii_lowercase().starts_with("data:") {
        return (ImageSource::Embedded, None);
    }
    match Url::parse(&display) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => (
            ImageSource::Remote,
            Some(bounded_display(url.as_str(), 8_192)),
        ),
        Ok(_) => (ImageSource::Blocked, None),
        Err(url::ParseError::RelativeUrlWithoutBase) => (ImageSource::Relative, Some(display)),
        Err(_) => (ImageSource::Blocked, None),
    }
}

pub(crate) fn render_document(
    document: &HtmlDocument,
    width: u16,
    options: &RenderOptions,
) -> Result<RenderedPage, RenderError> {
    if width == 0 {
        return Err(RenderError::InvalidWidth);
    }
    let mut composer = Composer::new(document, usize::from(width), options);
    let context = Context::default();
    render_nodes(&document.children, &context, &mut composer);
    composer.finish(false);
    if options.show_link_targets && !composer.links.is_empty() {
        append_link_targets(&mut composer, &context);
    }

    let mut truncated = false;
    let mut lines = Vec::new();
    let mut cells = 0usize;
    for (index, flow) in composer.flows.iter().enumerate() {
        for line in wrap_flow(flow, composer.width, &options.theme) {
            let line_cells = line.width();
            if lines.len() >= document.limits.max_output_lines
                || cells.saturating_add(line_cells) > document.limits.max_output_cells
            {
                truncated = true;
                break;
            }
            cells += line_cells;
            lines.push(line);
        }
        if truncated {
            break;
        }
        if flow.blank_after && index + 1 < composer.flows.len() {
            if lines.len() >= document.limits.max_output_lines {
                truncated = true;
                break;
            }
            lines.push(Line::default());
        }
    }
    if truncated {
        let warning_text = clip_to_width(
            "[Message rendering truncated at the configured resource limit]",
            usize::from(width),
        );
        let warning = Line::from(Span::styled(warning_text, options.theme.warning));
        if lines.len() == document.limits.max_output_lines {
            if let Some(last) = lines.last_mut() {
                *last = warning;
            }
        } else {
            lines.push(warning);
        }
        composer
            .warnings
            .push("Message rendering was truncated at a resource limit.".to_owned());
    }

    Ok(RenderedPage {
        lines,
        links: composer.links,
        images: composer.images,
        warnings: composer.warnings,
        truncated,
    })
}

fn render_nodes(nodes: &[Node], context: &Context, composer: &mut Composer<'_>) {
    for node in nodes {
        render_node(node, context, composer);
    }
}

fn render_node(node: &Node, context: &Context, composer: &mut Composer<'_>) {
    match node {
        Node::Text(text) => composer.append(text, context),
        Node::Element(element) => render_element(element, context, composer),
    }
}

fn render_element(element: &Element, context: &Context, composer: &mut Composer<'_>) {
    if is_hidden(element) {
        return;
    }

    match element.tag.as_str() {
        "#document" | "html" | "body" | "main" => {
            render_nodes(&element.children, context, composer)
        }
        "head" | "title" => {}
        "p" | "div" | "section" | "article" | "header" | "footer" | "aside" | "nav" | "figure"
        | "figcaption" | "address" | "center" => {
            let child_context = styled_context(element, context);
            composer.begin(&child_context, true);
            render_nodes(&element.children, &child_context, composer);
            composer.finish(true);
        }
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            let mut child_context = styled_context(element, context);
            child_context.style.heading = true;
            child_context.style.bold = true;
            if matches!(element.tag.as_str(), "h1" | "h2") {
                child_context.style.underline = true;
            }
            composer.begin(&child_context, true);
            render_nodes(&element.children, &child_context, composer);
            composer.finish(true);
        }
        "blockquote" => {
            composer.finish(false);
            let mut child_context = styled_context(element, context);
            child_context.prefix.push_str("│ ");
            child_context.style.italic = true;
            render_nodes(&element.children, &child_context, composer);
            composer.finish(true);
        }
        "pre" => {
            let mut child_context = styled_context(element, context);
            child_context.preserve = true;
            child_context.style.code = true;
            composer.begin(&child_context, true);
            render_nodes(&element.children, &child_context, composer);
            composer.finish(true);
        }
        "ul" => render_list(element, false, context, composer, 0),
        "ol" => render_list(element, true, context, composer, 0),
        "dl" => render_description_list(element, context, composer),
        "table" => render_table(element, context, composer),
        "hr" => {
            composer.finish(false);
            let character = if composer.options.unicode_borders {
                '─'
            } else {
                '-'
            };
            composer.raw_line(
                character.to_string().repeat(composer.width),
                TextStyle {
                    border: true,
                    ..context.style
                },
                context,
            );
        }
        "br" | "wbr" => composer.hard_break(context),
        "img" => composer.image(element, context),
        "a" => render_link(element, context, composer),
        "form" => {
            composer.finish(false);
            let mut warning_context = context.clone();
            warning_context.style.warning = true;
            composer.begin(&warning_context, true);
            composer.append_literal(
                "[Interactive form omitted]",
                warning_context.style,
                &warning_context,
            );
            composer.finish(true);
        }
        "input" | "button" | "select" | "textarea" | "option" | "fieldset" | "legend"
        | "datalist" | "output" => {}
        "b" | "strong" => {
            let mut child_context = styled_context(element, context);
            child_context.style.bold = true;
            render_nodes(&element.children, &child_context, composer);
        }
        "i" | "em" | "cite" | "dfn" | "var" => {
            let mut child_context = styled_context(element, context);
            child_context.style.italic = true;
            render_nodes(&element.children, &child_context, composer);
        }
        "u" | "ins" => {
            let mut child_context = styled_context(element, context);
            child_context.style.underline = true;
            render_nodes(&element.children, &child_context, composer);
        }
        "s" | "strike" | "del" => {
            let mut child_context = styled_context(element, context);
            child_context.style.crossed = true;
            render_nodes(&element.children, &child_context, composer);
        }
        "code" | "kbd" | "samp" | "tt" => {
            let mut child_context = styled_context(element, context);
            child_context.style.code = true;
            render_nodes(&element.children, &child_context, composer);
        }
        "small" | "sub" | "sup" => {
            let mut child_context = styled_context(element, context);
            child_context.style.dim = true;
            render_nodes(&element.children, &child_context, composer);
        }
        "q" => {
            let child_context = styled_context(element, context);
            composer.append_literal("“", child_context.style, &child_context);
            render_nodes(&element.children, &child_context, composer);
            composer.append_literal("”", child_context.style, &child_context);
        }
        "li" | "dt" | "dd" | "tr" | "td" | "th" | "thead" | "tbody" | "tfoot" | "caption"
        | "colgroup" | "col" => render_nodes(&element.children, context, composer),
        _ => {
            let child_context = styled_context(element, context);
            render_nodes(&element.children, &child_context, composer);
        }
    }
}

fn render_link(element: &Element, context: &Context, composer: &mut Composer<'_>) {
    let href = element.attr("href").unwrap_or_default();
    let number = composer.link(href);
    let mut child_context = styled_context(element, context);
    child_context.style.link = true;
    if has_renderable_content(&element.children) {
        render_nodes(&element.children, &child_context, composer);
    } else if let Some(label) = element.attr("aria-label") {
        composer.append(label, &child_context);
    }
    if let Some(number) = number {
        composer.append_literal(format!(" [{number}]"), child_context.style, &child_context);
    }
}

fn render_list(
    element: &Element,
    ordered: bool,
    context: &Context,
    composer: &mut Composer<'_>,
    nesting: usize,
) {
    composer.finish(false);
    let items: Vec<&Element> = element
        .children
        .iter()
        .filter_map(|node| match node {
            Node::Element(child) if child.tag == "li" => Some(child),
            _ => None,
        })
        .collect();
    let reversed = element.attr("reversed").is_some();
    let mut number = element
        .attr("start")
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(if reversed { items.len() as i64 } else { 1 });

    for item in items {
        if let Some(value) = item
            .attr("value")
            .and_then(|value| value.trim().parse::<i64>().ok())
        {
            number = value;
        }
        let marker_type = list_marker_type(item).or_else(|| list_marker_type(element));
        let marker = if marker_type.as_deref() == Some("none") {
            String::new()
        } else if ordered {
            format_ordered_marker(number, marker_type.as_deref())
        } else {
            match marker_type.as_deref() {
                Some("circle") => "◦".to_owned(),
                Some("square") => "▪".to_owned(),
                Some("disc") => "•".to_owned(),
                _ => match nesting % 3 {
                    0 => "•".to_owned(),
                    1 => "◦".to_owned(),
                    _ => "▪".to_owned(),
                },
            }
        };
        let marker_suffix = usize::from(!marker.is_empty());
        let first_prefix = format!("{}{}{}", context.prefix, marker, " ".repeat(marker_suffix));
        let rest_prefix = format!(
            "{}{}",
            context.prefix,
            " ".repeat(marker.width() + marker_suffix)
        );
        let item_context = styled_context(item, context);
        composer.begin_prefixed(&item_context, first_prefix, rest_prefix.clone(), false);
        render_list_item_inline(&item.children, &item_context, composer);
        composer.finish(false);

        let mut nested_context = item_context.clone();
        nested_context.prefix = format!("{}  ", context.prefix);
        for child in &item.children {
            if let Node::Element(nested) = child {
                if nested.tag == "ul" || nested.tag == "ol" {
                    render_list(
                        nested,
                        nested.tag == "ol",
                        &nested_context,
                        composer,
                        nesting + 1,
                    );
                }
            }
        }
        number += if reversed { -1 } else { 1 };
    }
    if let Some(last) = composer.flows.last_mut() {
        last.blank_after = true;
    }
}

fn render_list_item_inline(nodes: &[Node], context: &Context, composer: &mut Composer<'_>) {
    for node in nodes {
        match node {
            Node::Element(element) if matches!(element.tag.as_str(), "ul" | "ol") => {}
            Node::Element(element)
                if matches!(
                    element.tag.as_str(),
                    "p" | "div" | "section" | "article" | "header" | "footer"
                ) =>
            {
                render_list_item_inline(&element.children, context, composer)
            }
            _ => render_node(node, context, composer),
        }
    }
}

fn format_ordered_marker(number: i64, kind: Option<&str>) -> String {
    let value = match kind.unwrap_or("1") {
        "a" | "lower-alpha" | "lower-latin" => alpha_number(number, false),
        "A" | "upper-alpha" | "upper-latin" => alpha_number(number, true),
        "i" | "lower-roman" => roman_number(number, false),
        "I" | "upper-roman" => roman_number(number, true),
        _ => number.to_string(),
    };
    format!("{value}.")
}

fn list_marker_type(element: &Element) -> Option<String> {
    let mut marker = element.attr("type").map(|value| value.trim().to_owned());
    if let Some(style) = element.attr("style") {
        for declaration in style.split(';').take(256) {
            let Some((property, value)) = declaration.split_once(':') else {
                continue;
            };
            let property = property.trim().to_ascii_lowercase();
            if property == "list-style-type" {
                marker = Some(normalized_css_value(value));
            } else if property == "list-style" {
                let value = normalized_css_value(value);
                marker = value.split_whitespace().find_map(|part| {
                    matches!(
                        part,
                        "none"
                            | "disc"
                            | "circle"
                            | "square"
                            | "decimal"
                            | "lower-alpha"
                            | "upper-alpha"
                            | "lower-latin"
                            | "upper-latin"
                            | "lower-roman"
                            | "upper-roman"
                    )
                    .then(|| part.to_owned())
                });
            }
        }
    }
    marker
}

fn alpha_number(mut number: i64, uppercase: bool) -> String {
    if number <= 0 || number > 18_278 {
        return number.to_string();
    }
    let mut output = String::new();
    while number > 0 {
        number -= 1;
        let base = if uppercase { b'A' } else { b'a' };
        output.insert(0, (base + (number % 26) as u8) as char);
        number /= 26;
    }
    output
}

fn roman_number(number: i64, uppercase: bool) -> String {
    if !(1..=3_999).contains(&number) {
        return number.to_string();
    }
    let mut rest = number;
    let mut output = String::new();
    for (value, digits) in [
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
        while rest >= value {
            output.push_str(digits);
            rest -= value;
        }
    }
    if uppercase {
        output
    } else {
        output.to_ascii_lowercase()
    }
}

fn render_description_list(element: &Element, context: &Context, composer: &mut Composer<'_>) {
    composer.finish(false);
    for child in &element.children {
        let Node::Element(entry) = child else {
            continue;
        };
        match entry.tag.as_str() {
            "dt" => {
                let mut term_context = context.clone();
                term_context.style.bold = true;
                composer.begin(&term_context, false);
                render_nodes(&entry.children, &term_context, composer);
                composer.finish(false);
            }
            "dd" => {
                let mut definition_context = context.clone();
                definition_context.prefix.push_str("  ");
                composer.begin(&definition_context, false);
                render_nodes(&entry.children, &definition_context, composer);
                composer.finish(false);
            }
            _ => {}
        }
    }
    if let Some(last) = composer.flows.last_mut() {
        last.blank_after = true;
    }
}

#[derive(Debug, Clone)]
struct TableCell {
    text: String,
    header: bool,
    colspan: usize,
    rowspan: usize,
}

fn render_table(element: &Element, context: &Context, composer: &mut Composer<'_>) {
    composer.finish(false);
    let caption = element.children.iter().find_map(|node| match node {
        Node::Element(child) if child.tag == "caption" => {
            Some(cell_text(&child.children, composer))
        }
        _ => None,
    });
    if let Some(caption) = caption.filter(|text| !text.is_empty()) {
        let mut caption_context = context.clone();
        caption_context.style.bold = true;
        composer.begin(&caption_context, false);
        composer.append_literal(caption, caption_context.style, &caption_context);
        composer.finish(false);
    }

    let mut row_elements = Vec::new();
    collect_table_rows(&element.children, &mut row_elements);
    let mut rows = Vec::new();
    for row in row_elements {
        let mut cells = Vec::new();
        for node in &row.children {
            let Node::Element(cell) = node else {
                continue;
            };
            if !matches!(cell.tag.as_str(), "td" | "th") {
                continue;
            }
            composer.table_cells += 1;
            if composer.table_cells > composer.document.limits.max_table_cells {
                composer
                    .warnings
                    .push("Table was truncated at the configured cell limit.".to_owned());
                break;
            }
            let colspan = cell
                .attr("colspan")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(1)
                .clamp(1, 1_000);
            let rowspan = cell
                .attr("rowspan")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(1)
                .clamp(1, 65_536);
            cells.push(TableCell {
                text: cell_text(&cell.children, composer),
                header: cell.tag == "th",
                colspan,
                rowspan,
            });
        }
        if !cells.is_empty() {
            rows.push(cells);
        }
        if composer.table_cells > composer.document.limits.max_table_cells {
            break;
        }
    }
    if rows.is_empty() {
        return;
    }
    let (rows, columns) = normalize_table_rows(&rows);

    let minimum_grid_width = columns.saturating_mul(8).saturating_add(columns + 1);
    if columns <= 12 && composer.width >= minimum_grid_width {
        render_grid_table(&rows, columns, context, composer);
    } else {
        render_stacked_table(&rows, columns, context, composer);
    }
    if let Some(last) = composer.flows.last_mut() {
        last.blank_after = true;
    }
}

fn collect_table_rows<'a>(nodes: &'a [Node], rows: &mut Vec<&'a Element>) {
    for node in nodes {
        let Node::Element(element) = node else {
            continue;
        };
        match element.tag.as_str() {
            "tr" => rows.push(element),
            "thead" | "tbody" | "tfoot" => collect_table_rows(&element.children, rows),
            "table" => {}
            _ => {}
        }
    }
}

fn empty_table_cell() -> TableCell {
    TableCell {
        text: String::new(),
        header: false,
        colspan: 1,
        rowspan: 1,
    }
}

/// Applies row/column occupancy to a bounded rectangular matrix. Continuation
/// cells are blank so a spanned value is stated once rather than duplicated.
fn normalize_table_rows(rows: &[Vec<TableCell>]) -> (Vec<Vec<TableCell>>, usize) {
    const MAX_COLUMNS: usize = 128;
    let mut remaining_rowspan: Vec<usize> = Vec::new();
    let mut normalized = Vec::with_capacity(rows.len());
    let mut widest = 1usize;

    for row in rows {
        let occupied: Vec<bool> = remaining_rowspan
            .iter()
            .map(|remaining| *remaining > 0)
            .collect();
        for remaining in &mut remaining_rowspan {
            *remaining = remaining.saturating_sub(1);
        }
        let mut output = vec![empty_table_cell(); remaining_rowspan.len()];
        let mut column = 0usize;
        for cell in row {
            let requested_span = cell.colspan.clamp(1, MAX_COLUMNS);
            while column < MAX_COLUMNS
                && (column..column.saturating_add(requested_span).min(occupied.len()))
                    .any(|candidate| occupied[candidate])
            {
                column += 1;
            }
            if column >= MAX_COLUMNS {
                break;
            }
            let span = requested_span.min(MAX_COLUMNS - column);
            let required = column + span;
            if output.len() < required {
                output.resize(required, empty_table_cell());
                remaining_rowspan.resize(required, 0);
            }
            let mut origin = cell.clone();
            origin.colspan = 1;
            origin.rowspan = 1;
            output[column] = origin;
            for offset in 0..span {
                remaining_rowspan[column + offset] = cell.rowspan.saturating_sub(1);
            }
            column += span;
        }
        widest = widest.max(output.len()).min(MAX_COLUMNS);
        normalized.push(output);
    }
    for row in &mut normalized {
        row.resize(widest, empty_table_cell());
    }
    (normalized, widest)
}

fn render_grid_table(
    rows: &[Vec<TableCell>],
    columns: usize,
    context: &Context,
    composer: &mut Composer<'_>,
) {
    let inner_total = composer.width.saturating_sub(columns + 1);
    let base = inner_total / columns;
    let extra = inner_total % columns;
    let widths: Vec<usize> = (0..columns)
        .map(|index| base + usize::from(index < extra))
        .collect();
    let (
        tl,
        tr,
        bl,
        br,
        horizontal,
        vertical,
        top_join,
        mid_left,
        mid_join,
        mid_right,
        bottom_join,
    ) = if composer.options.unicode_borders {
        ('┌', '┐', '└', '┘', '─', '│', '┬', '├', '┼', '┤', '┴')
    } else {
        ('+', '+', '+', '+', '-', '|', '+', '+', '+', '+', '+')
    };
    let border_style = TextStyle {
        border: true,
        ..context.style
    };
    composer.raw_line(
        table_border_line(tl, top_join, tr, horizontal, &widths),
        border_style,
        context,
    );
    for (row_index, row) in rows.iter().enumerate() {
        let wrapped: Vec<Vec<String>> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| wrap_plain(&cell.text, *width))
            .collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        for line_index in 0..height {
            let mut line = String::new();
            line.push(vertical);
            for (column, width) in widths.iter().enumerate() {
                let value = wrapped[column]
                    .get(line_index)
                    .map(String::as_str)
                    .unwrap_or("");
                line.push_str(value);
                line.push_str(&" ".repeat(width.saturating_sub(value.width())));
                line.push(vertical);
            }
            let style = if row.iter().any(|cell| cell.header) {
                TextStyle {
                    bold: true,
                    ..context.style
                }
            } else {
                context.style
            };
            composer.raw_line(line, style, context);
        }
        if row_index + 1 < rows.len() {
            composer.raw_line(
                table_border_line(mid_left, mid_join, mid_right, horizontal, &widths),
                border_style,
                context,
            );
        }
    }
    composer.raw_line(
        table_border_line(bl, bottom_join, br, horizontal, &widths),
        border_style,
        context,
    );
}

fn table_border_line(
    left: char,
    join: char,
    right: char,
    horizontal: char,
    widths: &[usize],
) -> String {
    let mut line = String::new();
    line.push(left);
    for (index, width) in widths.iter().enumerate() {
        line.push_str(&horizontal.to_string().repeat(*width));
        line.push(if index + 1 == widths.len() {
            right
        } else {
            join
        });
    }
    line
}

fn render_stacked_table(
    rows: &[Vec<TableCell>],
    columns: usize,
    context: &Context,
    composer: &mut Composer<'_>,
) {
    let first_is_header = rows
        .first()
        .is_some_and(|row| row.iter().any(|cell| cell.header));
    let headers: Vec<String> = if first_is_header {
        rows[0]
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                if cell.text.is_empty() {
                    format!("Column {}", index + 1)
                } else {
                    cell.text.clone()
                }
            })
            .collect()
    } else {
        (1..=columns)
            .map(|number| format!("Column {number}"))
            .collect()
    };
    let data_rows = if first_is_header { &rows[1..] } else { rows };
    for (row_index, row) in data_rows.iter().enumerate() {
        let mut row_context = context.clone();
        row_context.prefix.push_str("  ");
        composer.begin(&row_context, row_index + 1 < data_rows.len());
        for (index, cell) in row.iter().enumerate() {
            if cell.text.is_empty() {
                continue;
            }
            if composer.has_content() {
                composer.hard_break(&row_context);
            }
            composer.append_literal(
                format!("{}: ", headers[index]),
                TextStyle {
                    bold: true,
                    ..row_context.style
                },
                &row_context,
            );
            composer.append_literal(cell.text.clone(), row_context.style, &row_context);
        }
        composer.finish(row_index + 1 < data_rows.len());
    }
}

fn cell_text(nodes: &[Node], composer: &mut Composer<'_>) -> String {
    let mut output = String::new();
    collect_cell_text(nodes, composer, &mut output);
    collapse_whitespace(&output)
}

fn collect_cell_text(nodes: &[Node], composer: &mut Composer<'_>, output: &mut String) {
    for node in nodes {
        match node {
            Node::Text(text) => output.push_str(&sanitize_text(text, Transform::None)),
            Node::Element(element) if is_hidden(element) => {}
            Node::Element(element) if element.tag == "br" => output.push(' '),
            Node::Element(element) if element.tag == "img" => {
                output.push_str(&composer.register_image(element));
            }
            Node::Element(element) if element.tag == "a" => {
                collect_cell_text(&element.children, composer, output);
                if let Some(number) = composer.link(element.attr("href").unwrap_or_default()) {
                    output.push_str(&format!(" [{number}]"));
                }
            }
            Node::Element(element) if element.tag == "form" => {
                output.push_str("[Interactive form omitted]")
            }
            Node::Element(element) => collect_cell_text(&element.children, composer, output),
        }
    }
}

fn append_link_targets(composer: &mut Composer<'_>, context: &Context) {
    composer.finish(false);
    let mut heading_context = context.clone();
    heading_context.style.heading = true;
    heading_context.style.bold = true;
    composer.begin(&heading_context, false);
    composer.append_literal("Links", heading_context.style, &heading_context);
    composer.finish(false);
    let links = composer.links.clone();
    for link in links {
        let mut target_context = context.clone();
        target_context.style.target = true;
        composer.begin(&target_context, false);
        let destination = match link.kind {
            LinkKind::Blocked => link
                .blocked_scheme
                .as_deref()
                .map(|scheme| format!("[blocked {scheme} link]"))
                .unwrap_or_else(|| "[blocked link]".to_owned()),
            LinkKind::Relative => format!(
                "[relative link] {}",
                link.destination.as_deref().unwrap_or_default()
            ),
            _ => link
                .destination
                .unwrap_or_else(|| "[unavailable]".to_owned()),
        };
        composer.append_literal(
            format!("{}. {}", link.number, destination),
            target_context.style,
            &target_context,
        );
        composer.finish(false);
    }
}

fn styled_context(element: &Element, parent: &Context) -> Context {
    let mut context = parent.clone();
    if element.tag == "center" {
        context.alignment = Alignment::Center;
    }
    if let Some(align) = element.attr("align") {
        match align.trim().to_ascii_lowercase().as_str() {
            "center" => context.alignment = Alignment::Center,
            "right" => context.alignment = Alignment::Right,
            "left" => context.alignment = Alignment::Left,
            _ => {}
        }
    }
    let Some(style) = element.attr("style") else {
        return context;
    };
    for declaration in style.split(';').take(256) {
        let Some((property, value)) = declaration.split_once(':') else {
            continue;
        };
        let property = property.trim().to_ascii_lowercase();
        let value = normalized_css_value(value);
        match property.as_str() {
            "font-weight" if value == "bold" => context.style.bold = true,
            "font-weight" => {
                if value.parse::<u16>().is_ok_and(|weight| weight >= 600) {
                    context.style.bold = true;
                }
            }
            "font-style" if matches!(value.as_str(), "italic" | "oblique") => {
                context.style.italic = true
            }
            "text-decoration" | "text-decoration-line" => {
                context.style.underline |= value.split_whitespace().any(|part| part == "underline");
                context.style.crossed |=
                    value.split_whitespace().any(|part| part == "line-through");
            }
            "white-space" if matches!(value.as_str(), "pre" | "pre-wrap" | "break-spaces") => {
                context.preserve = true
            }
            "text-transform" if value == "uppercase" => context.transform = Transform::Uppercase,
            "text-transform" if value == "lowercase" => context.transform = Transform::Lowercase,
            "text-transform" if value == "capitalize" => context.transform = Transform::Capitalize,
            "text-align" if value == "center" => context.alignment = Alignment::Center,
            "text-align" if value == "right" || value == "end" => {
                context.alignment = Alignment::Right
            }
            "text-align" if value == "left" || value == "start" => {
                context.alignment = Alignment::Left
            }
            _ => {}
        }
    }
    context
}

fn is_hidden(element: &Element) -> bool {
    if element.attr("hidden").is_some()
        || element
            .attr("aria-hidden")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
    {
        return true;
    }
    let Some(style) = element.attr("style") else {
        return false;
    };
    style.split(';').take(256).any(|declaration| {
        let Some((property, value)) = declaration.split_once(':') else {
            return false;
        };
        let property = property.trim().to_ascii_lowercase();
        let value = normalized_css_value(value);
        matches!(
            (property.as_str(), value.as_str()),
            ("display", "none")
                | ("visibility", "hidden")
                | ("visibility", "collapse")
                | ("mso-hide", "all")
        )
    })
}

fn normalized_css_value(raw: &str) -> String {
    let value = raw.trim().to_ascii_lowercase();
    value
        .strip_suffix("!important")
        .map_or(value.as_str(), str::trim_end)
        .to_owned()
}

fn has_renderable_content(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Text(text) => !text.trim().is_empty(),
        Node::Element(element) if is_hidden(element) => false,
        Node::Element(element) if matches!(element.tag.as_str(), "img" | "br") => true,
        Node::Element(element) => has_renderable_content(&element.children),
    })
}

fn sanitize_text(raw: &str, transform: Transform) -> String {
    let mut output = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '\n' | '\r' | '\t' => output.push(character),
            '\u{202a}' => output.push_str("⟦LRE⟧"),
            '\u{202b}' => output.push_str("⟦RLE⟧"),
            '\u{202c}' => output.push_str("⟦PDF⟧"),
            '\u{202d}' => output.push_str("⟦LRO⟧"),
            '\u{202e}' => output.push_str("⟦RLO⟧"),
            '\u{2066}' => output.push_str("⟦LRI⟧"),
            '\u{2067}' => output.push_str("⟦RLI⟧"),
            '\u{2068}' => output.push_str("⟦FSI⟧"),
            '\u{2069}' => output.push_str("⟦PDI⟧"),
            character if character.is_control() => output.push('�'),
            character => output.push(character),
        }
    }
    match transform {
        Transform::None => output,
        Transform::Uppercase => output.to_uppercase(),
        Transform::Lowercase => output.to_lowercase(),
        Transform::Capitalize => {
            let mut start = true;
            output
                .chars()
                .flat_map(|character| {
                    if character.is_whitespace() {
                        start = true;
                        vec![character]
                    } else if start {
                        start = false;
                        character.to_uppercase().collect()
                    } else {
                        vec![character]
                    }
                })
                .collect()
        }
    }
}

fn bounded_display(raw: &str, max_chars: usize) -> String {
    sanitize_text(
        &raw.chars().take(max_chars).collect::<String>(),
        Transform::None,
    )
}

fn collapse_whitespace(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn expand_tabs(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut column = 0usize;
    for character in raw.chars() {
        match character {
            '\t' => {
                let count = 4 - (column % 4);
                output.push_str(&" ".repeat(count));
                column += count;
            }
            '\n' | '\r' => {
                output.push('\n');
                column = 0;
            }
            character => {
                output.push(character);
                column += character.width().unwrap_or(0);
            }
        }
    }
    output
}

fn wrap_plain(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let flow = Flow {
        pieces: vec![Piece {
            text: text.to_owned(),
            style: TextStyle::default(),
        }],
        first_prefix: String::new(),
        rest_prefix: String::new(),
        alignment: Alignment::Left,
        preserve: false,
        blank_after: false,
    };
    wrap_flow(&flow, width, &Theme::default())
        .into_iter()
        .map(|line| {
            line.spans
                .into_iter()
                .map(|span| span.content.into_owned())
                .collect()
        })
        .collect()
}

#[derive(Debug)]
enum Token {
    Text(String, TextStyle),
    Space(TextStyle),
    Break,
}

fn flow_tokens(flow: &Flow) -> Vec<Token> {
    let mut tokens = Vec::new();
    for piece in &flow.pieces {
        for segment in piece.text.split_inclusive('\n') {
            let (content, has_break) = segment
                .strip_suffix('\n')
                .map_or((segment, false), |value| (value, true));
            if flow.preserve {
                if !content.is_empty() {
                    tokens.push(Token::Text(content.to_owned(), piece.style));
                }
            } else {
                for word in content.split_word_bounds() {
                    if word.chars().all(char::is_whitespace) {
                        tokens.push(Token::Space(piece.style));
                    } else if !word.is_empty() {
                        tokens.push(Token::Text(word.to_owned(), piece.style));
                    }
                }
            }
            if has_break {
                tokens.push(Token::Break);
            }
        }
    }
    tokens
}

fn wrap_flow(flow: &Flow, width: usize, theme: &Theme) -> Vec<Line<'static>> {
    let width = width.max(1);
    let tokens = flow_tokens(flow);
    let mut output = Vec::new();
    let mut pieces: Vec<Span<'static>> = Vec::new();
    let mut content_width = 0usize;
    let mut first_line = true;
    let mut pending_space: Option<TextStyle> = None;

    let start_line = |pieces: &mut Vec<Span<'static>>, first: bool| -> usize {
        let prefix = if first {
            &flow.first_prefix
        } else {
            &flow.rest_prefix
        };
        let prefix = clip_to_width(prefix, width.saturating_sub(1));
        if !prefix.is_empty() {
            pieces.push(Span::styled(
                prefix.clone(),
                TextStyle {
                    border: true,
                    ..TextStyle::default()
                }
                .ratatui(theme),
            ));
        }
        prefix.width()
    };
    let mut prefix_width = start_line(&mut pieces, first_line);

    let push_line =
        |output: &mut Vec<Line<'static>>, pieces: &mut Vec<Span<'static>>, alignment: Alignment| {
            let spans = std::mem::take(pieces);
            output.push(Line::from(spans).alignment(alignment));
        };

    for token in tokens {
        match token {
            Token::Break => {
                push_line(&mut output, &mut pieces, flow.alignment);
                first_line = false;
                prefix_width = start_line(&mut pieces, false);
                content_width = 0;
                pending_space = None;
            }
            Token::Space(style) if !flow.preserve => pending_space = Some(style),
            Token::Space(style) => {
                append_graphemes(
                    " ",
                    style,
                    width,
                    flow,
                    theme,
                    &mut output,
                    &mut pieces,
                    &mut first_line,
                    &mut prefix_width,
                    &mut content_width,
                );
            }
            Token::Text(text, style) => {
                let available = width.saturating_sub(prefix_width).max(1);
                let word_width = text.width();
                if let Some(space_style) = pending_space.take() {
                    if content_width > 0 && content_width + 1 + word_width <= available {
                        push_span(&mut pieces, " ".to_owned(), space_style, theme);
                        content_width += 1;
                    } else if content_width > 0 {
                        push_line(&mut output, &mut pieces, flow.alignment);
                        first_line = false;
                        prefix_width = start_line(&mut pieces, false);
                        content_width = 0;
                    }
                }
                append_graphemes(
                    &text,
                    style,
                    width,
                    flow,
                    theme,
                    &mut output,
                    &mut pieces,
                    &mut first_line,
                    &mut prefix_width,
                    &mut content_width,
                );
            }
        }
    }
    if !pieces.is_empty() || output.is_empty() {
        push_line(&mut output, &mut pieces, flow.alignment);
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn append_graphemes(
    text: &str,
    style: TextStyle,
    width: usize,
    flow: &Flow,
    theme: &Theme,
    output: &mut Vec<Line<'static>>,
    pieces: &mut Vec<Span<'static>>,
    first_line: &mut bool,
    prefix_width: &mut usize,
    content_width: &mut usize,
) {
    let mut chunk = String::new();
    for grapheme in text.graphemes(true) {
        let grapheme_width = grapheme.width();
        let available = width.saturating_sub(*prefix_width).max(1);
        if *content_width > 0 && content_width.saturating_add(grapheme_width) > available {
            if !chunk.is_empty() {
                push_span(pieces, std::mem::take(&mut chunk), style, theme);
            }
            let spans = std::mem::take(pieces);
            output.push(Line::from(spans).alignment(flow.alignment));
            *first_line = false;
            let prefix = clip_to_width(&flow.rest_prefix, width.saturating_sub(1));
            if !prefix.is_empty() {
                pieces.push(Span::styled(
                    prefix.clone(),
                    TextStyle {
                        border: true,
                        ..TextStyle::default()
                    }
                    .ratatui(theme),
                ));
            }
            *prefix_width = prefix.width();
            *content_width = 0;
        }
        // An individual grapheme can be wider than a one-cell viewport. Keep
        // it intact; Ratatui will clip it rather than corrupting the cluster.
        chunk.push_str(grapheme);
        *content_width = content_width.saturating_add(grapheme_width);
    }
    if !chunk.is_empty() {
        push_span(pieces, chunk, style, theme);
    }
}

fn push_span(pieces: &mut Vec<Span<'static>>, text: String, style: TextStyle, theme: &Theme) {
    if text.is_empty() {
        return;
    }
    let ratatui_style = style.ratatui(theme);
    if let Some(last) = pieces.last_mut() {
        if last.style == ratatui_style {
            last.content.to_mut().push_str(&text);
            return;
        }
    }
    pieces.push(Span::styled(text, ratatui_style));
}

fn clip_to_width(text: &str, max_width: usize) -> String {
    let mut output = String::new();
    let mut width = 0usize;
    for grapheme in text.graphemes(true) {
        let grapheme_width = grapheme.width();
        if width.saturating_add(grapheme_width) > max_width {
            break;
        }
        output.push_str(grapheme);
        width += grapheme_width;
    }
    output
}

#[cfg(test)]
mod tests {
    use ratatui::{backend::TestBackend, Terminal};

    use super::*;
    use crate::{HtmlRenderer, Limits, RenderError};

    fn page(html: &str, width: u16) -> RenderedPage {
        HtmlRenderer::default()
            .render(html.as_bytes(), width, &RenderOptions::default())
            .unwrap()
    }

    fn text(page: &RenderedPage) -> String {
        page.lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn active_content_controls_and_bidi_overrides_are_inert() {
        let rendered = page(
            "<p>Hello<script>alert(1)</script>\u{1b}[31m\u{202e}txt</p>",
            80,
        );
        let output = text(&rendered);
        assert!(output.contains("Hello�[31m⟦RLO⟧txt"));
        assert!(!output.contains("alert"));
        assert!(rendered
            .warnings
            .iter()
            .any(|warning| warning.contains("Active content")));
    }

    #[test]
    fn links_are_numbered_canonical_and_unsafe_schemes_are_not_repeated() {
        let rendered = page(
            "<p><a href='HTTPS://Example.COM/a'>safe</a> <a href='javascript:bad()'>bad</a></p>",
            80,
        );
        assert_eq!(rendered.links.len(), 2);
        assert_eq!(rendered.links[0].kind, LinkKind::Web);
        assert_eq!(
            rendered.links[0].destination.as_deref(),
            Some("https://example.com/a")
        );
        assert_eq!(rendered.links[1].kind, LinkKind::Blocked);
        let output = text(&rendered);
        assert!(output.contains("safe [1]"));
        assert!(output.contains("bad [2]"));
        assert!(output.contains("[blocked javascript link]"));
        assert!(!output.contains("bad()"));
    }

    #[test]
    fn different_blocked_schemes_get_distinct_references() {
        let rendered = page(
            "<a href='javascript:x'>one</a><a href='file:///tmp/x'>two</a>",
            80,
        );
        assert_eq!(rendered.links.len(), 2);
        assert_eq!(
            rendered.links[0].blocked_scheme.as_deref(),
            Some("javascript")
        );
        assert_eq!(rendered.links[1].blocked_scheme.as_deref(), Some("file"));
    }

    #[test]
    fn aria_label_supplies_text_for_an_empty_link() {
        let rendered = page(
            "<a aria-label='Account settings' href='https://example.com/settings'></a>",
            80,
        );
        assert!(text(&rendered).contains("Account settings [1]"));
    }

    #[test]
    fn images_are_metadata_and_label_only() {
        let rendered = page(
            "<p>Before <img src='https://tracker.invalid/pixel' alt='Company logo'> after</p>",
            80,
        );
        assert_eq!(rendered.images.len(), 1);
        assert_eq!(rendered.images[0].source, ImageSource::Remote);
        assert!(text(&rendered).contains("[Image: Company logo]"));
    }

    #[test]
    fn images_inside_tables_are_also_recorded_as_metadata() {
        let rendered = page(
            "<table><tr><td><img src='cid:logo' alt='Logo'></td></tr></table>",
            20,
        );
        assert_eq!(rendered.images.len(), 1);
        assert_eq!(rendered.images[0].source, ImageSource::ContentId);
        assert!(text(&rendered).contains("[Image: Logo]"));
    }

    #[test]
    fn forms_are_replaced_as_a_unit() {
        let rendered = page(
            "<form><p>Password <input type=password></p><button>Send</button></form>",
            80,
        );
        assert_eq!(text(&rendered).trim(), "[Interactive form omitted]");
    }

    #[test]
    fn narrow_tables_stack_under_headers() {
        let rendered = page(
            "<table><tr><th>Name</th><th>Value</th></tr><tr><td>Alpha</td><td>Beta</td></tr></table>",
            16,
        );
        let output = text(&rendered);
        assert!(output.contains("Name: Alpha"));
        assert!(output.contains("Value: Beta"));
    }

    #[test]
    fn wide_tables_fit_the_requested_width() {
        let rendered = page(
            "<table><tr><th>Name</th><th>Value</th></tr><tr><td>Alpha</td><td>Beta</td></tr></table>",
            40,
        );
        assert!(rendered.lines.iter().all(|line| line.width() <= 40));
        assert!(text(&rendered).contains('┌'));
    }

    #[test]
    fn rowspans_reserve_columns_in_following_rows() {
        let rows = vec![
            vec![
                TableCell {
                    text: "A".to_owned(),
                    header: false,
                    colspan: 1,
                    rowspan: 2,
                },
                TableCell {
                    text: "B".to_owned(),
                    header: false,
                    colspan: 1,
                    rowspan: 1,
                },
            ],
            vec![TableCell {
                text: "C".to_owned(),
                header: false,
                colspan: 1,
                rowspan: 1,
            }],
        ];
        let (normalized, columns) = normalize_table_rows(&rows);
        assert_eq!(columns, 2);
        assert_eq!(normalized[1][0].text, "");
        assert_eq!(normalized[1][1].text, "C");
    }

    #[test]
    fn lists_preformatted_text_and_semantics_render() {
        let rendered = page(
            "<h1>Title</h1><ol type='A'><li><strong>One</strong></li><li>Two<ul><li>Nested</li></ul></li></ol><pre>a\tb\n c</pre>",
            24,
        );
        let output = text(&rendered);
        assert!(output.contains("A. One"));
        assert!(output.contains("B. Two"));
        assert!(output.contains("◦ Nested"));
        assert!(output.contains("a   b"));
    }

    #[test]
    fn html5_tree_repair_is_used() {
        let rendered = page("<p>one<p>two", 80);
        let output = text(&rendered);
        assert!(output.contains("one"));
        assert!(output.contains("two"));
    }

    #[test]
    fn hidden_important_content_stays_hidden_and_author_colors_are_ignored() {
        let rendered = page(
            "<p style='color:white'>visible <span style='display: none !important'>secret</span></p>",
            80,
        );
        assert!(text(&rendered).contains("visible"));
        assert!(!text(&rendered).contains("secret"));
        assert_eq!(rendered.lines[0].spans[0].style.fg, None);
    }

    #[test]
    fn indentation_is_clipped_to_the_render_width() {
        let html = format!(
            "{}x{}",
            "<blockquote>".repeat(40),
            "</blockquote>".repeat(40)
        );
        let rendered = page(&html, 8);
        assert!(rendered.lines.iter().all(|line| line.width() <= 8));
        assert!(text(&rendered).contains('x'));
    }

    #[test]
    fn input_and_output_budgets_are_enforced() {
        let limits = Limits {
            max_input_bytes: 4,
            ..Limits::default()
        };
        let renderer = HtmlRenderer::new(limits);
        assert!(matches!(
            renderer.parse(b"12345"),
            Err(RenderError::InputTooLarge { .. })
        ));

        let limits = Limits {
            max_output_cells: 4,
            ..Limits::default()
        };
        let rendered = HtmlRenderer::new(limits)
            .render(b"<p>long output</p>", 80, &RenderOptions::default())
            .unwrap();
        assert!(rendered.truncated);
    }

    #[test]
    fn ratatui_widget_can_be_drawn_and_scrolled() {
        let rendered = page("<h1>Hello</h1><p>world</p>", 20);
        let backend = TestBackend::new(20, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| frame.render_widget(rendered.widget().scroll(2), frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let first_row: String = (0..20).map(|x| buffer[(x, 0)].symbol()).collect();
        assert!(first_row.contains("world"));
    }
}
