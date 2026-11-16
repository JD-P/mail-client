//! Regression checks for boundaries that are harder to diagnose with screenshots.
use lizard::{
    core::*,
    dom::Document,
    layout::{Draw, Engine, Scene},
    paint::Painter,
    text::Fonts,
};
fn scene(html: &str, fonts: &Fonts, width: i64, height: i64) -> Scene {
    let limits = Limits::default();
    let mut budget = Budget::new(limits.steps);
    let doc = Document::parse(html.as_bytes(), &limits, &mut budget).unwrap();
    let styles =
        lizard::style::compute(&doc, px(width), px(height), &limits, &mut budget, &[]).unwrap();
    Engine::new(
        &doc,
        &styles,
        fonts,
        &[],
        &limits,
        &mut budget,
        px(width),
        px(height),
    )
    .run()
    .unwrap()
}
#[test]
fn retained_scroll_restores_pixels_and_scene_replacement_drops_content() {
    let fonts = Fonts::system().unwrap();
    let mut s = scene("<style>html,body{margin:0}div{height:100px}</style><div style='background:red'>Top</div><div style='background:blue'>Bottom</div>", &fonts, 160, 80);
    let mut painter = Painter::new(&fonts, 160, 80).unwrap();
    painter.set_scene(&s, &[]).unwrap();
    let too_many = vec![
        lizard::layout::ImageResource {
            key: "cid:unused".into(),
            width: 1,
            height: 1,
            rgba: vec![0; 4]
        };
        257
    ];
    assert!(painter.set_scene(&s, &too_many).is_err());
    let top = painter.frame(0).unwrap();
    let bottom = painter.frame(px(100)).unwrap();
    assert_ne!(top, bottom);
    assert!(
        top == painter.frame(0).unwrap(),
        "returning to the top must restore pixels"
    );
    assert!(
        painter.frame(px(120)).unwrap() == painter.frame(px(1_000_000)).unwrap(),
        "scroll must clamp to the document extent"
    );
    assert!(painter.frame(-1).is_err());
    s.primitives.clear();
    painter.set_scene(&s, &[]).unwrap();
    assert!(painter.frame(0).unwrap().iter().all(|v| *v == 255));
    // Public scenes cannot underflow or leave open native stacking contexts.
    let mut bad = scene("<p>x</p>", &fonts, 160, 80);
    bad.primitives[0].draw = Draw::EndOpacity;
    assert!(painter.set_scene(&bad, &[]).is_err());
    bad.primitives[0].draw = Draw::BeginOpacity { opacity: 500 };
    assert!(painter.set_scene(&bad, &[]).is_err());
}
#[test]
fn invalid_declarations_do_not_erase_valid_winners() {
    let limits = Limits::default();
    let mut budget = Budget::new(limits.steps);
    let doc = Document::parse(
        b"<style>p{width:20px;width:NaNpx;color:red;color:broken}</style><p>x</p>",
        &limits,
        &mut budget,
    )
    .unwrap();
    let styles = lizard::style::compute(&doc, px(200), px(100), &limits, &mut budget, &[]).unwrap();
    let p = doc.nodes.iter().position(|n| n.tag == "p").unwrap();
    assert_eq!(
        styles[p]
            .width
            .eval(px(200), px(16), px(16), px(200), px(100)),
        Some(px(20))
    );
    assert_eq!(styles[p].color, 0xff0000ff);
    assert!(lizard::style::length("calc(1px + 2)").is_none());
    assert!(lizard::style::length("calc(2px / 0)").is_none());
    assert!(lizard::style::length("calc(2px * 3px)").is_none());
}
#[test]
fn table_occupancy_ranges_are_transactional() {
    let mut columns = vec![0, 0, 0, 0];
    assert!(lizard::verified::mark_columns(&mut columns, 1, 2, 7));
    assert_eq!(columns, vec![0, 7, 7, 0]);
    assert!(!lizard::verified::mark_columns(
        &mut columns,
        usize::MAX,
        2,
        9
    ));
    assert!(!lizard::verified::mark_columns(
        &mut columns,
        3,
        usize::MAX,
        9
    ));
    assert_eq!(columns, vec![0, 7, 7, 0]);
}
#[test]
fn wrapped_links_expose_fragments_and_never_fetch_targets() {
    let fonts = Fonts::system().unwrap();
    let s=scene("<style>body{margin:0;font:16px/24px 'DejaVu Sans'}</style><a href='https://example.invalid/private'>one two three four five six seven eight</a>", &fonts, 100, 150);
    assert_eq!(s.links.len(), 1);
    assert!(s.links[0].rectangles.len() > 1);
    assert!(s.links[0]
        .rectangles
        .iter()
        .all(|r| r.h < px(30) && r.w <= px(100)));
    assert_eq!(s.links[0].target, "https://example.invalid/private");
    assert!(s.readable_text.contains("one two three"));
}
#[test]
fn css_wide_values_copy_only_the_named_property() {
    let limits = Limits::default();
    let mut budget = Budget::new(limits.steps);
    let doc=Document::parse(b"<div style='width:120px;color:red;padding:8px'><p style='width:inherit;color:unset;padding:initial'>x</p></div>",&limits,&mut budget).unwrap();
    let st = lizard::style::compute(&doc, px(200), px(100), &limits, &mut budget, &[]).unwrap();
    let p = doc.nodes.iter().position(|n| n.tag == "p").unwrap();
    assert_eq!(st[p].color, 0xff0000ff);
    assert_eq!(
        st[p].width.eval(px(200), px(16), px(16), px(200), px(100)),
        Some(px(120))
    );
    assert_eq!(st[p].padding.left.eval(0, px(16), px(16), 0, 0), 0);
}
