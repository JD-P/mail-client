use lizard::{core::*, verified};
#[test]
fn work_budget_is_monotone_and_fails_without_debit() {
    let mut b = Budget::new(10);
    assert!(b.charge(7).is_ok());
    assert_eq!(b.remaining(), 3);
    assert!(b.charge(4).is_err());
    assert_eq!(b.remaining(), 3);
    assert!(b.charge(3).is_ok());
    assert_eq!(b.remaining(), 0);
}
#[test]
fn hostile_image_descriptors_fail() {
    assert!(image_len(256, 256, 1, 64 * 1024 * 1024).is_err());
    assert!(image_len(0, 2, 0, 100).is_err());
    assert!(image_len(10, 10, 40, 399).is_err());
    assert_eq!(image_len(10, 10, 40, 400).unwrap(), 400);
    assert_eq!(
        verified::rgba_length(u32::MAX, u32::MAX, u32::MAX, u64::MAX),
        None
    );
}
#[test]
fn containment_does_not_overflow() {
    assert!(!verified::contained(u64::MAX, 1, u64::MAX));
    assert!(verified::contained(u64::MAX, 0, u64::MAX));
    assert!(verified::contained(10, 20, 30));
    assert!(!verified::contained(31, 0, 30));
}
#[test]
fn coordinates_are_bounded() {
    assert_eq!(verified::add_coord(60_000_000, 1), None);
    assert_eq!(verified::add_coord(-60_000_000, -1), None);
    assert_eq!(verified::add_coord(10, -20), Some(-10));
    assert_eq!(verified::add_coord(i64::MAX, i64::MIN), None);
}
#[test]
fn raw_html_parser_repairs_tables() {
    let limits = Limits::default();
    let mut budget = Budget::new(limits.steps);
    let doc =
        lizard::dom::Document::parse(b"<table><td>A<td>B</table>", &limits, &mut budget).unwrap();
    assert!(doc.nodes.iter().any(|n| n.tag == "tbody"));
    assert_eq!(doc.nodes.iter().filter(|n| n.tag == "td").count(), 2);
}
#[test]
fn active_subtrees_do_not_become_readable_content() {
    let limits = Limits::default();
    let mut budget = Budget::new(limits.steps);
    let doc = lizard::dom::Document::parse(
        b"<p>visible</p><script>secret</script><style>p{color:red}</style>",
        &limits,
        &mut budget,
    )
    .unwrap();
    let text = doc.readable_text();
    assert!(text.contains("visible"));
    assert!(!text.contains("secret"));
    assert!(!text.contains("color:red"));
}
#[test]
fn all_ascii_less_thans_are_allocation_budgeted() {
    let limits = Limits {
        nodes: 100,
        ..Limits::default()
    };
    let mut budget = Budget::new(10000);
    assert!(lizard::dom::Document::parse(&vec![b'<'; 26], &limits, &mut budget).is_err());
}

#[test]
fn raster_png_decodes_known_source_pixels() {
    let html = include_str!("fixtures/image-data.html");
    let uri = html
        .split("src=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(uri.starts_with("data:image/png;base64,"));
    let limits = Limits::default();
    let mut budget = Budget::new(limits.steps);
    let image = lizard::resources::data_uri(uri, &limits, &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!((image.width, image.height), (8, 4));
    let mut expected = Vec::new();
    for y in 0..4 {
        for x in 0..8 {
            let pixel = if y < 2 {
                if x < 4 {
                    [255, 0, 0, 255]
                } else {
                    [0, 128, 0, 255]
                }
            } else if x < 4 {
                [0, 0, 255, 255]
            } else {
                [0, 0, 0, 0]
            };
            expected.extend_from_slice(&pixel);
        }
    }
    assert_eq!(image.rgba, expected);
}
