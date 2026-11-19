use std::{fs, path::PathBuf};

use lizard_mail_tui::{HtmlRenderer, RenderOptions};

#[test]
fn graphical_profile_fixtures_are_safe_at_wide_and_narrow_terminal_widths() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures");
    let mut fixtures: Vec<PathBuf> = fs::read_dir(&fixture_dir)
        .expect("fixture directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "html")
        })
        .collect();
    fixtures.sort();
    assert!(!fixtures.is_empty());

    let renderer = HtmlRenderer::default();
    let options = RenderOptions::default();
    for fixture in fixtures {
        let html = fs::read(&fixture).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", fixture.display());
        });
        for width in [20, 80] {
            let page = renderer
                .render(&html, width, &options)
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to render {} at width {width}: {error}",
                        fixture.display()
                    );
                });
            assert!(
                page.lines
                    .iter()
                    .all(|line| line.width() <= usize::from(width)),
                "{} emitted a line wider than {width} cells",
                fixture.display()
            );
        }
    }
}
