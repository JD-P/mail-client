// freetype-sys otherwise silently falls back to its bundled FreeType source.
// Require the maintained OS library selected by the developer's pkg-config.
fn main() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    let system = std::process::Command::new("pkg-config")
        .args(["--exists", "freetype2"])
        .status()
        .is_ok_and(|s| s.success());
    assert!(system, "Lizard requires system FreeType via pkg-config; install the FreeType development package. Bundled fallback is deliberately disabled.");
}
