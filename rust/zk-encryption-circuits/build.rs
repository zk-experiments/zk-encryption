//! Generates the bindings of this layer's frozen circuits (`circuits/manifest.toml`,
//! `resources/`, written by `noir-zk freeze`) and its families (channel/session, channel/envelope, channel/note_envelope).

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    println!("cargo:rerun-if-changed=circuits");
    println!("cargo:rerun-if-changed=resources");
    println!("cargo:rerun-if-changed=assets");
    // The circuits are small: their bytecode is bundled, so the layer is self-contained.
    let options = noir_zk_codegen::Options {
        bundle: vec!["*".into()],
        sources: vec![],
    };
    std::fs::write(
        out.join("circuits.rs"),
        noir_zk_codegen::generate_registry_with(&dir, &options),
    )
    .unwrap_or_else(|e| panic!("circuits.rs: {e}"));
}
