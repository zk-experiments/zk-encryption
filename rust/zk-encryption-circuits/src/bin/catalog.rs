#![allow(clippy::print_stdout, clippy::print_stderr)]
//! Writes the release catalog (`catalog.json`): the library's identity, the
//! toolchain pins, the families with their roots and layouts, and the
//! kernels this layer folds with, so a target project can check what a
//! published release is before depending on it.
//!
//! cargo run --release -p zk-encryption-circuits --bin catalog -- <version> <resources.tar.gz sha256>

use zk_encryption_circuits::circuits::{FAMILIES, LIBRARY};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (version, sha256) = (args.get(1).cloned(), args.get(2).cloned());
    let manifest: toml::Value = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/circuits/manifest.toml"
    )))
    .expect("manifest");
    let families: Vec<serde_json::Value> = FAMILIES
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": format!("{}/{}/{}", f.id.library, f.id.layer, f.id.family),
                "root": format!("0x{}", hex::encode(f.root)),
                "members": f.members.iter().map(|(l, h)| serde_json::json!({"label": l, "vk_hash": format!("0x{}", hex::encode(h))})).collect::<Vec<_>>(),
                "record_fields": f.record_fields,
                "link_in": f.link_in.map(|l| serde_json::json!({"index": l.index, "link": l.link})),
                "link_out": f.link_out.map(|l| serde_json::json!({"index": l.index, "link": l.link})),
                "binds": f.binds.iter().map(|b| serde_json::json!({"slot": b.slot, "index": b.index})).collect::<Vec<_>>(),
                "bind_const": f.consts.iter().map(|c| serde_json::json!({"index": c.index, "value": format!("0x{}", hex::encode(c.value))})).collect::<Vec<_>>(),
                "public_from": f.public_from,
                "slots": f.slots,
            })
        })
        .collect();
    let kernels = &noir_zk_backend::kernels::FAMILY;
    let out = serde_json::json!({
        "library": LIBRARY.name,
        "version": version.unwrap_or_else(|| LIBRARY.version.to_string()),
        "noir": manifest["noir"].as_str(),
        "bb": manifest["bb"].as_str(),
        "resources_sha256": sha256,
        "families": families,
        "kernels": {
            "library": kernels.id.library,
            "version": kernels.version,
            "family_root": format!("0x{}", hex::encode(kernels.root)),
            "noir_zk_rev": zk_encryption_circuits::NOIR_ZK_REV,
        },
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
}
