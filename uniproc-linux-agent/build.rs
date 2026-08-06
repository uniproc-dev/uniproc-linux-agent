use aya_build::{build_ebpf, Package, Toolchain};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_dir = manifest_dir
        .join("..")
        .join("uniproc-linux-agent-ebpf")
        .canonicalize()
        .expect("uniproc-linux-agent-ebpf directory not found");

    watch_dir(&ebpf_dir.join("src"));
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("Cargo.toml").display());

    build_ebpf(
        [Package {
            name: "uniproc-linux-agent-ebpf",
            root_dir: ebpf_dir.to_str().expect("non-utf8 path"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )
    .expect("failed to build uniproc-linux-agent-ebpf");
}

fn watch_dir(path: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            watch_dir(&p);
        } else {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
}
