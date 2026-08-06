use libbpf_cargo::SkeletonBuilder;
use std::path::PathBuf;
use std::{env, fs};

const SRC: &str = "src/prog.bpf.c";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-Isrc"])
        .build_and_generate(&out_dir.join("prog.skel.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");

    for dir in ["src/include", "src/probes"] {
        watch_dir(dir);
    }
}

fn watch_dir(path: &str) {
    let p = PathBuf::from(path);
    if p.is_file() {
        println!("cargo:rerun-if-changed={path}");
        return;
    }
    if let Ok(entries) = fs::read_dir(&p) {
        for entry in entries.filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            let s = entry_path.to_string_lossy();
            if entry_path.is_dir() {
                watch_dir(&s);
            } else {
                println!("cargo:rerun-if-changed={s}");
            }
        }
    }
}
