use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::fs;
use std::path::PathBuf;

const SRC: &str = "../uniproc-linux-agent-ebpf/src/prog.bpf.c";
const BPF_SRC_DIR: &str = "../uniproc-linux-agent-ebpf/src";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I../uniproc-linux-agent-ebpf/src"])
        .build_and_generate(&out_dir.join("prog.skel.rs"))
        .unwrap();

    watch_dir(BPF_SRC_DIR);
}

fn watch_dir(path: &str) {
    let p = PathBuf::from(path);
    if p.is_file() {
        println!("cargo:rerun-if-changed={path}");
        return;
    }
    if let Ok(entries) = fs::read_dir(&p) {
        for entry in entries.filter_map(|e| e.ok()) {
            let ep = entry.path();
            if ep.is_dir() {
                watch_dir(&ep.to_string_lossy());
            } else {
                println!("cargo:rerun-if-changed={}", ep.to_string_lossy());
            }
        }
    }
}
