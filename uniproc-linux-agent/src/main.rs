use crate::bpf::BpfAgent;
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::LevelFilter;

mod batch_lookup;
mod bpf;
mod environment_resolver;
mod iter_gc;
mod name_cache;
mod process_metrics_state;
mod report;
mod rpc;
mod seed;

#[compio::main]
async fn main() -> anyhow::Result<()> {
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 1);
        libc::mallopt(libc::M_TRIM_THRESHOLD, 131072);
        libc::mallopt(libc::M_MMAP_THRESHOLD, 131072);
        libc::malloc_trim(0);
    }

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    let agent = Arc::new(Mutex::new(BpfAgent::init()?));
    rpc::run(agent, read_shared_secret()?).await
}

/// The host writes a one-shot secret to our stdin and closes it, then uses the
/// same bytes as the HMAC key when it dials in. It is never persisted and never
/// appears in `/proc/*/cmdline`, unlike an argv or environment hand-off.
///
/// Required in every build profile. There is nothing to relax here: the host
/// mints the key per connection, so demanding one costs a developer nothing,
/// while accepting unauthenticated peers in debug builds would open the hole
/// precisely on the machine where the agent is actually run by hand. Starting
/// it manually just means piping one in: `echo -n dev | uniproc-agent`.
fn read_shared_secret() -> anyhow::Result<Vec<u8>> {
    use std::io::Read;

    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    // Trailing newline is whatever the writer happened to add, not key material.
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }

    if buf.is_empty() {
        anyhow::bail!(
            "no shared secret on stdin: the host writes one and closes the stream before we \
             start listening (to run by hand: `echo -n dev | uniproc-agent`)"
        );
    }
    Ok(buf)
}
