#![no_std]
#![no_main]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]

mod common;
mod constants;
mod disk;
mod globals;
mod lifecycle;
mod loopback;
mod maps;
mod mem;
mod process;
mod seed;
mod sockets;
mod vmlinux;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
