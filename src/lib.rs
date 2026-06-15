//! librsi — the Peios registry-source (RSI provider) C ABI library.
//!
//! A `no_std`, `panic = "abort"` cdylib/staticlib for implementing a **registry
//! source** (a storage backend) for the LCS registry. It is the source/provider
//! counterpart to libpeios's registry *client* surface: where a client opens keys
//! and reads/writes values via syscalls, a source registers with the kernel and
//! then serves the RSI (Registry Source Interface) framed protocol — receiving
//! requests and sending responses on its source fd.
//!
//! The crate is thin `extern "C"` shims layered on the shared C-ABI substrate
//! `peios-cabi`, over `lcs-core` (the pure-`core` RSI request parsers + status
//! vocabulary the kernel itself uses, so the wire handling is guaranteed
//! compatible), `peios-uapi`, and `libc`. The surface is `<rsi/*.h>`:
//!
//! - [`source`] — becoming a source (`<rsi/source.h>`): registration + the source fd.
//! - [`request`] — receiving and decoding RSI requests (`<rsi/request.h>`).
//! - [`response`] — building and sending RSI responses (`<rsi/response.h>`).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

// The allocator, errno slot, syscall/ioctl wrappers, and getxattr/builder helpers
// live in the shared `peios-cabi` substrate; re-export the plumbing modules so the
// domain modules reach them as `crate::{abi, error, sys}`.
pub(crate) use peios_cabi::{abi, error, sys};

mod request;
mod response;
mod source;

/// Install the shared malloc-backed global allocator (`peios_cabi::LibcAllocator`).
/// Declared here in the cdylib — not the substrate crate — so it is gated out of
/// `cfg(test)` builds, where std supplies its own global allocator.
#[cfg(not(test))]
#[global_allocator]
static GLOBAL: peios_cabi::LibcAllocator = peios_cabi::LibcAllocator;

#[cfg(not(test))]
extern "C" {
    /// libc `abort(3)`; resolved against the system C library at link time.
    fn abort() -> !;
}

/// Nothing may unwind across the C ABI boundary — abort the process on panic.
///
/// `lcs-core` is panic-free on malformed input (the kernel runs the same parsers on
/// untrusted bytes), so a panic here can only mean a genuine internal bug, for which
/// aborting loudly is the correct fail-safe. Gated out of `cfg(test)` builds, where
/// std supplies the panic runtime and test harness.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: `abort` never returns and performs no Rust unwinding.
    unsafe { abort() }
}
