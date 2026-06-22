//! `<rsi/source.h>` — becoming a registry source.
//!
//! [`rsi_register`] is the entry point: it opens `/dev/pkm_registry` and registers
//! the hives this process backs in one call, returning the **source fd**. From then
//! on the source serves the RSI protocol on that fd — `read(2)` dequeues one framed
//! request, `write(2)` sends one framed response (those land in sibling modules).
//!
//! Registration requires `SeTcbPrivilege`; the marshalling here is pure and
//! unit-testable, while the `open`/`ioctl` themselves are exercised live under
//! Provium.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_ulong, c_void};

use alloc::vec::Vec;

use peios_uapi::{reg_src_hive_entry, reg_src_register_args, REG_SRC_REGISTER};

use crate::error::{get_errno, set_errno};
use crate::sys::ioctl;

// The uapi argument structs are the wire format verbatim; pin their sizes so a
// layout change is caught here rather than sent to the kernel as a wrong-length
// struct or a wrong per-entry stride.
const _: () = assert!(core::mem::size_of::<reg_src_register_args>() == 24);
const _: () = assert!(core::mem::size_of::<reg_src_hive_entry>() == 56);

/// `/dev/pkm_registry`, NUL-terminated for `open(2)`. PSD-005 requires sources to
/// obtain their RSI fd through this device.
const DEVICE: &[u8] = b"/dev/pkm_registry\0";

/// One hive this source backs. Mirrors `struct rsi_hive`.
#[repr(C)]
pub struct rsi_hive {
    /// Hive name (not NUL-terminated).
    pub name: *const c_void,
    /// Length of `name` in bytes.
    pub name_len: u32,
    /// `RSI_HIVE_PRIVATE` for a private hive, or 0 for a global hive.
    pub flags: u32,
    /// Root key GUID (16 bytes).
    pub root_guid: [u8; 16],
    /// Scope GUID for a private hive; zero for a global hive.
    pub scope_guid: [u8; 16],
}

/// Marshal a caller `rsi_hive` into the wire `reg_src_hive_entry`. Pure: copies the
/// name pointer/length, GUIDs, and flags; the `_pad*` fields stay zero (the kernel
/// rejects a non-zero pad).
fn marshal_hive(h: &rsi_hive) -> reg_src_hive_entry {
    reg_src_hive_entry {
        name_len: h.name_len,
        name_ptr: h.name as usize as u64,
        root_guid: h.root_guid,
        flags: h.flags,
        scope_guid: h.scope_guid,
        ..Default::default()
    }
}

/// `rsi_register` — become a registry source backing `hives`.
///
/// Opens `/dev/pkm_registry` and registers all `count` hives in one call. Requires
/// `SeTcbPrivilege`. `max_sequence` is the highest sequence number this source has
/// already persisted (the kernel resumes its global counter past it). Returns the
/// source fd — `read(2)` RSI requests and `write(2)` responses on it — or `-1` with
/// `errno`, including `EPERM` without privilege, `EINVAL`, `ENOSPC`, `ENOMEM`,
/// `EFAULT`, or any `/dev/pkm_registry` `open(2)` error.
/// librsi rejects zero hives; the kernel enforces its configured maximum hive count.
///
/// # Safety
/// `hives` must point to `count` valid `rsi_hive`s, each `name` valid for `name_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn rsi_register(
    hives: *const rsi_hive,
    count: u32,
    max_sequence: u64,
) -> c_int {
    if count == 0 || hives.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    // Marshal the caller's hives into a contiguous wire array (the kernel reads
    // `count` entries from `hives_ptr`). Fallible allocation — never abort on OOM.
    let mut entries: Vec<reg_src_hive_entry> = Vec::new();
    if entries.try_reserve(count as usize).is_err() {
        set_errno(libc::ENOMEM);
        return -1;
    }
    for i in 0..count as usize {
        entries.push(marshal_hive(&*hives.add(i)));
    }
    let mut args = reg_src_register_args {
        hive_count: count,
        max_sequence,
        hives_ptr: entries.as_ptr() as usize as u64,
        ..Default::default()
    };

    let fd = libc::open(
        DEVICE.as_ptr() as *const c_char,
        libc::O_RDWR | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return -1; // errno set by open(2)
    }
    let r = ioctl(
        fd,
        REG_SRC_REGISTER as c_ulong,
        &mut args as *mut reg_src_register_args as *mut c_void,
    );
    if r < 0 {
        // Preserve the registration errno across the cleanup close().
        let err = get_errno();
        libc::close(fd);
        set_errno(err);
        return -1;
    }
    fd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_pinned() {
        assert_eq!(core::mem::size_of::<reg_src_register_args>(), 24);
        assert_eq!(core::mem::size_of::<reg_src_hive_entry>(), 56);
    }

    #[test]
    fn marshal_hive_packs_fields() {
        let name = b"Machine";
        let root = [0x11u8; 16];
        let scope = [0x22u8; 16];
        let h = rsi_hive {
            name: name.as_ptr() as *const c_void,
            name_len: name.len() as u32,
            flags: peios_uapi::RSI_HIVE_PRIVATE,
            root_guid: root,
            scope_guid: scope,
        };
        let e = marshal_hive(&h);
        assert_eq!(e.name_len, 7);
        assert_eq!(e.name_ptr, name.as_ptr() as usize as u64);
        assert_eq!(e.flags, peios_uapi::RSI_HIVE_PRIVATE);
        assert_eq!(e.root_guid, root);
        assert_eq!(e.scope_guid, scope);
        // Padding must stay zero — the kernel rejects a non-zero pad.
        assert_eq!(e._pad0, 0);
        assert_eq!(e._pad1, 0);
    }

    #[test]
    fn marshal_hive_global_is_zero_scope() {
        let name = b"Users";
        let h = rsi_hive {
            name: name.as_ptr() as *const c_void,
            name_len: name.len() as u32,
            flags: 0,
            root_guid: [1u8; 16],
            scope_guid: [0u8; 16],
        };
        let e = marshal_hive(&h);
        assert_eq!(e.flags, 0);
        assert_eq!(e.scope_guid, [0u8; 16]);
    }

    #[test]
    fn register_rejects_zero_hives() {
        use crate::error::get_errno;

        let r = unsafe { rsi_register(core::ptr::null(), 0, 0) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }
}
