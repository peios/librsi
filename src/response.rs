//! `<rsi/response.h>` — building and sending RSI responses.
//!
//! After handling a request, the source replies on the source fd with a framed
//! response: a 14-byte header (echoing the request id, op-code OR'd with the response
//! bit) + a 4-byte status, then an op-specific payload for the read ops on success.
//! lcs-core has no response builders (only the kernel builds requests), so librsi
//! encodes the frames here from the uapi offsets.
//!
//! Most ops are **status-only** ([`rsi_respond_status`], an 18-byte frame), and every
//! op uses a status-only frame to report a non-OK status. The four read ops carry a
//! payload on success ([`rsi_respond_lookup`], [`rsi_respond_enum_children`],
//! [`rsi_respond_read_key`], [`rsi_respond_query_values`]); the caller supplies the
//! result as flat arrays and librsi heap-encodes the frame. All multi-byte integers
//! are little-endian; names/data are length-prefixed (u32 LE length + bytes).

#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_void};

use alloc::vec::Vec;

use lcs_core::rsi::rsi_response_op_code;
use peios_uapi::{RSI_MIN_RESPONSE_SIZE, RSI_OK};

use crate::abi::try_extend;
use crate::error::set_errno;
use crate::request::rsi_request;

// The status-only frame is exactly the response header (14) + status (4).
const STATUS_FRAME_LEN: usize = 18;
const _: () = assert!(STATUS_FRAME_LEN == RSI_MIN_RESPONSE_SIZE as usize);

/// Write the 14-byte RSI response header into `buf[0..14]`: `total_len` (u32 LE) at 0,
/// `request_id` (u64 LE) at 4, `op_code` (u16 LE) at 12. All little-endian.
fn put_response_header(buf: &mut [u8], total_len: u32, request_id: u64, resp_op: u16) {
    buf[0..4].copy_from_slice(&total_len.to_le_bytes());
    buf[4..12].copy_from_slice(&request_id.to_le_bytes());
    buf[12..14].copy_from_slice(&resp_op.to_le_bytes());
}

/// Write one complete frame to the source fd (one `write` carries one response).
/// Returns 0, or `-1` with the `write(2)` errno.
unsafe fn write_frame(fd: c_int, frame: &[u8]) -> c_int {
    let r = libc::write(fd, frame.as_ptr() as *const c_void, frame.len());
    if r < 0 {
        -1
    } else {
        0
    }
}

// ----------------------------------------------------------------------------
// Status-only responses
// ----------------------------------------------------------------------------

/// Build an 18-byte status-only response frame. Pure and unit-testable.
fn build_status_frame(request_id: u64, resp_op: u16, status: u32) -> [u8; STATUS_FRAME_LEN] {
    let mut frame = [0u8; STATUS_FRAME_LEN];
    put_response_header(&mut frame, STATUS_FRAME_LEN as u32, request_id, resp_op);
    frame[14..18].copy_from_slice(&status.to_le_bytes());
    frame
}

/// `rsi_write_response` - write one pre-built response frame to the source fd.
///
/// Thin wrapper over `write(2)`. Returns the bytes written, or `-1` with `errno`.
/// Most callers should use the higher-level `rsi_respond_*` helpers.
///
/// # Safety
/// `frame` must be valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rsi_write_response(fd: c_int, frame: *const c_void, len: usize) -> isize {
    libc::write(fd, frame, len)
}

/// `rsi_respond_status` - reply to `req` with a status-only response.
///
/// Builds the 18-byte header+status frame (echoing `req->request_id`, op-code =
/// `req->op_code | RSI_RESPONSE_BIT`) and writes it. Use this for the mutating ops on
/// success (`status = RSI_OK`) and for *any* op to report a non-OK `RSI_*` status.
/// Returns 0, or `-1` with `errno` (`EINVAL` on a NULL/bad-op-code `req`, or the
/// `write(2)` error).
///
/// # Safety
/// `req` must be a request decoded by `rsi_parse_request`.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_status(
    fd: c_int,
    req: *const rsi_request,
    status: u32,
) -> c_int {
    let Some(req) = req.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let resp_op = match rsi_response_op_code(req.op_code) {
        Ok(o) => o,
        Err(_) => {
            set_errno(libc::EINVAL);
            return -1;
        }
    };
    let frame = build_status_frame(req.request_id, resp_op, status);
    write_frame(fd, &frame)
}

// ----------------------------------------------------------------------------
// Payload responses (the four read ops, on success). The caller passes the result
// as flat arrays; librsi heap-encodes the frame, writes it, and frees.
// ----------------------------------------------------------------------------

/// A fallible little-endian frame writer over a heap buffer. Sticky-OOM: a failed
/// allocation latches `oom`, checked once at finish (→ `ENOMEM`), never aborting.
struct FrameWriter {
    buf: Vec<u8>,
    oom: bool,
}

impl FrameWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            oom: false,
        }
    }

    fn raw(&mut self, b: &[u8]) {
        if !self.oom && try_extend(&mut self.buf, b).is_err() {
            self.oom = true;
        }
    }

    fn u8(&mut self, x: u8) {
        self.raw(&[x]);
    }
    fn u32(&mut self, x: u32) {
        self.raw(&x.to_le_bytes());
    }
    fn u64(&mut self, x: u64) {
        self.raw(&x.to_le_bytes());
    }
    fn guid(&mut self, g: &[u8; 16]) {
        self.raw(g);
    }

    /// A length-prefixed field: u32 LE length + bytes.
    ///
    /// # Safety
    /// `ptr` must be valid for `len` bytes when `len != 0`.
    unsafe fn lpf(&mut self, ptr: *const c_void, len: u32) {
        self.u32(len);
        if len != 0 {
            self.raw(core::slice::from_raw_parts(ptr as *const u8, len as usize));
        }
    }
}

/// A fresh writer pre-loaded with an 18-byte header+status placeholder (back-patched
/// by [`finish_response`]).
fn new_writer() -> FrameWriter {
    let mut w = FrameWriter::new();
    w.raw(&[0u8; STATUS_FRAME_LEN]);
    w
}

/// Back-patch the header (`total_len`, `request_id`, response op-code) and the `RSI_OK`
/// status onto an assembled payload. `Err` on a bad op-code (`EINVAL`) or OOM
/// (`ENOMEM`).
fn finish_response(req: &rsi_request, mut w: FrameWriter) -> Result<Vec<u8>, c_int> {
    let resp_op = rsi_response_op_code(req.op_code).map_err(|_| libc::EINVAL)?;
    if w.oom {
        return Err(libc::ENOMEM);
    }
    let total = w.buf.len() as u32;
    put_response_header(&mut w.buf, total, req.request_id, resp_op);
    w.buf[14..18].copy_from_slice(&RSI_OK.to_le_bytes());
    Ok(w.buf)
}

/// Finish the frame and write it, mapping a build error to `errno`.
unsafe fn finish_and_send(fd: c_int, req: &rsi_request, w: FrameWriter) -> c_int {
    match finish_response(req, w) {
        Ok(frame) => write_frame(fd, &frame),
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

/// One resolved path entry: a layer's view of a child (LOOKUP, ENUM_CHILDREN).
#[repr(C)]
pub struct rsi_path_entry {
    pub layer: *const c_void,
    pub layer_len: u32,
    /// `RSI_PATH_TARGET_GUID` (0) or `RSI_PATH_TARGET_HIDDEN` (1).
    pub target_type: u8,
    pub target_guid: [u8; 16],
    pub sequence: u64,
}

/// One key's non-layered metadata, returned alongside LOOKUP / ENUM_CHILDREN.
#[repr(C)]
pub struct rsi_key_metadata {
    pub guid: [u8; 16],
    pub sd: *const c_void,
    pub sd_len: u32,
    pub volatile_key: u8,
    pub symlink: u8,
    pub last_write_time: u64,
}

/// A `[count][entries...]` block of path entries.
unsafe fn encode_path_entry_block(w: &mut FrameWriter, entries: *const rsi_path_entry, count: u32) {
    w.u32(count);
    for i in 0..count as usize {
        let e = &*entries.add(i);
        w.lpf(e.layer, e.layer_len);
        w.u8(e.target_type);
        w.guid(&e.target_guid);
        w.u64(e.sequence);
    }
}

/// A `[count][metadata...]` block of key-metadata entries.
unsafe fn encode_metadata_block(
    w: &mut FrameWriter,
    metadata: *const rsi_key_metadata,
    count: u32,
) {
    w.u32(count);
    for i in 0..count as usize {
        let m = &*metadata.add(i);
        w.guid(&m.guid);
        w.lpf(m.sd, m.sd_len);
        w.u8(m.volatile_key);
        w.u8(m.symlink);
        w.u64(m.last_write_time);
    }
}

/// `rsi_respond_lookup` - LOOKUP success: the path `entries` for the looked-up child
/// plus the `metadata` for each referenced key.
///
/// # Safety
/// `req` decoded by `rsi_parse_request`; `entries`/`metadata` valid arrays of their
/// counts, with each borrowed `layer`/`sd` valid for its length.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_lookup(
    fd: c_int,
    req: *const rsi_request,
    entries: *const rsi_path_entry,
    entry_count: u32,
    metadata: *const rsi_key_metadata,
    metadata_count: u32,
) -> c_int {
    let Some(req) = req.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let mut w = new_writer();
    encode_path_entry_block(&mut w, entries, entry_count);
    encode_metadata_block(&mut w, metadata, metadata_count);
    finish_and_send(fd, req, w)
}

/// One enumerated child: its name and the path entries that resolve it.
#[repr(C)]
pub struct rsi_child_entry {
    pub child_name: *const c_void,
    pub child_name_len: u32,
    pub entries: *const rsi_path_entry,
    pub entry_count: u32,
}

/// `rsi_respond_enum_children` - ENUM_CHILDREN success: each child with its path
/// entries, plus the `metadata` for each referenced key.
///
/// # Safety
/// `req` decoded by `rsi_parse_request`; `children`/`metadata` valid arrays of their
/// counts, each `rsi_child_entry.entries` a valid array of `entry_count`.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_enum_children(
    fd: c_int,
    req: *const rsi_request,
    children: *const rsi_child_entry,
    child_count: u32,
    metadata: *const rsi_key_metadata,
    metadata_count: u32,
) -> c_int {
    let Some(req) = req.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let mut w = new_writer();
    w.u32(child_count);
    for i in 0..child_count as usize {
        let c = &*children.add(i);
        w.lpf(c.child_name, c.child_name_len);
        encode_path_entry_block(&mut w, c.entries, c.entry_count);
    }
    encode_metadata_block(&mut w, metadata, metadata_count);
    finish_and_send(fd, req, w)
}

/// `rsi_respond_read_key` - READ_KEY success: the key's non-layered metadata.
///
/// # Safety
/// `req` decoded by `rsi_parse_request`; `name` valid for `name_len`, `sd` for
/// `sd_len`, `parent_guid` for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_read_key(
    fd: c_int,
    req: *const rsi_request,
    name: *const c_void,
    name_len: u32,
    parent_guid: *const u8,
    sd: *const c_void,
    sd_len: u32,
    volatile_key: u8,
    symlink: u8,
    last_write_time: u64,
) -> c_int {
    let Some(req) = req.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let mut w = new_writer();
    w.lpf(name, name_len);
    w.raw(core::slice::from_raw_parts(parent_guid, 16));
    w.lpf(sd, sd_len);
    w.u8(volatile_key);
    w.u8(symlink);
    w.u64(last_write_time);
    finish_and_send(fd, req, w)
}

/// One effective value entry (QUERY_VALUES).
#[repr(C)]
pub struct rsi_value_entry {
    pub value_name: *const c_void,
    pub value_name_len: u32,
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
    pub value_type: u32,
    pub data: *const c_void,
    pub data_len: u32,
    pub sequence: u64,
}

/// One blanket-tombstone entry (QUERY_VALUES).
#[repr(C)]
pub struct rsi_blanket_entry {
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
    pub sequence: u64,
}

/// `rsi_respond_query_values` - QUERY_VALUES success: the value `entries` plus the
/// `blankets` (blanket tombstones).
///
/// # Safety
/// `req` decoded by `rsi_parse_request`; `entries`/`blankets` valid arrays of their
/// counts, with each borrowed name/data valid for its length.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_query_values(
    fd: c_int,
    req: *const rsi_request,
    entries: *const rsi_value_entry,
    entry_count: u32,
    blankets: *const rsi_blanket_entry,
    blanket_count: u32,
) -> c_int {
    let Some(req) = req.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let mut w = new_writer();
    w.u32(entry_count);
    for i in 0..entry_count as usize {
        let e = &*entries.add(i);
        w.lpf(e.value_name, e.value_name_len);
        w.lpf(e.layer_name, e.layer_name_len);
        w.u32(e.value_type);
        w.lpf(e.data, e.data_len);
        w.u64(e.sequence);
    }
    w.u32(blanket_count);
    for i in 0..blanket_count as usize {
        let b = &*blankets.add(i);
        w.lpf(b.layer_name, b.layer_name_len);
        w.u64(b.sequence);
    }
    finish_and_send(fd, req, w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lcs_core::rsi::{
        parse_rsi_lookup_success_response_payload, parse_rsi_read_key_success_response_payload,
        write_rsi_lookup_request_frame, write_rsi_read_key_request_frame, RSI_PATH_TARGET_GUID,
    };
    use peios_uapi::{RSI_LOOKUP, RSI_READ_KEY, RSI_RESPONSE_BIT};

    fn fake_request(op_code: u32, request_id: u64) -> rsi_request {
        rsi_request {
            request_id,
            txn_id: 0,
            payload: core::ptr::null(),
            payload_len: 0,
            op_code: op_code as u16,
        }
    }

    #[test]
    fn status_frame_layout() {
        let resp_op = (RSI_LOOKUP | RSI_RESPONSE_BIT) as u16;
        let f = build_status_frame(0x1122_3344_5566_7788, resp_op, RSI_OK);
        assert_eq!(u32::from_le_bytes(f[0..4].try_into().unwrap()), 18);
        assert_eq!(
            u64::from_le_bytes(f[4..12].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        assert_eq!(u16::from_le_bytes(f[12..14].try_into().unwrap()), resp_op);
        assert_eq!(u32::from_le_bytes(f[14..18].try_into().unwrap()), RSI_OK);
    }

    // The strongest check: encode a response, then parse it with the *kernel's own*
    // response parser (validating the header against the matching request) — a
    // success proves the source produced a kernel-acceptable frame.

    #[test]
    fn read_key_response_roundtrips() {
        let mut reqbuf = [0u8; 64];
        let built = write_rsi_read_key_request_frame(&mut reqbuf, 7, 0, [0x55; 16]).unwrap();
        let req = fake_request(RSI_READ_KEY, 7);

        let frame = unsafe {
            let mut w = new_writer();
            let name = b"App";
            let sd = [0xAAu8; 8];
            let parent = [0x33u8; 16];
            w.lpf(name.as_ptr() as *const c_void, name.len() as u32);
            w.raw(&parent);
            w.lpf(sd.as_ptr() as *const c_void, sd.len() as u32);
            w.u8(1); // volatile
            w.u8(0); // symlink
            w.u64(0xDEAD_BEEF);
            finish_response(&req, w).unwrap()
        };

        let parsed = parse_rsi_read_key_success_response_payload(&frame, built.retained).unwrap();
        assert_eq!(parsed.name.data, b"App");
        assert_eq!(parsed.parent_guid, [0x33; 16]);
        assert_eq!(parsed.sd.data, &[0xAA; 8]);
        assert!(parsed.volatile);
        assert!(!parsed.symlink);
        assert_eq!(parsed.last_write_time, 0xDEAD_BEEF);
    }

    #[test]
    fn lookup_response_roundtrips() {
        let mut reqbuf = [0u8; 128];
        let built =
            write_rsi_lookup_request_frame(&mut reqbuf, 11, 0, [0x01; 16], b"Software").unwrap();
        let req = fake_request(RSI_LOOKUP, 11);

        // Two path entries (one base layer, one overlay), one metadata record.
        let base = b"base";
        let overlay = b"overlay";
        let entries = [
            rsi_path_entry {
                layer: base.as_ptr() as *const c_void,
                layer_len: base.len() as u32,
                target_type: RSI_PATH_TARGET_GUID,
                target_guid: [0x10; 16],
                sequence: 100,
            },
            rsi_path_entry {
                layer: overlay.as_ptr() as *const c_void,
                layer_len: overlay.len() as u32,
                target_type: RSI_PATH_TARGET_GUID,
                target_guid: [0x20; 16],
                sequence: 200,
            },
        ];
        let sd = [0x77u8; 4];
        let metadata = [rsi_key_metadata {
            guid: [0x20; 16],
            sd: sd.as_ptr() as *const c_void,
            sd_len: sd.len() as u32,
            volatile_key: 0,
            symlink: 0,
            last_write_time: 42,
        }];

        let frame = unsafe {
            let mut w = new_writer();
            encode_path_entry_block(&mut w, entries.as_ptr(), entries.len() as u32);
            encode_metadata_block(&mut w, metadata.as_ptr(), metadata.len() as u32);
            finish_response(&req, w).unwrap()
        };

        let parsed = parse_rsi_lookup_success_response_payload(&frame, built.retained).unwrap();
        assert_eq!(parsed.entry_count, 2);
        assert_eq!(parsed.metadata_count, 1);
    }

    #[test]
    fn oom_is_not_aborted_path() {
        // A well-formed empty LOOKUP (zero entries) still produces a valid frame.
        let req = fake_request(RSI_LOOKUP, 1);
        let frame = unsafe {
            let mut w = new_writer();
            encode_path_entry_block(&mut w, core::ptr::null(), 0);
            encode_metadata_block(&mut w, core::ptr::null(), 0);
            finish_response(&req, w).unwrap()
        };
        // header(14) + status(4) + entry_count(4) + metadata_count(4) = 26 bytes.
        assert_eq!(frame.len(), 26);
    }
}
