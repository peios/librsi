//! `<rsi/request.h>` — receiving and decoding RSI requests.
//!
//! A source's serve loop reads one framed request at a time from its source fd
//! ([`rsi_read_request`]), splits the header from the payload
//! ([`rsi_parse_request`] → op-code / request id / transaction id), then decodes the
//! op-specific payload with the matching `rsi_request_*` parser. The decoders are
//! thin wrappers over `lcs-core`'s own request parsers — the exact code the kernel
//! validates against — so the wire handling is guaranteed compatible. Every decoded
//! name/data field **borrows** into the caller's frame buffer (no copies): the
//! pointers are valid only until that buffer is reused.

#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_void};

use lcs_core::rsi::{
    parse_rsi_abort_transaction_request_payload, parse_rsi_begin_transaction_request_payload,
    parse_rsi_commit_transaction_request_payload, parse_rsi_create_entry_request_payload,
    parse_rsi_create_key_request_payload, parse_rsi_delete_entry_request_payload,
    parse_rsi_delete_layer_request_payload, parse_rsi_delete_value_entry_request_payload,
    parse_rsi_drop_key_request_payload, parse_rsi_enum_children_request_payload,
    parse_rsi_flush_request_payload, parse_rsi_hide_entry_request_payload,
    parse_rsi_lookup_request_payload, parse_rsi_query_values_request_payload,
    parse_rsi_read_key_request_payload, parse_rsi_request_header,
    parse_rsi_set_blanket_tombstone_request_payload, parse_rsi_set_value_request_payload,
    parse_rsi_write_key_request_payload, RsiLengthPrefixedField,
};

use peios_uapi::{
    RSI_ABORT_TRANSACTION, RSI_BEGIN_TRANSACTION, RSI_COMMIT_TRANSACTION, RSI_CREATE_ENTRY,
    RSI_CREATE_KEY, RSI_DELETE_ENTRY, RSI_DELETE_LAYER, RSI_DELETE_VALUE_ENTRY, RSI_DROP_KEY,
    RSI_ENUM_CHILDREN, RSI_FLUSH, RSI_HIDE_ENTRY, RSI_LOOKUP, RSI_QUERY_VALUES, RSI_READ_KEY,
    RSI_REQUEST_HEADER_SIZE, RSI_SET_BLANKET_TOMBSTONE, RSI_SET_VALUE, RSI_WRITE_KEY,
};

use crate::error::set_errno;

// ----------------------------------------------------------------------------
// Shared plumbing
// ----------------------------------------------------------------------------

/// Borrow a request's payload bytes (the frame past the 22-byte header), after
/// verifying the caller used the decoder that matches the parsed op code.
///
/// # Safety
/// `req` must be NULL or a valid `rsi_request`; when `payload_len != 0`, `payload`
/// must be valid for `payload_len` bytes.
unsafe fn req_payload_for<'a>(
    req: *const rsi_request,
    expected_op: u32,
) -> Result<&'a [u8], c_int> {
    let Some(req) = req.as_ref() else {
        return Err(libc::EINVAL);
    };
    if req.op_code != expected_op as u16 {
        return Err(libc::EINVAL);
    }
    if req.payload.is_null() {
        if req.payload_len == 0 {
            return Ok(&[]);
        }
        return Err(libc::EINVAL);
    }
    Ok(core::slice::from_raw_parts(
        req.payload as *const u8,
        req.payload_len as usize,
    ))
}

macro_rules! req_payload_and_out {
    ($req:expr, $out:expr, $expected_op:expr) => {{
        let p = match req_payload_for($req, $expected_op) {
            Ok(p) => p,
            Err(e) => return fail_errno(e),
        };
        let Some(out) = $out.as_mut() else {
            return einval();
        };
        (p, out)
    }};
}

/// A length-prefixed field as a C `(ptr, len)` borrowing the frame buffer.
fn lpf(f: &RsiLengthPrefixedField) -> (*const c_void, u32) {
    (f.data.as_ptr() as *const c_void, f.data.len() as u32)
}

/// Set `errno = EBADMSG` (a malformed frame) and return the `-1` sentinel.
fn bad_msg() -> c_int {
    fail_errno(libc::EBADMSG)
}

/// `EINVAL` sentinel for a NULL arg, forged request, or op/helper mismatch.
fn einval() -> c_int {
    fail_errno(libc::EINVAL)
}

fn fail_errno(e: c_int) -> c_int {
    set_errno(e);
    -1
}

// ----------------------------------------------------------------------------
// Frame header
// ----------------------------------------------------------------------------

/// A received RSI request: the kernel-stamped header plus a borrowed view of the
/// op-specific payload. Mirrors `struct rsi_request`. Dispatch on `op_code` (one of
/// `RSI_LOOKUP` … from `<pkm/lcs.h>`) and call the matching `rsi_request_*` decoder.
#[repr(C)]
pub struct rsi_request {
    /// The kernel's unique request id — echo it in the response.
    pub request_id: u64,
    /// Transaction id (0 outside a transaction).
    pub txn_id: u64,
    /// Borrowed payload (frame past the header); valid until the frame is reused.
    pub payload: *const c_void,
    /// Payload length in bytes.
    pub payload_len: u32,
    /// `RSI_LOOKUP`, `RSI_SET_VALUE`, … — the request kind to dispatch on.
    pub op_code: u16,
}

/// `rsi_read_request` — read one framed RSI request from the source fd.
///
/// Thin wrapper over `read(2)`: blocks until a request is queued, then returns the
/// frame length (pass it to [`rsi_parse_request`]). Returns 0 at EOF (the source is
/// closing), or `-1` with `errno` — notably `EMSGSIZE` if `cap` is smaller than the
/// pending frame (size the buffer for the largest possible request to avoid it).
///
/// # Safety
/// `buf` must be valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn rsi_read_request(
    fd: c_int,
    buf: *mut c_void,
    cap: usize,
) -> libc::ssize_t {
    libc::read(fd, buf, cap)
}

/// `rsi_parse_request` — split a framed request into its header and payload view.
///
/// Validates the 22-byte RSI request header and fills `*out` with the request id,
/// transaction id, op-code, and a borrowed pointer to the op-specific payload.
/// Returns 0, or `-1` with `errno` (`EINVAL` on NULL args, `EBADMSG` on a malformed
/// frame).
///
/// # Safety
/// `frame` must be valid for `len` bytes; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_parse_request(
    frame: *const c_void,
    len: usize,
    out: *mut rsi_request,
) -> c_int {
    let Some(out) = out.as_mut() else {
        return einval();
    };
    if frame.is_null() {
        return einval();
    }
    let frame_slice = core::slice::from_raw_parts(frame as *const u8, len);
    // `parse_rsi_request_header` already enforces `len >= RSI_REQUEST_HEADER_SIZE`
    // and a known op-code, so the subtraction below cannot underflow.
    match parse_rsi_request_header(frame_slice) {
        Ok(h) => {
            let hdr = RSI_REQUEST_HEADER_SIZE as usize;
            out.request_id = h.request_id;
            out.txn_id = h.txn_id;
            out.op_code = h.op_code;
            out.payload = frame.cast::<u8>().add(hdr) as *const c_void;
            out.payload_len = (len - hdr) as u32;
            0
        }
        Err(_) => bad_msg(),
    }
}

// ----------------------------------------------------------------------------
// Per-op decoders. Each calls the lcs-core parser and copies the result into a
// flat C struct (GUIDs by value; names/data as borrowed (ptr, len) pairs).
// ----------------------------------------------------------------------------

/// LOOKUP: is `child_name` visible under `parent_guid`?
#[repr(C)]
pub struct rsi_lookup {
    pub parent_guid: [u8; 16],
    pub child_name: *const c_void,
    pub child_name_len: u32,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_lookup(
    req: *const rsi_request,
    out: *mut rsi_lookup,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_LOOKUP);
    match parse_rsi_lookup_request_payload(p) {
        Ok(v) => {
            out.parent_guid = v.parent_guid;
            (out.child_name, out.child_name_len) = lpf(&v.child_name);
            0
        }
        Err(_) => bad_msg(),
    }
}

/// CREATE_ENTRY: bind `child_name` → `child_guid` in `layer_name`.
#[repr(C)]
pub struct rsi_create_entry {
    pub parent_guid: [u8; 16],
    pub child_guid: [u8; 16],
    pub child_name: *const c_void,
    pub child_name_len: u32,
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
    pub sequence: u64,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_create_entry(
    req: *const rsi_request,
    out: *mut rsi_create_entry,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_CREATE_ENTRY);
    match parse_rsi_create_entry_request_payload(p) {
        Ok(v) => {
            out.parent_guid = v.parent_guid;
            out.child_guid = v.child_guid;
            (out.child_name, out.child_name_len) = lpf(&v.child_name);
            (out.layer_name, out.layer_name_len) = lpf(&v.layer_name);
            out.sequence = v.sequence;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// HIDE_ENTRY: tombstone `child_name` in `layer_name`.
#[repr(C)]
pub struct rsi_hide_entry {
    pub parent_guid: [u8; 16],
    pub child_name: *const c_void,
    pub child_name_len: u32,
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
    pub sequence: u64,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_hide_entry(
    req: *const rsi_request,
    out: *mut rsi_hide_entry,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_HIDE_ENTRY);
    match parse_rsi_hide_entry_request_payload(p) {
        Ok(v) => {
            out.parent_guid = v.parent_guid;
            (out.child_name, out.child_name_len) = lpf(&v.child_name);
            (out.layer_name, out.layer_name_len) = lpf(&v.layer_name);
            out.sequence = v.sequence;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// DELETE_ENTRY: remove `child_name`'s entry in `layer_name`.
#[repr(C)]
pub struct rsi_delete_entry {
    pub parent_guid: [u8; 16],
    pub child_name: *const c_void,
    pub child_name_len: u32,
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_delete_entry(
    req: *const rsi_request,
    out: *mut rsi_delete_entry,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_DELETE_ENTRY);
    match parse_rsi_delete_entry_request_payload(p) {
        Ok(v) => {
            out.parent_guid = v.parent_guid;
            (out.child_name, out.child_name_len) = lpf(&v.child_name);
            (out.layer_name, out.layer_name_len) = lpf(&v.layer_name);
            0
        }
        Err(_) => bad_msg(),
    }
}

/// ENUM_CHILDREN: list the children of `parent_guid`.
#[repr(C)]
pub struct rsi_enum_children {
    pub parent_guid: [u8; 16],
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_enum_children(
    req: *const rsi_request,
    out: *mut rsi_enum_children,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_ENUM_CHILDREN);
    match parse_rsi_enum_children_request_payload(p) {
        Ok(v) => {
            out.parent_guid = v.parent_guid;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// CREATE_KEY: create the key metadata record `guid` under `parent_guid`.
#[repr(C)]
pub struct rsi_create_key {
    pub guid: [u8; 16],
    pub parent_guid: [u8; 16],
    pub name: *const c_void,
    pub name_len: u32,
    pub sd: *const c_void,
    pub sd_len: u32,
    /// 1 if the key is volatile.
    pub volatile_key: u8,
    /// 1 if the key is a symlink.
    pub symlink: u8,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_create_key(
    req: *const rsi_request,
    out: *mut rsi_create_key,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_CREATE_KEY);
    match parse_rsi_create_key_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            out.parent_guid = v.parent_guid;
            (out.name, out.name_len) = lpf(&v.name);
            (out.sd, out.sd_len) = lpf(&v.sd);
            out.volatile_key = v.volatile as u8;
            out.symlink = v.symlink as u8;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// A request carrying just a key GUID (READ_KEY, DROP_KEY).
#[repr(C)]
pub struct rsi_key_guid {
    pub guid: [u8; 16],
}

/// READ_KEY: read the metadata for `guid`.
///
/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_read_key(
    req: *const rsi_request,
    out: *mut rsi_key_guid,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_READ_KEY);
    match parse_rsi_read_key_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// DROP_KEY: purge all data for the orphaned key `guid`.
///
/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_drop_key(
    req: *const rsi_request,
    out: *mut rsi_key_guid,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_DROP_KEY);
    match parse_rsi_drop_key_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// WRITE_KEY: update the mutable fields of `guid` named by `field_mask`.
#[repr(C)]
pub struct rsi_write_key {
    pub guid: [u8; 16],
    /// `RSI_WRITE_KEY_FIELD_SD` | `RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME` — which
    /// fields below are valid.
    pub field_mask: u32,
    /// New security descriptor; NULL when the SD bit is clear in `field_mask`.
    pub sd: *const c_void,
    pub sd_len: u32,
    /// New last-write time; valid only when the time bit is set in `field_mask`.
    pub last_write_time: u64,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_write_key(
    req: *const rsi_request,
    out: *mut rsi_write_key,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_WRITE_KEY);
    match parse_rsi_write_key_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            out.field_mask = v.field_mask;
            match v.sd {
                Some(f) => (out.sd, out.sd_len) = lpf(&f),
                None => {
                    out.sd = core::ptr::null();
                    out.sd_len = 0;
                }
            }
            out.last_write_time = v.last_write_time.unwrap_or(0);
            0
        }
        Err(_) => bad_msg(),
    }
}

/// QUERY_VALUES: read `value_name` (or all values when `query_all`) of `guid`.
#[repr(C)]
pub struct rsi_query_values {
    pub guid: [u8; 16],
    pub value_name: *const c_void,
    pub value_name_len: u32,
    /// 1 to request every value of the key (then `value_name` is ignored).
    pub query_all: u8,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_query_values(
    req: *const rsi_request,
    out: *mut rsi_query_values,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_QUERY_VALUES);
    match parse_rsi_query_values_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            (out.value_name, out.value_name_len) = lpf(&v.value_name);
            out.query_all = v.query_all as u8;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// SET_VALUE: store `value_name` in `layer_name` with the given type/data.
#[repr(C)]
pub struct rsi_set_value {
    pub guid: [u8; 16],
    pub value_name: *const c_void,
    pub value_name_len: u32,
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
    pub value_type: u32,
    pub data: *const c_void,
    pub data_len: u32,
    pub sequence: u64,
    /// Compare-and-swap guard (0 disables it).
    pub expected_sequence: u64,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_set_value(
    req: *const rsi_request,
    out: *mut rsi_set_value,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_SET_VALUE);
    match parse_rsi_set_value_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            (out.value_name, out.value_name_len) = lpf(&v.value_name);
            (out.layer_name, out.layer_name_len) = lpf(&v.layer_name);
            out.value_type = v.value_type;
            (out.data, out.data_len) = lpf(&v.data);
            out.sequence = v.sequence;
            out.expected_sequence = v.expected_sequence;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// DELETE_VALUE_ENTRY: remove `value_name`'s entry in `layer_name`.
#[repr(C)]
pub struct rsi_delete_value_entry {
    pub guid: [u8; 16],
    pub value_name: *const c_void,
    pub value_name_len: u32,
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_delete_value_entry(
    req: *const rsi_request,
    out: *mut rsi_delete_value_entry,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_DELETE_VALUE_ENTRY);
    match parse_rsi_delete_value_entry_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            (out.value_name, out.value_name_len) = lpf(&v.value_name);
            (out.layer_name, out.layer_name_len) = lpf(&v.layer_name);
            0
        }
        Err(_) => bad_msg(),
    }
}

/// SET_BLANKET_TOMBSTONE: set (`set`) or clear a blanket tombstone on `layer_name`.
#[repr(C)]
pub struct rsi_set_blanket_tombstone {
    pub guid: [u8; 16],
    pub layer_name: *const c_void,
    pub layer_name_len: u32,
    /// 1 to set the tombstone, 0 to clear it.
    pub set: u8,
    pub sequence: u64,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_set_blanket_tombstone(
    req: *const rsi_request,
    out: *mut rsi_set_blanket_tombstone,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_SET_BLANKET_TOMBSTONE);
    match parse_rsi_set_blanket_tombstone_request_payload(p) {
        Ok(v) => {
            out.guid = v.guid;
            (out.layer_name, out.layer_name_len) = lpf(&v.layer_name);
            out.set = v.set as u8;
            out.sequence = v.sequence;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// BEGIN_TRANSACTION: open transaction `transaction_id` in `mode`.
#[repr(C)]
pub struct rsi_begin_transaction {
    pub transaction_id: u64,
    /// `RSI_TXN_READ_WRITE` (0) or `RSI_TXN_READ_ONLY` (1).
    pub mode: u32,
}

/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_begin_transaction(
    req: *const rsi_request,
    out: *mut rsi_begin_transaction,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_BEGIN_TRANSACTION);
    match parse_rsi_begin_transaction_request_payload(p) {
        Ok(v) => {
            out.transaction_id = v.transaction_id;
            out.mode = v.mode.code();
            0
        }
        Err(_) => bad_msg(),
    }
}

/// A request carrying just a transaction id (COMMIT, ABORT).
#[repr(C)]
pub struct rsi_transaction {
    pub transaction_id: u64,
}

/// COMMIT_TRANSACTION: commit `transaction_id`.
///
/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_commit_transaction(
    req: *const rsi_request,
    out: *mut rsi_transaction,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_COMMIT_TRANSACTION);
    match parse_rsi_commit_transaction_request_payload(p) {
        Ok(v) => {
            out.transaction_id = v.transaction_id;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// ABORT_TRANSACTION: roll back `transaction_id`.
///
/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_abort_transaction(
    req: *const rsi_request,
    out: *mut rsi_transaction,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_ABORT_TRANSACTION);
    match parse_rsi_abort_transaction_request_payload(p) {
        Ok(v) => {
            out.transaction_id = v.transaction_id;
            0
        }
        Err(_) => bad_msg(),
    }
}

/// A request carrying just a length-prefixed name (DELETE_LAYER, FLUSH).
#[repr(C)]
pub struct rsi_name {
    pub name: *const c_void,
    pub name_len: u32,
}

/// DELETE_LAYER: remove every entry tagged with `name`.
///
/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_delete_layer(
    req: *const rsi_request,
    out: *mut rsi_name,
) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_DELETE_LAYER);
    match parse_rsi_delete_layer_request_payload(p) {
        Ok(v) => {
            (out.name, out.name_len) = lpf(&v.layer_name);
            0
        }
        Err(_) => bad_msg(),
    }
}

/// FLUSH: persist pending writes for the hive `name`.
///
/// # Safety
/// `req` from [`rsi_parse_request`]; `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn rsi_request_flush(req: *const rsi_request, out: *mut rsi_name) -> c_int {
    let (p, out) = req_payload_and_out!(req, out, RSI_FLUSH);
    match parse_rsi_flush_request_payload(p) {
        Ok(v) => {
            (out.name, out.name_len) = lpf(&v.hive_name);
            0
        }
        Err(_) => bad_msg(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lcs_core::rsi::{
        write_rsi_abort_transaction_request_frame, write_rsi_begin_transaction_request_frame,
        write_rsi_commit_transaction_request_frame, write_rsi_create_entry_request_frame,
        write_rsi_create_key_request_frame, write_rsi_delete_entry_request_frame,
        write_rsi_delete_layer_request_frame, write_rsi_delete_value_entry_request_frame,
        write_rsi_drop_key_request_frame, write_rsi_enum_children_request_frame,
        write_rsi_flush_request_frame, write_rsi_hide_entry_request_frame,
        write_rsi_lookup_request_frame, write_rsi_query_values_request_frame,
        write_rsi_read_key_request_frame, write_rsi_set_blanket_tombstone_request_frame,
        write_rsi_set_value_request_frame, write_rsi_write_key_request_frame, RsiTransactionMode,
        RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME, RSI_WRITE_KEY_FIELD_SD,
    };

    /// Parse a freshly-built frame into an `rsi_request` (the dispatch step).
    unsafe fn parse(frame: &[u8]) -> rsi_request {
        let mut req = core::mem::zeroed::<rsi_request>();
        assert_eq!(
            rsi_parse_request(frame.as_ptr() as *const c_void, frame.len(), &mut req),
            0
        );
        req
    }

    unsafe fn field_bytes(ptr: *const c_void, len: u32) -> &'static [u8] {
        core::slice::from_raw_parts(ptr as *const u8, len as usize)
    }

    #[test]
    fn lookup_roundtrips() {
        let mut buf = [0u8; 128];
        let built =
            write_rsi_lookup_request_frame(&mut buf, 7, 3, [0xAB; 16], b"Software").unwrap();
        let frame = &buf[..built.len];
        unsafe {
            let req = parse(frame);
            assert_eq!(req.request_id, 7);
            assert_eq!(req.txn_id, 3);
            let mut out = core::mem::zeroed::<rsi_lookup>();
            assert_eq!(rsi_request_lookup(&req, &mut out), 0);
            assert_eq!(out.parent_guid, [0xAB; 16]);
            assert_eq!(field_bytes(out.child_name, out.child_name_len), b"Software");
        }
    }

    #[test]
    fn set_value_roundtrips() {
        let mut buf = [0u8; 256];
        let built = write_rsi_set_value_request_frame(
            &mut buf,
            9,
            0,
            [0x01; 16],
            b"Color",
            b"base",
            3, // value_type
            &[0xDE, 0xAD, 0xBE, 0xEF],
            42,  // sequence
            100, // expected_sequence
        )
        .unwrap();
        let frame = &buf[..built.len];
        unsafe {
            let req = parse(frame);
            let mut out = core::mem::zeroed::<rsi_set_value>();
            assert_eq!(rsi_request_set_value(&req, &mut out), 0);
            assert_eq!(out.guid, [0x01; 16]);
            assert_eq!(field_bytes(out.value_name, out.value_name_len), b"Color");
            assert_eq!(field_bytes(out.layer_name, out.layer_name_len), b"base");
            assert_eq!(out.value_type, 3);
            assert_eq!(
                field_bytes(out.data, out.data_len),
                &[0xDE, 0xAD, 0xBE, 0xEF]
            );
            assert_eq!(out.sequence, 42);
            assert_eq!(out.expected_sequence, 100);
        }
    }

    #[test]
    fn write_key_options_roundtrip() {
        let mut buf = [0u8; 256];
        unsafe {
            let built = write_rsi_write_key_request_frame(
                &mut buf,
                1,
                0,
                [0x02; 16],
                Some(&[0x11, 0x22, 0x33]),
                None,
            )
            .unwrap();
            let frame = &buf[..built.len];
            let req = parse(frame);
            let mut out = core::mem::zeroed::<rsi_write_key>();
            assert_eq!(rsi_request_write_key(&req, &mut out), 0);
            assert_eq!(out.field_mask, RSI_WRITE_KEY_FIELD_SD);
            assert_eq!(field_bytes(out.sd, out.sd_len), &[0x11, 0x22, 0x33]);
            assert!(out.last_write_time == 0);
            assert_eq!(out.field_mask & RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME, 0);

            let built = write_rsi_write_key_request_frame(
                &mut buf,
                2,
                0,
                [0x03; 16],
                None,
                Some(0x1122_3344_5566_7788),
            )
            .unwrap();
            let frame = &buf[..built.len];
            let req = parse(frame);
            let mut out = core::mem::zeroed::<rsi_write_key>();
            assert_eq!(rsi_request_write_key(&req, &mut out), 0);
            assert_eq!(out.field_mask, RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME);
            assert!(out.sd.is_null());
            assert_eq!(out.sd_len, 0);
            assert_eq!(out.last_write_time, 0x1122_3344_5566_7788);

            let built = write_rsi_write_key_request_frame(
                &mut buf,
                3,
                0,
                [0x04; 16],
                Some(&[0x44, 0x55]),
                Some(0x8877_6655_4433_2211),
            )
            .unwrap();
            let frame = &buf[..built.len];
            let req = parse(frame);
            let mut out = core::mem::zeroed::<rsi_write_key>();
            assert_eq!(rsi_request_write_key(&req, &mut out), 0);
            assert_eq!(
                out.field_mask,
                RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME
            );
            assert_eq!(field_bytes(out.sd, out.sd_len), &[0x44, 0x55]);
            assert_eq!(out.last_write_time, 0x8877_6655_4433_2211);
        }
    }

    #[test]
    fn begin_transaction_roundtrips() {
        let mut buf = [0u8; 64];
        let built = write_rsi_begin_transaction_request_frame(
            &mut buf,
            5,
            0,
            99,
            RsiTransactionMode::ReadOnly,
        )
        .unwrap();
        let frame = &buf[..built.len];
        unsafe {
            let req = parse(frame);
            let mut out = core::mem::zeroed::<rsi_begin_transaction>();
            assert_eq!(rsi_request_begin_transaction(&req, &mut out), 0);
            assert_eq!(out.transaction_id, 99);
            assert_eq!(out.mode, 1);
        }

        let built = write_rsi_begin_transaction_request_frame(
            &mut buf,
            6,
            0,
            100,
            RsiTransactionMode::ReadWrite,
        )
        .unwrap();
        let frame = &buf[..built.len];
        unsafe {
            let req = parse(frame);
            let mut out = core::mem::zeroed::<rsi_begin_transaction>();
            assert_eq!(rsi_request_begin_transaction(&req, &mut out), 0);
            assert_eq!(out.transaction_id, 100);
            assert_eq!(out.mode, 0);
        }
    }

    #[test]
    fn entry_request_decoders_roundtrip() {
        unsafe {
            let mut buf = [0u8; 256];

            let built = write_rsi_create_entry_request_frame(
                &mut buf, 10, 4, [0x10; 16], b"Child", b"base", [0x11; 16], 55,
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut create_entry = core::mem::zeroed::<rsi_create_entry>();
            assert_eq!(rsi_request_create_entry(&req, &mut create_entry), 0);
            assert_eq!(create_entry.parent_guid, [0x10; 16]);
            assert_eq!(create_entry.child_guid, [0x11; 16]);
            assert_eq!(
                field_bytes(create_entry.child_name, create_entry.child_name_len),
                b"Child"
            );
            assert_eq!(
                field_bytes(create_entry.layer_name, create_entry.layer_name_len),
                b"base"
            );
            assert_eq!(create_entry.sequence, 55);

            let built = write_rsi_hide_entry_request_frame(
                &mut buf, 11, 4, [0x20; 16], b"Hidden", b"mask", 56,
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut hide_entry = core::mem::zeroed::<rsi_hide_entry>();
            assert_eq!(rsi_request_hide_entry(&req, &mut hide_entry), 0);
            assert_eq!(hide_entry.parent_guid, [0x20; 16]);
            assert_eq!(
                field_bytes(hide_entry.child_name, hide_entry.child_name_len),
                b"Hidden"
            );
            assert_eq!(
                field_bytes(hide_entry.layer_name, hide_entry.layer_name_len),
                b"mask"
            );
            assert_eq!(hide_entry.sequence, 56);

            let built = write_rsi_delete_entry_request_frame(
                &mut buf, 12, 4, [0x30; 16], b"Dead", b"overlay",
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut delete_entry = core::mem::zeroed::<rsi_delete_entry>();
            assert_eq!(rsi_request_delete_entry(&req, &mut delete_entry), 0);
            assert_eq!(delete_entry.parent_guid, [0x30; 16]);
            assert_eq!(
                field_bytes(delete_entry.child_name, delete_entry.child_name_len),
                b"Dead"
            );
            assert_eq!(
                field_bytes(delete_entry.layer_name, delete_entry.layer_name_len),
                b"overlay"
            );

            let built = write_rsi_enum_children_request_frame(&mut buf, 13, 4, [0x40; 16]).unwrap();
            let req = parse(&buf[..built.len]);
            let mut enum_children = core::mem::zeroed::<rsi_enum_children>();
            assert_eq!(rsi_request_enum_children(&req, &mut enum_children), 0);
            assert_eq!(enum_children.parent_guid, [0x40; 16]);
        }
    }

    #[test]
    fn key_request_decoders_roundtrip() {
        unsafe {
            let mut buf = [0u8; 256];

            let built = write_rsi_create_key_request_frame(
                &mut buf,
                14,
                4,
                [0x50; 16],
                b"Key",
                [0x51; 16],
                &[0xAA, 0xBB],
                true,
                false,
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut create_key = core::mem::zeroed::<rsi_create_key>();
            assert_eq!(rsi_request_create_key(&req, &mut create_key), 0);
            assert_eq!(create_key.guid, [0x50; 16]);
            assert_eq!(create_key.parent_guid, [0x51; 16]);
            assert_eq!(field_bytes(create_key.name, create_key.name_len), b"Key");
            assert_eq!(field_bytes(create_key.sd, create_key.sd_len), &[0xAA, 0xBB]);
            assert_eq!(create_key.volatile_key, 1);
            assert_eq!(create_key.symlink, 0);

            let built = write_rsi_create_key_request_frame(
                &mut buf,
                24,
                4,
                [0x52; 16],
                b"Link",
                [0x53; 16],
                &[0xCC],
                false,
                true,
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut create_key = core::mem::zeroed::<rsi_create_key>();
            assert_eq!(rsi_request_create_key(&req, &mut create_key), 0);
            assert_eq!(field_bytes(create_key.name, create_key.name_len), b"Link");
            assert_eq!(field_bytes(create_key.sd, create_key.sd_len), &[0xCC]);
            assert_eq!(create_key.volatile_key, 0);
            assert_eq!(create_key.symlink, 1);

            let built = write_rsi_read_key_request_frame(&mut buf, 15, 4, [0x60; 16]).unwrap();
            let req = parse(&buf[..built.len]);
            let mut key_guid = core::mem::zeroed::<rsi_key_guid>();
            assert_eq!(rsi_request_read_key(&req, &mut key_guid), 0);
            assert_eq!(key_guid.guid, [0x60; 16]);

            let built = write_rsi_drop_key_request_frame(&mut buf, 16, 4, [0x61; 16]).unwrap();
            let req = parse(&buf[..built.len]);
            let mut key_guid = core::mem::zeroed::<rsi_key_guid>();
            assert_eq!(rsi_request_drop_key(&req, &mut key_guid), 0);
            assert_eq!(key_guid.guid, [0x61; 16]);
        }
    }

    #[test]
    fn value_request_decoders_roundtrip() {
        unsafe {
            let mut buf = [0u8; 256];

            let built =
                write_rsi_query_values_request_frame(&mut buf, 17, 4, [0x70; 16], b"Value", false)
                    .unwrap();
            let req = parse(&buf[..built.len]);
            let mut query_values = core::mem::zeroed::<rsi_query_values>();
            assert_eq!(rsi_request_query_values(&req, &mut query_values), 0);
            assert_eq!(query_values.guid, [0x70; 16]);
            assert_eq!(
                field_bytes(query_values.value_name, query_values.value_name_len),
                b"Value"
            );
            assert_eq!(query_values.query_all, 0);

            let built =
                write_rsi_query_values_request_frame(&mut buf, 25, 4, [0x71; 16], b"", true)
                    .unwrap();
            let req = parse(&buf[..built.len]);
            let mut query_values = core::mem::zeroed::<rsi_query_values>();
            assert_eq!(rsi_request_query_values(&req, &mut query_values), 0);
            assert_eq!(query_values.guid, [0x71; 16]);
            assert_eq!(query_values.value_name_len, 0);
            assert_eq!(query_values.query_all, 1);

            let built = write_rsi_delete_value_entry_request_frame(
                &mut buf, 18, 4, [0x80; 16], b"Value", b"base",
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut delete_value = core::mem::zeroed::<rsi_delete_value_entry>();
            assert_eq!(rsi_request_delete_value_entry(&req, &mut delete_value), 0);
            assert_eq!(delete_value.guid, [0x80; 16]);
            assert_eq!(
                field_bytes(delete_value.value_name, delete_value.value_name_len),
                b"Value"
            );
            assert_eq!(
                field_bytes(delete_value.layer_name, delete_value.layer_name_len),
                b"base"
            );

            let built = write_rsi_set_blanket_tombstone_request_frame(
                &mut buf, 19, 4, [0x90; 16], b"mask", true, 57,
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut blanket = core::mem::zeroed::<rsi_set_blanket_tombstone>();
            assert_eq!(rsi_request_set_blanket_tombstone(&req, &mut blanket), 0);
            assert_eq!(blanket.guid, [0x90; 16]);
            assert_eq!(
                field_bytes(blanket.layer_name, blanket.layer_name_len),
                b"mask"
            );
            assert_eq!(blanket.set, 1);
            assert_eq!(blanket.sequence, 57);

            let built = write_rsi_set_blanket_tombstone_request_frame(
                &mut buf, 26, 4, [0x91; 16], b"mask", false, 58,
            )
            .unwrap();
            let req = parse(&buf[..built.len]);
            let mut blanket = core::mem::zeroed::<rsi_set_blanket_tombstone>();
            assert_eq!(rsi_request_set_blanket_tombstone(&req, &mut blanket), 0);
            assert_eq!(blanket.guid, [0x91; 16]);
            assert_eq!(
                field_bytes(blanket.layer_name, blanket.layer_name_len),
                b"mask"
            );
            assert_eq!(blanket.set, 0);
            assert_eq!(blanket.sequence, 58);
        }
    }

    #[test]
    fn transaction_and_name_request_decoders_roundtrip() {
        unsafe {
            let mut buf = [0u8; 256];

            let built =
                write_rsi_commit_transaction_request_frame(&mut buf, 20, 4, 0x1234).unwrap();
            let req = parse(&buf[..built.len]);
            let mut transaction = core::mem::zeroed::<rsi_transaction>();
            assert_eq!(rsi_request_commit_transaction(&req, &mut transaction), 0);
            assert_eq!(transaction.transaction_id, 0x1234);

            let built = write_rsi_abort_transaction_request_frame(&mut buf, 21, 4, 0x5678).unwrap();
            let req = parse(&buf[..built.len]);
            let mut transaction = core::mem::zeroed::<rsi_transaction>();
            assert_eq!(rsi_request_abort_transaction(&req, &mut transaction), 0);
            assert_eq!(transaction.transaction_id, 0x5678);

            let built = write_rsi_delete_layer_request_frame(&mut buf, 22, 4, b"overlay").unwrap();
            let req = parse(&buf[..built.len]);
            let mut name = core::mem::zeroed::<rsi_name>();
            assert_eq!(rsi_request_delete_layer(&req, &mut name), 0);
            assert_eq!(field_bytes(name.name, name.name_len), b"overlay");

            let built = write_rsi_flush_request_frame(&mut buf, 23, 4, b"Machine").unwrap();
            let req = parse(&buf[..built.len]);
            let mut name = core::mem::zeroed::<rsi_name>();
            assert_eq!(rsi_request_flush(&req, &mut name), 0);
            assert_eq!(field_bytes(name.name, name.name_len), b"Machine");
        }
    }

    #[test]
    fn short_frame_is_ebadmsg() {
        use crate::error::get_errno;
        let frame = [0u8; 4]; // shorter than the 22-byte header
        let mut req = unsafe { core::mem::zeroed::<rsi_request>() };
        let r =
            unsafe { rsi_parse_request(frame.as_ptr() as *const c_void, frame.len(), &mut req) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EBADMSG);
    }

    #[test]
    fn mismatched_decoder_is_einval() {
        use crate::error::get_errno;

        let mut buf = [0u8; 128];
        let built =
            write_rsi_lookup_request_frame(&mut buf, 7, 3, [0xAB; 16], b"Software").unwrap();
        let frame = &buf[..built.len];
        unsafe {
            let req = parse(frame);
            let mut out = core::mem::zeroed::<rsi_key_guid>();
            assert_eq!(rsi_request_read_key(&req, &mut out), -1);
            assert_eq!(get_errno(), libc::EINVAL);
        }
    }
}
