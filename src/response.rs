//! `<rsi/response.h>` — building and sending RSI responses.
//!
//! After handling a request, the source replies on the source fd with a framed
//! response: a 14-byte header (echoing the request id, op-code OR'd with the response
//! bit) + a 4-byte status, then an op-specific payload for payload-bearing successes.
//! lcs-core has no response builders (only the kernel builds requests), so librsi
//! encodes the frames here from the uapi offsets.
//!
//! Most ops are **status-only** ([`rsi_respond_status`], an 18-byte frame), and every
//! op uses a status-only frame to report a non-OK status. The payload-bearing success
//! responses are [`rsi_respond_lookup`], [`rsi_respond_enum_children`],
//! [`rsi_respond_read_key`], [`rsi_respond_delete_layer`], and
//! [`rsi_respond_query_values`]; the caller supplies the result as flat arrays and
//! librsi heap-encodes the frame. All multi-byte integers are little-endian;
//! names/data are length-prefixed (u32 LE length + bytes). For every `(ptr, len)`
//! field, `ptr` may be NULL only when `len` is zero.

#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_void};

use alloc::vec::Vec;

use lcs_core::rsi::{
    parse_rsi_status, rsi_request_has_status_only_response, rsi_response_op_code, RsiStatus,
};
use peios_uapi::{
    RSI_DELETE_LAYER, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_MIN_RESPONSE_SIZE, RSI_OK,
    RSI_PATH_TARGET_GUID, RSI_PATH_TARGET_HIDDEN, RSI_QUERY_VALUES, RSI_READ_KEY,
};

use crate::abi::try_extend;
use crate::error::set_errno;
use crate::request::rsi_request;

// The status-only frame is exactly the response header (14) + status (4).
const STATUS_FRAME_LEN: usize = 18;
const _: () = assert!(STATUS_FRAME_LEN == RSI_MIN_RESPONSE_SIZE as usize);

fn fail_errno(e: c_int) -> c_int {
    set_errno(e);
    -1
}

fn require_array<T>(ptr: *const T, count: u32) -> Result<(), c_int> {
    if count != 0 && ptr.is_null() {
        return Err(libc::EINVAL);
    }
    Ok(())
}

fn require_lpf(ptr: *const c_void, len: u32) -> Result<(), c_int> {
    if len != 0 && ptr.is_null() {
        return Err(libc::EINVAL);
    }
    Ok(())
}

fn require_bool(value: u8) -> Result<(), c_int> {
    match value {
        0 | 1 => Ok(()),
        _ => Err(libc::EINVAL),
    }
}

fn require_path_target(target_type: u8, target_guid: &[u8; 16]) -> Result<(), c_int> {
    match target_type as u32 {
        RSI_PATH_TARGET_GUID => Ok(()),
        RSI_PATH_TARGET_HIDDEN if *target_guid == [0; 16] => Ok(()),
        RSI_PATH_TARGET_HIDDEN => Err(libc::EINVAL),
        _ => Err(libc::EINVAL),
    }
}

fn is_guid_target(target_type: u8) -> bool {
    target_type as u32 == RSI_PATH_TARGET_GUID
}

fn guid_vec_with_capacity(capacity: usize) -> Result<Vec<[u8; 16]>, c_int> {
    let mut guids = Vec::new();
    guids.try_reserve(capacity).map_err(|_| libc::ENOMEM)?;
    Ok(guids)
}

fn push_guid(guids: &mut Vec<[u8; 16]>, guid: [u8; 16]) -> Result<(), c_int> {
    if guids.len() == guids.capacity() {
        guids.try_reserve(1).map_err(|_| libc::ENOMEM)?;
    }
    guids.push(guid);
    Ok(())
}

fn validate_unique_nonzero_guids(guids: &mut [[u8; 16]]) -> Result<(), c_int> {
    guids.sort_unstable();
    if matches!(guids.first(), Some(guid) if *guid == [0; 16]) {
        return Err(libc::EINVAL);
    }
    if guids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(libc::EINVAL);
    }
    Ok(())
}

fn sort_dedup_guids(guids: &mut Vec<[u8; 16]>) {
    guids.sort_unstable();
    guids.dedup();
}

unsafe fn metadata_guid_set(
    metadata: *const rsi_key_metadata,
    count: u32,
) -> Result<Vec<[u8; 16]>, c_int> {
    require_array(metadata, count)?;
    let mut guids = guid_vec_with_capacity(count as usize)?;
    for i in 0..count as usize {
        guids.push((*metadata.add(i)).guid);
    }
    validate_unique_nonzero_guids(&mut guids)?;
    Ok(guids)
}

unsafe fn lookup_target_guid_set(
    entries: *const rsi_path_entry,
    count: u32,
) -> Result<Vec<[u8; 16]>, c_int> {
    require_array(entries, count)?;
    let mut guids = Vec::new();
    for i in 0..count as usize {
        let entry = &*entries.add(i);
        require_path_target(entry.target_type, &entry.target_guid)?;
        if is_guid_target(entry.target_type) {
            push_guid(&mut guids, entry.target_guid)?;
        }
    }
    sort_dedup_guids(&mut guids);
    Ok(guids)
}

unsafe fn enum_children_target_guid_set(
    children: *const rsi_child_entry,
    count: u32,
) -> Result<Vec<[u8; 16]>, c_int> {
    require_array(children, count)?;
    let mut guids = Vec::new();
    for i in 0..count as usize {
        let child = &*children.add(i);
        require_array(child.entries, child.entry_count)?;
        for j in 0..child.entry_count as usize {
            let entry = &*child.entries.add(j);
            require_path_target(entry.target_type, &entry.target_guid)?;
            if is_guid_target(entry.target_type) {
                push_guid(&mut guids, entry.target_guid)?;
            }
        }
    }
    sort_dedup_guids(&mut guids);
    Ok(guids)
}

unsafe fn validate_lookup_metadata(
    entries: *const rsi_path_entry,
    entry_count: u32,
    metadata: *const rsi_key_metadata,
    metadata_count: u32,
) -> Result<(), c_int> {
    let target_guids = lookup_target_guid_set(entries, entry_count)?;
    let metadata_guids = metadata_guid_set(metadata, metadata_count)?;
    (metadata_guids == target_guids)
        .then_some(())
        .ok_or(libc::EINVAL)
}

unsafe fn validate_enum_children_metadata(
    children: *const rsi_child_entry,
    child_count: u32,
    metadata: *const rsi_key_metadata,
    metadata_count: u32,
) -> Result<(), c_int> {
    let target_guids = enum_children_target_guid_set(children, child_count)?;
    let metadata_guids = metadata_guid_set(metadata, metadata_count)?;
    (metadata_guids == target_guids)
        .then_some(())
        .ok_or(libc::EINVAL)
}

unsafe fn orphaned_guid_bytes<'a>(
    orphaned_guids: *const u8,
    orphaned_count: u32,
) -> Result<&'a [u8], c_int> {
    let guid_bytes_len = (orphaned_count as usize)
        .checked_mul(16)
        .ok_or(libc::EOVERFLOW)?;
    if guid_bytes_len == 0 {
        return Ok(&[]);
    }
    if orphaned_guids.is_null() {
        return Err(libc::EINVAL);
    }

    let bytes = core::slice::from_raw_parts(orphaned_guids, guid_bytes_len);
    let mut guids = guid_vec_with_capacity(orphaned_count as usize)?;
    for guid_bytes in bytes.chunks_exact(16) {
        let mut guid = [0u8; 16];
        guid.copy_from_slice(guid_bytes);
        guids.push(guid);
    }
    validate_unique_nonzero_guids(&mut guids)?;
    Ok(bytes)
}

unsafe fn require_response_req<'a>(
    req: *const rsi_request,
    expected_op: u32,
) -> Result<&'a rsi_request, c_int> {
    let Some(req) = req.as_ref() else {
        return Err(libc::EINVAL);
    };
    if req.op_code != expected_op as u16 {
        return Err(libc::EINVAL);
    }
    Ok(req)
}

fn validate_status_response(req: &rsi_request, status: u32) -> Result<(), c_int> {
    let status = parse_rsi_status(status).map_err(|_| libc::EINVAL)?;
    if status == RsiStatus::Ok
        && !rsi_request_has_status_only_response(req.op_code).map_err(|_| libc::EINVAL)?
    {
        return Err(libc::EINVAL);
    }
    Ok(())
}

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
    } else if r as usize == frame.len() {
        0
    } else {
        fail_errno(libc::EIO)
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
pub unsafe extern "C" fn rsi_write_response(
    fd: c_int,
    frame: *const c_void,
    len: usize,
) -> libc::ssize_t {
    libc::write(fd, frame, len)
}

/// `rsi_respond_status` - reply to `req` with a status-only response.
///
/// Builds the 18-byte header+status frame (echoing `req->request_id`, op-code =
/// `req->op_code | RSI_RESPONSE_BIT`) and writes it. Use this for the mutating ops on
/// success (`status = RSI_OK`) and for *any* op to report a non-OK `RSI_*` status.
/// Returns 0, or `-1` with `errno` (`EINVAL` on a NULL/bad-op-code `req`, unknown
/// status, `RSI_OK` for a payload-bearing op, `EIO` on a short write, or the
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
    if let Err(e) = validate_status_response(req, status) {
        return fail_errno(e);
    }
    let frame = build_status_frame(req.request_id, resp_op, status);
    write_frame(fd, &frame)
}

// ----------------------------------------------------------------------------
// Payload-bearing success responses. The caller passes the result as flat arrays;
// librsi heap-encodes the frame, writes it, and frees.
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
    unsafe fn lpf(&mut self, ptr: *const c_void, len: u32) -> Result<(), c_int> {
        require_lpf(ptr, len)?;
        self.u32(len);
        if len != 0 {
            self.raw(core::slice::from_raw_parts(ptr as *const u8, len as usize));
        }
        Ok(())
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
/// (`ENOMEM`) or oversized frame (`EOVERFLOW`).
fn finish_response(req: &rsi_request, mut w: FrameWriter) -> Result<Vec<u8>, c_int> {
    let resp_op = rsi_response_op_code(req.op_code).map_err(|_| libc::EINVAL)?;
    if w.oom {
        return Err(libc::ENOMEM);
    }
    let total = u32::try_from(w.buf.len()).map_err(|_| libc::EOVERFLOW)?;
    put_response_header(&mut w.buf, total, req.request_id, resp_op);
    w.buf[14..18].copy_from_slice(&RSI_OK.to_le_bytes());
    Ok(w.buf)
}

/// Finish the frame and write it, mapping a build error to `errno`.
unsafe fn finish_and_send(fd: c_int, req: &rsi_request, w: FrameWriter) -> c_int {
    match finish_response(req, w) {
        Ok(frame) => write_frame(fd, &frame),
        Err(e) => fail_errno(e),
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
unsafe fn encode_path_entry_block(
    w: &mut FrameWriter,
    entries: *const rsi_path_entry,
    count: u32,
) -> Result<(), c_int> {
    require_array(entries, count)?;
    w.u32(count);
    for i in 0..count as usize {
        let e = &*entries.add(i);
        w.lpf(e.layer, e.layer_len)?;
        require_path_target(e.target_type, &e.target_guid)?;
        w.u8(e.target_type);
        w.guid(&e.target_guid);
        w.u64(e.sequence);
    }
    Ok(())
}

/// A `[count][metadata...]` block of key-metadata entries.
unsafe fn encode_metadata_block(
    w: &mut FrameWriter,
    metadata: *const rsi_key_metadata,
    count: u32,
) -> Result<(), c_int> {
    require_array(metadata, count)?;
    w.u32(count);
    for i in 0..count as usize {
        let m = &*metadata.add(i);
        w.guid(&m.guid);
        w.lpf(m.sd, m.sd_len)?;
        require_bool(m.volatile_key)?;
        require_bool(m.symlink)?;
        w.u8(m.volatile_key);
        w.u8(m.symlink);
        w.u64(m.last_write_time);
    }
    Ok(())
}

/// `rsi_respond_lookup` - LOOKUP success: the path `entries` for the looked-up child
/// plus the `metadata` for each referenced key.
///
/// # Safety
/// `req` decoded by `rsi_parse_request`; `entries`/`metadata` valid arrays of their
/// counts, with each borrowed `layer`/`sd` valid for its length. NULL arrays are
/// accepted only when their count is zero.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_lookup(
    fd: c_int,
    req: *const rsi_request,
    entries: *const rsi_path_entry,
    entry_count: u32,
    metadata: *const rsi_key_metadata,
    metadata_count: u32,
) -> c_int {
    let req = match require_response_req(req, RSI_LOOKUP) {
        Ok(req) => req,
        Err(e) => return fail_errno(e),
    };
    if let Err(e) = validate_lookup_metadata(entries, entry_count, metadata, metadata_count) {
        return fail_errno(e);
    }
    let mut w = new_writer();
    if let Err(e) = encode_path_entry_block(&mut w, entries, entry_count)
        .and_then(|_| encode_metadata_block(&mut w, metadata, metadata_count))
    {
        return fail_errno(e);
    }
    finish_and_send(fd, req, w)
}

/// `rsi_respond_delete_layer` - DELETE_LAYER success: orphaned key GUIDs purged by
/// the layer deletion.
///
/// # Safety
/// `req` decoded by `rsi_parse_request`; `orphaned_guids` points to
/// `orphaned_count * 16` bytes, or is NULL only when `orphaned_count` is zero.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_delete_layer(
    fd: c_int,
    req: *const rsi_request,
    orphaned_guids: *const u8,
    orphaned_count: u32,
) -> c_int {
    let req = match require_response_req(req, RSI_DELETE_LAYER) {
        Ok(req) => req,
        Err(e) => return fail_errno(e),
    };
    let orphaned_bytes = match orphaned_guid_bytes(orphaned_guids, orphaned_count) {
        Ok(bytes) => bytes,
        Err(e) => return fail_errno(e),
    };

    let mut w = new_writer();
    w.u32(orphaned_count);
    w.raw(orphaned_bytes);
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
/// counts, each `rsi_child_entry.entries` a valid array of `entry_count`. NULL arrays
/// are accepted only when their count is zero.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_enum_children(
    fd: c_int,
    req: *const rsi_request,
    children: *const rsi_child_entry,
    child_count: u32,
    metadata: *const rsi_key_metadata,
    metadata_count: u32,
) -> c_int {
    let req = match require_response_req(req, RSI_ENUM_CHILDREN) {
        Ok(req) => req,
        Err(e) => return fail_errno(e),
    };
    if let Err(e) = validate_enum_children_metadata(children, child_count, metadata, metadata_count)
    {
        return fail_errno(e);
    }
    let mut w = new_writer();
    w.u32(child_count);
    for i in 0..child_count as usize {
        let c = &*children.add(i);
        if let Err(e) = w
            .lpf(c.child_name, c.child_name_len)
            .and_then(|_| encode_path_entry_block(&mut w, c.entries, c.entry_count))
        {
            return fail_errno(e);
        }
    }
    if let Err(e) = encode_metadata_block(&mut w, metadata, metadata_count) {
        return fail_errno(e);
    }
    finish_and_send(fd, req, w)
}

/// `rsi_respond_read_key` - READ_KEY success: the key's non-layered metadata.
///
/// # Safety
/// `req` decoded by `rsi_parse_request`; `name` valid for `name_len`, `sd` for
/// `sd_len`, `parent_guid` for 16 bytes. `parent_guid` is required even when other
/// fields are empty.
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
    let req = match require_response_req(req, RSI_READ_KEY) {
        Ok(req) => req,
        Err(e) => return fail_errno(e),
    };
    if parent_guid.is_null() {
        return fail_errno(libc::EINVAL);
    }
    let mut w = new_writer();
    if let Err(e) = w.lpf(name, name_len) {
        return fail_errno(e);
    }
    w.raw(core::slice::from_raw_parts(parent_guid, 16));
    if let Err(e) = w.lpf(sd, sd_len) {
        return fail_errno(e);
    }
    if let Err(e) = require_bool(volatile_key).and_then(|_| require_bool(symlink)) {
        return fail_errno(e);
    }
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
/// counts, with each borrowed name/data valid for its length. NULL arrays are
/// accepted only when their count is zero.
#[no_mangle]
pub unsafe extern "C" fn rsi_respond_query_values(
    fd: c_int,
    req: *const rsi_request,
    entries: *const rsi_value_entry,
    entry_count: u32,
    blankets: *const rsi_blanket_entry,
    blanket_count: u32,
) -> c_int {
    let req = match require_response_req(req, RSI_QUERY_VALUES) {
        Ok(req) => req,
        Err(e) => return fail_errno(e),
    };
    if let Err(e) =
        require_array(entries, entry_count).and_then(|_| require_array(blankets, blanket_count))
    {
        return fail_errno(e);
    }
    let mut w = new_writer();
    w.u32(entry_count);
    for i in 0..entry_count as usize {
        let e = &*entries.add(i);
        if let Err(err) = w
            .lpf(e.value_name, e.value_name_len)
            .and_then(|_| w.lpf(e.layer_name, e.layer_name_len))
        {
            return fail_errno(err);
        }
        w.u32(e.value_type);
        if let Err(err) = w.lpf(e.data, e.data_len) {
            return fail_errno(err);
        }
        w.u64(e.sequence);
    }
    w.u32(blanket_count);
    for i in 0..blanket_count as usize {
        let b = &*blankets.add(i);
        if let Err(e) = w.lpf(b.layer_name, b.layer_name_len) {
            return fail_errno(e);
        }
        w.u64(b.sequence);
    }
    finish_and_send(fd, req, w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lcs_core::rsi::{
        parse_rsi_delete_layer_success_response_payload,
        parse_rsi_enum_children_success_response_payload,
        parse_rsi_lookup_success_response_payload, parse_rsi_query_values_success_response_payload,
        parse_rsi_read_key_success_response_payload, validate_rsi_delete_layer_orphaned_guids,
        validate_rsi_enum_children_metadata_completeness,
        validate_rsi_lookup_metadata_completeness, validate_rsi_status_only_response_for_request,
        write_rsi_delete_layer_request_frame, write_rsi_enum_children_request_frame,
        write_rsi_flush_request_frame, write_rsi_lookup_request_frame,
        write_rsi_query_values_request_frame, write_rsi_read_key_request_frame,
        RSI_PATH_TARGET_GUID, RSI_PATH_TARGET_HIDDEN,
    };
    use peios_uapi::{
        RSI_DELETE_LAYER, RSI_ENUM_CHILDREN, RSI_FLUSH, RSI_LOOKUP, RSI_QUERY_VALUES, RSI_READ_KEY,
        RSI_RESPONSE_BIT,
    };

    unsafe fn response_from_pipe<F>(f: F) -> Vec<u8>
    where
        F: FnOnce(c_int) -> c_int,
    {
        let mut fds = [0; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);

        let read_fd = fds[0];
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut chunk = [0u8; 256];
            loop {
                let n =
                    unsafe { libc::read(read_fd, chunk.as_mut_ptr() as *mut c_void, chunk.len()) };
                assert!(n >= 0);
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..n as usize]);
            }
            assert_eq!(unsafe { libc::close(read_fd) }, 0);
            out
        });

        let rc = f(fds[1]);
        assert_eq!(libc::close(fds[1]), 0);
        assert_eq!(rc, 0);

        reader.join().unwrap()
    }

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

    // The strongest local check: write via the public C ABI helper, parse with
    // lcs-core's response parser, then run the semantic validators that apply to
    // source-provided payloads.

    #[test]
    fn read_key_response_roundtrips() {
        let mut reqbuf = [0u8; 64];
        let built = write_rsi_read_key_request_frame(&mut reqbuf, 7, 0, [0x55; 16]).unwrap();
        let req = fake_request(RSI_READ_KEY, 7);

        let name = b"App";
        let sd = [0xAAu8; 8];
        let parent = [0x33u8; 16];
        let frame = unsafe {
            response_from_pipe(|fd| {
                rsi_respond_read_key(
                    fd,
                    &req,
                    name.as_ptr() as *const c_void,
                    name.len() as u32,
                    parent.as_ptr(),
                    sd.as_ptr() as *const c_void,
                    sd.len() as u32,
                    1,
                    0,
                    0xDEAD_BEEF,
                )
            })
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

        // Two path entries (one base layer, one overlay), with matching metadata.
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
        let sd_base = [0x77u8; 4];
        let sd_overlay = [0x88u8; 4];
        let metadata = [
            rsi_key_metadata {
                guid: [0x10; 16],
                sd: sd_base.as_ptr() as *const c_void,
                sd_len: sd_base.len() as u32,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 41,
            },
            rsi_key_metadata {
                guid: [0x20; 16],
                sd: sd_overlay.as_ptr() as *const c_void,
                sd_len: sd_overlay.len() as u32,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 42,
            },
        ];
        let frame = unsafe {
            response_from_pipe(|fd| {
                rsi_respond_lookup(
                    fd,
                    &req,
                    entries.as_ptr(),
                    entries.len() as u32,
                    metadata.as_ptr(),
                    metadata.len() as u32,
                )
            })
        };

        let parsed = parse_rsi_lookup_success_response_payload(&frame, built.retained).unwrap();
        assert_eq!(parsed.entry_count, 2);
        assert_eq!(parsed.metadata_count, 2);
        validate_rsi_lookup_metadata_completeness(&parsed).unwrap();
    }

    #[test]
    fn delete_layer_response_roundtrips() {
        let mut reqbuf = [0u8; 64];
        let built = write_rsi_delete_layer_request_frame(&mut reqbuf, 13, 0, b"overlay").unwrap();
        let req = fake_request(RSI_DELETE_LAYER, 13);
        let mut guids = Vec::new();
        guids.extend_from_slice(&[0x10u8; 16]);
        guids.extend_from_slice(&[0x20u8; 16]);

        let frame = unsafe {
            response_from_pipe(|fd| rsi_respond_delete_layer(fd, &req, guids.as_ptr(), 2))
        };

        let parsed =
            parse_rsi_delete_layer_success_response_payload(&frame, built.retained).unwrap();
        assert_eq!(parsed.orphaned_guids.count, 2);
        assert_eq!(parsed.orphaned_guids.guid_at(0), Some([0x10; 16]));
        assert_eq!(parsed.orphaned_guids.guid_at(1), Some([0x20; 16]));
        assert_eq!(parsed.orphaned_guids.guid_at(2), None);
        validate_rsi_delete_layer_orphaned_guids(&parsed).unwrap();
    }

    #[test]
    fn enum_children_response_roundtrips() {
        let mut reqbuf = [0u8; 64];
        let built = write_rsi_enum_children_request_frame(&mut reqbuf, 17, 0, [0x44; 16]).unwrap();
        let req = fake_request(RSI_ENUM_CHILDREN, 17);

        let base = b"base";
        let mask = b"mask";
        let child_name = b"Child";
        let entries = [
            rsi_path_entry {
                layer: base.as_ptr() as *const c_void,
                layer_len: base.len() as u32,
                target_type: RSI_PATH_TARGET_GUID,
                target_guid: [0x30; 16],
                sequence: 300,
            },
            rsi_path_entry {
                layer: mask.as_ptr() as *const c_void,
                layer_len: mask.len() as u32,
                target_type: RSI_PATH_TARGET_HIDDEN,
                target_guid: [0; 16],
                sequence: 301,
            },
        ];
        let children = [rsi_child_entry {
            child_name: child_name.as_ptr() as *const c_void,
            child_name_len: child_name.len() as u32,
            entries: entries.as_ptr(),
            entry_count: entries.len() as u32,
        }];
        let sd = [0xABu8; 3];
        let metadata = [rsi_key_metadata {
            guid: [0x30; 16],
            sd: sd.as_ptr() as *const c_void,
            sd_len: sd.len() as u32,
            volatile_key: 1,
            symlink: 0,
            last_write_time: 1234,
        }];

        let frame = unsafe {
            response_from_pipe(|fd| {
                rsi_respond_enum_children(
                    fd,
                    &req,
                    children.as_ptr(),
                    children.len() as u32,
                    metadata.as_ptr(),
                    metadata.len() as u32,
                )
            })
        };

        let parsed =
            parse_rsi_enum_children_success_response_payload(&frame, built.retained).unwrap();
        assert_eq!(parsed.child_count, 1);
        assert_eq!(parsed.metadata_count, 1);
        validate_rsi_enum_children_metadata_completeness(&parsed).unwrap();

        let mut seen_child = false;
        parsed
            .for_each_child(|child| {
                seen_child = true;
                assert_eq!(child.child_name.data, b"Child");
                assert_eq!(child.path_entry_count, 2);
                Ok(())
            })
            .unwrap();
        assert!(seen_child);
    }

    #[test]
    fn query_values_response_roundtrips() {
        let mut reqbuf = [0u8; 96];
        let built =
            write_rsi_query_values_request_frame(&mut reqbuf, 19, 0, [0x66; 16], b"Answer", false)
                .unwrap();
        let req = fake_request(RSI_QUERY_VALUES, 19);

        let value_name = b"Answer";
        let layer_name = b"base";
        let data = [42u8, 0, 0, 0];
        let entries = [rsi_value_entry {
            value_name: value_name.as_ptr() as *const c_void,
            value_name_len: value_name.len() as u32,
            layer_name: layer_name.as_ptr() as *const c_void,
            layer_name_len: layer_name.len() as u32,
            value_type: 4,
            data: data.as_ptr() as *const c_void,
            data_len: data.len() as u32,
            sequence: 400,
        }];
        let blanket_layer = b"mask";
        let blankets = [rsi_blanket_entry {
            layer_name: blanket_layer.as_ptr() as *const c_void,
            layer_name_len: blanket_layer.len() as u32,
            sequence: 401,
        }];

        let frame = unsafe {
            response_from_pipe(|fd| {
                rsi_respond_query_values(
                    fd,
                    &req,
                    entries.as_ptr(),
                    entries.len() as u32,
                    blankets.as_ptr(),
                    blankets.len() as u32,
                )
            })
        };

        let parsed =
            parse_rsi_query_values_success_response_payload(&frame, built.retained).unwrap();
        assert_eq!(parsed.entry_count, 1);
        assert_eq!(parsed.blanket_count, 1);

        let mut seen_value = false;
        parsed
            .for_each_value_entry(|entry| {
                seen_value = true;
                assert_eq!(entry.value_name.data, b"Answer");
                assert_eq!(entry.layer_name.data, b"base");
                assert_eq!(entry.value_type, 4);
                assert_eq!(entry.data.data, &[42, 0, 0, 0]);
                assert_eq!(entry.sequence, 400);
                Ok(())
            })
            .unwrap();
        assert!(seen_value);
    }

    #[test]
    fn status_response_success_roundtrips() {
        let mut reqbuf = [0u8; 64];
        let built = write_rsi_flush_request_frame(&mut reqbuf, 23, 0, b"Machine").unwrap();
        let req = fake_request(RSI_FLUSH, 23);

        let frame = unsafe { response_from_pipe(|fd| rsi_respond_status(fd, &req, RSI_OK)) };
        let parsed = validate_rsi_status_only_response_for_request(&frame, built.retained).unwrap();
        assert_eq!(parsed.status, RsiStatus::Ok);
    }

    #[test]
    fn empty_lookup_response_frame_has_expected_len() {
        // A well-formed empty LOOKUP (zero entries) still produces a valid frame.
        let req = fake_request(RSI_LOOKUP, 1);
        let frame = unsafe {
            let mut w = new_writer();
            encode_path_entry_block(&mut w, core::ptr::null(), 0).unwrap();
            encode_metadata_block(&mut w, core::ptr::null(), 0).unwrap();
            finish_response(&req, w).unwrap()
        };
        // header(14) + status(4) + entry_count(4) + metadata_count(4) = 26 bytes.
        assert_eq!(frame.len(), 26);
    }

    #[test]
    fn sticky_oom_returns_enomem() {
        let req = fake_request(RSI_LOOKUP, 1);
        let mut w = new_writer();
        w.oom = true;
        assert_eq!(finish_response(&req, w), Err(libc::ENOMEM));
    }

    #[test]
    fn payload_response_rejects_wrong_request_op() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let parent = [0x33u8; 16];
        let r = unsafe {
            rsi_respond_read_key(
                -1,
                &req,
                core::ptr::null(),
                0,
                parent.as_ptr(),
                core::ptr::null(),
                0,
                0,
                0,
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn payload_response_rejects_null_array_with_count() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let r = unsafe { rsi_respond_lookup(-1, &req, core::ptr::null(), 1, core::ptr::null(), 0) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn lookup_response_rejects_missing_metadata() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let layer = b"base";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: RSI_PATH_TARGET_GUID,
            target_guid: [0x10; 16],
            sequence: 1,
        }];
        let r = unsafe {
            rsi_respond_lookup(
                -1,
                &req,
                entries.as_ptr(),
                entries.len() as u32,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn lookup_response_rejects_duplicate_metadata() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let layer = b"base";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: RSI_PATH_TARGET_GUID,
            target_guid: [0x10; 16],
            sequence: 1,
        }];
        let metadata = [
            rsi_key_metadata {
                guid: [0x10; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
            rsi_key_metadata {
                guid: [0x10; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
        ];
        let r = unsafe {
            rsi_respond_lookup(
                -1,
                &req,
                entries.as_ptr(),
                entries.len() as u32,
                metadata.as_ptr(),
                metadata.len() as u32,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn lookup_response_rejects_unreferenced_metadata() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let layer = b"base";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: RSI_PATH_TARGET_GUID,
            target_guid: [0x10; 16],
            sequence: 1,
        }];
        let metadata = [
            rsi_key_metadata {
                guid: [0x10; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
            rsi_key_metadata {
                guid: [0x20; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
        ];
        let r = unsafe {
            rsi_respond_lookup(
                -1,
                &req,
                entries.as_ptr(),
                entries.len() as u32,
                metadata.as_ptr(),
                metadata.len() as u32,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn enum_children_response_rejects_missing_metadata() {
        use crate::error::get_errno;

        let req = fake_request(RSI_ENUM_CHILDREN, 1);
        let child_name = b"Child";
        let layer = b"base";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: RSI_PATH_TARGET_GUID,
            target_guid: [0x30; 16],
            sequence: 1,
        }];
        let children = [rsi_child_entry {
            child_name: child_name.as_ptr() as *const c_void,
            child_name_len: child_name.len() as u32,
            entries: entries.as_ptr(),
            entry_count: entries.len() as u32,
        }];
        let r = unsafe {
            rsi_respond_enum_children(
                -1,
                &req,
                children.as_ptr(),
                children.len() as u32,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn enum_children_response_rejects_duplicate_metadata() {
        use crate::error::get_errno;

        let req = fake_request(RSI_ENUM_CHILDREN, 1);
        let child_name = b"Child";
        let layer = b"base";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: RSI_PATH_TARGET_GUID,
            target_guid: [0x30; 16],
            sequence: 1,
        }];
        let children = [rsi_child_entry {
            child_name: child_name.as_ptr() as *const c_void,
            child_name_len: child_name.len() as u32,
            entries: entries.as_ptr(),
            entry_count: entries.len() as u32,
        }];
        let metadata = [
            rsi_key_metadata {
                guid: [0x30; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
            rsi_key_metadata {
                guid: [0x30; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
        ];
        let r = unsafe {
            rsi_respond_enum_children(
                -1,
                &req,
                children.as_ptr(),
                children.len() as u32,
                metadata.as_ptr(),
                metadata.len() as u32,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn enum_children_response_rejects_unreferenced_metadata() {
        use crate::error::get_errno;

        let req = fake_request(RSI_ENUM_CHILDREN, 1);
        let child_name = b"Child";
        let layer = b"base";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: RSI_PATH_TARGET_GUID,
            target_guid: [0x30; 16],
            sequence: 1,
        }];
        let children = [rsi_child_entry {
            child_name: child_name.as_ptr() as *const c_void,
            child_name_len: child_name.len() as u32,
            entries: entries.as_ptr(),
            entry_count: entries.len() as u32,
        }];
        let metadata = [
            rsi_key_metadata {
                guid: [0x30; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
            rsi_key_metadata {
                guid: [0x40; 16],
                sd: core::ptr::null(),
                sd_len: 0,
                volatile_key: 0,
                symlink: 0,
                last_write_time: 0,
            },
        ];
        let r = unsafe {
            rsi_respond_enum_children(
                -1,
                &req,
                children.as_ptr(),
                children.len() as u32,
                metadata.as_ptr(),
                metadata.len() as u32,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn enum_children_response_rejects_null_child_entries_with_count() {
        use crate::error::get_errno;

        let req = fake_request(RSI_ENUM_CHILDREN, 1);
        let child_name = b"Child";
        let children = [rsi_child_entry {
            child_name: child_name.as_ptr() as *const c_void,
            child_name_len: child_name.len() as u32,
            entries: core::ptr::null(),
            entry_count: 1,
        }];
        let r = unsafe {
            rsi_respond_enum_children(
                -1,
                &req,
                children.as_ptr(),
                children.len() as u32,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn read_key_response_rejects_null_parent_guid() {
        use crate::error::get_errno;

        let req = fake_request(RSI_READ_KEY, 1);
        let r = unsafe {
            rsi_respond_read_key(
                -1,
                &req,
                core::ptr::null(),
                0,
                core::ptr::null(),
                core::ptr::null(),
                0,
                0,
                0,
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn delete_layer_response_rejects_nil_orphan_guid() {
        use crate::error::get_errno;

        let req = fake_request(RSI_DELETE_LAYER, 1);
        let guids = [0u8; 16];
        let r = unsafe { rsi_respond_delete_layer(-1, &req, guids.as_ptr(), 1) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn delete_layer_response_rejects_duplicate_orphan_guid() {
        use crate::error::get_errno;

        let req = fake_request(RSI_DELETE_LAYER, 1);
        let mut guids = Vec::new();
        guids.extend_from_slice(&[0x10u8; 16]);
        guids.extend_from_slice(&[0x10u8; 16]);
        let r = unsafe { rsi_respond_delete_layer(-1, &req, guids.as_ptr(), 2) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn status_response_rejects_ok_for_payload_op() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let r = unsafe { rsi_respond_status(-1, &req, RSI_OK) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn status_response_rejects_unknown_status() {
        use crate::error::get_errno;

        let req = fake_request(RSI_FLUSH, 1);
        let r = unsafe { rsi_respond_status(-1, &req, u32::MAX) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn read_key_response_rejects_invalid_booleans() {
        use crate::error::get_errno;

        let req = fake_request(RSI_READ_KEY, 1);
        let parent = [0x33u8; 16];
        let r = unsafe {
            rsi_respond_read_key(
                -1,
                &req,
                core::ptr::null(),
                0,
                parent.as_ptr(),
                core::ptr::null(),
                0,
                2,
                0,
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn lookup_response_rejects_invalid_target_type() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let layer = b"base";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: 0xff,
            target_guid: [0x10; 16],
            sequence: 1,
        }];
        let r = unsafe {
            rsi_respond_lookup(
                -1,
                &req,
                entries.as_ptr(),
                entries.len() as u32,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn lookup_response_rejects_hidden_with_nonzero_guid() {
        use crate::error::get_errno;

        let req = fake_request(RSI_LOOKUP, 1);
        let layer = b"mask";
        let entries = [rsi_path_entry {
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            target_type: RSI_PATH_TARGET_HIDDEN,
            target_guid: [0x10; 16],
            sequence: 1,
        }];
        let r = unsafe {
            rsi_respond_lookup(
                -1,
                &req,
                entries.as_ptr(),
                entries.len() as u32,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }
}
