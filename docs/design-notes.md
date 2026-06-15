# librsi — design notes & status

Checkpoint record so the architecture survives context compaction. **librsi** is the
Rust-implemented, C-ABI userspace library for implementing a Peios **registry source**
(a storage backend) — the provider/RSI side, counterpart to libpeios's registry
*client*. A source registers with the kernel, then serves the RSI (Registry Source
Interface) framed protocol on its source fd.

## Locked decisions

- **Identity:** `librsi.so.0`, `rsi_` symbols, `<rsi/…>` headers, lib name `rsi`
  (so `[lib] name = "rsi"` → `librsi.so` / `librsi.a`). Own repo `peios/librsi/`
  (a peer to libpeios, not part of it — different role/consumer/ABI).
- **Language / shape:** Rust, `#![cfg_attr(not(test), no_std)]` + `alloc`,
  `panic = "abort"`, cdylib+staticlib — same shape as libpeios.
- **Dependencies:** `peios-cabi` (git — the shared C-ABI substrate: allocator, errno,
  syscall/ioctl wrappers, getxattr/builder helpers), `lcs-core` (path; the pure-`core`
  RSI request parsers + status vocabulary the kernel itself uses → wire-compatible),
  `peios-uapi` (path; RSI constants + `#[repr(C)]` structs), `libc`. pkm crates stay
  path deps (pkm has unpushed changes); peios-cabi is a bare git dep tracking `main`.
- **lcs-core no_std fix (pkm edit — behavior-neutral):** lcs-core was
  `#![cfg_attr(feature = "kernel", no_std)]`, i.e. std without the kernel feature.
  It is pure `core` (zero `std`, zero `alloc`), so the gate was mis-scoped; changed to
  `#![cfg_attr(not(test), no_std)]` so userspace (librsi) gets a no_std lcs-core. Proven
  neutral: kernel builds no_std either way, tests build std either way, the `kernel`
  feature still gates the kacs-core/kernel wiring. **This change lives in pkm's
  uncommitted working tree — include it when pkm is next committed.**
- **Error model:** same as libpeios — `int` = fd/0/`-1`+errno; the kernel's errno
  passes straight through (the source-device `open`/`ioctl` and the `read`/`write`
  framing). LcsError→errno mapping (from lcs-core parsers) lands with the request slice.

## Source model (PSD-005 §7-rsi)

1. **Register:** open `/dev/pkm_registry` (misc char device), hold `SeTcbPrivilege`,
   `ioctl(REG_SRC_REGISTER, &reg_src_register_args)` with a `reg_src_hive_entry` array.
   `REG_SRC_REGISTER = 1075335680` (`0x40185200`, `_IOW('R',0,24)` — the uapi's own
   value; an earlier hand-computed `0x400052c0` was wrong). Returns 0/-1; the fd
   becomes the source fd.
2. **Serve:** `read(src_fd)` dequeues one framed RSI request (blocks; `-EMSGSIZE` if the
   buffer is too small; 0 = EOF on close). `write(src_fd, frame)` sends one response
   (kernel validates ≥18 bytes, total_len == count, request_id match, op_code = req |
   0x8000, status). Plain read/write of frames — no mmap ring.
3. **Frame format:** request header **22 bytes** (total_len u32, request_id u64, op_code
   u16, **txn_id u64** — resolved the u16/u64 ambiguity against lcs-core), response
   header 14 bytes + 4-byte status (18 min). Length-prefixed fields (u32 LE len + bytes).
   GUID 16 bytes. All little-endian.
- **lcs-core source-side surface:** has all 18 `parse_rsi_*_request_payload` + `parse_rsi_request_header`
  + `RsiStatus`/`parse_rsi_status`/`rsi_response_op_code` — but **NO response builders**
  (those exist only kernel-side). So librsi parses requests via lcs-core and **builds
  responses itself** from the uapi offsets.

## Built so far (verified)

- **Slice 1 — source registration — DONE.** `src/source.rs`: `rsi_register(hives,
  count, max_sequence)` opens `/dev/pkm_registry` (`O_RDWR|O_CLOEXEC`), marshals the
  caller's `struct rsi_hive` array into `reg_src_hive_entry`s (pure `marshal_hive`,
  unit-tested), `ioctl(REG_SRC_REGISTER)`, preserves the errno across the cleanup
  close. `<rsi/source.h>` + the `<rsi.h>` umbrella. cbindgen verify harness
  (`cbindgen.toml`, `abi/rsi-abi.h`, `tools/verify-abi.sh`) — all 5 checks green.
  Crate builds clean no_std, exports `rsi_register`, headers compile C/C++.
- **Slice 2 — request transport + decode — DONE.** `src/request.rs`,
  `<rsi/request.h>`: `rsi_read_request` (read(2) wrapper), `rsi_parse_request`
  (header → `struct rsi_request` with op_code/request_id/txn_id + a borrowed payload
  view), and **all 18 `rsi_request_*` decoders** wrapping lcs-core's own
  `parse_rsi_*_request_payload` (zero-copy; names/data borrow into the frame; GUIDs by
  value). Parse failures → `EBADMSG`. Round-trip-tested by building requests with
  lcs-core's `write_rsi_*_request_frame` then decoding.
- **Slice 3 — response building — DONE.** `src/response.rs`, `<rsi/response.h>`:
  `rsi_write_response` (write(2) wrapper), `rsi_respond_status` (18-byte header+status,
  covers every mutating op + all error replies), and the four read-op payload
  responses `rsi_respond_{lookup,enum_children,read_key,query_values}` — array-based
  (caller passes flat entry/metadata/value/blanket arrays; librsi heap-encodes the
  frame via a fallible sticky-OOM `FrameWriter`, writes, frees). lcs-core has no
  response builders, so these are hand-encoded from the uapi offsets (LE; length-
  prefixed fields; `[count][entries]` blocks; per-path-entry `target_type` tag).
  Round-trip-tested by encoding a response then parsing it with lcs-core's own
  `parse_rsi_*_success_response_payload` (proves kernel-acceptability).

**librsi status:** all three slices done — **27 `rsi_*` symbols**, 12 tests, clean
no_std build, all 5 ABI checks green, `<rsi/{source,request,response}.h>` + umbrella
compile C/C++. The full source-serve surface (register → read → decode → handle →
respond) is implemented.

## Next

- **Provium integration pass:** live coverage for the syscall/transport paths
  (`rsi_register`'s open+ioctl, `rsi_read_request`/`rsi_write_response`'s read/write) —
  only the pure marshalling/encoding is `cargo test`-covered today (via round-trips
  through lcs-core's own builders/parsers).
- **Repo:** create `peios/librsi/` on GitHub + push (public, like the siblings) — held
  off per the user's instruction; do when ready.
- **lcs-core no_std flip** still lives in pkm's uncommitted working tree (see Locked
  decisions) — commit it with pkm.
