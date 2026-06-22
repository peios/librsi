/* SPDX-License-Identifier: MIT */
/*
 * <rsi/response.h> — building and sending RSI responses.
 *
 * After handling a request, reply on the source fd with a framed response: a 14-byte
 * header (request id echoed, op-code OR'd with RSI_RESPONSE_BIT) + a 4-byte RSI_*
 * status, then an op-specific payload for payload-bearing successes.
 *
 * Most ops are status-only (rsi_respond_status), and any op reports a non-OK status
 * that way. LOOKUP, ENUM_CHILDREN, READ_KEY, DELETE_LAYER, and QUERY_VALUES carry a
 * payload on success — pass the result as flat arrays and librsi heap-encodes the frame.
 * Multi-byte integers are little-endian;
 * names/data are length-prefixed. Status / target-type constants (RSI_OK,
 * RSI_PATH_TARGET_GUID, …) come from <pkm/lcs.h>. For every (ptr, len) field, ptr
 * may be NULL only when len is zero. Boolean fields must be 0 or 1; hidden path
 * targets must carry an all-zero GUID. LOOKUP/ENUM_CHILDREN metadata must exactly
 * cover GUID path targets; DELETE_LAYER orphan GUIDs must be nonzero and unique.
 *
 * The rsi_respond_* helpers return 0, or -1 with errno. The pointer/count and
 * (ptr, len) rules above are caller-contract EINVAL cases; per-helper notes below
 * list op-specific additions. Helpers can also fail with ENOMEM during validation
 * or frame allocation, EOVERFLOW if validation arithmetic or the assembled frame is
 * too large, EIO on a short write, or the raw write(2) errno.
 */
#ifndef RSI_RESPONSE_H
#define RSI_RESPONSE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/lcs.h>
#include <rsi/request.h>	/* struct rsi_request */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * rsi_write_response - write one pre-built response frame to the source fd. Thin
 * wrapper over write(2); returns the bytes written, or -1 with errno. Most callers
 * should use the rsi_respond_* helpers below.
 */
ssize_t rsi_write_response(int fd, const void *frame, size_t len);

/*
 * rsi_respond_status - reply to @req with a status-only response.
 *
 * Use for status-only ops on success (@status = RSI_OK) and for ANY op to report a
 * non-OK RSI_* status. Returns 0, or -1 with errno (EINVAL on a bad @req, unknown
 * status, RSI_OK for a payload-bearing op, EIO on a short write, or the write(2)
 * error).
 */
int rsi_respond_status(int fd, const struct rsi_request *req, uint32_t status);

/* ---- payload-bearing success responses ------------------------------------ */

/* One resolved path entry: a layer's view of a child (LOOKUP, ENUM_CHILDREN). */
struct rsi_path_entry {
	const void     *layer;
	uint32_t	layer_len;
	uint8_t		target_type;	/* RSI_PATH_TARGET_GUID (0) / RSI_PATH_TARGET_HIDDEN (1) */
	uint8_t		target_guid[16];
	uint64_t	sequence;
};

/* One key's non-layered metadata, returned alongside LOOKUP / ENUM_CHILDREN. */
struct rsi_key_metadata {
	uint8_t		guid[16];
	const void     *sd;
	uint32_t	sd_len;
	uint8_t		volatile_key;
	uint8_t		symlink;
	uint64_t	last_write_time;
};

/*
 * rsi_respond_lookup - LOOKUP success: the path @entries for the looked-up child plus
 * the @metadata for each referenced key. Returns 0, or -1 with errno (EINVAL if @req
 * is not a LOOKUP request, a nonzero count has a NULL array, or an entry has invalid
 * target/boolean fields, missing/duplicate metadata, or unreferenced metadata).
 */
int rsi_respond_lookup(int fd, const struct rsi_request *req,
		       const struct rsi_path_entry *entries, uint32_t entry_count,
		       const struct rsi_key_metadata *metadata, uint32_t metadata_count);

/*
 * rsi_respond_delete_layer - DELETE_LAYER success: @orphaned_guids is a flat
 * orphaned_count * 16 byte array of key GUIDs orphaned by the deleted layer. Returns
 * 0, or -1 with errno (EINVAL if @req is not a DELETE_LAYER request or a nonzero
 * count has a NULL array, nil GUID, or duplicate GUID).
 */
int rsi_respond_delete_layer(int fd, const struct rsi_request *req,
			     const uint8_t *orphaned_guids, uint32_t orphaned_count);

/* One enumerated child: its name and the path entries that resolve it. */
struct rsi_child_entry {
	const void	       *child_name;
	uint32_t		child_name_len;
	const struct rsi_path_entry *entries;
	uint32_t		entry_count;
};

/*
 * rsi_respond_enum_children - ENUM_CHILDREN success: each child with its path entries,
 * plus the @metadata for each referenced key. Returns 0, or -1 with errno (EINVAL if
 * @req is not an ENUM_CHILDREN request, a nonzero count has a NULL array, or an entry
 * has invalid target/boolean fields, missing/duplicate metadata, or unreferenced
 * metadata).
 */
int rsi_respond_enum_children(int fd, const struct rsi_request *req,
			      const struct rsi_child_entry *children, uint32_t child_count,
			      const struct rsi_key_metadata *metadata, uint32_t metadata_count);

/*
 * rsi_respond_read_key - READ_KEY success: the key's non-layered metadata. Returns 0,
 * or -1 with errno (EINVAL if @req is not a READ_KEY request, @parent_guid is NULL,
 * or a boolean field is invalid).
 */
int rsi_respond_read_key(int fd, const struct rsi_request *req, const void *name,
			 uint32_t name_len, const uint8_t *parent_guid, const void *sd,
			 uint32_t sd_len, uint8_t volatile_key, uint8_t symlink,
			 uint64_t last_write_time);

/* One effective value entry (QUERY_VALUES). */
struct rsi_value_entry {
	const void     *value_name;
	uint32_t	value_name_len;
	const void     *layer_name;
	uint32_t	layer_name_len;
	uint32_t	value_type;
	const void     *data;
	uint32_t	data_len;
	uint64_t	sequence;
};

/* One blanket-tombstone entry (QUERY_VALUES). */
struct rsi_blanket_entry {
	const void     *layer_name;
	uint32_t	layer_name_len;
	uint64_t	sequence;
};

/*
 * rsi_respond_query_values - QUERY_VALUES success: the value @entries plus the
 * @blankets (blanket tombstones). Returns 0, or -1 with errno (EINVAL if @req is not a
 * QUERY_VALUES request or a nonzero count has a NULL array).
 */
int rsi_respond_query_values(int fd, const struct rsi_request *req,
			     const struct rsi_value_entry *entries, uint32_t entry_count,
			     const struct rsi_blanket_entry *blankets, uint32_t blanket_count);

#ifdef __cplusplus
}
#endif

#endif /* RSI_RESPONSE_H */
