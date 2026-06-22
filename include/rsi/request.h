/* SPDX-License-Identifier: MIT */
/*
 * <rsi/request.h> — receiving and decoding RSI requests.
 *
 * A source's serve loop reads one framed request from its source fd, splits the
 * header from the payload (rsi_parse_request → op-code / request id / transaction
 * id), dispatches on the op-code, and decodes the payload with the matching
 * rsi_request_* parser. Decoders are thin wrappers over the kernel's own RSI parsers,
 * so the wire handling is guaranteed compatible.
 *
 * Every decoded name/data field BORROWS into your frame buffer — the (ptr, len) pairs
 * are valid only until you reuse that buffer. Op-code and field constants (RSI_LOOKUP,
 * RSI_WRITE_KEY_FIELD_*, RSI_TXN_*) come from <pkm/lcs.h>.
 */
#ifndef RSI_REQUEST_H
#define RSI_REQUEST_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/lcs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A received RSI request: the kernel-stamped header plus a borrowed payload view. */
struct rsi_request {
	uint64_t	request_id;	/* echo this in the response */
	uint64_t	txn_id;		/* transaction id (0 outside a transaction) */
	const void     *payload;	/* borrowed; valid until the frame is reused */
	uint32_t	payload_len;
	uint16_t	op_code;	/* RSI_LOOKUP, RSI_SET_VALUE, … — dispatch on this */
};

/*
 * rsi_read_request - read one framed RSI request from the source fd.
 *
 * Thin wrapper over read(2): blocks until a request is queued, then returns the frame
 * length (pass it to rsi_parse_request). Returns 0 at EOF (source closing), or -1 with
 * errno — notably EMSGSIZE if @cap is smaller than the pending frame.
 */
ssize_t rsi_read_request(int fd, void *buf, size_t cap);

/*
 * rsi_parse_request - split a framed request into header + payload view.
 * Fills *@out (request id, txn id, op-code, borrowed payload pointer). Returns 0, or
 * -1 with errno (EINVAL on NULL args, EBADMSG on a malformed frame).
 */
int rsi_parse_request(const void *frame, size_t len, struct rsi_request *out);

/* ---- per-op payload decoders ---------------------------------------------- */
/*
 * Each takes the parsed @req and fills a flat struct: GUIDs by value, names/data as
 * borrowed (ptr, len) pairs into the frame. Returns 0, or -1 with errno (EINVAL on
 * NULL args or a decoder that does not match req->op_code, EBADMSG on a malformed
 * payload).
 */

/* LOOKUP: is @child_name visible under @parent_guid? */
struct rsi_lookup {
	uint8_t		parent_guid[16];
	const void     *child_name;
	uint32_t	child_name_len;
};
int rsi_request_lookup(const struct rsi_request *req, struct rsi_lookup *out);

/* CREATE_ENTRY: bind @child_name → @child_guid in @layer_name. */
struct rsi_create_entry {
	uint8_t		parent_guid[16];
	uint8_t		child_guid[16];
	const void     *child_name;
	uint32_t	child_name_len;
	const void     *layer_name;
	uint32_t	layer_name_len;
	uint64_t	sequence;
};
int rsi_request_create_entry(const struct rsi_request *req, struct rsi_create_entry *out);

/* HIDE_ENTRY: tombstone @child_name in @layer_name. */
struct rsi_hide_entry {
	uint8_t		parent_guid[16];
	const void     *child_name;
	uint32_t	child_name_len;
	const void     *layer_name;
	uint32_t	layer_name_len;
	uint64_t	sequence;
};
int rsi_request_hide_entry(const struct rsi_request *req, struct rsi_hide_entry *out);

/* DELETE_ENTRY: remove @child_name's entry in @layer_name. */
struct rsi_delete_entry {
	uint8_t		parent_guid[16];
	const void     *child_name;
	uint32_t	child_name_len;
	const void     *layer_name;
	uint32_t	layer_name_len;
};
int rsi_request_delete_entry(const struct rsi_request *req, struct rsi_delete_entry *out);

/* ENUM_CHILDREN: list the children of @parent_guid. */
struct rsi_enum_children {
	uint8_t		parent_guid[16];
};
int rsi_request_enum_children(const struct rsi_request *req, struct rsi_enum_children *out);

/* CREATE_KEY: create the key metadata record @guid under @parent_guid. */
struct rsi_create_key {
	uint8_t		guid[16];
	uint8_t		parent_guid[16];
	const void     *name;
	uint32_t	name_len;
	const void     *sd;
	uint32_t	sd_len;
	uint8_t		volatile_key;	/* 1 if volatile */
	uint8_t		symlink;	/* 1 if a symlink */
};
int rsi_request_create_key(const struct rsi_request *req, struct rsi_create_key *out);

/* READ_KEY / DROP_KEY: a request carrying just a key GUID. */
struct rsi_key_guid {
	uint8_t		guid[16];
};
int rsi_request_read_key(const struct rsi_request *req, struct rsi_key_guid *out);
int rsi_request_drop_key(const struct rsi_request *req, struct rsi_key_guid *out);

/* WRITE_KEY: update the mutable fields of @guid named by @field_mask. */
struct rsi_write_key {
	uint8_t		guid[16];
	uint32_t	field_mask;	/* RSI_WRITE_KEY_FIELD_SD | …_LAST_WRITE_TIME */
	const void     *sd;		/* NULL when the SD bit is clear */
	uint32_t	sd_len;
	uint64_t	last_write_time;	/* valid only when the time bit is set */
};
int rsi_request_write_key(const struct rsi_request *req, struct rsi_write_key *out);

/* QUERY_VALUES: read @value_name (or all values when @query_all) of @guid. */
struct rsi_query_values {
	uint8_t		guid[16];
	const void     *value_name;
	uint32_t	value_name_len;
	uint8_t		query_all;	/* 1 = every value (then value_name is ignored) */
};
int rsi_request_query_values(const struct rsi_request *req, struct rsi_query_values *out);

/* SET_VALUE: store @value_name in @layer_name with the given type/data. */
struct rsi_set_value {
	uint8_t		guid[16];
	const void     *value_name;
	uint32_t	value_name_len;
	const void     *layer_name;
	uint32_t	layer_name_len;
	uint32_t	value_type;
	const void     *data;
	uint32_t	data_len;
	uint64_t	sequence;
	uint64_t	expected_sequence;	/* CAS guard (0 disables) */
};
int rsi_request_set_value(const struct rsi_request *req, struct rsi_set_value *out);

/* DELETE_VALUE_ENTRY: remove @value_name's entry in @layer_name. */
struct rsi_delete_value_entry {
	uint8_t		guid[16];
	const void     *value_name;
	uint32_t	value_name_len;
	const void     *layer_name;
	uint32_t	layer_name_len;
};
int rsi_request_delete_value_entry(const struct rsi_request *req,
				   struct rsi_delete_value_entry *out);

/* SET_BLANKET_TOMBSTONE: set (@set) or clear a blanket tombstone on @layer_name. */
struct rsi_set_blanket_tombstone {
	uint8_t		guid[16];
	const void     *layer_name;
	uint32_t	layer_name_len;
	uint8_t		set;		/* 1 = set, 0 = clear */
	uint64_t	sequence;
};
int rsi_request_set_blanket_tombstone(const struct rsi_request *req,
				      struct rsi_set_blanket_tombstone *out);

/* BEGIN_TRANSACTION: open @transaction_id in @mode. */
struct rsi_begin_transaction {
	uint64_t	transaction_id;
	uint32_t	mode;		/* RSI_TXN_READ_WRITE (0) or RSI_TXN_READ_ONLY (1) */
};
int rsi_request_begin_transaction(const struct rsi_request *req,
				  struct rsi_begin_transaction *out);

/* COMMIT_TRANSACTION / ABORT_TRANSACTION: a request carrying just a transaction id. */
struct rsi_transaction {
	uint64_t	transaction_id;
};
int rsi_request_commit_transaction(const struct rsi_request *req, struct rsi_transaction *out);
int rsi_request_abort_transaction(const struct rsi_request *req, struct rsi_transaction *out);

/* DELETE_LAYER / FLUSH: a request carrying just a length-prefixed name. */
struct rsi_name {
	const void     *name;
	uint32_t	name_len;
};
int rsi_request_delete_layer(const struct rsi_request *req, struct rsi_name *out);
int rsi_request_flush(const struct rsi_request *req, struct rsi_name *out);

#ifdef __cplusplus
}
#endif

#endif /* RSI_REQUEST_H */
