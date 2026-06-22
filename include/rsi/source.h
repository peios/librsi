/* SPDX-License-Identifier: MIT */
/*
 * <rsi/source.h> — becoming a registry source.
 *
 * rsi_register() opens /dev/pkm_registry and registers the hives this process backs,
 * returning the source fd. From then on the source serves the RSI protocol on that
 * fd: read(2) dequeues one framed request, write(2) sends one framed response
 * (request/response helpers are in their own headers). Registration requires
 * SeTcbPrivilege. RSI wire constants (RSI_HIVE_PRIVATE, RSI_*) come from <pkm/lcs.h>.
 */
#ifndef RSI_SOURCE_H
#define RSI_SOURCE_H

#include <stddef.h>
#include <stdint.h>

#include <pkm/lcs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One hive this source backs. */
struct rsi_hive {
	const void     *name;		/* hive name (not NUL-terminated) */
	uint32_t	name_len;
	uint32_t	flags;		/* RSI_HIVE_PRIVATE, or 0 for a global hive */
	uint8_t		root_guid[16];	/* root key GUID */
	uint8_t		scope_guid[16];	/* private hives; zero for a global hive */
};

/*
 * rsi_register - become a registry source backing @hives.
 * @hives:        array of @count hives this source serves.
 * @count:        number of hives (>= 1; kernel MaxHivesPerSource limit applies).
 * @max_sequence: the highest sequence number this source has already persisted
 *                (the kernel resumes its global counter past it).
 *
 * Opens /dev/pkm_registry and registers all @count hives in one call. Returns the
 * source fd — read(2) RSI requests and write(2) responses on it — or -1 with errno,
 * including EPERM (no SeTcbPrivilege), EINVAL, ENOSPC, ENOMEM, EFAULT, or any
 * /dev/pkm_registry open(2) error.
 */
int rsi_register(const struct rsi_hive *hives, uint32_t count, uint64_t max_sequence);

#ifdef __cplusplus
}
#endif

#endif /* RSI_SOURCE_H */
