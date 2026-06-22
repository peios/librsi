/* SPDX-License-Identifier: MIT */
/*
 * <rsi.h> — librsi umbrella header.
 *
 * librsi is the userspace library for implementing a Peios registry *source* (a
 * storage backend) — the provider counterpart to libpeios's registry client. A
 * source registers with the kernel and then serves the RSI (Registry Source
 * Interface) framed protocol on its source fd: it receives requests and sends
 * responses. Include this for the whole API, or the individual concept headers for
 * a tighter surface.
 *
 *   Source lifecycle: <rsi/source.h>.
 *   Request decoding: <rsi/request.h>.
 *   Response building: <rsi/response.h>.
 */
#ifndef RSI_H
#define RSI_H

#include <rsi/source.h>
#include <rsi/request.h>
#include <rsi/response.h>

#endif /* RSI_H */
