/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Session-layer BFD-style probe marker for wirescale.
 *
 * The marker is the fixed-size prefix of a decrypted WireGuard data
 * payload. Both peers must be built with BFD support (bilateral); on
 * mismatch the packet flows to the TUN interface as usual.
 *
 * Wire format (30 bytes, all integers big-endian so that the layout
 * does not depend on host endianness):
 *
 *  Offset  Field     Size  Meaning
 *  0       magic     4     0x57534246 ("WSBF")
 *  4       version   1     WS_BFD_VERSION
 *  5       type      1     WS_BFD_TYPE_PROBE | WS_BFD_TYPE_REPLY
 *  6       seq       8     sequence number of the initiator
 *  14      ts_send   8     unix nanoseconds at the sender
 *  22      ts_recv   8     unix nanoseconds at the replier (reply only)
 *
 * The first byte is 'W' (never 0x00), so the marker cannot be mistaken
 * for a keepalive (all-zero payload check in wg_packet_consume_data_done).
 */

#ifndef _WG_BFD_H
#define _WG_BFD_H

#include <linux/types.h>

#define WS_BFD_MAGIC		0x57534246U
#define WS_BFD_VERSION		1
#define WS_BFD_MARKER_LEN	30

enum ws_bfd_type {
	WS_BFD_TYPE_PROBE = 1,
	WS_BFD_TYPE_REPLY = 2
};

struct ws_bfd_marker {
	u8 type;
	u64 seq;
	u64 ts_send;
	u64 ts_recv;
};

static inline void ws_bfd_encode(u8 *buf, u8 type, u64 seq, u64 ts_send,
				 u64 ts_recv)
{
	put_unaligned_be32(WS_BFD_MAGIC, buf);
	buf[4] = WS_BFD_VERSION;
	buf[5] = type;
	put_unaligned_be64(seq, buf + 6);
	put_unaligned_be64(ts_send, buf + 14);
	put_unaligned_be64(ts_recv, buf + 22);
}

static inline bool ws_bfd_decode(const u8 *buf, struct ws_bfd_marker *marker)
{
	if (get_unaligned_be32(buf) != WS_BFD_MAGIC)
		return false;
	if (buf[4] != WS_BFD_VERSION)
		return false;
	if (buf[5] != WS_BFD_TYPE_PROBE && buf[5] != WS_BFD_TYPE_REPLY)
		return false;
	marker->type = buf[5];
	marker->seq = get_unaligned_be64(buf + 6);
	marker->ts_send = get_unaligned_be64(buf + 14);
	marker->ts_recv = get_unaligned_be64(buf + 22);
	return true;
}

#endif /* _WG_BFD_H */
