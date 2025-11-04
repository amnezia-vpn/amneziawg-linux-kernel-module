/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_NETLINK_H
#define _WG_NETLINK_H

#include "peer.h"
#include "noise.h"

extern int bogus_endpoints;
extern char *bogus_endpoints_prefix;
extern char *bogus_endpoints_prefix6;

int wg_genl_mcast_peer_unknown(struct wg_device *wg, const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
	                           struct endpoint *endpoint);
int wg_genetlink_init(void);
void wg_genetlink_uninit(void);

#endif /* _WG_NETLINK_H */
