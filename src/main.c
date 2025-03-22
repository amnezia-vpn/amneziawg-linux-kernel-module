// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2024 AmneziaVPN <admin@amnezia.org>. All Rights Reserved.
 */

#include "version.h"
#include "device.h"
#include "noise.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "netlink.h"
#include "uapi/wireguard.h"
#include "crypto/zinc.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/genetlink.h>
#include <net/rtnetlink.h>

/* Module parameters */
static bool enable_advanced_security = false;
module_param(enable_advanced_security, bool, 0600);
MODULE_PARM_DESC(enable_advanced_security, "Enable advanced security features (adds overhead)");

static bool enable_ratelimiter = false;
module_param(enable_ratelimiter, bool, 0600);
MODULE_PARM_DESC(enable_ratelimiter, "Enable rate limiting for DoS protection (adds overhead)");

static bool enable_cookie_protection = false;
module_param(enable_cookie_protection, bool, 0600);
MODULE_PARM_DESC(enable_cookie_protection, "Enable cookie protection against UDP amplification (adds overhead)");

static bool enable_full_crypto = false;
module_param(enable_full_crypto, bool, 0600);
MODULE_PARM_DESC(enable_full_crypto, "Enable all crypto algorithms (disable for minimal crypto)");

static int __init wg_mod_init(void)
{
	int ret;

	if (enable_full_crypto) {
		if ((ret = chacha20_mod_init()) || (ret = poly1305_mod_init()) ||
		    (ret = chacha20poly1305_mod_init()) || (ret = blake2s_mod_init()) ||
		    (ret = curve25519_mod_init()))
			return ret;
	} else {
		if ((ret = chacha20poly1305_mod_init()) || (ret = curve25519_mod_init()))
			return ret;
	}

	ret = wg_allowedips_slab_init();
	if (ret < 0)
		goto err_allowedips;

	wg_noise_init();

	ret = wg_peer_init();
	if (ret < 0)
		goto err_peer;

	ret = wg_device_init();
	if (ret < 0)
		goto err_device;

	ret = wg_genetlink_init();
	if (ret < 0)
		goto err_netlink;

	pr_info("AmneziaWG " WIREGUARD_VERSION " loaded. See amnezia.org for information.\n");
	pr_info("Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.\n");
	pr_info("Copyright (C) 2024 AmneziaVPN <admin@amnezia.org>. All Rights Reserved.\n");

	return 0;

err_netlink:
	wg_device_uninit();
err_device:
	wg_peer_uninit();
err_peer:
	wg_allowedips_slab_uninit();
err_allowedips:
	return ret;
}

static void __exit wg_mod_exit(void)
{
	wg_genetlink_uninit();
	wg_device_uninit();
	wg_peer_uninit();
	wg_allowedips_slab_uninit();
}

module_param(bogus_endpoints, int, 0600);
module_param(bogus_endpoints_prefix, charp, 0600);
module_param(bogus_endpoints_prefix6, charp, 0600);
module_init(wg_mod_init);
module_exit(wg_mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("AmneziaWG secure network tunnel");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>, AmneziaVPN <admin@amnezia.org>");
MODULE_VERSION(WIREGUARD_VERSION);
MODULE_ALIAS_RTNL_LINK(KBUILD_MODNAME);
MODULE_ALIAS_GENL_FAMILY(WG_GENL_NAME);
MODULE_INFO(intree, "Y");
