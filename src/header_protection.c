#include "header_protection.h"
#include "device.h"

#include <crypto/chacha.h>

bool awg_header_protection_init(struct chacha_state *state, struct wg_device *wg, u8 *nonce) {
	struct header_protection* p = &wg->header_protection;
	bool res = false;
	u8 iv[16];

	read_lock_bh(&p->lock);
	if (!p->has_protection)
		goto out;

	memset(iv, 0, 4);
	memcpy(iv + 4, nonce, 12);

	chacha_init(state, p->key, iv);
	res = true;
out:
	read_unlock_bh(&p->lock);
	return res;
}

void awg_header_protection_set_key(struct header_protection *p, u8 key[HEADER_PROTECTION_KEY_SIZE]) {
	write_lock_bh(&p->lock);
	p->key[0] = get_unaligned_le32(key + 0);
	p->key[1] = get_unaligned_le32(key + 4);
	p->key[2] = get_unaligned_le32(key + 8);
	p->key[3] = get_unaligned_le32(key + 12);
	p->key[4] = get_unaligned_le32(key + 16);
	p->key[5] = get_unaligned_le32(key + 20);
	p->key[6] = get_unaligned_le32(key + 24);
	p->key[7] = get_unaligned_le32(key + 28);
	WRITE_ONCE(p->has_protection, true);
	write_unlock_bh(&p->lock);
}

bool awg_header_protection_get_key(struct header_protection *p, u8 key[HEADER_PROTECTION_KEY_SIZE]) {
	bool available;

	read_lock_bh(&p->lock);
	available = p->has_protection;
	put_unaligned_le32(p->key[0], key + 0);
	put_unaligned_le32(p->key[1], key + 4);
	put_unaligned_le32(p->key[2], key + 8);
	put_unaligned_le32(p->key[3], key + 12);
	put_unaligned_le32(p->key[4], key + 16);
	put_unaligned_le32(p->key[5], key + 20);
	put_unaligned_le32(p->key[6], key + 24);
	put_unaligned_le32(p->key[7], key + 28);
	read_unlock_bh(&p->lock);
	return available;
}
