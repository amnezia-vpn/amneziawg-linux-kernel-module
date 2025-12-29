#include "junk.h"
#include "messages.h"
#include "peer.h"

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/ktime.h>

/*
 * Protocol mimicry templates for DPI evasion
 * These generate valid-looking protocol headers with randomized fields
 */

/* QUIC Initial packet template (RFC 9000) */
static const u8 quic_template[] = {
	0xc0,						/* Long header, Initial type */
	0x00, 0x00, 0x00, 0x01,				/* Version: QUIC v1 */
	0x08,						/* DCID length: 8 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* DCID placeholder */
	0x08,						/* SCID length: 8 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* SCID placeholder */
	0x00,						/* Token length: 0 */
	0x44, 0xb4,					/* Length: 1200 (varint) */
	0x00, 0x00, 0x00, 0x00				/* Packet number placeholder */
};
#define QUIC_DCID_OFFSET	6
#define QUIC_SCID_OFFSET	15
#define QUIC_PKTNUM_OFFSET	26
#define QUIC_HEADER_SIZE	30
#define QUIC_MIN_SIZE		1200

/* DNS query template (RFC 1035) - google.com A record */
static const u8 dns_template[] = {
	0x00, 0x00,					/* Transaction ID placeholder */
	0x01, 0x00,					/* Flags: standard query, RD */
	0x00, 0x01,					/* Questions: 1 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		/* Answer/Auth/Add: 0 */
	0x06, 'g', 'o', 'o', 'g', 'l', 'e',		/* Label: google */
	0x03, 'c', 'o', 'm',				/* Label: com */
	0x00,						/* Root terminator */
	0x00, 0x01,					/* Type: A */
	0x00, 0x01					/* Class: IN */
};
#define DNS_TXID_OFFSET		0
#define DNS_SIZE		33

/* TLS 1.3 ClientHello template (RFC 8446) */
static const u8 tls_template[] = {
	/* Record layer */
	0x16,						/* Content type: Handshake */
	0x03, 0x01,					/* Version: TLS 1.0 (compat) */
	0x00, 0xb4,					/* Record length: 180 */
	/* Handshake header */
	0x01,						/* Type: ClientHello */
	0x00, 0x00, 0xb0,				/* Length: 176 */
	0x03, 0x03,					/* Version: TLS 1.2 */
	/* 32-byte ClientRandom placeholder */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* Session ID */
	0x20,						/* Session ID length: 32 */
	/* 32-byte Session ID placeholder */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* Cipher suites */
	0x00, 0x06,					/* Cipher suite length: 6 */
	0x13, 0x01,					/* TLS_AES_128_GCM_SHA256 */
	0x13, 0x02,					/* TLS_AES_256_GCM_SHA384 */
	0x13, 0x03,					/* TLS_CHACHA20_POLY1305 */
	/* Compression */
	0x01, 0x00,					/* Compression: null */
	/* Extensions */
	0x00, 0x61,					/* Extensions length: 97 */
	/* SNI extension (example.com) */
	0x00, 0x00,					/* Type: server_name */
	0x00, 0x10,					/* Length: 16 */
	0x00, 0x0e,					/* SNI list length: 14 */
	0x00,						/* Name type: hostname */
	0x00, 0x0b,					/* Hostname length: 11 */
	'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	/* supported_versions extension */
	0x00, 0x2b,					/* Type: supported_versions */
	0x00, 0x03,					/* Length: 3 */
	0x02,						/* Versions length: 2 */
	0x03, 0x04,					/* TLS 1.3 */
	/* supported_groups extension */
	0x00, 0x0a,					/* Type: supported_groups */
	0x00, 0x04,					/* Length: 4 */
	0x00, 0x02,					/* Groups length: 2 */
	0x00, 0x1d,					/* x25519 */
	/* key_share extension */
	0x00, 0x33,					/* Type: key_share */
	0x00, 0x26,					/* Length: 38 */
	0x00, 0x24,					/* Client shares length: 36 */
	0x00, 0x1d,					/* Group: x25519 */
	0x00, 0x20,					/* Key length: 32 */
	/* 32-byte key share placeholder */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* signature_algorithms extension */
	0x00, 0x0d,					/* Type: signature_algorithms */
	0x00, 0x10,					/* Length: 16 */
	0x00, 0x0e,					/* Algorithms length: 14 */
	0x04, 0x03,					/* ecdsa_secp256r1_sha256 */
	0x05, 0x03,					/* ecdsa_secp384r1_sha384 */
	0x06, 0x03,					/* ecdsa_secp521r1_sha512 */
	0x02, 0x03,					/* ecdsa_sha1 */
	0x08, 0x04,					/* rsa_pss_rsae_sha256 */
	0x08, 0x05,					/* rsa_pss_rsae_sha384 */
	0x08, 0x06					/* rsa_pss_rsae_sha512 */
};
#define TLS_RANDOM_OFFSET	11
#define TLS_SESSID_OFFSET	44
#define TLS_KEYSHARE_OFFSET	133
#define TLS_SIZE		185

static int parse_b_tag(char* val, struct list_head* head) {
    int err;
    int i;
    int len;
    u8* pkt;
    struct jp_tag* tag;

    if (!val || strncmp(val, "0x", 2))
        return -EINVAL;
    val += 2;

    len = strlen(val);
    if (len == 0 || len % 2 != 0)
        return -EINVAL;
    len /= 2;

    pkt = kmalloc(len, GFP_KERNEL);
    if (!pkt)
        return -ENOMEM;

    for (i = len - 1; i >= 0; --i) {
        err = kstrtou8(val + i * 2, 16, pkt + i);
        if (err) {
            err = -EINVAL;
            goto error;
        }

        val[i * 2] = '\0';
    }

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag) {
        err = -ENOMEM;
        goto error;
    }

    tag->pkt = pkt;
    tag->pkt_size = len;

    list_add(&tag->head, head);
    return 0;

error:
    kfree(pkt);
    return err;
}

static void pkt_counter_modifier(char* buf, int len, struct wg_peer *peer) {
    int val = atomic_read(&peer->jp_packet_counter);
    val = htonl(val);
    memcpy(buf, &val, sizeof(val));
}

static int parse_c_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;

    if (val)
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = sizeof(u32);
    tag->func = pkt_counter_modifier;

    list_add(&tag->head, head);
    return 0;
}

static void unix_time_modifier(char* buf, int len, struct wg_peer *peer) {
    u32 time = (u32)ktime_get_real_seconds();
    time = htonl(time);
    memcpy(buf, &time, sizeof(time));
}

static int parse_t_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;

    if (val)
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = sizeof(u32);
    tag->func = unix_time_modifier;

    list_add(&tag->head, head);
    return 0;
}

static void random_byte_modifier(char* buf, int len, struct wg_peer *peer) {
    get_random_bytes(buf, len);
}

static int parse_r_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len))
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = len;
    tag->func = random_byte_modifier;

    list_add(&tag->head, head);
    return 0;
}

#define ALPHABET_LEN 26
#define LETTER_LEN (ALPHABET_LEN * 2)

static void random_char_modifier(char* buf, int len, struct wg_peer *peer) {
    int i;
    u32 byte;

    for (i = 0; i < len; ++i) {
        byte = get_random_u32() % LETTER_LEN;
        buf[i] = (byte < ALPHABET_LEN) ? 'a' + byte : 'A' + byte - ALPHABET_LEN;
    }
}

static int parse_rc_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len))
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = len;
    tag->func = random_char_modifier;

    list_add(&tag->head, head);
    return 0;
}

#define DIGIT_LEN 10

static void random_digit_modifier(char* buf, int len, struct wg_peer *peer) {
    int i;

    for (i = 0; i < len; ++i)
        buf[i] = '0' + get_random_u32() % DIGIT_LEN;
}

static int parse_rd_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len))
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = len;
    tag->func = random_digit_modifier;

    list_add(&tag->head, head);
    return 0;
}

/*
 * Protocol mimicry modifiers - randomize dynamic fields at send time
 */

/* QUIC: Randomize DCID, SCID, packet number, and padding */
static void quic_modifier(char *buf, int len, struct wg_peer *peer)
{
	get_random_bytes(buf + QUIC_DCID_OFFSET, 8);
	get_random_bytes(buf + QUIC_SCID_OFFSET, 8);
	get_random_bytes(buf + QUIC_PKTNUM_OFFSET, 4);
	if (len > QUIC_HEADER_SIZE)
		get_random_bytes(buf + QUIC_HEADER_SIZE, len - QUIC_HEADER_SIZE);
}

static int parse_quic_tag(char *val, struct list_head *head)
{
	struct jp_tag *tag;
	u8 *pkt;

	if (val)
		return -EINVAL;

	pkt = kmalloc(QUIC_MIN_SIZE, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	memcpy(pkt, quic_template, QUIC_HEADER_SIZE);
	memset(pkt + QUIC_HEADER_SIZE, 0, QUIC_MIN_SIZE - QUIC_HEADER_SIZE);

	tag = kzalloc(sizeof(*tag), GFP_KERNEL);
	if (!tag) {
		kfree(pkt);
		return -ENOMEM;
	}

	tag->pkt = pkt;
	tag->pkt_size = QUIC_MIN_SIZE;
	tag->func = quic_modifier;

	list_add(&tag->head, head);
	return 0;
}

/* DNS: Randomize transaction ID */
static void dns_modifier(char *buf, int len, struct wg_peer *peer)
{
	get_random_bytes(buf + DNS_TXID_OFFSET, 2);
}

static int parse_dns_tag(char *val, struct list_head *head)
{
	struct jp_tag *tag;
	u8 *pkt;

	if (val)
		return -EINVAL;

	pkt = kmemdup(dns_template, DNS_SIZE, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	tag = kzalloc(sizeof(*tag), GFP_KERNEL);
	if (!tag) {
		kfree(pkt);
		return -ENOMEM;
	}

	tag->pkt = pkt;
	tag->pkt_size = DNS_SIZE;
	tag->func = dns_modifier;

	list_add(&tag->head, head);
	return 0;
}

/* TLS: Randomize ClientRandom, SessionID, and key_share */
static void tls_modifier(char *buf, int len, struct wg_peer *peer)
{
	get_random_bytes(buf + TLS_RANDOM_OFFSET, 32);
	get_random_bytes(buf + TLS_SESSID_OFFSET, 32);
	get_random_bytes(buf + TLS_KEYSHARE_OFFSET, 32);
}

static int parse_tls_tag(char *val, struct list_head *head)
{
	struct jp_tag *tag;
	u8 *pkt;

	if (val)
		return -EINVAL;

	pkt = kmemdup(tls_template, TLS_SIZE, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	tag = kzalloc(sizeof(*tag), GFP_KERNEL);
	if (!tag) {
		kfree(pkt);
		return -ENOMEM;
	}

	tag->pkt = pkt;
	tag->pkt_size = TLS_SIZE;
	tag->func = tls_modifier;

	list_add(&tag->head, head);
	return 0;
}

int jp_parse_tags(char* str, struct list_head* head) {
    int err = 0;
    char* key;
    char* val;

    while (true)
    {
        strsep(&str, "<");
        val = strsep(&str, ">");
        if (!val)
            break;

        key = strsep(&val, " ");

        if (!strcmp(key, "b")) {
            err = parse_b_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "c")) {
            err = parse_c_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "t")) {
            err = parse_t_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "r")) {
            err = parse_r_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "rc")) {
            err = parse_rc_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "rd")) {
            err = parse_rd_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "quic")) {
            err = parse_quic_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "dns")) {
            err = parse_dns_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "tls")) {
            err = parse_tls_tag(val, head);
            if (err)
                return err;
        }
        else
            return -EINVAL;
    }

    return 0;
}

void jp_tag_free(struct jp_tag* tag) {
    kfree(tag->pkt);
}

void jp_spec_free(struct jp_spec *spec) {
    kfree(spec->pkt);
    kfree(spec->mods);
}

int jp_spec_setup(struct jp_spec *spec) {
    int err = 0;
    int pkt_size, mods_size;
    struct jp_tag *tag, *tmp;
    struct jp_modifier *mod;
    char* buf;
    LIST_HEAD(head);

    mutex_init(&spec->lock);

    if (spec->desc == NULL)
        return 0;

    mutex_lock(&spec->lock);

    buf = kstrdup(spec->desc, GFP_KERNEL);
    if (!buf) {
        err = -ENOMEM;
        goto error;
    }

    err = jp_parse_tags(buf, &head);
    if (err)
        goto error;

    pkt_size = 0;
    mods_size = 0;

    list_for_each_entry(tag, &head, head) {
        pkt_size += tag->pkt_size;

        if (tag->func)
            ++mods_size;
    }

    if (pkt_size > MESSAGE_MAX_SIZE) {
        err = -EINVAL;
        goto error;
    }

    spec->pkt = kzalloc(pkt_size, GFP_KERNEL);
    spec->mods = kzalloc(mods_size * sizeof(*spec->mods), GFP_KERNEL);
    if (!spec->pkt || !spec->mods) {
        err = -ENOMEM;
        goto error;
    }

    spec->pkt_size = 0;
    list_for_each_entry_reverse(tag, &head, head) {
        if (tag->pkt) {
            memcpy(spec->pkt + spec->pkt_size, tag->pkt, tag->pkt_size);
        }

        if (tag->func) {
            mod = spec->mods + spec->mods_size;
            mod->func = tag->func;
            mod->buf = spec->pkt + spec->pkt_size;
            mod->buf_len = tag->pkt_size;
            
            spec->mods_size++;
        }

        spec->pkt_size += tag->pkt_size;
    }

error:
    list_for_each_entry_safe(tag, tmp, &head, head) {
        jp_tag_free(tag);
        list_del(&tag->head);
        kfree(tag);
    }
    kfree(buf);
    mutex_unlock(&spec->lock);
    return err;
}

void jp_spec_applymods(struct jp_spec* spec, struct wg_peer* peer) {
    int i;
    struct jp_modifier* mod;

    for (i = 0; i < spec->mods_size; i++) {
        mod = &spec->mods[i];
        if(mod->func)
            mod->func(mod->buf, mod->buf_len, peer);
    }
}
