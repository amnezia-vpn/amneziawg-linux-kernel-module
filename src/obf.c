#include "obf.h"

#include <linux/string.h>
#include <linux/types.h>
#include <linux/memcontrol.h>
#include <linux/list.h>

struct bytes_obf {
    int len;
    u8 buf[];
};

static void bytes_obf_encode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    struct bytes_obf* obf = ctx;
    memcpy(dst, obf->buf, obf->len);
}

static bool bytes_obf_decode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    struct bytes_obf* obf = ctx;
    return 0 == memcmp(src, obf->buf, obf->len);
}

static int bytes_obf_encoded_len(void *ctx, int decoded_len) {
    struct bytes_obf* obf = ctx;
    return obf->len;
}

static int bytes_obf_decoded_len(void *ctx, int encoded_len) {
    return 0;
}

static int bytes_obf_genspec(void *ctx, char* buf) {
    struct bytes_obf* obf = ctx;
    int i;

    if (buf) {
        sprintf(buf, "<b 0x");
        for (i = 0; i < obf->len; ++i)
            sprintf(buf + 5 + i * 2, "%02x", obf->buf[i]);
        sprintf(buf + 5 + obf->len * 2, ">");
    }

    return 5 + obf->len * 2 + 1;
}

static void bytes_obf_destroy(void* ctx) {
    kfree(ctx);
}

static const struct obf_ops bytes_obf_ops = {
    .encode = bytes_obf_encode,
    .decode = bytes_obf_decode,
    .encoded_len = bytes_obf_encoded_len,
    .decoded_len = bytes_obf_decoded_len,
    .genspec = bytes_obf_genspec,
    .destroy = bytes_obf_destroy,
};

static int bytes_obf_setup(struct obf* obf, char* val) {
    int len, i, err;
    struct bytes_obf* priv;

    if (!val)
        return -EINVAL;

    if (!strncmp(val, "0x", 2))
        val += 2;

    len = strlen(val);
    if (len == 0 || len % 2 != 0)
        return -EINVAL;
    len /= 2;

    priv = kmalloc(sizeof(*priv) + len, GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    priv->len = len;

    for (i = len - 1; i >= 0; --i) {
        err = kstrtou8(val + i * 2, 16, priv->buf + i);
        if (err) {
            err = -EINVAL;
            goto priv_error;
        }
        val[i * 2] = '\0';
    }

    obf->ops = &bytes_obf_ops;
    obf->priv = priv;

    return 0;

priv_error:
    kfree(priv);
    return err;
}

static void timestamp_obf_encode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    u32 time = (u32)ktime_get_real_seconds();
    time = htonl(time);
    memcpy(dst, &time, sizeof(time));
}

static bool timestamp_obf_decode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    return true;
}

static int timestamp_obf_encoded_len(void *ctx, int decoded_len) {
    return 4;
}

static int timestamp_obf_decoded_len(void *ctx, int encoded_len) {
    return 0;
}

static int timestamp_obf_genspec(void *ctx, char* buf) {
    return !buf ? 3 : sprintf(buf, "<t>");
}

static const struct obf_ops timestamp_obf_ops = {
    .encode = timestamp_obf_encode,
    .decode = timestamp_obf_decode,
    .encoded_len = timestamp_obf_encoded_len,
    .decoded_len = timestamp_obf_decoded_len,
    .genspec = timestamp_obf_genspec,
    .destroy = NULL,
};

static int timestamp_obf_setup(struct obf* obf, char *val) {
    if (val)
        return -EINVAL;

    obf->ops = &timestamp_obf_ops;
    obf->priv = NULL;

    return 0;
}

static void rand_obf_encode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    get_random_bytes(dst, nDst);
}

static bool rand_obf_decode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    return true;
}

static int rand_obf_encoded_len(void *ctx, int decoded_len) {
    return (uintptr_t)ctx;
}

static int rand_obf_decoded_len(void *ctx, int encoded_len) {
    return 0;
}

static int rand_obf_genspec(void *ctx, char *buf) {
    int len = (uintptr_t)ctx;
    return !buf ? 4 + 11 : sprintf(buf, "<r %d>", len);
}

static const struct obf_ops rand_obf_ops = {
    .encode = rand_obf_encode,
    .decode = rand_obf_decode,
    .encoded_len = rand_obf_encoded_len,
    .decoded_len = rand_obf_decoded_len,
    .genspec = rand_obf_genspec,
};

static int rand_obf_setup(struct obf* obf, char *val) {
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len) || len <= 0)
        return -EINVAL;

    obf->ops = &rand_obf_ops;
    obf->priv = (void*)(uintptr_t)len;

    return 0;
}

#define ALPHABET_LEN 26
#define LETTER_LEN (ALPHABET_LEN * 2)

static void randchar_obf_encode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    u8 *dst8 = dst;
    int i;
    u8 byte;

    for (i = 0; i < nDst; ++i) {
        byte = get_random_u32() % LETTER_LEN;
        dst8[i] = (byte < ALPHABET_LEN) ? 'a' + byte : 'A' + byte - ALPHABET_LEN;
    }
}

static bool randchar_obf_decode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    u8 *src8 = src;
    int i;
    u8 byte;

    for (i = 0; i < nSrc; ++i) {
        byte = src8[i];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z')))
            return false;
    }

    return true;
}

static int randchar_obf_encoded_len(void *ctx, int decoded_len) {
    return (uintptr_t)ctx;
}

static int randchar_obf_decoded_len(void *ctx, int encoded_len) {
    return 0;
}

static int randchar_obf_genspec(void *ctx, char *buf) {
    int len = (uintptr_t)ctx;
    return !buf ? 5 + 11 : sprintf(buf, "<rc %d>", len);
}

static const struct obf_ops randchar_obf_ops = {
    .encode = randchar_obf_encode,
    .decode = randchar_obf_decode,
    .encoded_len = randchar_obf_encoded_len,
    .decoded_len = randchar_obf_decoded_len,
    .genspec = randchar_obf_genspec,
};

static int randchar_obf_setup(struct obf* obf, char *val) {
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len) || len <= 0)
        return -EINVAL;

    obf->ops = &randchar_obf_ops;
    obf->priv = (void*)(uintptr_t)len;

    return 0;
}

#define DIGIT_LEN 10

static void randdigit_obf_encode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    u8 *dst8 = dst;
    int i;

    for (i = 0; i < nDst; ++i)
        dst8[i] = '0' + get_random_u32() % DIGIT_LEN;
}

static bool randdigit_obf_decode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    u8 *src8 = src;
    int i;
    u8 byte;

    for (i = 0; i < nSrc; ++i) {
        byte = src8[i];
        if (!(byte >= '0' && byte <= '9'))
            return false;
    }

    return true;
}

static int randdigit_obf_encoded_len(void *ctx, int decoded_len) {
    return (uintptr_t)ctx;
}

static int randdigit_obf_decoded_len(void *ctx, int encoded_len) {
    return 0;
}

static int randdigit_obf_genspec(void *ctx, char *buf) {
    int len = (uintptr_t)ctx;
    return !buf ? 5 + 11 : sprintf(buf, "<rd %d>", len);
}

static const struct obf_ops randdigit_obf_ops = {
    .encode = randdigit_obf_encode,
    .decode = randdigit_obf_decode,
    .encoded_len = randdigit_obf_encoded_len,
    .decoded_len = randdigit_obf_decoded_len,
    .genspec = randdigit_obf_genspec,
};

static int randdigit_obf_setup(struct obf* obf, char *val) {
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len) || len <= 0)
        return -EINVAL;

    obf->ops = &randdigit_obf_ops;
    obf->priv = (void*)(uintptr_t)len;

    return 0;
}

static void data_obf_encode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    memcpy(dst, src, nSrc);
}

static bool data_obf_decode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    memcpy(dst, src, nSrc);
    return true;
}

static int data_obf_encoded_len(void *ctx, int decoded_len) {
    return decoded_len;
}

static int data_obf_decoded_len(void *ctx, int encoded_len) {
    return encoded_len;
}

static int data_obf_genspec(void *ctx, char *buf) {
    if (buf)
        sprintf(buf, "<d>");

    return 3;
}

static const struct obf_ops data_obf_ops = {
    .encode = data_obf_encode,
    .decode = data_obf_decode,
    .encoded_len = data_obf_encoded_len,
    .decoded_len = data_obf_decoded_len,
    .genspec = data_obf_genspec,
};

static int data_obf_setup(struct obf* obf, char *val) {
    if (val)
        return -EINVAL;

    obf->ops = &data_obf_ops;
    obf->priv = NULL;

    return 0;
}

static void datasize_obf_encode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    u8 *dst8 = dst;
    int i;

    for (i = nDst - 1; i >= 0; --i) {
        dst8[i] = nSrc & 0xFF;
        nSrc >>= 8;
    }
}

static bool datasize_obf_decode(void *ctx, void *dst, int nDst, void *src, int nSrc) {
    return true;
}

static int datasize_obf_encoded_len(void *ctx, int decoded_len) {
    return (uintptr_t)ctx;
}

static int datasize_obf_decoded_len(void *ctx, int encoded_len) {
    return 0;
}

static int datasize_obf_genspec(void *ctx, char *buf) {
    int len = (uintptr_t)ctx;
    return !buf ? 4 + 11 : sprintf(buf, "<dz %d", len);
}

static const struct obf_ops datasize_obf_ops = {
    .encode = datasize_obf_encode,
    .decode = datasize_obf_decode,
    .encoded_len = datasize_obf_encoded_len,
    .decoded_len = datasize_obf_decoded_len,
    .genspec = datasize_obf_genspec,
};

static int datasize_obf_setup(struct obf* obf, char *val) {
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len) || len <= 0)
        return -EINVAL;

    obf->ops = &datasize_obf_ops;
    obf->priv = (void*)(uintptr_t)len;

    return 0;
}

struct obf_list {
    struct obf obf;
    struct list_head head;
};

int obf_chain_setup(struct obf_chain *chain, char* spec) {
    int err, len, i;
    char *key, *val;
    struct obf_list *obf_list, *tmp;
    struct obf *obfs;
    LIST_HEAD(head);

    while (true) {
        strsep(&spec, "<");
        val = strsep(&spec, ">");
        if (!val)
            break;

        key = strsep(&val, " ");

        obf_list = kmalloc(sizeof(*obf_list), GFP_KERNEL);
        if (!obf_list) {
            err = -ENOMEM;
            goto error_list;
        }

        if (!strcmp(key, "b")) {
            err = bytes_obf_setup(&obf_list->obf, val);
        }
        else if (!strcmp(key, "t")) {
            err = timestamp_obf_setup(&obf_list->obf, val);
        }
        else if (!strcmp(key, "r")) {
            err = rand_obf_setup(&obf_list->obf, val);
        }
        else if (!strcmp(key, "rc")) {
            err = randchar_obf_setup(&obf_list->obf, val);
        }
        else if (!strcmp(key, "rd")) {
            err = randdigit_obf_setup(&obf_list->obf, val);
        }
        else if (!strcmp(key, "dz")) {
            err = datasize_obf_setup(&obf_list->obf, val);
        }
        else if (!strcmp(key, "d")) {
            err = data_obf_setup(&obf_list->obf, val);
        }
        else {
            err = -EINVAL;
        }

        if (err)
            goto error_obf;

        list_add_tail(&obf_list->head, &head);
    }

    len = list_count_nodes(&head);
    obfs = kmalloc_array(len, sizeof(*obfs), GFP_KERNEL);
    if (!obfs) {
        err = -ENOMEM;
        goto error_list;
    }

    i = 0;
    list_for_each_entry_safe(obf_list, tmp, &head, head) {
        obfs[i] = obf_list->obf;
        i++;
        list_del(&obf_list->head);
        kfree(obf_list);
    }

    chain->len = len;
    chain->obfs = obfs;

    return 0;

error_obf:
    kfree(obf_list);
error_list:
    list_for_each_entry_safe(obf_list, tmp, &head, head) {
        if (obf_list->obf.ops->destroy)
            obf_list->obf.ops->destroy(obf_list->obf.priv);
        list_del(&obf_list->head);
        kfree(obf_list);
    }
    return err;
}

void obf_chain_free(struct obf_chain *chain) {
    struct obf *obf;
    int i;

    for (i = 0; i < chain->len; ++i) {
        obf = &chain->obfs[i];
        if (obf->ops->destroy)
            obf->ops->destroy(obf->priv);
    }
    kfree(chain->obfs);
}

void obf_chain_encode(struct obf_chain* chain, void *dst, int nDst, void *src, int nSrc) {
    int i, decoded_len, encoded_len;
    struct obf* obf;
    u8 *dst8 = (u8*)dst;
    u8 *src8 = (u8*)src;

    for (i = 0; i < chain->len; ++i) {
        obf = &chain->obfs[i];

        encoded_len = obf->ops->encoded_len(obf->priv, nSrc);
        decoded_len = obf->ops->decoded_len(obf->priv, encoded_len);

        if (encoded_len > nDst || decoded_len > nSrc)
            return;

        obf->ops->encode(obf->priv, dst8, encoded_len, src8, nSrc);

        dst8 += encoded_len;
        nDst -= encoded_len;

        src8 += decoded_len;
        nSrc -= decoded_len;
    }
}

bool obf_chain_decode(struct obf_chain *chain, void *dst, int nDst, void *src, int nSrc) {
    int i, decoded_len, encoded_len, dynamic_len;
    struct obf *obf;
    u8 *dst8, *src8;

    dynamic_len = nSrc - obf_chain_encoded_len(chain, 0);
    if (dynamic_len <= 0)
        return false;

    dst8 = (u8*)dst;
    src8 = (u8*)src;

    for (i = 0; i < chain->len; ++i) {
        obf = &chain->obfs[i];

        decoded_len = obf->ops->decoded_len(obf->priv, dynamic_len);
        encoded_len = obf->ops->encoded_len(obf->priv, decoded_len);

        if (decoded_len > nDst || encoded_len > nSrc)
            return false;

        if (!obf->ops->decode(obf->priv, dst8, decoded_len, src8, encoded_len))
            return false;

        dst8 += decoded_len;
        nDst -= decoded_len;

        src8 += encoded_len;
        nSrc -= encoded_len;
    }

    return true;
}

int obf_chain_encoded_len(struct obf_chain* chain, int decoded_len) {
    int i, size;
    struct obf* obf;

    size = 0;
    for (i = 0; i < chain->len; ++i) {
        obf = &chain->obfs[i];
        size += obf->ops->encoded_len(obf->priv, decoded_len);
    }

    return size;
}

int obf_chain_decoded_len(struct obf_chain* chain, int encoded_len) {
    int i, size, dynamic_len;
    struct obf* obf;

    dynamic_len = encoded_len - obf_chain_encoded_len(chain, 0);

    size = 0;
    for (i = 0; i < chain->len; ++i) {
        obf = &chain->obfs[i];
        size += obf->ops->decoded_len(obf->priv, dynamic_len);
    }

    return size;
}

char* obf_chain_genspec(struct obf_chain *chain) {
    int i;
    size_t len, pos;
    char *res;
    struct obf *obf;

    len = 0;
    for (i = 0; i < chain->len; ++i) {
        obf = &chain->obfs[i];
        len += obf->ops->genspec(obf->priv, NULL);
    }

    if (len == 0)
        return NULL;

    res = kmalloc(len + 1, GFP_KERNEL);
    if (!res)
        return NULL;

    pos = 0;
    for (i = 0; i < chain->len; ++i) {
        obf = &chain->obfs[i];
        pos += obf->ops->genspec(obf->priv, res + pos);
    }

    return res;
}