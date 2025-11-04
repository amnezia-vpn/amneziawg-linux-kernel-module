#ifndef _AWG_OBF_H
#define _AWG_OBF_H

#include <linux/types.h>

struct obf_ops {
    void (*encode)(void *ctx, void *dst, int nDst, void *src, int nSrc);
    bool (*decode)(void *ctx, void *dst, int nDst, void *src, int nSrc);
    int (*encoded_len)(void *ctx, int decoded_len);
    int (*decoded_len)(void *ctx, int encoded_len);
    int (*genspec)(void *ctx, char *buf);
    void (*destroy)(void *ctx);
};

struct obf {
    const struct obf_ops *ops;
    void *priv;
};

struct obf_chain {
    int len;
    struct obf *obfs;
};

int obf_chain_setup(struct obf_chain *chain, char* spec);
void obf_chain_free(struct obf_chain *chain);

void obf_chain_encode(struct obf_chain *chain, void *dst, int nDst, void *src, int nSrc);
bool obf_chain_decode(struct obf_chain *chain, void *dst, int nDst, void *src, int nSrc);

int obf_chain_encoded_len(struct obf_chain *chain, int decoded_len);
int obf_chain_decoded_len(struct obf_chain *chain, int encoded_len);

char* obf_chain_genspec(struct obf_chain *chain);

#endif