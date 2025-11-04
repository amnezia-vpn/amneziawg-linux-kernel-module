#ifndef _WG_ENCODE_H
#define _WG_ENCODE_H

#include <linux/skbuff.h>
#include "obf.h"
#include "device.h"

int awg_encode_skb(struct sk_buff* skb, u16 padding, struct obf_chain* chain);
int awg_decode_skb(struct wg_device *wg, struct sk_buff *skb);

#endif