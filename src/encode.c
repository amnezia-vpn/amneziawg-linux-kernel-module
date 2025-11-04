#include "encode.h"

int awg_encode_skb(struct sk_buff* skb, u16 padding, struct obf_chain* chain)
{
	void *src;
	int encoded_len, offset, src_len, required_len;

	if (unlikely(skb_linearize(skb)))
		return -ENOMEM;

	encoded_len = !chain ? 0 :
		obf_chain_encoded_len(chain, skb->len + padding);
	offset = encoded_len - skb->len;
	required_len = max(offset, padding);

	if (required_len > 0) {
		if (unlikely(skb_cow_head(skb, required_len)))
			return -ENOMEM;

		get_random_bytes(skb_push(skb, padding), padding);
		if (encoded_len > 0) {
			src = skb->data;
			src_len = skb->len;
			__skb_pull(skb, skb->len);
			obf_chain_encode(chain, skb_push(skb, encoded_len), encoded_len, src, src_len);
		}
	}

	return 0;
}

static int determine_msg_type(struct wg_device *wg, void *msg, size_t len, int expected_type, int *padding)
{
	struct message_header *hdr;
	u8 *msg8 = msg;

	if (!expected_type || expected_type == MESSAGE_HANDSHAKE_INITIATION) {
		if (len == wg->padding_handshake_init + MESSAGE_INITIATION_SIZE) {
			hdr = (struct message_header*)(msg8 + wg->padding_handshake_init);
			if (mh_validate(hdr->type, &wg->hdr_handshake_init)) {
				*padding = wg->padding_handshake_init;
				return MESSAGE_HANDSHAKE_INITIATION;
			}
		}
	}

	if (!expected_type || expected_type == MESSAGE_HANDSHAKE_RESPONSE) {
		if (len == wg->padding_handshake_resp + MESSAGE_RESPONSE_SIZE) {
			hdr = (struct message_header*)(msg8 + wg->padding_handshake_resp);
			if (mh_validate(hdr->type, &wg->hdr_handshake_resp)) {
				*padding = wg->padding_handshake_resp;
				return MESSAGE_HANDSHAKE_RESPONSE;
			}
		}
	}

	if (!expected_type || expected_type == MESSAGE_HANDSHAKE_COOKIE) {
		if (len == wg->padding_handshake_cookie + MESSAGE_COOKIE_REPLY_SIZE) {
			hdr = (struct message_header*)(msg8 + wg->padding_handshake_cookie);
			if (mh_validate(hdr->type, &wg->hdr_handshake_cookie)) {
				*padding = wg->padding_handshake_cookie;
				return MESSAGE_HANDSHAKE_COOKIE;
			}
		}
	}

	if (!expected_type || expected_type == MESSAGE_DATA) {
		if (len >= wg->padding_transport + MESSAGE_TRANSPORT_SIZE) {
			hdr = (struct message_header*)(msg8 + wg->padding_transport);
			if (mh_validate(hdr->type, &wg->hdr_transport)) {
				*padding = wg->padding_transport;
				return MESSAGE_DATA;
			}
		}
	}

	return MESSAGE_INVALID;
}

int awg_decode_skb(struct wg_device *wg, struct sk_buff *skb)
{
	void *buf = NULL;
	int len, padding, type = MESSAGE_INVALID;
	int src_len = skb->len;
	void *src = skb->data;

	buf = kmalloc(src_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (!type) {
		len = obf_chain_decoded_len(&wg->fmt_handshake_init, src_len);
		if (len > 0 && obf_chain_decode(&wg->fmt_handshake_init, buf, src_len, src, src_len))
			type = determine_msg_type(wg, buf, len, MESSAGE_HANDSHAKE_INITIATION, &padding);
	}

	if (!type) {
		len = obf_chain_decoded_len(&wg->fmt_handshake_resp, src_len);
		if (len > 0 && obf_chain_decode(&wg->fmt_handshake_resp, buf, src_len, src, src_len))
			type = determine_msg_type(wg, buf, len, MESSAGE_HANDSHAKE_RESPONSE, &padding);
	}

	if (!type) {
		len = obf_chain_decoded_len(&wg->fmt_handshake_cookie, src_len);
		if (len > 0 && obf_chain_decode(&wg->fmt_handshake_cookie, buf, src_len, src, src_len))
			type = determine_msg_type(wg, buf, len, MESSAGE_HANDSHAKE_COOKIE, &padding);
	}

	if (!type) {
		len = obf_chain_decoded_len(&wg->fmt_transport, src_len);
		if (len > 0 && obf_chain_decode(&wg->fmt_transport,  buf, src_len, src, src_len))
			type = determine_msg_type(wg, buf, len, MESSAGE_DATA, &padding);
	}

	if (type) {
		skb_trim(skb, len);
		memcpy(skb->data, buf, len);
	}
	else {
		// awg [v1-v2] processing of S and H params
		type = determine_msg_type(wg, src, src_len, MESSAGE_INVALID, &padding);
	}

	skb_pull(skb, padding);

	kfree(buf);
	return type;
}