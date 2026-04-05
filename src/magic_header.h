#ifndef H_MAGIC_HEADER
#define H_MAGIC_HEADER

#include <linux/types.h>

struct magic_header {
    u32 start;
    u32 end;
};

int mh_parse(struct magic_header *mh, char *desc);
int mh_genspec(struct magic_header *mh, char *desc, size_t buflen);

bool mh_validate(__le32 received, struct magic_header* mh);
u32 mh_genheader(struct magic_header* mh);

/* Generate a header appropriate for the peer's capability level.
 * Ranged peers get a random value from the range (AWG 2.0).
 * Fixed peers get the range start value (AWG 1.0 compatibility).
 */
static inline u32 mh_peerheader(struct magic_header *mh, bool ranged)
{
	return ranged ? mh_genheader(mh) : mh->start;
}

#endif