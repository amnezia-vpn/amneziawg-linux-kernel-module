#include "magic_header.h"

#include <linux/string.h>
#include <linux/kstrtox.h>
#include <linux/sprintf.h>
#include <linux/random.h>

int mh_parse(struct magic_header *mh, char *desc) {
    int err;
    char* val;

    val = strsep(&desc, "-");
    if (!val)
        return -EINVAL;

    err = kstrtouint(val, 10, &mh->start);
    if (err)
        return err;

    if (desc) {
        err = kstrtouint(desc, 10, &mh->end);
        if (err)
            return err;
    }
    else
        mh->end = mh->start;

    if (mh->start > mh->end)
        return -EINVAL;

    return 0;
}

int mh_genspec(struct magic_header *mh, char *buf, size_t buflen) {
    if (mh->start == mh->end)
        return scnprintf(buf, buflen, "%u", mh->start);
    return scnprintf(buf, buflen, "%u-%u", mh->start, mh->end);
}

bool mh_validate(__le32 received, struct magic_header* mh) {
    u32 received_host = le32_to_cpu(received);
	return received_host >= mh->start && received_host <= mh->end;
}

u32 mh_genheader(struct magic_header *mh) {
    return get_random_u32_inclusive(mh->start, mh->end);
}