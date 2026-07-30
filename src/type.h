#ifndef _WG_TYPE
#define _WG_TYPE

#include <linux/types.h>
#include <linux/random.h>

typedef u64 u32_range_t;

static inline void u32_range_init(u32_range_t *range, u32 lo, u32 hi) {
    *range = ((u64)(hi)<<32 | (u64)(lo));
}

static inline u32 u32_range_lo(u32_range_t range) {
    return (u32)(range);
}

static inline u32 u32_range_hi(u32_range_t range) {
    return (u32)(range>>32);
}

static inline bool u32_range_contains(u32_range_t range, u32 val) {
    return u32_range_lo(range) <= val && val <= u32_range_hi(range);
}

static inline bool u32_range_is_zero(u32_range_t range) {
    return range == 0;
}

static inline bool u32_range_overlap(u32_range_t left, u32_range_t right) {
    return u32_range_lo(left) <= u32_range_hi(right) && u32_range_lo(right) <= u32_range_hi(left);
}

static inline u32 u32_range_pick_one(u32_range_t range) {
    return get_random_u32_inclusive(u32_range_lo(range), u32_range_hi(range));
}

typedef u32 u16_range_t;

static inline void u16_range_init(u16_range_t *range, u16 lo, u16 hi) {
    *range = ((u32)(hi)<<16 | (u32)(lo));
}

static inline u16 u16_range_lo(u16_range_t range) {
    return (u16)(range);
}

static inline u16 u16_range_hi(u16_range_t range) {
    return (u16)(range>>16);
}

static inline bool u16_range_contains(u16_range_t range, u16 val) {
    return u16_range_lo(range) <= val && val <= u16_range_hi(range);
}

static inline bool u16_range_is_zero(u16_range_t range) {
    return range == 0;
}

static inline bool u16_range_overlap(u16_range_t left, u16_range_t right) {
    return u16_range_lo(left) <= u16_range_hi(right) && u16_range_lo(right) <= u16_range_hi(left);
}

static inline u16 u16_range_pick_one(u16_range_t range) {
    return get_random_u32_inclusive(u16_range_lo(range), u16_range_hi(range));
}

#endif // _WG_TYPE
