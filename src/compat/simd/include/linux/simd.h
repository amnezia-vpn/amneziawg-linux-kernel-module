/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_SIMD_H
#define _WG_SIMD_H

#include <linux/sched.h>
#include <asm/simd.h>
#if defined(CONFIG_X86_64)
#include <asm/fpu/api.h>
#elif defined(CONFIG_KERNEL_MODE_NEON)
#include <asm/neon.h>
#endif

typedef enum {
	HAVE_NO_SIMD = 1 << 0,
	HAVE_FULL_SIMD = 1 << 1,
	HAVE_SIMD_IN_USE = 1 << 31
} simd_state_t;

typedef struct {
	simd_state_t state;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0) && defined(CONFIG_KERNEL_MODE_NEON)
	struct user_fpsimd_state kstate;
#endif
} simd_context_t;

#define DONT_USE_SIMD ((simd_context_t []){ HAVE_NO_SIMD })

static inline void simd_get(simd_context_t *ctx)
{
	ctx->state = !IS_ENABLED(CONFIG_PREEMPT_RT) && !IS_ENABLED(CONFIG_PREEMPT_RT_BASE) && may_use_simd() ? HAVE_FULL_SIMD : HAVE_NO_SIMD;
}

static inline void simd_put(simd_context_t *ctx)
{
#if defined(CONFIG_X86_64)
	if (ctx->state & HAVE_SIMD_IN_USE)
		kernel_fpu_end();
#elif defined(CONFIG_KERNEL_MODE_NEON)
	if (ctx->state & HAVE_SIMD_IN_USE)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
		kernel_neon_end(&ctx->kstate);
#else
		kernel_neon_end();
#endif
#endif
	ctx->state = HAVE_NO_SIMD;
}

static inline bool simd_relax(simd_context_t *ctx)
{
#ifdef CONFIG_PREEMPT
	if ((ctx->state & HAVE_SIMD_IN_USE) && need_resched()) {
		simd_put(ctx);
		simd_get(ctx);
		return true;
	}
#endif
	return false;
}

static __must_check inline bool simd_use(simd_context_t *ctx)
{
	if (!(ctx->state & HAVE_FULL_SIMD))
		return false;
	if (ctx->state & HAVE_SIMD_IN_USE)
		return true;
#if defined(CONFIG_X86_64)
	kernel_fpu_begin();
#elif defined(CONFIG_KERNEL_MODE_NEON)
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 19, 0)
	kernel_neon_begin(&ctx->kstate);
#else
	kernel_neon_begin();
#endif
#endif
	ctx->state |= HAVE_SIMD_IN_USE;
	return true;
}

#endif /* _WG_SIMD_H */
