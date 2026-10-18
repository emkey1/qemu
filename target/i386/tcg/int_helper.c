/*
 *  x86 integer helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "qapi/error.h"
#include "qemu/guest-random.h"
#include "helper-tcg.h"

//#define DEBUG_MULDIV

/* division, flags are undefined */

void helper_divb_AL(CPUX86State *env, target_ulong t0)
{
    unsigned int num, den, q, r;

    num = (env->regs[R_EAX] & 0xffff);
    den = (t0 & 0xff);
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q > 0xff) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q &= 0xff;
    r = (num % den) & 0xff;
    env->regs[R_EAX] = (env->regs[R_EAX] & ~0xffff) | (r << 8) | q;
}

void helper_idivb_AL(CPUX86State *env, target_ulong t0)
{
    int num, den, q, r;

    num = (int16_t)env->regs[R_EAX];
    den = (int8_t)t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q != (int8_t)q) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q &= 0xff;
    r = (num % den) & 0xff;
    env->regs[R_EAX] = (env->regs[R_EAX] & ~0xffff) | (r << 8) | q;
}

void helper_divw_AX(CPUX86State *env, target_ulong t0)
{
    unsigned int num, den, q, r;

    num = (env->regs[R_EAX] & 0xffff) | ((env->regs[R_EDX] & 0xffff) << 16);
    den = (t0 & 0xffff);
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q > 0xffff) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q &= 0xffff;
    r = (num % den) & 0xffff;
    env->regs[R_EAX] = (env->regs[R_EAX] & ~0xffff) | q;
    env->regs[R_EDX] = (env->regs[R_EDX] & ~0xffff) | r;
}

void helper_idivw_AX(CPUX86State *env, target_ulong t0)
{
    int num, den, q, r;

    num = (env->regs[R_EAX] & 0xffff) | ((env->regs[R_EDX] & 0xffff) << 16);
    den = (int16_t)t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q != (int16_t)q) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q &= 0xffff;
    r = (num % den) & 0xffff;
    env->regs[R_EAX] = (env->regs[R_EAX] & ~0xffff) | q;
    env->regs[R_EDX] = (env->regs[R_EDX] & ~0xffff) | r;
}

void helper_divl_EAX(CPUX86State *env, target_ulong t0)
{
    unsigned int den, r;
    uint64_t num, q;

    num = ((uint32_t)env->regs[R_EAX]) | ((uint64_t)((uint32_t)env->regs[R_EDX]) << 32);
    den = t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    r = (num % den);
    if (q > 0xffffffff) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    env->regs[R_EAX] = (uint32_t)q;
    env->regs[R_EDX] = (uint32_t)r;
}

void helper_idivl_EAX(CPUX86State *env, target_ulong t0)
{
    int den, r;
    int64_t num, q;

    num = ((uint32_t)env->regs[R_EAX]) | ((uint64_t)((uint32_t)env->regs[R_EDX]) << 32);
    den = t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    r = (num % den);
    if (q != (int32_t)q) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    env->regs[R_EAX] = (uint32_t)q;
    env->regs[R_EDX] = (uint32_t)r;
}

/* bcd */

target_ulong helper_aam(target_ulong al, target_ulong base)
{
    int ah;

    al &= 0xff;
    base &= 0xff;           /* the decoder sign-extends the immediate */
    ah = al / base;
    al = al % base;
    return al | (ah << 8);
}

target_ulong helper_aad(target_ulong ax, target_ulong base)
{
    int al, ah;

    al = ax & 0xff;
    ah = (ax >> 8) & 0xff;
    al = ((ah * base) + al) & 0xff;
    return al;
}

/*
 * The flags the SDM leaves undefined are an AMD Ryzen's: DAA and DAS set SF
 * ZF PF OF as the 8-bit ADD or SUB of their correction to AL does, and AAA
 * and AAS as the 16-bit ADD or SUB of 0x106 to AX (of 0, when the low digit
 * needs no adjusting) does. (AAD's are its 8-bit ADD's: gen_AAD().)
 */
static int bcd_flags(int a, int b, int bits, bool sub)
{
    int sign = 1 << (bits - 1);
    int r = (sub ? a - b : a + b) & ((sign << 1) - 1);
    int over = sub ? (a ^ b) & (a ^ r) : ~(a ^ b) & (a ^ r);

    return (r & sign ? CC_S : 0) | (r == 0 ? CC_Z : 0) | compute_pf(r) |
           (over & sign ? CC_O : 0);
}

static void helper_aaa_aas(CPUX86State *env, bool sub)
{
    int eflags = cpu_cc_compute_all(env);
    int ax = env->regs[R_EAX] & 0xffff;
    bool adj = (ax & 0x0f) > 9 || (eflags & CC_A);
    int corr = adj ? 0x106 : 0;

    eflags = bcd_flags(ax, corr, 16, sub) | (adj ? CC_C | CC_A : 0);
    ax = (sub ? ax - corr : ax + corr) & 0xff0f;
    env->regs[R_EAX] = (env->regs[R_EAX] & ~0xffff) | ax;
    CC_SRC = eflags;
    CC_OP = CC_OP_EFLAGS;
}

void helper_aaa(CPUX86State *env)
{
    helper_aaa_aas(env, false);
}

void helper_aas(CPUX86State *env)
{
    helper_aaa_aas(env, true);
}

static void helper_daa_das(CPUX86State *env, bool sub)
{
    int eflags = cpu_cc_compute_all(env);
    int al = env->regs[R_EAX] & 0xff;
    bool adj1 = (al & 0x0f) > 9 || (eflags & CC_A);
    bool adj2 = al > 0x99 || (eflags & CC_C);
    int corr = (adj1 ? 6 : 0) + (adj2 ? 0x60 : 0);
    bool cf = adj2 || (sub && adj1 && al < 6);

    eflags = bcd_flags(al, corr, 8, sub) | (adj1 ? CC_A : 0) | (cf ? CC_C : 0);
    al = (sub ? al - corr : al + corr) & 0xff;
    env->regs[R_EAX] = (env->regs[R_EAX] & ~0xff) | al;
    CC_SRC = eflags;
    CC_OP = CC_OP_EFLAGS;
}

void helper_daa(CPUX86State *env)
{
    helper_daa_das(env, false);
}

void helper_das(CPUX86State *env)
{
    helper_daa_das(env, true);
}

#ifdef TARGET_X86_64
static void add128(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b)
{
    *plow += a;
    /* carry test */
    if (*plow < a) {
        (*phigh)++;
    }
    *phigh += b;
}

static void neg128(uint64_t *plow, uint64_t *phigh)
{
    *plow = ~*plow;
    *phigh = ~*phigh;
    add128(plow, phigh, 1, 0);
}

/* return TRUE if overflow */
static int div64(uint64_t *plow, uint64_t *phigh, uint64_t b)
{
    uint64_t q, r, a1, a0;
    int i, qb, ab;

    a0 = *plow;
    a1 = *phigh;
    if (a1 == 0) {
        q = a0 / b;
        r = a0 % b;
        *plow = q;
        *phigh = r;
    } else {
        if (a1 >= b) {
            return 1;
        }
        /* XXX: use a better algorithm */
        for (i = 0; i < 64; i++) {
            ab = a1 >> 63;
            a1 = (a1 << 1) | (a0 >> 63);
            if (ab || a1 >= b) {
                a1 -= b;
                qb = 1;
            } else {
                qb = 0;
            }
            a0 = (a0 << 1) | qb;
        }
#if defined(DEBUG_MULDIV)
        printf("div: 0x%016" PRIx64 "%016" PRIx64 " / 0x%016" PRIx64
               ": q=0x%016" PRIx64 " r=0x%016" PRIx64 "\n",
               *phigh, *plow, b, a0, a1);
#endif
        *plow = a0;
        *phigh = a1;
    }
    return 0;
}

/* return TRUE if overflow */
static int idiv64(uint64_t *plow, uint64_t *phigh, int64_t b)
{
    int sa, sb;

    sa = ((int64_t)*phigh < 0);
    if (sa) {
        neg128(plow, phigh);
    }
    sb = (b < 0);
    if (sb) {
        b = -b;
    }
    if (div64(plow, phigh, b) != 0) {
        return 1;
    }
    if (sa ^ sb) {
        if (*plow > (1ULL << 63)) {
            return 1;
        }
        *plow = -*plow;
    } else {
        if (*plow >= (1ULL << 63)) {
            return 1;
        }
    }
    if (sa) {
        *phigh = -*phigh;
    }
    return 0;
}

void helper_divq_EAX(CPUX86State *env, target_ulong t0)
{
    uint64_t r0, r1;

    if (t0 == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    r0 = env->regs[R_EAX];
    r1 = env->regs[R_EDX];
    if (div64(&r0, &r1, t0)) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    env->regs[R_EAX] = r0;
    env->regs[R_EDX] = r1;
}

void helper_idivq_EAX(CPUX86State *env, target_ulong t0)
{
    uint64_t r0, r1;

    if (t0 == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    r0 = env->regs[R_EAX];
    r1 = env->regs[R_EDX];
    if (idiv64(&r0, &r1, t0)) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    env->regs[R_EAX] = r0;
    env->regs[R_EDX] = r1;
}
#endif

#if TARGET_LONG_BITS == 32
# define ctztl  ctz32
# define clztl  clz32
#else
# define ctztl  ctz64
# define clztl  clz64
#endif

target_ulong helper_pdep(target_ulong src, target_ulong mask)
{
    target_ulong dest = 0;
    int i, o;

    for (i = 0; mask != 0; i++) {
        o = ctztl(mask);
        mask &= mask - 1;
        dest |= ((src >> i) & 1) << o;
    }
    return dest;
}

target_ulong helper_pext(target_ulong src, target_ulong mask)
{
    target_ulong dest = 0;
    int i, o;

    for (o = 0; mask != 0; o++) {
        i = ctztl(mask);
        mask &= mask - 1;
        dest |= ((src >> i) & 1) << o;
    }
    return dest;
}

/* Test that BIT is enabled in CR4.  If not, raise an illegal opcode
   exception.  This reduces the requirements for rare CR4 bits being
   mapped into HFLAGS.  */
void helper_cr4_testbit(CPUX86State *env, uint32_t bit)
{
    if (unlikely((env->cr[4] & bit) == 0)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
}

target_ulong HELPER(rdrand)(CPUX86State *env)
{
    Error *err = NULL;
    target_ulong ret;

    if (qemu_guest_getrandom(&ret, sizeof(ret), &err) < 0) {
        qemu_log_mask(LOG_UNIMP, "rdrand: Crypto failure: %s",
                      error_get_pretty(err));
        error_free(err);
        /* Failure clears CF and all other flags, and returns 0.  */
        env->cc_src = 0;
        ret = 0;
    } else {
        /* Success sets CF and clears all others.  */
        env->cc_src = CC_C;
    }
    env->cc_op = CC_OP_EFLAGS;
    return ret;
}
