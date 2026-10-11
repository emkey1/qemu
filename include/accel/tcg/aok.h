/*
 * AOK gadgets: a second translator for TCG on hosts that cannot JIT.
 *
 * A front end that implements TCGCPUOps.aok_translate_code turns guest
 * instructions straight into a stream of pointers to precompiled gadgets,
 * one gadget per guest instruction, without going through TCGOps and a TCG
 * backend. The result is an ordinary TranslationBlock: it lives in the code
 * buffer, is found, linked and invalidated like any other, and calls the
 * same softmmu helpers. Whatever the front end does not translate ends the
 * block, and the next TB is left to TCG.
 *
 * The gadgets come from iSH-AOK's user-mode engine.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_AOK_H
#define ACCEL_TCG_AOK_H

#include "exec/translation-block.h"
#include "exec/vaddr.h"

#ifdef CONFIG_AOK_GADGETS

/*
 * Register convention inside a stream (AArch64 host). Everything a gadget
 * needs across a call to C is callee-saved, so a helper is a plain `bl`.
 *
 *   x28  stream pointer: the next word to read
 *   x20  CPUArchState *
 *   x19  guest pc on entry to this TB (TBs are pc-relative under CF_PCREL)
 *   x21  &cpu->neg.icount_decr.u32, the exit request the TB checks first
 *   x22  &env->pc
 *   x23  &cpu->neg.tlb.f[mmu_idx], the softmmu fast table of this TB
 *   x24  cpu->tb_jmp_cache
 *   x25  &cpu->breakpoints: a lookup done in a gadget must see it empty
 *   x0-x17  scratch (x18 is never touched: the platform register on Darwin)
 */

/* Whether aok_translate_code is consulted at all; QEMU_AOK=0 turns it off. */
extern bool aok_enabled;

/* What aok_tb_exec loads into x21, x22, x24 and x25, in this order. */
typedef struct AokCPU {
    uint32_t *exit_request;
    uint64_t *pc;
    void *tb_jmp_cache;
    void *breakpoints;
} AokCPU;

/* Enter a stream. Returns what tcg_qemu_tb_exec returns: (TB | exit index). */
uintptr_t aok_tb_exec(CPUArchState *env, const void *stream,
                      const AokCPU *cpu);

/* Target-independent gadgets, accel/tcg/aok-entry.S. */
void aok_gadget_enter(void);    /* [tb][tlb fast offset]: every TB starts here */
void aok_gadget_exit_tb(void);  /* [value]: return value to the main loop */
void aok_gadget_goto(void);     /* [pc delta][slot]: set pc, continue at *slot */
/*
 * [flags | cflags << 32][cs_base], this TB's: env->pc is set, continue in
 * the TB there if it is a stream. This one asks aok_lookup_tb_ptr; a front
 * end may have a gadget that tries cpu->tb_jmp_cache first (AokGen.lookup).
 */
void aok_gadget_lookup(void);

/* Called by aok_gadget_lookup; cpu-exec.c. Returns a stream or NULL. */
const void *aok_lookup_tb_ptr(CPUArchState *env);

/*
 * Stream emission, for front ends.
 *
 * A TB may leave by up to two direct jumps that TB linking can patch, as with
 * goto_tb. aok_slot(g, n) is the word such a jump continues at: it starts out
 * pointing at a stub that returns (TB | n) to the main loop, and
 * tb_set_jmp_target moves it. aok_slot_unlinked(g) is for a destination that
 * may not be linked (another page, CF_NO_GOTO_TB): it continues at a lookup
 * of the TB at env->pc, or back in the main loop. Its value must be emitted
 * as the very next word.
 */
typedef struct AokGen {
    TranslationBlock *tb;
    const uint64_t *rx;         /* tb->tc.ptr: the stream as it will be run */
    uint64_t *base;             /* the same words, writable */
    uint64_t *p;                /* next word to emit */
    uint64_t *limit;
    bool overflow;
    int n_insns;
    int max_insns;
    uint64_t *insn_data;
    uint16_t *insn_end_off;
    /* The gadget an unlinked exit continues at; aok_gadget_lookup if unset. */
    void (*lookup)(void);
    /* aok_slot_unlinked operands, filled in by aok_gen_finish. */
    int n_fix;
    struct { uint64_t *word; } fix[8];
} AokGen;

void aok_gen_begin(AokGen *g, CPUState *cpu, TranslationBlock *tb,
                   int max_insns, int mmu_idx);
/* Record that the words emitted since the last call are one guest insn. */
void aok_gen_insn_end(AokGen *g, uint64_t pc_page_offset, uint64_t insn);
uint64_t aok_slot(AokGen *g, int n);
uint64_t aok_slot_unlinked(AokGen *g);
/* Emit the stubs, fill in the slots; the stream's size in bytes, or -1. */
int aok_gen_finish(AokGen *g, unsigned guest_size);

static inline void aok_emit(AokGen *g, uint64_t word)
{
    if (likely(g->p < g->limit)) {
        *g->p++ = word;
    } else {
        g->overflow = true;
    }
}

static inline void aok_emit_gadget(AokGen *g, void (*gadget)(void))
{
    aok_emit(g, (uintptr_t)gadget);
}

/* The lookup gadget's two operands: what a TB there must have to be next. */
static inline void aok_emit_lookup_operands(AokGen *g)
{
    aok_emit(g, g->tb->flags | (uint64_t)tb_cflags(g->tb) << 32);
    aok_emit(g, g->tb->cs_base);
}

/* Whether another insn of at most @words words still fits in this TB. */
static inline bool aok_gen_room(AokGen *g, int words)
{
    return !g->overflow && g->n_insns < g->max_insns &&
           (g->p - g->base + words + 16) * sizeof(uint64_t) < 0xf000;
}

/*
 * Before calling, from a stream, a helper that uses GETPC(): it takes that
 * for a position in a TCG TB and unwinds the CPU state from it when it
 * raises an exception. A stream has nothing to unwind (the caller has made
 * the state exact), and under the interpreters GETPC() is a variable still
 * holding the position of the last helper call some TCG TB made, so it has
 * to be told so.
 */
static inline void aok_no_retaddr(void)
{
#if defined(CONFIG_TCG_INTERPRETER)
    extern __thread uintptr_t tci_tb_ptr;
    tci_tb_ptr = 0;
#elif defined(CONFIG_TCG_THREADED_INTERPRETER) || \
      defined(CONFIG_TCG_HYBRID_RUNTIME)
    extern __thread uintptr_t tcti_call_return_address;
    tcti_call_return_address = 0;
#endif
}

/* Counters, printed at exit when QEMU_AOK_STATS is set. */
typedef struct AokStats {
    uint64_t tb_aok, tb_tcg, insns_aok, declined_first;
    /* Entries from the main loop into a stream and into TCG's code. */
    uint64_t enter_aok, enter_tcg;
    /* aok_lookup_tb_ptr: found a stream, found TCG's TB, found nothing. */
    uint64_t lookup_aok, lookup_tcg, lookup_none;
    /* TBs left to TCG, by the major opcode of their first insn. */
    uint64_t declined_op[128], declined_c;
} AokStats;
extern AokStats aok_stats;
extern bool aok_stats_enabled;

#endif /* CONFIG_AOK_GADGETS */
#endif /* ACCEL_TCG_AOK_H */
