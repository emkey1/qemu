/*
 * RCG's alternate structure: TBs that are streams of RCG's gadgets.
 *
 * A front end that implements TCGCPUOps.rcg_translate_code turns guest
 * instructions straight into a stream: the address of each instruction's
 * gadget, followed by its operand words. The result is an ordinary
 * TranslationBlock in the code buffer, found, linked and invalidated like
 * any other, which calls the same softmmu helpers. Whatever the front end
 * does not translate ends the stream, and the next TB is left to TCG. A
 * stream and a TCG TB are never linked to each other: going from one to the
 * other is a trip through the main loop.
 *
 * Only under TCTI (tcg_rcg_active()), which flushes every TB when the
 * hybrid switches to the JIT.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_RCG_STREAM_H
#define ACCEL_TCG_RCG_STREAM_H

#include "exec/translation-block.h"
#include "exec/vaddr.h"
#include "hw/core/cpu.h"
#include "tcg/rcg.h"

/* In system emulation, where a front end has a stream translator. */
#if defined(TCG_HAVE_RCG) && !defined(CONFIG_USER_ONLY)
#define TCG_HAVE_RCG_STREAM 1

/*
 * Registers while a stream runs (AArch64 host). Everything the core keeps
 * is in a register a C call keeps, so a gadget calls a helper with a plain
 * `bl`. x24, x26 and x27 are the guest-memory templates' (tcti_memory.py's
 * TMP), and are free for every gadget to use.
 *
 *   x28  stream pointer: the gadget's first operand word while it runs
 *   x20  CPUArchState *
 *   x19  guest pc on entry to this TB: TBs are pc-relative (CF_PCREL), and
 *        a direct jump's target is given as a delta from it
 *   x21  &cpu->neg.icount_decr.u32, the exit request
 *   x22  &env->pc, where a jump leaves the next TB's pc
 *   x23  cpu->tb_jmp_cache
 *   x25  &cpu->breakpoints: a lookup done in a gadget must see it empty
 *   x0-x17  scratch (x18, the platform register on Darwin, is never used)
 *
 * The return address a gadget gives a helper is the stream pointer. The
 * TB records where each insn's words end, as TCG records where its code
 * for each insn ends, so a fault unwinds as in any other TB.
 */

/*
 * A stream starts with the enter gadget and its operand. A jump from
 * another stream skips them, so the address it is given for a gadget
 * anywhere else is this many bytes before that gadget.
 */
#define RCG_STREAM_ENTER_BYTES (2 * sizeof(uint64_t))

/* What rcg_stream_exec loads into x21, x22, x23 and x25. */
typedef struct RcgStreamCPU {
    uint32_t *exit_request;
    uint64_t *pc;
    void *tb_jmp_cache;
    void *breakpoints;
} RcgStreamCPU;

/* Run a stream. Returns what tcg_qemu_tb_exec returns: (TB | exit index). */
uintptr_t rcg_stream_exec(CPUArchState *env, const void *stream,
                          const RcgStreamCPU *cpu);

/* The core's gadgets, accel/tcg/rcg-stream.c. */
void rcg_stream_enter(void);     /* [tb]: every stream starts here */
void rcg_stream_exit_tb(void);   /* [value]: return value to the main loop */
void rcg_stream_goto(void);      /* [pc delta][slot]: set pc, go on at *slot */
/*
 * [flags | cflags << 32][cs_base], this TB's: env->pc is set; go on in the
 * TB there if it is a stream, which rcg_stream_lookup_tb_ptr finds. A
 * front end's own lookup gadget first tries cpu->tb_jmp_cache itself
 * (RcgStreamGen.lookup), and falls back to this one.
 */
void rcg_stream_lookup(void);

/* Called by rcg_stream_lookup; cpu-exec.c. Returns a stream or NULL. */
const void *rcg_stream_lookup_tb_ptr(CPUArchState *env);

/*
 * Stream emission, for front ends.
 *
 * A TB may leave by up to two direct jumps that TB linking can patch, as
 * with goto_tb. rcg_stream_slot(g, n) is the word such a jump goes on at:
 * it starts out pointing at a stub that returns (TB | n) to the main loop,
 * and tb_set_jmp_target moves it. rcg_stream_slot_unlinked(g) is for a
 * destination that may not be linked (CF_NO_GOTO_TB): it goes on at a
 * lookup of the TB at env->pc. Its value must be emitted as the very next
 * word.
 */
typedef struct RcgStreamGen {
    TranslationBlock *tb;
    const uint64_t *rx;         /* tb->tc.ptr: the stream as it will run */
    uint64_t *base;             /* the same words, writable */
    uint64_t *p;                /* next word to emit */
    uint64_t *limit;
    bool overflow;
    int n_insns;
    int max_insns;
    uint64_t *insn_data;
    uint16_t *insn_end_off;
    /* The gadget an unlinked exit goes on at; rcg_stream_lookup if unset. */
    void (*lookup)(void);
    /* rcg_stream_slot_unlinked operands, filled in by rcg_stream_finish. */
    int n_fix;
    struct { uint64_t *word; } fix[8];
} RcgStreamGen;

void rcg_stream_begin(RcgStreamGen *g, CPUState *cpu, TranslationBlock *tb,
                      int max_insns);
/*
 * For a TB whose first insn runs into the next page, at @addr: that page's
 * code, the page having been made the TB's second, or NULL if it is not
 * RAM. It may not return: the fetch faults, as it should.
 */
const void *rcg_stream_next_page(RcgStreamGen *g, CPUState *cpu, vaddr addr);
/*
 * Record that the words emitted since the last call are one guest insn,
 * with what TCG's insn_start would have recorded for it.
 */
void rcg_stream_insn_end(RcgStreamGen *g, uint64_t data0, uint64_t data1);
uint64_t rcg_stream_slot(RcgStreamGen *g, int n);
uint64_t rcg_stream_slot_unlinked(RcgStreamGen *g);
/* Emit the stubs, fill in the slots; the stream's size in bytes, or -1. */
int rcg_stream_finish(RcgStreamGen *g, unsigned guest_size);

static inline void rcg_stream_emit(RcgStreamGen *g, uint64_t word)
{
    if (likely(g->p < g->limit)) {
        *g->p++ = word;
    } else {
        g->overflow = true;
    }
}

static inline void rcg_stream_emit_gadget(RcgStreamGen *g, void (*gadget)(void))
{
    rcg_stream_emit(g, (uintptr_t)gadget);
}

/* The lookup gadget's two operands: what a TB there must have to be next. */
static inline void rcg_stream_emit_lookup_operands(RcgStreamGen *g)
{
    rcg_stream_emit(g, g->tb->flags | (uint64_t)tb_cflags(g->tb) << 32);
    rcg_stream_emit(g, g->tb->cs_base);
}

/* Whether another insn of at most @words words still fits in this TB. */
static inline bool rcg_stream_room(RcgStreamGen *g, int words)
{
    return !g->overflow && g->n_insns < g->max_insns &&
           (g->p - g->base + words + 16) * sizeof(uint64_t) < 0xf000;
}

#endif /* TCG_HAVE_RCG_STREAM */
#endif /* ACCEL_TCG_RCG_STREAM_H */
