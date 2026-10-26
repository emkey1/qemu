/*
 * RCG's alternate structure: the core of TBs that are streams of RCG's
 * gadgets. See include/accel/tcg/rcg-stream.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "exec/cpu-common.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/tcg.h"
#include "tcg/insn-start-words.h"
#include "accel/tcg/rcg-stream.h"
#include "internal-common.h"
#include "tb-internal.h"
#include "trace.h"

/* rcg_stream_exec loads the four with two LDPs. */
QEMU_BUILD_BUG_ON(offsetof(RcgStreamCPU, pc) !=
                  offsetof(RcgStreamCPU, exit_request) + 8);
QEMU_BUILD_BUG_ON(offsetof(RcgStreamCPU, breakpoints) !=
                  offsetof(RcgStreamCPU, tb_jmp_cache) + 8);
QEMU_BUILD_BUG_ON(RCG_STREAM_ENTER_BYTES != 16);

/*
 * The core's gadgets. Each ends by going to the gadget whose address is
 * the next word of the stream, or by leaving the stream for the main loop.
 * What they read of QEMU's structures is "i" operands, which the C compiler
 * works out.
 */

/*
 * uintptr_t rcg_stream_exec(CPUArchState *env, const void *stream,
 *                           const RcgStreamCPU *cpu);
 */
__attribute__((naked)) uintptr_t rcg_stream_exec(CPUArchState *env,
                                                 const void *stream,
                                                 const RcgStreamCPU *cpu)
{
    asm("stp x29, x30, [sp, #-96]!\n"
        "mov x29, sp\n"
        "stp x19, x20, [sp, #16]\n"
        "stp x21, x22, [sp, #32]\n"
        "stp x23, x24, [sp, #48]\n"
        "stp x25, x26, [sp, #64]\n"
        "stp x27, x28, [sp, #80]\n"
        "mov x20, x0\n"
        "ldp x21, x22, [x2, %[exit_request]]\n"
        "ldp x23, x25, [x2, %[tb_jmp_cache]]\n"
        "ldr x16, [x1]\n"
        "add x28, x1, #8\n"
        "br x16\n"
        :: [exit_request] "i" (offsetof(RcgStreamCPU, exit_request)),
           [tb_jmp_cache] "i" (offsetof(RcgStreamCPU, tb_jmp_cache)));
}

/* Leave the stream: x0 is rcg_stream_exec's return value. */
__attribute__((naked)) void rcg_stream_exit(void);
__attribute__((naked)) void rcg_stream_exit(void)
{
    asm("ldp x19, x20, [sp, #16]\n"
        "ldp x21, x22, [sp, #32]\n"
        "ldp x23, x24, [sp, #48]\n"
        "ldp x25, x26, [sp, #64]\n"
        "ldp x27, x28, [sp, #80]\n"
        "ldp x29, x30, [sp], #96\n"
        "ret\n");
}

/*
 * [tb] -- how the main loop enters a TB. As TCG's TBs start with the same
 * test: leave if an exit has been requested, without having run any of the
 * TB. Then take the entry pc, which everything pc-relative in the TB is
 * measured from.
 *
 * A jump from another stream does not come through here: it has the pc
 * already, and makes the test itself, so it goes on RCG_STREAM_ENTER_BYTES
 * in, past this gadget and its operand.
 */
__attribute__((naked)) void rcg_stream_enter(void)
{
    asm("ldr w9, [x21]\n"
        "tbnz w9, #31, 1f\n"
        "ldr x19, [x22]\n"
        "ldr x16, [x28, #8]\n"
        "add x28, x28, #16\n"
        "br x16\n"
        "1:\n"
        "ldr x0, [x28]\n"
        "orr x0, x0, %[requested]\n"
        "b _rcg_stream_exit\n"
        :: [requested] "i" (TB_EXIT_REQUESTED));
}

/* [value] */
__attribute__((naked)) void rcg_stream_exit_tb(void)
{
    asm("ldr x0, [x28]\n"
        "b _rcg_stream_exit\n");
}

/*
 * [pc delta][slot] -- leave the TB for the one at the entry pc + delta:
 * store that pc, and go on in the stream the slot points to, past its enter
 * gadget, unless an exit has been requested; then return to the main loop
 * with no TB to link from, and env->pc says where to resume. A gadget that
 * branches out of the TB (a Jcc's) loads x9 and x10 and goes to
 * rcg_stream_goto_tail.
 *
 * What a slot holds is therefore RCG_STREAM_ENTER_BYTES before the gadget to
 * run: a TB's start, or that far before one of this TB's own stubs.
 */
__attribute__((naked)) void rcg_stream_goto(void)
{
    asm("ldp x9, x10, [x28]\n"
        ".globl _rcg_stream_goto_tail\n"
        "_rcg_stream_goto_tail:\n"
        "add x19, x19, x9\n"
        "ldr w11, [x21]\n"
        "ldr x28, [x10]\n"
        "str x19, [x22]\n"
        "tbnz w11, #31, 1f\n"
        "ldr x16, [x28, %[enter]]\n"
        "add x28, x28, %[enter_next]\n"
        "br x16\n"
        "1:\n"
        "mov x0, #0\n"
        "b _rcg_stream_exit\n"
        :: [enter] "i" (RCG_STREAM_ENTER_BYTES),
           [enter_next] "i" (RCG_STREAM_ENTER_BYTES + 8));
}

/*
 * [flags | cflags << 32][cs_base] -- env->pc is set and the next TB is not
 * known at translation time: an indirect jump, or a direct one that may not
 * be linked. Go on in that TB if it exists and is a stream, else return to
 * the main loop, which will find or make it.
 */
__attribute__((naked)) void rcg_stream_lookup(void)
{
    asm("mov x0, x20\n"
        "bl _rcg_stream_lookup_tb_ptr\n"
        "cbz x0, 1f\n"
        "ldr x16, [x0]\n"
        "add x28, x0, #8\n"
        "br x16\n"
        "1:\n"
        "b _rcg_stream_exit\n");
}

/*
 * Stream emission.
 */

void rcg_stream_begin(RcgStreamGen *g, CPUState *cpu, TranslationBlock *tb,
                      int max_insns)
{
    TCGContext *s = tcg_ctx;

    memset(g, 0, sizeof(*g));
    g->tb = tb;
    g->rx = tb->tc.ptr;
    g->base = tcg_splitwx_to_rw((void *)tb->tc.ptr);
    g->p = g->base;
    g->limit = (uint64_t *)s->code_gen_highwater;
    g->max_insns = MIN(max_insns, TCG_MAX_INSNS);

    /* What tcg_gen_code would have set up for the rest of tb_gen_code. */
    tb->jmp_reset_offset[0] = TB_JMP_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_OFFSET_INVALID;
    tb->jmp_insn_offset[0] = TB_JMP_OFFSET_INVALID;
    tb->jmp_insn_offset[1] = TB_JMP_OFFSET_INVALID;
    s->code_buf = (tcg_insn_unit *)g->base;
    s->code_ptr = s->code_buf;
    s->data_gen_ptr = NULL;
    s->gen_insn_data =
        tcg_malloc(sizeof(uint64_t) * g->max_insns * INSN_START_WORDS);
    g->insn_data = s->gen_insn_data;
    g->insn_end_off = s->gen_insn_end_off;

    rcg_stream_emit_gadget(g, rcg_stream_enter);
    rcg_stream_emit(g, (uintptr_t)tcg_splitwx_to_rx(tb));
}

const void *rcg_stream_next_page(RcgStreamGen *g, CPUState *cpu, vaddr addr)
{
    TranslationBlock *tb = g->tb;
    tb_page_addr_t page0, old_page1, new_page1;
    void *host;

    /* As translator_access() takes a TB into its second page. */
    new_page1 = get_page_addr_code_hostp(cpu_env(cpu), addr, &host);
    if (new_page1 == -1) {
        return NULL;
    }
    old_page1 = tb_page_addr1(tb);
    if (new_page1 != old_page1) {
        page0 = tb_page_addr0(tb);
        if (old_page1 != -1) {
            tb_unlock_page1(page0, old_page1);
        }
        tb_set_page_addr1(tb, new_page1);
        tb_lock_page1(page0, new_page1);
    }
    return host;
}

void rcg_stream_insn_end(RcgStreamGen *g, uint64_t data0, uint64_t data1)
{
    int n = g->n_insns++;

    g->insn_data[n * INSN_START_WORDS + 0] = data0;
    g->insn_data[n * INSN_START_WORDS + 1] = data1;
    g->insn_data[n * INSN_START_WORDS + 2] = 0;
    g->insn_end_off[n] = (g->p - g->base) * sizeof(uint64_t);
}

uint64_t rcg_stream_slot(RcgStreamGen *g, int n)
{
    TranslationBlock *tb = g->tb;

    assert(n == 0 || n == 1);
    if (tb_cflags(tb) & CF_NO_GOTO_TB) {
        return rcg_stream_slot_unlinked(g);
    }
    if (tb->jmp_reset_offset[n] == TB_JMP_OFFSET_INVALID) {
        /* Claimed; rcg_stream_finish gives it the stub's real offset. */
        tb->jmp_reset_offset[n] = 0;
    }
    return (uintptr_t)&((const TranslationBlock *)tcg_splitwx_to_rx(tb))
                           ->jmp_target_addr[n];
}

uint64_t rcg_stream_slot_unlinked(RcgStreamGen *g)
{
    /*
     * The caller emits the value returned as the very next word. It will be
     * the address of a word, emitted by rcg_stream_finish, that holds the
     * address of this TB's unlinked-exit stub; remember where to put it.
     */
    assert(g->n_fix < ARRAY_SIZE(g->fix));
    g->fix[g->n_fix++].word = g->p;
    return 0;
}

int rcg_stream_finish(RcgStreamGen *g, unsigned guest_size)
{
    TranslationBlock *tb = g->tb;
    uintptr_t tb_rx = (uintptr_t)tcg_splitwx_to_rx(tb);
    const uint64_t *holder = NULL;
    size_t size;

    for (int n = 0; n < 2; n++) {
        if (tb->jmp_reset_offset[n] != TB_JMP_OFFSET_INVALID) {
            /* What tb_reset_jump puts in the slot: RCG_STREAM_ENTER_BYTES. */
            tb->jmp_reset_offset[n] = (g->p - g->base) * sizeof(uint64_t)
                                      - RCG_STREAM_ENTER_BYTES;
            rcg_stream_emit_gadget(g, rcg_stream_exit_tb);
            rcg_stream_emit(g, tb_rx | n);
        }
    }
    if (g->n_fix || tb->jmp_reset_offset[0] != TB_JMP_OFFSET_INVALID ||
        tb->jmp_reset_offset[1] != TB_JMP_OFFSET_INVALID) {
        /*
         * One stub, and one word holding its address, for all of them. It
         * comes right after the slots' stubs, where the main loop finds it
         * for a slot whose TB may not be linked (rcg_stream_slot_to_lookup).
         */
        const uint64_t *stub = g->rx + (g->p - g->base);

        if (tb_cflags(tb) & CF_NO_GOTO_PTR) {
            rcg_stream_emit_gadget(g, rcg_stream_exit_tb);
            rcg_stream_emit(g, 0);
        } else {
            rcg_stream_emit_gadget(g, g->lookup ? g->lookup
                                                : rcg_stream_lookup);
            rcg_stream_emit_lookup_operands(g);
        }
        holder = g->rx + (g->p - g->base);
        rcg_stream_emit(g, (uintptr_t)stub - RCG_STREAM_ENTER_BYTES);
    }
    if (g->overflow) {
        return -1;
    }
    for (int i = 0; i < g->n_fix; i++) {
        *g->fix[i].word = (uintptr_t)holder;
    }

    size = (g->p - g->base) * sizeof(uint64_t);
    assert(size < UINT16_MAX);
    assert(g->n_insns > 0);
    tb->size = guest_size;
    tb->icount = g->n_insns;
    tb->rcg_stream = 1;
    tcg_ctx->code_ptr = (tcg_insn_unit *)g->p;
    trace_rcg_stream_tb(tb, g->n_insns, guest_size, size);
    return size;
}
