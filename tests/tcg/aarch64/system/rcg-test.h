/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * What the RCG tests share: running one instruction from a register and
 * flags state set up in memory.
 *
 * Each case is an instruction, or a few, that target/arm/tcg/rcg-gen.py
 * writes out, as encodings, from the same tables it makes RCG's gadgets
 * from. rcg_set_insn() puts a case's instructions in rcg_run_insn(), which
 * loads X0 to X30, SP and NZCV from rcg_in, runs them, and stores them
 * all to rcg_out. It keeps the caller's registers. There is one such
 * function, patched for each case, rather than a function for each case:
 * a function for each of thousands of cases would not fit in the 2 MiB
 * that kernel.ld gives the text.
 */

#ifndef RCG_TEST_H
#define RCG_TEST_H

#include <minilib.h>
#include <stddef.h>
#include <stdint.h>

/* X0 to X30, SP, and NZCV as MRS and MSR have it. */
struct rcg_state {
    uint64_t x[31];
    uint64_t sp;
    uint64_t nzcv;
};

/* Where rcg_load and rcg_store find sp and nzcv. */
_Static_assert(offsetof(struct rcg_state, sp) == 248, "sp moved");
_Static_assert(offsetof(struct rcg_state, nzcv) == 256, "nzcv moved");

struct rcg_state rcg_in, rcg_out;

/* The caller's SP, while a case has the guest's in its place. */
uint64_t rcg_saved_sp;

/*
 * rcg_load loads every register from rcg_in, X30 last, as it is the one
 * that finds the others. rcg_store stores them all to rcg_out: X30 waits
 * in TPIDR_EL0 while it finds rcg_out. Neither changes NZCV between
 * loading it and storing it, apart from the instruction between them.
 */
asm("    .macro rcg_load\n"
    "    adrp x30, rcg_in\n"
    "    add x30, x30, :lo12:rcg_in\n"
    "    ldr x0, [x30, #256]\n"
    "    msr nzcv, x0\n"
    "    ldr x0, [x30, #248]\n"
    "    mov sp, x0\n"
    "    ldp x0, x1, [x30, #0]\n"
    "    ldp x2, x3, [x30, #16]\n"
    "    ldp x4, x5, [x30, #32]\n"
    "    ldp x6, x7, [x30, #48]\n"
    "    ldp x8, x9, [x30, #64]\n"
    "    ldp x10, x11, [x30, #80]\n"
    "    ldp x12, x13, [x30, #96]\n"
    "    ldp x14, x15, [x30, #112]\n"
    "    ldp x16, x17, [x30, #128]\n"
    "    ldp x18, x19, [x30, #144]\n"
    "    ldp x20, x21, [x30, #160]\n"
    "    ldp x22, x23, [x30, #176]\n"
    "    ldp x24, x25, [x30, #192]\n"
    "    ldp x26, x27, [x30, #208]\n"
    "    ldp x28, x29, [x30, #224]\n"
    "    ldr x30, [x30, #240]\n"
    "    .endm\n"
    "    .macro rcg_store\n"
    "    msr tpidr_el0, x30\n"
    "    adrp x30, rcg_out\n"
    "    add x30, x30, :lo12:rcg_out\n"
    "    stp x0, x1, [x30, #0]\n"
    "    stp x2, x3, [x30, #16]\n"
    "    stp x4, x5, [x30, #32]\n"
    "    stp x6, x7, [x30, #48]\n"
    "    stp x8, x9, [x30, #64]\n"
    "    stp x10, x11, [x30, #80]\n"
    "    stp x12, x13, [x30, #96]\n"
    "    stp x14, x15, [x30, #112]\n"
    "    stp x16, x17, [x30, #128]\n"
    "    stp x18, x19, [x30, #144]\n"
    "    stp x20, x21, [x30, #160]\n"
    "    stp x22, x23, [x30, #176]\n"
    "    stp x24, x25, [x30, #192]\n"
    "    stp x26, x27, [x30, #208]\n"
    "    stp x28, x29, [x30, #224]\n"
    "    mrs x0, tpidr_el0\n"
    "    str x0, [x30, #240]\n"
    "    mov x0, sp\n"
    "    str x0, [x30, #248]\n"
    "    mrs x0, nzcv\n"
    "    str x0, [x30, #256]\n"
    "    .endm\n");

/*
 * rcg_run_insn(): it saves the registers its caller expects back, and its
 * SP, swaps in the state of rcg_in, runs the RCG_SLOT instructions at
 * rcg_insn_slot, and swaps the state out to rcg_out. A case that is a
 * branch goes forward within the slot, over an instruction that marks
 * the way it was not taken.
 */
#define RCG_SLOT 3
void rcg_run_insn(void);
extern uint32_t rcg_insn_slot[];
asm("    .pushsection .text\n"
    "    .balign 4\n"
    "    .global rcg_run_insn\n"
    "    .global rcg_insn_slot\n"
    "rcg_run_insn:\n"
    "    stp x29, x30, [sp, #-96]!\n"
    "    stp x19, x20, [sp, #16]\n"
    "    stp x21, x22, [sp, #32]\n"
    "    stp x23, x24, [sp, #48]\n"
    "    stp x25, x26, [sp, #64]\n"
    "    stp x27, x28, [sp, #80]\n"
    "    adrp x0, rcg_saved_sp\n"
    "    mov x1, sp\n"
    "    str x1, [x0, :lo12:rcg_saved_sp]\n"
    "    rcg_load\n"
    "rcg_insn_slot:\n"
    "    nop\n"
    "    nop\n"
    "    nop\n"
    "    rcg_store\n"
    "    adrp x0, rcg_saved_sp\n"
    "    ldr x1, [x0, :lo12:rcg_saved_sp]\n"
    "    mov sp, x1\n"
    "    ldp x19, x20, [sp, #16]\n"
    "    ldp x21, x22, [sp, #32]\n"
    "    ldp x23, x24, [sp, #48]\n"
    "    ldp x25, x26, [sp, #64]\n"
    "    ldp x27, x28, [sp, #80]\n"
    "    ldp x29, x30, [sp], #96\n"
    "    ret\n"
    "    .popsection\n");

/*
 * Makes insn the instructions that rcg_run_insn() runs. boot.S maps the
 * text so that EL1 can write it. The cache maintenance is what hardware
 * needs before it runs instructions that were just written.
 */
static inline void rcg_set_insn(const uint32_t *insn)
{
    for (int i = 0; i < RCG_SLOT; i++) {
        rcg_insn_slot[i] = insn[i];
        asm volatile("dc cvau, %0\n"
                     "dsb ish\n"
                     "ic ivau, %0\n"
                     "dsb ish\n"
                     "isb\n" : : "r" (&rcg_insn_slot[i]) : "memory");
    }
}

/*
 * A case: what to call it, its instructions, and the registers that take
 * the values tested, of which 31 is SP; -1 for none. adr is the register
 * that ADR or ADRP writes, or -1 for any other instruction, and page says
 * that it is ADRP. flags says that it reads NZCV: it then starts from
 * each value of NZCV, with fewer values in its registers.
 */
struct rcg_case {
    const char *name;
    uint32_t insn[RCG_SLOT];
    int8_t a, b, adr;
    uint8_t page, flags;
};

/*
 * The values a case's operands take: the edges of each width and of the
 * shifts, and some of no pattern.
 */
static const uint64_t rcg_values[] = {
    0, 1, 2, 0x7f, 0x80, 0xfff, 0x1000, 0x7fffffff, 0x80000000,
    0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000,
    0xfffffffffffff000, 0xffffffffffffffff, 0x0123456789abcdef,
    0xfedcba9876543210, 0x5555555555555555,
};
#define RCG_NB_VALUES (sizeof(rcg_values) / sizeof(rcg_values[0]))

/* The values of a case that starts from each value of NZCV. */
static const uint64_t rcg_flag_values[] = {
    0, 1, 0x80000000, 0xffffffffffffffff, 0x0123456789abcdef,
};
#define RCG_NB_FLAG_VALUES \
    (sizeof(rcg_flag_values) / sizeof(rcg_flag_values[0]))

/*
 * What a case starts from: NZCV, and a seed for the registers that take
 * no value, so that each holds something no other does.
 */
static const struct rcg_start {
    uint64_t nzcv;
    uint64_t seed;
} rcg_starts[] = {
    { 0x00000000, 0x0101010101010101 },
    { 0xf0000000, 0x8000000100000003 },
    { 0x60000000, 0x00000000ffffffff },
    { 0x90000000, 0xfedcba9800000000 },
};
#define RCG_NB_STARTS (sizeof(rcg_starts) / sizeof(rcg_starts[0]))

/* The flags: N, Z, C and V. */
#define RCG_NZCV 0xf0000000ul

/* rcg_in for a case whose operands take the values x and y, from start. */
static inline void rcg_setup(const struct rcg_case *c, uint64_t x, uint64_t y,
                             const struct rcg_start *start)
{
    for (int i = 0; i < 31; i++) {
        rcg_in.x[i] = start->seed * (i + 1) + i;
    }
    rcg_in.sp = start->seed * 32 + 31;
    rcg_in.nzcv = start->nzcv;
    if (c->a == 31) {
        rcg_in.sp = x;
    } else if (c->a >= 0) {
        rcg_in.x[c->a] = x;
    }
    if (c->b == 31) {
        rcg_in.sp = y;
    } else if (c->b >= 0) {
        rcg_in.x[c->b] = y;
    }
}

/* FNV-1a, 64 bits. */
#define RCG_HASH_INIT 0xcbf29ce484222325ul

static inline uint64_t rcg_hash(uint64_t h, const void *data, size_t n)
{
    const uint8_t *p = data;

    while (n--) {
        h = (h ^ *p++) * 0x100000001b3ul;
    }
    return h;
}

#endif /* RCG_TEST_H */
