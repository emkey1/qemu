/*
 * RCG's alternate structure for x86-64 guests: the translator from 64-bit
 * code to streams of RCG's gadgets (accel/tcg/rcg-stream.h).
 *
 * It translates what rcg-gen.py has a gadget for and stops in front of
 * anything else, so that the next TB starts there and TCG translates it; a
 * TB whose first insn is one of those is left to TCG. The plan lets this
 * prototype reach the gadgets through whichever decoder is quicker to stand
 * up, and that is this file's own small one: decode-new is TCG's.
 *
 * The flags are TCG's lazy ones. Which CC_OP the state in env is of is
 * known here insn by insn, as TCG's translator knows it, and is written to
 * env->cc_op only where the TB ends. Each insn records it with its pc, as
 * TCG's insn_start does, so that a fault unwinds to both.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "exec/memopidx.h"
#include "accel/tcg/cpu-mmu-index.h"
#include "accel/tcg/rcg-stream.h"
#include "accel/tcg/tb-jmp-cache.h"
#include "accel/tcg/tb-hash.h"
#include "tcg/tcg.h"
#include "tcg/tcg-internal.h"
#include "tcti-gadget-defs.h"
#include "target/i386/tcg/rcg_stream_gadgets.h"
#include "tcg-cpu.h"

/*
 * The front end's own gadgets.
 */

/* [cc_op] -- the lazy-flags state's CC_OP to env, where a TB ends. */
static __attribute__((naked)) void rcg_stream_x86_cc_op(void)
{
    asm("ldr x16, [x28, #8]\n"
        "ldr w9, [x28]\n"
        "str w9, [x20, %[cc_op]]\n"
        "add x28, x28, #16\n"
        "br x16\n"
        :: [cc_op] "i" (offsetof(CPUX86State, cc_op)));
}

/*
 * [flags | cflags << 32][cs_base] -- rcg_stream_lookup, with tb_lookup()'s
 * first step done here: the pc a jump left in env is hashed as
 * tb_jmp_cache_hash_func() hashes it, and both ways of cpu->tb_jmp_cache
 * are read. A TB there with this TB's cs_base, flags and cflags is gone on
 * in, as rcg_stream_goto goes on, if it is a stream: nothing a stream runs
 * changes them, and an invalidated TB has CF_INVALID in its cflags. With a
 * breakpoint set, or anything else, it is rcg_stream_lookup's to find.
 */
QEMU_BUILD_BUG_ON(sizeof(((CPUJumpCache *)0)->array[0]) != 16);
QEMU_BUILD_BUG_ON(offsetof(CPUJumpCache, array[0].pc) !=
                  offsetof(CPUJumpCache, array[0].tb) + 8);
QEMU_BUILD_BUG_ON(offsetof(TranslationBlock, flags) !=
                  offsetof(TranslationBlock, cs_base) + 8);
QEMU_BUILD_BUG_ON(offsetof(TranslationBlock, cflags) !=
                  offsetof(TranslationBlock, flags) + 4);
QEMU_BUILD_BUG_ON(offsetof(CPUState, breakpoints.tqh_first) !=
                  offsetof(CPUState, breakpoints));

static __attribute__((naked)) void rcg_stream_x86_lookup(void)
{
    asm("ldr x10, [x22]\n"
        "ldr x11, [x25]\n"
        "eor x12, x10, x10, lsr %[hash_shift]\n"
        "cbnz x11, 3f\n"
        "lsr x13, x12, %[hash_shift]\n"
        "and x12, x12, %[addr_mask]\n"
        "and x13, x13, %[page_mask]\n"
        "orr x12, x12, x13\n"
        "ldp x11, x9, [x28]\n"
        "add x13, x23, x12, lsl #4\n"
        "ldp x14, x15, [x13, %[jc_tb]]\n"
        "cmp x15, x10\n"
        "b.ne 2f\n"
        "cbz x14, 2f\n"
        "ldp x15, x16, [x14, %[tb_cs_base]]\n"
        "cmp x16, x11\n"
        "ccmp x15, x9, #0, eq\n"
        "b.eq 5f\n"
        "2:\n"
        "eor x12, x12, #1\n"
        "add x13, x23, x12, lsl #4\n"
        "ldp x14, x15, [x13, %[jc_tb]]\n"
        "cmp x15, x10\n"
        "b.ne 3f\n"
        "cbz x14, 3f\n"
        "ldp x15, x16, [x14, %[tb_cs_base]]\n"
        "cmp x16, x11\n"
        "ccmp x15, x9, #0, eq\n"
        "b.ne 3f\n"
        "5:\n"
        "ldrb w17, [x14, %[tb_rcg]]\n"
        "cbz w17, 3f\n"
        "ldr w11, [x21]\n"
        "ldr x28, [x14, %[tb_tc_ptr]]\n"
        "mov x19, x10\n"
        "tbnz w11, #31, 4f\n"
        "ldr x16, [x28, %[enter]]\n"
        "add x28, x28, %[enter_next]\n"
        "br x16\n"
        "3:\n"
        "b _rcg_stream_lookup\n"
        "4:\n"
        "mov x0, #0\n"
        "b _rcg_stream_exit\n"
        :: [hash_shift] "i" (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS),
           [addr_mask] "i" (TB_JMP_ADDR_MASK),
           [page_mask] "i" (TB_JMP_PAGE_MASK),
           [jc_tb] "i" (offsetof(CPUJumpCache, array[0].tb)),
           [tb_cs_base] "i" (offsetof(TranslationBlock, cs_base)),
           [tb_rcg] "i" (offsetof(TranslationBlock, rcg_stream)),
           [tb_tc_ptr] "i" (offsetof(TranslationBlock, tc.ptr)),
           [enter] "i" (RCG_STREAM_ENTER_BYTES),
           [enter_next] "i" (RCG_STREAM_ENTER_BYTES + 8));
}

/*
 * Decoding.
 */

enum { NEXT, END, UNKNOWN };

typedef struct Insn {
    const uint8_t *start, *p, *end;
    bool bad;                   /* ran into the end of what may be read */
    bool rex, w, r, x, b;       /* a REX prefix, and its bits */
    bool opsize;                /* 0x66 */
    int seg;                    /* R_FS or R_GS for their prefixes, or -1 */
    /* ModRM: reg and rm with REX.R and REX.B */
    int mod, reg, rm;
    /* A memory operand: registers or -1, and RCG_STREAM_SHAPE_* */
    int base, index, shape;
    bool rip;
    int64_t disp;
} Insn;

static unsigned u8(Insn *d)
{
    if (d->p >= d->end) {
        d->bad = true;
        return 0;
    }
    return *d->p++;
}

static int64_t s8(Insn *d)
{
    return (int8_t)u8(d);
}

static int64_t s16(Insn *d)
{
    unsigned v = u8(d);

    return (int16_t)(v | u8(d) << 8);
}

static int64_t s32(Insn *d)
{
    uint32_t v = 0;

    for (int i = 0; i < 4; i++) {
        v |= (uint32_t)u8(d) << (8 * i);
    }
    return (int32_t)v;
}

static int64_t imm64(Insn *d)
{
    uint64_t v = 0;

    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)u8(d) << (8 * i);
    }
    return v;
}

/* An immediate of an operation of size ot, as decode-new extends it. */
static int64_t imm(Insn *d, MemOp ot)
{
    return ot == MO_8 ? s8(d) : ot == MO_16 ? s16(d) : s32(d);
}

static void modrm(Insn *d)
{
    unsigned m = u8(d), sib;
    int scale = 0;
    bool no_base = false;

    d->mod = m >> 6;
    d->reg = ((m >> 3) & 7) | d->r << 3;
    d->rm = m & 7;
    if (d->mod == 3) {
        d->rm |= d->b << 3;
        return;
    }
    d->base = d->rm | d->b << 3;
    d->index = -1;
    if (d->rm == 4) {
        sib = u8(d);
        scale = sib >> 6;
        d->index = ((sib >> 3) & 7) | d->x << 3;
        if (d->index == 4) {
            d->index = -1;
        }
        d->base = (sib & 7) | d->b << 3;
        no_base = (sib & 7) == 5 && d->mod == 0;
    } else if (d->rm == 5 && d->mod == 0) {
        d->rip = true;
        no_base = true;
    }
    d->disp = d->mod == 1 ? s8(d) : d->mod == 2 || no_base ? s32(d) : 0;
    if (no_base) {
        d->base = -1;
    }
    if (d->rip || (d->base >= 0 && d->index < 0)) {
        d->shape = RCG_STREAM_SHAPE_B;
    } else if (d->base >= 0) {
        d->shape = RCG_STREAM_SHAPE_BI0 + scale;
    } else if (d->index >= 0) {
        d->shape = RCG_STREAM_SHAPE_I0 + scale;
    } else {
        d->shape = RCG_STREAM_SHAPE_D;
    }
}

/* Whether register n at size ot is one RCG has: not AH, CH, DH or BH. */
static bool reg_ok(const Insn *d, MemOp ot, int n)
{
    return ot != MO_8 || d->rex || n < 4;
}

/*
 * Translation.
 */

typedef struct Ctx {
    RcgStreamGen g;
    TranslationBlock *tb;
    vaddr pc;                   /* the TB's, which env->eip holds in it */
    unsigned page_off;          /* pc's offset in its page */
    unsigned off, len;          /* this insn's offset from pc, and length */
    int cc_op;                  /* the flags state's, or CC_OP_DYNAMIC */
    int mmu_idx;
    int64_t tlb;                /* TCTI_TLB_FAST_OFS(mmu_idx) */
    bool ord;                   /* the ordered twins: tcg_ldst_ordered() */
    /*
     * The first ROL or ROR whose CF and OF have not yet been overwritten:
     * its gadget leaves the flags state alone, so a later insn of this TB
     * must write every flag before anything reads one, before anything
     * accesses memory (a fault would show the flags), and before the TB
     * ends. Otherwise the TB is translated again, ending before it
     * (fail_off).
     */
    int stale_off, fail_off;
    unsigned stop_off;
} Ctx;

#define REG(n) (offsetof(CPUX86State, regs) + 8 * (n))

static void E(Ctx *c, uint64_t word)
{
    rcg_stream_emit(&c->g, word);
}

static void EG(Ctx *c, RcgStreamGadget gadget)
{
    assert(gadget);
    rcg_stream_emit_gadget(&c->g, gadget);
}

/* The next insn's pc less env->eip, which is the TB's pc. */
static int64_t next_delta(Ctx *c)
{
    return c->off + c->len;
}

/* A memory operand's words: rcg-gen.py's ea_words(). */
static void emit_ea(Ctx *c, const Insn *d, bool with_seg)
{
    if (d->rip) {
        E(c, offsetof(CPUX86State, eip));
    } else if (d->base >= 0) {
        E(c, REG(d->base));
    }
    if (d->index >= 0) {
        E(c, REG(d->index));
    }
    E(c, d->disp + (d->rip ? next_delta(c) : 0));
    if (with_seg && d->seg >= 0) {
        E(c, offsetof(CPUX86State, segs[0].base) +
             d->seg * sizeof(SegmentCache));
    }
}

/* An access's MemOpIdx and the CPUTLBDescFast's offset. */
static void emit_access(Ctx *c, MemOp ot)
{
    if (c->stale_off >= 0 && c->fail_off < 0) {
        c->fail_off = c->stale_off;
    }
    E(c, make_memop_idx(MO_LE | ot, c->mmu_idx));
    E(c, c->tlb);
}

/* The index of a memory gadget's table entry: [shape][seg][ordered]. */
#define MEM(d, c) [(d)->shape][(d)->seg >= 0][(c)->ord]

/* An insn that writes every flag: a stale ROL's or ROR's are gone. */
static void set_cc(Ctx *c, int cc_op)
{
    c->cc_op = cc_op;
    c->stale_off = -1;
}

/* The condition gadgets' class for the flags state, or -1. */
static int cond_class(Ctx *c)
{
    static const struct { int first, cls; } classes[] = {
        { CC_OP_SUBB, RCG_STREAM_CC_SUB8 },
        { CC_OP_ADDB, RCG_STREAM_CC_ADD8 },
        { CC_OP_LOGICB, RCG_STREAM_CC_LOGIC8 },
        { CC_OP_INCB, RCG_STREAM_CC_INC8 },
        { CC_OP_DECB, RCG_STREAM_CC_DEC8 },
    };

    if (c->stale_off >= 0) {
        return -1;
    }
    if (c->cc_op == CC_OP_EFLAGS) {
        return RCG_STREAM_CC_EFLAGS;
    }
    for (int i = 0; i < ARRAY_SIZE(classes); i++) {
        if (c->cc_op >= classes[i].first && c->cc_op <= classes[i].first + 3) {
            return classes[i].cls + c->cc_op - classes[i].first;
        }
    }
    return -1;
}

/* Where the TB ends: the flags state's CC_OP to env, if env lacks it. */
static void flush_cc(Ctx *c)
{
    if (c->cc_op != CC_OP_DYNAMIC) {
        EG(c, rcg_stream_x86_cc_op);
        E(c, c->cc_op);
    }
}

/*
 * The pc delta and slot of a direct jump to @target, by way n: a slot TB
 * linking may patch for a target in the TB's own page, as
 * translator_use_goto_tb() decides for TCG, else a lookup.
 */
static void emit_target(Ctx *c, vaddr target, int n)
{
    E(c, target - c->pc);
    if (((target ^ c->pc) & TARGET_PAGE_MASK) == 0) {
        E(c, rcg_stream_slot(&c->g, n));
    } else {
        E(c, rcg_stream_slot_unlinked(&c->g));
    }
}

static void exit_goto(Ctx *c, vaddr target)
{
    flush_cc(c);
    EG(c, rcg_stream_goto);
    emit_target(c, target, 0);
}

/* env->eip is set: go on in the TB there. */
static void exit_lookup(Ctx *c)
{
    flush_cc(c);
    if (tb_cflags(c->tb) & CF_NO_GOTO_PTR) {
        EG(c, rcg_stream_exit_tb);
        E(c, 0);
    } else {
        EG(c, rcg_stream_x86_lookup);
        rcg_stream_emit_lookup_operands(&c->g);
    }
}

/*
 * Two-operand arithmetic and MOV (op -1) with a ModRM, already decoded:
 * the register is the destination if to_reg.
 */
static int alu_modrm(Ctx *c, Insn *d, int op, MemOp ot, bool to_reg)
{
    if (d->mod == 3) {
        int dst = to_reg ? d->reg : d->rm, src = to_reg ? d->rm : d->reg;

        if (!reg_ok(d, ot, dst) || !reg_ok(d, ot, src)) {
            return UNKNOWN;
        }
        if (op == RCG_STREAM_ALU_XOR && dst == src) {
            /* TCG's zero idiom: 0, with the flags of CC_OP_EFLAGS. */
            EG(c, rcg_stream_zero[ot]);
            E(c, REG(dst));
            set_cc(c, CC_OP_EFLAGS);
            return NEXT;
        }
        EG(c, op < 0 ? rcg_stream_mov_r[0][ot] : rcg_stream_alu_r[op][0][ot]);
        E(c, REG(dst));
        E(c, REG(src));
    } else {
        if (!reg_ok(d, ot, d->reg)) {
            return UNKNOWN;
        }
        if (to_reg) {
            EG(c, op < 0 ? rcg_stream_mov_m[0][ot] MEM(d, c)
                         : rcg_stream_alu_m[op][0][ot] MEM(d, c));
            E(c, REG(d->reg));
            emit_ea(c, d, true);
        } else {
            EG(c, op < 0 ? rcg_stream_mov_m[1][ot] MEM(d, c)
                         : rcg_stream_alu_m[op][1][ot] MEM(d, c));
            emit_ea(c, d, true);
            E(c, REG(d->reg));
        }
        emit_access(c, ot);
    }
    if (op >= 0) {
        set_cc(c, rcg_stream_alu_cc[op] + ot);
    }
    return NEXT;
}

/* The same with an immediate source, its ModRM and immediate decoded. */
static int alu_imm(Ctx *c, Insn *d, int op, MemOp ot, int64_t value)
{
    if (d->mod == 3) {
        if (!reg_ok(d, ot, d->rm)) {
            return UNKNOWN;
        }
        EG(c, op < 0 ? rcg_stream_mov_r[1][ot] : rcg_stream_alu_r[op][1][ot]);
        E(c, REG(d->rm));
        E(c, value);
    } else {
        EG(c, op < 0 ? rcg_stream_mov_m[2][ot] MEM(d, c)
                     : rcg_stream_alu_m[op][2][ot] MEM(d, c));
        emit_ea(c, d, true);
        E(c, value);
        emit_access(c, ot);
    }
    if (op >= 0) {
        set_cc(c, rcg_stream_alu_cc[op] + ot);
    }
    return NEXT;
}

/* The x86 opcode's arithmetic, by its three bits: RCG's order, or -1. */
static const int alu_ops[8] = {
    RCG_STREAM_ALU_ADD, RCG_STREAM_ALU_OR, -1, -1,
    RCG_STREAM_ALU_AND, RCG_STREAM_ALU_SUB, RCG_STREAM_ALU_XOR,
    RCG_STREAM_ALU_CMP,
};

/* SHL, SHR, SAR, ROL and ROR by an immediate count (C0, C1, D0, D1). */
static int shift(Ctx *c, Insn *d, MemOp ot, unsigned count)
{
    unsigned width = 8 << ot;
    int op;

    count &= ot == MO_64 ? 63 : 31;
    if (count == 0) {
        /* Shifts nothing, and changes no flag: TCG's. */
        return UNKNOWN;
    }
    switch (d->reg & 7) {
    case 0: /* ROL, as ROR by the width less the count */
    case 1: /* ROR */
        if (d->mod != 3 || ot < MO_32) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_ror[ot]);
        E(c, REG(d->rm));
        E(c, (d->reg & 7) == 1 ? count : width - count);
        if (c->stale_off < 0) {
            c->stale_off = c->off;
        }
        return NEXT;
    case 4:
    case 6: /* SAL */
        op = RCG_STREAM_SHIFT_SHL;
        break;
    case 5:
        op = RCG_STREAM_SHIFT_SHR;
        break;
    case 7:
        op = RCG_STREAM_SHIFT_SAR;
        break;
    default:
        return UNKNOWN;
    }
    if (d->mod == 3) {
        if (!reg_ok(d, ot, d->rm)) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_shift_r[op][ot]);
        E(c, REG(d->rm));
        E(c, count);
    } else {
        EG(c, rcg_stream_shift_m[op][ot] MEM(d, c));
        emit_ea(c, d, true);
        E(c, count);
        emit_access(c, ot);
    }
    set_cc(c, rcg_stream_shift_cc[op] + ot);
    return NEXT;
}

/* MOVZX, MOVSX and MOVSXD, from src bits to operand size ot. */
static int extend(Ctx *c, Insn *d, int op, MemOp ot, MemOp src)
{
    if (!rcg_stream_extend_r[op][ot]) {
        return UNKNOWN;
    }
    if (d->mod == 3) {
        if (!reg_ok(d, src, d->rm)) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_extend_r[op][ot]);
        E(c, REG(d->reg));
        E(c, REG(d->rm));
    } else {
        EG(c, rcg_stream_extend_m[op][ot] MEM(d, c));
        E(c, REG(d->reg));
        emit_ea(c, d, true);
        emit_access(c, src);
    }
    return NEXT;
}

/* A Jcc, SETcc or CMOVcc's class, after the check that it has one. */
static int jcc(Ctx *c, unsigned cond, int64_t rel)
{
    int cls = cond_class(c);
    vaddr next = c->pc + next_delta(c);

    /* (P and NP only from CC_OP_EFLAGS) */
    if (cls < 0 || !rcg_stream_jcc[cls][cond]) {
        return UNKNOWN;
    }
    EG(c, rcg_stream_jcc[cls][cond]);
    E(c, c->cc_op);
    emit_target(c, next + rel, 0);
    /* The way not taken; the gadget has stored CC_OP. */
    EG(c, rcg_stream_goto);
    emit_target(c, next, 1);
    return END;
}

/* CALL, JMP and PUSH through r/m (FF /2, /4 and /6). */
static int group5(Ctx *c, Insn *d)
{
    switch (d->reg & 7) {
    case 2: /* CALL */
        if (d->mod == 3) {
            EG(c, rcg_stream_call[1][c->ord]);
            E(c, REG(d->rm));
        } else {
            EG(c, rcg_stream_call_m MEM(d, c));
            emit_ea(c, d, true);
        }
        E(c, next_delta(c));
        emit_access(c, MO_64);
        exit_lookup(c);
        return END;
    case 4: /* JMP */
        if (d->mod == 3) {
            EG(c, rcg_stream_jmp_r[0]);
            E(c, REG(d->rm));
        } else {
            EG(c, rcg_stream_jmp_m MEM(d, c));
            emit_ea(c, d, true);
            emit_access(c, MO_64);
        }
        exit_lookup(c);
        return END;
    case 6: /* PUSH */
        if (d->mod == 3) {
            EG(c, rcg_stream_push[0][c->ord]);
            E(c, REG(d->rm));
        } else {
            EG(c, rcg_stream_push_m MEM(d, c));
            emit_ea(c, d, true);
        }
        emit_access(c, MO_64);
        return NEXT;
    }
    return UNKNOWN;
}

/* One insn, from code: NEXT, END (it ends the TB) or UNKNOWN. */
static int insn(Ctx *c, Insn *d)
{
    unsigned b, op;
    bool rep = false;
    MemOp ot;
    int64_t value;
    int r;

    /* Prefixes: those of 64-bit code that change nothing RCG has, or FS/GS. */
    for (;;) {
        b = u8(d);
        switch (b) {
        case 0x66:
            d->opsize = true;
            continue;
        case 0x26: case 0x2e: case 0x36: case 0x3e:
            continue;
        case 0x64:
            d->seg = R_FS;
            continue;
        case 0x65:
            d->seg = R_GS;
            continue;
        case 0xf3:
            rep = true;
            continue;
        }
        break;
    }
    if ((b & 0xf0) == 0x40) {
        d->rex = true;
        d->w = b & 8;
        d->r = b & 4;
        d->x = b & 2;
        d->b = b & 1;
        b = u8(d);
    }
    if (d->bad) {
        return UNKNOWN;
    }
    ot = d->w ? MO_64 : d->opsize ? MO_16 : MO_32;

#define DONE()      do { if (d->bad) { return UNKNOWN; }                   \
                         c->len = d->p - d->start; } while (0)

    if (rep) {
        /* REP RET is RET; ENDBR64 and ENDBR32 are NOPs here, as for TCG. */
        if (b == 0xc3) {
            DONE();
            EG(c, rcg_stream_ret[c->ord]);
            E(c, 8);
            emit_access(c, MO_64);
            exit_lookup(c);
            return END;
        }
        if (b == 0x0f && u8(d) == 0x1e) {
            b = u8(d);
            DONE();
            return b == 0xfa || b == 0xfb ? NEXT : UNKNOWN;
        }
        return UNKNOWN;
    }

    if (b < 0x40 && (b & 7) < 6 && alu_ops[b >> 3] >= 0) {
        /* ADD, OR, AND, SUB, XOR and CMP in all their forms. */
        op = alu_ops[b >> 3];
        if (!(b & 1)) {
            ot = MO_8;
        }
        if ((b & 7) < 4) {
            modrm(d);
            DONE();
            return alu_modrm(c, d, op, ot, b & 2);
        }
        value = imm(d, ot);
        d->mod = 3;
        d->rm = 0;                  /* AL or rAX */
        DONE();
        return alu_imm(c, d, op, ot, value);
    }

    switch (b) {
    case 0x80: case 0x81: case 0x83:
        if (b == 0x80) {
            ot = MO_8;
        }
        modrm(d);
        value = b == 0x83 ? s8(d) : imm(d, ot);
        DONE();
        op = alu_ops[d->reg & 7];
        return (int)op < 0 ? UNKNOWN : alu_imm(c, d, op, ot, value);

    case 0x84: case 0x85: /* TEST r/m, reg */
        if (b == 0x84) {
            ot = MO_8;
        }
        modrm(d);
        DONE();
        return alu_modrm(c, d, RCG_STREAM_ALU_TEST, ot, false);

    case 0xa8: case 0xa9: /* TEST AL/rAX, imm */
        if (b == 0xa8) {
            ot = MO_8;
        }
        value = imm(d, ot);
        d->mod = 3;
        d->rm = 0;
        DONE();
        return alu_imm(c, d, RCG_STREAM_ALU_TEST, ot, value);

    case 0x88: case 0x89: case 0x8a: case 0x8b:
        if (!(b & 1)) {
            ot = MO_8;
        }
        modrm(d);
        DONE();
        return alu_modrm(c, d, -1, ot, b & 2);

    case 0xc6: case 0xc7:
        if (b == 0xc6) {
            ot = MO_8;
        }
        modrm(d);
        value = imm(d, ot);
        DONE();
        return (d->reg & 7) ? UNKNOWN : alu_imm(c, d, -1, ot, value);

    case 0xb0 ... 0xb7:
        value = s8(d);
        DONE();
        d->mod = 3;
        d->rm = (b & 7) | d->b << 3;
        return alu_imm(c, d, -1, MO_8, value);

    case 0xb8 ... 0xbf:
        value = ot == MO_64 ? imm64(d) : imm(d, ot);
        DONE();
        d->mod = 3;
        d->rm = (b & 7) | d->b << 3;
        return alu_imm(c, d, -1, ot, value);

    case 0x8d: /* LEA */
        modrm(d);
        DONE();
        if (d->mod == 3) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_lea[ot][d->shape]);
        E(c, REG(d->reg));
        emit_ea(c, d, false);
        return NEXT;

    case 0x50 ... 0x57: /* PUSH */
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_push[0][c->ord]);
        E(c, REG((b & 7) | d->b << 3));
        emit_access(c, MO_64);
        return NEXT;

    case 0x58 ... 0x5f: /* POP */
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_pop[c->ord]);
        E(c, REG((b & 7) | d->b << 3));
        emit_access(c, MO_64);
        return NEXT;

    case 0x68: case 0x6a: /* PUSH imm */
        value = b == 0x68 ? s32(d) : s8(d);
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_push[1][c->ord]);
        E(c, value);
        emit_access(c, MO_64);
        return NEXT;

    case 0x8f: /* POP r/m */
        modrm(d);
        DONE();
        if (d->opsize || d->mod != 3 || (d->reg & 7)) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_pop[c->ord]);
        E(c, REG(d->rm));
        emit_access(c, MO_64);
        return NEXT;

    case 0x63: /* MOVSXD */
        modrm(d);
        DONE();
        if (ot != MO_64) {
            return UNKNOWN;
        }
        return extend(c, d, RCG_STREAM_EXTEND_MOVSXD, ot, MO_32);

    case 0x90:
        DONE();
        return d->b ? UNKNOWN : NEXT;

    case 0xc0: case 0xc1: case 0xd0: case 0xd1:
        if (!(b & 1)) {
            ot = MO_8;
        }
        modrm(d);
        value = b < 0xd0 ? u8(d) : 1;
        DONE();
        return shift(c, d, ot, value);

    case 0xf6: case 0xf7:
        if (b == 0xf6) {
            ot = MO_8;
        }
        modrm(d);
        if ((d->reg & 7) < 2) {
            /* TEST r/m, imm */
            value = imm(d, ot);
            DONE();
            return alu_imm(c, d, RCG_STREAM_ALU_TEST, ot, value);
        }
        DONE();
        if ((d->reg & 7) == 2 || (d->reg & 7) == 3) {
            op = (d->reg & 7) == 2 ? RCG_STREAM_UNARY_NOT : RCG_STREAM_UNARY_NEG;
            if (d->mod == 3) {
                if (!reg_ok(d, ot, d->rm)) {
                    return UNKNOWN;
                }
                EG(c, rcg_stream_unary_r[op][ot]);
                E(c, REG(d->rm));
            } else {
                EG(c, rcg_stream_unary_m[op][ot] MEM(d, c));
                emit_ea(c, d, true);
                emit_access(c, ot);
            }
            if (rcg_stream_unary_cc[op] >= 0) {
                set_cc(c, rcg_stream_unary_cc[op] + ot);
            }
            return NEXT;
        }
        return UNKNOWN;

    case 0xff:
        modrm(d);
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        return group5(c, d);

    case 0x70 ... 0x7f:
        value = s8(d);
        DONE();
        return jcc(c, b & 15, value);

    case 0xe8: /* CALL rel32 */
        value = s32(d);
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_call[0][c->ord]);
        E(c, next_delta(c));
        emit_access(c, MO_64);
        exit_goto(c, c->pc + next_delta(c) + value);
        return END;

    case 0xe9: case 0xeb: /* JMP rel */
        value = b == 0xe9 ? s32(d) : s8(d);
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        exit_goto(c, c->pc + next_delta(c) + value);
        return END;

    case 0xc2: case 0xc3: /* RET */
        value = b == 0xc2 ? (uint16_t)s16(d) : 0;
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_ret[c->ord]);
        E(c, 8 + value);
        emit_access(c, MO_64);
        exit_lookup(c);
        return END;

    case 0x0f:
        break;

    default:
        return UNKNOWN;
    }

    b = u8(d);
    switch (b) {
    case 0x1f: /* NOP r/m */
        modrm(d);
        DONE();
        return NEXT;

    case 0x40 ... 0x4f: /* CMOVcc */
        modrm(d);
        DONE();
        r = cond_class(c);
        if (d->mod != 3 || r < 0 || ot == MO_8 ||
            !rcg_stream_cmov[ot][r][b & 15]) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_cmov[ot][r][b & 15]);
        E(c, REG(d->reg));
        E(c, REG(d->rm));
        return NEXT;

    case 0x80 ... 0x8f:
        value = s32(d);
        DONE();
        if (d->opsize) {
            return UNKNOWN;
        }
        return jcc(c, b & 15, value);

    case 0x90 ... 0x9f: /* SETcc */
        modrm(d);
        DONE();
        r = cond_class(c);
        if (d->mod != 3 || r < 0 || !reg_ok(d, MO_8, d->rm) ||
            !rcg_stream_setcc[r][b & 15]) {
            return UNKNOWN;
        }
        EG(c, rcg_stream_setcc[r][b & 15]);
        E(c, REG(d->rm));
        return NEXT;

    case 0xb6: case 0xb7: case 0xbe: case 0xbf:
        modrm(d);
        DONE();
        return extend(c, d, (b & 8 ? RCG_STREAM_EXTEND_MOVSXB
                                   : RCG_STREAM_EXTEND_MOVZXB) + (b & 1),
                      ot, b & 1 ? MO_16 : MO_8);
    }
    return UNKNOWN;
#undef DONE
}

/*
 * One attempt at the TB. Returns false if a ROL's or ROR's flags were left
 * stale where they may be seen: c->fail_off then says where the next
 * attempt stops.
 */
static bool translate(Ctx *c, CPUState *cs, int max_insns,
                      const uint8_t *code, int *r)
{
    rcg_stream_begin(&c->g, cs, c->tb, max_insns);
    c->g.lookup = rcg_stream_x86_lookup;
    c->off = 0;
    c->cc_op = CC_OP_DYNAMIC;
    c->stale_off = -1;
    c->fail_off = -1;
    *r = NEXT;

    /* Every insn starts in the TB's page; one may end in the next. */
    while (rcg_stream_room(&c->g, 24) && c->off != c->stop_off &&
           c->page_off + c->off < TARGET_PAGE_SIZE) {
        unsigned rem = TARGET_PAGE_SIZE - c->page_off - c->off;
        Insn d = {
            .start = code + c->off, .p = code + c->off,
            .end = code + c->off + MIN(rem, 15), .seg = -1,
        };
        uint64_t *start = c->g.p;
        int n_fix = c->g.n_fix, cc_op = c->cc_op, stale_off = c->stale_off;
        int fail_off = c->fail_off;

        *r = insn(c, &d);
        if (*r == UNKNOWN) {
            c->g.p = start;
            c->g.n_fix = n_fix;
            c->cc_op = cc_op;
            c->stale_off = stale_off;
            c->fail_off = fail_off;
            break;
        }
        rcg_stream_insn_end(&c->g, c->page_off + c->off, cc_op);
        c->off += c->len;
        if (*r == END) {
            break;
        }
    }
    if (c->stale_off >= 0 && c->fail_off < 0) {
        c->fail_off = c->stale_off;
    }
    if (c->fail_off >= 0) {
        return false;
    }
    if (c->g.n_insns && *r != END) {
        exit_goto(c, c->pc + c->off);
    }
    return true;
}

int x86_rcg_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc)
{
    uint32_t flags = tb->flags, cflags = tb_cflags(tb);
    Ctx cc = { 0 }, *c = &cc;
    int r;

    /*
     * 64-bit code in an ordinary TB: in RAM, pc-relative, that may check
     * for interrupts and need not stop after a set number of insns, in
     * code that is not being stepped or in the shadow of a mov to ss, not
     * in system management mode or a guest of SVM, and with no bound
     * registers to reset at each branch.
     */
    if (!host_pc || !(cflags & CF_PCREL) ||
        TARGET_PAGE_BITS != TCTI_TLB_PAGE_BITS ||
        (cflags & (CF_SINGLE_STEP | CF_MEMI_ONLY | CF_USE_ICOUNT |
                   CF_STEP_ATOMIC | CF_COUNT_MASK | CF_NOIRQ |
                   CF_BP_PAGE)) ||
        !(flags & HF_CS64_MASK) || tb->cs_base ||
        (flags & (HF_INHIBIT_IRQ_MASK | HF_TF_MASK | HF_RF_MASK |
                  HF_SMM_MASK | HF_GUEST_MASK | HF_MPX_EN_MASK))) {
        return 0;
    }

    /*
     * The guest's memory order: by the ordered twins, as TCTI keeps it, or
     * else only where it does not matter, with one vCPU.
     */
    c->ord = tcg_ldst_ordered(tcg_ctx);
    if (!c->ord && (cflags & CF_PARALLEL)) {
        return 0;
    }
    c->tb = tb;
    c->pc = pc;
    c->page_off = pc & ~TARGET_PAGE_MASK;
    c->mmu_idx = cpu_mmu_index(cs, false);
    c->tlb = TCTI_TLB_FAST_OFS(c->mmu_idx);
    c->stop_off = -1;

    if (!translate(c, cs, *max_insns, host_pc, &r)) {
        c->stop_off = c->fail_off;
        translate(c, cs, *max_insns, host_pc, &r);
    }
    if (c->g.n_insns == 0) {
        return 0;
    }
    return rcg_stream_finish(&c->g, c->off);
}
