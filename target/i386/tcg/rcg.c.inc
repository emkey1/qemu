/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RCG for x86: under TCTI, an instruction that rcg-gen.py has a gadget for
 * becomes one rich op in place of its TCG ops.
 *
 * disas_insn() offers each instruction here after decoding and every check,
 * exception and intercept, where TCG would start emitting its ops. What is
 * not taken goes to TCG, in the same TB.
 */

#if defined(TARGET_X86_64) && defined(TCG_HAVE_RCG)

#include "tcti-gadget-defs.h"
#include "tcg/rcg-table.c.inc"

/* The gadgets' fast paths are built for TCTI's page size. */
QEMU_BUILD_BUG_ON(TARGET_PAGE_BITS != TCTI_TLB_PAGE_BITS);

/*
 * An operand's kind, as a form names it: register, memory or immediate, or
 * 0 if no form takes it.
 */
static char rcg_kind(DisasContext *s, X86DecodedOp *op)
{
    /* Check has_ea first: decode-new gives LEA's memory operand no unit. */
    if (op->has_ea) {
        return 'm';
    }
    switch (op->unit) {
    case X86_OP_INT:
        /* AH, CH, DH and BH are left to TCG. */
        if (op->ot == MO_8 && byte_reg_is_xH(s, op->n)) {
            return 0;
        }
        return 'r';
    case X86_OP_IMM:
        return 'i';
    default:
        return 0;
    }
}

static int rcg_form(char a, char b)
{
    static const char *const names[RCG_NB_FORMS] = {
        [RCG_FORM_RR] = "rr", [RCG_FORM_RM] = "rm", [RCG_FORM_MR] = "mr",
        [RCG_FORM_RI] = "ri", [RCG_FORM_MI] = "mi", [RCG_FORM_R] = "r",
        [RCG_FORM_I] = "i", [RCG_FORM_M] = "m",
    };

    for (int i = 0; i < RCG_NB_FORMS; i++) {
        if (names[i][0] == a && names[i][1] == b) {
            return i;
        }
    }
    return -1;
}

/*
 * Returns the memory operand's shape, as gen_lea_modrm_1() forms the
 * address in 64-bit code. *seg is the segment whose base gen_lea_v_seg()
 * adds, which in 64-bit code is FS or GS only, else -1. Under CF_PCREL, a
 * RIP-relative address is env's eip plus a displacement, so it takes the
 * base-only shape.
 */
static RCGShape rcg_shape(DisasContext *s, X86DecodedInsn *decode, int *seg)
{
    AddressParts *a = &decode->mem;
    int ovr = s->override >= 0 ? s->override : a->def_seg;

    *seg = ovr >= R_FS ? ovr : -1;
    if (a->base == -2) {
        return tb_cflags(s->base.tb) & CF_PCREL ? RCG_EA_B : RCG_EA_D;
    }
    if (a->index >= 0) {
        return (a->base >= 0 ? RCG_EA_BI0 : RCG_EA_I0) + a->scale;
    }
    return a->base >= 0 ? RCG_EA_B : RCG_EA_D;
}

static uint64_t rcg_reg(int n)
{
    return offsetof(CPUX86State, regs[n]);
}

/*
 * Adds g to list unless list or other already holds it. If other, the
 * globals the gadget writes, holds it, the gadget reads that one too, and
 * it loses its TCG_RICH_WHOLE() in *whole.
 */
static void rcg_note(TCGv *list, unsigned *n, TCGv g, TCGv *other,
                     unsigned nb_other, unsigned *whole)
{
    for (unsigned i = 0; i < *n; i++) {
        if (list[i] == g) {
            return;
        }
    }
    for (unsigned i = 0; i < nb_other; i++) {
        if (other[i] == g) {
            *whole &= ~TCG_RICH_WHOLE(i);
            return;
        }
    }
    list[(*n)++] = g;
}

/* The RCG_CC_* index of lazy-flags state cc_op, or -1 if no gadget reads it. */
static int rcg_cc_index(CCOp cc_op)
{
    if (cc_op >= CC_OP_SUBB && cc_op <= CC_OP_SUBQ) {
        return RCG_CC_SUB8 + (cc_op - CC_OP_SUBB);
    } else if (cc_op >= CC_OP_ADDB && cc_op <= CC_OP_ADDQ) {
        return RCG_CC_ADD8 + (cc_op - CC_OP_ADDB);
    } else if (cc_op >= CC_OP_LOGICB && cc_op <= CC_OP_LOGICQ) {
        return RCG_CC_LOGIC8 + (cc_op - CC_OP_LOGICB);
    } else if (cc_op >= CC_OP_INCB && cc_op <= CC_OP_INCQ) {
        return RCG_CC_INC8 + (cc_op - CC_OP_INCB);
    } else if (cc_op >= CC_OP_DECB && cc_op <= CC_OP_DECQ) {
        return RCG_CC_DEC8 + (cc_op - CC_OP_DECB);
    } else if (cc_op == CC_OP_EFLAGS) {
        return RCG_CC_EFLAGS;
    }
    return -1;
}

/*
 * Jcc, SETcc and CMOVcc, when an earlier instruction in this TB left a
 * lazy-flags state the gadgets read.
 */
static bool rcg_translate_cond(DisasContext *s, X86DecodedInsn *decode)
{
    X86GenFunc gen = decode->e.gen;
    int cc = rcg_cc_index(s->cc_op), cond = decode->b & 0xf;
    TCGv flags_in[2] = { cpu_cc_dst, cpu_cc_src };

    if (cc < 0) {
        return false;
    }
    if (gen == gen_Jcc) {
        const void *gadget = rcg_jcc[cc][cond];
        TCGTemp *out = tcgv_i32_temp(cpu_cc_op);
        TCGTemp *ins[2] = { tcgv_tl_temp(cpu_cc_dst),
                            tcgv_tl_temp(cpu_cc_src) };
        uint64_t word = s->cc_op;
        TCGLabel *taken;

        if (!gadget) {
            return false;
        }
        /*
         * As gen_Jcc, but the gadget always stores CC_OP, even where it is
         * already clean (after COMISS, FCOMI or PUSHF, for example).
         */
        taken = gen_new_label();
        gen_bnd_jmp(s);
        tcg_gen_rich_br(gadget, &word, 1, taken, &out, 1, ins, 2);
        s->cc_op_dirty = false;
        gen_conditional_jump_labels(s, decode->immediate, NULL, taken);
        return true;
    }
    if (gen == gen_SETcc) {
        X86DecodedOp *d = &decode->op[0];
        const void *gadget = rcg_setcc[cc][cond];
        uint64_t word;
        TCGv out;

        if (!gadget || rcg_kind(s, d) != 'r') {
            return false;
        }
        word = rcg_reg(d->n);
        out = cpu_regs[d->n];
        tcg_gen_rich(gadget, &word, 1, 0, &out, 1, flags_in, 2);
        return true;
    }
    if (gen == gen_CMOVcc) {
        X86DecodedOp *d = &decode->op[0], *src = &decode->op[2];
        const void *gadget;
        uint64_t words[2];
        TCGv out, ins[3] = { cpu_cc_dst, cpu_cc_src };
        unsigned nb_ins = 2;

        if (d->ot < MO_16 || d->ot > MO_64 || rcg_kind(s, d) != 'r' ||
            rcg_kind(s, src) != 'r') {
            return false;
        }
        gadget = rcg_cmov[d->ot][cc][cond];
        if (!gadget) {
            return false;
        }
        words[0] = rcg_reg(d->n);
        words[1] = rcg_reg(src->n);
        out = cpu_regs[d->n];
        if (src->n != d->n) {
            ins[nb_ins++] = cpu_regs[src->n];
        }
        tcg_gen_rich(gadget, words, 2, 0, &out, 1, ins, nb_ins);
        return true;
    }
    return false;
}

/*
 * After the gadget has rotated register n (width ot) right by count, sets
 * CF and OF as gen_ROL and gen_ROR do and keeps the other flags. Those
 * leave CC_OP_ADCOX; this leaves CC_OP_EFLAGS, with every flag in cc_src.
 * TCG drops these ops if the flags are set again before anything reads
 * them.
 */
static void rcg_rotate_flags(DisasContext *s, MemOp ot, int n, bool left,
                             int count)
{
    TCGv res = tcg_temp_new(), old = tcg_temp_new();
    TCGv flags = tcg_temp_new(), bit = tcg_temp_new();
    int top = (8 << ot) - 1;

    gen_mov_eflags(s, flags);
    if (ot == MO_32) {
        TCGv_i32 t = tcg_temp_new_i32();

        tcg_gen_trunc_tl_i32(t, cpu_regs[n]);
        tcg_gen_extu_i32_tl(res, t);
        tcg_gen_rotli_i32(t, t, count);
        tcg_gen_extu_i32_tl(old, t);
    } else {
        tcg_gen_mov_tl(res, cpu_regs[n]);
        tcg_gen_rotli_tl(old, res, count);
    }
    /* CF: the bit that went round. OF: whether the top bit changed. */
    tcg_gen_extract_tl(bit, res, left ? 0 : top, 1);
    tcg_gen_deposit_tl(flags, flags, bit, ctz32(CC_C), 1);
    tcg_gen_xor_tl(bit, old, res);
    tcg_gen_extract_tl(bit, bit, top, 1);
    tcg_gen_deposit_tl(flags, flags, bit, ctz32(CC_O), 1);
    tcg_gen_mov_tl(cpu_cc_src, flags);
    set_cc_op(s, CC_OP_EFLAGS);
}

/*
 * Emits the gadget for decode's instruction, if there is one, and returns
 * whether it did. first and second are its operands in the order the forms
 * name them.
 */
static bool rcg_translate(DisasContext *s, X86DecodedInsn *decode)
{
    X86DecodedOp *first = NULL, *second = NULL;
    X86GenFunc gen = decode->e.gen;
    bool writes = decode->op[0].unit != X86_OP_SKIP;
    MemOp ot, memop = 0;
    RCGOp op;
    uint64_t imm = 0;
    int form, shape = 0, seg = -1;
    bool memory, ordered = false, rotate_left = false;
    const RCGSlot *slot;
    const RCGGadget *g;
    uint64_t words[RCG_MAX_WORDS];
    TCGv outs[4], ins[RCG_MAX_WORDS], cf = NULL;
    unsigned n, nb_outs = 0, nb_ins = 0, whole = 0;

    if (!tcg_rcg_active() || !CODE64(s) || s->aflag != MO_64 ||
        (s->prefix & PREFIX_LOCK) || s->base.plugin_enabled) {
        return false;
    }

    if (gen == gen_Jcc || gen == gen_SETcc || gen == gen_CMOVcc) {
        return rcg_translate_cond(s, decode);
    }
    if (gen == gen_ADD || gen == gen_SUB || gen == gen_AND ||
        gen == gen_OR || gen == gen_XOR) {
        if (decode->e.special != X86_SPECIAL_None &&
            decode->e.special != X86_SPECIAL_HasLock) {
            return false;
        }
        first = &decode->op[1];
        second = &decode->op[2];
        if (gen == gen_ADD) {
            op = RCG_OP_ADD;
        } else if (gen == gen_SUB) {
            op = writes ? RCG_OP_SUB : RCG_OP_CMP;
        } else if (gen == gen_AND) {
            op = writes ? RCG_OP_AND : RCG_OP_TEST;
        } else if (gen == gen_OR) {
            op = RCG_OP_OR;
        } else if (first->unit == X86_OP_INT && second->unit == X86_OP_INT &&
                   !first->has_ea && !second->has_ea &&
                   first->n == second->n) {
            /* A register XORed with itself, as gen_XOR special-cases. */
            op = RCG_OP_ZERO;
        } else {
            op = RCG_OP_XOR;
        }
    } else if (gen == gen_MOV && (decode->e.special == X86_SPECIAL_ZExtT0 ||
                                  decode->e.special == X86_SPECIAL_SExtT0)) {
        /* MOVZX, MOVSX and MOVSXD, by the source's size. */
        bool sext = decode->e.special == X86_SPECIAL_SExtT0;

        first = &decode->op[0];
        second = &decode->op[1];
        switch (second->ot) {
        case MO_8:
            op = sext ? RCG_OP_MOVSXB : RCG_OP_MOVZXB;
            break;
        case MO_16:
            op = sext ? RCG_OP_MOVSXW : RCG_OP_MOVZXW;
            break;
        case MO_32:
            if (!sext) {
                return false;
            }
            op = RCG_OP_MOVSXD;
            break;
        default:
            return false;
        }
    } else if (gen == gen_MOV || gen == gen_LEA) {
        if (decode->e.special != (gen == gen_LEA ? X86_SPECIAL_NoLoadEA
                                                 : X86_SPECIAL_None)) {
            return false;
        }
        op = gen == gen_MOV ? RCG_OP_MOV : RCG_OP_LEA;
        first = &decode->op[0];
        second = &decode->op[1];
    } else if (gen == gen_PUSH) {
        op = RCG_OP_PUSH;
        second = &decode->op[1];
    } else if (gen == gen_POP) {
        op = RCG_OP_POP;
        first = &decode->op[0];
    } else if (gen == gen_NOT || gen == gen_NEG || gen == gen_INC ||
               gen == gen_DEC) {
        if (decode->e.special != X86_SPECIAL_HasLock) {
            return false;
        }
        op = gen == gen_NOT ? RCG_OP_NOT : gen == gen_NEG ? RCG_OP_NEG
           : gen == gen_INC ? RCG_OP_INC : RCG_OP_DEC;
        first = &decode->op[0];
    } else if (gen == gen_SHL || gen == gen_SHR || gen == gen_SAR) {
        /* By an immediate count, or 1; a count in CL is left to TCG. */
        int mask = decode->op[0].ot <= MO_32 ? 0x1f : 0x3f;

        first = &decode->op[0];
        second = &decode->op[2];
        if (second->unit == X86_OP_IMM) {
            imm = second->imm & mask;
        } else if (second->unit == X86_OP_SKIP) {
            imm = 1;
        } else {
            return false;
        }
        if (!imm) {
            /*
             * Leave a count of 0 to TCG: no flags change, but the operand
             * is still written back.
             */
            return false;
        }
        op = gen == gen_SHL ? RCG_OP_SHL : gen == gen_SHR ? RCG_OP_SHR
                                                         : RCG_OP_SAR;
    } else if (gen == gen_ROL || gen == gen_ROR) {
        /*
         * ROL and ROR of a 32- or 64-bit register, by an immediate or by 1.
         * ROL by n is ROR by the width less n. At these widths, x86's count
         * mask keeps the count below the width.
         */
        int bits = 8 << decode->op[0].ot;

        first = &decode->op[0];
        second = &decode->op[2];
        if (second->unit == X86_OP_IMM) {
            imm = second->imm & (bits - 1);
        } else if (second->unit == X86_OP_SKIP) {
            imm = 1;
        } else {
            return false;
        }
        if (bits < 32 || !imm || rcg_kind(s, first) != 'r') {
            return false;
        }
        rotate_left = gen == gen_ROL;
        if (rotate_left) {
            imm = bits - imm;
        }
        op = RCG_OP_ROR;
    } else if (gen == gen_CALL || gen == gen_CALL_m || gen == gen_JMP_m ||
               gen == gen_RET) {
        /*
         * Only under CF_PCREL, which system mode always has. CALL pushes
         * env's eip plus the offset from pc_save, which is the return
         * address only when cpu_eip tracks pc_save.
         */
        if (!(tb_cflags(s->base.tb) & CF_PCREL)) {
            return false;
        }
        op = gen == gen_JMP_m ? RCG_OP_JMP : gen == gen_RET ? RCG_OP_RET
                                                            : RCG_OP_CALL;
        if (op == RCG_OP_RET) {
            /* An unsigned count, as gen_RET takes it. */
            uint16_t adjust = decode->e.op1 == X86_TYPE_I ? decode->immediate
                                                          : 0;
            imm = adjust + 8;
        } else {
            second = gen == gen_CALL ? NULL : &decode->op[1];
            imm = s->pc - s->pc_save;
        }
    } else {
        return false;
    }

    /* The form, and the width it works at. */
    if (op == RCG_OP_CALL || op == RCG_OP_JMP || op == RCG_OP_RET) {
        /* Only a 64-bit return address and target. */
        ot = op == RCG_OP_JMP ? second->ot : mo_pushpop(s, s->dflag);
        if (ot != MO_64) {
            return false;
        }
        form = second ? rcg_form(rcg_kind(s, second), 0) : RCG_FORM_I;
    } else if (op == RCG_OP_NOT || op == RCG_OP_NEG || op == RCG_OP_INC ||
               op == RCG_OP_DEC) {
        ot = first->ot;
        form = rcg_form(rcg_kind(s, first), 0);
    } else if (op == RCG_OP_SHL || op == RCG_OP_SHR || op == RCG_OP_SAR ||
               op == RCG_OP_ROR) {
        char a = rcg_kind(s, first);

        ot = first->ot;
        form = a ? rcg_form(a, 'i') : -1;
    } else if (op == RCG_OP_PUSH || op == RCG_OP_POP) {
        X86DecodedOp *o = first ? first : second;

        ot = mo_pushpop(s, s->dflag);
        if (ot != MO_64 || (op == RCG_OP_POP && o->has_ea)) {
            return false;
        }
        form = rcg_form(rcg_kind(s, o), 0);
        if (form == RCG_FORM_I) {
            imm = o->imm;
        }
    } else {
        char a = rcg_kind(s, first), b = rcg_kind(s, second);

        ot = first->ot;
        if (!a || !b || ot > MO_64 ||
            (b != 'i' && op != RCG_OP_LEA && op < RCG_OP_MOVZXB &&
             second->ot != ot)) {
            return false;
        }
        form = op == RCG_OP_ZERO ? RCG_FORM_RR : rcg_form(a, b);
        if (b == 'i') {
            imm = second->imm;
        }
    }
    if (form < 0) {
        return false;
    }
    slot = &rcg_slots[op][form];
    if (!slot->gadgets) {
        return false;
    }

    /* Memory, and the order its accesses keep. */
    if (slot->nb_shapes > 1) {
        shape = rcg_shape(s, decode, &seg);
        if (op == RCG_OP_LEA) {
            /* gen_LEA adds no segment base. */
            seg = -1;
        }
    }
    memory = (slot->nb_shapes > 1 && op != RCG_OP_LEA) ||
             op == RCG_OP_PUSH || op == RCG_OP_POP || op == RCG_OP_CALL ||
             op == RCG_OP_RET;
    g = &slot->gadgets[((ot * slot->nb_shapes + shape) * 2 + (seg >= 0)) * 2];
    /*
     * Check before emitting a barrier, so an instruction left to TCG gets
     * none. A gadget that accesses memory always has an ordered twin, so
     * checking this one is enough.
     */
    if (!g->gadget) {
        return false;
    }
    if (memory) {
        /*
         * The barriers gen_op_ld_v() and gen_op_st_v() would emit before
         * the access. CALL m's gadget, which loads and then stores
         * elsewhere, orders the two.
         */
        TCGBar bar = 0;
        bool load = op == RCG_OP_POP || op == RCG_OP_RET ||
                    form == RCG_FORM_MR || form == RCG_FORM_MI ||
                    form == RCG_FORM_RM || form == RCG_FORM_M;
        bool store = op == RCG_OP_PUSH || op == RCG_OP_CALL ||
                     (writes && (form == RCG_FORM_MR || form == RCG_FORM_MI));

        if (op == RCG_OP_MOV) {
            load = form == RCG_FORM_RM;
            store = !load;
        } else if (op >= RCG_OP_MOVZXB && op <= RCG_OP_MOVSXD) {
            load = true;
            store = false;
        } else if (op >= RCG_OP_NOT && op <= RCG_OP_SAR) {
            /* NOT, NEG, INC, DEC and the shifts: a read-modify-write. */
            load = store = true;
        }
        bar |= load ? TCG_MO_LD_LD | TCG_MO_ST_LD : 0;
        bar |= store ? TCG_MO_LD_ST | TCG_MO_ST_ST : 0;
        ordered = tcg_gen_rich_mo(bar);
        memop = ot | MO_LE;
        if (op >= RCG_OP_MOVZXB && op <= RCG_OP_MOVSXD) {
            /* The access is the source's size. */
            memop = second->ot | MO_LE;
        }
    }
    g += ordered;
    tcg_debug_assert(g->gadget);

    /*
     * The globals it writes. tcg_gen_rich() also reads each one, but those
     * in whole: eip after JMP and RET, the flags state, and a register that
     * MOV, LEA, POP, MOVZX, MOVSX or the zeroing XOR write at 32 or 64 bits
     * (the others read theirs, or write only part of it). Noting what the
     * gadget reads takes away any of these it reads as well.
     */
    if (op == RCG_OP_PUSH || op == RCG_OP_POP || op == RCG_OP_CALL ||
        op == RCG_OP_RET) {
        outs[nb_outs++] = cpu_regs[R_ESP];
    }
    if (op == RCG_OP_CALL && form == RCG_FORM_I) {
        /* Read for the return address; gen_JMP writes it after. */
        ins[nb_ins++] = cpu_eip;
    } else if (op == RCG_OP_CALL || op == RCG_OP_JMP || op == RCG_OP_RET) {
        /* CALL reads it for the return address. */
        whole |= op != RCG_OP_CALL ? TCG_RICH_WHOLE(nb_outs) : 0;
        outs[nb_outs++] = cpu_eip;
    }
    for (n = 0; n < RCG_MAX_WORDS && g->words[n] != RCG_W_END; n++) {
        if (g->words[n] == RCG_W_D) {
            unsigned i = nb_outs;

            rcg_note(outs, &nb_outs, cpu_regs[first->n], NULL, 0, NULL);
            if (nb_outs > i && ot >= MO_32 &&
                (op == RCG_OP_MOV || op == RCG_OP_LEA ||
                 op == RCG_OP_POP || op == RCG_OP_ZERO ||
                 (op >= RCG_OP_MOVZXB && op <= RCG_OP_MOVSXD))) {
                whole |= TCG_RICH_WHOLE(i);
            }
        }
    }
    if (rcg_facts[op].dst) {
        whole |= TCG_RICH_WHOLE(nb_outs);
        outs[nb_outs++] = cpu_cc_dst;
    }
    if (rcg_facts[op].src) {
        whole |= TCG_RICH_WHOLE(nb_outs);
        outs[nb_outs++] = cpu_cc_src;
    }

    /* The words, in the order the gadget takes them, and what it reads. */
    for (n = 0; n < RCG_MAX_WORDS && g->words[n] != RCG_W_END; n++) {
        AddressParts *a = &decode->mem;

        switch (g->words[n]) {
        case RCG_W_D:
            words[n] = rcg_reg(first->n);
            break;
        case RCG_W_S1:
            words[n] = rcg_reg(first->n);
            rcg_note(ins, &nb_ins, cpu_regs[first->n], outs, nb_outs, &whole);
            break;
        case RCG_W_S:
            words[n] = rcg_reg(second->n);
            rcg_note(ins, &nb_ins, cpu_regs[second->n], outs, nb_outs, &whole);
            break;
        case RCG_W_BASE:
            if (a->base == -2) {
                words[n] = offsetof(CPUX86State, eip);
                rcg_note(ins, &nb_ins, cpu_eip, outs, nb_outs, &whole);
            } else {
                words[n] = rcg_reg(a->base);
                rcg_note(ins, &nb_ins, cpu_regs[a->base], outs, nb_outs,
                         &whole);
            }
            break;
        case RCG_W_INDEX:
            words[n] = rcg_reg(a->index);
            rcg_note(ins, &nb_ins, cpu_regs[a->index], outs, nb_outs, &whole);
            break;
        case RCG_W_DISP:
            /* With CF_PCREL, cpu_eip holds the eip at pc_save. */
            words[n] = a->disp - (a->base == -2 && shape == RCG_EA_B
                                  ? s->pc_save : 0);
            break;
        case RCG_W_SEG:
            words[n] = offsetof(CPUX86State, segs[seg].base);
            rcg_note(ins, &nb_ins, cpu_seg_base[seg], outs, nb_outs, &whole);
            break;
        case RCG_W_IMM:
            words[n] = imm;
            break;
        case RCG_W_OI:
            words[n] = make_memop_idx(memop, s->mem_index);
            break;
        case RCG_W_TLB:
            words[n] = TCTI_TLB_FAST_OFS(s->mem_index);
            break;
        default:
            g_assert_not_reached();
        }
    }
    /*
     * INC and DEC keep CF, which gen_INC and gen_DEC put in cc_src: take it
     * from the flags state the gadget replaces, and store it after the
     * gadget, so that a fault in the gadget finds that state as it was.
     */
    if (rcg_facts[op].cf) {
        cf = tcg_temp_new();
        gen_compute_eflags_c(s, cf);
    }
    tcg_gen_rich(g->gadget, words, n,
                 (memory ? TCG_RICH_MAY_FAULT : 0) | whole,
                 outs, nb_outs, ins, nb_ins);
    if (rcg_facts[op].cf) {
        tcg_gen_mov_tl(cpu_cc_src, cf);
    }

    if (op == RCG_OP_ROR) {
        rcg_rotate_flags(s, ot, first->n, rotate_left, imm);
    }

    /*
     * CALL rel ends with gen_JMP, as gen_CALL does. The others have set
     * eip, and end the TB as gen_CALL_m, gen_JMP_m and gen_RET do.
     */
    if (op == RCG_OP_CALL && form == RCG_FORM_I) {
        gen_JMP(s, decode);
    } else if (op == RCG_OP_CALL || op == RCG_OP_JMP || op == RCG_OP_RET) {
        s->pc_save = -1;
        gen_bnd_jmp(s);
        s->base.is_jmp = DISAS_JUMP;
    }

    /* Record the lazy-flags state the gadget left. */
    if (rcg_facts[op].cc_op >= 0) {
        set_cc_op(s, rcg_facts[op].cc_op + (rcg_facts[op].by_width ? ot : 0));
        if (rcg_facts[op].srcT == RCG_SRCT_SUM) {
            tcg_gen_add_tl(s->cc_srcT, cpu_cc_dst, cpu_cc_src);
        } else if (rcg_facts[op].srcT == RCG_SRCT_ZERO) {
            tcg_gen_movi_tl(s->cc_srcT, 0);
        }
    }
    return true;
}

#else

static bool rcg_translate(DisasContext *s, X86DecodedInsn *decode)
{
    return false;
}

#endif
