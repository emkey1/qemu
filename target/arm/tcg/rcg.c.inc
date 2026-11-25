/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RCG for A64: under TCTI, an instruction that rcg-gen.py has a gadget for
 * becomes one rich op in place of its TCG ops.
 *
 * aarch64_tr_translate_insn() offers each instruction to rcg_translate()
 * before disas_a64(), after its own checks: single-stepping, PC alignment,
 * the illegal execution state, BTI and SME's streaming mode. It decodes
 * with rcg_a64(), a decoder that rcg-gen.py writes from a64.decode's own
 * lines for the patterns it has gadgets for, so an instruction reaches
 * trans_rcg_<name>() exactly when it would reach trans_<name>(), with the
 * same arguments. A trans_rcg_<name>() that does not take an instruction
 * returns false before it has emitted anything, and disas_a64() then
 * translates it as it always has, in the same TB.
 */

#if defined(TCG_HAVE_RCG) && !defined(CONFIG_USER_ONLY)

#include "trace/trace-accel_tcg.h"
#include "tcg/a64-rcg-table.c.inc"
#include "tcg/rcg-common.c.inc"
#include "tcg/decode-a64-rcg.c.inc"

/*
 * What RCG assumes of the translation state. Every field of DisasContext
 * is here with what it means to the instructions RCG takes, which so far
 * are the integer data processing instructions between registers: they
 * read and write X registers, SP and NZCV, ADR and ADRP also read the PC,
 * and that is all. A field that changes what such an instruction does, or
 * what must happen around it, has to be tested in rcg_translate() or by
 * the trans_rcg_<name>() it concerns.
 *
 * Tested by rcg_translate():
 *   base.plugin_enabled, ss_active.
 * Handled by aarch64_tr_translate_insn() around every instruction, whoever
 * translates it:
 *   base (but plugin_enabled), insn, pstate_ss, pstate_il, bt, btype,
 *   sme_trap_nonstreaming, is_nonstreaming, fp_access_checked,
 *   sve_access_checked, insn_start_updated.
 * Used by rcg_pcrel() as gen_pc_plus_diff() uses them:
 *   pc_curr, pc_save.
 * Program-counter relative code that no instruction taken needs:
 *   page_start.
 * Memory accesses, of which none is made:
 *   be_data, user, mmu_idx, tbii, tbid, tcma, mtx, lse2, is_ldex, unpriv,
 *   ata, mte_active, mte_store_only, align_mem, dcz_blocksize,
 *   gm_blocksize, nv2_mem_e20, nv2_mem_be, nv2_redirect_offset.
 * Floating point and vectors, which are TCG's:
 *   fp_excp_el, sve_excp_el, sme_excp_el, zt0_excp_el, vl, svl, max_svl,
 *   max_any_vl, pstate_sm, pstate_za, fpcr_ah, fpcr_nep, fpmr_el.
 * System registers, exceptions and branches, which are TCG's:
 *   isar, ns, svc_imm, current_el, cp_regs, features, pauth_active,
 *   hstr_active, fgt_active, fgt_svc, trap_eret, naa, e2h, nv, nv1, nv2,
 *   gcs_en, gcs_rvcen, gcsstr_el.
 * AArch32 and M-profile only:
 *   delay_excp_list, condjmp, condlabel, condexec_mask, condexec_cond,
 *   eci, eci_handled, sctlr_b, vfp_enabled, vec_len, vec_stride,
 *   v7m_handler_mode, v8m_secure, v8m_stackcheck, v8m_fpccr_s_wrong,
 *   v7m_new_fp_ctxt_needed, v7m_lspact, aarch64, thumb, mve_no_pred.
 *
 * A change to DisasContext's size is a field added or removed: account
 * for it above, then change the size here.
 */
QEMU_BUILD_BUG_ON(sizeof(DisasContext) != 344);

/*
 * What a gadget's words are made from: the xregs[] slots of the
 * destination and the sources, of which 31 is SP, an immediate, a mask
 * and two shift amounts. A gadget takes those its words name.
 */
typedef struct RCGArgs {
    int rd, rn, rm, ra;
    uint64_t imm, mask;
    unsigned sa, sa2;
} RCGArgs;

/* What a gadget touches besides the registers of its words. */
enum {
    RCG_WRITES_NZCV = 1,    /* NF, ZF, CF and VF, each whole */
    RCG_READS_CF = 2,
    RCG_READS_PC = 4,
    RCG_READS_RD = 8,       /* the "d" register, which it also writes */
};

/*
 * Emits g with its words from a, if there is a gadget at g, and returns
 * whether there is. The gadget writes the register of its "d" word whole,
 * and reads those of its "n", "m" and "a" words. touches says what else,
 * RCG_*. The trace event says which instructions RCG took, by gadget.
 */
static bool rcg_emit(DisasContext *s, const RCGGadget *g, const RCGArgs *a,
                     unsigned touches)
{
    uint64_t words[RCG_MAX_WORDS];
    TCGTemp *outs[RCG_MAX_WORDS], *ins[RCG_MAX_WORDS];
    unsigned n, nb_outs = 0, nb_ins = 0;

    if (!g->gadget) {
        return false;
    }
    for (n = 0; n < RCG_MAX_WORDS && g->words[n] != RCG_W_END; n++) {
        switch (g->words[n]) {
        case RCG_W_D:
            words[n] = offsetof(CPUARMState, xregs[a->rd]);
            rcg_note_temp(outs, &nb_outs, tcgv_i64_temp(cpu_X[a->rd]));
            if (touches & RCG_READS_RD) {
                rcg_note_temp(ins, &nb_ins, tcgv_i64_temp(cpu_X[a->rd]));
            }
            break;
        case RCG_W_N:
            words[n] = offsetof(CPUARMState, xregs[a->rn]);
            rcg_note_temp(ins, &nb_ins, tcgv_i64_temp(cpu_X[a->rn]));
            break;
        case RCG_W_M:
            words[n] = offsetof(CPUARMState, xregs[a->rm]);
            rcg_note_temp(ins, &nb_ins, tcgv_i64_temp(cpu_X[a->rm]));
            break;
        case RCG_W_A:
            words[n] = offsetof(CPUARMState, xregs[a->ra]);
            rcg_note_temp(ins, &nb_ins, tcgv_i64_temp(cpu_X[a->ra]));
            break;
        case RCG_W_IMM:
            words[n] = a->imm;
            break;
        case RCG_W_MASK:
            words[n] = a->mask;
            break;
        case RCG_W_SA:
            words[n] = a->sa;
            break;
        case RCG_W_SA2:
            words[n] = a->sa2;
            break;
        default:
            g_assert_not_reached();
        }
    }
    if (touches & RCG_WRITES_NZCV) {
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_NF));
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_ZF));
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_CF));
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_VF));
    }
    if (touches & RCG_READS_CF) {
        rcg_note_temp(ins, &nb_ins, tcgv_i32_temp(cpu_CF));
    }
    if (touches & RCG_READS_PC) {
        rcg_note_temp(ins, &nb_ins, tcgv_i64_temp(cpu_pc));
    }
    tcg_gen_rich(g->gadget, words, n, 0, outs, nb_outs, ins, nb_ins);
    trace_rcg_insn(s->pc_curr, g->gadget);
    return true;
}

/*
 * What an S form does with its result: with XZR as the destination it
 * writes only NZCV, and is CMN, CMP or TST.
 */
static unsigned rcg_flags(bool setflags, int rd)
{
    return !setflags ? RCG_FLAGS_NONE :
           rd == 31 ? RCG_FLAGS_ONLY : RCG_FLAGS_SET;
}

/* The shift of a shifted-register form: a shift by 0 is none. */
static unsigned rcg_shift(int st, int sa)
{
    static const uint8_t shifts[] = {
        RCG_SHIFT_LSL, RCG_SHIFT_LSR, RCG_SHIFT_ASR, RCG_SHIFT_ROR,
    };

    return sa ? shifts[st] : RCG_SHIFT_NONE;
}

/*
 * Add and subtract of an immediate, as gen_rri() does them. Register 31
 * is SP, except as the destination of an S form.
 */
static bool rcg_addsub_imm(DisasContext *s, arg_rri_sf *a, bool sub,
                           bool setflags)
{
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .imm = a->imm };
    unsigned flags = rcg_flags(setflags, a->rd);

    return rcg_emit(s, &rcg_addsub_i[sub][a->sf][flags], &args,
                    setflags ? RCG_WRITES_NZCV : 0);
}

/*
 * Add and subtract of a shifted register, as do_addsub_reg() does them.
 * Register 31 is XZR. As a source it has no word: the gadget for it
 * reads zero, and since a shifted zero is still zero, the one for the
 * second source has no shift.
 */
static bool rcg_addsub_shift(DisasContext *s, arg_addsub_shift *a,
                             bool sub, bool setflags)
{
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .rm = a->rm, .sa = a->sa };
    unsigned flags = rcg_flags(setflags, a->rd);
    unsigned shift = RCG_SHIFT_NONE, zero = RCG_ZERO_NONE;

    /* Unallocated, as do_addsub_reg() has it. */
    if (a->st == 3 || (!a->sf && (a->sa & 32))) {
        return false;
    }
    /*
     * XZR as the destination without S writes nothing at all, and with
     * both sources XZR there is nothing to read: neither is worth a
     * gadget.
     */
    if ((a->rd == 31 && !setflags) || (a->rn == 31 && a->rm == 31)) {
        return false;
    }
    if (a->rm == 31) {
        zero = RCG_ZERO_M;
    } else {
        if (a->rn == 31) {
            zero = RCG_ZERO_N;
        }
        shift = rcg_shift(a->st, a->sa);
    }
    return rcg_emit(s, &rcg_addsub_r[sub][a->sf][flags][shift][zero], &args,
                    setflags ? RCG_WRITES_NZCV : 0);
}

/*
 * Add and subtract of an extended register, as do_addsub_ext() does
 * them. Register 31 is SP as the first source, and as the destination
 * without S. An extension from 64 bits is none, and at 32 bits one from
 * 32 is none either. XZR as the second source is left to TCG.
 */
static bool rcg_addsub_ext(DisasContext *s, arg_addsub_ext *a,
                           bool sub, bool setflags)
{
    static const uint8_t extends[2][3] = {
        { RCG_EXTEND_UB, RCG_EXTEND_UH, RCG_EXTEND_UW },
        { RCG_EXTEND_SB, RCG_EXTEND_SH, RCG_EXTEND_SW },
    };
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .rm = a->rm, .sa = a->sa };
    unsigned flags = rcg_flags(setflags, a->rd);
    unsigned size = a->st & 3, extend = RCG_EXTEND_NONE;

    /* Unallocated, as do_addsub_ext() has it. */
    if (a->sa > 4) {
        return false;
    }
    if (a->rm == 31) {
        return false;
    }
    if (size < (a->sf ? 3 : 2)) {
        extend = extends[a->st >> 2][size];
    }
    return rcg_emit(s, &rcg_addsub_x[sub][a->sf][flags][extend], &args,
                    setflags ? RCG_WRITES_NZCV : 0);
}

/*
 * ADC, ADCS, SBC and SBCS, as do_adc_sbc() does them. XZR in any place
 * is left to TCG.
 */
static bool rcg_adc_sbc(DisasContext *s, arg_rrr_sf *a, bool sub,
                        bool setflags)
{
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .rm = a->rm };

    if (a->rd == 31 || a->rn == 31 || a->rm == 31) {
        return false;
    }
    return rcg_emit(s, &rcg_adc[sub][a->sf][setflags], &args,
                    RCG_READS_CF | (setflags ? RCG_WRITES_NZCV : 0));
}

/* A constant to register rd, of which 31 is SP. */
static bool rcg_movi(DisasContext *s, int rd, uint64_t imm)
{
    RCGArgs args = { .rd = rd, .imm = imm };

    return rcg_emit(s, &rcg_mov_i, &args, 0);
}

/*
 * The logical operations with an immediate, as gen_rri_log() does them.
 * Register 31 is SP as the destination, except ANDS's, and XZR as the
 * source: ORR and EOR of XZR are moves of the immediate, and AND and
 * ANDS of it are left to TCG.
 */
static bool rcg_logic_imm(DisasContext *s, arg_rri_log *a, unsigned op,
                          bool setflags)
{
    RCGArgs args = { .rd = a->rd, .rn = a->rn };
    unsigned flags = rcg_flags(setflags, a->rd);

    /* Some immediate field values are reserved. */
    if (!logic_imm_decode_wmask(&args.imm, extract32(a->dbm, 12, 1),
                                extract32(a->dbm, 0, 6),
                                extract32(a->dbm, 6, 6))) {
        return false;
    }
    if (!a->sf) {
        args.imm &= 0xffffffffull;
    }
    if (a->rn == 31) {
        return op != RCG_LOGIC_AND && rcg_movi(s, a->rd, args.imm);
    }
    return rcg_emit(s, &rcg_logic_i[op][a->sf][flags], &args,
                    setflags ? RCG_WRITES_NZCV : 0);
}

/*
 * The logical operations with a shifted register, as do_logic_reg() and
 * trans_ORR_r() do them. Register 31 is XZR. ORR and ORN of it and a
 * register that is not shifted are MOV and MVN, which have gadgets; any
 * other form that reads it, and one that writes it without S, is left to
 * TCG.
 */
static bool rcg_logic_shift(DisasContext *s, arg_logic_shift *a,
                            unsigned op, bool setflags)
{
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .rm = a->rm, .sa = a->sa };
    unsigned flags = rcg_flags(setflags, a->rd);
    unsigned shift = rcg_shift(a->st, a->sa);
    bool zn = a->rn == 31;

    /* Unallocated, as do_logic_reg() has it. */
    if (!a->sf && (a->sa & 32)) {
        return false;
    }
    if ((a->rd == 31 && !setflags) || a->rm == 31 ||
        (zn && (op != RCG_LOGIC_ORR || shift != RCG_SHIFT_NONE))) {
        return false;
    }
    return rcg_emit(s, &rcg_logic_r[op][a->n][a->sf][flags][shift][zn],
                    &args, setflags ? RCG_WRITES_NZCV : 0);
}

/* MOVZ and MOVN, as trans_MOVZ() and trans_MOVN() work the constant out. */
static bool rcg_mov_wide(DisasContext *s, arg_movw *a, bool invert)
{
    uint64_t imm = (uint64_t)a->imm << (a->hw << 4);

    if (invert) {
        imm = ~imm;
        if (!a->sf) {
            imm = (uint32_t)imm;
        }
    }
    return a->rd != 31 && rcg_movi(s, a->rd, imm);
}

/*
 * MOVK, as trans_MOVK() does it: 16 bits of the register replaced, and
 * at 32 bits its upper half cleared.
 */
static bool trans_rcg_MOVK(DisasContext *s, arg_movw *a)
{
    int pos = a->hw << 4;
    RCGArgs args = {
        .rd = a->rd,
        .imm = (uint64_t)a->imm << pos,
        .mask = (0xffffull << pos) | (a->sf ? 0 : 0xffffffff00000000ull),
    };

    return a->rd != 31 && rcg_emit(s, &rcg_movk, &args, RCG_READS_RD);
}

/*
 * The PC plus diff to register rd, as gen_pc_plus_diff() gives it: under
 * CF_PCREL from env's pc, which is pc_save, and else as a constant.
 */
static bool rcg_pcrel(DisasContext *s, int rd, int64_t diff)
{
    RCGArgs args = { .rd = rd };

    if (rd == 31 || s->pc_save == -1) {
        return false;
    }
    if (!(tb_cflags(s->base.tb) & CF_PCREL)) {
        return rcg_movi(s, rd, s->pc_curr + diff);
    }
    args.imm = (s->pc_curr - s->pc_save) + diff;
    return rcg_emit(s, &rcg_adr, &args, RCG_READS_PC);
}

static bool trans_rcg_ADR(DisasContext *s, arg_ri *a)
{
    return rcg_pcrel(s, a->rd, a->imm);
}

/* As trans_ADRP() works the offset out. */
static bool trans_rcg_ADRP(DisasContext *s, arg_ri *a)
{
    return rcg_pcrel(s, a->rd,
                     ((int64_t)a->imm << 12) - (s->pc_curr & 0xfff));
}

/*
 * SBFM and UBFM, whatever alias they are, as two shifts: left by the
 * width less one less imms, then right by that plus immr, modulo the
 * width. That is trans_SBFM()'s and trans_UBFM()'s extract where
 * imms >= immr, and their insert into zeros or sign bits where not. A
 * shift by 0 is left out. XZR in either place is left to TCG.
 */
static bool rcg_bitfield_move(DisasContext *s, arg_bitfield *a, bool is_signed)
{
    unsigned bits = a->sf ? 64 : 32;
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .sa = bits - 1 - a->imms };
    unsigned shifts;

    if (a->rd == 31 || a->rn == 31) {
        return false;
    }
    args.sa2 = (args.sa + a->immr) & (bits - 1);
    shifts = args.sa2 == 0 ? RCG_BITFIELD_FIRST :
             args.sa == 0 ? RCG_BITFIELD_SECOND : RCG_BITFIELD_BOTH;
    return rcg_emit(s, &rcg_bitfield[is_signed][a->sf][shifts], &args, 0);
}

/*
 * BFM, as trans_BFM() does it: the bits of the destination that it
 * replaces are len bits from pos, and the source rotated right by immr
 * has the field there in both of its cases.
 */
static bool trans_rcg_BFM(DisasContext *s, arg_bitfield *a)
{
    unsigned bits = a->sf ? 64 : 32;
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .sa = a->immr };
    unsigned pos, len;

    if (a->rd == 31 || a->rn == 31) {
        return false;
    }
    if (a->imms >= a->immr) {
        len = a->imms - a->immr + 1;
        pos = 0;
    } else {
        len = a->imms + 1;
        pos = (bits - a->immr) & (bits - 1);
    }
    args.mask = MAKE_64BIT_MASK(pos, len);
    return rcg_emit(s, &rcg_bfm[a->sf], &args, RCG_READS_RD);
}

/*
 * EXTR, as trans_EXTR() does it. From bit 0 it is a move, which is left
 * to TCG, as is XZR in any place. With both sources the same register it
 * is ROR.
 */
static bool trans_rcg_EXTR(DisasContext *s, arg_extract *a)
{
    RCGArgs args = {
        .rd = a->rd, .rn = a->rn, .rm = a->rm,
        .sa = a->imm, .sa2 = (a->sf ? 64 : 32) - a->imm,
    };

    if (a->imm == 0 || a->rd == 31 || a->rn == 31 || a->rm == 31) {
        return false;
    }
    return rcg_emit(s, &rcg_extr[a->sf][a->rn == a->rm], &args, 0);
}

/*
 * An instruction with a destination and two sources, whose gadget is g.
 * XZR in any place is left to TCG.
 */
static bool rcg_rrr(DisasContext *s, int rd, int rn, int rm,
                    const RCGGadget *g)
{
    RCGArgs args = { .rd = rd, .rn = rn, .rm = rm };

    if (rd == 31 || rn == 31 || rm == 31) {
        return false;
    }
    return rcg_emit(s, g, &args, 0);
}

/*
 * The multiply-adds, as do_muladd() does them. XZR as the register added
 * to or subtracted from makes MUL, MNEG and their like, which have
 * gadgets. XZR in any other place is left to TCG.
 */
static bool rcg_mul_add(DisasContext *s, arg_rrrr *a, unsigned mul, bool sub)
{
    RCGArgs args = { .rd = a->rd, .rn = a->rn, .rm = a->rm, .ra = a->ra };

    if (a->rd == 31 || a->rn == 31 || a->rm == 31) {
        return false;
    }
    return rcg_emit(s, &rcg_muladd[mul][sub][a->ra == 31], &args, 0);
}

/*
 * An operation on one register, whose gadget is g, as gen_rr() does
 * them. XZR in either place is left to TCG.
 */
static bool rcg_one_source(DisasContext *s, int rd, int rn, const RCGGadget *g)
{
    RCGArgs args = { .rd = rd, .rn = rn };

    if (rd == 31 || rn == 31) {
        return false;
    }
    return rcg_emit(s, g, &args, 0);
}

TRANS(rcg_ADD_i, rcg_addsub_imm, a, false, false)
TRANS(rcg_SUB_i, rcg_addsub_imm, a, true, false)
TRANS(rcg_ADDS_i, rcg_addsub_imm, a, false, true)
TRANS(rcg_SUBS_i, rcg_addsub_imm, a, true, true)
TRANS(rcg_ADD_r, rcg_addsub_shift, a, false, false)
TRANS(rcg_SUB_r, rcg_addsub_shift, a, true, false)
TRANS(rcg_ADDS_r, rcg_addsub_shift, a, false, true)
TRANS(rcg_SUBS_r, rcg_addsub_shift, a, true, true)
TRANS(rcg_ADD_ext, rcg_addsub_ext, a, false, false)
TRANS(rcg_SUB_ext, rcg_addsub_ext, a, true, false)
TRANS(rcg_ADDS_ext, rcg_addsub_ext, a, false, true)
TRANS(rcg_SUBS_ext, rcg_addsub_ext, a, true, true)
TRANS(rcg_ADC, rcg_adc_sbc, a, false, false)
TRANS(rcg_SBC, rcg_adc_sbc, a, true, false)
TRANS(rcg_ADCS, rcg_adc_sbc, a, false, true)
TRANS(rcg_SBCS, rcg_adc_sbc, a, true, true)
TRANS(rcg_AND_i, rcg_logic_imm, a, RCG_LOGIC_AND, false)
TRANS(rcg_ORR_i, rcg_logic_imm, a, RCG_LOGIC_ORR, false)
TRANS(rcg_EOR_i, rcg_logic_imm, a, RCG_LOGIC_EOR, false)
TRANS(rcg_ANDS_i, rcg_logic_imm, a, RCG_LOGIC_AND, true)
TRANS(rcg_AND_r, rcg_logic_shift, a, RCG_LOGIC_AND, false)
TRANS(rcg_ORR_r, rcg_logic_shift, a, RCG_LOGIC_ORR, false)
TRANS(rcg_EOR_r, rcg_logic_shift, a, RCG_LOGIC_EOR, false)
TRANS(rcg_ANDS_r, rcg_logic_shift, a, RCG_LOGIC_AND, true)
TRANS(rcg_MOVZ, rcg_mov_wide, a, false)
TRANS(rcg_MOVN, rcg_mov_wide, a, true)
TRANS(rcg_SBFM, rcg_bitfield_move, a, true)
TRANS(rcg_UBFM, rcg_bitfield_move, a, false)
TRANS(rcg_LSLV, rcg_rrr, a->rd, a->rn, a->rm,
      &rcg_shiftv[RCG_SHIFT_LSL][a->sf])
TRANS(rcg_LSRV, rcg_rrr, a->rd, a->rn, a->rm,
      &rcg_shiftv[RCG_SHIFT_LSR][a->sf])
TRANS(rcg_ASRV, rcg_rrr, a->rd, a->rn, a->rm,
      &rcg_shiftv[RCG_SHIFT_ASR][a->sf])
TRANS(rcg_RORV, rcg_rrr, a->rd, a->rn, a->rm,
      &rcg_shiftv[RCG_SHIFT_ROR][a->sf])
TRANS(rcg_UDIV, rcg_rrr, a->rd, a->rn, a->rm, &rcg_div[0][a->sf])
TRANS(rcg_SDIV, rcg_rrr, a->rd, a->rn, a->rm, &rcg_div[1][a->sf])
TRANS(rcg_UMULH, rcg_rrr, a->rd, a->rn, a->rm, &rcg_mulh[0])
TRANS(rcg_SMULH, rcg_rrr, a->rd, a->rn, a->rm, &rcg_mulh[1])
TRANS(rcg_MADD_w, rcg_mul_add, a, RCG_MUL_W, false)
TRANS(rcg_MSUB_w, rcg_mul_add, a, RCG_MUL_W, true)
TRANS(rcg_MADD_x, rcg_mul_add, a, RCG_MUL_X, false)
TRANS(rcg_MSUB_x, rcg_mul_add, a, RCG_MUL_X, true)
TRANS(rcg_SMADDL, rcg_mul_add, a, RCG_MUL_SL, false)
TRANS(rcg_SMSUBL, rcg_mul_add, a, RCG_MUL_SL, true)
TRANS(rcg_UMADDL, rcg_mul_add, a, RCG_MUL_UL, false)
TRANS(rcg_UMSUBL, rcg_mul_add, a, RCG_MUL_UL, true)
TRANS(rcg_RBIT, rcg_one_source, a->rd, a->rn,
      &rcg_unary[RCG_UNARY_RBIT][a->sf])
TRANS(rcg_REV16, rcg_one_source, a->rd, a->rn,
      &rcg_unary[RCG_UNARY_REV16][a->sf])
TRANS(rcg_REV32, rcg_one_source, a->rd, a->rn,
      &rcg_unary[RCG_UNARY_REV32][a->sf])
TRANS(rcg_REV64, rcg_one_source, a->rd, a->rn,
      &rcg_unary[RCG_UNARY_REV64][1])
TRANS(rcg_CLZ, rcg_one_source, a->rd, a->rn,
      &rcg_unary[RCG_UNARY_CLZ][a->sf])
TRANS(rcg_CLS, rcg_one_source, a->rd, a->rn,
      &rcg_unary[RCG_UNARY_CLS][a->sf])

/*
 * Emits one gadget for insn if RCG has one, and returns whether it did.
 * Plugins instrument an instruction through its TCG ops, which a gadget
 * replaces, and single-stepping is left to the code that has always done
 * it: RCG takes nothing under either.
 */
static bool rcg_translate(DisasContext *s, uint32_t insn)
{
    if (!tcg_rcg_active() || s->base.plugin_enabled || s->ss_active) {
        return false;
    }
    return rcg_a64(s, insn);
}

#else

static bool rcg_translate(DisasContext *s, uint32_t insn)
{
    return false;
}

#endif
