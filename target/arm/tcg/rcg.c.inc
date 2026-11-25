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
 * are integer adds and subtracts between registers: they read and write
 * X registers, SP and NZCV, and nothing else. A field that changes what
 * such an instruction does, or what must happen around it, has to be
 * tested in rcg_translate() or by the trans_rcg_<name>() it concerns.
 *
 * Tested by rcg_translate():
 *   base.plugin_enabled, ss_active.
 * Handled by aarch64_tr_translate_insn() around every instruction, whoever
 * translates it:
 *   base (but plugin_enabled), pc_curr, insn, pstate_ss, pstate_il, bt,
 *   btype, sme_trap_nonstreaming, is_nonstreaming, fp_access_checked,
 *   sve_access_checked, insn_start_updated.
 * Program-counter relative code, which no instruction taken reads:
 *   pc_save, page_start.
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
 * destination and the sources, of which 31 is SP, an immediate and a
 * shift amount. A gadget takes those its words name.
 */
typedef struct RCGArgs {
    int rd, rn, rm;
    uint64_t imm;
    unsigned sa;
} RCGArgs;

/*
 * Emits g with its words from a, if there is a gadget at g, and returns
 * whether there is. The gadget writes the register of its "d" word whole,
 * and reads those of its "n" and "m" words. nzcv says that it also writes
 * NF, ZF, CF and VF, each whole. The trace event says which instructions
 * RCG took, by gadget.
 */
static bool rcg_emit(DisasContext *s, const RCGGadget *g, const RCGArgs *a,
                     bool nzcv)
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
            break;
        case RCG_W_N:
            words[n] = offsetof(CPUARMState, xregs[a->rn]);
            rcg_note_temp(ins, &nb_ins, tcgv_i64_temp(cpu_X[a->rn]));
            break;
        case RCG_W_M:
            words[n] = offsetof(CPUARMState, xregs[a->rm]);
            rcg_note_temp(ins, &nb_ins, tcgv_i64_temp(cpu_X[a->rm]));
            break;
        case RCG_W_IMM:
            words[n] = a->imm;
            break;
        case RCG_W_SA:
            words[n] = a->sa;
            break;
        default:
            g_assert_not_reached();
        }
    }
    if (nzcv) {
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_NF));
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_ZF));
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_CF));
        rcg_note_temp(outs, &nb_outs, tcgv_i32_temp(cpu_VF));
    }
    tcg_gen_rich(g->gadget, words, n, 0, outs, nb_outs, ins, nb_ins);
    trace_rcg_insn(s->pc_curr, g->gadget);
    return true;
}

/*
 * What an S form does with its result: with XZR as the destination it
 * writes only NZCV, and is CMN or CMP.
 */
static unsigned rcg_flags(bool setflags, int rd)
{
    return !setflags ? RCG_FLAGS_NONE :
           rd == 31 ? RCG_FLAGS_ONLY : RCG_FLAGS_SET;
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

    return rcg_emit(s, &rcg_addsub_i[sub][a->sf][flags], &args, setflags);
}

/*
 * Add and subtract of a shifted register, as do_addsub_reg() does them.
 * Register 31 is XZR. As a source it has no word: the gadget for it
 * reads zero, and since a shifted zero is still zero, the one for the
 * second source has no shift. A shift by 0 is no shift either.
 */
static bool rcg_addsub_shift(DisasContext *s, arg_addsub_shift *a,
                             bool sub, bool setflags)
{
    static const uint8_t shifts[] = {
        RCG_SHIFT_LSL, RCG_SHIFT_LSR, RCG_SHIFT_ASR,
    };
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
        if (a->sa) {
            shift = shifts[a->st];
        }
    }
    return rcg_emit(s, &rcg_addsub_r[sub][a->sf][flags][shift][zero], &args,
                    setflags);
}

TRANS(rcg_ADD_i, rcg_addsub_imm, a, false, false)
TRANS(rcg_SUB_i, rcg_addsub_imm, a, true, false)
TRANS(rcg_ADDS_i, rcg_addsub_imm, a, false, true)
TRANS(rcg_SUBS_i, rcg_addsub_imm, a, true, true)
TRANS(rcg_ADD_r, rcg_addsub_shift, a, false, false)
TRANS(rcg_SUB_r, rcg_addsub_shift, a, true, false)
TRANS(rcg_ADDS_r, rcg_addsub_shift, a, false, true)
TRANS(rcg_SUBS_r, rcg_addsub_shift, a, true, true)

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
