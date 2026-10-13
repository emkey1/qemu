/*
 * AOK gadgets for AArch64 guests: the translator.
 *
 * Turns A64 integer, load/store, branch and system instructions into a
 * gadget stream (include/accel/tcg/aok.h). It translates what it is sure of
 * and stops in front of anything else -- floating point and SIMD, the LSE
 * atomics, an encoding it does not know, a feature it does not model -- so
 * that the next TB starts there and TCG translates it, raising whatever
 * exception is due. A TB whose first insn is one of those is declined
 * outright.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "qemu/int128.h"
#include "cpu.h"
#include "internals.h"
#include "cpu-features.h"
#include "cpregs.h"
#include "syndrome.h"
#include "helper.h"
#include "helper-a64.h"
#include "qemu/atomic.h"
#include "qemu/atomic128.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "accel/tcg/aok.h"
#include "accel/tcg/cpu-ldst-common.h"
#include "aok-arm.h"
#include "aok-arm-asm.h"

#define G(name) aok_gadget_a64_##name
#define DECL(name) void G(name)(void);
#define D2(name) DECL(name##64) DECL(name##32)
#define D2NF(name) D2(name) DECL(name##64_nf) DECL(name##32_nf)
/* Either width of a gadget, by sf. */
#define SF(name) (sf ? G(name##64) : G(name##32))

typedef void (*Gadget)(void);

/*
 * iSH-AOK's (gadgets-shared.S), under the names its translator knows them
 * by. Their operands are in its jit/guest-arm64/alu_spec.S and frag.h.
 */
D2(ospec_addi) D2(ospec_subi) D2(ospec_addsi) D2(ospec_subsi)
D2(ospec_andi) D2(ospec_orri) D2(ospec_eori) D2(ospec_andsi)
D2(ospec_cmpi) D2(ospec_cmni) D2(ospec_cmpr) D2(ospec_cmnr)
D2(ospec_addr) D2(ospec_subr) D2(ospec_addsr) D2(ospec_subsr)
D2(ospec_andr) D2(ospec_orrr) D2(ospec_eorr) D2(ospec_andsr)
D2(ospec_bicr) D2(ospec_ornr) D2(ospec_eonr) D2(ospec_mvn)
D2(ospec_addr_lsl) D2(ospec_subr_lsl)
D2(ospec_addr_lsr) D2(ospec_addr_asr) D2(ospec_subr_lsr) D2(ospec_subr_asr)
D2(ospec_ubfm) D2(ospec_sbfm) D2(ospec_ror)
D2NF(ospec_adc) D2NF(ospec_adcs) D2NF(ospec_sbc) D2NF(ospec_sbcs)
D2(ospec_mul) D2(ospec_madd) D2(ospec_msub)
DECL(ospec_umulh) DECL(ospec_smulh) DECL(ospec_umull) DECL(ospec_smull)
#define LOGIC_SH(op) D2(ospec_##op##_lsl) D2(ospec_##op##_lsr) \
                     D2(ospec_##op##_asr) D2(ospec_##op##_ror)
LOGIC_SH(and) LOGIC_SH(orr) LOGIC_SH(eor)
LOGIC_SH(bic) LOGIC_SH(orn) LOGIC_SH(eon)
#define EXT_OP(op) DECL(ospec_##op##_uxtb64) DECL(ospec_##op##_uxth64) \
    DECL(ospec_##op##_uxtw64) DECL(ospec_##op##_sxtb64) \
    DECL(ospec_##op##_sxth64) DECL(ospec_##op##_sxtw64) \
    DECL(ospec_##op##_uxtb32) DECL(ospec_##op##_uxth32) \
    DECL(ospec_##op##_sxtb32) DECL(ospec_##op##_sxth32)
EXT_OP(add) EXT_OP(sub)
DECL(mov_const) D2(umov)
#define LOADS(X, s) X(load8##s) X(load16##s) X(load32##s) X(load64##s) \
    X(loads8_32##s) X(loads8_64##s) X(loads16_32##s) X(loads16_64##s) \
    X(loads32_64##s)
#define STORES(X, s) X(store8##s) X(store16##s) X(store32##s) X(store64##s)
LOADS(DECL, _fast) STORES(DECL, _fast)
LOADS(DECL, _rx0) STORES(DECL, _rx0) LOADS(DECL, _rx1) STORES(DECL, _rx1)
LOADS(DECL, _rx2) STORES(DECL, _rx2)
LOADS(DECL, _wb0) STORES(DECL, _wb0) LOADS(DECL, _wb1) STORES(DECL, _wb1)
LOADS(DECL, _user) STORES(DECL, _user)
DECL(load16_ord) DECL(load32_ord) DECL(load64_ord)
DECL(store16_ord) DECL(store32_ord) DECL(store64_ord)
DECL(load32_lit) DECL(load64_lit) DECL(loads32_64_lit)
#define PAIRS(X, n) X(n##64_fast) X(n##32_fast) X(n##64_post) X(n##32_post) \
    X(n##64_pre) X(n##32_pre)
PAIRS(DECL, ldp) PAIRS(DECL, stp)

/* This front end's own (gadgets.S). */
DECL(pcrel) DECL(pcrel_page) DECL(movk)
D2(rbit) DECL(rev64) DECL(rev32) D2(rev16_) DECL(rev32_64) D2(clz) D2(cls)
D2(udiv) D2(sdiv) D2(lslv) D2(lsrv) D2(asrv) D2(rorv)
DECL(smaddl) DECL(smsubl) DECL(umaddl) DECL(umsubl)
D2(bfm) D2(extr)
#define ALUS(op) DECL(op##64_lslv) DECL(op##64_lsrv) DECL(op##64_asrv) \
    DECL(op##64_rorv) DECL(op##32_lslv) DECL(op##32_lsrv) DECL(op##32_asrv) \
    DECL(op##32_rorv)
ALUS(adds) ALUS(subs) ALUS(ands) ALUS(bics)
#define ALUXS(op) DECL(op##_uxtb64) DECL(op##_uxth64) DECL(op##_uxtw64) \
    DECL(op##_uxtx64) DECL(op##_sxtb64) DECL(op##_sxth64) DECL(op##_sxtw64) \
    DECL(op##_uxtb32) DECL(op##_uxth32) DECL(op##_uxtx32) \
    DECL(op##_sxtb32) DECL(op##_sxth32)
ALUXS(adds) ALUXS(subs)
DECL(b) DECL(bl) D2(cbz) D2(cbnz) DECL(tbz) DECL(tbnz)
DECL(br) DECL(blr) DECL(br_exit) DECL(blr_exit) DECL(lookup) DECL(barrier)
DECL(call) DECL(call_exit) DECL(mrs_sp_el0)

/* The gadgets there are one of for each condition, and their tables. */
#define CONDS(X, p, s) X(p##eq##s) X(p##ne##s) X(p##cs##s) X(p##cc##s) \
    X(p##mi##s) X(p##pl##s) X(p##vs##s) X(p##vc##s) X(p##hi##s) X(p##ls##s) \
    X(p##ge##s) X(p##lt##s) X(p##gt##s) X(p##le##s)
#define ENTRY(name) G(name),
/* [nf][cond]: NAME_cc, and NAME_nf_cc for flags that need no reloading */
#define COND_TABLE(p) { { CONDS(ENTRY, p, ) }, { CONDS(ENTRY, p##nf_, ) } }
#define COND_DECL(p) CONDS(DECL, p, ) CONDS(DECL, p##nf_, )

COND_DECL(b_)
static const Gadget bcond_tab[2][14] = COND_TABLE(b_);

#define CSEL_DECL(op) COND_DECL(op##64_) COND_DECL(op##32_)
CSEL_DECL(csel) CSEL_DECL(csinc) CSEL_DECL(csinv) CSEL_DECL(csneg)
/* [op][sf][nf][cond] */
static const Gadget csel_tab[4][2][2][14] = {
    { COND_TABLE(csel32_), COND_TABLE(csel64_) },
    { COND_TABLE(csinc32_), COND_TABLE(csinc64_) },
    { COND_TABLE(csinv32_), COND_TABLE(csinv64_) },
    { COND_TABLE(csneg32_), COND_TABLE(csneg64_) },
};

CSEL_DECL(ccmp) CSEL_DECL(ccmn) CSEL_DECL(ccmpi) CSEL_DECL(ccmni)
/* [imm][ccmp][sf][nf][cond] */
static const Gadget ccmp_tab[2][2][2][2][14] = {
    { { COND_TABLE(ccmn32_), COND_TABLE(ccmn64_) },
      { COND_TABLE(ccmp32_), COND_TABLE(ccmp64_) } },
    { { COND_TABLE(ccmni32_), COND_TABLE(ccmni64_) },
      { COND_TABLE(ccmpi32_), COND_TABLE(ccmpi64_) } },
};

/* What the assembly sources know of CPUARMState (aok-arm-asm.h). */
QEMU_BUILD_BUG_ON(offsetof(CPUARMState, CF) != AOK_A64_ENV_CF);
QEMU_BUILD_BUG_ON(offsetof(CPUARMState, VF) != AOK_A64_ENV_VF);
QEMU_BUILD_BUG_ON(offsetof(CPUARMState, NF) != AOK_A64_ENV_NF);
QEMU_BUILD_BUG_ON(offsetof(CPUARMState, ZF) != AOK_A64_ENV_ZF);
QEMU_BUILD_BUG_ON(offsetof(CPUARMState, xregs[30]) != AOK_A64_ENV_X30);
QEMU_BUILD_BUG_ON(offsetof(CPUARMState, pstate) != AOK_A64_ENV_PSTATE);
QEMU_BUILD_BUG_ON(PSTATE_SP != 1);
/* A pair's two register offsets share a word, sixteen bits each. */
QEMU_BUILD_BUG_ON(offsetof(CPUARMState, aok_sink) >= 0x10000);

enum { NEXT, END, UNKNOWN };

typedef struct Ctx {
    AokGen g;
    uint32_t insn;
    uint64_t page_off;      /* of the TB's first insn in its page */
    unsigned off;           /* of this insn from the TB's first */
    /*
     * Whether the host's NZCV is the guest's where the next gadget begins:
     * true after a gadget that sets or loads the flags, false after one that
     * uses the host's for its own ends, and as it was after any other.
     */
    bool nf;
    int tbi;                /* an indirect branch's operand (gadgets.S) */
    ARMCPU *cpu;
    int el, fp_excp_el;
    bool bti, pauth_active, pauth, fgt, no_goto_ptr;
    bool unpriv, trap_eret, fgt_svc, lse2, ras, gcs;
    bool no_sys, no_exc, no_atomic;     /* QEMU_AOK_NO_*, for bisecting */
} Ctx;

/* ---- Operands --------------------------------------------------------- */

#define XOFF(r) offsetof(CPUARMState, xregs[r])

/* A register as a source and as a destination, where 31 is XZR. */
static inline uint64_t rz(unsigned r)
{
    return r == 31 ? offsetof(CPUARMState, aok_zero) : XOFF(r);
}

static inline uint64_t wz(unsigned r)
{
    return r == 31 ? offsetof(CPUARMState, aok_sink) : XOFF(r);
}

/* Where 31 is SP. */
static inline uint64_t rsp(unsigned r)
{
    return XOFF(r);
}

static void emit(Ctx *c, Gadget gadget, int n, ...)
{
    va_list ap;

    aok_emit_gadget(&c->g, gadget);
    va_start(ap, n);
    while (n--) {
        aok_emit(&c->g, va_arg(ap, uint64_t));
    }
    va_end(ap);
}
#define E0(g)             emit(c, g, 0)
#define E2(g, a, b)       emit(c, g, 2, (uint64_t)(a), (uint64_t)(b))
#define E3(g, a, b, d)    emit(c, g, 3, (uint64_t)(a), (uint64_t)(b), \
                               (uint64_t)(d))
#define E4(g, a, b, d, e) emit(c, g, 4, (uint64_t)(a), (uint64_t)(b), \
                               (uint64_t)(d), (uint64_t)(e))

/*
 * The [pc delta][slot] pair of a direct jump to @delta bytes from the TB's
 * first insn. As with goto_tb, only a destination in the TB's own page may
 * be linked; any other is looked up each time.
 */
static void way(Ctx *c, int n, int64_t delta)
{
    int64_t dest = (int64_t)c->page_off + delta;

    aok_emit(&c->g, delta);
    if (dest >= 0 && dest < TARGET_PAGE_SIZE) {
        aok_emit(&c->g, aok_slot(&c->g, n));
    } else {
        aok_emit(&c->g, aok_slot_unlinked(&c->g));
    }
}

/* ---- The softmmu slow paths ------------------------------------------------
 *
 * Called by the load and store gadgets when the fast path does not apply
 * (gadgets-shared.S), with the insn's pc and opcode: the opcode says what
 * the access is, and an exception raised in here unwinds nothing, so what
 * arm_restore_state_to_opc would have recovered is stored first. A load's
 * bytes go to @out as they are in guest memory; the gadget extends them.
 */

/* As translate-a64.c's clean_data_tbi(): the top byte of a data address. */
static uint64_t a64_clean_addr(CPUARMState *env, uint64_t addr)
{
    int tbid = EX_TBFLAG_A64(env->hflags, TBID);
    ARMMMUIdx mmu_idx;
    uint64_t ext;

    if (tbid == 0) {
        return addr;
    }
    mmu_idx = core_to_aa64_mmu_idx(EX_TBFLAG_ANY(env->hflags, MMUIDX));
    if (!regime_has_2_ranges(mmu_idx)) {
        return extract64(addr, 0, 56);
    }
    ext = sextract64(addr, 0, 56);
    switch (tbid) {
    case 1:
        return ext & addr;
    case 2:
        return ext | addr;
    default:
        return ext;
    }
}

/* What a single-register load or store is: translate-a64.c's a->sz etc. */
typedef struct A64Access {
    bool pair, pair64;
    bool iss_valid, sign, sf;
    bool ordered, unpriv;
    unsigned size, rt, rt2;
} A64Access;

static A64Access a64_access(uint32_t insn)
{
    A64Access a = { .rt = insn & 31 };

    if ((insn & 0x3f000000) == 0x08000000) {
        /* ldar, stlr: the syndrome says which (AR), and they must be aligned */
        a.size = insn >> 30;
        a.sf = a.size == 3;
        a.iss_valid = true;
        a.ordered = true;
    } else if ((insn & 0x3a000000) == 0x28000000) {
        a.pair = true;
        a.pair64 = insn >> 31;
        a.rt2 = (insn >> 10) & 31;
    } else if ((insn & 0x3b000000) == 0x18000000) {
        /* A literal: ldr w, ldr x, ldrsw. */
        unsigned opc = insn >> 30;

        a.size = opc == 1 ? 3 : 2;
        a.sign = opc == 2;
        a.sf = opc != 0;
        a.iss_valid = true;
    } else {
        unsigned opc = (insn >> 22) & 3;
        bool ext = opc == 3;        /* a signed load to a W register */
        bool imm12 = insn & (1 << 24), regoff = insn & (1 << 21);

        a.size = insn >> 30;
        a.sign = opc & 2;
        /* translate-a64.c's ldst_iss_sf() */
        a.sf = a.sign ? !ext : a.size == 3;
        /* Write-back makes the syndrome's register fields meaningless. */
        a.iss_valid = imm12 || regoff || !(insn & (1 << 10));
        a.unpriv = !imm12 && !regoff && ((insn >> 10) & 3) == 2;
    }
    return a;
}

/* As translate-a64.c's core_a64_user_mem_index(). */
static int a64_mmu_idx(CPUARMState *env, bool unpriv)
{
    int idx = EX_TBFLAG_ANY(env->hflags, MMUIDX);

    if (unpriv && EX_TBFLAG_A64(env->hflags, UNPRIV)) {
        switch (core_to_aa64_mmu_idx(idx)) {
        case ARMMMUIdx_E10_1:
        case ARMMMUIdx_E10_1_PAN:
            return arm_to_core_mmu_idx(ARMMMUIdx_E10_0);
        case ARMMMUIdx_E20_2:
        case ARMMMUIdx_E20_2_PAN:
            return arm_to_core_mmu_idx(ARMMMUIdx_E20_0);
        default:
            g_assert_not_reached();
        }
    }
    return idx;
}

/*
 * What every function a stream calls does first: nothing is unwound from
 * here, so the pc an exception would report is stored now, with the
 * syndrome template arm_restore_state_to_opc would have left.
 */
static void a64_sync_pc(CPUARMState *env, uint64_t pc, uint32_t syn)
{
    aok_fold_fpsr(env_cpu(env));
    aok_no_retaddr();
    env->pc = pc;
    env->exception.syndrome = syn;
}

static MemOpIdx a64_sync(CPUARMState *env, uint64_t pc, const A64Access *a,
                         MemOp mop)
{
    uint32_t syn = 0;

    if (a->iss_valid) {
        /* As do_gpr_ld/do_gpr_st and disas_set_insn_syndrome leave it. */
        syn = syn_data_abort_with_iss(0, a->size, a->sign, a->rt, a->sf,
                                      a->ordered, 0, 0, 0, 0, 0, false);
        syn &= ARM_INSN_START_WORD2_MASK;
        syn = (syn >> ARM_INSN_START_WORD2_SHIFT) << ARM_INSN_START_WORD2_SHIFT;
    }
    a64_sync_pc(env, pc, syn);
    if (a->ordered && a->size) {
        mop |= MO_ALIGN;    /* check_ordered_align(), without LSE2 */
    }
    return make_memop_idx(mop, a64_mmu_idx(env, a->unpriv));
}

void aok_a64_helper_ld(CPUARMState *env, uint64_t addr, uint64_t pc,
                       uint32_t insn, uint64_t *out);
void aok_a64_helper_ld(CPUARMState *env, uint64_t addr, uint64_t pc,
                       uint32_t insn, uint64_t *out)
{
    A64Access a = a64_access(insn);

    addr = a64_clean_addr(env, addr);
    if (a.pair64) {
        MemOpIdx oi = a64_sync(env, pc, &a,
                               MO_128 | MO_LE | MO_ATOM_IFALIGN_PAIR);
        Int128 v = cpu_ld16_mmu(env, addr, oi, 0);

        out[0] = int128_getlo(v);
        out[1] = int128_gethi(v);
    } else if (a.pair) {
        MemOpIdx oi = a64_sync(env, pc, &a,
                               MO_64 | MO_LE | MO_ATOM_IFALIGN_PAIR);

        out[0] = cpu_ldq_mmu(env, addr, oi, 0);
    } else {
        switch (a.size) {
        case 0:
            out[0] = cpu_ldb_mmu(env, addr, a64_sync(env, pc, &a, MO_UB), 0);
            break;
        case 1:
            out[0] = cpu_ldw_mmu(env, addr, a64_sync(env, pc, &a, MO_LEUW), 0);
            break;
        case 2:
            out[0] = cpu_ldl_mmu(env, addr, a64_sync(env, pc, &a, MO_LEUL), 0);
            break;
        default:
            out[0] = cpu_ldq_mmu(env, addr, a64_sync(env, pc, &a, MO_LEUQ), 0);
            break;
        }
    }
}

void aok_a64_helper_st(CPUARMState *env, uint64_t addr, uint64_t pc,
                       uint32_t insn, uint64_t *out);
void aok_a64_helper_st(CPUARMState *env, uint64_t addr, uint64_t pc,
                       uint32_t insn, uint64_t *out)
{
    A64Access a = a64_access(insn);
    /* The registers are in env: a gadget stores what it computes at once. */
    uint64_t v = a.rt == 31 ? 0 : env->xregs[a.rt];
    uint64_t v2 = a.rt2 == 31 ? 0 : env->xregs[a.rt2];

    addr = a64_clean_addr(env, addr);
    if (a.pair64) {
        MemOpIdx oi = a64_sync(env, pc, &a,
                               MO_128 | MO_LE | MO_ATOM_IFALIGN_PAIR);

        cpu_st16_mmu(env, addr, int128_make128(v, v2), oi, 0);
    } else if (a.pair) {
        MemOpIdx oi = a64_sync(env, pc, &a,
                               MO_64 | MO_LE | MO_ATOM_IFALIGN_PAIR);

        cpu_stq_mmu(env, addr, (uint32_t)v | v2 << 32, oi, 0);
    } else {
        switch (a.size) {
        case 0:
            cpu_stb_mmu(env, addr, v, a64_sync(env, pc, &a, MO_UB), 0);
            break;
        case 1:
            cpu_stw_mmu(env, addr, v, a64_sync(env, pc, &a, MO_LEUW), 0);
            break;
        case 2:
            cpu_stl_mmu(env, addr, v, a64_sync(env, pc, &a, MO_LEUL), 0);
            break;
        default:
            cpu_stq_mmu(env, addr, v, a64_sync(env, pc, &a, MO_LEUQ), 0);
            break;
        }
    }
}

/* ---- One call to C --------------------------------------------------------
 *
 * Instructions done whole in C: fn(env, pc, insn, arg), from the call and
 * call_exit gadgets. Each does what translate-a64.c generates for the insn,
 * with the same helpers in the same order.
 */

static uint64_t a64_reg(CPUARMState *env, unsigned r)
{
    return r == 31 ? 0 : env->xregs[r];
}

static void a64_set_reg(CPUARMState *env, unsigned r, uint64_t v)
{
    if (r != 31) {
        env->xregs[r] = v;
    }
}

/*
 * handle_sys(): mrs, msr and sys with a register. The translator has made
 * the checks that need only the TB's flags. The register is looked up here,
 * as TCG's code does: a TB is every CPU's, and each CPU has its own
 * ARMCPRegInfo, alike but for what its functions are given to work on. A
 * write that may change what the next TB is ends this one in the main loop,
 * so the pc is left at the next insn.
 */
void aok_a64_helper_sysreg(CPUARMState *env, uint64_t pc, uint64_t insn,
                           void *unused);
void aok_a64_helper_sysreg(CPUARMState *env, uint64_t pc, uint64_t insn,
                           void *unused)
{
    bool isread = insn & (1 << 21);
    unsigned op0 = extract32(insn, 19, 2), op1 = extract32(insn, 16, 3);
    unsigned crn = extract32(insn, 12, 4), crm = extract32(insn, 8, 4);
    unsigned op2 = extract32(insn, 5, 3), rt = insn & 31;
    uint32_t key = ENCODE_AA64_CP_REG(op0, op1, crn, crm, op2);
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(env_archcpu(env)->cp_regs, key);
    int el = arm_current_el(env);
    uint64_t v;

    a64_sync_pc(env, pc, 0);
    if (ri->accessfn || (ri->fgt && EX_TBFLAG_ANY(env->hflags, FGT_ACTIVE))) {
        helper_access_check_cp_reg(env, key,
                                   syn_aa64_sysregtrap(op0, op1, op2, crn, crm,
                                                       rt, isread),
                                   isread);
    }
    env->pc = pc + 4;

    switch (ri->type & ARM_CP_SPECIAL_MASK) {
    case 0:
        break;
    case ARM_CP_NOP:
        return;
    case ARM_CP_NZCV:
        if (isread) {
            a64_set_reg(env, rt, (env->NF & 0x80000000u) |
                        (env->ZF == 0) << 30 | env->CF << 29 |
                        (env->VF >> 31) << 28);
        } else {
            uint32_t nzcv = a64_reg(env, rt);

            env->NF = nzcv & 0x80000000u;
            env->ZF = !(nzcv & (1 << 30));
            env->CF = (nzcv >> 29) & 1;
            env->VF = (nzcv & (1 << 28)) << 3;
        }
        return;
    case ARM_CP_CURRENTEL:
        a64_set_reg(env, rt, el << 2);
        return;
    case ARM_CP_DC_ZVA:
        env->pc = pc;
        helper_dc_zva(env, a64_clean_addr(env, a64_reg(env, rt)));
        env->pc = pc + 4;
        return;
    default:
        g_assert_not_reached();
    }

    if (isread) {
        if (ri->type & ARM_CP_CONST) {
            v = ri->resetvalue;
        } else if (ri->readfn) {
            env->pc = pc;
            v = helper_get_cp_reg64(env, ri);
            env->pc = pc + 4;
        } else {
            v = *(uint64_t *)((char *)env + ri->fieldoffset);
        }
        a64_set_reg(env, rt, v);
        return;
    }
    if (ri->type & ARM_CP_CONST) {
        return;
    }
    v = a64_reg(env, rt);
    if (ri->writefn) {
        env->pc = pc;
        helper_set_cp_reg64(env, ri, v);
        env->pc = pc + 4;
    } else {
        *(uint64_t *)((char *)env + ri->fieldoffset) = v;
    }
    if (!(ri->type & ARM_CP_SUPPRESS_TB_END)) {
        helper_rebuild_hflags_a64(env, el);
    }
}

/* msr daifset, #imm and msr daifclr, #imm */
void aok_a64_helper_msr_daif(CPUARMState *env, uint64_t pc, uint64_t insn,
                             void *unused);
void aok_a64_helper_msr_daif(CPUARMState *env, uint64_t pc, uint64_t insn,
                             void *unused)
{
    uint32_t imm = extract32(insn, 8, 4);

    a64_sync_pc(env, pc, 0);
    if (insn & (1 << 5)) {
        helper_msr_i_daifclear(env, imm);
    } else {
        helper_msr_i_daifset(env, imm);
    }
    env->pc = pc + 4;
}

/* svc: the exception is taken from the next insn. */
void aok_a64_helper_svc(CPUARMState *env, uint64_t pc, uint64_t insn,
                        void *unused);
void aok_a64_helper_svc(CPUARMState *env, uint64_t pc, uint64_t insn,
                        void *unused)
{
    a64_sync_pc(env, pc + 4, 0);
    helper_exception_with_syndrome(env, EXCP_SWI,
                                   syn_aa64_svc(extract32(insn, 5, 16)));
}

/* eret: the helper sets the pc and everything else. */
void aok_a64_helper_eret(CPUARMState *env, uint64_t pc, uint64_t insn,
                         void *unused);
void aok_a64_helper_eret(CPUARMState *env, uint64_t pc, uint64_t insn,
                         void *unused)
{
    a64_sync_pc(env, pc, 0);
    helper_exception_return(env, env->elr_el[arm_current_el(env)]);
}

/*
 * The exclusives, as gen_load_exclusive() and gen_store_exclusive(): a load
 * remembers the address and what was there, and a store is a compare and
 * swap against that. cputlb's atomic helpers are atomic whether or not the
 * TB is CF_PARALLEL. Without LSE2 (the translator has checked) every access
 * wider than a byte must be aligned.
 */
static MemOpIdx a64_excl_oi(CPUARMState *env, MemOp mop)
{
    if ((mop & MO_SIZE) == MO_128) {
        mop |= MO_ALIGN | MO_ATOM_IFALIGN_PAIR;
    } else if (mop & MO_SIZE) {
        mop |= MO_ALIGN;
    }
    return make_memop_idx(mop | MO_LE, EX_TBFLAG_ANY(env->hflags, MMUIDX));
}

void aok_a64_helper_ldx(CPUARMState *env, uint64_t pc, uint64_t insn,
                        void *unused);
void aok_a64_helper_ldx(CPUARMState *env, uint64_t pc, uint64_t insn,
                        void *unused)
{
    unsigned rt = insn & 31, rn = (insn >> 5) & 31, rt2 = (insn >> 10) & 31;
    bool pair = insn & (1 << 21);
    unsigned size = pair ? 2 | ((insn >> 30) & 1) : insn >> 30;
    uint64_t addr = a64_clean_addr(env, env->xregs[rn]);
    MemOpIdx oi = a64_excl_oi(env, size + pair);

    a64_sync_pc(env, pc, 0);
    if (pair && size == 3) {
        Int128 v = cpu_ld16_mmu(env, addr, oi, 0);

        env->exclusive_val = int128_getlo(v);
        env->exclusive_high = int128_gethi(v);
        a64_set_reg(env, rt, env->exclusive_val);
        a64_set_reg(env, rt2, env->exclusive_high);
    } else if (pair) {
        env->exclusive_val = cpu_ldq_mmu(env, addr, oi, 0);
        a64_set_reg(env, rt, (uint32_t)env->exclusive_val);
        a64_set_reg(env, rt2, env->exclusive_val >> 32);
    } else {
        env->exclusive_val = size == 0 ? cpu_ldb_mmu(env, addr, oi, 0)
                           : size == 1 ? cpu_ldw_mmu(env, addr, oi, 0)
                           : size == 2 ? cpu_ldl_mmu(env, addr, oi, 0)
                           : cpu_ldq_mmu(env, addr, oi, 0);
        a64_set_reg(env, rt, env->exclusive_val);
    }
    env->exclusive_addr = addr;
    if (insn & (1 << 15)) {
        smp_mb();           /* ldaxr */
    }
}

void aok_a64_helper_stx(CPUARMState *env, uint64_t pc, uint64_t insn,
                        void *unused);
void aok_a64_helper_stx(CPUARMState *env, uint64_t pc, uint64_t insn,
                        void *unused)
{
    unsigned rt = insn & 31, rn = (insn >> 5) & 31, rt2 = (insn >> 10) & 31;
    unsigned rs = (insn >> 16) & 31;
    bool pair = insn & (1 << 21);
    unsigned size = pair ? 2 | ((insn >> 30) & 1) : insn >> 30;
    uint64_t addr = a64_clean_addr(env, env->xregs[rn]);
    uint64_t v = a64_reg(env, rt), v2 = a64_reg(env, rt2);
    uint64_t cmp = env->exclusive_val, old;
    MemOpIdx oi = a64_excl_oi(env, size + pair);
    bool fail = true;

    a64_sync_pc(env, pc, 0);
    if (insn & (1 << 15)) {
        smp_mb();           /* stlxr */
    }
    if (addr == env->exclusive_addr) {
        if (pair && size == 3) {
#if HAVE_CMPXCHG128
            Int128 o = cpu_atomic_cmpxchgo_le_mmu(
                env, addr, int128_make128(cmp, env->exclusive_high),
                int128_make128(v, v2), oi, 0);

            fail = (int128_getlo(o) ^ cmp) |
                   (int128_gethi(o) ^ env->exclusive_high);
#else
            g_assert_not_reached();
#endif
        } else if (pair) {
            old = cpu_atomic_cmpxchgq_le_mmu(env, addr, cmp,
                                             (uint32_t)v | v2 << 32, oi, 0);
            fail = old != cmp;
        } else {
            old = size == 0 ? cpu_atomic_cmpxchgb_mmu(env, addr, cmp, v, oi, 0)
                : size == 1 ? cpu_atomic_cmpxchgw_le_mmu(env, addr, cmp, v,
                                                         oi, 0)
                : size == 2 ? cpu_atomic_cmpxchgl_le_mmu(env, addr, cmp, v,
                                                         oi, 0)
                : cpu_atomic_cmpxchgq_le_mmu(env, addr, cmp, v, oi, 0);
            fail = old != cmp;
        }
    }
    a64_set_reg(env, rs, fail);
    env->exclusive_addr = -1;
}

/* No gadget computes on the host's FP unit yet. */
void arm_aok_fold_fpsr(CPUState *cs, uint32_t fpsr)
{
    g_assert_not_reached();
}

/* ---- Data processing, immediate -------------------------------------------- */

/* A logical immediate's mask, as translate-a64.c's logic_imm_decode_wmask(). */
static bool decode_bitmask(uint64_t *result, unsigned immn, unsigned imms,
                           unsigned immr)
{
    uint64_t mask;
    unsigned e, levels, s, r;
    int len = 31 - clz32((immn << 6) | (~imms & 0x3f));

    if (len < 1) {
        return false;
    }
    e = 1 << len;
    levels = e - 1;
    s = imms & levels;
    r = immr & levels;
    if (s == levels) {
        return false;
    }
    mask = MAKE_64BIT_MASK(0, s + 1);
    if (r) {
        mask = (mask >> r) | (mask << (e - r));
        mask &= MAKE_64BIT_MASK(0, e);
    }
    while (e < 64) {
        mask |= mask << e;
        e *= 2;
    }
    *result = mask;
    return true;
}

static int dp_imm(Ctx *c, uint32_t insn)
{
    unsigned sf = insn >> 31, rd = insn & 31, rn = (insn >> 5) & 31;
    unsigned opc = (insn >> 29) & 3;
    unsigned immr = (insn >> 16) & 63, imms = (insn >> 10) & 63;
    unsigned n = (insn >> 22) & 1, rs = sf ? 64 : 32;

    switch ((insn >> 23) & 7) {
    case 0:
    case 1: {   /* adr, adrp */
        int64_t imm = sextract64(insn, 5, 19) << 2 | extract32(insn, 29, 2);

        if (insn >> 31) {
            E2(G(pcrel_page), wz(rd), imm << 12);
        } else {
            E2(G(pcrel), wz(rd), c->off + imm);
        }
        return NEXT;
    }
    case 2: {   /* add, sub, with or without flags; SP is a register here */
        uint64_t imm = extract32(insn, 10, 12) << (n ? 12 : 0);
        bool sub = insn & (1 << 30), s = insn & (1 << 29);

        if (s && rd == 31) {
            E2(sub ? SF(ospec_cmpi) : SF(ospec_cmni), rsp(rn), imm);
        } else if (s) {
            E3(sub ? SF(ospec_subsi) : SF(ospec_addsi), wz(rd), rsp(rn), imm);
        } else {
            E3(sub ? SF(ospec_subi) : SF(ospec_addi), rsp(rd), rsp(rn), imm);
        }
        c->nf |= s;
        return NEXT;
    }
    case 4: {   /* and, orr, eor, ands with a bitmask */
        uint64_t mask;

        if ((!sf && n) || !decode_bitmask(&mask, n, imms, immr)) {
            return UNKNOWN;
        }
        if (!sf) {
            mask &= 0xffffffffu;
        }
        switch (opc) {
        case 0:
            E3(SF(ospec_andi), rsp(rd), rz(rn), mask);
            break;
        case 1:
            if (rn == 31) {
                E2(G(mov_const), rsp(rd), mask);
            } else {
                E3(SF(ospec_orri), rsp(rd), rz(rn), mask);
            }
            break;
        case 2:
            E3(SF(ospec_eori), rsp(rd), rz(rn), mask);
            break;
        default:
            E3(SF(ospec_andsi), wz(rd), rz(rn), mask);
            c->nf = true;
            break;
        }
        return NEXT;
    }
    case 5: {   /* movn, movz, movk */
        unsigned sh = ((insn >> 21) & 3) * 16;
        uint64_t imm = (uint64_t)extract32(insn, 5, 16) << sh;

        if ((!sf && sh >= 32) || opc == 1) {
            return UNKNOWN;
        }
        if (opc == 3) {
            uint64_t keep = ~((uint64_t)0xffff << sh);

            E3(G(movk), wz(rd), sf ? keep : keep & 0xffffffffu, imm);
        } else {
            if (opc == 0) {
                imm = sf ? ~imm : ~imm & 0xffffffffu;
            }
            E2(G(mov_const), wz(rd), imm);
        }
        return NEXT;
    }
    case 6: {   /* sbfm, bfm, ubfm */
        if (n != sf || opc == 3 || (!sf && (immr >= 32 || imms >= 32))) {
            return UNKNOWN;
        }
        if (opc == 1) {
            /* The source rotated right by immr, and which bits of it. */
            uint64_t mask = imms >= immr
                ? MAKE_64BIT_MASK(0, imms - immr + 1)
                : MAKE_64BIT_MASK(0, imms + 1) << (rs - immr);

            E4(SF(bfm), wz(rd), rz(rn), immr, mask);
        } else {
            /* (src << l) >> s: iSH-AOK's lowering, its dpextra.S. */
            unsigned l = rs - 1 - imms;
            unsigned s = imms >= immr ? l + immr : immr - 1 - imms;

            E4(opc ? SF(ospec_ubfm) : SF(ospec_sbfm), wz(rd), rz(rn), l, s);
        }
        return NEXT;
    }
    case 7: {   /* extr */
        unsigned rm = (insn >> 16) & 31;

        if (opc || n != sf || (insn & (1 << 21)) || imms >= rs) {
            return UNKNOWN;
        }
        if (imms == 0) {
            E2(SF(umov), wz(rd), rz(rm));
        } else if (rn == rm) {
            E3(SF(ospec_ror), wz(rd), rz(rn), imms);
        } else {
            E4(SF(extr), wz(rd), rz(rn), rz(rm), imms);
        }
        return NEXT;
    }
    default:    /* add and sub with tags */
        return UNKNOWN;
    }
}

/* ---- Data processing, register ---------------------------------------------- */

static int dp_reg(Ctx *c, uint32_t insn)
{
    unsigned sf = insn >> 31, rd = insn & 31, rn = (insn >> 5) & 31;
    unsigned rm = (insn >> 16) & 31, imm6 = (insn >> 10) & 63;
    unsigned shift = (insn >> 22) & 3;
    bool op = insn & (1 << 30), s = insn & (1 << 29);
    unsigned op2 = (insn >> 21) & 15;

    if (!(insn & (1 << 28))) {
        if (!(op2 & 8)) {
            /* Logical, shifted register: and bic orr orn eor eon ands bics */
            static const Gadget plain[6][2] = {
                { G(ospec_andr32), G(ospec_andr64) },
                { G(ospec_bicr32), G(ospec_bicr64) },
                { G(ospec_orrr32), G(ospec_orrr64) },
                { G(ospec_ornr32), G(ospec_ornr64) },
                { G(ospec_eorr32), G(ospec_eorr64) },
                { G(ospec_eonr32), G(ospec_eonr64) },
            };
#define SH4(p) { { G(p##lsl32), G(p##lsl64) }, { G(p##lsr32), G(p##lsr64) }, \
                 { G(p##asr32), G(p##asr64) }, { G(p##ror32), G(p##ror64) } }
#define SHV4(op) { { G(op##32_lslv), G(op##64_lslv) }, \
                   { G(op##32_lsrv), G(op##64_lsrv) }, \
                   { G(op##32_asrv), G(op##64_asrv) }, \
                   { G(op##32_rorv), G(op##64_rorv) } }
            static const Gadget shifted[8][4][2] = {
                SH4(ospec_and_), SH4(ospec_bic_), SH4(ospec_orr_),
                SH4(ospec_orn_), SH4(ospec_eor_), SH4(ospec_eon_),
                SHV4(ands), SHV4(bics),
            };
            unsigned which = ((insn >> 29) & 3) << 1 | (op2 & 1);

            if (!sf && imm6 >= 32) {
                return UNKNOWN;
            }
            if (which >= 6) {
                if (which == 6 && imm6 == 0) {
                    E3(SF(ospec_andsr), wz(rd), rz(rn), rz(rm));
                } else {
                    E4(shifted[which][shift][sf], wz(rd), rz(rn), rz(rm), imm6);
                }
                c->nf = true;
            } else if (imm6) {
                E4(shifted[which][shift][sf], wz(rd), rz(rn), rz(rm), imm6);
            } else if (which == 2 && rn == 31) {
                E2(SF(umov), wz(rd), rz(rm));               /* mov */
            } else if (which == 3 && rn == 31) {
                E2(SF(ospec_mvn), wz(rd), rz(rm));
            } else {
                E3(plain[which][sf], wz(rd), rz(rn), rz(rm));
            }
            return NEXT;
        }
        if (!(op2 & 1)) {
            /* Add and subtract, shifted register. No SP here. */
            static const Gadget fl[2][4][2] = { SHV4(adds), SHV4(subs) };

            if (shift == 3 || (!sf && imm6 >= 32)) {
                return UNKNOWN;
            }
            if (s) {
                if (imm6) {
                    E4(fl[op][shift][sf], wz(rd), rz(rn), rz(rm), imm6);
                } else if (rd == 31) {
                    E2(op ? SF(ospec_cmpr) : SF(ospec_cmnr), rz(rn), rz(rm));
                } else {
                    E3(op ? SF(ospec_subsr) : SF(ospec_addsr),
                       wz(rd), rz(rn), rz(rm));
                }
                c->nf = true;
            } else if (!imm6) {
                E3(op ? SF(ospec_subr) : SF(ospec_addr), wz(rd), rz(rn), rz(rm));
            } else {
                Gadget g = shift == 0 ? op ? SF(ospec_subr_lsl) : SF(ospec_addr_lsl)
                         : shift == 1 ? op ? SF(ospec_subr_lsr) : SF(ospec_addr_lsr)
                         : op ? SF(ospec_subr_asr) : SF(ospec_addr_asr);

                E4(g, wz(rd), rz(rn), rz(rm), imm6);
            }
            return NEXT;
        }
        /*
         * Add and subtract, extended register: rn and, without flags, rd may
         * be SP; rm is extended from 8, 16 or 32 bits, or is a whole
         * register (uxtx and sxtx, and for a W result the 32-bit ones too).
         */
        {
            unsigned option = (insn >> 13) & 7, imm3 = (insn >> 10) & 7;
            /* 0: plain; else 1 + (b, h, w) + 3 * signed */
            unsigned ext = (option & 3) == 3 || (!sf && (option & 3) == 2)
                ? 0 : 1 + (option & 3) + (option & 4 ? 3 : 0);
#define X6(p, s) { NULL, G(p##uxtb##s), G(p##uxth##s), G(p##uxtw##s), \
                   G(p##sxtb##s), G(p##sxth##s), G(p##sxtw##s) }
#define X4(p, s) { NULL, G(p##uxtb##s), G(p##uxth##s), NULL, \
                   G(p##sxtb##s), G(p##sxth##s), NULL }
            static const Gadget nofl[2][2][7] = {
                { X4(ospec_add_, 32), X6(ospec_add_, 64) },
                { X4(ospec_sub_, 32), X6(ospec_sub_, 64) },
            };
            static const Gadget withfl[2][2][7] = {
                { X4(adds_, 32), X6(adds_, 64) },
                { X4(subs_, 32), X6(subs_, 64) },
            };

            if (shift || imm3 > 4) {
                return UNKNOWN;
            }
            if (s) {
                Gadget g = ext ? withfl[op][sf][ext]
                         : op ? SF(subs_uxtx) : SF(adds_uxtx);

                E4(g, wz(rd), rsp(rn), rz(rm), imm3);
                c->nf = true;
            } else {
                Gadget g = ext ? nofl[op][sf][ext]
                         : op ? SF(ospec_subr_lsl) : SF(ospec_addr_lsl);

                E4(g, rsp(rd), rsp(rn), rz(rm), imm3);
            }
            return NEXT;
        }
    }

    switch (op2) {
    case 0: {   /* adc, adcs, sbc, sbcs */
        static const Gadget tab[2][2][2][2] = {     /* [op][s][sf][nf] */
            { { { G(ospec_adc32), G(ospec_adc32_nf) },
                { G(ospec_adc64), G(ospec_adc64_nf) } },
              { { G(ospec_adcs32), G(ospec_adcs32_nf) },
                { G(ospec_adcs64), G(ospec_adcs64_nf) } } },
            { { { G(ospec_sbc32), G(ospec_sbc32_nf) },
                { G(ospec_sbc64), G(ospec_sbc64_nf) } },
              { { G(ospec_sbcs32), G(ospec_sbcs32_nf) },
                { G(ospec_sbcs64), G(ospec_sbcs64_nf) } } },
        };

        if (imm6) {
            return UNKNOWN;     /* rmif, setf8, setf16 */
        }
        E3(tab[op][s][sf][c->nf], wz(rd), rz(rn), rz(rm));
        c->nf = true;
        return NEXT;
    }
    case 2: {   /* ccmn, ccmp: with a register, with an immediate */
        unsigned cond = (insn >> 12) & 15;
        bool imm = insn & (1 << 11);

        if (!s || (insn & (1 << 10)) || (insn & (1 << 4))) {
            return UNKNOWN;
        }
        if (cond >= 14) {
            /* Always: the compare itself. */
            if (imm) {
                E2(op ? SF(ospec_cmpi) : SF(ospec_cmni), rz(rn), rm);
            } else {
                E2(op ? SF(ospec_cmpr) : SF(ospec_cmnr), rz(rn), rz(rm));
            }
        } else {
            E3(ccmp_tab[imm][op][sf][c->nf][cond], rz(rn),
               imm ? rm : rz(rm), (uint64_t)(insn & 15) << 28);
        }
        c->nf = true;
        return NEXT;
    }
    case 4: {   /* csel, csinc, csinv, csneg */
        unsigned cond = (insn >> 12) & 15;

        if (s || (insn & (1 << 11))) {
            return UNKNOWN;
        }
        if (cond >= 14) {
            E2(SF(umov), wz(rd), rz(rn));
        } else {
            E3(csel_tab[op << 1 | (imm6 & 1)][sf][c->nf][cond],
               wz(rd), rz(rn), rz(rm));
            c->nf = true;       /* loaded, if they were not there */
        }
        return NEXT;
    }
    case 6:
        if (s) {
            return UNKNOWN;
        }
        if (!op) {
            /* Two sources. */
            Gadget g = imm6 == 2 ? SF(udiv) : imm6 == 3 ? SF(sdiv)
                     : imm6 == 8 ? SF(lslv) : imm6 == 9 ? SF(lsrv)
                     : imm6 == 10 ? SF(asrv) : imm6 == 11 ? SF(rorv) : NULL;

            if (!g) {
                return UNKNOWN; /* crc32, pacga, the MTE and CSSC ones */
            }
            E3(g, wz(rd), rz(rn), rz(rm));
        } else {
            /* One source. */
            Gadget g = imm6 == 0 ? SF(rbit) : imm6 == 1 ? SF(rev16_)
                     : imm6 == 2 ? sf ? G(rev32_64) : G(rev32)
                     : imm6 == 3 && sf ? G(rev64)
                     : imm6 == 4 ? SF(clz) : imm6 == 5 ? SF(cls) : NULL;

            if (rm || !g) {
                return UNKNOWN; /* pointer authentication, CSSC */
            }
            E2(g, wz(rd), rz(rn));
        }
        return NEXT;
    case 8 ... 15: {    /* three sources */
        unsigned op31 = (insn >> 21) & 7, ra = (insn >> 10) & 31;
        bool o0 = insn & (1 << 15);

        if ((insn >> 29) & 3) {
            return UNKNOWN;
        }
        if (op31 == 0) {
            if (ra == 31 && !o0) {
                E3(SF(ospec_mul), wz(rd), rz(rn), rz(rm));
            } else {
                E4(o0 ? SF(ospec_msub) : SF(ospec_madd),
                   wz(rd), rz(rn), rz(rm), rz(ra));
            }
        } else if (!sf) {
            return UNKNOWN;
        } else if (op31 == 1 || op31 == 5) {
            if (ra == 31 && !o0) {
                E3(op31 == 1 ? G(ospec_smull) : G(ospec_umull),
                   wz(rd), rz(rn), rz(rm));
            } else {
                E4(op31 == 1 ? o0 ? G(smsubl) : G(smaddl)
                             : o0 ? G(umsubl) : G(umaddl),
                   wz(rd), rz(rn), rz(rm), rz(ra));
            }
        } else if ((op31 == 2 || op31 == 6) && !o0) {
            E3(op31 == 2 ? G(ospec_smulh) : G(ospec_umulh),
               wz(rd), rz(rn), rz(rm));
        } else {
            return UNKNOWN;
        }
        return NEXT;
    }
    default:
        return UNKNOWN;
    }
}

/* ---- System instructions ------------------------------------------------------ */

/* An insn that is one call to C (gadgets.S): fn(env, pc, insn, arg). */
static int call(Ctx *c, Gadget gadget, void *fn, const void *arg)
{
    emit(c, gadget, 4, (uint64_t)(uintptr_t)fn, (uint64_t)c->off,
         (uint64_t)c->insn, (uint64_t)(uintptr_t)arg);
    c->nf = false;
    return gadget == G(call) ? NEXT : END;
}

/*
 * mrs, msr and sys with a register: handle_sys(), for a register whose
 * access needs nothing a TB's flags do not say. Whatever is odd about one --
 * no such register, not at this EL, redirected, a special kind not listed --
 * is TCG's.
 */
static int sysreg(Ctx *c, uint32_t insn)
{
    bool isread = insn & (1 << 21);
    unsigned op0 = extract32(insn, 19, 2), op1 = extract32(insn, 16, 3);
    unsigned crn = extract32(insn, 12, 4), crm = extract32(insn, 8, 4);
    unsigned op2 = extract32(insn, 5, 3), rt = insn & 31;
    uint32_t key = ENCODE_AA64_CP_REG(op0, op1, crn, crm, op2);
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(c->cpu->cp_regs, key);
    bool check, ends;

    if (!ri || crn == 11 || crn == 15 || !cp_access_ok(c->el, ri, isread) ||
        (c->el >= 2 && (ri->vhe_redir_to_el2 || ri->vhe_redir_to_el01)) ||
        (ri->type & (ARM_CP_FPMR | ARM_CP_SVE | ARM_CP_SME)) ||
        ((ri->type & ARM_CP_FPU) && c->fp_excp_el)) {
        return UNKNOWN;
    }
    check = ri->accessfn || (ri->fgt && c->fgt);

    switch (ri->type & ARM_CP_SPECIAL_MASK) {
    case 0:
        break;
    case ARM_CP_NOP:
        if (!check) {
            return NEXT;
        }
        /* fall through */
    case ARM_CP_NZCV:
    case ARM_CP_DC_ZVA:
        return call(c, G(call), aok_a64_helper_sysreg, NULL);
    case ARM_CP_CURRENTEL:
        if (!check) {
            E2(G(mov_const), wz(rt), c->el << 2);
            return NEXT;
        }
        return call(c, G(call), aok_a64_helper_sysreg, NULL);
    default:
        return UNKNOWN;
    }

    if (ri->type & ARM_CP_CONST) {
        if (ri->type & ARM_CP_IO) {
            return UNKNOWN;
        }
        if (!check) {
            if (isread) {
                E2(G(mov_const), wz(rt), ri->resetvalue);
            }
            return NEXT;
        }
        return call(c, G(call), aok_a64_helper_sysreg, NULL);
    }
    /* An access to a device, and a write, end the TB in the main loop. */
    ends = (ri->type & ARM_CP_IO) ||
           (!isread && !(ri->type & ARM_CP_SUPPRESS_TB_END));
    if (isread && !ends && !ri->readfn) {
        if (!check) {
            E2(G(umov64), wz(rt), ri->fieldoffset);
            return NEXT;
        }
        if (key == ENCODE_AA64_CP_REG(3, 0, 4, 1, 0) && !(ri->fgt && c->fgt)) {
            /* sp_el0, whose access function tests PSTATE.SP: the gadget does */
            E2(G(mrs_sp_el0), wz(rt), ri->fieldoffset);
            aok_emit(&c->g, (uintptr_t)aok_a64_helper_sysreg);
            aok_emit(&c->g, c->off);
            aok_emit(&c->g, c->insn);
            aok_emit(&c->g, 0);
            c->nf = false;
            return NEXT;
        }
    }
    return call(c, ends ? G(call_exit) : G(call), aok_a64_helper_sysreg, NULL);
}

/* ---- Branches, hints and exceptions ------------------------------------------- */

static int branch_sys(Ctx *c, uint32_t insn)
{
    unsigned rt = insn & 31, sf = insn >> 31;
    int64_t imm19 = sextract64(insn, 5, 19) << 2;

    if ((insn & 0x7c000000) == 0x14000000) {            /* b, bl */
        int64_t imm = sextract64(insn, 0, 26) << 2;

        if (insn >> 31) {
            emit(c, G(bl), 1, (uint64_t)c->off + 4);
        } else {
            E0(G(b));
        }
        way(c, 0, c->off + imm);
        return END;
    }
    if ((insn & 0xff000010) == 0x54000000) {            /* b.cond */
        unsigned cond = insn & 15;

        if (cond >= 14) {
            E0(G(b));
            way(c, 0, c->off + imm19);
        } else {
            E0(bcond_tab[c->nf][cond]);
            way(c, 0, c->off + imm19);
            way(c, 1, c->off + 4);
        }
        return END;
    }
    if ((insn & 0x7e000000) == 0x34000000) {            /* cbz, cbnz */
        emit(c, insn & (1 << 24) ? SF(cbnz) : SF(cbz), 1, rz(rt));
        way(c, 0, c->off + imm19);
        way(c, 1, c->off + 4);
        return END;
    }
    if ((insn & 0x7e000000) == 0x36000000) {            /* tbz, tbnz */
        unsigned bit = (insn >> 31) << 5 | ((insn >> 19) & 31);

        E2(insn & (1 << 24) ? G(tbnz) : G(tbz), rz(rt), 1ull << bit);
        way(c, 0, c->off + (sextract64(insn, 5, 14) << 2));
        way(c, 1, c->off + 4);
        return END;
    }
    if ((insn & 0xff9ffc1f) == 0xd61f0000 && ((insn >> 21) & 3) <= 2) {
        /*
         * br, blr, ret. On a CPU with BTI they set PSTATE.BTYPE, which is in
         * the next TB's flags: left to TCG there.
         */
        bool link = ((insn >> 21) & 3) == 1;
        unsigned rn = (insn >> 5) & 31;

        if (c->bti) {
            return UNKNOWN;
        }
        if (c->no_goto_ptr) {
            E3(link ? G(blr_exit) : G(br_exit), rz(rn), c->tbi, c->off + 4);
        } else {
            E3(link ? G(blr) : G(br), rz(rn), c->tbi, c->off + 4);
            aok_emit_lookup_operands(&c->g);
        }
        return END;
    }
    if ((insn & 0xfffff01f) == 0xd503201f) {            /* the hints */
        unsigned crm = (insn >> 8) & 15, op2 = (insn >> 5) & 7;

        switch (crm << 3 | op2) {
        case 1: case 2: case 3:                 /* yield, wfe, wfi */
        case 4: case 5:
            /*
             * sev, sevl: they set the event register a wfe waits for. A
             * kernel's "sevl; wfe" would sleep on a sevl that did nothing.
             */
            return UNKNOWN;
        case 7:                                 /* xpaclri */
            return c->pauth ? UNKNOWN : NEXT;
        case 8: case 10: case 12: case 14:      /* pacia1716 ... autib1716 */
        case 24 ... 31:                         /* paciaz ... autibsp */
            return c->pauth_active ? UNKNOWN : NEXT;
        case 16:                                /* esb */
            return c->ras ? UNKNOWN : NEXT;
        case 19:                                /* gcsb */
            return c->gcs ? UNKNOWN : NEXT;
        default:
            /*
             * The rest of the space is a NOP. That includes bti: PSTATE.BTYPE
             * is zero inside a TB, and a TB that starts with it nonzero is
             * TCG's. And chkfeat: so is one with a guarded control stack.
             */
            return NEXT;
        }
    }
    if ((insn & 0xfffff0ff) == 0xd503305f) {            /* clrex */
        E2(G(mov_const), offsetof(CPUARMState, exclusive_addr), -1);
        return NEXT;
    }
    if ((insn & 0xfffff0ff) == 0xd50330df) {
        /* isb: the TB ends, for an interrupt or new code to be seen */
        E0(G(b));
        way(c, 0, c->off + 4);
        return END;
    }
    if ((insn & 0xfffff0df) == 0xd50340df && !c->no_exc) {
        /*
         * msr daifset and daifclr. Masking more needs no look at what is
         * pending; unmasking does.
         */
        if (insn & (1 << 5)) {
            return call(c, G(call_exit), aok_a64_helper_msr_daif, NULL);
        }
        call(c, G(call), aok_a64_helper_msr_daif, NULL);
        E0(G(b));
        way(c, 0, c->off + 4);
        return END;
    }
    if ((insn & 0xffc00000) == 0xd5000000 && extract32(insn, 19, 2) &&
        !c->no_sys) {
        return sysreg(c, insn);
    }
    if ((insn & 0xffe0001f) == 0xd4000001 && !c->fgt_svc && !c->no_exc) {
        call(c, G(call), aok_a64_helper_svc, NULL);     /* (does not return) */
        return END;
    }
    if (insn == 0xd69f03e0 && c->el && !c->trap_eret && !c->no_exc) {
        return call(c, G(call_exit), aok_a64_helper_eret, NULL);
    }
    if ((insn & 0xfffff09f) == 0xd503309f && ((insn >> 5) & 7) < 6) {
        E0(G(barrier));                                 /* dsb, dmb */
        return NEXT;
    }
    return UNKNOWN;
}

/* ---- Loads and stores ---------------------------------------------------------- */

#define TAB13(s) { LOADS(ENTRY, s) STORES(ENTRY, s) }
enum { K_L8, K_L16, K_L32, K_L64, K_LS8_32, K_LS8_64, K_LS16_32, K_LS16_64,
       K_LS32_64, K_S8, K_S16, K_S32, K_S64, K_PRFM, K_NONE };

/* Which of the thirteen a single-register access is. */
static int ldst_kind(unsigned size, unsigned opc)
{
    switch (opc) {
    case 0:
        return K_S8 + size;
    case 1:
        return K_L8 + size;
    case 2:
        return size == 0 ? K_LS8_64 : size == 1 ? K_LS16_64
             : size == 2 ? K_LS32_64 : K_PRFM;
    default:
        return size == 0 ? K_LS8_32 : size == 1 ? K_LS16_32 : K_NONE;
    }
}

static int ldst(Ctx *c, uint32_t insn)
{
    static const Gadget imm_tab[13] = TAB13(_fast);
    static const Gadget rx_tab[3][13] = { TAB13(_rx0), TAB13(_rx1), TAB13(_rx2) };
    static const Gadget wb_tab[2][13] = { TAB13(_wb0), TAB13(_wb1) };
    static const Gadget user_tab[13] = TAB13(_user);
    unsigned rt = insn & 31, rn = (insn >> 5) & 31, size = insn >> 30;
    /* The host's word: where the insn is, and what it is. */
    uint64_t word = (uint64_t)c->off << 32 | insn;
    int kind;

    if (insn & (1 << 26)) {
        return UNKNOWN;     /* FP and SIMD registers */
    }
    c->nf = false;          /* (the fast path compares) */

    switch ((insn >> 27) & 7) {
    case 3: {   /* a literal */
        int64_t delta = c->off + (sextract64(insn, 5, 19) << 2);

        if (insn & (1 << 24)) {
            return UNKNOWN; /* ldapur, stlur */
        }
        if (size == 3) {
            return NEXT;    /* prfm */
        }
        E4(size == 0 ? G(load32_lit) : size == 1 ? G(load64_lit)
           : G(loads32_64_lit), wz(rt), delta, 0, word);
        return NEXT;
    }
    case 5: {   /* a pair: no-allocate, post-index, offset, pre-index */
        static const Gadget tab[2][3][2] = {    /* [load][mode][64] */
            { { G(stp32_fast), G(stp64_fast) }, { G(stp32_post), G(stp64_post) },
              { G(stp32_pre), G(stp64_pre) } },
            { { G(ldp32_fast), G(ldp64_fast) }, { G(ldp32_post), G(ldp64_post) },
              { G(ldp32_pre), G(ldp64_pre) } },
        };
        unsigned mode = (insn >> 23) & 3, rt2 = (insn >> 10) & 31;
        bool load = insn & (1 << 22), wb = mode & 1;
        int64_t imm = sextract64(insn, 15, 7) * (size ? 8 : 4);

        if (size & 1) {
            return UNKNOWN; /* ldpsw, stgp */
        }
        /* What the architecture leaves open is TCG's to decide. */
        if ((load && rt == rt2) || (wb && rn != 31 && (rn == rt || rn == rt2))) {
            return UNKNOWN;
        }
        E4(tab[load][mode == 1 ? 1 : mode == 3 ? 2 : 0][size >> 1],
           load ? wz(rt) | wz(rt2) << 16 : rz(rt) | rz(rt2) << 16,
           rsp(rn), imm, word);
        return NEXT;
    }
    case 1: {   /* exclusives, and the ordered loads and stores */
        bool o2 = insn & (1 << 23), load = insn & (1 << 22);
        bool o1 = insn & (1 << 21);
        static const Gadget ord[2][4] = {
            { G(store8_fast), G(store16_ord), G(store32_ord), G(store64_ord) },
            { G(load8_fast), G(load16_ord), G(load32_ord), G(load64_ord) },
        };

        /* (with LSE2 what must be aligned is another rule: TCG's) */
        if ((insn & (1 << 24)) || c->lse2 || c->no_atomic) {
            return UNKNOWN;
        }
        if (!o2) {
            if (o1 && (!(insn >> 31) || (!HAVE_CMPXCHG128 && (insn >> 30) == 3))) {
                return UNKNOWN;     /* casp; a pair of doublewords */
            }
            return call(c, G(call),
                        load ? aok_a64_helper_ldx : aok_a64_helper_stx, NULL);
        }
        /* ldar, stlr; the LORegion twins need a feature, cas is LSE's */
        if (o1 || !(insn & (1 << 15)) || ((insn >> 16) & 31) != 31 ||
            ((insn >> 10) & 31) != 31) {
            return UNKNOWN;
        }
        if (!load) {
            E0(G(barrier));
        }
        E4(ord[load][size], load ? wz(rt) : rz(rt), rsp(rn), 0, word);
        if (load) {
            E0(G(barrier));
        }
        return NEXT;
    }
    case 7:
        break;
    default:
        return UNKNOWN;
    }

    /* A single register. */
    kind = ldst_kind(size, (insn >> 22) & 3);
    if (kind == K_NONE) {
        return UNKNOWN;
    }
    if (insn & (1 << 24)) {                             /* unsigned offset */
        if (kind != K_PRFM) {
            E4(imm_tab[kind], kind >= K_S8 ? rz(rt) : wz(rt), rsp(rn),
               (uint64_t)extract32(insn, 10, 12) << size, word);
        }
        return NEXT;
    }
    if (insn & (1 << 21)) {                             /* register offset */
        unsigned option = (insn >> 13) & 7, rm = (insn >> 16) & 31;

        if (((insn >> 10) & 3) != 2 || !(option & 2)) {
            return UNKNOWN; /* atomics, pointer authentication */
        }
        if (kind != K_PRFM) {
            emit(c, rx_tab[option == 6 ? 1 : option == 2 ? 2 : 0][kind], 5,
                 kind >= K_S8 ? rz(rt) : wz(rt), rsp(rn), rz(rm),
                 (uint64_t)(insn & (1 << 12) ? size : 0), word);
        }
        return NEXT;
    }
    switch ((insn >> 10) & 3) {
    case 0:                                             /* unscaled offset */
        if (kind != K_PRFM) {
            E4(imm_tab[kind], kind >= K_S8 ? rz(rt) : wz(rt), rsp(rn),
               sextract64(insn, 12, 9), word);
        }
        return NEXT;
    case 2:
        /*
         * Unprivileged: where that means another translation regime, cputlb
         * makes the access; elsewhere it is the unscaled access.
         */
        if (kind == K_PRFM) {
            return UNKNOWN;
        }
        E4(c->unpriv ? user_tab[kind] : imm_tab[kind],
           kind >= K_S8 ? rz(rt) : wz(rt), rsp(rn), sextract64(insn, 12, 9),
           word);
        return NEXT;
    default:                                            /* post- and pre-index */
        if (kind == K_PRFM || (rn == rt && rn != 31)) {
            return UNKNOWN;
        }
        E4(wb_tab[(insn >> 11) & 1][kind], kind >= K_S8 ? rz(rt) : wz(rt),
           rsp(rn), sextract64(insn, 12, 9), word);
        return NEXT;
    }
}

/* ---- The translator ------------------------------------------------------------ */

int arm_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMTBFlags f = { tb->flags, tb->cs_base };
    uint32_t cflags = tb_cflags(tb);
    const uint8_t *code = host_pc;
    ARMMMUIdx mmu_idx;
    Ctx c = { 0 };
    int r = NEXT;

    /*
     * The states this translator knows: A64 with a little-endian guest and
     * 4 KiB pages, no single-stepping, no illegal-state exception pending,
     * no alignment or tag checks, no branch-target check owed for the first
     * insn, no guarded control stack and no nested virtualization. And an
     * ordinary TB: one in RAM that may check for interrupts and need not
     * stop after a set number of insns.
     */
    if (!code || !(cflags & CF_PCREL) || TARGET_PAGE_BITS != 12 ||
        (cflags & (CF_COUNT_MASK | CF_SINGLE_STEP | CF_MEMI_ONLY |
                   CF_USE_ICOUNT | CF_NOIRQ | CF_BP_PAGE | CF_STEP_ATOMIC)) ||
        !EX_TBFLAG_ANY(f, AARCH64_STATE) ||
        EX_TBFLAG_ANY(f, SS_ACTIVE) ||
        EX_TBFLAG_ANY(f, PSTATE__IL) ||
        EX_TBFLAG_ANY(f, BE_DATA) ||
        EX_TBFLAG_ANY(f, ALIGN_MEM) ||
        EX_TBFLAG_A64(f, BTYPE) ||
        EX_TBFLAG_A64(f, MTE_ACTIVE) ||
        EX_TBFLAG_A64(f, MTE0_ACTIVE) ||
        EX_TBFLAG_A64(f, GCS_EN) ||
        EX_TBFLAG_A64(f, NV)) {
        return 0;
    }

    c.page_off = pc & ~TARGET_PAGE_MASK;
    c.cpu = cpu;
    c.no_sys = getenv("QEMU_AOK_NO_SYS");
    c.no_exc = getenv("QEMU_AOK_NO_EXC");
    c.no_atomic = getenv("QEMU_AOK_NO_ATOMIC");
    c.fp_excp_el = EX_TBFLAG_ANY(f, FPEXC_EL);
    c.unpriv = EX_TBFLAG_A64(f, UNPRIV);
    c.trap_eret = EX_TBFLAG_A64(f, TRAP_ERET);
    c.fgt_svc = EX_TBFLAG_ANY(f, FGT_SVC);
    c.lse2 = cpu_isar_feature(aa64_lse2, cpu);
    c.ras = cpu_isar_feature(aa64_ras, cpu);
    c.gcs = cpu_isar_feature(aa64_gcs, cpu);
    c.bti = cpu_isar_feature(aa64_bti, cpu);
    c.pauth = cpu_isar_feature(aa64_pauth, cpu);
    c.pauth_active = EX_TBFLAG_A64(f, PAUTH_ACTIVE);
    c.fgt = EX_TBFLAG_ANY(f, FGT_ACTIVE);
    c.no_goto_ptr = cflags & CF_NO_GOTO_PTR;
    /* gadgets.S's a64_tbi: translate-a64.c's gen_top_byte_ignore(tbii). */
    mmu_idx = core_to_aa64_mmu_idx(EX_TBFLAG_ANY(f, MMUIDX));
    c.el = arm_mmu_idx_to_el(mmu_idx);
    c.tbi = EX_TBFLAG_A64(f, TBII);
    if (c.tbi && !regime_has_2_ranges(mmu_idx)) {
        c.tbi = 4;
    }
    aok_gen_begin(&c.g, cs, tb, *max_insns, EX_TBFLAG_ANY(f, MMUIDX));
    c.g.lookup = G(lookup);

    /* A TB stays in its page. */
    while (aok_gen_room(&c.g, 12) &&
           c.page_off + c.off + 4 <= TARGET_PAGE_SIZE) {
        uint64_t *start = c.g.p;
        uint32_t insn = ldl_le_p(code + c.off);

        c.insn = insn;
        switch ((insn >> 25) & 15) {
        case 8: case 9:
            r = dp_imm(&c, insn);
            break;
        case 10: case 11:
            r = branch_sys(&c, insn);
            break;
        case 4: case 6: case 12: case 14:
            r = ldst(&c, insn);
            break;
        case 5: case 13:
            r = dp_reg(&c, insn);
            break;
        default:        /* FP and SIMD, SVE, SME, the unallocated */
            r = UNKNOWN;
            break;
        }
        if (r == UNKNOWN) {
            c.g.p = start;
            break;
        }
        aok_gen_insn_end(&c.g, c.page_off + c.off, 0);
        c.off += 4;
        if (r == END) {
            break;
        }
    }
    if (c.g.n_insns == 0) {
        aok_stats.declined_first++;
        aok_stats.declined_op[(c.insn >> 24) & 0x7f]++;
        return 0;
    }
    if (r != END) {
        emit(&c, G(b), 0);
        way(&c, 0, c.off);
    }
    return aok_gen_finish(&c.g, c.off);
}
