/*
 * AOK gadgets for 32-bit PowerPC guests (qemu-system-ppc): the translator.
 *
 * It turns the instructions a program spends its time in -- integer
 * arithmetic and logic, compares, the condition register, loads and stores,
 * branches -- into a stream of gadgets (gadgets.S), and stops in front of
 * anything else, which TCG translates. What each instruction does is what
 * target/ppc/translate.c generates for it, QEMU's choices included where the
 * architecture leaves a result undefined; the gates compare the two
 * (docs/devel/aok-gadgets-ppc.rst).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "spr_common.h"
#include "exec/helper-proto.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "accel/tcg/aok.h"
#include "accel/tcg/cpu-ldst-common.h"
#include "aok-ppc.h"
#include "aok-ppc-asm.h"

#define G(name) aok_gadget_ppc_##name
#define DECL(name) void G(name)(void);

DECL(li) DECL(mov)
DECL(add) DECL(addi) DECL(subf) DECL(neg)
DECL(addc) DECL(addic) DECL(adde) DECL(addme) DECL(addze)
DECL(subfc) DECL(subfic) DECL(subfe) DECL(subfme) DECL(subfze)
DECL(mullw) DECL(mulli) DECL(mulhw) DECL(mulhwu) DECL(divw) DECL(divwu)
DECL(and) DECL(andi) DECL(andc) DECL(or) DECL(ori) DECL(orc)
DECL(xor) DECL(xori) DECL(nand) DECL(nor) DECL(eqv)
DECL(extsb) DECL(extsh) DECL(cntlzw)
DECL(slw) DECL(srw) DECL(sraw) DECL(srawi)
DECL(rlwinm) DECL(rlwimi) DECL(rlwnm)
DECL(cr0) DECL(cmp) DECL(cmpi) DECL(cmpl) DECL(cmpli)
DECL(crand) DECL(cror) DECL(crxor) DECL(crnand) DECL(crnor) DECL(creqv)
DECL(crandc) DECL(crorc)
DECL(mfcr) DECL(mtcrf) DECL(mfxer) DECL(mtxer) DECL(mcrxr) DECL(sync)
DECL(b) DECL(bl) DECL(set_lr) DECL(bc_t) DECL(bc_f) DECL(bdnz) DECL(bdz)
DECL(blr) DECL(blrl) DECL(bctr) DECL(bctrl)
DECL(blr_exit) DECL(blrl_exit) DECL(bctr_exit) DECL(bctrl_exit)
DECL(lookup) DECL(call)
#define LDST(n) DECL(n##_d) DECL(n##_x)
LDST(lbz) LDST(lhz) LDST(lha) LDST(lwz) LDST(lbzu) LDST(lhzu) LDST(lhau)
LDST(lwzu) LDST(stb) LDST(sth) LDST(stw) LDST(stbu) LDST(sthu) LDST(stwu)
DECL(lhbrx) DECL(lwbrx) DECL(sthbrx) DECL(stwbrx)
DECL(bdnzt) DECL(bdnzf) DECL(bdzt) DECL(bdzf) DECL(bclr_t) DECL(bclr_f)
LDST(lfs) LDST(lfsu) LDST(lfd) LDST(lfdu) LDST(stfs) LDST(stfsu)
LDST(stfd) LDST(stfdu) DECL(stfiwx)
DECL(fmr) DECL(fneg) DECL(fabs) DECL(fnabs) DECL(fsel) DECL(cr1)
DECL(fadd) DECL(fsub) DECL(fmul) DECL(fdiv) DECL(fsqrt)
DECL(fmadd) DECL(fmsub) DECL(fnmadd) DECL(fnmsub)
DECL(frsp) DECL(fctiw) DECL(fctiwz) DECL(fcmp) DECL(mffs)

typedef void (*Gadget)(void);

/*
 * Fused pairs (include/accel/tcg/aok.h): an op and its record form's CR0,
 * and a compare and the branch on the field it set. Operand 0 of the second
 * names the register the first wrote when the two belong together, and the
 * f2n_ form then takes it from the first's host register.
 */
#define RC_PAIRS(X) \
    X(add, 4) X(subf, 4) X(and, 4) X(andc, 4) X(or, 4) X(orc, 4) X(xor, 4) \
    X(nand, 4) X(nor, 4) X(eqv, 4) X(mullw, 4) X(slw, 4) X(srw, 4) \
    X(andi, 4) X(addic, 4) X(rlwinm, 4) X(srawi, 4) \
    X(neg, 3) X(extsb, 3) X(extsh, 3) X(cntlzw, 3) X(mov, 3)
#define CMP_PAIRS(X) \
    X(cmp, bc_t) X(cmpi, bc_t) X(cmpl, bc_t) X(cmpli, bc_t) \
    X(cmp, bc_f) X(cmpi, bc_f) X(cmpl, bc_f) X(cmpli, bc_f)
#define DECL_RC(a, w) void G(f2_##a##__cr0)(void); void G(f2n_##a##__cr0)(void);
#define DECL_CMP(a, b) void G(f2_##a##__##b)(void); void G(f2n_##a##__##b)(void);
RC_PAIRS(DECL_RC)
CMP_PAIRS(DECL_CMP)

static const AokPair ppc_pair_list[] = {
#define PAIR_RC(a, w) \
    { G(a), G(cr0), G(f2_##a##__cr0), { G(f2n_##a##__cr0) }, w, \
      { { 0, AOK_PAIR_OP_SLOT } } },
#define PAIR_CMP(a, b) \
    { G(a), G(b), G(f2_##a##__##b), { G(f2n_##a##__##b) }, 4, \
      { { 0, AOK_PAIR_OP_SLOT } } },
    RC_PAIRS(PAIR_RC)
    CMP_PAIRS(PAIR_CMP)
};

static AokPairSet ppc_pairs = { ppc_pair_list, ARRAY_SIZE(ppc_pair_list) };
static bool ppc_pairs_on;

static void __attribute__((constructor)) ppc_pairs_init(void)
{
    ppc_pairs_on = !getenv("QEMU_AOK_NO_PAIRS");
    ppc_pairs.forward = !getenv("QEMU_AOK_NO_FWD");
    aok_pair_set_init(&ppc_pairs);
}

/* What gadgets.S knows of CPUPPCState (aok-ppc-asm.h). */
QEMU_BUILD_BUG_ON(TARGET_LONG_BITS != 32);
QEMU_BUILD_BUG_ON(TARGET_PAGE_BITS != 12);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, gpr) != AOK_PPC_ENV_GPR);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, aok_zero) != AOK_PPC_ENV_AOK_ZERO);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, lr) != AOK_PPC_ENV_LR);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, ctr) != AOK_PPC_ENV_CTR);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, crf) != AOK_PPC_ENV_CRF);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, xer) != AOK_PPC_ENV_XER);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, so) != AOK_PPC_ENV_SO);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, ov) != AOK_PPC_ENV_OV);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, ca) != AOK_PPC_ENV_CA);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, ov32) != AOK_PPC_ENV_OV32);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, ca32) != AOK_PPC_ENV_CA32);
QEMU_BUILD_BUG_ON(CRF_LT != AOK_PPC_CR_LT || CRF_GT != AOK_PPC_CR_GT ||
                  CRF_EQ != AOK_PPC_CR_EQ || CRF_SO != AOK_PPC_CR_SO);
QEMU_BUILD_BUG_ON(offsetof(CPUPPCState, fpscr) != AOK_PPC_ENV_FPSCR);
QEMU_BUILD_BUG_ON(FP_FX != AOK_PPC_FPSCR_FX || FP_XX != AOK_PPC_FPSCR_XX ||
                  FP_FI != AOK_PPC_FPSCR_FI || FP_FPRF != AOK_PPC_FPSCR_FPRF ||
                  FP_FPCC != AOK_PPC_FPSCR_FPCC);
QEMU_BUILD_BUG_ON((FP_RN | FP_NI | FP_XE | FP_UE | FP_OE) != AOK_PPC_FPSCR_SLOW);

/*
 * The softmmu slow paths of the load and store gadgets, and the insns done
 * in C. Called with the insn's pc: an exception raised in here unwinds
 * nothing, so nip, which ppc_restore_state_to_opc would have recovered, is
 * stored first, and access_type, which TCG's code stores at the first
 * memory insn of each TB and the MMU reads on a fault.
 */
static inline void aok_ppc_sync_as(CPUPPCState *env, uint64_t pc, int type)
{
    aok_no_retaddr();
    env->nip = pc;
    env->access_type = type;
}

static inline void aok_ppc_sync(CPUPPCState *env, uint64_t pc)
{
    aok_ppc_sync_as(env, pc, ACCESS_INT);
}

#define OI(env, mop) make_memop_idx(mop, ppc_env_mmu_index(env, false))

/* The value comes back as the guest's register sees it, the gadget's to extend. */
#define LOAD_HELPER(name, fn, mop)                                          \
uint64_t aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr,            \
                               uint64_t pc, uint64_t insn);                 \
uint64_t aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr,            \
                               uint64_t pc, uint64_t insn)                  \
{                                                                           \
    aok_ppc_sync(env, pc);                                                  \
    return fn(env, addr, OI(env, mop), 0);                                  \
}
LOAD_HELPER(load8, cpu_ldb_mmu, MO_UB)
LOAD_HELPER(load16, cpu_ldw_mmu, MO_BEUW)
LOAD_HELPER(load32, cpu_ldl_mmu, MO_BEUL)
LOAD_HELPER(load16_le, cpu_ldw_mmu, MO_LEUW)
LOAD_HELPER(load32_le, cpu_ldl_mmu, MO_LEUL)

#define STORE_HELPER(name, fn, mop)                                         \
void aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr, uint64_t val,  \
                           uint64_t pc, uint64_t insn);                     \
void aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr, uint64_t val,  \
                           uint64_t pc, uint64_t insn)                      \
{                                                                           \
    aok_ppc_sync(env, pc);                                                  \
    fn(env, addr, val, OI(env, mop), 0);                                    \
}
STORE_HELPER(store8, cpu_stb_mmu, MO_UB)
STORE_HELPER(store16, cpu_stw_mmu, MO_BEUW)
STORE_HELPER(store32, cpu_stl_mmu, MO_BEUL)
STORE_HELPER(store16_le, cpu_stw_mmu, MO_LEUW)
STORE_HELPER(store32_le, cpu_stl_mmu, MO_LEUL)

/* The FP loads' and stores' (lfs's value is the single's bits, made a double after) */
#define FLOAD_HELPER(name, fn, mop)                                         \
uint64_t aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr,            \
                               uint64_t pc, uint64_t insn);                 \
uint64_t aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr,            \
                               uint64_t pc, uint64_t insn)                  \
{                                                                           \
    aok_ppc_sync_as(env, pc, ACCESS_FLOAT);                                 \
    return fn(env, addr, OI(env, mop), 0);                                  \
}
FLOAD_HELPER(fload32, cpu_ldl_mmu, MO_BEUL)
FLOAD_HELPER(fload64, cpu_ldq_mmu, MO_BEUQ)

#define FSTORE_HELPER(name, fn, mop)                                        \
void aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr, uint64_t val,  \
                           uint64_t pc, uint64_t insn);                     \
void aok_ppc_helper_##name(CPUPPCState *env, uint64_t addr, uint64_t val,  \
                           uint64_t pc, uint64_t insn)                      \
{                                                                           \
    aok_ppc_sync_as(env, pc, ACCESS_FLOAT);                                 \
    fn(env, addr, val, OI(env, mop), 0);                                    \
}
FSTORE_HELPER(fstore32, cpu_stl_mmu, MO_BEUL)
FSTORE_HELPER(fstore64, cpu_stq_mmu, MO_BEUQ)

/*
 * An FP arithmetic, compare or convert insn, as TCG's code does it
 * (translate/fp-impl.c.inc): softfloat's flags reset, the op's helper, the
 * FPR written, FPRF set from the result where the insn sets it, the flags
 * checked, which may trap. The FP gadgets' slow path, and all of the
 * single-precision ops and the estimates. A record form's CR1 is the gadget
 * after this one.
 */
void aok_ppc_helper_fp(CPUPPCState *env, uint64_t pc, uint64_t insn);
void aok_ppc_helper_fp(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned op = insn >> 26, xo = (insn >> 1) & 0x3ff, xo5 = xo & 31;
    unsigned t = (insn >> 21) & 31;
    uint64_t fa = *cpu_fpr_ptr(env, (insn >> 16) & 31);
    uint64_t fb = *cpu_fpr_ptr(env, (insn >> 11) & 31);
    uint64_t fc = *cpu_fpr_ptr(env, (insn >> 6) & 31);
    bool s = op == 59, fprf = true;
    uint64_t r;

    aok_no_retaddr();
    env->nip = pc;
    helper_reset_fpstatus(env);
    if (op == 63 && xo5 < 16) {
        switch (xo) {
        case 0:
            helper_FCMPU(env, fa, fb, t >> 2);
            helper_float_check_status(env);
            return;
        case 32:
            helper_FCMPO(env, fa, fb, t >> 2);
            helper_float_check_status(env);
            return;
        case 12:
            r = helper_FRSP(env, fb);
            break;
        case 14:
            r = helper_FCTIW(env, fb);
            fprf = false;
            break;
        case 15:
            r = helper_FCTIWZ(env, fb);
            fprf = false;
            break;
        default:
            g_assert_not_reached();
        }
    } else {
        switch (xo5) {
        case 18: r = s ? helper_FDIVS(env, fa, fb) : helper_FDIV(env, fa, fb); break;
        case 20: r = s ? helper_FSUBS(env, fa, fb) : helper_FSUB(env, fa, fb); break;
        case 21: r = s ? helper_FADDS(env, fa, fb) : helper_FADD(env, fa, fb); break;
        case 22: r = s ? helper_FSQRTS(env, fb) : helper_FSQRT(env, fb); break;
        case 24: r = helper_FRES(env, fb); break;
        case 25: r = s ? helper_FMULS(env, fa, fc) : helper_FMUL(env, fa, fc); break;
        case 26: r = helper_FRSQRTE(env, fb); break;
        case 28:
            r = s ? helper_FMSUBS(env, fa, fc, fb) : helper_FMSUB(env, fa, fc, fb);
            break;
        case 29:
            r = s ? helper_FMADDS(env, fa, fc, fb) : helper_FMADD(env, fa, fc, fb);
            break;
        case 30:
            r = s ? helper_FNMSUBS(env, fa, fc, fb)
                  : helper_FNMSUB(env, fa, fc, fb);
            break;
        case 31:
            r = s ? helper_FNMADDS(env, fa, fc, fb)
                  : helper_FNMADD(env, fa, fc, fb);
            break;
        default:
            g_assert_not_reached();
        }
    }
    *cpu_fpr_ptr(env, t) = r;
    if (fprf) {
        helper_compute_fprf_float64(env, r);
    }
    helper_float_check_status(env);
}

/*
 * mtfsf, mtfsfi, mtfsb0, mtfsb1, as gen_mtfsf and the rest: FPSCR through
 * QEMU's store (which sets softfloat's rounding mode from it), the record
 * form's CR1, and the check for a deferred trap, in that order.
 */
static void aok_ppc_mtfs(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned xo = (insn >> 1) & 0x3ff, crb = 31 - ((insn >> 21) & 31);
    bool check = true;

    aok_no_retaddr();
    env->nip = pc;
    switch (xo) {
    case 711:   /* mtfsf: FLM, or every field with L */
        helper_store_fpscr(env, *cpu_fpr_ptr(env, (insn >> 11) & 31),
                           (insn & (1 << 25)) ? 0xff : (insn >> 17) & 0xff);
        break;
    case 134: { /* mtfsfi */
        unsigned sh = 7 - ((insn >> 23) & 7);

        helper_store_fpscr(env, (uint64_t)((insn >> 12) & 0xf) << (4 * sh),
                           1 << sh);
        break;
    }
    case 70:    /* mtfsb0: no check */
        helper_reset_fpstatus(env);
        if (crb != FPSCR_FEX && crb != FPSCR_VX) {
            helper_fpscr_clrbit(env, crb);
        }
        check = false;
        break;
    case 38:    /* mtfsb1 */
        if (crb != FPSCR_FEX && crb != FPSCR_VX && crb != FPSCR_NI) {
            helper_fpscr_setbit(env, crb);
        }
        break;
    }
    if (insn & 1) {
        env->crf[1] = (uint32_t)env->fpscr >> FPSCR_OX;
    }
    if (check) {
        helper_fpscr_check_status(env);
    }
}

/* mftb, and mfspr of TBL or TBU: the time base, as TCG's helpers read it */
static void aok_ppc_mftb(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned f = (insn >> 11) & 0x3ff, tbr = ((f >> 5) & 0x1f) | ((f & 0x1f) << 5);

    env->gpr[(insn >> 21) & 31] = tbr == 268 ? helper_load_tbl(env)
                                             : helper_load_tbu(env);
}

/* (rA|0) + rB */
static inline target_ulong ea_x(CPUPPCState *env, uint64_t insn)
{
    unsigned ra = (insn >> 16) & 31;

    return (ra ? env->gpr[ra] : 0) + env->gpr[(insn >> 11) & 31];
}

/* dcbz: QEMU's helper, its 32-byte line */
static void aok_ppc_dcbz(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    target_ulong ea = ea_x(env, insn);

    aok_ppc_sync_as(env, pc, ACCESS_CACHE);
    helper_dcbz(env, ea, ppc_env_mmu_index(env, false));
}

/*
 * lwarx and stwcx., as TCG generates them where it runs one CPU at a time
 * (gen_load_locked, gen_conditional_store): an aligned load that sets the
 * reservation, and a store conditional on its address that loads and then
 * always stores, the new value if memory still holds the reserved one and
 * the old otherwise.
 */
static void aok_ppc_lwarx(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    target_ulong ea = ea_x(env, insn);
    uint32_t v;

    aok_ppc_sync_as(env, pc, ACCESS_RES);
    v = cpu_ldl_mmu(env, ea, OI(env, MO_BEUL | MO_ALIGN), 0);
    env->gpr[(insn >> 21) & 31] = v;
    env->reserve_addr = ea;
    env->reserve_length = 4;
    env->reserve_val = v;
}

static void aok_ppc_stwcx(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    target_ulong ea = ea_x(env, insn);
    uint32_t cr0 = env->so;

    aok_ppc_sync_as(env, pc, ACCESS_RES);
    if (ea == env->reserve_addr && env->reserve_length == 4) {
        MemOpIdx oi = OI(env, MO_BEUL | MO_ALIGN);
        uint32_t old = cpu_ldl_mmu(env, ea, oi, 0);
        bool ok = old == env->reserve_val;

        cpu_stl_mmu(env, ea, ok ? env->gpr[(insn >> 21) & 31] : old, oi, 0);
        cr0 |= ok ? CRF_EQ : 0;
    }
    env->crf[0] = cr0;
    env->reserve_addr = -1;
}

/* lmw, stmw: QEMU's own helpers, at (rA|0) + d (TCG checks no form of them). */
static void aok_ppc_lmw(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned rd = (insn >> 21) & 31, ra = (insn >> 16) & 31;
    target_ulong ea = (ra ? env->gpr[ra] : 0) + (int16_t)insn;

    aok_ppc_sync(env, pc);
    helper_lmw(env, ea, rd);
}

static void aok_ppc_stmw(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned rs = (insn >> 21) & 31, ra = (insn >> 16) & 31;
    target_ulong ea = (ra ? env->gpr[ra] : 0) + (int16_t)insn;

    aok_ppc_sync(env, pc);
    helper_stmw(env, ea, rs);
}

typedef struct Ctx {
    AokGen g;
    uint32_t pc;            /* of the TB's first insn */
    unsigned page_off;      /* of the TB's first insn in its page */
    unsigned off;           /* of the current insn from the TB's first */
    uint32_t insn;
    bool pr;                /* user mode (MSR[PR]) */
    bool fp;                /* the FPU on (MSR[FP]); else FP insns are TCG's to trap */
    CPUPPCState *env;
    /* Where each gadget of the current insn began: the steps aok_gen_pair takes. */
    uint64_t *gs[8];
    int ngs;
    bool no_goto_ptr;
} Ctx;

/* What translating one insn came to. */
enum { UNKNOWN, NEXT, END };

static inline void emitg(Ctx *c, Gadget gadget)
{
    if (c->ngs < ARRAY_SIZE(c->gs)) {
        c->gs[c->ngs++] = c->g.p;
    }
    aok_emit_gadget(&c->g, gadget);
}

/* The insn's gadgets, in order, offered to the pair table */
static void pair_steps(Ctx *c)
{
    for (int i = 0; ppc_pairs_on && i < c->ngs; i++) {
        uint64_t *end = c->g.p;

        aok_gen_pair(&c->g, c->gs[i], &ppc_pairs);
        if (c->g.p != end) {
            /* fused: the gadget's word is gone, and what followed moved up */
            for (int j = i + 1; j < c->ngs; j++) {
                c->gs[j]--;
            }
        }
    }
    c->ngs = 0;
}

static inline uint64_t gpr(unsigned r)
{
    return offsetof(CPUPPCState, gpr[r]);
}

/* (rA|0): r0 as a base reads aok_zero */
static inline uint64_t base(unsigned r)
{
    return r ? gpr(r) : offsetof(CPUPPCState, aok_zero);
}

static inline uint64_t crf(unsigned n)
{
    return offsetof(CPUPPCState, crf[n]);
}

static void emit2(Ctx *c, Gadget gadget, uint64_t a, uint64_t b)
{
    emitg(c, gadget);
    aok_emit(&c->g, a);
    aok_emit(&c->g, b);
}

static void emit3(Ctx *c, Gadget gadget, uint64_t a, uint64_t b, uint64_t d)
{
    emit2(c, gadget, a, b);
    aok_emit(&c->g, d);
}

/* The record form's CR0, from the register just written */
static int rc(Ctx *c, unsigned r)
{
    if (c->insn & 1) {
        emitg(c, G(cr0));
        aok_emit(&c->g, gpr(r));
    }
    return NEXT;
}

static int rr(Ctx *c, Gadget gadget, unsigned d, unsigned a, unsigned b)
{
    emit3(c, gadget, gpr(d), gpr(a), gpr(b));
    return rc(c, d);
}

static int r1(Ctx *c, Gadget gadget, unsigned d, unsigned a)
{
    emit2(c, gadget, gpr(d), gpr(a));
    return rc(c, d);
}

static int ri(Ctx *c, Gadget gadget, unsigned d, unsigned a, uint64_t imm)
{
    emit3(c, gadget, gpr(d), gpr(a), imm);
    return NEXT;
}

static int li(Ctx *c, unsigned d, uint32_t value)
{
    emit2(c, G(li), gpr(d), value);
    return NEXT;
}

/* MASK(mb, me) in IBM bit numbering, as internal.h's for 32 bits */
static uint32_t mask32(unsigned mb, unsigned me)
{
    uint32_t m;

    if (mb == 0) {
        return 0xffffffffu << (31 - me);
    }
    if (me == 31) {
        return 0xffffffffu >> mb;
    }
    m = (0xffffffffu >> mb) ^ ((0xffffffffu >> me) >> 1);
    return mb > me ? ~m : m;
}

/*
 * The last operand of a load or store: what the slow path needs to name the
 * insn should it fault.
 */
static inline uint64_t mem_word(Ctx *c)
{
    return (uint64_t)c->off << 32 | c->insn;
}

static int ldst(Ctx *c, Gadget gadget, unsigned rt, unsigned ra, uint64_t third)
{
    emitg(c, gadget);
    aok_emit(&c->g, gpr(rt));
    aok_emit(&c->g, base(ra));
    aok_emit(&c->g, third);
    aok_emit(&c->g, mem_word(c));
    return NEXT;
}

/*
 * A D-form load or store (opcodes 32-45). The update forms that QEMU takes
 * for illegal (a load's rA of 0 or rD, a store's rA of 0) are TCG's to raise.
 */
static int dform(Ctx *c, unsigned op, unsigned rt, unsigned ra, int32_t d)
{
    static const Gadget g[14] = {
        G(lwz_d), G(lwzu_d), G(lbz_d), G(lbzu_d), G(stw_d), G(stwu_d),
        G(stb_d), G(stbu_d), G(lhz_d), G(lhzu_d), G(lha_d), G(lhau_d),
        G(sth_d), G(sthu_d),
    };
    unsigned i = op - 32;
    bool update = i & 1, store = (i >= 4 && i < 8) || i >= 12;

    if (update && (ra == 0 || (!store && ra == rt))) {
        return UNKNOWN;
    }
    return ldst(c, g[i], rt, ra, (int64_t)d);
}

/* An X-form one, by its own gadget; rB's offset is the third operand */
static int xform(Ctx *c, Gadget gadget, bool update, bool store, unsigned rt,
                 unsigned ra, unsigned rb)
{
    if (update && (ra == 0 || (!store && ra == rt))) {
        return UNKNOWN;
    }
    return ldst(c, gadget, rt, ra, gpr(rb));
}

/* A call to C: [function][pc delta][insn] */
static int call(Ctx *c, void (*fn)(CPUPPCState *, uint64_t, uint64_t))
{
    emitg(c, G(call));
    aok_emit(&c->g, (uintptr_t)fn);
    aok_emit(&c->g, c->off);
    aok_emit(&c->g, c->insn);
    return NEXT;
}

static inline uint64_t fpr(unsigned r)
{
    return fpr_offset(r);
}

/* A record form's CR1, from FPSCR */
static int rc1(Ctx *c)
{
    if (c->insn & 1) {
        emitg(c, G(cr1));
    }
    return NEXT;
}

/* FP loads and stores: the integer ones' streams, on an FPR. An update form's rA of 0 is illegal. */
static int fldst(Ctx *c, Gadget gadget, bool update, unsigned ft, unsigned ra,
                 uint64_t third)
{
    if (!c->fp || (update && ra == 0)) {
        return UNKNOWN;
    }
    emitg(c, gadget);
    aok_emit(&c->g, fpr(ft));
    aok_emit(&c->g, base(ra));
    aok_emit(&c->g, third);
    aok_emit(&c->g, mem_word(c));
    return NEXT;
}

/* The FP insns of opcodes 59 and 63 */
static int fp_op(Ctx *c, unsigned op)
{
    uint32_t insn = c->insn;
    unsigned xo = (insn >> 1) & 0x3ff, xo5 = xo & 31;
    unsigned t = (insn >> 21) & 31, a = (insn >> 16) & 31;
    unsigned b = (insn >> 11) & 31, cc = (insn >> 6) & 31;
    Gadget gadget = NULL;

    if (!c->fp) {
        return UNKNOWN;
    }
    if (op == 63 && xo5 < 16) {
        switch (xo) {
        case 0: case 32:    /* fcmpu, fcmpo */
            emitg(c, G(fcmp));
            aok_emit(&c->g, crf(t >> 2));
            aok_emit(&c->g, fpr(a));
            aok_emit(&c->g, fpr(b));
            aok_emit(&c->g, mem_word(c));
            return NEXT;
        case 12: gadget = G(frsp); break;
        case 14: gadget = G(fctiw); break;
        case 15: gadget = G(fctiwz); break;
        case 40: emit2(c, G(fneg), fpr(t), fpr(b)); return rc1(c);
        case 72: emit2(c, G(fmr), fpr(t), fpr(b)); return rc1(c);
        case 136: emit2(c, G(fnabs), fpr(t), fpr(b)); return rc1(c);
        case 264: emit2(c, G(fabs), fpr(t), fpr(b)); return rc1(c);
        case 583:   /* mffs (bits 20..11 are ignored before ISA 3.0) */
            emitg(c, G(mffs));
            aok_emit(&c->g, fpr(t));
            return rc1(c);
        case 711:   /* mtfsf; W is ISA 2.05's, illegal on a G4 */
            return (insn & (1 << 16)) ? UNKNOWN : call(c, aok_ppc_mtfs);
        case 134:   /* mtfsfi */
            return (insn & 0x006f0800) ? UNKNOWN : call(c, aok_ppc_mtfs);
        case 70: case 38:   /* mtfsb0, mtfsb1 */
            return (insn & 0x001ff800) ? UNKNOWN : call(c, aok_ppc_mtfs);
        default:
            return UNKNOWN;     /* mcrfs */
        }
        emit2(c, gadget, fpr(t), fpr(b));
        aok_emit(&c->g, mem_word(c));
        return rc1(c);
    }
    if (op == 59) {
        /* single precision, and fres: QEMU's helpers (aok_ppc_helper_fp) */
        switch (xo5) {
        case 18: case 20: case 21: case 22: case 24: case 25:
        case 28: case 29: case 30: case 31:
            call(c, aok_ppc_helper_fp);
            return rc1(c);
        }
        return UNKNOWN;
    }
    switch (xo5) {
    case 18: gadget = G(fdiv); break;
    case 20: gadget = G(fsub); break;
    case 21: gadget = G(fadd); break;
    case 25:
        emit3(c, G(fmul), fpr(t), fpr(a), fpr(cc));
        aok_emit(&c->g, mem_word(c));
        return rc1(c);
    case 22:
        emit2(c, G(fsqrt), fpr(t), fpr(b));
        aok_emit(&c->g, mem_word(c));
        return rc1(c);
    case 23:
        emit3(c, G(fsel), fpr(t), fpr(a), fpr(cc));
        aok_emit(&c->g, fpr(b));
        return rc1(c);
    case 26:
        call(c, aok_ppc_helper_fp);     /* frsqrte */
        return rc1(c);
    case 28: case 29: case 30: case 31: {
        static const Gadget m[4] = { G(fmsub), G(fmadd), G(fnmsub), G(fnmadd) };

        emit3(c, m[xo5 - 28], fpr(t), fpr(a), fpr(cc));
        aok_emit(&c->g, fpr(b));
        aok_emit(&c->g, mem_word(c));
        return rc1(c);
    }
    default:
        return UNKNOWN;
    }
    emit3(c, gadget, fpr(t), fpr(a), fpr(b));
    aok_emit(&c->g, mem_word(c));
    return rc1(c);
}

/*
 * The [pc delta][slot] of a jump to @dest. As with goto_tb, only a
 * destination in the TB's own page may be linked; any other is looked up
 * each time.
 */
static void way(Ctx *c, int n, uint32_t dest)
{
    aok_emit(&c->g, (uint32_t)(dest - c->pc));
    if ((dest & TARGET_PAGE_MASK) == (c->pc & TARGET_PAGE_MASK)) {
        aok_emit(&c->g, aok_slot(&c->g, n));
    } else {
        aok_emit(&c->g, aok_slot_unlinked(&c->g));
    }
}

static inline uint32_t cia(Ctx *c)
{
    return c->pc + c->off;
}

/* b, ba, bl, bla */
static int branch(Ctx *c)
{
    int32_t li = (int32_t)((c->insn & 0x03fffffc) << 6) >> 6;
    uint32_t dest = (c->insn & 2) ? li : cia(c) + li;

    if (c->insn & 1) {
        emitg(c, G(bl));
        aok_emit(&c->g, (uint32_t)(cia(c) + 4 - c->pc));
    } else {
        emitg(c, G(b));
    }
    way(c, 0, dest);
    return END;
}

/* bc: on a CR bit, or on CTR; both at once is TCG's */
static int bc(Ctx *c)
{
    unsigned bo = (c->insn >> 21) & 31, bi = (c->insn >> 16) & 31;
    int32_t bd = (int16_t)(c->insn & 0xfffc);
    uint32_t dest = (c->insn & 2) ? bd : cia(c) + bd;
    Gadget gadget;

    if ((bo & 0x14) == 0x14) {
        /* always: a b, or a bl (bcl 20,31: the PIC idiom) */
        if (c->insn & 1) {
            emitg(c, G(bl));
            aok_emit(&c->g, (uint32_t)(cia(c) + 4 - c->pc));
        } else {
            emitg(c, G(b));
        }
        way(c, 0, dest);
        return END;
    }
    if (bo & 0x04) {
        gadget = (bo & 0x08) ? G(bc_t) : G(bc_f);     /* on a CR bit */
    } else if (bo & 0x10) {
        gadget = (bo & 0x02) ? G(bdz) : G(bdnz);      /* on CTR, decremented first */
    } else if (bo & 0x02) {
        gadget = (bo & 0x08) ? G(bdzt) : G(bdzf);     /* on both */
    } else {
        gadget = (bo & 0x08) ? G(bdnzt) : G(bdnzf);
    }
    if (c->insn & 1) {
        emitg(c, G(set_lr));
        aok_emit(&c->g, (uint32_t)(cia(c) + 4 - c->pc));
    }
    emitg(c, gadget);
    if (!(bo & 0x10)) {
        aok_emit(&c->g, crf(bi >> 2));
        aok_emit(&c->g, 8 >> (bi & 3));
    }
    way(c, 0, dest);
    way(c, 1, cia(c) + 4);
    return END;
}

/* bclr and bcctr that always branch: blr, blrl, bctr, bctrl */
static int indirect(Ctx *c, bool ctr)
{
    unsigned bo = (c->insn >> 21) & 31;
    bool lk = c->insn & 1;
    static const Gadget look[2][2] = {
        { G(blr), G(blrl) }, { G(bctr), G(bctrl) },
    };
    static const Gadget exit[2][2] = {
        { G(blr_exit), G(blrl_exit) }, { G(bctr_exit), G(bctrl_exit) },
    };

    if ((bo & 0x14) == 0x04 && !ctr && !lk && !c->no_goto_ptr) {
        /* beqlr and the like: on a CR bit alone */
        unsigned bi = (c->insn >> 16) & 31;

        emitg(c, (bo & 0x08) ? G(bclr_t) : G(bclr_f));
        aok_emit(&c->g, crf(bi >> 2));
        aok_emit(&c->g, 8 >> (bi & 3));
        way(c, 1, cia(c) + 4);
        aok_emit_lookup_operands(&c->g);
        return END;
    }
    if ((bo & 0x14) != 0x14) {
        return UNKNOWN;
    }
    emitg(c, (c->no_goto_ptr ? exit : look)[ctr][lk]);
    if (lk) {
        aok_emit(&c->g, (uint32_t)(cia(c) + 4 - c->pc));
    }
    if (c->no_goto_ptr) {
        emitg(c, aok_gadget_exit_tb);
        aok_emit(&c->g, 0);
    } else {
        aok_emit_lookup_operands(&c->g);
    }
    return END;
}

/* opcode 19: branches to LR and CTR, and the CR's own insns */
static int op19(Ctx *c)
{
    uint32_t insn = c->insn;
    unsigned xo = (insn >> 1) & 0x3ff;
    unsigned d = (insn >> 21) & 31, a = (insn >> 16) & 31, b = (insn >> 11) & 31;
    Gadget gadget;

    if ((xo & 0x1f) == 0) {
        /* mcrf, whatever bits 10..6 hold */
        if (insn & 1) {
            return UNKNOWN;
        }
        emit2(c, G(mov), crf((insn >> 23) & 7), crf((insn >> 18) & 7));
        return NEXT;
    }
    switch (xo) {
    case 16:
        return indirect(c, false);
    case 528:
        return indirect(c, true);
    case 257: gadget = G(crand); break;
    case 129: gadget = G(crandc); break;
    case 289: gadget = G(creqv); break;
    case 225: gadget = G(crnand); break;
    case 33: gadget = G(crnor); break;
    case 449: gadget = G(cror); break;
    case 417: gadget = G(crorc); break;
    case 193: gadget = G(crxor); break;
    default:
        return UNKNOWN;
    }
    if (insn & 1) {
        return UNKNOWN;
    }
    emitg(c, gadget);
    aok_emit(&c->g, crf(d >> 2));
    aok_emit(&c->g, crf(a >> 2));
    aok_emit(&c->g, crf(b >> 2));
    aok_emit(&c->g, (3 - (d & 3)) | (3 - (a & 3)) << 8 | (3 - (b & 3)) << 16);
    return NEXT;
}

/* The SPR number of mfspr/mtspr: its two halves swapped */
static inline unsigned spr(uint32_t insn)
{
    unsigned f = (insn >> 11) & 0x3ff;

    return ((f >> 5) & 0x1f) | ((f & 0x1f) << 5);
}

/*
 * An SPR whose callback for this privilege is the generic one (VRSAVE, and
 * in supervisor mode the SPRGs, SRR0, SRR1 ...): a load or store of
 * env->spr[], as spr_read_generic and spr_write_generic generate.
 */
static bool spr_generic(Ctx *c, unsigned sprn, bool write)
{
    ppc_spr_t *cb = &c->env->spr_cb[sprn];

    /* (on a G4 ctx->hv is always set: supervisor mode uses the hea_ callbacks) */
    if (write) {
        return (c->pr ? cb->uea_write : cb->hea_write) == spr_write_generic;
    }
    return (c->pr ? cb->uea_read : cb->hea_read) == spr_read_generic;
}

/* opcode 31: the X and XO forms */
static int op31(Ctx *c)
{
    uint32_t insn = c->insn;
    unsigned xo = (insn >> 1) & 0x3ff, xo9 = xo & 0x1ff;
    unsigned d = (insn >> 21) & 31, a = (insn >> 16) & 31, b = (insn >> 11) & 31;
    bool oe = insn & 0x400;

    /* XO-form arithmetic. With OE set (OV and SO) it is TCG's for now. */
    switch (xo9) {
    case 75:    /* mulhw and mulhwu ignore OE */
        return rr(c, G(mulhw), d, a, b);
    case 11:
        return rr(c, G(mulhwu), d, a, b);
    case 266: case 10: case 138: case 234: case 202: case 40: case 8:
    case 136: case 232: case 200: case 104: case 235: case 491: case 459:
        if (oe) {
            return UNKNOWN;
        }
        switch (xo9) {
        case 266: return rr(c, G(add), d, a, b);
        case 10: return rr(c, G(addc), d, a, b);
        case 138: return rr(c, G(adde), d, a, b);
        case 234: return r1(c, G(addme), d, a);
        case 202: return r1(c, G(addze), d, a);
        case 40: return rr(c, G(subf), d, a, b);
        case 8: return rr(c, G(subfc), d, a, b);
        case 136: return rr(c, G(subfe), d, a, b);
        case 232: return r1(c, G(subfme), d, a);
        case 200: return r1(c, G(subfze), d, a);
        case 104: return r1(c, G(neg), d, a);
        case 235: return rr(c, G(mullw), d, a, b);
        case 491: return rr(c, G(divw), d, a, b);
        case 459: return rr(c, G(divwu), d, a, b);
        }
    }

    switch (xo) {
    /* logical: rA = op(rS, rB), the rS field in d's place */
    case 28: return rr(c, G(and), a, d, b);
    case 60: return rr(c, G(andc), a, d, b);
    case 476: return rr(c, G(nand), a, d, b);
    case 412: return rr(c, G(orc), a, d, b);
    case 124: return rr(c, G(nor), a, d, b);
    case 284: return rr(c, G(eqv), a, d, b);
    case 316: return rr(c, G(xor), a, d, b);
    case 444:
        if (d == b) {
            /* mr; or rA,rA,rA without Rc does nothing */
            if (d != a) {
                emit2(c, G(mov), gpr(a), gpr(d));
            }
            return rc(c, a);
        }
        return rr(c, G(or), a, d, b);
    case 954: return r1(c, G(extsb), a, d);
    case 922: return r1(c, G(extsh), a, d);
    case 26: return r1(c, G(cntlzw), a, d);
    case 24: return rr(c, G(slw), a, d, b);
    case 536: return rr(c, G(srw), a, d, b);
    case 792: return rr(c, G(sraw), a, d, b);
    case 824:
        emit3(c, G(srawi), gpr(a), gpr(d), b);
        return rc(c, a);

    /* compares: bits 22 (L, which a G4 ignores) and 0 are don't-cares */
    case 0:
        emit3(c, G(cmp), crf(d >> 2), gpr(a), gpr(b));
        return NEXT;
    case 32:
        emit3(c, G(cmpl), crf(d >> 2), gpr(a), gpr(b));
        return NEXT;

    /* the CR and XER, LR and CTR */
    case 19:    /* mfcr; the mfocrf form (bit 20) is TCG's */
        if (insn & 0x00100801) {
            return UNKNOWN;
        }
        emitg(c, G(mfcr));
        aok_emit(&c->g, gpr(d));
        return NEXT;
    case 144:   /* mtcrf; mtocrf likewise */
        if (insn & 0x00100801) {
            return UNKNOWN;
        }
        emit2(c, G(mtcrf), gpr(d), (insn >> 12) & 0xff);
        return NEXT;
    case 512:   /* mcrxr */
        if (insn & 0x007ff801) {
            return UNKNOWN;
        }
        emitg(c, G(mcrxr));
        aok_emit(&c->g, crf(d >> 2));
        return NEXT;
    case 339:   /* mfspr */
        if (insn & 1) {
            return UNKNOWN;
        }
        switch (spr(insn)) {
        case 268: case 269:
            return call(c, aok_ppc_mftb);
        case 1:
            emitg(c, G(mfxer));
            aok_emit(&c->g, gpr(d));
            return NEXT;
        case 8:
            emit2(c, G(mov), gpr(d), offsetof(CPUPPCState, lr));
            return NEXT;
        case 9:
            emit2(c, G(mov), gpr(d), offsetof(CPUPPCState, ctr));
            return NEXT;
        }
        if (spr_generic(c, spr(insn), false)) {
            emit2(c, G(mov), gpr(d), offsetof(CPUPPCState, spr[spr(insn)]));
            return NEXT;
        }
        return UNKNOWN;
    case 467:   /* mtspr (Rc is ignored) */
        switch (spr(insn)) {
        case 1:
            emitg(c, G(mtxer));
            aok_emit(&c->g, gpr(d));
            return NEXT;
        case 8:
            emit2(c, G(mov), offsetof(CPUPPCState, lr), gpr(d));
            return NEXT;
        case 9:
            emit2(c, G(mov), offsetof(CPUPPCState, ctr), gpr(d));
            return NEXT;
        }
        if (spr_generic(c, spr(insn), true)) {
            emit2(c, G(mov), offsetof(CPUPPCState, spr[spr(insn)]), gpr(d));
            return NEXT;
        }
        return UNKNOWN;

    /* X-form loads and stores (bit 0 a don't-care but in lhbrx and lwbrx) */
    case 23: return xform(c, G(lwz_x), false, false, d, a, b);
    case 55: return xform(c, G(lwzu_x), true, false, d, a, b);
    case 87: return xform(c, G(lbz_x), false, false, d, a, b);
    case 119: return xform(c, G(lbzu_x), true, false, d, a, b);
    case 279: return xform(c, G(lhz_x), false, false, d, a, b);
    case 311: return xform(c, G(lhzu_x), true, false, d, a, b);
    case 343: return xform(c, G(lha_x), false, false, d, a, b);
    case 375: return xform(c, G(lhau_x), true, false, d, a, b);
    case 151: return xform(c, G(stw_x), false, true, d, a, b);
    case 183: return xform(c, G(stwu_x), true, true, d, a, b);
    case 215: return xform(c, G(stb_x), false, true, d, a, b);
    case 247: return xform(c, G(stbu_x), true, true, d, a, b);
    case 407: return xform(c, G(sth_x), false, true, d, a, b);
    case 439: return xform(c, G(sthu_x), true, true, d, a, b);
    case 534:
        return insn & 1 ? UNKNOWN : xform(c, G(lwbrx), false, false, d, a, b);
    case 790:
        return insn & 1 ? UNKNOWN : xform(c, G(lhbrx), false, false, d, a, b);
    case 662: return xform(c, G(stwbrx), false, true, d, a, b);
    case 918: return xform(c, G(sthbrx), false, true, d, a, b);

    /* sync in user mode, and eieio: barriers. sync in supervisor mode is TCG's */
    case 598:
        if (!c->pr) {
            return UNKNOWN;
        }
        emitg(c, G(sync));
        return NEXT;
    case 854:
        emitg(c, G(sync));
        return NEXT;
    /* dcbt, dcbtst: nothing (Rc is illegal) */
    case 278: case 246:
        return insn & 1 ? UNKNOWN : NEXT;
    case 371:   /* mftb, of TBL or TBU (any other number reads that SPR) */
        if ((insn & 1) || (spr(insn) != 268 && spr(insn) != 269)) {
            return UNKNOWN;
        }
        return call(c, aok_ppc_mftb);
    case 4:     /* tw: with TO 0, nothing */
        return d ? UNKNOWN : NEXT;
    case 1014:  /* dcbz (bit 21, dcbzl's, is ignored on a G4) */
        return (insn & 0x03c00001) ? UNKNOWN : call(c, aok_ppc_dcbz);
    case 20:    /* lwarx (EH ignored) */
        return call(c, aok_ppc_lwarx);
    case 150:   /* stwcx. (with Rc 0 too) */
        return call(c, aok_ppc_stwcx);

    /* FP X-form loads and stores */
    case 535: return fldst(c, G(lfs_x), false, d, a, gpr(b));
    case 567: return fldst(c, G(lfsu_x), true, d, a, gpr(b));
    case 599: return fldst(c, G(lfd_x), false, d, a, gpr(b));
    case 631: return fldst(c, G(lfdu_x), true, d, a, gpr(b));
    case 663: return fldst(c, G(stfs_x), false, d, a, gpr(b));
    case 695: return fldst(c, G(stfsu_x), true, d, a, gpr(b));
    case 727: return fldst(c, G(stfd_x), false, d, a, gpr(b));
    case 759: return fldst(c, G(stfdu_x), true, d, a, gpr(b));
    case 983: return fldst(c, G(stfiwx), false, d, a, gpr(b));
    }
    return UNKNOWN;
}

static int insn32(Ctx *c)
{
    uint32_t insn = c->insn;
    unsigned op = insn >> 26;
    unsigned d = (insn >> 21) & 31, a = (insn >> 16) & 31, b = (insn >> 11) & 31;
    int32_t simm = (int16_t)insn;
    uint32_t uimm = insn & 0xffff;

    switch (op) {
    case 3:     /* twi: with TO 0, nothing */
        return d ? UNKNOWN : NEXT;
    case 7: return ri(c, G(mulli), d, a, simm);
    case 8: return ri(c, G(subfic), d, a, simm);
    case 10:
        emit3(c, G(cmpli), crf(d >> 2), gpr(a), uimm);
        return NEXT;
    case 11:
        emit3(c, G(cmpi), crf(d >> 2), gpr(a), simm);
        return NEXT;
    case 12:    /* addic: rA = 0 is r0 */
        return ri(c, G(addic), d, a, simm);
    case 13:    /* addic. */
        ri(c, G(addic), d, a, simm);
        emitg(c, G(cr0));
        aok_emit(&c->g, gpr(d));
        return NEXT;
    case 14:
        return a ? ri(c, G(addi), d, a, simm) : li(c, d, simm);
    case 15:
        return a ? ri(c, G(addi), d, a, (uint32_t)simm << 16)
                 : li(c, d, (uint32_t)simm << 16);
    case 16: return bc(c);
    case 18: return branch(c);
    case 19: return op19(c);
    case 20: case 21: {
        unsigned rot = (32 - b) & 31;
        uint64_t mask = mask32((insn >> 6) & 31, (insn >> 1) & 31);

        emit3(c, op == 20 ? G(rlwimi) : G(rlwinm), gpr(a), gpr(d),
              rot | mask << 32);
        return rc(c, a);
    }
    case 23:
        emit3(c, G(rlwnm), gpr(a), gpr(d), gpr(b));
        aok_emit(&c->g, mask32((insn >> 6) & 31, (insn >> 1) & 31));
        return rc(c, a);
    case 24:
        if (a == d && uimm == 0) {
            return NEXT;    /* nop: ori 0,0,0, and any ori rA,rA,0 */
        }
        return ri(c, G(ori), a, d, uimm);
    case 25: return ri(c, G(ori), a, d, uimm << 16);
    case 26: return ri(c, G(xori), a, d, uimm);
    case 27: return ri(c, G(xori), a, d, uimm << 16);
    case 28: case 29:   /* andi., andis.: always CR0 */
        ri(c, G(andi), a, d, op == 28 ? uimm : uimm << 16);
        emitg(c, G(cr0));
        aok_emit(&c->g, gpr(a));
        return NEXT;
    case 31: return op31(c);
    case 32 ... 45:
        return dform(c, op, d, a, simm);
    case 46: return call(c, aok_ppc_lmw);
    case 47: return call(c, aok_ppc_stmw);
    case 48: return fldst(c, G(lfs_d), false, d, a, (int64_t)simm);
    case 49: return fldst(c, G(lfsu_d), true, d, a, (int64_t)simm);
    case 50: return fldst(c, G(lfd_d), false, d, a, (int64_t)simm);
    case 51: return fldst(c, G(lfdu_d), true, d, a, (int64_t)simm);
    case 52: return fldst(c, G(stfs_d), false, d, a, (int64_t)simm);
    case 53: return fldst(c, G(stfsu_d), true, d, a, (int64_t)simm);
    case 54: return fldst(c, G(stfd_d), false, d, a, (int64_t)simm);
    case 55: return fldst(c, G(stfdu_d), true, d, a, (int64_t)simm);
    case 59: case 63:
        return fp_op(c, op);
    }
    return UNKNOWN;
}

int ppc_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc)
{
    uint32_t flags = tb->flags, cflags = tb_cflags(tb);
    const uint8_t *code = host_pc;
    Ctx c = { 0 };
    int r = NEXT;

    /*
     * The states this translator knows: a big-endian guest, not
     * single-stepped and not tracing branches (MSR[SE] and MSR[BE], which
     * TCG turns into trace exceptions). And an ordinary TB: one in RAM that
     * may check for interrupts and need not stop after a set number of insns.
     */
    if (!code ||
        (cflags & (CF_COUNT_MASK | CF_SINGLE_STEP | CF_MEMI_ONLY |
                   CF_USE_ICOUNT | CF_NOIRQ | CF_BP_PAGE | CF_STEP_ATOMIC)) ||
        (flags & ((1 << HFLAGS_LE) | (1 << HFLAGS_SE) | (1 << HFLAGS_BE)))) {
        return 0;
    }

    c.pc = pc;
    c.page_off = pc & ~TARGET_PAGE_MASK;
    c.pr = flags & (1 << HFLAGS_PR);
    c.fp = flags & (1 << HFLAGS_FP);
    c.env = cpu_env(cs);
    c.no_goto_ptr = cflags & CF_NO_GOTO_PTR;
    aok_gen_begin(&c.g, cs, tb, *max_insns, (flags >> HFLAGS_DMMU_IDX) & 7);
    c.g.lookup = G(lookup);

    /* A TB stays in its page, as TCG's do. */
    while (aok_gen_room(&c.g, 16) && c.page_off + c.off < TARGET_PAGE_SIZE) {
        uint64_t *start = c.g.p;

        c.insn = ldl_be_p(code + c.off);
        c.ngs = 0;
        r = insn32(&c);
        if (r == UNKNOWN) {
            c.g.p = start;
            break;
        }
        pair_steps(&c);
        aok_gen_insn_end(&c.g, cia(&c), c.insn);
        c.off += 4;
        if (r == END) {
            break;
        }
    }
    if (c.g.n_insns == 0) {
        aok_stats.declined_first++;
        aok_stats.declined_op[(c.insn >> 26) & 0x7f]++;
        return 0;
    }
    if (r != END) {
        /* Not an insn, but a gadget like another to the insn before it. */
        c.ngs = 0;
        emitg(&c, G(b));
        way(&c, 0, cia(&c));
        pair_steps(&c);
    }
    return aok_gen_finish(&c.g, c.off);
}
