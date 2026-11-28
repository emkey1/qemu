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
#include "helper_regs.h"
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
DECL(addo) DECL(addco) DECL(addeo) DECL(addmeo) DECL(addzeo)
DECL(subfo) DECL(subfco) DECL(subfeo) DECL(subfmeo) DECL(subfzeo)
DECL(nego) DECL(mullwo) DECL(divwo) DECL(divwuo)
DECL(bcctr_t) DECL(bcctr_f)
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
DECL(lookup) DECL(call) DECL(call_sync) DECL(call_leave) DECL(call_exit)
DECL(mfocrf) DECL(lvx) DECL(stvx)
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
DECL(fadds) DECL(fsubs) DECL(fmuls) DECL(fdivs)
DECL(fmadds) DECL(fmsubs) DECL(fnmadds) DECL(fnmsubs)
DECL(frsp) DECL(fctiw) DECL(fctiwz) DECL(fcmp) DECL(mffs)

/*
 * AltiVec's VX forms by their extended opcode, eleven bits: RR is [vD][vA]
 * [vB], SAT has the offset of vscr_sat after it, R1 is [vD][vB] (vA's field
 * is zero), FP and FP1 are RR and R1 with the insn after them, for C.
 */
#define VX_LIST(X) \
    X(0, RR, vaddubm) X(64, RR, vadduhm) X(128, RR, vadduwm) \
    X(384, RR, vaddcuw) X(1024, RR, vsububm) X(1088, RR, vsubuhm) \
    X(1152, RR, vsubuwm) X(1408, RR, vsubcuw) \
    X(2, RR, vmaxub) X(66, RR, vmaxuh) X(130, RR, vmaxuw) \
    X(258, RR, vmaxsb) X(322, RR, vmaxsh) X(386, RR, vmaxsw) \
    X(514, RR, vminub) X(578, RR, vminuh) X(642, RR, vminuw) \
    X(770, RR, vminsb) X(834, RR, vminsh) X(898, RR, vminsw) \
    X(1026, RR, vavgub) X(1090, RR, vavguh) X(1154, RR, vavguw) \
    X(1282, RR, vavgsb) X(1346, RR, vavgsh) X(1410, RR, vavgsw) \
    X(4, RR, vrlb) X(68, RR, vrlh) X(132, RR, vrlw) \
    X(260, RR, vslb) X(324, RR, vslh) X(388, RR, vslw) X(452, RR, vsl) \
    X(516, RR, vsrb) X(580, RR, vsrh) X(644, RR, vsrw) X(708, RR, vsr) \
    X(772, RR, vsrab) X(836, RR, vsrah) X(900, RR, vsraw) \
    X(1028, RR, vand) X(1092, RR, vandc) X(1156, RR, vor) \
    X(1220, RR, vxor) X(1284, RR, vnor) \
    X(8, RR, vmuloub) X(72, RR, vmulouh) X(264, RR, vmulosb) \
    X(328, RR, vmulosh) X(520, RR, vmuleub) X(584, RR, vmuleuh) \
    X(776, RR, vmulesb) X(840, RR, vmulesh) \
    X(12, RR, vmrghb) X(76, RR, vmrghh) X(140, RR, vmrghw) \
    X(268, RR, vmrglb) X(332, RR, vmrglh) X(396, RR, vmrglw) \
    X(1036, RR, vslo) X(1100, RR, vsro) \
    X(14, RR, vpkuhum) X(78, RR, vpkuwum) \
    X(512, SAT, vaddubs) X(576, SAT, vadduhs) X(640, SAT, vadduws) \
    X(768, SAT, vaddsbs) X(832, SAT, vaddshs) X(896, SAT, vaddsws) \
    X(1536, SAT, vsububs) X(1600, SAT, vsubuhs) X(1664, SAT, vsubuws) \
    X(1792, SAT, vsubsbs) X(1856, SAT, vsubshs) X(1920, SAT, vsubsws) \
    X(1544, SAT, vsum4ubs) X(1800, SAT, vsum4sbs) X(1608, SAT, vsum4shs) \
    X(1672, SAT, vsum2sws) X(1928, SAT, vsumsws) \
    X(142, SAT, vpkuhus) X(206, SAT, vpkuwus) X(270, SAT, vpkshus) \
    X(334, SAT, vpkswus) X(398, SAT, vpkshss) X(462, SAT, vpkswss) \
    X(526, R1, vupkhsb) X(590, R1, vupkhsh) \
    X(654, R1, vupklsb) X(718, R1, vupklsh) \
    X(10, FP, vaddfp) X(74, FP, vsubfp) X(1034, FP, vmaxfp) \
    X(1098, FP, vminfp) \
    X(266, FP1, vrefp) X(330, FP1, vrsqrtefp) X(522, FP1, vrfin) \
    X(586, FP1, vrfiz) X(650, FP1, vrfip) X(714, FP1, vrfim)
#define VX_DECL(xo, kind, name) DECL(name)
VX_LIST(VX_DECL)
/* The compares, by ten bits; the record form is the eleventh */
#define VC_LIST(X) \
    X(6, vcmpequb) X(70, vcmpequh) X(134, vcmpequw) \
    X(518, vcmpgtub) X(582, vcmpgtuh) X(646, vcmpgtuw) \
    X(774, vcmpgtsb) X(838, vcmpgtsh) X(902, vcmpgtsw) \
    X(198, vcmpeqfp) X(454, vcmpgefp) X(710, vcmpgtfp)
#define VC_DECL(xo, name) DECL(name) DECL(name##_rc)
VC_LIST(VC_DECL)
DECL(vspltb) DECL(vsplth) DECL(vspltw) DECL(vli) DECL(vmr)
DECL(vsldoi) DECL(vperm) DECL(vsel) DECL(vmladduhm)
DECL(vmhaddshs) DECL(vmhraddshs) DECL(vmsumubm) DECL(vmsummbm)
DECL(vmsumuhm) DECL(vmsumshm) DECL(vmsumuhs) DECL(vmsumshs)
DECL(vmaddfp) DECL(vnmsubfp) DECL(vcfsx) DECL(vcfux) DECL(vctsxs)
DECL(vctuxs) DECL(mfvscr) DECL(lvsl) DECL(lvsr)

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
/* QEMU_AOK_NO_ALTIVEC: AltiVec's own opcode and lvsl, lvsr and the element loads and stores are TCG's again */
static bool ppc_altivec_on;

static void __attribute__((constructor)) ppc_pairs_init(void)
{
    ppc_pairs_on = !getenv("QEMU_AOK_NO_PAIRS");
    ppc_altivec_on = !getenv("QEMU_AOK_NO_ALTIVEC");
    ppc_pairs.forward = !getenv("QEMU_AOK_NO_FWD");
    aok_pair_set_init(&ppc_pairs);
}

/* What gadgets.S knows of CPUPPCState (aok-ppc-asm.h). */
QEMU_BUILD_BUG_ON(TARGET_LONG_BITS != 32);
QEMU_BUILD_BUG_ON(TARGET_PAGE_BITS != AOK_TLB_PAGE_BITS);
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
/*
 * QEMU_AOK_STATS: the FP insns done by QEMU's helpers, by [double, single,
 * the compares and conversions][low five bits of the extended opcode], and
 * how many of them came with FPSCR in a state no gadget takes (RN, NI or an
 * enable). The rest were a gadget's slow path, or an insn that has none.
 */
static uint64_t aok_ppc_fp_helped[3][32], aok_ppc_fp_helped_slow;

/*
 * Why an arithmetic insn was not a gadget's to finish, the first of these
 * that holds: FPSCR; an operand a signalling NaN, a quiet one, an infinity,
 * a zero, a denormal; (single ops) an operand that is no single; the result
 * zero; the result a NaN or an infinity; and where the gadget's check of
 * exactness does not hold: the product tiny, or huge, or the result tiny
 * (a denormal too); or something else.
 */
enum { WHY_FPSCR, WHY_SNAN, WHY_QNAN, WHY_INF, WHY_ZERO, WHY_DENORMAL,
       WHY_NOT_SINGLE, WHY_RESULT_ZERO, WHY_RESULT_NONFINITE,
       WHY_PRODUCT_TINY, WHY_PRODUCT_HUGE, WHY_RESULT_TINY, WHY_RANGE,
       WHY_NB };
static uint64_t aok_ppc_fp_why[2][32][WHY_NB];

static int aok_ppc_fp_class(uint64_t v)
{
    unsigned e = (v >> 52) & 0x7ff;

    return e == 0x7ff ? ((v << 12) == 0 ? WHY_INF
                         : (v >> 51) & 1 ? WHY_QNAN : WHY_SNAN)
           : (v << 1) == 0 ? WHY_ZERO : e == 0 ? WHY_DENORMAL : -1;
}

static bool aok_ppc_fp_is_single(uint64_t v)
{
    union { double d; uint64_t u; } x = { .u = v }, y;

    y.d = (float)x.d;
    return y.u == x.u;
}

static void aok_ppc_fp_note_why(CPUPPCState *env, bool s, unsigned xo5,
                                uint64_t fa, uint64_t fb, uint64_t fc,
                                uint64_t r, bool fpscr_slow)
{
    /* which of frA, frB, frC the insn reads: A-form's bits */
    bool ra = xo5 != 22 && xo5 != 24 && xo5 != 26;
    bool rb = xo5 != 25, rc = xo5 == 25 || xo5 >= 28;
    int why = -1, k;

    if (fpscr_slow) {
        why = WHY_FPSCR;
    }
    for (int rank = WHY_SNAN; why < 0 && rank <= WHY_DENORMAL; rank++) {
        if ((ra && aok_ppc_fp_class(fa) == rank) ||
            (rb && aok_ppc_fp_class(fb) == rank) ||
            (rc && aok_ppc_fp_class(fc) == rank)) {
            why = rank;
        }
    }
    if (why < 0 && s && ((ra && !aok_ppc_fp_is_single(fa)) ||
                         (rb && !aok_ppc_fp_is_single(fb)) ||
                         (rc && !aok_ppc_fp_is_single(fc)))) {
        why = WHY_NOT_SINGLE;
    }
    if (why < 0) {
        union { uint64_t u; double d; } x = { .u = fa }, y = { .u = fc }, p;
        unsigned lo = s ? 921 : 54, hi = s ? 1149 : 2045, e;

        p.d = x.d * y.d;
        e = (p.u >> 52) & 0x7ff;
        k = aok_ppc_fp_class(r);
        why = k == WHY_ZERO ? WHY_RESULT_ZERO
              : k >= WHY_SNAN && k <= WHY_INF ? WHY_RESULT_NONFINITE
              : rc && e < lo ? WHY_PRODUCT_TINY
              : rc && e > hi ? WHY_PRODUCT_HUGE
              : ((r >> 52) & 0x7ff) < lo ? WHY_RESULT_TINY : WHY_RANGE;
    }
    aok_ppc_fp_why[s][xo5][why]++;
}

static void __attribute__((destructor)) aok_ppc_fp_stats(void)
{
    static const char *const kind[3] = { "double", "single", "cmp/conv" };
    uint64_t all = 0;

    for (int k = 0; k < 3; k++) {
        for (int i = 0; i < 32; i++) {
            all += aok_ppc_fp_helped[k][i];
        }
    }
    if (!aok_stats_enabled || !all) {
        return;
    }
    fprintf(stderr, "aok: ppc: %" PRIu64 " FP insns by QEMU's helpers, %"
            PRIu64 " of them with FPSCR's RN, NI or an enable set:", all,
            aok_ppc_fp_helped_slow);
    for (int k = 0; k < 3; k++) {
        for (int i = 0; i < 32; i++) {
            if (aok_ppc_fp_helped[k][i]) {
                fprintf(stderr, " %s/%d:%" PRIu64, kind[k], i,
                        aok_ppc_fp_helped[k][i]);
            }
        }
    }
    fprintf(stderr, "\n");
    for (int k = 0; k < 2; k++) {
        for (int i = 0; i < 32; i++) {
            static const char *const why[WHY_NB] = {
                "fpscr", "snan", "qnan", "inf", "zero", "denormal",
                "not-a-single", "result-zero", "result-nan-or-inf",
                "product-tiny", "product-huge", "result-tiny", "range"
            };
            uint64_t n = 0;

            for (int w = 0; w < WHY_NB; w++) {
                n += aok_ppc_fp_why[k][i][w];
            }
            if (!n) {
                continue;
            }
            fprintf(stderr, "aok: ppc: %s/%d, why:", kind[k], i);
            for (int w = 0; w < WHY_NB; w++) {
                if (aok_ppc_fp_why[k][i][w]) {
                    fprintf(stderr, " %s %" PRIu64, why[w],
                            aok_ppc_fp_why[k][i][w]);
                }
            }
            fprintf(stderr, "\n");
        }
    }
}

void aok_ppc_helper_fp(CPUPPCState *env, uint64_t pc, uint64_t insn);
void aok_ppc_helper_fp(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned op = insn >> 26, xo = (insn >> 1) & 0x3ff, xo5 = xo & 31;
    unsigned t = (insn >> 21) & 31;
    uint64_t fa = *cpu_fpr_ptr(env, (insn >> 16) & 31);
    uint64_t fb = *cpu_fpr_ptr(env, (insn >> 11) & 31);
    uint64_t fc = *cpu_fpr_ptr(env, (insn >> 6) & 31);
    bool s = op == 59, fprf = true;
    bool fpscr_slow = (env->fpscr & AOK_PPC_FPSCR_SLOW) != 0;
    uint64_t r;

    aok_no_retaddr();
    env->nip = pc;
    if (unlikely(aok_stats_enabled)) {
        aok_ppc_fp_helped[op == 63 && xo5 < 16 ? 2 : s][xo5]++;
        aok_ppc_fp_helped_slow += fpscr_slow;
    }
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
    if (unlikely(aok_stats_enabled) && !(op == 63 && xo5 < 16)) {
        aok_ppc_fp_note_why(env, s, xo5, fa, fb, fc, r, fpscr_slow);
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

/* lswi, stswi: QEMU's helpers, at (rA|0); NB 0 is 32 bytes */
static void aok_ppc_lsw(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned rt = (insn >> 21) & 31, ra = (insn >> 16) & 31;
    unsigned nb = (insn >> 11) & 31 ? (insn >> 11) & 31 : 32;
    target_ulong ea = ra ? env->gpr[ra] : 0;

    aok_ppc_sync(env, pc);
    if (((insn >> 1) & 0x3ff) == 597) {
        helper_lsw(env, ea, nb, rt);
    } else {
        helper_stsw(env, ea, nb, rt);
    }
}

/* dcbf, dcbst: a byte loaded, for its faults; icbi: a word of the line (helper_icbi) */
static void aok_ppc_cache(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    target_ulong ea = ea_x(env, insn);

    aok_ppc_sync_as(env, pc, ACCESS_CACHE);
    if (((insn >> 1) & 0x3ff) == 982) {
        cpu_ldl_mmu(env, ea & ~(env->dcache_line_size - 1),
                    OI(env, MO_UL | MO_UNALN), 0);
    } else {
        cpu_ldb_mmu(env, ea, OI(env, MO_UB), 0);
    }
}

/* mtsr, mtsrin, mfsr, mfsrin: QEMU's helpers. A write waits for the next isync. */
static void aok_ppc_sr(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned xo = (insn >> 1) & 0x3ff, t = (insn >> 21) & 31;
    unsigned n = xo == 210 || xo == 595 ? (insn >> 16) & 15
                 : (env->gpr[(insn >> 11) & 31] >> 28) & 15;

    if (xo == 210 || xo == 242) {
        helper_store_sr(env, n, env->gpr[t]);
    } else {
        env->gpr[t] = helper_load_sr(env, n);
    }
}

/*
 * isync, and a supervisor's sync: check_tlb_flush(), as TCG's code calls it
 * where a flush is pending. It may flush the TLB, or give the CPU another
 * TLB and jump cache (tlb_context_switch()), and a stream holds the jump
 * cache's address: so these say whether there was anything to do, and the
 * gadget (call_sync) then leaves for the main loop.
 */
static uint64_t aok_ppc_flush(CPUPPCState *env, bool global)
{
    if (likely(!env->tlb_need_flush)) {
        return 0;
    }
    check_tlb_flush(env, global);
    return 1;
}

static uint64_t aok_ppc_isync(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    return aok_ppc_flush(env, false);
}

static uint64_t aok_ppc_sync_sv(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    return aok_ppc_flush(env, true);
}

/* mtmsr, as gen_mtmsr: the main loop looks again afterwards (call_leave) */
static void aok_ppc_mtmsr(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    target_ulong mask = 0xffffffff, val = env->gpr[(insn >> 21) & 31];

    aok_no_retaddr();
    if (insn & 0x00010000) {
        /* the L form: EE and RI alone */
        mask &= (1ULL << MSR_RI) | (1ULL << MSR_EE);
    } else {
        if (likely(!(env->insns_flags2 & PPC2_PPE42))) {
            mask &= ~((1ULL << MSR_LE) | (1ULL << MSR_ME) | (1ULL << MSR_S));
        }
        /* where a CPU put to sleep by this is to wake */
        env->nip = pc + 4;
    }
    helper_store_msr(env, (val & mask) | (env->msr & ~mask));
}

/* rfi: nip and the MSR from SRR0 and SRR1 (call_exit) */
static void aok_ppc_rfi(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    aok_no_retaddr();
    env->nip = pc;
    helper_rfi(env);
}

/*
 * lvx and stvx off the fast path: two doublewords, the high one first, as
 * TCG's code loads and stores them. @addr is the address less its low four
 * bits.
 */
void aok_ppc_helper_lvx(CPUPPCState *env, uint64_t addr, uint64_t pc,
                        uint64_t insn);
void aok_ppc_helper_lvx(CPUPPCState *env, uint64_t addr, uint64_t pc,
                        uint64_t insn)
{
    ppc_avr_t *v = cpu_avr_ptr(env, (insn >> 21) & 31);
    MemOpIdx oi = OI(env, MO_BEUQ);
    uint64_t hi;

    aok_ppc_sync(env, pc);
    hi = cpu_ldq_mmu(env, (uint32_t)addr, oi, 0);
    v->VsrD(1) = cpu_ldq_mmu(env, (uint32_t)addr + 8, oi, 0);
    v->VsrD(0) = hi;
}

void aok_ppc_helper_stvx(CPUPPCState *env, uint64_t addr, uint64_t pc,
                         uint64_t insn);
void aok_ppc_helper_stvx(CPUPPCState *env, uint64_t addr, uint64_t pc,
                         uint64_t insn)
{
    ppc_avr_t *v = cpu_avr_ptr(env, (insn >> 21) & 31);
    MemOpIdx oi = OI(env, MO_BEUQ);

    aok_ppc_sync(env, pc);
    cpu_stq_mmu(env, (uint32_t)addr, v->VsrD(0), oi, 0);
    cpu_stq_mmu(env, (uint32_t)addr + 8, v->VsrD(1), oi, 0);
}

/*
 * An AltiVec FP insn whose operands or result the host's arithmetic would
 * not give QEMU's for (a NaN, a denormal, a result under the least normal
 * number), and the few that are always QEMU's helpers: its own for the
 * insn. None of them can trap.
 */
static uint64_t aok_ppc_vfp_helped;

static void __attribute__((destructor)) aok_ppc_vfp_stats(void)
{
    if (aok_stats_enabled && aok_ppc_vfp_helped) {
        fprintf(stderr, "aok: ppc: %" PRIu64 " AltiVec FP insns by QEMU's "
                "helpers\n", aok_ppc_vfp_helped);
    }
}

void aok_ppc_helper_vfp(CPUPPCState *env, uint64_t insn);
void aok_ppc_helper_vfp(CPUPPCState *env, uint64_t insn)
{
    ppc_avr_t *d = cpu_avr_ptr(env, (insn >> 21) & 31);
    ppc_avr_t *a = cpu_avr_ptr(env, (insn >> 16) & 31);
    ppc_avr_t *b = cpu_avr_ptr(env, (insn >> 11) & 31);
    ppc_avr_t *c = cpu_avr_ptr(env, (insn >> 6) & 31);
    bool rc = insn & 0x400;

    aok_ppc_vfp_helped++;
    switch (insn & 0x3f) {
    case 46: helper_vmaddfp(env, d, a, b, c); return;
    case 47: helper_vnmsubfp(env, d, a, b, c); return;
    }
    switch (insn & 0x3ff) {
    case 198: (rc ? helper_vcmpeqfp_dot : helper_vcmpeqfp)(env, d, a, b); return;
    case 454: (rc ? helper_vcmpgefp_dot : helper_vcmpgefp)(env, d, a, b); return;
    case 710: (rc ? helper_vcmpgtfp_dot : helper_vcmpgtfp)(env, d, a, b); return;
    case 966: (rc ? helper_vcmpbfp_dot : helper_vcmpbfp)(env, d, a, b); return;
    }
    switch (insn & 0x7ff) {
    case 10: helper_vaddfp(env, d, a, b); return;
    case 74: helper_vsubfp(env, d, a, b); return;
    case 1034: helper_vmaxfp(env, d, a, b); return;
    case 1098: helper_vminfp(env, d, a, b); return;
    case 266: helper_vrefp(env, d, b); return;
    case 330: helper_vrsqrtefp(env, d, b); return;
    case 394: helper_vexptefp(env, d, b); return;
    case 458: helper_vlogefp(env, d, b); return;
    case 522: helper_vrfin(env, d, b); return;
    case 586: helper_vrfiz(env, d, b); return;
    case 650: helper_vrfip(env, d, b); return;
    case 714: helper_vrfim(env, d, b); return;
    }
    g_assert_not_reached();
}

/*
 * The AltiVec insns that are a call: vcmpbfp, the two estimates QEMU has
 * its own series for, the pixel packs, mtvscr (which changes vec_status),
 * and the element loads and stores, which may fault.
 */
static void aok_ppc_vc(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    ppc_avr_t *d = cpu_avr_ptr(env, (insn >> 21) & 31);
    ppc_avr_t *a = cpu_avr_ptr(env, (insn >> 16) & 31);
    ppc_avr_t *b = cpu_avr_ptr(env, (insn >> 11) & 31);

    if ((insn >> 26) == 31) {
        target_ulong ea = ea_x(env, insn);

        aok_ppc_sync(env, pc);
        switch ((insn >> 1) & 0x3ff) {
        case 7: helper_LVEBX(env, d, ea); return;
        case 39: helper_LVEHX(env, d, ea & ~1); return;
        case 71: helper_LVEWX(env, d, ea & ~3); return;
        case 135: helper_STVEBX(env, d, ea); return;
        case 167: helper_STVEHX(env, d, ea & ~1); return;
        case 199: helper_STVEWX(env, d, ea & ~3); return;
        }
        g_assert_not_reached();
    }
    switch (insn & 0x7ff) {
    case 782: helper_vpkpx(d, a, b); return;
    case 846: helper_vupkhpx(d, b); return;
    case 974: helper_vupklpx(d, b); return;
    case 1604: helper_mtvscr(env, b->VsrW(3)); return;
    }
    aok_ppc_helper_vfp(env, insn);
}

/* lswx, stswx: QEMU's helpers, at (rA|0) + rB, XER's low seven bits the count */
static void aok_ppc_lswx(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    unsigned rt = (insn >> 21) & 31;
    target_ulong ea = ea_x(env, insn);

    aok_ppc_sync(env, pc);
    if (((insn >> 1) & 0x3ff) == 533) {
        /* (raises a program exception itself where rA or rB would be loaded) */
        helper_lswx(env, ea, rt, (insn >> 16) & 31, (insn >> 11) & 31);
    } else {
        helper_stsw(env, ea, env->xer & 0x7f, rt);
    }
}

/*
 * sc: the exception, from the insn's own address (delivering it moves nip
 * on), as gen_exception_err() raises it. It does not return.
 */
static void aok_ppc_sc(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    env->nip = pc;
    raise_exception_err_ra(env, POWERPC_EXCP_SYSCALL, (insn >> 5) & 1, 0);
}

/* mfspr and mtspr of the decrementer: QEMU's helpers, as spr_read_decr and spr_write_decr call them */
static void aok_ppc_mfdec(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    env->gpr[(insn >> 21) & 31] = helper_load_decr(env);
}

static void aok_ppc_mtdec(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    helper_store_decr(env, env->gpr[(insn >> 21) & 31]);
}

/* tlbie: QEMU's helper, and the flush it asks of the next sync or isync, as do_tlbie() generates */
static void aok_ppc_tlbie(CPUPPCState *env, uint64_t pc, uint64_t insn)
{
    helper_tlbie(env, env->gpr[(insn >> 11) & 31]);
    env->tlb_need_flush |= TLB_NEED_GLOBAL_FLUSH;
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
    bool vr;                /* AltiVec on (MSR[VR]); likewise */
    bool hv;                /* HFLAGS_HV: on a CPU without a hypervisor mode, always */
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

/* A call to C that may leave the stream, or always does: the same operands */
static int call_as(Ctx *c, Gadget gadget, void *fn, int r)
{
    emitg(c, gadget);
    aok_emit(&c->g, (uintptr_t)fn);
    aok_emit(&c->g, c->off);
    aok_emit(&c->g, c->insn);
    return r;
}

/* Whether the CPU has the insns of @flag: one it lacks is TCG's, to trap. */
static inline bool has(Ctx *c, uint64_t flag)
{
    return (c->env->insns_flags & flag) != 0;
}

static inline uint64_t fpr(unsigned r)
{
    return fpr_offset(r);
}

/* lvx, lvxl, stvx, stvxl: an X-form load's or store's stream, on a vector register */
static int vldst(Ctx *c, Gadget gadget, unsigned vt, unsigned ra, unsigned rb)
{
    if (!c->vr || !has(c, PPC_ALTIVEC) || (c->insn & 1)) {
        return UNKNOWN;
    }
    emitg(c, gadget);
    aok_emit(&c->g, avr_full_offset(vt));
    aok_emit(&c->g, base(ra));
    aok_emit(&c->g, gpr(rb));
    aok_emit(&c->g, mem_word(c));
    return NEXT;
}

static inline uint64_t avr(unsigned r)
{
    return avr_full_offset(r);
}

/* AltiVec's own opcode, 4 */
static int altivec(Ctx *c)
{
    enum { RR, SAT, R1, FP, FP1 };
    static const struct {
        uint16_t xo;
        uint8_t kind;
        Gadget gadget;
    } vx[] = {
#define VX_ROW(xo, kind, name) { xo, kind, G(name) },
        VX_LIST(VX_ROW)
    };
    static const struct {
        uint16_t xo;
        Gadget gadget[2];
        bool fp;
    } vc[] = {
#define VC_ROW(xo, name) { xo, { G(name), G(name##_rc) }, xo == 198 || xo == 454 || xo == 710 },
        VC_LIST(VC_ROW)
    };
    uint32_t insn = c->insn;
    unsigned d = (insn >> 21) & 31, a = (insn >> 16) & 31, b = (insn >> 11) & 31;
    unsigned e = (insn >> 6) & 31, xo = insn & 0x7ff;
    uint64_t sat = offsetof(CPUPPCState, vscr_sat);

    if (!c->vr || !has(c, PPC_ALTIVEC) || !ppc_altivec_on) {
        return UNKNOWN;
    }
    if ((insn & 0x3f) >= 32) {
        /* the VA forms: vD, vA, vB and vC (or vsldoi's SH) */
        Gadget g = NULL;
        int extra = 0;      /* 1: vscr_sat after; 2: the insn after */

        switch (insn & 0x3f) {
        case 32: g = G(vmhaddshs); extra = 1; break;
        case 33: g = G(vmhraddshs); extra = 1; break;
        case 34: g = G(vmladduhm); break;
        case 36: g = G(vmsumubm); break;
        case 37: g = G(vmsummbm); break;
        case 38: g = G(vmsumuhm); break;
        case 39: g = G(vmsumuhs); extra = 1; break;
        case 40: g = G(vmsumshm); break;
        case 41: g = G(vmsumshs); extra = 1; break;
        case 42: g = G(vsel); break;
        case 43: g = G(vperm); break;
        case 46: g = G(vmaddfp); extra = 2; break;
        case 47: g = G(vnmsubfp); extra = 2; break;
        case 44:
            if (insn & 0x400) {
                return UNKNOWN;
            }
            if ((e & 15) == 0) {
                emit2(c, G(vmr), avr(d), avr(a));
            } else {
                emit3(c, G(vsldoi), avr(d), avr(a), avr(b));
                aok_emit(&c->g, 16 - (e & 15));
            }
            return NEXT;
        default:
            return UNKNOWN;
        }
        emit3(c, g, avr(d), avr(a), avr(b));
        aok_emit(&c->g, avr(e));
        if (extra) {
            aok_emit(&c->g, extra == 1 ? sat : insn);
        }
        return NEXT;
    }
    if ((xo & 0x3f) == 6) {
        if ((xo & 0x3ff) == 966) {
            return call(c, aok_ppc_vc);     /* vcmpbfp */
        }
        for (int i = 0; i < ARRAY_SIZE(vc); i++) {
            if (vc[i].xo == (xo & 0x3ff)) {
                emit3(c, vc[i].gadget[xo >> 10], avr(d), avr(a), avr(b));
                if (vc[i].fp) {
                    aok_emit(&c->g, insn);
                }
                return NEXT;
            }
        }
        return UNKNOWN;
    }
    switch (xo) {
    case 524: case 588: case 652: {     /* vspltb, vsplth, vspltw */
        static const Gadget g[3] = { G(vspltb), G(vsplth), G(vspltw) };
        int vece = (xo - 524) / 64;
        /* the element's bytes in the state, as gen_vsplt finds them */
        int at = (((a << vece) & 15) ^ 15) & ~((1 << vece) - 1);

        emit2(c, g[vece], avr(d), avr(b) + at);
        return NEXT;
    }
    case 780: case 844: case 908: {     /* vspltisb, vspltish, vspltisw */
        int32_t simm = (int32_t)(a << 27) >> 27;
        uint64_t v = xo == 780 ? (uint8_t)simm * 0x0101010101010101ull
                   : xo == 844 ? (uint16_t)simm * 0x0001000100010001ull
                   : (uint32_t)simm * 0x0000000100000001ull;

        if (b) {
            return UNKNOWN;
        }
        emit3(c, G(vli), avr(d), v, v);
        return NEXT;
    }
    case 778: case 842:                 /* vcfux, vcfsx: times 2^-UIMM */
        emit3(c, xo == 778 ? G(vcfux) : G(vcfsx), avr(d), avr(b),
              (uint64_t)(127 - a) << 23);
        return NEXT;
    case 906: case 970:                 /* vctuxs, vctsxs: times 2^UIMM */
        emit3(c, xo == 906 ? G(vctuxs) : G(vctsxs), avr(d), avr(b),
              (uint64_t)(127 + a) << 23);
        aok_emit(&c->g, sat);
        return NEXT;
    case 1540:                          /* mfvscr */
        if (a || b) {
            return UNKNOWN;
        }
        emit3(c, G(mfvscr), avr(d), offsetof(CPUPPCState, vscr), sat);
        return NEXT;
    case 1604:                          /* mtvscr */
        return d || a ? UNKNOWN : call(c, aok_ppc_vc);
    case 782:                           /* vpkpx */
        return call(c, aok_ppc_vc);
    case 394: case 458:                 /* vexptefp, vlogefp */
    case 846: case 974:                 /* vupkhpx, vupklpx */
        return a ? UNKNOWN : call(c, aok_ppc_vc);
    }
    for (int i = 0; i < ARRAY_SIZE(vx); i++) {
        if (vx[i].xo != xo) {
            continue;
        }
        switch (vx[i].kind) {
        case RR:
            emit3(c, vx[i].gadget, avr(d), avr(a), avr(b));
            return NEXT;
        case SAT:
            emit3(c, vx[i].gadget, avr(d), avr(a), avr(b));
            aok_emit(&c->g, sat);
            return NEXT;
        case FP:
            emit3(c, vx[i].gadget, avr(d), avr(a), avr(b));
            aok_emit(&c->g, insn);
            return NEXT;
        case R1:
            if (a) {
                return UNKNOWN;
            }
            emit2(c, vx[i].gadget, avr(d), avr(b));
            return NEXT;
        case FP1:
            if (a) {
                return UNKNOWN;
            }
            emit3(c, vx[i].gadget, avr(d), avr(b), insn);
            return NEXT;
        }
    }
    return UNKNOWN;
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
        /* single precision: the operand words of the double forms */
        switch (xo5) {
        case 18: gadget = G(fdivs); break;
        case 20: gadget = G(fsubs); break;
        case 21: gadget = G(fadds); break;
        case 25:
            emit3(c, G(fmuls), fpr(t), fpr(a), fpr(cc));
            aok_emit(&c->g, mem_word(c));
            return rc1(c);
        case 28: case 29: case 30: case 31: {
            static const Gadget m[4] = {
                G(fmsubs), G(fmadds), G(fnmsubs), G(fnmadds)
            };

            emit3(c, m[xo5 - 28], fpr(t), fpr(a), fpr(cc));
            aok_emit(&c->g, fpr(b));
            aok_emit(&c->g, mem_word(c));
            return rc1(c);
        }
        case 22: case 24:
            /* fsqrts and fres: QEMU's helpers (aok_ppc_helper_fp) */
            call(c, aok_ppc_helper_fp);
            return rc1(c);
        default:
            return UNKNOWN;
        }
        emit3(c, gadget, fpr(t), fpr(a), fpr(b));
        aok_emit(&c->g, mem_word(c));
        return rc1(c);
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

    if ((bo & 0x14) == 0x04 && (ctr || !lk) && !c->no_goto_ptr) {
        /*
         * beqlr, beqctr and the like: on a CR bit alone. With LK, bcctr's
         * LR is written first, taken or not; bclrl's old LR is its target,
         * and that one is TCG's.
         */
        unsigned bi = (c->insn >> 16) & 31;

        if (lk) {
            emitg(c, G(set_lr));
            aok_emit(&c->g, (uint32_t)(cia(c) + 4 - c->pc));
        }
        emitg(c, ctr ? ((bo & 0x08) ? G(bcctr_t) : G(bcctr_f))
                     : ((bo & 0x08) ? G(bclr_t) : G(bclr_f)));
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
    case 150:   /* isync: in user mode a barrier, as sync */
        if (insn & 0x03fff801) {
            return UNKNOWN;
        }
        emitg(c, G(sync));
        return c->pr ? NEXT : call_as(c, G(call_sync), aok_ppc_isync, NEXT);
    case 50:    /* rfi */
        if ((insn & 0x03ff8001) || c->pr) {
            return UNKNOWN;
        }
        return call_as(c, G(call_exit), aok_ppc_rfi, END);
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

    /* XO-form arithmetic; with OE, gadgets that set XER[OV] and add it to SO */
    switch (xo9) {
    case 75:    /* mulhw and mulhwu ignore OE */
        return rr(c, G(mulhw), d, a, b);
    case 11:
        return rr(c, G(mulhwu), d, a, b);
    case 266: case 10: case 138: case 234: case 202: case 40: case 8:
    case 136: case 232: case 200: case 104: case 235: case 491: case 459:
        if (oe) {
            switch (xo9) {
            case 266: return rr(c, G(addo), d, a, b);
            case 10: return rr(c, G(addco), d, a, b);
            case 138: return rr(c, G(addeo), d, a, b);
            case 234: return r1(c, G(addmeo), d, a);
            case 202: return r1(c, G(addzeo), d, a);
            case 40: return rr(c, G(subfo), d, a, b);
            case 8: return rr(c, G(subfco), d, a, b);
            case 136: return rr(c, G(subfeo), d, a, b);
            case 232: return r1(c, G(subfmeo), d, a);
            case 200: return r1(c, G(subfzeo), d, a);
            case 104: return r1(c, G(nego), d, a);
            case 235: return rr(c, G(mullwo), d, a, b);
            case 491: return rr(c, G(divwo), d, a, b);
            case 459: return rr(c, G(divwuo), d, a, b);
            }
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
    case 19:    /* mfcr, and mfocrf (bit 20): its one field, or with another mask nothing */
        if (insn & 0x00000801) {
            return UNKNOWN;
        }
        if (insn & 0x00100000) {
            unsigned crm = (insn >> 12) & 0xff;

            if (crm && !(crm & (crm - 1))) {
                emit3(c, G(mfocrf), gpr(d), crf(7 - ctz32(crm)),
                      4 * ctz32(crm));
            }
            return NEXT;
        }
        emitg(c, G(mfcr));
        aok_emit(&c->g, gpr(d));
        return NEXT;
    case 144:   /* mtcrf, and mtocrf likewise */
        if (insn & 0x00000801) {
            return UNKNOWN;
        }
        if (insn & 0x00100000) {
            unsigned crm = (insn >> 12) & 0xff;

            if (crm && !(crm & (crm - 1))) {
                emit2(c, G(mtcrf), gpr(d), crm);
            }
            return NEXT;
        }
        emit2(c, G(mtcrf), gpr(d), (insn >> 12) & 0xff);
        return NEXT;
    /* the MSR and the segment registers, a supervisor's */
    case 83:    /* mfmsr */
        if ((insn & 0x001ff801) || c->pr) {
            return UNKNOWN;
        }
        emit2(c, G(mov), gpr(d), offsetof(CPUPPCState, msr));
        return NEXT;
    case 146:   /* mtmsr */
        if ((insn & 0x001ef801) || c->pr) {
            return UNKNOWN;
        }
        return call_as(c, G(call_leave), aok_ppc_mtmsr, END);
    case 210: case 595:     /* mtsr, mfsr */
        if ((insn & 0x0010f801) || c->pr || !has(c, PPC_SEGMENT)) {
            return UNKNOWN;
        }
        return call(c, aok_ppc_sr);
    case 242: case 659:     /* mtsrin, mfsrin */
        if ((insn & 0x001f0001) || c->pr || !has(c, PPC_SEGMENT)) {
            return UNKNOWN;
        }
        return call(c, aok_ppc_sr);
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
        if (spr(insn) == SPR_DECR && !c->pr && c->hv &&
            c->env->spr_cb[SPR_DECR].hea_read == spr_read_decr) {
            return call(c, aok_ppc_mfdec);
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
        if (spr(insn) == SPR_DECR && !c->pr && c->hv &&
            c->env->spr_cb[SPR_DECR].hea_write == spr_write_decr) {
            return call(c, aok_ppc_mtdec);
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

    /* sync and eieio: barriers; a supervisor's sync is also where a flush that is due is done */
    case 598:
        if (c->pr) {
            emitg(c, G(sync));
            return NEXT;
        }
        if (!has(c, PPC_MEM_SYNC)) {
            return UNKNOWN;
        }
        emitg(c, G(sync));
        return call_as(c, G(call_sync), aok_ppc_sync_sv, NEXT);
    case 854:
        emitg(c, G(sync));
        return NEXT;
    /* dcbt, dcbtst: nothing (Rc is illegal) */
    case 278: case 246:
        return insn & 1 ? UNKNOWN : NEXT;
    /* AltiVec's hints, dst and dstst (illegal with rA 0) and dss; dcba: nothing either */
    case 342: case 374:
        return (insn & 0x01800001) || a == 0 || !has(c, PPC_ALTIVEC)
               ? UNKNOWN : NEXT;
    case 822:
        return (insn & 0x019ff801) || !has(c, PPC_ALTIVEC) ? UNKNOWN : NEXT;
    case 758:
        return (insn & 0x03e00001) || !has(c, PPC_CACHE_DCBA)
               ? UNKNOWN : NEXT;
    /* dcbf, dcbst, icbi: a load, for the faults it may raise */
    case 86:
        return (insn & 0x03c00001) || !has(c, PPC_CACHE)
               ? UNKNOWN : call(c, aok_ppc_cache);
    case 54:
        return (insn & 0x03e00001) || !has(c, PPC_CACHE)
               ? UNKNOWN : call(c, aok_ppc_cache);
    case 982:
        return (insn & 0x03e00001) || !has(c, PPC_CACHE_ICBI)
               ? UNKNOWN : call(c, aok_ppc_cache);
    /* lswi (illegal where it would load rA: TCG's to say so), stswi */
    case 597:
        if ((insn & 1) || !has(c, PPC_STRING) ||
            lsw_reg_in_range(d, DIV_ROUND_UP(b ? b : 32, 4), a)) {
            return UNKNOWN;
        }
        return call(c, aok_ppc_lsw);
    case 725:
        return (insn & 1) || !has(c, PPC_STRING) ? UNKNOWN
                                                  : call(c, aok_ppc_lsw);
    case 533: case 661:     /* lswx, stswx */
        return (insn & 1) || !has(c, PPC_STRING) ? UNKNOWN
                                                  : call(c, aok_ppc_lswx);
    case 306:               /* tlbie: its reserved fields are ignored */
        if (c->pr || !c->hv || !has(c, PPC_MEM_TLBIE) ||
            (c->env->insns_flags2 & PPC2_ISA300)) {
            return UNKNOWN;
        }
        return call(c, aok_ppc_tlbie);
    case 566:               /* tlbsync: nothing, but on a BookE CPU */
        return (insn & 0x03fff801) || c->pr || !c->hv ||
               !has(c, PPC_MEM_TLBSYNC) || has(c, PPC_BOOKE) ? UNKNOWN : NEXT;
    /* AltiVec's aligned loads and stores (the l forms hint at the cache) */
    case 103: case 359:
        return vldst(c, G(lvx), d, a, b);
    case 6: case 38:        /* lvsl, lvsr */
        if (!c->vr || !has(c, PPC_ALTIVEC) || (insn & 1) || !ppc_altivec_on) {
            return UNKNOWN;
        }
        emit3(c, xo == 6 ? G(lvsl) : G(lvsr), avr(d), base(a), gpr(b));
        return NEXT;
    case 7: case 39: case 71: case 135: case 167: case 199:
        /* lvebx, lvehx, lvewx, stvebx, stvehx, stvewx */
        if (!c->vr || !has(c, PPC_ALTIVEC) || (insn & 1) || !ppc_altivec_on) {
            return UNKNOWN;
        }
        return call(c, aok_ppc_vc);
    case 231: case 487:
        return vldst(c, G(stvx), d, a, b);
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
    case 4: return altivec(c);
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
    case 17:    /* sc */
        if ((insn & 0x03fff01d) || !(insn & 2) || !has(c, PPC_FLOW)) {
            return UNKNOWN;
        }
        return call_as(c, G(call_exit), aok_ppc_sc, END);
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

/*
 * A TB stops before an insn that is TCG's, and TCG's TB runs from there to
 * the end of the block. Where that block ends by branching back into this
 * TB, the two would take turns through the main loop at every pass of a
 * loop that TCG's code alone links to itself: then the whole TB is TCG's.
 * (A loop of AltiVec arithmetic between an lvx and a stvx, for one.)
 */
static uint64_t aok_ppc_loops_left;

static void __attribute__((destructor)) aok_ppc_loops_stats(void)
{
    if (aok_stats_enabled && aok_ppc_loops_left) {
        fprintf(stderr, "aok: ppc: %" PRIu64 " TBs left whole to TCG, which "
                "has an insn of the loop they are in\n", aok_ppc_loops_left);
    }
}

static bool tail_loops_back(Ctx *c, const uint8_t *code)
{
    for (unsigned off = c->off, n = 0;
         c->page_off + off < TARGET_PAGE_SIZE && n < 64; off += 4, n++) {
        uint32_t insn = ldl_be_p(code + off), at = c->pc + off, dest;

        switch (insn >> 26) {
        case 16:
            dest = (int16_t)(insn & 0xfffc) + ((insn & 2) ? 0 : at);
            return dest >= c->pc && dest < c->pc + c->off;
        case 18:
            dest = ((int32_t)((insn & 0x03fffffc) << 6) >> 6) +
                   ((insn & 2) ? 0 : at);
            return dest >= c->pc && dest < c->pc + c->off;
        case 17:
            return false;
        case 19:
            switch ((insn >> 1) & 0x3ff) {
            case 16: case 528: case 50:
                return false;
            }
            break;
        }
    }
    return false;
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
    c.vr = flags & (1 << HFLAGS_VR);
    c.hv = flags & (1 << HFLAGS_HV);
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
            if (c.g.n_insns && tail_loops_back(&c, code)) {
                aok_ppc_loops_left++;
                return 0;
            }
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
