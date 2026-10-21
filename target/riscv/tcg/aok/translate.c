/*
 * AOK gadgets for RISC-V guests: the translator.
 *
 * Turns RV64 integer, load/store and branch instructions into a gadget
 * stream (include/accel/tcg/aok.h). It translates what it is sure of and
 * stops in front of anything else -- system and CSR instructions, floating
 * point, atomics, vectors, an encoding it does not know, a disabled
 * extension -- so that the next TB starts there and TCG translates it,
 * raising whatever exception is due. A TB whose first insn is one of those
 * is declined outright.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "accel/tcg/aok.h"
#include "accel/tcg/cpu-ldst-common.h"
#include "exec/helper-proto.h"
#include "fpu/softfloat.h"
#include "aok-riscv.h"

#define G(name) aok_gadget_rv_##name
#define DECL(name) void G(name)(void);

/*
 * The integer gadgets, the loads and stores and the branches are iSH-AOK's
 * (gadgets-shared.S), under the names its translator knows them by; the
 * rest are this front end's own (gadgets.S).
 */
#define ALU_BOTH(X) \
    X(add) X(and) X(or) X(xor) X(sll) X(srl) X(sra) X(slt) X(sltu) \
    X(addw) X(sllw) X(srlw) X(sraw) X(ror) X(rorw) \
    X(bclr) X(bset) X(binv) X(bext)
#define ALU_RR(X) \
    X(sub) X(subw) X(mul) X(mulw) X(mulh) X(mulhu) X(mulhsu) \
    X(div) X(divu) X(rem) X(remu) X(divw) X(divuw) X(remw) X(remuw) \
    X(sh1add) X(sh2add) X(sh3add) X(add_uw) \
    X(sh1add_uw) X(sh2add_uw) X(sh3add_uw) \
    X(andn) X(orn) X(xnor) X(max) X(maxu) X(min) X(minu) \
    X(rol) X(rolw) X(czero_eqz) X(czero_nez)
#define ALU_RI(X) \
    X(slli_uw) X(clz) X(clzw) X(ctz) X(ctzw) X(cpop) X(cpopw) \
    X(sext_b) X(sext_h) X(zext_h) X(rev8) X(orc_b)
#define DECL_RR(n) DECL(n##_rr)
#define DECL_RI(n) DECL(n##_ri)
ALU_BOTH(DECL_RR) ALU_BOTH(DECL_RI) ALU_RR(DECL_RR) ALU_RI(DECL_RI)
DECL(mov_const) DECL(addi)
DECL(pcrel) DECL(fence) DECL(jalr) DECL(jalr_cached) DECL(lookup)
DECL(call) DECL(call_exit)
DECL(fadd_d) DECL(fsub_d) DECL(fmul_d) DECL(fdiv_d) DECL(fsqrt_d)
DECL(fmadd_d) DECL(fmsub_d) DECL(fnmsub_d) DECL(fnmadd_d)
DECL(feq_d) DECL(flt_d) DECL(fle_d)
DECL(fcvt_w_d_rtz) DECL(fcvt_wu_d_rtz) DECL(fcvt_l_d_rtz) DECL(fcvt_lu_d_rtz)
DECL(fcvt_w_d_dyn) DECL(fcvt_wu_d_dyn) DECL(fcvt_l_d_dyn) DECL(fcvt_lu_d_dyn)
DECL(fcvt_d_w) DECL(fcvt_d_wu) DECL(fcvt_d_l) DECL(fcvt_d_lu)
DECL(fsgnj_d) DECL(fsgnjn_d) DECL(fsgnjx_d)
DECL(lb) DECL(lbu) DECL(lh) DECL(lhu) DECL(lw) DECL(lwu) DECL(ld) DECL(flw)
DECL(sb) DECL(sh) DECL(sw) DECL(sd)
DECL(beq) DECL(bne) DECL(blt) DECL(bge) DECL(bltu) DECL(bgeu)
DECL(beq_bk) DECL(bne_bk) DECL(blt_bk) DECL(bge_bk) DECL(bltu_bk) DECL(bgeu_bk)
DECL(b) DECL(jal_link)

typedef void (*Gadget)(void);

/*
 * The fused pairs: iSH-AOK's list (shared/pairs.h), read as its own
 * translator reads it, less the pairs with a gadget this front end does not
 * have (shared/host-gadgets.h). FUSE2(a, b) names a pair; HR_a says that a
 * leaves its result in a host register as well, K_b how many operands b can
 * take from one, and OPS_b which operand words those are.
 */
#include "shared/host-gadgets.h"
#define PAIR_OP_NONE AOK_PAIR_OP_NONE
#define PAIR_OP_SLOT AOK_PAIR_OP_SLOT
#define FUSE2(a, b) RV_HOST(HOST_##a, HOST_##b)(a, b)
#define RV_HOST(x, y) RV_HOST_(x, y)
#define RV_HOST_(x, y) RV_HOST_##x##y
#define RV_HOST_00(a, b)
#define RV_HOST_01(a, b)
#define RV_HOST_10(a, b)
#define RV_HOST_11(a, b) RV_FUSE2_SEL(HR_##a, K_##b)(a, b)
#define RV_FUSE2_SEL(h, k) RV_FUSE2_SEL_(h, k)
#define RV_FUSE2_SEL_(h, k) RV_FUSE2_##h##_##k
#define RV_FUSE2_0_0(a, b) \
    RV_PAIR(a, b, NULL, NULL, {0, PAIR_OP_NONE}, {0, PAIR_OP_NONE})
#define RV_FUSE2_0_1(a, b) RV_FUSE2_0_0(a, b)
#define RV_FUSE2_0_2(a, b) RV_FUSE2_0_0(a, b)
#define RV_FUSE2_1_0(a, b) RV_FUSE2_0_0(a, b)
#define RV_FUSE2_1_1(a, b) RV_FW1(a, b) \
    RV_PAIR(a, b, G(f2n_##a##__##b), NULL, OPS_##b, {0, PAIR_OP_NONE})
#define RV_FUSE2_1_2(a, b) RV_FW1(a, b) RV_FW2(a, b) \
    RV_PAIR(a, b, G(f2n_##a##__##b), G(f2m_##a##__##b), OPS_##b)

#define RV_PAIR(a, b, fn, fm, ...) DECL(a) DECL(b) DECL(f2_##a##__##b)
#define RV_FW1(a, b) DECL(f2n_##a##__##b)
#define RV_FW2(a, b) DECL(f2m_##a##__##b)
#include "shared/pairs.h"
#undef RV_PAIR
#undef RV_FW1
#undef RV_FW2

static const AokPair rv_pair_list[] = {
#define RV_PAIR(a, b, fn, fm, ...) \
    { G(a), G(b), G(f2_##a##__##b), { fn, fm }, 1 + NP_##a, { __VA_ARGS__ } },
#define RV_FW1(a, b)
#define RV_FW2(a, b)
#include "shared/pairs.h"
#undef RV_PAIR
#undef RV_FW1
#undef RV_FW2
#undef FUSE2
};

static AokPairSet rv_pairs = { rv_pair_list, ARRAY_SIZE(rv_pair_list) };
static bool rv_pairs_on;

static void __attribute__((constructor)) rv_pairs_init(void)
{
    rv_pairs_on = !getenv("QEMU_AOK_NO_PAIRS");
    rv_pairs.forward = !getenv("QEMU_AOK_NO_FWD");
    aok_pair_set_init(&rv_pairs);
}

/* gadgets.S: the tag masks of the loads and stores, and rv_lookup's hash. */
QEMU_BUILD_BUG_ON(TARGET_PAGE_BITS != AOK_TLB_PAGE_BITS);

/*
 * The softmmu slow paths of the load and store gadgets. Called with the
 * insn's pc and opcode: an exception raised in here unwinds nothing, so the
 * two things riscv_restore_state_to_opc would have recovered are stored
 * first. The mmu index is the one the TB was translated for, since nothing
 * a stream executes can change it.
 */
#define OI(env, mop) make_memop_idx(mop, riscv_env_mmu_index(env, false))

static inline void aok_rv_sync(CPURISCVState *env, uint64_t pc, uint64_t insn)
{
    /* The flags of FP gadgets this stream ran, before anything reads them. */
    aok_fold_fpsr(env_cpu(env));
    aok_no_retaddr();
    env->pc = pc;
    env->bins = insn;
    env->excp_uw2 = 0;
}

/*
 * (One a size. A load's value comes back whole: the gadget extends it, as it
 * extends what it reads on the fast path.)
 */
#define LOAD_HELPER(bits, fn, mop)                                          \
uint64_t aok_rv_helper_load##bits(CPURISCVState *env, uint64_t addr,       \
                                  uint64_t pc, uint64_t insn);              \
uint64_t aok_rv_helper_load##bits(CPURISCVState *env, uint64_t addr,       \
                                  uint64_t pc, uint64_t insn)               \
{                                                                           \
    aok_rv_sync(env, pc, insn);                                             \
    return fn(env, addr, OI(env, mop), 0);                                  \
}
LOAD_HELPER(8,  cpu_ldb_mmu, MO_UB)
LOAD_HELPER(16, cpu_ldw_mmu, MO_LEUW)
LOAD_HELPER(32, cpu_ldl_mmu, MO_LEUL)
LOAD_HELPER(64, cpu_ldq_mmu, MO_LEUQ)

#define STORE_HELPER(bits, fn, mop)                                         \
void aok_rv_helper_store##bits(CPURISCVState *env, uint64_t addr,          \
                               uint64_t val, uint64_t pc, uint64_t insn);   \
void aok_rv_helper_store##bits(CPURISCVState *env, uint64_t addr,          \
                               uint64_t val, uint64_t pc, uint64_t insn)    \
{                                                                           \
    aok_rv_sync(env, pc, insn);                                             \
    fn(env, addr, val, OI(env, mop), 0);                                    \
}
STORE_HELPER(8,  cpu_stb_mmu, MO_UB)
STORE_HELPER(16, cpu_stw_mmu, MO_LEUW)
STORE_HELPER(32, cpu_stl_mmu, MO_LEUL)
STORE_HELPER(64, cpu_stq_mmu, MO_LEUQ)

/*
 * The A extension, in C for now: one call does the whole insn. These are
 * what trans_rva.c.inc generates, on cputlb's atomic helpers, which are
 * atomic whether or not the TB is CF_PARALLEL.
 */
void aok_rv_helper_atomic(CPURISCVState *env, uint64_t pc, uint64_t insn);
void aok_rv_helper_atomic(CPURISCVState *env, uint64_t pc, uint64_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31;
    bool d = ((insn >> 12) & 7) == 3;
    uint64_t addr = rs1 ? env->gpr[rs1] : 0;
    uint64_t src = rs2 ? env->gpr[rs2] : 0;
    MemOpIdx oi = OI(env, (d ? MO_LEUQ : MO_LEUL) | MO_ALIGN);
    uint64_t old;

    aok_rv_sync(env, pc, insn);

#define AMO(op)                                                             \
    old = d ? cpu_atomic_##op##q_le_mmu(env, addr, src, oi, 0)              \
            : (uint64_t)(int32_t)cpu_atomic_##op##l_le_mmu(env, addr, src, oi, 0)

    switch (insn >> 27) {
    case 0x02: /* lr */
        smp_mb();
        old = d ? cpu_ldq_mmu(env, addr, oi, 0)
                : (uint64_t)(int32_t)cpu_ldl_mmu(env, addr, oi, 0);
        smp_mb();
        env->load_val = old;
        env->load_res = addr;
        break;
    case 0x03: /* sc */
        if (env->load_res == addr) {
            old = d ? cpu_atomic_cmpxchgq_le_mmu(env, addr, env->load_val,
                                                 src, oi, 0)
                    : (uint64_t)(int32_t)cpu_atomic_cmpxchgl_le_mmu(
                          env, addr, env->load_val, src, oi, 0);
            old = old != env->load_val;
        } else {
            smp_mb();
            old = 1;
        }
        env->load_res = -1;
        break;
    case 0x01: AMO(xchg); break;
    case 0x00: AMO(fetch_add); break;
    case 0x04: AMO(fetch_xor); break;
    case 0x0c: AMO(fetch_and); break;
    case 0x08: AMO(fetch_or); break;
    case 0x10: AMO(fetch_smin); break;
    case 0x14: AMO(fetch_smax); break;
    case 0x18: AMO(fetch_umin); break;
    case 0x1c: AMO(fetch_umax); break;
    default:
        g_assert_not_reached();
    }
#undef AMO
    if (rd) {
        env->gpr[rd] = old;
    }
}

/*
 * Zicsr, as trans_csr* in trans_rvi.c.inc: the same helpers with the same
 * arguments. The TB ends after it, in the main loop.
 */
void aok_rv_helper_csr(CPURISCVState *env, uint64_t pc, uint64_t insn);
void aok_rv_helper_csr(CPURISCVState *env, uint64_t pc, uint64_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned f3 = (insn >> 12) & 7;
    int csr = insn >> 20;
    uint64_t src = (f3 & 4) ? rs1 : rs1 ? env->gpr[rs1] : 0;
    uint64_t val = 0;

    aok_rv_sync(env, pc, insn);
    switch (f3 & 3) {
    case 1: /* csrrw, csrrwi: with rd == x0 the csr is not read */
        if (rd == 0) {
            helper_csrw(env, csr, src);
        } else {
            val = helper_csrrw(env, csr, src, -1);
        }
        break;
    case 2: /* csrrs, csrrsi: with rs1 == x0 (or a zero imm) it is not written */
        val = rs1 ? helper_csrrw(env, csr, -1, src) : helper_csrr(env, csr);
        break;
    case 3: /* csrrc, csrrci */
        val = rs1 ? helper_csrrw(env, csr, 0, src) : helper_csrr(env, csr);
        break;
    default:
        g_assert_not_reached();
    }
    if (rd) {
        env->gpr[rd] = val;
    }
    env->pc = pc + 4;
}

/*
 * F and D arithmetic, in C for now: what trans_rvf.c.inc and trans_rvd.c.inc
 * generate, with the same softfloat helpers in the same order, for a TB
 * whose mstatus.FS is already dirty. The translator has checked the
 * encoding is one of these.
 */
static inline uint64_t aok_check_nanbox_s(uint64_t f)
{
    return f >= 0xffffffff00000000ull ? f : 0xffffffff7fc00000ull;
}

void aok_rv_helper_fp(CPURISCVState *env, uint64_t pc, uint64_t insn);
void aok_rv_helper_fp(CPURISCVState *env, uint64_t pc, uint64_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, rs3 = insn >> 27;
    unsigned rm = (insn >> 12) & 7, f7 = insn >> 25;
    bool d = f7 & 1;
    uint64_t *f = env->fpr;
    uint64_t a = f[rs1], b = f[rs2], x = rs1 ? env->gpr[rs1] : 0, r;

#define FD(name, ...) (d ? helper_##name##_d(env, __VA_ARGS__) \
                         : helper_##name##_s(env, __VA_ARGS__))
#define TO_GPR(v) do { if (rd) { env->gpr[rd] = (v); } } while (0)

    aok_rv_sync(env, pc, insn);

    switch (insn & 0x7f) {
    case 0x43: helper_set_rounding_mode(env, rm); f[rd] = FD(fmadd, a, b, f[rs3]); return;
    case 0x47: helper_set_rounding_mode(env, rm); f[rd] = FD(fmsub, a, b, f[rs3]); return;
    case 0x4b: helper_set_rounding_mode(env, rm); f[rd] = FD(fnmsub, a, b, f[rs3]); return;
    case 0x4f: helper_set_rounding_mode(env, rm); f[rd] = FD(fnmadd, a, b, f[rs3]); return;
    }

    switch (f7 >> 2) {
    case 0x00: helper_set_rounding_mode(env, rm); f[rd] = FD(fadd, a, b); break;
    case 0x01: helper_set_rounding_mode(env, rm); f[rd] = FD(fsub, a, b); break;
    case 0x02: helper_set_rounding_mode(env, rm); f[rd] = FD(fmul, a, b); break;
    case 0x03: helper_set_rounding_mode(env, rm); f[rd] = FD(fdiv, a, b); break;
    case 0x0b: helper_set_rounding_mode(env, rm); f[rd] = FD(fsqrt, a); break;
    case 0x04: { /* fsgnj, fsgnjn, fsgnjx: S keeps rs1's box, checked */
        uint64_t sign = d ? 1ull << 63 : 1ull << 31;

        if (!d) {
            a = aok_check_nanbox_s(a);
            b = aok_check_nanbox_s(b);
        }
        f[rd] = rm == 0 ? ((a & ~sign) | (b & sign)) :
                rm == 1 ? ((a & ~sign) | (~b & sign)) : (a ^ (b & sign));
        break;
    }
    case 0x05: f[rd] = rm == 0 ? FD(fmin, a, b) : FD(fmax, a, b); break;
    case 0x08: /* fcvt.s.d, fcvt.d.s */
        helper_set_rounding_mode(env, rm);
        f[rd] = d ? helper_fcvt_d_s(env, a) : helper_fcvt_s_d(env, a);
        break;
    case 0x14:
        r = rm == 0 ? FD(fle, a, b) : rm == 1 ? FD(flt, a, b) : FD(feq, a, b);
        TO_GPR(r);
        break;
    case 0x18: /* float to integer */
        helper_set_rounding_mode(env, rm);
        r = rs2 == 0 ? FD(fcvt_w, a) : rs2 == 1 ? FD(fcvt_wu, a) :
            rs2 == 2 ? FD(fcvt_l, a) : FD(fcvt_lu, a);
        TO_GPR(r);
        break;
    case 0x1a: /* integer to float */
        helper_set_rounding_mode(env, rm);
        if (d) {
            f[rd] = rs2 == 0 ? helper_fcvt_d_w(env, x) :
                    rs2 == 1 ? helper_fcvt_d_wu(env, x) :
                    rs2 == 2 ? helper_fcvt_d_l(env, x) :
                               helper_fcvt_d_lu(env, x);
        } else {
            f[rd] = rs2 == 0 ? helper_fcvt_s_w(env, x) :
                    rs2 == 1 ? helper_fcvt_s_wu(env, x) :
                    rs2 == 2 ? helper_fcvt_s_l(env, x) :
                               helper_fcvt_s_lu(env, x);
        }
        break;
    case 0x1c:
        if (rm == 0) { /* fmv.x.d, fmv.x.w */
            TO_GPR(d ? a : (uint64_t)(int32_t)a);
        } else { /* fclass */
            r = d ? helper_fclass_d(a) : helper_fclass_s(env, a);
            TO_GPR(r);
        }
        break;
    case 0x1e: /* fmv.d.x, fmv.w.x */
        f[rd] = d ? x : x | 0xffffffff00000000ull;
        break;
    default:
        g_assert_not_reached();
    }
#undef FD
#undef TO_GPR
}

/*
 * A stream is about to compute on the host's FP unit (gadgets.S). From here
 * to the stream's next aok_fp_end the host's FPSR is the guest's flags.
 * Returns whether the host rounds the way the guest's frm asks: QEMU leaves
 * the host's FPCR as it found it, to nearest even and nothing else, and if
 * something has not, the gadgets are told to use softfloat.
 */
uint64_t aok_rv_fp_begin(CPURISCVState *env);
uint64_t aok_rv_fp_begin(CPURISCVState *env)
{
    uint64_t fpcr;

    __asm__ volatile("mrs %0, fpcr\n\tmsr fpsr, xzr" : "=r"(fpcr));
    /* RMode, FZ, DN, AHP, FZ16, and the trap enables. */
    return env->frm == RISCV_FRM_RNE && !(fpcr & 0x07f89f00);
}

/* TCGCPUOps.aok_fold_fpsr: AArch64's cumulative flags to softfloat's. */
void riscv_aok_fold_fpsr(CPUState *cs, uint32_t fpsr)
{
    CPURISCVState *env = cpu_env(cs);
    int flags = 0;

    flags |= fpsr & 0x01 ? float_flag_invalid : 0;      /* IOC */
    flags |= fpsr & 0x02 ? float_flag_divbyzero : 0;    /* DZC */
    flags |= fpsr & 0x04 ? float_flag_overflow : 0;     /* OFC */
    flags |= fpsr & 0x10 ? float_flag_inexact : 0;      /* IXC */
    /* Not UFC: see gadgets.S on underflow. */
    if (flags) {
        set_float_exception_flags(get_float_exception_flags(&env->fp_status)
                                  | flags, &env->fp_status);
    }
}

typedef struct Ctx {
    AokGen g;
    unsigned page_off;      /* of the TB's first insn in its page */
    unsigned off;           /* of the current insn from the TB's first */
    unsigned len;           /* of the current insn */
    uint32_t insn;
    bool has_m, has_mul, has_a, has_fd, has_zba, has_zbb, has_zbs, has_zicond;
    bool no_goto_ptr, no_csr, fp_native;
} Ctx;

/* What translating one insn came to. */
enum { UNKNOWN, NEXT, END };

static inline int64_t sext(uint64_t v, int bits)
{
    return (int64_t)(v << (64 - bits)) >> (64 - bits);
}

/* x0 reads as zero and discards writes: both are slots of their own. */
static inline uint64_t rd_off(unsigned r)
{
    return r ? offsetof(CPURISCVState, gpr[r])
             : offsetof(CPURISCVState, aok_sink);
}

static inline uint64_t rs_off(unsigned r)
{
    return r ? offsetof(CPURISCVState, gpr[r])
             : offsetof(CPURISCVState, aok_zero);
}

static int alu_rr(Ctx *c, Gadget gadget, unsigned rd, unsigned rs1,
                  unsigned rs2)
{
    if (rd) {
        aok_emit_gadget(&c->g, gadget);
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, rs_off(rs1));
        aok_emit(&c->g, rs_off(rs2));
    }
    return NEXT;
}

/* [gadget][a][b][c]: the ALU gadgets' stream, on any three operands. */
static void alu_ri_off(Ctx *c, Gadget gadget, uint64_t rd, uint64_t rs1,
                       uint64_t third)
{
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, rd);
    aok_emit(&c->g, rs1);
    aok_emit(&c->g, third);
}

static int alu_ri(Ctx *c, Gadget gadget, unsigned rd, unsigned rs1,
                  int64_t imm)
{
    if (rd) {
        aok_emit_gadget(&c->g, gadget);
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, rs_off(rs1));
        aok_emit(&c->g, imm);
    }
    return NEXT;
}

static int li(Ctx *c, unsigned rd, int64_t value)
{
    if (rd) {
        aok_emit_gadget(&c->g, G(mov_const));
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, value);
    }
    return NEXT;
}

static int addi(Ctx *c, unsigned rd, unsigned rs1, int64_t imm)
{
    /* (the gadgets iSH-AOK's translator picks for the two: its pairs' names) */
    return rs1 ? alu_ri(c, G(addi), rd, rs1, imm) : li(c, rd, imm);
}

/*
 * The last operand of a load or store, the one the shared gadgets leave to
 * their host: what the slow path needs to name the insn, should it fault.
 */
static inline uint64_t mem_word(Ctx *c)
{
    return (uint64_t)c->off << 32 | c->insn;
}

/* A load is done even into x0: it can fault, or read a device. */
static int load_to(Ctx *c, Gadget gadget, uint64_t reg_off, unsigned rs1,
                   int64_t imm)
{
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, reg_off);
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, imm);
    aok_emit(&c->g, mem_word(c));
    return NEXT;
}

static int load(Ctx *c, Gadget gadget, unsigned rd, unsigned rs1, int64_t imm)
{
    return load_to(c, gadget, rd_off(rd), rs1, imm);
}

static int store_from(Ctx *c, Gadget gadget, uint64_t reg_off, unsigned rs1,
                      int64_t imm)
{
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, reg_off);
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, imm);
    aok_emit(&c->g, mem_word(c));
    return NEXT;
}

static int store(Ctx *c, Gadget gadget, unsigned rs2, unsigned rs1,
                 int64_t imm)
{
    return store_from(c, gadget, rs_off(rs2), rs1, imm);
}

static inline uint64_t fpr_off(unsigned r)
{
    return offsetof(CPURISCVState, fpr[r]);
}

/* fld, fsd, flw, fsw: the integer loads and stores, on an FP register. */
static int fp_load(Ctx *c, bool d, unsigned rd, unsigned rs1, int64_t imm)
{
    if (!c->has_fd) {
        return UNKNOWN;
    }
    return load_to(c, d ? G(ld) : G(flw), fpr_off(rd), rs1, imm);
}

static int fp_store(Ctx *c, bool d, unsigned rs2, unsigned rs1, int64_t imm)
{
    if (!c->has_fd) {
        return UNKNOWN;
    }
    return store_from(c, d ? G(sd) : G(sw), fpr_off(rs2), rs1, imm);
}

/*
 * The [pc delta][slot] pair of a direct jump to @delta bytes from the TB's
 * first insn. As with goto_tb, only a destination in the TB's own page may
 * be linked; any other is looked up each time.
 */
static void jump_operands(Ctx *c, int n, int64_t delta)
{
    int64_t dest = (int64_t)c->page_off + delta;

    aok_emit(&c->g, delta);
    if (dest >= 0 && dest < TARGET_PAGE_SIZE) {
        aok_emit(&c->g, aok_slot(&c->g, n));
    } else {
        aok_emit(&c->g, aok_slot_unlinked(&c->g));
    }
}

/* (iSH-AOK's b: aok_gadget_goto under the name its pairs know) */
static void jump(Ctx *c, int n, int64_t delta)
{
    aok_emit_gadget(&c->g, G(b));
    jump_operands(c, n, delta);
}

/*
 * A conditional branch, by funct3. Each has two layouts, as in iSH-AOK: a
 * backward branch (a loop: mostly taken) gets the one whose taken way is the
 * straight line.
 */
static int branch(Ctx *c, unsigned f3, unsigned rs1, unsigned rs2,
                  int64_t imm)
{
    static const Gadget fw[8] = {
        G(beq), G(bne), NULL, NULL, G(blt), G(bge), G(bltu), G(bgeu),
    };
    static const Gadget bk[8] = {
        G(beq_bk), G(bne_bk), NULL, NULL,
        G(blt_bk), G(bge_bk), G(bltu_bk), G(bgeu_bk),
    };
    Gadget gadget = (imm < 0 ? bk : fw)[f3];

    if (!gadget) {
        return UNKNOWN;
    }
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, rs_off(rs2));
    jump_operands(c, 0, c->off + imm);
    jump_operands(c, 1, c->off + c->len);
    return END;
}

static int jal(Ctx *c, unsigned rd, int64_t imm)
{
    if (rd) {
        /* A call: the link and the jump in one gadget. */
        aok_emit_gadget(&c->g, G(jal_link));
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, c->off + c->len);
        jump_operands(c, 0, c->off + imm);
    } else {
        jump(c, 0, c->off + imm);
    }
    return END;
}

static int jalr(Ctx *c, unsigned rd, unsigned rs1, int64_t imm)
{
    aok_emit_gadget(&c->g, c->no_goto_ptr ? G(jalr) : G(jalr_cached));
    aok_emit(&c->g, rd_off(rd));
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, imm);
    aok_emit(&c->g, c->off + c->len);
    if (c->no_goto_ptr) {
        aok_emit_gadget(&c->g, aok_gadget_exit_tb);
        aok_emit(&c->g, 0);
    } else {
        aok_emit_lookup_operands(&c->g);
    }
    return END;
}

static int call(Ctx *c, Gadget gadget, void *fn)
{
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, (uintptr_t)fn);
    aok_emit(&c->g, c->off);
    aok_emit(&c->g, c->insn);
    return gadget == G(call) ? NEXT : END;
}

static int atomic(Ctx *c, uint32_t insn)
{
    unsigned f3 = (insn >> 12) & 7, rs2 = (insn >> 20) & 31;

    if (!c->has_a || (f3 != 2 && f3 != 3)) {
        return UNKNOWN;
    }
    switch (insn >> 27) {
    case 0x02:
        if (rs2) {
            return UNKNOWN;
        }
        /* fall through */
    case 0x03: case 0x01: case 0x00: case 0x04: case 0x0c: case 0x08:
    case 0x10: case 0x14: case 0x18: case 0x1c:
        return call(c, G(call), aok_rv_helper_atomic);
    }
    return UNKNOWN;
}

/* A host-FP gadget's stream; @n register offsets, then the pc and insn. */
static bool fp_emit(Ctx *c, Gadget gadget, int n, uint64_t o0, uint64_t o1,
                    uint64_t o2, uint64_t o3)
{
    uint64_t o[4] = { o0, o1, o2, o3 };

    aok_emit_gadget(&c->g, gadget);
    for (int i = 0; i < n; i++) {
        aok_emit(&c->g, o[i]);
    }
    aok_emit(&c->g, c->off);
    aok_emit(&c->g, c->insn);
    return true;
}

/*
 * The double-precision insns that have a gadget on the host's FP unit, for
 * the rounding modes it has one for. The rest of F and D is C's.
 */
static bool fp_native(Ctx *c, uint32_t insn)
{
    static const Gadget arith[4] = {
        G(fadd_d), G(fsub_d), G(fmul_d), G(fdiv_d),
    };
    static const Gadget toint[2][4] = {
        { G(fcvt_w_d_rtz), G(fcvt_wu_d_rtz), G(fcvt_l_d_rtz), G(fcvt_lu_d_rtz) },
        { G(fcvt_w_d_dyn), G(fcvt_wu_d_dyn), G(fcvt_l_d_dyn), G(fcvt_lu_d_dyn) },
    };
    static const Gadget fromint[4] = {
        G(fcvt_d_w), G(fcvt_d_wu), G(fcvt_d_l), G(fcvt_d_lu),
    };
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, rs3 = insn >> 27;
    unsigned rm = (insn >> 12) & 7, f7 = insn >> 25;
    uint64_t fd = fpr_off(rd), fa = fpr_off(rs1), fb = fpr_off(rs2);
    bool nearest = rm == 7 || rm == 0;  /* the gadgets test frm for both */

    if ((insn & 0x7f) != 0x53) {
        static const Gadget fma[4] = {
            G(fmadd_d), G(fmsub_d), G(fnmsub_d), G(fnmadd_d),
        };

        if (((insn >> 25) & 3) != 1 || !nearest) {
            return false;
        }
        return fp_emit(c, fma[((insn & 0x7f) - 0x43) >> 2], 4,
                       fd, fa, fb, fpr_off(rs3));
    }
    if (!(f7 & 1)) {
        return false;
    }
    switch (f7 >> 2) {
    case 0x00: case 0x01: case 0x02: case 0x03:
        return nearest && fp_emit(c, arith[f7 >> 2], 3, fd, fa, fb, 0);
    case 0x0b:
        return nearest && fp_emit(c, G(fsqrt_d), 3, fd, fa, fa, 0);
    case 0x04:
        if (rs1 == rs2) { /* fmv.d, fneg.d, fabs.d */
            alu_ri_off(c, rm == 0 ? G(add_ri) : rm == 1 ? G(xor_ri) : G(and_ri),
                       fd, fa, rm == 0 ? 0 : rm == 1 ? INT64_MIN : INT64_MAX);
        } else {
            alu_ri_off(c, rm == 0 ? G(fsgnj_d) : rm == 1 ? G(fsgnjn_d)
                                                         : G(fsgnjx_d),
                       fd, fa, fb);
        }
        return true;
    case 0x14: /* fle, flt, feq */
        return fp_emit(c, rm == 0 ? G(fle_d) : rm == 1 ? G(flt_d) : G(feq_d),
                       3, rd_off(rd), fa, fb, 0);
    case 0x18:
        if (rm != 1 && rm != 7) {
            return false;
        }
        return fp_emit(c, toint[rm == 7][rs2], 3, rd_off(rd), fa, fa, 0);
    case 0x1a:
        return rm == 7 &&
               fp_emit(c, fromint[rs2], 3, fd, rs_off(rs1), rs_off(rs1), 0);
    case 0x1c:
        if (rm == 0) { /* fmv.x.d */
            if (rd) {
                alu_ri_off(c, G(add_ri), rd_off(rd), fa, 0);
            }
            return true;
        }
        return false;
    case 0x1e: /* fmv.d.x */
        alu_ri_off(c, G(add_ri), fd, rs_off(rs1), 0);
        return true;
    }
    return false;
}

/* OP-FP and the fused multiply-adds: exactly what aok_rv_helper_fp knows. */
static int fp(Ctx *c, uint32_t insn)
{
    unsigned rs2 = (insn >> 20) & 31, rm = (insn >> 12) & 7, f7 = insn >> 25;
    bool ok;

    if (!c->has_fd) {
        return UNKNOWN;
    }
    if ((insn & 0x7f) != 0x53) {
        ok = ((insn >> 25) & 3) < 2;
    } else {
        switch (f7 >> 2) {
        case 0x00: case 0x01: case 0x02: case 0x03:
            ok = true;
            break;
        case 0x0b: ok = rs2 == 0; break;
        case 0x04: ok = rm < 3; break;
        case 0x05: ok = rm < 2; break;
        case 0x08: ok = rs2 == (f7 == 0x20 ? 1 : 0); break;
        case 0x14: ok = rm < 3; break;
        case 0x18: case 0x1a: ok = rs2 < 4; break;
        case 0x1c: ok = rs2 == 0 && rm < 2; break;
        case 0x1e: ok = rs2 == 0 && rm == 0; break;
        default: ok = false;
        }
        ok = ok && (f7 & 3) < 2;
    }
    if (!ok) {
        return UNKNOWN;
    }
    if (c->fp_native && fp_native(c, insn)) {
        return NEXT;
    }
    return call(c, G(call), aok_rv_helper_fp);
}

static int op_imm(Ctx *c, uint32_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned f3 = (insn >> 12) & 7, top6 = insn >> 26, imm12 = insn >> 20;
    unsigned shamt = imm12 & 63;
    int64_t imm = sext(imm12, 12);

    switch (f3) {
    case 0: return addi(c, rd, rs1, imm);
    case 2: return alu_ri(c, G(slt_ri), rd, rs1, imm);
    case 3: return alu_ri(c, G(sltu_ri), rd, rs1, imm);
    case 4: return alu_ri(c, G(xor_ri), rd, rs1, imm);
    case 6: return alu_ri(c, G(or_ri), rd, rs1, imm);
    case 7: return alu_ri(c, G(and_ri), rd, rs1, imm);
    case 1:
        if (top6 == 0x00) {
            return alu_ri(c, G(sll_ri), rd, rs1, shamt);
        }
        if (c->has_zbb) {
            switch (imm12) {
            case 0x600: return alu_ri(c, G(clz_ri), rd, rs1, 0);
            case 0x601: return alu_ri(c, G(ctz_ri), rd, rs1, 0);
            case 0x602: return alu_ri(c, G(cpop_ri), rd, rs1, 0);
            case 0x604: return alu_ri(c, G(sext_b_ri), rd, rs1, 0);
            case 0x605: return alu_ri(c, G(sext_h_ri), rd, rs1, 0);
            }
        }
        if (c->has_zbs) {
            switch (top6) {
            case 0x12: return alu_ri(c, G(bclr_ri), rd, rs1, shamt);
            case 0x0a: return alu_ri(c, G(bset_ri), rd, rs1, shamt);
            case 0x1a: return alu_ri(c, G(binv_ri), rd, rs1, shamt);
            }
        }
        return UNKNOWN;
    case 5:
        if (top6 == 0x00) {
            return alu_ri(c, G(srl_ri), rd, rs1, shamt);
        }
        if (top6 == 0x10) {
            return alu_ri(c, G(sra_ri), rd, rs1, shamt);
        }
        if (c->has_zbb) {
            if (imm12 == 0x287) {
                return alu_ri(c, G(orc_b_ri), rd, rs1, 0);
            }
            if (imm12 == 0x6b8) {
                return alu_ri(c, G(rev8_ri), rd, rs1, 0);
            }
            if (top6 == 0x18) {
                return alu_ri(c, G(ror_ri), rd, rs1, shamt);
            }
        }
        if (c->has_zbs && top6 == 0x12) {
            return alu_ri(c, G(bext_ri), rd, rs1, shamt);
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

static int op_imm_32(Ctx *c, uint32_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned f3 = (insn >> 12) & 7, f7 = insn >> 25, imm12 = insn >> 20;
    unsigned shamt = imm12 & 31;

    switch (f3) {
    case 0:
        return alu_ri(c, G(addw_ri), rd, rs1, sext(imm12, 12));
    case 1:
        if (f7 == 0x00) {
            return alu_ri(c, G(sllw_ri), rd, rs1, shamt);
        }
        if (c->has_zba && (insn >> 26) == 0x02) {
            return alu_ri(c, G(slli_uw_ri), rd, rs1, imm12 & 63);
        }
        if (c->has_zbb) {
            switch (imm12) {
            case 0x600: return alu_ri(c, G(clzw_ri), rd, rs1, 0);
            case 0x601: return alu_ri(c, G(ctzw_ri), rd, rs1, 0);
            case 0x602: return alu_ri(c, G(cpopw_ri), rd, rs1, 0);
            }
        }
        return UNKNOWN;
    case 5:
        switch (f7) {
        case 0x00: return alu_ri(c, G(srlw_ri), rd, rs1, shamt);
        case 0x20: return alu_ri(c, G(sraw_ri), rd, rs1, shamt);
        case 0x30:
            if (c->has_zbb) {
                return alu_ri(c, G(rorw_ri), rd, rs1, shamt);
            }
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

static int op(Ctx *c, uint32_t insn)
{
    static const Gadget base[8] = {
        G(add_rr), G(sll_rr), G(slt_rr), G(sltu_rr),
        G(xor_rr), G(srl_rr), G(or_rr), G(and_rr),
    };
    static const Gadget muldiv[8] = {
        G(mul_rr), G(mulh_rr), G(mulhsu_rr), G(mulhu_rr),
        G(div_rr), G(divu_rr), G(rem_rr), G(remu_rr),
    };
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, f3 = (insn >> 12) & 7, f7 = insn >> 25;
    Gadget g = NULL;

    switch (f7) {
    case 0x00:
        g = base[f3];
        break;
    case 0x20:
        g = f3 == 0 ? G(sub_rr) : f3 == 5 ? G(sra_rr) : NULL;
        if (!g && c->has_zbb) {
            g = f3 == 7 ? G(andn_rr) : f3 == 6 ? G(orn_rr) :
                f3 == 4 ? G(xnor_rr) : NULL;
        }
        break;
    case 0x01:
        if (c->has_m || (c->has_mul && f3 < 4)) {
            g = muldiv[f3];
        }
        break;
    case 0x10:
        if (c->has_zba) {
            g = f3 == 2 ? G(sh1add_rr) : f3 == 4 ? G(sh2add_rr) :
                f3 == 6 ? G(sh3add_rr) : NULL;
        }
        break;
    case 0x05:
        if (c->has_zbb) {
            g = f3 == 4 ? G(min_rr) : f3 == 5 ? G(minu_rr) :
                f3 == 6 ? G(max_rr) : f3 == 7 ? G(maxu_rr) : NULL;
        }
        break;
    case 0x30:
        if (c->has_zbb) {
            g = f3 == 1 ? G(rol_rr) : f3 == 5 ? G(ror_rr) : NULL;
        }
        break;
    case 0x24:
        if (c->has_zbs) {
            g = f3 == 1 ? G(bclr_rr) : f3 == 5 ? G(bext_rr) : NULL;
        }
        break;
    case 0x14:
        if (c->has_zbs && f3 == 1) {
            g = G(bset_rr);
        }
        break;
    case 0x34:
        if (c->has_zbs && f3 == 1) {
            g = G(binv_rr);
        }
        break;
    case 0x07:
        if (c->has_zicond) {
            g = f3 == 5 ? G(czero_eqz_rr) : f3 == 7 ? G(czero_nez_rr) : NULL;
        }
        break;
    }
    return g ? alu_rr(c, g, rd, rs1, rs2) : UNKNOWN;
}

static int op_32(Ctx *c, uint32_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, f3 = (insn >> 12) & 7, f7 = insn >> 25;
    Gadget g = NULL;

    switch (f7) {
    case 0x00:
        g = f3 == 0 ? G(addw_rr) : f3 == 1 ? G(sllw_rr) :
            f3 == 5 ? G(srlw_rr) : NULL;
        break;
    case 0x20:
        g = f3 == 0 ? G(subw_rr) : f3 == 5 ? G(sraw_rr) : NULL;
        break;
    case 0x01:
        if (c->has_m || (c->has_mul && f3 == 0)) {
            g = f3 == 0 ? G(mulw_rr) : f3 == 4 ? G(divw_rr) :
                f3 == 5 ? G(divuw_rr) : f3 == 6 ? G(remw_rr) :
                f3 == 7 ? G(remuw_rr) : NULL;
        }
        break;
    case 0x04:
        if (c->has_zba && f3 == 0) {
            g = G(add_uw_rr);
        } else if (c->has_zbb && f3 == 4 && rs2 == 0) {
            return alu_ri(c, G(zext_h_ri), rd, rs1, 0);
        }
        break;
    case 0x10:
        if (c->has_zba) {
            g = f3 == 2 ? G(sh1add_uw_rr) : f3 == 4 ? G(sh2add_uw_rr) :
                f3 == 6 ? G(sh3add_uw_rr) : NULL;
        }
        break;
    case 0x30:
        if (c->has_zbb) {
            g = f3 == 1 ? G(rolw_rr) : f3 == 5 ? G(rorw_rr) : NULL;
        }
        break;
    }
    return g ? alu_rr(c, g, rd, rs1, rs2) : UNKNOWN;
}

static int insn32(Ctx *c, uint32_t insn)
{
    static const Gadget loads[8] = {
        G(lb), G(lh), G(lw), G(ld), G(lbu), G(lhu), G(lwu), NULL,
    };
    static const Gadget stores[8] = { G(sb), G(sh), G(sw), G(sd) };
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, f3 = (insn >> 12) & 7;

    switch (insn & 0x7f) {
    case 0x37: /* lui */
        return li(c, rd, sext(insn & 0xfffff000, 32));
    case 0x17: /* auipc */
        if (rd) {
            aok_emit_gadget(&c->g, G(pcrel));
            aok_emit(&c->g, rd_off(rd));
            aok_emit(&c->g, c->off + sext(insn & 0xfffff000, 32));
        }
        return NEXT;
    case 0x6f: /* jal */
        return jal(c, rd, sext((((insn >> 31) & 1) << 20) |
                               (((insn >> 12) & 0xff) << 12) |
                               (((insn >> 20) & 1) << 11) |
                               (((insn >> 21) & 0x3ff) << 1), 21));
    case 0x67: /* jalr */
        return f3 == 0 ? jalr(c, rd, rs1, sext(insn >> 20, 12)) : UNKNOWN;
    case 0x63: /* branches */
        return branch(c, f3, rs1, rs2,
                      sext((((insn >> 31) & 1) << 12) |
                           (((insn >> 7) & 1) << 11) |
                           (((insn >> 25) & 0x3f) << 5) |
                           (((insn >> 8) & 0xf) << 1), 13));
    case 0x03: /* loads */
        return loads[f3] ? load(c, loads[f3], rd, rs1, sext(insn >> 20, 12))
                         : UNKNOWN;
    case 0x23: /* stores */
        return stores[f3] ? store(c, stores[f3], rs2, rs1,
                                  sext(((insn >> 25) << 5) |
                                       ((insn >> 7) & 31), 12))
                          : UNKNOWN;
    case 0x13:
        return op_imm(c, insn);
    case 0x1b:
        return op_imm_32(c, insn);
    case 0x33:
        return op(c, insn);
    case 0x3b:
        return op_32(c, insn);
    case 0x2f:
        return atomic(c, insn);
    case 0x07: /* flw, fld */
        return f3 == 2 || f3 == 3 ? fp_load(c, f3 == 3, rd, rs1,
                                            sext(insn >> 20, 12)) : UNKNOWN;
    case 0x27: /* fsw, fsd */
        return f3 == 2 || f3 == 3 ? fp_store(c, f3 == 3, rs2, rs1,
                                             sext(((insn >> 25) << 5) |
                                                  ((insn >> 7) & 31), 12))
                                  : UNKNOWN;
    case 0x43: case 0x47: case 0x4b: case 0x4f: case 0x53:
        return fp(c, insn);
    case 0x73:
        /* The CSR accesses; ecall, sret and the rest of f3 == 0 are TCG's. */
        if ((f3 & 3) == 0 || c->no_csr) {
            return UNKNOWN;
        }
        return call(c, G(call_exit), aok_rv_helper_csr);
    case 0x0f:
        if (f3 == 0) { /* fence; fence.i is TCG's */
            aok_emit_gadget(&c->g, G(fence));
            return NEXT;
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

/* The C extension, RV64: each insn here is one of the above in 16 bits. */
static int insn16(Ctx *c, uint32_t insn)
{
    unsigned f3 = (insn >> 13) & 7, b12 = (insn >> 12) & 1;
    unsigned rd = (insn >> 7) & 31, rs2 = (insn >> 2) & 31;
    unsigned rdp = 8 + ((insn >> 2) & 7), rs1p = 8 + ((insn >> 7) & 7);
    unsigned imm5 = (insn >> 2) & 0x1f;
    int64_t imm6 = sext((b12 << 5) | imm5, 6);
    int64_t imm;

    switch (insn & 3) {
    case 0:
        switch (f3) {
        case 0: /* c.addi4spn */
            imm = (((insn >> 11) & 3) << 4) | (((insn >> 7) & 0xf) << 6) |
                  (((insn >> 6) & 1) << 2) | (((insn >> 5) & 1) << 3);
            return imm ? alu_ri(c, G(addi), rdp, 2, imm) : UNKNOWN;
        case 2: /* c.lw */
        case 6: /* c.sw */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 6) & 1) << 2) |
                  (((insn >> 5) & 1) << 6);
            return f3 == 2 ? load(c, G(lw), rdp, rs1p, imm)
                           : store(c, G(sw), rdp, rs1p, imm);
        case 3: /* c.ld */
        case 7: /* c.sd */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 5) & 3) << 6);
            return f3 == 3 ? load(c, G(ld), rdp, rs1p, imm)
                           : store(c, G(sd), rdp, rs1p, imm);
        case 1: /* c.fld */
        case 5: /* c.fsd */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 5) & 3) << 6);
            return f3 == 1 ? fp_load(c, true, rdp, rs1p, imm)
                           : fp_store(c, true, rdp, rs1p, imm);
        }
        return UNKNOWN;
    case 1:
        switch (f3) {
        case 0: /* c.addi, c.nop */
            return alu_ri(c, G(addi), rd, rd, imm6);
        case 1: /* c.addiw */
            return rd ? alu_ri(c, G(addw_ri), rd, rd, imm6) : UNKNOWN;
        case 2: /* c.li */
            return li(c, rd, imm6);
        case 3:
            if (rd == 2) { /* c.addi16sp */
                imm = sext((b12 << 9) | (((insn >> 6) & 1) << 4) |
                           (((insn >> 5) & 1) << 6) |
                           (((insn >> 3) & 3) << 7) |
                           (((insn >> 2) & 1) << 5), 10);
                return imm ? alu_ri(c, G(addi), 2, 2, imm) : UNKNOWN;
            }
            /* c.lui */
            return imm6 ? li(c, rd, imm6 << 12) : UNKNOWN;
        case 4:
            switch ((insn >> 10) & 3) {
            case 0: /* c.srli */
                return alu_ri(c, G(srl_ri), rs1p, rs1p, (b12 << 5) | imm5);
            case 1: /* c.srai */
                return alu_ri(c, G(sra_ri), rs1p, rs1p, (b12 << 5) | imm5);
            case 2: /* c.andi */
                return alu_ri(c, G(and_ri), rs1p, rs1p, imm6);
            }
            switch ((b12 << 2) | ((insn >> 5) & 3)) {
            case 0: return alu_rr(c, G(sub_rr), rs1p, rs1p, rdp);
            case 1: return alu_rr(c, G(xor_rr), rs1p, rs1p, rdp);
            case 2: return alu_rr(c, G(or_rr), rs1p, rs1p, rdp);
            case 3: return alu_rr(c, G(and_rr), rs1p, rs1p, rdp);
            case 4: return alu_rr(c, G(subw_rr), rs1p, rs1p, rdp);
            case 5: return alu_rr(c, G(addw_rr), rs1p, rs1p, rdp);
            }
            return UNKNOWN; /* Zcb */
        case 5: /* c.j */
            return jal(c, 0, sext((b12 << 11) | (((insn >> 11) & 1) << 4) |
                                  (((insn >> 9) & 3) << 8) |
                                  (((insn >> 8) & 1) << 10) |
                                  (((insn >> 7) & 1) << 6) |
                                  (((insn >> 6) & 1) << 7) |
                                  (((insn >> 3) & 7) << 1) |
                                  (((insn >> 2) & 1) << 5), 12));
        case 6: /* c.beqz */
        case 7: /* c.bnez */
            imm = sext((b12 << 8) | (((insn >> 10) & 3) << 3) |
                       (((insn >> 5) & 3) << 6) | (((insn >> 3) & 3) << 1) |
                       (((insn >> 2) & 1) << 5), 9);
            return branch(c, f3 == 6 ? 0 : 1, rs1p, 0, imm);
        }
        return UNKNOWN;
    case 2:
        switch (f3) {
        case 0: /* c.slli */
            return alu_ri(c, G(sll_ri), rd, rd, (b12 << 5) | imm5);
        case 2: /* c.lwsp */
            imm = (b12 << 5) | (((insn >> 4) & 7) << 2) |
                  (((insn >> 2) & 3) << 6);
            return rd ? load(c, G(lw), rd, 2, imm) : UNKNOWN;
        case 3: /* c.ldsp */
            imm = (b12 << 5) | (((insn >> 5) & 3) << 3) |
                  (((insn >> 2) & 7) << 6);
            return rd ? load(c, G(ld), rd, 2, imm) : UNKNOWN;
        case 1: /* c.fldsp */
            imm = (b12 << 5) | (((insn >> 5) & 3) << 3) |
                  (((insn >> 2) & 7) << 6);
            return fp_load(c, true, rd, 2, imm);
        case 5: /* c.fsdsp */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 7) & 7) << 6);
            return fp_store(c, true, rs2, 2, imm);
        case 4:
            if (!b12) {
                if (rs2) { /* c.mv */
                    return alu_ri(c, G(add_ri), rd, rs2, 0);
                }
                return rd ? jalr(c, 0, rd, 0) : UNKNOWN; /* c.jr */
            }
            if (rs2) { /* c.add */
                return alu_rr(c, G(add_rr), rd, rd, rs2);
            }
            return rd ? jalr(c, 1, rd, 0) : UNKNOWN; /* c.jalr; c.ebreak */
        case 6: /* c.swsp */
            imm = (((insn >> 9) & 0xf) << 2) | (((insn >> 7) & 3) << 6);
            return store(c, G(sw), rs2, 2, imm);
        case 7: /* c.sdsp */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 7) & 7) << 6);
            return store(c, G(sd), rs2, 2, imm);
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

int riscv_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                             int *max_insns, vaddr pc, void *host_pc)
{
    CPURISCVState *env = cpu_env(cs);
    const RISCVCPUConfig *cfg = &env_archcpu(env)->cfg;
    uint32_t flags = tb->flags, cflags = tb_cflags(tb);
    uint32_t misa = FIELD_EX64(tb->cs_base, EXT_TB_FLAGS, MISA_EXT);
    const uint8_t *code = host_pc;
    Ctx c = { .len = 4 };
    int r = NEXT;

    /*
     * The states this translator knows: RV64 with a little-endian guest,
     * not virtualized, no pointer masking, no CFI, no instruction-count
     * trigger, and the C extension, without which a jump can raise a
     * misaligned-address exception. And an ordinary TB: one in RAM that may
     * check for interrupts and need not stop after a set number of insns.
     */
    if (!code || !(cflags & CF_PCREL) ||
        (cflags & (CF_COUNT_MASK | CF_SINGLE_STEP | CF_MEMI_ONLY |
                   CF_USE_ICOUNT | CF_NOIRQ | CF_BP_PAGE | CF_STEP_ATOMIC)) ||
        FIELD_EX32(flags, TB_FLAGS, XL) != MXL_RV64 ||
        FIELD_EX32(flags, TB_FLAGS, AXL) != MXL_RV64 ||
        FIELD_EX32(flags, TB_FLAGS, PM_PMM) ||
        FIELD_EX32(flags, TB_FLAGS, ITRIGGER) ||
        FIELD_EX32(flags, TB_FLAGS, VIRT_ENABLED) ||
        FIELD_EX32(flags, TB_FLAGS, FCFI_ENABLED) ||
        FIELD_EX32(flags, TB_FLAGS, BCFI_ENABLED) ||
        FIELD_EX64(tb->cs_base, EXT_TB_FLAGS, BIG_ENDIAN) ||
        !cfg->ext_zca) {
        return 0;
    }

    c.page_off = pc & ~TARGET_PAGE_MASK;
    c.off = 0;
    c.has_m = misa & RVM;
    c.has_mul = c.has_m || cfg->ext_zmmul;
    c.has_a = (misa & RVA) && !getenv("QEMU_AOK_NO_ATOMIC");
    /* F and D as registers of their own, and already dirty in mstatus. */
    c.has_fd = (misa & RVF) && (misa & RVD) && !cfg->ext_zfinx &&
               FIELD_EX32(flags, TB_FLAGS, FS) == EXT_STATUS_DIRTY &&
               !getenv("QEMU_AOK_NO_FP");
    c.no_csr = getenv("QEMU_AOK_NO_CSR");
    c.fp_native = !getenv("QEMU_AOK_NO_FPNATIVE");
    c.has_zba = cfg->ext_zba;
    c.has_zbb = cfg->ext_zbb;
    c.has_zbs = cfg->ext_zbs;
    c.has_zicond = cfg->ext_zicond;
    c.no_goto_ptr = cflags & CF_NO_GOTO_PTR;
    aok_gen_begin(&c.g, cs, tb, *max_insns, FIELD_EX32(flags, TB_FLAGS, MEM_IDX));
    c.g.lookup = G(lookup);

    /* A TB stays in its page: an insn that would straddle the end is TCG's. */
    while (aok_gen_room(&c.g, 12)) {
        unsigned left = TARGET_PAGE_SIZE - (c.page_off + c.off);
        uint64_t *start = c.g.p;

        if (left < 2) {
            break;
        }
        c.insn = lduw_le_p(code + c.off);
        if ((c.insn & 3) != 3) {
            c.len = 2;
            r = insn16(&c, c.insn);
        } else if (left < 4) {
            break;
        } else {
            c.insn = ldl_le_p(code + c.off);
            c.len = 4;
            r = insn32(&c, c.insn);
        }
        if (r == UNKNOWN) {
            c.g.p = start;
            break;
        }
        if (rv_pairs_on) {
            aok_gen_pair(&c.g, start, &rv_pairs);
        }
        aok_gen_insn_end(&c.g, c.page_off + c.off, c.insn);
        c.off += c.len;
        if (r == END) {
            break;
        }
    }
    if (c.g.n_insns == 0) {
        aok_stats.declined_first++;
        if (c.len == 4) {
            aok_stats.declined_op[c.insn & 0x7f]++;
        } else {
            aok_stats.declined_c++;
        }
        return 0;
    }
    if (r != END) {
        /* Not an insn, but a gadget like another to the insn before it. */
        uint64_t *start = c.g.p;

        jump(&c, 0, c.off);
        if (rv_pairs_on) {
            aok_gen_pair(&c.g, start, &rv_pairs);
        }
    }
    return aok_gen_finish(&c.g, c.off);
}
