/*
 * AOK gadgets for x86-64 guests: the translator.
 *
 * Turns 64-bit code into a gadget stream (include/accel/tcg/aok.h). It
 * decodes what it is sure of and stops in front of anything else, so that
 * the next TB starts there and TCG translates it; a TB whose first insn is
 * one of those is declined outright. Two kinds of code are translated: long
 * mode's 64-bit code, and 32-bit protected-mode code with a 32-bit stack and
 * flat segments, which is what a 32-bit operating system and its programs
 * run in (and a 64-bit one's 32-bit programs). The rest of the architecture's
 * modes are firmware's and a boot loader's, and TCG's.
 *
 * Conditions. The flags are QEMU's lazy ones and every gadget that sets them
 * stores them (gadgets.S), so they are exact wherever anything looks. What
 * is tracked here is only a shortcut: which of the guest's flags the host's
 * NZCV holds where the next gadget begins (Ctx.hf), and which lazy operation
 * the stored state is of (Ctx.cc). A condition that the host's flags decide
 * is tested on them; one they do not is first made so from the stored state
 * (the hf gadgets), or computed in C.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "qemu/host-utils.h"
#include "qemu/int128.h"
#include "qemu/atomic128.h"
#include "cpu.h"
#include "fpu/softfloat.h"
#include "exec/helper-proto.h"
#include "tcg/helper-tcg.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "accel/tcg/aok.h"
#include "accel/tcg/cpu-ldst-common.h"
#include "accel/tcg/cpu-mmu-index.h"
#include "accel/tcg/probe.h"
#include "aok-i386.h"
#include "aok-i386-asm.h"

#define G(name) aok_gadget_x86_##name
#define DECL(name) void G(name)(void);
#define SIZES(X, n) X(n##8) X(n##16) X(n##32) X(n##64)
#define ENTRY(name) G(name),

typedef void (*Gadget)(void);

/*
 * A gadget with a memory operand: [form][with barriers]. The forms are a
 * base and a displacement, what an ea gadget left, and a base and a
 * displacement in 32-bit code.
 */
enum { F_BD, F_EA, F_B3 };
typedef Gadget MemTab[3][2];
#define MEMD(n) DECL(n##_bd) DECL(n##_bd_mp) DECL(n##_ea) DECL(n##_ea_mp) \
    DECL(n##_b3) DECL(n##_b3_mp)
#define MEMT(n) { { G(n##_bd), G(n##_bd_mp) }, { G(n##_ea), G(n##_ea_mp) }, \
                  { G(n##_b3), G(n##_b3_mp) } },

DECL(ea) DECL(ea_seg) DECL(ea_pc) DECL(ea_pc_seg) DECL(ea32) DECL(ea32_seg)
DECL(ea32_seg64) DECL(ea_pc32) DECL(ea_pc32_seg)
DECL(bt_ea64) DECL(bt_ea32) DECL(bt_ea32_32)
SIZES(DECL, mov)
DECL(movzx8) DECL(movzx16) DECL(movsx8_32) DECL(movsx8_64)
DECL(movsx16_32) DECL(movsx16_64) DECL(movsx32_64)
DECL(movi8) DECL(movi16) DECL(movi64) DECL(pcrel)
DECL(lea64) DECL(lea32) DECL(lea_ea64) DECL(lea_ea32)
DECL(xchg32) DECL(xchg64) DECL(cdqe) DECL(cwde) DECL(cqo) DECL(cdq)

SIZES(MEMD, load) SIZES(MEMD, loadw) SIZES(MEMD, store) SIZES(MEMD, storei)
MEMD(loadzx8) MEMD(loadzx16) MEMD(loadsx8_32) MEMD(loadsx8_64)
MEMD(loadsx16_32) MEMD(loadsx16_64) MEMD(loadsx32_64)
static const MemTab load_tab[4] = { SIZES(MEMT, load) };
static const MemTab loadw_tab[4] = { SIZES(MEMT, loadw) };
static const MemTab store_tab[4] = { SIZES(MEMT, store) };
static const MemTab storei_tab[4] = { SIZES(MEMT, storei) };
/* [the source's size][a 64-bit destination] */
static const MemTab loadzx_tab[2] = { MEMT(loadzx8) MEMT(loadzx16) };
static const MemTab loadsx_tab[3][2] = {
    { MEMT(loadsx8_32) MEMT(loadsx8_64) },
    { MEMT(loadsx16_32) MEMT(loadsx16_64) },
    { MEMT(loadsx32_64) MEMT(loadsx32_64) },
};
static const Gadget mov_tab[4] = { SIZES(ENTRY, mov) };

/* SSE (gadgets.S): the loads and stores, the shapes, and the thunks. */
MEMD(vload128) MEMD(vload128a) MEMD(vstore128) MEMD(vstore128a)
MEMD(vload32z) MEMD(vload64z)
/* [aligned] */
static const MemTab vload_tab[2] = { MEMT(vload128) MEMT(vload128a) };
static const MemTab vstore_tab[2] = { MEMT(vstore128) MEMT(vstore128a) };
/* [64 bits] */
static const MemTab vloadz_tab[2] = { MEMT(vload32z) MEMT(vload64z) };
DECL(vmov128) DECL(vmov32) DECL(vmovq) DECL(vmovd)
DECL(vop) DECL(vshift) DECL(vtbl) DECL(vtbl2) DECL(pmovmskb)
DECL(call_h3) DECL(call_h3cc) DECL(call_hval) DECL(call_hret32)
DECL(call_hret64)
/* Doubles on the host's FP unit: each is call_h3 (or as named) otherwise. */
DECL(fp_addsd) DECL(fp_subsd) DECL(fp_mulsd) DECL(fp_divsd) DECL(fp_sqrtsd)
DECL(fp_addpd) DECL(fp_subpd) DECL(fp_mulpd) DECL(fp_divpd)
DECL(fp_comisd) DECL(fp_cvtsi2sd) DECL(fp_cvtsq2sd)
DECL(fp_cvttsd2si) DECL(fp_cvttsd2sq)
#define TH(name) aok_x86_thunk_##name
#define THD(name) void TH(name)(void);
#define BWD(X, n) X(n##b) X(n##w) X(n##d)
#define BW(X, n) X(n##b) X(n##w)
THD(xor) THD(or) THD(and) THD(andn)
BWD(THD, cmeq) BWD(THD, cmgt) BWD(THD, add) BWD(THD, sub) THD(addq) THD(subq)
BW(THD, uqadd) BW(THD, sqadd) BW(THD, uqsub) BW(THD, sqsub) BW(THD, urhadd)
THD(uminb) THD(umaxb) THD(sminw) THD(smaxw) THD(mulw)
BWD(THD, zip1) THD(zip1q) BWD(THD, zip2) THD(zip2q)
THD(ushlw) THD(ushld) THD(ushlq) THD(sshlw) THD(sshld)

/* The two-operand arithmetic, by the opcode's three bits, and test. */
enum { ALU_ADD, ALU_OR, ALU_ADC, ALU_SBB, ALU_AND, ALU_SUB, ALU_XOR, ALU_CMP,
       ALU_TEST };
typedef struct AluG {
    Gadget rr, ri;
    MemTab rm, mr, mi;
} AluG;
#define ALUD(n) DECL(n##_rr) DECL(n##_ri) MEMD(n##_rm) MEMD(n##_mr) \
    MEMD(n##_mi)
#define ALUT(n) { G(n##_rr), G(n##_ri), MEMT(n##_rm) MEMT(n##_mr) \
    MEMT(n##_mi) },
SIZES(ALUD, add) SIZES(ALUD, or) SIZES(ALUD, and) SIZES(ALUD, sub)
SIZES(ALUD, xor) SIZES(ALUD, cmp) SIZES(ALUD, test)
static const AluG alu_g[9][4] = {
    [ALU_ADD] = { SIZES(ALUT, add) },
    [ALU_OR] = { SIZES(ALUT, or) },
    [ALU_AND] = { SIZES(ALUT, and) },
    [ALU_SUB] = { SIZES(ALUT, sub) },
    [ALU_XOR] = { SIZES(ALUT, xor) },
    [ALU_CMP] = { SIZES(ALUT, cmp) },
    [ALU_TEST] = { SIZES(ALUT, test) },
};

SIZES(DECL, not) SIZES(DECL, neg) SIZES(DECL, inc) SIZES(DECL, dec)
static const Gadget not_tab[4] = { SIZES(ENTRY, not) };
static const Gadget neg_tab[4] = { SIZES(ENTRY, neg) };
static const Gadget incdec_tab[2][4] = {
    { SIZES(ENTRY, inc) }, { SIZES(ENTRY, dec) },
};
DECL(adc32_rr) DECL(adc64_rr) DECL(adc32_ri) DECL(adc64_ri)
DECL(sbb32_rr) DECL(sbb64_rr) DECL(sbb32_ri) DECL(sbb64_ri)
DECL(adc16_rr) DECL(adc16_ri) DECL(sbb16_rr) DECL(sbb16_ri)
/* [sbb][16, 32, 64 bits][an immediate] */
static const Gadget adc_tab[2][3][2] = {
    { { G(adc16_rr), G(adc16_ri) }, { G(adc32_rr), G(adc32_ri) },
      { G(adc64_rr), G(adc64_ri) } },
    { { G(sbb16_rr), G(sbb16_ri) }, { G(sbb32_rr), G(sbb32_ri) },
      { G(sbb64_rr), G(sbb64_ri) } },
};
DECL(adcx32) DECL(adcx64) DECL(adox32) DECL(adox64)
/* [adox][32, 64 bits] */
static const Gadget adx_tab[2][2] = {
    { G(adcx32), G(adcx64) }, { G(adox32), G(adox64) },
};
DECL(popcnt32) DECL(popcnt64)
#define CL(n) DECL(n##_cl)
#define CLENTRY(n) G(n##_cl),
SIZES(DECL, shl) SIZES(DECL, shr) SIZES(DECL, sar)
SIZES(CL, shl) SIZES(CL, shr) SIZES(CL, sar)
/* [shl, shr, sar][size] */
static const Gadget shift_tab[3][4] = {
    { SIZES(ENTRY, shl) }, { SIZES(ENTRY, shr) }, { SIZES(ENTRY, sar) },
};
static const Gadget shift_cl_tab[3][4] = {
    { SIZES(CLENTRY, shl) }, { SIZES(CLENTRY, shr) }, { SIZES(CLENTRY, sar) },
};
DECL(imul32_rr) DECL(imul64_rr) DECL(imul32_ri) DECL(imul64_ri)
SIZES(DECL, ror) DECL(rot32_cl) DECL(rot64_cl) DECL(bswap32) DECL(bswap64)
static const Gadget ror_tab[4] = { SIZES(ENTRY, ror) };
#define BTD(n) DECL(n##32_ri) DECL(n##64_ri) DECL(n##32_rr) DECL(n##64_rr)
#define BTT(n) { { G(n##32_ri), G(n##32_rr) }, { G(n##64_ri), G(n##64_rr) } }
BTD(bt) BTD(bts) BTD(btr) BTD(btc)
/* [bt, bts, btr, btc][64 bits][the bit is a register's] */
static const Gadget bt_tab[4][2][2] = { BTT(bt), BTT(bts), BTT(btr), BTT(btc) };
DECL(bsf32) DECL(bsf64) DECL(bsr32) DECL(bsr64)
DECL(tzcnt32) DECL(tzcnt64) DECL(lzcnt32) DECL(lzcnt64)
DECL(cli) DECL(sti) DECL(cld) DECL(std) DECL(mb_ld) DECL(mb_st) DECL(mb)
DECL(loop) DECL(loop32) DECL(jcxz) DECL(jcxz32)

SIZES(DECL, hf_sub) SIZES(DECL, hf_add) SIZES(DECL, hf_logic)
static const Gadget hf_sub_tab[4] = { SIZES(ENTRY, hf_sub) };
static const Gadget hf_add_tab[4] = { SIZES(ENTRY, hf_add) };
static const Gadget hf_logic_tab[4] = { SIZES(ENTRY, hf_logic) };
DECL(cond) DECL(cf_sub) DECL(cf_add) DECL(cf_zero) DECL(cf) DECL(cf_bt)
DECL(flush_cc)
DECL(clr_rf)

/* The host's conditions, in the order of the tables there is one of each in. */
enum { A_EQ, A_NE, A_CS, A_CC, A_MI, A_PL, A_VS, A_VC, A_HI, A_LS, A_GE, A_LT,
       A_GT, A_LE, A_N };
#define CONDS(X, p) X(p##eq) X(p##ne) X(p##cs) X(p##cc) X(p##mi) X(p##pl) \
    X(p##vs) X(p##vc) X(p##hi) X(p##ls) X(p##ge) X(p##lt) X(p##gt) X(p##le)
CONDS(DECL, set_) CONDS(DECL, cmov16_) CONDS(DECL, cmov32_) CONDS(DECL, cmov64_) CONDS(DECL, jcc_)
CONDS(DECL, jcc32_)
static const Gadget set_tab[A_N] = { CONDS(ENTRY, set_) };
static const Gadget cmov_tab[3][A_N] = {
    { CONDS(ENTRY, cmov16_) }, { CONDS(ENTRY, cmov32_) }, { CONDS(ENTRY, cmov64_) },
};
/* [64-bit code] */
static const Gadget jcc_tab[2][A_N] = {
    { CONDS(ENTRY, jcc32_) }, { CONDS(ENTRY, jcc_) },
};

DECL(jmp) DECL(jmp32) DECL(jmpi) DECL(jmpi32) DECL(lookup)
DECL(call_c) DECL(call_c_exit)
DECL(call_c_ea) DECL(call_c_stop) DECL(exit) DECL(irq_check)
/* The stack: [64-bit code][with barriers] */
#define MPD(n) DECL(n) DECL(n##_mp) DECL(n##32) DECL(n##32_mp)
#define MPT(n) { { G(n##32), G(n##32_mp) }, { G(n), G(n##_mp) } }
MPD(push) MPD(pushi) MPD(pop) MPD(leave) MPD(call) MPD(calli) MPD(ret)
static const Gadget push_tab[2][2] = MPT(push), pushi_tab[2][2] = MPT(pushi);
static const Gadget pop_tab[2][2] = MPT(pop), leave_tab[2][2] = MPT(leave);
static const Gadget call_tab[2][2] = MPT(call), calli_tab[2][2] = MPT(calli);
static const Gadget ret_tab[2][2] = MPT(ret);

/* What the assembly sources know of CPUX86State (aok-i386-asm.h). */
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, regs) != AOK_X86_ENV_REGS);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, mxcsr) != AOK_X86_ENV_MXCSR);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, xmm_regs) != AOK_X86_ENV_XMM);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, opmask_regs) != AOK_X86_ENV_OPMASK);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, aok_vstage) != AOK_X86_ENV_VSTAGE);
QEMU_BUILD_BUG_ON(sizeof(ZMMReg) != 64);
QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->regs[0]) != 8);
QEMU_BUILD_BUG_ON(R_EAX != 0 || R_ECX != 1 || R_EDX != 2);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, regs[R_ESP]) != AOK_X86_ENV_RSP);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, regs[R_EBP]) != AOK_X86_ENV_RBP);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, cc_dst) != AOK_X86_ENV_CC_DST);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, cc_src) != AOK_X86_ENV_CC_SRC);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, cc_src2) != AOK_X86_ENV_CC_SRC2);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, cc_op) != AOK_X86_ENV_CC_OP);
QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->cc_op) != 4);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, aok_zero) != AOK_X86_ENV_AOK_ZERO);
QEMU_BUILD_BUG_ON(CC_OP_MULB != AOK_CC_OP_MUL);
QEMU_BUILD_BUG_ON(CC_OP_ADDB != AOK_CC_OP_ADD);
QEMU_BUILD_BUG_ON(CC_OP_ADCB != AOK_CC_OP_ADC);
QEMU_BUILD_BUG_ON(CC_OP_SUBB != AOK_CC_OP_SUB);
QEMU_BUILD_BUG_ON(CC_OP_SBBB != AOK_CC_OP_SBB);
QEMU_BUILD_BUG_ON(CC_OP_LOGICB != AOK_CC_OP_LOGIC);
QEMU_BUILD_BUG_ON(CC_OP_INCB != AOK_CC_OP_INC);
QEMU_BUILD_BUG_ON(CC_OP_DECB != AOK_CC_OP_DEC);
QEMU_BUILD_BUG_ON(CC_OP_SHLB != AOK_CC_OP_SHL);
QEMU_BUILD_BUG_ON(CC_OP_SARB != AOK_CC_OP_SAR);
QEMU_BUILD_BUG_ON(CC_OP_BMILGB != AOK_CC_OP_BMILG);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, eflags) != AOK_X86_ENV_EFLAGS);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, aok_tmp) != AOK_X86_ENV_AOK_TMP);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpstt) != AOK_X86_ENV_FPSTT);
QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->fpstt) != 4);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpus) != AOK_X86_ENV_FPUS);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpuc) != AOK_X86_ENV_FPUC);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fptags) != AOK_X86_ENV_FPTAGS);
QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->fptags) != 8);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpregs) != AOK_X86_ENV_FPREGS);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpop) != AOK_X86_ENV_FPOP);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpcs) != AOK_X86_ENV_FPOP + 2);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpds) != AOK_X86_ENV_FPOP + 4);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpip) != AOK_X86_ENV_FPIP);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpdp) != AOK_X86_ENV_FPDP);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, segs[R_CS].selector) !=
                  AOK_X86_ENV_CS_SEL);
QEMU_BUILD_BUG_ON(sizeof(FPReg) != 16);
QEMU_BUILD_BUG_ON(offsetof(floatx80, low) != 0 || offsetof(floatx80, high) != 8);
QEMU_BUILD_BUG_ON(CC_OP_EFLAGS != AOK_CC_OP_EFLAGS);
QEMU_BUILD_BUG_ON(IF_MASK != AOK_X86_IF);
QEMU_BUILD_BUG_ON(offsetof(CPUX86State, df) != AOK_X86_ENV_DF);

enum { NEXT, END, UNKNOWN };

/* What the host's NZCV says of the guest's flags. */
enum { HF_NONE, HF_SUB, HF_ADD, HF_LOGIC, HF_INCDEC, HF_NZ, HF_BT, HF_FCMP,
       HF_N };
/* The lazy operations with a size, in cc_op's order: (cc_op - 4) / 4. */
enum { CLS_MUL, CLS_ADD, CLS_ADC, CLS_SUB, CLS_SBB, CLS_LOGIC, CLS_INC,
       CLS_DEC, CLS_SHL, CLS_SAR, CLS_N };

typedef struct Ctx {
    AokGen g;
    uint64_t page_off;      /* of the TB's first insn in its page */
    unsigned off;           /* of this insn from the TB's first */
    unsigned len;           /* of this insn */
    unsigned op;            /* its opcode, for the statistics */
    bool c64;               /* 64-bit code; else 32-bit, flat */
    bool mp;                /* other CPUs run: LOCK is atomic, fences are barriers */
    bool mb;                /* and the memory gadgets with barriers (x86_nomb) */
    bool no_goto_ptr;
    bool iopl_ok;           /* cli and sti are allowed here, and I/O */
    int cpl;
    bool io_ok;             /* a port may be read and written with no check */
    bool abm, bmi1;         /* f3 before bsf and bsr makes tzcnt and lzcnt */
    bool bmi2;
    bool adx;               /* adcx and adox exist here */
    bool avx;               /* VEX's vector insns are gadgets-vec.S's here */
    bool avx512;            /* and EVEX's (AVX-512), and the opmask ones */
    const CPUX86State *env; /* the features the CPU offers */
    bool lahf;              /* lahf and sahf exist here */
    bool sse;               /* SSE insns raise nothing here */
    bool x87;               /* nor do x87 ones (no EM, no TS) */
    bool sse3;              /* fisttp exists */
    bool fp;                /* doubles on the host's FP unit */
    int hf;
    int cc;                 /* the lazy cc_op, or -1 where it is not known */
    /* Liveness: see flags_dead(). */
    bool live;
    unsigned must;          /* insns after this one that have to be here */
    const uint8_t *next, *end;      /* the code after this insn */
    bool sti;               /* this insn was sti */
    bool after_sti;         /* this insn follows one */
    bool sti_jmp;           /* and is a jmp that has looked for an interrupt */
    bool cut;               /* this insn has bytes beyond the page */
} Ctx;

/* ---- Operands --------------------------------------------------------- */

#define R(r)    ((uint64_t)(r) * 8)
#define ZERO    offsetof(CPUX86State, aok_zero)
#define T0      offsetof(CPUX86State, aok_tmp[0])
/* irq_check's operand: the interrupt requests, from env. */
#define IRQ_REQUEST ((int64_t)offsetof(X86CPU, parent_obj.interrupt_request) - \
                     (int64_t)offsetof(X86CPU, env))
#define T1      offsetof(CPUX86State, aok_tmp[1])
#define SEGBASE(s) offsetof(CPUX86State, segs[s].base)
#define SEGSEL(s)  offsetof(CPUX86State, segs[s].selector)
/* An XMM register, and where a memory operand of an SSE operation goes. */
#define X(r)    offsetof(CPUX86State, xmm_regs[r])
#define XT0     offsetof(CPUX86State, xmm_t0)

typedef struct Mem {
    int base, index;        /* a register, or -1 */
    int scale;
    int64_t disp;
    bool riprel;
    int seg;                /* R_FS, R_GS, or -1 */
    bool ea_done;           /* an ea gadget has left the address (bit strings) */
} Mem;

typedef struct Insn {
    const uint8_t *p, *end;
    bool c64;
    bool bad;               /* ran into the end of the page */
    bool o16, rep, repne, lock;
    bool a32;               /* 67: fine where there is no address */
    bool a32_ok;            /* ... and in 64-bit code a 32-bit one (the vector insns') */
    bool a32_bad;           /* declined for 67's address, not the page's end */
    bool rex, w;
    int rr, rx, rb;         /* REX.R, REX.X and REX.B, as 0 or 8 */
    int seg;
    int sreg;               /* the last es, cs, ss or ds prefix, or -1 */
    int mod, reg, rm;
    Mem m;
} Insn;

static unsigned f8(Insn *d)
{
    if (d->p >= d->end) {
        d->bad = true;
        return 0;
    }
    return *d->p++;
}

/* An immediate of @n bytes, sign-extended. */
static int64_t fimm(Insn *d, int n)
{
    int64_t v;

    if (d->end - d->p < n) {
        d->bad = true;
        d->p = d->end;
        return 0;
    }
    switch (n) {
    case 1:
        v = (int8_t)d->p[0];
        break;
    case 2:
        v = (int16_t)lduw_le_p(d->p);
        break;
    case 4:
        v = (int32_t)ldl_le_p(d->p);
        break;
    default:
        v = ldq_le_p(d->p);
        break;
    }
    d->p += n;
    return v;
}

/* The immediate of an operand of size @sz that is at most four bytes. */
static int64_t fimmz(Insn *d, int sz)
{
    return fimm(d, sz == 0 ? 1 : sz == 1 ? 2 : 4);
}

static void modrm(Insn *d)
{
    unsigned b = f8(d);

    d->mod = b >> 6;
    d->reg = ((b >> 3) & 7) | d->rr;
    d->rm = b & 7;
    d->m = (Mem){ .base = -1, .index = -1, .seg = d->seg };
    if (d->mod == 3) {
        d->rm |= d->rb;
        return;
    }
    if (d->a32 && !(d->c64 && d->a32_ok)) {
        d->bad = d->a32_bad = true;     /* (32-bit code's 16-bit addresses: TCG's) */
    }
    if (d->rm == 4) {
        unsigned sib = f8(d);
        int index = ((sib >> 3) & 7) | d->rx;

        if (index != 4) {
            d->m.index = index;
            d->m.scale = sib >> 6;
        }
        if ((sib & 7) == 5 && d->mod == 0) {
            d->m.disp = fimm(d, 4);
        } else {
            d->m.base = (sib & 7) | d->rb;
        }
    } else if (d->rm == 5 && d->mod == 0) {
        /* rip-relative, which in 32-bit code is an address by itself */
        d->m.riprel = d->c64;
        d->m.disp = fimm(d, 4);
    } else {
        d->m.base = d->rm | d->rb;
    }
    if (d->mod == 1) {
        d->m.disp = fimm(d, 1);
    } else if (d->mod == 2) {
        d->m.disp = fimm(d, 4);
    }
}

/* A byte register: without a REX prefix 4 to 7 are ah, ch, dh and bh. */
static uint64_t r8(const Insn *d, int r)
{
    return !d->rex && r >= 4 && r < 8 ? R(r - 4) + 1 : R(r);
}

static uint64_t rn(const Insn *d, int r, int sz)
{
    return sz == 0 ? r8(d, r) : R(r);
}

static uint64_t ro(int r)
{
    return r < 0 ? ZERO : R(r);
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
#define E1(g, a)          emit(c, g, 1, (uint64_t)(a))
#define E2(g, a, b)       emit(c, g, 2, (uint64_t)(a), (uint64_t)(b))
#define E3(g, a, b, d)    emit(c, g, 3, (uint64_t)(a), (uint64_t)(b), \
                               (uint64_t)(d))
#define E4(g, a, b, d, e) emit(c, g, 4, (uint64_t)(a), (uint64_t)(b), \
                               (uint64_t)(d), (uint64_t)(e))
#define E5(g, a, b, d, e, f) emit(c, g, 5, (uint64_t)(a), (uint64_t)(b), \
                               (uint64_t)(d), (uint64_t)(e), (uint64_t)(f))

/* The size of a slot of the stack, and of a code address. */
#define SW(c)   ((c)->c64 ? 3 : 2)

/* A memory gadget's last operand (gadgets.S, "Guest memory"). */
static uint64_t word(Ctx *c, int sz)
{
    return (uint64_t)c->off << 32 | sz;
}

/*
 * A gadget with the insn's memory operand: [own] and the address, which an
 * ea gadget before it has computed unless it is a base and a displacement.
 * @again: this is the store of an insn whose load was the gadget before the
 * last, and what that load's ea gadget left is still there.
 */
/*
 * The ea gadget of the insn's memory operand. With 67 in 64-bit code (a32_ok)
 * the sum wraps at 32 bits as 32-bit code's does, and then fs's or gs's base,
 * which is 64 bits there, is added: ea32_seg64, ea_pc32 (eip + disp).
 */
static void emit_ea(Ctx *c, const Insn *d)
{
    const Mem *m = &d->m;
    bool a32 = c->c64 && d->a32;

    if (m->ea_done) {
        return;
    } else if (m->riprel) {
        uint64_t delta = (int64_t)c->off + c->len + m->disp;

        if (m->seg >= 0) {
            E2(a32 ? G(ea_pc32_seg) : G(ea_pc_seg), delta, SEGBASE(m->seg));
        } else {
            E1(a32 ? G(ea_pc32) : G(ea_pc), delta);
        }
    } else if (m->seg >= 0) {
        E5(!c->c64 ? G(ea32_seg) : a32 ? G(ea32_seg64) : G(ea_seg), ro(m->base),
           ro(m->index), m->scale, m->disp, SEGBASE(m->seg));
    } else {
        E4(c->c64 && !a32 ? G(ea) : G(ea32), ro(m->base), ro(m->index), m->scale,
           m->disp);
    }
}

static void mem2(Ctx *c, const Insn *d, const MemTab tab, uint64_t own, int sz,
                 bool again)
{
    const Mem *m = &d->m;
    bool ea = m->ea_done || m->riprel || m->seg >= 0 || m->index >= 0;

    if (ea && !again) {
        emit_ea(c, d);
    }
    aok_emit_gadget(&c->g, tab[ea ? F_EA : c->c64 && !d->a32 ? F_BD : F_B3][c->mb]);
    aok_emit(&c->g, own);
    if (!ea) {
        aok_emit(&c->g, ro(m->base));
        aok_emit(&c->g, m->disp);
    }
    aok_emit(&c->g, word(c, sz));
    c->hf = HF_NONE;        /* the softmmu compare */
}

static void mem(Ctx *c, const Insn *d, const MemTab tab, uint64_t own, int sz)
{
    mem2(c, d, tab, own, sz, false);
}

/* The insn's E operand as a source: the register, or a temporary loaded. */
static uint64_t src_e(Ctx *c, const Insn *d, int sz)
{
    if (d->mod == 3) {
        return rn(d, d->rm, sz);
    }
    mem(c, d, load_tab[sz], T0, sz);
    return T0;
}

/*
 * The insn's E operand as one a register gadget reads and writes: the
 * register, or a temporary between a load that has checked the page may be
 * written and the store. Nothing between the two may call C (the address).
 */
static uint64_t rmw_begin(Ctx *c, const Insn *d, int sz)
{
    if (d->mod == 3) {
        return rn(d, d->rm, sz);
    }
    mem(c, d, loadw_tab[sz], T0, sz);
    return T0;
}

/* @again: nothing since rmw_begin() called C: the address is still there. */
static void rmw_end(Ctx *c, const Insn *d, int sz, bool again)
{
    if (d->mod != 3) {
        mem2(c, d, store_tab[sz], T0, sz, again);
    }
}

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

/* ---- Conditions --------------------------------------------------------- */

/*
 * The host's condition for each of the sixteen of x86 (o no b ae e ne be a
 * s ns p np l ge le g), by what its flags hold; -1 where they do not say.
 * After a subtraction the host's carry is the guest's inverted; after a
 * logic operation the gadget compared the result with zero, which leaves no
 * overflow, and the guest has no carry.
 */
static const int8_t cond_tab[HF_N][16] = {
    [HF_NONE]   = { -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1 },
    [HF_SUB]    = { A_VS, A_VC, A_CC, A_CS, A_EQ, A_NE, A_LS, A_HI,
                    A_MI, A_PL, -1, -1, A_LT, A_GE, A_LE, A_GT },
    [HF_ADD]    = { A_VS, A_VC, A_CS, A_CC, A_EQ, A_NE, -1, -1,
                    A_MI, A_PL, -1, -1, A_LT, A_GE, A_LE, A_GT },
    [HF_LOGIC]  = { -1, -1, -1, -1, A_EQ, A_NE, A_EQ, A_NE,
                    A_MI, A_PL, -1, -1, A_LT, A_GE, A_LE, A_GT },
    [HF_INCDEC] = { A_VS, A_VC, -1, -1, A_EQ, A_NE, -1, -1,
                    A_MI, A_PL, -1, -1, A_LT, A_GE, A_LE, A_GT },
    [HF_NZ]     = { -1, -1, -1, -1, A_EQ, A_NE, -1, -1,
                    A_MI, A_PL, -1, -1, -1, -1, -1, -1 },
    /* After a bt gadget the host's Z is the guest's carry inverted. */
    [HF_BT]     = { -1, -1, A_NE, A_EQ, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1 },
    /*
     * After comisd's gadget: fcmp's flags, or for an unordered pair N, Z
     * and V with no C. The guest has no overflow or sign then.
     */
    [HF_FCMP]   = { -1, -1, A_MI, A_PL, A_EQ, A_NE, A_LS, A_HI,
                    -1, -1, A_VS, A_VC, -1, -1, A_EQ, A_NE },
};

static int cc_class(int cc)
{
    return cc >= CC_OP_MULB && cc < CC_OP_MULB + 4 * CLS_N ?
           (cc - CC_OP_MULB) >> 2 : -1;
}

/* Make the host's flags the stored state's, if a gadget can. */
static void hf_restore(Ctx *c, bool nz_only)
{
    int cls = cc_class(c->cc), sz = c->cc & 3;

    if (c->hf != HF_NONE || cls < 0) {
        return;
    }
    if (cls == CLS_SUB) {
        E0(hf_sub_tab[sz]);
        c->hf = HF_SUB;
    } else if (cls == CLS_ADD) {
        E0(hf_add_tab[sz]);
        c->hf = HF_ADD;
    } else if (cls == CLS_LOGIC) {
        E0(hf_logic_tab[sz]);
        c->hf = HF_LOGIC;
    } else if (nz_only) {
        /* Every one of them keeps its result in cc_dst. */
        E0(hf_logic_tab[sz]);
        c->hf = HF_NZ;
    }
}

/*
 * QEMU_AOK_X86_NOHF, for bisecting: a mask of the HF_ classes whose
 * conditions are computed in C all the same, and bit 8 for "restore none".
 */
static unsigned x86_nohf;
/*
 * QEMU_AOK_X86_NOMB, a test's control only: with several CPUs, the memory
 * gadgets without their barriers (LOCK stays atomic). aok-vm's tsotest then
 * sees the orders x86 forbids, as it does natively on an ARM host.
 */
static bool x86_nomb;
/* QEMU_AOK_X86_NOLIVE: every flag is computed (see "Liveness"). */
static bool x86_nolive;
/* QEMU_AOK_X86_NOFP: every floating-point insn is softfloat's. */
static bool x86_nofp;
/* QEMU_AOK_X86_NOVEC: no VEX insns (gadgets-vec.S), for bisecting */
static bool x86_novec;
/* QEMU_AOK_X86_NOX87: the x87 is TCG's (softfloat's). */
static bool x86_nox87;
/* QEMU_AOK_X86_NO32, QEMU_AOK_X86_NO64: that kind of code is TCG's. */
static bool x86_no32, x86_no64;
/* QEMU_AOK_X86_NOONE: a stepped AVX-512 insn TCG's too (which raises #UD). */
static bool x86_noone;
/* QEMU_AOK_X86_SSEHELPERS: legacy SSE's float ops QEMU's helpers, not VEX's frames. */
static bool x86_sse_helpers;

/* Emit what makes x86 condition @cc one of the host's, and return that. */
static int cond_arm(Ctx *c, unsigned cc)
{
    int a = cond_tab[c->hf][cc];

    if (a < 0 && c->hf == HF_NONE && !(x86_nohf & 0x100)) {
        hf_restore(c, cc == 4 || cc == 5 || cc == 8 || cc == 9);
        a = cond_tab[c->hf][cc];
    }
    if ((x86_nohf & (1 << c->hf)) || (x86_nohf >> 16 & (1 << cc))) {
        a = -1;
    }
    if (a < 0) {
        E1(G(cond), cc);
        c->hf = HF_NONE;
        a = A_NE;
    }
    return a;
}

/*
 * Emit what makes the carry flag a byte, and return the byte's offset: inc,
 * dec, adc and sbb take it so. This comes before anything of the insn that
 * may change the host's flags.
 */
static uint64_t emit_cf(Ctx *c)
{
    int cls = cc_class(c->cc);

    if (cls == CLS_INC || cls == CLS_DEC) {
        return offsetof(CPUX86State, cc_src);   /* where the last one put it */
    }
    hf_restore(c, false);
    switch (c->hf) {
    case HF_SUB:
        E0(G(cf_sub));
        break;
    case HF_ADD:
        E0(G(cf_add));
        break;
    case HF_LOGIC:
        E0(G(cf_zero));
        break;
    case HF_BT:
        E0(G(cf_bt));
        break;
    default:
        E0(G(cf));
        c->hf = HF_NONE;
        break;
    }
    return T1;
}

static void set_flags(Ctx *c, int hf, int cc)
{
    c->hf = hf;
    c->cc = cc;
}

/* ---- The softmmu slow paths, and the instructions done in C -----------------
 *
 * Nothing is unwound from a stream, so each of these stores the insn's pc
 * before anything that may raise an exception. The lazy flags need nothing:
 * they are in env at all times.
 */

static void x86_sync(CPUX86State *env, uint64_t pc)
{
    aok_no_retaddr();
    env->eip = pc;
}

/*
 * A near jmp, call or ret in 64-bit code whose target is not 48 bits sign-
 * extended (the gadgets' test): #GP at the insn, before its push or pop,
 * unless 5-level paging makes the target canonical.
 */
void aok_x86_helper_branch_target(CPUX86State *env, uint64_t addr,
                                  uint64_t pc, uint32_t sz, uint64_t target);
void aok_x86_helper_branch_target(CPUX86State *env, uint64_t addr,
                                  uint64_t pc, uint32_t sz, uint64_t target)
{
    int bits = env->cr[4] & CR4_LA57_MASK ? 57 : 48;

    if (sextract64(target, 0, bits) != (int64_t)target) {
        x86_sync(env, pc);
        raise_exception_err_ra(env, EXCP0D_GPF, 0, 0);
    }
}

static MemOpIdx x86_oi(CPUX86State *env, unsigned sz)
{
    return make_memop_idx(sz | MO_LE, cpu_mmu_index(env_cpu(env), false));
}

static uint64_t x86_ld(CPUX86State *env, uint64_t addr, unsigned sz)
{
    MemOpIdx oi = x86_oi(env, sz);

    switch (sz) {
    case 0:
        return cpu_ldb_mmu(env, addr, oi, 0);
    case 1:
        return cpu_ldw_mmu(env, addr, oi, 0);
    case 2:
        return cpu_ldl_mmu(env, addr, oi, 0);
    default:
        return cpu_ldq_mmu(env, addr, oi, 0);
    }
}

void aok_x86_helper_ld(CPUX86State *env, uint64_t addr, uint64_t pc,
                       uint32_t sz, uint64_t *out);
/* Sixteen bytes, as gen_ldo_env_A0() loads them: @sz is 4, | 16 if aligned. */
static MemOpIdx x86_oi16(CPUX86State *env, unsigned sz)
{
    MemOp atom = env->features[FEAT_1_ECX] & CPUID_EXT_AVX ?
                 MO_ATOM_IFALIGN : MO_ATOM_IFALIGN_PAIR;

    return make_memop_idx(MO_128 | MO_LE | atom | (sz & 16 ? MO_ALIGN_16 : 0),
                          cpu_mmu_index(env_cpu(env), false));
}

void aok_x86_helper_ld(CPUX86State *env, uint64_t addr, uint64_t pc,
                       uint32_t sz, uint64_t *out)
{
    x86_sync(env, pc);
    if ((sz & 15) == 4) {
        Int128 v = cpu_ld16_mmu(env, addr, x86_oi16(env, sz), 0);

        out[0] = int128_getlo(v);
        out[1] = int128_gethi(v);
    } else {
        *out = x86_ld(env, addr, sz);
    }
}

void aok_x86_helper_vst(CPUX86State *env, uint64_t addr, uint64_t pc,
                        uint32_t sz, const uint64_t *in);
void aok_x86_helper_vst(CPUX86State *env, uint64_t addr, uint64_t pc,
                        uint32_t sz, const uint64_t *in)
{
    x86_sync(env, pc);
    cpu_st16_mmu(env, addr, int128_make128(in[0], in[1]), x86_oi16(env, sz), 0);
}

/*
 * The vector frames' memory operands of 32 and 64 bytes (gadgets-vec.S), as
 * TCG's gen_ldy_env_A0() makes them: sixteen bytes at a time, the first
 * access checking the alignment of the whole when @sz says it must be
 * aligned (| 16). A load fills @out only once every access has succeeded. A
 * store raises whatever it would before it writes a byte: the #GP of an
 * operand that must be aligned and is not, and then each page's fault.
 */
void aok_x86_helper_vldn(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t *out);
void aok_x86_helper_vldn(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t *out)
{
    unsigned n = 1u << (sz & 15);
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    uint64_t v[8];

    x86_sync(env, pc);
    for (unsigned i = 0; i < n / 16; i++) {
        MemOp align = !i && (sz & 16) ? (n == 64 ? MO_ALIGN_64 : MO_ALIGN_32) : 0;
        Int128 x = cpu_ld16_mmu(env, addr + 16 * i,
                                make_memop_idx(MO_128 | MO_LE | MO_ATOM_IFALIGN_PAIR |
                                               align, mmu_idx), 0);

        v[2 * i] = int128_getlo(x);
        v[2 * i + 1] = int128_gethi(x);
    }
    memcpy(out, v, n);
}

static void x86_vprobe(CPUX86State *env, uint64_t addr, unsigned n,
                       bool aligned)
{
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    unsigned first = -(addr | TARGET_PAGE_MASK);

    if (aligned && (addr & (n - 1))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, 0);
    }
    probe_write(env, addr, MIN(n, first), mmu_idx, 0);
    if (first < n) {
        probe_write(env, addr + first, n - first, mmu_idx, 0);
    }
}

void aok_x86_helper_vstn(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, const uint64_t *in);
void aok_x86_helper_vstn(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, const uint64_t *in)
{
    unsigned n = 1u << (sz & 15);
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);

    x86_sync(env, pc);
    x86_vprobe(env, addr, n, sz & 16);
    for (unsigned i = 0; i < n / 16; i++) {
        cpu_st16_mmu(env, addr + 16 * i, int128_make128(in[2 * i], in[2 * i + 1]),
                     make_memop_idx(MO_128 | MO_LE | MO_ATOM_IFALIGN_PAIR, mmu_idx), 0);
    }
}

/* Whether a store of 1 << @sz bytes may be made, and nothing stored. */
void aok_x86_helper_vprobe(CPUX86State *env, uint64_t addr, uint64_t pc,
                           uint32_t sz, uint64_t unused);
void aok_x86_helper_vprobe(CPUX86State *env, uint64_t addr, uint64_t pc,
                           uint32_t sz, uint64_t unused)
{
    x86_sync(env, pc);
    x86_vprobe(env, addr, 1u << (sz & 15), false);
}

static void x86_st(CPUX86State *env, uint64_t addr, unsigned sz, uint64_t v)
{
    MemOpIdx oi = x86_oi(env, sz);

    switch (sz) {
    case 0:
        cpu_stb_mmu(env, addr, v, oi, 0);
        break;
    case 1:
        cpu_stw_mmu(env, addr, v, oi, 0);
        break;
    case 2:
        cpu_stl_mmu(env, addr, v, oi, 0);
        break;
    default:
        cpu_stq_mmu(env, addr, v, oi, 0);
        break;
    }
}

void aok_x86_helper_st(CPUX86State *env, uint64_t addr, uint64_t pc,
                       uint32_t sz, uint64_t v);
void aok_x86_helper_st(CPUX86State *env, uint64_t addr, uint64_t pc,
                       uint32_t sz, uint64_t v)
{
    x86_sync(env, pc);
    x86_st(env, addr, sz, v);
}

/*
 * The load of an insn that then stores to the same place: the read, as the
 * insn makes it, and then whatever a write would raise, raised now, while
 * nothing has been changed.
 */
static uint64_t x86_ld_rmw(CPUX86State *env, uint64_t addr, unsigned sz)
{
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    unsigned size = 1 << sz, first = -(addr | TARGET_PAGE_MASK);
    uint64_t v = x86_ld(env, addr, sz);

    if (first >= size) {
        probe_write(env, addr, size, mmu_idx, 0);
    } else {
        probe_write(env, addr, first, mmu_idx, 0);
        probe_write(env, addr + first, size - first, mmu_idx, 0);
    }
    return v;
}

void aok_x86_helper_rmw(CPUX86State *env, uint64_t addr, uint64_t pc,
                        uint32_t sz, uint64_t *out);
void aok_x86_helper_rmw(CPUX86State *env, uint64_t addr, uint64_t pc,
                        uint32_t sz, uint64_t *out)
{
    x86_sync(env, pc);
    *out = x86_ld_rmw(env, addr, sz);
}

/* Whether x86 condition @cc holds of the lazy flags. */
uint64_t aok_x86_helper_cond(CPUX86State *env, uint64_t cc);
uint64_t aok_x86_helper_cond(CPUX86State *env, uint64_t cc)
{
    uint32_t f = cpu_cc_compute_all(env);
    bool s = f & CC_S, o = f & CC_O, r;

    switch (cc >> 1) {
    case 0:
        r = o;
        break;
    case 1:
        r = f & CC_C;
        break;
    case 2:
        r = f & CC_Z;
        break;
    case 3:
        r = f & (CC_C | CC_Z);
        break;
    case 4:
        r = s;
        break;
    case 5:
        r = f & CC_P;
        break;
    case 6:
        r = s != o;
        break;
    default:
        r = (f & CC_Z) || s != o;
        break;
    }
    return r ^ (cc & 1);
}

uint64_t aok_x86_helper_cf(CPUX86State *env);
uint64_t aok_x86_helper_cf(CPUX86State *env)
{
    return helper_cc_compute_c(env->cc_dst, env->cc_src, env->cc_src2,
                               env->cc_op) & 1;
}

/* An operand of an insn done in C, by its offset. */
static uint64_t x86_rd(CPUX86State *env, uint64_t off, unsigned sz)
{
    void *p = (void *)env + off;

    switch (sz) {
    case 0:
        return ldub_p(p);
    case 1:
        return lduw_he_p(p);
    case 2:
        return (uint32_t)ldl_he_p(p);
    default:
        return ldq_he_p(p);
    }
}

static void x86_set16(CPUX86State *env, int r, uint64_t v)
{
    env->regs[r] = deposit64(env->regs[r], 0, 16, v);
}

/* mul and imul with one operand: gen_MUL() and gen_IMUL(). */
void aok_x86_helper_mul(CPUX86State *env, uint64_t pc, uint64_t off,
                        uint64_t sz);
void aok_x86_helper_mul(CPUX86State *env, uint64_t pc, uint64_t off,
                        uint64_t sz)
{
    uint64_t v = x86_rd(env, off, sz), a = env->regs[R_EAX], t, hi;

    switch (sz) {
    case 0:
        t = (uint8_t)a * v;
        x86_set16(env, R_EAX, t);
        env->cc_dst = t;
        env->cc_src = t & 0xff00;
        break;
    case 1:
        t = (uint16_t)a * v;
        x86_set16(env, R_EAX, t);
        x86_set16(env, R_EDX, t >> 16);
        env->cc_dst = t;
        env->cc_src = t >> 16;
        break;
    case 2:
        t = (uint64_t)(uint32_t)a * v;
        env->regs[R_EAX] = (uint32_t)t;
        env->regs[R_EDX] = t >> 32;
        env->cc_dst = env->regs[R_EAX];
        env->cc_src = env->regs[R_EDX];
        break;
    default:
        mulu64(&t, &hi, a, v);
        env->regs[R_EAX] = t;
        env->regs[R_EDX] = hi;
        env->cc_dst = t;
        env->cc_src = hi;
        break;
    }
    env->cc_op = CC_OP_MULB + sz;
}

void aok_x86_helper_imul(CPUX86State *env, uint64_t pc, uint64_t off,
                         uint64_t sz);
void aok_x86_helper_imul(CPUX86State *env, uint64_t pc, uint64_t off,
                         uint64_t sz)
{
    uint64_t v = x86_rd(env, off, sz), a = env->regs[R_EAX], t, hi;

    switch (sz) {
    case 0:
        t = (int64_t)(int8_t)a * (int8_t)v;
        x86_set16(env, R_EAX, t);
        env->cc_src = (int64_t)(int8_t)t - t;
        break;
    case 1:
        t = (int64_t)(int16_t)a * (int16_t)v;
        x86_set16(env, R_EAX, t);
        x86_set16(env, R_EDX, t >> 16);
        env->cc_src = (int64_t)(int16_t)t - t;
        break;
    case 2:
        t = (int64_t)(int32_t)a * (int32_t)v;
        env->regs[R_EAX] = (uint32_t)t;
        env->regs[R_EDX] = t >> 32;
        env->cc_src = (int64_t)(int32_t)t - t;
        break;
    default:
        muls64(&t, &hi, a, v);
        env->regs[R_EAX] = t;
        env->regs[R_EDX] = hi;
        env->cc_src = ((int64_t)t < 0 ? -1 : 0) - hi;
        break;
    }
    env->cc_dst = t;
    env->cc_op = CC_OP_MULB + sz;
}

/* div and idiv: QEMU's helpers, which raise #DE. @sz: + 4 for idiv. */
void aok_x86_helper_div(CPUX86State *env, uint64_t pc, uint64_t off,
                        uint64_t sz);
void aok_x86_helper_div(CPUX86State *env, uint64_t pc, uint64_t off,
                        uint64_t sz)
{
    uint64_t v = x86_rd(env, off, sz & 3);

    x86_sync(env, pc);
    switch (sz) {
    case 0:
        helper_divb_AL(env, v);
        break;
    case 1:
        helper_divw_AX(env, v);
        break;
    case 2:
        helper_divl_EAX(env, v);
        break;
    case 3:
        helper_divq_EAX(env, v);
        break;
    case 4:
        helper_idivb_AL(env, v);
        break;
    case 5:
        helper_idivw_AX(env, v);
        break;
    case 6:
        helper_idivl_EAX(env, v);
        break;
    default:
        helper_idivq_EAX(env, v);
        break;
    }
}

/* A register of a size, or a temporary, written as a register is. */
static void x86_wr(CPUX86State *env, uint64_t off, unsigned sz, uint64_t v)
{
    void *p = (void *)env + off;

    switch (sz) {
    case 0:
        stb_p(p, v);
        break;
    case 1:
        stw_he_p(p, v);
        break;
    case 2:
        stq_he_p(p, (uint32_t)v);
        break;
    default:
        stq_he_p(p, v);
        break;
    }
}

static uint64_t x86_mask(unsigned sz)
{
    return sz == 3 ? UINT64_MAX : (1ull << (8 << sz)) - 1;
}

void aok_x86_helper_flush_cc(CPUX86State *env);
void aok_x86_helper_flush_cc(CPUX86State *env)
{
    env->cc_src = cpu_cc_compute_all(env);
    env->cc_op = CC_OP_EFLAGS;
}

/*
 * rol and ror whose flags are wanted: gen_ROL() and gen_ROR(), which leave
 * every flag but the carry and the overflow, here as CC_OP_EFLAGS. @arg:
 * the size, 4 to the right, 8 by cl, the count from bit 8.
 */
void aok_x86_helper_rot(CPUX86State *env, uint64_t pc, uint64_t off,
                        uint64_t arg);
void aok_x86_helper_rot(CPUX86State *env, uint64_t pc, uint64_t off,
                        uint64_t arg)
{
    unsigned sz = arg & 3;
    bool right = arg & 4;
    unsigned count = (arg & 8 ? env->regs[R_ECX] : arg >> 8) &
                     (sz == 3 ? 63 : 31);
    uint64_t v = x86_rd(env, off, sz), res;
    uint32_t f, cf;

    if (!count) {
        x86_wr(env, off, sz, v);
        return;
    }
    if (sz == 3) {
        res = right ? ror64(v, count) : rol64(v, count);
        cf = right ? res >> 63 : res & 1;
    } else {
        /* As gen_rot_replicate(): the value repeated to 32 bits. */
        uint32_t w = sz == 0 ? v * 0x01010101u : sz == 1 ? v | v << 16 : v;

        w = right ? ror32(w, count) : rol32(w, count);
        res = w;
        cf = right ? w >> 31 : w & 1;
    }
    f = cpu_cc_compute_all(env) & ~(CC_C | CC_O);
    f |= cf;
    if (((v ^ res) >> ((8 << sz) - 1)) & 1) {
        f |= CC_O;
    }
    x86_wr(env, off, sz, res);
    env->cc_src = f;
    env->cc_op = CC_OP_EFLAGS;
}

/*
 * shld and shrd, 32 and 64 bits: gen_shiftd_rm_T1(). @arg: as for the
 * rotates, and the source register from bit 16.
 */
void aok_x86_helper_shiftd(CPUX86State *env, uint64_t pc, uint64_t off,
                           uint64_t arg);
void aok_x86_helper_shiftd(CPUX86State *env, uint64_t pc, uint64_t off,
                           uint64_t arg)
{
    unsigned sz = arg & 3;
    bool right = arg & 4;
    unsigned count = (arg & 8 ? env->regs[R_ECX] : (arg >> 8) & 0xff) &
                     (sz == 3 ? 63 : 31);
    uint64_t dst = x86_rd(env, off, sz);
    uint64_t src = x86_rd(env, R((arg >> 16) & 31), sz), res, cs;

    if (!count) {
        x86_wr(env, off, sz, dst);
        return;
    }
    if (sz == 2) {
        if (right) {
            uint64_t t = src << 32 | dst;

            cs = t >> (count - 1);
            res = (uint32_t)(t >> count);
        } else {
            uint64_t t = dst << 32 | src;

            cs = (t << (count - 1)) >> 32;
            res = (t << count) >> 32;
        }
    } else if (right) {
        cs = dst >> (count - 1);
        res = dst >> count | src << (64 - count);
    } else {
        cs = dst << (count - 1);
        res = dst << count | src >> (64 - count);
    }
    x86_wr(env, off, sz, res);
    env->cc_dst = res;
    env->cc_src = cs;
    env->cc_op = (right ? CC_OP_SARB : CC_OP_SHLB) + sz;
}

/* pushf's value, to the first temporary: the flags become CC_OP_EFLAGS. */
void aok_x86_helper_pushf(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b);
void aok_x86_helper_pushf(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b)
{
    env->aok_tmp[0] = helper_read_eflags(env);
}

void aok_x86_helper_rdtsc(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b);
void aok_x86_helper_rdtsc(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b)
{
    x86_sync(env, pc);
    helper_rdtsc(env);
}

/*
 * The system insns a kernel's fast paths run, each the call of the helper
 * TCG's code for it calls; those after which TCG ends its TB go to the main
 * loop after (call_c_exit). @pc: the insn's, where a fault leaves eip; a
 * helper that succeeds leaves it where the guest goes next.
 */
void aok_x86_helper_rdtscp(CPUX86State *env, uint64_t pc, uint64_t w, uint64_t b);
void aok_x86_helper_rdtscp(CPUX86State *env, uint64_t pc, uint64_t w, uint64_t b)
{
    x86_sync(env, pc);
    helper_rdtsc(env);
    env->regs[R_ECX] = w ? helper_rdpid(env) : (uint32_t)helper_rdpid(env);
}

/* clac and stac, @set: AC, which a TB is made for. @len: the insn's. */
void aok_x86_helper_ac(CPUX86State *env, uint64_t pc, uint64_t set, uint64_t len);
void aok_x86_helper_ac(CPUX86State *env, uint64_t pc, uint64_t set, uint64_t len)
{
    env->eflags = set ? env->eflags | AC_MASK : env->eflags & ~AC_MASK;
    env->eip = pc + len;
}

/* invlpg of the address an ea gadget left in the first temporary. */
void aok_x86_helper_invlpg(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t len);
void aok_x86_helper_invlpg(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t len)
{
    helper_flush_page(env, env->aok_tmp[0]);
    env->eip = pc + len;
}

/* iret in protected and long mode: @shift 0 for 16 bits, 1 for 32, 2 for 64. */
void aok_x86_helper_iret(CPUX86State *env, uint64_t pc, uint64_t shift, uint64_t len);
void aok_x86_helper_iret(CPUX86State *env, uint64_t pc, uint64_t shift, uint64_t len)
{
    x86_sync(env, pc);
    helper_iret_protected(env, shift, pc + len);
}

/*
 * syscall and sysret (@dflag 1 for 32 bits, 2 for 64). The TF they leave
 * is looked at after them, as TCG's DISAS_EOB_RECHECK_TF does.
 */
void aok_x86_helper_syscall(CPUX86State *env, uint64_t pc, uint64_t len, uint64_t b);
void aok_x86_helper_syscall(CPUX86State *env, uint64_t pc, uint64_t len, uint64_t b)
{
    x86_sync(env, pc);
    helper_syscall(env, len);
    helper_rechecking_single_step(env);
}

void aok_x86_helper_sysret(CPUX86State *env, uint64_t pc, uint64_t dflag, uint64_t b);
void aok_x86_helper_sysret(CPUX86State *env, uint64_t pc, uint64_t dflag, uint64_t b)
{
    x86_sync(env, pc);
    helper_sysret(env, dflag);
    helper_rechecking_single_step(env);
}

/* mov to a control register (0, 2, 3, 4): @a its number | the register's offset << 8. */
void aok_x86_helper_wrcr(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t len);
void aok_x86_helper_wrcr(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t len)
{
    uint64_t v = *(uint64_t *)((char *)env + (a >> 8));

    x86_sync(env, pc);
    helper_write_crN(env, a & 15, env->hflags & HF_CS64_MASK ? v : (uint32_t)v);
    env->eip = pc + len;
}

/*
 * rdfsbase, rdgsbase, wrfsbase, wrgsbase: @a which (0-3) | 64 bits (4) |
 * the register's offset << 8; #UD unless CR4 allows them.
 */
void aok_x86_helper_fsgsbase(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b);
void aok_x86_helper_fsgsbase(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b)
{
    uint64_t *r = (uint64_t *)((char *)env + (a >> 8));
    target_ulong *base = &env->segs[a & 1 ? R_GS : R_FS].base;

    x86_sync(env, pc);
    if (!(env->cr[4] & CR4_FSGSBASE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, 0);
    }
    if (a & 2) {
        *base = a & 4 ? *r : (uint32_t)*r;
    } else {
        *r = a & 4 ? *base : (uint32_t)*base;
    }
}

/* verr, verw (@w) of the selector at @a's offset. */
void aok_x86_helper_verrw(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t w);
void aok_x86_helper_verrw(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t w)
{
    uint16_t sel = *(uint16_t *)((char *)env + a);

    x86_sync(env, pc);
    if (w) {
        helper_verw(env, sel);
    } else {
        helper_verr(env, sel);
    }
    env->cc_op = CC_OP_EFLAGS;
}

void aok_x86_helper_cpuid(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b);
void aok_x86_helper_cpuid(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b)
{
    x86_sync(env, pc);
    helper_cpuid(env);
}

/*
 * xsave (xsaveopt with @opt) at @addr, of the components edx:eax asks for;
 * @rexw: xsave64's image.
 */
void aok_x86_helper_xsave(CPUX86State *env, uint64_t pc, uint64_t opt,
                          uint64_t rexw, uint64_t addr);
void aok_x86_helper_xsave(CPUX86State *env, uint64_t pc, uint64_t opt,
                          uint64_t rexw, uint64_t addr)
{
    uint64_t rfbm = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);

    x86_sync(env, pc);
    if (opt) {
        helper_xsaveopt(env, addr, rfbm, rexw);
    } else {
        helper_xsave(env, addr, rfbm, rexw);
    }
}

/*
 * xrstor (xrstor64 with @rexw) at the address in the first temporary; then
 * the main loop.
 */
void aok_x86_helper_xrstor(CPUX86State *env, uint64_t pc, uint64_t rexw,
                           uint64_t len);
void aok_x86_helper_xrstor(CPUX86State *env, uint64_t pc, uint64_t rexw,
                           uint64_t len)
{
    uint64_t rfbm = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);

    x86_sync(env, pc);
    helper_xrstor(env, env->aok_tmp[0], rfbm, rexw);
    env->eip = pc + len;
}

/* MXCSR: the rounding control, flush to zero, denormals are zero. */
#define MXCSR_RC    0x6000
#define MXCSR_FZ    0x8000
#define MXCSR_DAZ   0x0040

/*
 * A stream is about to compute on the host's FP unit (gadgets.S, "SSE
 * arithmetic on doubles"). From here to the stream's next aok_fp_end the
 * host's FPSR collects what its insns raise. Returns whether the host
 * rounds as MXCSR asks, with denormals as they are: QEMU leaves the host's
 * FPCR to nearest even and nothing else.
 */
uint64_t aok_x86_fp_begin(CPUX86State *env);
uint64_t aok_x86_fp_begin(CPUX86State *env)
{
    uint64_t fpcr;
    unsigned rc = (env->mxcsr >> 13) & 3;

    __asm__ volatile("mrs %0, fpcr\n\tmsr fpsr, xzr" : "=r"(fpcr));
    /*
     * The vector frames (gadgets-vec.S) round as MXCSR says, on the host's
     * unit: FPCR's RMode is RC's (x86 down is AArch64's RM, up its RP), and
     * nothing else of FPCR changes; DAZ and FTZ are the frames' own. The
     * double gadgets compute only where MXCSR asks for nearest even and
     * nothing more, which the answer says (_fpok), and then RMode is zero.
     */
    if (rc && !(fpcr & 0x07f89f00)) {
        uint64_t rmode = (rc & 1) << 1 | rc >> 1;

        __asm__ volatile("msr fpcr, %0" :: "r"(rmode << 22));
        return 0;
    }
    /* The host's RMode, FZ, DN, AHP, FZ16, and its trap enables. */
    return !(env->mxcsr & (MXCSR_RC | MXCSR_FZ | MXCSR_DAZ)) &&
           !(fpcr & 0x07f89f00);
}

/*
 * TCGCPUOps.aok_fold_fpsr: what the host's FP unit raised for the guest, as
 * MXCSR's flags. The double gadgets leave only inexact there; the vector
 * frames (gadgets-vec.S) anything: IOC is IE, DZC ZE, OFC OE, UFC UE, IXC
 * PE and IDC DE.
 */
void x86_aok_fold_fpsr(CPUState *cs, uint32_t fpsr)
{
    CPUX86State *env = cpu_env(cs);
    int f = (fpsr & 0x01 ? float_flag_invalid : 0) |
            (fpsr & 0x02 ? float_flag_divbyzero : 0) |
            (fpsr & 0x04 ? float_flag_overflow : 0) |
            (fpsr & 0x08 ? float_flag_underflow : 0) |
            (fpsr & 0x10 ? float_flag_inexact : 0) |
            (fpsr & 0x80 ? float_flag_input_denormal_used : 0);

    if (f) {
        set_float_exception_flags(get_float_exception_flags(&env->sse_status) | f,
                                  &env->sse_status);
    }
}

/*
 * popf, the value popped to the first temporary: @pc is the next insn's,
 * where the main loop continues, since the flags a TB is made for may have
 * changed and an interrupt may now be due. @mask: what this CPL may write.
 */
void aok_x86_helper_popf(CPUX86State *env, uint64_t pc, uint64_t mask,
                         uint64_t b);
void aok_x86_helper_popf(CPUX86State *env, uint64_t pc, uint64_t mask,
                         uint64_t b)
{
    helper_write_eflags(env, env->aok_tmp[0], mask);
    env->eip = pc;
}

/*
 * clc, stc, cmc, lahf, sahf (@op, in that order): the flags themselves are
 * wanted, so the lazy state becomes them, as gen_compute_eflags() makes it.
 */
void aok_x86_helper_flagop(CPUX86State *env, uint64_t pc, uint64_t op,
                           uint64_t b);
void aok_x86_helper_flagop(CPUX86State *env, uint64_t pc, uint64_t op,
                           uint64_t b)
{
    uint32_t f = cpu_cc_compute_all(env);

    switch (op) {
    case 0:
        f &= ~CC_C;
        break;
    case 1:
        f |= CC_C;
        break;
    case 2:
        f ^= CC_C;
        break;
    case 3:
        env->regs[R_EAX] = deposit64(env->regs[R_EAX], 8, 8, f | 2);
        break;
    default:
        f = (f & CC_O) | ((env->regs[R_EAX] >> 8) &
                          (CC_S | CC_Z | CC_A | CC_P | CC_C));
        break;
    }
    env->cc_src = f;
    env->cc_op = CC_OP_EFLAGS;
}

/* A segment register loaded: @sel is where the selector is, 16 bits. */
void aok_x86_helper_load_seg(CPUX86State *env, uint64_t pc, uint64_t seg,
                             uint64_t sel);
void aok_x86_helper_load_seg(CPUX86State *env, uint64_t pc, uint64_t seg,
                             uint64_t sel)
{
    x86_sync(env, pc);
    helper_load_seg(env, seg, lduw_he_p((void *)env + sel));
}

/*
 * in and out, where the CPL may use any port. @port: the number, or with
 * bit 16 dx's; @arg: the size, and 4 for out.
 */
void aok_x86_helper_io(CPUX86State *env, uint64_t pc, uint64_t port,
                       uint64_t arg);
void aok_x86_helper_io(CPUX86State *env, uint64_t pc, uint64_t port,
                       uint64_t arg)
{
    uint32_t p = port & 0x10000 ? (uint16_t)env->regs[R_EDX] : port;
    uint32_t v = env->regs[R_EAX];

    x86_sync(env, pc);
    switch (arg) {
    case 0:
        x86_wr(env, R(R_EAX), 0, helper_inb(env, p));
        break;
    case 1:
        x86_wr(env, R(R_EAX), 1, helper_inw(env, p));
        break;
    case 2:
        x86_wr(env, R(R_EAX), 2, helper_inl(env, p));
        break;
    case 4:
        helper_outb(env, p, v & 0xff);
        break;
    case 5:
        helper_outw(env, p, v & 0xffff);
        break;
    default:
        helper_outl(env, p, v);
        break;
    }
}

/* pause: @pc is the next insn's, where the CPU is when it has yielded. */
void aok_x86_helper_pause(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b);
void aok_x86_helper_pause(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b)
{
    x86_sync(env, pc);
    helper_pause(env);
}

/* ---- Read-modify-write of memory as one step -------------------------------
 *
 * cmpxchg, xadd and xchg always, and with other CPUs running the insns that
 * have a lock prefix. Where no other CPU runs (@par clear) it is a load and
 * a store, as TCG makes it then; otherwise cputlb's atomic helpers.
 */

enum { F_ADD, F_AND, F_OR, F_XOR, F_XCHG };

#define ATOMIC4(name, ...)                                  \
    switch (sz) {                                           \
    case 0:                                                 \
        return cpu_atomic_##name##b_mmu(__VA_ARGS__);       \
    case 1:                                                 \
        return cpu_atomic_##name##w_le_mmu(__VA_ARGS__);    \
    case 2:                                                 \
        return cpu_atomic_##name##l_le_mmu(__VA_ARGS__);    \
    default:                                                \
        return cpu_atomic_##name##q_le_mmu(__VA_ARGS__);    \
    }

/* What was there, having put there that @kind @v. */
static uint64_t x86_fetch_op(CPUX86State *env, uint64_t addr, int kind,
                             uint64_t v, unsigned sz, bool par)
{
    MemOpIdx oi = x86_oi(env, sz);

    if (!par) {
        uint64_t old = x86_ld_rmw(env, addr, sz);

        x86_st(env, addr, sz,
               kind == F_ADD ? old + v : kind == F_AND ? old & v :
               kind == F_OR ? old | v : kind == F_XOR ? old ^ v : v);
        return old;
    }
    switch (kind) {
    case F_ADD:
        ATOMIC4(fetch_add, env, addr, v, oi, 0);
    case F_AND:
        ATOMIC4(fetch_and, env, addr, v, oi, 0);
    case F_OR:
        ATOMIC4(fetch_or, env, addr, v, oi, 0);
    case F_XOR:
        ATOMIC4(fetch_xor, env, addr, v, oi, 0);
    default:
        ATOMIC4(xchg, env, addr, v, oi, 0);
    }
}

static uint64_t x86_cmpxchg(CPUX86State *env, uint64_t addr, uint64_t cmp,
                            uint64_t new, unsigned sz, bool par)
{
    MemOpIdx oi = x86_oi(env, sz);

    if (!par) {
        uint64_t old = x86_ld_rmw(env, addr, sz);

        /* A store either way, as the instruction makes one. */
        x86_st(env, addr, sz, old == cmp ? new : old);
        return old;
    }
    ATOMIC4(cmpxchg, env, addr, cmp, new, oi, 0);
}

/* The operations beyond the ALU_ ones, which are themselves here. */
enum { AT_INC = 16, AT_DEC, AT_NOT, AT_NEG, AT_XCHG, AT_XADD, AT_CMPXCHG,
       AT_CMPXCHG8B, AT_BTS, AT_BTR, AT_BTC, AT_CMPXCHG16B };
#define AT_IMM  0x1000
#define AT_PAR  0x2000

/*
 * @a: the offset of the register that is the other operand, or with AT_IMM
 * the operand itself; @b: the operation, the size from bit 8, and the two
 * flags above. The lazy flags are stored as TCG's code for the insn would.
 */
void aok_x86_helper_atomic(CPUX86State *env, uint64_t pc, uint64_t a,
                           uint64_t b, uint64_t addr);
void aok_x86_helper_atomic(CPUX86State *env, uint64_t pc, uint64_t a,
                           uint64_t b, uint64_t addr)
{
    unsigned op = b & 0xff, sz = (b >> 8) & 3;
    bool par = b & AT_PAR;
    uint64_t m = x86_mask(sz);
    uint64_t v = (b & AT_IMM ? a : x86_rd(env, a, sz)) & m, old, res;
    uint32_t f;

    x86_sync(env, pc);
    switch (op) {
    case ALU_ADD:
        old = x86_fetch_op(env, addr, F_ADD, v, sz, par);
        env->cc_dst = old + v;
        env->cc_src = v;
        env->cc_op = CC_OP_ADDB + sz;
        break;
    case ALU_SUB:
        old = x86_fetch_op(env, addr, F_ADD, -v & m, sz, par);
        env->cc_dst = old - v;
        env->cc_src = v;
        env->cc_op = CC_OP_SUBB + sz;
        break;
    case ALU_AND:
        old = x86_fetch_op(env, addr, F_AND, v, sz, par);
        env->cc_dst = old & v;
        env->cc_op = CC_OP_LOGICB + sz;
        break;
    case ALU_OR:
        old = x86_fetch_op(env, addr, F_OR, v, sz, par);
        env->cc_dst = old | v;
        env->cc_op = CC_OP_LOGICB + sz;
        break;
    case ALU_XOR:
        old = x86_fetch_op(env, addr, F_XOR, v, sz, par);
        env->cc_dst = old ^ v;
        env->cc_op = CC_OP_LOGICB + sz;
        break;
    case AT_INC:
    case AT_DEC:
        /* They keep the carry, which the lazy state of theirs holds. */
        f = helper_cc_compute_c(env->cc_dst, env->cc_src, env->cc_src2,
                                env->cc_op) & 1;
        v = op == AT_INC ? 1 : m;
        old = x86_fetch_op(env, addr, F_ADD, v, sz, par);
        env->cc_dst = old + v;
        env->cc_src = f;
        env->cc_op = (op == AT_INC ? CC_OP_INCB : CC_OP_DECB) + sz;
        break;
    case AT_NOT:
        x86_fetch_op(env, addr, F_XOR, m, sz, par);
        break;
    case AT_NEG:
        do {
            old = x86_ld(env, addr, sz);
            res = -old & m;
        } while (x86_cmpxchg(env, addr, old, res, sz, par) != old);
        env->cc_dst = res;
        env->cc_src = old;
        env->cc_op = CC_OP_SUBB + sz;
        break;
    case AT_XCHG:
        old = x86_fetch_op(env, addr, F_XCHG, v, sz, par);
        x86_wr(env, a, sz, old);
        break;
    case AT_XADD:
        old = x86_fetch_op(env, addr, F_ADD, v, sz, par);
        env->cc_dst = old + v;
        env->cc_src = v;
        env->cc_op = CC_OP_ADDB + sz;
        x86_wr(env, a, sz, old);
        break;
    case AT_CMPXCHG: {
        uint64_t cmp = env->regs[R_EAX] & m;

        old = x86_cmpxchg(env, addr, cmp, v, sz, par);
        if (old != cmp) {
            x86_wr(env, R(R_EAX), sz, old);
        }
        env->cc_dst = cmp - old;
        env->cc_src = old;
        env->cc_op = CC_OP_SUBB + sz;
        break;
    }
    case AT_CMPXCHG16B: {
        /* rdx:rax against sixteen aligned bytes, rcx:rbx to them: gen_CMPXCHG16B() */
        Int128 cmp = int128_make128(env->regs[R_EAX], env->regs[R_EDX]);
        Int128 new = int128_make128(env->regs[R_EBX], env->regs[R_ECX]);
        MemOpIdx oi = make_memop_idx(MO_128 | MO_LE | MO_ALIGN,
                                     cpu_mmu_index(env_cpu(env), false));
        Int128 o;

        if (addr & 15) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, 0);
        }
        f = cpu_cc_compute_all(env) & ~CC_Z;
        if (par) {
#if HAVE_CMPXCHG128
            o = cpu_atomic_cmpxchgo_le_mmu(env, addr, cmp, new, oi, 0);
#else
            cpu_loop_exit_atomic(env_cpu(env), 0);
#endif
        } else {
            /* A store either way, as the instruction makes one. */
            x86_vprobe(env, addr, 16, true);
            o = cpu_ld16_mmu(env, addr, oi, 0);
            cpu_st16_mmu(env, addr, int128_eq(o, cmp) ? new : o, oi, 0);
        }
        if (int128_eq(o, cmp)) {
            f |= CC_Z;
        } else {
            env->regs[R_EAX] = int128_getlo(o);
            env->regs[R_EDX] = int128_gethi(o);
        }
        env->cc_src = f;
        env->cc_op = CC_OP_EFLAGS;
        break;
    }
    case AT_CMPXCHG8B: {
        /* edx:eax against eight bytes, ecx:ebx to them: gen_CMPXCHG8B() */
        uint64_t cmp = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
        uint64_t new = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

        f = cpu_cc_compute_all(env) & ~CC_Z;
        old = x86_cmpxchg(env, addr, cmp, new, 3, par);
        if (old == cmp) {
            f |= CC_Z;
        } else {
            env->regs[R_EAX] = (uint32_t)old;
            env->regs[R_EDX] = old >> 32;
        }
        env->cc_src = f;
        env->cc_op = CC_OP_EFLAGS;
        break;
    }
    default: {
        /* bts, btr, btc with the bit's number: the carry is the old bit. */
        unsigned bit = v & ((8 << sz) - 1);
        uint64_t mask = 1ull << bit;

        f = cpu_cc_compute_all(env) & ~CC_C;
        old = x86_fetch_op(env, addr, op == AT_BTS ? F_OR :
                           op == AT_BTR ? F_AND : F_XOR,
                           op == AT_BTR ? ~mask & m : mask, sz, par);
        env->cc_src = f | ((old >> bit) & 1);
        env->cc_op = CC_OP_EFLAGS;
        break;
    }
    }
}

/* ---- The string instructions -------------------------------------------- */

enum { S_MOVS, S_CMPS, S_STOS, S_LODS, S_SCAS };
#define S_A32   0x1000      /* 32-bit code: the registers are 32 bits */

/*
 * @a: which, the size from bit 4, and from bit 8 whether repeated (1, or 2
 * for repnz); @b: the offset of the base of the source's segment, or zero.
 * A rep goes page by page on the host's memory where the pages are RAM and
 * the direction is up, which is the same as going element by element, and
 * the registers are brought up to date before anything that may fault.
 * Returns whether to go by the main loop and start the insn again: a long
 * rep must not keep an interrupt waiting.
 */
uint64_t aok_x86_helper_string(CPUX86State *env, uint64_t pc, uint64_t a,
                               uint64_t b);
uint64_t aok_x86_helper_string(CPUX86State *env, uint64_t pc, uint64_t a,
                               uint64_t b)
{
    unsigned op = a & 15, sz = (a >> 4) & 3, rep = (a >> 8) & 3;
    uint64_t size = 1 << sz, m = x86_mask(sz);
    uint64_t am = a & S_A32 ? UINT32_MAX : UINT64_MAX;
    uint64_t seg = b ? ldq_he_p((void *)env + b) : 0;
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    int64_t step = env->df < 0 ? -(int64_t)size : size;
    uint64_t n = rep ? env->regs[R_ECX] & am : 1;
    unsigned budget = 4096;

    x86_sync(env, pc);
    while (n) {
        uint64_t di = env->regs[R_EDI] & am, si = env->regs[R_ESI] & am;
        uint64_t sa = (si + seg) & am, done = 1, v, v2;
        bool stop = false;

        if (!budget--) {
            return 1;
        }
        switch (op) {
        case S_MOVS:
        case S_STOS: {
            uint64_t room = -(di | TARGET_PAGE_MASK), cnt;
            uint8_t *hd = NULL, *hs = NULL;

            if (op == S_MOVS) {
                room = MIN(room, -(sa | TARGET_PAGE_MASK));
            }
            cnt = MIN(n, room >> sz);
            if (step > 0 && cnt) {
                if (op == S_MOVS) {
                    hs = probe_access(env, sa, cnt << sz, MMU_DATA_LOAD,
                                      mmu_idx, 0);
                }
                if (op == S_STOS || hs) {
                    hd = probe_access(env, di, cnt << sz, MMU_DATA_STORE,
                                      mmu_idx, 0);
                }
            }
            if (hd && op == S_STOS) {
                v = env->regs[R_EAX];
                if (sz == 0) {
                    memset(hd, v, cnt);
                } else {
                    for (uint64_t i = 0; i < cnt; i++) {
                        if (sz == 1) {
                            stw_le_p(hd + i * 2, v);
                        } else if (sz == 2) {
                            stl_le_p(hd + i * 4, v);
                        } else {
                            stq_le_p(hd + i * 8, v);
                        }
                    }
                }
                done = cnt;
            } else if (hd) {
                if ((uintptr_t)(hd - hs) >= cnt << sz) {
                    memmove(hd, hs, cnt << sz);
                } else {
                    /* The destination overlaps what is yet to be read. */
                    for (uint64_t i = 0; i < cnt; i++) {
                        uint64_t t;

                        memcpy(&t, hs + i * size, size);
                        memcpy(hd + i * size, &t, size);
                    }
                }
                done = cnt;
            } else {
                v = op == S_STOS ? env->regs[R_EAX] : x86_ld(env, sa, sz);
                x86_st(env, di, sz, v);
            }
            break;
        }
        case S_LODS:
            v = x86_ld(env, sa, sz);
            x86_wr(env, R(R_EAX), sz, v);
            break;
        default:
            if (op == S_SCAS) {
                v = env->regs[R_EAX] & m;
            } else {
                v = x86_ld(env, sa, sz);
            }
            v2 = x86_ld(env, di, sz);
            env->cc_dst = v - v2;
            env->cc_src = v2;
            env->cc_op = CC_OP_SUBB + sz;
            stop = (((v - v2) & m) == 0) ? rep == 2 : rep == 1;
            break;
        }
        if (op != S_STOS && op != S_SCAS) {
            env->regs[R_ESI] = (si + step * done) & am;
        }
        if (op != S_LODS) {
            env->regs[R_EDI] = (di + step * done) & am;
        }
        if (rep) {
            env->regs[R_ECX] = (n - done) & am;
        }
        n -= done;
        if (stop) {
            break;
        }
    }
    return 0;
}

/* ---- Liveness --------------------------------------------------------------
 *
 * Some insns set flags in a way the lazy state can only say by computing
 * every flag first: a rotate changes the carry and the overflow and keeps
 * the rest, inc and dec keep the carry. Usually nothing reads what they set
 * (a rotate in a hash is followed by an add), and TCG then drops the
 * computation as dead code. Here the same is seen by looking ahead: the
 * flags an insn sets are dead if the insns after it neither read them, nor
 * can fault or leave the TB, up to one that sets them all. Such an insn is
 * then translated with no flags at all, and the stored state stays that of
 * the insn before it until it is replaced.
 *
 * peek() knows only the commonest forms, all between registers, and every
 * one of them is a form insn() translates: the insns looked at have to be in
 * this TB, which the translator's loop checks (Ctx.must).
 */

enum { P_OTHER, P_PASS, P_WRITE };

/* What the insn at @p does to the flags, and its length. */
static int peek(bool c64, const uint8_t *p, const uint8_t *end, unsigned *len)
{
    Insn dd = { .p = p, .end = end, .seg = -1, .c64 = c64 }, *d = &dd;
    unsigned b = f8(d), count;
    int sz, bsz, r = P_OTHER;

    if (b == 0x66) {
        d->o16 = true;
        b = f8(d);
    }
    if (c64 && b >= 0x40 && b <= 0x4f) {
        d->rex = true;
        d->w = b & 8;
        d->rr = (b & 4) << 1;
        d->rx = (b & 2) << 2;
        d->rb = (b & 1) << 3;
        b = f8(d);
    }
    sz = d->w ? 3 : d->o16 ? 1 : 2;
    bsz = b & 1 ? sz : 0;
    d->mod = 0;
    if (b == 0x0f) {
        b = f8(d);
        switch (b) {
        case 0x1f:
            modrm(d);
            r = P_PASS;
            break;
        case 0xaf:
            modrm(d);
            if (d->mod == 3 && sz >= 2) {
                r = P_WRITE;
            }
            break;
        case 0xb6:
        case 0xb7:
        case 0xbe:
        case 0xbf:
            modrm(d);
            if (d->mod == 3 && sz >= 2) {
                r = P_PASS;
            }
            break;
        case 0xc8 ... 0xcf:
            if (sz >= 2) {
                r = P_PASS;
            }
            break;
        }
        b = 0x100;
    }
    switch (b) {
    case 0x00 ... 0x3f:
        if ((b & 7) < 4) {
            modrm(d);
        } else if ((b & 7) < 6) {
            fimmz(d, bsz);
            d->mod = 3;
        }
        if (d->mod == 3 && (b & 7) < 6 && (b >> 3) != ALU_ADC &&
            (b >> 3) != ALU_SBB) {
            r = P_WRITE;
        }
        break;
    case 0x80:
    case 0x81:
    case 0x83:
        modrm(d);
        if (b == 0x81) {
            fimmz(d, sz);
        } else {
            fimm(d, 1);
        }
        if (d->mod == 3 && (d->reg & 7) != ALU_ADC &&
            (d->reg & 7) != ALU_SBB) {
            r = P_WRITE;
        }
        break;
    case 0x84:
    case 0x85:
        modrm(d);
        if (d->mod == 3) {
            r = P_WRITE;
        }
        break;
    case 0xa8:
    case 0xa9:
        fimmz(d, bsz);
        r = P_WRITE;
        break;
    case 0x69:
    case 0x6b:
        modrm(d);
        if (b == 0x69) {
            fimmz(d, sz);
        } else {
            fimm(d, 1);
        }
        if (d->mod == 3 && sz >= 2) {
            r = P_WRITE;
        }
        break;
    case 0x63:
        modrm(d);
        if (d->mod == 3 && d->w) {
            r = P_PASS;
        }
        break;
    case 0x88 ... 0x8b:
        modrm(d);
        if (d->mod == 3) {
            r = P_PASS;
        }
        break;
    case 0x8d:
        modrm(d);
        if (d->mod != 3 && sz >= 2) {
            r = P_PASS;
        }
        break;
    case 0x90:
        if (!d->rb) {
            r = P_PASS;
        }
        break;
    case 0x98:
    case 0x99:
        if (sz >= 2) {
            r = P_PASS;
        }
        break;
    case 0xb0 ... 0xb7:
        fimm(d, 1);
        r = P_PASS;
        break;
    case 0xb8 ... 0xbf:
        fimm(d, sz == 3 ? 8 : sz == 1 ? 2 : 4);
        r = P_PASS;
        break;
    case 0xc6:
    case 0xc7:
        modrm(d);
        fimmz(d, bsz);
        if (d->mod == 3 && !(d->reg & 7)) {
            r = P_PASS;
        }
        break;
    case 0xc0:
    case 0xc1:
    case 0xd0:
    case 0xd1:
        modrm(d);
        count = (b < 0xd0 ? fimm(d, 1) : 1) & (bsz == 3 ? 63 : 31);
        if (d->mod == 3 && count) {
            /* A shift sets them all; a rotate will be one of these too. */
            r = (d->reg & 7) >= 4 ? P_WRITE : (d->reg & 7) < 2 ? P_PASS :
                P_OTHER;
        }
        break;
    case 0xf6:
    case 0xf7:
        modrm(d);
        if ((d->reg & 7) < 2) {
            fimmz(d, bsz);
        }
        if (d->mod == 3) {
            r = (d->reg & 7) < 2 || (d->reg & 7) == 3 ? P_WRITE :
                (d->reg & 7) == 2 ? P_PASS : P_OTHER;
        }
        break;
    }
    if (d->bad) {
        return P_OTHER;
    }
    *len = d->p - p;
    return r;
}

#define LIVE_HORIZON 6

/* Whether nothing reads the flags the insn being translated sets. */
static bool flags_dead(Ctx *c)
{
    const uint8_t *p = c->next;
    unsigned len;

    if (!c->live) {
        return false;
    }
    for (unsigned n = 1; n <= LIVE_HORIZON; n++) {
        switch (peek(c->c64, p, c->end, &len)) {
        case P_WRITE:
            /* All of them will be translated, and into this TB? */
            if (c->g.n_insns + 1 + n >= c->g.max_insns ||
                !aok_gen_room(&c->g, 24 + 8 * n)) {
                return false;
            }
            c->must = MAX(c->must, n);
            return true;
        case P_PASS:
            p += len;
            break;
        default:
            return false;
        }
    }
    return false;
}

/* ---- Instructions ------------------------------------------------------- */

static void alu_flags(Ctx *c, int op, int sz)
{
    switch (op) {
    case ALU_ADD:
        set_flags(c, HF_ADD, CC_OP_ADDB + sz);
        break;
    case ALU_SUB:
    case ALU_CMP:
        set_flags(c, HF_SUB, CC_OP_SUBB + sz);
        break;
    default:
        set_flags(c, HF_LOGIC, CC_OP_LOGICB + sz);
        break;
    }
}

/*
 * An insn on memory that is one step (aok_x86_helper_atomic): @a is the
 * other operand, a register's offset or with @imm itself.
 */
static int atomic(Ctx *c, const Insn *d, int op, int sz, uint64_t a, bool imm,
                  bool par)
{
    emit_ea(c, d);
    E4(G(call_c_ea), aok_x86_helper_atomic, c->off, a,
       op | sz << 8 | (imm ? AT_IMM : 0) | (par ? AT_PAR : 0));
    c->hf = HF_NONE;
    switch (op) {
    case ALU_ADD:
    case AT_XADD:
        c->cc = CC_OP_ADDB + sz;
        break;
    case ALU_SUB:
    case AT_NEG:
    case AT_CMPXCHG:
        c->cc = CC_OP_SUBB + sz;
        break;
    case ALU_AND:
    case ALU_OR:
    case ALU_XOR:
        c->cc = CC_OP_LOGICB + sz;
        break;
    case AT_INC:
        c->cc = CC_OP_INCB + sz;
        break;
    case AT_DEC:
        c->cc = CC_OP_DECB + sz;
        break;
    case AT_CMPXCHG8B:
    case AT_CMPXCHG16B:
    case AT_BTS:
    case AT_BTR:
    case AT_BTC:
        c->cc = CC_OP_EFLAGS;
        break;
    default:            /* not and xchg set none */
        break;
    }
    return NEXT;
}

/*
 * adc and sbb, which take the carry as a byte: E op= G, G op= E (@to_reg)
 * or E op= immediate. To memory it is a load, the register form on a
 * temporary, and a store.
 */
static int adc(Ctx *c, const Insn *d, int op, int sz, bool to_reg,
               bool has_imm, int64_t imm)
{
    bool sbb = op == ALU_SBB;
    uint64_t cf, dst, src = 0;
    bool rmw = false;

    if (sz < 1 || (d->lock && c->mp)) {
        return UNKNOWN;
    }
    cf = emit_cf(c);
    if (to_reg) {
        dst = R(d->reg);
        src = src_e(c, d, sz);
    } else {
        dst = rmw_begin(c, d, sz);
        src = R(d->reg);
        rmw = true;
    }
    E3(adc_tab[sbb][sz - 1][has_imm], dst, has_imm ? imm : src, cf);
    set_flags(c, sz == 1 ? HF_NONE : sbb ? HF_SUB : HF_ADD,
              (sbb ? CC_OP_SBBB : CC_OP_ADCB) + sz);
    if (rmw) {
        rmw_end(c, d, sz, true);
    }
    return NEXT;
}

/*
 * adcx (CF) and adox (OF, @ox): G += E + that flag, which is all the result
 * sets. Bignum code (OpenSSL, libgcrypt) runs two chains of them at once,
 * one on each flag; the lazy state is made CC_OP_EFLAGS once, before the
 * first, and each gadget reads and writes its bit of cc_src.
 */
static int adx(Ctx *c, const Insn *d, bool ox)
{
    int sz = d->w ? 3 : 2;
    uint64_t src;

    if (!c->adx) {
        return UNKNOWN;         /* TCG's #UD */
    }
    if (c->cc != CC_OP_EFLAGS) {
        E0(G(flush_cc));
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
    }
    src = src_e(c, d, sz);
    E2(adx_tab[ox][sz - 2], R(d->reg), src);
    set_flags(c, HF_NONE, CC_OP_EFLAGS);
    return NEXT;
}

/* E op= G, or G op= E (@to_reg). */
static int alu_modrm(Ctx *c, const Insn *d, int op, int sz, bool to_reg)
{
    const AluG *a = &alu_g[op][sz];
    uint64_t g = rn(d, d->reg, sz);

    if (d->lock) {
        /* Only with memory to write; where no other CPU runs it is nothing. */
        if (to_reg || d->mod == 3 || op == ALU_CMP || op == ALU_TEST) {
            return UNKNOWN;
        }
        if (c->mp && op != ALU_ADC && op != ALU_SBB) {
            return atomic(c, d, op, sz, g, false, true);
        }
    }
    if (op == ALU_ADC || op == ALU_SBB) {
        return adc(c, d, op, sz, to_reg, false, 0);
    }
    if (d->mod == 3) {
        uint64_t e = rn(d, d->rm, sz);

        if (to_reg) {
            E2(a->rr, g, e);
        } else {
            E2(a->rr, e, g);
        }
    } else {
        mem(c, d, to_reg ? a->rm : a->mr, g, sz);
    }
    alu_flags(c, op, sz);
    return NEXT;
}

/* E op= immediate. */
static int alu_imm(Ctx *c, const Insn *d, int op, int sz, int64_t imm)
{
    const AluG *a = &alu_g[op][sz];

    if (sz < 3) {
        imm &= MAKE_64BIT_MASK(0, 8 << sz);
    }
    if (d->lock) {
        if (d->mod == 3 || op == ALU_CMP || op == ALU_TEST) {
            return UNKNOWN;
        }
        if (c->mp && op != ALU_ADC && op != ALU_SBB) {
            return atomic(c, d, op, sz, imm, true, true);
        }
    }
    if (op == ALU_ADC || op == ALU_SBB) {
        return adc(c, d, op, sz, false, true, imm);
    }
    if (d->mod == 3) {
        E2(a->ri, rn(d, d->rm, sz), imm);
    } else {
        mem(c, d, a->mi, imm, sz);
    }
    alu_flags(c, op, sz);
    return NEXT;
}

/* rol and ror of E. */
static int rotate(Ctx *c, const Insn *d, int sz, bool cl, unsigned count,
                  bool right)
{
    unsigned bits = 8 << sz;
    uint64_t e;

    if (flags_dead(c) && !(cl && sz < 2)) {
        e = rmw_begin(c, d, sz);
        if (cl) {
            E2(sz == 3 ? G(rot64_cl) : G(rot32_cl), e, !right);
        } else {
            /* To the right, in the size: by nothing is still a write. */
            count %= bits;
            E2(ror_tab[sz], e, right ? count : (bits - count) % bits);
        }
        set_flags(c, HF_NONE, -1);
        rmw_end(c, d, sz, true);
        return NEXT;
    }
    e = rmw_begin(c, d, sz);
    E4(G(call_c), aok_x86_helper_rot, c->off, e,
       sz | (right ? 4 : 0) | (cl ? 8 : 0) | count << 8);
    set_flags(c, HF_NONE, cl ? -1 : CC_OP_EFLAGS);
    rmw_end(c, d, sz, false);
    return NEXT;
}

/* The shifts and rotates of E, by an immediate or by cl. */
static int shift(Ctx *c, const Insn *d, int sz, bool cl, unsigned count)
{
    unsigned mask = sz == 3 ? 63 : 31;
    uint64_t e;
    int k;

    count &= mask;
    if (!cl && !count) {
        return UNKNOWN;
    }
    switch (d->reg & 7) {
    case 0:
    case 1:
        return rotate(c, d, sz, cl, count, d->reg & 1);
    case 4:
    case 6:
        k = 0;
        break;
    case 5:
        k = 1;
        break;
    case 7:
        k = 2;
        break;
    default:            /* through the carry */
        return UNKNOWN;
    }
    e = rmw_begin(c, d, sz);
    if (cl) {
        /* By nothing it changes no flag, and what the host's say is lost. */
        E2(shift_cl_tab[k][sz], e, mask);
        set_flags(c, HF_NONE, -1);
    } else {
        E2(shift_tab[k][sz], e, count);
        set_flags(c, HF_NZ, (k == 0 ? CC_OP_SHLB : CC_OP_SARB) + sz);
    }
    rmw_end(c, d, sz, true);
    return NEXT;
}

/* shld and shrd of E by G, in C. */
static int shiftd(Ctx *c, const Insn *d, int sz, bool right, bool cl,
                  unsigned count)
{
    uint64_t e;

    count &= sz == 3 ? 63 : 31;
    if (sz < 2 || (!cl && !count)) {
        return UNKNOWN;
    }
    e = rmw_begin(c, d, sz);
    E4(G(call_c), aok_x86_helper_shiftd, c->off, e,
       sz | (right ? 4 : 0) | (cl ? 8 : 0) | count << 8 | d->reg << 16);
    set_flags(c, HF_NONE, cl ? -1 : (right ? CC_OP_SARB : CC_OP_SHLB) + sz);
    rmw_end(c, d, sz, false);
    return NEXT;
}

/*
 * bt, bts, btr, btc (@op) of E, the bit an immediate or G's. They change
 * the carry alone: see the gadgets for how the lazy flags say that.
 */
/*
 * With a register's bit number memory is a bit string of any length: the
 * operand is the dword or qword that number, signed, reaches from the
 * address (its bits above the size's, in units of the size), and the bit
 * that number's low bits. An ea gadget leaves the address, bt_ea* moves it
 * there, and the rest goes as for any operand there.
 */
static void bitstring_ea(Ctx *c, Insn *dd, int sz)
{
    emit_ea(c, dd);
    E1(!c->c64 ? G(bt_ea32_32) : sz == 3 ? G(bt_ea64) : G(bt_ea32), R(dd->reg));
    dd->m.ea_done = true;
}

static int bittest(Ctx *c, const Insn *d, int sz, int op, bool has_imm,
                   int64_t imm)
{
    uint64_t e, ccop = 0;
    bool string = !has_imm && d->mod != 3;
    Insn dd = *d;

    if (sz < 2 || (string && !c->c64 && d->m.seg >= 0)) {
        return UNKNOWN;     /* (32-bit code's fs or gs: the offset wraps first) */
    }
    if (d->lock) {
        if (op == 0 || d->mod == 3) {
            return UNKNOWN;
        }
        if (c->mp) {
            if (string) {
                bitstring_ea(c, &dd, sz);
                return atomic(c, &dd, AT_BTS + op - 1, sz, R(d->reg), false, true);
            }
            return atomic(c, d, AT_BTS + op - 1, sz, imm, true, true);
        }
    }
    if (cc_class(c->cc) >= 0) {
        ccop = CC_OP_SARB + (c->cc & 3);
    } else if (c->cc != CC_OP_EFLAGS) {
        E0(G(flush_cc));
    }
    if (string) {
        bitstring_ea(c, &dd, sz);
        d = &dd;
    }
    e = op ? rmw_begin(c, d, sz) : src_e(c, d, sz);
    E3(bt_tab[op][sz == 3][!has_imm], e,
       has_imm ? imm & ((8 << sz) - 1) : R(d->reg), ccop);
    set_flags(c, HF_BT, ccop ? ccop : CC_OP_EFLAGS);
    if (op) {
        rmw_end(c, d, sz, true);
    }
    return NEXT;
}

/* F6 and F7 but for test: not, neg, mul, imul, div, idiv of E. */
static int group3(Ctx *c, const Insn *d, int sz)
{
    int op = d->reg & 7;
    uint64_t e;

    if (d->lock) {
        if ((op != 2 && op != 3) || d->mod == 3) {
            return UNKNOWN;
        }
        if (c->mp) {
            return atomic(c, d, op == 2 ? AT_NOT : AT_NEG, sz, 0, true, true);
        }
    }
    switch (op) {
    case 2:
        e = rmw_begin(c, d, sz);
        E1(not_tab[sz], e);
        rmw_end(c, d, sz, true);
        return NEXT;
    case 3:
        e = rmw_begin(c, d, sz);
        E1(neg_tab[sz], e);
        set_flags(c, HF_SUB, CC_OP_SUBB + sz);
        rmw_end(c, d, sz, true);
        return NEXT;
    case 4:
    case 5:
        e = src_e(c, d, sz);
        E4(G(call_c), op == 4 ? aok_x86_helper_mul : aok_x86_helper_imul,
           c->off, e, sz);
        set_flags(c, HF_NONE, CC_OP_MULB + sz);
        return NEXT;
    default:
        e = src_e(c, d, sz);
        E4(G(call_c), aok_x86_helper_div, c->off, e, sz + (op == 7 ? 4 : 0));
        c->hf = HF_NONE;
        return NEXT;
    }
}

/* FE and FF: inc, dec, call, jmp and push of E. */
static int group5(Ctx *c, const Insn *d, int sz, bool ff)
{
    int op = d->reg & 7;
    uint64_t e, cf;

    if (d->lock) {
        if (op >= 2 || d->mod == 3) {
            return UNKNOWN;
        }
        if (c->mp) {
            return atomic(c, d, op ? AT_DEC : AT_INC, sz, 0, true, true);
        }
    }
    if (op < 2) {
        if (d->mod == 3 && sz >= 2 && flags_dead(c)) {
            /* Nothing wants its flags, the carry it keeps included. */
            E5(sz == 3 ? G(lea64) : G(lea32), R(d->rm), R(d->rm), ZERO, 0,
               op ? -1 : 1);
            set_flags(c, HF_NONE, -1);
            return NEXT;
        }
        cf = emit_cf(c);
        e = rmw_begin(c, d, sz);
        E2(incdec_tab[op][sz], e, cf);
        set_flags(c, HF_INCDEC, (op ? CC_OP_DECB : CC_OP_INCB) + sz);
        rmw_end(c, d, sz, true);
        return NEXT;
    }
    if (!ff || d->o16) {
        return UNKNOWN;
    }
    switch (op) {
    case 2:
        if (c->no_goto_ptr) {
            return UNKNOWN;
        }
        e = src_e(c, d, SW(c));
        E3(calli_tab[c->c64][c->mb], e, c->off + c->len, word(c, SW(c)));
        aok_emit_lookup_operands(&c->g);
        return END;
    case 4:
        if (c->no_goto_ptr) {
            return UNKNOWN;
        }
        e = src_e(c, d, SW(c));
        if (c->c64) {
            E2(G(jmpi), e, word(c, SW(c)));
        } else {
            E1(G(jmpi32), e);
        }
        aok_emit_lookup_operands(&c->g);
        return END;
    case 6:
        e = src_e(c, d, SW(c));
        E2(push_tab[c->c64][c->mb], e, word(c, SW(c)));
        c->hf = HF_NONE;
        return NEXT;
    default:            /* the far ones */
        return UNKNOWN;
    }
}

/* push of a segment register: its selector, extended with zeros. */
static int push_seg(Ctx *c, const Insn *d, int seg)
{
    if (d->o16) {
        return UNKNOWN;
    }
    E2(G(mov32), T0, SEGSEL(seg));
    E2(push_tab[c->c64][c->mb], T0, word(c, SW(c)));
    c->hf = HF_NONE;
    return NEXT;
}

/*
 * A segment register loaded from the 16 bits at @sel, as gen_movl_seg()
 * does it: in C, where the descriptor is read and what is due is raised.
 * The flags a TB is made for say whether es, ds and ss are at zero, so after
 * one of those the main loop looks again; ss has a shadow besides, and is
 * TCG's.
 */
static int load_seg(Ctx *c, int seg, uint64_t sel)
{
    E4(G(call_c), aok_x86_helper_load_seg, c->off, seg, sel);
    c->hf = HF_NONE;
    if (seg < R_FS) {
        E1(G(exit), c->off + c->len);
        return END;
    }
    return NEXT;
}

/* pop to a segment register: the stack pointer moves when it is loaded. */
static int pop_seg(Ctx *c, Insn *d, int seg)
{
    if (d->o16) {
        return UNKNOWN;
    }
    d->mod = 0;
    d->m = (Mem){ .base = R_ESP, .index = -1, .seg = -1 };
    mem(c, d, load_tab[SW(c)], T0, SW(c));
    E4(G(call_c), aok_x86_helper_load_seg, c->off, seg, T0);
    E5(c->c64 ? G(lea64) : G(lea32), R(R_ESP), R(R_ESP), ZERO, 0,
       c->c64 ? 8 : 4);
    c->hf = HF_NONE;
    if (seg < R_FS) {
        E1(G(exit), c->off + c->len);
        return END;
    }
    return NEXT;
}

static int jcc(Ctx *c, unsigned cc, int64_t rel)
{
    int a = cond_arm(c, cc);

    aok_emit_gadget(&c->g, jcc_tab[c->c64][a]);
    way(c, 0, (int64_t)c->off + c->len + rel);
    way(c, 1, c->off + c->len);
    return END;
}

/*
 * Whether the CPU may offer AVX-512 (target/i386/cpu.c): only TCG with these
 * gadgets computes it, in 64-bit code and flat 32-bit code alike (a 32-bit
 * Linux's CRC code uses it), so not with QEMU_AOK=0, QEMU_AOK_X86_NOVEC,
 * QEMU_AOK_X86_NO64 or QEMU_AOK_X86_NO32, nor with QEMU_AOK_X86_NOAVX512.
 */
bool x86_aok_avx512(void)
{
    return aok_enabled && !x86_novec && !x86_no64 && !x86_no32 &&
           !getenv("QEMU_AOK_X86_NOAVX512");
}

/*
 * 32-bit code this translator takes: protected mode with a 32-bit stack and
 * every segment but fs and gs at zero (a TB's cs_base too: the caller's), so
 * that an address is an offset and eip is the pc.
 */
static bool x86_aok_flat32(uint32_t flags)
{
    return (flags & (HF_PE_MASK | HF_CS32_MASK | HF_SS32_MASK | HF_ADDSEG_MASK |
                     HF_VM_MASK)) == (HF_PE_MASK | HF_CS32_MASK | HF_SS32_MASK);
}

/* Opcodes this translator is told to leave to TCG: QEMU_AOK_X86_SKIP. */
static bool x86_skip[512];

static void __attribute__((constructor)) x86_aok_init(void)
{
    const char *s = getenv("QEMU_AOK_X86_NOHF");

    if (s) {
        x86_nohf = strtoul(s, NULL, 16);
    }
    x86_nolive = getenv("QEMU_AOK_X86_NOLIVE");
    x86_nomb = getenv("QEMU_AOK_X86_NOMB");
    x86_nofp = getenv("QEMU_AOK_X86_NOFP");
    x86_novec = getenv("QEMU_AOK_X86_NOVEC");
    x86_nox87 = getenv("QEMU_AOK_X86_NOX87");
    x86_no32 = getenv("QEMU_AOK_X86_NO32");
    x86_no64 = getenv("QEMU_AOK_X86_NO64");
    x86_noone = getenv("QEMU_AOK_X86_NOONE");
    x86_sse_helpers = getenv("QEMU_AOK_X86_SSEHELPERS");
    s = getenv("QEMU_AOK_X86_SKIP");

    /* "88,89,1af": one-byte opcodes, and 0F ones as 1xx */
    while (s && *s) {
        char *end;
        unsigned long v = strtoul(s, &end, 16);

        if (end == s) {
            break;
        }
        if (v < ARRAY_SIZE(x86_skip)) {
            x86_skip[v] = true;
        }
        s = *end ? end + 1 : end;
    }
}

#define FIN() do {                      \
        if (d->bad) {                   \
            return UNKNOWN;             \
        }                               \
        c->len = d->p - code;           \
        c->next = d->p;                 \
        c->end = d->end;                \
    } while (0)

#include "translate-vec.c.inc"

/* ---- SSE -------------------------------------------------------------------
 *
 * The moves, and the integer operations that are one insn of the host's.
 * Nothing here reads or sets MXCSR; arithmetic in floating point is TCG's.
 * Without VEX an operation's memory operand must be aligned, and is loaded
 * to xmm_t0 as TCG's code loads it.
 */

/* The source of an operation: the register, or xmm_t0 loaded. */
static uint64_t sse_src(Ctx *c, const Insn *d)
{
    if (d->mod == 3) {
        return X(d->rm);
    }
    mem(c, d, vload_tab[1], XT0, 4 | 16);
    return XT0;
}

static int sse_op(Ctx *c, const Insn *d, void (*thunk)(void))
{
    uint64_t src = sse_src(c, d);

    E3(G(vop), X(d->reg), src, thunk);
    return NEXT;
}

/* A choice of the source's bytes (gadgets.S, vtbl). */
static int sse_tbl(Ctx *c, uint64_t dst, uint64_t src, const uint8_t *idx)
{
    E4(G(vtbl), dst, src, ldq_le_p(idx), ldq_le_p(idx + 8));
    return NEXT;
}

/*
 * Floating point: one call of the helper TCG's code would call, on the
 * registers by address. A scalar's memory operand is loaded to xmm_t0.
 */
static int sse_fp(Ctx *c, const Insn *d, unsigned b, int pfx, int64_t imm)
{
#define FP4(n) { helper_##n##ps_xmm, helper_##n##pd_xmm, helper_##n##ss, \
                 helper_##n##sd }
    /* add mul . . sub min div max, each for ps, pd, ss, sd */
    static void (*const arith[8][4])(CPUX86State *, ZMMReg *, ZMMReg *,
                                     ZMMReg *) = {
        FP4(add), FP4(mul), { NULL }, { NULL },
        FP4(sub), FP4(min), FP4(div), FP4(max),
    };
    bool mem_op = d->mod != 3, w = d->w;
    uint64_t g = X(d->reg), e = X(d->rm);
    uint8_t idx[16];
    void *fn;

    switch (b) {
    case 0x58 ... 0x5f:
        if (b == 0x5a) {
            /* cvtss2sd, cvtsd2ss; the packed ones between registers */
            if (pfx >= 2) {
                if (mem_op) {
                    mem(c, d, load_tab[pfx], XT0, pfx);
                    e = XT0;
                }
                E4(G(call_h3), pfx == 2 ? helper_cvtss2sd : helper_cvtsd2ss,
                   g, g, e);
            } else if (!mem_op) {
                E4(G(call_h3), pfx ? helper_cvtpd2ps_xmm : helper_cvtps2pd_xmm,
                   g, e, 0);
            } else {
                return UNKNOWN;
            }
        } else if (b == 0x5b) {
            if (pfx == 3 || mem_op) {
                return UNKNOWN;
            }
            E4(G(call_h3), pfx == 0 ? helper_cvtdq2ps_xmm :
               pfx == 1 ? helper_cvtps2dq_xmm : helper_cvttps2dq_xmm, g, e, 0);
        } else {
            /* add mul . . sub . div .: doubles, scalar and packed */
            static const Gadget host[8][2] = {
                { G(fp_addpd), G(fp_addsd) }, { G(fp_mulpd), G(fp_mulsd) },
                { NULL }, { NULL }, { G(fp_subpd), G(fp_subsd) }, { NULL },
                { G(fp_divpd), G(fp_divsd) }, { NULL },
            };
            Gadget gadget = G(call_h3);

            if (c->fp && (pfx & 1) && host[b - 0x58][pfx >> 1]) {
                gadget = host[b - 0x58][pfx >> 1];
            }
            if (pfx < 2) {
                e = sse_src(c, d);
            } else if (mem_op) {
                mem(c, d, load_tab[pfx], XT0, pfx);
                e = XT0;
            }
            E4(gadget, arith[b - 0x58][pfx], g, g, e);
        }
        c->hf = HF_NONE;
        return NEXT;

    case 0x51:              /* sqrt */
        if (pfx < 2) {
            e = sse_src(c, d);
            E4(G(call_h3), pfx ? helper_sqrtpd_xmm : helper_sqrtps_xmm, g, e,
               0);
        } else {
            if (mem_op) {
                mem(c, d, load_tab[pfx], XT0, pfx);
                e = XT0;
            }
            E4(c->fp && pfx == 3 ? G(fp_sqrtsd) : G(call_h3),
               pfx == 2 ? helper_sqrtss : helper_sqrtsd, g, g, e);
        }
        c->hf = HF_NONE;
        return NEXT;

    case 0x2a:              /* cvtsi2ss, cvtsi2sd: from a general register */
        if (pfx < 2) {
            return UNKNOWN;
        }
        fn = pfx == 2 ? (w ? (void *)helper_cvtsq2ss : (void *)helper_cvtsi2ss)
                      : (w ? (void *)helper_cvtsq2sd : (void *)helper_cvtsi2sd);
        if (mem_op) {
            mem(c, d, load_tab[w ? 3 : 2], T0, w ? 3 : 2);
        }
        E3(!c->fp || pfx == 2 ? G(call_hval) :
           w ? G(fp_cvtsq2sd) : G(fp_cvtsi2sd), fn, g, mem_op ? T0 : R(d->rm));
        c->hf = HF_NONE;
        return NEXT;

    case 0x2c:              /* cvttss2si, cvttsd2si */
    case 0x2d:              /* cvtss2si, cvtsd2si: to a general register */
        if (pfx < 2) {
            return UNKNOWN;
        }
        if (b == 0x2c) {
            fn = pfx == 2 ? (w ? (void *)helper_cvttss2sq
                               : (void *)helper_cvttss2si)
                          : (w ? (void *)helper_cvttsd2sq
                               : (void *)helper_cvttsd2si);
        } else {
            fn = pfx == 2 ? (w ? (void *)helper_cvtss2sq
                               : (void *)helper_cvtss2si)
                          : (w ? (void *)helper_cvtsd2sq
                               : (void *)helper_cvtsd2si);
        }
        if (mem_op) {
            mem(c, d, load_tab[pfx], XT0, pfx);
            e = XT0;
        }
        if (c->fp && b == 0x2c && pfx == 3) {
            E3(w ? G(fp_cvttsd2sq) : G(fp_cvttsd2si), fn, R(d->reg), e);
        } else {
            E3(w ? G(call_hret64) : G(call_hret32), fn, R(d->reg), e);
        }
        c->hf = HF_NONE;
        return NEXT;

    case 0x2e:              /* ucomiss, ucomisd */
    case 0x2f:              /* comiss, comisd */
        if (pfx > 1) {
            return UNKNOWN;
        }
        if (mem_op) {
            mem(c, d, load_tab[pfx ? 3 : 2], XT0, pfx ? 3 : 2);
            e = XT0;
        }
        E4(c->fp && pfx ? G(fp_comisd) : G(call_h3cc),
           b == 0x2e ? (pfx ? helper_ucomisd : helper_ucomiss)
                     : (pfx ? helper_comisd : helper_comiss), g, e, 0);
        set_flags(c, c->fp && pfx ? HF_FCMP : HF_NONE, CC_OP_EFLAGS);
        return NEXT;

    case 0x50:              /* movmskps, movmskpd */
        if (pfx > 1 || mem_op) {
            return UNKNOWN;
        }
        E3(G(call_hret32), pfx ? helper_movmskpd_xmm : helper_movmskps_xmm,
           R(d->reg), e);
        c->hf = HF_NONE;
        return NEXT;

    case 0xc6:              /* shufps, shufpd: lanes of both operands */
        if (pfx > 1) {
            return UNKNOWN;
        }
        e = sse_src(c, d);
        if (pfx == 0) {
            for (int i = 0; i < 16; i++) {
                idx[i] = (i >= 8 ? 16 : 0) + ((imm >> (i / 4 * 2)) & 3) * 4 +
                         i % 4;
            }
        } else {
            for (int i = 0; i < 16; i++) {
                idx[i] = (i >= 8 ? 16 : 0) + ((imm >> (i / 8)) & 1) * 8 + i % 8;
            }
        }
        E4(G(vtbl2), g, e, ldq_le_p(idx), ldq_le_p(idx + 8));
        return NEXT;

    default:
        return UNKNOWN;
    }
#undef FP4
}

/* @pfx: none, 66, f3, f2. @b: the opcode after 0f; the modrm is decoded. */
static int sse(Ctx *c, const Insn *d, unsigned b, int pfx, int64_t imm)
{
    /* The operations of 66 0f xx on registers, by xx. */
    static void (*const op66[256])(void) = {
        [0x14] = TH(zip1q), [0x15] = TH(zip2q),
        [0x54] = TH(and), [0x55] = TH(andn), [0x56] = TH(or),
        [0x57] = TH(xor),
        [0x60] = TH(zip1b), [0x61] = TH(zip1w), [0x62] = TH(zip1d),
        [0x64] = TH(cmgtb), [0x65] = TH(cmgtw), [0x66] = TH(cmgtd),
        [0x68] = TH(zip2b), [0x69] = TH(zip2w), [0x6a] = TH(zip2d),
        [0x6c] = TH(zip1q), [0x6d] = TH(zip2q),
        [0x74] = TH(cmeqb), [0x75] = TH(cmeqw), [0x76] = TH(cmeqd),
        [0xd4] = TH(addq), [0xd5] = TH(mulw),
        [0xd8] = TH(uqsubb), [0xd9] = TH(uqsubw), [0xda] = TH(uminb),
        [0xdb] = TH(and), [0xdc] = TH(uqaddb), [0xdd] = TH(uqaddw),
        [0xde] = TH(umaxb), [0xdf] = TH(andn),
        [0xe0] = TH(urhaddb), [0xe3] = TH(urhaddw),
        [0xe8] = TH(sqsubb), [0xe9] = TH(sqsubw), [0xea] = TH(sminw),
        [0xeb] = TH(or), [0xec] = TH(sqaddb), [0xed] = TH(sqaddw),
        [0xee] = TH(smaxw), [0xef] = TH(xor),
        [0xf8] = TH(subb), [0xf9] = TH(subw), [0xfa] = TH(subd),
        [0xfb] = TH(subq), [0xfc] = TH(addb), [0xfd] = TH(addw),
        [0xfe] = TH(addd),
    };
    bool mem_op = d->mod != 3;
    uint64_t g = X(d->reg), e = X(d->rm);
    uint8_t idx[16];

    if (!c->sse) {
        return UNKNOWN;
    }
    /* floating point, and its conversions: VEX's frames (sse_vex) */
    if (sse_vex(c, d, 1, b, pfx, imm) == NEXT) {
        return NEXT;
    }
    switch (b) {
    case 0x10:              /* movups, movupd, movss, movsd: G from E */
        if (pfx < 2) {
            if (mem_op) {
                mem(c, d, vload_tab[0], g, 4);
            } else {
                E2(G(vmov128), g, e);
            }
        } else if (mem_op) {
            mem(c, d, vloadz_tab[pfx == 3], g, pfx == 3 ? 3 : 2);
        } else {
            E2(pfx == 3 ? G(mov64) : G(vmov32), g, e);
        }
        return NEXT;
    case 0x11:              /* and E from G */
        if (pfx < 2) {
            if (mem_op) {
                mem(c, d, vstore_tab[0], g, 4);
            } else {
                E2(G(vmov128), e, g);
            }
        } else if (mem_op) {
            mem(c, d, store_tab[pfx == 3 ? 3 : 2], g, pfx == 3 ? 3 : 2);
        } else {
            E2(pfx == 3 ? G(mov64) : G(vmov32), e, g);
        }
        return NEXT;

    case 0x12:              /* movlps, movlpd; movhlps */
    case 0x16:              /* movhps, movhpd; movlhps */
        if (pfx > 1 || (pfx == 1 && !mem_op)) {
            return UNKNOWN;
        }
        if (mem_op) {
            mem(c, d, load_tab[3], g + (b == 0x16 ? 8 : 0), 3);
        } else if (b == 0x12) {
            E2(G(mov64), g, e + 8);
        } else {
            E2(G(mov64), g + 8, e);
        }
        return NEXT;
    case 0x13:
    case 0x17:
        if (pfx > 1 || !mem_op) {
            return UNKNOWN;
        }
        mem(c, d, store_tab[3], g + (b == 0x17 ? 8 : 0), 3);
        return NEXT;

    case 0x28:              /* movaps, movapd */
    case 0x29:
        if (pfx > 1) {
            return UNKNOWN;
        }
        if (!mem_op) {
            E2(G(vmov128), b == 0x28 ? g : e, b == 0x28 ? e : g);
        } else if (b == 0x28) {
            mem(c, d, vload_tab[1], g, 4 | 16);
        } else {
            mem(c, d, vstore_tab[1], g, 4 | 16);
        }
        return NEXT;
    case 0x2b:              /* movntps, movntpd, movntdq: stores */
    case 0xe7:
        if ((b == 0x2b ? pfx > 1 : pfx != 1) || !mem_op) {
            return UNKNOWN;
        }
        mem(c, d, vstore_tab[1], g, 4 | 16);
        return NEXT;

    case 0x6e:              /* movd, movq: from a general register */
        if (pfx != 1) {
            return UNKNOWN;
        }
        if (mem_op) {
            mem(c, d, vloadz_tab[d->w], g, d->w ? 3 : 2);
        } else {
            E2(d->w ? G(vmovq) : G(vmovd), g, R(d->rm));
        }
        return NEXT;
    case 0x7e:              /* and to one; after f3, movq between XMMs */
        if (pfx == 1) {
            if (mem_op) {
                mem(c, d, store_tab[d->w ? 3 : 2], g, d->w ? 3 : 2);
            } else {
                E2(d->w ? G(mov64) : G(mov32), R(d->rm), g);
            }
        } else if (pfx == 2) {
            if (mem_op) {
                mem(c, d, vloadz_tab[1], g, 3);
            } else {
                E2(G(vmovq), g, e);
            }
        } else {
            return UNKNOWN;
        }
        return NEXT;
    case 0xd6:              /* movq to E */
        if (pfx != 1) {
            return UNKNOWN;
        }
        if (mem_op) {
            mem(c, d, store_tab[3], g, 3);
        } else {
            E2(G(vmovq), e, g);
        }
        return NEXT;

    case 0x6f:              /* movdqa, and after f3 movdqu */
    case 0x7f:
        if (pfx != 1 && pfx != 2) {
            return UNKNOWN;
        }
        if (!mem_op) {
            E2(G(vmov128), b == 0x6f ? g : e, b == 0x6f ? e : g);
        } else if (b == 0x6f) {
            mem(c, d, vload_tab[pfx == 1], g, pfx == 1 ? 4 | 16 : 4);
        } else {
            mem(c, d, vstore_tab[pfx == 1], g, pfx == 1 ? 4 | 16 : 4);
        }
        return NEXT;

    case 0xd7:              /* pmovmskb */
        if (pfx != 1 || mem_op) {
            return UNKNOWN;
        }
        E2(G(pmovmskb), R(d->reg), e);
        return NEXT;

    case 0x70:              /* pshufd, pshufhw, pshuflw */
        if (pfx == 0) {
            return UNKNOWN;
        }
        for (int i = 0; i < 16; i++) {
            idx[i] = i;
        }
        if (pfx == 1) {
            for (int i = 0; i < 16; i++) {
                idx[i] = ((imm >> (i / 4 * 2)) & 3) * 4 + i % 4;
            }
        } else {
            int base = pfx == 2 ? 8 : 0;

            for (int i = 0; i < 8; i++) {
                idx[base + i] = base + ((imm >> (i / 2 * 2)) & 3) * 2 + i % 2;
            }
        }
        return sse_tbl(c, g, sse_src(c, d), idx);

    case 0x71:              /* the shifts by an immediate */
    case 0x72:
    case 0x73: {
        static void (*const lanes[3][2])(void) = {
            { TH(ushlw), TH(sshlw) }, { TH(ushld), TH(sshld) },
            { TH(ushlq), NULL },
        };
        int op = d->reg & 7, bits = 16 << (b - 0x71), n = imm & 0xff;

        if (pfx != 1 || mem_op) {
            return UNKNOWN;
        }
        if (b == 0x73 && (op == 3 || op == 7)) {
            /* psrldq and pslldq: by bytes */
            for (int i = 0; i < 16; i++) {
                int from = op == 3 ? i + n : i - n;

                idx[i] = from >= 0 && from < 16 ? from : 0xff;
            }
            return sse_tbl(c, e, e, idx);
        }
        if (op != 2 && op != 4 && op != 6) {
            return UNKNOWN;
        }
        if (op == 4) {
            /* An arithmetic shift by more leaves the sign everywhere. */
            if (b == 0x73) {
                return UNKNOWN;
            }
            E3(G(vshift), e, lanes[b - 0x71][1], -MIN(n, bits - 1));
        } else {
            /* By the lane's size or more it clears, as the host's does. */
            n = MIN(n, bits);
            E3(G(vshift), e, lanes[b - 0x71][0], op == 2 ? -n : n);
        }
        return NEXT;
    }

    case 0x14:              /* unpcklps, unpckhps: lanes of 32 bits */
    case 0x15:
        if (pfx == 0) {
            return sse_op(c, d, b == 0x14 ? TH(zip1d) : TH(zip2d));
        }
        break;
    case 0x54 ... 0x57:     /* andps, andnps, orps, xorps */
        if (pfx == 0) {
            return sse_op(c, d, op66[b]);
        }
        break;
    }
    if (pfx == 1 && op66[b]) {
        return sse_op(c, d, op66[b]);
    }
    return sse_fp(c, d, b, pfx, imm);
}

/* The opcodes after 0F. */
/* (with the x87's, below) */
void aok_x86_helper_ldmxcsr(CPUX86State *env, uint64_t pc, uint64_t a,
                            uint64_t b);
void aok_x86_helper_stmxcsr(CPUX86State *env, uint64_t pc, uint64_t a,
                            uint64_t b);

/* 0F 01: swapgs, rdtscp, clac, stac and invlpg; the rest TCG's. */
static int insn_0f01(Ctx *c, Insn *d, const uint8_t *code)
{
    unsigned m;

    if (d->p >= d->end) {
        return UNKNOWN;
    }
    m = *d->p;
    if ((m >> 6) != 3) {
        if (((m >> 3) & 7) != 7) {
            return UNKNOWN;
        }
        modrm(d);               /* invlpg */
        FIN();
        if (c->cpl != 0 || d->lock) {
            return UNKNOWN;
        }
        emit_ea(c, d);
        E1(c->c64 ? G(lea_ea64) : G(lea_ea32), T0);
        E4(G(call_c_exit), aok_x86_helper_invlpg, c->off, 0, c->len);
        return END;
    }
    d->p++;
    FIN();
    if (d->lock || d->o16 || d->rep || d->repne) {
        return UNKNOWN;
    }
    switch (m) {
    case 0xf8:                  /* swapgs */
        if (!c->c64 || c->cpl != 0) {
            return UNKNOWN;
        }
        E2(G(xchg64), SEGBASE(R_GS), offsetof(CPUX86State, kernelgsbase));
        return NEXT;
    case 0xf9:                  /* rdtscp */
        if (!(c->env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_RDTSCP)) {
            return UNKNOWN;
        }
        E4(G(call_c), aok_x86_helper_rdtscp, c->off, d->w, 0);
        c->hf = HF_NONE;
        return NEXT;
    case 0xca:                  /* clac */
    case 0xcb:                  /* stac */
        if (c->cpl != 0 || !(c->env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_SMAP)) {
            return UNKNOWN;
        }
        E4(G(call_c_exit), aok_x86_helper_ac, c->off, m == 0xcb, c->len);
        return END;
    default:
        return UNKNOWN;
    }
}

static int insn_0f(Ctx *c, Insn *d, const uint8_t *code, int sz)
{
    unsigned b = f8(d);
    int64_t imm;
    uint64_t e;
    int a;

    c->op = 0x100 | b;
    if (x86_skip[c->op]) {
        return UNKNOWN;
    }
    if (b == 0x38 || b == 0x3a) {
        return sse_3byte(c, d, code, b);
    }
    if ((b >= 0x10 && b <= 0x17) || (b >= 0x28 && b <= 0x2f) ||
        (b >= 0x50 && b <= 0x7f && b != 0x77) || b == 0xc2 || b == 0xc6 ||
        (b >= 0xd0 && b != 0xff)) {
        int pfx = d->repne ? 3 : d->rep ? 2 : d->o16 ? 1 : 0;

        /* The SSE opcodes, which the prefixes tell apart. */
        if (d->lock || (d->w && b != 0x6e && b != 0x7e && b != 0x2a &&
                        b != 0x2c && b != 0x2d)) {
            return UNKNOWN;
        }
        modrm(d);
        imm = (b >= 0x70 && b <= 0x73) || b == 0xc2 || b == 0xc6 ? fimm(d, 1) : 0;
        FIN();
        return sse(c, d, b, pfx, imm);
    }
    if ((d->rep || d->repne) && (b & 0xf0) != 0x80 && b != 0x1e &&
        b != 0x1f && b != 0xbc && b != 0xbd && b != 0xae && b != 0xb8) {
        return UNKNOWN;
    }
    if (d->lock && b != 0xb0 && b != 0xb1 && b != 0xc0 && b != 0xc1 &&
        b != 0xab && b != 0xb3 && b != 0xbb && b != 0xba && b != 0xc7) {
        return UNKNOWN;
    }
    switch (b) {
    case 0x31:              /* rdtsc */
        FIN();
        E4(G(call_c), aok_x86_helper_rdtsc, c->off, 0, 0);
        c->hf = HF_NONE;
        return NEXT;

    case 0x01:              /* the kernel's: swapgs, rdtscp, clac, stac, invlpg */
        return insn_0f01(c, d, code);

    case 0x00:              /* verr and verw (a 32-bit kernel's on its way out) */
        modrm(d);
        FIN();
        if ((d->reg & 7) != 4 && (d->reg & 7) != 5) {
            return UNKNOWN;
        }
        e = src_e(c, d, 1);
        E4(G(call_c), aok_x86_helper_verrw, c->off, e, (d->reg & 7) == 5);
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
        return NEXT;

    case 0xa2:              /* cpuid */
        FIN();
        E4(G(call_c), aok_x86_helper_cpuid, c->off, 0, 0);
        c->hf = HF_NONE;
        return NEXT;

    case 0xb8:              /* popcnt (f3) */
        modrm(d);
        FIN();
        if (!d->rep || d->repne || sz < 2 ||
            !(c->env->features[FEAT_1_ECX] & CPUID_EXT_POPCNT)) {
            return UNKNOWN;
        }
        e = src_e(c, d, sz);
        E2(sz == 3 ? G(popcnt64) : G(popcnt32), R(d->reg), e);
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
        return NEXT;

    case 0x05:              /* syscall, in 64-bit code */
        FIN();
        if (d->lock || !c->c64 ||
            !(c->env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL)) {
            return UNKNOWN;
        }
        E4(G(call_c_exit), aok_x86_helper_syscall, c->off, c->len, 0);
        return END;
    case 0x07:              /* sysret: the kernel's */
        FIN();
        if (d->lock || c->cpl != 0 || !c->c64 ||
            !(c->env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL)) {
            return UNKNOWN;
        }
        E4(G(call_c_exit), aok_x86_helper_sysret, c->off, d->w ? 2 : 1, 0);
        return END;

    case 0x20:              /* mov from and to cr0, cr2, cr3, cr4: the kernel's */
    case 0x22: {
        int cr;

        modrm(d);
        FIN();
        cr = (d->reg & 7) | (d->rr & 8);
        if (c->cpl != 0 || d->lock || d->mod != 3 ||
            (cr != 0 && cr != 2 && cr != 3 && cr != 4)) {
            return UNKNOWN;
        }
        if (b == 0x20) {
            E2(c->c64 ? G(mov64) : G(mov32), R(d->rm),
               offsetof(CPUX86State, cr[cr]));
            return NEXT;
        }
        E4(G(call_c_exit), aok_x86_helper_wrcr, c->off,
           cr | (uint64_t)R(d->rm) << 8, c->len);
        return END;
    }

    case 0xa3:              /* bt, bts, btr, btc of E by G */
    case 0xab:
    case 0xb3:
    case 0xbb:
        modrm(d);
        FIN();
        return bittest(c, d, sz, (b >> 3) & 3, false, 0);

    case 0xba:              /* and by an immediate */
        modrm(d);
        imm = fimm(d, 1);
        FIN();
        if ((d->reg & 7) < 4) {
            return UNKNOWN;
        }
        return bittest(c, d, sz, d->reg & 3, true, imm);

    case 0xa4:              /* shld and shrd, by an immediate and by cl */
    case 0xac:
        modrm(d);
        imm = fimm(d, 1);
        FIN();
        return shiftd(c, d, sz, b == 0xac, false, imm);
    case 0xa5:
    case 0xad:
        modrm(d);
        FIN();
        return shiftd(c, d, sz, b == 0xad, true, 0);

    case 0xae:              /* ldmxcsr, stmxcsr; the fences */
        modrm(d);
        FIN();
        if (d->mod != 3 && ((d->reg & 7) == 2 || (d->reg & 7) == 3)) {
            if (!c->sse || d->o16 || d->rep || d->repne || d->lock) {
                return UNKNOWN;
            }
            if ((d->reg & 7) == 2) {
                mem(c, d, load_tab[2], T0, 2);
                E4(G(call_c), aok_x86_helper_ldmxcsr, c->off, 0, 0);
            } else {
                E4(G(call_c), aok_x86_helper_stmxcsr, c->off, 0, 0);
                mem(c, d, store_tab[2], T0, 2);
            }
            c->hf = HF_NONE;
            return NEXT;
        }
        /* rdfsbase, rdgsbase, wrfsbase, wrgsbase */
        if (d->mod == 3 && d->rep && !d->repne && !d->o16 && !d->lock &&
            (d->reg & 7) < 4 && c->c64 &&
            (c->env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_FSGSBASE)) {
            E4(G(call_c), aok_x86_helper_fsgsbase, c->off,
               (d->reg & 3) | (d->w ? 4 : 0) | (uint64_t)R(d->rm) << 8, 0);
            return NEXT;
        }
        /* xsave, xrstor, xsaveopt: TCG's helpers */
        if (d->mod != 3 && (d->reg & 7) >= 4 && (d->reg & 7) <= 6 &&
            !d->rep && !d->repne && !d->o16 && !d->lock &&
            (c->env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE) &&
            ((d->reg & 7) != 6 ||
             (c->env->features[FEAT_XSAVE] & CPUID_XSAVE_XSAVEOPT))) {
            if ((d->reg & 7) == 5) {
                /* xrstor: what may change the TB's flags, then the main loop */
                emit_ea(c, d);
                E1(c->c64 ? G(lea_ea64) : G(lea_ea32), T0);
                E4(G(call_c_exit), aok_x86_helper_xrstor, c->off, d->w != 0,
                   c->len);
                return END;
            }
            emit_ea(c, d);
            E4(G(call_c_ea), aok_x86_helper_xsave, c->off, (d->reg & 7) == 6,
               d->w != 0);
            c->hf = HF_NONE;
            return NEXT;
        }
        /* lfence, mfence, sfence: an order of accesses */
        if (d->mod != 3 || (d->reg & 7) < 5 || d->o16 || d->rep || d->repne) {
            return UNKNOWN;
        }
        if (c->mp) {
            E0((d->reg & 7) == 5 ? G(mb_ld) : (d->reg & 7) == 6 ? G(mb) :
               G(mb_st));
        }
        return NEXT;

    case 0xa0:              /* push and pop of fs and gs */
    case 0xa8:
        FIN();
        return push_seg(c, d, b == 0xa0 ? R_FS : R_GS);
    case 0xa1:
    case 0xa9:
        FIN();
        return pop_seg(c, d, b == 0xa1 ? R_FS : R_GS);

    case 0xc7:              /* cmpxchg8b */
        modrm(d);
        FIN();
        if ((d->reg & 7) != 1 || d->mod == 3 || d->o16) {
            return UNKNOWN;
        }
        if (d->w) {             /* cmpxchg16b, where the CPU has it */
            if (!(c->env->features[FEAT_1_ECX] & CPUID_EXT_CX16)) {
                return UNKNOWN;
            }
            return atomic(c, d, AT_CMPXCHG16B, 3, 0, true, d->lock && c->mp);
        }
        return atomic(c, d, AT_CMPXCHG8B, 3, 0, true, d->lock && c->mp);

    case 0xb0:              /* cmpxchg, xadd: one step on memory */
    case 0xb1:
    case 0xc0:
    case 0xc1:
        modrm(d);
        FIN();
        if (d->mod == 3) {
            return UNKNOWN;
        }
        return atomic(c, d, b < 0xc0 ? AT_CMPXCHG : AT_XADD, b & 1 ? sz : 0,
                      rn(d, d->reg, b & 1 ? sz : 0), false,
                      d->lock && c->mp);

    case 0xbc:              /* bsf and bsr; after f3, tzcnt and lzcnt */
    case 0xbd: {
        static const Gadget scan[2][2][2] = {
            { { G(bsf32), G(bsf64) }, { G(tzcnt32), G(tzcnt64) } },
            { { G(bsr32), G(bsr64) }, { G(lzcnt32), G(lzcnt64) } },
        };
        /* (The feature each asks for is the other's: decode_0FBC().) */
        bool cnt = d->rep && (b == 0xbc ? c->abm : c->bmi1);

        modrm(d);
        FIN();
        if (sz < 2) {
            return UNKNOWN;
        }
        e = src_e(c, d, sz);
        E2(scan[b & 1][cnt][sz == 3], R(d->reg), e);
        if (cnt) {
            set_flags(c, HF_NONE, CC_OP_BMILGB + sz);
        } else {
            set_flags(c, HF_LOGIC, CC_OP_LOGICB + sz);
        }
        return NEXT;
    }

    case 0xc8 ... 0xcf:     /* bswap */
        FIN();
        if (sz < 2) {
            return UNKNOWN;
        }
        E1(sz == 3 ? G(bswap64) : G(bswap32), R((b & 7) | d->rb));
        return NEXT;

    case 0x0d:              /* prefetch, and the nops with an operand */
    case 0x18 ... 0x19:
    case 0x1c ... 0x1f:
        modrm(d);
        if (b == 0x0d && d->mod == 3) {
            return UNKNOWN;     /* prefetch of a register: #UD (TCG's) */
        }
        FIN();
        return NEXT;

    case 0x40 ... 0x4f:     /* cmov */
        modrm(d);
        FIN();
        e = src_e(c, d, sz);
        a = cond_arm(c, b & 15);
        E2(cmov_tab[sz - 1][a], R(d->reg), e);
        return NEXT;

    case 0x80 ... 0x8f: {
        int64_t rel = fimm(d, 4);

        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        return jcc(c, b & 15, rel);
    }

    case 0x90 ... 0x9f:     /* setcc */
        modrm(d);
        FIN();
        a = cond_arm(c, b & 15);
        if (d->mod == 3) {
            E1(set_tab[a], r8(d, d->rm));
        } else {
            E1(set_tab[a], T0);
            mem(c, d, store_tab[0], T0, 0);
        }
        return NEXT;

    case 0xaf:              /* imul G, E */
        modrm(d);
        FIN();
        if (sz < 2) {
            return UNKNOWN;
        }
        e = src_e(c, d, sz);
        E3(sz == 3 ? G(imul64_rr) : G(imul32_rr), R(d->reg), R(d->reg), e);
        set_flags(c, HF_NONE, CC_OP_MULB + sz);
        return NEXT;

    case 0xb6:              /* movzx G, Eb and G, Ew */
    case 0xb7:
    case 0xbe:              /* movsx */
    case 0xbf: {
        int ssz = b & 1;
        bool sign = b & 8;

        modrm(d);
        FIN();
        if (sz < 2) {
            return UNKNOWN;
        }
        if (d->mod == 3) {
            static const Gadget zx[2] = { G(movzx8), G(movzx16) };
            static const Gadget sx[2][2] = {
                { G(movsx8_32), G(movsx8_64) },
                { G(movsx16_32), G(movsx16_64) },
            };

            E2(sign ? sx[ssz][sz == 3] : zx[ssz], R(d->reg),
               rn(d, d->rm, ssz));
        } else {
            mem(c, d, sign ? loadsx_tab[ssz][sz == 3] : loadzx_tab[ssz],
                R(d->reg), ssz);
        }
        return NEXT;
    }

    default:
        return UNKNOWN;
    }
}

/*
 * One instruction at @code. Whatever is not recognised here returns UNKNOWN
 * with nothing emitted that matters: the caller takes the stream back to
 * where the insn began.
 */
/* ---- The x87 (D8-DF) ----------------------------------------------------------
 *
 * The gadgets are the aok-gadgets repository's (x87-host.S): the hardware's
 * answers in integer arithmetic, where TCG calls softfloat. What is decided
 * here is which gadget an opcode and its ModRM are, and that follows iSH-AOK's
 * jit/gen.c (x87_reg_gadget, X87M_TABLE), whose gadgets they are.
 *
 * A register form's word is [what the gadget wants in its low byte | the
 * insn's distance from the TB's first << 32]; a memory form's is a memory
 * gadget's, after an ea gadget. Left to TCG: fldenv, fnstenv, frstor, fnsave
 * and fninit, which also sets what softfloat keeps.
 */
void aok_x86_helper_fwait(CPUX86State *env, uint64_t pc);
void aok_x86_helper_fwait(CPUX86State *env, uint64_t pc)
{
    x86_sync(env, pc);
    helper_fwait(env);
}

/* The ten-byte operands, to and from aok_tmp, as helper_fldt and fstt do. */
void aok_x86_helper_ld80(CPUX86State *env, uint64_t addr, uint64_t pc);
void aok_x86_helper_ld80(CPUX86State *env, uint64_t addr, uint64_t pc)
{
    uint64_t hi = env->hflags & HF_CS64_MASK ? addr + 8 : (uint32_t)(addr + 8);

    x86_sync(env, pc);
    env->aok_tmp[0] = x86_ld(env, addr, 3);
    env->aok_tmp[1] = x86_ld(env, hi, 1);
}

void aok_x86_helper_st80(CPUX86State *env, uint64_t addr, uint64_t pc);
void aok_x86_helper_st80(CPUX86State *env, uint64_t addr, uint64_t pc)
{
    uint64_t hi = env->hflags & HF_CS64_MASK ? addr + 8 : (uint32_t)(addr + 8);

    x86_sync(env, pc);
    x86_st(env, addr, 3, env->aok_tmp[0]);
    x86_st(env, hi, 1, env->aok_tmp[1]);
}

/*
 * MXCSR, through aok_tmp. A read wants every flag there is: what the host's
 * FP unit raised in this stream is folded in first.
 */
void aok_x86_helper_ldmxcsr(CPUX86State *env, uint64_t pc, uint64_t a,
                            uint64_t b);
void aok_x86_helper_ldmxcsr(CPUX86State *env, uint64_t pc, uint64_t a,
                            uint64_t b)
{
    x86_sync(env, pc);
    if (env->aok_tmp[0] & ~(uint64_t)MXCSR_MASK) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, 0);
    }
    cpu_set_mxcsr(env, env->aok_tmp[0]);
}

void aok_x86_helper_stmxcsr(CPUX86State *env, uint64_t pc, uint64_t a,
                            uint64_t b);
void aok_x86_helper_stmxcsr(CPUX86State *env, uint64_t pc, uint64_t a,
                            uint64_t b)
{
    CPUState *cs = env_cpu(env);

    if (cs->aok_host_fpsr) {
        x86_aok_fold_fpsr(cs, cs->aok_host_fpsr);
        cs->aok_host_fpsr = 0;
    }
    update_mxcsr_from_sse_status(env);
    env->aok_tmp[0] = env->mxcsr;
}

/*
 * fldcw: the word is in aok_tmp. It waits, keeps the bits that exist (bit 6
 * reads as 1) and makes ES and B follow the flags and the new masks, as the
 * hardware does and iSH-AOK's gadget; through QEMU's helper, which sets
 * softfloat's modes for the insns that are still TCG's.
 */
void aok_x86_helper_fldcw(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b);
void aok_x86_helper_fldcw(CPUX86State *env, uint64_t pc, uint64_t a,
                          uint64_t b)
{
    uint16_t cw = (env->aok_tmp[0] & 0x1f3f) | 0x40;

    x86_sync(env, pc);
    if (env->fpus & 0x80) {
        helper_fwait(env);
    }
    helper_fldcw(env, cw);
    env->fpus &= ~0x8080;
    if (env->fpus & ~cw & 0x3f) {
        env->fpus |= 0x8080;
    }
}

#define X87_REG(X)                                                          \
    X(fwait) X(add_rr) X(sub_rr) X(subr_rr) X(mul_rr) X(div_rr) X(divr_rr)  \
    X(com_rr) X(ucom_rr) X(comi_rr) X(ucomi_rr) X(fld_rr) X(fst_rr)         \
    X(fxch) X(ffree) X(fchs) X(fabs) X(ftst) X(fxam) X(fldc) X(fincstp)     \
    X(fdecstp) X(fsqrt) X(frndint) X(fscale) X(fxtract) X(fprem) X(fprem1)  \
    X(f2xm1) X(fyl2x) X(fptan) X(fpatan) X(fyl2xp1) X(fsincos) X(fsin)      \
    X(fcos) X(fcmovb) X(fcmove) X(fcmovbe) X(fcmovu) X(fcmovnb) X(fcmovne)  \
    X(fcmovnbe) X(fcmovnu) X(fnclex)
#define X87_DECL(n) DECL(x87_##n)
X87_REG(X87_DECL)
#undef X87_DECL
#define X87_MEM(X)                                                          \
    X(add_f32) X(mul_f32) X(com_f32) X(comp_f32) X(sub_f32) X(subr_f32)     \
    X(div_f32) X(divr_f32) X(add_f64) X(mul_f64) X(com_f64) X(comp_f64)     \
    X(sub_f64) X(subr_f64) X(div_f64) X(divr_f64) X(add_i16) X(mul_i16)     \
    X(com_i16) X(comp_i16) X(sub_i16) X(subr_i16) X(div_i16) X(divr_i16)    \
    X(add_i32) X(mul_i32) X(com_i32) X(comp_i32) X(sub_i32) X(subr_i32)     \
    X(div_i32) X(divr_i32) X(fld_f32) X(fst_f32) X(fstp_f32) X(fild_i32)    \
    X(fisttp_i32) X(fist_i32) X(fistp_i32) X(fld_f64) X(fisttp_i64)         \
    X(fst_f64) X(fstp_f64) X(fild_i16) X(fisttp_i16) X(fist_i16)            \
    X(fistp_i16) X(fild_i64) X(fistp_i64) X(fld_f80) X(fstp_f80) X(fbld)    \
    X(fbstp)
#define X87_DECL(n) DECL(x87m_##n) DECL(x87m_##n##_mp)
X87_MEM(X87_DECL)
#undef X87_DECL
DECL(x87h_fnstsw)
DECL(x87h_fnstcw)

typedef struct X87Mem {
    Gadget g[2];            /* without barriers, with */
    int sz;                 /* the log2 of the operand's bytes; 0: none */
} X87Mem;
#define XM(n, sz) { { G(x87m_##n), G(x87m_##n##_mp) }, sz }
#define XA(k, sz) XM(add_##k, sz), XM(mul_##k, sz), XM(com_##k, sz),        \
                  XM(comp_##k, sz), XM(sub_##k, sz), XM(subr_##k, sz),      \
                  XM(div_##k, sz), XM(divr_##k, sz)
#define XN { { NULL, NULL }, 0 }
static const X87Mem x87_mem[8][8] = {
    { XA(f32, 2) },
    { XM(fld_f32, 2), XN, XM(fst_f32, 2), XM(fstp_f32, 2), XN, XN, XN, XN },
    { XA(i32, 2) },
    { XM(fild_i32, 2), XM(fisttp_i32, 2), XM(fist_i32, 2), XM(fistp_i32, 2),
      XN, XM(fld_f80, 3), XN, XM(fstp_f80, 3) },
    { XA(f64, 3) },
    { XM(fld_f64, 3), XM(fisttp_i64, 3), XM(fst_f64, 3), XM(fstp_f64, 3),
      XN, XN, XN, XN },
    { XA(i16, 1) },
    { XM(fild_i16, 1), XM(fisttp_i16, 1), XM(fist_i16, 1), XM(fistp_i16, 1),
      XM(fbld, 3), XM(fild_i64, 3), XM(fbstp, 3), XM(fistp_i64, 3) },
};
#undef XM
#undef XA
#undef XN

/* What x87_reg() found that is not a gadget with a word. */
#define X87_UD      ((Gadget)0)
#define X87_NOP     ((Gadget)1)     /* feni, fdisi, fsetpm: nothing since the 387 */
#define X87_FNSTSW  ((Gadget)2)     /* fnstsw ax */

/* A register form's gadget and what it wants: iSH-AOK's x87_reg_gadget(). */
static Gadget x87_reg(unsigned b, unsigned reg, unsigned rm, uint64_t *imm)
{
    static const Gadget fcmov[8] = {
        G(x87_fcmovb), G(x87_fcmove), G(x87_fcmovbe), G(x87_fcmovu),
        G(x87_fcmovnb), G(x87_fcmovne), G(x87_fcmovnbe), G(x87_fcmovnu),
    };
    /*
     * D8 /r is ST(0) op ST(i), DC /r ST(i) op ST(0) (whose sub and div pairs
     * Intel names the other way round), DE the DC forms and a pop.
     */
    static const Gadget arith_d8[8] = {
        G(x87_add_rr), G(x87_mul_rr), NULL, NULL,
        G(x87_sub_rr), G(x87_subr_rr), G(x87_div_rr), G(x87_divr_rr),
    };
    static const Gadget arith_dc[8] = {
        G(x87_add_rr), G(x87_mul_rr), NULL, NULL,
        G(x87_subr_rr), G(x87_sub_rr), G(x87_divr_rr), G(x87_div_rr),
    };

    *imm = rm;
    switch (b) {
    case 0xd8:
        if (reg == 2 || reg == 3) {
            *imm = rm | (reg == 3 ? 1 << 6 : 0);
            return G(x87_com_rr);
        }
        return arith_d8[reg];
    case 0xd9:
        switch (reg) {
        case 0:
            return G(x87_fld_rr);
        case 1:
            return G(x87_fxch);
        case 2:
            return rm == 0 ? G(x87_fwait) : X87_UD;     /* fnop waits */
        case 3:
            *imm = rm | 3 << 6;                         /* fstp1, an alias */
            return G(x87_fst_rr);
        case 4:
            return rm == 0 ? G(x87_fchs) : rm == 1 ? G(x87_fabs) :
                   rm == 4 ? G(x87_ftst) : rm == 5 ? G(x87_fxam) : X87_UD;
        case 5:
            return rm == 7 ? X87_UD : G(x87_fldc);
        case 6:
            switch (rm) {
            case 0:
                return G(x87_f2xm1);
            case 1:
                return G(x87_fyl2x);
            case 2:
                return G(x87_fptan);
            case 4:
                return G(x87_fxtract);
            case 5:
                return G(x87_fprem1);
            case 6:
                return G(x87_fdecstp);
            case 7:
                return G(x87_fincstp);
            default:
                return G(x87_fpatan);
            }
        default:
            switch (rm) {
            case 0:
                return G(x87_fprem);
            case 1:
                return G(x87_fyl2xp1);
            case 2:
                return G(x87_fsqrt);
            case 3:
                return G(x87_fsincos);
            case 4:
                return G(x87_frndint);
            case 5:
                return G(x87_fscale);
            case 6:
                return G(x87_fsin);
            default:
                return G(x87_fcos);
            }
        }
    case 0xda:
        if (reg < 4) {
            return fcmov[reg];
        }
        if (reg == 5 && rm == 1) {
            *imm = 1 | 2 << 6;                          /* fucompp */
            return G(x87_ucom_rr);
        }
        return X87_UD;
    case 0xdb:
        if (reg < 4) {
            return fcmov[reg + 4];
        }
        if (reg == 4) {
            /* (fninit, rm 3, is TCG's: it sets softfloat's modes as well) */
            return rm == 0 || rm == 1 || rm == 4 ? X87_NOP :
                   rm == 2 ? G(x87_fnclex) : X87_UD;
        }
        return reg == 5 ? G(x87_ucomi_rr) : reg == 6 ? G(x87_comi_rr) : X87_UD;
    case 0xdc:
        if (reg == 2 || reg == 3) {                     /* fcom2, fcomp3 */
            *imm = rm | (reg == 3 ? 1 << 6 : 0);
            return G(x87_com_rr);
        }
        *imm = rm << 3;
        return arith_dc[reg];
    case 0xdd:
        switch (reg) {
        case 0:
            return G(x87_ffree);
        case 1:
            return G(x87_fxch);                         /* fxch4 */
        case 2:
            return G(x87_fst_rr);
        case 3:
            *imm = rm | 1 << 6;
            return G(x87_fst_rr);
        case 4:
            return G(x87_ucom_rr);
        case 5:
            *imm = rm | 1 << 6;
            return G(x87_ucom_rr);
        default:
            return X87_UD;
        }
    case 0xde:
        if (reg == 2) {                                 /* fcomp5 */
            *imm = rm | 1 << 6;
            return G(x87_com_rr);
        }
        if (reg == 3) {
            if (rm != 1) {
                return X87_UD;
            }
            *imm = 1 | 2 << 6;                          /* fcompp */
            return G(x87_com_rr);
        }
        *imm = rm << 3 | 1 << 6;
        return arith_dc[reg];
    default:
        switch (reg) {
        case 0:
            *imm = rm | 1 << 6;                         /* ffreep */
            return G(x87_ffree);
        case 1:
            return G(x87_fxch);                         /* fxch7 */
        case 2:
        case 3:
            *imm = rm | 1 << 6;                         /* fstp8, fstp9 */
            return G(x87_fst_rr);
        case 4:
            return rm == 0 ? X87_FNSTSW : X87_UD;
        case 5:
            *imm = rm | 1 << 6;
            return G(x87_ucomi_rr);
        case 6:
            *imm = rm | 1 << 6;
            return G(x87_comi_rr);
        default:
            return X87_UD;
        }
    }
}

/*
 * A waiting x87 gadget's second word, for x87h_note (x87-host.S), which
 * leaves the insn's address and opcode as the last instruction's (fpcs,
 * fpip, fpop): the opcode, and bit 15 to say so; 0 for a control insn,
 * which leaves them as they were. A memory form's also has its operand's
 * offset and segment (fpdp, fpds): where in env that segment's selector is
 * (bits 16-31), the base to take from the address (32-47: fs's, gs's, or
 * the eight zero bytes), and bit 14 in 32-bit code, whose offsets wrap at
 * 32 bits. The segment is the one the access uses, as an AMD Ryzen records
 * it: an es, cs, ss or ds prefix counts in 32-bit code only, and with
 * neither that nor fs or gs, a base of esp or ebp (r12 and r13 are not) is
 * ss's.
 */
QEMU_BUILD_BUG_ON(SEGBASE(R_GS) > 0xffff || ZERO > 0xffff);

static uint64_t x87_note(Ctx *c, const Insn *d, unsigned b)
{
    uint64_t note = 0x8000 | (b & 7) << 8 | d->mod << 6 | (d->reg & 7) << 3 |
                    (d->rm & 7);
    int seg = R_DS;

    if (d->mod == 3) {
        return note;
    }
    if (d->m.seg >= 0) {
        seg = d->m.seg;
    } else if (!c->c64 && d->sreg >= 0) {
        seg = d->sreg;
    } else if (d->m.base == R_ESP || d->m.base == R_EBP) {
        seg = R_SS;
    }
    return note | (uint64_t)SEGSEL(seg) << 16 | (c->c64 ? 0 : 0x4000) |
           (uint64_t)(d->m.seg >= 0 ? SEGBASE(d->m.seg) : ZERO) << 32;
}

static int x87(Ctx *c, Insn *d, const uint8_t *code, unsigned b)
{
    unsigned reg, rm;
    uint64_t imm;
    Gadget g;

    modrm(d);
    FIN();
    if (!c->x87 || d->lock) {
        return UNKNOWN;
    }
    reg = d->reg & 7;
    rm = d->rm & 7;
    if (d->mod != 3) {
        const X87Mem *m = &x87_mem[b - 0xd8][reg];

        if (b == 0xd9 && reg == 5) {            /* fldcw */
            mem(c, d, load_tab[1], T0, 1);
            E4(G(call_c), aok_x86_helper_fldcw, c->off, 0, 0);
            c->hf = HF_NONE;
            return NEXT;
        }
        if ((b == 0xd9 || b == 0xdd) && reg == 7) {     /* fnstcw, fnstsw */
            E1(b == 0xd9 ? G(x87h_fnstcw) : G(x87h_fnstsw), T0);
            mem(c, d, store_tab[1], T0, 1);
            return NEXT;
        }
        if (!m->sz || (!c->sse3 && reg == 1 && (b & 1))) {      /* (fisttp) */
            return UNKNOWN;
        }
        emit_ea(c, d);
        E2(m->g[c->mb], word(c, m->sz), x87_note(c, d, b));
        c->hf = HF_NONE;
        return NEXT;
    }

    g = x87_reg(b, reg, rm, &imm);
    if (g == X87_UD) {
        return UNKNOWN;
    }
    if (g == X87_NOP) {
        return NEXT;
    }
    if (g == X87_FNSTSW) {
        E1(G(x87h_fnstsw), R(R_EAX));
        c->hf = HF_NONE;
        return NEXT;
    }
    if ((b == 0xda || b == 0xdb) && reg < 4 && c->cc != CC_OP_EFLAGS) {
        E0(G(flush_cc));                        /* fcmov reads cc_src */
        c->cc = CC_OP_EFLAGS;
    }
    E2(g, imm | (uint64_t)c->off << 32,
       g == G(x87_fnclex) ? 0 : x87_note(c, d, b));
    c->hf = HF_NONE;
    if (g == G(x87_comi_rr) || g == G(x87_ucomi_rr)) {
        c->cc = CC_OP_EFLAGS;
    }
    return NEXT;
}

static int insn1(Ctx *c, Insn *d, const uint8_t *code)
{
    unsigned b;
    int64_t imm;
    int sz, bsz, r;
    uint64_t e;

    for (;;) {
        b = f8(d);
        switch (b) {
        case 0x66:
            d->o16 = true;
            continue;
        case 0xf0:
            d->lock = true;
            continue;
        case 0xf2:
            d->repne = true;
            d->rep = false;
            continue;
        case 0xf3:
            d->rep = true;
            d->repne = false;
            continue;
        case 0x26:          /* es, cs, ss, ds: nothing in 64-bit code, and */
        case 0x2e:          /* bases of 0 in flat 32-bit code, where only */
        case 0x36:          /* the x87's data selector sees them */
        case 0x3e:
            d->sreg = (b >> 3) & 3;
            continue;
        case 0x64:
            d->seg = R_FS;
            continue;
        case 0x65:
            d->seg = R_GS;
            continue;
        case 0x67:
            d->a32 = true;
            continue;
        }
        break;
    }
    if (c->c64 && b >= 0x40 && b <= 0x4f) {
        /* REX, which counts only as the last prefix: any other is no opcode */
        d->rex = true;
        d->w = b & 8;
        d->rr = (b & 4) << 1;
        d->rx = (b & 2) << 2;
        d->rb = (b & 1) << 3;
        b = f8(d);
    }
    c->op = b;
    if (d->bad || x86_skip[b]) {
        return UNKNOWN;
    }
    /* A lock prefix is for an insn that writes memory: each checks that. */
    if (d->lock && !((b < 0x40 && (b & 7) < 2) || b == 0x80 || b == 0x81 ||
                     b == 0x83 || b == 0x86 || b == 0x87 || b == 0xf6 ||
                     b == 0xf7 || b == 0xfe || b == 0xff || b == 0x0f)) {
        return UNKNOWN;
    }
    sz = d->w ? 3 : d->o16 ? 1 : 2;
    bsz = b & 1 ? sz : 0;       /* where bit 0 says "not a byte" */
    if (b == 0x0f) {
        return insn_0f(c, d, code, sz);
    }
    /*
     * VEX and EVEX; in 32-bit code only where the next byte starts with two
     * set bits: otherwise they are les, lds and bound (TCG's). With that
     * byte in the next page, the insn runs into it (translate() then reads
     * on there).
     */
    if (!c->c64 && (b == 0xc4 || b == 0xc5 || b == 0x62) && d->p >= d->end) {
        d->bad = true;
        return UNKNOWN;
    }
    if ((b == 0xc4 || b == 0xc5) && (c->c64 || (d->p[0] & 0xc0) == 0xc0)) {
        return vex(c, d, code, b);
    }
    if (b == 0x62 && (c->c64 || (d->p[0] & 0xc0) == 0xc0)) {
        return evex(c, d, code);
    }
    /* rep ret, and bnd before a branch, are that ret and that branch. */
    if ((d->rep || d->repne) &&
        !(b == 0xc2 || b == 0xc3 || b == 0xe8 || b == 0xe9 || b == 0xeb ||
          b == 0xff || (b & 0xf0) == 0x70 || (b >= 0xa4 && b <= 0xa7) ||
          (b >= 0xaa && b <= 0xaf) || b == 0x90)) {
        return UNKNOWN;
    }

    switch (b) {
    case 0x00 ... 0x3f:     /* add or adc sbb and sub xor cmp */
        if (!c->c64 && (b & 7) >= 6 && b < 0x20) {
            /* In 32-bit code: push and pop of es, cs, ss, ds. */
            static const uint8_t seg[4] = { R_ES, R_CS, R_SS, R_DS };

            FIN();
            if (!(b & 1)) {
                return push_seg(c, d, seg[b >> 3]);
            }
            if (b == 0x07 || b == 0x1f) {
                return pop_seg(c, d, seg[b >> 3]);
            }
            return UNKNOWN;
        }
        switch (b & 7) {
        case 0:
        case 1:
            modrm(d);
            FIN();
            return alu_modrm(c, d, b >> 3, bsz, false);
        case 2:
        case 3:
            modrm(d);
            FIN();
            return alu_modrm(c, d, b >> 3, bsz, true);
        case 4:
        case 5:
            imm = fimmz(d, bsz);
            FIN();
            d->mod = 3;
            d->rm = R_EAX;
            return alu_imm(c, d, b >> 3, bsz, imm);
        default:
            return UNKNOWN;
        }

    case 0x40 ... 0x4f:     /* in 32-bit code: inc and dec of a register */
        FIN();
        if (c->c64) {
            return UNKNOWN;
        }
        d->mod = 3;
        d->rm = b & 7;
        d->reg = (b >> 3) & 1;
        return group5(c, d, sz, false);

    case 0x50 ... 0x57:
        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        E2(push_tab[c->c64][c->mb], R((b & 7) | d->rb), word(c, SW(c)));
        c->hf = HF_NONE;
        return NEXT;

    case 0x58 ... 0x5f:
        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        E2(pop_tab[c->c64][c->mb], R((b & 7) | d->rb), word(c, SW(c)));
        c->hf = HF_NONE;
        return NEXT;

    case 0x63:              /* movsxd */
        modrm(d);
        FIN();
        if (!d->w) {
            return UNKNOWN;
        }
        if (d->mod == 3) {
            E2(G(movsx32_64), R(d->reg), R(d->rm));
        } else {
            mem(c, d, loadsx_tab[2][1], R(d->reg), 2);
        }
        return NEXT;

    case 0x68:
    case 0x6a:
        imm = fimm(d, b == 0x68 ? 4 : 1);
        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        E2(pushi_tab[c->c64][c->mb], imm, word(c, SW(c)));
        c->hf = HF_NONE;
        return NEXT;

    case 0x69:              /* imul G, E, immediate */
    case 0x6b:
        modrm(d);
        imm = b == 0x69 ? fimmz(d, sz) : fimm(d, 1);
        FIN();
        if (sz < 2) {
            return UNKNOWN;
        }
        e = src_e(c, d, sz);
        E3(sz == 3 ? G(imul64_ri) : G(imul32_ri), R(d->reg), e, imm);
        set_flags(c, HF_NONE, CC_OP_MULB + sz);
        return NEXT;

    case 0x70 ... 0x7f:
        imm = fimm(d, 1);
        FIN();
        if (d->o16) {
            return UNKNOWN;     /* a 16-bit ip (as jcc rel16's, jmp's and call's) */
        }
        return jcc(c, b & 15, imm);

    case 0x80:
    case 0x81:
    case 0x83:
        modrm(d);
        imm = b == 0x81 ? fimmz(d, sz) : fimm(d, 1);
        FIN();
        return alu_imm(c, d, d->reg & 7, bsz, imm);

    case 0x84:
    case 0x85:
        modrm(d);
        FIN();
        return alu_modrm(c, d, ALU_TEST, bsz, false);

    case 0x86:              /* xchg, which with memory is one step */
    case 0x87:
        modrm(d);
        FIN();
        if (d->mod != 3) {
            return atomic(c, d, AT_XCHG, bsz, rn(d, d->reg, bsz), false,
                          c->mp);
        }
        if (d->lock || bsz < 2) {
            return UNKNOWN;
        }
        E2(bsz == 3 ? G(xchg64) : G(xchg32), R(d->rm), R(d->reg));
        return NEXT;

    case 0x88:              /* mov E, G */
    case 0x89:
        modrm(d);
        FIN();
        if (d->mod == 3) {
            E2(mov_tab[bsz], rn(d, d->rm, bsz), rn(d, d->reg, bsz));
        } else {
            mem(c, d, store_tab[bsz], rn(d, d->reg, bsz), bsz);
        }
        return NEXT;

    case 0x8a:              /* mov G, E */
    case 0x8b:
        modrm(d);
        FIN();
        if (d->mod == 3) {
            E2(mov_tab[bsz], rn(d, d->reg, bsz), rn(d, d->rm, bsz));
        } else {
            mem(c, d, load_tab[bsz], rn(d, d->reg, bsz), bsz);
        }
        return NEXT;

    case 0x8c:              /* mov E, a segment register: its selector */
        modrm(d);
        FIN();
        if ((d->reg & 7) > R_GS) {
            return UNKNOWN;
        }
        if (d->mod != 3) {
            mem(c, d, store_tab[1], SEGSEL(d->reg & 7), 1);
        } else {
            E2(sz == 1 ? G(mov16) : G(mov32), R(d->rm), SEGSEL(d->reg & 7));
        }
        return NEXT;
    case 0x8e:              /* mov a segment register, E */
        modrm(d);
        FIN();
        r = d->reg & 7;
        if (r > R_GS || r == R_CS || r == R_SS) {
            return UNKNOWN;
        }
        e = src_e(c, d, 1);
        return load_seg(c, r, e);

    case 0x9b:              /* fwait */
        FIN();
        if (!c->x87) {
            return UNKNOWN;
        }
        E2(G(x87_fwait), (uint64_t)c->off << 32, 0);
        c->hf = HF_NONE;
        return NEXT;
    case 0xd8 ... 0xdf:
        return x87(c, d, code, b);

    case 0x8f:              /* pop E */
        modrm(d);
        FIN();
        if ((d->reg & 7) || d->o16) {
            return UNKNOWN;
        }
        if (d->mod == 3) {
            E2(pop_tab[c->c64][c->mb], R(d->rm), word(c, SW(c)));
        } else {
            /*
             * The store may fault, so the stack pointer moves after it; but
             * an address made with the stack pointer is made with the one
             * it will have (QEMU's popl_esp_hack).
             */
            Insn top = *d;

            top.m = (Mem){ .base = R_ESP, .index = -1, .seg = -1 };
            mem(c, &top, load_tab[SW(c)], T0, SW(c));
            if (d->m.base == R_ESP) {
                d->m.disp += c->c64 ? 8 : 4;
            }
            mem(c, d, store_tab[SW(c)], T0, SW(c));
            E5(c->c64 ? G(lea64) : G(lea32), R(R_ESP), R(R_ESP), ZERO, 0,
               c->c64 ? 8 : 4);
        }
        c->hf = HF_NONE;
        return NEXT;

    case 0x8d:              /* lea: no segment's base, whatever the prefix */
        modrm(d);
        FIN();
        if (d->mod == 3 || sz < 2) {
            return UNKNOWN;
        }
        if (d->m.riprel) {
            uint64_t delta = (int64_t)c->off + c->len + d->m.disp;

            if (sz == 3) {
                E2(G(pcrel), R(d->reg), delta);
            } else {
                E1(G(ea_pc), delta);
                E1(G(lea_ea32), R(d->reg));
            }
        } else {
            E5(sz == 3 ? G(lea64) : G(lea32), R(d->reg), ro(d->m.base),
               ro(d->m.index), d->m.scale, d->m.disp);
        }
        return NEXT;

    case 0x90 ... 0x97:     /* xchg with rax; 90 itself is nop */
        FIN();
        r = (b & 7) | d->rb;
        if (d->rep || d->repne) {
            if (!d->rep || r != R_EAX) {
                return UNKNOWN;
            }
            /* pause: the CPU's turn ends, at the next insn */
            E4(G(call_c), aok_x86_helper_pause, c->off + c->len, 0, 0);
            return END;
        }
        if (r == R_EAX) {
            return NEXT;
        }
        if (sz < 2) {
            return UNKNOWN;
        }
        E2(sz == 3 ? G(xchg64) : G(xchg32), R(R_EAX), R(r));
        return NEXT;

    case 0x98:
        FIN();
        if (sz < 2) {
            return UNKNOWN;
        }
        E0(sz == 3 ? G(cdqe) : G(cwde));
        return NEXT;

    case 0x99:
        FIN();
        if (sz < 2) {
            return UNKNOWN;
        }
        E0(sz == 3 ? G(cqo) : G(cdq));
        return NEXT;

    case 0x9d: {            /* popf, which ends the TB */
        uint32_t mask = TF_MASK | AC_MASK | ID_MASK | NT_MASK;

        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        if (c->cpl == 0) {
            mask |= IF_MASK | IOPL_MASK;
        } else if (c->iopl_ok) {
            mask |= IF_MASK;
        }
        E2(pop_tab[c->c64][c->mb], T0, word(c, SW(c)));
        E4(G(call_c_exit), aok_x86_helper_popf, c->off + c->len, mask, 0);
        return END;
    }

    case 0x9c:              /* pushf */
        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        E4(G(call_c), aok_x86_helper_pushf, c->off, 0, 0);
        E2(push_tab[c->c64][c->mb], T0, word(c, SW(c)));
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
        return NEXT;

    case 0xa0 ... 0xa3: {   /* mov between al or eax and an address */
        uint64_t addr = c->c64 ? fimm(d, 8) : (uint32_t)fimm(d, 4);

        FIN();
        if (d->a32) {
            return UNKNOWN;
        }
        d->mod = 0;
        d->m = (Mem){ .base = -1, .index = -1, .disp = addr, .seg = d->seg };
        mem(c, d, b < 0xa2 ? load_tab[bsz] : store_tab[bsz],
            rn(d, R_EAX, bsz), bsz);
        return NEXT;
    }

    case 0xa4 ... 0xa7:     /* movs, cmps, stos, lods, scas */
    case 0xaa ... 0xaf: {
        static const uint8_t kind[6] = { S_MOVS, S_CMPS, 0, S_STOS, S_LODS,
                                         S_SCAS };
        int k = kind[(b - 0xa4) >> 1], rp = d->rep ? 1 : d->repne ? 2 : 0;

        FIN();
        if (d->a32) {
            return UNKNOWN;
        }
        E4(G(call_c_stop), aok_x86_helper_string, c->off,
           k | bsz << 4 | rp << 8 | (c->c64 ? 0 : S_A32),
           d->seg >= 0 ? SEGBASE(d->seg) : 0);
        c->hf = HF_NONE;
        if (k == S_CMPS || k == S_SCAS) {
            c->cc = rp ? -1 : CC_OP_SUBB + bsz;
        }
        return NEXT;
    }

    case 0xa8:
    case 0xa9:
        imm = fimmz(d, bsz);
        FIN();
        d->mod = 3;
        d->rm = R_EAX;
        return alu_imm(c, d, ALU_TEST, bsz, imm);

    case 0xb0 ... 0xb7:
        imm = fimm(d, 1);
        FIN();
        E2(G(movi8), r8(d, (b & 7) | d->rb), imm);
        return NEXT;

    case 0xb8 ... 0xbf:
        imm = fimm(d, sz == 3 ? 8 : sz == 1 ? 2 : 4);
        FIN();
        r = (b & 7) | d->rb;
        if (sz == 1) {
            E2(G(movi16), R(r), imm);
        } else {
            E2(G(movi64), R(r), sz == 3 ? imm : (uint32_t)imm);
        }
        return NEXT;

    case 0xc0:              /* shifts by an immediate, by one, by cl */
    case 0xc1:
        modrm(d);
        imm = fimm(d, 1);
        FIN();
        return shift(c, d, bsz, false, imm);
    case 0xd0:
    case 0xd1:
        modrm(d);
        FIN();
        return shift(c, d, bsz, false, 1);
    case 0xd2:
    case 0xd3:
        modrm(d);
        FIN();
        return shift(c, d, bsz, true, 0);

    case 0xc2:
    case 0xc3:
        imm = b == 0xc2 ? (uint16_t)fimm(d, 2) : 0;
        FIN();
        if (d->o16 || c->no_goto_ptr) {
            return UNKNOWN;
        }
        E2(ret_tab[c->c64][c->mb], imm, word(c, SW(c)));
        aok_emit_lookup_operands(&c->g);
        return END;

    case 0xc6:              /* mov E, immediate */
    case 0xc7:
        modrm(d);
        imm = fimmz(d, bsz);
        FIN();
        if (d->reg & 7) {
            return UNKNOWN;
        }
        if (d->mod != 3) {
            mem(c, d, storei_tab[bsz], imm, bsz);
        } else if (bsz == 0) {
            E2(G(movi8), r8(d, d->rm), imm);
        } else if (bsz == 1) {
            E2(G(movi16), R(d->rm), imm);
        } else {
            E2(G(movi64), R(d->rm), bsz == 3 ? imm : (uint32_t)imm);
        }
        return NEXT;

    case 0xc9:
        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        E1(leave_tab[c->c64][c->mb], word(c, SW(c)));
        c->hf = HF_NONE;
        return NEXT;

    case 0xe8:
        imm = fimm(d, 4);
        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        E2(call_tab[c->c64][c->mb], c->off + c->len, word(c, SW(c)));
        way(c, 0, (int64_t)c->off + c->len + imm);
        return END;

    case 0xe9:
    case 0xeb:
        imm = fimm(d, b == 0xe9 ? 4 : 1);
        FIN();
        if (d->o16) {
            return UNKNOWN;
        }
        if (c->after_sti) {
            /*
             * The insn after sti (the kernel's local_irq_enable and on): an
             * interrupt waiting is taken where the jmp goes, as at the end
             * of any other.
             */
            E2(G(irq_check), (int64_t)c->off + c->len + imm, IRQ_REQUEST);
            c->sti_jmp = true;
        }
        E0(c->c64 ? G(jmp) : G(jmp32));
        way(c, 0, (int64_t)c->off + c->len + imm);
        return END;

    case 0xe2:              /* loop, jcxz: the count is rcx, or ecx */
    case 0xe3:
        imm = fimm(d, 1);
        FIN();
        if (d->a32 || d->o16) {
            return UNKNOWN;
        }
        E0(b == 0xe2 ? (c->c64 ? G(loop) : G(loop32))
                     : (c->c64 ? G(jcxz) : G(jcxz32)));
        way(c, 0, (int64_t)c->off + c->len + imm);
        way(c, 1, c->off + c->len);
        return END;

    case 0xe4 ... 0xe7:     /* in and out: a port by number, and dx's */
    case 0xec ... 0xef:
        imm = b < 0xe8 ? (uint8_t)fimm(d, 1) : 0x10000;
        FIN();
        if (!c->io_ok) {
            return UNKNOWN;
        }
        E4(G(call_c), aok_x86_helper_io, c->off, imm,
           MIN(bsz, 2) | (b & 2 ? 4 : 0));
        c->hf = HF_NONE;
        return NEXT;

    case 0x9e:              /* sahf, lahf */
    case 0x9f:
        FIN();
        if (!c->lahf) {
            return UNKNOWN;
        }
        E4(G(call_c), aok_x86_helper_flagop, c->off, b == 0x9f ? 3 : 4, 0);
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
        return NEXT;
    case 0xf5:              /* cmc, clc, stc */
    case 0xf8:
    case 0xf9:
        FIN();
        E4(G(call_c), aok_x86_helper_flagop, c->off,
           b == 0xf5 ? 2 : b - 0xf8, 0);
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
        return NEXT;

    case 0xfc:              /* cld, std */
        FIN();
        E0(G(cld));
        return NEXT;
    case 0xfd:
        FIN();
        E0(G(std));
        return NEXT;

    case 0xcf:              /* iret, in protected or long mode */
        FIN();
        E4(G(call_c_exit), aok_x86_helper_iret, c->off,
           d->w ? 2 : d->o16 ? 0 : 1, c->len);
        return END;

    case 0xfa:              /* cli and sti, where IOPL allows them */
        FIN();
        if (!c->iopl_ok) {
            return UNKNOWN;
        }
        E0(G(cli));
        return NEXT;
    case 0xfb:
        FIN();
        if (!c->iopl_ok) {
            return UNKNOWN;
        }
        E0(G(sti));
        c->sti = true;
        return NEXT;

    case 0xf6:
    case 0xf7:
        modrm(d);
        if ((d->reg & 7) < 2) {
            imm = fimmz(d, bsz);
            FIN();
            return alu_imm(c, d, ALU_TEST, bsz, imm);
        }
        FIN();
        return group3(c, d, bsz);

    case 0xfe:
    case 0xff:
        modrm(d);
        FIN();
        return group5(c, d, bsz, b == 0xff);

    default:
        return UNKNOWN;
    }
}

/* The same, of the insn at @code, which has bytes up to @end. */
static int insn(Ctx *c, const uint8_t *code, const uint8_t *end)
{
    Insn d = { .p = code, .end = end, .seg = -1, .sreg = -1, .c64 = c->c64 };
    int r = insn1(c, &d, code);

    /* Unknown because it ran into the end of the page? */
    c->cut = r == UNKNOWN && d.bad && !d.a32_bad;
    return r;
}

/*
 * One attempt at the TB. Returns false if an insn that flags_dead() counted
 * on did not get into it: then what was emitted is wrong, and the TB is
 * translated again with every flag computed.
 */
static bool translate(Ctx *c, CPUState *cs, TranslationBlock *tb,
                      int max_insns, vaddr pc, const uint8_t *code, int *r)
{
    uint64_t *sti_start = NULL;
    unsigned sti_off = 0;
    int sti_fix = 0;
    bool live = c->live;

    c->off = 0;
    c->hf = HF_NONE;
    c->cc = -1;
    c->must = 0;
    c->sti = false;
    *r = NEXT;
    aok_gen_begin(&c->g, cs, tb, max_insns, cpu_mmu_index(cs, false));
    c->g.lookup = G(lookup);
    if (tb->flags & HF_RF_MASK) {
        /*
         * The insn a fault is returned to: the resume flag is what tells this
         * TB from the one that will be run there next time, and no more than
         * that here (breakpoints are found before a TB is entered). It is
         * cleared at once, where TCG clears it at the TB's end.
         */
        E0(G(clr_rf));
    }

    /* A TB stays in its page, and so does each of its insns. */
    while (aok_gen_room(&c->g, 24) && c->page_off + c->off < TARGET_PAGE_SIZE) {
        uint64_t *start = c->g.p;
        int n_fix = c->g.n_fix;
        unsigned owed = c->must;
        bool after_sti = c->sti;

        c->must = 0;
        c->sti = false;
        c->cut = false;
        /* (After an sti the TB may be left behind this insn: every flag.) */
        c->live = live && !after_sti;
        c->after_sti = after_sti;
        c->sti_jmp = false;
        *r = insn(c, code + c->off, code + (TARGET_PAGE_SIZE - c->page_off));
        c->live = live;
        if (*r == UNKNOWN && c->cut && c->off == 0) {
            /*
             * The TB's first insn runs into the next page: then it is the
             * whole TB, as it is TCG's (which ends a TB before such an insn,
             * so that a fault of the fetch is this insn's).
             */
            unsigned rem = TARGET_PAGE_SIZE - c->page_off;
            const uint8_t *next = aok_gen_next_page(&c->g, cs, pc + rem);
            uint8_t buf[32];

            if (!next) {
                return true;
            }
            memcpy(buf, code, rem);
            memcpy(buf + rem, next, 16);
            c->g.p = start;
            c->g.n_fix = n_fix;
            c->live = false;
            *r = insn(c, buf, buf + rem + 16);
            c->live = live;
            if (*r == UNKNOWN || c->sti) {
                c->g.p = start;
                c->g.n_fix = n_fix;
                c->sti = false;
                *r = UNKNOWN;
                return true;
            }
            aok_gen_insn_end(&c->g, c->page_off, CC_OP_DYNAMIC);
            c->off = c->len;
            return true;
        }
        if (after_sti && ((*r != NEXT && !c->sti_jmp) || c->sti)) {
            /*
             * sti takes effect after the insn that follows it, and here that
             * is done by keeping the two in one TB, with a look for a waiting
             * interrupt after the second. This insn cannot be that one, so
             * the sti is not ours.
             */
            c->g.p = sti_start;
            c->g.n_fix = sti_fix;
            c->g.n_insns--;
            c->off = sti_off;
            c->sti = false;
            *r = UNKNOWN;
            return !owed;
        }
        if (*r == UNKNOWN) {
            c->g.p = start;
            c->g.n_fix = n_fix;
            return !owed;
        }
        aok_gen_insn_end(&c->g, c->page_off + c->off, CC_OP_DYNAMIC);
        if (c->sti) {
            sti_start = start;
            sti_fix = n_fix;
            sti_off = c->off;
        }
        c->off += c->len;
        if (owed > 1) {
            c->must = MAX(c->must, owed - 1);
        }
        if (after_sti && !c->sti_jmp) {
            /* Interrupts are enabled from here: is one waiting? */
            E2(G(irq_check), c->off, IRQ_REQUEST);
        }
        if (*r == END) {
            return !c->must;
        }
    }
    if (c->sti) {
        /* Nothing after it fits: as above. */
        c->g.p = sti_start;
        c->g.n_fix = sti_fix;
        c->g.n_insns--;
        c->off = sti_off;
        c->sti = false;
        *r = UNKNOWN;
    }
    return !c->must;
}

int x86_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc)
{
    uint32_t flags = tb->flags, cflags = tb_cflags(tb);
    CPUX86State *env = cpu_env(cs);
    Ctx cc = { 0 }, *c = &cc;
    int r;

    /*
     * The state this translator knows: code that is not being stepped, is
     * not in the shadow of a mov to ss, in system management mode or a
     * guest of SVM, and has no bound registers to reset at each branch. And
     * an ordinary TB: one in RAM that may check for interrupts and need not
     * stop after a set number of insns.
     */
    bool one = false;

    if (!host_pc || !(cflags & CF_PCREL) || TARGET_PAGE_BITS != AOK_TLB_PAGE_BITS ||
        (cflags & (CF_SINGLE_STEP | CF_MEMI_ONLY | CF_USE_ICOUNT |
                   CF_STEP_ATOMIC)) ||
        (flags & (HF_INHIBIT_IRQ_MASK | HF_VM_MASK | HF_SMM_MASK |
                  HF_GUEST_MASK | HF_MPX_EN_MASK))) {
        return 0;
    }
    if ((cflags & (CF_COUNT_MASK | CF_NOIRQ | CF_BP_PAGE)) ||
        (flags & HF_TF_MASK)) {
        /*
         * Stepped (EFLAGS.TF), or one insn alone for the main loop's sake
         * (after a write to the TB's own code, say): TCG's, unless TCG has
         * not got the insn (AVX-512). Then it is this translator's, with
         * the main loop's after it, or the step's #DB.
         */
        bool c64 = flags & HF_CS64_MASK;
        bool avx = !(flags & (HF_EM_MASK | HF_TS_MASK)) &&
                   (flags & HF_OSFXSR_MASK) && (flags & HF_AVX_EN_MASK);
        unsigned rem = TARGET_PAGE_SIZE - (pc & ~TARGET_PAGE_MASK);
        int only;

        if ((c64 ? x86_no64 : !x86_aok_flat32(flags) || tb->cs_base || x86_no32) ||
            x86_noone) {
            return 0;
        }
        only = x86_aok_only(host_pc, (const uint8_t *)host_pc + rem, c64, avx,
                            flags & HF_AVX512_EN_MASK);
        if (only < 0 && rem < 16) {
            /* It runs into the next page: ask again with that page's bytes. */
            const uint8_t *next;
            uint8_t buf[32];

            c->g.tb = tb;
            next = aok_gen_next_page(&c->g, cs, pc + rem);
            if (next) {
                memcpy(buf, host_pc, rem);
                memcpy(buf + rem, next, 16);
                only = x86_aok_only(buf, buf + rem + 16, c64, avx,
                                    flags & HF_AVX512_EN_MASK);
            }
        }
        if (only != 1) {
            return 0;
        }
        one = true;
        *max_insns = 1;
    }
    /*
     * And either 64-bit code, or 32-bit code in protected mode with a
     * 32-bit stack and every segment but fs and gs at zero: then an address
     * is an offset, eip is the pc, and what the two differ in is sizes.
     */
    c->c64 = flags & HF_CS64_MASK;
    if (!c->c64 && (!x86_aok_flat32(flags) || tb->cs_base || x86_no32)) {
        return 0;
    }
    if (c->c64 && x86_no64) {
        return 0;
    }

    c->page_off = pc & ~TARGET_PAGE_MASK;
    c->env = env;
    c->mp = cflags & CF_PARALLEL;
    c->mb = c->mp && !x86_nomb;
    c->no_goto_ptr = cflags & CF_NO_GOTO_PTR;
    c->cpl = flags & HF_CPL_MASK;
    c->iopl_ok = c->cpl <= ((flags >> IOPL_SHIFT) & 3);
    /* (An I/O breakpoint is looked for after the access: TCG's.) */
    c->io_ok = c->iopl_ok && !(flags & HF_IOBPT_MASK);
    c->abm = env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_ABM;
    c->bmi1 = env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_BMI1;
    c->lahf = !c->c64 ||
              (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_LAHF_LM);
    c->sse = !(flags & (HF_EM_MASK | HF_TS_MASK)) && (flags & HF_OSFXSR_MASK);
    c->fp = !x86_nofp;
    c->x87 = !(flags & (HF_EM_MASK | HF_TS_MASK)) && !x86_nox87;
    c->sse3 = env->features[FEAT_1_ECX] & CPUID_EXT_SSE3;
    c->bmi2 = env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_BMI2;
    c->adx = env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_ADX;
    /*
     * VEX's vector insns (gadgets-vec.S): with AVX enabled (CR4 and XCR0, a
     * TB flag) and SSE's state usable, on a CPU with AVX2, FMA and F16C,
     * all of which the frames compute. Otherwise every VEX insn is TCG's,
     * which raises what is due.
     */
    c->avx = c->sse && (flags & HF_AVX_EN_MASK) && !x86_novec &&
             (env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_AVX2) &&
             (env->features[FEAT_1_ECX] & CPUID_EXT_FMA) &&
             (env->features[FEAT_1_ECX] & CPUID_EXT_F16C);
    /*
     * EVEX's (AVX-512's), with it enabled too: XCR0's opmask and ZMM state,
     * which the CPU offers only where these gadgets compute it.
     */
    c->avx512 = c->avx && (flags & HF_AVX512_EN_MASK) &&
                (env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_AVX512F);
    c->live = !x86_nolive;
    if (!translate(c, cs, tb, *max_insns, pc, host_pc, &r)) {
        c->live = false;
        translate(c, cs, tb, *max_insns, pc, host_pc, &r);
    }
    if (c->g.n_insns == 0) {
        aok_stats.declined_first++;
        aok_stats.declined_op[(c->op >> 1) & 0x7f]++;
        return 0;
    }
    if (one) {
        E4(G(call_c_exit), flags & HF_TF_MASK ? aok_x86_helper_tf : aok_x86_helper_eob,
           c->off, 0, 0);
    } else if (r != END) {
        E0(c->c64 ? G(jmp) : G(jmp32));
        way(c, 0, c->off);
    }
    return aok_gen_finish(&c->g, c->off);
}
