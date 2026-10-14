/*
 * The VEX instructions (AVX, AVX2, FMA3, F16C, BMI1/2 and the opmask ones),
 * included by translate-x86.c: iSH-AOK's table of them and its planner,
 * which say which of gadgets-vec.S's frames computes each and with what
 * operand word, and this front end's emitter.
 *
 * The table, the planner and x86_shuffle_index are iSH-AOK's jit/gen.c
 * (commit 651f974a2, contributed there by Mike Miller after iSH's 0e3a4144
 * and so GPLv2 as well as GPLv3), taken on 2026-10-14 and this tree's own
 * since; its "gadget_" names are this front end's aok_gadget_x86_. The SSE
 * gadgets of iSH-AOK's math.S the table names for VPEXTR* and VPCMP*STR*
 * are not here: those instructions are QEMU's engine's (aok_vec_none).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define aok_gadget_x86_amd64_s4_pextrb_r aok_vec_none
#define aok_gadget_x86_amd64_s4_pextrw_r aok_vec_none
#define aok_gadget_x86_amd64_s4_pextrd_r aok_vec_none
#define aok_gadget_x86_amd64_s4_pextrq_r aok_vec_none
#define aok_gadget_x86_amd64_pcmpestrm_r aok_vec_none
#define aok_gadget_x86_amd64_pcmpestri_r aok_vec_none
#define aok_gadget_x86_amd64_pcmpistrm_r aok_vec_none
#define aok_gadget_x86_amd64_pcmpistri_r aok_vec_none
void aok_vec_none(void);

// The tbl index for math.S's amd64_v_tbl1/tbl2 shuffle gadgets, as two
// little-endian quadwords. kind: 0 shufps, 1 shufpd (tbl2: {dst, src}), 2
// pshufd, 3 pshuflw, 4 pshufhw (tbl1: the source alone).
static void x86_shuffle_index(int kind, uint8_t imm, unsigned long *lo_out, unsigned long *hi_out) {
    uint8_t idx[16];
    for (unsigned i = 0; i < 16; i++) idx[i] = i;
    switch (kind) {
    case 0: for (unsigned k = 0; k < 4; k++) { unsigned sel = (imm >> (2 * k)) & 3;
                for (unsigned j = 0; j < 4; j++) idx[4 * k + j] = (k < 2 ? 0 : 16) + 4 * sel + j; } break;
    case 1: for (unsigned k = 0; k < 2; k++) { unsigned sel = (imm >> k) & 1;
                for (unsigned j = 0; j < 8; j++) idx[8 * k + j] = (k == 0 ? 0 : 16) + 8 * sel + j; } break;
    case 2: for (unsigned k = 0; k < 4; k++) { unsigned sel = (imm >> (2 * k)) & 3;
                for (unsigned j = 0; j < 4; j++) idx[4 * k + j] = 4 * sel + j; } break;
    case 3: for (unsigned k = 0; k < 4; k++) { unsigned sel = (imm >> (2 * k)) & 3;
                for (unsigned j = 0; j < 2; j++) idx[2 * k + j] = 2 * sel + j; } break;
    default: for (unsigned k = 0; k < 4; k++) { unsigned sel = (imm >> (2 * k)) & 3;
                for (unsigned j = 0; j < 2; j++) idx[8 + 2 * k + j] = 8 + 2 * sel + j; } break;
    }
    unsigned long lo = 0, hi = 0;
    for (unsigned i = 0; i < 8; i++) { lo |= (unsigned long) idx[i] << (8 * i); hi |= (unsigned long) idx[8 + i] << (8 * i); }
    *lo_out = lo;
    *hi_out = hi;
}

// ---- VEX (AVX, AVX2), both x86 guests: math.S's vex.inc gadgets --------
// A decoded VEX instruction, whichever guest it came from: the map (1 0F,
// 2 0F38, 3 0F3A), pp (0 none, 1 66, 2 F3, 3 F2), the opcode, VEX.L and .W,
// vvvv, the ModRM reg and r/m register numbers (0-7 on i386, 0-15 on
// amd64), whether r/m is memory, and imm8.
struct vex_insn {
    unsigned map, pp, op, l, w, vvvv, reg, rm;
    bool mem;
    uint8_t imm;
    int vsib_index;             // the SIB's index field as a vector register, -1 without a SIB
    unsigned vsib_scale;
    bool vvvv_hi;               // 32-bit mode: VEX.vvvv's bit 3 was set (vvvv holds the other three)
};
// kinds: the operand roles of a vex.inc frame (see its header)
enum vex_kind {
    VXK_L3,     // dst = reg, s1 = vvvv, s2 = r/m
    VXK_L2,     // dst = reg, s2 = r/m; vvvv must be 1111b
    VXK_SHX,    // dst = reg, s1 = vvvv, s2 = r/m: the count, an m128 at either L
    VXK_SHI,    // dst = vvvv, s2 = r/m (a register), imm8; the op in ModRM.reg
    VXK_SCAL,   // a scalar op: as VXK_L3, VEX.L ignored, the operand sbytes wide
    VXK_TBL1,   // dst = reg, s2 = r/m, vvvv 1111b: a one-source shuffle by imm8 (aux = its kind)
    VXK_TBL2,   // dst = reg, s1 = vvvv, s2 = r/m: a two-source shuffle by imm8
    VXK_TBL2U,  // dst = reg, s2 = r/m, vvvv 1111b: VPERMILPD's two-source index of one
    VXK_LOAD,   // dst = reg, s2 = r/m, vvvv 1111b, a full-width (or sbytes) load or copy
    VXK_STORE,  // r/m = reg: memory a store (sbytes or the width), a register a copy
    VXK_MOVS,   // VMOVSS/SD load: memory dst = m (vvvv 1111b), register a 3-operand merge
    VXK_MOVSST, // VMOVSS/SD store: memory a store, register rm = {reg low, vvvv rest}
    VXK_LOHI,   // VMOVLPS/HPS..: memory a 3-operand merge of m64 (aux: the gadget for a register)
    VXK_STQ,    // VMOVLPS/HPS.. store: m64 from reg's low (aux 0) or high (aux 8) qword
    VXK_GPRIN,  // VMOVD/Q xmm, r/m: a register staged from the GPR, memory 4 or 8 (W)
    VXK_GPROUT, // VMOVD/Q r/m, xmm: a register write, a memory store of 4 or 8 (W)
    VXK_BCAST,  // dst = reg, s2 = r/m (sbytes of memory): a broadcast
    VXK_INS128, // dst = reg, s1 = vvvv, s2 = r/m (16 bytes): VINSERTF128/I128
    VXK_EXT128, // r/m = reg's 128-bit lane: VEXTRACTF128/I128
    VXK_PERMQ,  // dst = reg, s2 = r/m (32 bytes), vvvv 1111b: VPERMQ/PD imm8
    VXK_ZERO,   // VZEROUPPER / VZEROALL (no ModRM)
    VXK_WIDEN,  // dst = reg, s2 = r/m, vvvv 1111b: each half from sbytes of the source (2x for VEX.256)
    VXK_NARROW, // dst = reg (128 bits), s2 = r/m (the width), vvvv 1111b
    VXK_G2R,    // GPR reg = f(s2 = r/m: a register, or sbytes of memory), vvvv 1111b
    VXK_FLAGS,  // EFLAGS = f(s1 = reg, s2 = r/m: sbytes of memory), vvvv 1111b
    VXK_TEST,   // EFLAGS = f(s1 = reg, s2 = r/m), vvvv 1111b, the full width
    VXK_INTIN,  // dst = reg, s1 = vvvv, s2 = a GPR (r/m, staged) or sbytes of memory
    VXK_INSPS,  // VINSERTPS: as VXK_L3, memory 4 bytes and imm8[7:6] 0
    VXK_PEXTR,  // r/m (a GPR or memory) = reg's lane imm8: sbytes wide (gadget: the SSE one)
    VXK_BLENDV, // dst = reg, s1 = vvvv, s2 = r/m, the mask register imm8[7:4]
    VXK_SPECIAL,// emitted by each guest's emitter (aux: which)
    VXK_MASKMOV,// VMASKMOV*/VPMASKMOV*: memory only; aux 0 load (dst = reg), 1 store (data = reg); sbytes the element
    VXK_BMI,    // BMI1/BMI2 on general registers (aux: vex_bmi's op)
    VXK_PS2PH,  // VCVTPS2PH: r/m (an xmm, or memory 8/16 bytes) = reg converted, imm8
    VXK_GATHER, // VSIB gathers: dst = reg, mask = vvvv; aux: qword indices; VEX.W: qword data
    VXK_KOP,    // the opmask instructions (vex.inc vex_kop): aux = its op | log2 of the width in bytes << 5
    VXK_UD,     // an encoding the hardware rejects (wreq picks W)
};
// VXK_SPECIAL's
#define VEX_SP_LDMXCSR 1
#define VEX_SP_STMXCSR 2
#define VEX_SP_PCMPSTR 3
#define VEX_SP_MASKMOVDQU 4
struct vex_entry {
    uint8_t map, pp, op;
    int8_t group;           // ModRM.reg for the 71-73 groups, else -1
    uint8_t kind;
    uint8_t lmask;          // bit 0: VEX.128 exists, bit 1: VEX.256
    uint8_t sbytes;         // VXK_SCAL: the memory operand's bytes; VEX.128's when not 16 (MOVDDUP's 8)
    void (*gadget)(void);
    uint8_t aux;            // VXK_TBL*: x86_shuffle_index's kind
    uint8_t ihs;            // VXK_TBL*: the high lane's imm8 is imm8 >> ihs
    uint8_t wreq;           // 0: VEX.W either; 1: W0 only; 2: W1 only
    uint8_t align;          // VXK_LOAD/STORE: a memory operand aligned to the width
    void (*gadget2)(void);  // VXK_LOHI: the register form's gadget (VMOVHLPS, VMOVLHPS)
};
#define VEX_L128 1
#define VEX_L256 2
#define VEX_LBOTH 3
// A row's common fields; the rest zero (a row that sets any of them spells
// out all 13: the table must not lean on positional defaults).
#define VE(map, pp, op, group, kind, lmask, sbytes, gadget) \
    {map, pp, op, group, kind, lmask, sbytes, gadget, 0, 0, 0, 0, NULL}
// 66 0F: the integer ops (vex.inc vex_vi_*)
#define VEX_0F_INT(X) X(0x60, punpcklbw) X(0x61, punpcklwd) X(0x62, punpckldq) X(0x63, packsswb) \
    X(0x64, pcmpgtb) X(0x65, pcmpgtw) X(0x66, pcmpgtd) X(0x67, packuswb) X(0x68, punpckhbw) \
    X(0x69, punpckhwd) X(0x6a, punpckhdq) X(0x6b, packssdw) X(0x6c, punpcklqdq) X(0x6d, punpckhqdq) \
    X(0x74, pcmpeqb) X(0x75, pcmpeqw) X(0x76, pcmpeqd) X(0xd4, paddq) X(0xd5, pmullw) \
    X(0xd8, psubusb) X(0xd9, psubusw) X(0xda, pminub) X(0xdb, pand) X(0xdc, paddusb) X(0xdd, paddusw) \
    X(0xde, pmaxub) X(0xdf, pandn) X(0xe0, pavgb) X(0xe3, pavgw) X(0xe4, pmulhuw) X(0xe5, pmulhw) \
    X(0xe8, psubsb) X(0xe9, psubsw) X(0xea, pminsw) X(0xeb, por) X(0xec, paddsb) X(0xed, paddsw) \
    X(0xee, pmaxsw) X(0xef, pxor) X(0xf4, pmuludq) X(0xf5, pmaddwd) X(0xf6, psadbw) X(0xf8, psubb) \
    X(0xf9, psubw) X(0xfa, psubd) X(0xfb, psubq) X(0xfc, paddb) X(0xfd, paddw) X(0xfe, paddd)
// 66 0F38, two-operand and three
#define VEX_38_INT(X) X(0x00, pshufb) X(0x01, phaddw) X(0x02, phaddd) X(0x03, phaddsw) X(0x04, pmaddubsw) \
    X(0x05, phsubw) X(0x06, phsubd) X(0x07, phsubsw) X(0x08, psignb) X(0x09, psignw) X(0x0a, psignd) \
    X(0x0b, pmulhrsw) X(0x28, pmuldq) X(0x29, pcmpeqq) X(0x2b, packusdw) X(0x37, pcmpgtq) X(0x38, pminsb) \
    X(0x39, pminsd) X(0x3a, pminuw) X(0x3b, pminud) X(0x3c, pmaxsb) X(0x3d, pmaxsd) X(0x3e, pmaxuw) \
    X(0x3f, pmaxud) X(0x40, pmulld)
#define VEX_38_UNARY(X) X(0x1c, pabsb) X(0x1d, pabsw) X(0x1e, pabsd)
// 66 0F D1-F3: shifts by an xmm count; 71-73: by imm8 (group, ModRM.reg)
#define VEX_SHX(X) X(0xd1, psrlw) X(0xd2, psrld) X(0xd3, psrlq) X(0xe1, psraw) X(0xe2, psrad) \
    X(0xf1, psllw) X(0xf2, pslld) X(0xf3, psllq)
#define VEX_SHI(X) X(0x71, 2, psrlw) X(0x71, 4, psraw) X(0x71, 6, psllw) X(0x72, 2, psrld) \
    X(0x72, 4, psrad) X(0x72, 6, pslld) X(0x73, 2, psrlq) X(0x73, 3, psrldq) X(0x73, 6, psllq) \
    X(0x73, 7, pslldq)
// 0F: the float ops, by pp (none ps, 66 pd, F3 ss, F2 sd)
#define VEX_FARITH(X) X(0x58, add) X(0x59, mul) X(0x5c, sub) X(0x5d, min) X(0x5e, div) X(0x5f, max)
#define VEX_DECL_XF(op, n) void aok_gadget_x86_vex_xf_##n##ps(void), aok_gadget_x86_vex_xf_##n##pd(void), \
    aok_gadget_x86_vex_xf_##n##ss(void), aok_gadget_x86_vex_xf_##n##sd(void);
VEX_FARITH(VEX_DECL_XF) VEX_DECL_XF(0x51, sqrt) VEX_DECL_XF(0xc2, cmp)
void aok_gadget_x86_vex_xf_addsubps(void), aok_gadget_x86_vex_xf_addsubpd(void), aok_gadget_x86_vex_xf_haddps(void),
       aok_gadget_x86_vex_xf_haddpd(void), aok_gadget_x86_vex_xf_hsubps(void), aok_gadget_x86_vex_xf_hsubpd(void);
#define VEX_ROW_XF(op, n) VE(1, 0, op, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_##n##ps), \
    VE(1, 1, op, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_##n##pd), \
    VE(1, 2, op, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_##n##ss), \
    VE(1, 3, op, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_##n##sd),
#define VEX_DECL_VI(op, n) void aok_gadget_x86_vex_vi_##n(void);
#define VEX_DECL_SHX(op, n) void aok_gadget_x86_vex_vsh_##n##_x(void);
#define VEX_DECL_SHI(op, r, n) void aok_gadget_x86_vex_vsh_##n##_i(void);
VEX_0F_INT(VEX_DECL_VI) VEX_38_INT(VEX_DECL_VI) VEX_38_UNARY(VEX_DECL_VI) VEX_SHX(VEX_DECL_SHX) VEX_SHI(VEX_DECL_SHI)
#define VEX_MOVX(X) X(0x20, pmovsxbw, 8) X(0x21, pmovsxbd, 4) X(0x22, pmovsxbq, 2) X(0x23, pmovsxwd, 8) \
    X(0x24, pmovsxwq, 4) X(0x25, pmovsxdq, 8) X(0x30, pmovzxbw, 8) X(0x31, pmovzxbd, 4) X(0x32, pmovzxbq, 2) \
    X(0x33, pmovzxwd, 8) X(0x34, pmovzxwq, 4) X(0x35, pmovzxdq, 8)
#define VEX_DECL_MOVX(op, n, b) void aok_gadget_x86_vex_vi_##n(void);
VEX_MOVX(VEX_DECL_MOVX)
#define VEX_ROW_MOVX(op, n, b) VE(2, 1, op, -1, VXK_WIDEN, VEX_LBOTH, b, aok_gadget_x86_vex_vi_##n),
void aok_gadget_x86_vex_fma_maddsub132ps(void), aok_gadget_x86_vex_fma_maddsub132pd(void), aok_gadget_x86_vex_fma_msubadd132ps(void), aok_gadget_x86_vex_fma_msubadd132pd(void), aok_gadget_x86_vex_fma_madd132ps(void), aok_gadget_x86_vex_fma_madd132pd(void), aok_gadget_x86_vex_fma_madd132ss(void), aok_gadget_x86_vex_fma_madd132sd(void), aok_gadget_x86_vex_fma_msub132ps(void), aok_gadget_x86_vex_fma_msub132pd(void), aok_gadget_x86_vex_fma_msub132ss(void), aok_gadget_x86_vex_fma_msub132sd(void), aok_gadget_x86_vex_fma_nmadd132ps(void), aok_gadget_x86_vex_fma_nmadd132pd(void), aok_gadget_x86_vex_fma_nmadd132ss(void), aok_gadget_x86_vex_fma_nmadd132sd(void), aok_gadget_x86_vex_fma_nmsub132ps(void), aok_gadget_x86_vex_fma_nmsub132pd(void), aok_gadget_x86_vex_fma_nmsub132ss(void), aok_gadget_x86_vex_fma_nmsub132sd(void), aok_gadget_x86_vex_fma_maddsub213ps(void), aok_gadget_x86_vex_fma_maddsub213pd(void), aok_gadget_x86_vex_fma_msubadd213ps(void), aok_gadget_x86_vex_fma_msubadd213pd(void), aok_gadget_x86_vex_fma_madd213ps(void), aok_gadget_x86_vex_fma_madd213pd(void), aok_gadget_x86_vex_fma_madd213ss(void), aok_gadget_x86_vex_fma_madd213sd(void), aok_gadget_x86_vex_fma_msub213ps(void), aok_gadget_x86_vex_fma_msub213pd(void), aok_gadget_x86_vex_fma_msub213ss(void), aok_gadget_x86_vex_fma_msub213sd(void), aok_gadget_x86_vex_fma_nmadd213ps(void), aok_gadget_x86_vex_fma_nmadd213pd(void), aok_gadget_x86_vex_fma_nmadd213ss(void), aok_gadget_x86_vex_fma_nmadd213sd(void), aok_gadget_x86_vex_fma_nmsub213ps(void), aok_gadget_x86_vex_fma_nmsub213pd(void), aok_gadget_x86_vex_fma_nmsub213ss(void), aok_gadget_x86_vex_fma_nmsub213sd(void), aok_gadget_x86_vex_fma_maddsub231ps(void), aok_gadget_x86_vex_fma_maddsub231pd(void), aok_gadget_x86_vex_fma_msubadd231ps(void), aok_gadget_x86_vex_fma_msubadd231pd(void), aok_gadget_x86_vex_fma_madd231ps(void), aok_gadget_x86_vex_fma_madd231pd(void), aok_gadget_x86_vex_fma_madd231ss(void), aok_gadget_x86_vex_fma_madd231sd(void), aok_gadget_x86_vex_fma_msub231ps(void), aok_gadget_x86_vex_fma_msub231pd(void), aok_gadget_x86_vex_fma_msub231ss(void), aok_gadget_x86_vex_fma_msub231sd(void), aok_gadget_x86_vex_fma_nmadd231ps(void), aok_gadget_x86_vex_fma_nmadd231pd(void), aok_gadget_x86_vex_fma_nmadd231ss(void), aok_gadget_x86_vex_fma_nmadd231sd(void), aok_gadget_x86_vex_fma_nmsub231ps(void), aok_gadget_x86_vex_fma_nmsub231pd(void), aok_gadget_x86_vex_fma_nmsub231ss(void), aok_gadget_x86_vex_fma_nmsub231sd(void);
void aok_gadget_x86_vex_xf_cvttss2si32(void), aok_gadget_x86_vex_xf_cvttss2si64(void), aok_gadget_x86_vex_xf_cvttsd2si32(void),
       aok_gadget_x86_vex_xf_cvttsd2si64(void), aok_gadget_x86_vex_xf_cvtss2si32(void), aok_gadget_x86_vex_xf_cvtss2si64(void),
       aok_gadget_x86_vex_xf_cvtsd2si32(void), aok_gadget_x86_vex_xf_cvtsd2si64(void), aok_gadget_x86_vex_movmskps(void),
       aok_gadget_x86_vex_movmskpd(void), aok_gadget_x86_vex_pmovmskb(void), aok_gadget_x86_vex_xf_ucomiss(void), aok_gadget_x86_vex_xf_ucomisd(void),
       aok_gadget_x86_vex_xf_comiss(void), aok_gadget_x86_vex_xf_comisd(void), aok_gadget_x86_vex_ptest(void), aok_gadget_x86_vex_testps(void),
       aok_gadget_x86_vex_testpd(void), aok_gadget_x86_vex_xf_cvtsi2ss32(void), aok_gadget_x86_vex_xf_cvtsi2ss64(void),
       aok_gadget_x86_vex_xf_cvtsi2sd32(void), aok_gadget_x86_vex_xf_cvtsi2sd64(void), aok_gadget_x86_vex_pinsrb(void), aok_gadget_x86_vex_pinsrw(void),
       aok_gadget_x86_vex_pinsrd(void), aok_gadget_x86_vex_pinsrq(void), aok_gadget_x86_vex_insertps(void),
       aok_gadget_x86_amd64_s4_pextrb_r(void), aok_gadget_x86_amd64_s4_pextrw_r(void), aok_gadget_x86_amd64_s4_pextrd_r(void),
       aok_gadget_x86_amd64_s4_pextrq_r(void), aok_gadget_x86_vex_blendvps(void), aok_gadget_x86_vex_blendvpd(void),
       aok_gadget_x86_vex_pblendvb(void), aok_gadget_x86_amd64_pcmpestrm_r(void), aok_gadget_x86_amd64_pcmpestri_r(void),
       aok_gadget_x86_amd64_pcmpistrm_r(void), aok_gadget_x86_amd64_pcmpistri_r(void);
void aok_gadget_x86_vex_xf_cvtps2pd(void), aok_gadget_x86_vex_xf_cvtdq2pd(void), aok_gadget_x86_vex_xf_cvtpd2ps(void),
       aok_gadget_x86_vex_xf_cvtpd2dq(void), aok_gadget_x86_vex_xf_cvttpd2dq(void), aok_gadget_x86_vex_xf_cvtss2sd(void),
       aok_gadget_x86_vex_xf_cvtsd2ss(void), aok_gadget_x86_vex_xf_cvtph2ps(void), aok_gadget_x86_vex_cvtps2ph(void), aok_gadget_x86_vex_kop(void);
void aok_gadget_x86_vex_vi_phminposuw(void), aok_gadget_x86_vex_tbl1(void), aok_gadget_x86_vex_tbl2(void),
       aok_gadget_x86_vex_v3a_palignr(void), aok_gadget_x86_vex_v3a_pblendw(void), aok_gadget_x86_vex_v3a_blendps(void),
       aok_gadget_x86_vex_v3a_blendpd(void), aok_gadget_x86_vex_v3a_mpsadbw(void), aok_gadget_x86_vex_xf_dpps(void),
       aok_gadget_x86_vex_xf_dppd(void), aok_gadget_x86_vex_xf_roundps(void), aok_gadget_x86_vex_xf_roundpd(void),
       aok_gadget_x86_vex_xf_roundss(void), aok_gadget_x86_vex_xf_roundsd(void), aok_gadget_x86_vex_xf_cvtdq2ps(void),
       aok_gadget_x86_vex_xf_cvtps2dq(void), aok_gadget_x86_vex_xf_cvttps2dq(void), aok_gadget_x86_vex_xf_rcpps(void),
       aok_gadget_x86_vex_xf_rcpss(void), aok_gadget_x86_vex_xf_rsqrtps(void), aok_gadget_x86_vex_xf_rsqrtss(void),
       aok_gadget_x86_vex_xf_movsldup(void), aok_gadget_x86_vex_xf_movshdup(void), aok_gadget_x86_vex_xf_movddup(void),
       aok_gadget_x86_vex_mv_all(void), aok_gadget_x86_vex_mv_ss(void), aok_gadget_x86_vex_mv_sd(void), aok_gadget_x86_vex_mv_hl(void),
       aok_gadget_x86_vex_mv_lh(void), aok_gadget_x86_vex_mv_q(void), aok_gadget_x86_vex_bc_b(void), aok_gadget_x86_vex_bc_w(void),
       aok_gadget_x86_vex_bc_d(void), aok_gadget_x86_vex_bc_q(void), aok_gadget_x86_vex_bc_x(void), aok_gadget_x86_vex_zeroupper(void),
       aok_gadget_x86_vex_zeroall(void), aok_gadget_x86_vex_ins128(void), aok_gadget_x86_vex_ext128(void), aok_gadget_x86_vex_perm2x128(void),
       aok_gadget_x86_vex_permq(void), aok_gadget_x86_vex_permd(void), aok_gadget_x86_vex_permilps_v(void), aok_gadget_x86_vex_permilpd_v(void),
       aok_gadget_x86_vex_shv_srld(void), aok_gadget_x86_vex_shv_srlq(void), aok_gadget_x86_vex_shv_srad(void), aok_gadget_x86_vex_shv_slld(void),
       aok_gadget_x86_vex_shv_sllq(void);
#define VEX_ROW_0F(op, n) VE(1, 1, op, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_##n),
#define VEX_ROW_38(op, n) VE(2, 1, op, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_##n),
#define VEX_ROW_38U(op, n) VE(2, 1, op, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_##n),
#define VEX_ROW_SHX(op, n) VE(1, 1, op, -1, VXK_SHX, VEX_LBOTH, 0, aok_gadget_x86_vex_vsh_##n##_x),
#define VEX_ROW_SHI(op, r, n) VE(1, 1, op, r, VXK_SHI, VEX_LBOTH, 1, aok_gadget_x86_vex_vsh_##n##_i),
static const struct vex_entry vex_table[] = {
    VEX_0F_INT(VEX_ROW_0F) VEX_38_INT(VEX_ROW_38) VEX_38_UNARY(VEX_ROW_38U)
    VE(2, 1, 0x41, -1, VXK_L2, VEX_L128, 0, aok_gadget_x86_vex_vi_phminposuw),
    VEX_SHX(VEX_ROW_SHX) VEX_SHI(VEX_ROW_SHI)
    VEX_FARITH(VEX_ROW_XF) VEX_ROW_XF(0xc2, cmp)
    VE(1, 0, 0x51, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_sqrtps),
    VE(1, 1, 0x51, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_sqrtpd),
    VE(1, 2, 0x51, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_sqrtss),
    VE(1, 3, 0x51, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_sqrtsd),
    VE(1, 1, 0xd0, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_addsubpd),
    VE(1, 3, 0xd0, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_addsubps),
    VE(1, 1, 0x7c, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_haddpd),
    VE(1, 3, 0x7c, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_haddps),
    VE(1, 1, 0x7d, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_hsubpd),
    VE(1, 3, 0x7d, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_hsubps),
    // the bitwise ps/pd ops and the ps/pd unpacks: the integer bodies
    VE(1, 0, 0x54, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_pand), VE(1, 1, 0x54, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_pand),
    VE(1, 0, 0x55, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_pandn), VE(1, 1, 0x55, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_pandn),
    VE(1, 0, 0x56, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_por), VE(1, 1, 0x56, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_por),
    VE(1, 0, 0x57, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_pxor), VE(1, 1, 0x57, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_pxor),
    VE(1, 0, 0x14, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_punpckldq), VE(1, 1, 0x14, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_punpcklqdq),
    VE(1, 0, 0x15, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_punpckhdq), VE(1, 1, 0x15, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_vi_punpckhqdq),
    // shuffles by imm8
    {1, 1, 0x70, -1, VXK_TBL1, VEX_LBOTH, 0, aok_gadget_x86_vex_tbl1, 2, 0, 0, 0, NULL},       // VPSHUFD
    {1, 2, 0x70, -1, VXK_TBL1, VEX_LBOTH, 0, aok_gadget_x86_vex_tbl1, 4, 0, 0, 0, NULL},       // VPSHUFHW
    {1, 3, 0x70, -1, VXK_TBL1, VEX_LBOTH, 0, aok_gadget_x86_vex_tbl1, 3, 0, 0, 0, NULL},       // VPSHUFLW
    {1, 0, 0xc6, -1, VXK_TBL2, VEX_LBOTH, 0, aok_gadget_x86_vex_tbl2, 0, 0, 0, 0, NULL},       // VSHUFPS
    {1, 1, 0xc6, -1, VXK_TBL2, VEX_LBOTH, 0, aok_gadget_x86_vex_tbl2, 1, 2, 0, 0, NULL},       // VSHUFPD
    {3, 1, 0x04, -1, VXK_TBL1, VEX_LBOTH, 0, aok_gadget_x86_vex_tbl1, 2, 0, 1, 0, NULL},       // VPERMILPS imm (W0)
    {3, 1, 0x05, -1, VXK_TBL2U, VEX_LBOTH, 0, aok_gadget_x86_vex_tbl1, 1, 2, 1, 0, NULL},      // VPERMILPD imm (W0)
    // 0F3A: blends, align, MPSADBW, DPPS/DPPD, ROUND
    VE(3, 1, 0x0f, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_v3a_palignr),
    VE(3, 1, 0x0e, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_v3a_pblendw),
    VE(3, 1, 0x0c, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_v3a_blendps),
    VE(3, 1, 0x0d, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_v3a_blendpd),
    {3, 1, 0x02, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_v3a_blendps, 0, 0, 1, 0, NULL},   // VPBLENDD: dwords; W0
    VE(3, 1, 0x42, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_v3a_mpsadbw),
    VE(3, 1, 0x40, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_dpps),
    VE(3, 1, 0x41, -1, VXK_L3, VEX_L128, 0, aok_gadget_x86_vex_xf_dppd),
    VE(3, 1, 0x08, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_roundps),
    VE(3, 1, 0x09, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_roundpd),
    VE(3, 1, 0x0a, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_roundss),
    VE(3, 1, 0x0b, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_roundsd),
    // the lane-local conversions, reciprocals, dups
    VE(1, 0, 0x5b, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_cvtdq2ps),
    VE(1, 1, 0x5b, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_cvtps2dq),
    VE(1, 2, 0x5b, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_cvttps2dq),
    VE(1, 0, 0x52, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_rsqrtps),
    VE(1, 2, 0x52, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_rsqrtss),
    VE(1, 0, 0x53, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_rcpps),
    VE(1, 2, 0x53, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_rcpss),
    VE(1, 2, 0x12, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_movsldup),
    VE(1, 2, 0x16, -1, VXK_L2, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_movshdup),
    VE(1, 3, 0x12, -1, VXK_L2, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_movddup),           // VEX.128 reads an m64
    // data movement: {map, pp, op, group, kind, lmask, sbytes, gadget, aux, ihs, wreq, align, gadget2}
    VE(1, 0, 0x10, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all),                // VMOVUPS
    VE(1, 1, 0x10, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all),                // VMOVUPD
    {1, 2, 0x10, -1, VXK_MOVS, VEX_LBOTH, 4, aok_gadget_x86_vex_mv_all, 0, 0, 0, 0, aok_gadget_x86_vex_mv_ss},  // VMOVSS
    {1, 3, 0x10, -1, VXK_MOVS, VEX_LBOTH, 8, aok_gadget_x86_vex_mv_all, 0, 0, 0, 0, aok_gadget_x86_vex_mv_sd},  // VMOVSD
    VE(1, 0, 0x11, -1, VXK_STORE, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all),
    VE(1, 1, 0x11, -1, VXK_STORE, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all),
    {1, 2, 0x11, -1, VXK_MOVSST, VEX_LBOTH, 4, NULL, 0, 0, 0, 0, aok_gadget_x86_vex_mv_ss},
    {1, 3, 0x11, -1, VXK_MOVSST, VEX_LBOTH, 8, NULL, 0, 0, 0, 0, aok_gadget_x86_vex_mv_sd},
    {1, 0, 0x28, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 0, 0, 0, 1, NULL},   // VMOVAPS
    {1, 1, 0x28, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 0, 0, 0, 1, NULL},   // VMOVAPD
    {1, 0, 0x29, -1, VXK_STORE, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 0, 0, 0, 1, NULL},
    {1, 1, 0x29, -1, VXK_STORE, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 0, 0, 0, 1, NULL},
    {1, 1, 0x6f, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 0, 0, 0, 1, NULL},   // VMOVDQA
    VE(1, 2, 0x6f, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all),                // VMOVDQU
    {1, 1, 0x7f, -1, VXK_STORE, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 0, 0, 0, 1, NULL},
    VE(1, 2, 0x7f, -1, VXK_STORE, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all),
    {1, 3, 0xf0, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 1, 0, 0, 0, NULL},             // VLDDQU (aux 1: memory only)
    {2, 1, 0x2a, -1, VXK_LOAD, VEX_LBOTH, 0, aok_gadget_x86_vex_mv_all, 1, 0, 0, 1, NULL},   // VMOVNTDQA
    {1, 0, 0x2b, -1, VXK_STORE, VEX_LBOTH, 0, NULL, 0, 0, 0, 1, NULL},                // VMOVNTPS
    {1, 1, 0x2b, -1, VXK_STORE, VEX_LBOTH, 0, NULL, 0, 0, 0, 1, NULL},                // VMOVNTPD
    {1, 1, 0xe7, -1, VXK_STORE, VEX_LBOTH, 0, NULL, 0, 0, 0, 1, NULL},                // VMOVNTDQ
    {1, 0, 0x12, -1, VXK_LOHI, VEX_L128, 0, aok_gadget_x86_vex_mv_sd, 0, 0, 0, 0, aok_gadget_x86_vex_mv_hl},  // VMOVLPS / VMOVHLPS
    VE(1, 1, 0x12, -1, VXK_LOHI, VEX_L128, 0, aok_gadget_x86_vex_mv_sd),                // VMOVLPD
    {1, 0, 0x16, -1, VXK_LOHI, VEX_L128, 0, aok_gadget_x86_vex_mv_lh, 0, 0, 0, 0, aok_gadget_x86_vex_mv_lh},  // VMOVHPS / VMOVLHPS
    VE(1, 1, 0x16, -1, VXK_LOHI, VEX_L128, 0, aok_gadget_x86_vex_mv_lh),                // VMOVHPD
    {1, 0, 0x13, -1, VXK_STQ, VEX_L128, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 1, 0x13, -1, VXK_STQ, VEX_L128, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 0, 0x17, -1, VXK_STQ, VEX_L128, 0, NULL, 8, 0, 0, 0, NULL},
    {1, 1, 0x17, -1, VXK_STQ, VEX_L128, 0, NULL, 8, 0, 0, 0, NULL},
    VE(1, 1, 0x6e, -1, VXK_GPRIN, VEX_L128, 0, aok_gadget_x86_vex_mv_all),                // VMOVD/VMOVQ xmm, r/m
    VE(1, 1, 0x7e, -1, VXK_GPROUT, VEX_L128, 0, NULL),                            // VMOVD/VMOVQ r/m, xmm
    VE(1, 2, 0x7e, -1, VXK_LOAD, VEX_L128, 8, aok_gadget_x86_vex_mv_q),                   // VMOVQ xmm, xmm/m64
    VE(1, 1, 0xd6, -1, VXK_STORE, VEX_L128, 8, aok_gadget_x86_vex_mv_q),                  // VMOVQ xmm/m64, xmm
    {1, 0, 0x77, -1, VXK_ZERO, VEX_LBOTH, 0, aok_gadget_x86_vex_zeroupper, 0, 0, 0, 0, aok_gadget_x86_vex_zeroall},
    // broadcasts (aux 1: memory only)
    {2, 1, 0x18, -1, VXK_BCAST, VEX_LBOTH, 4, aok_gadget_x86_vex_bc_d, 0, 0, 1, 0, NULL},        // VBROADCASTSS
    {2, 1, 0x19, -1, VXK_BCAST, VEX_L256, 8, aok_gadget_x86_vex_bc_q, 0, 0, 1, 0, NULL},         // VBROADCASTSD
    {2, 1, 0x1a, -1, VXK_BCAST, VEX_L256, 16, aok_gadget_x86_vex_bc_x, 1, 0, 1, 0, NULL},        // VBROADCASTF128
    {2, 1, 0x5a, -1, VXK_BCAST, VEX_L256, 16, aok_gadget_x86_vex_bc_x, 1, 0, 1, 0, NULL},        // VBROADCASTI128
    {2, 1, 0x78, -1, VXK_BCAST, VEX_LBOTH, 1, aok_gadget_x86_vex_bc_b, 0, 0, 1, 0, NULL},        // VPBROADCASTB
    {2, 1, 0x79, -1, VXK_BCAST, VEX_LBOTH, 2, aok_gadget_x86_vex_bc_w, 0, 0, 1, 0, NULL},        // VPBROADCASTW
    {2, 1, 0x58, -1, VXK_BCAST, VEX_LBOTH, 4, aok_gadget_x86_vex_bc_d, 0, 0, 1, 0, NULL},        // VPBROADCASTD
    {2, 1, 0x59, -1, VXK_BCAST, VEX_LBOTH, 8, aok_gadget_x86_vex_bc_q, 0, 0, 1, 0, NULL},        // VPBROADCASTQ
    // 128-bit lanes, permutes, variable shifts
    {3, 1, 0x18, -1, VXK_INS128, VEX_L256, 0, aok_gadget_x86_vex_ins128, 0, 0, 1, 0, NULL},      // VINSERTF128
    {3, 1, 0x38, -1, VXK_INS128, VEX_L256, 0, aok_gadget_x86_vex_ins128, 0, 0, 1, 0, NULL},      // VINSERTI128
    {3, 1, 0x19, -1, VXK_EXT128, VEX_L256, 0, aok_gadget_x86_vex_ext128, 0, 0, 1, 0, NULL},      // VEXTRACTF128
    {3, 1, 0x39, -1, VXK_EXT128, VEX_L256, 0, aok_gadget_x86_vex_ext128, 0, 0, 1, 0, NULL},      // VEXTRACTI128
    {3, 1, 0x06, -1, VXK_L3, VEX_L256, 0, aok_gadget_x86_vex_perm2x128, 0, 0, 1, 0, NULL},       // VPERM2F128
    {3, 1, 0x46, -1, VXK_L3, VEX_L256, 0, aok_gadget_x86_vex_perm2x128, 0, 0, 1, 0, NULL},       // VPERM2I128
    {3, 1, 0x00, -1, VXK_PERMQ, VEX_L256, 0, aok_gadget_x86_vex_permq, 0, 0, 2, 0, NULL},        // VPERMQ
    {3, 1, 0x01, -1, VXK_PERMQ, VEX_L256, 0, aok_gadget_x86_vex_permq, 0, 0, 2, 0, NULL},        // VPERMPD
    {2, 1, 0x36, -1, VXK_L3, VEX_L256, 0, aok_gadget_x86_vex_permd, 0, 0, 1, 0, NULL},           // VPERMD
    {2, 1, 0x16, -1, VXK_L3, VEX_L256, 0, aok_gadget_x86_vex_permd, 0, 0, 1, 0, NULL},           // VPERMPS
    {2, 1, 0x0c, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_permilps_v, 0, 0, 1, 0, NULL},     // VPERMILPS
    {2, 1, 0x0d, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_permilpd_v, 0, 0, 1, 0, NULL},     // VPERMILPD
    {2, 1, 0x45, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_shv_srld, 0, 0, 1, 0, NULL},       // VPSRLVD
    {2, 1, 0x45, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_shv_srlq, 0, 0, 2, 0, NULL},       // VPSRLVQ
    {2, 1, 0x46, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_shv_srad, 0, 0, 1, 0, NULL},       // VPSRAVD
    {2, 1, 0x47, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_shv_slld, 0, 0, 1, 0, NULL},       // VPSLLVD
    {2, 1, 0x47, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_shv_sllq, 0, 0, 2, 0, NULL},       // VPSLLVQ
    // the width-changing conversions and VPMOVSX/ZX
    VE(1, 0, 0x5a, -1, VXK_WIDEN, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtps2pd),
    VE(1, 1, 0x5a, -1, VXK_NARROW, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_cvtpd2ps),
    {2, 1, 0x13, -1, VXK_WIDEN, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtph2ps, 0, 0, 1, 0, NULL},  // VCVTPH2PS
    {3, 1, 0x1d, -1, VXK_PS2PH, VEX_LBOTH, 0, aok_gadget_x86_vex_cvtps2ph, 0, 0, 1, 0, NULL},    // VCVTPS2PH
    // the opmask instructions: KAND KANDN KOR KXNOR KXOR KADD KNOT KUNPCK, KMOV,
    // KORTEST KTEST, KSHIFTL/R
    {1, 0, 0x41, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 0 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x41, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 0 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x41, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 0 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x41, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 0 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x42, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 1 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x42, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 1 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x42, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 1 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x42, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 1 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x45, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 2 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x45, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 2 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x45, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 2 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x45, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 2 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x46, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 3 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x46, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 3 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x46, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 3 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x46, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 3 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x47, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 4 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x47, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 4 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x47, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 4 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x47, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 4 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x4a, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 5 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x4a, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 5 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x4a, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 5 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x4a, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 5 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x44, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 6 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x44, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 6 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x44, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 6 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x44, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 6 | 2 << 5, 0, 2, 0, NULL},
    {1, 1, 0x4b, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 7 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x4b, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 7 | 1 << 5, 0, 1, 0, NULL},
    {1, 0, 0x4b, -1, VXK_KOP, VEX_L256, 0, aok_gadget_x86_vex_kop, 7 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x90, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 8 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x90, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 8 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x90, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 8 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x90, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 8 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x91, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 10 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x91, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 10 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x91, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 10 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x91, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 10 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x98, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 13 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x98, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 13 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x98, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 13 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x98, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 13 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x99, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 14 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x99, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 14 | 0 << 5, 0, 1, 0, NULL},
    {1, 0, 0x99, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 14 | 3 << 5, 0, 2, 0, NULL},
    {1, 1, 0x99, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 14 | 2 << 5, 0, 2, 0, NULL},
    {1, 0, 0x92, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 11 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x92, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 11 | 0 << 5, 0, 1, 0, NULL},
    {1, 3, 0x92, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 11 | 2 << 5, 0, 1, 0, NULL},
    {1, 3, 0x92, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 11 | 3 << 5, 0, 2, 0, NULL},
    {1, 0, 0x93, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 12 | 1 << 5, 0, 1, 0, NULL},
    {1, 1, 0x93, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 12 | 0 << 5, 0, 1, 0, NULL},
    {1, 3, 0x93, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 12 | 2 << 5, 0, 1, 0, NULL},
    {1, 3, 0x93, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 12 | 3 << 5, 0, 2, 0, NULL},
    {3, 1, 0x30, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 16 | 0 << 5, 0, 1, 0, NULL},
    {3, 1, 0x30, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 16 | 1 << 5, 0, 2, 0, NULL},
    {3, 1, 0x31, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 16 | 2 << 5, 0, 1, 0, NULL},
    {3, 1, 0x31, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 16 | 3 << 5, 0, 2, 0, NULL},
    {3, 1, 0x32, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 15 | 0 << 5, 0, 1, 0, NULL},
    {3, 1, 0x32, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 15 | 1 << 5, 0, 2, 0, NULL},
    {3, 1, 0x33, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 15 | 2 << 5, 0, 1, 0, NULL},
    {3, 1, 0x33, -1, VXK_KOP, VEX_L128, 0, aok_gadget_x86_vex_kop, 15 | 3 << 5, 0, 2, 0, NULL},
    // ... and the encodings around them that are #UD (SDE)
    {1, 2, 0x41, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x41, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x42, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x42, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x44, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x44, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x45, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x45, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x46, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x46, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x47, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x47, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x4a, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x4a, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x4b, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x4b, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x90, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x90, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x91, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x91, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x98, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x98, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x99, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 3, 0x99, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x92, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 2, 0x93, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {1, 1, 0x4b, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 2, 0, NULL},
    {1, 0, 0x92, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 2, 0, NULL},
    {1, 1, 0x92, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 2, 0, NULL},
    {1, 0, 0x93, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 2, 0, NULL},
    {1, 1, 0x93, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 2, 0, NULL},
    {3, 0, 0x30, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 2, 0x30, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 3, 0x30, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 0, 0x31, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 2, 0x31, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 3, 0x31, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 0, 0x32, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 2, 0x32, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 3, 0x32, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 0, 0x33, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 2, 0x33, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {3, 3, 0x33, -1, VXK_UD, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},
    {2, 1, 0x90, -1, VXK_GATHER, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},  // VPGATHERDD/DQ
    {2, 1, 0x91, -1, VXK_GATHER, VEX_LBOTH, 0, NULL, 1, 0, 0, 0, NULL},  // VPGATHERQD/QQ
    {2, 1, 0x92, -1, VXK_GATHER, VEX_LBOTH, 0, NULL, 0, 0, 0, 0, NULL},  // VGATHERDPS/DPD
    {2, 1, 0x93, -1, VXK_GATHER, VEX_LBOTH, 0, NULL, 1, 0, 0, 0, NULL},  // VGATHERQPS/QPD
    VE(1, 2, 0x5a, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_cvtss2sd),
    VE(1, 3, 0x5a, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtsd2ss),
    VE(1, 2, 0xe6, -1, VXK_WIDEN, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtdq2pd),
    VE(1, 1, 0xe6, -1, VXK_NARROW, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_cvttpd2dq),
    VE(1, 3, 0xe6, -1, VXK_NARROW, VEX_LBOTH, 0, aok_gadget_x86_vex_xf_cvtpd2dq),
    VEX_MOVX(VEX_ROW_MOVX)
    // to and from general registers, and the flags
    {1, 2, 0x2c, -1, VXK_G2R, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_cvttss2si32, 0, 0, 1, 0, NULL},
    {1, 2, 0x2c, -1, VXK_G2R, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_cvttss2si64, 0, 0, 2, 0, NULL},
    {1, 3, 0x2c, -1, VXK_G2R, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvttsd2si32, 0, 0, 1, 0, NULL},
    {1, 3, 0x2c, -1, VXK_G2R, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvttsd2si64, 0, 0, 2, 0, NULL},
    {1, 2, 0x2d, -1, VXK_G2R, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_cvtss2si32, 0, 0, 1, 0, NULL},
    {1, 2, 0x2d, -1, VXK_G2R, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_cvtss2si64, 0, 0, 2, 0, NULL},
    {1, 3, 0x2d, -1, VXK_G2R, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtsd2si32, 0, 0, 1, 0, NULL},
    {1, 3, 0x2d, -1, VXK_G2R, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtsd2si64, 0, 0, 2, 0, NULL},
    VE(1, 0, 0x50, -1, VXK_G2R, VEX_LBOTH, 0, aok_gadget_x86_vex_movmskps),
    VE(1, 1, 0x50, -1, VXK_G2R, VEX_LBOTH, 0, aok_gadget_x86_vex_movmskpd),
    VE(1, 1, 0xd7, -1, VXK_G2R, VEX_LBOTH, 0, aok_gadget_x86_vex_pmovmskb),
    VE(1, 0, 0x2e, -1, VXK_FLAGS, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_ucomiss),
    VE(1, 1, 0x2e, -1, VXK_FLAGS, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_ucomisd),
    VE(1, 0, 0x2f, -1, VXK_FLAGS, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_comiss),
    VE(1, 1, 0x2f, -1, VXK_FLAGS, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_comisd),
    VE(2, 1, 0x17, -1, VXK_TEST, VEX_LBOTH, 0, aok_gadget_x86_vex_ptest),
    {2, 1, 0x0e, -1, VXK_TEST, VEX_LBOTH, 0, aok_gadget_x86_vex_testps, 0, 0, 1, 0, NULL},
    {2, 1, 0x0f, -1, VXK_TEST, VEX_LBOTH, 0, aok_gadget_x86_vex_testpd, 0, 0, 1, 0, NULL},
    {1, 2, 0x2a, -1, VXK_INTIN, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_cvtsi2ss32, 0, 0, 1, 0, NULL},
    {1, 2, 0x2a, -1, VXK_INTIN, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtsi2ss64, 0, 0, 2, 0, NULL},
    {1, 3, 0x2a, -1, VXK_INTIN, VEX_LBOTH, 4, aok_gadget_x86_vex_xf_cvtsi2sd32, 0, 0, 1, 0, NULL},
    {1, 3, 0x2a, -1, VXK_INTIN, VEX_LBOTH, 8, aok_gadget_x86_vex_xf_cvtsi2sd64, 0, 0, 2, 0, NULL},
    VE(3, 1, 0x20, -1, VXK_INTIN, VEX_L128, 1, aok_gadget_x86_vex_pinsrb),
    VE(1, 1, 0xc4, -1, VXK_INTIN, VEX_L128, 2, aok_gadget_x86_vex_pinsrw),
    {3, 1, 0x22, -1, VXK_INTIN, VEX_L128, 4, aok_gadget_x86_vex_pinsrd, 0, 0, 1, 0, NULL},
    {3, 1, 0x22, -1, VXK_INTIN, VEX_L128, 8, aok_gadget_x86_vex_pinsrq, 0, 0, 2, 0, NULL},
    VE(3, 1, 0x21, -1, VXK_INSPS, VEX_L128, 0, aok_gadget_x86_vex_insertps),
    VE(3, 1, 0x14, -1, VXK_PEXTR, VEX_L128, 1, aok_gadget_x86_amd64_s4_pextrb_r),
    VE(3, 1, 0x15, -1, VXK_PEXTR, VEX_L128, 2, aok_gadget_x86_amd64_s4_pextrw_r),
    {3, 1, 0x16, -1, VXK_PEXTR, VEX_L128, 4, aok_gadget_x86_amd64_s4_pextrd_r, 0, 0, 1, 0, NULL},
    {3, 1, 0x16, -1, VXK_PEXTR, VEX_L128, 8, aok_gadget_x86_amd64_s4_pextrq_r, 0, 0, 2, 0, NULL},
    VE(3, 1, 0x17, -1, VXK_PEXTR, VEX_L128, 4, aok_gadget_x86_amd64_s4_pextrd_r),         // VEXTRACTPS
    VE(1, 1, 0xc5, -1, VXK_PEXTR, VEX_L128, 2, aok_gadget_x86_amd64_s4_pextrw_r),
    {3, 1, 0x4a, -1, VXK_BLENDV, VEX_LBOTH, 0, aok_gadget_x86_vex_blendvps, 0, 0, 1, 0, NULL},
    {3, 1, 0x4b, -1, VXK_BLENDV, VEX_LBOTH, 0, aok_gadget_x86_vex_blendvpd, 0, 0, 1, 0, NULL},
    {3, 1, 0x4c, -1, VXK_BLENDV, VEX_LBOTH, 0, aok_gadget_x86_vex_pblendvb, 0, 0, 1, 0, NULL},
    {1, 0, 0xae, 2, VXK_SPECIAL, VEX_L128, 0, NULL, VEX_SP_LDMXCSR, 0, 0, 0, NULL},
    {1, 0, 0xae, 3, VXK_SPECIAL, VEX_L128, 0, NULL, VEX_SP_STMXCSR, 0, 0, 0, NULL},
    {3, 1, 0x60, -1, VXK_SPECIAL, VEX_L128, 0, aok_gadget_x86_amd64_pcmpestrm_r, VEX_SP_PCMPSTR, 0, 0, 0, NULL},
    {3, 1, 0x61, -1, VXK_SPECIAL, VEX_L128, 0, aok_gadget_x86_amd64_pcmpestri_r, VEX_SP_PCMPSTR, 0, 0, 0, NULL},
    {3, 1, 0x62, -1, VXK_SPECIAL, VEX_L128, 0, aok_gadget_x86_amd64_pcmpistrm_r, VEX_SP_PCMPSTR, 0, 0, 0, NULL},
    {3, 1, 0x63, -1, VXK_SPECIAL, VEX_L128, 0, aok_gadget_x86_amd64_pcmpistri_r, VEX_SP_PCMPSTR, 0, 0, 0, NULL},
    {1, 1, 0xf7, -1, VXK_SPECIAL, VEX_L128, 0, NULL, VEX_SP_MASKMOVDQU, 0, 0, 0, NULL},
    {2, 1, 0x2c, -1, VXK_MASKMOV, VEX_LBOTH, 4, NULL, 0, 0, 1, 0, NULL},              // VMASKMOVPS load
    {2, 1, 0x2d, -1, VXK_MASKMOV, VEX_LBOTH, 8, NULL, 0, 0, 1, 0, NULL},              // VMASKMOVPD load
    {2, 1, 0x2e, -1, VXK_MASKMOV, VEX_LBOTH, 4, NULL, 1, 0, 1, 0, NULL},              // VMASKMOVPS store
    {2, 1, 0x2f, -1, VXK_MASKMOV, VEX_LBOTH, 8, NULL, 1, 0, 1, 0, NULL},              // VMASKMOVPD store
    {2, 1, 0x8c, -1, VXK_MASKMOV, VEX_LBOTH, 4, NULL, 0, 0, 1, 0, NULL},              // VPMASKMOVD load
    {2, 1, 0x8c, -1, VXK_MASKMOV, VEX_LBOTH, 8, NULL, 0, 0, 2, 0, NULL},              // VPMASKMOVQ load
    {2, 1, 0x8e, -1, VXK_MASKMOV, VEX_LBOTH, 4, NULL, 1, 0, 1, 0, NULL},              // VPMASKMOVD store
    {2, 1, 0x8e, -1, VXK_MASKMOV, VEX_LBOTH, 8, NULL, 1, 0, 2, 0, NULL},              // VPMASKMOVQ store
    // BMI1/BMI2
    {2, 0, 0xf2, -1, VXK_BMI, VEX_L128, 0, NULL, 0, 0, 0, 0, NULL},                         // ANDN
    {2, 0, 0xf3, 1, VXK_BMI, VEX_L128, 0, NULL, 1, 0, 0, 0, NULL},                          // BLSR
    {2, 0, 0xf3, 2, VXK_BMI, VEX_L128, 0, NULL, 2, 0, 0, 0, NULL},                          // BLSMSK
    {2, 0, 0xf3, 3, VXK_BMI, VEX_L128, 0, NULL, 3, 0, 0, 0, NULL},                          // BLSI
    {2, 0, 0xf5, -1, VXK_BMI, VEX_L128, 0, NULL, 4, 0, 0, 0, NULL},                         // BZHI
    {2, 2, 0xf5, -1, VXK_BMI, VEX_L128, 0, NULL, 5, 0, 0, 0, NULL},                         // PEXT
    {2, 3, 0xf5, -1, VXK_BMI, VEX_L128, 0, NULL, 6, 0, 0, 0, NULL},                         // PDEP
    {2, 3, 0xf6, -1, VXK_BMI, VEX_L128, 0, NULL, 7, 0, 0, 0, NULL},                         // MULX
    {2, 0, 0xf7, -1, VXK_BMI, VEX_L128, 0, NULL, 8, 0, 0, 0, NULL},                         // BEXTR
    {2, 1, 0xf7, -1, VXK_BMI, VEX_L128, 0, NULL, 9, 0, 0, 0, NULL},                         // SHLX
    {2, 2, 0xf7, -1, VXK_BMI, VEX_L128, 0, NULL, 10, 0, 0, 0, NULL},                        // SARX
    {2, 3, 0xf7, -1, VXK_BMI, VEX_L128, 0, NULL, 11, 0, 0, 0, NULL},                        // SHRX
    {3, 3, 0xf0, -1, VXK_BMI, VEX_L128, 0, NULL, 12, 0, 0, 0, NULL},                        // RORX
    // FMA3
    {2, 1, 0x96, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_maddsub132ps, 0, 0, 1, 0, NULL},
    {2, 1, 0x96, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_maddsub132pd, 0, 0, 2, 0, NULL},
    {2, 1, 0x97, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msubadd132ps, 0, 0, 1, 0, NULL},
    {2, 1, 0x97, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msubadd132pd, 0, 0, 2, 0, NULL},
    {2, 1, 0x98, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_madd132ps, 0, 0, 1, 0, NULL},
    {2, 1, 0x98, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_madd132pd, 0, 0, 2, 0, NULL},
    {2, 1, 0x99, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_madd132ss, 0, 0, 1, 0, NULL},
    {2, 1, 0x99, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_madd132sd, 0, 0, 2, 0, NULL},
    {2, 1, 0x9a, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msub132ps, 0, 0, 1, 0, NULL},
    {2, 1, 0x9a, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msub132pd, 0, 0, 2, 0, NULL},
    {2, 1, 0x9b, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_msub132ss, 0, 0, 1, 0, NULL},
    {2, 1, 0x9b, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_msub132sd, 0, 0, 2, 0, NULL},
    {2, 1, 0x9c, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmadd132ps, 0, 0, 1, 0, NULL},
    {2, 1, 0x9c, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmadd132pd, 0, 0, 2, 0, NULL},
    {2, 1, 0x9d, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_nmadd132ss, 0, 0, 1, 0, NULL},
    {2, 1, 0x9d, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_nmadd132sd, 0, 0, 2, 0, NULL},
    {2, 1, 0x9e, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmsub132ps, 0, 0, 1, 0, NULL},
    {2, 1, 0x9e, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmsub132pd, 0, 0, 2, 0, NULL},
    {2, 1, 0x9f, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_nmsub132ss, 0, 0, 1, 0, NULL},
    {2, 1, 0x9f, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_nmsub132sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xa6, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_maddsub213ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xa6, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_maddsub213pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xa7, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msubadd213ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xa7, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msubadd213pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xa8, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_madd213ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xa8, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_madd213pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xa9, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_madd213ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xa9, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_madd213sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xaa, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msub213ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xaa, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msub213pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xab, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_msub213ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xab, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_msub213sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xac, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmadd213ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xac, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmadd213pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xad, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_nmadd213ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xad, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_nmadd213sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xae, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmsub213ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xae, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmsub213pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xaf, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_nmsub213ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xaf, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_nmsub213sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xb6, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_maddsub231ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xb6, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_maddsub231pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xb7, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msubadd231ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xb7, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msubadd231pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xb8, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_madd231ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xb8, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_madd231pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xb9, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_madd231ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xb9, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_madd231sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xba, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msub231ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xba, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_msub231pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xbb, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_msub231ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xbb, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_msub231sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xbc, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmadd231ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xbc, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmadd231pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xbd, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_nmadd231ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xbd, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_nmadd231sd, 0, 0, 2, 0, NULL},
    {2, 1, 0xbe, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmsub231ps, 0, 0, 1, 0, NULL},
    {2, 1, 0xbe, -1, VXK_L3, VEX_LBOTH, 0, aok_gadget_x86_vex_fma_nmsub231pd, 0, 0, 2, 0, NULL},
    {2, 1, 0xbf, -1, VXK_SCAL, VEX_LBOTH, 4, aok_gadget_x86_vex_fma_nmsub231ss, 0, 0, 1, 0, NULL},
    {2, 1, 0xbf, -1, VXK_SCAL, VEX_LBOTH, 8, aok_gadget_x86_vex_fma_nmsub231sd, 0, 0, 2, 0, NULL},
};

static const struct vex_entry *vex_lookup(const struct vex_insn *v) {
    for (size_t i = 0; i < sizeof(vex_table) / sizeof(vex_table[0]); i++) {
        const struct vex_entry *e = &vex_table[i];
        if (e->map == v->map && e->pp == v->pp && e->op == v->op &&
                (e->group < 0 || (unsigned) e->group == (v->reg & 7)) &&
                (e->wreq == 0 || e->wreq == 1 + v->w))
            return e;
    }
    return NULL;
}

// Whether the instruction has an imm8 (read by the decoders before the
// lookup): the 0F3A map, and the shift groups.
static bool vex_has_imm8(unsigned map, unsigned op) {
    return map == 3 || (map == 1 && ((op >= 0x70 && op <= 0x73) || op == 0xc2 || (op >= 0xc4 && op <= 0xc6)));
}

// What to emit for v. VP_FRAME: a vex.inc frame gadget and its word (and
// extra words), after staging its memory operand (stage_bytes) or a general
// register (gpr_stage); VP_STORE: st_bytes from cpu_state offsets st_src to
// the memory operand; VP_GPROUT: the low 4/8 bytes at gpr_src to GPR
// gpr_dst; VP_UD: #UD. False: v is not in the table (the caller's old path).
enum vex_plan_type { VP_FRAME, VP_STORE, VP_GPROUT, VP_SPECIAL, VP_MASKED, VP_BMI, VP_GATHER, VP_UD };
struct vex_plan {
    enum vex_plan_type type;
    void (*gadget)(void);
    unsigned long word;
    unsigned nextra;
    unsigned long extra[4];     // code-stream words after the word (the tbl indices)
    unsigned stage_bytes, align;
    int gpr_stage;              // a general register to stage, or -1
    bool gpr_w;                 // amd64: 64 bits of it
    unsigned st_bytes;
    unsigned long st_src;       // lo offset | hi offset << 16
    unsigned gpr_dst;
    unsigned long gpr_src;
    bool writes_gpr;            // a VP_FRAME gadget writes amd64_regs (amd64: flush the cache)
    uint8_t word_imm_mask;      // nonzero: the imm8 the word carries is masked with it
    unsigned special;           // VP_SPECIAL: VEX_SP_*
    unsigned masked_store, masked_esz;  // VP_MASKED
    unsigned bmi_op, bmi_dst, bmi_a, bmi_b, bmi_dst2;  // VP_BMI: registers (amd64 numbering)
    int gpr_out;                // i386: copy amd64_regs[0] to this register after, or -1
    unsigned st_after;          // a VP_FRAME into VEX_STAGE, stored to memory (these bytes) after a write probe
    int gpr_in;                 // i386: copy this register to amd64_regs[0] before, or -1
};
#define VEX_XMM_OFF(i) ((unsigned long) X((i) & 15))
#define VEX_YHI_OFF(i) ((unsigned long) X((i) & 15) + 16)
static bool vex_plan(const struct vex_insn *v, struct vex_plan *p, bool i386) {
    const struct vex_entry *e = vex_lookup(v);
    if (e == NULL)
        return false;
    memset(p, 0, sizeof(*p));
    p->gpr_stage = -1;
    p->gpr_out = -1;
    p->gpr_in = -1;
    p->type = VP_UD;
    if (!(e->lmask & (v->l ? VEX_L256 : VEX_L128)))
        return true;
    unsigned width = v->l ? 32 : 16;
    unsigned s1 = v->vvvv, s2 = v->rm, d = v->reg, bytes = width;
    bool lbit = v->l, stage = v->mem;
    void (*g)(void) = e->gadget;
#define NEED_VVVV0 do { if (v->vvvv != 0 || v->vvvv_hi) return true; } while (0)
#define STORE(n, lo, hi) do { p->type = VP_STORE; p->st_bytes = (n); p->st_src = (lo) | (hi) << 16; \
        p->align = e->align ? (n) : 0; return true; } while (0)
    switch (e->kind) {
    case VXK_L3:
        break;
    case VXK_L2:
        NEED_VVVV0;
        s1 = v->rm;
        if (!v->l && e->sbytes != 0)
            bytes = e->sbytes;
        break;
    case VXK_SHX:
        bytes = 16;
        break;
    case VXK_SHI:
        if (v->mem)
            return true;
        d = v->vvvv;
        s1 = 0;
        break;
    case VXK_SCAL:
        bytes = e->sbytes;
        lbit = false;
        break;
    case VXK_TBL1:
    case VXK_TBL2U:
        NEED_VVVV0;
        s1 = v->rm;
        break;
    case VXK_TBL2:
        break;
    case VXK_LOAD:
        NEED_VVVV0;
        if (!v->mem && e->aux)
            return true;                        // memory only
        s1 = v->rm;
        if (e->sbytes != 0) {
            bytes = e->sbytes;
            lbit = false;
        }
        p->align = e->align && v->mem ? bytes : 0;
        break;
    case VXK_STORE:
        NEED_VVVV0;
        if (v->mem) {
            unsigned n = e->sbytes ? e->sbytes : width;
            STORE(n, VEX_XMM_OFF(v->reg), VEX_YHI_OFF(v->reg));
        }
        if (g == NULL)
            return true;                        // the non-temporal stores: memory only
        d = v->rm;
        s1 = s2 = v->reg;
        if (e->sbytes != 0)
            lbit = false;
        break;
    case VXK_MOVS:
        lbit = false;
        if (v->mem) {
            NEED_VVVV0;
            bytes = e->sbytes;
        } else {
            g = e->gadget2;
        }
        break;
    case VXK_MOVSST:
        if (v->mem) {
            NEED_VVVV0;
            STORE(e->sbytes, VEX_XMM_OFF(v->reg), 0ul);
        }
        g = e->gadget2;
        d = v->rm;
        s2 = v->reg;
        lbit = false;
        break;
    case VXK_LOHI:
        if (v->mem) {
            bytes = 8;
        } else {
            if (e->gadget2 == NULL)
                return true;
            g = e->gadget2;
        }
        break;
    case VXK_STQ:
        if (!v->mem)
            return true;
        NEED_VVVV0;
        STORE(8, VEX_XMM_OFF(v->reg) + e->aux, 0ul);
    case VXK_GPRIN:
        NEED_VVVV0;
        s1 = v->rm;
        lbit = false;
        if (v->mem) {
            bytes = v->w ? 8 : 4;
        } else {
            p->gpr_stage = v->rm;
            p->gpr_w = v->w;
            stage = true;
        }
        break;
    case VXK_GPROUT:
        NEED_VVVV0;
        if (v->mem)
            STORE(v->w ? 8u : 4u, VEX_XMM_OFF(v->reg), 0ul);
        p->type = VP_GPROUT;
        p->gpr_dst = v->rm;
        p->gpr_src = VEX_XMM_OFF(v->reg);
        p->gpr_w = v->w;
        return true;
    case VXK_BCAST:
        NEED_VVVV0;
        if (!v->mem && e->aux)
            return true;                        // VBROADCASTF128/I128: memory only
        s1 = v->rm;
        bytes = e->sbytes;
        break;
    case VXK_INS128:
        bytes = 16;
        break;
    case VXK_EXT128:
        NEED_VVVV0;
        if (v->mem)
            STORE(16, (v->imm & 1) ? VEX_YHI_OFF(v->reg) : VEX_XMM_OFF(v->reg), 0ul);
        d = v->rm;
        s2 = v->reg;
        break;
    case VXK_PERMQ: {
        NEED_VVVV0;
        uint8_t idx[32];
        for (unsigned q = 0; q < 4; q++)
            for (unsigned j = 0; j < 8; j++)
                idx[8 * q + j] = 8 * ((v->imm >> (2 * q)) & 3) + j;
        memcpy(p->extra, idx, 32);
        p->nextra = 4;
        break;
    }
    case VXK_WIDEN:
        NEED_VVVV0;
        s1 = v->rm;
        bytes = v->l ? 2 * e->sbytes : e->sbytes;
        break;
    case VXK_NARROW:
        NEED_VVVV0;
        s1 = v->rm;
        break;
    case VXK_UD:
        return true;
    case VXK_KOP: {
        unsigned kop = e->aux & 31, wlog = e->aux >> 5;
        if (kop != 0 && kop != 1 && kop != 2 && kop != 3 && kop != 4 && kop != 5 && kop != 7)
            NEED_VVVV0;
        if (v->mem ? (kop != 8 && kop != 10) : kop == 10)
            return true;                        // register forms only, but KMOV k <-> m
        if (i386 && (kop == 11 || kop == 12) && wlog == 3)
            return true;                        // KMOVQ with a GPR: 64-bit mode only
        if ((kop != 12 && (v->reg & 8)) || v->vvvv > 7)
            return true;                        // VEX.R on a k register, or k8+ in vvvv (SDE; VEX.B on one is ignored)
        unsigned gpr = 0;
        if (kop == 8 && v->mem) {
            kop = 9;
            p->stage_bytes = 1u << wlog;
        } else if (kop == 10) {
            p->st_after = 1u << wlog;
        } else if (kop == 11) {
            gpr = i386 ? 0 : v->rm;
            p->gpr_in = i386 ? (int) (v->rm & 7) : -1;
        } else if (kop == 12) {
            gpr = i386 ? 0 : v->reg;
            p->gpr_out = i386 ? (int) (v->reg & 7) : -1;
        }
        p->type = VP_FRAME;
        p->gadget = g;
        p->writes_gpr = kop >= 11 && kop <= 14;  // GPRs or the flags: amd64 flushes its cache
        unsigned src1 = kop == 13 || kop == 14 ? v->reg : v->vvvv;    // KORTEST/KTEST: reg and r/m
        unsigned src2 = kop == 10 ? v->reg : v->rm;                     // KMOV m, k: the k is reg
        p->word = kop | (unsigned long) (v->reg & 7) << 8 | (unsigned long) (src1 & 7) << 12 |
                (unsigned long) (src2 & 7) << 16 | (unsigned long) wlog << 20 | (unsigned long) v->imm << 24 |
                (unsigned long) (gpr & 15) << 32 | (wlog == 3 ? 1ul << 36 : 0);
        return true;
    }
    case VXK_GATHER:
        // VSIB: memory with a SIB, its index a vector register; dst, mask
        // and index three different registers
        if (!v->mem || v->vsib_index < 0)
            return true;
        if (v->reg == v->vvvv || v->reg == (unsigned) v->vsib_index || v->vvvv == (unsigned) v->vsib_index)
            return true;
        p->type = VP_GATHER;
        p->word = (v->reg & 15) | (unsigned long) (v->vvvv & 15) << 4 | (unsigned long) (v->vsib_index & 15) << 8 |
                (unsigned long) (v->vsib_scale & 3) << 12 | (v->w ? 1ul << 14 : 0) | (e->aux ? 1ul << 15 : 0) |
                (v->l ? 1ul << 16 : 0);
        return true;
    case VXK_PS2PH:
        NEED_VVVV0;
        s1 = v->reg;
        s2 = 0;
        d = v->rm;
        if (v->mem) {
            p->st_after = v->l ? 16 : 8;
            stage = false;
            d = 0;
        }
        break;
    case VXK_G2R:
        NEED_VVVV0;
        if (v->mem && e->sbytes == 0)
            return true;                        // VMOVMSKPS/PD, VPMOVMSKB: register only
        bytes = e->sbytes;
        if (e->sbytes != 0)
            lbit = false;
        d = i386 ? 0 : v->reg;
        p->writes_gpr = true;
        p->gpr_out = i386 ? (int) v->reg : -1;
        break;
    case VXK_FLAGS:
        NEED_VVVV0;
        s1 = v->reg;
        bytes = e->sbytes;
        lbit = false;
        break;
    case VXK_TEST:
        NEED_VVVV0;
        s1 = v->reg;
        break;
    case VXK_INTIN:
        lbit = false;
        if (v->mem) {
            bytes = e->sbytes;
        } else {
            p->gpr_stage = v->rm;
            p->gpr_w = e->sbytes == 8;
            stage = true;
        }
        break;
    case VXK_INSPS:
        if (v->mem) {
            bytes = 4;
            p->word_imm_mask = 0x3f;
        }
        break;
    case VXK_PEXTR: {
        NEED_VVVV0;
        unsigned n = e->sbytes, lane = v->imm & (16 / n - 1);
        if (v->op == 0xc5) {                    // VPEXTRW r32, xmm, imm8: the 0F map's, register only
            if (v->mem)
                return true;
            p->type = VP_FRAME;
            p->gadget = g;
            p->word = (v->rm & 15) | (unsigned long) (i386 ? 0 : v->reg & 15) << 4 | (unsigned long) lane << 8;
            p->writes_gpr = true;
            p->gpr_out = i386 ? (int) v->reg : -1;
            return true;
        }
        if (v->mem)
            STORE(n, VEX_XMM_OFF(v->reg) + lane * n, 0ul);
        p->type = VP_FRAME;
        p->gadget = g;
        p->word = (v->reg & 15) | (unsigned long) (i386 ? 0 : v->rm & 15) << 4 | (unsigned long) lane << 8;
        p->writes_gpr = true;
        p->gpr_out = i386 ? (int) v->rm : -1;
        return true;
    }
    case VXK_BLENDV:
        if (!i386 || (v->imm >> 4) < 8)
            break;
        return true;                            // xmm8-15 do not exist in 32-bit mode
    case VXK_BMI:
        if (e->aux == 12)                       // RORX: no vvvv (before the type: NEED_VVVV0 leaves it)
            NEED_VVVV0;
        p->type = VP_BMI;
        p->bmi_op = e->aux;
        p->bmi_dst = v->reg;
        p->bmi_a = v->vvvv;
        p->bmi_b = v->rm;
        p->bmi_dst2 = 0;
        if (e->aux >= 1 && e->aux <= 3) {       // BLSR BLSMSK BLSI: dst is vvvv
            p->bmi_dst = v->vvvv;
        } else if (e->aux == 7) {               // MULX: a is EDX/RDX, low to vvvv
            p->bmi_a = 2;
            p->bmi_dst2 = v->vvvv;
        }
        p->word = e->aux | (v->w ? 1ul << 16 : 0) | (v->mem ? 1ul << 17 : 0) | (unsigned long) v->imm << 24;
        p->stage_bytes = v->mem ? (v->w ? 8 : 4) : 0;
        return true;
    case VXK_MASKMOV:
        if (!v->mem)
            return true;
        p->type = VP_MASKED;
        p->masked_store = e->aux;
        p->masked_esz = e->sbytes;
        p->word = (width / e->sbytes) | (unsigned long) (v->reg & 15) << 8 | (unsigned long) (v->vvvv & 15) << 12 |
                (v->l ? 1ul << 16 : 0);
        return true;
    case VXK_SPECIAL:
        if (e->aux == VEX_SP_MASKMOVDQU) {
            NEED_VVVV0;
            if (v->mem)
                return true;
            p->type = VP_SPECIAL;
            p->special = e->aux;
            return true;
        }
        NEED_VVVV0;
        if ((e->aux == VEX_SP_LDMXCSR || e->aux == VEX_SP_STMXCSR) && !v->mem)
            return true;
        p->type = VP_SPECIAL;
        p->gadget = g;
        p->special = e->aux;
        return true;
    case VXK_ZERO:
        NEED_VVVV0;                             // (Intel: vvvv must be 1111b)
        p->type = VP_FRAME;
        p->gadget = v->l ? e->gadget2 : g;
        p->word = v->rm;                        // (the caller puts the register count here)
        return true;
    }
#undef NEED_VVVV0
#undef STORE
    if (e->kind == VXK_TBL1 || e->kind == VXK_TBL2 || e->kind == VXK_TBL2U) {
        x86_shuffle_index(e->aux, v->imm, &p->extra[0], &p->extra[1]);
        x86_shuffle_index(e->aux, (uint8_t) (v->imm >> e->ihs), &p->extra[2], &p->extra[3]);
        p->nextra = 4;
        // VPERMILPD: SHUFPD's index with both sources the one register, so
        // a one-source tbl of it
        if (e->kind == VXK_TBL2U)
            for (unsigned i = 0; i < 4; i++)
                p->extra[i] &= 0x0f0f0f0f0f0f0f0full;
    }
    p->type = VP_FRAME;
    p->gadget = g;
    if (v->mem && p->gpr_stage < 0 && p->st_after == 0)
        p->stage_bytes = bytes;
    uint8_t imm = p->word_imm_mask ? (uint8_t) (v->imm & p->word_imm_mask) : v->imm;
    p->word = (s1 & 15) | (unsigned long) (s2 & 15) << 4 | (unsigned long) (d & 15) << 8 |
            (stage ? 1ul << 12 : 0) | (lbit ? 1ul << 13 : 0) | (p->st_after ? 1ul << 14 : 0) |
            (unsigned long) imm << 16;
    return true;
}

/*
 * The VEX forms of GFNI, AES, VPCLMULQDQ and AVX-VNNI, which iSH-AOK computes
 * with the EVEX table's ops (not here yet: QEMU's engine's).
 */
static inline bool vex_via_evex(unsigned map, unsigned pp, unsigned op)
{
    return pp == 1 && ((map == 2 && (op == 0xcf || (op >= 0xdb && op <= 0xdf) || (op >= 0x50 && op <= 0x53))) ||
            (map == 3 && (op == 0xce || op == 0xcf || op == 0xdf || op == 0x44)));
}

/* ---- This front end's emitter ------------------------------------------------- */

/* Never run: the table's name for a gadget iSH-AOK has and this front end does not. */
void aok_vec_none(void)
{
    g_assert_not_reached();
}

/* gadgets-vec.S's loads to VEX_STAGE, stores and write probes, by log2 of the bytes. */
#define VSZ(X, n) X(n##1) X(n##2) X(n##4) X(n##8) X(n##16) X(n##32) X(n##64)
VSZ(MEMD, vld) VSZ(MEMD, vst) VSZ(MEMD, vwp)
MEMD(vld16a) MEMD(vld32a) MEMD(vld64a) MEMD(vst16a) MEMD(vst32a) MEMD(vst64a)
static const MemTab vld_tab[7] = { VSZ(MEMT, vld) };
static const MemTab vst_tab[7] = { VSZ(MEMT, vst) };
static const MemTab vwp_tab[7] = { VSZ(MEMT, vwp) };
static const MemTab vlda_tab[7] = { [4] = MEMT(vld16a) [5] = MEMT(vld32a) [6] = MEMT(vld64a) };
static const MemTab vsta_tab[7] = { [4] = MEMT(vst16a) [5] = MEMT(vst32a) [6] = MEMT(vst64a) };
#define VSTAGE  offsetof(CPUX86State, aok_vstage)
DECL(vex_gst_amd64) DECL(vex_to_gpr_amd64) DECL(vex_bmi)

static unsigned vlog2(unsigned bytes)
{
    return ctz32(bytes);
}

/*
 * A vector memory operand: the gadget of @tab for its form, [@own] if it has
 * one, the address and the host's word: the log2 of the bytes, | 16 for an
 * operand that must be aligned to its size.
 */
static void vmem(Ctx *c, const Insn *d, const MemTab tab, bool has_own,
                 uint64_t own, unsigned bytes, bool aligned)
{
    const Mem *m = &d->m;
    bool ea = m->riprel || m->seg >= 0 || m->index >= 0;

    if (ea) {
        emit_ea(c, d);
    }
    aok_emit_gadget(&c->g, tab[ea ? F_EA : c->c64 ? F_BD : F_B3][c->mp]);
    if (has_own) {
        aok_emit(&c->g, own);
    }
    if (!ea) {
        aok_emit(&c->g, ro(m->base));
        aok_emit(&c->g, m->disp);
    }
    aok_emit(&c->g, word(c, vlog2(bytes) | (aligned ? 16 : 0)));
    c->hf = HF_NONE;
}

/* #UD, raised where the insn is. */
void aok_x86_helper_ud(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b);
void aok_x86_helper_ud(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b)
{
    x86_sync(env, pc);
    raise_exception_ra(env, EXCP06_ILLOP, 0);
}

static int vex_ud(Ctx *c, Insn *d, const uint8_t *code)
{
    FIN();
    E4(G(call_c), aok_x86_helper_ud, c->off, 0, 0);
    return END;
}

/*
 * A VEX insn, @lead (C4 or C5) and the legacy prefixes before it read. In
 * 64-bit code; 32-bit code's (where C4 and C5 are also les and lds) and
 * anything the table does not have are TCG's. An encoding the hardware
 * rejects is #UD here, as iSH-AOK's table says.
 */
static int vex(Ctx *c, Insn *d, const uint8_t *code, unsigned lead)
{
    const struct vex_entry *e;
    struct vex_insn v = { 0 };
    struct vex_plan p;
    unsigned b1, b2;
    bool r, x, b;

    if (!c->c64) {
        return UNKNOWN;
    }
    b1 = f8(d);
    if (lead == 0xc5) {
        r = !(b1 & 0x80);
        x = b = false;
        v.map = 1;
        v.vvvv = (~b1 >> 3) & 15;
        v.l = (b1 >> 2) & 1;
        v.pp = b1 & 3;
    } else {
        b2 = f8(d);
        r = !(b1 & 0x80);
        x = !(b1 & 0x40);
        b = !(b1 & 0x20);
        v.map = b1 & 0x1f;
        v.w = b2 >> 7;
        v.vvvv = (~b2 >> 3) & 15;
        v.l = (b2 >> 2) & 1;
        v.pp = b2 & 3;
    }
    v.op = f8(d);
    if (d->bad) {
        return UNKNOWN;
    }
    if (d->o16 || d->rep || d->repne || d->lock || d->rex ||
        v.map < 1 || v.map > 3) {
        return c->avx ? vex_ud(c, d, code) : UNKNOWN;
    }
    if (v.map == 1 && v.op == 0x77) {           /* vzeroupper, vzeroall */
        if (!c->avx) {
            return UNKNOWN;
        }
        v.rm = 16;
        if (!vex_plan(&v, &p, false) || p.type == VP_UD) {
            return vex_ud(c, d, code);
        }
        FIN();
        E1(p.gadget, p.word);
        c->hf = HF_NONE;
        return NEXT;
    }
    d->rr = r ? 8 : 0;
    d->rx = x ? 8 : 0;
    d->rb = b ? 8 : 0;
    modrm(d);
    v.reg = d->reg & 15;
    v.rm = (d->rm & 7) | d->rb;
    v.mem = d->mod != 3;
    v.vsib_index = -1;
    if (d->bad || vex_via_evex(v.map, v.pp, v.op)) {
        return UNKNOWN;                         /* (GFNI, AES, VPCLMUL, VNNI: EVEX's) */
    }
    e = vex_lookup(&v);
    if (e && e->kind == VXK_BMI ? !(c->bmi1 && c->bmi2) : !c->avx) {
        return UNKNOWN;
    }
    if (!e) {
        return vex_ud(c, d, code);
    }
    if ((e->kind == VXK_KOP && !c->avx512) || e->kind == VXK_GATHER ||
        e->kind == VXK_MASKMOV || e->kind == VXK_SPECIAL) {
        return UNKNOWN;         /* (not here yet: QEMU's engine's) */
    }
    if (vex_has_imm8(v.map, v.op)) {
        v.imm = f8(d);
    }
    FIN();
    vex_plan(&v, &p, false);
    switch (p.type) {
    case VP_UD:
        return vex_ud(c, d, code);
    case VP_STORE:
        vmem(c, d, p.align ? vsta_tab[vlog2(p.st_bytes)] : vst_tab[vlog2(p.st_bytes)],
             true, p.st_src & 0xffff, p.st_bytes, p.align);
        return NEXT;
    case VP_GPROUT:
        E1(G(vex_to_gpr_amd64), p.gpr_src | (uint64_t)(p.gpr_dst & 15) << 16 |
           (p.gpr_w ? 1ull << 20 : 0));
        return NEXT;
    case VP_BMI:
        if (v.mem) {
            vmem(c, d, vld_tab[vlog2(p.stage_bytes)], false, 0, p.stage_bytes, false);
        }
        E1(G(vex_bmi), p.word | (uint64_t)(p.bmi_dst & 15) << 4 |
           (uint64_t)(p.bmi_a & 15) << 8 | (uint64_t)(p.bmi_b & 15) << 12 |
           (uint64_t)(p.bmi_dst2 & 15) << 20);
        c->hf = HF_NONE;
        if (p.bmi_op <= 4 || p.bmi_op == 8) {
            set_flags(c, HF_NONE, CC_OP_EFLAGS);
        }
        return NEXT;
    case VP_FRAME:
        if (p.gadget == aok_vec_none) {
            return UNKNOWN;
        }
        if (v.mem && !p.stage_bytes && p.gpr_stage < 0 && !p.st_after) {
            return vex_ud(c, d, code);
        }
        if (p.gpr_stage >= 0) {
            E1(G(vex_gst_amd64), (p.gpr_stage & 15) | (p.gpr_w ? 16 : 0));
        } else if (p.stage_bytes) {
            vmem(c, d, p.align ? vlda_tab[vlog2(p.stage_bytes)]
                               : vld_tab[vlog2(p.stage_bytes)],
                 false, 0, p.stage_bytes, p.align);
        }
        if (p.st_after) {
            /* the store's fault before the frame changes anything (MXCSR) */
            vmem(c, d, vwp_tab[vlog2(p.st_after)], false, 0, p.st_after, false);
        }
        aok_emit_gadget(&c->g, p.gadget);
        aok_emit(&c->g, p.word);
        for (unsigned i = 0; i < p.nextra; i++) {
            aok_emit(&c->g, p.extra[i]);
        }
        if (p.st_after) {
            vmem(c, d, vst_tab[vlog2(p.st_after)], true, VSTAGE, p.st_after, false);
        }
        c->hf = HF_NONE;
        if (e->kind == VXK_FLAGS || e->kind == VXK_TEST ||
            (e->kind == VXK_KOP && ((e->aux & 31) == 13 || (e->aux & 31) == 14))) {
            set_flags(c, HF_NONE, CC_OP_EFLAGS);
        }
        return NEXT;
    default:                    /* gathers, masked moves, the specials: TCG's */
        return UNKNOWN;
    }
}
