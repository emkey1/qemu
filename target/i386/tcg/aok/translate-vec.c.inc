/*
 * The VEX instructions (AVX, AVX2, FMA3, F16C, BMI1/2 and the opmask ones)
 * and the EVEX ones (AVX-512 and the extensions that come with it, and the
 * VEX and legacy forms of GFNI, AES, PCLMULQDQ and AVX-VNNI, which are its
 * ops), included by translate-x86.c: iSH-AOK's tables of them and its
 * planners, which say which of gadgets-vec.S's frames computes each and
 * with what operand word, and this front end's emitter.
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

// The VEX forms of GFNI (VGF2P8MULB, VGF2P8AFFINE(INV)QB), AES (VAES*,
// VAESIMC, VAESKEYGENASSIST), VPCLMULQDQ and AVX-VNNI are the EVEX table's ops
// at VL 128/256, unmasked: EVEX's P0-P2 from the VEX fields (R X B and vvvv
// as VEX has them, R' and V' clear, L'L = L). Their legacy SSE forms too
// (sse_via_evex: which).
static inline bool vex_via_evex(unsigned map, unsigned pp, unsigned op) {
    return pp == 1 && ((map == 2 && (op == 0xcf || (op >= 0xdb && op <= 0xdf) || (op >= 0x50 && op <= 0x53))) ||
            (map == 3 && (op == 0xce || op == 0xcf || op == 0xdf || op == 0x44)));
}
static inline bool sse_via_evex(unsigned map, unsigned op) {           // GFNI, AES, PCLMULQDQ (not AVX-VNNI)
    return vex_via_evex(map, 1, op) && !(map == 2 && op >= 0x50 && op <= 0x53);
}
static inline bool sse_via_evex_unary(unsigned map, unsigned op) {     // AESIMC, AESKEYGENASSIST: no s1
    return (map == 2 && op == 0xdb) || (map == 3 && op == 0xdf);
}
static inline void vex_to_evex(bool r, bool x, bool b, unsigned map, bool w, unsigned vvvv, bool l, unsigned pp,
        unsigned *p0, unsigned *p1, unsigned *p2) {
    *p0 = (r ? 0 : 0x80) | (x ? 0 : 0x40) | (b ? 0 : 0x20) | 0x10 | map;
    *p1 = (w ? 0x80 : 0) | ((~vvvv & 15) << 3) | 4 | pp;
    *p2 = (l ? 0x20 : 0) | 8;
}
enum { EVF_EVEX, EVF_VEX, EVF_SSE };

// Whether an EVEX opcode has an imm8 after its operand (the decoder reads it
// before the lookup): the 0F3A map, and the 0F map's shift groups, CMPPS/PD
// and the shuffles.
static inline bool evex_has_imm8(unsigned map, unsigned op) {
    return map == 3 || (map == 1 && ((op >= 0x70 && op <= 0x73) || op == 0xc2 || (op >= 0xc4 && op <= 0xc6)));
}

// ---- EVEX (AVX-512): vec/evex.inc's frames ----
//
// An entry gives the opcode's operand roles (kind), the VEX.W it requires,
// the element size masking works at (esz, log2 bytes), the embedded
// broadcast's element (bcast, log2 bytes; 0: none, EVEX.b with memory is
// #UD), the memory operand's tuple for disp8*N, whether a memory operand
// must be aligned to the vector length, and whether masking is #UD.
enum evex_kind {
    EVK_L3,     // dst = reg, s1 = vvvv, s2 = r/m
    EVK_L2,     // dst = reg, s2 = r/m (as s1 too); vvvv must be 1111b
    EVK_LOAD,   // dst = reg, s2 = r/m: a move; vvvv 1111b
    EVK_STORE,  // r/m = reg: a move to memory (masked: only the elements the mask enables) or a register
    EVK_TOMASK, // k[reg] = s1 OP s2, element by element (the compares, VPTESTM/NM); zeroing only
    EVK_SHI,    // dst = vvvv, s2 = r/m: the imm8 shifts and rotates (a group in ModRM.reg)
    EVK_BCAST,  // dst = reg, s2 = r/m, vvvv 1111b: a broadcast (the frame's flags pick the quarter)
    EVK_BCASTG, // dst = reg, s2 = the r/m GPR (staged), vvvv 1111b: VPBROADCASTB/W/D/Q from a GPR
    EVK_SCAL,   // a scalar op: as EVK_L3 at VL 128, element 0 masked (the rest s1's), memory 1 << esz bytes
    EVK_TOMASKS,// a scalar compare into an opmask: as EVK_TOMASK at VL 128, memory 1 << esz bytes
    EVK_FULL,   // as EVK_L3, on evex_full's whole-vector frame (the lane-crossing ops)
    EVK_FULL1,  // as EVK_FULL with vvvv 1111b: dst = reg, the source s2 = r/m
    EVK_FULL8,  // as EVK_FULL, word bit 39 (VINSERT*32x8/64x4)
    EVK_EXTRACT,  // r/m (an xmm, or a masked store) = a 128-bit lane of reg: VEXTRACT*32x4/64x2
    EVK_EXTRACT8, // ... a 256-bit half: VEXTRACT*32x8/64x4
    EVK_V2M,    // k[reg] = each element's sign of the r/m register (VPMOVB2M ...): vvvv 1111b, no mask
    EVK_M2V,    // dst = reg, from the r/m k register (VPMOVM2B ...): vvvv 1111b, no mask
    EVK_EXT,    // dst = reg, s2 = r/m of VL >> ld bytes: VPMOVSX/ZX; vvvv 1111b
    EVK_NARROW, // r/m (a register, or memory of VL >> ld bytes) = reg narrowed: VPMOV(S/US)*; vvvv 1111b
    EVK_COMPRESS, // r/m (a register, or memory) = reg's enabled elements packed: VPCOMPRESS*
    EVK_EXPAND, // dst = reg, the r/m's low elements spread to the enabled ones: VPEXPAND*
    EVK_GATHER, // reg = the VSIB elements the mask enables (opcode bit 0: qword indices; W: qword data)
    EVK_SCATTER,// the VSIB elements the mask enables = reg's
    EVK_CVTW,   // a widening conversion: dst = reg, s2 = r/m of VL / 2 (evex_cvtw); vvvv 1111b
    EVK_CVTN,   // a narrowing one: dst = reg of VL / 2 (VL 128: 64 bits), s2 = r/m (evex_cvtn); vvvv 1111b
    EVK_CVTNR,  // VCVTPS2PH: as EVK_CVTN with the source reg, the destination r/m (memory: VL / 2 bytes)
    EVK_CVTSI,  // VCVT(U)SI2SS/SD: as EVK_SCAL, s2 a GPR (staged) or memory of ld bytes
    EVK_CVT2GPR,// VCVT(T)SS/SD2(U)SI: the GPR reg = s2's low element (evex_cvt2gpr; gen_evex_cvt2gpr_word)
    EVK_FLAGS,  // (V)(U)COMISS/SD: EFLAGS = s1 (reg) against s2's low element (r/m: ld bytes); vvvv 1111b
    EVK_INS,    // dst = reg = s1 (vvvv) with an element from a GPR (staged) or memory of ld bytes: VPINSR*, VMOVD/Q in
    EVK_EXTR,   // r/m (a GPR, or memory of ld bytes) = an element of reg (evex_extr; gen_evex_extr_word)
    EVK_SSTORE, // VMOVSS/SD 11: memory = reg's element 0 (masked); register: rm = s1 (vvvv) <- reg's, as EVK_SCAL
};
// evex_entry.flags bits 4-7
#define EVF_MEMONLY 0x10
#define EVF_REGONLY 0x20
#define EVF_MIN256 0x40
#define EVF_MIN512 0x80
#define EVF_LEGACY 0x100
#define EVF_NOVVVV 0x200        // vvvv must be 1111b (a one-source op into an opmask: VFPCLASS)
#define EVF_L128 0x400          // EVEX.128 only: L'L must be 0 (the element moves)
#define EVF_ZEROS1 0x800        // EVK_INS into zeros, not s1 (VMOVD/VMOVQ in): vvvv 1111b; word bit 46
#define EVF_MEMNOVVVV 0x1000    // the memory form's vvvv must be 1111b (VMOVSS/SD's load)
#define EVF_EXTR_SWAP 0x2000    // EVK_EXTR with the GPR in ModRM.reg and the source r/m (VPEXTRW 0F C5)        // SSE and VEX.128 only (AESIMC, AESKEYGENASSIST): EVEX, VEX.256 #UD
enum evex_tuple { EVT_FV, EVT_FVM, EVT_FIX, EVT_DIV, EVT_DUP };  // DUP: VMOVDDUP's, 8 bytes at VL 128  // FIX: disp8 * the fixed size (ld); DIV: VL bytes >> ld
struct evex_entry {
    uint8_t map, pp, op;
    uint8_t kind, wreq, esz, bcast, tuple, align, nomask;
    void (*gadget)(void);
    uint8_t grp;                // ModRM.reg + 1 for a group (the imm8 shifts), else 0
    uint16_t flags;             // the frame's word bits 33-36 (s2's quarter 0, q & 1; merge s1; dst in), EVF_*
    uint8_t ld;                 // a memory operand of this many bytes whatever VL (0: VL's)
    uint8_t fp;                 // a float op: 1 with {er} (EVEX.b, register: RC in L'L), 2 {sae} only
};
#define EVEX_INT(X) \
    X(1, 0xfc, 0, 0, 0, paddb) X(1, 0xfd, 0, 1, 0, paddw) X(1, 0xfe, 1, 2, 2, paddd) X(1, 0xd4, 2, 3, 3, paddq) \
    X(1, 0xf8, 0, 0, 0, psubb) X(1, 0xf9, 0, 1, 0, psubw) X(1, 0xfa, 1, 2, 2, psubd) X(1, 0xfb, 2, 3, 3, psubq) \
    X(1, 0xec, 0, 0, 0, paddsb) X(1, 0xed, 0, 1, 0, paddsw) X(1, 0xdc, 0, 0, 0, paddusb) X(1, 0xdd, 0, 1, 0, paddusw) \
    X(1, 0xe8, 0, 0, 0, psubsb) X(1, 0xe9, 0, 1, 0, psubsw) X(1, 0xd8, 0, 0, 0, psubusb) X(1, 0xd9, 0, 1, 0, psubusw) \
    X(1, 0xdb, 1, 2, 2, pand) X(1, 0xdb, 2, 3, 3, pand) X(1, 0xdf, 1, 2, 2, pandn) X(1, 0xdf, 2, 3, 3, pandn) \
    X(1, 0xeb, 1, 2, 2, por) X(1, 0xeb, 2, 3, 3, por) X(1, 0xef, 1, 2, 2, pxor) X(1, 0xef, 2, 3, 3, pxor) \
    X(1, 0xda, 0, 0, 0, pminub) X(1, 0xde, 0, 0, 0, pmaxub) X(1, 0xea, 0, 1, 0, pminsw) X(1, 0xee, 0, 1, 0, pmaxsw) \
    X(1, 0xe0, 0, 0, 0, pavgb) X(1, 0xe3, 0, 1, 0, pavgw) X(1, 0xd5, 0, 1, 0, pmullw) X(1, 0xe5, 0, 1, 0, pmulhw) \
    X(1, 0xe4, 0, 1, 0, pmulhuw) X(1, 0xf4, 2, 3, 3, pmuludq) X(1, 0xf5, 0, 2, 0, pmaddwd) \
    X(1, 0x60, 0, 0, 0, punpcklbw) X(1, 0x61, 0, 1, 0, punpcklwd) X(1, 0x62, 1, 2, 2, punpckldq) \
    X(1, 0x6c, 2, 3, 3, punpcklqdq) X(1, 0x68, 0, 0, 0, punpckhbw) X(1, 0x69, 0, 1, 0, punpckhwd) \
    X(1, 0x6a, 1, 2, 2, punpckhdq) X(1, 0x6d, 2, 3, 3, punpckhqdq) X(1, 0x63, 0, 0, 0, packsswb) \
    X(1, 0x67, 0, 0, 0, packuswb) X(1, 0x6b, 1, 1, 2, packssdw) \
    X(2, 0x00, 0, 0, 0, pshufb) X(2, 0x04, 0, 1, 0, pmaddubsw) X(2, 0x0b, 0, 1, 0, pmulhrsw) \
    X(2, 0x28, 2, 3, 3, pmuldq) X(2, 0x2b, 1, 1, 2, packusdw) X(2, 0x38, 0, 0, 0, pminsb) \
    X(2, 0x39, 1, 2, 2, pminsd) X(2, 0x3a, 0, 1, 0, pminuw) X(2, 0x3b, 1, 2, 2, pminud) X(2, 0x3c, 0, 0, 0, pmaxsb) \
    X(2, 0x3d, 1, 2, 2, pmaxsd) X(2, 0x3e, 0, 1, 0, pmaxuw) X(2, 0x3f, 1, 2, 2, pmaxud) X(2, 0x40, 1, 2, 2, pmulld)
#define EVEX_INT_UN(X) X(2, 0x1c, 0, 0, 0, pabsb) X(2, 0x1d, 0, 1, 0, pabsw) X(2, 0x1e, 1, 2, 2, pabsd)
#define EVEX_DECL(map, op, w, esz, bc, n) void aok_gadget_x86_evex_vi_##n(void);
EVEX_INT(EVEX_DECL) EVEX_INT_UN(EVEX_DECL)
void aok_gadget_x86_evex_mov(void), aok_gadget_x86_evex_vi_psadbw(void);
void aok_gadget_x86_evex_compress0(void), aok_gadget_x86_evex_compress1(void), aok_gadget_x86_evex_compress2(void), aok_gadget_x86_evex_compress3(void), aok_gadget_x86_evex_expand0(void), aok_gadget_x86_evex_expand1(void), aok_gadget_x86_evex_expand2(void), aok_gadget_x86_evex_expand3(void), aok_gadget_x86_evex_pmov0xbd(void), aok_gadget_x86_evex_pmov0xbq(void), aok_gadget_x86_evex_pmov0xbw(void), aok_gadget_x86_evex_pmov0xdq(void), aok_gadget_x86_evex_pmov0xwd(void), aok_gadget_x86_evex_pmov0xwq(void), aok_gadget_x86_evex_pmov1xbd(void), aok_gadget_x86_evex_pmov1xbq(void), aok_gadget_x86_evex_pmov1xbw(void), aok_gadget_x86_evex_pmov1xdq(void), aok_gadget_x86_evex_pmov1xwd(void), aok_gadget_x86_evex_pmov1xwq(void), aok_gadget_x86_evex_pmov_sqxtn_db(void), aok_gadget_x86_evex_pmov_sqxtn_dw(void), aok_gadget_x86_evex_pmov_sqxtn_qb(void), aok_gadget_x86_evex_pmov_sqxtn_qd(void), aok_gadget_x86_evex_pmov_sqxtn_qw(void), aok_gadget_x86_evex_pmov_sqxtn_wb(void), aok_gadget_x86_evex_pmov_uqxtn_db(void), aok_gadget_x86_evex_pmov_uqxtn_dw(void), aok_gadget_x86_evex_pmov_uqxtn_qb(void), aok_gadget_x86_evex_pmov_uqxtn_qd(void), aok_gadget_x86_evex_pmov_uqxtn_qw(void), aok_gadget_x86_evex_pmov_uqxtn_wb(void), aok_gadget_x86_evex_pmov_xtn_db(void), aok_gadget_x86_evex_pmov_xtn_dw(void), aok_gadget_x86_evex_pmov_xtn_qb(void), aok_gadget_x86_evex_pmov_xtn_qd(void), aok_gadget_x86_evex_pmov_xtn_qw(void), aok_gadget_x86_evex_pmov_xtn_wb(void);
void aok_gadget_x86_evex_fma_maddsub132ps(void), aok_gadget_x86_evex_fma_maddsub132pd(void), aok_gadget_x86_evex_fma_msubadd132ps(void), aok_gadget_x86_evex_fma_msubadd132pd(void), aok_gadget_x86_evex_fma_madd132ps(void), aok_gadget_x86_evex_fma_madd132pd(void), aok_gadget_x86_evex_fma_madd132ss(void), aok_gadget_x86_evex_fma_madd132sd(void), aok_gadget_x86_evex_fma_msub132ps(void), aok_gadget_x86_evex_fma_msub132pd(void), aok_gadget_x86_evex_fma_msub132ss(void), aok_gadget_x86_evex_fma_msub132sd(void), aok_gadget_x86_evex_fma_nmadd132ps(void), aok_gadget_x86_evex_fma_nmadd132pd(void), aok_gadget_x86_evex_fma_nmadd132ss(void), aok_gadget_x86_evex_fma_nmadd132sd(void), aok_gadget_x86_evex_fma_nmsub132ps(void), aok_gadget_x86_evex_fma_nmsub132pd(void), aok_gadget_x86_evex_fma_nmsub132ss(void), aok_gadget_x86_evex_fma_nmsub132sd(void), aok_gadget_x86_evex_fma_maddsub213ps(void), aok_gadget_x86_evex_fma_maddsub213pd(void), aok_gadget_x86_evex_fma_msubadd213ps(void), aok_gadget_x86_evex_fma_msubadd213pd(void), aok_gadget_x86_evex_fma_madd213ps(void), aok_gadget_x86_evex_fma_madd213pd(void), aok_gadget_x86_evex_fma_madd213ss(void), aok_gadget_x86_evex_fma_madd213sd(void), aok_gadget_x86_evex_fma_msub213ps(void), aok_gadget_x86_evex_fma_msub213pd(void), aok_gadget_x86_evex_fma_msub213ss(void), aok_gadget_x86_evex_fma_msub213sd(void), aok_gadget_x86_evex_fma_nmadd213ps(void), aok_gadget_x86_evex_fma_nmadd213pd(void), aok_gadget_x86_evex_fma_nmadd213ss(void), aok_gadget_x86_evex_fma_nmadd213sd(void), aok_gadget_x86_evex_fma_nmsub213ps(void), aok_gadget_x86_evex_fma_nmsub213pd(void), aok_gadget_x86_evex_fma_nmsub213ss(void), aok_gadget_x86_evex_fma_nmsub213sd(void), aok_gadget_x86_evex_fma_maddsub231ps(void), aok_gadget_x86_evex_fma_maddsub231pd(void), aok_gadget_x86_evex_fma_msubadd231ps(void), aok_gadget_x86_evex_fma_msubadd231pd(void), aok_gadget_x86_evex_fma_madd231ps(void), aok_gadget_x86_evex_fma_madd231pd(void), aok_gadget_x86_evex_fma_madd231ss(void), aok_gadget_x86_evex_fma_madd231sd(void), aok_gadget_x86_evex_fma_msub231ps(void), aok_gadget_x86_evex_fma_msub231pd(void), aok_gadget_x86_evex_fma_msub231ss(void), aok_gadget_x86_evex_fma_msub231sd(void), aok_gadget_x86_evex_fma_nmadd231ps(void), aok_gadget_x86_evex_fma_nmadd231pd(void), aok_gadget_x86_evex_fma_nmadd231ss(void), aok_gadget_x86_evex_fma_nmadd231sd(void), aok_gadget_x86_evex_fma_nmsub231ps(void), aok_gadget_x86_evex_fma_nmsub231pd(void), aok_gadget_x86_evex_fma_nmsub231ss(void), aok_gadget_x86_evex_fma_nmsub231sd(void);
void aok_gadget_x86_evex_rcp14ps(void), aok_gadget_x86_evex_rcp14pd(void), aok_gadget_x86_evex_rcp14ss(void), aok_gadget_x86_evex_rcp14sd(void);
void aok_gadget_x86_evex_rsqrt14ps(void), aok_gadget_x86_evex_rsqrt14pd(void), aok_gadget_x86_evex_rsqrt14ss(void), aok_gadget_x86_evex_rsqrt14sd(void);
void aok_gadget_x86_evex_getexpps(void), aok_gadget_x86_evex_getexppd(void), aok_gadget_x86_evex_getexpss(void), aok_gadget_x86_evex_getexpsd(void);
void aok_gadget_x86_evex_getmantps(void), aok_gadget_x86_evex_getmantpd(void), aok_gadget_x86_evex_getmantss(void), aok_gadget_x86_evex_getmantsd(void);
void aok_gadget_x86_evex_rndscaleps(void), aok_gadget_x86_evex_rndscalepd(void), aok_gadget_x86_evex_rndscaless(void), aok_gadget_x86_evex_rndscalesd(void);
void aok_gadget_x86_evex_reduceps(void), aok_gadget_x86_evex_reducepd(void), aok_gadget_x86_evex_reducess(void), aok_gadget_x86_evex_reducesd(void);
void aok_gadget_x86_evex_scalefps(void), aok_gadget_x86_evex_scalefpd(void), aok_gadget_x86_evex_scalefss(void), aok_gadget_x86_evex_scalefsd(void);
void aok_gadget_x86_evex_rangeps(void), aok_gadget_x86_evex_rangepd(void), aok_gadget_x86_evex_rangess(void), aok_gadget_x86_evex_rangesd(void);
void aok_gadget_x86_evex_fpclassps(void), aok_gadget_x86_evex_fpclasspd(void), aok_gadget_x86_evex_fpclassss(void), aok_gadget_x86_evex_fpclasssd(void);
void aok_gadget_x86_evex_fixupimmps(void), aok_gadget_x86_evex_fixupimmpd(void), aok_gadget_x86_evex_fixupimmss(void), aok_gadget_x86_evex_fixupimmsd(void);
void aok_gadget_x86_evex_cvtdq2ps(void), aok_gadget_x86_evex_cvtudq2ps(void), aok_gadget_x86_evex_cvtqq2pd(void), aok_gadget_x86_evex_cvtuqq2pd(void), aok_gadget_x86_evex_cvtps2dq(void), aok_gadget_x86_evex_cvttps2dq(void), aok_gadget_x86_evex_cvtps2udq(void), aok_gadget_x86_evex_cvttps2udq(void), aok_gadget_x86_evex_cvtpd2qq(void), aok_gadget_x86_evex_cvttpd2qq(void), aok_gadget_x86_evex_cvtpd2uqq(void), aok_gadget_x86_evex_cvttpd2uqq(void);
void aok_gadget_x86_evex_cvtps2pd(void), aok_gadget_x86_evex_cvtdq2pd(void), aok_gadget_x86_evex_cvtudq2pd(void), aok_gadget_x86_evex_cvtps2qq(void), aok_gadget_x86_evex_cvttps2qq(void), aok_gadget_x86_evex_cvtps2uqq(void), aok_gadget_x86_evex_cvttps2uqq(void), aok_gadget_x86_evex_cvtpd2ps(void), aok_gadget_x86_evex_cvtqq2ps(void), aok_gadget_x86_evex_cvtuqq2ps(void), aok_gadget_x86_evex_cvtpd2dq(void), aok_gadget_x86_evex_cvttpd2dq(void), aok_gadget_x86_evex_cvtpd2udq(void), aok_gadget_x86_evex_cvttpd2udq(void);
void aok_gadget_x86_evex_cvtss2si32_0(void), aok_gadget_x86_evex_cvtss2si64_0(void), aok_gadget_x86_evex_cvtss2si32_1(void), aok_gadget_x86_evex_cvtss2si64_1(void), aok_gadget_x86_evex_cvttss2si32_0(void), aok_gadget_x86_evex_cvttss2si64_0(void), aok_gadget_x86_evex_cvttss2si32_1(void), aok_gadget_x86_evex_cvttss2si64_1(void), aok_gadget_x86_evex_cvtsi2ss32(void), aok_gadget_x86_evex_cvtsi2ss64(void), aok_gadget_x86_evex_cvtusi2ss32(void), aok_gadget_x86_evex_cvtusi2ss64(void), aok_gadget_x86_evex_cvtsd2si32_0(void), aok_gadget_x86_evex_cvtsd2si64_0(void), aok_gadget_x86_evex_cvtsd2si32_1(void), aok_gadget_x86_evex_cvtsd2si64_1(void), aok_gadget_x86_evex_cvttsd2si32_0(void), aok_gadget_x86_evex_cvttsd2si64_0(void), aok_gadget_x86_evex_cvttsd2si32_1(void), aok_gadget_x86_evex_cvttsd2si64_1(void), aok_gadget_x86_evex_cvtsi2sd32(void), aok_gadget_x86_evex_cvtsi2sd64(void), aok_gadget_x86_evex_cvtusi2sd32(void), aok_gadget_x86_evex_cvtusi2sd64(void), aok_gadget_x86_evex_cvtss2sd(void), aok_gadget_x86_evex_cvtsd2ss(void);
void aok_gadget_x86_evex_cvtph2ps(void), aok_gadget_x86_evex_cvtps2ph(void);
void aok_gadget_x86_evex_movsldup(void), aok_gadget_x86_evex_movshdup(void), aok_gadget_x86_evex_movddup(void), aok_gadget_x86_evex_bcastmb2q(void), aok_gadget_x86_evex_bcastmw2d(void), aok_gadget_x86_evex_comiss(void), aok_gadget_x86_evex_ucomiss(void), aok_gadget_x86_evex_comisd(void), aok_gadget_x86_evex_ucomisd(void);
void aok_gadget_x86_evex_insb(void), aok_gadget_x86_evex_insw(void), aok_gadget_x86_evex_insd(void), aok_gadget_x86_evex_insq(void), aok_gadget_x86_evex_extrb(void), aok_gadget_x86_evex_extrw(void), aok_gadget_x86_evex_extrd(void), aok_gadget_x86_evex_extrq(void), aok_gadget_x86_evex_insertps(void), aok_gadget_x86_evex_movlo(void), aok_gadget_x86_evex_movhi(void), aok_gadget_x86_evex_hi2lo(void), aok_gadget_x86_evex_movss(void), aok_gadget_x86_evex_movsd(void), aok_gadget_x86_evex_movq0(void);
void aok_gadget_x86_evex_dbpsadbw(void), aok_gadget_x86_evex_cvtneps2bf16(void), aok_gadget_x86_evex_cvtne2ps2bf16(void), aok_gadget_x86_evex_dpbf16ps(void);
void aok_gadget_x86_evex_aesenc(void), aok_gadget_x86_evex_aesenclast(void), aok_gadget_x86_evex_aesdec(void), aok_gadget_x86_evex_aesdeclast(void), aok_gadget_x86_evex_aesimc(void), aok_gadget_x86_evex_aeskeygenassist(void), aok_gadget_x86_evex_pclmulqdq(void);
void aok_gadget_x86_evex_pmultishiftqb(void), aok_gadget_x86_evex_pshldw(void), aok_gadget_x86_evex_pshldd(void), aok_gadget_x86_evex_pshldq(void), aok_gadget_x86_evex_pshrdw(void), aok_gadget_x86_evex_pshrdd(void), aok_gadget_x86_evex_pshrdq(void), aok_gadget_x86_evex_pshldvw(void), aok_gadget_x86_evex_pshldvd(void), aok_gadget_x86_evex_pshldvq(void), aok_gadget_x86_evex_pshrdvw(void), aok_gadget_x86_evex_pshrdvd(void), aok_gadget_x86_evex_pshrdvq(void), aok_gadget_x86_evex_pdpbusd(void), aok_gadget_x86_evex_pdpbusds(void), aok_gadget_x86_evex_pdpwssd(void), aok_gadget_x86_evex_pdpwssds(void), aok_gadget_x86_evex_pmadd52luq(void), aok_gadget_x86_evex_pmadd52huq(void), aok_gadget_x86_evex_popcntb(void), aok_gadget_x86_evex_popcntw(void), aok_gadget_x86_evex_pshufbitqmb(void), aok_gadget_x86_evex_gf2p8mulb(void), aok_gadget_x86_evex_gf2p8affineqb(void), aok_gadget_x86_evex_gf2p8affineinvqb(void);
void aok_gadget_x86_evex_pconflictd(void), aok_gadget_x86_evex_pconflictq(void), aok_gadget_x86_evex_plzcntd(void), aok_gadget_x86_evex_plzcntq(void), aok_gadget_x86_evex_pmovb2m(void), aok_gadget_x86_evex_pmovd2m(void), aok_gadget_x86_evex_pmovm2b(void), aok_gadget_x86_evex_pmovm2d(void), aok_gadget_x86_evex_pmovm2q(void), aok_gadget_x86_evex_pmovm2w(void), aok_gadget_x86_evex_pmovq2m(void), aok_gadget_x86_evex_pmovw2m(void), aok_gadget_x86_evex_popcntd(void), aok_gadget_x86_evex_popcntq(void);
void aok_gadget_x86_evex_alignd(void), aok_gadget_x86_evex_alignq(void), aok_gadget_x86_evex_extract(void), aok_gadget_x86_evex_insert(void), aok_gadget_x86_evex_palignr(void), aok_gadget_x86_evex_permb(void), aok_gadget_x86_evex_permd(void), aok_gadget_x86_evex_permi2b(void), aok_gadget_x86_evex_permi2d(void), aok_gadget_x86_evex_permi2q(void), aok_gadget_x86_evex_permi2w(void), aok_gadget_x86_evex_permilpd_i(void), aok_gadget_x86_evex_permilpd_v(void), aok_gadget_x86_evex_permilps_v(void), aok_gadget_x86_evex_permq(void), aok_gadget_x86_evex_permqi(void), aok_gadget_x86_evex_permt2b(void), aok_gadget_x86_evex_permt2d(void), aok_gadget_x86_evex_permt2q(void), aok_gadget_x86_evex_permt2w(void), aok_gadget_x86_evex_permw(void), aok_gadget_x86_evex_pshufd(void), aok_gadget_x86_evex_pshufhw(void), aok_gadget_x86_evex_pshuflw(void), aok_gadget_x86_evex_shuf4(void), aok_gadget_x86_evex_shufpd(void), aok_gadget_x86_evex_shufps(void);
void aok_gadget_x86_evex_xf_addpd(void), aok_gadget_x86_evex_xf_addps(void), aok_gadget_x86_evex_xf_addsd(void), aok_gadget_x86_evex_xf_addss(void), aok_gadget_x86_evex_xf_cmppd(void), aok_gadget_x86_evex_xf_cmpps(void), aok_gadget_x86_evex_xf_cmpsd(void), aok_gadget_x86_evex_xf_cmpss(void), aok_gadget_x86_evex_xf_divpd(void), aok_gadget_x86_evex_xf_divps(void), aok_gadget_x86_evex_xf_divsd(void), aok_gadget_x86_evex_xf_divss(void), aok_gadget_x86_evex_xf_maxpd(void), aok_gadget_x86_evex_xf_maxps(void), aok_gadget_x86_evex_xf_maxsd(void), aok_gadget_x86_evex_xf_maxss(void), aok_gadget_x86_evex_xf_minpd(void), aok_gadget_x86_evex_xf_minps(void), aok_gadget_x86_evex_xf_minsd(void), aok_gadget_x86_evex_xf_minss(void), aok_gadget_x86_evex_xf_mulpd(void), aok_gadget_x86_evex_xf_mulps(void), aok_gadget_x86_evex_xf_mulsd(void), aok_gadget_x86_evex_xf_mulss(void), aok_gadget_x86_evex_xf_sqrtpd(void), aok_gadget_x86_evex_xf_sqrtps(void), aok_gadget_x86_evex_xf_sqrtsd(void), aok_gadget_x86_evex_xf_sqrtss(void), aok_gadget_x86_evex_xf_subpd(void), aok_gadget_x86_evex_xf_subps(void), aok_gadget_x86_evex_xf_subsd(void), aok_gadget_x86_evex_xf_subss(void);
void aok_gadget_x86_evex_bcast_b(void), aok_gadget_x86_evex_bcast_d(void), aok_gadget_x86_evex_bcast_q(void), aok_gadget_x86_evex_bcast_w(void), aok_gadget_x86_evex_blendm(void), aok_gadget_x86_evex_pabsq(void), aok_gadget_x86_evex_pmaxsq(void), aok_gadget_x86_evex_pmaxuq(void), aok_gadget_x86_evex_pminsq(void), aok_gadget_x86_evex_pminuq(void), aok_gadget_x86_evex_pmullq(void), aok_gadget_x86_evex_pslldq(void), aok_gadget_x86_evex_psrldq(void), aok_gadget_x86_evex_pternlog(void), aok_gadget_x86_evex_roli_d(void), aok_gadget_x86_evex_roli_q(void), aok_gadget_x86_evex_rolv_d(void), aok_gadget_x86_evex_rolv_q(void), aok_gadget_x86_evex_rori_d(void), aok_gadget_x86_evex_rori_q(void), aok_gadget_x86_evex_rorv_d(void), aok_gadget_x86_evex_rorv_q(void), aok_gadget_x86_evex_shi_slld(void), aok_gadget_x86_evex_shi_sllq(void), aok_gadget_x86_evex_shi_sllw(void), aok_gadget_x86_evex_shi_srad(void), aok_gadget_x86_evex_shi_sraq(void), aok_gadget_x86_evex_shi_sraw(void), aok_gadget_x86_evex_shi_srld(void), aok_gadget_x86_evex_shi_srlq(void), aok_gadget_x86_evex_shi_srlw(void), aok_gadget_x86_evex_shv_slld(void), aok_gadget_x86_evex_shv_sllq(void), aok_gadget_x86_evex_shv_sllw(void), aok_gadget_x86_evex_shv_srad(void), aok_gadget_x86_evex_shv_sraq(void), aok_gadget_x86_evex_shv_sraw(void), aok_gadget_x86_evex_shv_srld(void), aok_gadget_x86_evex_shv_srlq(void), aok_gadget_x86_evex_shv_srlw(void), aok_gadget_x86_evex_shx_slld(void), aok_gadget_x86_evex_shx_sllq(void), aok_gadget_x86_evex_shx_sllw(void), aok_gadget_x86_evex_shx_srad(void), aok_gadget_x86_evex_shx_sraq(void), aok_gadget_x86_evex_shx_sraw(void), aok_gadget_x86_evex_shx_srld(void), aok_gadget_x86_evex_shx_srlq(void), aok_gadget_x86_evex_shx_srlw(void);
void aok_gadget_x86_evex_pcmpeqb(void), aok_gadget_x86_evex_pcmpeqw(void), aok_gadget_x86_evex_pcmpeqd(void), aok_gadget_x86_evex_pcmpeqq(void), aok_gadget_x86_evex_pcmpgtb(void), aok_gadget_x86_evex_pcmpgtw(void), aok_gadget_x86_evex_pcmpgtd(void), aok_gadget_x86_evex_pcmpgtq(void), aok_gadget_x86_evex_pcmpb(void), aok_gadget_x86_evex_pcmpw(void), aok_gadget_x86_evex_pcmpd(void), aok_gadget_x86_evex_pcmpq(void), aok_gadget_x86_evex_pcmpub(void), aok_gadget_x86_evex_pcmpuw(void), aok_gadget_x86_evex_pcmpud(void), aok_gadget_x86_evex_pcmpuq(void), aok_gadget_x86_evex_ptestmb(void), aok_gadget_x86_evex_ptestmw(void), aok_gadget_x86_evex_ptestmd(void), aok_gadget_x86_evex_ptestmq(void), aok_gadget_x86_evex_ptestnmb(void), aok_gadget_x86_evex_ptestnmw(void), aok_gadget_x86_evex_ptestnmd(void), aok_gadget_x86_evex_ptestnmq(void);

#define EVEX_ROW(map, op, w, esz, bc, n) {map, 1, op, EVK_L3, w, esz, bc, bc ? EVT_FV : EVT_FVM, 0, 0, aok_gadget_x86_evex_vi_##n, 0, 0, 0, 0},
#define EVEX_ROW_UN(map, op, w, esz, bc, n) {map, 1, op, EVK_L2, w, esz, bc, bc ? EVT_FV : EVT_FVM, 0, 0, aok_gadget_x86_evex_vi_##n, 0, 0, 0, 0},
static const struct evex_entry evex_table[] = {
    // the moves: VMOVDQA32/64, VMOVDQU8/16/32/64, VMOVUPS/PD, VMOVAPS/PD
    {1, 1, 0x6f, EVK_LOAD, 1, 2, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 1, 0x6f, EVK_LOAD, 2, 3, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 2, 0x6f, EVK_LOAD, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 2, 0x6f, EVK_LOAD, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 3, 0x6f, EVK_LOAD, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 3, 0x6f, EVK_LOAD, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 1, 0x7f, EVK_STORE, 1, 2, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 1, 0x7f, EVK_STORE, 2, 3, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 2, 0x7f, EVK_STORE, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 2, 0x7f, EVK_STORE, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 3, 0x7f, EVK_STORE, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 3, 0x7f, EVK_STORE, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 0, 0x10, EVK_LOAD, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 1, 0x10, EVK_LOAD, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 0, 0x11, EVK_STORE, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 1, 0x11, EVK_STORE, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 0, 0x28, EVK_LOAD, 1, 2, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 1, 0x28, EVK_LOAD, 2, 3, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    {1, 0, 0x29, EVK_STORE, 1, 2, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0}, {1, 1, 0x29, EVK_STORE, 2, 3, 0, EVT_FVM, 1, 0, aok_gadget_x86_evex_mov, 0, 0, 0, 0},
    // the integer ops (vex.inc's bodies); VPSADBW takes no mask
    EVEX_INT(EVEX_ROW) EVEX_INT_UN(EVEX_ROW_UN)
    {1, 1, 0xf6, EVK_L3, 0, 3, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_vi_psadbw, 0, 0, 0, 0},
    // the compares and tests into an opmask
    {1, 1, 0x74, EVK_TOMASK, 0, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpeqb, 0, 0, 0, 0},
    {1, 1, 0x75, EVK_TOMASK, 0, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpeqw, 0, 0, 0, 0},
    {1, 1, 0x76, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpeqd, 0, 0, 0, 0},
    {1, 1, 0x64, EVK_TOMASK, 0, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpgtb, 0, 0, 0, 0},
    {1, 1, 0x65, EVK_TOMASK, 0, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpgtw, 0, 0, 0, 0},
    {1, 1, 0x66, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpgtd, 0, 0, 0, 0},
    {2, 1, 0x29, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpeqq, 0, 0, 0, 0},
    {2, 1, 0x37, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpgtq, 0, 0, 0, 0},
    {3, 1, 0x3f, EVK_TOMASK, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpb, 0, 0, 0, 0},
    {3, 1, 0x3f, EVK_TOMASK, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpw, 0, 0, 0, 0},
    {3, 1, 0x3e, EVK_TOMASK, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpub, 0, 0, 0, 0},
    {3, 1, 0x3e, EVK_TOMASK, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pcmpuw, 0, 0, 0, 0},
    {3, 1, 0x1f, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpd, 0, 0, 0, 0},
    {3, 1, 0x1f, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpq, 0, 0, 0, 0},
    {3, 1, 0x1e, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpud, 0, 0, 0, 0},
    {3, 1, 0x1e, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pcmpuq, 0, 0, 0, 0},
    {2, 1, 0x26, EVK_TOMASK, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_ptestmb, 0, 0, 0, 0},
    {2, 1, 0x26, EVK_TOMASK, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_ptestmw, 0, 0, 0, 0},
    {2, 1, 0x27, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_ptestmd, 0, 0, 0, 0},
    {2, 1, 0x27, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_ptestmq, 0, 0, 0, 0},
    {2, 2, 0x26, EVK_TOMASK, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_ptestnmb, 0, 0, 0, 0},
    {2, 2, 0x26, EVK_TOMASK, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_ptestnmw, 0, 0, 0, 0},
    {2, 2, 0x27, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_ptestnmd, 0, 0, 0, 0},
    {2, 2, 0x27, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_ptestnmq, 0, 0, 0, 0},
    // the shifts and rotates, the qword ops, VPTERNLOG, VPBLENDM, the broadcasts, the non-temporal moves
    {1, 1, 0x71, EVK_SHI, 0, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_shi_srlw, 3, 0, 0, 0},
    {1, 1, 0x71, EVK_SHI, 0, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_shi_sraw, 5, 0, 0, 0},
    {1, 1, 0x71, EVK_SHI, 0, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_shi_sllw, 7, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_rori_d, 1, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_rori_q, 1, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_roli_d, 2, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_roli_q, 2, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shi_srld, 3, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shi_srad, 5, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shi_sraq, 5, 0, 0, 0},
    {1, 1, 0x72, EVK_SHI, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shi_slld, 7, 0, 0, 0},
    {1, 1, 0x73, EVK_SHI, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shi_srlq, 3, 0, 0, 0},
    {1, 1, 0x73, EVK_SHI, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shi_sllq, 7, 0, 0, 0},
    {1, 1, 0x73, EVK_SHI, 0, 3, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_psrldq, 4, 0, 0, 0},
    {1, 1, 0x73, EVK_SHI, 0, 3, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_pslldq, 8, 0, 0, 0},
    {1, 1, 0xd1, EVK_L3, 0, 1, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_srlw, 0, 1, 16, 0},
    {1, 1, 0xd2, EVK_L3, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_srld, 0, 1, 16, 0},
    {1, 1, 0xd3, EVK_L3, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_srlq, 0, 1, 16, 0},
    {1, 1, 0xe1, EVK_L3, 0, 1, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_sraw, 0, 1, 16, 0},
    {1, 1, 0xe2, EVK_L3, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_srad, 0, 1, 16, 0},
    {1, 1, 0xe2, EVK_L3, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_sraq, 0, 1, 16, 0},
    {1, 1, 0xf1, EVK_L3, 0, 1, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_sllw, 0, 1, 16, 0},
    {1, 1, 0xf2, EVK_L3, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_slld, 0, 1, 16, 0},
    {1, 1, 0xf3, EVK_L3, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_shx_sllq, 0, 1, 16, 0},
    {2, 1, 0x45, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shv_srld, 0, 0, 0, 0},
    {2, 1, 0x45, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shv_srlq, 0, 0, 0, 0},
    {2, 1, 0x46, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shv_srad, 0, 0, 0, 0},
    {2, 1, 0x46, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shv_sraq, 0, 0, 0, 0},
    {2, 1, 0x47, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shv_slld, 0, 0, 0, 0},
    {2, 1, 0x47, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shv_sllq, 0, 0, 0, 0},
    {2, 1, 0x10, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_shv_srlw, 0, 0, 0, 0},
    {2, 1, 0x11, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_shv_sraw, 0, 0, 0, 0},
    {2, 1, 0x12, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_shv_sllw, 0, 0, 0, 0},
    {2, 1, 0x15, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_rolv_d, 0, 0, 0, 0},
    {2, 1, 0x15, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_rolv_q, 0, 0, 0, 0},
    {2, 1, 0x14, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_rorv_d, 0, 0, 0, 0},
    {2, 1, 0x14, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_rorv_q, 0, 0, 0, 0},
    {2, 1, 0x39, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pminsq, 0, 0, 0, 0},
    {2, 1, 0x3b, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pminuq, 0, 0, 0, 0},
    {2, 1, 0x3d, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pmaxsq, 0, 0, 0, 0},
    {2, 1, 0x3f, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pmaxuq, 0, 0, 0, 0},
    {2, 1, 0x40, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pmullq, 0, 0, 0, 0},
    {2, 1, 0x1f, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pabsq, 0, 0, 0, 0},
    {3, 1, 0x25, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pternlog, 0, 8, 0, 0},
    {3, 1, 0x25, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pternlog, 0, 8, 0, 0},
    {2, 1, 0x64, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_blendm, 0, 4, 0, 0},
    {2, 1, 0x64, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_blendm, 0, 4, 0, 0},
    {2, 1, 0x65, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_blendm, 0, 4, 0, 0},
    {2, 1, 0x65, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_blendm, 0, 4, 0, 0},
    {2, 1, 0x66, EVK_L3, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_blendm, 0, 4, 0, 0},
    {2, 1, 0x66, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_blendm, 0, 4, 0, 0},
    {2, 1, 0x78, EVK_BCAST, 1, 0, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_b, 0, 1, 1, 0},
    {2, 1, 0x79, EVK_BCAST, 1, 1, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_w, 0, 1, 2, 0},
    {2, 1, 0x58, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_d, 0, 1, 4, 0},
    {2, 1, 0x59, EVK_BCAST, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_q, 0, 1, 8, 0},
    {2, 1, 0x59, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_q, 0, 1, 8, 0},
    {2, 1, 0x18, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_d, 0, 1, 4, 0},
    {2, 1, 0x19, EVK_BCAST, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_q, 0, 65, 8, 0},
    {2, 1, 0x19, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_bcast_q, 0, 65, 8, 0},
    {2, 1, 0x5a, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 81, 16, 0},
    {2, 1, 0x5a, EVK_BCAST, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 81, 16, 0},
    {2, 1, 0x1a, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 81, 16, 0},
    {2, 1, 0x1a, EVK_BCAST, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 81, 16, 0},
    {2, 1, 0x5b, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 146, 32, 0},
    {2, 1, 0x5b, EVK_BCAST, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 146, 32, 0},
    {2, 1, 0x1b, EVK_BCAST, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 146, 32, 0},
    {2, 1, 0x1b, EVK_BCAST, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_mov, 0, 146, 32, 0},
    {2, 1, 0x7a, EVK_BCASTG, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_bcast_b, 0, 33, 0, 0},
    {2, 1, 0x7b, EVK_BCASTG, 1, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_bcast_w, 0, 33, 0, 0},
    {2, 1, 0x7c, EVK_BCASTG, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_bcast_d, 0, 33, 0, 0},
    {2, 1, 0x7c, EVK_BCASTG, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_bcast_q, 0, 33, 0, 0},
    {1, 1, 0xe7, EVK_STORE, 1, 2, 0, EVT_FVM, 1, 1, aok_gadget_x86_evex_mov, 0, 16, 0, 0},
    {1, 0, 0x2b, EVK_STORE, 1, 2, 0, EVT_FVM, 1, 1, aok_gadget_x86_evex_mov, 0, 16, 0, 0},
    {1, 1, 0x2b, EVK_STORE, 2, 3, 0, EVT_FVM, 1, 1, aok_gadget_x86_evex_mov, 0, 16, 0, 0},
    {2, 1, 0x2a, EVK_LOAD, 1, 2, 0, EVT_FVM, 1, 1, aok_gadget_x86_evex_mov, 0, 16, 0, 0},
    // floating point
    {1, 0, 0x58, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_addps, 0, 0, 0, 1},
    {1, 1, 0x58, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_addpd, 0, 0, 0, 1},
    {1, 2, 0x58, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_addss, 0, 0, 4, 1},
    {1, 3, 0x58, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_addsd, 0, 0, 8, 1},
    {1, 0, 0x59, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_mulps, 0, 0, 0, 1},
    {1, 1, 0x59, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_mulpd, 0, 0, 0, 1},
    {1, 2, 0x59, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_mulss, 0, 0, 4, 1},
    {1, 3, 0x59, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_mulsd, 0, 0, 8, 1},
    {1, 0, 0x5c, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_subps, 0, 0, 0, 1},
    {1, 1, 0x5c, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_subpd, 0, 0, 0, 1},
    {1, 2, 0x5c, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_subss, 0, 0, 4, 1},
    {1, 3, 0x5c, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_subsd, 0, 0, 8, 1},
    {1, 0, 0x5e, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_divps, 0, 0, 0, 1},
    {1, 1, 0x5e, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_divpd, 0, 0, 0, 1},
    {1, 2, 0x5e, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_divss, 0, 0, 4, 1},
    {1, 3, 0x5e, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_divsd, 0, 0, 8, 1},
    {1, 0, 0x5d, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_minps, 0, 0, 0, 2},
    {1, 1, 0x5d, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_minpd, 0, 0, 0, 2},
    {1, 2, 0x5d, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_minss, 0, 0, 4, 2},
    {1, 3, 0x5d, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_minsd, 0, 0, 8, 2},
    {1, 0, 0x5f, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_maxps, 0, 0, 0, 2},
    {1, 1, 0x5f, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_maxpd, 0, 0, 0, 2},
    {1, 2, 0x5f, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_maxss, 0, 0, 4, 2},
    {1, 3, 0x5f, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_maxsd, 0, 0, 8, 2},
    {1, 0, 0x51, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_sqrtps, 0, 0, 0, 1},
    {1, 1, 0x51, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_sqrtpd, 0, 0, 0, 1},
    {1, 2, 0x51, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_sqrtss, 0, 0, 4, 1},
    {1, 3, 0x51, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_sqrtsd, 0, 0, 8, 1},
    {1, 0, 0xc2, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_cmpps, 0, 0, 0, 2},
    {1, 1, 0xc2, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_xf_cmppd, 0, 0, 0, 2},
    {1, 2, 0xc2, EVK_TOMASKS, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_cmpss, 0, 0, 4, 2},
    {1, 3, 0xc2, EVK_TOMASKS, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_xf_cmpsd, 0, 0, 8, 2},
    // the lane-crossing ops (evex_full) and the in-lane shuffles
    {2, 1, 0x36, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_permd, 0, 64, 0, 0},
    {2, 1, 0x36, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permq, 0, 64, 0, 0},
    {2, 1, 0x16, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_permd, 0, 64, 0, 0},
    {2, 1, 0x16, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permq, 0, 64, 0, 0},
    {2, 1, 0x8d, EVK_FULL, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_permb, 0, 0, 0, 0},
    {2, 1, 0x8d, EVK_FULL, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_permw, 0, 0, 0, 0},
    {3, 1, 0x00, EVK_FULL1, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permqi, 0, 64, 0, 0},
    {3, 1, 0x01, EVK_FULL1, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permqi, 0, 64, 0, 0},
    {2, 1, 0x75, EVK_FULL, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_permi2b, 0, 0, 0, 0},
    {2, 1, 0x75, EVK_FULL, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_permi2w, 0, 0, 0, 0},
    {2, 1, 0x7d, EVK_FULL, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_permt2b, 0, 0, 0, 0},
    {2, 1, 0x7d, EVK_FULL, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_permt2w, 0, 0, 0, 0},
    {2, 1, 0x76, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_permi2d, 0, 0, 0, 0},
    {2, 1, 0x76, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permi2q, 0, 0, 0, 0},
    {2, 1, 0x77, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_permi2d, 0, 0, 0, 0},
    {2, 1, 0x77, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permi2q, 0, 0, 0, 0},
    {2, 1, 0x7e, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_permt2d, 0, 0, 0, 0},
    {2, 1, 0x7e, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permt2q, 0, 0, 0, 0},
    {2, 1, 0x7f, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_permt2d, 0, 0, 0, 0},
    {2, 1, 0x7f, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permt2q, 0, 0, 0, 0},
    {3, 1, 0x03, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_alignd, 0, 0, 0, 0},
    {3, 1, 0x03, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_alignq, 0, 0, 0, 0},
    {3, 1, 0x43, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shuf4, 0, 64, 0, 0},
    {3, 1, 0x43, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shuf4, 0, 64, 0, 0},
    {3, 1, 0x23, EVK_FULL, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shuf4, 0, 64, 0, 0},
    {3, 1, 0x23, EVK_FULL, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shuf4, 0, 64, 0, 0},
    {3, 1, 0x38, EVK_FULL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 64, 16, 0},
    {3, 1, 0x38, EVK_FULL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 64, 16, 0},
    {3, 1, 0x18, EVK_FULL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 64, 16, 0},
    {3, 1, 0x18, EVK_FULL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 64, 16, 0},
    {3, 1, 0x3a, EVK_FULL8, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 128, 32, 0},
    {3, 1, 0x3a, EVK_FULL8, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 128, 32, 0},
    {3, 1, 0x1a, EVK_FULL8, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 128, 32, 0},
    {3, 1, 0x1a, EVK_FULL8, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_insert, 0, 128, 32, 0},
    {3, 1, 0x39, EVK_EXTRACT, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 64, 16, 0},
    {3, 1, 0x39, EVK_EXTRACT, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 64, 16, 0},
    {3, 1, 0x19, EVK_EXTRACT, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 64, 16, 0},
    {3, 1, 0x19, EVK_EXTRACT, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 64, 16, 0},
    {3, 1, 0x3b, EVK_EXTRACT8, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 128, 32, 0},
    {3, 1, 0x3b, EVK_EXTRACT8, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 128, 32, 0},
    {3, 1, 0x1b, EVK_EXTRACT8, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 128, 32, 0},
    {3, 1, 0x1b, EVK_EXTRACT8, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_extract, 0, 128, 32, 0},
    {1, 1, 0x70, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pshufd, 0, 0, 0, 0},
    {1, 2, 0x70, EVK_L2, 0, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pshufhw, 0, 0, 0, 0},
    {1, 3, 0x70, EVK_L2, 0, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pshuflw, 0, 0, 0, 0},
    {1, 0, 0xc6, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_shufps, 0, 0, 0, 0},
    {1, 1, 0xc6, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_shufpd, 0, 0, 0, 0},
    {3, 1, 0x04, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pshufd, 0, 0, 0, 0},
    {3, 1, 0x05, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permilpd_i, 0, 0, 0, 0},
    {2, 1, 0x0c, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_permilps_v, 0, 0, 0, 0},
    {2, 1, 0x0d, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_permilpd_v, 0, 0, 0, 0},
    {3, 1, 0x0f, EVK_L3, 0, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_palignr, 0, 0, 0, 0},
    {1, 0, 0x14, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_punpckldq, 0, 0, 0, 0},
    {1, 0, 0x15, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_punpckhdq, 0, 0, 0, 0},
    {1, 1, 0x14, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_punpcklqdq, 0, 0, 0, 0},
    {1, 1, 0x15, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_punpckhqdq, 0, 0, 0, 0},
    // VPLZCNT, VPOPCNT, VPCONFLICT, the mask <-> vector moves
    {2, 1, 0x44, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_plzcntd, 0, 0, 0, 0},
    {2, 1, 0x44, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_plzcntq, 0, 0, 0, 0},
    {2, 1, 0x55, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_popcntd, 0, 0, 0, 0},
    {2, 1, 0x55, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_popcntq, 0, 0, 0, 0},
    {2, 1, 0xc4, EVK_FULL1, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pconflictd, 0, 0, 0, 0},
    {2, 1, 0xc4, EVK_FULL1, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pconflictq, 0, 0, 0, 0},
    {2, 2, 0x29, EVK_V2M, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovb2m, 0, 32, 0, 0},
    {2, 2, 0x29, EVK_V2M, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovw2m, 0, 32, 0, 0},
    {2, 2, 0x39, EVK_V2M, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovd2m, 0, 32, 0, 0},
    {2, 2, 0x39, EVK_V2M, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovq2m, 0, 32, 0, 0},
    {2, 2, 0x28, EVK_M2V, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovm2b, 0, 32, 0, 0},
    {2, 2, 0x28, EVK_M2V, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovm2w, 0, 32, 0, 0},
    {2, 2, 0x38, EVK_M2V, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovm2d, 0, 32, 0, 0},
    {2, 2, 0x38, EVK_M2V, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pmovm2q, 0, 32, 0, 0},
    // the extends, the narrowing moves, compress and expand
    {2, 1, 0x20, EVK_EXT, 0, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov1xbw, 0, 0, 1, 0},
    {2, 1, 0x21, EVK_EXT, 0, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov1xbd, 0, 0, 2, 0},
    {2, 1, 0x22, EVK_EXT, 0, 3, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov1xbq, 0, 0, 3, 0},
    {2, 1, 0x23, EVK_EXT, 0, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov1xwd, 0, 0, 1, 0},
    {2, 1, 0x24, EVK_EXT, 0, 3, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov1xwq, 0, 0, 2, 0},
    {2, 1, 0x25, EVK_EXT, 1, 3, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov1xdq, 0, 0, 1, 0},
    {2, 1, 0x30, EVK_EXT, 0, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov0xbw, 0, 0, 1, 0},
    {2, 1, 0x31, EVK_EXT, 0, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov0xbd, 0, 0, 2, 0},
    {2, 1, 0x32, EVK_EXT, 0, 3, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov0xbq, 0, 0, 3, 0},
    {2, 1, 0x33, EVK_EXT, 0, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov0xwd, 0, 0, 1, 0},
    {2, 1, 0x34, EVK_EXT, 0, 3, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov0xwq, 0, 0, 2, 0},
    {2, 1, 0x35, EVK_EXT, 1, 3, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov0xdq, 0, 0, 1, 0},
    {2, 2, 0x10, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_uqxtn_wb, 0, 0, 1, 0},
    {2, 2, 0x11, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_uqxtn_db, 0, 0, 2, 0},
    {2, 2, 0x12, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_uqxtn_qb, 0, 0, 3, 0},
    {2, 2, 0x13, EVK_NARROW, 1, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_uqxtn_dw, 0, 0, 1, 0},
    {2, 2, 0x14, EVK_NARROW, 1, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_uqxtn_qw, 0, 0, 2, 0},
    {2, 2, 0x15, EVK_NARROW, 1, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_uqxtn_qd, 0, 0, 1, 0},
    {2, 2, 0x20, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_sqxtn_wb, 0, 0, 1, 0},
    {2, 2, 0x21, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_sqxtn_db, 0, 0, 2, 0},
    {2, 2, 0x22, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_sqxtn_qb, 0, 0, 3, 0},
    {2, 2, 0x23, EVK_NARROW, 1, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_sqxtn_dw, 0, 0, 1, 0},
    {2, 2, 0x24, EVK_NARROW, 1, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_sqxtn_qw, 0, 0, 2, 0},
    {2, 2, 0x25, EVK_NARROW, 1, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_sqxtn_qd, 0, 0, 1, 0},
    {2, 2, 0x30, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_xtn_wb, 0, 0, 1, 0},
    {2, 2, 0x31, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_xtn_db, 0, 0, 2, 0},
    {2, 2, 0x32, EVK_NARROW, 1, 0, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_xtn_qb, 0, 0, 3, 0},
    {2, 2, 0x33, EVK_NARROW, 1, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_xtn_dw, 0, 0, 1, 0},
    {2, 2, 0x34, EVK_NARROW, 1, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_xtn_qw, 0, 0, 2, 0},
    {2, 2, 0x35, EVK_NARROW, 1, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_pmov_xtn_qd, 0, 0, 1, 0},
    {2, 1, 0x8b, EVK_COMPRESS, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_compress2, 0, 0, 4, 0},
    {2, 1, 0x8b, EVK_COMPRESS, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_compress3, 0, 0, 8, 0},
    {2, 1, 0x8a, EVK_COMPRESS, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_compress2, 0, 0, 4, 0},
    {2, 1, 0x8a, EVK_COMPRESS, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_compress3, 0, 0, 8, 0},
    {2, 1, 0x63, EVK_COMPRESS, 1, 0, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_compress0, 0, 0, 1, 0},
    {2, 1, 0x63, EVK_COMPRESS, 2, 1, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_compress1, 0, 0, 2, 0},
    {2, 1, 0x89, EVK_EXPAND, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_expand2, 0, 0, 4, 0},
    {2, 1, 0x89, EVK_EXPAND, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_expand3, 0, 0, 8, 0},
    {2, 1, 0x88, EVK_EXPAND, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_expand2, 0, 0, 4, 0},
    {2, 1, 0x88, EVK_EXPAND, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_expand3, 0, 0, 8, 0},
    {2, 1, 0x62, EVK_EXPAND, 1, 0, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_expand0, 0, 0, 1, 0},
    {2, 1, 0x62, EVK_EXPAND, 2, 1, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_expand1, 0, 0, 2, 0},
    // gathers and scatters (gadgets picked by the guest: gen_evex_vsib_word)
    {2, 1, 0x90, EVK_GATHER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0x90, EVK_GATHER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    {2, 1, 0x91, EVK_GATHER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0x91, EVK_GATHER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    {2, 1, 0x92, EVK_GATHER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0x92, EVK_GATHER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    {2, 1, 0x93, EVK_GATHER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0x93, EVK_GATHER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    {2, 1, 0xa0, EVK_SCATTER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0xa0, EVK_SCATTER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    {2, 1, 0xa1, EVK_SCATTER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0xa1, EVK_SCATTER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    {2, 1, 0xa2, EVK_SCATTER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0xa2, EVK_SCATTER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    {2, 1, 0xa3, EVK_SCATTER, 1, 2, 0, EVT_FIX, 0, 0, NULL, 0, 0, 4, 0},
    {2, 1, 0xa3, EVK_SCATTER, 2, 3, 0, EVT_FIX, 0, 0, NULL, 0, 0, 8, 0},
    // VBMI's VPMULTISHIFTQB, VBMI2's VPSHLD/VPSHRD(V), VNNI, IFMA, BITALG, GFNI
    {2, 1, 0x83, EVK_L3, 2, 0, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pmultishiftqb, 0, 0, 0, 0},
    {3, 1, 0x70, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pshldw, 0, 0, 0, 0},
    {3, 1, 0x71, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pshldd, 0, 0, 0, 0},
    {3, 1, 0x71, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pshldq, 0, 0, 0, 0},
    {3, 1, 0x72, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pshrdw, 0, 0, 0, 0},
    {3, 1, 0x73, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pshrdd, 0, 0, 0, 0},
    {3, 1, 0x73, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pshrdq, 0, 0, 0, 0},
    {2, 1, 0x70, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pshldvw, 0, 8, 0, 0},
    {2, 1, 0x71, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pshldvd, 0, 8, 0, 0},
    {2, 1, 0x71, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pshldvq, 0, 8, 0, 0},
    {2, 1, 0x72, EVK_L3, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pshrdvw, 0, 8, 0, 0},
    {2, 1, 0x73, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pshrdvd, 0, 8, 0, 0},
    {2, 1, 0x73, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pshrdvq, 0, 8, 0, 0},
    {2, 1, 0x50, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pdpbusd, 0, 8, 0, 0},
    {2, 1, 0x51, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pdpbusds, 0, 8, 0, 0},
    {2, 1, 0x52, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pdpwssd, 0, 8, 0, 0},
    {2, 1, 0x53, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_pdpwssds, 0, 8, 0, 0},
    {2, 1, 0xb4, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pmadd52luq, 0, 8, 0, 0},
    {2, 1, 0xb5, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_pmadd52huq, 0, 8, 0, 0},
    {2, 1, 0x54, EVK_L2, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_popcntb, 0, 0, 0, 0},
    {2, 1, 0x54, EVK_L2, 2, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_popcntw, 0, 0, 0, 0},
    {2, 1, 0x8f, EVK_TOMASK, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_pshufbitqmb, 0, 0, 0, 0},
    {2, 1, 0xcf, EVK_L3, 1, 0, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_gf2p8mulb, 0, 0, 0, 0},
    {3, 1, 0xce, EVK_L3, 2, 0, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_gf2p8affineqb, 0, 0, 0, 0},
    {3, 1, 0xcf, EVK_L3, 2, 0, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_gf2p8affineinvqb, 0, 0, 0, 0},
    // FMA: 132/213/231 (vex.inc fma_body; the destination in, word bit 36)
    {2, 1, 0x96, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_maddsub132ps, 0, 8, 0, 1},
    {2, 1, 0x96, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_maddsub132pd, 0, 8, 0, 1},
    {2, 1, 0x97, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msubadd132ps, 0, 8, 0, 1},
    {2, 1, 0x97, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msubadd132pd, 0, 8, 0, 1},
    {2, 1, 0x98, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_madd132ps, 0, 8, 0, 1},
    {2, 1, 0x98, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_madd132pd, 0, 8, 0, 1},
    {2, 1, 0x99, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_madd132ss, 0, 8, 4, 1},
    {2, 1, 0x99, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_madd132sd, 0, 8, 8, 1},
    {2, 1, 0x9a, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msub132ps, 0, 8, 0, 1},
    {2, 1, 0x9a, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msub132pd, 0, 8, 0, 1},
    {2, 1, 0x9b, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_msub132ss, 0, 8, 4, 1},
    {2, 1, 0x9b, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_msub132sd, 0, 8, 8, 1},
    {2, 1, 0x9c, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmadd132ps, 0, 8, 0, 1},
    {2, 1, 0x9c, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmadd132pd, 0, 8, 0, 1},
    {2, 1, 0x9d, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmadd132ss, 0, 8, 4, 1},
    {2, 1, 0x9d, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmadd132sd, 0, 8, 8, 1},
    {2, 1, 0x9e, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmsub132ps, 0, 8, 0, 1},
    {2, 1, 0x9e, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmsub132pd, 0, 8, 0, 1},
    {2, 1, 0x9f, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmsub132ss, 0, 8, 4, 1},
    {2, 1, 0x9f, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmsub132sd, 0, 8, 8, 1},
    {2, 1, 0xa6, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_maddsub213ps, 0, 8, 0, 1},
    {2, 1, 0xa6, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_maddsub213pd, 0, 8, 0, 1},
    {2, 1, 0xa7, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msubadd213ps, 0, 8, 0, 1},
    {2, 1, 0xa7, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msubadd213pd, 0, 8, 0, 1},
    {2, 1, 0xa8, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_madd213ps, 0, 8, 0, 1},
    {2, 1, 0xa8, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_madd213pd, 0, 8, 0, 1},
    {2, 1, 0xa9, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_madd213ss, 0, 8, 4, 1},
    {2, 1, 0xa9, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_madd213sd, 0, 8, 8, 1},
    {2, 1, 0xaa, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msub213ps, 0, 8, 0, 1},
    {2, 1, 0xaa, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msub213pd, 0, 8, 0, 1},
    {2, 1, 0xab, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_msub213ss, 0, 8, 4, 1},
    {2, 1, 0xab, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_msub213sd, 0, 8, 8, 1},
    {2, 1, 0xac, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmadd213ps, 0, 8, 0, 1},
    {2, 1, 0xac, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmadd213pd, 0, 8, 0, 1},
    {2, 1, 0xad, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmadd213ss, 0, 8, 4, 1},
    {2, 1, 0xad, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmadd213sd, 0, 8, 8, 1},
    {2, 1, 0xae, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmsub213ps, 0, 8, 0, 1},
    {2, 1, 0xae, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmsub213pd, 0, 8, 0, 1},
    {2, 1, 0xaf, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmsub213ss, 0, 8, 4, 1},
    {2, 1, 0xaf, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmsub213sd, 0, 8, 8, 1},
    {2, 1, 0xb6, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_maddsub231ps, 0, 8, 0, 1},
    {2, 1, 0xb6, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_maddsub231pd, 0, 8, 0, 1},
    {2, 1, 0xb7, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msubadd231ps, 0, 8, 0, 1},
    {2, 1, 0xb7, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msubadd231pd, 0, 8, 0, 1},
    {2, 1, 0xb8, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_madd231ps, 0, 8, 0, 1},
    {2, 1, 0xb8, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_madd231pd, 0, 8, 0, 1},
    {2, 1, 0xb9, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_madd231ss, 0, 8, 4, 1},
    {2, 1, 0xb9, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_madd231sd, 0, 8, 8, 1},
    {2, 1, 0xba, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msub231ps, 0, 8, 0, 1},
    {2, 1, 0xba, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_msub231pd, 0, 8, 0, 1},
    {2, 1, 0xbb, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_msub231ss, 0, 8, 4, 1},
    {2, 1, 0xbb, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_msub231sd, 0, 8, 8, 1},
    {2, 1, 0xbc, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmadd231ps, 0, 8, 0, 1},
    {2, 1, 0xbc, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmadd231pd, 0, 8, 0, 1},
    {2, 1, 0xbd, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmadd231ss, 0, 8, 4, 1},
    {2, 1, 0xbd, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmadd231sd, 0, 8, 8, 1},
    {2, 1, 0xbe, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmsub231ps, 0, 8, 0, 1},
    {2, 1, 0xbe, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fma_nmsub231pd, 0, 8, 0, 1},
    {2, 1, 0xbf, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmsub231ss, 0, 8, 4, 1},
    {2, 1, 0xbf, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fma_nmsub231sd, 0, 8, 8, 1},
    // VGETEXP ({sae})
    {2, 1, 0x4c, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_rcp14ps, 0, 0, 0, 0},
    {2, 1, 0x4c, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_rcp14pd, 0, 0, 0, 0},
    {2, 1, 0x4d, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rcp14ss, 0, 0, 4, 0},
    {2, 1, 0x4d, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rcp14sd, 0, 0, 8, 0},
    {2, 1, 0x4e, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_rsqrt14ps, 0, 0, 0, 0},
    {2, 1, 0x4e, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_rsqrt14pd, 0, 0, 0, 0},
    {2, 1, 0x4f, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rsqrt14ss, 0, 0, 4, 0},
    {2, 1, 0x4f, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rsqrt14sd, 0, 0, 8, 0},
    {2, 1, 0x42, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_getexpps, 0, 0, 0, 2},
    {2, 1, 0x42, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_getexppd, 0, 0, 0, 2},
    {2, 1, 0x43, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_getexpss, 0, 0, 4, 2},
    {2, 1, 0x43, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_getexpsd, 0, 0, 8, 2},
    // VGETMANT (imm8, {sae})
    {3, 1, 0x26, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_getmantps, 0, 0, 0, 2},
    {3, 1, 0x26, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_getmantpd, 0, 0, 0, 2},
    {3, 1, 0x27, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_getmantss, 0, 0, 4, 2},
    {3, 1, 0x27, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_getmantsd, 0, 0, 8, 2},
    // VRNDSCALE (imm8, {sae})
    {3, 1, 0x08, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_rndscaleps, 0, 0, 0, 2},
    {3, 1, 0x09, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_rndscalepd, 0, 0, 0, 2},
    {3, 1, 0x0a, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rndscaless, 0, 0, 4, 2},
    {3, 1, 0x0b, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rndscalesd, 0, 0, 8, 2},
    // VREDUCE (imm8, {sae})
    {3, 1, 0x56, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_reduceps, 0, 0, 0, 2},
    {3, 1, 0x56, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_reducepd, 0, 0, 0, 2},
    {3, 1, 0x57, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_reducess, 0, 0, 4, 2},
    {3, 1, 0x57, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_reducesd, 0, 0, 8, 2},
    // VSCALEF ({er})
    {2, 1, 0x2c, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_scalefps, 0, 0, 0, 1},
    {2, 1, 0x2c, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_scalefpd, 0, 0, 0, 1},
    {2, 1, 0x2d, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_scalefss, 0, 0, 4, 1},
    {2, 1, 0x2d, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_scalefsd, 0, 0, 8, 1},
    // VRANGE (imm8, {sae})
    {3, 1, 0x50, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_rangeps, 0, 0, 0, 2},
    {3, 1, 0x50, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_rangepd, 0, 0, 0, 2},
    {3, 1, 0x51, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rangess, 0, 0, 4, 2},
    {3, 1, 0x51, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_rangesd, 0, 0, 8, 2},
    // VFPCLASS (into an opmask; no flags)
    {3, 1, 0x66, EVK_TOMASK, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fpclassps, 0, EVF_NOVVVV, 0, 0},
    {3, 1, 0x66, EVK_TOMASK, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fpclasspd, 0, EVF_NOVVVV, 0, 0},
    {3, 1, 0x67, EVK_TOMASKS, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fpclassss, 0, EVF_NOVVVV, 4, 0},
    {3, 1, 0x67, EVK_TOMASKS, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fpclasssd, 0, EVF_NOVVVV, 8, 0},
    // VFIXUPIMM (imm8, {sae}; the destination an operand)
    {3, 1, 0x54, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_fixupimmps, 0, 8, 0, 2},
    {3, 1, 0x54, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_fixupimmpd, 0, 8, 0, 2},
    {3, 1, 0x55, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fixupimmss, 0, 8, 4, 2},
    {3, 1, 0x55, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_fixupimmsd, 0, 8, 8, 2},
    // conversions, the same width: VCVT(U)DQ2PS, VCVT(U)QQ2PD ({er}); VCVT(T)PS2(U)DQ, VCVT(T)PD2(U)QQ
    {1, 0, 0x5b, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtdq2ps, 0, 0, 0, 1},
    {1, 3, 0x7a, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtudq2ps, 0, 0, 0, 1},
    {1, 2, 0xe6, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtqq2pd, 0, 0, 0, 1},
    {1, 2, 0x7a, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtuqq2pd, 0, 0, 0, 1},
    {1, 1, 0x5b, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtps2dq, 0, 0, 0, 1},
    {1, 2, 0x5b, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvttps2dq, 0, 0, 0, 2},
    {1, 0, 0x79, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtps2udq, 0, 0, 0, 1},
    {1, 0, 0x78, EVK_L2, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvttps2udq, 0, 0, 0, 2},
    {1, 1, 0x7b, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtpd2qq, 0, 0, 0, 1},
    {1, 1, 0x7a, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvttpd2qq, 0, 0, 0, 2},
    {1, 1, 0x79, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtpd2uqq, 0, 0, 0, 1},
    {1, 1, 0x78, EVK_L2, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvttpd2uqq, 0, 0, 0, 2},
    // conversions that widen (from VL / 2) or narrow (to VL / 2): evex_cvtw/cvtn
    {1, 0, 0x5a, EVK_CVTW, 1, 3, 2, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvtps2pd, 0, 0, 1, 2},
    {1, 2, 0xe6, EVK_CVTW, 1, 3, 2, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvtdq2pd, 0, 0, 1, 0},
    {1, 2, 0x7a, EVK_CVTW, 1, 3, 2, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvtudq2pd, 0, 0, 1, 0},
    {1, 1, 0x7b, EVK_CVTW, 1, 3, 2, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvtps2qq, 0, 0, 1, 1},
    {1, 1, 0x7a, EVK_CVTW, 1, 3, 2, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvttps2qq, 0, 0, 1, 2},
    {1, 1, 0x79, EVK_CVTW, 1, 3, 2, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvtps2uqq, 0, 0, 1, 1},
    {1, 1, 0x78, EVK_CVTW, 1, 3, 2, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvttps2uqq, 0, 0, 1, 2},
    {1, 1, 0x5a, EVK_CVTN, 2, 2, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtpd2ps, 0, 0, 0, 1},
    {1, 0, 0x5b, EVK_CVTN, 2, 2, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtqq2ps, 0, 0, 0, 1},
    {1, 3, 0x7a, EVK_CVTN, 2, 2, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtuqq2ps, 0, 0, 0, 1},
    {1, 3, 0xe6, EVK_CVTN, 2, 2, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtpd2dq, 0, 0, 0, 1},
    {1, 1, 0xe6, EVK_CVTN, 2, 2, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvttpd2dq, 0, 0, 0, 2},
    {1, 0, 0x79, EVK_CVTN, 2, 2, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtpd2udq, 0, 0, 0, 1},
    {1, 0, 0x78, EVK_CVTN, 2, 2, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_cvttpd2udq, 0, 0, 0, 2},
    // scalar conversions: to and from general registers, SS <-> SD
    {1, 2, 0x2d, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtss2si32_0, 0, 0, 4, 1},
    {1, 2, 0x2d, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtss2si64_0, 0, 0, 4, 1},
    {1, 2, 0x79, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtss2si32_1, 0, 0, 4, 1},
    {1, 2, 0x79, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtss2si64_1, 0, 0, 4, 1},
    {1, 2, 0x2c, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttss2si32_0, 0, 0, 4, 2},
    {1, 2, 0x2c, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttss2si64_0, 0, 0, 4, 2},
    {1, 2, 0x78, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttss2si32_1, 0, 0, 4, 2},
    {1, 2, 0x78, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttss2si64_1, 0, 0, 4, 2},
    {1, 2, 0x2a, EVK_CVTSI, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsi2ss32, 0, 0, 4, 1},
    {1, 2, 0x2a, EVK_CVTSI, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsi2ss64, 0, 0, 8, 1},
    {1, 2, 0x7b, EVK_CVTSI, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtusi2ss32, 0, 0, 4, 1},
    {1, 2, 0x7b, EVK_CVTSI, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtusi2ss64, 0, 0, 8, 1},
    {1, 3, 0x2d, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsd2si32_0, 0, 0, 8, 1},
    {1, 3, 0x2d, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsd2si64_0, 0, 0, 8, 1},
    {1, 3, 0x79, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsd2si32_1, 0, 0, 8, 1},
    {1, 3, 0x79, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsd2si64_1, 0, 0, 8, 1},
    {1, 3, 0x2c, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttsd2si32_0, 0, 0, 8, 2},
    {1, 3, 0x2c, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttsd2si64_0, 0, 0, 8, 2},
    {1, 3, 0x78, EVK_CVT2GPR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttsd2si32_1, 0, 0, 8, 2},
    {1, 3, 0x78, EVK_CVT2GPR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvttsd2si64_1, 0, 0, 8, 2},
    {1, 3, 0x2a, EVK_CVTSI, 1, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsi2sd32, 0, 0, 4, 0},
    {1, 3, 0x2a, EVK_CVTSI, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtsi2sd64, 0, 0, 8, 1},
    {1, 3, 0x7b, EVK_CVTSI, 1, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtusi2sd32, 0, 0, 4, 0},
    {1, 3, 0x7b, EVK_CVTSI, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_cvtusi2sd64, 0, 0, 8, 1},
    {1, 2, 0x5a, EVK_SCAL, 1, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_cvtss2sd, 0, 0, 4, 2},
    {1, 3, 0x5a, EVK_SCAL, 2, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_cvtsd2ss, 0, 0, 8, 1},
    // VCVTPH2PS ({sae}), VCVTPS2PH (imm8, {sae}; to a register or memory)
    {2, 1, 0x13, EVK_CVTW, 1, 2, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvtph2ps, 0, 0, 1, 2},
    {3, 1, 0x1d, EVK_CVTNR, 1, 1, 0, EVT_DIV, 0, 0, aok_gadget_x86_evex_cvtps2ph, 0, 0, 1, 2},
    // AVX512DQ's float logic: the integer ops at the float element sizes
    {1, 0, 0x54, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_pand, 0, 0, 0, 0},
    {1, 1, 0x54, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_pand, 0, 0, 0, 0},
    {1, 0, 0x55, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_pandn, 0, 0, 0, 0},
    {1, 1, 0x55, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_pandn, 0, 0, 0, 0},
    {1, 0, 0x56, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_por, 0, 0, 0, 0},
    {1, 1, 0x56, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_por, 0, 0, 0, 0},
    {1, 0, 0x57, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_pxor, 0, 0, 0, 0},
    {1, 1, 0x57, EVK_L3, 2, 3, 3, EVT_FV, 0, 0, aok_gadget_x86_evex_vi_pxor, 0, 0, 0, 0},
    // VMOVSLDUP/SHDUP/DDUP; VPBROADCASTMB2Q/MW2D; (V)(U)COMISS/SD ({sae})
    {1, 2, 0x12, EVK_L2, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_movsldup, 0, 0, 0, 0},
    {1, 2, 0x16, EVK_L2, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_movshdup, 0, 0, 0, 0},
    {1, 3, 0x12, EVK_L2, 2, 3, 0, EVT_DUP, 0, 0, aok_gadget_x86_evex_movddup, 0, 0, 0, 0},
    {2, 2, 0x2a, EVK_M2V, 2, 3, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_bcastmb2q, 0, 32, 0, 0},
    {2, 2, 0x3a, EVK_M2V, 1, 2, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_bcastmw2d, 0, 32, 0, 0},
    {1, 0, 0x2f, EVK_FLAGS, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_comiss, 0, 0, 4, 2},
    {1, 0, 0x2e, EVK_FLAGS, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_ucomiss, 0, 0, 4, 2},
    {1, 1, 0x2f, EVK_FLAGS, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_comisd, 0, 0, 8, 2},
    {1, 1, 0x2e, EVK_FLAGS, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_ucomisd, 0, 0, 8, 2},
    // the EVEX.128 element moves: VMOVSS/SD, VMOVLPS/HPS/LPD/HPD/HLPS/LHPS, VMOVD/VMOVQ, VPINSR*, VPEXTR*,
    // VEXTRACTPS, VINSERTPS
    {1, 2, 0x10, EVK_SCAL, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_movss, 0, EVF_MEMNOVVVV, 4, 0},
    {1, 3, 0x10, EVK_SCAL, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_movsd, 0, EVF_MEMNOVVVV, 8, 0},
    {1, 2, 0x11, EVK_SSTORE, 1, 2, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_movss, 0, 0, 4, 0},
    {1, 3, 0x11, EVK_SSTORE, 2, 3, 0, EVT_FIX, 0, 0, aok_gadget_x86_evex_movsd, 0, 0, 8, 0},
    {1, 0, 0x12, EVK_L3, 1, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_movlo, 0, EVF_L128, 8, 0},
    {1, 1, 0x12, EVK_L3, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_movlo, 0, EVF_L128 | EVF_MEMONLY, 8, 0},
    {1, 0, 0x13, EVK_STORE, 1, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_mov, 0, EVF_L128 | EVF_MEMONLY, 8, 0},
    {1, 1, 0x13, EVK_STORE, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_mov, 0, EVF_L128 | EVF_MEMONLY, 8, 0},
    {1, 0, 0x16, EVK_L3, 1, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_movhi, 0, EVF_L128, 8, 0},
    {1, 1, 0x16, EVK_L3, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_movhi, 0, EVF_L128 | EVF_MEMONLY, 8, 0},
    {1, 0, 0x17, EVK_STORE, 1, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_hi2lo, 0, EVF_L128 | EVF_MEMONLY, 8, 0},
    {1, 1, 0x17, EVK_STORE, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_hi2lo, 0, EVF_L128 | EVF_MEMONLY, 8, 0},
    {1, 1, 0x6e, EVK_INS, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insd, 0, EVF_L128 | EVF_ZEROS1, 4, 0},
    {1, 1, 0x6e, EVK_INS, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insq, 0, EVF_L128 | EVF_ZEROS1, 8, 0},
    {1, 1, 0x7e, EVK_EXTR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrd, 0, EVF_L128, 4, 0},
    {1, 1, 0x7e, EVK_EXTR, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrq, 0, EVF_L128, 8, 0},
    {1, 2, 0x7e, EVK_L2, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_movq0, 0, EVF_L128, 8, 0},
    {1, 1, 0xd6, EVK_STORE, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_movq0, 0, EVF_L128, 8, 0},
    {1, 1, 0xc4, EVK_INS, 1, 1, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insw, 0, EVF_L128, 2, 0},
    {1, 1, 0xc5, EVK_EXTR, 1, 1, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrw, 0, EVF_L128 | EVF_REGONLY | EVF_EXTR_SWAP, 2, 0},
    {3, 1, 0x14, EVK_EXTR, 1, 0, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrb, 0, EVF_L128, 1, 0},
    {3, 1, 0x15, EVK_EXTR, 1, 1, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrw, 0, EVF_L128, 2, 0},
    {3, 1, 0x17, EVK_EXTR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrd, 0, EVF_L128, 4, 0},
    {3, 1, 0x20, EVK_INS, 1, 0, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insb, 0, EVF_L128, 1, 0},
    {1, 1, 0xc4, EVK_INS, 2, 1, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insw, 0, EVF_L128, 2, 0},
    {1, 1, 0xc5, EVK_EXTR, 2, 1, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrw, 0, EVF_L128 | EVF_REGONLY | EVF_EXTR_SWAP, 2, 0},
    {3, 1, 0x14, EVK_EXTR, 2, 0, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrb, 0, EVF_L128, 1, 0},
    {3, 1, 0x15, EVK_EXTR, 2, 1, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrw, 0, EVF_L128, 2, 0},
    {3, 1, 0x17, EVK_EXTR, 2, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrd, 0, EVF_L128, 4, 0},
    {3, 1, 0x20, EVK_INS, 2, 0, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insb, 0, EVF_L128, 1, 0},
    {3, 1, 0x16, EVK_EXTR, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrd, 0, EVF_L128, 4, 0},
    {3, 1, 0x16, EVK_EXTR, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_extrq, 0, EVF_L128, 8, 0},
    {3, 1, 0x21, EVK_L3, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insertps, 0, EVF_L128, 4, 0},
    {3, 1, 0x22, EVK_INS, 1, 2, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insd, 0, EVF_L128, 4, 0},
    {3, 1, 0x22, EVK_INS, 2, 3, 0, EVT_FIX, 0, 1, aok_gadget_x86_evex_insq, 0, EVF_L128, 8, 0},
    // VDBPSADBW; BF16: VCVTNEPS2BF16, VCVTNE2PS2BF16, VDPBF16PS
    {3, 1, 0x42, EVK_L3, 1, 1, 0, EVT_FVM, 0, 0, aok_gadget_x86_evex_dbpsadbw, 0, 0, 0, 0},
    {2, 2, 0x72, EVK_CVTN, 1, 1, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtneps2bf16, 0, 0, 0, 0},
    {2, 3, 0x72, EVK_FULL, 1, 1, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_cvtne2ps2bf16, 0, 0, 0, 0},
    {2, 2, 0x52, EVK_L3, 1, 2, 2, EVT_FV, 0, 0, aok_gadget_x86_evex_dpbf16ps, 0, 8, 0, 0},
    // AES and PCLMULQDQ (VAES, VPCLMULQDQ; the SSE and VEX forms through vex_to_evex)
    {2, 1, 0xdc, EVK_L3, 0, 2, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_aesenc, 0, 0, 0, 0},
    {2, 1, 0xdd, EVK_L3, 0, 2, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_aesenclast, 0, 0, 0, 0},
    {2, 1, 0xde, EVK_L3, 0, 2, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_aesdec, 0, 0, 0, 0},
    {2, 1, 0xdf, EVK_L3, 0, 2, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_aesdeclast, 0, 0, 0, 0},
    {2, 1, 0xdb, EVK_L2, 0, 2, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_aesimc, 0, EVF_LEGACY, 0, 0},
    {3, 1, 0xdf, EVK_L2, 0, 2, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_aeskeygenassist, 0, EVF_LEGACY, 0, 0},
    {3, 1, 0x44, EVK_L3, 0, 2, 0, EVT_FVM, 0, 1, aok_gadget_x86_evex_pclmulqdq, 0, 0, 0, 0},
};
struct evex_insn {
    unsigned map, pp, op, w, vvvv, reg, rm, ll, aaa;
    bool z, b, mem;
    uint8_t imm;
    bool vvvv_hi;               // 32-bit mode: vvvv's bit 3 was set (vvvv holds the other bits)
};
static const struct evex_entry *evex_lookup(const struct evex_insn *v) {
    for (unsigned i = 0; i < sizeof(evex_table) / sizeof(evex_table[0]); i++) {
        const struct evex_entry *e = &evex_table[i];
        if (e->map == v->map && e->pp == v->pp && e->op == v->op &&
                (e->wreq == 0 || e->wreq == (v->w ? 2 : 1)) && (e->grp == 0 || e->grp == (v->reg & 7) + 1))
            return e;
    }
    return NULL;
}
// disp8 * N for the memory operand
static unsigned evex_disp_scale(const struct evex_entry *e, const struct evex_insn *v) {
    if (v->b && e->bcast != 0 && (e->kind == EVK_CVTW || e->kind == EVK_CVTN))
        return 1u << e->bcast;
    if (e->tuple == EVT_FV && v->b)
        return 1u << e->bcast;
    if (e->tuple == EVT_FIX)
        return e->ld;
    if (e->tuple == EVT_DIV)
        return (16u << v->ll) >> e->ld;
    if (e->tuple == EVT_DUP)
        return v->ll == 0 ? 8 : 16u << v->ll;
    return 16u << v->ll;
}
// VPEXTR*, VEXTRACTPS, VMOVD/VMOVQ out: evex_extr's word, or -1 for #UD:
// vvvv 1111b, no masking, EVEX.128. g the GPR (amd64; i386 slot 0).
static long gen_evex_extr_word(const struct evex_entry *e, const struct evex_insn *v, unsigned g) {
    if ((v->vvvv & 15) != 0 || v->vvvv_hi || v->aaa != 0 || v->z || v->b || v->ll != 0)
        return -1;
    if ((e->flags & EVF_REGONLY) && v->mem)
        return -1;
    unsigned src = (e->flags & EVF_EXTR_SWAP) ? v->rm : v->reg;
    return (long) (g | (unsigned long) (src & 31) << 10 | (unsigned long) v->imm << 24 | (v->mem ? 1ul << 32 : 0));
}
// VCVT(T)SS/SD2(U)SI's word (evex.inc evex_cvt2gpr), or -1 for #UD: vvvv
// 1111b, no masking, EVEX.b on a register only ({er}, or {sae} truncating).
static long gen_evex_cvt2gpr_word(const struct evex_entry *e, const struct evex_insn *v, unsigned g) {
    if ((v->vvvv & 15) != 0 || v->vvvv_hi || v->aaa != 0 || v->z || (v->b && v->mem))
        return -1;
    unsigned long w = g | (unsigned long) (v->rm & 31) << 10 | (v->mem ? 1ul << 15 : 0);
    if (v->b)
        w |= 1ul << 51 | (e->fp == 1 ? 1ul << 48 | (unsigned long) v->ll << 49 : 0);
    return (long) w;
}
// A gather's or scatter's word (evex.inc evg_*), or -1 for #UD: memory with
// a SIB (index: its index register, 0-31), an opmask, no EVEX.z or b,
// vvvv 1111b, a gather's destination not its index.
static long gen_evex_vsib_word(const struct evex_entry *e, const struct evex_insn *v, bool sib,
        unsigned index, unsigned scale) {
    if (!v->mem || !sib || v->aaa == 0 || v->z || v->b || (v->vvvv & 15) != 0 || v->vvvv_hi || v->ll == 3)
        return -1;
    if (e->kind == EVK_GATHER && index == v->reg)
        return -1;
    return (long) (v->reg | index << 5 | scale << 10 | v->w << 12 | (v->op & 1) << 13 | v->ll << 16 |
            v->aaa << 18 | (e->kind == EVK_SCATTER ? 1u << 21 : 0));
}
struct evex_plan {
    bool ud;
    unsigned long word;
    unsigned ld_bytes, bcast;   // the memory source: a loader for these bytes, or a broadcast of 1 << bcast
    unsigned st_bytes;          // a store of the result (from EVEX_STAGE)
    bool st_masked;             // ... of only the elements the mask enables
    unsigned align;             // the memory operand must be aligned to this
    int gpr_stage;              // a GPR to stage as s2 (VPBROADCAST from a GPR), or -1
    bool gpr_w;                 // ... all 64 bits of it
    bool ld_masked;             // the load reads only the enabled elements (with ld_word)
    unsigned long ld_word;
};
// False: v is not in the table (the caller's old path).
static bool evex_plan(const struct evex_insn *v, struct evex_plan *p) {
    const struct evex_entry *e = evex_lookup(v);
    if (e == NULL)
        return false;
    memset(p, 0, sizeof(*p));
    p->ud = true;
    p->gpr_stage = -1;
    bool scalar = e->kind == EVK_SCAL || e->kind == EVK_TOMASKS || e->kind == EVK_CVTSI || e->kind == EVK_FLAGS ||
            (e->kind == EVK_SSTORE && !v->mem);
    bool round = v->b && !v->mem && e->fp != 0;   // {er} or {sae}: L'L is no length
    unsigned ll = round || scalar ? (scalar ? 0 : 2) : v->ll;
    unsigned bytes = 16u << ll;
    if (((e->flags & EVF_MEMONLY) && !v->mem) || ((e->flags & EVF_REGONLY) && v->mem) ||
            ((e->flags & EVF_MIN256) && v->ll == 0) || ((e->flags & EVF_MIN512) && v->ll < 2))
        return true;
    if ((v->ll == 3 && !round) || (v->z && v->aaa == 0) || (e->nomask && (v->aaa != 0 || v->z)))
        return true;
    if (((e->flags & EVF_L128) && v->ll != 0) || ((e->flags & EVF_MEMNOVVVV) && v->mem && (v->vvvv != 0 || v->vvvv_hi)))
        return true;
    if (v->b && (v->mem ? e->bcast == 0 : e->fp == 0))
        return true;                            // no broadcast for this op, or no rounding control
    unsigned dst = v->reg, s1 = v->vvvv, s2 = v->rm;
    bool stage = v->mem, to_stage = false;
    unsigned aaa = v->aaa;
    bool z = v->z;
    switch (e->kind) {
    case EVK_L3:
        break;
    case EVK_SHI:
        dst = v->vvvv;
        s1 = 0;
        break;
    case EVK_BCAST:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        break;
    case EVK_BCASTG:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        p->gpr_stage = (int) v->rm;
        p->gpr_w = v->w;
        stage = true;
        break;
    case EVK_SCAL:
    case EVK_FULL:
    case EVK_FULL8:
        break;
    case EVK_FULL1:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s1 = 0;
        break;
    case EVK_EXTRACT:
    case EVK_EXTRACT8:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s1 = v->reg;
        if (v->mem) {
            if (v->z)
                return true;                    // zeroing into memory
            stage = false;
            to_stage = true;
            p->st_bytes = e->kind == EVK_EXTRACT8 ? 32 : 16;
            p->st_masked = v->aaa != 0;
            aaa = 0;
            z = false;
            dst = 0;
        } else {
            dst = v->rm;
        }
        break;
    case EVK_EXT:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        break;
    case EVK_NARROW:
    case EVK_COMPRESS:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s1 = v->reg;
        if (v->mem) {
            if (v->z)
                return true;                    // zeroing into memory
            stage = false;
            to_stage = true;
            p->st_bytes = e->kind == EVK_NARROW ? bytes >> e->ld : bytes;
            p->st_masked = v->aaa != 0;
            dst = 0;
        } else {
            dst = v->rm;
        }
        aaa = 0;                                // (the body masks: word bits 54-57)
        z = false;
        break;
    case EVK_EXPAND:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        aaa = 0;
        z = false;
        break;
    case EVK_CVTW:
    case EVK_CVTN:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s1 = v->rm;
        break;
    case EVK_CVTNR:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s2 = v->reg;
        stage = false;
        if (v->mem) {
            if (v->z)
                return true;                    // zeroing into memory
            to_stage = true;
            p->st_bytes = bytes >> 1;
            p->st_masked = v->aaa != 0;
            z = false;                          // (aaa stays: the frame's masked-off elements raise
            dst = 0;                            //  nothing; the stage takes the result unmasked)
        } else {
            dst = v->rm;
        }
        break;
    case EVK_FLAGS:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s1 = v->reg;
        dst = 0;
        break;
    case EVK_INS:
        if ((e->flags & EVF_ZEROS1) && (v->vvvv != 0 || v->vvvv_hi))
            return true;
        if (!v->mem) {
            p->gpr_stage = (int) v->rm;
            p->gpr_w = v->w;
            stage = true;
        }
        break;
    case EVK_EXTR:
        return true;                            // (gen_evex_extr_word's)
    case EVK_SSTORE:
        s2 = v->reg;
        if (v->mem) {
            if (v->z || v->vvvv != 0 || v->vvvv_hi)
                return true;
            stage = false;
            to_stage = true;
            p->st_bytes = e->ld;
            p->st_masked = v->aaa != 0;
            aaa = 0;
            z = false;
            dst = 0;
        } else {
            stage = false;
            dst = v->rm;
        }
        break;
    case EVK_CVTSI:
        if (!v->mem) {
            p->gpr_stage = (int) v->rm;
            p->gpr_w = v->w;
            stage = true;
        }
        break;
    case EVK_CVT2GPR:
        return true;                            // (gen_evex_cvt2gpr_word's)
    case EVK_V2M:
        if (v->vvvv != 0 || v->vvvv_hi || v->aaa != 0 || v->reg > 7)
            return true;
        dst = v->reg;
        break;
    case EVK_M2V:
        if (v->vvvv != 0 || v->vvvv_hi || v->aaa != 0 || v->z)
            return true;
        s2 = 0;
        break;
    case EVK_TOMASKS:
    case EVK_TOMASK:
        if (v->z || v->reg > 7)
            return true;                        // zeroing is the only kind; EVEX.R/R' on a k register (SDE)
        if ((e->flags & EVF_NOVVVV) && (v->vvvv != 0 || v->vvvv_hi))
            return true;
        dst = v->reg;
        break;
    case EVK_L2:
    case EVK_LOAD:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s1 = v->rm;
        break;
    case EVK_STORE:
        if (v->vvvv != 0 || v->vvvv_hi)
            return true;
        s2 = v->reg;
        if (v->mem) {
            if (v->z)
                return true;                    // zeroing into memory
            stage = false;
            to_stage = true;
            p->st_bytes = e->ld ? e->ld : bytes;
            p->st_masked = v->aaa != 0;
            aaa = 0;                            // (the store applies it)
            z = false;
            dst = 0;
        } else {
            dst = v->rm;
        }
        break;
    }
    if (v->mem && e->align)
        p->align = bytes;
    if (stage && p->gpr_stage < 0) {
        if (v->b)
            p->bcast = e->bcast;
        else
            p->ld_bytes = e->tuple == EVT_DIV ? bytes >> e->ld : e->tuple == EVT_DUP && ll == 0 ? 8 :
                    e->kind == EVK_EXPAND ? bytes : e->ld ? e->ld : bytes;
    }
    p->ud = false;
    p->word = (dst & 31) | (unsigned long) (s1 & 31) << 5 | (unsigned long) (s2 & 31) << 10 |
            (stage ? 1ul << 15 : 0) | (unsigned long) ll << 16 | (unsigned long) (aaa & 7) << 18 |
            (z ? 1ul << 21 : 0) | (unsigned long) e->esz << 22 | (unsigned long) v->imm << 24 |
            (to_stage ? 1ul << 32 : 0) | (unsigned long) (e->flags & 15) << 33 |
            (e->fp ? 1ul << 37 : 0) | (scalar ? 1ul << 38 : 0);
    if (e->kind == EVK_EXTRACT || e->kind == EVK_EXTRACT8)   // the result's VL, the source's at 52-53
        p->word = (p->word & ~(3ul << 16)) | (e->kind == EVK_EXTRACT8 ? 1ul << 16 : 0) | (unsigned long) ll << 52;
    if (e->kind == EVK_FULL8 || e->kind == EVK_EXTRACT8)
        p->word |= 1ul << 39;
    if (e->kind == EVK_M2V)                     // the source k, for the body
        p->word |= (unsigned long) (v->rm & 7) << 54;
    if (e->kind == EVK_NARROW || e->kind == EVK_COMPRESS || e->kind == EVK_EXPAND)   // the body's mask
        p->word |= (unsigned long) (v->aaa & 7) << 54 | (v->z ? 1ul << 57 : 0);
    if (e->kind == EVK_NARROW) {                // the result's VL; the source's at 52-53
        unsigned rb = bytes >> e->ld;
        p->word = (p->word & ~(3ul << 16)) | (rb > 16 ? 1ul << 16 : 0) | (unsigned long) ll << 52;
        if (p->st_masked)                       // a store of rb bytes, element by element
            p->word |= 1ul << 58 | (unsigned long) __builtin_ctz(rb) << 59;
    }
    if (e->kind == EVK_CVTN || e->kind == EVK_CVTNR)   // the destination's VL half the source's (at 52-53)
        p->word = (p->word & ~(3ul << 16)) | (unsigned long) (ll ? ll - 1 : 0) << 16 | (unsigned long) ll << 52 |
                (ll == 0 && !to_stage ? 1ul << 47 : 0);
    if (e->kind == EVK_CVTNR && p->st_masked)   // a store of VL / 2 bytes, element by element
        p->word |= 1ul << 58 | (unsigned long) __builtin_ctz(bytes >> 1) << 59;
    if ((e->kind == EVK_SSTORE || e->kind == EVK_STORE) && p->st_masked && e->ld)   // (one element's bytes)
        p->word |= 1ul << 58 | (unsigned long) __builtin_ctz(e->ld) << 59;
    if (e->flags & EVF_ZEROS1)
        p->word |= 1ul << 46;
    if (e->kind == EVK_COMPRESS && p->st_masked)
        p->word |= 1ul << 62;                   // the store: the first popcount(k) elements
    p->ld_word = p->word;
    p->ld_masked = v->aaa != 0 && (p->bcast != 0 || (p->ld_bytes == bytes && e->tuple != EVT_FIX)) &&
            e->kind != EVK_CVTW && e->kind != EVK_CVTN && e->kind != EVK_CVTNR;  // (not the mask's elements: whole)
    if (e->kind == EVK_EXPAND && v->mem && v->aaa != 0) {   // read only the first popcount(k) elements
        p->ld_masked = true;
        p->ld_word = p->word | (unsigned long) (v->aaa & 7) << 18 | 1ul << 62;
    }
    if (round)                                  // {sae}; {er} sets the rounding too
        p->word |= 1ul << 51 | (e->fp == 1 ? 1ul << 48 | (unsigned long) v->ll << 49 : 0);
    // the store gadget's own word: the mask and element size
    if (p->st_masked)
        p->word |= (unsigned long) (v->aaa & 7) << 40 | (unsigned long) e->esz << 44;
    return true;
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

/* gadgets-vec.S's EVEX memory gadgets. */
MEMD(vldb4) MEMD(vldb8) MEMD(vldbm4) MEMD(vldbm8) MEMD(vldm) MEMD(vstm)
MEMD(vgather) MEMD(vscatter) MEMD(vwpm)
static const MemTab vldb_tab[2][2] = {
    { MEMT(vldb4) MEMT(vldb8) }, { MEMT(vldbm4) MEMT(vldbm8) },
};
static const MemTab evex_mem_tab[5] = {
    MEMT(vldm) MEMT(vstm) MEMT(vwpm) MEMT(vgather) MEMT(vscatter)
};
#define vldm_tab        evex_mem_tab[0]
#define vstm_tab        evex_mem_tab[1]
#define vwpm_tab        evex_mem_tab[2]
#define vgather_tab     evex_mem_tab[3]
#define vscatter_tab    evex_mem_tab[4]
DECL(vex_gst_amd64) DECL(vex_to_gpr_amd64) DECL(vex_bmi) DECL(vmskk) DECL(vmskld)
DECL(fpx_addsd) DECL(fpx_subsd) DECL(fpx_mulsd) DECL(fpx_divsd) DECL(fpx_sqrtsd)
DECL(fpx_addpd) DECL(fpx_subpd) DECL(fpx_mulpd) DECL(fpx_divpd)

static unsigned vlog2(unsigned bytes)
{
    return ctz32(bytes);
}

/*
 * A vector memory operand: the gadget of @tab for its form, [@own] if it has
 * one, the address and the host's word: the log2 of the bytes, | 16 for an
 * operand that must be aligned to its size (vmem_w: those bits as given).
 */
static void vmem_w(Ctx *c, const Insn *d, const MemTab tab, bool has_own,
                   uint64_t own, uint32_t wbits)
{
    const Mem *m = &d->m;
    bool ea = m->riprel || m->seg >= 0 || m->index >= 0;

    if (ea) {
        emit_ea(c, d);
    }
    aok_emit_gadget(&c->g, tab[ea ? F_EA : c->c64 ? F_BD : F_B3][c->mb]);
    if (has_own) {
        aok_emit(&c->g, own);
    }
    if (!ea) {
        aok_emit(&c->g, ro(m->base));
        aok_emit(&c->g, m->disp);
    }
    aok_emit(&c->g, word(c, wbits));
    c->hf = HF_NONE;
}

static void vmem(Ctx *c, const Insn *d, const MemTab tab, bool has_own,
                 uint64_t own, unsigned bytes, bool aligned)
{
    vmem_w(c, d, tab, has_own, own, vlog2(bytes) | (aligned ? 16 : 0));
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

static int evex_at(Ctx *c, Insn *d, const uint8_t *code, unsigned p0,
                   unsigned p1, unsigned p2, unsigned op, int from);

/*
 * A VP_FRAME plan's gadgets: its memory operand or general register
 * staged, a write probe for a result that goes to memory (its fault before
 * the frame changes anything, MXCSR), the frame and its words, the store.
 * @legacy: a legacy SSE encoding of the op (sse_vex): word bit 15, and a
 * 16-byte operand in memory aligned.
 */
static void vex_frame(Ctx *c, const Insn *d, const struct vex_entry *e,
                      const struct vex_plan *p, bool legacy)
{
    bool aligned = p->align || (legacy && p->stage_bytes == 16);

    if (p->gpr_stage >= 0) {
        E1(G(vex_gst_amd64), (p->gpr_stage & 15) | (p->gpr_w ? 16 : 0));
    } else if (p->stage_bytes) {
        vmem(c, d, aligned ? vlda_tab[vlog2(p->stage_bytes)]
                           : vld_tab[vlog2(p->stage_bytes)],
             false, 0, p->stage_bytes, aligned);
    }
    if (p->st_after) {
        vmem(c, d, vwp_tab[vlog2(p->st_after)], false, 0, p->st_after, false);
    }
    aok_emit_gadget(&c->g, p->gadget);
    aok_emit(&c->g, p->word | (legacy ? 1ull << 15 : 0));
    for (unsigned i = 0; i < p->nextra; i++) {
        aok_emit(&c->g, p->extra[i]);
    }
    if (p->st_after) {
        vmem(c, d, vst_tab[vlog2(p->st_after)], true, VSTAGE, p->st_after, false);
    }
    c->hf = HF_NONE;
    if (e->kind == VXK_FLAGS || e->kind == VXK_TEST ||
        (e->kind == VXK_KOP && ((e->aux & 31) == 13 || (e->aux & 31) == 14))) {
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
    }
}

/*
 * A VEX insn, @lead (C4 or C5) and the legacy prefixes before it read (in
 * 32-bit code the caller has seen the byte after it start with two set bits:
 * otherwise C4 and C5 are les and lds). Anything the table does not have is
 * TCG's. An encoding the hardware rejects is #UD here, as iSH-AOK's table
 * says.
 *
 * 32-bit code has eight vector registers. As iSH-AOK's gen_vex32 has it (an
 * AMD Ryzen and SDE): VEX.R, X and B are no register bits there, and vvvv's
 * bit 3 is none either, but it still counts where vvvv must be 1111b
 * (vvvv_hi); W is ignored where it would make a GPR 64 bits (VMOVD, VCVT*SI*,
 * VPEXTRD, VPINSRD, KMOVD, BMI's); VZEROUPPER and VZEROALL clear eight
 * registers.
 * These gadgets take it rather than TCG for AVX-512's sake: TCG's VEX clears
 * a destination only to bit 255, and the EVEX code beside it reads to 511.
 */
static int vex(Ctx *c, Insn *d, const uint8_t *code, unsigned lead)
{
    const struct vex_entry *e;
    struct vex_insn v = { 0 };
    struct vex_plan p;
    unsigned b1, b2;
    bool r, x, b, c32 = !c->c64;

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
    if (c32) {
        r = x = b = false;
        v.vvvv_hi = v.vvvv > 7;
        v.vvvv &= 7;
        if ((v.map == 1 && v.pp == 1 && (v.op == 0x6e || v.op == 0x7e)) ||
            (v.map == 1 && (v.op == 0x2a || v.op == 0x2c || v.op == 0x2d)) ||
            (v.map == 3 && (v.op == 0x16 || v.op == 0x22)) ||
            (v.map == 1 && v.pp == 3 && (v.op == 0x92 || v.op == 0x93)) ||
            (v.map == 2 && v.op >= 0xf2 && v.op <= 0xf7 && v.op != 0xf4) ||
            (v.map == 3 && v.op == 0xf0)) {
            v.w = 0;                    /* (and BMI's: ANDN to SHRX, RORX) */
        }
    }
    if (v.map == 1 && v.op == 0x77) {           /* vzeroupper, vzeroall */
        if (!c->avx) {
            return UNKNOWN;
        }
        v.rm = c32 ? 8 : 16;
        if (!vex_plan(&v, &p, false) || p.type == VP_UD) {
            return vex_ud(c, d, code);
        }
        FIN();
        E1(p.gadget, p.word);
        c->hf = HF_NONE;
        return NEXT;
    }
    if (vex_via_evex(v.map, v.pp, v.op)) {      /* GFNI, AES, VPCLMUL, VNNI: EVEX's ops */
        unsigned p0, p1, p2;

        if (!c->avx) {
            return UNKNOWN;
        }
        vex_to_evex(r, x, b, v.map, v.w, v.vvvv | (v.vvvv_hi ? 8 : 0), v.l, v.pp,
                    &p0, &p1, &p2);
        return evex_at(c, d, code, p0, p1, p2, v.op, EVF_VEX);
    }
    d->rr = r ? 8 : 0;
    d->rx = x ? 8 : 0;
    d->rb = b ? 8 : 0;
    modrm(d);
    v.reg = d->reg & 15;
    v.rm = (d->rm & 7) | d->rb;
    v.mem = d->mod != 3;
    v.vsib_index = -1;
    if (d->bad) {
        return UNKNOWN;
    }
    e = vex_lookup(&v);
    if (e && e->kind == VXK_BMI ? !(c->bmi1 && c->bmi2) : !c->avx) {
        return UNKNOWN;
    }
    if (!e) {
        return vex_ud(c, d, code);
    }
    if ((e->kind == VXK_KOP && !c->avx512) || e->kind == VXK_GATHER ||
        e->kind == VXK_SPECIAL) {
        return UNKNOWN;         /* (not here yet: QEMU's engine's) */
    }
    if (vex_has_imm8(v.map, v.op)) {
        v.imm = f8(d);
    }
    if (d->bad) {
        return UNKNOWN;
    }
    if (c32 && e->kind == VXK_BLENDV && (v.imm >> 4) >= 8) {
        return vex_ud(c, d, code);      /* imm8's register: xmm8-15 are none in 32-bit code */
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
        vex_frame(c, d, e, &p, false);
        return NEXT;
    case VP_MASKED: {
        /*
         * VMASKMOV*, VPMASKMOV*: the mask's signs to VM_KSTAGE, then
         * gadgets-vec.S's masked load (masked-off elements zeroed by
         * vmskld) or store, which touch only the enabled elements.
         */
        unsigned esz = p.masked_esz == 8 ? 3 : 2;
        uint64_t w = (v.l ? 1ull << 16 : 0) | (uint64_t)esz << (p.masked_store ? 44 : 22);

        E1(G(vmskk), (v.vvvv & 15) | (esz == 3 ? 16 : 0));
        if (p.masked_store) {
            E2(G(vmov128), VSTAGE, X(v.reg));
            E2(G(vmov128), VSTAGE + 16, X(v.reg) + 16);
            vmem_w(c, d, vstm_tab, true, w, vlog2(16u << v.l) | 32);
        } else {
            vmem_w(c, d, vldm_tab, true, w, vlog2(16u << v.l) | 32);
            E1(G(vmskld), (v.reg & 15) | (v.vvvv & 15) << 4 |
               (esz == 3 ? 1 << 8 : 0) | (v.l ? 1 << 9 : 0));
        }
        c->hf = HF_NONE;
        return NEXT;
    }
    default:                    /* gathers, the specials: TCG's */
        return UNKNOWN;
    }
}

/* ---- EVEX: this front end's emitter -------------------------------------------- */


/*
 * A masked operand's elements (gadgets-vec.S's vm_elems): the EVEX word's
 * opmask, the field at bit @ks (and the log2 of the elements' size 4 bits
 * up), over the operand's elements: 16 << VL bytes, or 1 << bits 59-61 with
 * bit 58 (a narrowing store's). With @sz | 32 (the host's word) the mask
 * is vmskk's (VEX's VMASKMOV).
 */
static uint64_t vm_elems(CPUX86State *env, uint64_t w, uint32_t sz, int ks,
                         unsigned *bytes, unsigned *esz)
{
    uint64_t k = sz & 32 ? ldq_le_p(env->aok_vstage + 248)      /* (vmskk's) */
                         : env->opmask_regs[(w >> ks) & 7];
    unsigned n;

    *esz = (w >> (ks + 4)) & 3;
    *bytes = (w >> 58) & 1 ? 1u << ((w >> 59) & 7) : 16u << ((w >> 16) & 3);
    n = *bytes >> *esz;
    return n < 64 ? k & ((1ull << n) - 1) : k;
}

/*
 * Which of an operand's two pages, [0, *split) and [*split, bytes), an
 * enabled element has a byte in. Compress and expand (word bit 62) touch
 * the first popcount(k) elements, but fault as SDE has them, by the enabled
 * elements' own positions: those reach at least as far as the packed ones,
 * so the first page if any element is enabled, the second by position.
 */
static void vm_needs(uint64_t w, uint64_t k, uint64_t addr, unsigned bytes,
                     unsigned esz, unsigned *split, bool need[2])
{
    unsigned s = MIN(TARGET_PAGE_SIZE - (addr & ~TARGET_PAGE_MASK), bytes);
    unsigned lo = (s + (1u << esz) - 1) >> esz;

    *split = s;
    need[0] = (lo >= 64 ? k : k & ((1ull << lo) - 1)) != 0;
    need[1] = s < bytes && (k >> (s >> esz)) != 0;
    if ((w >> 62) & 1) {
        need[0] = k != 0;
    }
}

/*
 * A masked load to the stage (gadgets-vec.S's vldm, past its fast path): a
 * page an enabled element needs is read whole, one none does is not read
 * and its bytes are zeros. @sz is the host's word: | 16, the operand must
 * be aligned to its size.
 */
void aok_x86_helper_vldm(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t w);
void aok_x86_helper_vldm(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t w)
{
    MemOpIdx oi = make_memop_idx(MO_UB, cpu_mmu_index(env_cpu(env), false));
    unsigned bytes, esz, split;
    uint8_t buf[64];
    bool need[2];
    uint64_t k;

    x86_sync(env, pc);
    k = vm_elems(env, w, sz, 18, &bytes, &esz);
    if ((sz & 16) && (addr & (bytes - 1))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, 0);
    }
    vm_needs(w, k, addr, bytes, esz, &split, need);
    for (unsigned i = 0; i < bytes; i++) {
        buf[i] = need[i >= split] ? cpu_ldb_mmu(env, addr + i, oi, 0) : 0;
    }
    memcpy(env->aok_vstage, buf, bytes);
}

/*
 * A masked store from the stage (vstm, past its fast path): the enabled
 * elements (compress: the first popcount of them), each page they need
 * checked first, so that a fault leaves memory as it was. @probe: only
 * that (vwpm), the store's faults before a frame that changes state (MXCSR)
 * computes what it stores.
 */
static void x86_vstm(CPUX86State *env, uint64_t addr, uint64_t pc, uint32_t sz,
                     uint64_t w, bool probe)
{
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    MemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);
    unsigned bytes, esz, split;
    bool need[2];
    uint64_t k;

    x86_sync(env, pc);
    k = vm_elems(env, w, sz, 40, &bytes, &esz);
    if ((sz & 16) && (addr & (bytes - 1))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, 0);
    }
    vm_needs(w, k, addr, bytes, esz, &split, need);
    if (need[0]) {
        probe_write(env, addr, split, mmu_idx, 0);
    }
    if (need[1]) {
        probe_write(env, addr + split, bytes - split, mmu_idx, 0);
    }
    if (probe) {
        return;
    }
    if ((w >> 62) & 1) {
        unsigned n = ctpop64(k);

        k = n >= 64 ? -1ull : (1ull << n) - 1;
    }
    for (unsigned i = 0; i < bytes; i++) {
        if (((k >> (i >> esz)) & 1) && need[i >= split]) {
            cpu_stb_mmu(env, addr + i, env->aok_vstage[i], oi, 0);
        }
    }
}

void aok_x86_helper_vstm(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t w);
void aok_x86_helper_vstm(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t w)
{
    x86_vstm(env, addr, pc, sz, w, false);
}

void aok_x86_helper_vwpm(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t w);
void aok_x86_helper_vwpm(CPUX86State *env, uint64_t addr, uint64_t pc,
                         uint32_t sz, uint64_t w)
{
    x86_vstm(env, addr, pc, sz, w, true);
}

/*
 * Whether the CPU offers what an EVEX-table op needs that AVX-512F's frames
 * do not say by themselves: the VEX and legacy forms of AES, PCLMULQDQ,
 * GFNI and AVX-VNNI, their 256-bit and EVEX forms, and EVEX.128/256's
 * AVX512VL. (AVX-512's other subsets go with AVX512F here: the CPU offers
 * all of them or none.)
 */
static bool evex_cpuid_ok(const CPUX86State *env, const struct evex_insn *v, int from)
{
    uint32_t ecx1 = env->features[FEAT_1_ECX];
    uint32_t ecx7 = env->features[FEAT_7_0_ECX];
    bool wide = from == EVF_EVEX || v->ll != 0;

    if (from == EVF_EVEX && v->ll < 2 &&
        !(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_AVX512VL)) {
        return false;
    }
    if (v->map == 2 && v->op >= 0xdb && v->op <= 0xdf) {          /* AES */
        return (ecx1 & CPUID_EXT_AES) && (!wide || (ecx7 & CPUID_7_0_ECX_VAES));
    }
    if (v->map == 3 && v->op == 0xdf) {                             /* AESKEYGENASSIST */
        return ecx1 & CPUID_EXT_AES;
    }
    if (v->map == 3 && v->op == 0x44) {                             /* PCLMULQDQ */
        return (ecx1 & CPUID_EXT_PCLMULQDQ) &&
               (!wide || (ecx7 & CPUID_7_0_ECX_VPCLMULQDQ));
    }
    if ((v->map == 2 && v->op == 0xcf) ||
        (v->map == 3 && (v->op == 0xce || v->op == 0xcf))) {        /* GFNI */
        return ecx7 & CPUID_7_0_ECX_GFNI;
    }
    if (from == EVF_VEX && v->map == 2 && v->op >= 0x50 && v->op <= 0x53) {
        return env->features[FEAT_7_1_EAX] & CPUID_7_1_EAX_AVX_VNNI;
    }
    return true;
}

/*
 * An EVEX insn from its P0-P2 and opcode, d at its ModRM (64-bit code).
 * @from: EVF_EVEX, or a VEX or legacy SSE encoding of an op the EVEX table
 * has (GFNI, AES, PCLMULQDQ, AVX-VNNI), P0-P2 made from its fields
 * (vex_to_evex): no disp8*N, the prefixes already checked; SSE's operand is
 * 16-byte aligned and the bits above 128 are left alone (word bit 63). As
 * iSH-AOK's gen_amd64_evex_at.
 */
static int evex_at(Ctx *c, Insn *d, const uint8_t *code, unsigned p0,
                   unsigned p1, unsigned p2, unsigned op, int from)
{
    const CPUX86State *env = c->env;
    bool from_vex = from != EVF_EVEX;
    const struct evex_entry *e;
    struct evex_insn v = { 0 };
    struct evex_plan p;
    const uint8_t *mp;
    bool r, x, b, r2, v2;
    long word;

    v.map = p0 & 7;
    v.op = op;
    v.w = p1 >> 7;
    v.pp = p1 & 3;
    v.z = p2 >> 7;
    v.ll = (p2 >> 5) & 3;
    v.b = (p2 >> 4) & 1;
    v.aaa = p2 & 7;
    r = !(p0 & 0x80);
    x = !(p0 & 0x40);
    b = !(p0 & 0x20);
    r2 = !(p0 & 0x10);
    v2 = !(p2 & 8);
    v.vvvv = ((~p1 >> 3) & 15) | (v2 ? 16 : 0);
    if (v.map == 0 || v.map > 3 || (p0 & 0x08) || !(p1 & 4)) {
        return vex_ud(c, d, code);      /* map 0, 4-7, or a reserved bit */
    }
    if (!c->c64) {
        /*
         * 32-bit code, as iSH-AOK's gen_evex32_at has it (SDE): eight
         * registers, so EVEX.R, X, B and R' are no register bits and nor is
         * vvvv's bit 3, which still counts where vvvv must be 1111b
         * (vvvv_hi); V' set is #UD. W is ignored where it would make a GPR
         * 64 bits: VCVT(U)SI2SS/SD, VCVT(T)SS/SD2(U)SI, VMOVD/Q, VPEXTRD/Q,
         * VPINSRD/Q, VPBROADCASTD/Q from a GPR (the SDM's N.E.); VPINSRB/W
         * are WIG.
         */
        if (v2) {
            return vex_ud(c, d, code);
        }
        r = x = b = r2 = false;
        v.vvvv_hi = ((~p1 >> 3) & 15) > 7;
        v.vvvv = (~p1 >> 3) & 7;
        if ((v.map == 1 && (v.pp == 2 || v.pp == 3) &&
             (v.op == 0x2a || v.op == 0x2c || v.op == 0x2d || v.op == 0x78 ||
              v.op == 0x79 || v.op == 0x7b)) ||
            (v.map == 1 && v.pp == 1 && (v.op == 0x6e || v.op == 0x7e)) ||
            (v.map == 3 && v.pp == 1 && (v.op == 0x16 || v.op == 0x22 || v.op == 0x20)) ||
            (v.map == 1 && v.pp == 1 && v.op == 0xc4) ||
            (v.map == 2 && v.pp == 1 && v.op == 0x7c)) {
            v.w = 0;
        }
    }
    d->rr = (r ? 8 : 0) | (r2 ? 16 : 0);
    d->rx = x ? 8 : 0;
    d->rb = b ? 8 : 0;
    mp = d->p;
    modrm(d);
    if (d->bad) {
        return UNKNOWN;
    }
    v.reg = d->reg;
    v.mem = d->mod != 3;
    v.rm = (mp[0] & 7) | d->rb | (!v.mem && x ? 16 : 0);
    e = evex_lookup(&v);
    if (!e) {
        for (unsigned i = 0; i < ARRAY_SIZE(evex_table); i++) {
            if (evex_table[i].map == v.map && evex_table[i].pp == v.pp &&
                evex_table[i].op == v.op &&
                (evex_table[i].grp == 0 || evex_table[i].grp == (v.reg & 7) + 1)) {
                return vex_ud(c, d, code);  /* here, but not with this W */
            }
        }
        return from_vex ? UNKNOWN : vex_ud(c, d, code);
    }
    if (!from_vex && (d->o16 || d->rep || d->repne || d->lock || d->rex)) {
        return vex_ud(c, d, code);      /* a legacy prefix or REX before 62 */
    }
    if ((e->flags & EVF_LEGACY) && (from == EVF_EVEX || v.ll != 0)) {
        return vex_ud(c, d, code);
    }
    if (!evex_cpuid_ok(env, &v, from)) {
        return vex_ud(c, d, code);
    }
    if (evex_has_imm8(v.map, v.op)) {
        v.imm = f8(d);
    }
    if (d->bad) {
        return UNKNOWN;
    }
    if (v.mem && d->mod == 1 && !from_vex) {
        d->m.disp *= evex_disp_scale(e, &v);
    }

    if (e->kind == EVK_EXTR) {
        word = from_vex ? -1 : gen_evex_extr_word(e, &v, (e->flags & EVF_EXTR_SWAP) ?
                                                  v.reg & 15 : v.rm & 15);
        if (word < 0) {
            return vex_ud(c, d, code);
        }
        FIN();
        E1(e->gadget, word);
        if (v.mem) {
            vmem(c, d, vst_tab[vlog2(e->ld)], true, VSTAGE, e->ld, false);
        }
        c->hf = HF_NONE;
        return NEXT;
    }
    if (e->kind == EVK_CVT2GPR) {
        word = from_vex ? -1 : gen_evex_cvt2gpr_word(e, &v, v.reg & 15);
        if (word < 0) {
            return vex_ud(c, d, code);
        }
        FIN();
        if (v.mem) {
            vmem(c, d, vld_tab[vlog2(e->ld)], false, 0, e->ld, false);
        }
        E1(e->gadget, word);
        c->hf = HF_NONE;
        return NEXT;
    }
    if (e->kind == EVK_GATHER || e->kind == EVK_SCATTER) {
        bool sib = v.mem && (mp[0] & 7) == 4;
        unsigned s = sib ? mp[1] : 0;
        Insn base = *d;

        word = from_vex ? -1 :
               gen_evex_vsib_word(e, &v, sib, ((s >> 3) & 7) | (x ? 8 : 0) | (v2 ? 16 : 0),
                                  s >> 6);
        if (word < 0) {
            return vex_ud(c, d, code);
        }
        if (!c->c64) {
            word |= 1l << 22;           /* each element's address wraps at 4 GB */
        }
        FIN();
        base.m.index = -1;      /* the address without the index: the vector register's */
        vmem(c, &base, e->kind == EVK_GATHER ? vgather_tab : vscatter_tab, true, word,
             v.w ? 8 : 4, false);
        return NEXT;
    }

    evex_plan(&v, &p);
    if (p.ud) {
        return vex_ud(c, d, code);
    }
    if (from == EVF_SSE) {
        p.word |= 1ull << 63;
        if (v.mem && !p.align) {
            p.align = 16;
        }
    }
    FIN();
    if (p.gpr_stage >= 0) {
        E1(G(vex_gst_amd64), (p.gpr_stage & 15) | (p.gpr_w ? 16 : 0));
    }
    if (p.bcast) {
        vmem(c, d, vldb_tab[p.ld_masked][p.bcast == 3], p.ld_masked, p.ld_word,
             1u << p.bcast, false);
    } else if (p.ld_bytes && p.ld_masked) {
        vmem(c, d, vldm_tab, true, p.ld_word, p.ld_bytes, p.align);
    } else if (p.ld_bytes) {
        vmem(c, d, p.align ? vlda_tab[vlog2(p.ld_bytes)] : vld_tab[vlog2(p.ld_bytes)],
             false, 0, p.ld_bytes, p.align);
    }
    if (p.st_bytes && e->kind == EVK_CVTNR) {
        /* VCVTPS2PH to memory: the store's faults before MXCSR changes */
        if (p.st_masked) {
            vmem(c, d, vwpm_tab, true, p.word, p.st_bytes, false);
        } else {
            vmem(c, d, vwp_tab[vlog2(p.st_bytes)], false, 0, p.st_bytes, false);
        }
    }
    aok_emit_gadget(&c->g, e->gadget);
    aok_emit(&c->g, p.word);
    if (p.st_bytes) {
        if (p.st_masked) {
            vmem(c, d, vstm_tab, true, p.word, p.st_bytes, p.align);
        } else {
            vmem(c, d, p.align ? vsta_tab[vlog2(p.st_bytes)] : vst_tab[vlog2(p.st_bytes)],
                 true, VSTAGE, p.st_bytes, p.align);
        }
    }
    c->hf = HF_NONE;
    if (e->kind == EVK_FLAGS) {
        set_flags(c, HF_NONE, CC_OP_EFLAGS);
    }
    return NEXT;
}

/*
 * An EVEX insn (62 read), with AVX-512 enabled: in 64-bit code, or in 32-bit
 * code where the byte after 62 starts with two set bits (the caller's; bound
 * otherwise). TCG's otherwise, which raises #UD.
 */
static int evex(Ctx *c, Insn *d, const uint8_t *code)
{
    unsigned p0, p1, p2, op;

    if (!c->avx512) {
        return UNKNOWN;
    }
    p0 = f8(d);
    p1 = f8(d);
    p2 = f8(d);
    op = f8(d);
    if (d->bad) {
        return UNKNOWN;
    }
    return evex_at(c, d, code, p0, p1, p2, op, EVF_EVEX);
}

/*
 * The legacy SSE forms of GFNI, AES and PCLMULQDQ (66 0F 38 or 3A, @esc
 * read): EVEX's ops, as iSH-AOK computes them. The rest of 0F 38 and 0F 3A
 * is TCG's.
 */
static int sse_evex(Ctx *c, Insn *d, const uint8_t *code, unsigned esc)
{
    unsigned map = esc == 0x38 ? 2 : 3, op, vvvv = 0, p0, p1, p2;

    if (!c->sse || d->end - d->p < 2) {
        return UNKNOWN;
    }
    op = d->p[0];
    if (!d->o16 || d->rep || d->repne || d->lock || d->a32 ||
        !sse_via_evex(map, op)) {
        return UNKNOWN;
    }
    /* s1 is the destination (the ModRM reg); AESIMC, AESKEYGENASSIST have none */
    if (!sse_via_evex_unary(map, op)) {
        vvvv = ((d->p[1] >> 3) & 7) | d->rr;
    }
    d->p++;
    vex_to_evex(d->rr != 0, d->rx != 0, d->rb != 0, map, map == 3, vvvv, false, 1,
                &p0, &p1, &p2);
    return evex_at(c, d, code, p0, p1, p2, op, EVF_SSE);
}

/*
 * Whether the insn at @p, in 64-bit code or (@c64 false) flat 32-bit code,
 * is one only these gadgets compute: EVEX's, the opmask insns, and the VEX
 * and legacy forms of the EVEX table's ops (TCG has neither AVX-512 nor GFNI
 * nor AVX-VNNI, and would raise #UD): 1, or 0; -1 if what tells runs past
 * @end (the page's: ask again with the next page's bytes after). Then a TB
 * that is TCG's otherwise (one being stepped) is this translator's, of that
 * insn alone (x86_aok_translate_code). In 32-bit code 40-4F are no REX, and
 * C4, C5 and 62 are VEX and EVEX only before a byte that starts with two set
 * bits.
 */
static int x86_aok_only(const uint8_t *p, const uint8_t *end, bool c64,
                        bool avx, bool avx512)
{
    struct vex_insn v = { 0 };
    const struct vex_entry *e;
    bool o16 = false;
    unsigned b;

    for (;;) {
        if (p >= end) {
            return -1;
        }
        b = *p++;
        if (b == 0x66) {
            o16 = true;
        } else if (!(b == 0x67 || b == 0xf0 || b == 0xf2 || b == 0xf3 ||
                     b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
                     b == 0x64 || b == 0x65)) {
            break;
        }
    }
    if (c64 && (b & 0xf0) == 0x40) {
        if (p >= end) {
            return -1;
        }
        b = *p++;
    }
    if ((b == 0x62 || b == 0xc4 || b == 0xc5 || b == 0x0f) &&
        end - p < (b == 0xc4 ? 4 : b == 0xc5 ? 3 : 2)) {
        return -1;                      /* the bytes looked at below */
    }
    if (!c64 && (b == 0x62 || b == 0xc4 || b == 0xc5) && (p[0] & 0xc0) != 0xc0) {
        return 0;                       /* bound, les, lds */
    }
    switch (b) {
    case 0x62:
        return avx512;
    case 0xc4:
    case 0xc5:
        if (b == 0xc5) {
            v.map = 1;
            v.l = (p[0] >> 2) & 1;
            v.pp = p[0] & 3;
            p += 1;
        } else {
            v.map = p[0] & 0x1f;
            v.w = p[1] >> 7;
            v.l = (p[1] >> 2) & 1;
            v.pp = p[1] & 3;
            p += 2;
        }
        v.op = p[0];
        v.reg = (p[1] >> 3) & 7;
        if (vex_via_evex(v.map, v.pp, v.op)) {
            return avx;
        }
        e = vex_lookup(&v);
        return avx512 && e && e->kind == VXK_KOP;
    case 0x0f:
        return o16 && (p[0] == 0x38 || p[0] == 0x3a) &&
               sse_via_evex(p[0] == 0x38 ? 2 : 3, p[1]);
    default:
        return 0;
    }
}

/*
 * For TCG's translator, at an insn of a TB that is TCG's (this translator
 * declined its first insn), not that first one: whether it is one only these
 * gadgets compute (x86_aok_only), which TCG would raise #UD for. TCG then
 * ends its TB before it, and the TB that starts there is this translator's.
 * OpenSSL's AVX-512 RSA has an 8-bit adc (TCG's here) a few insns before a
 * kmovb.
 */
bool x86_aok_tcg_stop(uint32_t flags, const uint8_t *p, const uint8_t *end)
{
    bool c64 = flags & HF_CS64_MASK;

    /*
     * (-1, an insn that runs into the next page: TCG ends its TB before
     * that anyway, and this translator has the TB that starts with it.)
     */
    return aok_enabled && (c64 ? !x86_no64 : x86_aok_flat32(flags) && !x86_no32) &&
           x86_aok_only(p, end, c64, !(flags & (HF_EM_MASK | HF_TS_MASK)) &&
                        (flags & HF_OSFXSR_MASK) && (flags & HF_AVX_EN_MASK),
                        flags & HF_AVX512_EN_MASK) == 1;
}

/* The end of such a TB: at the next insn, the main loop's. */
void aok_x86_helper_eob(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b);
void aok_x86_helper_eob(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b)
{
    x86_sync(env, pc);
}

/* ... and of one being stepped (EFLAGS.TF): its #DB, after the insn. */
void aok_x86_helper_tf(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b);
void aok_x86_helper_tf(CPUX86State *env, uint64_t pc, uint64_t a, uint64_t b)
{
    x86_sync(env, pc);
    helper_single_step(env);
}

/*
 * A legacy SSE op as its VEX form computes it: the frames are exact to x86
 * (which NaN, DAZ in MINPS and MAXPS, the flags, RCPPS's table), where
 * QEMU's softfloat helpers are not, and SSSE3 to SSE4.1 are TCG's
 * otherwise. VEX's dst = s1 OP s2 with s1 the destination, at L 0, the
 * word's bit 15 keeping bits 511:128 as a legacy write does; a 16-byte
 * operand in memory must be aligned. The ops: 0F's floating point and its
 * conversions, and the 66 0F 38 and 66 0F 3A ops of SSSE3 and SSE4.1 that
 * have a VEX form (legacy BLENDV's implicit xmm0 is the VEX form's mask
 * register). @map: 1 (0F), 2 (0F 38), 3 (0F 3A); @pfx: none, 66, F3, F2.
 * UNKNOWN for anything else (the caller's other path).
 */
static bool sse_vex_op(unsigned map, unsigned op, int pfx)
{
    switch (map) {
    case 1:
        /* (and SSE2's integer ops the SSE path above has not) */
        return op == 0x51 || op == 0x52 || op == 0x53 || (op >= 0x58 && op <= 0x5f) ||
               op == 0xc2 || op == 0x2a || op == 0x2c || op == 0x2d || op == 0x2e ||
               op == 0x2f || op == 0xd0 || op == 0x7c || op == 0x7d || op == 0xe6 ||
               (op == 0x12 && pfx >= 2) || (op == 0x16 && pfx == 2) ||
               (pfx == 1 && (op == 0x63 || op == 0x67 || op == 0x6b ||
                             (op >= 0xd1 && op <= 0xd3) || op == 0xe1 || op == 0xe2 ||
                             op == 0xe4 || op == 0xe5 || (op >= 0xf1 && op <= 0xf6)));
    case 2:
        return pfx == 1 && (op <= 0x0b || op == 0x10 || op == 0x14 || op == 0x15 ||
                            op == 0x17 || (op >= 0x1c && op <= 0x1e) ||
                            (op >= 0x20 && op <= 0x25) || op == 0x28 || op == 0x29 ||
                            op == 0x2b || (op >= 0x30 && op <= 0x35) ||
                            (op >= 0x37 && op <= 0x41));
    case 3:
        return pfx == 1 && ((op >= 0x08 && op <= 0x0f) || op == 0x20 || op == 0x21 ||
                            op == 0x22 || (op >= 0x40 && op <= 0x42));
    default:
        return false;
    }
}

/*
 * Whether the CPU offers such an op: SSE3's (ADDSUB, HADD, HSUB, MOVDDUP,
 * MOVSLDUP, MOVSHDUP), SSSE3's, SSE4.1's, SSE4.2's PCMPGTQ. (Without, TCG
 * raises the #UD.)
 */
static bool sse_vex_cpuid_ok(const CPUX86State *env, unsigned map, unsigned op)
{
    uint32_t ecx = env->features[FEAT_1_ECX];

    switch (map) {
    case 1:
        if (op == 0xd0 || op == 0x7c || op == 0x7d || op == 0x12 || op == 0x16) {
            return ecx & CPUID_EXT_SSE3;
        }
        return true;
    case 2:
        if (op <= 0x0b || (op >= 0x1c && op <= 0x1e)) {
            return ecx & CPUID_EXT_SSSE3;
        }
        return ecx & (op == 0x37 ? CPUID_EXT_SSE42 : CPUID_EXT_SSE41);
    default:
        return ecx & (op == 0x0f ? CPUID_EXT_SSSE3 : CPUID_EXT_SSE41);
    }
}

static int sse_vex(Ctx *c, const Insn *d, unsigned map, unsigned op, int pfx,
                   int64_t imm)
{
    struct vex_insn v = { 0 };
    const struct vex_entry *e;
    struct vex_plan p;

    if (x86_novec || x86_sse_helpers || !sse_vex_op(map, op, pfx) ||
        !sse_vex_cpuid_ok(c->env, map, op)) {
        return UNKNOWN;
    }
    v.map = map;
    v.pp = pfx;
    v.op = op;
    /* W selects only for these; elsewhere legacy ignores REX.W */
    v.w = ((map == 1 && (op == 0x2a || op == 0x2c || op == 0x2d)) ||
           (map == 3 && op == 0x22)) && d->w;
    v.reg = d->reg & 15;
    v.rm = d->rm & 15;
    v.mem = d->mod != 3;
    v.vsib_index = -1;
    v.imm = map == 1 && op == 0xc2 ? imm & 7 : imm;   /* (CMPccPS: predicates 0-7) */
    if (map == 2 && (op == 0x10 || op == 0x14 || op == 0x15)) {
        /* PBLENDVB, BLENDVPS, BLENDVPD: VEX's 0F 3A 4C, 4A, 4B, the mask xmm0 */
        v.map = 3;
        v.op = op == 0x10 ? 0x4c : op == 0x14 ? 0x4a : 0x4b;
        v.imm = 0;
    }
    e = vex_lookup(&v);
    if (!e || e->gadget == aok_vec_none) {
        return UNKNOWN;
    }
    switch (e->kind) {
    case VXK_L3: case VXK_SCAL: case VXK_TBL2: case VXK_INTIN: case VXK_INSPS:
    case VXK_BLENDV: case VXK_SHX:
        v.vvvv = v.reg;             /* s1: the destination */
        break;
    case VXK_L2: case VXK_TBL1: case VXK_FLAGS: case VXK_TEST: case VXK_WIDEN:
    case VXK_NARROW: case VXK_G2R:
        break;
    default:
        return UNKNOWN;
    }
    if (!vex_plan(&v, &p, false) || p.type != VP_FRAME || p.gadget == aok_vec_none ||
        (v.mem && !p.stage_bytes && p.gpr_stage < 0)) {
        return UNKNOWN;
    }
    if (c->fp && map == 1 && (pfx == 1 || pfx == 3) &&
        (op == 0x58 || op == 0x59 || op == 0x5c || op == 0x5e || (op == 0x51 && pfx == 3))) {
        /*
         * Doubles: the host's FP unit first, where it is exact (gadgets.S's
         * fpx_*), the frame for the rest.
         */
        static const Gadget fpx[2][8] = {
            { G(fpx_addpd), G(fpx_mulpd), NULL, NULL, G(fpx_subpd), NULL, G(fpx_divpd) },
            { G(fpx_addsd), G(fpx_mulsd), NULL, NULL, G(fpx_subsd), NULL, G(fpx_divsd) },
        };
        Gadget g = op == 0x51 ? G(fpx_sqrtsd) : fpx[pfx == 3][op - 0x58];

        if (v.mem) {
            vmem(c, d, p.stage_bytes == 16 ? vlda_tab[4] : vld_tab[vlog2(p.stage_bytes)],
                 false, 0, p.stage_bytes, p.stage_bytes == 16);
        }
        E4(g, X(v.reg), v.mem ? VSTAGE : X(v.rm), p.gadget, p.word | 1ull << 15);
        c->hf = HF_NONE;
        return NEXT;
    }
    vex_frame(c, d, e, &p, true);
    return NEXT;
}

/*
 * 0F 38 and 0F 3A (@esc read): GFNI, AES and PCLMULQDQ as EVEX's ops
 * (sse_evex), SSSE3 and SSE4.1 as VEX's (sse_vex); the rest TCG's.
 */
static int sse_3byte(Ctx *c, Insn *d, const uint8_t *code, unsigned esc)
{
    unsigned map = esc == 0x38 ? 2 : 3, op;
    int pfx = d->repne ? 3 : d->rep ? 2 : d->o16 ? 1 : 0;
    int64_t imm = 0;

    if (d->p >= d->end) {
        return UNKNOWN;
    }
    op = *d->p;
    /* 66 0f 38 f6 adcx, f3 0f 38 f6 adox: integer insns, SSE or not */
    if (map == 2 && op == 0xf6 && !d->lock && !d->repne &&
        d->o16 != d->rep) {
        d->p++;
        modrm(d);
        FIN();
        return adx(c, d, d->rep);
    }
    if (!c->sse) {
        return UNKNOWN;
    }
    if (sse_via_evex(map, op)) {
        return sse_evex(c, d, code, esc);
    }
    if (d->lock || !sse_vex_op(map, op, pfx)) {
        return UNKNOWN;
    }
    d->p++;
    modrm(d);
    if (map == 3) {
        imm = fimm(d, 1);
    }
    FIN();
    return sse_vex(c, d, map, op, pfx, imm);
}
