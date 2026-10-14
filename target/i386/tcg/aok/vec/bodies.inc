/*
 * The bodies of iSH-AOK's x86 vector gadgets: what an SSE, VEX or EVEX
 * operation computes on 128 bits in q registers, as macros the frames in
 * vex.inc and evex.inc expand. Taken from iSH-AOK's
 * jit/gadgets-aarch64/math.S (commit 651f974a2, its lines from 4578 on, all
 * of them contributed by Mike Miller after iSH's 0e3a4144 and so GPLv2 as
 * well as GPLv3) on 2026-10-14; this tree's own since. Only the macros the
 * frames use are here, in math.S's order.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 */

.macro vi_body kind, op, arr, q
.ifc \kind,bin
    \op  v0.\arr, v0.\arr, v1.\arr
.endif
.ifc \kind,binr
    \op  v0.\arr, v1.\arr, v0.\arr
.endif
.ifc \kind,dq
  .if \q
    \op  v0.2d, v0.2d, v1.2d
  .else
    \op  d0, d0, d1
  .endif
.endif
.ifc \kind,mulh                      /* PMULHW (smull) / PMULHUW (umull) */
    \op  v2.4s, v0.4h, v1.4h
  .if \q
    \op\()2 v3.4s, v0.8h, v1.8h
  .endif
    shrn v0.4h, v2.4s, 16
  .if \q
    shrn2 v0.8h, v3.4s, 16
  .endif
.endif
.ifc \kind,madd                      /* PMADDWD */
    smull v2.4s, v0.4h, v1.4h
  .if \q
    smull2 v3.4s, v0.8h, v1.8h
    addp v0.4s, v2.4s, v3.4s
  .else
    addp v0.4s, v2.4s, v2.4s
  .endif
.endif
.ifc \kind,muludq                    /* PMULUDQ: the even dwords */
  .if \q
    xtn  v2.2s, v0.2d
    xtn  v3.2s, v1.2d
    umull v0.2d, v2.2s, v3.2s
  .else
    umull v0.2d, v0.2s, v1.2s
  .endif
.endif
.ifc \kind,sad                       /* PSADBW: per quadword */
  .if \q
    uabd v2.16b, v0.16b, v1.16b
    uaddlp v2.8h, v2.16b
    uaddlp v2.4s, v2.8h
    uaddlp v0.2d, v2.4s
  .else
    uabd v2.8b, v0.8b, v1.8b
    uaddlp v2.4h, v2.8b
    uaddlp v2.2s, v2.4h
    uaddlp v0.1d, v2.2s
  .endif
.endif
.ifc \kind,packbw                    /* PACKSSWB (sqxtn) / PACKUSWB (sqxtun) */
  .if \q
    \op  v0.8b, v0.8h
    \op\()2 v0.16b, v1.8h
  .else
    mov  v0.d[1], v1.d[0]
    \op  v0.8b, v0.8h
  .endif
.endif
.ifc \kind,packwd                    /* PACKSSDW */
  .if \q
    \op  v0.4h, v0.4s
    \op\()2 v0.8h, v1.4s
  .else
    mov  v0.d[1], v1.d[0]
    \op  v0.4h, v0.4s
  .endif
.endif
.endm

# ---- SSSE3 / SSE4.1 integer ops (0F 38), as more amd64_vi_* kinds: the same
# four gadgets per op (XMM/MMX x register/memory), the same layouts.
.macro vi38_body kind, op, arr, q
.ifc \kind,pshufb                        /* index & 0x0f (0x07 for MMX); bit 7 -> 0 */
  .if \q
    movi v3.16b, 0x8f
    and  v3.16b, v1.16b, v3.16b
    tbl  v0.16b, {v0.16b}, v3.16b
  .else
    movi v3.8b, 0x87
    and  v3.8b, v1.8b, v3.8b
    tbl  v0.8b, {v0.16b}, v3.8b
  .endif
.endif
.ifc \kind,hpair                         /* the even elements OP the odd: PHADDSW, PHSUB* */
    uzp1 v2.\arr, v0.\arr, v1.\arr
    uzp2 v3.\arr, v0.\arr, v1.\arr
    \op  v0.\arr, v2.\arr, v3.\arr
.endif
.ifc \kind,maddubs                       /* unsigned dst bytes x signed src bytes, pairs, saturated */
    uxtl v2.8h, v0.8b
    sxtl v4.8h, v1.8b
    mul  v2.8h, v2.8h, v4.8h
  .if \q
    uxtl2 v3.8h, v0.16b
    sxtl2 v5.8h, v1.16b
    mul  v3.8h, v3.8h, v5.8h
    uzp1 v4.8h, v2.8h, v3.8h
    uzp2 v5.8h, v2.8h, v3.8h
    sqadd v0.8h, v4.8h, v5.8h
  .else
    uzp1 v4.8h, v2.8h, v2.8h
    uzp2 v5.8h, v2.8h, v2.8h
    sqadd v0.4h, v4.4h, v5.4h
  .endif
.endif
.ifc \kind,mulhrs                        /* (a*b + 0x4000) >> 15, truncated (no saturation) */
    smull v2.4s, v0.4h, v1.4h
    rshrn v4.4h, v2.4s, 15
  .if \q
    smull2 v3.4s, v0.8h, v1.8h
    rshrn2 v4.8h, v3.4s, 15
  .endif
    mov  v0.16b, v4.16b
.endif
.ifc \kind,sign                          /* src < 0 ? -dst : src == 0 ? 0 : dst */
    cmlt v2.\arr, v1.\arr, 0
    cmeq v3.\arr, v1.\arr, 0
    neg  v4.\arr, v0.\arr
    bit  v0.16b, v4.16b, v2.16b
    bic  v0.16b, v0.16b, v3.16b
.endif
.ifc \kind,abs                           /* of the source; -128 stays 0x80 */
    abs  v0.\arr, v1.\arr
.endif
.ifc \kind,muldq                         /* PMULDQ: the even dwords, signed */
    xtn  v2.2s, v0.2d
    xtn  v3.2s, v1.2d
    smull v0.2d, v2.2s, v3.2s
.endif
.ifc \kind,minpos                        /* PHMINPOSUW: {min, its lowest index, 0...} of src */
    uminv h2, v1.8h
    dup  v3.8h, v2.h[0]
    cmeq v3.8h, v1.8h, v3.8h
    movi v4.2d, 0
    movz x9, 0x0000
    movk x9, 0x0001, lsl 16
    movk x9, 0x0002, lsl 32
    movk x9, 0x0003, lsl 48
    mov  v4.d[0], x9
    movz x9, 0x0004
    movk x9, 0x0005, lsl 16
    movk x9, 0x0006, lsl 32
    movk x9, 0x0007, lsl 48
    mov  v4.d[1], x9                     /* 0 1 ... 7 */
    orn  v4.16b, v4.16b, v3.16b          /* not equal: 0xffff */
    uminv h4, v4.8h
    movi v0.2d, 0
    mov  v0.h[0], v2.h[0]
    mov  v0.h[1], v4.h[0]
.endif
.ifc \kind,blendv                        /* PBLENDVB / BLENDVPS / BLENDVPD: by xmm0's signs */
    add  x9, _cpu, CPU_xmm
    ldr  q3, [x9]
    cmlt v3.\arr, v3.\arr, 0
    bit  v0.16b, v1.16b, v3.16b
.endif
.endm

# a chain of widenings: v1 -> v0 (8b->8h, 4h->4s, 2s->2d as given)
.macro vmovx_chain s, a1, a2, b1=, b2=, c1=, c2=
.ifc \s,s
    sxtl v0.\a1, v1.\a2
  .ifnb \b1
    sxtl v0.\b1, v0.\b2
  .endif
  .ifnb \c1
    sxtl v0.\c1, v0.\c2
  .endif
.else
    uxtl v0.\a1, v1.\a2
  .ifnb \b1
    uxtl v0.\b1, v0.\b2
  .endif
  .ifnb \c1
    uxtl v0.\c1, v0.\c2
  .endif
.endif
.endm

# ---- the 0F 3A immediate ops (amd64_v3a_*): PALIGNR (XMM, MMX), PBLENDW,
# BLENDPS, BLENDPD, MPSADBW. reg [src (0-3) | dst (4-7) | imm (8-15)], gret 1;
# mem [meta][disp][next_ip][imm], gret 4. imm in w12; v0 dst, v1 src.
.macro v3a_body kind, q
.ifc \kind,palignr                       /* (dst:src) >> 8*imm, the low half; past it, 0 */
  .if \q
    cmp  w12, 32
    mov  w9, 32
    csel w12, w9, w12, hi
    movz x9, 0x0100
    movk x9, 0x0302, lsl 16
    movk x9, 0x0504, lsl 32
    movk x9, 0x0706, lsl 48
    mov  v4.d[0], x9
    movz x9, 0x0908
    movk x9, 0x0b0a, lsl 16
    movk x9, 0x0d0c, lsl 32
    movk x9, 0x0f0e, lsl 48
    mov  v4.d[1], x9
    dup  v5.16b, w12
    add  v4.16b, v4.16b, v5.16b
    mov  v6.16b, v1.16b
    mov  v7.16b, v0.16b
    tbl  v0.16b, {v6.16b, v7.16b}, v4.16b
  .else
    cmp  w12, 16
    mov  w9, 16
    csel w12, w9, w12, hi
    movz x9, 0x0100
    movk x9, 0x0302, lsl 16
    movk x9, 0x0504, lsl 32
    movk x9, 0x0706, lsl 48
    fmov d4, x9
    dup  v5.8b, w12
    add  v4.8b, v4.8b, v5.8b
    mov  v6.d[0], v1.d[0]
    mov  v6.d[1], v0.d[0]
    tbl  v0.8b, {v6.16b}, v4.8b
  .endif
.endif
.ifc \kind,blendw                        /* imm bit i: lane i from src */
    movz x9, 0x0001
    movk x9, 0x0002, lsl 16
    movk x9, 0x0004, lsl 32
    movk x9, 0x0008, lsl 48
    mov  v4.d[0], x9
    movz x9, 0x0010
    movk x9, 0x0020, lsl 16
    movk x9, 0x0040, lsl 32
    movk x9, 0x0080, lsl 48
    mov  v4.d[1], x9
    dup  v3.8h, w12
    cmtst v3.8h, v3.8h, v4.8h
    bit  v0.16b, v1.16b, v3.16b
.endif
.ifc \kind,blendps
    and  w12, w12, 0xf
    movz x9, 0x0001
    movk x9, 0x0002, lsl 32
    mov  v4.d[0], x9
    movz x9, 0x0004
    movk x9, 0x0008, lsl 32
    mov  v4.d[1], x9
    dup  v3.4s, w12
    cmtst v3.4s, v3.4s, v4.4s
    bit  v0.16b, v1.16b, v3.16b
.endif
.ifc \kind,blendpd
    and  w12, w12, 3
    mov  x9, 1
    mov  v4.d[0], x9
    mov  x9, 2
    mov  v4.d[1], x9
    dup  v3.2d, x12
    cmtst v3.2d, v3.2d, v4.2d
    bit  v0.16b, v1.16b, v3.16b
.endif
.ifc \kind,mpsadbw                       /* 8 sums of |dst[off+i+j] - src[so+j]|, j < 4 */
    ubfx w9, w12, 2, 1
    lsl  w9, w9, 2                       /* the dst offset: 0 or 4 */
    dup  v5.16b, w9
    movz x9, 0x0100
    movk x9, 0x0302, lsl 16
    movk x9, 0x0201, lsl 32
    movk x9, 0x0403, lsl 48
    mov  v4.d[0], x9
    movz x9, 0x0302
    movk x9, 0x0504, lsl 16
    movk x9, 0x0403, lsl 32
    movk x9, 0x0605, lsl 48
    mov  v4.d[1], x9                     /* 0 1 2 3 1 2 3 4 2 3 4 5 3 4 5 6 */
    add  v4.16b, v4.16b, v5.16b
    tbl  v2.16b, {v0.16b}, v4.16b        /* windows 0-3 */
    movi v5.16b, 4
    add  v4.16b, v4.16b, v5.16b
    tbl  v3.16b, {v0.16b}, v4.16b        /* windows 4-7 */
    and  w9, w12, 3
    lsl  w9, w9, 2                       /* the src offset */
    dup  v5.16b, w9
    movz x9, 0x0100
    movk x9, 0x0302, lsl 16
    movk x9, 0x0100, lsl 32
    movk x9, 0x0302, lsl 48
    mov  v4.d[0], x9
    mov  v4.d[1], x9
    add  v4.16b, v4.16b, v5.16b
    tbl  v6.16b, {v1.16b}, v4.16b        /* src[so..so+3], four times */
    uabd v2.16b, v2.16b, v6.16b
    uabd v3.16b, v3.16b, v6.16b
    uaddlp v2.8h, v2.16b
    uaddlp v3.8h, v3.16b
    uaddlp v2.4s, v2.8h
    uaddlp v3.4s, v3.8h
    xtn  v0.4h, v2.4s
    xtn2 v0.8h, v3.4s
.endif
.endm

# v0 shifted by x10 (the count) per lane: kind srl/sra/sll, lane bits L,
# arrangement arr (8h 4s 2d / 4h 2s 1d). Clobbers x10, v2.
.macro vsh_body kind, L, arr
    cmp  x10, (\L - 1)
.ifc \kind,sra
    b.ls 1f
    mov  x10, (\L - 1)               /* past the width: all sign */
1:  neg  x10, x10
.else
    b.ls 1f
    movi v0.2d, 0                    /* past the width: all zero */
    b    2f
1:
  .ifc \kind,srl
    neg  x10, x10
  .endif
.endif
.ifc \arr,1d
    fmov d2, x10
  .ifc \kind,sra
    sshl d0, d0, d2
  .else
    ushl d0, d0, d2
  .endif
.else
  .if \L == 64
    dup  v2.\arr, x10
  .else
    dup  v2.\arr, w10
  .endif
  .ifc \kind,sra
    sshl v0.\arr, v0.\arr, v2.\arr
  .else
    ushl v0.\arr, v0.\arr, v2.\arr
  .endif
.endif
2:
.endm

.macro xf_consts t
.ifc \t,s
    mov  w9, 0x7f800000
    dup  v16.4s, w9
    mov  w9, 0x7fffff
    dup  v17.4s, w9
    mov  w9, 0x400000
    dup  v19.4s, w9
.else
    mov  x9, 0x7ff0000000000000
    dup  v16.2d, x9
    mov  x9, 0xfffffffffffff
    dup  v17.2d, x9
    mov  x9, 0x8000000000000
    dup  v19.2d, x9
.endif
.endm

.macro xf_lanes t, p                    /* v7: the lanes the op writes */
.if \p
    movi v7.16b, 0xff
.else
  .ifc \t,s
    movi d7, 0x00000000ffffffff
  .else
    movi d7, 0xffffffffffffffff
  .endif
.endif
.endm

.macro xf_denorm m, x, a, tmp           /* exponent 0, mantissa not */
    cmtst \tmp\().\a, \x\().\a, v16.\a
    cmtst \m\().\a, \x\().\a, v17.\a
    bic  \m\().16b, \m\().16b, \tmp\().16b
.endm

.macro xf_isnan m, x, a                 /* |x| above infinity */
    shl  \m\().\a, \x\().\a, 1
    ushr \m\().\a, \m\().\a, 1
    cmhi \m\().\a, \m\().\a, v16.\a
.endm

.macro xf_any m, label                  /* branch if no byte of \m is set */
    umaxv b18, \m\().16b
    fmov w11, s18
    cbz  w11, \label
.endm

# Both operands: DAZ, or DE. excl 1 = DIV (a zero divisor comes first).
.macro xf_pre2 a, excl
    mov  v4.16b, v0.16b
    mov  v5.16b, v1.16b
    xf_denorm v3, v0, \a, v2
    xf_denorm v6, v1, \a, v2
    orr  v2.16b, v3.16b, v6.16b
    and  v2.16b, v2.16b, v7.16b
    xf_any v2, .Lxp2_done_\@
    ldr  w9, [_cpu, CPU_mxcsr]
    tbz  w9, 6, .Lxp2_de_\@
    orr  v18.16b, v16.16b, v17.16b      /* DAZ: signed zeros */
    and  v3.16b, v3.16b, v18.16b
    and  v6.16b, v6.16b, v18.16b
    bic  v4.16b, v4.16b, v3.16b
    bic  v5.16b, v5.16b, v6.16b
    b    .Lxp2_done_\@
.Lxp2_de_\@:
    xf_isnan v3, v0, \a
    xf_isnan v6, v1, \a
    orr  v3.16b, v3.16b, v6.16b
    bic  v2.16b, v2.16b, v3.16b
.if \excl == 1
    shl  v6.\a, v1.\a, 1
    cmeq v6.\a, v6.\a, 0
    bic  v2.16b, v2.16b, v6.16b
.endif
    xf_any v2, .Lxp2_done_\@
    orr  w9, w9, 2
    str  w9, [_cpu, CPU_mxcsr]
.Lxp2_done_\@:
.endm

# The second operand only (SQRT): a negative one is invalid first.
.macro xf_pre1 a
    mov  v5.16b, v1.16b
    xf_denorm v6, v1, \a, v2
    and  v2.16b, v6.16b, v7.16b
    xf_any v2, .Lxp1_done_\@
    ldr  w9, [_cpu, CPU_mxcsr]
    tbz  w9, 6, .Lxp1_de_\@
    orr  v18.16b, v16.16b, v17.16b
    and  v6.16b, v6.16b, v18.16b
    bic  v5.16b, v5.16b, v6.16b
    b    .Lxp1_done_\@
.Lxp1_de_\@:
    cmlt v3.\a, v1.\a, 0
    bic  v2.16b, v2.16b, v3.16b
    xf_any v2, .Lxp1_done_\@
    orr  w9, w9, 2
    str  w9, [_cpu, CPU_mxcsr]
.Lxp1_done_\@:
.endm

.macro xf_ftz a                         /* FTZ: denormal results -> signed zeros, UE PE */
    ldr  w9, [_cpu, CPU_mxcsr]
    tbz  w9, 15, .Lxz_done_\@
    xf_denorm v3, v2, \a, v6
    and  v3.16b, v3.16b, v7.16b
    xf_any v3, .Lxz_done_\@
    orr  v18.16b, v16.16b, v17.16b
    and  v3.16b, v3.16b, v18.16b
    bic  v2.16b, v2.16b, v3.16b
    orr  w9, w9, 0x30
    str  w9, [_cpu, CPU_mxcsr]
.Lxz_done_\@:
.endm

.macro xf_minnorm m, x, t               /* lanes that are exactly +-the smallest normal */
.ifc \t,s
    mov  w9, 0x7fffffff
    dup  \m\().4s, w9
    and  \m\().16b, \x\().16b, \m\().16b
    mov  w9, 0x00800000
    dup  v31.4s, w9
    cmeq \m\().4s, \m\().4s, v31.4s
.else
    mov  x9, 0x7fffffffffffffff
    dup  \m\().2d, x9
    and  \m\().16b, \x\().16b, \m\().16b
    mov  x9, 0x0010000000000000
    dup  v31.2d, x9
    cmeq \m\().2d, \m\().2d, v31.2d
.endif
.endm

.macro xf_pow2 m, t, e                  /* every lane 2^\e */
.ifc \t,s
    mov  w9, ((\e + 127) << 23)
    dup  \m\().4s, w9
.else
    mov  x9, ((\e + 1023) << 52)
    dup  \m\().2d, x9
.endif
.endm

.macro xf_lanebits_sign m, t             /* every lane's sign bit. Clobbers x15 (not x9: */
.ifc \t,s                                /* both callers hold MXCSR there) */
    movi \m\().4s, 0x80, lsl 24
.else
    mov  x15, 0x8000000000000000
    dup  \m\().2d, x15
.endif
.endm

# Tininess: x86 decides it after rounding (to the precision, the exponent
# unbounded), the host before. They differ only where the result came out
# exactly +-the smallest normal (v21, of the lanes v7). The tail: x17 holds
# the op's FPSR, x16 the FPSR before it, v22 the candidates x86 has tiny, and
# x9 the other lanes' UFC; rebuild UFC from those and flush the tiny ones
# under FTZ (the sign kept, UE PE).
.macro xf_tiny_tail t, a, ftz=1
    and  x15, x16, 8
    orr  x9, x9, x15                     /* or from before the op */
    bic  x17, x17, 8
    orr  x17, x17, x9
    umaxv b31, v22.16b
    fmov w15, s31
    cbz  w15, 1f
    orr  x17, x17, 8                     /* a candidate x86 has tiny */
.if \ftz
    ldr  w9, [_cpu, CPU_mxcsr]
    tbz  w9, 15, 1f
    xf_lanebits_sign v3, \t
    and  v3.16b, v3.16b, v22.16b
    and  v3.16b, v3.16b, v2.16b
    bic  v2.16b, v2.16b, v22.16b
    orr  v2.16b, v2.16b, v3.16b
    orr  w9, w9, 0x30
    str  w9, [_cpu, CPU_mxcsr]
.endif
1:  msr  fpsr, x17
.endm

.macro xf_tiny_test t, a                 /* v22: v21's lanes whose v28 (scaled by 2^64) is tiny */
    fabs v28.\a, v28.\a
.ifc \t,s
    xf_pow2 v30, s, -62
.else
    xf_pow2 v30, d, -958
.endif
    fcmgt v22.\a, v30.\a, v28.\a
    and  v22.16b, v22.16b, v21.16b
.endm

# MUL/DIV of v4, v5 into v2 (x16: FPSR before the op): redo the candidates
# with an operand scaled by 2^64 -- exact, the result normal, so rounded as
# unbounded -- and the op again with them zeroed for the other lanes' UFC.
# Clobbers v20-v31, x9, x15-x17.
.macro xf_tiny op, t, a, p
    xf_minnorm v21, v2, \t
    and  v21.16b, v21.16b, v7.16b
    xf_any v21, .Lxt_done\@
    mrs  x17, fpsr
    xf_pow2 v30, \t, 64
.ifc \op,fmul                            /* scale the smaller */
    fabs v27.\a, v4.\a
    fabs v31.\a, v5.\a
    fcmge v29.\a, v31.\a, v27.\a
    fmul v27.\a, v4.\a, v30.\a
    fmul v28.\a, v5.\a, v30.\a
    bsl  v29.16b, v27.16b, v4.16b
    mov  v27.16b, v5.16b
    fabs v31.\a, v4.\a
    fabs v26.\a, v5.\a
    fcmge v31.\a, v26.\a, v31.\a
    bif  v27.16b, v28.16b, v31.16b
    fmul v28.\a, v29.\a, v27.\a
.else                                    /* the dividend */
    fmul v29.\a, v4.\a, v30.\a
    fdiv v28.\a, v29.\a, v5.\a
.endif
    xf_tiny_test \t, \a
    mov  x9, 0
.if \p
    bic  v27.16b, v4.16b, v21.16b
    bic  v28.16b, v5.16b, v21.16b
    msr  fpsr, xzr
    \op v27.\a, v27.\a, v28.\a
    mrs  x9, fpsr
    and  x9, x9, 8
.endif
    xf_tiny_tail \t, \a
.Lxt_done\@:
.endm

# CVTPD2PS/CVTSD2SS of v5 into v2's singles (v7 their lanes).
.macro xf_tiny_cvt p
    xf_minnorm v21, v2, s
    and  v21.16b, v21.16b, v7.16b
    xf_any v21, .Lxtc_done\@
    mrs  x17, fpsr
    xf_pow2 v30, d, 64
    fmul v29.2d, v5.2d, v30.2d
    fcvtn v28.2s, v29.2d
    xf_tiny_test s, 4s
    mov  x9, 0
.if \p
    sxtl v27.2d, v21.2s
    bic  v27.16b, v5.16b, v27.16b
    msr  fpsr, xzr
    fcvtn v28.2s, v27.2d
    mrs  x9, fpsr
    and  x9, x9, 8
.endif
    xf_tiny_tail s, 4s
.Lxtc_done\@:
.endm

.macro xf_defnan t                      /* v18: x86's default NaN */
.ifc \t,s
    mov  w9, 0xffc00000
    dup  v18.4s, w9
.else
    mov  x9, 0xfff8000000000000
    dup  v18.2d, x9
.endif
.endm

# A NaN result: the first operand's NaN (quieted), else the second's, else
# the default NaN. n = 2 (v0, v1) or 1 (v1).
.macro xf_nanfix t, a, n
    xf_isnan v3, v2, \a
    and  v3.16b, v3.16b, v7.16b
    xf_any v3, .Lxn_done_\@
    xf_defnan \t
    xf_isnan v5, v1, \a
    orr  v6.16b, v1.16b, v19.16b
    bsl  v5.16b, v6.16b, v18.16b
.if \n == 2
    xf_isnan v4, v0, \a
    orr  v6.16b, v0.16b, v19.16b
    bsl  v4.16b, v6.16b, v5.16b
    bit  v2.16b, v4.16b, v3.16b
.else
    bit  v2.16b, v5.16b, v3.16b
.endif
.Lxn_done_\@:
.endm

.macro xf_merge t, p                    /* the result into v2, whole */
.if \p == 0
    mov  v0.\t[0], v2.\t[0]
    mov  v2.16b, v0.16b
.endif
.endm

# ---- bodies (v0, v1 loaded; result v2) ----
.macro xf_body_arith op, t, a, p, excl
    xf_consts \t
    xf_lanes \t, \p
    xf_pre2 \a, \excl
    mrs  x16, fpsr
.if \p
    \op  v2.\a, v4.\a, v5.\a
.else
    \op  \t\()2, \t\()4, \t\()5
.endif
.ifc \op,fmul
    xf_tiny fmul, \t, \a, \p
.endif
.ifc \op,fdiv
    xf_tiny fdiv, \t, \a, \p
.endif
    xf_ftz \a
    xf_nanfix \t, \a, 2
    xf_merge \t, \p
.endm

.macro xf_body_minmax max, t, a, p
    xf_consts \t
    xf_lanes \t, \p
    xf_pre2 \a, 0
.if \p
  .if \max
    fcmgt v3.\a, v4.\a, v5.\a
  .else
    fcmgt v3.\a, v5.\a, v4.\a
  .endif
.else
  .if \max
    fcmgt \t\()3, \t\()4, \t\()5
  .else
    fcmgt \t\()3, \t\()5, \t\()4
  .endif
.endif
    bsl  v3.16b, v4.16b, v5.16b
    mov  v2.16b, v3.16b
    xf_merge \t, \p
.endm

.macro xf_body_sqrt t, a, p
    xf_consts \t
    xf_lanes \t, \p
    xf_pre1 \a
.if \p
    fsqrt v2.\a, v5.\a
.else
    fsqrt \t\()2, \t\()5
.endif
    xf_nanfix \t, \a, 1
    xf_merge \t, \p
.endm

# ADDSUB: the even lanes subtract (as an add of the negated second operand:
# the same rounding and zero signs; the NaN fix sees the original).
.macro xf_body_addsub t, a
    xf_consts \t
    xf_lanes \t, 1
    xf_pre2 \a, 0
.ifc \t,s
    mov  x9, 0x80000000
    dup  v3.2d, x9
.else
    mov  x9, 0x8000000000000000
    fmov d3, x9
.endif
    eor  v5.16b, v5.16b, v3.16b
    fadd v2.\a, v4.\a, v5.\a
    xf_ftz \a
    xf_nanfix \t, \a, 2
.endm

# HADD / HSUB: the pairs of each operand, regrouped into first (the lower
# element) and second (the upper) operands: r = lo + hi, lo - hi. The lower
# is the first operand for the NaN choice too (hardware: an AMD Ryzen).
.macro xf_body_hadd sub, t, a
    uzp1 v2.\a, v0.\a, v1.\a             /* lo elements */
    uzp2 v3.\a, v0.\a, v1.\a             /* hi elements */
    mov  v0.16b, v2.16b
    mov  v1.16b, v3.16b
.if \sub
    xf_body_arith fsub, \t, \a, 1, 0
.else
    xf_body_arith fadd, \t, \a, 1, 0
.endif
.endm

# DE for a denormal source operand (no exclusion), or DAZ.
.macro xf_pre1n a
    mov  v5.16b, v1.16b
    xf_denorm v6, v1, \a, v2
    and  v2.16b, v6.16b, v7.16b
    xf_any v2, .Lxq_done_\@
    ldr  w9, [_cpu, CPU_mxcsr]
    tbz  w9, 6, .Lxq_de_\@
    orr  v18.16b, v16.16b, v17.16b
    and  v6.16b, v6.16b, v18.16b
    bic  v5.16b, v5.16b, v6.16b
    b    .Lxq_done_\@
.Lxq_de_\@:
    orr  w9, w9, 2
    str  w9, [_cpu, CPU_mxcsr]
.Lxq_done_\@:
.endm

# DAZ only (float -> int)
.macro xf_daz a
    mov  v5.16b, v1.16b
    ldr  w9, [_cpu, CPU_mxcsr]
    tbz  w9, 6, .Lxd_done_\@
    xf_denorm v6, v1, \a, v2
    orr  v18.16b, v16.16b, v17.16b
    and  v6.16b, v6.16b, v18.16b
    bic  v5.16b, v5.16b, v6.16b
.Lxd_done_\@:
.endm

# Packed float -> int32 (s: 4 lanes; d: 2 lanes, narrowed into the low half).
# v5 the (DAZ'd) source; out v2. trunc: CVTT. Clobbers v3 v4 v6 v18.
.macro xf_f2i_packed t, a, trunc
.ifc \t,s
    mov  w9, 0x4f000000                  /* 2^31 */
    dup  v4.4s, w9
    mov  w9, 0xcf000000                  /* -2^31 */
    dup  v18.4s, w9
.else
    mov  x9, 0x41e0000000000000
    dup  v4.2d, x9
    mov  x9, 0xc1e0000000000000
    dup  v18.2d, x9
.endif
.if \trunc
    frintz v3.\a, v5.\a
.else
    frinti v3.\a, v5.\a
.endif
    fcmgt v6.\a, v4.\a, v3.\a            /* r < 2^31 (false for a NaN: IE) */
    fcmge v3.\a, v3.\a, v18.\a           /* r >= -2^31 */
    and  v6.16b, v6.16b, v3.16b          /* valid */
    xf_isnan v3, v5, \a
    orr  v3.16b, v3.16b, v6.16b
    mvn  v3.16b, v3.16b                  /* out of range and not a NaN: IE by hand */
    and  v3.16b, v3.16b, v7.16b
    xf_any v3, .Lxfi_ok_\@
    ldr  w9, [_cpu, CPU_mxcsr]
    orr  w9, w9, 1
    str  w9, [_cpu, CPU_mxcsr]
.Lxfi_ok_\@:
    and  v4.16b, v5.16b, v6.16b          /* in-range lanes only (0 elsewhere) */
.if \trunc == 0
    frintx v4.\a, v4.\a
.endif
    fcvtzs v4.\a, v4.\a
.ifc \t,s
    movi v3.4s, 0x80, lsl 24
.else
    mov  x9, 0x80000000                  /* the int32 indefinite, in the half xtn keeps */
    dup  v3.2d, x9
.endif
    bsl  v6.16b, v4.16b, v3.16b
.ifc \t,s
    mov  v2.16b, v6.16b
.else
    xtn  v2.2s, v6.2d                    /* the 64-bit results fit 32 bits; upper half 0 */
.endif
.endm

# Scalar float (lane 0 of v5) -> a GPR (w12/x12): iw 32 or 64.
.macro xf_f2i_scalar t, iw, trunc
.ifc \t,s
  .if \iw == 32
    mov  w9, 0x4f000000
  .else
    mov  w9, 0x5f000000
  .endif
    fmov s4, w9
    eor  w9, w9, 0x80000000
    fmov s18, w9
.else
  .if \iw == 32
    mov  x9, 0x41e0000000000000
  .else
    mov  x9, 0x43e0000000000000
  .endif
    fmov d4, x9
    eor  x9, x9, 0x8000000000000000
    fmov d18, x9
.endif
.if \trunc
    frintz \t\()3, \t\()5
.else
    frinti \t\()3, \t\()5
.endif
    fcmp \t\()3, \t\()3
    b.vs 8f                              /* NaN */
    fcmp \t\()3, \t\()4
    b.ge 7f
    fcmp \t\()3, \t\()18
    b.lt 7f
.if \trunc == 0
    frintx \t\()3, \t\()5
.else
    fmov \t\()3, \t\()5
.endif
.if \iw == 32
    fcvtzs w12, \t\()3
.else
    fcvtzs x12, \t\()3
.endif
    b    9f
7:  ldr  w9, [_cpu, CPU_mxcsr]           /* out of range: IE by hand (not the host's */
    orr  w9, w9, 1                       /* conversion: truncating, it can land in range, */
    str  w9, [_cpu, CPU_mxcsr]           /* inexact, and raise PE) */
    b    6f
8:  fcvtzs w12, \t\()5                   /* a NaN: the host raises IE (result unused) */
6:  mov  x12, 0x8000000000000000
.if \iw == 32
    mov  w12, 0x80000000
.endif
9:
.endm

.macro xfb_cvtps2pd
    xf_consts s
    movi d7, 0xffffffffffffffff          /* the two low singles */
    xf_pre1n 4s
    fcvtl v2.2d, v5.2s
.endm

.macro xfb_cvtpd2ps
    xf_consts d
    movi v7.16b, 0xff
    xf_pre1n 2d
    mrs  x16, fpsr
    fcvtn v2.2s, v5.2d
    xf_consts s
    movi d7, 0xffffffffffffffff
    xf_tiny_cvt 1
    xf_ftz 4s
.endm

.macro xfb_cvtss2sd
    xf_consts s
    movi d7, 0x00000000ffffffff
    xf_pre1n 4s
    fcvt d2, s5
    mov  v0.d[0], v2.d[0]
    mov  v2.16b, v0.16b
.endm

.macro xfb_cvtsd2ss
    xf_consts d
    movi d7, 0xffffffffffffffff
    xf_pre1n 2d
    mrs  x16, fpsr
    fcvt s2, d5
    xf_consts s
    movi d7, 0x00000000ffffffff
    xf_tiny_cvt 0
    xf_ftz 4s
    mov  v0.s[0], v2.s[0]
    mov  v2.16b, v0.16b
.endm

.macro xfb_cvtdq2ps
    scvtf v2.4s, v1.4s
.endm

.macro xfb_cvtdq2pd
    sxtl v2.2d, v1.2s
    scvtf v2.2d, v2.2d
.endm

.macro xfb_cvtps2dq
    xf_consts s
    movi v7.16b, 0xff
    xf_daz 4s
    xf_f2i_packed s, 4s, 0
.endm

.macro xfb_cvttps2dq
    xf_consts s
    movi v7.16b, 0xff
    xf_daz 4s
    xf_f2i_packed s, 4s, 1
.endm

.macro xfb_cvtpd2dq
    xf_consts d
    movi v7.16b, 0xff
    xf_daz 2d
    xf_f2i_packed d, 2d, 0
.endm

.macro xfb_cvttpd2dq
    xf_consts d
    movi v7.16b, 0xff
    xf_daz 2d
    xf_f2i_packed d, 2d, 1
.endm

# RCPPS/SS, RSQRTPS/SS: the host estimate (8 bits) and one Newton step
# (~16 bits; x86 guarantees 12). x86 raises no flag for these, so FPSR is
# put back afterwards. Zeros, infinities, NaNs keep the estimate's answer.
.macro xf_recip_body rsq, p
    mrs  x12, fpsr
.if \rsq
  .if \p
    frsqrte v2.4s, v1.4s
    fmul v3.4s, v1.4s, v2.4s
    frsqrts v3.4s, v3.4s, v2.4s
  .else
    frsqrte s2, s1
    fmul s3, s1, s2
    frsqrts s3, s3, s2
  .endif
.else
  .if \p
    frecpe v2.4s, v1.4s
    frecps v3.4s, v1.4s, v2.4s
  .else
    frecpe s2, s1
    frecps s3, s1, s2
  .endif
.endif
    fmul v3.4s, v2.4s, v3.4s
    msr  fpsr, x12
    mov  w9, 0x7f800000
    dup  v16.4s, w9
    cmtst v4.4s, v2.4s, v16.4s           /* exponent nonzero */
    and  v5.16b, v2.16b, v16.16b
    cmeq v5.4s, v5.4s, v16.4s            /* exponent all ones */
    bic  v4.16b, v4.16b, v5.16b          /* finite, nonzero, normal: refine */
    bit  v2.16b, v3.16b, v4.16b
.if \rsq                                 /* a negative (non-zero, non-NaN) operand: */
    cmlt v3.4s, v1.4s, 0                 /* x86's default NaN, which is negative */
    shl  v4.4s, v1.4s, 1
    cmeq v5.4s, v4.4s, 0
    bic  v3.16b, v3.16b, v5.16b          /* not -0 */
    mov  w9, 0xff000000
    dup  v5.4s, w9
    cmhi v4.4s, v4.4s, v5.4s             /* |x| << 1 above inf << 1: a NaN */
    bic  v3.16b, v3.16b, v4.16b
    mov  w9, 0xffc00000
    dup  v5.4s, w9
    bit  v2.16b, v5.16b, v3.16b
.endif
.if \p == 0
    mov  v0.s[0], v2.s[0]
    mov  v2.16b, v0.16b
.endif
.endm

.macro xf_dup_body kind
.ifc \kind,sl
    trn1 v2.4s, v1.4s, v1.4s
.endif
.ifc \kind,sh
    trn2 v2.4s, v1.4s, v1.4s
.endif
.ifc \kind,dd
    dup  v2.2d, v1.d[0]
.endif
.endm

# ROUNDPS/PD/SS/SD (66 0F 3A 08-0B): imm[1:0] the mode (nearest, down, up,
# zero) unless imm[2], which takes MXCSR's; imm[3] suppresses PE. DAZ
# applies; DE is not raised. An SNaN raises IE and comes back quieted (the
# host's FRINT* do both); PE, which they never raise, is set here when a
# result differs from its (non-NaN) operand. imm in w12. Frames as amd64_xf.
.macro xf_round_op t, a, p, insn
.if \p
    \insn v2.\a, v5.\a
.else
    \insn \t\()2, \t\()5
.endif
.endm

.macro xf_body_round t, a, p
    xf_consts \t
    xf_lanes \t, \p
    xf_daz \a
    tbnz w12, 2, 14f
    and  w9, w12, 3
    cbz  w9, 10f
    cmp  w9, 1
    b.eq 11f
    cmp  w9, 2
    b.eq 12f
    xf_round_op \t, \a, \p, frintz
    b    15f
10: xf_round_op \t, \a, \p, frintn
    b    15f
11: xf_round_op \t, \a, \p, frintm
    b    15f
12: xf_round_op \t, \a, \p, frintp
    b    15f
14: xf_round_op \t, \a, \p, frinti
15: tbnz w12, 3, 16f                     /* PE suppressed */
    cmeq v3.\a, v2.\a, v5.\a             /* (integer compare: no flags) */
    xf_isnan v4, v5, \a
    orr  v3.16b, v3.16b, v4.16b
    mvn  v3.16b, v3.16b                  /* changed, not a NaN */
    and  v3.16b, v3.16b, v7.16b
    xf_any v3, 16f
    ldr  w9, [_cpu, CPU_mxcsr]
    orr  w9, w9, 0x20
    str  w9, [_cpu, CPU_mxcsr]
16: xf_merge \t, \p
.endm

# DPPS / DPPD (66 0F 3A 40 41): the lanes imm[7:4] (DPPD imm[5:4]) select are
# multiplied -- the others are +0, so they raise nothing -- then summed as x86
# does, (p0 + p1) + (p2 + p3) for DPPS, each step rounded and given the same
# DAZ/DE, FTZ and NaN treatment as a lone op; the sum goes to the lanes
# imm[3:0] (imm[1:0]) select, zero elsewhere. imm in w12.
.macro xf_lanebits t, sh, dst            /* \dst: the lanes whose bit of imm >> \sh is set */
.ifc \t,s
    movz x9, 1
    movk x9, 2, lsl 32
    mov  v18.d[0], x9
    movz x9, 4
    movk x9, 8, lsl 32
    mov  v18.d[1], x9
    lsr  w9, w12, \sh
    and  w9, w9, 0xf
    dup  \dst\().4s, w9
    cmtst \dst\().4s, \dst\().4s, v18.4s
.else
    mov  x9, 1
    mov  v18.d[0], x9
    mov  x9, 2
    mov  v18.d[1], x9
    lsr  w9, w12, \sh
    and  w9, w9, 3
    dup  \dst\().2d, x9
    cmtst \dst\().2d, \dst\().2d, v18.2d
.endif
.endm

.macro xf_body_dpps
    xf_consts s
    xf_lanebits s, 4, v7
    and  v0.16b, v0.16b, v7.16b
    and  v1.16b, v1.16b, v7.16b
    xf_pre2 4s, 0
    mrs  x16, fpsr
    fmul v2.4s, v4.4s, v5.4s
    xf_tiny fmul, s, 4s, 1
    xf_ftz 4s
    xf_nanfix s, 4s, 2
    uzp1 v0.4s, v2.4s, v2.4s             /* p0 p2 */
    uzp2 v1.4s, v2.4s, v2.4s             /* p1 p3 */
    movi d7, 0xffffffffffffffff
    xf_pre2 4s, 0                        /* the products are operands now: DAZ, DE */
    fadd v2.4s, v4.4s, v5.4s
    xf_ftz 4s
    xf_nanfix s, 4s, 2
    mov  v0.16b, v2.16b
    dup  v1.4s, v2.s[1]
    movi d7, 0x00000000ffffffff
    xf_pre2 4s, 0
    fadd s2, s4, s5
    xf_ftz 4s
    xf_nanfix s, 4s, 2
    dup  v2.4s, v2.s[0]
    xf_lanebits s, 0, v3
    and  v2.16b, v2.16b, v3.16b
.endm

.macro xf_body_dppd
    xf_consts d
    xf_lanebits d, 4, v7
    and  v0.16b, v0.16b, v7.16b
    and  v1.16b, v1.16b, v7.16b
    xf_pre2 2d, 0
    mrs  x16, fpsr
    fmul v2.2d, v4.2d, v5.2d
    xf_tiny fmul, d, 2d, 1
    xf_ftz 2d
    xf_nanfix d, 2d, 2
    mov  v0.16b, v2.16b
    dup  v1.2d, v2.d[1]
    movi d7, 0xffffffffffffffff
    xf_pre2 2d, 0
    fadd d2, d4, d5
    xf_ftz 2d
    xf_nanfix d, 2d, 2
    dup  v2.2d, v2.d[0]
    xf_lanebits d, 0, v3
    and  v2.16b, v2.16b, v3.16b
.endm

# comiss/ucomiss (0F 2F/2E) and comisd/ucomisd (66 ...): ZF/PF/CF from an
# ordered compare -- unordered sets all three, less sets CF, equal sets ZF --
# and OF/SF/AF cleared. Written straight into eflags (and the CF/OF bytes),
# lazy bits cleared. \fcmp is "fcmp s0, s1" or "fcmp d0, d1".
.macro amd64_v_comis_flags
    /* NZCV after fcmp: unordered -> C=1,V=1; lt -> N=1; eq -> Z=1; gt -> C=1 */
    mov  w15, 0
    b.vc 1f
    mov  w15, (1 | (1 << 2) | (1 << 6))     /* unordered: CF|PF|ZF */
    b    3f
1:  b.pl 2f
    mov  w15, 1                              /* less: CF */
    b    3f
2:  b.ne 3f
    mov  w15, (1 << 6)                       /* equal: ZF */
3:  x86_vflags 15
.endm
