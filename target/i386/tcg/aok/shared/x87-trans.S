# The x87's transcendentals. See x87-arith.S for the conventions.

# ===========================================================================
# The transcendentals: F2XM1, FYL2X, FYL2XP1, FPTAN, FPATAN, FSIN, FCOS,
# FSINCOS.
#
# An AMD Ryzen's results are not correctly rounded -- 2-3% of them are a unit
# away from it, from its own internal approximation, and no model of extra
# internal bits reproduces them -- so these compute the correctly rounded
# value, which is camd's in ~98% of cases and a unit from it otherwise
# (tests/manual/x86/x87_trans.c allows that unit, and C1 with it). What the
# hardware does exactly, these do exactly: the argument reduction of
# FSIN/FCOS/FPTAN/FSINCOS uses pi truncated to 66 bits (as Intel documents
# too), reducing |x| to the nearest multiple of pi66/2; |x| >= 2^63 sets C2
# and changes nothing; every special operand, the stack faults, PE (set for
# every computed result, exact or not), precision control (ignored).
#
# Values in flight are 128-bit "bigfloats" in a stack frame: [lo][hi][e][s],
# the value (-1)^s * (hi:lo) * 2^(e - 16383 - 127) with bit 127 of hi:lo set,
# or zero -- x87_round's own scale. Multiply, add and divide truncate. Each
# function is a leading term plus a power series in a small argument X (sin r
# = r + r P(r^2), cos r = 1 + P(r^2), atan u = u + u Q(u^2), atanh s = s + s
# S(s^2), expm1 t = t + t E(t)), and the series runs in 128-bit binary
# fractions against a table of coefficients until a term is zero. Where the
# leading term is exact (r, 1, u), the tail is kept apart and joined to it
# with a sticky bit, so a result just off a representable value still rounds
# the right way in every mode. Checked against a 130-digit reference over
# camd's cases: every result is the correctly rounded one, save FPTAN of
# arguments below 2^-32, where the reference itself is too short (and the
# hardware is a unit off, low, about half the time).
#
# The routines take pointers: x12 the destination (it may be an operand),
# x13 and x14 the operands. They clobber
# x0, x3-x6, x8-x11, x16, x17 and the argument registers, and keep x7 (the
# exceptions), x15 (the control word), x19 and the guests' x20-x28.
# ===========================================================================

#define BF_SIZE 32

# x10:x9 (hi:lo) with exponent x11 and sign x17, normalized, to [x12].
bf_put:
    orr x0, x9, x10
    cbz x0, 2f
    clz x0, x10
    cbnz x10, 1f
    clz x0, x9
    add x0, x0, 64
1:  cbz x0, 3f
    cmp x0, 64
    b.lo 4f
    sub x16, x0, 64
    lsl x10, x9, x16
    mov x9, 0
    b 5f
4:  neg x16, x0
    lsr x16, x9, x16
    lsl x10, x10, x0
    orr x10, x10, x16
    lsl x9, x9, x0
5:  sub x11, x11, x0
3:  stp x9, x10, [x12]
    stp x11, x17, [x12, 16]
    ret
2:  stp xzr, xzr, [x12]
    stp xzr, x17, [x12, 16]
    ret

bf_copy:                            // [x12] = [x13]
    ldp x9, x10, [x13]
    ldp x11, x17, [x13, 16]
    stp x9, x10, [x12]
    stp x11, x17, [x12, 16]
    ret
bf_neg:                             // [x12] = -[x13]
    ldp x9, x10, [x13]
    ldp x11, x17, [x13, 16]
    eor x17, x17, 1
    stp x9, x10, [x12]
    stp x11, x17, [x12, 16]
    ret
bf_int:                             // [x12] = x0, a signed integer
    lsr x17, x0, 63
    cmp x0, 0
    cneg x9, x0, lt
    mov x10, 0
    mov x11, 16383 + 127
    b bf_put
bf_from_f80:                        // [x12] = the extended value x3 / w4
    mov x9, 0
    mov x10, x3
    and w11, w4, 0x7fff
    cmp w11, 0
    csinc w11, w11, wzr, ne
    ubfx w17, w4, 15, 1
    b bf_put

# [x12] = [x13] * [x14]: the high half of the 256-bit product, exactly.
bf_mul:
    ldp x3, x4, [x13]
    ldp x5, x6, [x14]
    ldr x16, [x13, 24]
    ldr x17, [x14, 24]
    eor x17, x16, x17
    cbz x4, 9f
    cbz x6, 9f
    ldr x16, [x13, 16]
    ldr x0, [x14, 16]
    add x16, x16, x0
    mov x0, 16382
    sub x16, x16, x0
    umulh x8, x3, x5                // lo*lo, high word
    mul x9, x4, x5                  // hi*lo
    umulh x10, x4, x5
    mul x11, x3, x6                 // lo*hi
    umulh x0, x3, x6
    adds x8, x8, x9                 // word 1
    cset x9, cs
    adds x8, x8, x11
    cinc x9, x9, cs
    mul x11, x4, x6                 // hi*hi
    umulh x4, x4, x6
    adds x11, x11, x10              // word 2
    cset x10, cs
    adds x11, x11, x0
    cinc x10, x10, cs
    adds x11, x11, x9
    cinc x10, x10, cs
    add x4, x4, x10                 // word 3
    tbnz x4, 63, 1f
    extr x4, x4, x11, 63
    extr x11, x11, x8, 63
    sub x16, x16, 1
1:  stp x11, x4, [x12]
    stp x16, x17, [x12, 16]
    ret
9:  stp xzr, xzr, [x12]
    stp xzr, x17, [x12, 16]
    ret

# [x12] = [x13] + [x14] (bf_sub: - [x14]), the smaller aligned by a
# truncating shift.
bf_sub:
    mov x0, 1
    b 0f
bf_add:
    mov x0, 0
0:  ldp x3, x4, [x13]
    ldp x5, x6, [x14]
    ldp x8, x16, [x13, 16]
    ldp x10, x17, [x14, 16]
    eor x17, x17, x0
    cbz x6, 7f                      // b is zero: a
    cbz x4, 8f                      // a is zero: b
    // |a| >= |b|
    cmp x8, x10
    b.gt 2f
    b.lt 1f
    cmp x4, x6
    b.hi 2f
    b.lo 1f
    cmp x3, x5
    b.hs 2f
1:  mov x0, x3
    mov x3, x5
    mov x5, x0
    mov x0, x4
    mov x4, x6
    mov x6, x0
    mov x0, x8
    mov x8, x10
    mov x10, x0
    mov x0, x16
    mov x16, x17
    mov x17, x0
2:  sub x10, x8, x10                // the shift
    cmp x10, 128
    b.hs 7f                         // b vanishes
    cmp x10, 64
    b.lo 3f
    sub x10, x10, 64
    lsr x5, x6, x10
    mov x6, 0
    b 4f
3:  cbz x10, 4f
    neg x0, x10
    lsr x5, x5, x10
    lsl x0, x6, x0
    orr x5, x5, x0
    lsr x6, x6, x10
4:  eor x0, x16, x17
    cbnz x0, 5f
    adds x9, x3, x5
    adcs x10, x4, x6
    b.cc 6f
    extr x9, x10, x9, 1
    lsr x10, x10, 1
    orr x10, x10, 0x8000000000000000
    add x8, x8, 1
    b 6f
5:  subs x9, x3, x5
    sbc x10, x4, x6
6:  mov x11, x8
    mov x17, x16
    b bf_put
7:  // the result is a: x3 x4 x8 x16
    mov x9, x3
    mov x10, x4
    mov x11, x8
    mov x17, x16
    b bf_put
8:  mov x9, x5
    mov x10, x6
    mov x11, x10
    ldr x11, [x14, 16]
    b bf_put

# [x12] = [x13] / [x14]: the quotient truncated to 128 bits, floor(A 2^127 /
# B) for significands A and B. Its top bit is A >= B; then 32 bits at a time
# (31 the last time), each chunk c = floor(R 2^32 / B) estimated as R's top
# word over B's top 32 bits + 1 -- never over, at most 3 under -- and the
# remainder kept exact, so the corrections bring c to the floor.
bf_div:
    ldp x3, x4, [x13]
    ldp x5, x6, [x14]
    ldr x11, [x13, 16]
    ldr x0, [x14, 16]
    sub x11, x11, x0
    mov x0, 16383
    add x11, x11, x0
    ldr x17, [x13, 24]
    ldr x0, [x14, 24]
    eor x17, x17, x0
    mov x9, 0
    mov x10, 0
    cbz x4, bf_put                  // 0 / b
    stp x11, x17, [sp, -32]!
    str x12, [sp, 16]
    cmp x3, x5
    sbcs xzr, x4, x6
    cset x9, hs
    b.lo 1f
    subs x3, x3, x5
    sbc x4, x4, x6
1:  lsr x16, x6, 32
    add x16, x16, 1
    mov x17, 4
2:  cmp x17, 1
    b.eq 3f
    udiv x0, x4, x16
    lsr x8, x4, 32                  // R <<= 32, three words: x8:x4:x3
    extr x4, x4, x3, 32
    lsl x3, x3, 32
    extr x10, x10, x9, 32           // and Q
    lsl x9, x9, 32
    b 4f
3:  lsr x0, x4, 1
    udiv x0, x0, x16
    lsr x8, x4, 33
    extr x4, x4, x3, 33
    lsl x3, x3, 31
    extr x10, x10, x9, 33
    lsl x9, x9, 31
4:  mul x13, x0, x5                 // R -= c B
    umulh x14, x0, x5
    mul x11, x0, x6
    umulh x12, x0, x6
    adds x11, x11, x14
    cinc x12, x12, cs
    subs x3, x3, x13
    sbcs x4, x4, x11
    sbc x8, x8, x12
5:  cbnz x8, 6f                     // R >= B: once more
    cmp x3, x5
    sbcs xzr, x4, x6
    b.lo 7f
6:  subs x3, x3, x5
    sbcs x4, x4, x6
    sbc x8, x8, xzr
    add x0, x0, 1
    b 5b
7:  orr x9, x9, x0
    subs x17, x17, 1
    b.ne 2b
    ldr x12, [sp, 16]
    ldp x11, x17, [sp], 32
    b bf_put

# lead [x13] + tail [x14], joined with a sticky bit, for x87_round: x8:x9
# (hi:lo, unnormalized is fine), x10 the exponent, w11 the sign.
bf_join:
    ldp x3, x4, [x13]
    ldp x5, x6, [x14]
    ldp x8, x16, [x13, 16]
    ldp x10, x17, [x14, 16]
    cbz x6, 7f
    cbz x4, 8f
    cmp x8, x10
    b.gt 2f
    b.lt 1f
    cmp x4, x6
    b.hi 2f
    b.lo 1f
    cmp x3, x5
    b.hs 2f
1:  mov x0, x3
    mov x3, x5
    mov x5, x0
    mov x0, x4
    mov x4, x6
    mov x6, x0
    mov x0, x8
    mov x8, x10
    mov x10, x0
    mov x0, x16
    mov x16, x17
    mov x17, x0
2:  sub x10, x8, x10
    mov x0, 0                       // sticky
    cmp x10, 128
    b.lo 21f
    orr x0, x5, x6
    cmp x0, 0
    cset x0, ne
    mov x5, 0
    mov x6, 0
    b 4f
21: cmp x10, 64
    b.lo 3f
    sub x10, x10, 64
    mov x13, -1
    lsl x13, x13, x10
    bic x13, x6, x13
    orr x13, x13, x5
    cmp x13, 0
    cset x0, ne
    lsr x5, x6, x10
    mov x6, 0
    b 4f
3:  cbz x10, 4f
    neg x13, x10
    lsl x14, x5, x13
    cmp x14, 0
    cset x0, ne
    lsr x5, x5, x10
    lsl x13, x6, x13
    orr x5, x5, x13
    lsr x6, x6, x10
4:  eor x13, x16, x17
    cbnz x13, 5f
    adds x9, x3, x5
    adcs x10, x4, x6
    b.cc 6f
    and x13, x9, 1
    orr x0, x0, x13
    extr x9, x10, x9, 1
    lsr x10, x10, 1
    orr x10, x10, 0x8000000000000000
    add x8, x8, 1
    b 6f
5:  // a - b - sticky: the truncated part made b's magnitude a little more
    subs x9, x3, x5
    sbc x10, x4, x6
    subs x9, x9, x0
    sbc x10, x10, xzr
6:  orr x9, x9, x0
    mov x13, x8
    mov x8, x10
    mov x10, x13
    mov w11, w16
    ret
7:  mov x9, x3
    mov x10, x8
    mov x8, x4
    mov w11, w16
    ret
8:  mov x9, x5
    mov x8, x6
    mov w11, w17
    ret

// The x87_round call for a bigfloat result: [x13] -> A (x3/w4), w7's PE set
// (the hardware sets it for every computed result), C1 from the rounding.
// Clobbers what x87_round does.
.macro bf_round_slot off
    add x13, sp, \off
    ldp x9, x8, [x13]
    ldp x10, x11, [x13, 16]
    bl x87_round_bf
.endm
x87_round_bf:                       // x8:x9, x10, w11 -> A
    str lr, [sp, -16]!
    orr x0, x8, x9
    cbnz x0, 1f
    mov x3, 0
    lsl w4, w11, 15
    orr w7, w7, X87_PE
    bic w7, w7, X87_C1
    ldr lr, [sp], 16
    ret
1:  mov w16, 0
    mov w17, 0x7ffe
    bl x87_round
    // a transcendental's result is never exact to the hardware: PE always,
    // and so UE for a tiny one even where this value was exact
    orr w7, w7, X87_PE
    cbnz x10, 2f
    cbz x8, 2f
    orr w7, w7, X87_UE
2:  x87_pack
    ldr lr, [sp], 16
    ret


# x14:x13 = the high half of x6:x5 * x4:x3 (128-bit binary fractions: the
# product, truncated). Clobbers x8, x11.
.macro FX_MUL
    umulh x8, x5, x3
    mul x11, x6, x3
    umulh x13, x6, x3
    adds x8, x8, x11
    cset x11, cs
    mul x14, x5, x4
    adds x8, x8, x14
    cinc x11, x11, cs
    umulh x14, x5, x4
    adds x13, x13, x14
    cset x14, cs
    adds x13, x13, x11
    cinc x14, x14, cs
    mul x11, x6, x4
    adds x13, x13, x11
    cinc x14, x14, cs
    umulh x11, x6, x4
    add x14, x14, x11
.endm

# x10:x9 = |[x13]| as a 128-bit binary fraction (the value is below 1).
bf_fx:
    ldp x9, x10, [x13]
    ldr x11, [x13, 16]
    mov x0, 16382
    subs x11, x0, x11
    b.lt 8f                         // (never: 1 or more)
    cbz x10, 8f
    cmp x11, 128
    b.hs 8f
    cmp x11, 64
    b.lo 1f
    sub x11, x11, 64
    lsr x9, x10, x11
    mov x10, 0
    ret
1:  cbz x11, 2f
    neg x0, x11
    lsr x9, x9, x11
    lsl x0, x10, x0
    orr x9, x9, x0
    lsr x10, x10, x11
2:  ret
8:  mov x9, 0
    mov x10, 0
    ret

# x10:x9 = T = c1 + c2 X + c3 X^2 + ..., or alternating (c1 - c2 X + c3 X^2
# - ...) with bit 0 of x0 set; X = x10:x9 on entry, a binary fraction; the c
# from [x16], every (x0 >> 8) bytes, up to x17. A series is X T: T is of the
# order of c1, so it keeps its precision however small X is. It stops when a
# term is zero. Clobbers x0, x3-x6, x8, x11, x13, x14, x16, x17.
fx_series:
    stp x9, x10, [sp, -16]!
    ldp x9, x10, [x16]
    add x16, x16, x0, lsr 8
    and x8, x0, 1
    orr x0, x0, x8, lsl 1           // bit 1: the next term is subtracted
    ldp x5, x6, [sp]                // the power of X
1:  cmp x16, x17
    b.hs 9f
    ldp x3, x4, [x16]
    add x16, x16, x0, lsr 8
    FX_MUL
    orr x8, x13, x14
    cbz x8, 9f
    tbnz x0, 1, 2f
    adds x9, x9, x13
    adc x10, x10, x14
    b 3f
2:  subs x9, x9, x13
    sbc x10, x10, x14
3:  and x8, x0, 1
    eor x0, x0, x8, lsl 1
    ldp x3, x4, [sp]
    FX_MUL
    mov x5, x13
    mov x6, x14
    b 1b
9:  add sp, sp, 16
    ret

# Frames: n bigfloat slots, then lr, two spare words and x19 (the series
# loops count in it; the memory forms keep a write's address there).
.macro BF_ENTER n
    sub sp, sp, (\n) * BF_SIZE + 32
    str lr, [sp, (\n) * BF_SIZE]
    str x19, [sp, (\n) * BF_SIZE + 24]
.endm
.macro BF_LEAVE n
    ldr lr, [sp, (\n) * BF_SIZE]
    ldr x19, [sp, (\n) * BF_SIZE + 24]
    add sp, sp, (\n) * BF_SIZE + 32
    ret
.endm
.macro BF3 fn, d, a, b
    add x12, sp, (\d) * BF_SIZE
    add x13, sp, (\a) * BF_SIZE
    add x14, sp, (\b) * BF_SIZE
    bl \fn
.endm
.macro BF2 fn, d, a
    add x12, sp, (\d) * BF_SIZE
    add x13, sp, (\a) * BF_SIZE
    bl \fn
.endm
.macro BFC d, label
    add x12, sp, (\d) * BF_SIZE
    adr x13, \label
    bl bf_copy
.endm
.macro BFI d, val
    mov x0, \val
    add x12, sp, (\d) * BF_SIZE
    bl bf_int
.endm
// The exponent of slot d, + 1 (doubling), unless it is zero.
.macro BFX2 d
    ldr x0, [sp, (\d) * BF_SIZE + 8]
    cbz x0, .Lx2\@
    ldr x0, [sp, (\d) * BF_SIZE + 16]
    add x0, x0, 1
    str x0, [sp, (\d) * BF_SIZE + 16]
.Lx2\@:
.endm

// [d] = (-1)^sign [a] T(|[a]|): a series by fx_series over a table, as a
// bigfloat ([a] is X, nonnegative).
.macro BF_FXSERIES d, a, table, end, stride, alt, sign
    add x13, sp, (\a) * BF_SIZE
    bl bf_fx
    adr x16, \table
    adr x17, \end
    mov x0, (\alt) | ((\stride) << 8)
    bl fx_series
    mov x11, 16382
    mov x17, \sign
    add x12, sp, (\d) * BF_SIZE
    bl bf_put
    add x12, sp, (\d) * BF_SIZE
    add x13, sp, (\a) * BF_SIZE
    add x14, sp, (\d) * BF_SIZE
    bl bf_mul
.endm

# [x12] = log2(e) * 2 atanh([x13]) (that is, log2((1 + s) / (1 - s))):
# atanh s = s + s (s^2/3 + s^4/5 + ...).
k_atanh_log2:
    BF_ENTER 4                      // 0 s, 1 s^2 / atanh, 2 the series, 3 log2(e)
    str x12, [sp, 4 * BF_SIZE + 8]
    add x12, sp, 0
    bl bf_copy
    BF3 bf_mul, 1, 0, 0
    BF_FXSERIES 2, 1, fx_odd, fx_odd_end, 16, 0, 0
    BF3 bf_mul, 2, 0, 2
    BF3 bf_add, 1, 0, 2
    BFX2 1
    BFC 3, bfc_log2e
    ldr x12, [sp, 4 * BF_SIZE + 8]
    add x13, sp, 1 * BF_SIZE
    add x14, sp, 3 * BF_SIZE
    bl bf_mul
    BF_LEAVE 4

# [x12] = log2([x13]), [x13] finite, positive: E + log2(m), m in [sqrt(2)/2,
# sqrt(2)), by atanh((m - 1) / (m + 1)).
k_log2:
    BF_ENTER 5                      // 0 m, 1 one, 2 m - 1, 3 m + 1, 4 s
    str x12, [sp, 5 * BF_SIZE + 8]
    add x12, sp, 0
    bl bf_copy
    ldr x10, [sp, 16]
    mov x0, 16383
    sub x11, x10, x0                // E
    mov x10, x0
    ldp x8, x9, [sp]
    mov x0, 0x6484
    movk x0, 0xf9de, lsl 16
    movk x0, 0xf333, lsl 32
    movk x0, 0xb504, lsl 48         // sqrt(2) * 2^127, the high word
    cmp x9, x0
    b.lo 1f
    b.hi 0f
    mov x0, 0xc7c5
    movk x0, 0xc9b5, lsl 16
    movk x0, 0x6ef3, lsl 32
    movk x0, 0xf8dc, lsl 48         // ... and the low
    cmp x8, x0
    b.ls 1f
0:
    sub x10, x10, 1
    add x11, x11, 1
1:  str x10, [sp, 16]
    str x11, [sp, 5 * BF_SIZE + 16]
    BFI 1, 1
    BF3 bf_sub, 2, 0, 1
    ldr x0, [sp, 2 * BF_SIZE + 8]
    cbz x0, 3f                      // m is 1: log2 is E exactly
    BF3 bf_add, 3, 0, 1
    BF3 bf_div, 4, 2, 3
    add x12, sp, 0
    add x13, sp, 4 * BF_SIZE
    bl k_atanh_log2
    ldr x0, [sp, 5 * BF_SIZE + 16]
    cbz x0, 2f
    BFI 1, x0
    BF3 bf_add, 0, 1, 0
2:  ldr x12, [sp, 5 * BF_SIZE + 8]
    add x13, sp, 0
    bl bf_copy
    BF_LEAVE 5
3:  ldr x0, [sp, 5 * BF_SIZE + 16]
    ldr x12, [sp, 5 * BF_SIZE + 8]
    bl bf_int
    BF_LEAVE 5

# [x12] = atan([x13]) for [x13] in [0, 1]: atan(k/16) from the table, k the
# nearest, plus the series for (t - k/16) / (1 + t k/16).
k_atan:
    BF_ENTER 7                      // 0 t, 1 c, 2 num, 3 den/u, 4 sum, 5 u^2, 6 power/term
    str x12, [sp, 7 * BF_SIZE + 8]
    add x12, sp, 0
    bl bf_copy
    // k = round(16 t): t = hi * 2^(e - 16446), so 16 t = hi >> (16442 - e)
    ldr x9, [sp, 8]
    ldr x10, [sp, 16]
    mov x0, 0
    cbz x9, 2f
    mov x11, 16442
    sub x11, x11, x10               // the shift
    cmp x11, 64
    b.hi 2f
    b.lo 1f
    lsr x0, x9, 63                  // shift 64: only the rounding bit
    b 2f
1:  lsr x0, x9, x11
    sub x11, x11, 1
    lsr x10, x9, x11
    and x10, x10, 1
    add x0, x0, x10
2:  str x0, [sp, 7 * BF_SIZE + 16]
    cbz x0, 5f
    // u = (t - c) / (1 + t c), c = k / 16
    add x12, sp, 1 * BF_SIZE
    bl bf_int
    ldr x0, [sp, 1 * BF_SIZE + 16]
    sub x0, x0, 4
    str x0, [sp, 1 * BF_SIZE + 16]
    BF3 bf_sub, 2, 0, 1
    BF3 bf_mul, 3, 0, 1
    BFI 4, 1
    BF3 bf_add, 3, 4, 3
    BF3 bf_div, 3, 2, 3
    b 6f
5:  BF2 bf_copy, 3, 0               // k = 0: u = t
6:  // atan u = u + u Q
    BF2 bf_copy, 4, 3
    ldr x0, [sp, 3 * BF_SIZE + 8]
    cbz x0, 8f
    add x12, sp, 2 * BF_SIZE
    add x13, sp, 3 * BF_SIZE
    bl k_atan_tail
    BF3 bf_add, 4, 3, 2
8:  ldr x0, [sp, 7 * BF_SIZE + 16]
    cbz x0, 9f
    adr x14, bfc_atan16
    add x14, x14, x0, lsl 5
    add x12, sp, 4 * BF_SIZE
    add x13, sp, 4 * BF_SIZE
    bl bf_add
9:  ldr x12, [sp, 7 * BF_SIZE + 8]
    add x13, sp, 4 * BF_SIZE
    bl bf_copy
    BF_LEAVE 7

# atan u = u + u Q: [x12] = the tail u Q, Q = -u^2/3 + u^4/5 - ...
k_atan_tail:
    BF_ENTER 3                      // 0 u, 1 u^2, 2 Q
    str x12, [sp, 3 * BF_SIZE + 8]
    add x12, sp, 0
    bl bf_copy
    BF3 bf_mul, 1, 0, 0
    BF_FXSERIES 2, 1, fx_odd, fx_odd_end, 16, 1, 1
    ldr x12, [sp, 3 * BF_SIZE + 8]
    add x13, sp, 0
    add x14, sp, 2 * BF_SIZE
    bl bf_mul
    BF_LEAVE 3

# F2XM1: A = 2^A - 1 = expm1(A ln 2), A finite, nonzero, |A| < 1:
# expm1 t = t + t^2 T, T = 1/2! + t/3! + t^2/4! + ... (alternating in |t| for
# t < 0).
v_f2xm1:
    BF_ENTER 4                      // 0 x, 1 t, 2 E, 3 ln 2
    add x12, sp, 0
    bl bf_from_f80
    BFC 3, bfc_ln2
    BF3 bf_mul, 1, 0, 3
    add x13, sp, 1 * BF_SIZE
    bl bf_fx
    adr x16, fx_fact2
    adr x17, fx_fact_end
    ldr x0, [sp, 1 * BF_SIZE + 24]
    orr x0, x0, 16 << 8
    bl fx_series
    mov x11, 16382
    mov x17, 0
    add x12, sp, 2 * BF_SIZE
    bl bf_put
    BF3 bf_mul, 2, 1, 2
    BF3 bf_mul, 2, 1, 2
    BF3 bf_add, 2, 1, 2
    bf_round_slot 2 * BF_SIZE
    BF_LEAVE 4

# FYL2X: A = B * log2(A), A finite and positive, B finite and nonzero.
v_fyl2x:
    BF_ENTER 3                      // 0 x, then the product; 1 log2; 2 y
    stp x5, x6, [sp, 3 * BF_SIZE + 8]
    add x12, sp, 0
    bl bf_from_f80
    add x12, sp, 1 * BF_SIZE
    add x13, sp, 0
    bl k_log2
    ldp x3, x4, [sp, 3 * BF_SIZE + 8]
    add x12, sp, 2 * BF_SIZE
    bl bf_from_f80
    BF3 bf_mul, 0, 2, 1
    bf_round_slot 0
    BF_LEAVE 3

# FYL2XP1: A = B * log2(1 + A), A finite and above -1, B finite and nonzero.
# |A| < 1/4: 2 atanh(A / (2 + A)), exact in A's own scale; else log2 of 1 + A.
v_fyl2xp1:
    BF_ENTER 3                      // 0 x, 1 log2, 2 scratch / y
    stp x5, x6, [sp, 3 * BF_SIZE + 8]
    and w0, w4, 0x7fff
    mov w9, 0x3ffd
    cmp w0, w9
    add x12, sp, 0
    b.hs 1f
    bl bf_from_f80
    BFI 2, 2
    BF3 bf_add, 2, 2, 0
    BF3 bf_div, 2, 0, 2
    add x12, sp, 1 * BF_SIZE
    add x13, sp, 2 * BF_SIZE
    bl k_atanh_log2
    b 2f
1:  bl bf_from_f80
    BFI 2, 1
    BF3 bf_add, 2, 2, 0
    add x12, sp, 1 * BF_SIZE
    add x13, sp, 2 * BF_SIZE
    bl k_log2
2:  ldp x3, x4, [sp, 3 * BF_SIZE + 8]
    add x12, sp, 2 * BF_SIZE
    bl bf_from_f80
    BF3 bf_mul, 0, 2, 1
    bf_round_slot 0
    BF_LEAVE 3

# FPATAN: A = atan2(B, A) (y = B, x = A), both finite and nonzero.
v_fpatan:
    BF_ENTER 6                      // 0 |y|, 1 |x|, 2 t, 3 atan, 4 tail / pi, 5 scratch
    ubfx w9, w4, 15, 1
    ubfx w10, w6, 15, 1
    stp x9, x10, [sp, 6 * BF_SIZE + 8]    // x's sign, y's sign
    add x12, sp, 1 * BF_SIZE
    bl bf_from_f80
    str xzr, [sp, 1 * BF_SIZE + 24]
    mov x3, x5
    mov w4, w6
    add x12, sp, 0
    bl bf_from_f80
    str xzr, [sp, 24]
    // |y| <= |x|?
    ldp x9, x10, [sp, 16]           // |y|: e (x9)
    ldr x11, [sp, 1 * BF_SIZE + 16] // |x|: e
    cmp x9, x11
    b.gt 5f
    b.lt 1f
    ldr x9, [sp, 8]
    ldr x10, [sp, 1 * BF_SIZE + 8]
    cmp x9, x10
    b.hi 5f
    b.lo 1f
    ldr x9, [sp, 0]
    ldr x10, [sp, 1 * BF_SIZE]
    cmp x9, x10
    b.hi 5f
1:  BF3 bf_div, 2, 0, 1             // t = |y| / |x|, in [0, 1]
    ldr x0, [sp, 6 * BF_SIZE + 8]
    cbnz x0, 2f                     // x < 0: through pi
    // atan(t) of a t below 1/32: t + t Q, joined with a sticky bit
    ldr x9, [sp, 2 * BF_SIZE + 16]
    mov x10, 16378                  // 2^-5
    cmp x9, x10
    b.ge 2f
    add x12, sp, 4 * BF_SIZE
    add x13, sp, 2 * BF_SIZE
    bl k_atan_tail
    ldr x0, [sp, 6 * BF_SIZE + 16]  // y's sign on both
    str x0, [sp, 2 * BF_SIZE + 24]
    ldr x9, [sp, 4 * BF_SIZE + 24]
    eor x9, x9, x0
    str x9, [sp, 4 * BF_SIZE + 24]
    add x13, sp, 2 * BF_SIZE
    add x14, sp, 4 * BF_SIZE
    bl bf_join
    bl x87_round_bf
    BF_LEAVE 6
2:  add x12, sp, 3 * BF_SIZE
    add x13, sp, 2 * BF_SIZE
    bl k_atan
    b 6f
5:  BF3 bf_div, 2, 1, 0             // t = |x| / |y|: pi/2 - atan t
    add x12, sp, 3 * BF_SIZE
    add x13, sp, 2 * BF_SIZE
    bl k_atan
    BFC 4, bfc_pi2
    BF3 bf_sub, 3, 4, 3
6:  ldr x0, [sp, 6 * BF_SIZE + 8]
    cbz x0, 7f
    BFC 4, bfc_pi                   // x < 0: pi - that
    BF3 bf_sub, 3, 4, 3
7:  ldr x0, [sp, 6 * BF_SIZE + 16]
    str x0, [sp, 3 * BF_SIZE + 24]
    bf_round_slot 3 * BF_SIZE
    BF_LEAVE 6
    .balign 16
bfc_ln2:
    .quad 0xc9e3b39803f2f6af, 0xb17217f7d1cf79ab, 16382, 0
bfc_log2e:
    .quad 0xbe87fed0691d3e88, 0xb8aa3b295c17f0bb, 16383, 0
bfc_pi:
    .quad 0xc4c6628b80dc1cd1, 0xc90fdaa22168c234, 16384, 0
bfc_pi2:
    .quad 0xc4c6628b80dc1cd1, 0xc90fdaa22168c234, 16383, 0
bfc_atan16:
    .quad 0x0000000000000000, 0x0000000000000000, 0, 0    // atan(0/16)
    .quad 0xcb2792dc0e2e0d51, 0xffaaddb967ef4e36, 16378, 0    // atan(1/16)
    .quad 0xc897989f3e888ef7, 0xfeadd4d5617b6e32, 16379, 0    // atan(2/16)
    .quad 0x7b0b4f881c9c7487, 0xbdcbda5e72d81134, 16380, 0    // atan(3/16)
    .quad 0x6dc79ef5f7a217e5, 0xfadbafc96406eb15, 16380, 0    // atan(4/16)
    .quad 0xc5abb498d27af328, 0x9b13b9b83f5e5e69, 16381, 0    // atan(5/16)
    .quad 0x8aa32122dcfe4483, 0xb7b0ca0f26f78473, 16381, 0    // atan(6/16)
    .quad 0x427c95e9001e7136, 0xd327761e611fe5b6, 16381, 0    // atan(7/16)
    .quad 0x6fe445ecbc3a8d03, 0xed63382b0dda7b45, 16381, 0    // atan(8/16)
    .quad 0x4b6a09cb61a515c0, 0x832bf4a6d9867e2a, 16382, 0    // atan(9/16)
    .quad 0x5c835e1665c43747, 0x8f005d5ef7f59f9b, 16382, 0    // atan(10/16)
    .quad 0x4226f8e2204ff3bc, 0x9a2f80e671bdda20, 16382, 0    // atan(11/16)
    .quad 0x19a87f2a457dac9e, 0xa4bc7d1934f70924, 16382, 0    // atan(12/16)
    .quad 0x14725e2f3e52070a, 0xaeac4c38b4d8c080, 16382, 0    // atan(13/16)
    .quad 0xcb2da55210a4443d, 0xb8053e2bc2319e73, 16382, 0    // atan(14/16)
    .quad 0x89dd62c46e92fa24, 0xc0ce85b8ac526640, 16382, 0    // atan(15/16)
    .quad 0xc4c6628b80dc1cd1, 0xc90fdaa22168c234, 16382, 0    // atan(16/16)
// pi66 = P66 * 2^-64: P66 = 0x3243f6a8885a308d3 (66 bits)
x87_p66: .quad 0x243f6a8885a308d3, 0x3

// Flip the signs of slots a and b.
.macro BF_FLIP2 a, b
    ldr x0, [sp, (\a) * BF_SIZE + 24]
    eor x0, x0, 1
    str x0, [sp, (\a) * BF_SIZE + 24]
    ldr x0, [sp, (\b) * BF_SIZE + 24]
    eor x0, x0, 1
    str x0, [sp, (\b) * BF_SIZE + 24]
.endm

// lead (slot a) + tail (slot b), joined and rounded into A.
.macro BF_JOIN_ROUND a, b
    add x13, sp, (\a) * BF_SIZE
    add x14, sp, (\b) * BF_SIZE
    bl bf_join
    bl x87_round_bf
.endm

// lead (slot a) + tail (slot b), joined, to slot d as a bigfloat.
.macro BF_JOIN_PUT d, a, b
    add x13, sp, (\a) * BF_SIZE
    add x14, sp, (\b) * BF_SIZE
    bl bf_join
    mov w17, w11
    mov x11, x10
    mov x10, x8
    add x12, sp, (\d) * BF_SIZE
    bl bf_put
.endm

# FSIN (w0 = 0), FCOS (1), FPTAN (2), FSINCOS (3), A finite, nonzero, below
# 2^63: A = the sine, cosine or tangent; for FSINCOS A = the sine, B = the
# cosine (rounded first).
#
# The reduction is the x87's own: |x| = q pi66/2 + r, q the nearest integer
# and pi66 = P66 * 2^-64 -- pi to 66 bits, which is why a large x's sine is
# not the true one, on the hardware or here. In units of 2^-65, X = |x| is
# an integer below 2^128 and pi66/2 is P66; q and the remainder R come from
# a long division, R exact. Then sin r = r + r Ps and cos r = 1 + Pc, the
# leading terms kept apart from the tails.
v_trig:
    BF_ENTER 9                      // 0 r, 1 r^2, 2 term, 3 Ps, 4 Pc, 5 r Ps, 6 one, 7, 8
    str x0, [sp, 9 * BF_SIZE + 8]
    ubfx w0, w4, 15, 1
    str x0, [sp, 9 * BF_SIZE + 16]
    and w9, w4, 0x7fff
    cmp w9, 0
    csinc w9, w9, wzr, ne
    mov w10, 16381
    subs w9, w9, w10                // the shift that makes X an integer
    b.ge 1f
    // |x| below 2^-65: r = |x|, q = 0
    and w4, w4, 0x7fff
    add x12, sp, 0
    bl bf_from_f80
    mov x0, 0
    b 5f
1:  // X = m << w9 (0-64): x8 the high word, x10 the low
    mov x10, 0
    mov x8, x3
    cmp w9, 64
    b.eq 2f
    mov x10, x3
    mov x8, 0
    cbz w9, 2f
    lsl x10, x3, x9
    neg w11, w9
    lsr x8, x3, x11
2:  mov x5, 0x08d3
    movk x5, 0x85a3, lsl 16
    movk x5, 0x6a88, lsl 32
    movk x5, 0x243f, lsl 48         // P66 = 3:x5
    mov x6, 3
    // q = floor(X / P66): X's high word times floor(2^64 / pi) is at most 2
    // under it, never over; then R = X - q P66, and up to q + 2
    mov x0, 0x0a94
    movk x0, 0x2722, lsl 16
    movk x0, 0xc1b7, lsl 32
    movk x0, 0x517c, lsl 48
    umulh x11, x8, x0
    mul x12, x11, x5
    umulh x13, x11, x5
    add x13, x13, x11, lsl 1
    add x13, x13, x11               // q P66 = x13:x12
    subs x12, x10, x12
    sbc x9, x8, x13
    mov x8, x12                     // R = x9:x8
    b 31f
3:  subs x8, x8, x5
    sbc x9, x9, x6
    add x11, x11, 1
31: cmp x8, x5
    sbcs xzr, x9, x6
    b.hs 3b
    // the nearest: R above P66 / 2 = 1:921fb54442d18469 (P66 is odd: no
    // ties), that is, at least 1:921fb54442d1846a
    mov x17, 0
    mov x12, 0x846a
    movk x12, 0x42d1, lsl 16
    movk x12, 0xb544, lsl 32
    movk x12, 0x921f, lsl 48
    mov x13, 1
    cmp x8, x12
    sbcs xzr, x9, x13
    b.lo 41f
    add x11, x11, 1
    subs x8, x5, x8
    sbc x9, x6, x9
    mov x17, 1
41: str x11, [sp, 7 * BF_SIZE]
    mov x10, x9
    mov x9, x8
    mov x11, 16445
    add x12, sp, 0
    bl bf_put
    ldr x0, [sp, 7 * BF_SIZE]
5:  and x0, x0, 3
    ldr x9, [sp, 9 * BF_SIZE + 16]
    orr x0, x0, x9, lsl 2           // q mod 4, and x's sign at bit 2
    str x0, [sp, 9 * BF_SIZE + 16]
    // the series: FSIN and FCOS need only the one their quadrant uses
    BF3 bf_mul, 1, 0, 0
    BFI 6, 1
    ldp x9, x10, [sp, 9 * BF_SIZE + 8]
    eor x10, x10, x9
    cmp x9, 2
    b.hs 52f
    tbnz x10, 0, 53f
52: BF_FXSERIES 3, 1, fx_sinc, fx_fact_end, 32, 1, 1
    BF3 bf_mul, 5, 0, 3
    ldr x9, [sp, 9 * BF_SIZE + 8]
    cmp x9, 2
    b.lo 54f
53: BF_FXSERIES 4, 1, fx_cosc, fx_fact_end, 32, 1, 1
54:
    ldr x0, [sp, 9 * BF_SIZE + 8]
    cmp x0, 2
    b.ne 6f
    ldr x0, [sp, 9 * BF_SIZE + 16]
    tbnz x0, 0, 6f
    // FPTAN, q even: tan r = r + r Q, Q = (Ps - Pc) / (1 + Pc)
    BF3 bf_sub, 7, 3, 4
    BF3 bf_add, 8, 6, 4
    BF3 bf_div, 7, 7, 8
    BF3 bf_mul, 7, 0, 7
    ldr x0, [sp, 9 * BF_SIZE + 16]
    tbz x0, 2, 51f
    BF_FLIP2 0, 7
51: BF_JOIN_ROUND 0, 7
    b 9f
6:  // the quadrant: S = sin, cos, -sin, -cos; C = cos, -sin, -cos, sin
    // (r q), then S negated for a negative x. Flips go onto the pairs:
    // S's is (q >= 2) ^ sign, C's (q is 1 or 2).
    ldr x0, [sp, 9 * BF_SIZE + 16]
    ubfx x9, x0, 1, 1
    ubfx x10, x0, 2, 1
    eor x9, x9, x10                 // S flips
    ubfx x10, x0, 0, 1
    ubfx x11, x0, 1, 1
    eor x10, x10, x11               // C flips
    stp x9, x10, [sp, 7 * BF_SIZE]  // (slot 7 as two scratch words)
    tbnz x0, 0, 7f
    cbz x9, 61f
    BF_FLIP2 0, 5
61: ldr x10, [sp, 7 * BF_SIZE + 8]
    cbz x10, 8f
    BF_FLIP2 6, 4
    b 8f
7:  cbz x9, 71f
    BF_FLIP2 6, 4
71: ldr x10, [sp, 7 * BF_SIZE + 8]
    cbz x10, 8f
    BF_FLIP2 0, 5
8:  // S is the sine pair (0, 5) for q even, the cosine pair (6, 4) for q odd
    ldr x0, [sp, 9 * BF_SIZE + 8]
    ldr x9, [sp, 9 * BF_SIZE + 16]
    cmp x0, 1
    b.eq 82f
    cmp x0, 2
    b.eq 83f
    cmp x0, 3
    b.eq 84f
    tbnz x9, 0, 81f                 // FSIN
    BF_JOIN_ROUND 0, 5
    b 9f
81: BF_JOIN_ROUND 6, 4
    b 9f
82: tbnz x9, 0, 821f                // FCOS
    BF_JOIN_ROUND 6, 4
    b 9f
821: BF_JOIN_ROUND 0, 5
    b 9f
83: // FPTAN, q odd: S / C, each joined
    BF_JOIN_PUT 7, 6, 4
    BF_JOIN_PUT 8, 0, 5
    BF3 bf_div, 7, 7, 8
    bf_round_slot 7 * BF_SIZE
    b 9f
84: tbnz x9, 0, 841f                // FSINCOS: the cosine, then the sine
    BF_JOIN_ROUND 6, 4
    stp x3, x4, [sp, 8 * BF_SIZE]
    BF_JOIN_ROUND 0, 5
    b 842f
841: BF_JOIN_ROUND 0, 5
    stp x3, x4, [sp, 8 * BF_SIZE]
    BF_JOIN_ROUND 6, 4
842: ldp x5, x6, [sp, 8 * BF_SIZE]
9:  BF_LEAVE 9
bfc_pi4:
    .quad 0xc4c6628b80dc1cd1, 0xc90fdaa22168c234, 16382, 0
bfc_pi34:
    .quad 0x9394c9e8a0a5159c, 0x96cbe3f9990e91a7, 16384, 0

# Series coefficients as 128-bit binary fractions (floor(2^128 c)): 1/n! for
# n = 2..40 -- the sine takes the odd ones from 1/3!, the cosine the even
# ones from 1/2!, expm1 all of them -- and 1/(2k+1) for the arctangents.
    .balign 16
fx_fact2:
fx_cosc:
    .quad 0x0000000000000000, 0x8000000000000000   // 1/2!
fx_sinc:
    .quad 0xaaaaaaaaaaaaaaaa, 0x2aaaaaaaaaaaaaaa   // 1/3!
    .quad 0xaaaaaaaaaaaaaaaa, 0x0aaaaaaaaaaaaaaa   // 1/4!
    .quad 0x2222222222222222, 0x0222222222222222   // 1/5!
    .quad 0x05b05b05b05b05b0, 0x005b05b05b05b05b   // 1/6!
    .quad 0x00d00d00d00d00d0, 0x000d00d00d00d00d   // 1/7!
    .quad 0xa01a01a01a01a01a, 0x0001a01a01a01a01   // 1/8!
    .quad 0x671f5583911ca002, 0x00002e3bc74aad8e   // 1/9!
    .quad 0xd71cbbc05b4fa999, 0x0000049f93edde27   // 1/10!
    .quad 0x138e3f9d1f92e0df, 0x0000006b99159fd5   // 1/11!
    .quad 0x6c4bdaa26d4c3d67, 0x00000008f76c77fc   // 1/12!
    .quad 0x43684be51c198e91, 0x00000000b092309d   // 1/13!
    .quad 0x603e4e905d6f8a2e, 0x000000000c9cba54   // 1/14!
    .quad 0x399dc0f88ec32b58, 0x0000000000d73f9f   // 1/15!
    .quad 0xf399dc0f88ec32b5, 0x00000000000d73f9   // 1/16!
    .quad 0x3b81856a53593028, 0x000000000000ca96   // 1/17!
    .quad 0x3c31dcbecbbdd802, 0x0000000000000b41   // 1/18!
    .quad 0xa4da340a0ab92650, 0x0000000000000097   // 1/19!
    .quad 0x950ae900808941ea, 0x0000000000000007   // 1/20!
    .quad 0x5c6e3bdb73d5c62f, 0x0000000000000000   // 1/21!
    .quad 0x04338e5b6dfe14a5, 0x0000000000000000   // 1/22!
    .quad 0x002ec368262c7033, 0x0000000000000000   // 1/23!
    .quad 0x0001f2cf01972f57, 0x0000000000000000   // 1/24!
    .quad 0x000013f3ccdd165f, 0x0000000000000000   // 1/25!
    .quad 0x000000c4742fe352, 0x0000000000000000   // 1/26!
    .quad 0x0000000746ac70b7, 0x0000000000000000   // 1/27!
    .quad 0x0000000042862898, 0x0000000000000000   // 1/28!
    .quad 0x00000000024b3f31, 0x0000000000000000   // 1/29!
    .quad 0x000000000013932c, 0x0000000000000000   // 1/30!
    .quad 0x000000000000a1a6, 0x0000000000000000   // 1/31!
    .quad 0x000000000000050d, 0x0000000000000000   // 1/32!
    .quad 0x0000000000000027, 0x0000000000000000   // 1/33!
    .quad 0x0000000000000001, 0x0000000000000000   // 1/34!
    .quad 0x0000000000000000, 0x0000000000000000   // 1/35!
    .quad 0x0000000000000000, 0x0000000000000000   // 1/36!
    .quad 0x0000000000000000, 0x0000000000000000   // 1/37!
    .quad 0x0000000000000000, 0x0000000000000000   // 1/38!
    .quad 0x0000000000000000, 0x0000000000000000   // 1/39!
    .quad 0x0000000000000000, 0x0000000000000000   // 1/40!
fx_fact_end:
fx_odd:
    .quad 0x5555555555555555, 0x5555555555555555   // 1/3
    .quad 0x3333333333333333, 0x3333333333333333   // 1/5
    .quad 0x4924924924924924, 0x2492492492492492   // 1/7
    .quad 0xc71c71c71c71c71c, 0x1c71c71c71c71c71   // 1/9
    .quad 0x745d1745d1745d17, 0x1745d1745d1745d1   // 1/11
    .quad 0x3b13b13b13b13b13, 0x13b13b13b13b13b1   // 1/13
    .quad 0x1111111111111111, 0x1111111111111111   // 1/15
    .quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f   // 1/17
    .quad 0xe50d79435e50d794, 0x0d79435e50d79435   // 1/19
    .quad 0xc30c30c30c30c30c, 0x0c30c30c30c30c30   // 1/21
    .quad 0x42c8590b21642c85, 0x0b21642c8590b216   // 1/23
    .quad 0xa3d70a3d70a3d70a, 0x0a3d70a3d70a3d70   // 1/25
    .quad 0xed097b425ed097b4, 0x097b425ed097b425   // 1/27
    .quad 0xd3dcb08d3dcb08d3, 0x08d3dcb08d3dcb08   // 1/29
    .quad 0x8421084210842108, 0x0842108421084210   // 1/31
    .quad 0x7c1f07c1f07c1f07, 0x07c1f07c1f07c1f0   // 1/33
    .quad 0x7507507507507507, 0x0750750750750750   // 1/35
    .quad 0x5306eb3e45306eb3, 0x06eb3e45306eb3e4   // 1/37
    .quad 0x6906906906906906, 0x0690690690690690   // 1/39
    .quad 0x63e7063e7063e706, 0x063e7063e7063e70   // 1/41
    .quad 0xf417d05f417d05f4, 0x05f417d05f417d05   // 1/43
    .quad 0x5b05b05b05b05b05, 0x05b05b05b05b05b0   // 1/45
    .quad 0x882b9310572620ae, 0x0572620ae4c415c9   // 1/47
    .quad 0x0a72f05397829cbc, 0x05397829cbc14e5e   // 1/49
    .quad 0x0505050505050505, 0x0505050505050505   // 1/51
    .quad 0x4873ecade304d487, 0x04d4873ecade304d   // 1/53
    .quad 0x4a7904a7904a7904, 0x04a7904a7904a790   // 1/55
    .quad 0xf7047dc11f7047dc, 0x047dc11f7047dc11   // 1/57
    .quad 0x15b1e5f75270d045, 0x0456c797dd49c341   // 1/59
    .quad 0x4325c53ef368eb04, 0x04325c53ef368eb0   // 1/61
    .quad 0x4104104104104104, 0x0410410410410410   // 1/63
    .quad 0x3f03f03f03f03f03, 0x03f03f03f03f03f0   // 1/65
    .quad 0x40f4898d5f85bb39, 0x03d226357e16ece5   // 1/67
    .quad 0xc0ed7303b5cc0ed7, 0x03b5cc0ed7303b5c   // 1/69
    .quad 0x240e6c2b4481cd85, 0x039b0ad12073615a   // 1/71
    .quad 0x070381c0e070381c, 0x0381c0e070381c0e   // 1/73
    .quad 0x369d0369d0369d03, 0x0369d0369d0369d0   // 1/75
    .quad 0x3531dec0d4c77b03, 0x03531dec0d4c77b0   // 1/77
    .quad 0xa5440cf6474a8819, 0x033d91d2a2067b23   // 1/79
    .quad 0xa4587e6b74f03291, 0x0329161f9add3c0c   // 1/81
    .quad 0x6f0940c565c87b5f, 0x03159721ed7e7534   // 1/83
    .quad 0x0303030303030303, 0x0303030303030303   // 1/85
    .quad 0xf149902f149902f1, 0x02f149902f149902   // 1/87
    .quad 0xc0b81702e05c0b81, 0x02e05c0b81702e05   // 1/89
    .quad 0x2d02d02d02d02d02, 0x02d02d02d02d02d0   // 1/91
    .quad 0x2c0b02c0b02c0b02, 0x02c0b02c0b02c0b0   // 1/93
    .quad 0x6102b1da46102b1d, 0x02b1da46102b1da4   // 1/95
    .quad 0xa0fd5c5f02a3a0fd, 0x02a3a0fd5c5f02a3   // 1/97
    .quad 0x295fad40a57eb502, 0x0295fad40a57eb50   // 1/99
    .quad 0xc83cd4e930288df0, 0x0288df0cac5b3f5d   // 1/101
    .quad 0x88b2f392a409f116, 0x027c45979c95204f   // 1/103
    .quad 0x2702702702702702, 0x0270270270270270   // 1/105
    .quad 0xdc1cb5d4ef40991f, 0x02647c69456217ec   // 1/107
    .quad 0x9b02593f69b02593, 0x02593f69b02593f6   // 1/109
    .quad 0x71024e6a171024e6, 0x024e6a171024e6a1   // 1/111
    .quad 0x43f6f0243f6f0243, 0x0243f6f0243f6f02   // 1/113
    .quad 0x0d5b450239e0d5b4, 0x0239e0d5b450239e   // 1/115
    .quad 0x2302302302302302, 0x0230230230230230   // 1/117
    .quad 0xb90226b90226b902, 0x0226b90226b90226   // 1/119
    .quad 0xc4c2a50658dc0876, 0x021d9ead7cd391fb   // 1/121
    .quad 0x214d0214d0214d02, 0x0214d0214d0214d0   // 1/123
    .quad 0xed916872b020c49b, 0x020c49ba5e353f7c   // 1/125
    .quad 0x0408102040810204, 0x0204081020408102   // 1/127
    .quad 0xfc07f01fc07f01fc, 0x01fc07f01fc07f01   // 1/129
fx_odd_end:

# ---------------------------------------------------------------------------
# The transcendentals' special operands, as an AMD Ryzen takes them (camd's
# records: tests/manual/x86/x87_trans.c). The value routines above get only
# what is left: finite, nonzero, in the domain.
# ---------------------------------------------------------------------------

// x87_ret_a and the rest again, within a tbz's reach.
xt_ret_a:
    ldr lr, [sp], 16
    ret
xt_ret_invalid:
    orr w7, w7, X87_IE
    x87_indef x3, w4
    ldr lr, [sp], 16
    ret
xt_ret_nan:
    bl x87_nan2
    ldr lr, [sp], 16
    ret

// A = the constant [x13], sign w11, rounded: PE, and C1 if it rounded up.
x87_round_const:
    ldp x9, x8, [x13]
    ldr x10, [x13, 16]
    b x87_round_bf

// The NaN of a one-operand transcendental: A quieted, IE for an SNaN (class
// w12); B the same, for the two-result ones.
x87_tnan1:
    cmp w12, 5
    b.ne 1f
    orr w7, w7, X87_IE
1:  orr x3, x3, 0x4000000000000000
    mov x5, x3
    mov w6, w4
    b xt_ret_a

# F2XM1: A = 2^A - 1. Out of its domain (|A| > 1), A itself with PE.
x87_f2xm1_core:
    str lr, [sp, -16]!
    x87_class w12, x3, w4, w0
    cmp w12, 6
    b.eq xt_ret_invalid
    cmp w12, 4
    b.hs x87_tnan1
    cbz w12, xt_ret_a              // +-0: itself
    cmp w12, 3
    b.ne 1f
    tbz w4, 15, xt_ret_a           // +infinity: itself; -infinity: -1
    mov w4, 0xbfff
    b xt_ret_a
1:  cmp w12, 2
    b.ne 2f
    orr w7, w7, X87_DE
    tbz w15, 1, xt_ret_a           // DE unmasked: nothing happens
    b 4f
2:  and w9, w4, 0x7fff
    mov w10, 0x3fff
    cmp w9, w10
    b.lo 4f
    b.hi 3f
    mov x10, 0x8000000000000000
    cmp x3, x10
    b.ne 3f
    // +-1: -1 gives -0.5; +1 gives 1 rounding to nearest or up (with C1),
    // else the largest value below it
    orr w7, w7, X87_PE
    tbz w4, 15, 5f
    mov w4, 0xbffe
    b xt_ret_a
5:  tbnz w15, 10, 6f                // RC 01 (down) or 11 (toward zero)
    orr w7, w7, X87_C1
    b xt_ret_a
6:  mov x3, -1
    mov w4, 0x3ffe
    b xt_ret_a
3:  orr w7, w7, X87_PE
    b xt_ret_a
4:  bl v_f2xm1
    b xt_ret_a

# FSIN (w0 = 0), FCOS (1), FPTAN (2), FSINCOS (3) on A. FPTAN's B is the 1
# it pushes, FSINCOS's the cosine; A the value that replaces ST(0). An
# operand of 2^63 or more is out of range: C2 set, nothing else changes.
x87_trig_core:
    stp lr, x0, [sp, -16]!
    x87_class w12, x3, w4, w9
    cmp w12, 3
    b.eq 7f
    cmp w12, 6
    b.eq 7f
    cmp w12, 4
    b.hs x87_tnan1
    cbz w12, 5f
    and w9, w4, 0x7fff
    mov w10, 0x403e
    cmp w9, w10
    b.hs 6f
    cmp w12, 2
    b.ne 1f
    orr w7, w7, X87_DE
    tbz w15, 1, xt_ret_a
1:  bl v_trig
    ldr x0, [sp, 8]
    cmp w0, 2
    b.ne xt_ret_a
    mov x5, 0x8000000000000000      // FPTAN pushes 1
    mov w6, 0x3fff
    b xt_ret_a
5:  // zero: the sine and tangent are the zero, the cosine 1, exactly
    cbz w0, xt_ret_a
    mov x5, 0x8000000000000000
    mov w6, 0x3fff
    cmp w0, 1
    b.ne xt_ret_a
    mov x3, x5
    mov w4, w6
    b xt_ret_a
6:  orr w7, w7, X87_C2
    b xt_ret_a
7:  orr w7, w7, X87_IE              // infinity, unsupported: the indefinite
    x87_indef x3, w4
    mov x5, x3
    mov w6, w4
    b xt_ret_a

# Two operands, A = ST(0) = x and B = ST(1) = y: unsupported is invalid, then
# the NaN rule; w12, w13 the classes, w14 DE if either is a denormal (the
# cases below raise it or not as the hardware does).
.macro x87_tcheck2
    bl x87_cls2
    cmp w12, 6
    ccmp w13, 6, 4, ne
    b.eq xt_ret_invalid
    cmp w12, 4
    ccmp w13, 4, 2, lo
    b.hs xt_ret_nan
    cmp w12, 2
    ccmp w13, 2, 4, ne
    cset w14, eq
    lsl w14, w14, 1
.endm
// DE as w14 says, and if it is unmasked, nothing happens.
.macro x87_tde
    orr w7, w7, w14
    bic w9, w14, w15
    cbnz w9, xt_ret_a
.endm

# FYL2X: A = y log2 x.
x87_fyl2x_core:
    str lr, [sp, -16]!
    x87_tcheck2
    cbz w12, 1f
    tbnz w4, 15, xt_ret_invalid    // x < 0
    cmp w12, 3
    b.eq 2f
    and w9, w4, 0x7fff
    mov w10, 0x3fff
    cmp w9, w10
    cset w10, lo                    // x < 1: the result's sign flips
    b.ne 3f
    mov x9, 0x8000000000000000
    cmp x3, x9
    b.ne 3f
    // x = 1: a zero with y's sign; y infinite is invalid
    cmp w13, 3
    b.eq xt_ret_invalid
    x87_tde
    mov x3, 0
    and w4, w6, 0x8000
    b xt_ret_a
3:  cbz w13, 4f
    cmp w13, 3
    b.eq 5f
    x87_tde
    bl v_fyl2x
    b xt_ret_a
4:  x87_tde                 // y zero: a zero
    mov x3, 0
    eor w4, w6, w10, lsl 15
    and w4, w4, 0x8000
    b xt_ret_a
5:  x87_tde                 // y infinite: an infinity
    mov x3, x5
    eor w4, w6, w10, lsl 15
    b xt_ret_a
1:  // x zero: -y infinity, ZE unless y is infinite; y zero is invalid
    cbz w13, xt_ret_invalid
    cmp w13, 3
    b.eq 11f
    orr w7, w7, X87_ZE
11: mov x3, 0x8000000000000000
    mvn w4, w6
    and w4, w4, 0x8000
    mov w9, 0x7fff
    orr w4, w4, w9
    b xt_ret_a
2:  // x +infinity: infinity with y's sign; y zero is invalid
    cbz w13, xt_ret_invalid
    x87_tde
    and w4, w6, 0x8000
    mov w9, 0x7fff
    orr w4, w4, w9
    b xt_ret_a

# FYL2XP1: A = y log2(1 + x). An x at or below -1 is A itself, with PE.
x87_fyl2xp1_core:
    str lr, [sp, -16]!
    x87_tcheck2
    cbz w12, 1f
    cmp w12, 3
    b.eq 2f
    tbz w4, 15, 3f
    and w9, w4, 0x7fff
    mov w10, 0x3fff
    cmp w9, w10
    b.lo 3f
    // x <= -1
    cbz w13, 4f
    cmp w13, 3
    b.eq 5f
    x87_tde
    orr w7, w7, X87_PE
    b xt_ret_a
4:  x87_tde                 // y zero: -y
    mov x3, 0
    mvn w4, w6
    and w4, w4, 0x8000
    b xt_ret_a
5:  mov x3, x5                      // y infinite: -y
    eor w4, w6, 0x8000
    b xt_ret_a
3:  eor w10, w4, w6
    and w10, w10, 0x8000            // the result's sign, for a zero or infinite y
    cbz w13, 31f
    cmp w13, 3
    b.eq 32f
    x87_tde
    bl v_fyl2xp1
    b xt_ret_a
31: x87_tde
    mov x3, 0
    mov w4, w10
    b xt_ret_a
32: x87_tde
    mov x3, x5
    mov w9, 0x7fff
    orr w4, w10, w9
    b xt_ret_a
1:  // x zero: a zero, the signs' product; y infinite is invalid
    cmp w13, 3
    b.eq xt_ret_invalid
    x87_tde
    mov x3, 0
    eor w4, w4, w6
    and w4, w4, 0x8000
    b xt_ret_a
2:  // x infinite: -infinity is invalid, so is y zero; else y's infinity
    tbnz w4, 15, xt_ret_invalid
    cbz w13, xt_ret_invalid
    x87_tde
    and w4, w6, 0x8000
    mov w9, 0x7fff
    orr w4, w4, w9
    b xt_ret_a

# FPATAN: A = atan2(y, x), the IEEE conventions for zeros and infinities.
x87_fpatan_core:
    str lr, [sp, -16]!
    x87_tcheck2
    ubfx w11, w6, 15, 1             // the result has y's sign
    cbnz w13, 1f
    // y zero: x negative, +-pi; else y
    x87_tde
    tbz w4, 15, 11f
    adr x13, bfc_pi
    bl x87_round_const
    b xt_ret_a
11: mov x3, x5
    mov w4, w6
    b xt_ret_a
1:  cbz w12, 2f
    cmp w13, 3
    b.ne 3f
    cmp w12, 3
    b.eq 4f
2:  // x zero, or y infinite and x finite: +-pi/2
    x87_tde
    adr x13, bfc_pi2
    bl x87_round_const
    b xt_ret_a
3:  cmp w12, 3
    b.ne 5f
    // x infinite, y finite: x negative, +-pi; else a zero
    x87_tde
    tbz w4, 15, 31f
    adr x13, bfc_pi
    bl x87_round_const
    b xt_ret_a
31: mov x3, 0
    and w4, w6, 0x8000
    b xt_ret_a
4:  // both infinite: +-pi/4, or +-3pi/4 for x negative
    adr x13, bfc_pi4
    tbz w4, 15, 41f
    adr x13, bfc_pi34
41: bl x87_round_const
    b xt_ret_a
5:  x87_tde
    bl v_fpatan
    b xt_ret_a

# ---------------------------------------------------------------------------
# The transcendental gadgets.
# ---------------------------------------------------------------------------

// C2 from w7 into the status word.
x87_put_c2:
    x87_ld_fsw w8
    ubfx w9, w7, 10, 1
    bfi w8, w9, 10, 1
    x87_st_fsw w8
    ret

// ST(0) = A, then push B, C2 clear -- unless an unmasked IE, DE or ZE,
// which change nothing.
x87_put_push:
    x87_ld_fsw w8
    bic w8, w8, X87_C2
    bic w10, w7, w15
    tst w10, (X87_IE | X87_DE | X87_ZE)
    b.ne x87_put_fsw
    x87_st_fsw w8
    ubfx w9, w8, 11, 3
    add x10, _cpu, CPU_fp
    add x10, x10, x9, lsl 4
    str x3, [x10]
    strh w4, [x10, 8]
    x87_ld_valid w11
    mov w10, 1
    lsl w10, w10, w9
    orr w11, w11, w10
    x87_st_valid w11
    mov x3, x5
    mov w4, w6
    b x87_push

.gadget x87_f2xm1
    x87_wait
    x87_begin
    mov w0, 0
    bl x87_get1
    cbnz w0, 1f
    bl x87_f2xm1_core
1:  mov w0, 0
    bl x87_put
    gret_nomem 1

// FSIN, FCOS: ST(0) replaced, C2 for an operand out of range.
.macro x87_trig1 name, op
.gadget x87_\name
    x87_wait
    x87_begin
    mov w0, 0
    bl x87_get1
    cbnz w0, 1f
    mov w0, \op
    bl x87_trig_core
1:  bl x87_put_c2
    mov w0, 0
    bl x87_put
    gret_nomem 1
.endm
x87_trig1 fsin, 0
x87_trig1 fcos, 1

// FPTAN, FSINCOS: ST(0) replaced and a value pushed. A full stack overflows
// (IE, SF, C1, the indefinite in ST(0) and pushed) -- unless the operand is
// out of range, which is only C2.
.macro x87_trig2 name, op
.gadget x87_\name
    x87_wait
    x87_begin
    mov w0, 0
    bl x87_get1
    cbnz w0, 2f
    x87_class w12, x3, w4, w0
    x87_ld_fsw w8
    x87_ld_valid w11
    ubfx w9, w8, 11, 3
    sub w9, w9, 1
    and w9, w9, 7
    lsr w11, w11, w9
    tbz w11, 0, 1f
    cmp w12, 1
    b.ne 3f
    and w9, w4, 0x7fff
    mov w10, 0x403e
    cmp w9, w10
    b.lo 3f
1:  mov w0, \op
    bl x87_trig_core
    tbnz w7, 10, 5f
    b 4f
2:  mov x5, x3                      // underflow: the indefinite, twice
    mov w6, w4
    b 4f
3:  x87_indef x3, w4
    mov x5, x3
    mov w6, w4
    mov w7, (X87_IE | X87_SF | X87_C1)
4:  bl x87_put_push
    gret_nomem 1
5:  x87_ld_fsw w8
    orr w8, w8, X87_C2
    bl x87_put_fsw
    gret_nomem 1
.endm
x87_trig2 fptan, 2
x87_trig2 fsincos, 3

// FYL2X, FYL2XP1, FPATAN: ST(1) = the result, then pop.
.macro x87_t2 name
.gadget x87_\name
    x87_wait
    x87_begin
    mov w0, 0
    mov w10, 1
    bl x87_get2
    cbnz w0, 1f
    bl x87_\name\()_core
1:  mov w0, (1 << 3) | (1 << 6)
    bl x87_put
    gret_nomem 1
.endm
x87_t2 fyl2x
x87_t2 fyl2xp1
x87_t2 fpatan
