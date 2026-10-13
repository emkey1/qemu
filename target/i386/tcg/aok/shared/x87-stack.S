# The x87's register stack and status word: see x87-arith.S for the
# conventions and for what a host supplies.

# ---------------------------------------------------------------------------
# Stack access. x87_slot: x9 = &ST(w0) for TOP in w8. Clobbers w0.
# ---------------------------------------------------------------------------
.macro x87_slot dst, idx, top
    add \idx, \idx, \top
    and \idx, \idx, 7
    add \dst, _cpu, CPU_fp
    add \dst, \dst, \idx, uxtw 4
.endm

# The start of every operation: the control word, and nothing raised yet.
.macro x87_begin
    ldrh w15, [_cpu, CPU_fcw]
    mov w7, 0
.endm

# A = ST(w0), B = ST(w10): both must hold values, else stack underflow --
# IE and SF, C1 clear, and the indefinite for a result. w0 out: 0, or 1 on
# underflow. Clobbers x8-x13.
x87_get2:
    x87_ld_fsw w8
    x87_ld_valid w9
    ubfx w8, w8, 11, 3
    add w0, w0, w8
    and w0, w0, 7
    add w10, w10, w8
    and w10, w10, 7
    add x12, _cpu, CPU_fp
    add x13, x12, x10, lsl 4
    add x12, x12, x0, lsl 4
    ldr x3, [x12]
    ldrh w4, [x12, 8]
    ldr x5, [x13]
    ldrh w6, [x13, 8]
    lsr w0, w9, w0
    lsr w10, w9, w10
    and w0, w0, w10
    tbz w0, 0, x87_underflow
    mov w0, 0
    ret
x87_underflow:
    mov w0, (X87_C1 | X87_DE | X87_PE | X87_UE | X87_OE | X87_ZE)
    bic w7, w7, w0
    mov w0, (X87_IE | X87_SF)
    orr w7, w7, w0
    x87_indef x3, w4
    mov w0, 1
    ret

# A = ST(w0) (one operand). Same contract.
x87_get1:
    x87_ld_fsw w8
    x87_ld_valid w9
    ubfx w8, w8, 11, 3
    add w0, w0, w8
    and w0, w0, 7
    add x12, _cpu, CPU_fp
    add x12, x12, x0, lsl 4
    ldr x3, [x12]
    ldrh w4, [x12, 8]
    lsr w0, w9, w0
    tbz w0, 0, x87_underflow
    mov w0, 0
    ret

# The status word after an operation: fsw w8 gains the exceptions in w7 and
# takes C1 from it; ES and B follow any unmasked exception. Stored.
x87_put_fsw:
    and w10, w7, 0x7f
    orr w8, w8, w10
    ubfx w10, w7, 9, 1
    bfi w8, w10, 9, 1
    and w10, w8, 0x3f
    bic w10, w10, w15
    cbz w10, 1f
    mov w10, 0x8080
    orr w8, w8, w10
1:  x87_st_fsw w8
    ret

# ST(w0 bits 3-5) = A, then pop if bit 6, then the status word -- unless an
# unmasked IE, DE or ZE, which leave the registers and TOP as they were.
x87_put:
    x87_ld_fsw w8
    bic w10, w7, w15
    tst w10, (X87_IE | X87_DE | X87_ZE)
    b.ne x87_put_fsw
    ubfx w9, w8, 11, 3
    ubfx w10, w0, 3, 3
    x87_slot x11, w10, w9
    str x3, [x11]
    strh w4, [x11, 8]
    x87_ld_valid w11
    mov w12, 1
    lsl w12, w12, w10
    orr w11, w11, w12
    tbz w0, 6, 1f
    mov w12, 1
    lsl w12, w12, w9
    bic w11, w11, w12
    add w9, w9, 1
    bfi w8, w9, 11, 3
1:  x87_st_valid w11
    b x87_put_fsw

# Pop w0 registers (0-2), then the status word with the compare's condition
# codes: C0 C2 C3 from the compare's result in w12 (0 >, 1 <, 2 =, 3
# unordered), C1 clear. An unmasked IE or DE still sets the codes, but pops
# nothing (an AMD Ryzen).
x87_put_cc:
    x87_ld_fsw w8
    bic w10, w7, w15
    tst w10, (X87_IE | X87_DE)      // unmasked: the codes, but no pops
    b.eq 6f
    mov w0, 0
6:  mov w10, (X87_C0 | X87_C2 | X87_C3)
    cmp w12, 1
    b.hi 1f
    mov w10, X87_C0
    b.eq 1f
    mov w10, 0
1:  cmp w12, 2
    b.ne 2f
    mov w10, X87_C3
2:  mov w11, X87_CC
    bic w8, w8, w11
    orr w8, w8, w10
    x87_ld_valid w11
    ubfx w9, w8, 11, 3
    cbz w0, 4f
5:  mov w12, 1
    lsl w12, w12, w9
    bic w11, w11, w12
    add w9, w9, 1
    and w9, w9, 7
    subs w0, w0, 1
    b.ne 5b
    bfi w8, w9, 11, 3
    x87_st_valid w11
4:  bic w7, w7, X87_C1
    b x87_put_fsw

# Push A: the register below TOP must be empty, else stack overflow -- IE and
# SF, C1 set, the indefinite pushed. An unmasked IE (overflow or the load's)
# pushes nothing; a load's DE, unmasked, still loads.
x87_push:
    x87_ld_fsw w8
    x87_ld_valid w11
    ubfx w9, w8, 11, 3
    sub w9, w9, 1
    and w9, w9, 7
    lsr w10, w11, w9
    tbz w10, 0, 1f
    mov w7, (X87_IE | X87_SF | X87_C1)
    x87_indef x3, w4
1:  bic w10, w7, w15
    tbnz w10, 0, x87_put_fsw
    add x10, _cpu, CPU_fp
    add x10, x10, w9, uxtw 4
    str x3, [x10]
    strh w4, [x10, 8]
    mov w10, 1
    lsl w10, w10, w9
    orr w11, w11, w10
    x87_st_valid w11
    bfi w8, w9, 11, 3
    b x87_put_fsw

# Pop once, then the status word: x87_pop1. A macro, so that a host has the
# routine where it wants it in its text; it must expand it once.
.macro x87_pop1_here
x87_pop1:
    x87_ld_fsw w8
    x87_ld_valid w11
    ubfx w9, w8, 11, 3
    mov w12, 1
    lsl w12, w12, w9
    bic w11, w11, w12
    x87_st_valid w11
    add w9, w9, 1
    bfi w8, w9, 11, 3
    b x87_put_fsw
.endm

