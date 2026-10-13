# The x87's memory forms: what each instruction with a memory operand does,
# as macros that emit nothing until a host builds a gadget of one, around its
# own way to guest memory. See x87-arith.S for the conventions. ARCH is the
# host's own word, passed on to its hooks; ID names one access.
#
#   x87m_gadget ARCH, NAME     the gadget's head
#   x87m_wait ARCH             as x87_wait
#   x87m_rprep ARCH, BITS, ID  x9 = a host pointer to the operand, BITS wide
#                              (16, 32, 64 or 80), which may fault and leave
#   x87m_rtail ARCH, BITS, ID  whatever of that is out of line
#   x87m_wprep ARCH, BITS, ID  x87_wp (a register of the host's naming that the
#                              arithmetic does not touch) = where the result
#                              is to be written, which may fault and leave
#   x87m_wdone ARCH, BITS, ID  after the write, before the stack is popped
#                              and the status word written: a host that
#                              wrote to a place of its own stores from there
#                              now. It keeps w7 and w15
#   x87m_wtail ARCH, BITS, ID  whatever of that is out of line
#   x87m_ret ARCH              the gadget's end
#
# A store changes nothing of the x87's before x87m_wdone, so an access that
# faults leaves the instruction to be run again from its start.

.macro x87m_load_kind kind
    .ifc \kind,f32
        ldr w0, [x9]
    .endif
    .ifc \kind,f64
        ldr x0, [x9]
    .endif
    .ifc \kind,i16
        ldrsh x0, [x9]
    .endif
    .ifc \kind,i32
        ldrsw x0, [x9]
    .endif
.endm
.macro x87m_arith arch, kind, bits, ld, op, core
x87m_gadget \arch, \op\()_\kind
    x87m_wait \arch
    x87m_rprep \arch, \bits, \arch\()_\op\()_\kind
    x87m_load_kind \kind
    x87_begin
    bl \ld
    mov w0, 0
    bl x87_get1
    cbnz w0, 1f
    bl \core
1:  mov w0, 0
    bl x87_put
    x87m_ret \arch
    x87m_rtail \arch, \bits, \arch\()_\op\()_\kind
.endm
.macro x87m_com arch, kind, bits, ld, op, pops
x87m_gadget \arch, \op\()_\kind
    x87m_wait \arch
    x87m_rprep \arch, \bits, \arch\()_\op\()_\kind
    x87m_load_kind \kind
    x87_begin
    bl \ld
    mov w0, 0
    bl x87_get1
    mov w12, 3
    cbnz w0, 1f
    mov w0, 1
    bl x87_cmp
    mov w12, w0
1:  mov w0, \pops
    bl x87_put_cc
    x87m_ret \arch
    x87m_rtail \arch, \bits, \arch\()_\op\()_\kind
.endm
.macro x87m_arith_all arch, kind, bits, ld
    x87m_arith \arch, \kind, \bits, \ld, add, x87_add
    x87m_arith \arch, \kind, \bits, \ld, mul, x87_mul
    x87m_com \arch, \kind, \bits, \ld, com, 0
    x87m_com \arch, \kind, \bits, \ld, comp, 1
    x87m_arith \arch, \kind, \bits, \ld, sub, x87_sub
    x87m_arith \arch, \kind, \bits, \ld, subr, x87_subr
    x87m_arith \arch, \kind, \bits, \ld, div, x87_div
    x87m_arith \arch, \kind, \bits, \ld, divr, x87_divr
.endm

# Loads: push the converted value. FLD m32/m64 quiet an SNaN, with IE.
.macro x87m_fld_float arch, kind, bits, ld
x87m_gadget \arch, fld_\kind
    x87m_wait \arch
    x87m_rprep \arch, \bits, \arch\()_fld_\kind
    x87m_load_kind \kind
    x87_begin
    bl \ld
    tbz w7, 16, 2f
    orr w7, w7, X87_DE
2:  x87_class w12, x5, w6, w0
    cmp w12, 5
    b.ne 1f
    orr w7, w7, X87_IE
    orr x5, x5, 0x4000000000000000
1:  mov x3, x5
    mov w4, w6
    bl x87_push
    x87m_ret \arch
    x87m_rtail \arch, \bits, \arch\()_fld_\kind
.endm
.macro x87m_fild arch, kind, bits, ldi
x87m_gadget \arch, fild_\kind
    x87m_wait \arch
    x87m_rprep \arch, \bits, \arch\()_fild_\kind
    \ldi x0, [x9]
    x87_begin
    bl x87_ld_int
    mov x3, x5
    mov w4, w6
    bl x87_push
    x87m_ret \arch
    x87m_rtail \arch, \bits, \arch\()_fild_\kind
.endm
.macro x87m_loads arch
    x87m_fld_float \arch, f32, 32, x87_ld_f32
    x87m_fld_float \arch, f64, 64, x87_ld_f64
    x87m_fild \arch, i16, 16, ldrsh
    x87m_fild \arch, i32, 32, ldrsw
    x87m_fild \arch, i64, 64, ldr
x87m_gadget \arch, fld_f80
    x87m_wait \arch
    x87m_rprep \arch, 80, \arch\()_fld_f80
    ldr x3, [x9]
    ldrh w4, [x9, 8]
    x87_begin
    bl x87_push
    x87m_ret \arch
    x87m_rtail \arch, 80, \arch\()_fld_f80
x87m_gadget \arch, fbld
    x87m_wait \arch
    x87m_rprep \arch, 80, \arch\()_fbld
    ldr x0, [x9]
    ldrh w9, [x9, 8]
    x87_begin
    bl x87_ld_bcd
    mov x3, x5
    mov w4, w6
    bl x87_push
    x87m_ret \arch
    x87m_rtail \arch, 80, \arch\()_fbld
.endm

# Stores: convert ST(0) (the indefinite if it is empty), then -- unless an
# unmasked IE, OE or UE, which store nothing and pop nothing -- store, and
# pop for the P forms.
.macro x87m_store arch, name, bits, pop, conv, st
x87m_gadget \arch, \name
    x87m_wait \arch
    x87m_wprep \arch, \bits, \arch\()_\name
    x87_begin
    mov w0, 0
    bl x87_get1
    \conv
    bic w10, w7, w15
    mov w11, (X87_IE | X87_OE | X87_UE)
    tst w10, w11
    b.ne 8f
    \st
    x87m_wdone \arch, \bits, \arch\()_\name
    .if \pop
        bl x87_pop1
    .else
        x87_ld_fsw w8
        bl x87_put_fsw
    .endif
    x87m_ret \arch
8:  x87_ld_fsw w8
    bl x87_put_fsw
    x87m_ret \arch
    x87m_wtail \arch, \bits, \arch\()_\name
.endm
.macro x87c_f32
    mov w16, 40
    mov w17, 0xfe
    bl x87_to_ieee
.endm
.macro x87c_f64
    mov w16, 11
    mov w17, 0x7fe
    bl x87_to_ieee
.endm
.macro x87c_none
.endm
.macro x87c_i16
    mov w0, 16
    bl x87_to_int
.endm
.macro x87c_i32
    mov w0, 32
    bl x87_to_int
.endm
.macro x87c_i64
    mov w0, 64
    bl x87_to_int
.endm
.macro x87c_tt16
    orr w15, w15, 0xc00
    mov w0, 16
    bl x87_to_int
.endm
.macro x87c_tt32
    orr w15, w15, 0xc00
    mov w0, 32
    bl x87_to_int
.endm
.macro x87c_tt64
    orr w15, w15, 0xc00
    mov w0, 64
    bl x87_to_int
.endm
.macro x87c_bcd
    bl x87_to_bcd
.endm
.macro x87s_w
    str w0, [x87_wp]
.endm
.macro x87s_x
    str x0, [x87_wp]
.endm
.macro x87s_h
    strh w0, [x87_wp]
.endm
.macro x87s_t
    str x3, [x87_wp]
    strh w4, [x87_wp, 8]
.endm
.macro x87s_bcd
    str x0, [x87_wp]
    strh w9, [x87_wp, 8]
.endm
.macro x87m_stores arch
    x87m_store \arch, fst_f32, 32, 0, x87c_f32, x87s_w
    x87m_store \arch, fstp_f32, 32, 1, x87c_f32, x87s_w
    x87m_store \arch, fst_f64, 64, 0, x87c_f64, x87s_x
    x87m_store \arch, fstp_f64, 64, 1, x87c_f64, x87s_x
    x87m_store \arch, fstp_f80, 80, 1, x87c_none, x87s_t
    x87m_store \arch, fist_i16, 16, 0, x87c_i16, x87s_h
    x87m_store \arch, fistp_i16, 16, 1, x87c_i16, x87s_h
    x87m_store \arch, fist_i32, 32, 0, x87c_i32, x87s_w
    x87m_store \arch, fistp_i32, 32, 1, x87c_i32, x87s_w
    x87m_store \arch, fistp_i64, 64, 1, x87c_i64, x87s_x
    x87m_store \arch, fisttp_i16, 16, 1, x87c_tt16, x87s_h
    x87m_store \arch, fisttp_i32, 32, 1, x87c_tt32, x87s_w
    x87m_store \arch, fisttp_i64, 64, 1, x87c_tt64, x87s_x
    x87m_store \arch, fbstp, 80, 1, x87c_bcd, x87s_bcd
.endm
