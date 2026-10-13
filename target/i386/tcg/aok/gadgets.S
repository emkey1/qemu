/*
 * AOK gadgets for x86-64 guests.
 *
 * Operands are byte offsets into CPUX86State, so one gadget serves every
 * register: a 32-bit result is stored as eight bytes, as the architecture
 * zero-extends it; an 8- or 16-bit one as one or two, leaving the rest; AH is
 * the offset of AL plus one. A register that is absent (no base, no index) is
 * the offset of eight bytes that are always zero, and a memory operand of a
 * rare form is first loaded to a temporary there (cpu.h: aok_zero, aok_tmp).
 *
 * The flags are QEMU's own lazy ones: a gadget that sets them stores cc_dst,
 * cc_src and cc_op exactly as the code TCG generates would, so the flags an
 * exception, an interrupt or a TB of TCG's finds are right with nothing to
 * convert, undefined bits included. The same gadget computes with the host's
 * flag-setting instruction, and what the host's NZCV then says of the guest's
 * flags is the translator's to track (translate-x86.c, "Conditions"): a jcc,
 * setcc or cmov right after a cmp tests the host's flags and reads nothing.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define AOK_ASM_OWN_GADGET
#include "accel/tcg/aok-asm.h"
#include "aok-i386-asm.h"

.macro .gadget name
    .balign 16
    .globl SYM(aok_gadget_x86_\name)
SYM(aok_gadget_x86_\name):
.endm

/*
 * The address of an access, and the one an ea gadget leaves for the memory
 * gadget after it. Nothing survives a call to C that is not saved around it:
 * the slow paths below save x1-x6, x8 and x17, so a gadget keeps what must
 * outlive its access in those.
 */
_addr   .req x7
_ea     .req x6

/* The dispatch of a gadget that has already moved _ip past the next word. */
.macro gret_ahead
    ldr x9, [_ip, #-8]
    br x9
.endm

/* Load zero-extended, store as a register is written, store to memory. */
.macro ldsz bits, reg, mem:vararg
    .if \bits == 8
    ldrb w\reg, \mem
    .elseif \bits == 16
    ldrh w\reg, \mem
    .elseif \bits == 32
    ldr w\reg, \mem
    .else
    ldr x\reg, \mem
    .endif
.endm
.macro streg bits, reg, mem:vararg
    .if \bits == 8
    strb w\reg, \mem
    .elseif \bits == 16
    strh w\reg, \mem
    .else
    str x\reg, \mem
    .endif
.endm
.macro stmem bits, reg, mem:vararg
    .if \bits == 8
    strb w\reg, \mem
    .elseif \bits == 16
    strh w\reg, \mem
    .elseif \bits == 32
    str w\reg, \mem
    .else
    str x\reg, \mem
    .endif
.endm

/*
 * cc_dst = x12, cc_src = x11, cc_op = \op + log2 of the bytes. The host's
 * flags stay as they are.
 */
.macro setcc op, bits
    stp x12, x11, [_cpu, #AOK_X86_ENV_CC_DST]
    .if \bits == 8
    mov w16, #(\op)
    .elseif \bits == 16
    mov w16, #(\op + 1)
    .elseif \bits == 32
    mov w16, #(\op + 2)
    .else
    mov w16, #(\op + 3)
    .endif
    str w16, [_cpu, #AOK_X86_ENV_CC_OP]
.endm

/* ---- Guest memory ----------------------------------------------------------
 *
 * The softmmu fast path, as the AArch64 front end has it (its
 * gadgets-shared.S has the account): one compare for an aligned access to a
 * plain page, a second chance for one that is only unaligned, which x86 code
 * is free to make, and cputlb for the rest. A memory gadget's last operand is
 * this host's word, the insn's distance from the TB's first in its upper
 * half and the log2 of the access's bytes below, and _ip is past the next
 * gadget by then.
 *
 * X86_MP: for the gadgets instantiated while it is set, the barriers that
 * give a guest with several CPUs its ordering: every load before whatever
 * follows it, and stores in their order.
 */
#define TLB_FOLD        8       /* CPU_TLB_INDEX_FOLD */
#define TLB_SHIFT       7       /* TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS */
#define TLBE_READ       0
#define TLBE_WRITE      8
#define TLBE_ADDEND     24

.set X86_MP, 0

.macro ld_barrier
    .if X86_MP
    dmb ishld
    .endif
.endm
.macro st_barrier
    .if X86_MP
    dmb ishst
    .endif
.endm

.macro x86_probe size, id, tag
    ldp x9, x10, [_tlb]         /* mask, table */
    eor x11, _addr, _addr, lsr #TLB_FOLD
    and x9, x9, x11, lsr #TLB_SHIFT
    add x10, x10, x9
    ldr x11, [x10, #\tag]
    ldr x10, [x10, #TLBE_ADDEND]
    .if \size == 8
    and x9, _addr, #0xfffffffffffff000
    .else
    and x9, _addr, #(0xfffffffffffff000 | (\size / 8 - 1))
    .endif
    cmp x11, x9
    b.ne miss_\id
    add _addr, _addr, x10
back_\id:
.endm

/* Unaligned, but inside its page and the page plain RAM: the entry's addend. */
.macro x86_unaligned size, id
    .if \size > 8
    and x9, _addr, #0xfff
    cmp x9, #(0x1000 - \size / 8)
    b.hi 1f
    tst _addr, #(\size / 8 - 1)
    b.eq 1f
    and x9, _addr, #0xfffffffffffff000
    cmp x11, x9
    b.ne 1f
    add _addr, _addr, x10
    b back_\id
1:
    .endif
.endm

/* fn(env, address, pc, the word's lower half, \arg) */
.macro x86_call_slow fn, arg
    stp x1, x2, [sp, #-64]!
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x8, x17, [sp, #48]
    mov x4, \arg
    aok_fp_end                  /* (x14-x17 are its scratch) */
    ldr x3, [_ip, #-16]
    mov x0, _cpu
    mov x1, _addr
    add x2, _pc, x3, lsr #32
    and x3, x3, #0xffffffff
    bl SYM(\fn)
    ldp x3, x4, [sp, #16]
    ldp x5, x6, [sp, #32]
    ldp x8, x17, [sp, #48]
    ldp x1, x2, [sp], #64
.endm

/*
 * The out-of-line half of a load, a store (the value is in x17) and a
 * read-modify-write. Each comes back with _addr at the frame's scratch
 * words: a load finds there what cputlb read, a store's write goes nowhere,
 * and a read-modify-write, which cputlb has checked may be written, works on
 * the copy and x86_rmw_done writes it back.
 */
.macro x86_slow_ld size, id
miss_\id:
    x86_unaligned \size, \id
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_ld, x9
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\id
.endm
.macro x86_slow_st size, id
miss_\id:
    x86_unaligned \size, \id
    x86_call_slow aok_x86_helper_st, x17
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\id
.endm
.macro x86_slow_rmw size, id
miss_\id:
    x86_unaligned \size, \id
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_rmw, x9
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\id
.endm
/*
 * After a read-modify-write's store: x5 is the guest address, x12 the value.
 * The host's flags are the operation's by now, and the translator counts on
 * them (a "sub; je" is one compare), so they are kept across the call.
 */
.macro x86_rmw_done
    sub x9, _addr, x29
    sub x9, x9, #AOK_FRAME_SCRATCH
    cbnz x9, 6f
    mrs x9, nzcv
    stp x11, x12, [sp, #-32]!
    str x9, [sp, #16]
    mov _addr, x5
    x86_call_slow aok_x86_helper_st, x12
    ldr x9, [sp, #16]
    ldp x11, x12, [sp], #32
    msr nzcv, x9
6:
.endm

/*
 * Where a memory gadget's address comes from. \n operands of the gadget's
 * own come first, which it has read by now.
 *   bd: [...][base offset][displacement][word]
 *   ea: [...][word], the address what the ea gadget before it left
 */
.macro mem_begin form, n
    .ifc \form, bd
    ldp x9, x10, [_ip, #(8 * \n)]
    add _ip, _ip, #(8 * (\n + 4))
    ldr x9, [_cpu, x9]
    add _addr, x9, x10
    .else
    add _ip, _ip, #(8 * (\n + 2))
    mov _addr, _ea
    .endif
.endm

/* [base offset][index offset][scale][displacement] */
.gadget ea
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x9, [_cpu, x9]
    ldr x10, [_cpu, x10]
    lsl x10, x10, x11
    add x9, x9, x12
    add _ea, x9, x10
    gret 4
/* The same and a segment's base: [...][offset of the base] */
.gadget ea_seg
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x13, [_ip, #32]
    ldr x9, [_cpu, x9]
    ldr x10, [_cpu, x10]
    ldr x13, [_cpu, x13]
    lsl x10, x10, x11
    add x9, x9, x12
    add x9, x9, x13
    add _ea, x9, x10
    gret 5
/* rip-relative: [distance from the TB's first insn] */
.gadget ea_pc
    ldr x9, [_ip]
    add _ea, _pc, x9
    gret 1

/* rip-relative and a segment's base: [distance][offset of the base] */
.gadget ea_pc_seg
    ldp x9, x10, [_ip]
    ldr x10, [_cpu, x10]
    add x9, _pc, x9
    add _ea, x9, x10
    gret 2

/* ---- Moves -------------------------------------------------------------- */

/* Register to register: [destination][source] */
.macro g_mov name, bits
.gadget \name
    ldp x8, x9, [_ip]
    ldsz \bits, 12, [_cpu, x9]
    streg \bits, 12, [_cpu, x8]
    gret 2
.endm
g_mov mov8, 8
g_mov mov16, 16
g_mov mov32, 32
g_mov mov64, 64
/* movzx and movsx between registers: [destination][source] */
.macro g_movx name, insn:vararg
.gadget \name
    ldp x8, x9, [_ip]
    add x9, _cpu, x9
    \insn
    str x12, [_cpu, x8]
    gret 2
.endm
g_movx movzx8, ldrb w12, [x9]
g_movx movzx16, ldrh w12, [x9]
g_movx movsx8_32, ldrsb w12, [x9]
g_movx movsx8_64, ldrsb x12, [x9]
g_movx movsx16_32, ldrsh w12, [x9]
g_movx movsx16_64, ldrsh x12, [x9]
g_movx movsx32_64, ldrsw x12, [x9]

/* An immediate to a register: [destination][value] */
.macro g_movi name, bits
.gadget \name
    ldp x8, x12, [_ip]
    streg \bits, 12, [_cpu, x8]
    gret 2
.endm
g_movi movi8, 8
g_movi movi16, 16
g_movi movi64, 64

/* A code address: [destination][distance from the TB's first insn] */
.gadget pcrel
    ldp x8, x9, [_ip]
    add x9, _pc, x9
    str x9, [_cpu, x8]
    gret 2

/* lea: [destination][base][index][scale][displacement], and the 32-bit one */
.gadget lea64
    ldp x8, x9, [_ip]
    ldp x10, x11, [_ip, #16]
    ldr x12, [_ip, #32]
    ldr x9, [_cpu, x9]
    ldr x10, [_cpu, x10]
    lsl x10, x10, x11
    add x9, x9, x12
    add x9, x9, x10
    str x9, [_cpu, x8]
    gret 5
.gadget lea32
    ldp x8, x9, [_ip]
    ldp x10, x11, [_ip, #16]
    ldr x12, [_ip, #32]
    ldr x9, [_cpu, x9]
    ldr x10, [_cpu, x10]
    lsl x10, x10, x11
    add x9, x9, x12
    add w9, w9, w10
    str x9, [_cpu, x8]
    gret 5
/* What an ea gadget computed, to a register: [destination] */
.gadget lea_ea64
    ldr x8, [_ip]
    str _ea, [_cpu, x8]
    gret 1
.gadget lea_ea32
    ldr x8, [_ip]
    mov w9, w6
    str x9, [_cpu, x8]
    gret 1

/* xchg of two registers: [a][b] */
.macro g_xchg name, bits
.gadget \name
    ldp x8, x9, [_ip]
    ldsz \bits, 12, [_cpu, x8]
    ldsz \bits, 13, [_cpu, x9]
    streg \bits, 13, [_cpu, x8]
    streg \bits, 12, [_cpu, x9]
    gret 2
.endm
g_xchg xchg32, 32
g_xchg xchg64, 64

/* cwde, cdqe: ax to eax and eax to rax, signed. cdq, cqo: rdx is rax's sign. */
.gadget cdqe
    ldrsw x12, [_cpu, #AOK_X86_ENV_REGS]
    str x12, [_cpu, #AOK_X86_ENV_REGS]
    gret
.gadget cwde
    ldrsh w12, [_cpu, #AOK_X86_ENV_REGS]
    str x12, [_cpu, #AOK_X86_ENV_REGS]
    gret
.gadget cqo
    ldr x12, [_cpu, #AOK_X86_ENV_REGS]
    asr x12, x12, #63
    str x12, [_cpu, #(AOK_X86_ENV_REGS + 16)]
    gret
.gadget cdq
    ldr w12, [_cpu, #AOK_X86_ENV_REGS]
    asr w12, w12, #31
    str x12, [_cpu, #(AOK_X86_ENV_REGS + 16)]
    gret

/* ---- Loads and stores ------------------------------------------------------
 *
 * load: [destination] and the address; \ldinsn reads x17 or w17, and the
 * register is written as \stbits says. store: [source] and the address.
 * storei: [value] and the address.
 */
.macro g_load name, bits, stbits, form, ldinsn:vararg
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    x86_probe \bits, \name, TLBE_READ
    \ldinsn, [_addr]
    ld_barrier
    streg \stbits, 17, [_cpu, x8]
    gret_ahead
    x86_slow_ld \bits, \name
.endm
/*
 * The load of an instruction that will store to the same place: the page
 * must be writable before anything is changed, so this is where it faults.
 * [temporary] and the address; the value is zero-extended.
 */
.macro g_loadw name, bits, form, ldinsn:vararg
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    x86_probe \bits, \name, TLBE_WRITE
    \ldinsn, [_addr]
    ld_barrier
    str x17, [_cpu, x8]
    gret_ahead
    x86_slow_rmw \bits, \name
.endm
.macro g_store name, bits, form
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    ldr x17, [_cpu, x8]
    x86_probe \bits, \name, TLBE_WRITE
    st_barrier
    stmem \bits, 17, [_addr]
    gret_ahead
    x86_slow_st \bits, \name
.endm
.macro g_storei name, bits, form
.gadget \name
    ldr x17, [_ip]
    mem_begin \form, 1
    x86_probe \bits, \name, TLBE_WRITE
    st_barrier
    stmem \bits, 17, [_addr]
    gret_ahead
    x86_slow_st \bits, \name
.endm

/*
 * (An .irp inside a macro will not do for these: the macro's expansion takes
 * the "\()" that ends a name before the .irp sees it.)
 */
.macro loads_stores1 form, sfx
g_load load8_\form\sfx, 8, 8, \form, ldrb w17
g_load load16_\form\sfx, 16, 16, \form, ldrh w17
g_load load32_\form\sfx, 32, 64, \form, ldr w17
g_load load64_\form\sfx, 64, 64, \form, ldr x17
g_load loadzx8_\form\sfx, 8, 64, \form, ldrb w17
g_load loadzx16_\form\sfx, 16, 64, \form, ldrh w17
g_load loadsx8_32_\form\sfx, 8, 64, \form, ldrsb w17
g_load loadsx8_64_\form\sfx, 8, 64, \form, ldrsb x17
g_load loadsx16_32_\form\sfx, 16, 64, \form, ldrsh w17
g_load loadsx16_64_\form\sfx, 16, 64, \form, ldrsh x17
g_load loadsx32_64_\form\sfx, 32, 64, \form, ldrsw x17
g_loadw loadw8_\form\sfx, 8, \form, ldrb w17
g_loadw loadw16_\form\sfx, 16, \form, ldrh w17
g_loadw loadw32_\form\sfx, 32, \form, ldr w17
g_loadw loadw64_\form\sfx, 64, \form, ldr x17
g_store store8_\form\sfx, 8, \form
g_store store16_\form\sfx, 16, \form
g_store store32_\form\sfx, 32, \form
g_store store64_\form\sfx, 64, \form
g_storei storei8_\form\sfx, 8, \form
g_storei storei16_\form\sfx, 16, \form
g_storei storei32_\form\sfx, 32, \form
g_storei storei64_\form\sfx, 64, \form
.endm
.macro loads_stores sfx
loads_stores1 bd, \sfx
loads_stores1 ea, \sfx
.endm

/* ---- Arithmetic and logic --------------------------------------------------
 *
 * alu_core: x10 op x11 at \bits, the result in x12 (zero-extended), the host's
 * flags set as the translator expects of the operation's class: by adds or
 * subs, on operands moved to the top of the register where they are
 * narrower, or for the logic ones by a compare of the result with zero.
 */
.macro alu_core op, bits
    .if \bits >= 32
    .if \bits == 32
    alu_core1 \op, w10, w11, w12, w12
    .else
    alu_core1 \op, x10, x11, x12, x12
    .endif
    .else
    alu_narrow \op, (32 - \bits)
    .endif
.endm
.macro alu_core1 op, a, b, r, rflags
    .ifc \op, add
    adds \r, \a, \b
    .endif
    .ifc \op, sub
    subs \r, \a, \b
    .endif
    .ifc \op, and
    and \r, \a, \b
    cmp \rflags, #0
    .endif
    .ifc \op, or
    orr \r, \a, \b
    cmp \rflags, #0
    .endif
    .ifc \op, xor
    eor \r, \a, \b
    cmp \rflags, #0
    .endif
.endm
.macro alu_narrow op, sh
    .ifc \op, add
    lsl w13, w10, #\sh
    adds w12, w13, w11, lsl #\sh
    lsr w12, w12, #\sh
    .endif
    .ifc \op, sub
    lsl w13, w10, #\sh
    subs w12, w13, w11, lsl #\sh
    lsr w12, w12, #\sh
    .endif
    .ifc \op, and
    and w12, w10, w11
    lsl w13, w12, #\sh
    cmp w13, #0
    .endif
    .ifc \op, or
    orr w12, w10, w11
    lsl w13, w12, #\sh
    cmp w13, #0
    .endif
    .ifc \op, xor
    eor w12, w10, w11
    lsl w13, w12, #\sh
    cmp w13, #0
    .endif
.endm
/* The lazy flags of \op at \bits: cc_dst = x12, cc_src = x11. */
.macro alu_setcc op, bits
    .ifc \op, add
    setcc AOK_CC_OP_ADD, \bits
    .else
    .ifc \op, sub
    setcc AOK_CC_OP_SUB, \bits
    .else
    setcc AOK_CC_OP_LOGIC, \bits
    .endif
    .endif
.endm

/*
 * \store 1: the result is written (add, or, and, sub, xor); 0: it is not
 * (cmp, test). The forms:
 *   rr  [destination][source]
 *   ri  [destination][immediate]
 *   rm  [destination] and the address: destination = destination op memory
 *   mr  [source] and the address: memory = memory op source
 *   mi  [immediate] and the address
 */
.macro g_alu_rr name, op, bits, store
.gadget \name
    ldp x8, x9, [_ip]
    ldsz \bits, 10, [_cpu, x8]
    ldsz \bits, 11, [_cpu, x9]
    alu_core \op, \bits
    .if \store
    streg \bits, 12, [_cpu, x8]
    .endif
    alu_setcc \op, \bits
    gret 2
.endm
.macro g_alu_ri name, op, bits, store
.gadget \name
    ldp x8, x11, [_ip]
    ldsz \bits, 10, [_cpu, x8]
    alu_core \op, \bits
    .if \store
    streg \bits, 12, [_cpu, x8]
    .endif
    alu_setcc \op, \bits
    gret 2
.endm
.macro g_alu_rm name, op, bits, store, form
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    x86_probe \bits, \name, TLBE_READ
    ldsz \bits, 11, [_addr]
    ld_barrier
    ldsz \bits, 10, [_cpu, x8]
    alu_core \op, \bits
    .if \store
    streg \bits, 12, [_cpu, x8]
    .endif
    alu_setcc \op, \bits
    gret_ahead
    x86_slow_ld \bits, \name
.endm
/* \src reg: x8 is a register's offset; imm: x8 is the value */
.macro g_alu_mem name, op, bits, store, form, src
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    .if \store
    mov x5, _addr
    x86_probe \bits, \name, TLBE_WRITE
    .else
    x86_probe \bits, \name, TLBE_READ
    .endif
    ldsz \bits, 10, [_addr]
    ld_barrier
    .ifc \src, reg
    ldsz \bits, 11, [_cpu, x8]
    .else
    mov x11, x8
    .endif
    alu_core \op, \bits
    .if \store
    st_barrier
    stmem \bits, 12, [_addr]
    x86_rmw_done
    .endif
    alu_setcc \op, \bits
    gret_ahead
    .if \store
    x86_slow_rmw \bits, \name
    .else
    x86_slow_ld \bits, \name
    .endif
.endm

.macro alu_reg_forms1 op, store, name, bits
g_alu_rr \name\bits\()_rr, \op, \bits, \store
g_alu_ri \name\bits\()_ri, \op, \bits, \store
.endm
.macro alu_reg_forms op, store, name
alu_reg_forms1 \op, \store, \name, 8
alu_reg_forms1 \op, \store, \name, 16
alu_reg_forms1 \op, \store, \name, 32
alu_reg_forms1 \op, \store, \name, 64
.endm
alu_reg_forms add, 1, add
alu_reg_forms or, 1, or
alu_reg_forms and, 1, and
alu_reg_forms sub, 1, sub
alu_reg_forms xor, 1, xor
alu_reg_forms sub, 0, cmp
alu_reg_forms and, 0, test

.macro alu_mem_forms1 op, store, name, form, bits, sfx
g_alu_rm \name\bits\()_rm_\form\sfx, \op, \bits, \store, \form
g_alu_mem \name\bits\()_mr_\form\sfx, \op, \bits, \store, \form, reg
g_alu_mem \name\bits\()_mi_\form\sfx, \op, \bits, \store, \form, imm
.endm
.macro alu_mem_forms op, store, name, sfx
alu_mem_forms1 \op, \store, \name, bd, 8, \sfx
alu_mem_forms1 \op, \store, \name, bd, 16, \sfx
alu_mem_forms1 \op, \store, \name, bd, 32, \sfx
alu_mem_forms1 \op, \store, \name, bd, 64, \sfx
alu_mem_forms1 \op, \store, \name, ea, 8, \sfx
alu_mem_forms1 \op, \store, \name, ea, 16, \sfx
alu_mem_forms1 \op, \store, \name, ea, 32, \sfx
alu_mem_forms1 \op, \store, \name, ea, 64, \sfx
.endm
.macro all_mem sfx
loads_stores \sfx
alu_mem_forms add, 1, add, \sfx
alu_mem_forms or, 1, or, \sfx
alu_mem_forms and, 1, and, \sfx
alu_mem_forms sub, 1, sub, \sfx
alu_mem_forms xor, 1, xor, \sfx
alu_mem_forms sub, 0, cmp, \sfx
alu_mem_forms and, 0, test, \sfx
.endm
all_mem
.set X86_MP, 1
all_mem _mp
.set X86_MP, 0

/* not and neg of a register: [register]. neg is 0 - x, with sub's flags. */
.macro g_not name, bits
.gadget \name
    ldr x8, [_ip]
    ldsz \bits, 10, [_cpu, x8]
    mvn w12, w10
    .if \bits == 64
    mvn x12, x10
    .endif
    streg \bits, 12, [_cpu, x8]
    gret 1
.endm
.macro g_neg name, bits
.gadget \name
    ldr x8, [_ip]
    ldsz \bits, 11, [_cpu, x8]
    mov x10, #0
    alu_core sub, \bits
    streg \bits, 12, [_cpu, x8]
    setcc AOK_CC_OP_SUB, \bits
    gret 1
.endm
.irp bits, 8, 16, 32, 64
g_not not\bits, \bits
g_neg neg\bits, \bits
.endr

/*
 * inc and dec of a register: [register][the carry flag as it is]. They leave
 * CF alone, so the lazy state wants it: the translator gives it as the
 * offset of a byte that holds it (a cf gadget wrote aok_tmp[1]).
 */
.macro g_incdec name, bits, insn, ccop
.gadget \name
    ldp x8, x9, [_ip]
    ldsz \bits, 10, [_cpu, x8]
    ldrb w11, [_cpu, x9]
    .if \bits == 64
    \insn x12, x10, #1
    .elseif \bits == 32
    \insn w12, w10, #1
    .else
    lsl w13, w10, #(32 - \bits)
    mov w14, #(1 << (32 - \bits))
    \insn w12, w13, w14
    lsr w12, w12, #(32 - \bits)
    .endif
    streg \bits, 12, [_cpu, x8]
    setcc \ccop, \bits
    gret 2
.endm
.irp bits, 8, 16, 32, 64
g_incdec inc\bits, \bits, adds, AOK_CC_OP_INC
g_incdec dec\bits, \bits, subs, AOK_CC_OP_DEC
.endr

/*
 * adc and sbb of registers, 32 and 64 bits: [destination][source][carry
 * byte's offset], and with an immediate. cc_src2 is the carry that came in.
 */
.macro g_adc name, r, insn, ccop, bits, imm
.gadget \name
    ldp x8, x9, [_ip]
    ldr x13, [_ip, #16]
    ldr \r\()10, [_cpu, x8]
    .if \imm
    mov x11, x9
    .else
    ldr \r\()11, [_cpu, x9]
    .endif
    ldrb w13, [_cpu, x13]
    .ifc \insn, adcs
    cmp x13, #1                 /* C = the carry */
    .else
    negs x14, x13               /* C = no borrow */
    .endif
    \insn \r\()12, \r\()10, \r\()11
    str x12, [_cpu, x8]
    str x13, [_cpu, #AOK_X86_ENV_CC_SRC2]
    setcc \ccop, \bits
    gret 3
.endm
g_adc adc32_rr, w, adcs, AOK_CC_OP_ADC, 32, 0
g_adc adc64_rr, x, adcs, AOK_CC_OP_ADC, 64, 0
g_adc adc32_ri, w, adcs, AOK_CC_OP_ADC, 32, 1
g_adc adc64_ri, x, adcs, AOK_CC_OP_ADC, 64, 1
g_adc sbb32_rr, w, sbcs, AOK_CC_OP_SBB, 32, 0
g_adc sbb64_rr, x, sbcs, AOK_CC_OP_SBB, 64, 0
g_adc sbb32_ri, w, sbcs, AOK_CC_OP_SBB, 32, 1
g_adc sbb64_ri, x, sbcs, AOK_CC_OP_SBB, 64, 1

/*
 * Shifts of a register by a count that is not zero (the translator has
 * masked it, and a count of zero is no shift): [register][count]. The lazy
 * state is the result and the value one step short of it, whose top or
 * bottom bit is the carry.
 */
.macro g_shift name, bits, insn, ccop, ldinsn:vararg
.gadget \name
    ldp x8, x9, [_ip]
    add x10, _cpu, x8
    \ldinsn, [x10]
    sub x13, x9, #1
    .if \bits == 64
    \insn x11, x10, x13
    \insn x12, x10, x9
    cmp x12, #0
    .else
    \insn w11, w10, w13
    \insn w12, w10, w9
    .if \bits == 32
    cmp w12, #0
    .else
    lsl w13, w12, #(32 - \bits)
    cmp w13, #0
    .endif
    .endif
    streg \bits, 12, [_cpu, x8]
    setcc \ccop, \bits
    gret 2
.endm
g_shift shl8, 8, lsl, AOK_CC_OP_SHL, ldrb w10
g_shift shl16, 16, lsl, AOK_CC_OP_SHL, ldrh w10
g_shift shl32, 32, lsl, AOK_CC_OP_SHL, ldr w10
g_shift shl64, 64, lsl, AOK_CC_OP_SHL, ldr x10
g_shift shr8, 8, lsr, AOK_CC_OP_SAR, ldrb w10
g_shift shr16, 16, lsr, AOK_CC_OP_SAR, ldrh w10
g_shift shr32, 32, lsr, AOK_CC_OP_SAR, ldr w10
g_shift shr64, 64, lsr, AOK_CC_OP_SAR, ldr x10
g_shift sar8, 8, asr, AOK_CC_OP_SAR, ldrsb w10
g_shift sar16, 16, asr, AOK_CC_OP_SAR, ldrsh w10
g_shift sar32, 32, asr, AOK_CC_OP_SAR, ldr w10
g_shift sar64, 64, asr, AOK_CC_OP_SAR, ldr x10

/*
 * The same by cl: [register][mask of the count]. A count of zero changes
 * nothing, flags included, but a 32-bit register is still written.
 */
.macro g_shift_cl name, bits, insn, ccop, ldinsn:vararg
.gadget \name
    ldp x8, x9, [_ip]
    ldrb w14, [_cpu, #(AOK_X86_ENV_REGS + 8)]
    add x10, _cpu, x8
    \ldinsn, [x10]
    ands x9, x14, x9
    b.eq 1f
    sub x13, x9, #1
    .if \bits == 64
    \insn x11, x10, x13
    \insn x12, x10, x9
    cmp x12, #0
    .else
    \insn w11, w10, w13
    \insn w12, w10, w9
    .if \bits == 32
    cmp w12, #0
    .else
    lsl w13, w12, #(32 - \bits)
    cmp w13, #0
    .endif
    .endif
    streg \bits, 12, [_cpu, x8]
    setcc \ccop, \bits
    gret 2
1:
    .if \bits == 32
    mov w12, w10
    str x12, [_cpu, x8]
    .endif
    gret 2
.endm
g_shift_cl shl8_cl, 8, lsl, AOK_CC_OP_SHL, ldrb w10
g_shift_cl shl16_cl, 16, lsl, AOK_CC_OP_SHL, ldrh w10
g_shift_cl shl32_cl, 32, lsl, AOK_CC_OP_SHL, ldr w10
g_shift_cl shl64_cl, 64, lsl, AOK_CC_OP_SHL, ldr x10
g_shift_cl shr8_cl, 8, lsr, AOK_CC_OP_SAR, ldrb w10
g_shift_cl shr16_cl, 16, lsr, AOK_CC_OP_SAR, ldrh w10
g_shift_cl shr32_cl, 32, lsr, AOK_CC_OP_SAR, ldr w10
g_shift_cl shr64_cl, 64, lsr, AOK_CC_OP_SAR, ldr x10
g_shift_cl sar8_cl, 8, asr, AOK_CC_OP_SAR, ldrsb w10
g_shift_cl sar16_cl, 16, asr, AOK_CC_OP_SAR, ldrsh w10
g_shift_cl sar32_cl, 32, asr, AOK_CC_OP_SAR, ldr w10
g_shift_cl sar64_cl, 64, asr, AOK_CC_OP_SAR, ldr x10

/*
 * imul with two and three operands: [destination][source][second source, or
 * the immediate]. The lazy state is the result and a word that is zero when
 * it fits: the high half less the low half's sign.
 */
.macro g_imul name, bits, imm
.gadget \name
    ldp x8, x9, [_ip]
    ldr x11, [_ip, #16]
    .if \bits == 64
    ldr x10, [_cpu, x9]
    .if \imm == 0
    ldr x11, [_cpu, x11]
    .endif
    mul x12, x10, x11
    smulh x13, x10, x11
    sub x11, x13, x12, asr #63
    .else
    ldrsw x10, [_cpu, x9]
    .if \imm == 0
    ldrsw x11, [_cpu, x11]
    .endif
    mul x12, x10, x11
    sxtw x13, w12
    sub x11, x12, x13
    mov w12, w12
    .endif
    str x12, [_cpu, x8]
    setcc AOK_CC_OP_MUL, \bits
    gret 3
.endm
g_imul imul32_rr, 32, 0
g_imul imul64_rr, 64, 0
g_imul imul32_ri, 32, 1
g_imul imul64_ri, 64, 1

/*
 * Rotates whose flags nothing reads (translate-x86.c, "Liveness"):
 * [register][count], to the right: the translator turns a count to the left
 * around. The narrow ones rotate the value repeated to 32 bits.
 */
.gadget ror64
    ldp x8, x9, [_ip]
    ldr x10, [_cpu, x8]
    ror x10, x10, x9
    str x10, [_cpu, x8]
    gret 2
.gadget ror32
    ldp x8, x9, [_ip]
    ldr w10, [_cpu, x8]
    ror w10, w10, w9
    str x10, [_cpu, x8]
    gret 2
.gadget ror16
    ldp x8, x9, [_ip]
    ldrh w10, [_cpu, x8]
    orr w10, w10, w10, lsl #16
    ror w10, w10, w9
    strh w10, [_cpu, x8]
    gret 2
.gadget ror8
    ldp x8, x9, [_ip]
    ldrb w10, [_cpu, x8]
    orr w10, w10, w10, lsl #8
    orr w10, w10, w10, lsl #16
    ror w10, w10, w9
    strb w10, [_cpu, x8]
    gret 2
/* The same by cl: [register][whether to the left] */
.macro g_rot_cl name, r
.gadget \name
    ldp x8, x9, [_ip]
    ldrb w11, [_cpu, #(AOK_X86_ENV_REGS + 8)]
    ldr \r\()10, [_cpu, x8]
    cbz x9, 1f
    neg w11, w11
1:  ror \r\()10, \r\()10, \r\()11
    str x10, [_cpu, x8]
    gret 2
.endm
g_rot_cl rot32_cl, w
g_rot_cl rot64_cl, x

/* bswap: [register] */
.gadget bswap32
    ldr x8, [_ip]
    ldr w10, [_cpu, x8]
    rev w10, w10
    str x10, [_cpu, x8]
    gret 1
.gadget bswap64
    ldr x8, [_ip]
    ldr x10, [_cpu, x8]
    rev x10, x10
    str x10, [_cpu, x8]
    gret 1

/*
 * bt, bts, btr and btc of a register or a temporary: [operand][the bit][cc_op].
 * Only the carry changes, which the lazy flags have two ways to say, as in
 * QEMU's gen_bt_flags(): where the state is of an operation with a size, the
 * shifted operand as cc_src and the "sar" of that size as the operation,
 * which keeps Z where it was (the cc_op to store); where it is the flags
 * themselves (0), bit 0 of them. The host's Z says the bit was clear.
 * \rr: the bit's number is a register's, modulo the size.
 */
.macro g_bt name, op, bits, rr
.gadget \name
    ldp x8, x9, [_ip]
    ldr x13, [_ip, #16]
    .if \rr
    ldr x9, [_cpu, x9]
    .endif
    and x9, x9, #(\bits - 1)
    .if \bits == 64
    ldr x10, [_cpu, x8]
    .else
    ldr w10, [_cpu, x8]
    .endif
    mov x14, #1
    lsl x14, x14, x9
    lsr x11, x10, x9
    .ifc \op, bts
    orr x12, x10, x14
    str x12, [_cpu, x8]
    .endif
    .ifc \op, btr
    bic x12, x10, x14
    str x12, [_cpu, x8]
    .endif
    .ifc \op, btc
    eor x12, x10, x14
    str x12, [_cpu, x8]
    .endif
    cbz x13, 1f
    str x11, [_cpu, #AOK_X86_ENV_CC_SRC]
    str w13, [_cpu, #AOK_X86_ENV_CC_OP]
    tst x10, x14
    gret 3
1:  ldr x12, [_cpu, #AOK_X86_ENV_CC_SRC]
    bfi x12, x11, #0, #1
    str x12, [_cpu, #AOK_X86_ENV_CC_SRC]
    tst x10, x14
    gret 3
.endm
.irp op, bt, bts, btr, btc
g_bt \op\()32_ri, \op, 32, 0
g_bt \op\()64_ri, \op, 64, 0
g_bt \op\()32_rr, \op, 32, 1
g_bt \op\()64_rr, \op, 64, 1
.endr

/*
 * bsf and bsr: [destination][source]. Of zero they leave the destination
 * as it was, and the flags are the source's. tzcnt and lzcnt: the size for
 * zero, and flags of their own (CC_OP_BMILG: cc_src the source).
 */
.macro g_bitscan name, kind, r, ccop, top=0
.gadget \name
    ldp x8, x9, [_ip]
    ldr \r\()10, [_cpu, x9]
    ldr \r\()13, [_cpu, x8]
    .ifc \kind, bsf
    rbit \r\()12, \r\()10
    clz \r\()12, \r\()12
    cmp \r\()10, #0
    csel \r\()12, \r\()13, \r\()12, eq
    .endif
    .ifc \kind, bsr
    clz \r\()12, \r\()10
    eor \r\()12, \r\()12, #\top
    cmp \r\()10, #0
    csel \r\()12, \r\()13, \r\()12, eq
    .endif
    .ifc \kind, tzcnt
    rbit \r\()12, \r\()10
    clz \r\()12, \r\()12
    .endif
    .ifc \kind, lzcnt
    clz \r\()12, \r\()10
    .endif
    str x12, [_cpu, x8]
    mov w16, #\ccop
    .if \ccop >= AOK_CC_OP_BMILG
    stp x12, x10, [_cpu, #AOK_X86_ENV_CC_DST]
    .else
    str x10, [_cpu, #AOK_X86_ENV_CC_DST]
    .endif
    str w16, [_cpu, #AOK_X86_ENV_CC_OP]
    gret 2
.endm
g_bitscan bsf32, bsf, w, (AOK_CC_OP_LOGIC + 2)
g_bitscan bsf64, bsf, x, (AOK_CC_OP_LOGIC + 3)
g_bitscan bsr32, bsr, w, (AOK_CC_OP_LOGIC + 2), 31
g_bitscan bsr64, bsr, x, (AOK_CC_OP_LOGIC + 3), 63
g_bitscan tzcnt32, tzcnt, w, (AOK_CC_OP_BMILG + 2)
g_bitscan tzcnt64, tzcnt, x, (AOK_CC_OP_BMILG + 3)
g_bitscan lzcnt32, lzcnt, w, (AOK_CC_OP_BMILG + 2)
g_bitscan lzcnt64, lzcnt, x, (AOK_CC_OP_BMILG + 3)

/* cli and sti; and the barriers of lfence, sfence and mfence. */
.gadget cli
    ldr x9, [_cpu, #AOK_X86_ENV_EFLAGS]
    and x9, x9, #~AOK_X86_IF
    str x9, [_cpu, #AOK_X86_ENV_EFLAGS]
    gret
.gadget sti
    ldr x9, [_cpu, #AOK_X86_ENV_EFLAGS]
    orr x9, x9, #AOK_X86_IF
    str x9, [_cpu, #AOK_X86_ENV_EFLAGS]
    gret
.gadget mb_ld
    dmb ishld
    gret
.gadget mb_st
    dmb ishst
    gret
.gadget mb
    dmb ish
    gret

/* ---- Conditions ------------------------------------------------------------
 *
 * hf: make the host's flags the guest's again from the lazy state, for a
 * condition whose compare is not the gadget before it. One per class and
 * size; what each leaves is what the gadgets of that class leave.
 */
.macro g_hf name, op, bits
.gadget \name
    ldp x12, x11, [_cpu, #AOK_X86_ENV_CC_DST]
    .ifc \op, sub
    add x10, x12, x11           /* the first operand: result + second */
    alu_core sub, \bits
    .endif
    .ifc \op, add
    sub x10, x12, x11           /* the second: result - first */
    alu_core add, \bits
    .endif
    .ifc \op, logic
    .if \bits == 64
    cmp x12, #0
    .elseif \bits == 32
    cmp w12, #0
    .else
    lsl w13, w12, #(32 - \bits)
    cmp w13, #0
    .endif
    .endif
    gret
.endm
.irp bits, 8, 16, 32, 64
g_hf hf_sub\bits, sub, \bits
g_hf hf_add\bits, add, \bits
g_hf hf_logic\bits, logic, \bits
.endr

/*
 * Any condition of any lazy state, in C: [the x86 condition]. Leaves the
 * host's Z clear when it holds, for the "ne" form of whatever follows.
 */
.gadget cond
    aok_fp_end
    ldr x1, [_ip]
    mov x0, _cpu
    bl SYM(aok_x86_helper_cond)
    cmp x0, #0
    gret 1

/*
 * The carry flag, to the byte inc, dec, adc and sbb take it from
 * (aok_tmp[1]): from the host's flags after a subtraction (cf_sub) or an
 * addition (cf_add), as zero (cf_zero), or computed in C (cf).
 */
#define AOK_X86_ENV_TMP1    (AOK_X86_ENV_AOK_ZERO + 16)
.gadget cf_sub
    cset w9, cc
    strb w9, [_cpu, #AOK_X86_ENV_TMP1]
    gret
.gadget cf_add
    cset w9, cs
    strb w9, [_cpu, #AOK_X86_ENV_TMP1]
    gret
.gadget cf_zero
    strb wzr, [_cpu, #AOK_X86_ENV_TMP1]
    gret
.gadget cf
    aok_fp_end
    mov x0, _cpu
    bl SYM(aok_x86_helper_cf)
    strb w0, [_cpu, #AOK_X86_ENV_TMP1]
    gret
/* After a bt gadget. */
.gadget cf_bt
    cset w9, ne
    strb w9, [_cpu, #AOK_X86_ENV_TMP1]
    gret

/* Make the lazy flags the flags themselves (CC_OP_EFLAGS), in C. */
.gadget flush_cc
    aok_fp_end
    mov x0, _cpu
    bl SYM(aok_x86_helper_flush_cc)
    gret

#define CONDS eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le

/* setcc: [the byte's offset] */
.macro g_setcc cc
.gadget set_\cc
    ldr x8, [_ip]
    cset w9, \cc
    strb w9, [_cpu, x8]
    gret 1
.endm
/* cmov: [destination][source]. The 32-bit one writes its register anyway. */
.macro g_cmov cc
.gadget cmov32_\cc
    ldp x8, x9, [_ip]
    ldr w10, [_cpu, x8]
    ldr w11, [_cpu, x9]
    csel w10, w11, w10, \cc
    str x10, [_cpu, x8]
    gret 2
.gadget cmov64_\cc
    ldp x8, x9, [_ip]
    ldr x10, [_cpu, x8]
    ldr x11, [_cpu, x9]
    csel x10, x11, x10, \cc
    str x10, [_cpu, x8]
    gret 2
.endm
.irp cc, CONDS
g_setcc \cc
g_cmov \cc
.endr

/* ---- Leaving a TB ----------------------------------------------------------
 *
 * A way out is aok_gadget_goto's two operands, [pc delta][slot], each its own
 * copy of aok_goto_tail so that each ends in an indirect branch of its own.
 */
.macro x86_leave off
    ldp x9, x10, [_ip, #\off]
    ldr w11, [_exitreq]
    add _pc, _pc, x9
    ldr _ip, [x10]
    str _pc, [_pcp]
    tbnz w11, #31, 7f
    gret AOK_ENTER_WORDS
7:  b SYM(aok_exit_requested)
.endm

/* [pc delta][slot] (jmp, and whatever ends a TB without a branch) */
.gadget jmp
    x86_leave 0

/* jcc on the host's flags: [taken: pc delta][slot][not: pc delta][slot] */
.macro g_jcc cc
.gadget jcc_\cc
    b.\cc 1f
    x86_leave 16
1:  x86_leave 0
.endm
.irp cc, CONDS
g_jcc \cc
.endr

/* ---- The stack -------------------------------------------------------------
 *
 * push: [source's offset][word]; pushi: [value][word]. The store is made
 * before rsp moves, so a fault leaves it where it was.
 */
.macro g_push name, imm, sfx
.gadget \name\sfx
    ldr x8, [_ip]
    add _ip, _ip, #24
    .if \imm
    mov x17, x8
    .else
    ldr x17, [_cpu, x8]
    .endif
    ldr x5, [_cpu, #AOK_X86_ENV_RSP]
    sub x5, x5, #8
    mov _addr, x5
    x86_probe 64, \name\sfx, TLBE_WRITE
    st_barrier
    str x17, [_addr]
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    gret_ahead
    x86_slow_st 64, \name\sfx
.endm
/* pop: [destination's offset][word]. rsp first: "pop rsp" keeps what it got. */
.macro g_pop sfx
.gadget pop\sfx
    ldr x8, [_ip]
    add _ip, _ip, #24
    ldr x5, [_cpu, #AOK_X86_ENV_RSP]
    mov _addr, x5
    x86_probe 64, pop\sfx, TLBE_READ
    ldr x17, [_addr]
    ld_barrier
    add x5, x5, #8
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    str x17, [_cpu, x8]
    gret_ahead
    x86_slow_ld 64, pop\sfx
.endm
/* leave: [word]. rsp = rbp, then pop rbp. */
.macro g_leave sfx
.gadget leave\sfx
    add _ip, _ip, #16
    ldr x5, [_cpu, #AOK_X86_ENV_RBP]
    mov _addr, x5
    x86_probe 64, leave\sfx, TLBE_READ
    ldr x17, [_addr]
    ld_barrier
    add x5, x5, #8
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    str x17, [_cpu, #AOK_X86_ENV_RBP]
    gret_ahead
    x86_slow_ld 64, leave\sfx
.endm

/*
 * call: [return address's distance from the TB's first insn][word], then a
 * way out: the return address is pushed, then it is a jmp.
 */
.macro g_call sfx
.gadget call\sfx
    ldr x8, [_ip]
    add _ip, _ip, #24
    add x17, _pc, x8
    ldr x5, [_cpu, #AOK_X86_ENV_RSP]
    sub x5, x5, #8
    mov _addr, x5
    x86_probe 64, call\sfx, TLBE_WRITE
    st_barrier
    str x17, [_addr]
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    sub _ip, _ip, #8
    x86_leave 0
    x86_slow_st 64, call\sfx
.endm
/*
 * An indirect call: [target's offset][return address's distance][word], then
 * a lookup's operands. The target is read first: it may be rsp-relative.
 */
.macro g_calli sfx
.gadget calli\sfx
    ldp x8, x9, [_ip]
    add _ip, _ip, #32
    ldr x4, [_cpu, x8]
    add x17, _pc, x9
    ldr x5, [_cpu, #AOK_X86_ENV_RSP]
    sub x5, x5, #8
    mov _addr, x5
    x86_probe 64, calli\sfx, TLBE_WRITE
    st_barrier
    str x17, [_addr]
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    mov x10, x4
    str x10, [_pcp]
    sub _ip, _ip, #8
    b SYM(aok_x86_lookup_pc)
    x86_slow_st 64, calli\sfx
.endm
/* ret: [bytes to drop besides][word], then a lookup's operands */
.macro g_ret sfx
.gadget ret\sfx
    ldr x8, [_ip]
    add _ip, _ip, #24
    ldr x5, [_cpu, #AOK_X86_ENV_RSP]
    mov _addr, x5
    x86_probe 64, ret\sfx, TLBE_READ
    ldr x10, [_addr]
    ld_barrier
    add x5, x5, #8
    add x5, x5, x8
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    str x10, [_pcp]
    sub _ip, _ip, #8
    b SYM(aok_x86_lookup_pc)
    x86_slow_ld 64, ret\sfx
.endm
.macro all_stack sfx
g_push push, 0, \sfx
g_push pushi, 1, \sfx
g_pop \sfx
g_leave \sfx
g_call \sfx
g_calli \sfx
g_ret \sfx
.endm
all_stack
.set X86_MP, 1
all_stack _mp
.set X86_MP, 0

/* An indirect jmp: [target's offset], then a lookup's operands */
.gadget jmpi
    ldr x8, [_ip]
    ldr x10, [_cpu, x8]
    str x10, [_pcp]
    add _ip, _ip, #8
    b SYM(aok_x86_lookup_pc)

/*
 * [flags | cflags << 32][cs_base] -- aok_gadget_lookup with tb_lookup()'s
 * first step done here, as the other front ends do it (the RISC-V one's
 * gadgets.S has the account). A TB may be taken only if it has this TB's
 * flags, which is sound because nothing a stream executes changes them.
 */
.gadget lookup
    ldr x10, [_pcp]
    /* (entered here with env->eip in x10 and _ip at the two operands) */
    .globl SYM(aok_x86_lookup_pc)
SYM(aok_x86_lookup_pc):
    ldr x11, [_bps]
    eor x12, x10, x10, lsr #5
    cbnz x11, 3f
    lsr x13, x12, #5
    and x12, x12, #0x7f
    and x13, x13, #0x3f80
    orr x12, x12, x13               /* the hash */
    ldp x11, x9, [_ip]              /* what the TB must have */
    add x13, _jc, x12, lsl #4
    ldp x14, x15, [x13, #16]        /* tb, pc */
    cmp x15, x10
    b.ne 2f
    cbz x14, 2f
    ldp x15, x16, [x14, #8]         /* cs_base, flags | cflags << 32 */
    cmp x16, x11
    ccmp x15, x9, #0, eq
    b.eq 5f
    /*
     * The other way. It is tried also when the first has the pc and other
     * flags: kernel code runs with an ss from a syscall and with the null
     * one an interrupt leaves, which is a bit of the flags (HF_SS32), so
     * the two TBs of one pc sit side by side.
     */
2:  eor x12, x12, #1
    add x13, _jc, x12, lsl #4
    ldp x14, x15, [x13, #16]
    cmp x15, x10
    b.ne 3f
    cbz x14, 3f
    ldp x15, x16, [x14, #8]
    cmp x16, x11
    ccmp x15, x9, #0, eq
    b.ne 3f
5:  ldrb w17, [x14, #28]            /* aok */
    cbz w17, 3f
    /* A jump between streams, as aok_goto_tail makes it. */
    ldr w11, [_exitreq]
    ldr _ip, [x14, #32]             /* tc.ptr */
    mov _pc, x10
    tbnz w11, #31, 4f
    gret AOK_ENTER_WORDS
3:  b SYM(aok_lookup_slow)
4:  b SYM(aok_exit_requested)

/* ---- Instructions that are a call to C -------------------------------------
 *
 * [fn][the insn's distance from the TB's first][a][b]: fn(env, pc, a, b),
 * which stores the pc before anything that may raise. The host's flags are
 * not the guest's afterwards.
 */
.gadget call_c
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _pc, x1
    blr x9
    gret 4
/* The same with the address an ea gadget left: fn(env, pc, a, b, address). */
.gadget call_c_ea
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    mov x4, _ea
    add x1, _pc, x1
    blr x9
    gret 4
/*
 * The same, for an insn that may want the main loop before it is done (a
 * long rep): fn returns whether, having left env->eip at the insn.
 */
.gadget call_c_stop
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _pc, x1
    blr x9
    cbnz x0, 1f
    gret 4
1:  mov x0, #0
    b SYM(aok_exit)
/* [pc delta]: to the main loop, for the insn there next. */
.gadget exit
    ldr x9, [_ip]
    add _pc, _pc, x9
    str _pc, [_pcp]
    mov x0, #0
    b SYM(aok_exit)
/* The same, for an insn that ends its TB in the main loop: fn set env->eip. */
.gadget call_c_exit
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _pc, x1
    blr x9
    mov x0, #0
    b SYM(aok_exit)
