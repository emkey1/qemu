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
 * 32-bit code has the same gadgets, since a register's upper half is not
 * read by the 32-bit forms and their results are stored zero-extended, as
 * TCG's are. What it has of its own is addresses that wrap at 32 bits (the
 * "b3" form of a memory operand, ea32), a stack of 4-byte slots, and an eip
 * that wraps (the gadgets named 32).
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

/*
 * fn(env, address, pc, the word's lower half, \arg). \woff: where the word is
 * from _ip (a gadget that has not moved _ip yet has it at 0).
 */
.macro x86_call_slow fn, arg, woff=-16
    stp x1, x2, [sp, #-64]!
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x8, x17, [sp, #48]
    mov x4, \arg
    aok_fp_end                  /* (x14-x17 are its scratch) */
    ldr x3, [_ip, #\woff]
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
.macro x86_slow_ld size, id, woff=-16
miss_\id:
    x86_unaligned \size, \id
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_ld, x9, \woff
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\id
.endm
.macro x86_slow_st size, id, woff=-16
miss_\id:
    x86_unaligned \size, \id
    x86_call_slow aok_x86_helper_st, x17, \woff
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
 *   b3: the same in 32-bit code, where the sum wraps
 *   ea: [...][word], the address what the ea gadget before it left
 */
.macro mem_begin form, n
    .ifc \form, bd
    ldp x9, x10, [_ip, #(8 * \n)]
    add _ip, _ip, #(8 * (\n + 4))
    ldr x9, [_cpu, x9]
    add _addr, x9, x10
    .endif
    .ifc \form, b3
    ldp x9, x10, [_ip, #(8 * \n)]
    add _ip, _ip, #(8 * (\n + 4))
    ldr w9, [_cpu, x9]
    add w7, w9, w10
    .endif
    .ifc \form, ea
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

/* In 32-bit code: the same sums, which wrap. */
.gadget ea32
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr w9, [_cpu, x9]
    ldr w10, [_cpu, x10]
    lsl w10, w10, w11
    add w9, w9, w12
    add w6, w9, w10
    gret 4
.gadget ea32_seg
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x13, [_ip, #32]
    ldr w9, [_cpu, x9]
    ldr w10, [_cpu, x10]
    ldr x13, [_cpu, x13]
    lsl w10, w10, w11
    add w9, w9, w12
    add w9, w9, w13
    add w6, w9, w10
    gret 5
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
loads_stores1 b3, \sfx
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
alu_mem_forms1 \op, \store, \name, b3, 8, \sfx
alu_mem_forms1 \op, \store, \name, b3, 16, \sfx
alu_mem_forms1 \op, \store, \name, b3, 32, \sfx
alu_mem_forms1 \op, \store, \name, b3, 64, \sfx
alu_mem_forms1 \op, \store, \name, ea, 8, \sfx
alu_mem_forms1 \op, \store, \name, ea, 16, \sfx
alu_mem_forms1 \op, \store, \name, ea, 32, \sfx
alu_mem_forms1 \op, \store, \name, ea, 64, \sfx
.endm
/*
 * The XMM registers. A load of all of one, and a store: [register] and the
 * address. The ones called "a" are for an operand that must be aligned,
 * which the fast path sees and anything else leaves to C, to raise what is
 * due. Loads of the low 32 and 64 bits that clear the rest.
 */
.macro g_vload name, form, aligned
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    x86_probe 128, \name, TLBE_READ
    ldr q16, [_addr]
    ld_barrier
    str q16, [_cpu, x8]
    gret_ahead
miss_\name:
    .if \aligned == 0
    x86_unaligned 128, \name
    .endif
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_ld, x9
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\name
.endm
.macro g_vstore name, form, aligned
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    ldr q16, [_cpu, x8]
    x86_probe 128, \name, TLBE_WRITE
    st_barrier
    str q16, [_addr]
    gret_ahead
miss_\name:
    .if \aligned == 0
    x86_unaligned 128, \name
    .endif
    stur q16, [x29, #AOK_FRAME_SCRATCH]
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_vst, x9
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\name
.endm
.macro g_vloadz name, bits, form, ldinsn:vararg
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    x86_probe \bits, \name, TLBE_READ
    \ldinsn, [_addr]
    ld_barrier
    add x9, _cpu, x8
    stp x17, xzr, [x9]
    gret_ahead
    x86_slow_ld \bits, \name
.endm
.macro vloads_stores1 form, sfx
g_vload vload128_\form\sfx, \form, 0
g_vload vload128a_\form\sfx, \form, 1
g_vstore vstore128_\form\sfx, \form, 0
g_vstore vstore128a_\form\sfx, \form, 1
g_vloadz vload32z_\form\sfx, 32, \form, ldr w17
g_vloadz vload64z_\form\sfx, 64, \form, ldr x17
.endm

.macro all_mem sfx
loads_stores \sfx
vloads_stores1 bd, \sfx
vloads_stores1 b3, \sfx
vloads_stores1 ea, \sfx
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
 * adcx and adox (ADX), 32 and 64 bits: [destination][source]. The flags are
 * CC_OP_EFLAGS (flush_cc first, once for a whole chain); the carry in and
 * out is cc_src's CF (adcx) or OF (adox), and no other flag changes.
 */
.macro g_adx name, r, bit
.gadget \name
    ldp x8, x9, [_ip]
    ldr x13, [_cpu, #AOK_X86_ENV_CC_SRC]
    ldr \r\()10, [_cpu, x8]
    ldr \r\()11, [_cpu, x9]
    ubfx x14, x13, #\bit, #1
    cmp x14, #1                 /* C = the carry in */
    adcs \r\()12, \r\()10, \r\()11
    cset x14, cs
    bfi x13, x14, #\bit, #1
    str x12, [_cpu, x8]
    str x13, [_cpu, #AOK_X86_ENV_CC_SRC]
    gret 2
.endm
g_adx adcx32, w, 0
g_adx adcx64, x, 0
g_adx adox32, w, 11
g_adx adox64, x, 11
/*
 * The same at 16 bits, the rest of the register staying: the lazy state
 * only (the host's flags of a 32-bit sum are not a 16-bit one's).
 */
.macro g_adc16 name, sbb, ccop, imm
.gadget \name
    ldp x8, x9, [_ip]
    ldr x13, [_ip, #16]
    ldrh w10, [_cpu, x8]
    .if \imm
    and w11, w9, #0xffff
    .else
    ldrh w11, [_cpu, x9]
    .endif
    ldrb w13, [_cpu, x13]
    .if \sbb
    sub w12, w10, w11
    sub w12, w12, w13
    .else
    add w12, w10, w11
    add w12, w12, w13
    .endif
    and w12, w12, #0xffff
    strh w12, [_cpu, x8]
    str x13, [_cpu, #AOK_X86_ENV_CC_SRC2]
    setcc \ccop, 16
    gret 3
.endm
g_adc16 adc16_rr, 0, AOK_CC_OP_ADC, 0
g_adc16 adc16_ri, 0, AOK_CC_OP_ADC, 1
g_adc16 sbb16_rr, 1, AOK_CC_OP_SBB, 0
g_adc16 sbb16_ri, 1, AOK_CC_OP_SBB, 1

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

/* popcnt: [destination][source]; ZF that the source is zero, the rest clear. */
.macro g_popcnt name, r
.gadget \name
    ldp x8, x9, [_ip]
    ldr \r\()10, [_cpu, x9]
    fmov d16, x10
    cnt v16.8b, v16.8b
    addv b16, v16.8b
    fmov w12, s16
    str x12, [_cpu, x8]
    cmp \r\()10, #0
    cset w13, eq
    lsl w13, w13, #6
    str x13, [_cpu, #AOK_X86_ENV_CC_SRC]
    str wzr, [_cpu, #AOK_X86_ENV_CC_OP]
    gret 2
.endm
g_popcnt popcnt32, w
g_popcnt popcnt64, x

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
.gadget cld
    mov w9, #1
    str w9, [_cpu, #AOK_X86_ENV_DF]
    gret
.gadget std
    mov w9, #-1
    str w9, [_cpu, #AOK_X86_ENV_DF]
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

/* ---- SSE: moves and the integer operations ----------------------------------
 *
 * Between registers: [destination][source], offsets of sixteen bytes.
 */
.gadget vmov128
    ldp x8, x9, [_ip]
    ldr q16, [_cpu, x9]
    str q16, [_cpu, x8]
    gret 2
/*
 * A bit string's operand (bt, bts, btr, btc of memory by a register): the
 * address an ea gadget left moved by the register's bit number, signed, in
 * units of the operand: [the register]. bt_ea32_32: 32-bit code, whose
 * address wraps at 32 bits.
 */
.gadget bt_ea64
    ldr x8, [_ip]
    ldr x9, [_cpu, x8]
    asr x9, x9, #6
    add _ea, _ea, x9, lsl #3
    gret 1
.gadget bt_ea32
    ldr x8, [_ip]
    ldrsw x9, [_cpu, x8]
    asr x9, x9, #5
    add _ea, _ea, x9, lsl #2
    gret 1
.gadget bt_ea32_32
    ldr x8, [_ip]
    ldrsw x9, [_cpu, x8]
    asr x9, x9, #5
    add w6, w6, w9, lsl #2
    gret 1

/* The low 32 bits, the rest staying (movss). */
.gadget vmov32
    ldp x8, x9, [_ip]
    ldr w12, [_cpu, x9]
    str w12, [_cpu, x8]
    gret 2
/* The low 64 and the low 32, the rest cleared (movq, movd). */
.gadget vmovq
    ldp x8, x9, [_ip]
    ldr x12, [_cpu, x9]
    add x8, _cpu, x8
    stp x12, xzr, [x8]
    gret 2
.gadget vmovd
    ldp x8, x9, [_ip]
    ldr w12, [_cpu, x9]
    add x8, _cpu, x8
    stp x12, xzr, [x8]
    gret 2

/*
 * An operation of two operands: [destination][source][thunk]. The thunk
 * is the host's insn for it, on v0 and v1 into v0, and a ret.
 */
.gadget vop
    ldp x8, x9, [_ip]
    ldr x10, [_ip, #16]
    ldr q0, [_cpu, x8]
    ldr q1, [_cpu, x9]
    blr x10
    str q0, [_cpu, x8]
    gret 3
/* A shift of every lane by a count: [register][thunk][count, signed] */
.gadget vshift
    ldp x8, x10, [_ip]
    ldr x9, [_ip, #16]
    ldr q0, [_cpu, x8]
    blr x10
    str q0, [_cpu, x8]
    gret 3
/*
 * A choice of bytes: [destination][source][sixteen indices, two words]. An
 * index past the source gives zero, which makes the shifts by bytes too.
 */
.gadget vtbl
    ldp x8, x9, [_ip]
    ldr q2, [_ip, #16]
    ldr q1, [_cpu, x9]
    tbl v0.16b, {v1.16b}, v2.16b
    str q0, [_cpu, x8]
    gret 4
/* The same of two sources: [destination][its other half][indices] */
.gadget vtbl2
    ldp x8, x9, [_ip]
    ldr q2, [_ip, #16]
    ldr q0, [_cpu, x8]
    ldr q1, [_cpu, x9]
    tbl v3.16b, {v0.16b, v1.16b}, v2.16b
    str q3, [_cpu, x8]
    gret 4
/* pmovmskb: [destination, a general register][source] */
.gadget pmovmskb
    ldp x8, x9, [_ip]
    ldr q0, [_cpu, x9]
    ushr v0.16b, v0.16b, #7
    usra v0.8h, v0.8h, #7
    usra v0.4s, v0.4s, #14
    usra v0.2d, v0.2d, #28
    umov w10, v0.b[0]
    umov w11, v0.b[8]
    orr w10, w10, w11, lsl #8
    str x10, [_cpu, x8]
    gret 2

.macro thunk name, insn:vararg
    .balign 8
    .globl SYM(aok_x86_thunk_\name)
SYM(aok_x86_thunk_\name):
    \insn
    ret
.endm
thunk xor, eor v0.16b, v0.16b, v1.16b
thunk or, orr v0.16b, v0.16b, v1.16b
thunk and, and v0.16b, v0.16b, v1.16b
thunk andn, bic v0.16b, v1.16b, v0.16b
.irp op, cmeq, cmgt, add, sub
thunk \op\()b, \op v0.16b, v0.16b, v1.16b
thunk \op\()w, \op v0.8h, v0.8h, v1.8h
thunk \op\()d, \op v0.4s, v0.4s, v1.4s
.endr
thunk addq, add v0.2d, v0.2d, v1.2d
thunk subq, sub v0.2d, v0.2d, v1.2d
.irp op, uqadd, sqadd, uqsub, sqsub, urhadd
thunk \op\()b, \op v0.16b, v0.16b, v1.16b
thunk \op\()w, \op v0.8h, v0.8h, v1.8h
.endr
thunk uminb, umin v0.16b, v0.16b, v1.16b
thunk umaxb, umax v0.16b, v0.16b, v1.16b
thunk sminw, smin v0.8h, v0.8h, v1.8h
thunk smaxw, smax v0.8h, v0.8h, v1.8h
thunk mulw, mul v0.8h, v0.8h, v1.8h
.irp op, zip1, zip2
thunk \op\()b, \op v0.16b, v0.16b, v1.16b
thunk \op\()w, \op v0.8h, v0.8h, v1.8h
thunk \op\()d, \op v0.4s, v0.4s, v1.4s
thunk \op\()q, \op v0.2d, v0.2d, v1.2d
.endr
/* The shifts: the count is in w9, negative to the right. */
.macro thunk_shift name, op, lanes, r
    .balign 16
    .globl SYM(aok_x86_thunk_\name)
SYM(aok_x86_thunk_\name):
    dup v1.\lanes, \r\()9
    \op v0.\lanes, v0.\lanes, v1.\lanes
    ret
.endm
thunk_shift ushlw, ushl, 8h, w
thunk_shift ushld, ushl, 4s, w
thunk_shift ushlq, ushl, 2d, x
thunk_shift sshlw, sshl, 8h, w
thunk_shift sshld, sshl, 4s, w
    .balign 16

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

/* The resume flag, cleared: the head of a TB a fault was returned to. */
.gadget clr_rf
    ldr w9, [_cpu, #AOK_X86_ENV_EFLAGS]
    and w9, w9, #0xfffeffff
    str w9, [_cpu, #AOK_X86_ENV_EFLAGS]
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
/* (16 bits: the rest of the register stays, whichever way) */
.gadget cmov16_\cc
    ldp x8, x9, [_ip]
    ldrh w10, [_cpu, x8]
    ldrh w11, [_cpu, x9]
    csel w10, w11, w10, \cc
    strh w10, [_cpu, x8]
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
.macro x86_leave off, r=x
    ldp x9, x10, [_ip, #\off]
    ldr w11, [_exitreq]
    .ifc \r, w
    add w19, w19, w9                /* eip, which wraps */
    .else
    add _pc, _pc, x9
    .endif
    ldr _ip, [x10]
    str _pc, [_pcp]
    tbnz w11, #31, 7f
    gret AOK_ENTER_WORDS
7:  b SYM(aok_exit_requested)
.endm

/* [pc delta][slot] (jmp, and whatever ends a TB without a branch) */
.gadget jmp
    x86_leave 0
.gadget jmp32
    x86_leave 0, w

/* jcc on the host's flags: [taken: pc delta][slot][not: pc delta][slot] */
.macro g_jcc cc
.gadget jcc_\cc
    b.\cc 1f
    x86_leave 16
1:  x86_leave 0
.gadget jcc32_\cc
    b.\cc 1f
    x86_leave 16, w
1:  x86_leave 0, w
.endm
.irp cc, CONDS
g_jcc \cc
.endr

/*
 * loop and jcxz: [taken: pc delta][slot][not: pc delta][slot]. loop counts
 * rcx down, with no flags; in 32-bit code both mean ecx.
 */
.macro g_loop name, r, dec
.gadget \name
    ldr \r\()9, [_cpu, #(AOK_X86_ENV_REGS + 8)]
    .if \dec
    sub \r\()9, \r\()9, #1
    str x9, [_cpu, #(AOK_X86_ENV_REGS + 8)]
    cbnz \r\()9, 1f
    .else
    cbz \r\()9, 1f
    .endif
    x86_leave 16, \r
1:  x86_leave 0, \r
.endm
g_loop loop, x, 1
g_loop loop32, w, 1
g_loop jcxz, x, 0
g_loop jcxz32, w, 0

/* ---- The stack -------------------------------------------------------------
 *
 * Each of these twice: for 64-bit code, and (named 32) for 32-bit code with
 * a 32-bit stack, where a slot is four bytes and esp wraps. \r is the
 * host's register size for that, x or w.
 *
 * push: [source's offset][word]; pushi: [value][word]. The store is made
 * before rsp moves, so a fault leaves it where it was.
 */
.macro g_push name, imm, r, bytes, bits
.gadget \name
    ldr x8, [_ip]
    add _ip, _ip, #24
    .if \imm
    mov x17, x8
    .else
    ldr \r\()17, [_cpu, x8]
    .endif
    ldr \r\()5, [_cpu, #AOK_X86_ENV_RSP]
    sub \r\()5, \r\()5, #\bytes
    mov _addr, x5
    x86_probe \bits, \name, TLBE_WRITE
    st_barrier
    str \r\()17, [_addr]
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    gret_ahead
    x86_slow_st \bits, \name
.endm
/* pop: [destination's offset][word]. rsp first: "pop rsp" keeps what it got. */
.macro g_pop name, r, bytes, bits
.gadget \name
    ldr x8, [_ip]
    add _ip, _ip, #24
    ldr \r\()5, [_cpu, #AOK_X86_ENV_RSP]
    mov _addr, x5
    x86_probe \bits, \name, TLBE_READ
    ldr \r\()17, [_addr]
    ld_barrier
    add \r\()5, \r\()5, #\bytes
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    str x17, [_cpu, x8]
    gret_ahead
    x86_slow_ld \bits, \name
.endm
/* leave: [word]. rsp = rbp, then pop rbp. */
.macro g_leave name, r, bytes, bits
.gadget \name
    add _ip, _ip, #16
    ldr \r\()5, [_cpu, #AOK_X86_ENV_RBP]
    mov _addr, x5
    x86_probe \bits, \name, TLBE_READ
    ldr \r\()17, [_addr]
    ld_barrier
    add \r\()5, \r\()5, #\bytes
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    str x17, [_cpu, #AOK_X86_ENV_RBP]
    gret_ahead
    x86_slow_ld \bits, \name
.endm

/*
 * call: [return address's distance from the TB's first insn][word], then a
 * way out: the return address is pushed, then it is a jmp.
 */
.macro g_call name, r, bytes, bits
.gadget \name
    ldr x8, [_ip]
    add _ip, _ip, #24
    add \r\()17, \r\()19, \r\()8
    ldr \r\()5, [_cpu, #AOK_X86_ENV_RSP]
    sub \r\()5, \r\()5, #\bytes
    mov _addr, x5
    x86_probe \bits, \name, TLBE_WRITE
    st_barrier
    str \r\()17, [_addr]
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    sub _ip, _ip, #8
    x86_leave 0, \r
    x86_slow_st \bits, \name
.endm
/*
 * An indirect call: [target's offset][return address's distance][word], then
 * a lookup's operands. The target is read first: it may be rsp-relative.
 */
.macro g_calli name, r, bytes, bits
.gadget \name
    ldp x8, x9, [_ip]
    add _ip, _ip, #32
    ldr \r\()4, [_cpu, x8]
    add \r\()17, \r\()19, \r\()9
    ldr \r\()5, [_cpu, #AOK_X86_ENV_RSP]
    sub \r\()5, \r\()5, #\bytes
    mov _addr, x5
    x86_probe \bits, \name, TLBE_WRITE
    st_barrier
    str \r\()17, [_addr]
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    mov x10, x4
    str x10, [_pcp]
    sub _ip, _ip, #8
    b SYM(aok_x86_lookup_pc)
    x86_slow_st \bits, \name
.endm
/* ret: [bytes to drop besides][word], then a lookup's operands */
.macro g_ret name, r, bytes, bits
.gadget \name
    ldr x8, [_ip]
    add _ip, _ip, #24
    ldr \r\()5, [_cpu, #AOK_X86_ENV_RSP]
    mov _addr, x5
    x86_probe \bits, \name, TLBE_READ
    ldr \r\()10, [_addr]
    ld_barrier
    add \r\()5, \r\()5, #\bytes
    add \r\()5, \r\()5, \r\()8
    str x5, [_cpu, #AOK_X86_ENV_RSP]
    str x10, [_pcp]
    sub _ip, _ip, #8
    b SYM(aok_x86_lookup_pc)
    x86_slow_ld \bits, \name
.endm
.set X86_MP, 0
g_push push, 0, x, 8, 64
g_push pushi, 1, x, 8, 64
g_pop pop, x, 8, 64
g_leave leave, x, 8, 64
g_call call, x, 8, 64
g_calli calli, x, 8, 64
g_ret ret, x, 8, 64
g_push push32, 0, w, 4, 32
g_push pushi32, 1, w, 4, 32
g_pop pop32, w, 4, 32
g_leave leave32, w, 4, 32
g_call call32, w, 4, 32
g_calli calli32, w, 4, 32
g_ret ret32, w, 4, 32
.set X86_MP, 1
g_push push_mp, 0, x, 8, 64
g_push pushi_mp, 1, x, 8, 64
g_pop pop_mp, x, 8, 64
g_leave leave_mp, x, 8, 64
g_call call_mp, x, 8, 64
g_calli calli_mp, x, 8, 64
g_ret ret_mp, x, 8, 64
g_push push32_mp, 0, w, 4, 32
g_push pushi32_mp, 1, w, 4, 32
g_pop pop32_mp, w, 4, 32
g_leave leave32_mp, w, 4, 32
g_call call32_mp, w, 4, 32
g_calli calli32_mp, w, 4, 32
g_ret ret32_mp, w, 4, 32
.set X86_MP, 0

/* An indirect jmp: [target's offset], then a lookup's operands */
.gadget jmpi
    ldr x8, [_ip]
    ldr x10, [_cpu, x8]
    str x10, [_pcp]
    add _ip, _ip, #8
    b SYM(aok_x86_lookup_pc)
.gadget jmpi32
    ldr x8, [_ip]
    ldr w10, [_cpu, x8]
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
    aok_lookup_jc

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
/*
 * Arithmetic in floating point is QEMU's helpers', which are exact: [fn]
 * and offsets of what they take by address, fn(env, env + a, env + b,
 * env + c). They raise nothing. The second is for comis and ucomis, which
 * leave the flags in cc_src as CC_OP_EFLAGS.
 */
.gadget call_h3
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _cpu, x1
    add x2, _cpu, x2
    add x3, _cpu, x3
    blr x9
    gret 4
.gadget call_h3cc
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _cpu, x1
    add x2, _cpu, x2
    add x3, _cpu, x3
    blr x9
    str wzr, [_cpu, #AOK_X86_ENV_CC_OP]
    gret 4
/* [fn][a][source]: fn(env, env + a, the eight bytes at the source) */
.gadget call_hval
    aok_fp_end
    ldp x9, x1, [_ip]
    ldr x2, [_ip, #16]
    mov x0, _cpu
    add x1, _cpu, x1
    ldr x2, [_cpu, x2]
    blr x9
    gret 3
/* [fn][destination][a]: a general register = fn(env, env + a), 32 or 64 bits */
.gadget call_hret32
    aok_fp_end
    ldp x9, x8, [_ip]
    ldr x1, [_ip, #16]
    mov x0, _cpu
    add x1, _cpu, x1
    blr x9
    ldr x8, [_ip, #8]
    mov w0, w0
    str x0, [_cpu, x8]
    gret 3
.gadget call_hret64
    aok_fp_end
    ldp x9, x8, [_ip]
    ldr x1, [_ip, #16]
    mov x0, _cpu
    add x1, _cpu, x1
    blr x9
    ldr x8, [_ip, #8]
    str x0, [_cpu, x8]
    gret 3

/* ---- SSE arithmetic on doubles, on the host's FP unit ---------------------
 *
 * Each of these has the operands of call_h3 and is also that: [fn][d][d][s]
 * (or as said), fn QEMU's helper for the insn, which is softfloat. The
 * gadget does the cases where the host gives softfloat's answer, flags
 * included, and calls fn for the rest. What differs between AArch64 and
 * SSE, and what is done about it:
 *
 *   MXCSR. The host rounds to nearest even, and QEMU never changes that.
 *   _fpok says MXCSR asks for the same and for nothing else (no DAZ, no
 *   FZ); it is found when a stream first uses the FP unit, and nothing can
 *   change MXCSR without a call to C, which ends that use (aok_fp_end).
 *
 *   Denormal operands raise a flag of their own in SSE (DE) and none in
 *   AArch64: an operand must be a normal number or a zero.
 *
 *   NaNs. SSE's rule for which operand's NaN a result is, and the sign of
 *   the NaN an invalid operation makes, are not AArch64's. An operand that
 *   is a NaN or an infinity is fn's, and so is a result that is either:
 *   that leaves overflow, invalid and division by zero to softfloat too.
 *
 *   Underflow. SSE detects tininess after rounding and AArch64 before. A
 *   product or quotient below the smallest normal, or equal to it, is fn's
 *   unless an operand shows it is an exact zero; sums that small are exact.
 *
 * So the only flag the host can have raised for an insn it completed is
 * inexact, and that is all x86_aok_fold_fpsr() takes from its FPSR.
 */

/* The stream's first use of the FP unit since it last called C. */
.macro x86_fp_begin again
    mov x0, _cpu
    bl SYM(aok_x86_fp_begin)
    mov _fpok, x0
    mov _fpact, #1
    b \again
.endm

/* To \soft unless the double whose bits are \reg is normal or a zero. */
.macro x86_fp_operand reg, soft
    ubfx x13, \reg, #52, #11
    sub w13, w13, #1
    cmp w13, #0x7fd
    b.ls 1f
    lsl x14, \reg, #1
    cbnz x14, \soft
1:
.endm

/* The call of fn, as call_h3 makes it. */
.macro x86_fp_soft
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _cpu, x1
    add x2, _cpu, x2
    add x3, _cpu, x3
    blr x9
.endm

/*
 * x12 = \insn of d16 and d17, whose bits are x10 and x11; to \soft where
 * the result is not the host's to give. \zero: exact for a sum, mul, div
 * or sqrt for which operand makes a zero result exact.
 */
.macro x86_fp_compute insn, zero, a, b, r, soft
    fmov d16, \a
    fmov d17, \b
    .ifc \zero, sqrt
    \insn d18, d17
    .else
    \insn d18, d16, d17
    .endif
    fmov \r, d18
    ubfx x13, \r, #52, #11
    .ifc \zero, exact
    cmp w13, #0x7ff
    b.eq \soft
    .else
    sub w13, w13, #2
    cmp w13, #0x7fc
    b.ls 2f
    lsl x14, \r, #1
    cbnz x14, \soft
    .ifc \zero, mul
    lsl x14, \a, #1
    cbz x14, 2f
    lsl x14, \b, #1
    cbnz x14, \soft
    .endif
    .ifc \zero, div
    lsl x14, \a, #1
    cbnz x14, \soft
    .endif
2:
    .endif
.endm

/* The scalar ones: the low eight bytes of d, the rest staying. */
.macro x86_fp_sd name, insn, zero
.gadget \name
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldr x8, [_ip, #8]
    ldr x9, [_ip, #24]
    ldr x10, [_cpu, x8]
    ldr x11, [_cpu, x9]
    .ifnc \zero, sqrt
    x86_fp_operand x10, 7f
    .endif
    x86_fp_operand x11, 7f
    x86_fp_compute \insn, \zero, x10, x11, x12, 7f
    str x12, [_cpu, x8]
    gret 4
7:  x86_fp_soft
    gret 4
8:  x86_fp_begin 0b
.endm
x86_fp_sd fp_addsd, fadd, exact
x86_fp_sd fp_subsd, fsub, exact
x86_fp_sd fp_mulsd, fmul, mul
x86_fp_sd fp_divsd, fdiv, div
x86_fp_sd fp_sqrtsd, fsqrt, sqrt

/* The packed ones: both lanes must be the host's, or neither is stored. */
.macro x86_fp_pd name, insn, zero
.gadget \name
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldr x8, [_ip, #8]
    ldr x9, [_ip, #24]
    add x8, _cpu, x8
    add x9, _cpu, x9
    ldp x10, x15, [x8]
    ldp x11, x16, [x9]
    x86_fp_operand x10, 7f
    x86_fp_operand x11, 7f
    x86_fp_operand x15, 7f
    x86_fp_operand x16, 7f
    x86_fp_compute \insn, \zero, x10, x11, x12, 7f
    x86_fp_compute \insn, \zero, x15, x16, x17, 7f
    stp x12, x17, [x8]
    gret 4
7:  x86_fp_soft
    gret 4
8:  x86_fp_begin 0b
.endm
x86_fp_pd fp_addpd, fadd, exact
x86_fp_pd fp_subpd, fsub, exact
x86_fp_pd fp_mulpd, fmul, mul
x86_fp_pd fp_divpd, fdiv, div

/*
 * The same in front of VEX's frames (translate-vec.c.inc's sse_vex):
 * [d][s][frame][its word], s VEX_STAGE for an operand in memory, which a
 * load has put there. What the host does not give exactly here (MXCSR not
 * plain, an operand or result that is not a normal number or a zero) is the
 * frame's, which is x86's in every case: it runs next, as if dispatched.
 * FPSR accumulates the stream's flags (gadgets-vec.S), so the host must not
 * raise a flag x86 would not: a product or quotient that may be tiny goes
 * to the frame before it is computed (x86_fpx_tiny), since AArch64's
 * underflow is tiny before rounding and x86's after. Every other bail-out
 * (an infinity, a NaN) raises what x86 raises too.
 */
.macro x86_fpx_slow
    add _ip, _ip, #16
    ldr x9, [_ip], #8
    br x9
.endm
/*
 * To \slow where \a * \b or \a / \b, normal numbers or zeros, may come out
 * below the smallest normal or at it: a product's biased exponent is ea + eb
 * - 1023 (+ 1), a quotient's ea - eb + 1023 (- 1), each bounded here with a
 * step to spare. A zero dividend or factor makes an exact zero.
 */
.macro x86_fpx_tiny zero, a, b, slow
    .ifc \zero, mul
    lsl x13, \a, #1
    cbz x13, 1f
    lsl x13, \b, #1
    cbz x13, 1f
    ubfx x13, \a, #52, #11
    ubfx x14, \b, #52, #11
    add x13, x13, x14
    cmp x13, #1025
    b.ls \slow
    .endif
    .ifc \zero, div
    lsl x13, \a, #1
    cbz x13, 1f
    ubfx x13, \a, #52, #11
    ubfx x14, \b, #52, #11
    sub x13, x13, x14
    cmn x13, #1020
    b.le \slow
    .endif
1:
.endm
.macro x86_fpx_sd name, insn, zero
.gadget \name
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldp x8, x9, [_ip]
    ldr x10, [_cpu, x8]
    ldr x11, [_cpu, x9]
    .ifnc \zero, sqrt
    x86_fp_operand x10, 7f
    .endif
    x86_fp_operand x11, 7f
    x86_fpx_tiny \zero, x10, x11, 7f
    x86_fp_compute \insn, \zero, x10, x11, x12, 7f
    str x12, [_cpu, x8]
    gret 4
7:  x86_fpx_slow
8:  x86_fp_begin 0b
.endm
x86_fpx_sd fpx_addsd, fadd, exact
x86_fpx_sd fpx_subsd, fsub, exact
x86_fpx_sd fpx_mulsd, fmul, mul
x86_fpx_sd fpx_divsd, fdiv, div
x86_fpx_sd fpx_sqrtsd, fsqrt, sqrt
.macro x86_fpx_pd name, insn, zero
.gadget \name
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldp x8, x9, [_ip]
    add x8, _cpu, x8
    add x9, _cpu, x9
    ldp x10, x15, [x8]
    ldp x11, x16, [x9]
    x86_fp_operand x10, 7f
    x86_fp_operand x11, 7f
    x86_fp_operand x15, 7f
    x86_fp_operand x16, 7f
    x86_fpx_tiny \zero, x10, x11, 7f
    x86_fpx_tiny \zero, x15, x16, 7f
    x86_fp_compute \insn, \zero, x10, x11, x12, 7f
    x86_fp_compute \insn, \zero, x15, x16, x17, 7f
    stp x12, x17, [x8]
    gret 4
7:  x86_fpx_slow
8:  x86_fp_begin 0b
.endm
x86_fpx_pd fpx_addpd, fadd, exact
x86_fpx_pd fpx_subpd, fsub, exact
x86_fpx_pd fpx_mulpd, fmul, mul
x86_fpx_pd fpx_divpd, fdiv, div

/*
 * ucomisd and comisd: [fn][a][b][-]. Without a NaN they are one compare,
 * and with one (or a denormal) fn's; either way cc_src holds ZF, PF and CF
 * as CC_OP_EFLAGS, and the host's flags are left as fcmp leaves them for an
 * ordered result, and for an unordered one so that the same conditions
 * serve (translate-x86.c, HF_FCMP): N is the carry, V the parity.
 */
.macro x86_fp_cmp_operand reg, soft
    ubfx x13, \reg, #52, #11
    sub w13, w13, #1
    cmp w13, #0x7fd
    b.ls 1f
    lsl x14, \reg, #1
    cbz x14, 1f
    lsl x14, \reg, #12
    cbnz x14, \soft
1:
.endm
.gadget fp_comisd
    ldr x8, [_ip, #8]
    ldr x9, [_ip, #16]
    ldr x10, [_cpu, x8]
    ldr x11, [_cpu, x9]
    x86_fp_cmp_operand x10, 7f
    x86_fp_cmp_operand x11, 7f
    fmov d16, x10
    fmov d17, x11
    fcmp d16, d17
    cset w12, eq
    cset w13, mi
    orr w12, w13, w12, lsl #6
    str x12, [_cpu, #AOK_X86_ENV_CC_SRC]
    str wzr, [_cpu, #AOK_X86_ENV_CC_OP]
    gret 4
7:  x86_fp_soft
    str wzr, [_cpu, #AOK_X86_ENV_CC_OP]
    ldr x12, [_cpu, #AOK_X86_ENV_CC_SRC]
    and x14, x12, #1                /* CF */
    ubfx x13, x12, #6, #1           /* ZF */
    lsl x15, x14, #31
    orr x15, x15, x13, lsl #30
    eor x14, x14, #1
    orr x15, x15, x14, lsl #29
    ubfx x13, x12, #2, #1           /* PF */
    orr x15, x15, x13, lsl #28
    msr nzcv, x15
    gret 4

/*
 * cvtsi2sd: [fn][d][source]. From 32 bits it is exact. From 64 it may
 * round, which is the host's to do under a plain MXCSR.
 */
.gadget fp_cvtsi2sd
    ldp x8, x9, [_ip, #8]
    ldr w10, [_cpu, x9]
    scvtf d16, w10
    str d16, [_cpu, x8]
    gret 3
.gadget fp_cvtsq2sd
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldp x8, x9, [_ip, #8]
    ldr x10, [_cpu, x9]
    scvtf d16, x10
    str d16, [_cpu, x8]
    gret 3
7:  aok_fp_end
    ldp x9, x1, [_ip]
    ldr x2, [_ip, #16]
    mov x0, _cpu
    add x1, _cpu, x1
    ldr x2, [_cpu, x2]
    blr x9
    gret 3
8:  x86_fp_begin 0b

/*
 * cvttsd2si: [fn][destination][a]. Truncation, whatever MXCSR says, of a
 * normal number or zero that is in range; the host raises inexact as SSE
 * does. Out of range SSE gives the "integer indefinite", which is fn's.
 */
.macro x86_fp_cvtt name, r, limit, retgadget
.gadget \name
0:  cbz _fpact, 8f
    ldp x8, x9, [_ip, #8]
    ldr x10, [_cpu, x9]
    x86_fp_operand x10, 7f
    ubfx x13, x10, #52, #11
    cmp w13, #\limit
    b.hs 7f
    fmov d16, x10
    fcvtzs \r\()12, d16
    str x12, [_cpu, x8]
    gret 3
7:  b SYM(aok_gadget_x86_\retgadget)
8:  x86_fp_begin 0b
.endm
x86_fp_cvtt fp_cvttsd2si, w, 0x41e, call_hret32
x86_fp_cvtt fp_cvttsd2sq, x, 0x43e, call_hret64

/*
 * After the insn that follows an sti: [pc delta][where interrupt_request
 * is]. If an interrupt has been waiting for the flag, the main loop takes
 * it now; one that comes later asks for an exit as any does.
 */
.gadget irq_check
    ldp x9, x10, [_ip]
    ldr w11, [_cpu, x10]
    cbnz w11, 1f
    gret 2
1:  add _pc, _pc, x9
    str _pc, [_pcp]
    mov x0, #0
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

#include "x87-host.S"
