/*
 * AOK gadgets for AArch64 guests: what this front end does its own way.
 * Anything that leaves the stream; the instructions iSH-AOK's shared sources
 * have no specialised gadget for; the loads and stores those sources have no
 * body for. The rest is gadgets-shared.S.
 *
 * Operands are byte offsets into CPUARMState, so one gadget serves every
 * register: XZR as a source is the offset of a word that is always zero, as
 * a destination that of a word nobody reads (cpu.h, aok_zero and aok_sink).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define A64_GADGET_HOST qemu
#define AOK_ASM_OWN_GADGET
#include "accel/tcg/aok-asm.h"
#include "aok-arm-asm.h"


/* As gadgets-shared.S: the flags, and the softmmu fast path. */
_addr   .req x7


    .text

/* ---- Constants and moves -------------------------------------------------- */

/* [rd offset][delta]: rd = entry pc + delta (adr, and the link of a bl) */
.gadget pcrel
    ldp x9, x10, [_ip]
    add x10, _pc, x10
    str x10, [_cpu, x9]
    gret 2

/* [rd offset][delta]: rd = the entry pc's page + delta (adrp) */
.gadget pcrel_page
    ldp x9, x10, [_ip]
    and x11, _pc, #0xfffffffffffff000
    add x10, x11, x10
    str x10, [_cpu, x9]
    gret 2

/* [rd offset][mask to keep][bits to set] (movk) */
.gadget movk
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr x12, [_cpu, x9]
    and x12, x12, x10
    orr x12, x12, x11
    str x12, [_cpu, x9]
    gret 3

/* ---- Data processing the shared sources have no specialised gadget for ---- */

/* [rd offset][rn offset] */
.macro dp1 name, r, insn:vararg
.gadget \name
    ldp x9, x10, [_ip]
    ldr x12, [_cpu, x10]
    \insn
    str x12, [_cpu, x9]
    gret 2
.endm
dp1 rbit64, x, rbit x12, x12
dp1 rbit32, w, rbit w12, w12
dp1 rev64, x, rev x12, x12
dp1 rev32, w, rev w12, w12
dp1 rev16_64, x, rev16 x12, x12
dp1 rev16_32, w, rev16 w12, w12
dp1 rev32_64, x, rev32 x12, x12
dp1 clz64, x, clz x12, x12
dp1 clz32, w, clz w12, w12
dp1 cls64, x, cls x12, x12
dp1 cls32, w, cls w12, w12

/* [rd offset][rn offset][rm offset] */
.macro dp2 name, insn:vararg
.gadget \name
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr x12, [_cpu, x10]
    ldr x13, [_cpu, x11]
    \insn
    str x12, [_cpu, x9]
    gret 3
.endm
.irp op, udiv, sdiv, lslv, lsrv, asrv, rorv
dp2 \op\()64, \op x12, x12, x13
dp2 \op\()32, \op w12, w12, w13
.endr

/* [rd offset][rn offset][rm offset][ra offset]: the widening multiply-adds */
.irp op, smaddl, smsubl, umaddl, umsubl
.gadget \op
    ldp x9, x10, [_ip]
    ldp x11, x14, [_ip, #16]
    ldr x12, [_cpu, x10]
    ldr x13, [_cpu, x11]
    ldr x14, [_cpu, x14]
    \op x12, w12, w13, x14
    str x12, [_cpu, x9]
    gret 4
.endr

/*
 * BFM (bfi, bfxil): [rd offset][rn offset][rotate][mask]: the source rotated
 * right, and of that the bits of the mask put into the destination.
 */
.macro bfm name, r
.gadget \name
    ldp x9, x10, [_ip]
    ldp x11, x14, [_ip, #16]
    ldr x12, [_cpu, x10]
    ldr x13, [_cpu, x9]
    rorv \r\()12, \r\()12, \r\()11
    and \r\()12, \r\()12, \r\()14
    bic \r\()13, \r\()13, \r\()14     /* (a W result: the upper half cleared) */
    orr \r\()12, \r\()12, \r\()13
    str x12, [_cpu, x9]
    gret 4
.endm
bfm bfm64, x
bfm bfm32, w

/* EXTR with two registers: [rd offset][rn offset][rm offset][lsb], lsb not 0 */
.macro extr name, r, bits
.gadget \name
    ldp x9, x10, [_ip]
    ldp x11, x14, [_ip, #16]
    ldr x12, [_cpu, x10]
    ldr x13, [_cpu, x11]
    mov w15, #\bits
    sub w15, w15, w14
    lsrv \r\()13, \r\()13, \r\()14
    lslv \r\()12, \r\()12, \r\()15
    orr \r\()12, \r\()12, \r\()13
    str x12, [_cpu, x9]
    gret 4
.endm
extr extr64, x, 64
extr extr32, w, 32

/*
 * Flag-setting arithmetic and logic on a shifted register (the shared
 * sources have the unshifted forms and the ones that set no flags):
 * [rd offset][rn offset][rm offset][amount]
 */
.macro alus name, op, r, shv
.gadget \name
    ldp x9, x10, [_ip]
    ldp x11, x14, [_ip, #16]
    ldr x13, [_cpu, x11]
    ldr x12, [_cpu, x10]
    \shv \r\()13, \r\()13, \r\()14
    \op \r\()12, \r\()12, \r\()13
    store_flags
    str x12, [_cpu, x9]
    gret 4
.endm
/* (names end in what an inner loop varies: a nested \() is the outer loop's) */
.macro alus_all op
.irp shv, lslv, lsrv, asrv, rorv
alus \op\()64_\shv, \op, x, \shv
alus \op\()32_\shv, \op, w, \shv
.endr
.endm
alus_all adds
alus_all subs
alus_all ands
alus_all bics

/*
 * ADDS and SUBS with the second register extended and shifted left 0-4, the
 * forms of f_alu_ext that set flags: [rd offset][rn offset][rm offset][shift]
 */
.macro aluxs name, op, r, ext:vararg
.gadget \name
    ldp x9, x10, [_ip]
    ldp x11, x14, [_ip, #16]
    ldr x13, [_cpu, x11]
    ldr x12, [_cpu, x10]
    \ext
    lslv x13, x13, x14
    \op \r\()12, \r\()12, \r\()13
    store_flags
    str x12, [_cpu, x9]
    gret 4
.endm
.irp op, adds, subs
aluxs \op\()_uxtb64, \op, x, and x13, x13, #0xff
aluxs \op\()_uxth64, \op, x, and x13, x13, #0xffff
aluxs \op\()_uxtw64, \op, x, mov w13, w13
aluxs \op\()_uxtx64, \op, x, nop
aluxs \op\()_sxtb64, \op, x, sxtb x13, w13
aluxs \op\()_sxth64, \op, x, sxth x13, w13
aluxs \op\()_sxtw64, \op, x, sxtw x13, w13
aluxs \op\()_uxtb32, \op, w, and x13, x13, #0xff
aluxs \op\()_uxth32, \op, w, and x13, x13, #0xffff
aluxs \op\()_uxtx32, \op, w, nop
aluxs \op\()_sxtb32, \op, w, sxtb x13, w13
aluxs \op\()_sxth32, \op, w, sxth x13, w13
.endr

/* ---- Conditional data processing --------------------------------------------
 *
 * One gadget a condition, the host's own conditional instruction doing the
 * work on the guest's flags. Each exists twice: NAME_cc loads the flags first,
 * NAME_nf_cc is for when the gadget before it left the host's flags the guest's
 * (a flag-setting gadget; store_flags changes none).
 */
#define CONDS eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le

/* [rd offset][rn offset][rm offset]: csel, csinc, csinv, csneg */
.macro csel_one name, op, r, cc, reload
.gadget \name
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr x12, [_cpu, x10]
    ldr x13, [_cpu, x11]
    .if \reload
    load_flags
    .endif
    \op \r\()12, \r\()12, \r\()13, \cc
    str x12, [_cpu, x9]
    gret 3
.endm
.macro csel_all op
.irp cc, CONDS
csel_one \op\()64_\cc, \op, x, \cc, 1
csel_one \op\()32_\cc, \op, w, \cc, 1
csel_one \op\()64_nf_\cc, \op, x, \cc, 0
csel_one \op\()32_nf_\cc, \op, w, \cc, 0
.endr
.endm
csel_all csel
csel_all csinc
csel_all csinv
csel_all csneg

/*
 * CCMP and CCMN: [rn offset][rm offset or immediate][nzcv << 28]. The
 * flags when the condition fails are an operand, so the compare is made or
 * they are set, by a branch.
 */
.macro ccmp_one name, op, r, cc, imm, reload
.gadget \name
    ldp x10, x11, [_ip]
    ldr x14, [_ip, #16]
    ldr x12, [_cpu, x10]
    .if \imm == 0
    ldr x11, [_cpu, x11]
    .endif
    .if \reload
    load_flags
    .endif
    b.\cc 1f
    msr nzcv, x14
    b 2f
1:  \op \r\()zr, \r\()12, \r\()11
2:  store_flags
    gret 3
.endm
.irp cc, CONDS
ccmp_one ccmp64_\cc, subs, x, \cc, 0, 1
ccmp_one ccmp32_\cc, subs, w, \cc, 0, 1
ccmp_one ccmn64_\cc, adds, x, \cc, 0, 1
ccmp_one ccmn32_\cc, adds, w, \cc, 0, 1
ccmp_one ccmpi64_\cc, subs, x, \cc, 1, 1
ccmp_one ccmpi32_\cc, subs, w, \cc, 1, 1
ccmp_one ccmni64_\cc, adds, x, \cc, 1, 1
ccmp_one ccmni32_\cc, adds, w, \cc, 1, 1
ccmp_one ccmp64_nf_\cc, subs, x, \cc, 0, 0
ccmp_one ccmp32_nf_\cc, subs, w, \cc, 0, 0
ccmp_one ccmn64_nf_\cc, adds, x, \cc, 0, 0
ccmp_one ccmn32_nf_\cc, adds, w, \cc, 0, 0
ccmp_one ccmpi64_nf_\cc, subs, x, \cc, 1, 0
ccmp_one ccmpi32_nf_\cc, subs, w, \cc, 1, 0
ccmp_one ccmni64_nf_\cc, adds, x, \cc, 1, 0
ccmp_one ccmni32_nf_\cc, adds, w, \cc, 1, 0
.endr

/* ---- Leaving a TB ------------------------------------------------------------
 *
 * A way out is aok_gadget_goto's two operands, [pc delta][slot]. Each is its
 * own copy of aok_goto_tail rather than a jump to it, so that each ends in an
 * indirect branch of its own (the RISC-V front end's gadgets-shared.S has
 * why).
 */
.macro a64_leave off
    ldp x9, x10, [_ip, #\off]
    ldr w11, [_exitreq]
    add _pc, _pc, x9
    ldr _ip, [x10]
    str _pc, [_pcp]
    tbnz w11, #31, 7f
    gret AOK_ENTER_WORDS
7:  b SYM(aok_exit_requested)
.endm

/* [pc delta][slot] (b, and whatever ends a TB without a branch) */
.gadget b
    a64_leave 0

/* [link delta][pc delta][slot]: x30 = entry pc + link delta, then b */
.gadget bl
    ldr x12, [_ip]
    add x12, _pc, x12
    str x12, [_cpu, #AOK_A64_ENV_X30]
    a64_leave 8

/* [taken: pc delta][slot][not taken: pc delta][slot] */
.macro bcond_one name, cc, reload
.gadget \name
    .if \reload
    load_flags
    .endif
    b.\cc 1f
    a64_leave 16
1:  a64_leave 0
.endm
.irp cc, CONDS
bcond_one b_\cc, \cc, 1
bcond_one b_nf_\cc, \cc, 0
.endr

/* [rt offset][taken way][other way] */
.macro cbz_one name, insn, r
.gadget \name
    ldr x9, [_ip]
    ldr x12, [_cpu, x9]
    \insn \r\()12, 1f
    a64_leave 24
1:  a64_leave 8
.endm
cbz_one cbz64, cbz, x
cbz_one cbz32, cbz, w
cbz_one cbnz64, cbnz, x
cbz_one cbnz32, cbnz, w

/* [rt offset][bit mask][taken way][other way] */
.macro tbz_one name, cc
.gadget \name
    ldp x9, x10, [_ip]
    ldr x12, [_cpu, x9]
    tst x12, x10
    b.\cc 1f
    a64_leave 32
1:  a64_leave 16
.endm
tbz_one tbz, eq
tbz_one tbnz, ne

/* ---- Indirect branches -----------------------------------------------------
 *
 * br, blr, ret: [rn offset][tbi][link delta][flags | cflags << 32][cs_base].
 * The target is read before the link is written, since blr's register may be
 * x30, and has its top byte seen to as TCG's gen_top_byte_ignore does it:
 * tbi 0, as it is; 1, 2, 3, sign-extended from bit 55 where the address is in
 * the half that has TBI (the low one, the high one, both); 4, for a regime
 * with one range, its top byte cleared. Then the lookup below.
 */
.macro a64_tbi
    cbz x11, 4f
    sbfx x12, x10, #0, #56
    cmp x11, #2
    b.hi 3f
    b.eq 2f
    and x10, x12, x10           /* 1: only where bit 55 is clear */
    b 4f
2:  orr x10, x12, x10           /* 2: only where bit 55 is set */
    b 4f
3:  cmp x11, #4
    csel x10, x12, x10, ne      /* 3: both halves */
    b.ne 4f
    and x10, x10, #0x00ffffffffffffff
4:
.endm

.gadget br
    ldp x9, x11, [_ip]
    ldr x10, [_cpu, x9]
    a64_tbi
    str x10, [_pcp]
    add _ip, _ip, #24
    b SYM(aok_a64_lookup_pc)

.gadget blr
    ldp x9, x11, [_ip]
    ldr x13, [_ip, #16]
    ldr x10, [_cpu, x9]
    add x13, _pc, x13
    a64_tbi
    str x13, [_cpu, #AOK_A64_ENV_X30]
    str x10, [_pcp]
    add _ip, _ip, #24
    b SYM(aok_a64_lookup_pc)

/* The same two for a TB that may not look its successor up: the stream exits. */
.gadget br_exit
    ldp x9, x11, [_ip]
    ldr x10, [_cpu, x9]
    a64_tbi
    str x10, [_pcp]
    mov x0, #0
    b SYM(aok_exit)

.gadget blr_exit
    ldp x9, x11, [_ip]
    ldr x13, [_ip, #16]
    ldr x10, [_cpu, x9]
    add x13, _pc, x13
    a64_tbi
    str x13, [_cpu, #AOK_A64_ENV_X30]
    str x10, [_pcp]
    mov x0, #0
    b SYM(aok_exit)

/*
 * [flags | cflags << 32][cs_base] -- aok_gadget_lookup with tb_lookup()'s
 * first step done here, as the RISC-V front end's rv_lookup does it (its
 * gadgets.S has the account; cpu-exec.c the build-time checks of the layout).
 * A TB may be taken only if it has this TB's flags, and for an A64 guest that
 * is sound for the same reason: nothing a stream executes changes them. (An
 * indirect branch on a CPU with BTI would, and is not translated there.)
 */
.gadget lookup
    ldr x10, [_pcp]
    /* (entered here with env->pc in x10 and _ip at the two operands) */
    .globl SYM(aok_a64_lookup_pc)
SYM(aok_a64_lookup_pc):
    aok_lookup_jc

/* dmb, dsb: a full barrier, as TCG's tcg_gen_mb(TCG_MO_ALL | TCG_BAR_SC) */
.gadget barrier
    dmb ish
    gret

/* ---- Instructions that are a call to C ---------------------------------------
 *
 * [fn][the insn's distance from the TB's first][insn][arg]:
 * fn(env, pc, insn, arg), which stores the pc before anything that may raise
 * (translate-a64.c, "One call to C"). The host's flags are not the guest's
 * afterwards.
 */
.gadget call
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _pc, x1
    blr x9
    gret 4

/* The same, for an insn that ends its TB in the main loop: fn has set env->pc. */
.gadget call_exit
    aok_fp_end
    ldp x9, x1, [_ip]
    ldp x2, x3, [_ip, #16]
    mov x0, _cpu
    add x1, _pc, x1
    blr x9
    mov x0, #0
    b SYM(aok_exit)

/*
 * mrs xt, sp_el0, a kernel's "current": [rt offset][sp_el[0]'s offset], and
 * then a call's operands. The register's one access check is that PSTATE.SP
 * is set. With it clear the access is undefined: the call finds that out
 * again, and raises it.
 */
.gadget mrs_sp_el0
    ldr w9, [_cpu, #AOK_A64_ENV_PSTATE]
    ldp x10, x11, [_ip]
    tbz w9, #0, 1f
    ldr x12, [_cpu, x11]
    str x12, [_cpu, x10]
    gret 6
1:  add _ip, _ip, #16
    b SYM(aok_gadget_a64_call)
