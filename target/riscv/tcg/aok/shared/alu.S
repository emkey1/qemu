// RISC-V integer ALU gadgets: OP/OP-IMM (RV64I) + M extension.
// Reg-reg code stream: [gadget][rd_off][rs1_off][rs2_off]
// Reg-imm code stream: [gadget][rd_off][rs1_off][imm] (imm sign-extended
// to 64 bits by gen). W-suffix forms compute in 32 bits and sign-extend,
// exactly the RV64 rule.
//
// SHARED SOURCE. Another host assembles this file as it is (frag.h, "A second
// host", has the contract): everything here that is not between the
// RV_GADGET_HOST guards is its code as much as AOK's, and must keep to the
// registers and the stream layout the contract names.

#ifndef RV_GADGET_HOST
#include "gadgets.h"
#endif
#include "frag.h"

// x9=rd_off, x10=rs1 value, x11=rs2 value/imm; result in x10.
// (`fn`, `fm`: frag.h's f_src -- rs1 or rs2 forwarded by a pair's first half)
.macro alu_head fn=_
    ldr x9, [_ip]
    ldr x10, [_ip, #8]
    ldr x11, [_ip, #16]
    f_src 10, x10, \fn
.endm
.macro alu_rr_head fn=_, fm=_
    alu_head \fn
    f_src 11, x11, \fm
.endm
.macro alu_tail
    str x10, [_cpu, x9]
    gret 3
.endm
.macro alu_tail_f last, res=0
    str x10, [_cpu, x9]
    f_res \res, x10
    f_end \last, 3
.endm

// Two variants per op: _rr (reg-reg) and _ri (reg-imm) where the ISA has
// both. Shift immediates arrive as the raw 0-63 shamt.
.macro alu_op name, insn:vararg
.macro f_\name\()_rr\()_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    \insn
    alu_tail_f \last, \res
.endm
f_nostub \name\()_rr
f_gadget \name\()_rr
.macro f_\name\()_ri\()_body id, last, fn=_, fm=_, res=0
    alu_head \fn
    \insn
    alu_tail_f \last, \res
.endm
f_nostub \name\()_ri
f_gadget \name\()_ri
.endm

alu_op add,  add x10, x10, x11
alu_op and,  and x10, x10, x11
alu_op or,   orr x10, x10, x11
alu_op xor,  eor x10, x10, x11
alu_op sll,  lsl x10, x10, x11
alu_op srl,  lsr x10, x10, x11
alu_op sra,  asr x10, x10, x11
// slt/sltu spelled out: `;` inside a macro argument is a statement
// separator to gas, so the two-instruction body can't ride the vararg.
.macro f_slt_rr_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    cmp x10, x11
    cset x10, lt
    alu_tail_f \last, \res
.endm
f_nostub slt_rr
f_gadget slt_rr
.macro f_slt_ri_body id, last, fn=_, fm=_, res=0
    alu_head \fn
    cmp x10, x11
    cset x10, lt
    alu_tail_f \last, \res
.endm
f_nostub slt_ri
f_gadget slt_ri
.macro f_sltu_rr_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    cmp x10, x11
    cset x10, lo
    alu_tail_f \last, \res
.endm
f_nostub sltu_rr
f_gadget sltu_rr
.macro f_sltu_ri_body id, last, fn=_, fm=_, res=0
    alu_head \fn
    cmp x10, x11
    cset x10, lo
    alu_tail_f \last, \res
.endm
f_nostub sltu_ri
f_gadget sltu_ri

// W-suffix 32-bit forms (sign-extended results)
.macro alu_opw name, insn:vararg
.macro f_\name\()w_rr\()_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    \insn
    sxtw x10, w10
    alu_tail_f \last, \res
.endm
f_nostub \name\()w_rr
f_gadget \name\()w_rr
.macro f_\name\()w_ri\()_body id, last, fn=_, fm=_, res=0
    alu_head \fn
    \insn
    sxtw x10, w10
    alu_tail_f \last, \res
.endm
f_nostub \name\()w_ri
f_gadget \name\()w_ri
.endm

alu_opw add, add w10, w10, w11
alu_opw sll, lsl w10, w10, w11
alu_opw srl, lsr w10, w10, w11
alu_opw sra, asr w10, w10, w11

// sub/subw have no immediate form
.macro f_sub_rr_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    sub x10, x10, x11
    alu_tail_f \last, \res
.endm
f_nostub sub_rr
f_gadget sub_rr
.macro f_subw_rr_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    sub w10, w10, w11
    sxtw x10, w10
    alu_tail_f \last, \res
.endm
f_nostub subw_rr
f_gadget subw_rr

// ---- M extension ----------------------------------------------------------
.macro f_mul_rr_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    mul x10, x10, x11
    alu_tail_f \last, \res
.endm
f_nostub mul_rr
f_gadget mul_rr
.macro f_mulw_rr_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    mul w10, w10, w11
    sxtw x10, w10
    alu_tail_f \last, \res
.endm
f_nostub mulw_rr
f_gadget mulw_rr
.gadget mulh_rr
    alu_rr_head
    smulh x10, x10, x11
    alu_tail
.gadget mulhu_rr
    alu_rr_head
    umulh x10, x10, x11
    alu_tail
.gadget mulhsu_rr
    // signed(rs1) * unsigned(rs2), high half: smulh then correct — the
    // standard identity: mulhsu(a,b) = smulh(a,b) + (a<0 ? 0 : 0) ... the
    // clean form: umulh(a,b) - (a<0 ? b : 0).
    alu_rr_head
    umulh x12, x10, x11
    cmp x10, #0
    csel x13, x11, xzr, lt
    sub x10, x12, x13
    alu_tail

// RISC-V division semantics (RV spec table 7.1): x/0 = -1 (divu: all
// ones), rem by 0 = rs1, INT_MIN/-1 = INT_MIN rem 0. AArch64 sdiv already
// gives INT_MIN for the overflow case and 0 for /0, so only the /0 result
// needs fixing; rem is msub-derived which yields rs1 automatically when
// the (patched) quotient is forced to the spec value... it does NOT for
// div-by-zero (spec quotient -1 would give rem = rs1 + rs2), so rem
// branches on zero explicitly.
.gadget div_rr
    alu_rr_head
    cbz x11, 1f
    sdiv x10, x10, x11
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget divu_rr
    alu_rr_head
    cbz x11, 1f
    udiv x10, x10, x11
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget rem_rr
    alu_rr_head
    cbz x11, 1f              // rem by zero = rs1 (x10 already holds it)
    sdiv x12, x10, x11
    msub x10, x12, x11, x10
1:  alu_tail
.gadget remu_rr
    alu_rr_head
    cbz x11, 1f
    udiv x12, x10, x11
    msub x10, x12, x11, x10
1:  alu_tail
.gadget divw_rr
    alu_rr_head
    cbz w11, 1f
    sdiv w10, w10, w11
    sxtw x10, w10
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget divuw_rr
    alu_rr_head
    cbz w11, 1f
    udiv w10, w10, w11
    sxtw x10, w10
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget remw_rr
    alu_rr_head
    cbz w11, 1f
    sdiv w12, w10, w11
    msub w10, w12, w11, w10
1:  sxtw x10, w10
    alu_tail
.gadget remuw_rr
    alu_rr_head
    cbz w11, 1f
    udiv w12, w10, w11
    msub w10, w12, w11, w10
1:  sxtw x10, w10
    alu_tail

// ---- Conditional branches (fused compare+branch, the ISA's own shape) ----
// Code stream: [gadget][rs1_off][rs2_off][taken][fallthrough]; the last two
// are ways out of the block, the host's (frag.h's branch_leave), F_WAY_WORDS
// words each. AOK's is one word, in the tagged-chainable scheme
// (riscv64_branch_dispatch).
//
// Each branch comes in two layouts, and gen picks by direction (the "btfn"
// fuse bit): b<name> keeps the fallthrough straight-line for forward branches
// (mostly not taken), b<name>_bk keeps the taken path straight-line for
// backward ones (loops, mostly taken). On the A10X whichever path jumps inside
// the gadget pays ~1.3 ns more (a lone beq: 3.0 vs 4.4 ns); a branchless csel
// select was slower on both paths (5.1-5.5 ns), since the next block's
// address then waits on the compare instead of being predicted.
.macro branch_tail cond, taken_off, fall_off, bk
.ifc \bk, bk
    b.\cond 1f
    branch_leave \taken_off
1:  branch_leave \fall_off
.else
    b.\cond 1f
    branch_leave \fall_off
1:  branch_leave \taken_off
.endif
.endm

// cond is the branch's condition; ncond its inverse (the _bk layout jumps on
// it to reach the fallthrough).
.macro branch_op name, cond, ncond
.macro f_b\name\()_body id, last, fn=_, fm=_, res=0
    ldr x9, [_ip]
    ldr x10, [_ip, #8]
    f_src 9, x9, \fn
    f_src 10, x10, \fm
    cmp x9, x10
    branch_tail \cond, 16, (16+8*F_WAY_WORDS), fw
.endm
f_nostub b\name
f_gadget b\name
.macro f_b\name\()_bk\()_body id, last, fn=_, fm=_, res=0
    ldr x9, [_ip]
    ldr x10, [_ip, #8]
    f_src 9, x9, \fn
    f_src 10, x10, \fm
    cmp x9, x10
    branch_tail \ncond, 16, (16+8*F_WAY_WORDS), bk
.endm
f_nostub b\name\()_bk
f_gadget b\name\()_bk
.endm

branch_op eq, eq, ne
branch_op ne, ne, eq
branch_op lt, lt, ge
branch_op ge, ge, lt
branch_op ltu, lo, hs
branch_op geu, hs, lo

// li t, K ; b<cond> with t as one operand (the "br" fuse bit): the constant
// compare gcc emits for switch cases and loop bounds. Code stream:
// [gadget][t_off][rs_off][K][taken][fallthrough]. _ri compares rs against K
// (t was rs2), _ir compares K against rs (t was rs1); eq/ne need only _ri.
// rs is read before t is written: gen refuses rs == t.
.macro branch_const_body cond, order, bk, fn=_
    ldp x9, x10, [_ip]        // t_off, rs_off
    ldr x11, [_ip, #16]       // K
    f_src 10, x10, \fn
    str x11, [_cpu, x9]
.ifc \order, ri
    cmp x10, x11
.else
    cmp x11, x10
.endif
    branch_tail \cond, 24, (24+8*F_WAY_WORDS), \bk
.endm
.macro branch_const name, cond, ncond, order
.macro f_b\name\()_\order\()_body id, last, fn=_, fm=_, res=0
    branch_const_body \cond, \order, fw, \fn
.endm
f_nostub b\name\()_\order
f_gadget b\name\()_\order
.macro f_b\name\()_\order\()_bk\()_body id, last, fn=_, fm=_, res=0
    branch_const_body \ncond, \order, bk, \fn
.endm
f_nostub b\name\()_\order\()_bk
f_gadget b\name\()_\order\()_bk
.endm
branch_const eq, eq, ne, ri
branch_const ne, ne, eq, ri
branch_const lt, lt, ge, ri
branch_const ge, ge, lt, ri
branch_const ltu, lo, hs, ri
branch_const geu, hs, lo, ri
branch_const lt, lt, ge, ir
branch_const ge, ge, lt, ir
branch_const ltu, lo, hs, ir
branch_const geu, hs, lo, ir

// andi t, rs, K ; beqz/bnez t (bit and flag tests). Same code stream as above.
.macro andi_branch_body cond, bk, fn=_
    ldp x9, x10, [_ip]        // t_off, rs_off
    ldr x11, [_ip, #16]       // K
    f_src 10, x10, \fn
    ands x10, x10, x11
    str x10, [_cpu, x9]
    branch_tail \cond, 24, (24+8*F_WAY_WORDS), \bk
.endm
.macro andi_branch name, cond, ncond
.macro f_andi_\name\()_body id, last, fn=_, fm=_, res=0
    andi_branch_body \cond, fw, \fn
.endm
f_nostub andi_\name
f_gadget andi_\name
.macro f_andi_\name\()_bk\()_body id, last, fn=_, fm=_, res=0
    andi_branch_body \ncond, bk, \fn
.endm
f_nostub andi_\name\()_bk
f_gadget andi_\name\()_bk
.endm
andi_branch beqz, eq, ne
andi_branch bnez, ne, eq

// JAL with rd != 0 -- i.e. a CALL -- in one gadget instead of two.
//
// gen used to emit the link write and the branch separately:
//     [mov_const][rd_off][link]  +  [b][target]        2 dispatches
//     [jal_link][rd_off][link][target]                 1
// which is what arm64's BL already costs here, so this closes a gap rather than
// inventing anything. Every guest function call pays it.
//
// The tail is deliberately identical to gadget_riscv64_b: load the tagged target
// word into _ip and fall into riscv64_branch_dispatch, which owns the
// chained/unchained split, the poke check and the chain budget. Reading the
// target from [_ip, #16] instead of [_ip] is the only difference, and it is safe
// because _ip's own arguments are not needed once the target is in hand -- the
// dispatcher either replaces _ip with a pointer into the target block or exits
// to C with pc set. gen records jump_ip[0] as the index of that target word, so
// the frontend patches THIS slot when it links the edge.
//
// The link must be written before the branch, and unlike jalr below there is no
// rd/rs1 aliasing hazard to order around: the target is a compile-time constant.
.macro f_jal_link_body id, last, fn=_, fm=_, res=0
    ldr x9, [_ip]             // rd_off
    ldr x10, [_ip, #8]        // link value (pc + insn length)
    pc_param x10
    str x10, [_cpu, x9]
    branch_leave 16           // the target
.endm
f_nostub jal_link
f_gadget jal_link

#ifndef RV_GADGET_HOST   // AOK's own: an indirect jump, by its block cache
// JALR: indirect jump, target = (rs1 + imm) & ~1. No chaining (target is
// runtime-computed). Target computed from rs1 BEFORE the link write, because rd may alias
// rs1 (jalr ra, 0(ra)): the spec reads the base first. Code stream:
// [gadget][rd_off][rs1_off][imm][link]  (rd_off = zero sink when rd=x0).
.gadget jalr
    ldr x9, [_ip]             // rd_off
    ldr x10, [_ip, #8]        // rs1_off
    ldr x11, [_ip, #16]       // imm
    ldr x12, [_ip, #24]       // link value (pc + insn length)
    ldr x10, [_cpu, x10]
    add x10, x10, x11
    bic x10, x10, #1
    str x12, [_cpu, x9]       // link AFTER target is computed
    str x10, [_cpu, #CPU_riscv64_pc]
    b jit_ret

// JALR that consults the return cache. Identical to `jalr` above through the
// link write; only the tail differs, replacing the unconditional exit to C with
// a lookup that can dispatch straight into an already-translated block. Both
// gadgets exist in every build and gen picks between them
// (/proc/ish/riscv64_jit_fuse retcache), so the OFF arm is byte-for-byte the
// gadget that shipped before this.
//
// WHY THE CACHE IS FILLED BY THE FRONTEND, NOT BY THE CALL. i386's design
// records at `call` and validates at `ret` (gadgets-aarch64/control.S), which
// this guest cannot copy directly anyway -- RISC-V returns through a link
// register, not a stack pop -- but the deeper reason not to is that it is
// unnecessary here. This engine leaves the JIT almost exclusively through jalr
// (measured: exit count and jalr count one apart), so the set of addresses the
// frontend dispatches at IS the set of jalr targets. Recording at the call
// would add work to compute a set the frontend already has, and would cover
// strictly less: keyed by target, one lookup serves returns, indirect calls and
// `jr` tail calls alike.
//
// The entry is self-validating. It points at block->code, so block->addr sits
// one negative-offset load away and is compared against the computed target --
// a stale or conflict-evicted entry can only miss, never mis-dispatch. The
// is_jetsam test is load-bearing rather than defensive: an invalidated block
// stays allocated until a write-locked cleanup, and the frontend's cleanup_seq
// purge does not reach this thread until it next returns to C, which is exactly
// what this gadget avoids doing. A chained edge is protected there by
// jit_block_disconnect restoring jump_ip; a cache entry has no such backlink,
// so it has to check for itself. The pointer itself cannot dangle: freeing a
// block needs the jetsam WRITE lock and jit_enter runs under the read lock.
//
// Hash MUST match LINKREG_RET_CACHE_HASH in jit/frame.h bit for bit (the arm64
// guest shares that macro and the same dispatch tail); the
// failure mode of a mismatch is a silent 0% hit rate, not a crash.
.macro f_jalr_cached_body id, last, fn=_, fm=_, res=0
    ldr x9, [_ip]             // rd_off
    ldr x10, [_ip, #8]        // rs1_off
    ldr x11, [_ip, #16]       // imm
    f_src 10, x10, \fn        // (before x12, a forward's register, is the link)
    ldr x12, [_ip, #24]       // link value (pc + insn length)
    add x10, x10, x11
    bic x10, x10, #1
    str x12, [_cpu, x9]       // link AFTER target is computed
    eor x13, x10, x10, lsr #12
    ubfx x13, x13, #1, #12
    mov x14, LOCAL_ret_cache
    add x14, _cpu, x14
    ldr x14, [x14, x13, lsl #3]
    cbz x14, 1f               // empty slot
    ldur x15, [x14, #(JIT_BLOCK_addr - JIT_BLOCK_code)]
    cmp x15, x10
    b.ne 1f                   // some other address hashes here
    ldurb w15, [x14, #(JIT_BLOCK_is_jetsam - JIT_BLOCK_code)]
    cbnz w15, 1f              // invalidated; let C compile the replacement
    mov _ip, x14
    // riscv64_chain (core.S) owns the poke check, the chain budget and the
    // last_block store, exactly as it does for a chained branch edge. Entering
    // it below the tagged-word test is deliberate: this pointer is a host
    // address that has already been validated, so there is no tag to strip.
    b riscv64_chain
1:  str x10, [_cpu, #CPU_riscv64_pc]
    b jit_ret
.endm
f_nostub jalr_cached
f_gadget jalr_cached
#endif // !RV_GADGET_HOST

// ---- Fused ALU pairs (gen_riscv64_try_alu_pair, the "alu" fuse bit) -------
// slli rd, rs, a ; srli/srai rd, rd, b -- the zero/sign extension and
// bit-field idiom RV64GC spells with two shifts (slli+srli 32 is zext.w):
// [gadget][rd_off][rs_off][a][b].
.macro f_sll_srl_body id, last, fn=_, fm=_, res=0
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x10, [_cpu, x10]
    lslv x10, x10, x11
    lsrv x10, x10, x12
    str x10, [_cpu, x9]
    f_res \res, x10
    f_end \last, 4
.endm
f_nostub sll_srl
f_gadget sll_srl
.macro f_sll_sra_body id, last, fn=_, fm=_, res=0
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x10, [_cpu, x10]
    lslv x10, x10, x11
    asrv x10, x10, x12
    str x10, [_cpu, x9]
    f_res \res, x10
    f_end \last, 4
.endm
f_nostub sll_sra
f_gadget sll_sra

// slli t, rs, s ; add rd, t, rb (or rb, t) -- the scaled index RV64GC has no
// shNadd for: [gadget][t_off][rs_off][s][rd_off][rb_off]. t is written first
// and rb read after, so rb == t (and rd == t) come out as unfused.
.macro f_sll_add_body id, last, fn=_, fm=_, res=0
    ldp x9, x10, [_ip]        // t_off, rs_off
    ldp x11, x12, [_ip, #16]  // s, rd_off
    ldr x13, [_ip, #32]       // rb_off
    ldr x10, [_cpu, x10]
    lslv x10, x10, x11
    str x10, [_cpu, x9]
    ldr x14, [_cpu, x13]
    add x14, x14, x10
    str x14, [_cpu, x12]
    f_end \last, 5
.endm
f_nostub sll_add
f_gadget sll_add

// ---- Zba, Zbb, Zbs, Zicond (RVA23U64's scalar bit-manipulation) -----------
// Same streams as above: reg-reg [gadget][rd_off][rs1_off][rs2_off], reg-imm
// and unary [gadget][rd_off][rs1_off][imm] (unary ops ignore the imm).
// x10 = rs1, x11 = rs2 or imm on entry; the result goes back in x10.
.macro rv_rr name, insn:vararg
.macro f_\name\()_rr\()_body id, last, fn=_, fm=_, res=0
    alu_rr_head \fn, \fm
    \insn
    alu_tail_f \last, \res
.endm
f_nostub \name\()_rr
f_gadget \name\()_rr
.endm
.macro rv_ri name, insn:vararg
.macro f_\name\()_ri\()_body id, last, fn=_, fm=_, res=0
    alu_head \fn
    \insn
    alu_tail_f \last, \res
.endm
f_nostub \name\()_ri
f_gadget \name\()_ri
.endm

// Zba: shNadd rd = rs2 + (rs1 << N); the .uw forms take rs1's low word,
// zero-extended; slli.uw shifts that word left by the immediate.
rv_rr sh1add, add x10, x11, x10, lsl #1
rv_rr sh2add, add x10, x11, x10, lsl #2
rv_rr sh3add, add x10, x11, x10, lsl #3
rv_rr add_uw, add x10, x11, w10, uxtw
rv_rr sh1add_uw, add x10, x11, w10, uxtw #1
rv_rr sh2add_uw, add x10, x11, w10, uxtw #2
rv_rr sh3add_uw, add x10, x11, w10, uxtw #3
.gadget slli_uw_ri
    alu_head
    mov w10, w10
    lsl x10, x10, x11
    alu_tail

// Zbb
rv_rr andn, bic x10, x10, x11
rv_rr orn, orn x10, x10, x11
rv_rr xnor, eon x10, x10, x11
rv_ri clz, clz x10, x10
rv_ri clzw, clz w10, w10
.gadget ctz_ri
    alu_head
    rbit x10, x10
    clz x10, x10
    alu_tail
.gadget ctzw_ri
    alu_head
    rbit w10, w10
    clz w10, w10
    alu_tail
.gadget cpop_ri
    alu_head
    fmov d0, x10
    cnt v0.8b, v0.8b
    addv b0, v0.8b
    fmov w10, s0
    alu_tail
.gadget cpopw_ri
    alu_head
    mov w10, w10
    fmov d0, x10
    cnt v0.8b, v0.8b
    addv b0, v0.8b
    fmov w10, s0
    alu_tail
rv_ri sext_b, sxtb x10, w10
rv_ri sext_h, sxth x10, w10
rv_ri zext_h, uxth w10, w10
rv_ri rev8, rev x10, x10
.gadget orc_b_ri
    alu_head
    fmov d0, x10
    cmtst v0.8b, v0.8b, v0.8b
    fmov x10, d0
    alu_tail
.irp op, max,maxu,min,minu
.gadget \op\()_rr
    alu_rr_head
    cmp x10, x11
    .ifc \op, max
    csel x10, x10, x11, gt
    .endif
    .ifc \op, maxu
    csel x10, x10, x11, hi
    .endif
    .ifc \op, min
    csel x10, x10, x11, lt
    .endif
    .ifc \op, minu
    csel x10, x10, x11, lo
    .endif
    alu_tail
.endr
// rotates: AArch64 has only ror (by register, mod the width); rol by n is
// ror by -n.
.gadget rol_rr
    alu_rr_head
    neg x11, x11
    ror x10, x10, x11
    alu_tail
rv_rr ror, ror x10, x10, x11
rv_ri ror, ror x10, x10, x11
.gadget rolw_rr
    alu_rr_head
    neg w11, w11
    ror w10, w10, w11
    sxtw x10, w10
    alu_tail
.gadget rorw_rr
    alu_rr_head
    ror w10, w10, w11
    sxtw x10, w10
    alu_tail
.gadget rorw_ri
    alu_head
    ror w10, w10, w11
    sxtw x10, w10
    alu_tail

// Zbs: the bit index is rs2 (or the immediate) mod 64.
.irp form, rr,ri
.gadget bclr_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    mov x12, #1
    lsl x12, x12, x11
    bic x10, x10, x12
    alu_tail
.gadget bset_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    mov x12, #1
    lsl x12, x12, x11
    orr x10, x10, x12
    alu_tail
.gadget binv_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    mov x12, #1
    lsl x12, x12, x11
    eor x10, x10, x12
    alu_tail
.gadget bext_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    lsr x10, x10, x11
    and x10, x10, #1
    alu_tail
.endr

// Zicond: czero.eqz rd = rs2 == 0 ? 0 : rs1; czero.nez rd = rs2 != 0 ? 0 : rs1.
.gadget czero_eqz_rr
    alu_rr_head
    cmp x11, #0
    csel x10, xzr, x10, eq
    alu_tail
.gadget czero_nez_rr
    alu_rr_head
    cmp x11, #0
    csel x10, xzr, x10, ne
    alu_tail

// ---- Fused pairs ----------------------------------------------------------
// One gadget for two guest instructions that run one after the other: the
// first body, the second, one dispatch (frag.h). pairs.h lists them; the
// translator finds them by the two gadgets it would otherwise have emitted
// (gen.c's jit_pair_fuse). Here, at the end of the file that defines most of
// the bodies; frag.h has those of core.S's and memory.S's gadgets.
.text
#ifdef RV_GADGET_HOST
// A second host builds the pairs it has both halves of (frag.h's fuse2_host).
#define FUSE2(a, b) fuse2_host HOST_##a, HOST_##b, a, b, HR_##a, K_##b
#else
#define FUSE2(a, b) fuse2 a, b, HR_##a, K_##b
#endif
#include "pairs.h"
#undef FUSE2
