// The fused pairs of the riscv64 guest: which two gadgets, when one follows
// the other in a block, are replaced by one gadget that does both
// (jit/guest-riscv64/frag.h; jit/guest-arm64/frag.h has the reasoning). Read
// by the assembler, which builds a gadget for each FUSE2 line (alu.S), and by
// the translator, which looks adjacent gadgets up in the same list (gen.c's
// jit_pair_fuse). The `fuse2` bit of /proc/ish/riscv64_jit_fuse turns the
// pass off.
//
// A gadget takes part once it has a body macro (f_<gadget>_body, defined
// where the gadget is) and a line here: F_<gadget> marks it for the tool
// below, and NP_<gadget> is the number of parameter words that follow it in
// the stream. A gadget that ends its block has no NP_: it can only be the
// second of a pair. HR_<gadget>: its body leaves a result in x12 for the
// next; K_<gadget>: how many of its operands a pair can forward to it, and
// OPS_ where the translator finds each one's slot among its parameters.
//
// The second table is chosen by measurement: the commonest adjacent pairs of
// such gadgets in the gadget-level JIT profiles of Python, gcc, gzip/bzip2,
// 7-Zip, digests and big-number arithmetic (the coreutils digests and
// Python's hashlib and pow), a shell-and-busybox script, and awk and sort
// (ISH_JIT_PROFILE, --min 0.015), most frequent first. Regenerate it with
//
//     python3 tools/jitprof-gadget-pairs.py --fuse jit/guest-riscv64/pairs.h --min 0.015 PROFILE...

#define F_add_rr 1
#define HR_add_rr 1
#define K_add_rr 2
#define OPS_add_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_add_rr 3
#define F_add_ri 1
#define HR_add_ri 1
#define K_add_ri 1
#define OPS_add_ri {1, PAIR_OP_SLOT}
#define NP_add_ri 3
#define F_and_rr 1
#define HR_and_rr 1
#define K_and_rr 2
#define OPS_and_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_and_rr 3
#define F_and_ri 1
#define HR_and_ri 1
#define K_and_ri 1
#define OPS_and_ri {1, PAIR_OP_SLOT}
#define NP_and_ri 3
#define F_or_rr 1
#define HR_or_rr 1
#define K_or_rr 2
#define OPS_or_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_or_rr 3
#define F_or_ri 1
#define HR_or_ri 1
#define K_or_ri 1
#define OPS_or_ri {1, PAIR_OP_SLOT}
#define NP_or_ri 3
#define F_xor_rr 1
#define HR_xor_rr 1
#define K_xor_rr 2
#define OPS_xor_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_xor_rr 3
#define F_xor_ri 1
#define HR_xor_ri 1
#define K_xor_ri 1
#define OPS_xor_ri {1, PAIR_OP_SLOT}
#define NP_xor_ri 3
#define F_sll_rr 1
#define HR_sll_rr 1
#define K_sll_rr 2
#define OPS_sll_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sll_rr 3
#define F_sll_ri 1
#define HR_sll_ri 1
#define K_sll_ri 1
#define OPS_sll_ri {1, PAIR_OP_SLOT}
#define NP_sll_ri 3
#define F_srl_rr 1
#define HR_srl_rr 1
#define K_srl_rr 2
#define OPS_srl_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_srl_rr 3
#define F_srl_ri 1
#define HR_srl_ri 1
#define K_srl_ri 1
#define OPS_srl_ri {1, PAIR_OP_SLOT}
#define NP_srl_ri 3
#define F_sra_rr 1
#define HR_sra_rr 1
#define K_sra_rr 2
#define OPS_sra_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sra_rr 3
#define F_sra_ri 1
#define HR_sra_ri 1
#define K_sra_ri 1
#define OPS_sra_ri {1, PAIR_OP_SLOT}
#define NP_sra_ri 3
#define F_addw_rr 1
#define HR_addw_rr 1
#define K_addw_rr 2
#define OPS_addw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_addw_rr 3
#define F_addw_ri 1
#define HR_addw_ri 1
#define K_addw_ri 1
#define OPS_addw_ri {1, PAIR_OP_SLOT}
#define NP_addw_ri 3
#define F_sllw_rr 1
#define HR_sllw_rr 1
#define K_sllw_rr 2
#define OPS_sllw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sllw_rr 3
#define F_sllw_ri 1
#define HR_sllw_ri 1
#define K_sllw_ri 1
#define OPS_sllw_ri {1, PAIR_OP_SLOT}
#define NP_sllw_ri 3
#define F_srlw_rr 1
#define HR_srlw_rr 1
#define K_srlw_rr 2
#define OPS_srlw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_srlw_rr 3
#define F_srlw_ri 1
#define HR_srlw_ri 1
#define K_srlw_ri 1
#define OPS_srlw_ri {1, PAIR_OP_SLOT}
#define NP_srlw_ri 3
#define F_sraw_rr 1
#define HR_sraw_rr 1
#define K_sraw_rr 2
#define OPS_sraw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sraw_rr 3
#define F_sraw_ri 1
#define HR_sraw_ri 1
#define K_sraw_ri 1
#define OPS_sraw_ri {1, PAIR_OP_SLOT}
#define NP_sraw_ri 3
#define F_slt_rr 1
#define HR_slt_rr 1
#define K_slt_rr 2
#define OPS_slt_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_slt_rr 3
#define F_slt_ri 1
#define HR_slt_ri 1
#define K_slt_ri 1
#define OPS_slt_ri {1, PAIR_OP_SLOT}
#define NP_slt_ri 3
#define F_sltu_rr 1
#define HR_sltu_rr 1
#define K_sltu_rr 2
#define OPS_sltu_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sltu_rr 3
#define F_sltu_ri 1
#define HR_sltu_ri 1
#define K_sltu_ri 1
#define OPS_sltu_ri {1, PAIR_OP_SLOT}
#define NP_sltu_ri 3
#define F_sub_rr 1
#define HR_sub_rr 1
#define K_sub_rr 2
#define OPS_sub_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sub_rr 3
#define F_subw_rr 1
#define HR_subw_rr 1
#define K_subw_rr 2
#define OPS_subw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_subw_rr 3
#define F_mul_rr 1
#define HR_mul_rr 1
#define K_mul_rr 2
#define OPS_mul_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_mul_rr 3
#define F_mulw_rr 1
#define HR_mulw_rr 1
#define K_mulw_rr 2
#define OPS_mulw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_mulw_rr 3
#define F_sll_srl 1
#define HR_sll_srl 1
#define K_sll_srl 0
#define NP_sll_srl 4
#define F_sll_sra 1
#define HR_sll_sra 1
#define K_sll_sra 0
#define NP_sll_sra 4
#define F_sll_add 1
#define HR_sll_add 0
#define K_sll_add 0
#define NP_sll_add 5
#define F_sh1add_rr 1
#define HR_sh1add_rr 1
#define K_sh1add_rr 2
#define OPS_sh1add_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sh1add_rr 3
#define F_sh2add_rr 1
#define HR_sh2add_rr 1
#define K_sh2add_rr 2
#define OPS_sh2add_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sh2add_rr 3
#define F_sh3add_rr 1
#define HR_sh3add_rr 1
#define K_sh3add_rr 2
#define OPS_sh3add_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sh3add_rr 3
#define F_add_uw_rr 1
#define HR_add_uw_rr 1
#define K_add_uw_rr 2
#define OPS_add_uw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_add_uw_rr 3
#define F_sh1add_uw_rr 1
#define HR_sh1add_uw_rr 1
#define K_sh1add_uw_rr 2
#define OPS_sh1add_uw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sh1add_uw_rr 3
#define F_sh2add_uw_rr 1
#define HR_sh2add_uw_rr 1
#define K_sh2add_uw_rr 2
#define OPS_sh2add_uw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sh2add_uw_rr 3
#define F_sh3add_uw_rr 1
#define HR_sh3add_uw_rr 1
#define K_sh3add_uw_rr 2
#define OPS_sh3add_uw_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_sh3add_uw_rr 3
#define F_andn_rr 1
#define HR_andn_rr 1
#define K_andn_rr 2
#define OPS_andn_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_andn_rr 3
#define F_orn_rr 1
#define HR_orn_rr 1
#define K_orn_rr 2
#define OPS_orn_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_orn_rr 3
#define F_xnor_rr 1
#define HR_xnor_rr 1
#define K_xnor_rr 2
#define OPS_xnor_rr {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_xnor_rr 3
#define F_mov_const 1
#define HR_mov_const 1
#define K_mov_const 0
#define NP_mov_const 2
#define F_addi 1
#define HR_addi 1
#define K_addi 1
#define OPS_addi {1, PAIR_OP_SLOT}
#define NP_addi 3
#define F_lb 1
#define HR_lb 1
#define K_lb 1
#define OPS_lb {1, PAIR_OP_SLOT}
#define NP_lb 4
#define F_lbu 1
#define HR_lbu 1
#define K_lbu 1
#define OPS_lbu {1, PAIR_OP_SLOT}
#define NP_lbu 4
#define F_lh 1
#define HR_lh 1
#define K_lh 1
#define OPS_lh {1, PAIR_OP_SLOT}
#define NP_lh 4
#define F_lhu 1
#define HR_lhu 1
#define K_lhu 1
#define OPS_lhu {1, PAIR_OP_SLOT}
#define NP_lhu 4
#define F_lw 1
#define HR_lw 1
#define K_lw 1
#define OPS_lw {1, PAIR_OP_SLOT}
#define NP_lw 4
#define F_lwu 1
#define HR_lwu 1
#define K_lwu 1
#define OPS_lwu {1, PAIR_OP_SLOT}
#define NP_lwu 4
#define F_ld 1
#define HR_ld 1
#define K_ld 1
#define OPS_ld {1, PAIR_OP_SLOT}
#define NP_ld 4
#define F_sb 1
#define HR_sb 0
#define K_sb 2
#define OPS_sb {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_sb 4
#define F_sh 1
#define HR_sh 0
#define K_sh 2
#define OPS_sh {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_sh 4
#define F_sw 1
#define HR_sw 0
#define K_sw 2
#define OPS_sw {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_sw 4
#define F_sd 1
#define HR_sd 0
#define K_sd 2
#define OPS_sd {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_sd 4
#define F_b 1
#define HR_b 0
#define K_b 0
#define F_jal_link 1
#define HR_jal_link 0
#define K_jal_link 0
#define F_jalr_cached 1
#define HR_jalr_cached 0
#define K_jalr_cached 1
#define OPS_jalr_cached {1, PAIR_OP_SLOT}
#define F_beq 1
#define HR_beq 0
#define K_beq 2
#define OPS_beq {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_beq_bk 1
#define HR_beq_bk 0
#define K_beq_bk 2
#define OPS_beq_bk {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_beq_ri 1
#define HR_beq_ri 0
#define K_beq_ri 1
#define OPS_beq_ri {1, PAIR_OP_SLOT}
#define F_beq_ri_bk 1
#define HR_beq_ri_bk 0
#define K_beq_ri_bk 1
#define OPS_beq_ri_bk {1, PAIR_OP_SLOT}
#define F_bne 1
#define HR_bne 0
#define K_bne 2
#define OPS_bne {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bne_bk 1
#define HR_bne_bk 0
#define K_bne_bk 2
#define OPS_bne_bk {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bne_ri 1
#define HR_bne_ri 0
#define K_bne_ri 1
#define OPS_bne_ri {1, PAIR_OP_SLOT}
#define F_bne_ri_bk 1
#define HR_bne_ri_bk 0
#define K_bne_ri_bk 1
#define OPS_bne_ri_bk {1, PAIR_OP_SLOT}
#define F_blt 1
#define HR_blt 0
#define K_blt 2
#define OPS_blt {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_blt_bk 1
#define HR_blt_bk 0
#define K_blt_bk 2
#define OPS_blt_bk {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_blt_ri 1
#define HR_blt_ri 0
#define K_blt_ri 1
#define OPS_blt_ri {1, PAIR_OP_SLOT}
#define F_blt_ri_bk 1
#define HR_blt_ri_bk 0
#define K_blt_ri_bk 1
#define OPS_blt_ri_bk {1, PAIR_OP_SLOT}
#define F_bge 1
#define HR_bge 0
#define K_bge 2
#define OPS_bge {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bge_bk 1
#define HR_bge_bk 0
#define K_bge_bk 2
#define OPS_bge_bk {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bge_ri 1
#define HR_bge_ri 0
#define K_bge_ri 1
#define OPS_bge_ri {1, PAIR_OP_SLOT}
#define F_bge_ri_bk 1
#define HR_bge_ri_bk 0
#define K_bge_ri_bk 1
#define OPS_bge_ri_bk {1, PAIR_OP_SLOT}
#define F_bltu 1
#define HR_bltu 0
#define K_bltu 2
#define OPS_bltu {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bltu_bk 1
#define HR_bltu_bk 0
#define K_bltu_bk 2
#define OPS_bltu_bk {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bltu_ri 1
#define HR_bltu_ri 0
#define K_bltu_ri 1
#define OPS_bltu_ri {1, PAIR_OP_SLOT}
#define F_bltu_ri_bk 1
#define HR_bltu_ri_bk 0
#define K_bltu_ri_bk 1
#define OPS_bltu_ri_bk {1, PAIR_OP_SLOT}
#define F_bgeu 1
#define HR_bgeu 0
#define K_bgeu 2
#define OPS_bgeu {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bgeu_bk 1
#define HR_bgeu_bk 0
#define K_bgeu_bk 2
#define OPS_bgeu_bk {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define F_bgeu_ri 1
#define HR_bgeu_ri 0
#define K_bgeu_ri 1
#define OPS_bgeu_ri {1, PAIR_OP_SLOT}
#define F_bgeu_ri_bk 1
#define HR_bgeu_ri_bk 0
#define K_bgeu_ri_bk 1
#define OPS_bgeu_ri_bk {1, PAIR_OP_SLOT}
#define F_blt_ir 1
#define HR_blt_ir 0
#define K_blt_ir 1
#define OPS_blt_ir {1, PAIR_OP_SLOT}
#define F_blt_ir_bk 1
#define HR_blt_ir_bk 0
#define K_blt_ir_bk 1
#define OPS_blt_ir_bk {1, PAIR_OP_SLOT}
#define F_bge_ir 1
#define HR_bge_ir 0
#define K_bge_ir 1
#define OPS_bge_ir {1, PAIR_OP_SLOT}
#define F_bge_ir_bk 1
#define HR_bge_ir_bk 0
#define K_bge_ir_bk 1
#define OPS_bge_ir_bk {1, PAIR_OP_SLOT}
#define F_bltu_ir 1
#define HR_bltu_ir 0
#define K_bltu_ir 1
#define OPS_bltu_ir {1, PAIR_OP_SLOT}
#define F_bltu_ir_bk 1
#define HR_bltu_ir_bk 0
#define K_bltu_ir_bk 1
#define OPS_bltu_ir_bk {1, PAIR_OP_SLOT}
#define F_bgeu_ir 1
#define HR_bgeu_ir 0
#define K_bgeu_ir 1
#define OPS_bgeu_ir {1, PAIR_OP_SLOT}
#define F_bgeu_ir_bk 1
#define HR_bgeu_ir_bk 0
#define K_bgeu_ir_bk 1
#define OPS_bgeu_ir_bk {1, PAIR_OP_SLOT}
#define F_andi_beqz 1
#define HR_andi_beqz 0
#define K_andi_beqz 1
#define OPS_andi_beqz {1, PAIR_OP_SLOT}
#define F_andi_beqz_bk 1
#define HR_andi_beqz_bk 0
#define K_andi_beqz_bk 1
#define OPS_andi_beqz_bk {1, PAIR_OP_SLOT}
#define F_andi_bnez 1
#define HR_andi_bnez 0
#define K_andi_bnez 1
#define OPS_andi_bnez {1, PAIR_OP_SLOT}
#define F_andi_bnez_bk 1
#define HR_andi_bnez_bk 0
#define K_andi_bnez_bk 1
#define OPS_andi_bnez_bk {1, PAIR_OP_SLOT}

// ---- generated: the pairs ----
FUSE2(add_rr, add_rr)
FUSE2(ld, ld)
FUSE2(sllw_ri, addw_rr)
FUSE2(ld, addi)
FUSE2(sll_ri, srl_ri)
FUSE2(lbu, lbu)
FUSE2(addi, jalr_cached)
FUSE2(ld, add_rr)
FUSE2(ld, beq)
FUSE2(addi, addi)
FUSE2(addi, sd)
FUSE2(sd, ld)
FUSE2(addi, bne_bk)
FUSE2(lbu, addi)
FUSE2(srl_ri, add_rr)
FUSE2(srlw_ri, sllw_ri)
FUSE2(mov_const, mov_const)
FUSE2(addw_rr, xor_rr)
FUSE2(addw_rr, addw_rr)
FUSE2(ld, mov_const)
FUSE2(ld, xor_rr)
FUSE2(sll_add, lhu)
FUSE2(add_rr, b)
FUSE2(ld, sd)
FUSE2(addw_ri, bne_bk)
FUSE2(sll_add, ld)
FUSE2(lhu, bgeu)
FUSE2(lbu, sllw_ri)
FUSE2(sd, mov_const)
FUSE2(and_rr, sll_add)
FUSE2(sll_add, lw)
FUSE2(sll_ri, sll_ri)
FUSE2(add_rr, jal_link)
FUSE2(add_rr, sd)
FUSE2(add_rr, ld)
FUSE2(lw, add_rr)
FUSE2(and_rr, xor_rr)
FUSE2(ld, bne_bk)
FUSE2(addi, add_rr)
FUSE2(xor_rr, addw_rr)
FUSE2(srl_ri, sll_add)
FUSE2(add_rr, mov_const)
FUSE2(add_rr, beq)
FUSE2(sll_ri, add_rr)
FUSE2(addw_rr, bne_bk)
FUSE2(addi, ld)
FUSE2(add_rr, jalr_cached)
FUSE2(mov_const, ld)
FUSE2(ld, jalr_cached)
FUSE2(addw_ri, sw)
FUSE2(mov_const, add_rr)
FUSE2(addi, lbu)
FUSE2(add_rr, xor_rr)
FUSE2(xor_rr, sd)
FUSE2(addw_rr, addi)
FUSE2(sd, add_rr)
FUSE2(lw, addw_ri)
FUSE2(add_rr, addi)
FUSE2(addw_ri, addw_ri)
FUSE2(xor_rr, xor_rr)
FUSE2(mov_const, b)
FUSE2(add_rr, lbu)
FUSE2(addw_rr, srlw_ri)
FUSE2(addw_ri, sll_ri)
FUSE2(mov_const, addi)
FUSE2(sd, b)
FUSE2(sll_ri, addi)
FUSE2(xor_rr, srlw_ri)
FUSE2(srl_ri, srl_ri)
FUSE2(addw_rr, sllw_ri)
FUSE2(mov_const, sd)
FUSE2(lw, lw)
FUSE2(sll_add, sd)
FUSE2(addw_ri, addi)
FUSE2(lw, addi)
FUSE2(sd, addi)
FUSE2(addi, b)
FUSE2(srl_ri, and_ri)
FUSE2(xor_rr, srl_ri)
FUSE2(sd, jal_link)
FUSE2(add_rr, sll_ri)
FUSE2(ld, lw)
FUSE2(ld, bne)
FUSE2(addi, addw_rr)
FUSE2(and_rr, and_rr)
FUSE2(xor_rr, add_rr)
FUSE2(ld, sll_add)
FUSE2(mov_const, and_rr)
FUSE2(ld, sll_ri)
FUSE2(add_rr, bne)
FUSE2(lhu, lhu)
FUSE2(lw, beq)
FUSE2(lw, srlw_ri)
FUSE2(addi, mov_const)
FUSE2(lbu, bne_bk)
FUSE2(xor_rr, ld)
FUSE2(sllw_ri, srlw_ri)
FUSE2(and_ri, sll_add)
FUSE2(mov_const, jalr_cached)
FUSE2(sb, add_rr)
FUSE2(lhu, bne_bk)
FUSE2(lw, mov_const)
FUSE2(ld, srl_ri)
FUSE2(xor_ri, and_rr)
FUSE2(addw_rr, sw)
FUSE2(sw, addi)
FUSE2(lbu, beq)
FUSE2(srlw_ri, xor_rr)
FUSE2(add_rr, srl_ri)
FUSE2(add_rr, lhu)
FUSE2(addi, sb)
FUSE2(sd, srl_ri)
FUSE2(xor_rr, and_rr)
FUSE2(mov_const, bne)
FUSE2(and_rr, bne)
FUSE2(lbu, bne)
FUSE2(addi, srl_ri)
FUSE2(sll_ri, mov_const)
FUSE2(sb, sb)
FUSE2(ld, and_ri)
FUSE2(ld, beq_bk)
FUSE2(sd, beq)
FUSE2(lbu, addw_ri)
FUSE2(mov_const, sll_add)
FUSE2(mov_const, jal_link)
FUSE2(and_rr, beq)
FUSE2(srlw_ri, addw_rr)
FUSE2(xor_rr, mov_const)
FUSE2(add_rr, blt)
FUSE2(sd, lw)
FUSE2(sub_rr, ld)
FUSE2(lw, lbu)
FUSE2(add_rr, addw_ri)
FUSE2(and_ri, and_ri)
FUSE2(addw_ri, and_ri)
FUSE2(add_rr, sb)
FUSE2(lw, ld)
FUSE2(srl_ri, ld)
FUSE2(addi, beq)
FUSE2(addi, xor_rr)
FUSE2(sw, sd)
FUSE2(lw, sll_add)
FUSE2(sd, sll_ri)
FUSE2(add_rr, bne_bk)
FUSE2(or_rr, and_rr)
FUSE2(and_rr, beq_bk)
FUSE2(mov_const, beq)
FUSE2(and_ri, mov_const)
FUSE2(lw, sll_srl)
FUSE2(add_rr, bge_bk)
FUSE2(and_ri, addi)
FUSE2(lhu, addi)
FUSE2(addi, sll_ri)
FUSE2(sll_ri, or_rr)
FUSE2(lbu, mov_const)
FUSE2(addw_ri, and_rr)
FUSE2(sub_rr, beq)
FUSE2(addw_ri, add_rr)
FUSE2(ld, sw)
FUSE2(or_rr, lbu)
FUSE2(lw, bltu_bk)
FUSE2(lbu, sb)
FUSE2(sb, addw_ri)
FUSE2(addi, addw_ri)
FUSE2(srl_ri, jalr_cached)
FUSE2(ld, lbu)
FUSE2(sw, b)
FUSE2(mov_const, or_rr)
FUSE2(mov_const, sll_ri)
FUSE2(and_ri, add_rr)
FUSE2(mov_const, lw)
FUSE2(sd, xor_ri)
FUSE2(addi, bne)
FUSE2(ld, addw_ri)
FUSE2(sra_ri, ld)
FUSE2(lw, srlw_rr)
FUSE2(add_rr, bltu)
FUSE2(and_rr, sll_ri)
FUSE2(mov_const, srl_ri)
FUSE2(sd, and_ri)
FUSE2(sll_ri, bge)
FUSE2(lw, and_rr)
FUSE2(addi, and_rr)
FUSE2(addi, lw)
FUSE2(and_rr, ld)
FUSE2(addw_ri, bgeu)
FUSE2(addw_ri, bge)
FUSE2(srl_ri, or_rr)
FUSE2(srlw_ri, addi)
FUSE2(srl_ri, sll_ri)
FUSE2(srl_ri, bne)
FUSE2(xor_rr, b)
FUSE2(addi, bgeu)
FUSE2(addi, sll_add)
FUSE2(or_rr, xor_rr)
FUSE2(and_ri, ld)
FUSE2(and_rr, mov_const)
FUSE2(srlw_rr, andi_bnez_bk)
FUSE2(lbu, add_rr)
FUSE2(sd, lbu)
FUSE2(and_rr, or_rr)
FUSE2(lbu, sll_ri)
FUSE2(sb, lbu)
FUSE2(lhu, beq)
FUSE2(ld, and_rr)
FUSE2(xor_rr, sll_ri)
FUSE2(mov_const, sllw_rr)
FUSE2(mov_const, bltu)
FUSE2(mov_const, addw_rr)
FUSE2(srlw_ri, or_rr)
FUSE2(lhu, addw_ri)
FUSE2(lw, sd)
FUSE2(addw_rr, add_rr)
FUSE2(mov_const, sll_rr)
FUSE2(lw, or_ri)
FUSE2(or_ri, bne_bk)
FUSE2(and_ri, addw_ri)
FUSE2(addi, sub_rr)
FUSE2(add_rr, and_rr)
FUSE2(sw, beq)
FUSE2(or_rr, ld)
FUSE2(sw, sw)
FUSE2(add_rr, sll_add)
FUSE2(ld, jal_link)
FUSE2(sll_ri, blt_bk)
FUSE2(sb, ld)
FUSE2(or_ri, add_rr)
FUSE2(sll_ri, or_ri)
FUSE2(sd, sd)
FUSE2(addw_rr, lw)
FUSE2(xor_rr, lw)
FUSE2(add_rr, xor_ri)
FUSE2(sll_ri, ld)
FUSE2(or_rr, srl_ri)
FUSE2(sw, bne_bk)
FUSE2(sll_add, add_rr)
FUSE2(sllw_ri, or_rr)
FUSE2(lbu, ld)
FUSE2(addw_ri, beq)
FUSE2(addw_ri, bltu)
FUSE2(ld, andi_bnez)
FUSE2(mov_const, addw_ri)
FUSE2(sll_add, srl_ri)
FUSE2(add_rr, and_ri)
FUSE2(srl_rr, andi_beqz)
FUSE2(sll_add, sll_add)
FUSE2(srl_ri, mov_const)
FUSE2(sw, lw)
FUSE2(xor_rr, and_ri)
FUSE2(sub_rr, sltu_rr)
FUSE2(sd, and_rr)
FUSE2(addw_rr, mov_const)
FUSE2(sd, addw_ri)
FUSE2(sll_srl, add_rr)
FUSE2(and_ri, sll_ri)
FUSE2(sltu_rr, addi)
FUSE2(lw, addw_rr)
FUSE2(sll_ri, addw_ri)
FUSE2(xor_rr, xor_ri)
FUSE2(addi, sltu_ri)
FUSE2(sd, bne_bk)
FUSE2(srl_ri, xor_rr)
FUSE2(mov_const, and_ri)
FUSE2(addw_ri, b)
FUSE2(addw_ri, mov_const)
FUSE2(lw, subw_rr)
FUSE2(addw_ri, bltu_ir)
FUSE2(sw, ld)
FUSE2(subw_rr, bge)
FUSE2(and_ri, bltu_ir)
FUSE2(lw, beq_bk)
FUSE2(ld, bge_bk)
FUSE2(srl_ri, andi_beqz)
FUSE2(lw, sll_ri)
FUSE2(xor_ri, ld)
FUSE2(ld, sll_srl)
FUSE2(and_rr, sh)
FUSE2(addw_ri, blt)
FUSE2(sh, bne_bk)
FUSE2(slt_rr, and_ri)
FUSE2(or_rr, srlw_ri)
FUSE2(addi, or_rr)
FUSE2(sllw_ri, sraw_ri)
FUSE2(addw_ri, sll_srl)
FUSE2(add_rr, sw)
FUSE2(srl_rr, andi_bnez)
FUSE2(and_ri, lbu)
FUSE2(lbu, jalr_cached)
FUSE2(lw, bne)
FUSE2(addw_ri, or_rr)
FUSE2(sb, beq_bk)
FUSE2(sll_ri, and_ri)
FUSE2(mov_const, srlw_rr)
FUSE2(srlw_rr, srl_rr)
FUSE2(sw, add_rr)
FUSE2(mov_const, sh)
FUSE2(sltu_rr, ld)
FUSE2(ld, slt_rr)
FUSE2(sll_srl, sll_ri)
FUSE2(or_rr, b)
FUSE2(lw, xor_rr)
FUSE2(ld, blt_bk)
FUSE2(and_rr, addw_ri)
FUSE2(lw, sllw_rr)
FUSE2(sraw_ri, bge)
FUSE2(sw, sltu_rr)
FUSE2(sd, bne)
FUSE2(lwu, ld)
FUSE2(or_rr, mov_const)
FUSE2(sll_add, xor_rr)
FUSE2(lb, bne)
FUSE2(lw, bltu)
FUSE2(lw, sw)
FUSE2(srl_ri, bgeu)
FUSE2(addi, jal_link)
FUSE2(sll_ri, sd)
FUSE2(mul_rr, ld)
FUSE2(addw_rr, xor_ri)
FUSE2(subw_rr, sw)
FUSE2(srlw_ri, srlw_ri)
FUSE2(lbu, lhu)
FUSE2(sub_rr, addi)
FUSE2(sd, or_rr)
FUSE2(subw_rr, sll_srl)
FUSE2(srlw_ri, and_ri)
FUSE2(and_rr, sw)
FUSE2(lhu, add_rr)
FUSE2(sll_add, lwu)
FUSE2(mulw_rr, mov_const)
FUSE2(addw_ri, addw_rr)
FUSE2(mov_const, srlw_ri)
FUSE2(add_rr, lw)
FUSE2(ld, srlw_ri)
FUSE2(ld, b)
FUSE2(and_ri, sh)
FUSE2(sll_add, sw)
FUSE2(srlw_ri, mov_const)
FUSE2(sltu_ri, add_rr)
FUSE2(ld, or_rr)
FUSE2(sh, sb)
FUSE2(add_rr, beq_ri)
FUSE2(sllw_ri, sub_rr)
FUSE2(srlw_ri, sll_add)
FUSE2(lw, blt)
FUSE2(or_rr, sd)
FUSE2(addw_ri, sll_add)
FUSE2(sll_srl, subw_rr)
FUSE2(sllw_ri, mul_rr)
FUSE2(addw_ri, bne)
FUSE2(sll_ri, beq)
FUSE2(lhu, sll_ri)
FUSE2(subw_rr, beq)
FUSE2(sll_rr, srlw_ri)
FUSE2(sll_add, sll_ri)
FUSE2(or_rr, addw_rr)
FUSE2(sh, sw)
FUSE2(addw_rr, bge_bk)
FUSE2(sub_rr, srl_ri)
FUSE2(mulw_rr, blt_bk)
FUSE2(srlw_ri, sraw_rr)
FUSE2(and_ri, sraw_rr)
FUSE2(sraw_rr, andi_bnez_bk)
FUSE2(sraw_rr, andi_beqz)
FUSE2(sh, sub_rr)
FUSE2(and_ri, addw_rr)
FUSE2(ld, sub_rr)
FUSE2(addw_rr, sb)
FUSE2(sb, subw_rr)
FUSE2(sub_rr, sb)
FUSE2(sllw_rr, and_rr)
FUSE2(slt_ri, beq)
FUSE2(ld, lhu)
FUSE2(subw_rr, and_rr)
FUSE2(lw, sllw_ri)
FUSE2(sllw_ri, xor_rr)
FUSE2(or_rr, addw_ri)
FUSE2(and_ri, blt_bk)
FUSE2(add_rr, bgeu)
FUSE2(subw_rr, bne)
FUSE2(addw_ri, lw)
FUSE2(sraw_ri, sll_add)
FUSE2(mov_const, sllw_ri)
FUSE2(lw, bge)
FUSE2(sw, sb)
FUSE2(xor_rr, sll_add)
FUSE2(sllw_rr, addw_ri)
FUSE2(lhu, mov_const)
FUSE2(subw_rr, addw_ri)
FUSE2(add_rr, sh)
FUSE2(mov_const, subw_rr)
FUSE2(srl_ri, beq)
FUSE2(sw, addw_ri)
FUSE2(and_ri, or_rr)
FUSE2(mov_const, lbu)
FUSE2(sd, sw)
FUSE2(srl_ri, bltu)
FUSE2(addw_rr, addw_ri)
FUSE2(ld, xor_ri)
FUSE2(addw_rr, lbu)
FUSE2(lbu, lw)
FUSE2(lwu, addi)
FUSE2(subw_rr, mov_const)
FUSE2(and_rr, xor_ri)
FUSE2(addi, bltu)
FUSE2(add_rr, subw_rr)
FUSE2(mov_const, bne_bk)
FUSE2(addw_rr, sll_ri)
FUSE2(sw, mov_const)
FUSE2(srl_ri, bgeu_ir)
FUSE2(subw_rr, add_rr)
FUSE2(sub_rr, sra_ri)
FUSE2(addw_rr, lwu)
FUSE2(addi, and_ri)
FUSE2(add_rr, bge)
FUSE2(sll_ri, lhu)
FUSE2(ld, blt)
FUSE2(addw_ri, srl_ri)
FUSE2(sw, addw_rr)
FUSE2(addw_ri, sllw_rr)
FUSE2(sw, beq_bk)
FUSE2(sb, blt_ir)
FUSE2(addw_ri, srlw_ri)
FUSE2(srl_ri, addi)
FUSE2(sllw_rr, mov_const)
FUSE2(sllw_rr, addi)
FUSE2(mul_rr, add_rr)
FUSE2(srl_ri, sw)
FUSE2(and_rr, lhu)
FUSE2(srlw_ri, lw)
FUSE2(xor_ri, or_rr)
FUSE2(lbu, and_ri)
FUSE2(and_ri, sd)
FUSE2(lw, and_ri)
FUSE2(add_rr, blt_bk)
FUSE2(sb, lw)
FUSE2(sh, sh)
FUSE2(sllw_rr, sllw_rr)
FUSE2(sllw_rr, srl_ri)
FUSE2(lw, andi_beqz)
FUSE2(add_rr, beq_bk)
FUSE2(lhu, ld)
FUSE2(sllw_ri, subw_rr)
FUSE2(xor_rr, subw_rr)
FUSE2(addw_ri, lb)
FUSE2(sb, b)
FUSE2(lhu, lw)
FUSE2(addw_rr, and_rr)
FUSE2(and_ri, beq)
FUSE2(addw_rr, beq)
FUSE2(ld, sllw_rr)
FUSE2(mul_rr, mov_const)
FUSE2(addw_ri, sb)
FUSE2(subw_rr, subw_rr)
FUSE2(sllw_ri, mov_const)
FUSE2(ld, srl_rr)
FUSE2(addw_ri, sub_rr)
FUSE2(and_ri, bge)
FUSE2(and_rr, bltu_ir)
FUSE2(mov_const, mul_rr)
FUSE2(sllw_rr, or_rr)
FUSE2(xor_ri, sd)
FUSE2(lw, bne_bk)
FUSE2(or_ri, sll_ri)
FUSE2(addi, bltu_bk)
FUSE2(xor_ri, add_rr)
FUSE2(addw_rr, or_rr)
FUSE2(mov_const, sw)
FUSE2(sll_ri, xor_rr)
FUSE2(addw_ri, sh)
FUSE2(mov_const, lhu)
FUSE2(add_rr, sub_rr)
FUSE2(and_ri, bne)
FUSE2(or_rr, jalr_cached)
FUSE2(sd, jalr_cached)
FUSE2(sllw_ri, bltu_bk)
FUSE2(or_rr, sll_ri)
FUSE2(sw, bge_bk)
FUSE2(sraw_ri, andi_bnez)
FUSE2(lbu, sd)
FUSE2(and_ri, bltu)
FUSE2(and_ri, or_ri)
FUSE2(mov_const, bltu_bk)
FUSE2(sd, sb)
FUSE2(lbu, addw_rr)
FUSE2(sw, bne)
FUSE2(lhu, and_ri)
FUSE2(addw_rr, sll_srl)
FUSE2(sll_srl, blt)
FUSE2(lbu, beq_ri)
FUSE2(sw, srlw_ri)
FUSE2(lw, bgeu)
FUSE2(sb, addi)
FUSE2(lbu, srlw_ri)
FUSE2(mov_const, sub_rr)
FUSE2(mov_const, bge)
FUSE2(sd, lhu)
FUSE2(subw_rr, sll_ri)
FUSE2(srlw_ri, bne)
FUSE2(addw_ri, ld)
FUSE2(lhu, sd)
FUSE2(sll_add, mov_const)
FUSE2(ld, addw_rr)
FUSE2(and_rr, subw_rr)
FUSE2(sll_rr, and_rr)
FUSE2(or_rr, sll_add)
FUSE2(sd, blt)
FUSE2(sll_ri, blt)
FUSE2(sub_rr, bltu)
FUSE2(lw, bltu_ir)
FUSE2(addw_ri, mulw_rr)
FUSE2(addw_ri, subw_rr)
FUSE2(subw_rr, srlw_ri)
FUSE2(or_rr, sw)
FUSE2(subw_rr, lw)
FUSE2(lwu, mov_const)
FUSE2(sltu_rr, add_rr)
FUSE2(sllw_ri, sllw_ri)
FUSE2(xor_rr, or_rr)
FUSE2(srl_ri, sd)
FUSE2(sll_rr, addi)
FUSE2(addi, sllw_ri)
FUSE2(addi, blt_bk)
FUSE2(sw, jal_link)
FUSE2(addi, srlw_ri)
FUSE2(addi, bgeu_bk)
FUSE2(and_rr, jal_link)
FUSE2(addw_ri, bgeu_ir)
FUSE2(sra_ri, slt_ri)
FUSE2(sltu_ri, ld)
FUSE2(and_rr, mulw_rr)
FUSE2(subw_rr, sll_add)
FUSE2(srl_rr, andi_beqz_bk)
FUSE2(mov_const, blt)
FUSE2(addw_rr, bne)
FUSE2(sub_rr, sub_rr)
