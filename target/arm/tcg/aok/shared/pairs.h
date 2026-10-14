// The fused pairs of the arm64 guest: which two gadgets, when one follows the
// other in a block, are replaced by one gadget that does both (frag.h has the
// how and the why). Read by the assembler, which builds a gadget for each
// FUSE2 line (alu_spec.S), and by the translator, which looks adjacent gadgets
// up in the same list (gen.c's arm64_pair_fuse). The `pair` bit of
// /proc/ish/arm64_jit_fuse turns the pass off.
//
// A gadget takes part once it has a line in the first table: F_<gadget> is
// its body's family and arguments (frag.h), padded to five with `_`;
// R_<gadget> the host register its body leaves its result in (`_`: none) and
// HR_ whether it has one; K_<gadget> how many of its operands a pair can
// forward to it and OPS_ where the translator finds each one's register
// among its parameters (frag.h's fuse2, gen.c's jit_pair_fuse); and
// NP_<gadget> the number of parameter words that follow it in the stream. A
// gadget that ends its block (a branch) has no NP_: it can only be the second
// of a pair, and that is the only place such gadgets appear in the profiles.
//
// The second table is chosen by measurement, not by hand: it is the commonest
// adjacent pairs of such gadgets in the gadget-level JIT profiles of Python,
// sqlite, gcc, 7-Zip, perl, a shell-and-coreutils script, openssl (its
// speed tests, and separately its digests and ciphers), the coreutils
// digests, and awk, sort and gzip (ISH_JIT_PROFILE,
// tools/jitprof-gadget-pairs.py --fuse --min 0.015), most frequent first.
// Regenerate it with
//
//     python3 tools/jitprof-gadget-pairs.py --fuse jit/guest-arm64/pairs.h --min 0.015 PROFILE...
//
// after adding a family, or to weigh in another workload.

#define F_ospec_addi64 f_alu_imm, add, x, 0, _, _
#define R_ospec_addi64 12
#define HR_ospec_addi64 1
#define K_ospec_addi64 1
#define OPS_ospec_addi64 {1, PAIR_OP_SLOT}
#define NP_ospec_addi64 3
#define F_ospec_addsi64 f_alu_imm, adds, x, 1, _, _
#define R_ospec_addsi64 12
#define HR_ospec_addsi64 1
#define K_ospec_addsi64 1
#define OPS_ospec_addsi64 {1, PAIR_OP_SLOT}
#define NP_ospec_addsi64 3
#define F_ospec_addr64 f_alu_reg, add, x, 0, _, _
#define R_ospec_addr64 12
#define HR_ospec_addr64 1
#define K_ospec_addr64 2
#define OPS_ospec_addr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr64 3
#define F_ospec_addsr64 f_alu_reg, adds, x, 1, _, _
#define R_ospec_addsr64 12
#define HR_ospec_addsr64 1
#define K_ospec_addsr64 2
#define OPS_ospec_addsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addsr64 3
#define F_ospec_addr_lsl64 f_alu_reg_lsl, add, x, _, _, _
#define R_ospec_addr_lsl64 12
#define HR_ospec_addr_lsl64 1
#define K_ospec_addr_lsl64 2
#define OPS_ospec_addr_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr_lsl64 4
#define F_ospec_addi32 f_alu_imm, add, w, 0, _, _
#define R_ospec_addi32 12
#define HR_ospec_addi32 1
#define K_ospec_addi32 1
#define OPS_ospec_addi32 {1, PAIR_OP_SLOT}
#define NP_ospec_addi32 3
#define F_ospec_addsi32 f_alu_imm, adds, w, 1, _, _
#define R_ospec_addsi32 12
#define HR_ospec_addsi32 1
#define K_ospec_addsi32 1
#define OPS_ospec_addsi32 {1, PAIR_OP_SLOT}
#define NP_ospec_addsi32 3
#define F_ospec_addr32 f_alu_reg, add, w, 0, _, _
#define R_ospec_addr32 12
#define HR_ospec_addr32 1
#define K_ospec_addr32 2
#define OPS_ospec_addr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr32 3
#define F_ospec_addsr32 f_alu_reg, adds, w, 1, _, _
#define R_ospec_addsr32 12
#define HR_ospec_addsr32 1
#define K_ospec_addsr32 2
#define OPS_ospec_addsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addsr32 3
#define F_ospec_addr_lsl32 f_alu_reg_lsl, add, w, _, _, _
#define R_ospec_addr_lsl32 12
#define HR_ospec_addr_lsl32 1
#define K_ospec_addr_lsl32 2
#define OPS_ospec_addr_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr_lsl32 4
#define F_ospec_subi64 f_alu_imm, sub, x, 0, _, _
#define R_ospec_subi64 12
#define HR_ospec_subi64 1
#define K_ospec_subi64 1
#define OPS_ospec_subi64 {1, PAIR_OP_SLOT}
#define NP_ospec_subi64 3
#define F_ospec_subsi64 f_alu_imm, subs, x, 1, _, _
#define R_ospec_subsi64 12
#define HR_ospec_subsi64 1
#define K_ospec_subsi64 1
#define OPS_ospec_subsi64 {1, PAIR_OP_SLOT}
#define NP_ospec_subsi64 3
#define F_ospec_subr64 f_alu_reg, sub, x, 0, _, _
#define R_ospec_subr64 12
#define HR_ospec_subr64 1
#define K_ospec_subr64 2
#define OPS_ospec_subr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr64 3
#define F_ospec_subsr64 f_alu_reg, subs, x, 1, _, _
#define R_ospec_subsr64 12
#define HR_ospec_subsr64 1
#define K_ospec_subsr64 2
#define OPS_ospec_subsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subsr64 3
#define F_ospec_subr_lsl64 f_alu_reg_lsl, sub, x, _, _, _
#define R_ospec_subr_lsl64 12
#define HR_ospec_subr_lsl64 1
#define K_ospec_subr_lsl64 2
#define OPS_ospec_subr_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr_lsl64 4
#define F_ospec_subi32 f_alu_imm, sub, w, 0, _, _
#define R_ospec_subi32 12
#define HR_ospec_subi32 1
#define K_ospec_subi32 1
#define OPS_ospec_subi32 {1, PAIR_OP_SLOT}
#define NP_ospec_subi32 3
#define F_ospec_subsi32 f_alu_imm, subs, w, 1, _, _
#define R_ospec_subsi32 12
#define HR_ospec_subsi32 1
#define K_ospec_subsi32 1
#define OPS_ospec_subsi32 {1, PAIR_OP_SLOT}
#define NP_ospec_subsi32 3
#define F_ospec_subr32 f_alu_reg, sub, w, 0, _, _
#define R_ospec_subr32 12
#define HR_ospec_subr32 1
#define K_ospec_subr32 2
#define OPS_ospec_subr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr32 3
#define F_ospec_subsr32 f_alu_reg, subs, w, 1, _, _
#define R_ospec_subsr32 12
#define HR_ospec_subsr32 1
#define K_ospec_subsr32 2
#define OPS_ospec_subsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subsr32 3
#define F_ospec_subr_lsl32 f_alu_reg_lsl, sub, w, _, _, _
#define R_ospec_subr_lsl32 12
#define HR_ospec_subr_lsl32 1
#define K_ospec_subr_lsl32 2
#define OPS_ospec_subr_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr_lsl32 4
#define F_ospec_andi64 f_alu_imm, and, x, 0, _, _
#define R_ospec_andi64 12
#define HR_ospec_andi64 1
#define K_ospec_andi64 1
#define OPS_ospec_andi64 {1, PAIR_OP_SLOT}
#define NP_ospec_andi64 3
#define F_ospec_andr64 f_alu_reg, and, x, 0, _, _
#define R_ospec_andr64 12
#define HR_ospec_andr64 1
#define K_ospec_andr64 2
#define OPS_ospec_andr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_andr64 3
#define F_ospec_andi32 f_alu_imm, and, w, 0, _, _
#define R_ospec_andi32 12
#define HR_ospec_andi32 1
#define K_ospec_andi32 1
#define OPS_ospec_andi32 {1, PAIR_OP_SLOT}
#define NP_ospec_andi32 3
#define F_ospec_andr32 f_alu_reg, and, w, 0, _, _
#define R_ospec_andr32 12
#define HR_ospec_andr32 1
#define K_ospec_andr32 2
#define OPS_ospec_andr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_andr32 3
#define F_ospec_orri64 f_alu_imm, orr, x, 0, _, _
#define R_ospec_orri64 12
#define HR_ospec_orri64 1
#define K_ospec_orri64 1
#define OPS_ospec_orri64 {1, PAIR_OP_SLOT}
#define NP_ospec_orri64 3
#define F_ospec_orrr64 f_alu_reg, orr, x, 0, _, _
#define R_ospec_orrr64 12
#define HR_ospec_orrr64 1
#define K_ospec_orrr64 2
#define OPS_ospec_orrr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orrr64 3
#define F_ospec_orri32 f_alu_imm, orr, w, 0, _, _
#define R_ospec_orri32 12
#define HR_ospec_orri32 1
#define K_ospec_orri32 1
#define OPS_ospec_orri32 {1, PAIR_OP_SLOT}
#define NP_ospec_orri32 3
#define F_ospec_orrr32 f_alu_reg, orr, w, 0, _, _
#define R_ospec_orrr32 12
#define HR_ospec_orrr32 1
#define K_ospec_orrr32 2
#define OPS_ospec_orrr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orrr32 3
#define F_ospec_eori64 f_alu_imm, eor, x, 0, _, _
#define R_ospec_eori64 12
#define HR_ospec_eori64 1
#define K_ospec_eori64 1
#define OPS_ospec_eori64 {1, PAIR_OP_SLOT}
#define NP_ospec_eori64 3
#define F_ospec_eorr64 f_alu_reg, eor, x, 0, _, _
#define R_ospec_eorr64 12
#define HR_ospec_eorr64 1
#define K_ospec_eorr64 2
#define OPS_ospec_eorr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eorr64 3
#define F_ospec_eori32 f_alu_imm, eor, w, 0, _, _
#define R_ospec_eori32 12
#define HR_ospec_eori32 1
#define K_ospec_eori32 1
#define OPS_ospec_eori32 {1, PAIR_OP_SLOT}
#define NP_ospec_eori32 3
#define F_ospec_eorr32 f_alu_reg, eor, w, 0, _, _
#define R_ospec_eorr32 12
#define HR_ospec_eorr32 1
#define K_ospec_eorr32 2
#define OPS_ospec_eorr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eorr32 3
#define F_ospec_andsi64 f_alu_imm, ands, x, 1, _, _
#define R_ospec_andsi64 12
#define HR_ospec_andsi64 1
#define K_ospec_andsi64 1
#define OPS_ospec_andsi64 {1, PAIR_OP_SLOT}
#define NP_ospec_andsi64 3
#define F_ospec_andsr64 f_alu_reg, ands, x, 1, _, _
#define R_ospec_andsr64 12
#define HR_ospec_andsr64 1
#define K_ospec_andsr64 2
#define OPS_ospec_andsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_andsr64 3
#define F_ospec_ubfm64 f_bfm, lsrv, x, _, _, _
#define R_ospec_ubfm64 12
#define HR_ospec_ubfm64 1
#define K_ospec_ubfm64 1
#define OPS_ospec_ubfm64 {1, PAIR_OP_SLOT}
#define NP_ospec_ubfm64 4
#define F_ospec_sbfm64 f_bfm, asrv, x, _, _, _
#define R_ospec_sbfm64 12
#define HR_ospec_sbfm64 1
#define K_ospec_sbfm64 1
#define OPS_ospec_sbfm64 {1, PAIR_OP_SLOT}
#define NP_ospec_sbfm64 4
#define F_ospec_andsi32 f_alu_imm, ands, w, 1, _, _
#define R_ospec_andsi32 12
#define HR_ospec_andsi32 1
#define K_ospec_andsi32 1
#define OPS_ospec_andsi32 {1, PAIR_OP_SLOT}
#define NP_ospec_andsi32 3
#define F_ospec_andsr32 f_alu_reg, ands, w, 1, _, _
#define R_ospec_andsr32 12
#define HR_ospec_andsr32 1
#define K_ospec_andsr32 2
#define OPS_ospec_andsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_andsr32 3
#define F_ospec_ubfm32 f_bfm, lsrv, w, _, _, _
#define R_ospec_ubfm32 12
#define HR_ospec_ubfm32 1
#define K_ospec_ubfm32 1
#define OPS_ospec_ubfm32 {1, PAIR_OP_SLOT}
#define NP_ospec_ubfm32 4
#define F_ospec_sbfm32 f_bfm, asrv, w, _, _, _
#define R_ospec_sbfm32 12
#define HR_ospec_sbfm32 1
#define K_ospec_sbfm32 1
#define OPS_ospec_sbfm32 {1, PAIR_OP_SLOT}
#define NP_ospec_sbfm32 4
#define F_vspec_umov64 f_umov, ldr, x12, _, _, _
#define R_vspec_umov64 12
#define HR_vspec_umov64 1
#define K_vspec_umov64 1
#define OPS_vspec_umov64 {1, PAIR_OP_SLOT}
#define NP_vspec_umov64 2
#define F_vspec_umov32 f_umov, ldr, w12, _, _, _
#define R_vspec_umov32 12
#define HR_vspec_umov32 1
#define K_vspec_umov32 1
#define OPS_vspec_umov32 {1, PAIR_OP_SLOT}
#define NP_vspec_umov32 2
#define F_mov_const f_mov_const, _, _, _, _, _
#define R_mov_const 12
#define HR_mov_const 1
#define K_mov_const 0
#define NP_mov_const 2
#define F_load8_fast f_load, 8, ldrb, w17, _, _
#define R_load8_fast 17
#define HR_load8_fast 1
#define K_load8_fast 1
#define OPS_load8_fast {1, PAIR_OP_SLOT}
#define NP_load8_fast 4
#define F_load16_fast f_load, 16, ldrh, w17, _, _
#define R_load16_fast 17
#define HR_load16_fast 1
#define K_load16_fast 1
#define OPS_load16_fast {1, PAIR_OP_SLOT}
#define NP_load16_fast 4
#define F_load32_fast f_load, 32, ldr, w17, _, _
#define R_load32_fast 17
#define HR_load32_fast 1
#define K_load32_fast 1
#define OPS_load32_fast {1, PAIR_OP_SLOT}
#define NP_load32_fast 4
#define F_load64_fast f_load, 64, ldr, x17, _, _
#define R_load64_fast 17
#define HR_load64_fast 1
#define K_load64_fast 1
#define OPS_load64_fast {1, PAIR_OP_SLOT}
#define NP_load64_fast 4
#define F_loads8_32_fast f_load, 8, ldrsb, w17, _, _
#define R_loads8_32_fast 17
#define HR_loads8_32_fast 1
#define K_loads8_32_fast 1
#define OPS_loads8_32_fast {1, PAIR_OP_SLOT}
#define NP_loads8_32_fast 4
#define F_loads8_64_fast f_load, 8, ldrsb, x17, _, _
#define R_loads8_64_fast 17
#define HR_loads8_64_fast 1
#define K_loads8_64_fast 1
#define OPS_loads8_64_fast {1, PAIR_OP_SLOT}
#define NP_loads8_64_fast 4
#define F_loads16_32_fast f_load, 16, ldrsh, w17, _, _
#define R_loads16_32_fast 17
#define HR_loads16_32_fast 1
#define K_loads16_32_fast 1
#define OPS_loads16_32_fast {1, PAIR_OP_SLOT}
#define NP_loads16_32_fast 4
#define F_loads16_64_fast f_load, 16, ldrsh, x17, _, _
#define R_loads16_64_fast 17
#define HR_loads16_64_fast 1
#define K_loads16_64_fast 1
#define OPS_loads16_64_fast {1, PAIR_OP_SLOT}
#define NP_loads16_64_fast 4
#define F_loads32_64_fast f_load, 32, ldrsw, x17, _, _
#define R_loads32_64_fast 17
#define HR_loads32_64_fast 1
#define K_loads32_64_fast 1
#define OPS_loads32_64_fast {1, PAIR_OP_SLOT}
#define NP_loads32_64_fast 4
#define F_store8_fast f_store, 8, strb, w17, _, _
#define R_store8_fast _
#define HR_store8_fast 0
#define K_store8_fast 2
#define OPS_store8_fast {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store8_fast 4
#define F_store16_fast f_store, 16, strh, w17, _, _
#define R_store16_fast _
#define HR_store16_fast 0
#define K_store16_fast 2
#define OPS_store16_fast {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store16_fast 4
#define F_store32_fast f_store, 32, str, w17, _, _
#define R_store32_fast _
#define HR_store32_fast 0
#define K_store32_fast 2
#define OPS_store32_fast {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store32_fast 4
#define F_store64_fast f_store, 64, str, x17, _, _
#define R_store64_fast _
#define HR_store64_fast 0
#define K_store64_fast 2
#define OPS_store64_fast {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store64_fast 4
#define F_load8_rxl f_load_rx, 8, ldrb, w17, 0, _
#define R_load8_rxl 17
#define HR_load8_rxl 1
#define K_load8_rxl 2
#define OPS_load8_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load8_rxl 5
#define F_load8_rxs f_load_rx, 8, ldrb, w17, 1, _
#define R_load8_rxs 17
#define HR_load8_rxs 1
#define K_load8_rxs 2
#define OPS_load8_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load8_rxs 5
#define F_load8_rxu f_load_rx, 8, ldrb, w17, 2, _
#define R_load8_rxu 17
#define HR_load8_rxu 1
#define K_load8_rxu 2
#define OPS_load8_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load8_rxu 5
#define F_load16_rxl f_load_rx, 16, ldrh, w17, 0, _
#define R_load16_rxl 17
#define HR_load16_rxl 1
#define K_load16_rxl 2
#define OPS_load16_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load16_rxl 5
#define F_load16_rxs f_load_rx, 16, ldrh, w17, 1, _
#define R_load16_rxs 17
#define HR_load16_rxs 1
#define K_load16_rxs 2
#define OPS_load16_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load16_rxs 5
#define F_load16_rxu f_load_rx, 16, ldrh, w17, 2, _
#define R_load16_rxu 17
#define HR_load16_rxu 1
#define K_load16_rxu 2
#define OPS_load16_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load16_rxu 5
#define F_load32_rxl f_load_rx, 32, ldr, w17, 0, _
#define R_load32_rxl 17
#define HR_load32_rxl 1
#define K_load32_rxl 2
#define OPS_load32_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load32_rxl 5
#define F_load32_rxs f_load_rx, 32, ldr, w17, 1, _
#define R_load32_rxs 17
#define HR_load32_rxs 1
#define K_load32_rxs 2
#define OPS_load32_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load32_rxs 5
#define F_load32_rxu f_load_rx, 32, ldr, w17, 2, _
#define R_load32_rxu 17
#define HR_load32_rxu 1
#define K_load32_rxu 2
#define OPS_load32_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load32_rxu 5
#define F_load64_rxl f_load_rx, 64, ldr, x17, 0, _
#define R_load64_rxl 17
#define HR_load64_rxl 1
#define K_load64_rxl 2
#define OPS_load64_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load64_rxl 5
#define F_load64_rxs f_load_rx, 64, ldr, x17, 1, _
#define R_load64_rxs 17
#define HR_load64_rxs 1
#define K_load64_rxs 2
#define OPS_load64_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load64_rxs 5
#define F_load64_rxu f_load_rx, 64, ldr, x17, 2, _
#define R_load64_rxu 17
#define HR_load64_rxu 1
#define K_load64_rxu 2
#define OPS_load64_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_load64_rxu 5
#define F_loads8_32_rxl f_load_rx, 8, ldrsb, w17, 0, _
#define R_loads8_32_rxl 17
#define HR_loads8_32_rxl 1
#define K_loads8_32_rxl 2
#define OPS_loads8_32_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads8_32_rxl 5
#define F_loads8_32_rxs f_load_rx, 8, ldrsb, w17, 1, _
#define R_loads8_32_rxs 17
#define HR_loads8_32_rxs 1
#define K_loads8_32_rxs 2
#define OPS_loads8_32_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads8_32_rxs 5
#define F_loads8_32_rxu f_load_rx, 8, ldrsb, w17, 2, _
#define R_loads8_32_rxu 17
#define HR_loads8_32_rxu 1
#define K_loads8_32_rxu 2
#define OPS_loads8_32_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads8_32_rxu 5
#define F_loads8_64_rxl f_load_rx, 8, ldrsb, x17, 0, _
#define R_loads8_64_rxl 17
#define HR_loads8_64_rxl 1
#define K_loads8_64_rxl 2
#define OPS_loads8_64_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads8_64_rxl 5
#define F_loads8_64_rxs f_load_rx, 8, ldrsb, x17, 1, _
#define R_loads8_64_rxs 17
#define HR_loads8_64_rxs 1
#define K_loads8_64_rxs 2
#define OPS_loads8_64_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads8_64_rxs 5
#define F_loads8_64_rxu f_load_rx, 8, ldrsb, x17, 2, _
#define R_loads8_64_rxu 17
#define HR_loads8_64_rxu 1
#define K_loads8_64_rxu 2
#define OPS_loads8_64_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads8_64_rxu 5
#define F_loads16_32_rxl f_load_rx, 16, ldrsh, w17, 0, _
#define R_loads16_32_rxl 17
#define HR_loads16_32_rxl 1
#define K_loads16_32_rxl 2
#define OPS_loads16_32_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads16_32_rxl 5
#define F_loads16_32_rxs f_load_rx, 16, ldrsh, w17, 1, _
#define R_loads16_32_rxs 17
#define HR_loads16_32_rxs 1
#define K_loads16_32_rxs 2
#define OPS_loads16_32_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads16_32_rxs 5
#define F_loads16_32_rxu f_load_rx, 16, ldrsh, w17, 2, _
#define R_loads16_32_rxu 17
#define HR_loads16_32_rxu 1
#define K_loads16_32_rxu 2
#define OPS_loads16_32_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads16_32_rxu 5
#define F_loads16_64_rxl f_load_rx, 16, ldrsh, x17, 0, _
#define R_loads16_64_rxl 17
#define HR_loads16_64_rxl 1
#define K_loads16_64_rxl 2
#define OPS_loads16_64_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads16_64_rxl 5
#define F_loads16_64_rxs f_load_rx, 16, ldrsh, x17, 1, _
#define R_loads16_64_rxs 17
#define HR_loads16_64_rxs 1
#define K_loads16_64_rxs 2
#define OPS_loads16_64_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads16_64_rxs 5
#define F_loads16_64_rxu f_load_rx, 16, ldrsh, x17, 2, _
#define R_loads16_64_rxu 17
#define HR_loads16_64_rxu 1
#define K_loads16_64_rxu 2
#define OPS_loads16_64_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads16_64_rxu 5
#define F_loads32_64_rxl f_load_rx, 32, ldrsw, x17, 0, _
#define R_loads32_64_rxl 17
#define HR_loads32_64_rxl 1
#define K_loads32_64_rxl 2
#define OPS_loads32_64_rxl {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads32_64_rxl 5
#define F_loads32_64_rxs f_load_rx, 32, ldrsw, x17, 1, _
#define R_loads32_64_rxs 17
#define HR_loads32_64_rxs 1
#define K_loads32_64_rxs 2
#define OPS_loads32_64_rxs {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads32_64_rxs 5
#define F_loads32_64_rxu f_load_rx, 32, ldrsw, x17, 2, _
#define R_loads32_64_rxu 17
#define HR_loads32_64_rxu 1
#define K_loads32_64_rxu 2
#define OPS_loads32_64_rxu {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_loads32_64_rxu 5
#define F_store8_rxl f_store_rx, 8, strb, w17, 0, _
#define R_store8_rxl _
#define HR_store8_rxl 0
#define K_store8_rxl 2
#define OPS_store8_rxl {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store8_rxl 5
#define F_store8_rxs f_store_rx, 8, strb, w17, 1, _
#define R_store8_rxs _
#define HR_store8_rxs 0
#define K_store8_rxs 2
#define OPS_store8_rxs {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store8_rxs 5
#define F_store8_rxu f_store_rx, 8, strb, w17, 2, _
#define R_store8_rxu _
#define HR_store8_rxu 0
#define K_store8_rxu 2
#define OPS_store8_rxu {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store8_rxu 5
#define F_store16_rxl f_store_rx, 16, strh, w17, 0, _
#define R_store16_rxl _
#define HR_store16_rxl 0
#define K_store16_rxl 2
#define OPS_store16_rxl {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store16_rxl 5
#define F_store16_rxs f_store_rx, 16, strh, w17, 1, _
#define R_store16_rxs _
#define HR_store16_rxs 0
#define K_store16_rxs 2
#define OPS_store16_rxs {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store16_rxs 5
#define F_store16_rxu f_store_rx, 16, strh, w17, 2, _
#define R_store16_rxu _
#define HR_store16_rxu 0
#define K_store16_rxu 2
#define OPS_store16_rxu {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store16_rxu 5
#define F_store32_rxl f_store_rx, 32, str, w17, 0, _
#define R_store32_rxl _
#define HR_store32_rxl 0
#define K_store32_rxl 2
#define OPS_store32_rxl {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store32_rxl 5
#define F_store32_rxs f_store_rx, 32, str, w17, 1, _
#define R_store32_rxs _
#define HR_store32_rxs 0
#define K_store32_rxs 2
#define OPS_store32_rxs {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store32_rxs 5
#define F_store32_rxu f_store_rx, 32, str, w17, 2, _
#define R_store32_rxu _
#define HR_store32_rxu 0
#define K_store32_rxu 2
#define OPS_store32_rxu {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store32_rxu 5
#define F_store64_rxl f_store_rx, 64, str, x17, 0, _
#define R_store64_rxl _
#define HR_store64_rxl 0
#define K_store64_rxl 2
#define OPS_store64_rxl {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store64_rxl 5
#define F_store64_rxs f_store_rx, 64, str, x17, 1, _
#define R_store64_rxs _
#define HR_store64_rxs 0
#define K_store64_rxs 2
#define OPS_store64_rxs {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store64_rxs 5
#define F_store64_rxu f_store_rx, 64, str, x17, 2, _
#define R_store64_rxu _
#define HR_store64_rxu 0
#define K_store64_rxu 2
#define OPS_store64_rxu {0, PAIR_OP_SLOT}, {1, PAIR_OP_SLOT}
#define NP_store64_rxu 5
#define F_ldp64_fast f_ldp, 128, 8, x17, _fval2, _
#define R_ldp64_fast _
#define HR_ldp64_fast 0
#define K_ldp64_fast 1
#define OPS_ldp64_fast {1, PAIR_OP_SLOT}
#define NP_ldp64_fast 4
#define F_stp64_fast f_stp, 128, 8, x17, _fval2, _
#define R_stp64_fast _
#define HR_stp64_fast 0
#define K_stp64_fast 1
#define OPS_stp64_fast {1, PAIR_OP_SLOT}
#define NP_stp64_fast 4
#define F_ldp64_post f_ldp_wb, 128, 8, x17, _fval2, 0
#define R_ldp64_post _
#define HR_ldp64_post 0
#define K_ldp64_post 1
#define OPS_ldp64_post {1, PAIR_OP_SLOT}
#define NP_ldp64_post 4
#define F_stp64_pre f_stp_wb, 128, 8, x17, _fval2, 1
#define R_stp64_pre _
#define HR_stp64_pre 0
#define K_stp64_pre 1
#define OPS_stp64_pre {1, PAIR_OP_SLOT}
#define NP_stp64_pre 4
#define F_b f_b, _, _, _, _, _
#define R_b _
#define HR_b 0
#define K_b 0
#define F_bl f_bl, _, _, _, _, _
#define R_bl _
#define HR_bl 0
#define K_bl 0
#define F_br_cached f_br_cached, _, _, _, _, _
#define R_br_cached _
#define HR_br_cached 0
#define K_br_cached 1
#define OPS_br_cached {0, PAIR_OP_SLOT}
#define F_blr_cached f_blr_cached, _, _, _, _, _
#define R_blr_cached _
#define HR_blr_cached 0
#define K_blr_cached 1
#define OPS_blr_cached {0, PAIR_OP_SLOT}
#define F_ret_cached f_br_cached, _, _, _, _, _
#define R_ret_cached _
#define HR_ret_cached 0
#define K_ret_cached 1
#define OPS_ret_cached {0, PAIR_OP_SLOT}
#define F_cbz_x f_cb, x9, cbz, _, _, _
#define R_cbz_x _
#define HR_cbz_x 0
#define K_cbz_x 1
#define OPS_cbz_x {0, PAIR_OP_SLOT}
#define F_cbz_x_bk f_cb_bk, x9, cbnz, _, _, _
#define R_cbz_x_bk _
#define HR_cbz_x_bk 0
#define K_cbz_x_bk 1
#define OPS_cbz_x_bk {0, PAIR_OP_SLOT}
#define F_cbz_w f_cb, w9, cbz, _, _, _
#define R_cbz_w _
#define HR_cbz_w 0
#define K_cbz_w 1
#define OPS_cbz_w {0, PAIR_OP_SLOT}
#define F_cbz_w_bk f_cb_bk, w9, cbnz, _, _, _
#define R_cbz_w_bk _
#define HR_cbz_w_bk 0
#define K_cbz_w_bk 1
#define OPS_cbz_w_bk {0, PAIR_OP_SLOT}
#define F_cbnz_x f_cb, x9, cbnz, _, _, _
#define R_cbnz_x _
#define HR_cbnz_x 0
#define K_cbnz_x 1
#define OPS_cbnz_x {0, PAIR_OP_SLOT}
#define F_cbnz_x_bk f_cb_bk, x9, cbz, _, _, _
#define R_cbnz_x_bk _
#define HR_cbnz_x_bk 0
#define K_cbnz_x_bk 1
#define OPS_cbnz_x_bk {0, PAIR_OP_SLOT}
#define F_cbnz_w f_cb, w9, cbnz, _, _, _
#define R_cbnz_w _
#define HR_cbnz_w 0
#define K_cbnz_w 1
#define OPS_cbnz_w {0, PAIR_OP_SLOT}
#define F_cbnz_w_bk f_cb_bk, w9, cbz, _, _, _
#define R_cbnz_w_bk _
#define HR_cbnz_w_bk 0
#define K_cbnz_w_bk 1
#define OPS_cbnz_w_bk {0, PAIR_OP_SLOT}
#define F_tb_z f_tb, cbz, _, _, _, _
#define R_tb_z _
#define HR_tb_z 0
#define K_tb_z 1
#define OPS_tb_z {0, PAIR_OP_SLOT}
#define F_tb_z_bk f_tb_bk, cbnz, _, _, _, _
#define R_tb_z_bk _
#define HR_tb_z_bk 0
#define K_tb_z_bk 1
#define OPS_tb_z_bk {0, PAIR_OP_SLOT}
#define F_tb_nz f_tb, cbnz, _, _, _, _
#define R_tb_nz _
#define HR_tb_nz 0
#define K_tb_nz 1
#define OPS_tb_nz {0, PAIR_OP_SLOT}
#define F_tb_nz_bk f_tb_bk, cbz, _, _, _, _
#define R_tb_nz_bk _
#define HR_tb_nz_bk 0
#define K_tb_nz_bk 1
#define OPS_tb_nz_bk {0, PAIR_OP_SLOT}
#define F_bcond_eq f_bcond, eq, _, _, _, _
#define R_bcond_eq _
#define HR_bcond_eq 0
#define K_bcond_eq 0
#define F_bcond_nf_eq f_bcond_nf, eq, _, _, _, _
#define R_bcond_nf_eq _
#define HR_bcond_nf_eq 0
#define K_bcond_nf_eq 0
#define F_fused_cmpi64_eq f_fused_cmpi, subs, xzr, x15, x11, eq
#define R_fused_cmpi64_eq _
#define HR_fused_cmpi64_eq 0
#define K_fused_cmpi64_eq 1
#define OPS_fused_cmpi64_eq {0, PAIR_OP_REG}
#define F_fused_cmpi32_eq f_fused_cmpi, subs, wzr, w15, w11, eq
#define R_fused_cmpi32_eq _
#define HR_fused_cmpi32_eq 0
#define K_fused_cmpi32_eq 1
#define OPS_fused_cmpi32_eq {0, PAIR_OP_REG}
#define F_fused_cmpr64_eq f_fused_cmpr, subs, xzr, x15, x13, eq
#define R_fused_cmpr64_eq _
#define HR_fused_cmpr64_eq 0
#define K_fused_cmpr64_eq 2
#define OPS_fused_cmpr64_eq {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_eq f_fused_cmpr, subs, wzr, w15, w13, eq
#define R_fused_cmpr32_eq _
#define HR_fused_cmpr32_eq 0
#define K_fused_cmpr32_eq 2
#define OPS_fused_cmpr32_eq {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_ne f_bcond, ne, _, _, _, _
#define R_bcond_ne _
#define HR_bcond_ne 0
#define K_bcond_ne 0
#define F_bcond_nf_ne f_bcond_nf, ne, _, _, _, _
#define R_bcond_nf_ne _
#define HR_bcond_nf_ne 0
#define K_bcond_nf_ne 0
#define F_fused_cmpi64_ne f_fused_cmpi, subs, xzr, x15, x11, ne
#define R_fused_cmpi64_ne _
#define HR_fused_cmpi64_ne 0
#define K_fused_cmpi64_ne 1
#define OPS_fused_cmpi64_ne {0, PAIR_OP_REG}
#define F_fused_cmpi32_ne f_fused_cmpi, subs, wzr, w15, w11, ne
#define R_fused_cmpi32_ne _
#define HR_fused_cmpi32_ne 0
#define K_fused_cmpi32_ne 1
#define OPS_fused_cmpi32_ne {0, PAIR_OP_REG}
#define F_fused_cmpr64_ne f_fused_cmpr, subs, xzr, x15, x13, ne
#define R_fused_cmpr64_ne _
#define HR_fused_cmpr64_ne 0
#define K_fused_cmpr64_ne 2
#define OPS_fused_cmpr64_ne {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_ne f_fused_cmpr, subs, wzr, w15, w13, ne
#define R_fused_cmpr32_ne _
#define HR_fused_cmpr32_ne 0
#define K_fused_cmpr32_ne 2
#define OPS_fused_cmpr32_ne {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_cs f_bcond, cs, _, _, _, _
#define R_bcond_cs _
#define HR_bcond_cs 0
#define K_bcond_cs 0
#define F_bcond_nf_cs f_bcond_nf, cs, _, _, _, _
#define R_bcond_nf_cs _
#define HR_bcond_nf_cs 0
#define K_bcond_nf_cs 0
#define F_fused_cmpi64_cs f_fused_cmpi, subs, xzr, x15, x11, cs
#define R_fused_cmpi64_cs _
#define HR_fused_cmpi64_cs 0
#define K_fused_cmpi64_cs 1
#define OPS_fused_cmpi64_cs {0, PAIR_OP_REG}
#define F_fused_cmpi32_cs f_fused_cmpi, subs, wzr, w15, w11, cs
#define R_fused_cmpi32_cs _
#define HR_fused_cmpi32_cs 0
#define K_fused_cmpi32_cs 1
#define OPS_fused_cmpi32_cs {0, PAIR_OP_REG}
#define F_fused_cmpr64_cs f_fused_cmpr, subs, xzr, x15, x13, cs
#define R_fused_cmpr64_cs _
#define HR_fused_cmpr64_cs 0
#define K_fused_cmpr64_cs 2
#define OPS_fused_cmpr64_cs {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_cs f_fused_cmpr, subs, wzr, w15, w13, cs
#define R_fused_cmpr32_cs _
#define HR_fused_cmpr32_cs 0
#define K_fused_cmpr32_cs 2
#define OPS_fused_cmpr32_cs {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_cc f_bcond, cc, _, _, _, _
#define R_bcond_cc _
#define HR_bcond_cc 0
#define K_bcond_cc 0
#define F_bcond_nf_cc f_bcond_nf, cc, _, _, _, _
#define R_bcond_nf_cc _
#define HR_bcond_nf_cc 0
#define K_bcond_nf_cc 0
#define F_fused_cmpi64_cc f_fused_cmpi, subs, xzr, x15, x11, cc
#define R_fused_cmpi64_cc _
#define HR_fused_cmpi64_cc 0
#define K_fused_cmpi64_cc 1
#define OPS_fused_cmpi64_cc {0, PAIR_OP_REG}
#define F_fused_cmpi32_cc f_fused_cmpi, subs, wzr, w15, w11, cc
#define R_fused_cmpi32_cc _
#define HR_fused_cmpi32_cc 0
#define K_fused_cmpi32_cc 1
#define OPS_fused_cmpi32_cc {0, PAIR_OP_REG}
#define F_fused_cmpr64_cc f_fused_cmpr, subs, xzr, x15, x13, cc
#define R_fused_cmpr64_cc _
#define HR_fused_cmpr64_cc 0
#define K_fused_cmpr64_cc 2
#define OPS_fused_cmpr64_cc {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_cc f_fused_cmpr, subs, wzr, w15, w13, cc
#define R_fused_cmpr32_cc _
#define HR_fused_cmpr32_cc 0
#define K_fused_cmpr32_cc 2
#define OPS_fused_cmpr32_cc {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_mi f_bcond, mi, _, _, _, _
#define R_bcond_mi _
#define HR_bcond_mi 0
#define K_bcond_mi 0
#define F_bcond_nf_mi f_bcond_nf, mi, _, _, _, _
#define R_bcond_nf_mi _
#define HR_bcond_nf_mi 0
#define K_bcond_nf_mi 0
#define F_fused_cmpi64_mi f_fused_cmpi, subs, xzr, x15, x11, mi
#define R_fused_cmpi64_mi _
#define HR_fused_cmpi64_mi 0
#define K_fused_cmpi64_mi 1
#define OPS_fused_cmpi64_mi {0, PAIR_OP_REG}
#define F_fused_cmpi32_mi f_fused_cmpi, subs, wzr, w15, w11, mi
#define R_fused_cmpi32_mi _
#define HR_fused_cmpi32_mi 0
#define K_fused_cmpi32_mi 1
#define OPS_fused_cmpi32_mi {0, PAIR_OP_REG}
#define F_fused_cmpr64_mi f_fused_cmpr, subs, xzr, x15, x13, mi
#define R_fused_cmpr64_mi _
#define HR_fused_cmpr64_mi 0
#define K_fused_cmpr64_mi 2
#define OPS_fused_cmpr64_mi {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_mi f_fused_cmpr, subs, wzr, w15, w13, mi
#define R_fused_cmpr32_mi _
#define HR_fused_cmpr32_mi 0
#define K_fused_cmpr32_mi 2
#define OPS_fused_cmpr32_mi {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_pl f_bcond, pl, _, _, _, _
#define R_bcond_pl _
#define HR_bcond_pl 0
#define K_bcond_pl 0
#define F_bcond_nf_pl f_bcond_nf, pl, _, _, _, _
#define R_bcond_nf_pl _
#define HR_bcond_nf_pl 0
#define K_bcond_nf_pl 0
#define F_fused_cmpi64_pl f_fused_cmpi, subs, xzr, x15, x11, pl
#define R_fused_cmpi64_pl _
#define HR_fused_cmpi64_pl 0
#define K_fused_cmpi64_pl 1
#define OPS_fused_cmpi64_pl {0, PAIR_OP_REG}
#define F_fused_cmpi32_pl f_fused_cmpi, subs, wzr, w15, w11, pl
#define R_fused_cmpi32_pl _
#define HR_fused_cmpi32_pl 0
#define K_fused_cmpi32_pl 1
#define OPS_fused_cmpi32_pl {0, PAIR_OP_REG}
#define F_fused_cmpr64_pl f_fused_cmpr, subs, xzr, x15, x13, pl
#define R_fused_cmpr64_pl _
#define HR_fused_cmpr64_pl 0
#define K_fused_cmpr64_pl 2
#define OPS_fused_cmpr64_pl {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_pl f_fused_cmpr, subs, wzr, w15, w13, pl
#define R_fused_cmpr32_pl _
#define HR_fused_cmpr32_pl 0
#define K_fused_cmpr32_pl 2
#define OPS_fused_cmpr32_pl {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_vs f_bcond, vs, _, _, _, _
#define R_bcond_vs _
#define HR_bcond_vs 0
#define K_bcond_vs 0
#define F_bcond_nf_vs f_bcond_nf, vs, _, _, _, _
#define R_bcond_nf_vs _
#define HR_bcond_nf_vs 0
#define K_bcond_nf_vs 0
#define F_fused_cmpi64_vs f_fused_cmpi, subs, xzr, x15, x11, vs
#define R_fused_cmpi64_vs _
#define HR_fused_cmpi64_vs 0
#define K_fused_cmpi64_vs 1
#define OPS_fused_cmpi64_vs {0, PAIR_OP_REG}
#define F_fused_cmpi32_vs f_fused_cmpi, subs, wzr, w15, w11, vs
#define R_fused_cmpi32_vs _
#define HR_fused_cmpi32_vs 0
#define K_fused_cmpi32_vs 1
#define OPS_fused_cmpi32_vs {0, PAIR_OP_REG}
#define F_fused_cmpr64_vs f_fused_cmpr, subs, xzr, x15, x13, vs
#define R_fused_cmpr64_vs _
#define HR_fused_cmpr64_vs 0
#define K_fused_cmpr64_vs 2
#define OPS_fused_cmpr64_vs {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_vs f_fused_cmpr, subs, wzr, w15, w13, vs
#define R_fused_cmpr32_vs _
#define HR_fused_cmpr32_vs 0
#define K_fused_cmpr32_vs 2
#define OPS_fused_cmpr32_vs {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_vc f_bcond, vc, _, _, _, _
#define R_bcond_vc _
#define HR_bcond_vc 0
#define K_bcond_vc 0
#define F_bcond_nf_vc f_bcond_nf, vc, _, _, _, _
#define R_bcond_nf_vc _
#define HR_bcond_nf_vc 0
#define K_bcond_nf_vc 0
#define F_fused_cmpi64_vc f_fused_cmpi, subs, xzr, x15, x11, vc
#define R_fused_cmpi64_vc _
#define HR_fused_cmpi64_vc 0
#define K_fused_cmpi64_vc 1
#define OPS_fused_cmpi64_vc {0, PAIR_OP_REG}
#define F_fused_cmpi32_vc f_fused_cmpi, subs, wzr, w15, w11, vc
#define R_fused_cmpi32_vc _
#define HR_fused_cmpi32_vc 0
#define K_fused_cmpi32_vc 1
#define OPS_fused_cmpi32_vc {0, PAIR_OP_REG}
#define F_fused_cmpr64_vc f_fused_cmpr, subs, xzr, x15, x13, vc
#define R_fused_cmpr64_vc _
#define HR_fused_cmpr64_vc 0
#define K_fused_cmpr64_vc 2
#define OPS_fused_cmpr64_vc {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_vc f_fused_cmpr, subs, wzr, w15, w13, vc
#define R_fused_cmpr32_vc _
#define HR_fused_cmpr32_vc 0
#define K_fused_cmpr32_vc 2
#define OPS_fused_cmpr32_vc {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_hi f_bcond, hi, _, _, _, _
#define R_bcond_hi _
#define HR_bcond_hi 0
#define K_bcond_hi 0
#define F_bcond_nf_hi f_bcond_nf, hi, _, _, _, _
#define R_bcond_nf_hi _
#define HR_bcond_nf_hi 0
#define K_bcond_nf_hi 0
#define F_fused_cmpi64_hi f_fused_cmpi, subs, xzr, x15, x11, hi
#define R_fused_cmpi64_hi _
#define HR_fused_cmpi64_hi 0
#define K_fused_cmpi64_hi 1
#define OPS_fused_cmpi64_hi {0, PAIR_OP_REG}
#define F_fused_cmpi32_hi f_fused_cmpi, subs, wzr, w15, w11, hi
#define R_fused_cmpi32_hi _
#define HR_fused_cmpi32_hi 0
#define K_fused_cmpi32_hi 1
#define OPS_fused_cmpi32_hi {0, PAIR_OP_REG}
#define F_fused_cmpr64_hi f_fused_cmpr, subs, xzr, x15, x13, hi
#define R_fused_cmpr64_hi _
#define HR_fused_cmpr64_hi 0
#define K_fused_cmpr64_hi 2
#define OPS_fused_cmpr64_hi {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_hi f_fused_cmpr, subs, wzr, w15, w13, hi
#define R_fused_cmpr32_hi _
#define HR_fused_cmpr32_hi 0
#define K_fused_cmpr32_hi 2
#define OPS_fused_cmpr32_hi {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_ls f_bcond, ls, _, _, _, _
#define R_bcond_ls _
#define HR_bcond_ls 0
#define K_bcond_ls 0
#define F_bcond_nf_ls f_bcond_nf, ls, _, _, _, _
#define R_bcond_nf_ls _
#define HR_bcond_nf_ls 0
#define K_bcond_nf_ls 0
#define F_fused_cmpi64_ls f_fused_cmpi, subs, xzr, x15, x11, ls
#define R_fused_cmpi64_ls _
#define HR_fused_cmpi64_ls 0
#define K_fused_cmpi64_ls 1
#define OPS_fused_cmpi64_ls {0, PAIR_OP_REG}
#define F_fused_cmpi32_ls f_fused_cmpi, subs, wzr, w15, w11, ls
#define R_fused_cmpi32_ls _
#define HR_fused_cmpi32_ls 0
#define K_fused_cmpi32_ls 1
#define OPS_fused_cmpi32_ls {0, PAIR_OP_REG}
#define F_fused_cmpr64_ls f_fused_cmpr, subs, xzr, x15, x13, ls
#define R_fused_cmpr64_ls _
#define HR_fused_cmpr64_ls 0
#define K_fused_cmpr64_ls 2
#define OPS_fused_cmpr64_ls {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_ls f_fused_cmpr, subs, wzr, w15, w13, ls
#define R_fused_cmpr32_ls _
#define HR_fused_cmpr32_ls 0
#define K_fused_cmpr32_ls 2
#define OPS_fused_cmpr32_ls {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_ge f_bcond, ge, _, _, _, _
#define R_bcond_ge _
#define HR_bcond_ge 0
#define K_bcond_ge 0
#define F_bcond_nf_ge f_bcond_nf, ge, _, _, _, _
#define R_bcond_nf_ge _
#define HR_bcond_nf_ge 0
#define K_bcond_nf_ge 0
#define F_fused_cmpi64_ge f_fused_cmpi, subs, xzr, x15, x11, ge
#define R_fused_cmpi64_ge _
#define HR_fused_cmpi64_ge 0
#define K_fused_cmpi64_ge 1
#define OPS_fused_cmpi64_ge {0, PAIR_OP_REG}
#define F_fused_cmpi32_ge f_fused_cmpi, subs, wzr, w15, w11, ge
#define R_fused_cmpi32_ge _
#define HR_fused_cmpi32_ge 0
#define K_fused_cmpi32_ge 1
#define OPS_fused_cmpi32_ge {0, PAIR_OP_REG}
#define F_fused_cmpr64_ge f_fused_cmpr, subs, xzr, x15, x13, ge
#define R_fused_cmpr64_ge _
#define HR_fused_cmpr64_ge 0
#define K_fused_cmpr64_ge 2
#define OPS_fused_cmpr64_ge {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_ge f_fused_cmpr, subs, wzr, w15, w13, ge
#define R_fused_cmpr32_ge _
#define HR_fused_cmpr32_ge 0
#define K_fused_cmpr32_ge 2
#define OPS_fused_cmpr32_ge {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_lt f_bcond, lt, _, _, _, _
#define R_bcond_lt _
#define HR_bcond_lt 0
#define K_bcond_lt 0
#define F_bcond_nf_lt f_bcond_nf, lt, _, _, _, _
#define R_bcond_nf_lt _
#define HR_bcond_nf_lt 0
#define K_bcond_nf_lt 0
#define F_fused_cmpi64_lt f_fused_cmpi, subs, xzr, x15, x11, lt
#define R_fused_cmpi64_lt _
#define HR_fused_cmpi64_lt 0
#define K_fused_cmpi64_lt 1
#define OPS_fused_cmpi64_lt {0, PAIR_OP_REG}
#define F_fused_cmpi32_lt f_fused_cmpi, subs, wzr, w15, w11, lt
#define R_fused_cmpi32_lt _
#define HR_fused_cmpi32_lt 0
#define K_fused_cmpi32_lt 1
#define OPS_fused_cmpi32_lt {0, PAIR_OP_REG}
#define F_fused_cmpr64_lt f_fused_cmpr, subs, xzr, x15, x13, lt
#define R_fused_cmpr64_lt _
#define HR_fused_cmpr64_lt 0
#define K_fused_cmpr64_lt 2
#define OPS_fused_cmpr64_lt {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_lt f_fused_cmpr, subs, wzr, w15, w13, lt
#define R_fused_cmpr32_lt _
#define HR_fused_cmpr32_lt 0
#define K_fused_cmpr32_lt 2
#define OPS_fused_cmpr32_lt {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_gt f_bcond, gt, _, _, _, _
#define R_bcond_gt _
#define HR_bcond_gt 0
#define K_bcond_gt 0
#define F_bcond_nf_gt f_bcond_nf, gt, _, _, _, _
#define R_bcond_nf_gt _
#define HR_bcond_nf_gt 0
#define K_bcond_nf_gt 0
#define F_fused_cmpi64_gt f_fused_cmpi, subs, xzr, x15, x11, gt
#define R_fused_cmpi64_gt _
#define HR_fused_cmpi64_gt 0
#define K_fused_cmpi64_gt 1
#define OPS_fused_cmpi64_gt {0, PAIR_OP_REG}
#define F_fused_cmpi32_gt f_fused_cmpi, subs, wzr, w15, w11, gt
#define R_fused_cmpi32_gt _
#define HR_fused_cmpi32_gt 0
#define K_fused_cmpi32_gt 1
#define OPS_fused_cmpi32_gt {0, PAIR_OP_REG}
#define F_fused_cmpr64_gt f_fused_cmpr, subs, xzr, x15, x13, gt
#define R_fused_cmpr64_gt _
#define HR_fused_cmpr64_gt 0
#define K_fused_cmpr64_gt 2
#define OPS_fused_cmpr64_gt {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_gt f_fused_cmpr, subs, wzr, w15, w13, gt
#define R_fused_cmpr32_gt _
#define HR_fused_cmpr32_gt 0
#define K_fused_cmpr32_gt 2
#define OPS_fused_cmpr32_gt {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_bcond_le f_bcond, le, _, _, _, _
#define R_bcond_le _
#define HR_bcond_le 0
#define K_bcond_le 0
#define F_bcond_nf_le f_bcond_nf, le, _, _, _, _
#define R_bcond_nf_le _
#define HR_bcond_nf_le 0
#define K_bcond_nf_le 0
#define F_fused_cmpi64_le f_fused_cmpi, subs, xzr, x15, x11, le
#define R_fused_cmpi64_le _
#define HR_fused_cmpi64_le 0
#define K_fused_cmpi64_le 1
#define OPS_fused_cmpi64_le {0, PAIR_OP_REG}
#define F_fused_cmpi32_le f_fused_cmpi, subs, wzr, w15, w11, le
#define R_fused_cmpi32_le _
#define HR_fused_cmpi32_le 0
#define K_fused_cmpi32_le 1
#define OPS_fused_cmpi32_le {0, PAIR_OP_REG}
#define F_fused_cmpr64_le f_fused_cmpr, subs, xzr, x15, x13, le
#define R_fused_cmpr64_le _
#define HR_fused_cmpr64_le 0
#define K_fused_cmpr64_le 2
#define OPS_fused_cmpr64_le {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_fused_cmpr32_le f_fused_cmpr, subs, wzr, w15, w13, le
#define R_fused_cmpr32_le _
#define HR_fused_cmpr32_le 0
#define K_fused_cmpr32_le 2
#define OPS_fused_cmpr32_le {0, PAIR_OP_REG}, {0, PAIR_OP_REG8}
#define F_ospec_adc64 f_adc, adc, x, 0, 0, _
#define R_ospec_adc64 12
#define HR_ospec_adc64 1
#define K_ospec_adc64 2
#define OPS_ospec_adc64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adc64 3
#define F_ospec_adc64_nf f_adc, adc, x, 0, 1, _
#define R_ospec_adc64_nf 12
#define HR_ospec_adc64_nf 1
#define K_ospec_adc64_nf 2
#define OPS_ospec_adc64_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adc64_nf 3
#define F_ospec_adc32 f_adc, adc, w, 0, 0, _
#define R_ospec_adc32 12
#define HR_ospec_adc32 1
#define K_ospec_adc32 2
#define OPS_ospec_adc32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adc32 3
#define F_ospec_adc32_nf f_adc, adc, w, 0, 1, _
#define R_ospec_adc32_nf 12
#define HR_ospec_adc32_nf 1
#define K_ospec_adc32_nf 2
#define OPS_ospec_adc32_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adc32_nf 3
#define F_ospec_adcs64 f_adc, adcs, x, 1, 0, _
#define R_ospec_adcs64 12
#define HR_ospec_adcs64 1
#define K_ospec_adcs64 2
#define OPS_ospec_adcs64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adcs64 3
#define F_ospec_adcs64_nf f_adc, adcs, x, 1, 1, _
#define R_ospec_adcs64_nf 12
#define HR_ospec_adcs64_nf 1
#define K_ospec_adcs64_nf 2
#define OPS_ospec_adcs64_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adcs64_nf 3
#define F_ospec_adcs32 f_adc, adcs, w, 1, 0, _
#define R_ospec_adcs32 12
#define HR_ospec_adcs32 1
#define K_ospec_adcs32 2
#define OPS_ospec_adcs32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adcs32 3
#define F_ospec_adcs32_nf f_adc, adcs, w, 1, 1, _
#define R_ospec_adcs32_nf 12
#define HR_ospec_adcs32_nf 1
#define K_ospec_adcs32_nf 2
#define OPS_ospec_adcs32_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_adcs32_nf 3
#define F_ospec_sbc64 f_adc, sbc, x, 0, 0, _
#define R_ospec_sbc64 12
#define HR_ospec_sbc64 1
#define K_ospec_sbc64 2
#define OPS_ospec_sbc64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbc64 3
#define F_ospec_sbc64_nf f_adc, sbc, x, 0, 1, _
#define R_ospec_sbc64_nf 12
#define HR_ospec_sbc64_nf 1
#define K_ospec_sbc64_nf 2
#define OPS_ospec_sbc64_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbc64_nf 3
#define F_ospec_sbc32 f_adc, sbc, w, 0, 0, _
#define R_ospec_sbc32 12
#define HR_ospec_sbc32 1
#define K_ospec_sbc32 2
#define OPS_ospec_sbc32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbc32 3
#define F_ospec_sbc32_nf f_adc, sbc, w, 0, 1, _
#define R_ospec_sbc32_nf 12
#define HR_ospec_sbc32_nf 1
#define K_ospec_sbc32_nf 2
#define OPS_ospec_sbc32_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbc32_nf 3
#define F_ospec_sbcs64 f_adc, sbcs, x, 1, 0, _
#define R_ospec_sbcs64 12
#define HR_ospec_sbcs64 1
#define K_ospec_sbcs64 2
#define OPS_ospec_sbcs64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbcs64 3
#define F_ospec_sbcs64_nf f_adc, sbcs, x, 1, 1, _
#define R_ospec_sbcs64_nf 12
#define HR_ospec_sbcs64_nf 1
#define K_ospec_sbcs64_nf 2
#define OPS_ospec_sbcs64_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbcs64_nf 3
#define F_ospec_sbcs32 f_adc, sbcs, w, 1, 0, _
#define R_ospec_sbcs32 12
#define HR_ospec_sbcs32 1
#define K_ospec_sbcs32 2
#define OPS_ospec_sbcs32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbcs32 3
#define F_ospec_sbcs32_nf f_adc, sbcs, w, 1, 1, _
#define R_ospec_sbcs32_nf 12
#define HR_ospec_sbcs32_nf 1
#define K_ospec_sbcs32_nf 2
#define OPS_ospec_sbcs32_nf {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sbcs32_nf 3
#define F_ospec_mul64 f_alu_reg, mul, x, 0, _, _
#define R_ospec_mul64 12
#define HR_ospec_mul64 1
#define K_ospec_mul64 2
#define OPS_ospec_mul64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_mul64 3
#define F_ospec_mul32 f_alu_reg, mul, w, 0, _, _
#define R_ospec_mul32 12
#define HR_ospec_mul32 1
#define K_ospec_mul32 2
#define OPS_ospec_mul32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_mul32 3
#define F_ospec_umulh f_alu_reg, umulh, x, 0, _, _
#define R_ospec_umulh 12
#define HR_ospec_umulh 1
#define K_ospec_umulh 2
#define OPS_ospec_umulh {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_umulh 3
#define F_ospec_smulh f_alu_reg, smulh, x, 0, _, _
#define R_ospec_smulh 12
#define HR_ospec_smulh 1
#define K_ospec_smulh 2
#define OPS_ospec_smulh {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_smulh 3
#define F_ospec_madd64 f_madd, madd, x, _, _, _
#define R_ospec_madd64 12
#define HR_ospec_madd64 1
#define K_ospec_madd64 2
#define OPS_ospec_madd64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_madd64 4
#define F_ospec_madd32 f_madd, madd, w, _, _, _
#define R_ospec_madd32 12
#define HR_ospec_madd32 1
#define K_ospec_madd32 2
#define OPS_ospec_madd32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_madd32 4
#define F_ospec_msub64 f_madd, msub, x, _, _, _
#define R_ospec_msub64 12
#define HR_ospec_msub64 1
#define K_ospec_msub64 2
#define OPS_ospec_msub64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_msub64 4
#define F_ospec_msub32 f_madd, msub, w, _, _, _
#define R_ospec_msub32 12
#define HR_ospec_msub32 1
#define K_ospec_msub32 2
#define OPS_ospec_msub32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_msub32 4
#define F_ospec_umull f_mull, umull, _, _, _, _
#define R_ospec_umull 12
#define HR_ospec_umull 1
#define K_ospec_umull 2
#define OPS_ospec_umull {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_umull 3
#define F_ospec_smull f_mull, smull, _, _, _, _
#define R_ospec_smull 12
#define HR_ospec_smull 1
#define K_ospec_smull 2
#define OPS_ospec_smull {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_smull 3
#define F_ospec_ror64 f_alu_imm, rorv, x, 0, _, _
#define R_ospec_ror64 12
#define HR_ospec_ror64 1
#define K_ospec_ror64 1
#define OPS_ospec_ror64 {1, PAIR_OP_SLOT}
#define NP_ospec_ror64 3
#define F_ospec_ror32 f_alu_imm, rorv, w, 0, _, _
#define R_ospec_ror32 12
#define HR_ospec_ror32 1
#define K_ospec_ror32 1
#define OPS_ospec_ror32 {1, PAIR_OP_SLOT}
#define NP_ospec_ror32 3
#define F_ospec_mvn64 f_mvn, x, _, _, _, _
#define R_ospec_mvn64 12
#define HR_ospec_mvn64 1
#define K_ospec_mvn64 1
#define OPS_ospec_mvn64 {1, PAIR_OP_SLOT}
#define NP_ospec_mvn64 2
#define F_ospec_mvn32 f_mvn, w, _, _, _, _
#define R_ospec_mvn32 12
#define HR_ospec_mvn32 1
#define K_ospec_mvn32 1
#define OPS_ospec_mvn32 {1, PAIR_OP_SLOT}
#define NP_ospec_mvn32 2
#define F_ospec_bicr64 f_alu_reg, bic, x, 0, _, _
#define R_ospec_bicr64 12
#define HR_ospec_bicr64 1
#define K_ospec_bicr64 2
#define OPS_ospec_bicr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bicr64 3
#define F_ospec_bicr32 f_alu_reg, bic, w, 0, _, _
#define R_ospec_bicr32 12
#define HR_ospec_bicr32 1
#define K_ospec_bicr32 2
#define OPS_ospec_bicr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bicr32 3
#define F_ospec_ornr64 f_alu_reg, orn, x, 0, _, _
#define R_ospec_ornr64 12
#define HR_ospec_ornr64 1
#define K_ospec_ornr64 2
#define OPS_ospec_ornr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_ornr64 3
#define F_ospec_ornr32 f_alu_reg, orn, w, 0, _, _
#define R_ospec_ornr32 12
#define HR_ospec_ornr32 1
#define K_ospec_ornr32 2
#define OPS_ospec_ornr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_ornr32 3
#define F_ospec_eonr64 f_alu_reg, eon, x, 0, _, _
#define R_ospec_eonr64 12
#define HR_ospec_eonr64 1
#define K_ospec_eonr64 2
#define OPS_ospec_eonr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eonr64 3
#define F_ospec_eonr32 f_alu_reg, eon, w, 0, _, _
#define R_ospec_eonr32 12
#define HR_ospec_eonr32 1
#define K_ospec_eonr32 2
#define OPS_ospec_eonr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eonr32 3
#define F_ospec_and_lsl64 f_alu_reg_sh, and, x, lslv, _, _
#define R_ospec_and_lsl64 12
#define HR_ospec_and_lsl64 1
#define K_ospec_and_lsl64 2
#define OPS_ospec_and_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_lsl64 4
#define F_ospec_and_lsl32 f_alu_reg_sh, and, w, lslv, _, _
#define R_ospec_and_lsl32 12
#define HR_ospec_and_lsl32 1
#define K_ospec_and_lsl32 2
#define OPS_ospec_and_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_lsl32 4
#define F_ospec_and_lsr64 f_alu_reg_sh, and, x, lsrv, _, _
#define R_ospec_and_lsr64 12
#define HR_ospec_and_lsr64 1
#define K_ospec_and_lsr64 2
#define OPS_ospec_and_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_lsr64 4
#define F_ospec_and_lsr32 f_alu_reg_sh, and, w, lsrv, _, _
#define R_ospec_and_lsr32 12
#define HR_ospec_and_lsr32 1
#define K_ospec_and_lsr32 2
#define OPS_ospec_and_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_lsr32 4
#define F_ospec_and_asr64 f_alu_reg_sh, and, x, asrv, _, _
#define R_ospec_and_asr64 12
#define HR_ospec_and_asr64 1
#define K_ospec_and_asr64 2
#define OPS_ospec_and_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_asr64 4
#define F_ospec_and_asr32 f_alu_reg_sh, and, w, asrv, _, _
#define R_ospec_and_asr32 12
#define HR_ospec_and_asr32 1
#define K_ospec_and_asr32 2
#define OPS_ospec_and_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_asr32 4
#define F_ospec_and_ror64 f_alu_reg_sh, and, x, rorv, _, _
#define R_ospec_and_ror64 12
#define HR_ospec_and_ror64 1
#define K_ospec_and_ror64 2
#define OPS_ospec_and_ror64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_ror64 4
#define F_ospec_and_ror32 f_alu_reg_sh, and, w, rorv, _, _
#define R_ospec_and_ror32 12
#define HR_ospec_and_ror32 1
#define K_ospec_and_ror32 2
#define OPS_ospec_and_ror32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_and_ror32 4
#define F_ospec_orr_lsl64 f_alu_reg_sh, orr, x, lslv, _, _
#define R_ospec_orr_lsl64 12
#define HR_ospec_orr_lsl64 1
#define K_ospec_orr_lsl64 2
#define OPS_ospec_orr_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_lsl64 4
#define F_ospec_orr_lsl32 f_alu_reg_sh, orr, w, lslv, _, _
#define R_ospec_orr_lsl32 12
#define HR_ospec_orr_lsl32 1
#define K_ospec_orr_lsl32 2
#define OPS_ospec_orr_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_lsl32 4
#define F_ospec_orr_lsr64 f_alu_reg_sh, orr, x, lsrv, _, _
#define R_ospec_orr_lsr64 12
#define HR_ospec_orr_lsr64 1
#define K_ospec_orr_lsr64 2
#define OPS_ospec_orr_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_lsr64 4
#define F_ospec_orr_lsr32 f_alu_reg_sh, orr, w, lsrv, _, _
#define R_ospec_orr_lsr32 12
#define HR_ospec_orr_lsr32 1
#define K_ospec_orr_lsr32 2
#define OPS_ospec_orr_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_lsr32 4
#define F_ospec_orr_asr64 f_alu_reg_sh, orr, x, asrv, _, _
#define R_ospec_orr_asr64 12
#define HR_ospec_orr_asr64 1
#define K_ospec_orr_asr64 2
#define OPS_ospec_orr_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_asr64 4
#define F_ospec_orr_asr32 f_alu_reg_sh, orr, w, asrv, _, _
#define R_ospec_orr_asr32 12
#define HR_ospec_orr_asr32 1
#define K_ospec_orr_asr32 2
#define OPS_ospec_orr_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_asr32 4
#define F_ospec_orr_ror64 f_alu_reg_sh, orr, x, rorv, _, _
#define R_ospec_orr_ror64 12
#define HR_ospec_orr_ror64 1
#define K_ospec_orr_ror64 2
#define OPS_ospec_orr_ror64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_ror64 4
#define F_ospec_orr_ror32 f_alu_reg_sh, orr, w, rorv, _, _
#define R_ospec_orr_ror32 12
#define HR_ospec_orr_ror32 1
#define K_ospec_orr_ror32 2
#define OPS_ospec_orr_ror32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orr_ror32 4
#define F_ospec_eor_lsl64 f_alu_reg_sh, eor, x, lslv, _, _
#define R_ospec_eor_lsl64 12
#define HR_ospec_eor_lsl64 1
#define K_ospec_eor_lsl64 2
#define OPS_ospec_eor_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_lsl64 4
#define F_ospec_eor_lsl32 f_alu_reg_sh, eor, w, lslv, _, _
#define R_ospec_eor_lsl32 12
#define HR_ospec_eor_lsl32 1
#define K_ospec_eor_lsl32 2
#define OPS_ospec_eor_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_lsl32 4
#define F_ospec_eor_lsr64 f_alu_reg_sh, eor, x, lsrv, _, _
#define R_ospec_eor_lsr64 12
#define HR_ospec_eor_lsr64 1
#define K_ospec_eor_lsr64 2
#define OPS_ospec_eor_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_lsr64 4
#define F_ospec_eor_lsr32 f_alu_reg_sh, eor, w, lsrv, _, _
#define R_ospec_eor_lsr32 12
#define HR_ospec_eor_lsr32 1
#define K_ospec_eor_lsr32 2
#define OPS_ospec_eor_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_lsr32 4
#define F_ospec_eor_asr64 f_alu_reg_sh, eor, x, asrv, _, _
#define R_ospec_eor_asr64 12
#define HR_ospec_eor_asr64 1
#define K_ospec_eor_asr64 2
#define OPS_ospec_eor_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_asr64 4
#define F_ospec_eor_asr32 f_alu_reg_sh, eor, w, asrv, _, _
#define R_ospec_eor_asr32 12
#define HR_ospec_eor_asr32 1
#define K_ospec_eor_asr32 2
#define OPS_ospec_eor_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_asr32 4
#define F_ospec_eor_ror64 f_alu_reg_sh, eor, x, rorv, _, _
#define R_ospec_eor_ror64 12
#define HR_ospec_eor_ror64 1
#define K_ospec_eor_ror64 2
#define OPS_ospec_eor_ror64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_ror64 4
#define F_ospec_eor_ror32 f_alu_reg_sh, eor, w, rorv, _, _
#define R_ospec_eor_ror32 12
#define HR_ospec_eor_ror32 1
#define K_ospec_eor_ror32 2
#define OPS_ospec_eor_ror32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eor_ror32 4
#define F_ospec_bic_lsl64 f_alu_reg_sh, bic, x, lslv, _, _
#define R_ospec_bic_lsl64 12
#define HR_ospec_bic_lsl64 1
#define K_ospec_bic_lsl64 2
#define OPS_ospec_bic_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_lsl64 4
#define F_ospec_bic_lsl32 f_alu_reg_sh, bic, w, lslv, _, _
#define R_ospec_bic_lsl32 12
#define HR_ospec_bic_lsl32 1
#define K_ospec_bic_lsl32 2
#define OPS_ospec_bic_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_lsl32 4
#define F_ospec_bic_lsr64 f_alu_reg_sh, bic, x, lsrv, _, _
#define R_ospec_bic_lsr64 12
#define HR_ospec_bic_lsr64 1
#define K_ospec_bic_lsr64 2
#define OPS_ospec_bic_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_lsr64 4
#define F_ospec_bic_lsr32 f_alu_reg_sh, bic, w, lsrv, _, _
#define R_ospec_bic_lsr32 12
#define HR_ospec_bic_lsr32 1
#define K_ospec_bic_lsr32 2
#define OPS_ospec_bic_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_lsr32 4
#define F_ospec_bic_asr64 f_alu_reg_sh, bic, x, asrv, _, _
#define R_ospec_bic_asr64 12
#define HR_ospec_bic_asr64 1
#define K_ospec_bic_asr64 2
#define OPS_ospec_bic_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_asr64 4
#define F_ospec_bic_asr32 f_alu_reg_sh, bic, w, asrv, _, _
#define R_ospec_bic_asr32 12
#define HR_ospec_bic_asr32 1
#define K_ospec_bic_asr32 2
#define OPS_ospec_bic_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_asr32 4
#define F_ospec_bic_ror64 f_alu_reg_sh, bic, x, rorv, _, _
#define R_ospec_bic_ror64 12
#define HR_ospec_bic_ror64 1
#define K_ospec_bic_ror64 2
#define OPS_ospec_bic_ror64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_ror64 4
#define F_ospec_bic_ror32 f_alu_reg_sh, bic, w, rorv, _, _
#define R_ospec_bic_ror32 12
#define HR_ospec_bic_ror32 1
#define K_ospec_bic_ror32 2
#define OPS_ospec_bic_ror32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_bic_ror32 4
#define F_ospec_orn_lsl64 f_alu_reg_sh, orn, x, lslv, _, _
#define R_ospec_orn_lsl64 12
#define HR_ospec_orn_lsl64 1
#define K_ospec_orn_lsl64 2
#define OPS_ospec_orn_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_lsl64 4
#define F_ospec_orn_lsl32 f_alu_reg_sh, orn, w, lslv, _, _
#define R_ospec_orn_lsl32 12
#define HR_ospec_orn_lsl32 1
#define K_ospec_orn_lsl32 2
#define OPS_ospec_orn_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_lsl32 4
#define F_ospec_orn_lsr64 f_alu_reg_sh, orn, x, lsrv, _, _
#define R_ospec_orn_lsr64 12
#define HR_ospec_orn_lsr64 1
#define K_ospec_orn_lsr64 2
#define OPS_ospec_orn_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_lsr64 4
#define F_ospec_orn_lsr32 f_alu_reg_sh, orn, w, lsrv, _, _
#define R_ospec_orn_lsr32 12
#define HR_ospec_orn_lsr32 1
#define K_ospec_orn_lsr32 2
#define OPS_ospec_orn_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_lsr32 4
#define F_ospec_orn_asr64 f_alu_reg_sh, orn, x, asrv, _, _
#define R_ospec_orn_asr64 12
#define HR_ospec_orn_asr64 1
#define K_ospec_orn_asr64 2
#define OPS_ospec_orn_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_asr64 4
#define F_ospec_orn_asr32 f_alu_reg_sh, orn, w, asrv, _, _
#define R_ospec_orn_asr32 12
#define HR_ospec_orn_asr32 1
#define K_ospec_orn_asr32 2
#define OPS_ospec_orn_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_asr32 4
#define F_ospec_orn_ror64 f_alu_reg_sh, orn, x, rorv, _, _
#define R_ospec_orn_ror64 12
#define HR_ospec_orn_ror64 1
#define K_ospec_orn_ror64 2
#define OPS_ospec_orn_ror64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_ror64 4
#define F_ospec_orn_ror32 f_alu_reg_sh, orn, w, rorv, _, _
#define R_ospec_orn_ror32 12
#define HR_ospec_orn_ror32 1
#define K_ospec_orn_ror32 2
#define OPS_ospec_orn_ror32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_orn_ror32 4
#define F_ospec_eon_lsl64 f_alu_reg_sh, eon, x, lslv, _, _
#define R_ospec_eon_lsl64 12
#define HR_ospec_eon_lsl64 1
#define K_ospec_eon_lsl64 2
#define OPS_ospec_eon_lsl64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_lsl64 4
#define F_ospec_eon_lsl32 f_alu_reg_sh, eon, w, lslv, _, _
#define R_ospec_eon_lsl32 12
#define HR_ospec_eon_lsl32 1
#define K_ospec_eon_lsl32 2
#define OPS_ospec_eon_lsl32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_lsl32 4
#define F_ospec_eon_lsr64 f_alu_reg_sh, eon, x, lsrv, _, _
#define R_ospec_eon_lsr64 12
#define HR_ospec_eon_lsr64 1
#define K_ospec_eon_lsr64 2
#define OPS_ospec_eon_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_lsr64 4
#define F_ospec_eon_lsr32 f_alu_reg_sh, eon, w, lsrv, _, _
#define R_ospec_eon_lsr32 12
#define HR_ospec_eon_lsr32 1
#define K_ospec_eon_lsr32 2
#define OPS_ospec_eon_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_lsr32 4
#define F_ospec_eon_asr64 f_alu_reg_sh, eon, x, asrv, _, _
#define R_ospec_eon_asr64 12
#define HR_ospec_eon_asr64 1
#define K_ospec_eon_asr64 2
#define OPS_ospec_eon_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_asr64 4
#define F_ospec_eon_asr32 f_alu_reg_sh, eon, w, asrv, _, _
#define R_ospec_eon_asr32 12
#define HR_ospec_eon_asr32 1
#define K_ospec_eon_asr32 2
#define OPS_ospec_eon_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_asr32 4
#define F_ospec_eon_ror64 f_alu_reg_sh, eon, x, rorv, _, _
#define R_ospec_eon_ror64 12
#define HR_ospec_eon_ror64 1
#define K_ospec_eon_ror64 2
#define OPS_ospec_eon_ror64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_ror64 4
#define F_ospec_eon_ror32 f_alu_reg_sh, eon, w, rorv, _, _
#define R_ospec_eon_ror32 12
#define HR_ospec_eon_ror32 1
#define K_ospec_eon_ror32 2
#define OPS_ospec_eon_ror32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_eon_ror32 4
#define F_ospec_addr_lsr64 f_alu_reg_sh, add, x, lsrv, _, _
#define R_ospec_addr_lsr64 12
#define HR_ospec_addr_lsr64 1
#define K_ospec_addr_lsr64 2
#define OPS_ospec_addr_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr_lsr64 4
#define F_ospec_addr_lsr32 f_alu_reg_sh, add, w, lsrv, _, _
#define R_ospec_addr_lsr32 12
#define HR_ospec_addr_lsr32 1
#define K_ospec_addr_lsr32 2
#define OPS_ospec_addr_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr_lsr32 4
#define F_ospec_addr_asr64 f_alu_reg_sh, add, x, asrv, _, _
#define R_ospec_addr_asr64 12
#define HR_ospec_addr_asr64 1
#define K_ospec_addr_asr64 2
#define OPS_ospec_addr_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr_asr64 4
#define F_ospec_addr_asr32 f_alu_reg_sh, add, w, asrv, _, _
#define R_ospec_addr_asr32 12
#define HR_ospec_addr_asr32 1
#define K_ospec_addr_asr32 2
#define OPS_ospec_addr_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_addr_asr32 4
#define F_ospec_add_uxtw64 f_alu_ext, add, x, uxtw, _, _
#define R_ospec_add_uxtw64 12
#define HR_ospec_add_uxtw64 1
#define K_ospec_add_uxtw64 2
#define OPS_ospec_add_uxtw64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_uxtw64 4
#define F_ospec_add_sxtw64 f_alu_ext, add, x, sxtw, _, _
#define R_ospec_add_sxtw64 12
#define HR_ospec_add_sxtw64 1
#define K_ospec_add_sxtw64 2
#define OPS_ospec_add_sxtw64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_sxtw64 4
#define F_ospec_add_uxtb64 f_alu_ext, add, x, uxtb, _, _
#define R_ospec_add_uxtb64 12
#define HR_ospec_add_uxtb64 1
#define K_ospec_add_uxtb64 2
#define OPS_ospec_add_uxtb64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_uxtb64 4
#define F_ospec_add_uxth64 f_alu_ext, add, x, uxth, _, _
#define R_ospec_add_uxth64 12
#define HR_ospec_add_uxth64 1
#define K_ospec_add_uxth64 2
#define OPS_ospec_add_uxth64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_uxth64 4
#define F_ospec_add_sxtb64 f_alu_ext, add, x, sxtb, _, _
#define R_ospec_add_sxtb64 12
#define HR_ospec_add_sxtb64 1
#define K_ospec_add_sxtb64 2
#define OPS_ospec_add_sxtb64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_sxtb64 4
#define F_ospec_add_sxth64 f_alu_ext, add, x, sxth, _, _
#define R_ospec_add_sxth64 12
#define HR_ospec_add_sxth64 1
#define K_ospec_add_sxth64 2
#define OPS_ospec_add_sxth64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_sxth64 4
#define F_ospec_add_uxtb32 f_alu_ext, add, w, uxtb, _, _
#define R_ospec_add_uxtb32 12
#define HR_ospec_add_uxtb32 1
#define K_ospec_add_uxtb32 2
#define OPS_ospec_add_uxtb32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_uxtb32 4
#define F_ospec_add_uxth32 f_alu_ext, add, w, uxth, _, _
#define R_ospec_add_uxth32 12
#define HR_ospec_add_uxth32 1
#define K_ospec_add_uxth32 2
#define OPS_ospec_add_uxth32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_uxth32 4
#define F_ospec_add_sxtb32 f_alu_ext, add, w, sxtb, _, _
#define R_ospec_add_sxtb32 12
#define HR_ospec_add_sxtb32 1
#define K_ospec_add_sxtb32 2
#define OPS_ospec_add_sxtb32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_sxtb32 4
#define F_ospec_add_sxth32 f_alu_ext, add, w, sxth, _, _
#define R_ospec_add_sxth32 12
#define HR_ospec_add_sxth32 1
#define K_ospec_add_sxth32 2
#define OPS_ospec_add_sxth32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_add_sxth32 4
#define F_ospec_subr_lsr64 f_alu_reg_sh, sub, x, lsrv, _, _
#define R_ospec_subr_lsr64 12
#define HR_ospec_subr_lsr64 1
#define K_ospec_subr_lsr64 2
#define OPS_ospec_subr_lsr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr_lsr64 4
#define F_ospec_subr_lsr32 f_alu_reg_sh, sub, w, lsrv, _, _
#define R_ospec_subr_lsr32 12
#define HR_ospec_subr_lsr32 1
#define K_ospec_subr_lsr32 2
#define OPS_ospec_subr_lsr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr_lsr32 4
#define F_ospec_subr_asr64 f_alu_reg_sh, sub, x, asrv, _, _
#define R_ospec_subr_asr64 12
#define HR_ospec_subr_asr64 1
#define K_ospec_subr_asr64 2
#define OPS_ospec_subr_asr64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr_asr64 4
#define F_ospec_subr_asr32 f_alu_reg_sh, sub, w, asrv, _, _
#define R_ospec_subr_asr32 12
#define HR_ospec_subr_asr32 1
#define K_ospec_subr_asr32 2
#define OPS_ospec_subr_asr32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_subr_asr32 4
#define F_ospec_sub_uxtw64 f_alu_ext, sub, x, uxtw, _, _
#define R_ospec_sub_uxtw64 12
#define HR_ospec_sub_uxtw64 1
#define K_ospec_sub_uxtw64 2
#define OPS_ospec_sub_uxtw64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_uxtw64 4
#define F_ospec_sub_sxtw64 f_alu_ext, sub, x, sxtw, _, _
#define R_ospec_sub_sxtw64 12
#define HR_ospec_sub_sxtw64 1
#define K_ospec_sub_sxtw64 2
#define OPS_ospec_sub_sxtw64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_sxtw64 4
#define F_ospec_sub_uxtb64 f_alu_ext, sub, x, uxtb, _, _
#define R_ospec_sub_uxtb64 12
#define HR_ospec_sub_uxtb64 1
#define K_ospec_sub_uxtb64 2
#define OPS_ospec_sub_uxtb64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_uxtb64 4
#define F_ospec_sub_uxth64 f_alu_ext, sub, x, uxth, _, _
#define R_ospec_sub_uxth64 12
#define HR_ospec_sub_uxth64 1
#define K_ospec_sub_uxth64 2
#define OPS_ospec_sub_uxth64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_uxth64 4
#define F_ospec_sub_sxtb64 f_alu_ext, sub, x, sxtb, _, _
#define R_ospec_sub_sxtb64 12
#define HR_ospec_sub_sxtb64 1
#define K_ospec_sub_sxtb64 2
#define OPS_ospec_sub_sxtb64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_sxtb64 4
#define F_ospec_sub_sxth64 f_alu_ext, sub, x, sxth, _, _
#define R_ospec_sub_sxth64 12
#define HR_ospec_sub_sxth64 1
#define K_ospec_sub_sxth64 2
#define OPS_ospec_sub_sxth64 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_sxth64 4
#define F_ospec_sub_uxtb32 f_alu_ext, sub, w, uxtb, _, _
#define R_ospec_sub_uxtb32 12
#define HR_ospec_sub_uxtb32 1
#define K_ospec_sub_uxtb32 2
#define OPS_ospec_sub_uxtb32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_uxtb32 4
#define F_ospec_sub_uxth32 f_alu_ext, sub, w, uxth, _, _
#define R_ospec_sub_uxth32 12
#define HR_ospec_sub_uxth32 1
#define K_ospec_sub_uxth32 2
#define OPS_ospec_sub_uxth32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_uxth32 4
#define F_ospec_sub_sxtb32 f_alu_ext, sub, w, sxtb, _, _
#define R_ospec_sub_sxtb32 12
#define HR_ospec_sub_sxtb32 1
#define K_ospec_sub_sxtb32 2
#define OPS_ospec_sub_sxtb32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_sxtb32 4
#define F_ospec_sub_sxth32 f_alu_ext, sub, w, sxth, _, _
#define R_ospec_sub_sxth32 12
#define HR_ospec_sub_sxth32 1
#define K_ospec_sub_sxth32 2
#define OPS_ospec_sub_sxth32 {1, PAIR_OP_SLOT}, {2, PAIR_OP_SLOT}
#define NP_ospec_sub_sxth32 4
#define F_ospec_adcz64 f_adc_z, adc, x, 0, 0, _
#define R_ospec_adcz64 12
#define HR_ospec_adcz64 1
#define K_ospec_adcz64 1
#define OPS_ospec_adcz64 {1, PAIR_OP_SLOT}
#define NP_ospec_adcz64 2
#define F_ospec_adcz64_nf f_adc_z, adc, x, 0, 1, _
#define R_ospec_adcz64_nf 12
#define HR_ospec_adcz64_nf 1
#define K_ospec_adcz64_nf 1
#define OPS_ospec_adcz64_nf {1, PAIR_OP_SLOT}
#define NP_ospec_adcz64_nf 2
#define F_ospec_adcz32 f_adc_z, adc, w, 0, 0, _
#define R_ospec_adcz32 12
#define HR_ospec_adcz32 1
#define K_ospec_adcz32 1
#define OPS_ospec_adcz32 {1, PAIR_OP_SLOT}
#define NP_ospec_adcz32 2
#define F_ospec_adcz32_nf f_adc_z, adc, w, 0, 1, _
#define R_ospec_adcz32_nf 12
#define HR_ospec_adcz32_nf 1
#define K_ospec_adcz32_nf 1
#define OPS_ospec_adcz32_nf {1, PAIR_OP_SLOT}
#define NP_ospec_adcz32_nf 2
#define F_ospec_adcsz64 f_adc_z, adcs, x, 1, 0, _
#define R_ospec_adcsz64 12
#define HR_ospec_adcsz64 1
#define K_ospec_adcsz64 1
#define OPS_ospec_adcsz64 {1, PAIR_OP_SLOT}
#define NP_ospec_adcsz64 2
#define F_ospec_adcsz64_nf f_adc_z, adcs, x, 1, 1, _
#define R_ospec_adcsz64_nf 12
#define HR_ospec_adcsz64_nf 1
#define K_ospec_adcsz64_nf 1
#define OPS_ospec_adcsz64_nf {1, PAIR_OP_SLOT}
#define NP_ospec_adcsz64_nf 2
#define F_ospec_adcsz32 f_adc_z, adcs, w, 1, 0, _
#define R_ospec_adcsz32 12
#define HR_ospec_adcsz32 1
#define K_ospec_adcsz32 1
#define OPS_ospec_adcsz32 {1, PAIR_OP_SLOT}
#define NP_ospec_adcsz32 2
#define F_ospec_adcsz32_nf f_adc_z, adcs, w, 1, 1, _
#define R_ospec_adcsz32_nf 12
#define HR_ospec_adcsz32_nf 1
#define K_ospec_adcsz32_nf 1
#define OPS_ospec_adcsz32_nf {1, PAIR_OP_SLOT}
#define NP_ospec_adcsz32_nf 2
#define F_ospec_sbcz64 f_adc_z, sbc, x, 0, 0, _
#define R_ospec_sbcz64 12
#define HR_ospec_sbcz64 1
#define K_ospec_sbcz64 1
#define OPS_ospec_sbcz64 {1, PAIR_OP_SLOT}
#define NP_ospec_sbcz64 2
#define F_ospec_sbcz64_nf f_adc_z, sbc, x, 0, 1, _
#define R_ospec_sbcz64_nf 12
#define HR_ospec_sbcz64_nf 1
#define K_ospec_sbcz64_nf 1
#define OPS_ospec_sbcz64_nf {1, PAIR_OP_SLOT}
#define NP_ospec_sbcz64_nf 2
#define F_ospec_sbcz32 f_adc_z, sbc, w, 0, 0, _
#define R_ospec_sbcz32 12
#define HR_ospec_sbcz32 1
#define K_ospec_sbcz32 1
#define OPS_ospec_sbcz32 {1, PAIR_OP_SLOT}
#define NP_ospec_sbcz32 2
#define F_ospec_sbcz32_nf f_adc_z, sbc, w, 0, 1, _
#define R_ospec_sbcz32_nf 12
#define HR_ospec_sbcz32_nf 1
#define K_ospec_sbcz32_nf 1
#define OPS_ospec_sbcz32_nf {1, PAIR_OP_SLOT}
#define NP_ospec_sbcz32_nf 2
#define F_ospec_sbcsz64 f_adc_z, sbcs, x, 1, 0, _
#define R_ospec_sbcsz64 12
#define HR_ospec_sbcsz64 1
#define K_ospec_sbcsz64 1
#define OPS_ospec_sbcsz64 {1, PAIR_OP_SLOT}
#define NP_ospec_sbcsz64 2
#define F_ospec_sbcsz64_nf f_adc_z, sbcs, x, 1, 1, _
#define R_ospec_sbcsz64_nf 12
#define HR_ospec_sbcsz64_nf 1
#define K_ospec_sbcsz64_nf 1
#define OPS_ospec_sbcsz64_nf {1, PAIR_OP_SLOT}
#define NP_ospec_sbcsz64_nf 2
#define F_ospec_sbcsz32 f_adc_z, sbcs, w, 1, 0, _
#define R_ospec_sbcsz32 12
#define HR_ospec_sbcsz32 1
#define K_ospec_sbcsz32 1
#define OPS_ospec_sbcsz32 {1, PAIR_OP_SLOT}
#define NP_ospec_sbcsz32 2
#define F_ospec_sbcsz32_nf f_adc_z, sbcs, w, 1, 1, _
#define R_ospec_sbcsz32_nf 12
#define HR_ospec_sbcsz32_nf 1
#define K_ospec_sbcsz32_nf 1
#define OPS_ospec_sbcsz32_nf {1, PAIR_OP_SLOT}
#define NP_ospec_sbcsz32_nf 2

// ---- generated: the pairs ----
FUSE2(ospec_adcs64, ospec_umulh)
FUSE2(mov_const, load64_fast)
FUSE2(ospec_umulh, ospec_adcs64)
FUSE2(ospec_ror64, ospec_addr64)
FUSE2(load64_fast, load64_fast)
FUSE2(ldp64_fast, ldp64_fast)
FUSE2(ospec_addr64, ospec_ror64)
FUSE2(ospec_mul64, ospec_adcs64)
FUSE2(load64_fast, ospec_addi64)
FUSE2(ospec_addr64, ospec_eorr64)
FUSE2(ospec_eorr32, ospec_addr32)
FUSE2(ospec_addr32, ospec_eorr32)
FUSE2(mov_const, mov_const)
FUSE2(ospec_addr64, ospec_addr64)
FUSE2(ldp64_post, ret_cached)
FUSE2(ospec_adcs64, ospec_mul64)
FUSE2(ospec_eorr64, ospec_ror64)
FUSE2(ospec_addi64, stp64_fast)
FUSE2(vspec_umov64, vspec_umov64)
FUSE2(stp64_fast, vspec_umov64)
FUSE2(ospec_eorr64, ospec_eorr64)
FUSE2(load64_fast, store64_fast)
FUSE2(ospec_eorr64, ospec_addr64)
FUSE2(ospec_addi64, br_cached)
FUSE2(stp64_pre, ospec_addi64)
FUSE2(ospec_andr64, ospec_andr64)
FUSE2(ldp64_fast, ldp64_post)
FUSE2(ospec_ror64, ospec_eorr64)
FUSE2(vspec_umov64, bl)
FUSE2(ospec_adcs64_nf, ospec_adcs64_nf)
FUSE2(ospec_addi64, store64_fast)
FUSE2(load64_fast, vspec_umov64)
FUSE2(vspec_umov64, stp64_fast)
FUSE2(load64_fast, cbz_x)
FUSE2(vspec_umov64, load64_fast)
FUSE2(vspec_umov64, mov_const)
FUSE2(store64_fast, store64_fast)
FUSE2(mov_const, ospec_addi64)
FUSE2(load64_fast, ospec_addr64)
FUSE2(ospec_addsr64, ospec_umulh)
FUSE2(store64_fast, mov_const)
FUSE2(load64_fast, mov_const)
FUSE2(ospec_addi64, load64_fast)
FUSE2(stp64_fast, stp64_fast)
FUSE2(stp64_fast, ospec_addi64)
FUSE2(ospec_adcs64, ospec_adcs64_nf)
FUSE2(ospec_ubfm32, ospec_mul32)
FUSE2(ospec_mul32, fused_cmpr32_ls)
FUSE2(ospec_mul64, ospec_addsr64)
FUSE2(store64_fast, load64_fast)
FUSE2(stp64_fast, mov_const)
FUSE2(store64_fast, vspec_umov64)
FUSE2(vspec_umov64, ospec_addi64)
FUSE2(load64_fast, load32_fast)
FUSE2(load64_fast, stp64_fast)
FUSE2(load64_fast, load8_fast)
FUSE2(load64_fast, cbnz_x)
FUSE2(ospec_addsr64, ospec_mul64)
FUSE2(ospec_ubfm32, ospec_ubfm32)
FUSE2(mov_const, bl)
FUSE2(ospec_addi64, ospec_mul64)
FUSE2(load8_fast, cbnz_w_bk)
FUSE2(load32_fast, mov_const)
FUSE2(vspec_umov32, vspec_umov64)
FUSE2(load32_fast, load64_fast)
FUSE2(ospec_addi64, mov_const)
FUSE2(ospec_addi64, ospec_addi64)
FUSE2(ospec_addi64, fused_cmpi32_hi)
FUSE2(load64_fast, ldp64_fast)
FUSE2(ospec_mul64, ospec_addi64)
FUSE2(ospec_adcs64_nf, cbnz_x_bk)
FUSE2(stp64_fast, vspec_umov32)
FUSE2(ospec_ubfm32, ospec_andi32)
FUSE2(ospec_addi32, ospec_addi64)
FUSE2(vspec_umov64, ldp64_fast)
FUSE2(mov_const, store64_fast)
FUSE2(mov_const, b)
FUSE2(mov_const, bcond_ne)
FUSE2(load64_fast, ospec_ubfm64)
FUSE2(ospec_addi64, b)
FUSE2(load64_fast, ospec_subsr64)
FUSE2(load8_fast, cbz_w)
FUSE2(ospec_ubfm64, ospec_addr32)
FUSE2(vspec_umov64, vspec_umov32)
FUSE2(ospec_subsr64, mov_const)
FUSE2(load64_rxl, ospec_andr64)
FUSE2(ospec_andr64, ospec_orrr64)
FUSE2(ospec_subi32, load64_rxl)
FUSE2(load64_rxl, ospec_subi32)
FUSE2(store64_fast, b)
FUSE2(ospec_addi64, ospec_orrr64)
FUSE2(ospec_orrr64, ospec_andr64)
FUSE2(ospec_orrr64, fused_cmpr32_ne)
FUSE2(ospec_orrr64, ospec_orrr64)
FUSE2(load64_fast, ospec_eorr32)
FUSE2(ospec_andr64, ospec_addi32)
FUSE2(ospec_sbfm64, ospec_orrr64)
FUSE2(ospec_orrr64, ospec_sbfm64)
FUSE2(ospec_eorr32, load64_rxl)
FUSE2(load64_rxl, ospec_eonr32)
FUSE2(ospec_eonr32, load64_rxl)
FUSE2(load32_fast, load32_fast)
FUSE2(load64_fast, ldp64_post)
FUSE2(load8_fast, ospec_addi64)
FUSE2(vspec_umov64, load8_fast)
FUSE2(ospec_mul64, ospec_mul64)
FUSE2(vspec_umov64, cbz_x)
FUSE2(load8_fast, load64_fast)
FUSE2(ospec_addi64, bl)
FUSE2(ospec_addr64, load64_fast)
FUSE2(stp64_pre, mov_const)
FUSE2(mov_const, load32_fast)
FUSE2(ospec_umulh, load64_rxl)
FUSE2(store32_fast, load64_fast)
FUSE2(mov_const, stp64_fast)
FUSE2(store64_fast, bl)
FUSE2(load16_rxu, mov_const)
FUSE2(load16_rxl, fused_cmpr32_hi)
FUSE2(load64_fast, ospec_subr64)
FUSE2(ospec_umulh, ospec_adcz64)
FUSE2(vspec_umov64, store64_fast)
FUSE2(load64_fast, ospec_andi64)
FUSE2(mov_const, load8_fast)
FUSE2(ospec_addi64, vspec_umov64)
FUSE2(load64_rxl, ospec_adcs64)
FUSE2(ldp64_fast, ospec_addi64)
FUSE2(load64_fast, ret_cached)
FUSE2(load32_fast, cbnz_w)
FUSE2(stp64_pre, vspec_umov64)
FUSE2(mov_const, ospec_add_sxth64)
FUSE2(ospec_add_sxth64, br_cached)
FUSE2(load32_fast, vspec_umov64)
FUSE2(ospec_addr64, store64_fast)
FUSE2(store64_fast, ospec_addi64)
FUSE2(load8_fast, cbnz_w)
FUSE2(load16_rxu, fused_cmpr32_hi)
FUSE2(mov_const, vspec_umov64)
FUSE2(load8_fast, fused_cmpi32_eq)
FUSE2(ospec_subr32, ospec_subr_lsr32)
FUSE2(load64_fast, tb_z)
FUSE2(mov_const, ldp64_fast)
FUSE2(load64_fast, store32_fast)
FUSE2(vspec_umov32, stp64_fast)
FUSE2(ospec_addi32, ospec_subr32)
FUSE2(stp64_fast, load64_fast)
FUSE2(ospec_addi64, fused_cmpr64_ne)
FUSE2(load32_fast, cbz_w)
FUSE2(ospec_ubfm64, ospec_addr64)
FUSE2(load8_fast, vspec_umov64)
FUSE2(mov_const, ret_cached)
FUSE2(ospec_addi32, store32_fast)
FUSE2(ospec_subi64, store64_fast)
FUSE2(load64_fast, fused_cmpi32_ne)
FUSE2(vspec_umov64, load32_fast)
FUSE2(store64_fast, load8_fast)
FUSE2(load64_rxs, br_cached)
FUSE2(ospec_andi32, load64_rxs)
FUSE2(ospec_subr32, ospec_ubfm64)
FUSE2(ospec_mul64, ospec_adc64)
FUSE2(vspec_umov64, fused_cmpi32_eq)
FUSE2(store64_fast, ldp64_fast)
FUSE2(ospec_umulh, ospec_mul64)
FUSE2(load64_fast, vspec_umov32)
FUSE2(load64_fast, b)
FUSE2(vspec_umov32, mov_const)
FUSE2(load32_fast, tb_nz)
FUSE2(store64_fast, cbz_x)
FUSE2(ospec_subr32, b)
FUSE2(ldp64_fast, vspec_umov64)
FUSE2(vspec_umov32, ldp64_fast)
FUSE2(vspec_umov64, b)
FUSE2(ospec_adc64, ospec_mul64)
FUSE2(load8_fast, tb_nz)
FUSE2(ospec_addi64, fused_cmpi32_ne)
FUSE2(ospec_addr32, store16_fast)
FUSE2(mov_const, store32_fast)
FUSE2(ospec_subr_lsr32, ospec_addi32)
FUSE2(load8_fast, load8_fast)
FUSE2(stp64_fast, store64_fast)
FUSE2(load8_fast, ospec_andi32)
FUSE2(ospec_subi64, load64_fast)
FUSE2(ldp64_fast, load64_fast)
FUSE2(load64_fast, bl)
FUSE2(ldp64_fast, ospec_adcs64)
FUSE2(load64_fast, blr_cached)
FUSE2(load64_fast, cbz_x_bk)
FUSE2(ospec_addi64, blr_cached)
FUSE2(ospec_addi64, fused_cmpi32_eq)
FUSE2(store64_fast, store32_fast)
FUSE2(load8_fast, ospec_addr32)
FUSE2(load64_fast, tb_nz)
FUSE2(vspec_umov32, load64_fast)
FUSE2(store32_fast, bl)
FUSE2(vspec_umov32, load8_fast)
FUSE2(load64_fast, ospec_subi64)
FUSE2(ldp64_fast, mov_const)
FUSE2(ospec_andi32, mov_const)
FUSE2(ospec_andi32, ospec_ubfm32)
FUSE2(ospec_addr32, cbz_w)
FUSE2(ospec_addsr64, ospec_subr64)
FUSE2(load8_fast, mov_const)
FUSE2(load64_rxl, load64_fast)
FUSE2(load64_fast, load16_fast)
FUSE2(store32_fast, store64_fast)
FUSE2(ospec_adcs64, ldp64_fast)
FUSE2(ospec_addi64, load32_fast)
FUSE2(load64_fast, load16_rxu)
FUSE2(load8_fast, fused_cmpr32_ne)
FUSE2(ospec_addr32, ospec_addr32)
FUSE2(load32_fast, store32_fast)
FUSE2(ospec_addr32, cbnz_w_bk)
FUSE2(ospec_adcz64, ospec_mul64)
FUSE2(load32_fast, ospec_andr32)
FUSE2(load64_fast, ospec_andi32)
FUSE2(store16_rxl, ospec_ubfm64)
FUSE2(vspec_umov64, ospec_addr64)
FUSE2(ospec_madd32, ospec_addr32)
FUSE2(ospec_mul64, ospec_subi64)
FUSE2(ospec_addr_lsl64, load64_fast)
FUSE2(ospec_addi64, ospec_subi64)
FUSE2(ospec_addr64, fused_cmpr64_cs)
FUSE2(ospec_subi32, fused_cmpi32_ls)
FUSE2(ospec_adcs64_nf, ldp64_fast)
FUSE2(ospec_addr32, store16_rxl)
FUSE2(ospec_addi64, fused_cmpr64_eq)
FUSE2(ospec_ubfm64, ospec_addr_lsl64)
FUSE2(load64_fast, cbnz_x_bk)
FUSE2(ospec_andi32, fused_cmpi32_eq)
FUSE2(load8_fast, tb_z)
FUSE2(ospec_mul64, ospec_adcz64)
FUSE2(store64_fast, fused_cmpi32_hi)
FUSE2(load32_fast, ospec_andi32)
FUSE2(load64_rxl, ospec_addsr64)
FUSE2(store64_fast, load32_fast)
FUSE2(ospec_subi64, ospec_mul64)
FUSE2(ospec_adcs64_nf, ospec_adc64_nf)
FUSE2(ospec_adc64_nf, cbnz_x_bk)
FUSE2(ospec_mul64, ospec_andi64)
FUSE2(ospec_andi64, ospec_mul64)
FUSE2(store32_fast, b)
FUSE2(ospec_sbfm64, mov_const)
FUSE2(load32_fast, ospec_addi64)
FUSE2(load8_rxs, vspec_umov64)
FUSE2(store16_fast, ospec_add_uxtw64)
FUSE2(ospec_sbfm32, cbz_w)
FUSE2(vspec_umov32, b)
FUSE2(load64_fast, ospec_ubfm32)
FUSE2(ospec_ubfm64, ospec_addi64)
FUSE2(ospec_addi32, ospec_andr32)
FUSE2(ospec_ubfm64, load16_rxu)
FUSE2(load32_fast, store64_fast)
FUSE2(ospec_subi64, ospec_subi64)
FUSE2(load64_fast, load64_rxl)
FUSE2(ospec_subi32, ospec_andi32)
FUSE2(load64_rxl, cbz_x)
FUSE2(ospec_addr32, bcond_ne)
FUSE2(load8_rxu, load8_rxu)
FUSE2(ospec_addr_lsl32, ospec_addr32)
FUSE2(ospec_addi64, ldp64_fast)
FUSE2(ospec_add_uxtw64, load16_rxu)
FUSE2(ospec_ror64, load64_fast)
FUSE2(vspec_umov32, bl)
FUSE2(ospec_addi64, fused_cmpi64_ne)
FUSE2(store64_fast, ret_cached)
FUSE2(load64_fast, ospec_eorr64)
FUSE2(ospec_andi32, tb_z)
FUSE2(ospec_subr64, ospec_adcs64)
FUSE2(ospec_sbfm32, ospec_addi32)
FUSE2(ospec_subr32, ospec_sbfm32)
FUSE2(ospec_ubfm32, ospec_subsi32)
FUSE2(ospec_subsi32, ospec_subr32)
FUSE2(ospec_andr32, ospec_addr_lsl32)
FUSE2(ospec_addi64, ospec_addr64)
FUSE2(vspec_umov32, vspec_umov32)
FUSE2(ospec_subi64, load32_fast)
FUSE2(ospec_andi64, load64_fast)
FUSE2(load16_fast, load64_fast)
FUSE2(vspec_umov32, ospec_addi64)
FUSE2(ospec_andi32, store32_fast)
FUSE2(ospec_addr64, ospec_addi64)
FUSE2(ldp64_fast, vspec_umov32)
FUSE2(ospec_addi32, fused_cmpr32_eq)
FUSE2(load32_rxl, ospec_addr32)
FUSE2(store32_fast, vspec_umov64)
FUSE2(ospec_addr64, load8_rxl)
FUSE2(vspec_umov64, store32_fast)
FUSE2(load32_fast, stp64_fast)
FUSE2(ospec_addr64, bl)
FUSE2(ospec_mul64, ospec_umulh)
FUSE2(ospec_subr64, fused_cmpi64_hi)
FUSE2(ospec_subr64, store64_fast)
FUSE2(ospec_addr64, load64_rxl)
FUSE2(ospec_addi64, ospec_ubfm32)
FUSE2(load32_fast, tb_z)
FUSE2(mov_const, ospec_orrr32)
FUSE2(store32_fast, mov_const)
FUSE2(load32_fast, ospec_eorr32)
FUSE2(load64_fast, ospec_addi32)
FUSE2(vspec_umov64, blr_cached)
FUSE2(ospec_addr_lsl64, load16_rxl)
FUSE2(load8_fast, fused_cmpi32_ne)
FUSE2(ospec_ror64, ospec_ror64)
FUSE2(ospec_eorr64, load64_fast)
FUSE2(ospec_subr32, ospec_subr32)
FUSE2(ospec_andi32, ospec_orr_lsl32)
FUSE2(load16_fast, ospec_addi64)
FUSE2(ospec_ubfm32, load16_fast)
FUSE2(ospec_andr64, ospec_add_uxth64)
FUSE2(load16_fast, load16_rxs)
FUSE2(load8_rxu, fused_cmpr32_eq)
FUSE2(store32_fast, store32_fast)
FUSE2(ospec_andi32, ospec_andi32)
FUSE2(store32_fast, load32_fast)
FUSE2(ospec_addi64, load8_fast)
FUSE2(ospec_addr64, store64_rxl)
FUSE2(load8_fast, cbz_w_bk)
FUSE2(load32_fast, fused_cmpi32_hi)
FUSE2(load8_fast, ospec_addr_lsl64)
FUSE2(store32_fast, load8_fast)
FUSE2(mov_const, ospec_andi32)
FUSE2(ospec_ubfm32, ospec_orr_lsl32)
FUSE2(mov_const, ospec_andr32)
FUSE2(ospec_orr_lsl32, ospec_ubfm32)
FUSE2(ospec_and_lsl32, ospec_addr32)
FUSE2(stp64_fast, ldp64_fast)
FUSE2(ospec_addi64, load16_fast)
FUSE2(store8_rxl, ospec_addi64)
FUSE2(load16_fast, mov_const)
FUSE2(ospec_addi64, ospec_subr64)
FUSE2(load64_fast, fused_cmpi32_eq)
FUSE2(ldp64_fast, ospec_ubfm32)
FUSE2(ospec_ubfm64, load16_rxl)
FUSE2(load16_rxs, load8_fast)
FUSE2(ospec_add_uxth64, cbnz_w)
FUSE2(loads8_64_fast, tb_z)
FUSE2(loads8_32_fast, ospec_andi32)
FUSE2(ospec_orrr32, b)
FUSE2(mov_const, ospec_ubfm64)
FUSE2(ospec_addr64, load16_rxl)
FUSE2(mov_const, cbz_x)
FUSE2(ospec_adcs64, load64_rxl)
FUSE2(mov_const, ospec_addr64)
FUSE2(ospec_subr32, mov_const)
FUSE2(stp64_fast, load32_fast)
FUSE2(ospec_addr64, cbz_x)
FUSE2(mov_const, vspec_umov32)
FUSE2(ospec_andi32, fused_cmpi32_hi)
FUSE2(mov_const, ospec_subr32)
FUSE2(vspec_umov32, store64_fast)
FUSE2(ospec_addsr64, ospec_adcs64_nf)
FUSE2(ospec_orr_lsl32, tb_z)
FUSE2(ospec_subi32, store32_fast)
FUSE2(ospec_andi32, load64_fast)
FUSE2(ospec_addr64, stp64_fast)
FUSE2(ospec_addr64, vspec_umov64)
FUSE2(ospec_andi32, ospec_orrr32)
FUSE2(vspec_umov64, ldp64_post)
FUSE2(ospec_ubfm64, load64_rxl)
FUSE2(ospec_eorr32, ospec_ubfm64)
FUSE2(store16_fast, ospec_addr_lsl64)
FUSE2(vspec_umov64, cbnz_x_bk)
FUSE2(load8_fast, ospec_subi32)
FUSE2(ospec_addi64, load32_rxl)
FUSE2(ospec_ubfm64, load64_fast)
FUSE2(load16_fast, ospec_ubfm32)
FUSE2(load32_fast, ospec_addr32)
FUSE2(ospec_addr64, mov_const)
FUSE2(ldp64_post, b)
FUSE2(stp64_fast, bl)
FUSE2(ospec_addr_lsl64, load32_fast)
FUSE2(load8_rxl, load8_rxl)
FUSE2(store8_fast, store8_fast)
FUSE2(store32_fast, ospec_addi64)
FUSE2(ospec_sbcs64, ldp64_fast)
FUSE2(ldp64_fast, b)
FUSE2(ldp64_post, mov_const)
FUSE2(load32_fast, fused_cmpi32_eq)
FUSE2(load16_fast, store64_fast)
FUSE2(load64_fast, ospec_sbfm64)
FUSE2(ospec_ubfm64, mov_const)
FUSE2(load64_fast, load16_rxl)
FUSE2(ldp64_fast, store64_fast)
FUSE2(load32_fast, tb_z_bk)
FUSE2(ospec_orrr32, store32_fast)
FUSE2(ospec_sbfm32, b)
FUSE2(ospec_addr32, ospec_sbfm32)
FUSE2(ldp64_fast, ospec_mul64)
FUSE2(ospec_addi64, ospec_ubfm64)
FUSE2(vspec_umov64, ospec_subi64)
FUSE2(load8_fast, load32_rxs)
FUSE2(ospec_ubfm32, ospec_ubfm64)
FUSE2(ospec_andi64, fused_cmpr64_cs)
FUSE2(ospec_ubfm64, load32_rxl)
FUSE2(ospec_andr32, ospec_ubfm64)
FUSE2(ospec_subi64, ospec_ubfm64)
FUSE2(load8_fast, load32_rxl)
FUSE2(load16_fast, fused_cmpr32_hi)
FUSE2(store64_fast, vspec_umov32)
FUSE2(ospec_ubfm64, ospec_subr32)
FUSE2(load16_fast, vspec_umov64)
FUSE2(store32_fast, vspec_umov32)
FUSE2(load16_fast, fused_cmpi32_eq)
FUSE2(ospec_addi64, store32_fast)
FUSE2(store64_fast, ospec_addr64)
FUSE2(ospec_addr64, load8_fast)
FUSE2(ospec_addi64, load64_rxl)
FUSE2(stp64_fast, load8_fast)
FUSE2(load16_fast, ospec_subi32)
FUSE2(ospec_addi64, fused_cmpr64_ls)
FUSE2(ospec_add_uxtw64, store64_fast)
FUSE2(load8_fast, load16_fast)
FUSE2(ospec_addi32, fused_cmpr32_lt)
FUSE2(load64_fast, loads32_64_fast)
FUSE2(ldp64_fast, ospec_addr64)
FUSE2(ospec_andi32, ospec_subi32)
FUSE2(ldp64_fast, ospec_subr64)
FUSE2(ldp64_fast, stp64_fast)
FUSE2(ospec_addsr64, store64_fast)
FUSE2(ospec_ubfm64, stp64_fast)
FUSE2(ospec_addr_lsl64, ospec_addi64)
FUSE2(ldp64_fast, ospec_sbcs64)
FUSE2(vspec_umov32, ospec_andi32)
FUSE2(ospec_andr64, tb_nz)
FUSE2(vspec_umov64, load16_fast)
FUSE2(ospec_addi32, load64_fast)
FUSE2(store8_fast, load64_fast)
FUSE2(ospec_sbfm64, ospec_addr64)
FUSE2(ospec_ubfm32, load64_rxl)
FUSE2(store64_fast, stp64_fast)
FUSE2(ospec_addr_lsl64, ospec_addi32)
FUSE2(load64_rxl, store64_fast)
FUSE2(store32_fast, ldp64_fast)
FUSE2(ospec_andi32, fused_cmpi32_ls)
FUSE2(ospec_addr32, mov_const)
FUSE2(ospec_addi64, ospec_andi64)
FUSE2(ospec_ubfm64, store16_fast)
FUSE2(ospec_andi32, tb_nz)
FUSE2(ospec_bicr64, ospec_bicr64)
FUSE2(load32_fast, fused_cmpi32_ne)
FUSE2(ospec_addr64, ospec_eor_ror64)
FUSE2(ospec_addi32, load32_fast)
FUSE2(store64_rxl, fused_cmpr64_hi)
FUSE2(ospec_andi32, ospec_ubfm64)
FUSE2(ospec_addr32, ospec_addi32)
FUSE2(ospec_addi64, ospec_addr_lsl64)
FUSE2(ospec_ubfm32, ospec_addr_lsl32)
FUSE2(stp64_fast, ospec_ubfm32)
FUSE2(vspec_umov64, ospec_ubfm64)
FUSE2(ospec_addi32, ospec_sbfm64)
FUSE2(store16_fast, load16_rxl)
FUSE2(ospec_mul64, ldp64_post)
FUSE2(store64_fast, ospec_orri64)
FUSE2(load32_fast, ospec_bicr32)
FUSE2(mov_const, store8_fast)
FUSE2(store64_fast, ospec_ubfm32)
FUSE2(ospec_add_sxtw64, ospec_addi64)
FUSE2(ospec_addr_lsl32, ospec_subi64)
FUSE2(ospec_bicr32, ospec_ubfm32)
FUSE2(load8_fast, store32_fast)
FUSE2(vspec_umov64, ospec_andi32)
FUSE2(ldp64_post, ospec_umulh)
FUSE2(stp64_fast, ospec_adcs64)
FUSE2(vspec_umov32, ospec_addi32)
FUSE2(load64_fast, load8_rxs)
FUSE2(load64_fast, cbz_w)
FUSE2(vspec_umov64, fused_cmpr64_eq)
FUSE2(ospec_andi64, ospec_orrr64)
FUSE2(ospec_addi32, vspec_umov32)
FUSE2(ospec_addi64, ospec_addi32)
FUSE2(ospec_addr64, load32_fast)
FUSE2(ospec_addi32, ospec_ubfm64)
FUSE2(ospec_sbcs64, stp64_fast)
FUSE2(ospec_ubfm32, tb_z)
FUSE2(load64_fast, ospec_addr_lsl64)
FUSE2(load16_fast, cbz_w)
FUSE2(ospec_subr_lsr32, ospec_subr32)
FUSE2(ospec_subr64, ospec_sbfm64)
FUSE2(ospec_umulh, stp64_fast)
FUSE2(stp64_fast, ospec_subi64)
FUSE2(ospec_andi64, load32_fast)
FUSE2(vspec_umov64, ospec_subi32)
FUSE2(ospec_andi32, store8_fast)
FUSE2(loads8_32_fast, load32_fast)
FUSE2(store64_fast, loads8_32_fast)
FUSE2(vspec_umov32, load32_fast)
FUSE2(store64_fast, fused_cmpr64_ls)
FUSE2(ospec_ubfm64, ospec_andi32)
FUSE2(ospec_andi32, vspec_umov64)
FUSE2(stp64_fast, ospec_sbcs64)
FUSE2(ospec_umulh, ospec_addsr64)
FUSE2(ospec_subr64, ldp64_fast)
FUSE2(ospec_subr32, fused_cmpr32_hi)
FUSE2(store64_fast, store16_rxl)
FUSE2(ospec_ubfm32, load64_fast)
FUSE2(load32_fast, ospec_addi32)
FUSE2(store16_fast, mov_const)
FUSE2(ospec_addr32, load32_fast)
FUSE2(load16_fast, ospec_andi32)
FUSE2(ospec_andr32, fused_cmpr32_ne)
FUSE2(ospec_ubfm64, vspec_umov32)
FUSE2(ospec_subi64, load8_fast)
FUSE2(vspec_umov32, cbnz_w)
FUSE2(ospec_addi64, tb_nz)
FUSE2(ospec_addr_lsl32, ospec_addr_lsl64)
FUSE2(load64_fast, ospec_ror64)
FUSE2(load32_fast, b)
FUSE2(load64_rxs, cbz_x)
FUSE2(store32_fast, fused_cmpi32_hi)
FUSE2(ospec_subi64, mov_const)
FUSE2(vspec_umov32, ospec_addr64)
FUSE2(ospec_bicr64, ospec_eorr64)
FUSE2(store64_fast, ospec_subi32)
FUSE2(load8_fast, store64_fast)
FUSE2(store64_fast, ospec_subi64)
FUSE2(vspec_umov64, cbnz_w)
FUSE2(ospec_subi64, cbz_w)
FUSE2(load8_rxl, fused_cmpr32_eq)
FUSE2(ospec_addi32, fused_cmpr32_ne)
FUSE2(ospec_addr64, ldp64_fast)
FUSE2(store64_fast, cbnz_x)
FUSE2(store64_fast, tb_nz)
FUSE2(mov_const, store16_fast)
FUSE2(ospec_subi64, fused_cmpi64_hi)
FUSE2(ospec_subi32, load64_fast)
FUSE2(load32_fast, ospec_subi32)
FUSE2(load64_fast, bcond_ne)
FUSE2(ospec_andr32, ospec_andr32)
FUSE2(load16_fast, load16_fast)
FUSE2(vspec_umov64, cbnz_x)
FUSE2(ospec_addr64, tb_nz)
FUSE2(store64_fast, ospec_andi64)
FUSE2(load16_fast, fused_cmpi32_ne)
FUSE2(load8_rxs, fused_cmpi32_ls)
FUSE2(vspec_umov32, cbz_w)
FUSE2(mov_const, load16_fast)
FUSE2(ospec_andr32, fused_cmpi32_eq)
FUSE2(load32_fast, cbnz_w_bk)
FUSE2(ospec_subr64, ospec_subr64)
FUSE2(stp64_fast, ospec_addr64)
FUSE2(ospec_subr32, store32_fast)
FUSE2(ospec_addi64, fused_cmpr64_hi)
FUSE2(ospec_subi64, ospec_andi64)
FUSE2(store32_fast, cbz_w)
FUSE2(stp64_fast, ospec_andi32)
FUSE2(ospec_ubfm64, load64_rxs)
FUSE2(load32_fast, cbz_w_bk)
FUSE2(ospec_addi64, load8_rxl)
FUSE2(ospec_addr32, store32_fast)
FUSE2(vspec_umov32, ospec_ubfm64)
FUSE2(load32_fast, fused_cmpi32_le)
FUSE2(ospec_sbfm64, load64_fast)
FUSE2(ospec_add_uxtw64, ospec_addr64)
FUSE2(mov_const, ldp64_post)
FUSE2(ospec_subi32, ospec_subi64)
FUSE2(load64_rxs, ospec_subi64)
FUSE2(ospec_addi64, cbz_w)
FUSE2(ospec_addr32, ospec_addi64)
FUSE2(load32_rxl, load32_rxl)
FUSE2(ospec_ubfm64, load32_fast)
FUSE2(ospec_orri32, store8_fast)
FUSE2(ospec_subr64, load8_fast)
FUSE2(load32_rxl, ospec_subr64)
FUSE2(store32_fast, tb_z)
FUSE2(ospec_umull, ospec_addr64)
FUSE2(ldp64_fast, load8_fast)
FUSE2(store64_fast, tb_z)
FUSE2(vspec_umov64, br_cached)
FUSE2(load32_fast, ospec_andi64)
FUSE2(load32_fast, ospec_addr_lsl64)
FUSE2(store32_fast, cbnz_w)
FUSE2(store16_fast, b)
FUSE2(ospec_subr64, load32_fast)
FUSE2(ospec_sub_uxtw64, load8_fast)
FUSE2(store16_fast, load64_fast)
FUSE2(ospec_andi64, store64_fast)
FUSE2(ospec_ubfm64, ospec_addr_lsl32)
FUSE2(ospec_addr_lsl32, ospec_subr_lsl32)
FUSE2(ospec_andr32, store32_fast)
FUSE2(load64_fast, ospec_addsr64)
FUSE2(ospec_addi32, mov_const)
FUSE2(ospec_addr64, fused_cmpr64_ne)
FUSE2(ospec_subi64, ospec_addr64)
FUSE2(ospec_subr64, mov_const)
FUSE2(load64_rxl, bl)
FUSE2(ospec_umull, ospec_ubfm64)
FUSE2(load64_fast, ospec_subi32)
FUSE2(mov_const, ospec_addi32)
FUSE2(ospec_andi32, ospec_addr64)
FUSE2(ospec_subr32, ospec_eorr32)
FUSE2(ospec_addr32, ospec_and_lsl32)
FUSE2(ospec_andi32, fused_cmpi32_ne)
FUSE2(ospec_eor_ror64, ospec_addr64)
