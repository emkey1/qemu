/*
 * AOK gadgets for RISC-V guests: the translator.
 *
 * Turns RV64 integer, load/store and branch instructions into a gadget
 * stream (include/accel/tcg/aok.h). It translates what it is sure of and
 * stops in front of anything else -- system and CSR instructions, floating
 * point, atomics, vectors, an encoding it does not know, a disabled
 * extension -- so that the next TB starts there and TCG translates it,
 * raising whatever exception is due. A TB whose first insn is one of those
 * is declined outright.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "accel/tcg/aok.h"
#include "accel/tcg/cpu-ldst-common.h"
#include "aok-riscv.h"

#define G(name) aok_gadget_rv_##name
#define DECL(name) void G(name)(void);

/* target/riscv/tcg/aok/gadgets.S */
#define ALU_BOTH(X) \
    X(add) X(and) X(or) X(xor) X(sll) X(srl) X(sra) X(slt) X(sltu) \
    X(addw) X(sllw) X(srlw) X(sraw) X(ror) X(rorw) \
    X(bclr) X(bset) X(binv) X(bext)
#define ALU_RR(X) \
    X(sub) X(subw) X(mul) X(mulw) X(mulh) X(mulhu) X(mulhsu) \
    X(div) X(divu) X(rem) X(remu) X(divw) X(divuw) X(remw) X(remuw) \
    X(sh1add) X(sh2add) X(sh3add) X(add_uw) \
    X(sh1add_uw) X(sh2add_uw) X(sh3add_uw) \
    X(andn) X(orn) X(xnor) X(max) X(maxu) X(min) X(minu) \
    X(rol) X(rolw) X(czero_eqz) X(czero_nez)
#define ALU_RI(X) \
    X(slli_uw) X(clz) X(clzw) X(ctz) X(ctzw) X(cpop) X(cpopw) \
    X(sext_b) X(sext_h) X(zext_h) X(rev8) X(orc_b)
#define DECL_RR(n) DECL(n##_rr)
#define DECL_RI(n) DECL(n##_ri)
ALU_BOTH(DECL_RR) ALU_BOTH(DECL_RI) ALU_RR(DECL_RR) ALU_RI(DECL_RI)
DECL(li) DECL(pcrel) DECL(fence) DECL(jalr)
DECL(lb) DECL(lbu) DECL(lh) DECL(lhu) DECL(lw) DECL(lwu) DECL(ld)
DECL(sb) DECL(sh) DECL(sw) DECL(sd)
DECL(beq) DECL(bne) DECL(blt) DECL(bge) DECL(bltu) DECL(bgeu)

typedef void (*Gadget)(void);

/*
 * The softmmu slow paths of the load and store gadgets. Called with the
 * insn's pc and opcode: an exception raised in here unwinds nothing, so the
 * two things riscv_restore_state_to_opc would have recovered are stored
 * first. The mmu index is the one the TB was translated for, since nothing
 * a stream executes can change it.
 */
#define OI(env, mop) make_memop_idx(mop, riscv_env_mmu_index(env, false))

static inline void aok_rv_sync(CPURISCVState *env, uint64_t pc, uint64_t insn)
{
    env->pc = pc;
    env->bins = insn;
    env->excp_uw2 = 0;
}

#define LOAD_HELPER(name, type, fn, mop)                                    \
uint64_t aok_rv_helper_##name(CPURISCVState *env, uint64_t addr,           \
                              uint64_t pc, uint64_t insn);                  \
uint64_t aok_rv_helper_##name(CPURISCVState *env, uint64_t addr,           \
                              uint64_t pc, uint64_t insn)                   \
{                                                                           \
    aok_rv_sync(env, pc, insn);                                             \
    return (type)fn(env, addr, OI(env, mop), 0);                            \
}
LOAD_HELPER(lb,  int8_t,   cpu_ldb_mmu, MO_UB)
LOAD_HELPER(lbu, uint8_t,  cpu_ldb_mmu, MO_UB)
LOAD_HELPER(lh,  int16_t,  cpu_ldw_mmu, MO_LEUW)
LOAD_HELPER(lhu, uint16_t, cpu_ldw_mmu, MO_LEUW)
LOAD_HELPER(lw,  int32_t,  cpu_ldl_mmu, MO_LEUL)
LOAD_HELPER(lwu, uint32_t, cpu_ldl_mmu, MO_LEUL)
LOAD_HELPER(ld,  uint64_t, cpu_ldq_mmu, MO_LEUQ)

#define STORE_HELPER(name, fn, mop)                                         \
void aok_rv_helper_##name(CPURISCVState *env, uint64_t addr, uint64_t val, \
                          uint64_t pc, uint64_t insn);                      \
void aok_rv_helper_##name(CPURISCVState *env, uint64_t addr, uint64_t val, \
                          uint64_t pc, uint64_t insn)                       \
{                                                                           \
    aok_rv_sync(env, pc, insn);                                             \
    fn(env, addr, val, OI(env, mop), 0);                                    \
}
STORE_HELPER(sb, cpu_stb_mmu, MO_UB)
STORE_HELPER(sh, cpu_stw_mmu, MO_LEUW)
STORE_HELPER(sw, cpu_stl_mmu, MO_LEUL)
STORE_HELPER(sd, cpu_stq_mmu, MO_LEUQ)

typedef struct Ctx {
    AokGen g;
    unsigned page_off;      /* of the TB's first insn in its page */
    unsigned off;           /* of the current insn from the TB's first */
    unsigned len;           /* of the current insn */
    uint32_t insn;
    bool has_m, has_mul, has_zba, has_zbb, has_zbs, has_zicond;
    bool no_goto_ptr;
} Ctx;

/* What translating one insn came to. */
enum { UNKNOWN, NEXT, END };

static inline int64_t sext(uint64_t v, int bits)
{
    return (int64_t)(v << (64 - bits)) >> (64 - bits);
}

/* x0 reads as zero and discards writes: both are slots of their own. */
static inline uint64_t rd_off(unsigned r)
{
    return r ? offsetof(CPURISCVState, gpr[r])
             : offsetof(CPURISCVState, aok_sink);
}

static inline uint64_t rs_off(unsigned r)
{
    return r ? offsetof(CPURISCVState, gpr[r])
             : offsetof(CPURISCVState, aok_zero);
}

static int alu_rr(Ctx *c, Gadget gadget, unsigned rd, unsigned rs1,
                  unsigned rs2)
{
    if (rd) {
        aok_emit_gadget(&c->g, gadget);
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, rs_off(rs1));
        aok_emit(&c->g, rs_off(rs2));
    }
    return NEXT;
}

static int alu_ri(Ctx *c, Gadget gadget, unsigned rd, unsigned rs1,
                  int64_t imm)
{
    if (rd) {
        aok_emit_gadget(&c->g, gadget);
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, rs_off(rs1));
        aok_emit(&c->g, imm);
    }
    return NEXT;
}

static int li(Ctx *c, unsigned rd, int64_t value)
{
    if (rd) {
        aok_emit_gadget(&c->g, G(li));
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, value);
    }
    return NEXT;
}

static int addi(Ctx *c, unsigned rd, unsigned rs1, int64_t imm)
{
    return rs1 ? alu_ri(c, G(add_ri), rd, rs1, imm) : li(c, rd, imm);
}

/* A load is done even into x0: it can fault, or read a device. */
static int load(Ctx *c, Gadget gadget, unsigned rd, unsigned rs1, int64_t imm)
{
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, rd_off(rd));
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, imm);
    aok_emit(&c->g, c->off);
    aok_emit(&c->g, c->insn);
    return NEXT;
}

static int store(Ctx *c, Gadget gadget, unsigned rs2, unsigned rs1,
                 int64_t imm)
{
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, rs_off(rs2));
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, imm);
    aok_emit(&c->g, c->off);
    aok_emit(&c->g, c->insn);
    return NEXT;
}

/*
 * The [pc delta][slot] pair of a direct jump to @delta bytes from the TB's
 * first insn. As with goto_tb, only a destination in the TB's own page may
 * be linked; any other is looked up each time.
 */
static void jump_operands(Ctx *c, int n, int64_t delta)
{
    int64_t dest = (int64_t)c->page_off + delta;

    aok_emit(&c->g, delta);
    if (dest >= 0 && dest < TARGET_PAGE_SIZE) {
        aok_emit(&c->g, aok_slot(&c->g, n));
    } else {
        aok_emit(&c->g, aok_slot_unlinked(&c->g));
    }
}

static void jump(Ctx *c, int n, int64_t delta)
{
    aok_emit_gadget(&c->g, aok_gadget_goto);
    jump_operands(c, n, delta);
}

static int branch(Ctx *c, Gadget gadget, unsigned rs1, unsigned rs2,
                  int64_t imm)
{
    aok_emit_gadget(&c->g, gadget);
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, rs_off(rs2));
    jump_operands(c, 0, c->off + imm);
    jump_operands(c, 1, c->off + c->len);
    return END;
}

static int jal(Ctx *c, unsigned rd, int64_t imm)
{
    if (rd) {
        aok_emit_gadget(&c->g, G(pcrel));
        aok_emit(&c->g, rd_off(rd));
        aok_emit(&c->g, c->off + c->len);
    }
    jump(c, 0, c->off + imm);
    return END;
}

static int jalr(Ctx *c, unsigned rd, unsigned rs1, int64_t imm)
{
    aok_emit_gadget(&c->g, G(jalr));
    aok_emit(&c->g, rd_off(rd));
    aok_emit(&c->g, rs_off(rs1));
    aok_emit(&c->g, imm);
    aok_emit(&c->g, c->off + c->len);
    if (c->no_goto_ptr) {
        aok_emit_gadget(&c->g, aok_gadget_exit_tb);
        aok_emit(&c->g, 0);
    } else {
        aok_emit_gadget(&c->g, aok_gadget_lookup);
    }
    return END;
}

static int op_imm(Ctx *c, uint32_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned f3 = (insn >> 12) & 7, top6 = insn >> 26, imm12 = insn >> 20;
    unsigned shamt = imm12 & 63;
    int64_t imm = sext(imm12, 12);

    switch (f3) {
    case 0: return addi(c, rd, rs1, imm);
    case 2: return alu_ri(c, G(slt_ri), rd, rs1, imm);
    case 3: return alu_ri(c, G(sltu_ri), rd, rs1, imm);
    case 4: return alu_ri(c, G(xor_ri), rd, rs1, imm);
    case 6: return alu_ri(c, G(or_ri), rd, rs1, imm);
    case 7: return alu_ri(c, G(and_ri), rd, rs1, imm);
    case 1:
        if (top6 == 0x00) {
            return alu_ri(c, G(sll_ri), rd, rs1, shamt);
        }
        if (c->has_zbb) {
            switch (imm12) {
            case 0x600: return alu_ri(c, G(clz_ri), rd, rs1, 0);
            case 0x601: return alu_ri(c, G(ctz_ri), rd, rs1, 0);
            case 0x602: return alu_ri(c, G(cpop_ri), rd, rs1, 0);
            case 0x604: return alu_ri(c, G(sext_b_ri), rd, rs1, 0);
            case 0x605: return alu_ri(c, G(sext_h_ri), rd, rs1, 0);
            }
        }
        if (c->has_zbs) {
            switch (top6) {
            case 0x12: return alu_ri(c, G(bclr_ri), rd, rs1, shamt);
            case 0x0a: return alu_ri(c, G(bset_ri), rd, rs1, shamt);
            case 0x1a: return alu_ri(c, G(binv_ri), rd, rs1, shamt);
            }
        }
        return UNKNOWN;
    case 5:
        if (top6 == 0x00) {
            return alu_ri(c, G(srl_ri), rd, rs1, shamt);
        }
        if (top6 == 0x10) {
            return alu_ri(c, G(sra_ri), rd, rs1, shamt);
        }
        if (c->has_zbb) {
            if (imm12 == 0x287) {
                return alu_ri(c, G(orc_b_ri), rd, rs1, 0);
            }
            if (imm12 == 0x6b8) {
                return alu_ri(c, G(rev8_ri), rd, rs1, 0);
            }
            if (top6 == 0x18) {
                return alu_ri(c, G(ror_ri), rd, rs1, shamt);
            }
        }
        if (c->has_zbs && top6 == 0x12) {
            return alu_ri(c, G(bext_ri), rd, rs1, shamt);
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

static int op_imm_32(Ctx *c, uint32_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned f3 = (insn >> 12) & 7, f7 = insn >> 25, imm12 = insn >> 20;
    unsigned shamt = imm12 & 31;

    switch (f3) {
    case 0:
        return alu_ri(c, G(addw_ri), rd, rs1, sext(imm12, 12));
    case 1:
        if (f7 == 0x00) {
            return alu_ri(c, G(sllw_ri), rd, rs1, shamt);
        }
        if (c->has_zba && (insn >> 26) == 0x02) {
            return alu_ri(c, G(slli_uw_ri), rd, rs1, imm12 & 63);
        }
        if (c->has_zbb) {
            switch (imm12) {
            case 0x600: return alu_ri(c, G(clzw_ri), rd, rs1, 0);
            case 0x601: return alu_ri(c, G(ctzw_ri), rd, rs1, 0);
            case 0x602: return alu_ri(c, G(cpopw_ri), rd, rs1, 0);
            }
        }
        return UNKNOWN;
    case 5:
        switch (f7) {
        case 0x00: return alu_ri(c, G(srlw_ri), rd, rs1, shamt);
        case 0x20: return alu_ri(c, G(sraw_ri), rd, rs1, shamt);
        case 0x30:
            if (c->has_zbb) {
                return alu_ri(c, G(rorw_ri), rd, rs1, shamt);
            }
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

static int op(Ctx *c, uint32_t insn)
{
    static const Gadget base[8] = {
        G(add_rr), G(sll_rr), G(slt_rr), G(sltu_rr),
        G(xor_rr), G(srl_rr), G(or_rr), G(and_rr),
    };
    static const Gadget muldiv[8] = {
        G(mul_rr), G(mulh_rr), G(mulhsu_rr), G(mulhu_rr),
        G(div_rr), G(divu_rr), G(rem_rr), G(remu_rr),
    };
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, f3 = (insn >> 12) & 7, f7 = insn >> 25;
    Gadget g = NULL;

    switch (f7) {
    case 0x00:
        g = base[f3];
        break;
    case 0x20:
        g = f3 == 0 ? G(sub_rr) : f3 == 5 ? G(sra_rr) : NULL;
        if (!g && c->has_zbb) {
            g = f3 == 7 ? G(andn_rr) : f3 == 6 ? G(orn_rr) :
                f3 == 4 ? G(xnor_rr) : NULL;
        }
        break;
    case 0x01:
        if (c->has_m || (c->has_mul && f3 < 4)) {
            g = muldiv[f3];
        }
        break;
    case 0x10:
        if (c->has_zba) {
            g = f3 == 2 ? G(sh1add_rr) : f3 == 4 ? G(sh2add_rr) :
                f3 == 6 ? G(sh3add_rr) : NULL;
        }
        break;
    case 0x05:
        if (c->has_zbb) {
            g = f3 == 4 ? G(min_rr) : f3 == 5 ? G(minu_rr) :
                f3 == 6 ? G(max_rr) : f3 == 7 ? G(maxu_rr) : NULL;
        }
        break;
    case 0x30:
        if (c->has_zbb) {
            g = f3 == 1 ? G(rol_rr) : f3 == 5 ? G(ror_rr) : NULL;
        }
        break;
    case 0x24:
        if (c->has_zbs) {
            g = f3 == 1 ? G(bclr_rr) : f3 == 5 ? G(bext_rr) : NULL;
        }
        break;
    case 0x14:
        if (c->has_zbs && f3 == 1) {
            g = G(bset_rr);
        }
        break;
    case 0x34:
        if (c->has_zbs && f3 == 1) {
            g = G(binv_rr);
        }
        break;
    case 0x07:
        if (c->has_zicond) {
            g = f3 == 5 ? G(czero_eqz_rr) : f3 == 7 ? G(czero_nez_rr) : NULL;
        }
        break;
    }
    return g ? alu_rr(c, g, rd, rs1, rs2) : UNKNOWN;
}

static int op_32(Ctx *c, uint32_t insn)
{
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, f3 = (insn >> 12) & 7, f7 = insn >> 25;
    Gadget g = NULL;

    switch (f7) {
    case 0x00:
        g = f3 == 0 ? G(addw_rr) : f3 == 1 ? G(sllw_rr) :
            f3 == 5 ? G(srlw_rr) : NULL;
        break;
    case 0x20:
        g = f3 == 0 ? G(subw_rr) : f3 == 5 ? G(sraw_rr) : NULL;
        break;
    case 0x01:
        if (c->has_m || (c->has_mul && f3 == 0)) {
            g = f3 == 0 ? G(mulw_rr) : f3 == 4 ? G(divw_rr) :
                f3 == 5 ? G(divuw_rr) : f3 == 6 ? G(remw_rr) :
                f3 == 7 ? G(remuw_rr) : NULL;
        }
        break;
    case 0x04:
        if (c->has_zba && f3 == 0) {
            g = G(add_uw_rr);
        } else if (c->has_zbb && f3 == 4 && rs2 == 0) {
            return alu_ri(c, G(zext_h_ri), rd, rs1, 0);
        }
        break;
    case 0x10:
        if (c->has_zba) {
            g = f3 == 2 ? G(sh1add_uw_rr) : f3 == 4 ? G(sh2add_uw_rr) :
                f3 == 6 ? G(sh3add_uw_rr) : NULL;
        }
        break;
    case 0x30:
        if (c->has_zbb) {
            g = f3 == 1 ? G(rolw_rr) : f3 == 5 ? G(rorw_rr) : NULL;
        }
        break;
    }
    return g ? alu_rr(c, g, rd, rs1, rs2) : UNKNOWN;
}

static int insn32(Ctx *c, uint32_t insn)
{
    static const Gadget loads[8] = {
        G(lb), G(lh), G(lw), G(ld), G(lbu), G(lhu), G(lwu), NULL,
    };
    static const Gadget stores[8] = { G(sb), G(sh), G(sw), G(sd) };
    static const Gadget branches[8] = {
        G(beq), G(bne), NULL, NULL, G(blt), G(bge), G(bltu), G(bgeu),
    };
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31;
    unsigned rs2 = (insn >> 20) & 31, f3 = (insn >> 12) & 7;

    switch (insn & 0x7f) {
    case 0x37: /* lui */
        return li(c, rd, sext(insn & 0xfffff000, 32));
    case 0x17: /* auipc */
        if (rd) {
            aok_emit_gadget(&c->g, G(pcrel));
            aok_emit(&c->g, rd_off(rd));
            aok_emit(&c->g, c->off + sext(insn & 0xfffff000, 32));
        }
        return NEXT;
    case 0x6f: /* jal */
        return jal(c, rd, sext((((insn >> 31) & 1) << 20) |
                               (((insn >> 12) & 0xff) << 12) |
                               (((insn >> 20) & 1) << 11) |
                               (((insn >> 21) & 0x3ff) << 1), 21));
    case 0x67: /* jalr */
        return f3 == 0 ? jalr(c, rd, rs1, sext(insn >> 20, 12)) : UNKNOWN;
    case 0x63: /* branches */
        if (!branches[f3]) {
            return UNKNOWN;
        }
        return branch(c, branches[f3], rs1, rs2,
                      sext((((insn >> 31) & 1) << 12) |
                           (((insn >> 7) & 1) << 11) |
                           (((insn >> 25) & 0x3f) << 5) |
                           (((insn >> 8) & 0xf) << 1), 13));
    case 0x03: /* loads */
        return loads[f3] ? load(c, loads[f3], rd, rs1, sext(insn >> 20, 12))
                         : UNKNOWN;
    case 0x23: /* stores */
        return stores[f3] ? store(c, stores[f3], rs2, rs1,
                                  sext(((insn >> 25) << 5) |
                                       ((insn >> 7) & 31), 12))
                          : UNKNOWN;
    case 0x13:
        return op_imm(c, insn);
    case 0x1b:
        return op_imm_32(c, insn);
    case 0x33:
        return op(c, insn);
    case 0x3b:
        return op_32(c, insn);
    case 0x0f:
        if (f3 == 0) { /* fence; fence.i is TCG's */
            aok_emit_gadget(&c->g, G(fence));
            return NEXT;
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

/* The C extension, RV64: each insn here is one of the above in 16 bits. */
static int insn16(Ctx *c, uint32_t insn)
{
    unsigned f3 = (insn >> 13) & 7, b12 = (insn >> 12) & 1;
    unsigned rd = (insn >> 7) & 31, rs2 = (insn >> 2) & 31;
    unsigned rdp = 8 + ((insn >> 2) & 7), rs1p = 8 + ((insn >> 7) & 7);
    unsigned imm5 = (insn >> 2) & 0x1f;
    int64_t imm6 = sext((b12 << 5) | imm5, 6);
    int64_t imm;

    switch (insn & 3) {
    case 0:
        switch (f3) {
        case 0: /* c.addi4spn */
            imm = (((insn >> 11) & 3) << 4) | (((insn >> 7) & 0xf) << 6) |
                  (((insn >> 6) & 1) << 2) | (((insn >> 5) & 1) << 3);
            return imm ? alu_ri(c, G(add_ri), rdp, 2, imm) : UNKNOWN;
        case 2: /* c.lw */
        case 6: /* c.sw */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 6) & 1) << 2) |
                  (((insn >> 5) & 1) << 6);
            return f3 == 2 ? load(c, G(lw), rdp, rs1p, imm)
                           : store(c, G(sw), rdp, rs1p, imm);
        case 3: /* c.ld */
        case 7: /* c.sd */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 5) & 3) << 6);
            return f3 == 3 ? load(c, G(ld), rdp, rs1p, imm)
                           : store(c, G(sd), rdp, rs1p, imm);
        }
        return UNKNOWN;
    case 1:
        switch (f3) {
        case 0: /* c.addi, c.nop */
            return alu_ri(c, G(add_ri), rd, rd, imm6);
        case 1: /* c.addiw */
            return rd ? alu_ri(c, G(addw_ri), rd, rd, imm6) : UNKNOWN;
        case 2: /* c.li */
            return li(c, rd, imm6);
        case 3:
            if (rd == 2) { /* c.addi16sp */
                imm = sext((b12 << 9) | (((insn >> 6) & 1) << 4) |
                           (((insn >> 5) & 1) << 6) |
                           (((insn >> 3) & 3) << 7) |
                           (((insn >> 2) & 1) << 5), 10);
                return imm ? alu_ri(c, G(add_ri), 2, 2, imm) : UNKNOWN;
            }
            /* c.lui */
            return imm6 ? li(c, rd, imm6 << 12) : UNKNOWN;
        case 4:
            switch ((insn >> 10) & 3) {
            case 0: /* c.srli */
                return alu_ri(c, G(srl_ri), rs1p, rs1p, (b12 << 5) | imm5);
            case 1: /* c.srai */
                return alu_ri(c, G(sra_ri), rs1p, rs1p, (b12 << 5) | imm5);
            case 2: /* c.andi */
                return alu_ri(c, G(and_ri), rs1p, rs1p, imm6);
            }
            switch ((b12 << 2) | ((insn >> 5) & 3)) {
            case 0: return alu_rr(c, G(sub_rr), rs1p, rs1p, rdp);
            case 1: return alu_rr(c, G(xor_rr), rs1p, rs1p, rdp);
            case 2: return alu_rr(c, G(or_rr), rs1p, rs1p, rdp);
            case 3: return alu_rr(c, G(and_rr), rs1p, rs1p, rdp);
            case 4: return alu_rr(c, G(subw_rr), rs1p, rs1p, rdp);
            case 5: return alu_rr(c, G(addw_rr), rs1p, rs1p, rdp);
            }
            return UNKNOWN; /* Zcb */
        case 5: /* c.j */
            return jal(c, 0, sext((b12 << 11) | (((insn >> 11) & 1) << 4) |
                                  (((insn >> 9) & 3) << 8) |
                                  (((insn >> 8) & 1) << 10) |
                                  (((insn >> 7) & 1) << 6) |
                                  (((insn >> 6) & 1) << 7) |
                                  (((insn >> 3) & 7) << 1) |
                                  (((insn >> 2) & 1) << 5), 12));
        case 6: /* c.beqz */
        case 7: /* c.bnez */
            imm = sext((b12 << 8) | (((insn >> 10) & 3) << 3) |
                       (((insn >> 5) & 3) << 6) | (((insn >> 3) & 3) << 1) |
                       (((insn >> 2) & 1) << 5), 9);
            return branch(c, f3 == 6 ? G(beq) : G(bne), rs1p, 0, imm);
        }
        return UNKNOWN;
    case 2:
        switch (f3) {
        case 0: /* c.slli */
            return alu_ri(c, G(sll_ri), rd, rd, (b12 << 5) | imm5);
        case 2: /* c.lwsp */
            imm = (b12 << 5) | (((insn >> 4) & 7) << 2) |
                  (((insn >> 2) & 3) << 6);
            return rd ? load(c, G(lw), rd, 2, imm) : UNKNOWN;
        case 3: /* c.ldsp */
            imm = (b12 << 5) | (((insn >> 5) & 3) << 3) |
                  (((insn >> 2) & 7) << 6);
            return rd ? load(c, G(ld), rd, 2, imm) : UNKNOWN;
        case 4:
            if (!b12) {
                if (rs2) { /* c.mv */
                    return alu_ri(c, G(add_ri), rd, rs2, 0);
                }
                return rd ? jalr(c, 0, rd, 0) : UNKNOWN; /* c.jr */
            }
            if (rs2) { /* c.add */
                return alu_rr(c, G(add_rr), rd, rd, rs2);
            }
            return rd ? jalr(c, 1, rd, 0) : UNKNOWN; /* c.jalr; c.ebreak */
        case 6: /* c.swsp */
            imm = (((insn >> 9) & 0xf) << 2) | (((insn >> 7) & 3) << 6);
            return store(c, G(sw), rs2, 2, imm);
        case 7: /* c.sdsp */
            imm = (((insn >> 10) & 7) << 3) | (((insn >> 7) & 7) << 6);
            return store(c, G(sd), rs2, 2, imm);
        }
        return UNKNOWN;
    }
    return UNKNOWN;
}

int riscv_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                             int *max_insns, vaddr pc, void *host_pc)
{
    CPURISCVState *env = cpu_env(cs);
    const RISCVCPUConfig *cfg = &env_archcpu(env)->cfg;
    uint32_t flags = tb->flags, cflags = tb_cflags(tb);
    uint32_t misa = FIELD_EX64(tb->cs_base, EXT_TB_FLAGS, MISA_EXT);
    const uint8_t *code = host_pc;
    Ctx c;
    int r = NEXT;

    /*
     * The states this translator knows: RV64 with a little-endian guest,
     * not virtualized, no pointer masking, no CFI, no instruction-count
     * trigger, and the C extension, without which a jump can raise a
     * misaligned-address exception. And an ordinary TB: one in RAM that may
     * check for interrupts and need not stop after a set number of insns.
     */
    if (!code || !(cflags & CF_PCREL) ||
        (cflags & (CF_COUNT_MASK | CF_SINGLE_STEP | CF_MEMI_ONLY |
                   CF_USE_ICOUNT | CF_NOIRQ | CF_BP_PAGE | CF_STEP_ATOMIC)) ||
        FIELD_EX32(flags, TB_FLAGS, XL) != MXL_RV64 ||
        FIELD_EX32(flags, TB_FLAGS, AXL) != MXL_RV64 ||
        FIELD_EX32(flags, TB_FLAGS, PM_PMM) ||
        FIELD_EX32(flags, TB_FLAGS, ITRIGGER) ||
        FIELD_EX32(flags, TB_FLAGS, VIRT_ENABLED) ||
        FIELD_EX32(flags, TB_FLAGS, FCFI_ENABLED) ||
        FIELD_EX32(flags, TB_FLAGS, BCFI_ENABLED) ||
        FIELD_EX64(tb->cs_base, EXT_TB_FLAGS, BIG_ENDIAN) ||
        !cfg->ext_zca) {
        return 0;
    }

    c.page_off = pc & ~TARGET_PAGE_MASK;
    c.off = 0;
    c.has_m = misa & RVM;
    c.has_mul = c.has_m || cfg->ext_zmmul;
    c.has_zba = cfg->ext_zba;
    c.has_zbb = cfg->ext_zbb;
    c.has_zbs = cfg->ext_zbs;
    c.has_zicond = cfg->ext_zicond;
    c.no_goto_ptr = cflags & CF_NO_GOTO_PTR;
    aok_gen_begin(&c.g, cs, tb, *max_insns, FIELD_EX32(flags, TB_FLAGS, MEM_IDX));

    /* A TB stays in its page: an insn that would straddle the end is TCG's. */
    while (aok_gen_room(&c.g, 12)) {
        unsigned left = TARGET_PAGE_SIZE - (c.page_off + c.off);
        uint64_t *start = c.g.p;

        if (left < 2) {
            break;
        }
        c.insn = lduw_le_p(code + c.off);
        if ((c.insn & 3) != 3) {
            c.len = 2;
            r = insn16(&c, c.insn);
        } else if (left < 4) {
            break;
        } else {
            c.insn = ldl_le_p(code + c.off);
            c.len = 4;
            r = insn32(&c, c.insn);
        }
        if (r == UNKNOWN) {
            c.g.p = start;
            break;
        }
        aok_gen_insn_end(&c.g, c.page_off + c.off, c.insn);
        c.off += c.len;
        if (r == END) {
            break;
        }
    }
    if (c.g.n_insns == 0) {
        aok_stats.declined_first++;
        return 0;
    }
    if (r != END) {
        jump(&c, 0, c.off);
    }
    return aok_gen_finish(&c.g, c.off);
}
