/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Every instruction form RCG has a gadget for, over awkward values.
 *
 * RCG runs an A64 instruction under TCTI as one gadget, where TCG runs a
 * TCG op at a time; it must give exactly what TCG gives. The cases come
 * from the tables in target/arm/tcg/rcg-gen.py that RCG's gadgets are made
 * from (see rcg-test.h): every value of each encoding class's fields, with
 * the neighbors that are left to TCG. Each runs over every pair of values
 * from rcg_values (or each single value, where it takes one operand), from
 * every start in rcg_starts; one that reads NZCV runs over the pairs from
 * rcg_flag_values, from each of NZCV's 16 values. X0 to X30, SP and NZCV
 * after it are hashed, and a case prints its hash. What ADR or ADRP wrote
 * is hashed as its distance from the instruction, or from the
 * instruction's page, so that the hash does not depend on where the test
 * was linked.
 *
 * rcg-insns.ref holds TCG's hashes. To regenerate it after rcg-gen.py
 * changes the cases, run the test under TCG (in a build with TCTI, with
 * -accel tcg,rcg=off) and copy the output over it.
 */

#include "rcg-test.h"
#ifndef RCG_INSN_CASES
#define RCG_INSN_CASES "rcg-insns.h"
#endif
#include RCG_INSN_CASES

#define NB_CASES (sizeof(rcg_insn_cases) / sizeof(rcg_insn_cases[0]))

static uint64_t run(const struct rcg_case *c)
{
    const uint64_t *values = c->flags ? rcg_flag_values : rcg_values;
    int nb_values = c->flags ? RCG_NB_FLAG_VALUES : RCG_NB_VALUES;
    int nb_starts = c->flags ? 16 : RCG_NB_STARTS;
    int nx = c->a >= 0 ? nb_values : 1;
    int ny = c->b >= 0 ? nb_values : 1;
    uint64_t h = RCG_HASH_INIT;

    rcg_set_insn(c->insn);
    for (int s = 0; s < nb_starts; s++) {
        struct rcg_start start = rcg_starts[s % RCG_NB_STARTS];

        if (c->flags) {
            start.nzcv = (uint64_t)s << 28;
        }
        for (int x = 0; x < nx; x++) {
            for (int y = 0; y < ny; y++) {
                uint64_t nzcv;

                rcg_setup(c, values[x], values[y], &start);
                rcg_run_insn();
                if (c->adr >= 0) {
                    uint64_t pc = (uint64_t)rcg_insn_slot;

                    rcg_out.x[c->adr] -= c->page ? pc & ~0xffful : pc;
                }
                nzcv = rcg_out.nzcv & RCG_NZCV;
                h = rcg_hash(h, rcg_out.x, sizeof(rcg_out.x));
                h = rcg_hash(h, &rcg_out.sp, sizeof(rcg_out.sp));
                h = rcg_hash(h, &nzcv, sizeof(nzcv));
            }
        }
    }
    return h;
}

int main(void)
{
    for (int i = 0; i < NB_CASES; i++) {
        ml_printf("%s: %lx\n", rcg_insn_cases[i].name,
                  run(&rcg_insn_cases[i]));
    }
    return 0;
}
