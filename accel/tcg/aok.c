/*
 * AOK gadgets: stream emission shared by the front ends.
 * See include/accel/tcg/aok.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "exec/cpu-common.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/tcg.h"
#include "tcg/insn-start-words.h"
#include "accel/tcg/aok.h"
#include "internal-common.h"
#include "tb-internal.h"

bool aok_enabled = true;
bool aok_stats_enabled;
AokStats aok_stats;

/*
 * QEMU_AOK_STATS=2: which of TCG's TBs the main loop enters most, by pc and
 * first insn. Each such entry is a stream that could not go on, so this is
 * the list of what a front end should learn next.
 */
#define AOK_PROF_SIZE 65536
static bool aok_prof_enabled;
static uint64_t aok_prof_dropped;
static struct AokProf {
    uint64_t pc, n;
    uint32_t insn;
} aok_prof[AOK_PROF_SIZE];

void aok_stats_tcg_entry(CPUState *cpu)
{
    void *pcp;
    uint64_t pc;
    unsigned h;

    if (!aok_prof_enabled || !cpu->cc->tcg_ops->aok_translate_code) {
        return;
    }
    pcp = (void *)cpu_env(cpu) + cpu->cc->tcg_ops->aok_pc_offset;
    pc = cpu->cc->tcg_ops->aok_pc32 ? *(uint32_t *)pcp : *(uint64_t *)pcp;
    h = (pc >> 1) * 0x9e3779b97f4a7c15ull >> 40;
    for (int i = 0; i < 16; i++) {
        struct AokProf *e = &aok_prof[(h + i) % AOK_PROF_SIZE];

        if (e->n && e->pc == pc) {
            e->n++;
            return;
        }
        if (!e->n) {
            e->pc = pc;
            e->n = 1;
            cpu_memory_rw_debug(cpu, pc, &e->insn, 4, false);
            return;
        }
    }
    aok_prof_dropped++;
}

static int aok_prof_cmp(const void *a, const void *b)
{
    const struct AokProf *x = a, *y = b;

    return x->n < y->n ? 1 : x->n > y->n ? -1 : 0;
}

static void aok_print_stats(void)
{
    uint64_t tbs = aok_stats.tb_aok + aok_stats.tb_tcg;

    if (aok_prof_enabled) {
        qsort(aok_prof, AOK_PROF_SIZE, sizeof(aok_prof[0]), aok_prof_cmp);
        /* The head of the list, and of the tail whatever is not noise. */
        for (int i = 0; i < AOK_PROF_SIZE && aok_prof[i].n; i++) {
            if (i >= 400 && aok_prof[i].n < 100) {
                break;
            }
            fprintf(stderr, "aok: tcg-entry %10" PRIu64 " %016" PRIx64
                    " %08x\n", aok_prof[i].n, aok_prof[i].pc,
                    aok_prof[i].insn);
        }
        fprintf(stderr, "aok: %" PRIu64 " entries into TCG's code went "
                "uncounted\n", aok_prof_dropped);
    }

    fprintf(stderr, "aok: %" PRIu64 " of %" PRIu64 " TBs (%.1f%%), "
            "%" PRIu64 " guest insns; TCG kept %" PRIu64 " TBs, "
            "%" PRIu64 " because of their first insn\n",
            aok_stats.tb_aok, tbs, tbs ? 100.0 * aok_stats.tb_aok / tbs : 0.0,
            aok_stats.insns_aok, aok_stats.tb_tcg, aok_stats.declined_first);
    fprintf(stderr, "aok: main loop entered streams %" PRIu64 " times and "
            "TCG's code %" PRIu64 " times; lookups in C found a stream %"
            PRIu64 ", TCG's TB %" PRIu64 ", nothing %" PRIu64 "\n",
            aok_stats.enter_aok, aok_stats.enter_tcg, aok_stats.lookup_aok,
            aok_stats.lookup_tcg, aok_stats.lookup_none);
    fprintf(stderr, "aok: of those lookups %" PRIu64 " were for a pc the "
            "jump cache had, %" PRIu64 " of them under other flags and %"
            PRIu64 " other cflags\n", aok_stats.lookup_cached,
            aok_stats.lookup_cached_flags, aok_stats.lookup_cached_cflags);
    fprintf(stderr, "aok: streams came back by an unlinked slot %" PRIu64
            " times (%" PRIu64 " into a TB of two pages), for an exit "
            "request %" PRIu64 ", otherwise %" PRIu64 "\n",
            aok_stats.ret_slot, aok_stats.two_page, aok_stats.ret_request,
            aok_stats.ret_none);
    if (aok_stats.lookup_cached_flags) {
        fprintf(stderr, "aok: the flags that differed, by bit:");
        for (int i = 0; i < 32; i++) {
            if (aok_stats.lookup_flag_bit[i]) {
                fprintf(stderr, " %d:%" PRIu64, i,
                        aok_stats.lookup_flag_bit[i]);
            }
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "aok: first insns left to TCG, by major opcode:");
    for (int i = 0; i < 128; i++) {
        if (aok_stats.declined_op[i]) {
            fprintf(stderr, " %#x:%" PRIu64, i, aok_stats.declined_op[i]);
        }
    }
    fprintf(stderr, " compressed:%" PRIu64 "\n", aok_stats.declined_c);
    fprintf(stderr, "aok: %" PRIu64 " pairs fused, %" PRIu64
            " of them forwarding a register\n",
            aok_stats.pairs, aok_stats.pairs_fw);
}

static void __attribute__((constructor)) aok_init(void)
{
    const char *s = getenv("QEMU_AOK");

    if (s && !strcmp(s, "0")) {
        aok_enabled = false;
    }
    s = getenv("QEMU_AOK_STATS");
    if (s) {
        aok_stats_enabled = true;
        aok_prof_enabled = !strcmp(s, "2");
        atexit(aok_print_stats);
    }
}

void aok_gen_begin(AokGen *g, CPUState *cpu, TranslationBlock *tb,
                   int max_insns, int mmu_idx)
{
    TCGContext *s = tcg_ctx;
    /* As tlb_mask_table_ofs() in tcg.c: where TCG's backends find it. */
    int fi = mmuidx_to_fast_index(mmu_idx);
    intptr_t tlb_ofs = offsetof(CPUNegativeOffsetState, tlb.f[fi])
                       - sizeof(CPUNegativeOffsetState);

    memset(g, 0, sizeof(*g));
    g->tb = tb;
    g->rx = tb->tc.ptr;
    g->base = tcg_splitwx_to_rw((void *)tb->tc.ptr);
    g->p = g->base;
    g->limit = (uint64_t *)s->code_gen_highwater;
    g->max_insns = MIN(max_insns, TCG_MAX_INSNS);

    /* What tcg_gen_code would have set up for the rest of tb_gen_code. */
    tb->jmp_reset_offset[0] = TB_JMP_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_OFFSET_INVALID;
    tb->jmp_insn_offset[0] = TB_JMP_OFFSET_INVALID;
    tb->jmp_insn_offset[1] = TB_JMP_OFFSET_INVALID;
    s->code_buf = (tcg_insn_unit *)g->base;
    s->code_ptr = s->code_buf;
    s->data_gen_ptr = NULL;
    s->gen_insn_data =
        tcg_malloc(sizeof(uint64_t) * g->max_insns * INSN_START_WORDS);
    g->insn_data = s->gen_insn_data;
    g->insn_end_off = s->gen_insn_end_off;

    aok_emit_gadget(g, cpu->cc->tcg_ops->aok_pc32 ? aok_gadget_enter32
                                                  : aok_gadget_enter);
    aok_emit(g, (uintptr_t)tcg_splitwx_to_rx(tb));
    aok_emit(g, tlb_ofs);
}

static unsigned aok_pair_slot(uintptr_t a, uintptr_t b)
{
    uint64_t h = (uint64_t)a * 0x9e3779b97f4a7c15ull ^
                 (uint64_t)b * 0xc2b2ae3d27d4eb4full;

    return (h >> 40) & (AOK_PAIR_HASH - 1);
}

void aok_pair_set_init(AokPairSet *set)
{
    assert(set->n * 3 < AOK_PAIR_HASH);
    for (unsigned i = 0; i < set->n; i++) {
        unsigned slot = aok_pair_slot((uintptr_t)set->pairs[i].a,
                                      (uintptr_t)set->pairs[i].b);

        while (set->hash[slot]) {
            slot = (slot + 1) & (AOK_PAIR_HASH - 1);
        }
        set->hash[slot] = i + 1;
    }
}

void aok_gen_pair(AokGen *g, uint64_t *from, const AokPairSet *set)
{
    uint64_t *prev = g->pair_prev;
    unsigned slot;

    g->pair_prev = NULL;
    if (g->p == from || g->overflow) {
        return;
    }
    if (!prev) {
        g->pair_prev = from;
        return;
    }
    slot = aok_pair_slot(prev[0], from[0]);
    for (unsigned i; (i = set->hash[slot]); slot = (slot + 1) & (AOK_PAIR_HASH - 1)) {
        const AokPair *p = &set->pairs[i - 1];
        void (*fused)(void) = p->fused;

        if ((uintptr_t)p->a != prev[0] || (uintptr_t)p->b != from[0]) {
            continue;
        }
        /*
         * The step before must have been that one gadget and nothing after
         * it, or what follows its operands is not this step.
         */
        if (from - prev != p->a_words) {
            break;
        }
        /* The first's result goes to the register its first operand names. */
        for (unsigned k = 0; set->forward && k < 2 && p->fused_fw[k]; k++) {
            uint64_t word = from[1 + p->op[k].index], slot = ~(uint64_t)0;

            switch (p->op[k].kind) {
            case AOK_PAIR_OP_SLOT:
                slot = word;
                break;
            case AOK_PAIR_OP_REG:
                slot = set->reg_base + 8 * (word & 0x1f);
                break;
            case AOK_PAIR_OP_REG8:
                slot = set->reg_base + 8 * ((word >> 8) & 0x1f);
                break;
            case AOK_PAIR_OP_REG_NOT31:
                if ((word & 0x1f) != 31) {
                    slot = set->reg_base + 8 * (word & 0x1f);
                }
                break;
            }
            if (slot == prev[1]) {
                fused = p->fused_fw[k];
                aok_stats.pairs_fw++;
                break;
            }
        }
        prev[0] = (uintptr_t)fused;
        memmove(from, from + 1, (g->p - from - 1) * sizeof(*from));
        g->p--;
        /* Words this step asked aok_gen_finish to fill in moved with it. */
        for (int j = 0; j < g->n_fix; j++) {
            if (g->fix[j].word > from) {
                g->fix[j].word--;
            }
        }
        aok_stats.pairs++;
        return;                 /* a pair is not the head of another */
    }
    g->pair_prev = from;
}

const void *aok_gen_next_page(AokGen *g, CPUState *cpu, vaddr addr)
{
    TranslationBlock *tb = g->tb;
    tb_page_addr_t page0, old_page1, new_page1;
    void *host;

    /* As translator_access() takes a TB into its second page. */
    new_page1 = get_page_addr_code_hostp(cpu_env(cpu), addr, &host);
    if (new_page1 == -1) {
        return NULL;
    }
    old_page1 = tb_page_addr1(tb);
    if (new_page1 != old_page1) {
        page0 = tb_page_addr0(tb);
        if (old_page1 != -1) {
            tb_unlock_page1(page0, old_page1);
        }
        tb_set_page_addr1(tb, new_page1);
        tb_lock_page1(page0, new_page1);
    }
    return host;
}

void aok_gen_insn_end(AokGen *g, uint64_t pc_page_offset, uint64_t insn)
{
    int n = g->n_insns++;

    g->insn_data[n * INSN_START_WORDS + 0] = pc_page_offset;
    g->insn_data[n * INSN_START_WORDS + 1] = insn;
    g->insn_data[n * INSN_START_WORDS + 2] = 0;
    g->insn_end_off[n] = (g->p - g->base) * sizeof(uint64_t);
}

uint64_t aok_slot(AokGen *g, int n)
{
    TranslationBlock *tb = g->tb;

    assert(n == 0 || n == 1);
    if (tb_cflags(tb) & CF_NO_GOTO_TB) {
        return aok_slot_unlinked(g);
    }
    if (tb->jmp_reset_offset[n] == TB_JMP_OFFSET_INVALID) {
        /* Claimed; aok_gen_finish gives it the stub's real offset. */
        tb->jmp_reset_offset[n] = 0;
    }
    return (uintptr_t)&((const TranslationBlock *)tcg_splitwx_to_rx(tb))
                           ->jmp_target_addr[n];
}

uint64_t aok_slot_unlinked(AokGen *g)
{
    /*
     * The caller emits the value returned as the very next word. It will be
     * the address of a word, emitted by aok_gen_finish, that holds the
     * address of this TB's unlinked-exit stub; remember where to put it.
     */
    assert(g->n_fix < ARRAY_SIZE(g->fix));
    g->fix[g->n_fix++].word = g->p;
    return 0;
}

int aok_gen_finish(AokGen *g, unsigned guest_size)
{
    TranslationBlock *tb = g->tb;
    uintptr_t tb_rx = (uintptr_t)tcg_splitwx_to_rx(tb);
    const uint64_t *holder = NULL;
    size_t size;

    for (int n = 0; n < 2; n++) {
        if (tb->jmp_reset_offset[n] != TB_JMP_OFFSET_INVALID) {
            /* What tb_reset_jump puts in the slot: see AOK_ENTER_BYTES. */
            tb->jmp_reset_offset[n] = (g->p - g->base) * sizeof(uint64_t)
                                      - AOK_ENTER_BYTES;
            aok_emit_gadget(g, aok_gadget_exit_tb);
            aok_emit(g, tb_rx | n);
        }
    }
    if (g->n_fix || tb->jmp_reset_offset[0] != TB_JMP_OFFSET_INVALID ||
        tb->jmp_reset_offset[1] != TB_JMP_OFFSET_INVALID) {
        /*
         * One stub, and one word holding its address, for all of them. It
         * comes right after the slots' stubs, where the main loop finds it
         * for a slot whose TB may not be linked (aok_slot_to_lookup).
         */
        const uint64_t *stub = g->rx + (g->p - g->base);

        if (tb_cflags(tb) & CF_NO_GOTO_PTR) {
            aok_emit_gadget(g, aok_gadget_exit_tb);
            aok_emit(g, 0);
        } else {
            aok_emit_gadget(g, g->lookup ? g->lookup : aok_gadget_lookup);
            aok_emit_lookup_operands(g);
        }
        holder = g->rx + (g->p - g->base);
        aok_emit(g, (uintptr_t)stub - AOK_ENTER_BYTES);
    }
    if (g->overflow) {
        return -1;
    }
    for (int i = 0; i < g->n_fix; i++) {
        *g->fix[i].word = (uintptr_t)holder;
    }

    size = (g->p - g->base) * sizeof(uint64_t);
    assert(size < UINT16_MAX);
    assert(g->n_insns > 0);
    tb->size = guest_size;
    tb->icount = g->n_insns;
    tb->aok = 1;
    tcg_ctx->code_ptr = (tcg_insn_unit *)g->p;

    aok_stats.tb_aok++;
    aok_stats.insns_aok += g->n_insns;
    return size;
}
