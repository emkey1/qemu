/*
 * Cross-modifying code with several vCPUs at once
 *
 * One vCPU patches a function while three others call it. xmc_fn is
 * `movz w0, #imm; ret`, alone on its page. Each round, the writer
 * patches in a poison value, waits a while, patches in the round's
 * number and publishes it. Any TB of the page is gone after the first
 * store, so the second one is the page's first store since. A reader
 * that sees the round published must, after an ISB, get the round's
 * number from xmc_fn. If it keeps getting the poison or an older number,
 * a TB of the old bytes has outlived the store that replaced them.
 *
 * Runs with -smp 4: the readers are started with PSCI CPU_ON.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <minilib.h>

#define READERS 3
#define ROUNDS 10000
#define POISON 0xffff
#define MAX_DELAY 2000
#define STACK_SIZE 16384

#define PSCI_CPU_ON_64 0xc4000003

/* movz w0, #imm */
#define MOVZ_W0(imm) (0x52800000 | ((uint32_t)(imm) << 5))

asm(".pushsection .text\n"
    ".balign 4096\n"
    ".global xmc_fn\n"
    "xmc_fn:\n"
    "movz w0, #0\n"
    "ret\n"
    ".balign 4096\n"
    ".popsection\n");

/* What the readers set up their EL1 from: the writer's own registers. */
uint64_t xmc_boot_regs[6] __attribute__((aligned(64)));
uint8_t xmc_stacks[READERS][STACK_SIZE] __attribute__((aligned(16)));

/*
 * A reader's first instructions, with x0 its index. Its MMU is off until
 * it takes the writer's translation table, so these reach memory by
 * physical address, which the table maps to itself.
 */
asm(".pushsection .text\n"
    ".balign 8\n"
    "xmc_secondary:\n"
    "adrp x1, xmc_boot_regs\n"
    "add x1, x1, :lo12:xmc_boot_regs\n"
    "ldp x2, x3, [x1]\n"
    "msr vbar_el1, x2\n"
    "msr ttbr0_el1, x3\n"
    "ldp x2, x3, [x1, #16]\n"
    "msr tcr_el1, x2\n"
    "msr mair_el1, x3\n"
    "ldp x2, x3, [x1, #32]\n"
    "msr cpacr_el1, x2\n"
    "isb\n"
    "dsb sy\n"
    "msr sctlr_el1, x3\n"
    "isb\n"
    "adrp x1, xmc_stacks\n"
    "add x1, x1, :lo12:xmc_stacks\n"
    "add x2, x0, #1\n"
    "lsl x2, x2, #14\n"
    "add sp, x1, x2\n"
    "bl xmc_reader\n"
    "1: wfe\n"
    "b 1b\n"
    ".popsection\n");

#define SYMBOL_ADDRESS(sym) ({                              \
    uint64_t __addr;                                        \
    asm("adrp %0, " #sym "\n\t"                             \
        "add %0, %0, :lo12:" #sym : "=r" (__addr));         \
    __addr;                                                 \
})

static uint32_t published;
static uint32_t ready[READERS];
static uint32_t ack[READERS];
static uint32_t failed;
static uint32_t stale_round[READERS];
static uint32_t stale_value[READERS];
static uint32_t transient[READERS];

#define read_sysreg(r) ({                                   \
    uint64_t __val;                                         \
    asm volatile("mrs %0, " #r : "=r" (__val));             \
    __val;                                                  \
})

static inline uint32_t load_acquire(uint32_t *p)
{
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void store_release(uint32_t *p, uint32_t v)
{
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static uint32_t call_xmc_fn(void)
{
    asm volatile("isb" : : : "memory");
    return ((uint32_t (*)(void))SYMBOL_ADDRESS(xmc_fn))();
}

/* The sequence the architecture asks of a CPU that modifies code. */
static void patch(uint32_t imm)
{
    uint32_t *xmc_fn = (uint32_t *)SYMBOL_ADDRESS(xmc_fn);

    __atomic_store_n(xmc_fn, MOVZ_W0(imm), __ATOMIC_RELAXED);
    asm volatile("dc cvau, %0\n\t"
                 "dsb ish\n\t"
                 "ic ivau, %0\n\t"
                 "dsb ish\n\t"
                 "isb"
                 : : "r" (xmc_fn) : "memory");
}

/* Called from xmc_secondary. */
void __attribute__((used)) xmc_reader(uint64_t id)
{
    uint64_t second = read_sysreg(cntfrq_el0);
    uint32_t last = 0;

    store_release(&ready[id], 1);
    while (!load_acquire(&failed)) {
        uint32_t round, value;

        call_xmc_fn();
        round = load_acquire(&published);
        if (round == last) {
            continue;
        }
        value = call_xmc_fn();
        if (value != round) {
            uint64_t start = read_sysreg(cntvct_el0);

            transient[id]++;
            while ((value = call_xmc_fn()) != round) {
                if (read_sysreg(cntvct_el0) - start > second) {
                    stale_round[id] = round;
                    stale_value[id] = value;
                    store_release(&failed, 1);
                    return;
                }
            }
        }
        last = round;
        store_release(&ack[id], round);
        if (round == ROUNDS) {
            return;
        }
    }
}

static int64_t psci_cpu_on(uint64_t mpidr, uint64_t entry, uint64_t context)
{
    register uint64_t x0 asm("x0") = PSCI_CPU_ON_64;
    register uint64_t x1 asm("x1") = mpidr;
    register uint64_t x2 asm("x2") = entry;
    register uint64_t x3 asm("x3") = context;

    asm volatile("hvc #0"
                 : "+r" (x0)
                 : "r" (x1), "r" (x2), "r" (x3)
                 : "memory");
    return x0;
}

/* Waits for *p to reach v, for at most ten seconds. */
static int wait_for(uint32_t *p, uint32_t v)
{
    uint64_t limit = 10 * read_sysreg(cntfrq_el0);
    uint64_t start = read_sysreg(cntvct_el0);

    while (load_acquire(p) != v) {
        if (load_acquire(&failed)) {
            return 0;
        }
        if (read_sysreg(cntvct_el0) - start > limit) {
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    uint32_t seed = 1, total = 0;
    int i;

    xmc_boot_regs[0] = read_sysreg(vbar_el1);
    xmc_boot_regs[1] = read_sysreg(ttbr0_el1);
    xmc_boot_regs[2] = read_sysreg(tcr_el1);
    xmc_boot_regs[3] = read_sysreg(mair_el1);
    xmc_boot_regs[4] = read_sysreg(cpacr_el1);
    xmc_boot_regs[5] = read_sysreg(sctlr_el1);
    /* The readers load these with their MMU, and so their caches, off. */
    asm volatile("dc civac, %0\n\tdsb sy" : : "r" (xmc_boot_regs) : "memory");

    patch(0);
    for (i = 0; i < READERS; i++) {
        int64_t ret = psci_cpu_on(i + 1, SYMBOL_ADDRESS(xmc_secondary), i);
        if (ret != 0) {
            ml_printf("FAIL: PSCI CPU_ON for CPU %d returned %ld\n",
                      i + 1, ret);
            return 1;
        }
    }
    for (i = 0; i < READERS; i++) {
        if (wait_for(&ready[i], 1) < 0) {
            ml_printf("FAIL: reader %d did not start\n", i);
            return 1;
        }
    }

    for (uint32_t round = 1; round <= ROUNDS; round++) {
        patch(POISON);
        seed = seed * 1103515245 + 12345;
        /* volatile, so that the delay loop is not optimized away */
        for (volatile uint32_t d = (seed >> 16) % (MAX_DELAY + 1); d; d--) {
        }
        patch(round);
        store_release(&published, round);
        for (i = 0; i < READERS; i++) {
            if (wait_for(&ack[i], round) < 0) {
                ml_printf("FAIL: reader %d did not answer round %d\n",
                          i, round);
                return 1;
            }
        }
        if (load_acquire(&failed)) {
            break;
        }
    }

    for (i = 0; i < READERS; i++) {
        total += transient[i];
        if (stale_round[i]) {
            ml_printf("FAIL: reader %d: round %d published, "
                      "xmc_fn returns %d%s\n", i, stale_round[i],
                      stale_value[i],
                      stale_value[i] == POISON ? " (the poison)" : "");
        }
    }
    if (load_acquire(&failed)) {
        return 1;
    }
    ml_printf("PASS: %d rounds, %d reads that caught up within a second\n",
              ROUNDS, total);
    return 0;
}
