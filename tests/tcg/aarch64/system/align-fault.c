/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Loads and stores that require alignment, misaligned and aligned.
 *
 * On a CPU without FEAT_LSE2, LDXR, LDAR and STLR require their natural
 * alignment, and with SCTLR_EL1.A set so do plain loads and stores. A
 * misaligned one must raise an alignment fault and leave memory alone; an
 * aligned one must not fault, and must read or write the right bytes.
 * TCTI's fast paths for 2, 4 and 8 bytes once ignored the alignment an
 * access required, and let misaligned ones through. Needs -cpu cortex-a57.
 */

#include <stdint.h>
#include <minilib.h>

/* Counted, with the last syndrome, by the synchronous exception handler. */
volatile uint64_t fault_count, fault_esr;

/* SYS_EXIT's block for an unexpected exception: an application exit, 2. */
const uint64_t unexpected_exit[2] __attribute__((used)) = { 0x20026, 2 };

/*
 * EL1's vectors: a synchronous exception at EL1 is counted and the
 * instruction skipped; anything else ends the test.
 */
asm(
    "    .balign 2048\n"
    "align_vectors:\n"
    "    .rept 4\n"
    "    b align_unexpected\n"
    "    .balign 128\n"
    "    .endr\n"
    "    sub sp, sp, #16\n"
    "    stp x0, x1, [sp]\n"
    "    adrp x0, fault_count\n"
    "    ldr x1, [x0, :lo12:fault_count]\n"
    "    add x1, x1, #1\n"
    "    str x1, [x0, :lo12:fault_count]\n"
    "    adrp x0, fault_esr\n"
    "    mrs x1, esr_el1\n"
    "    str x1, [x0, :lo12:fault_esr]\n"
    "    mrs x0, elr_el1\n"
    "    add x0, x0, #4\n"
    "    msr elr_el1, x0\n"
    "    ldp x0, x1, [sp]\n"
    "    add sp, sp, #16\n"
    "    eret\n"
    "    .balign 128\n"
    "    .rept 11\n"
    "    b align_unexpected\n"
    "    .balign 128\n"
    "    .endr\n"
    "align_unexpected:\n"
    "    mov x0, #0x18\n"
    "    adrp x1, unexpected_exit\n"
    "    add x1, x1, :lo12:unexpected_exit\n"
    "    hlt #0xf000\n"
    "    b .\n"
);

static uint8_t buf[64] __attribute__((aligned(64)));
static int checks, failed;

/* An alignment fault, data abort at EL1, as the last exception. */
static int alignment_faulted(void)
{
    return fault_count == 1 && (fault_esr >> 26 & 0x3f) == 0x25 &&
           (fault_esr & 0x3f) == 0x21;
}

static void fail(const char *what, int off)
{
    ml_printf("FAIL: %s at buf + %d\n", what, off);
    failed++;
}

/* A load of x0 from [x1], as one instruction. */
#define CHECK_LOAD(insn, size, off, faults) do {                        \
    uint64_t v = 0, want = 0;                                           \
    for (int i = size - 1; i >= 0; i--) {                               \
        want = want << 8 | buf[(off) + i];                              \
    }                                                                   \
    fault_count = 0;                                                    \
    asm volatile("mov x1, %1\n\t" insn "\n\tclrex\n\tmov %0, x0"        \
                 : "+r"(v) : "r"(buf + (off)) : "x0", "x1", "memory");  \
    checks++;                                                           \
    if ((faults) ? !alignment_faulted()                                 \
                 : fault_count || (v & mask(size)) != want) {           \
        fail(insn, off);                                                \
    }                                                                   \
} while (0)

/* A store of x0 to [x1], as one instruction; buf is put back after. */
#define CHECK_STORE(insn, size, off, faults) do {                       \
    uint8_t before[sizeof(buf)], want[sizeof(buf)];                     \
    const uint64_t v = 0xa1a2a3a4a5a6a7a8ull;                           \
    int ok = 1;                                                         \
    for (int i = 0; i < sizeof(buf); i++) {                             \
        before[i] = want[i] = buf[i];                                   \
    }                                                                   \
    if (!(faults)) {                                                    \
        for (int i = 0; i < size; i++) {                                \
            want[(off) + i] = v >> (8 * i);                             \
        }                                                               \
    }                                                                   \
    fault_count = 0;                                                    \
    asm volatile("mov x0, %0\n\tmov x1, %1\n\t" insn                    \
                 : : "r"(v), "r"(buf + (off)) : "x0", "x1", "memory");  \
    checks++;                                                           \
    for (int i = 0; i < sizeof(buf); i++) {                             \
        ok &= buf[i] == want[i];                                        \
        buf[i] = before[i];                                             \
    }                                                                   \
    if (!ok || ((faults) ? !alignment_faulted() : fault_count != 0)) {  \
        fail(insn, off);                                                \
    }                                                                   \
} while (0)

static uint64_t mask(int size)
{
    return size == 8 ? ~0ull : (1ull << (8 * size)) - 1;
}

/* The instructions that require alignment whatever SCTLR_EL1.A is. */
static void check_ordered_and_exclusive(void)
{
    CHECK_LOAD("ldxrh w0, [x1]", 2, 1, 1);
    CHECK_LOAD("ldxrh w0, [x1]", 2, 2, 0);
    CHECK_LOAD("ldxr w0, [x1]", 4, 2, 1);
    CHECK_LOAD("ldxr w0, [x1]", 4, 4, 0);
    CHECK_LOAD("ldxr x0, [x1]", 8, 4, 1);
    CHECK_LOAD("ldxr x0, [x1]", 8, 8, 0);
    CHECK_LOAD("ldarh w0, [x1]", 2, 3, 1);
    CHECK_LOAD("ldarh w0, [x1]", 2, 6, 0);
    CHECK_LOAD("ldar w0, [x1]", 4, 6, 1);
    CHECK_LOAD("ldar w0, [x1]", 4, 12, 0);
    CHECK_LOAD("ldar x0, [x1]", 8, 12, 1);
    CHECK_LOAD("ldar x0, [x1]", 8, 16, 0);
    CHECK_STORE("stlrh w0, [x1]", 2, 1, 1);
    CHECK_STORE("stlrh w0, [x1]", 2, 2, 0);
    CHECK_STORE("stlr w0, [x1]", 4, 2, 1);
    CHECK_STORE("stlr w0, [x1]", 4, 4, 0);
    CHECK_STORE("stlr x0, [x1]", 8, 4, 1);
    CHECK_STORE("stlr x0, [x1]", 8, 8, 0);
}

static void set_sctlr_a(int on)
{
    uint64_t sctlr;

    asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr = on ? sctlr | 2 : sctlr & ~2ull;
    asm volatile("msr sctlr_el1, %0\n\tisb" : : "r"(sctlr) : "memory");
}

int main(void)
{
    asm volatile("adrp x0, align_vectors\n\t"
                 "add x0, x0, :lo12:align_vectors\n\t"
                 "msr vbar_el1, x0\n\t"
                 "isb" : : : "x0");
    for (int i = 0; i < sizeof(buf); i++) {
        buf[i] = i + 1;
    }

    check_ordered_and_exclusive();
    CHECK_LOAD("ldr x0, [x1]", 8, 1, 0);
    CHECK_STORE("str x0, [x1]", 8, 3, 0);

    set_sctlr_a(1);
    check_ordered_and_exclusive();
    CHECK_LOAD("ldrh w0, [x1]", 2, 1, 1);
    CHECK_LOAD("ldrh w0, [x1]", 2, 2, 0);
    CHECK_LOAD("ldrsh x0, [x1]", 2, 5, 1);
    CHECK_LOAD("ldr w0, [x1]", 4, 2, 1);
    CHECK_LOAD("ldrsw x0, [x1]", 4, 6, 1);
    CHECK_LOAD("ldr w0, [x1]", 4, 4, 0);
    CHECK_LOAD("ldr x0, [x1]", 8, 4, 1);
    CHECK_LOAD("ldr x0, [x1]", 8, 8, 0);
    CHECK_STORE("strh w0, [x1]", 2, 3, 1);
    CHECK_STORE("str w0, [x1]", 4, 6, 1);
    CHECK_STORE("str w0, [x1]", 4, 4, 0);
    CHECK_STORE("str x0, [x1]", 8, 2, 1);
    CHECK_STORE("str x0, [x1]", 8, 8, 0);
    set_sctlr_a(0);

    ml_printf("%d checks, %d failed\n", checks, failed);
    return failed ? 1 : 0;
}
