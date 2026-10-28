/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RCG's gadgets between TCG's instructions in one TB.
 *
 * An instruction RCG has no gadget for (IMUL, BSWAP, a shift by CL, STC,
 * ADC) leaves a register or the flags state in a TCG register, and a
 * gadget then writes all of it, reads it, or writes part of it. Each case
 * loads every register, runs its instructions and stores the registers and
 * the arithmetic flags, all in one asm statement, and prints them for three
 * IMUL multipliers. The output must be TCG's, held in rcg-mix.ref.
 */

#include "minilib.h"

typedef unsigned long u64;

u64 in[16], out[17];

#define LOAD \
    "mov in+0(%%rip), %%rax\n" "mov in+8(%%rip), %%rcx\n" \
    "mov in+16(%%rip), %%rdx\n" "mov in+24(%%rip), %%rbx\n" \
    "mov in+40(%%rip), %%rbp\n" "mov in+48(%%rip), %%rsi\n" \
    "mov in+56(%%rip), %%rdi\n" "mov in+64(%%rip), %%r8\n" \
    "mov in+72(%%rip), %%r9\n" "mov in+80(%%rip), %%r10\n" \
    "mov in+88(%%rip), %%r11\n" "mov in+96(%%rip), %%r12\n" \
    "mov in+104(%%rip), %%r13\n" "mov in+112(%%rip), %%r14\n" \
    "mov in+120(%%rip), %%r15\n"

#define STORE \
    "mov %%rax, out+0(%%rip)\n" "mov %%rcx, out+8(%%rip)\n" \
    "mov %%rdx, out+16(%%rip)\n" "mov %%rbx, out+24(%%rip)\n" \
    "mov %%rbp, out+40(%%rip)\n" "mov %%rsi, out+48(%%rip)\n" \
    "mov %%rdi, out+56(%%rip)\n" "mov %%r8, out+64(%%rip)\n" \
    "mov %%r9, out+72(%%rip)\n" "mov %%r10, out+80(%%rip)\n" \
    "mov %%r11, out+88(%%rip)\n" "mov %%r12, out+96(%%rip)\n" \
    "mov %%r13, out+104(%%rip)\n" "mov %%r14, out+112(%%rip)\n" \
    "mov %%r15, out+120(%%rip)\n" \
    "pushfq\n" "pop %%rax\n" "mov %%rax, out+128(%%rip)\n"

#define CASE(name, body) \
    static void name(void) \
    { \
        asm volatile(LOAD body STORE ::: "rax", "rbx", "rcx", "rdx", \
                     "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", \
                     "r13", "r14", "r15", "memory", "cc"); \
    }

/* RMW gadgets after IMUL left the register in a TCG register. */
CASE(c_add, "imul %%rbx, %%rax\n" "add %%rcx, %%rax\n")
CASE(c_unary, "imul %%rbx, %%rax\n" "not %%rax\n" "neg %%rax\n")
CASE(c_ror, "imul %%rbx, %%rax\n" "ror $5, %%rax\n")
CASE(c_dec16, "imul %%rbx, %%rax\n" "dec %%ax\n")
CASE(c_sub_setb, "imul %%rbx, %%rax\n" "sub %%rcx, %%rax\n" "setb %%dl\n")
/* Whole writes over it. */
CASE(c_mov32, "imul %%rbx, %%rax\n" "mov %%ecx, %%eax\n")
CASE(c_mov64, "imul %%rbx, %%rax\n" "mov %%rcx, %%rax\n" "add %%rax, %%rdx\n")
CASE(c_zero32, "imul %%rbx, %%rax\n" "xor %%eax, %%eax\n")
CASE(c_shl_mov, "shl %%cl, %%rax\n" "mov %%ebx, %%eax\n")
CASE(c_pop, "imul %%rbx, %%rax\n" "push %%rcx\n" "pop %%rax\n")
CASE(c_lea, "imul %%rcx, %%rbx\n" "lea 8(%%rbx), %%rax\n")
CASE(c_movzx, "imul %%rbx, %%rax\n" "movzbl %%cl, %%eax\n")
/* Partial writes over it. */
CASE(c_mov16, "imul %%rbx, %%rax\n" "mov %%cx, %%ax\n")
CASE(c_mov8, "bswap %%rax\n" "mov %%cl, %%al\n")
CASE(c_zero16, "imul %%rbx, %%rcx\n" "xor %%cx, %%cx\n")
CASE(c_movzx16, "imul %%rbx, %%rax\n" "movzbw %%cl, %%ax\n")
CASE(c_setl, "imul %%rbx, %%rdx\n" "cmp %%rax, %%rbx\n" "setl %%dl\n")
/* A whole-write form that reads its destination too. */
CASE(c_lea_self, "imul %%rcx, %%rbx\n" "lea (%%rbx,%%rbx), %%rbx\n")
CASE(c_movzx_self, "bswap %%eax\n" "movzbl %%al, %%eax\n")
CASE(c_movsxd_self, "imul %%rbx, %%rax\n" "movslq %%eax, %%rax\n")
CASE(c_mov_self, "imul %%rbx, %%rax\n" "mov %%rax, %%rax\n"
     "add %%rax, %%rdx\n")
CASE(c_mov_rip, "imul %%rbx, %%rax\n" "mov in+8(%%rip), %%rax\n")
CASE(c_cmov, "imul %%rbx, %%rdx\n" "cmp %%rax, %%rbx\n" "cmovl %%rcx, %%rdx\n")
/* A gadget reading what IMUL left. */
CASE(c_mov_from, "imul %%rbx, %%rax\n" "mov %%rax, %%rcx\n"
     "imul %%rbx, %%rcx\n")
/* The flags state: CF kept by INC and DEC, set whole by ADD and CMP. */
CASE(c_inc_adc, "imul %%rbx, %%rax\n" "inc %%rax\n" "adc $0, %%rdx\n")
CASE(c_dec_adc, "stc\n" "dec %%rcx\n" "adc $0, %%rdx\n")
CASE(c_inc_cmp, "imul %%rbx, %%rax\n" "inc %%rax\n" "cmp %%rbx, %%rax\n"
     "setb %%dl\n")
CASE(c_inc_add_adc, "stc\n" "inc %%rax\n" "add %%rbx, %%rcx\n"
     "adc $0, %%rdx\n")
CASE(c_imul_cmp, "imul %%rbx, %%rax\n" "cmp %%rcx, %%rdx\n")
CASE(c_imul_xor, "imul %%rbx, %%rax\n" "xor %%ecx, %%ecx\n" "adc $0, %%rdx\n")
/* Across TBs: a loop, a call and return, an indirect jump. */
CASE(c_loop, "mov $5, %%ecx\n" "1: imul %%rbx, %%rax\n" "inc %%rax\n"
     "add %%rax, %%rdx\n" "dec %%ecx\n" "jnz 1b\n")
CASE(c_call, "call 2f\n" "jmp 3f\n" "2: imul %%rbx, %%rax\n" "ret\n" "3:\n")
CASE(c_jmp, "lea 4f(%%rip), %%rsi\n" "imul %%rbx, %%rax\n" "jmp *%%rsi\n"
     "4: lea 4b(%%rip), %%rdi\n" "sub %%rdi, %%rsi\n" "xor %%edi, %%edi\n")

static const struct {
    const char *name;
    void (*fn)(void);
} cases[] = {
#define C(n) { #n, n }
    C(c_add), C(c_unary), C(c_ror), C(c_dec16), C(c_sub_setb), C(c_mov32),
    C(c_mov64), C(c_zero32), C(c_shl_mov), C(c_pop), C(c_lea), C(c_movzx),
    C(c_mov16), C(c_mov8), C(c_zero16), C(c_movzx16), C(c_setl),
    C(c_lea_self), C(c_movzx_self), C(c_movsxd_self), C(c_mov_self),
    C(c_mov_rip), C(c_cmov), C(c_mov_from), C(c_inc_adc), C(c_dec_adc),
    C(c_inc_cmp), C(c_inc_add_adc), C(c_imul_cmp), C(c_imul_xor), C(c_loop),
    C(c_call), C(c_jmp),
};

/* rbx, the IMUL multiplier: overflowing, 1, and -1. */
static const u64 multipliers[] = {
    0xfedcba9876543211ul, 1, ~0ul,
};

int main(void)
{
    int n = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < n; i++) {
        for (int m = 0; m < 3; m++) {
            for (int r = 0; r < 16; r++) {
                in[r] = 0x0123456789abcdeful * (r + 1) ^ (0x80ul << r);
            }
            in[1] = 0x7fffffff80000003ul;
            in[3] = multipliers[m];
            cases[i].fn();
            ml_printf("%s/%d:", cases[i].name, m);
            for (int r = 0; r < 16; r++) {
                if (r != 4) {
                    ml_printf(" %lx", out[r]);
                }
            }
            ml_printf(" f=%lx\n", out[16] & 0x8d5);
        }
    }
    return 0;
}
