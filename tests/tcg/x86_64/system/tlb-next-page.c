/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Loads and stores at the end of a page whose TLB slot may hold the next
 * page's entry.
 *
 * The fast paths of the AArch64 JIT and TCTI check an access that may cross
 * a page by comparing its last byte's page with the entry in its first
 * byte's slot, which is only enough if consecutive pages never share a slot.
 * That holds while the TLB index is the page number's low bits. tctiSH once
 * folded higher page bits into the index, and then pages 0x7fff and 0x8000
 * shared one in TLBs of 64 to 256 entries: every size this test's TLB can
 * have, since it starts at 256 and can only shrink here. Touching page
 * 0x8000 put its entry in the slot, and an access at the end of page 0x7fff
 * then used its addend, going to the host memory just below page 0x8000's.
 * TCTI checks the last of 8 bytes for every access of 2 to 8, so there
 * accesses within the page went wrong too.
 *
 * boot.S maps memory one to one, which gives every page the same addend, so
 * the wrong entry would still come out right. The 2 MiB that start at page
 * 0x8000 are remapped to other memory first. Needs -m 256M.
 */

#include <minilib.h>
#include <stdint.h>

#define PAGE 4096
#define MiB (1024 * 1024)

/* The higher page of the pair, and where its 2 MiB are remapped to. */
#define HI 0x08000000
#define REMAP_TO 0x0c000000

/*
 * Every access here is part of what is tested, so the compiler must make
 * each one as written, at its size, and none it can do without.
 */
#define MEM(type, addr) (*(type volatile *)(addr))

static uint64_t read_cr3(void)
{
    uint64_t cr3;

    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

/* Maps the 2 MiB at virt to phys, through boot.S's page tables. */
static void map_2m(uintptr_t virt, uintptr_t phys)
{
    uint64_t *pml4 = (uint64_t *)(read_cr3() & ~0xfffull);
    uint64_t *pdp = (uint64_t *)(pml4[(virt >> 39) & 511] & ~0xfffull);
    uint64_t *pd = (uint64_t *)(pdp[(virt >> 30) & 511] & ~0xfffull);
    uint64_t *pde = &pd[(virt >> 21) & 511];

    *pde = (phys & ~(2ull * MiB - 1)) | (*pde & 0xfff);
    asm volatile("mov %0, %%cr3" : : "r"(read_cr3()) : "memory");
}

static uint64_t bytes_at(uintptr_t addr, int n)
{
    uint64_t v = 0;

    for (int i = n - 1; i >= 0; i--) {
        v = v << 8 | MEM(uint8_t, addr + i);
    }
    return v;
}

static uint64_t load(uintptr_t addr, int n)
{
    switch (n) {
    case 2:
        return MEM(uint16_t, addr);
    case 4:
        return MEM(uint32_t, addr);
    default:
        return MEM(uint64_t, addr);
    }
}

static void store(uintptr_t addr, int n, uint64_t v)
{
    switch (n) {
    case 2:
        MEM(uint16_t, addr) = v;
        break;
    case 4:
        MEM(uint32_t, addr) = v;
        break;
    default:
        MEM(uint64_t, addr) = v;
        break;
    }
}

int main(void)
{
    const uintptr_t hi = HI, lo = HI - PAGE;
    int checks = 0, bad = 0;

    map_2m(hi, REMAP_TO);
    for (int i = 0; i < 2 * PAGE; i++) {
        MEM(uint8_t, lo + i) = (i < PAGE ? 0x10 : 0xa0) + (i & 7);
    }

    for (int n = 2; n <= 8; n *= 2) {
        /* The last 8 bytes of the lower page, crossing or not. */
        for (uintptr_t addr = hi - 8; addr < hi; addr++) {
            const char *what = addr + n > hi ? "crossing" : "within";
            uint64_t mask = n == 8 ? ~0ull : (1ull << (8 * n)) - 1;
            uint64_t want, got, before, value;

            want = bytes_at(addr, n);
            (void)MEM(uint8_t, hi);
            got = load(addr, n);
            checks++;
            if (got != want) {
                ml_printf("FAIL: load%d at %lx (%s): %lx, not %lx\n", n, addr,
                          what, got, want);
                bad++;
            }

            before = bytes_at(addr, n);
            value = 0x0123456789abcdefull ^ addr * 0x9e3779b97f4a7c15ull;
            value &= mask;
            (void)MEM(uint8_t, hi);
            store(addr, n, value);
            got = bytes_at(addr, n);
            checks++;
            if (got != value) {
                ml_printf("FAIL: store%d at %lx (%s): memory has %lx, "
                          "not %lx\n", n, addr, what, got, value);
                bad++;
            }
            for (int i = 0; i < n; i++) {
                MEM(uint8_t, addr + i) = before >> (8 * i);
            }
        }
    }

    ml_printf("%d checks, %d failed\n", checks, bad);
    return bad ? 1 : 0;
}
