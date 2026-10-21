/*
 * AOK gadgets: the softmmu TLB as the gadgets' fast path reads it.
 *
 * The assembly cannot include QEMU's C headers, so the numbers are written
 * here, for every front end's gadgets, and accel/tcg/aok.c checks each one
 * against QEMU's own when it is built. A change to the TLB upstream then
 * fails the build, where it would otherwise send the gadgets to a slot that
 * is not the access's, or read the wrong word of the entry.
 *
 * The fast path, as TCG's backends inline it: the index is the page number
 * (address >> AOK_TLB_PAGE_BITS) masked with CPUTLBDescFast.mask, which
 * holds the table's size less one already shifted by AOK_TLB_ENTRY_BITS, so
 * one AND of the address shifted right by AOK_TLB_SHIFT is the entry's
 * offset in the table.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_AOK_TLB_H
#define ACCEL_TCG_AOK_TLB_H

/* The guest page every front end's gadgets assume; each checks its own. */
#define AOK_TLB_PAGE_BITS   12
/* CPU_TLB_ENTRY_BITS on a 64-bit host: an entry is 32 bytes. */
#define AOK_TLB_ENTRY_BITS  5
#define AOK_TLB_SHIFT       (AOK_TLB_PAGE_BITS - AOK_TLB_ENTRY_BITS)

/* CPUTLBDescFast: mask and table, loaded together with one LDP. */
#define AOK_TLBF_MASK       0
#define AOK_TLBF_TABLE      8

/* CPUTLBEntry: the comparators and the addend. */
#define AOK_TLBE_READ       0
#define AOK_TLBE_WRITE      8
#define AOK_TLBE_ADDEND     24

#endif
