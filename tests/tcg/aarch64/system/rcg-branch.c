/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * rcg-insns' cases that branch, run without goto_tb.
 *
 * Where each way out of a conditional branch starts with a goto_tb, TCTI
 * swaps in the branch gadget that makes the jump too, so rcg-insns runs
 * those. With -d nochain there is no goto_tb, and the same cases run the
 * gadgets that only branch. Their hashes are rcg-insns.ref's lines for
 * these cases.
 */

#define RCG_INSN_CASES "rcg-branch.h"
#include "rcg-insns.c"
