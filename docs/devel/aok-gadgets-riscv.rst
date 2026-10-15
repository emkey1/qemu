.. SPDX-License-Identifier: GPL-2.0-or-later

====================
AOK gadgets: RISC-V
====================

``target/riscv/tcg/aok``: RV64 guests.

Translated: the integer base, M, A, Zba, Zbb, Zbs and Zicond, C, loads and
stores, branches, ``jal`` and ``jalr``, CSR accesses, and F and D.

* Atomics and CSR accesses are one call to C, which does what
  ``trans_rva.c.inc`` and the ``trans_csr*`` functions generate with the same
  helpers. A CSR access ends its TB in the main loop, as with TCG.
* Double-precision arithmetic, comparisons and integer conversions run on
  the host's FP unit when the rounding mode is to nearest, in the cases where
  the host gives softfloat's answer, flags included (``gadgets.S`` lists
  them). Single precision, other rounding modes and the rarer operations are
  softfloat's, called from the stream.
* Left to TCG: ``ecall``, ``ebreak``, ``sret``, ``mret``, ``wfi``, the
  fences other than ``fence``, vectors, and every extension not listed.

A TB is translated only for RV64 with a little-endian guest, not
virtualized, with no pointer masking, CFI or instruction-count trigger, and
with the C extension. It stays within its page. The ``virt`` machine says
which engine runs it in its device tree (``aok_fdt_announce()``).

Gadgets taken from iSH-AOK
==========================

RISC-V's integer gadgets, its loads and stores, its branches and direct
jumps, and the pairs made of them came from iSH-AOK: ``shared/alu.S``,
``shared/frag.h`` and ``shared/pairs.h`` were its ``jit/guest-riscv64``
files of those names, and ``gadgets-shared.S`` assembles them with this
tree's definitions of what they ask of a host (``frag.h``, "A second host").
How a TB is left (``branch_leave``) is ``aok_gadget_goto``'s code, a copy for
each way out, so that each ends in an indirect branch of its own. ``jalr`` is
this tree's own, since it ends in a TB lookup, but it is written as a body
under the name of iSH-AOK's ``jalr_cached``, and so takes the pairs that end
in that.

``translate.c`` reads ``pairs.h`` as iSH-AOK's translator does: its table
of 535 pairs, measured from seven workloads, every one of them built here.
Not all can occur yet: iSH-AOK's translator also folds a few
two-instruction idioms into one gadget (a shift pair, a shift and an add, a
constant or a bit test and the branch on it), which this one does not, and
the pairs that name those gadgets wait for that.

With iSH-AOK's first table (332 pairs), in host CPU cycles on an Apple M5 Max,
without pairs (``QEMU_AOK_NO_PAIRS=1``) and with them, five interleaved runs
of each:

==================== ============ ========== =======
Workload             Without      With pairs Ratio
==================== ============ ========== =======
CoreMark             6.72 G       6.23 G     1.080
n-body (doubles)     3.37 G       3.25 G     1.035
Python               12.92 G      11.80 G    1.095
xz -3                5.58 G       4.88 G     1.144
sha256sum            3.36 G       3.09 G     1.087
awk                  5.02 G       4.65 G     1.080
==================== ============ ========== =======

In a guest boot and those programs, 220,000 pairs were fused out of 697,000
translated instructions, 66,000 of them forwarding a register.

Results
=======

Host CPU cycles a guest program takes under TCTI (``QEMU_AOK=0``, the same
binary) and under the gadgets, with ``-M virt -cpu rv64``, one guest CPU and
Alpine 3.24 (its 6.18 kernel and userland): what the QEMU process spends
between a program's first line of output and its last, the median of two runs.
On an Apple M5 Max (macOS); the last column is the same ratio on an iPad Pro
with an M4, in an iOS app, where nothing may be generated at run time and TCTI
is what the gadgets replace.

==================== ========= ============ =========== =======
Workload             TCTI      AOK gadgets  TCTI / AOK  M4
==================== ========= ============ =========== =======
CoreMark              11.7 G     6.1 G      1.91        1.90
n-body (doubles)      10.1 G     3.2 G      3.13        2.77
Python                32.5 G    10.3 G      3.16        3.18
xz -3                  8.5 G     5.1 G      1.66        1.70
sha256sum              5.1 G     2.9 G      1.72        1.75
awk                   11.5 G     4.5 G      2.56        2.58
==================== ========= ============ =========== =======

Run-time switches
=================

``QEMU_AOK_NO_CSR``, ``QEMU_AOK_NO_ATOMIC``, ``QEMU_AOK_NO_FP``, ``QEMU_AOK_NO_FPNATIVE``
  Leave that instruction class to TCG (or, for the last, to softfloat), for
  bisecting.
