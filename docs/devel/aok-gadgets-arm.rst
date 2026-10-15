.. SPDX-License-Identifier: GPL-2.0-or-later

=====================
AOK gadgets: AArch64
=====================

``target/arm/tcg/aok``. Here the guest is the architecture iSH-AOK's first
64-bit engine was written for, and the host's own, so an instruction is most
often the same instruction with its registers read from ``env`` and written
back.

Translated: data processing with immediates and registers (all of it but the
tagged, pointer-authentication, CRC and CSSC instructions), conditional
selects and compares, loads and stores of X and W registers in every
addressing mode, pairs, literals, the unprivileged and the ordered ones,
exclusives, direct, conditional and indirect branches, the hint space,
barriers, system register accesses, ``msr daifset``/``daifclr``, ``svc`` and
``eret``; and the base architecture's floating point and Advanced SIMD, with
AES, SHA-1, SHA-256, PMULL and CRC32 where guest and host both have them.

* **Shared with iSH-AOK:** ``shared/alu_spec.S``, ``shared/frag.h`` and
  ``shared/pairs.h`` are its ``jit/guest-arm64`` files: the
  operand-specialised integer gadgets, the bodies of loads, stores, pairs and
  branches, and the table of pairs. ``gadgets-shared.S`` gives them this
  tree's host (``frag.h``, "A second host"): registers, the split flags,
  guest memory through the softmmu fast path, and how a TB is left.
* **Fused pairs**: iSH-AOK's 592, every one of them built here, with the
  forwarded result and a ``cmp`` and the ``b.cond`` after it as one gadget.
  The branch gadgets are iSH-AOK's bodies under its names, so that pairs can
  end in them; ``br``, ``blr`` and ``ret`` are this host's own bodies under
  those names (the TBI and the TB lookup).
* **XZR** is two slots after ``pc`` in ``CPUARMState``: ``aok_zero``, which
  nothing writes, and ``aok_sink``, which nothing reads. A gadget then takes
  register 31 as any other, and the translator chooses SP or one of those by
  the operand.
* **Flags** are QEMU's four words. A gadget that sets them stores them from
  the host's NZCV, and one that reads them loads the host's from them, unless
  the translator knows the host's are still the guest's from the gadget
  before (``Ctx.nf``), when the ``_nf`` variant is used.
* **A fault** in a load or store is raised from C with the instruction's pc
  and the syndrome template ``translate-a64.c`` would have left in the insn
  start words, both made from the opcode, which is the access's last operand.
* **System registers, exclusives, ``svc``, ``eret``** are one call to C each
  (``call``, ``call_exit``), which does what ``handle_sys()`` and the
  ``trans_*`` functions generate, with the same helpers. The translator makes
  the decisions a TB's flags allow; a read of a plain field with no access
  function is a move, and so is ``mrs xt, sp_el0`` once its gadget has seen
  PSTATE.SP. A write ends the TB in the main loop, as with TCG. The register
  is looked up at run time: a TB is every CPU's, an ``ARMCPRegInfo`` is one
  CPU's.
* **Hints** are NOPs only where QEMU's are. ``sev`` and ``sevl`` set the
  event register a ``wfe`` waits for, and are TCG's with ``wfe``, ``wfi`` and
  ``yield``.
* **Floating point and SIMD** are computed by the instruction itself. The
  guest's instruction set is the host's, so ``gadgets-simd.S`` holds every
  encoding of the class assembled on fixed registers, as a two-instruction
  thunk, in tables indexed by the bits that are not registers; a gadget is
  one of a few shapes (which registers are loaded from ``env`` and what is
  stored back) and calls the thunk it is given. What the translator decides
  is therefore not what an instruction does but whether it exists for the
  guest: the tables of the base architecture, without half-precision
  arithmetic and every later extension, which are TCG's.

  The host's FPCR is the guest's while such gadgets run, and the host's FPSR
  collects what they raise (``fp_on``, ``aok_fp_end``): rounding mode,
  flush-to-zero, default NaN, the cumulative flags and QC are the hardware's
  own. That is sound only for those three FPCR fields, and a TB does not say
  what the FPCR is: the first time any CPU's FPCR gets another bit
  (alternative half precision, FZ16, the AFP modes), FP becomes TCG's for
  good and every TB is flushed. FP is also TCG's while it traps, in
  streaming mode, and wherever SVE is enabled with vectors longer than 128
  bits, whose upper part a write would have to clear.
* **The structure loads and stores**: ``ld1`` and ``st1`` of one to four
  whole registers are gadgets (in a little-endian guest they are that many
  loads or stores of 8 or 16 bytes, whatever the arrangement); the
  interleaved ones, a single lane and the replicating loads are a call to C
  that reads and writes an element at a time as ``trans_LD_mult()`` and its
  kin do.
* Left to TCG: the other exceptions, the LSE atomics, SVE and SME; and with
  LSE2, whose alignment rule is another, the exclusives and ordered
  accesses.

A TB is translated only in AArch64 state with a little-endian guest and
4 KiB pages, with no single-step, alignment checking, MTE, GCS, nested
virtualization or pending branch-target check. On a CPU with BTI the
indirect branches are TCG's, since they set ``PSTATE.BTYPE``. The ``virt``
machine says which engine runs it in its device tree
(``aok_fdt_announce()``).

Results
=======

Host CPU cycles a guest program takes under TCTI (``QEMU_AOK=0``, the same
binary) and under the gadgets, with ``-M virt -cpu cortex-a72``, one guest CPU
and Alpine 3.24 (its 6.18 kernel and userland): what the QEMU process spends
between a program's first line of output and its last, the median of two runs.
On an Apple M5 Max (macOS); the last column is the same ratio on an iPad Pro
with an M4, in an iOS app, where nothing may be generated at run time and TCTI
is what the gadgets replace.

==================== ========= ============ =========== =======
Workload             TCTI      AOK gadgets  TCTI / AOK  M4
==================== ========= ============ =========== =======
CoreMark              10.7 G     3.6 G      3.01        3.09
n-body (doubles)      10.8 G     3.0 G      3.54        3.27
Python                31.3 G     9.0 G      3.49        3.69
xz -3                 10.1 G     4.4 G      2.30        2.82
sha256sum              4.6 G     1.9 G      2.43        2.45
awk                   10.8 G     4.0 G      2.71        2.96
==================== ========= ============ =========== =======

The fused pairs, with the forwarded result and ``cmp`` and ``b.cond`` as one
gadget, against none of the three (``QEMU_AOK_NO_PAIRS=1``,
``QEMU_AOK_NO_FUSE=1``), best of three interleaved runs on the M5 Max:
CoreMark 1.16, Python 1.08, xz 1.08, awk 1.04, sha256sum 1.03; on the M4,
best of two: CoreMark 1.15, sha256sum 1.11, Python 1.07, xz 1.05, awk 1.05.

Testing
=======

Beside the three transcripts every front end has, ``simdtest``: every
encoding of the scalar FP and Advanced SIMD data-processing space (560,640
of them, with fixed registers), each run on four sets of inputs, one under
another rounding mode with flush-to-zero and default NaN, and the result,
flags and FPSR hashed. An encoding that does not exist is a SIGILL and hashed
as that, so the transcript checks both which instructions a guest CPU has and
what each computes. The reference for this one is TCG with a JIT backend:
against QEMU 11.0.3 on a ``cortex-a72`` the transcripts are identical. The
threaded interpreter in this tree is not a reference here. It differs from
the JIT, from the gadgets and from hardware (the same guest under HVF) in
``cmlt #0`` and ``cmle #0`` on 8-, 16- and 32-bit lanes, and in ``sshl`` on
16- and 32-bit lanes.

The gates pass under UTM's machine options (``virt,virtualization=on,
gic-version=3``) and with ``-cpu max`` as well.

Run-time switches
=================

``QEMU_AOK_NO_SYS``, ``QEMU_AOK_NO_EXC``, ``QEMU_AOK_NO_ATOMIC``, ``QEMU_AOK_NO_FP``
  Leave to TCG: system register accesses; ``svc``, ``eret`` and the DAIF
  immediates; exclusives and ordered accesses; floating point and SIMD.

``QEMU_AOK_NO_FUSE``
  Do not make a ``cmp`` and the ``b.cond`` after it one gadget.
