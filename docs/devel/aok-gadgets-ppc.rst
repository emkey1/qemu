.. SPDX-License-Identifier: GPL-2.0-or-later

======================
AOK gadgets: PowerPC
======================

``target/ppc/tcg/aok``: 32-bit PowerPC guests in ``qemu-system-ppc``, the
Power Macintoshes (``mac99``, ``g3beige``). ``cpu_init.c`` offers the
translator to TCG only in that binary; ``qemu-system-ppc64`` runs as it did.

Translated: integer arithmetic and logic (without OE), compares, rotates and
shifts, the record forms, XER's CA, the CR's own insns (the logical ops,
``mcrf``, ``mfcr``, ``mtcrf``, ``mcrxr``), ``mfspr`` and ``mtspr`` of LR, CTR
and XER and of any SPR whose callback is the generic one (VRSAVE; in
supervisor mode the SPRGs, SRR0, SRR1 and others), the time base (``mftb``), the integer loads and stores of every
size, update and indexed form and the byte-reversed ones, ``lmw`` and
``stmw``, ``lwarx`` and ``stwcx.``, ``dcbz``, ``b``, ``bc`` on a CR bit, on
CTR or on both, ``blr`` (also on a CR bit), ``bctr`` and their linking forms,
``sync`` in user mode, ``eieio``, ``dcbt`` and ``dcbtst``, traps with TO 0
(which do nothing); and floating point: the loads and stores, ``fmr``,
``fneg``, ``fabs``, ``fnabs``, ``fsel``, the double-precision arithmetic, the
fused multiply-adds, ``fsqrt``, ``frsp``, ``fctiw``, ``fctiwz``, ``fcmpu``,
``fcmpo``, ``mffs``, and as calls to C the single-precision arithmetic, the
estimates and the FPSCR's other insns.

* ``lmw``, ``stmw``, ``dcbz`` and ``mftb`` are one call to C, QEMU's own
  helpers. ``lwarx`` and ``stwcx.`` are one call each, what TCG generates
  for them where it runs one CPU at a time (as qemu-system-ppc always does):
  the aligned load that reserves, and the conditional store that loads and
  then always stores.
* A record form is the insn's gadget and then one that sets CR0 from the
  register it wrote, as ``gen_set_Rc0`` does. The carry is the host's: its
  ``adds``/``adcs`` set C as PowerPC sets CA, and ``subs``/``sbcs`` compute
  rB + ~rA + C, ``subf``'s definition.
* Where the architecture leaves a result undefined, the gadgets give QEMU's:
  ``divw`` and ``divwu`` by zero, and ``0x80000000 / -1``, leave rA in rD;
  ``sraw`` writes CA32 as QEMU's helper does, ``srawi`` does not.
* Left to TCG, where its TB ends or an exception is due: the OE forms,
  AltiVec, ``sc``, ``rfi``, ``isync``, ``mtmsr`` and ``mfmsr``, ``sync`` in
  supervisor mode, ``dcbf``, ``dcbst`` and ``icbi``, traps that test
  something, the forms QEMU takes for illegal (an update load whose rA is 0
  or rD, an update store whose rA is 0, ``lwbrx.``), ``mfocrf`` and
  ``mtocrf``, ``mcrfs``, a conditional ``bcctr``, and every FP insn while
  MSR[FP] is clear.

A TB is translated only for a big-endian guest (MSR[LE] clear) that is not
single-stepping or tracing branches (MSR[SE], MSR[BE]), which TCG turns into
trace exceptions. It stays within its page. PowerPC's TBs are not
pc-relative, and its pc, ``nip``, is 32 bits: ``TCGCPUOps.aok_pc32`` makes the
core enter and leave its streams with ``aok_gadget_enter32`` and a 32-bit
store, and a stream's jumps wrap as the guest's do.

Guest memory
============

The guest is big-endian on a little-endian host: a load reverses what it
read, a store what it writes, and ``lhbrx`` and its kin are the plain
host-order accesses. The slow path does the whole access in C, a big-endian
one (little-endian for the byte-reversed insns), and a load rejoins the
gadget with the value past the reversal. Before it, it stores ``nip`` and
``access_type``, which TCG's code stores at the first memory insn of a TB and
the 32-bit MMU reads on a fault. An update form writes rA once its access is
done, so that a fault leaves rA as it was.

Where rA is 0, ``(rA|0)`` reads ``aok_zero``, a word of ``CPUPPCState`` that
is always 0, so that one gadget serves both forms; Mac OS reaches its
low-memory globals that way.

Fused pairs
===========

Two families, with the core's ``aok_gen_pair`` (the general page): an op and
its record form's CR0 (``add.``, ``and.``, ``andi.``, ``rlwinm.``, ``mr.``
and the like, 22 ops), and a compare (``cmp``, ``cmpi``, ``cmpl``,
``cmpli``) and a branch on a CR bit after it. Each has a forwarding form,
which takes the register the first wrote (the result, or the CR field's
value) from the first's host register. The integer gadgets are one body per
op (``op_add`` ...) for the op's own gadget and the pairs it is in; a
translated insn's gadgets are offered to the pair table one by one
(``pair_steps``). ``QEMU_AOK_NO_PAIRS`` and ``QEMU_AOK_NO_FWD`` turn them
off. Host cycles, five interleaved runs each, medians, without pairs over
with: CoreMark 1.064, n-body 1.017, xz 1.018, sha256 1.003, awk 0.997. The
list is a first one, by hand; one measured from what programs execute is
to follow, as RISC-V's was.

Floating point
==============

The FPRs are doublewords of ``vsr[]``. ``lfs`` and ``stfs`` convert between a
single and a double as QEMU's ``helper_todouble`` and ``helper_tosingle`` do,
bit for bit and without rounding, in the gadgets.

An arithmetic insn in TCG resets softfloat's flags, calls its helper, writes
the FPR, sets FPRF from the result and checks the flags
(``do_float_check_status``), which may set FPSCR's exception bits and trap.
For a clean result that is all: FPRF, FI set to whether it was inexact, and
XX and FX if it was; and with RN to nearest, NI off and the XE, UE and OE
enables clear it cannot trap. The gadgets compute on the host's FP unit
where that is so, and otherwise do the insn again in C by QEMU's helpers in
TCG's order (``aok_ppc_helper_fp``).

They cannot ask the host's FPSR which results are clean: on an Apple M5 Max an
``fmadd`` that clears it first and reads it after costs 13.5 ns against 1.0,
writing FPSR stalling the FP unit. So each finds whether its result was
exact by an error-free transformation (TwoSum for an add, an FMA for the
error of a product, the remainder of a quotient or a square root, and for
the fused ops the exact product against the exact difference of the result
and the addend, each as a pair of doubles), in the exponent range where
that is exact, and reads the rest from the values: a NaN (an invalid op, or
one propagated, which PowerPC does its own way), an infinity (an overflow or
a zero divide), an inexact zero (an underflow), a denormal or a result small
enough that tininess before rounding (QEMU's for PowerPC) and after it (the
host's) could disagree, and operands outside that range, all go to C.
``fnmadd`` and ``fnmsub`` negate the rounded result, as QEMU's
``float_muladd_negate_result`` does, so that the sign of a zero is theirs.
``fctiw`` returns the word sign-extended, as QEMU's helper does.

For iSH-AOK
===========

The gadgets are written so that a PowerPC guest in iSH-AOK can take them:
nothing in ``gadgets.S`` but the memory macros and the ways a TB is left is
particular to QEMU, the operands are offsets into a CPU state, and the
condition register and XER are kept as QEMU keeps them (a word per CR field,
SO, OV and CA a word each), which suits a gadget that writes one of them.

Results
=======

Host CPU cycles on an Apple M5 Max, the kit's Linux 6.12 guest (``mac99``,
a G4), TCTI alone (``QEMU_AOK=0``) and with the gadgets, three interleaved
runs of each, medians:

==================== ============ ========== =======
Workload             TCTI         Gadgets    Ratio
==================== ============ ========== =======
CoreMark             13.55 G      4.65 G     2.91
n-body (doubles)     98.54 G      17.33 G    5.69
xz -3                16.95 G      7.79 G     2.18
sha256sum            6.50 G       3.43 G     1.90
awk                  10.55 G      4.00 G     2.64
==================== ============ ========== =======

n-body was 0.83 while floating point was TCG's (its loops went from a
stream to a TCG TB and back through the main loop at each FP insn), and 1.59
with FP gadgets that read the host's FPSR.

Tests
=====

The kit's ``check``, ``fptest`` and ``memtest`` transcripts (see the
general page) are identical with ``QEMU_AOK=0`` and with the gadgets, 143
lines, the guest's clock at boot aside; with pairs, without forwarding and
without pairs.

``fpstress`` (aok-vm's ``aok/bench-pm/stress``) runs two million FP ops on
operands chosen to sit where the gadgets draw their lines: exponents near
the bottom and top of the range, zeros, denormals, infinities, NaNs, values
with few mantissa bits so that many results are exact, in random rounding
modes and with random sticky bits in FPSCR, and hashes the result and
FPSCR after each. Its ten hashes are identical; with XX left unset on an
inexact result, all ten differ.
