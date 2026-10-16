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
and XER, the integer loads and stores of every size, update and indexed form
and the byte-reversed ones, ``lmw`` and ``stmw``, ``b``, ``bc`` on a CR bit
or on CTR, ``blr``, ``bctr`` and their linking forms, ``sync`` in user mode,
``eieio``, ``dcbt`` and ``dcbtst``.

* ``lmw`` and ``stmw`` are one call to C, QEMU's own helpers.
* A record form is the insn's gadget and then one that sets CR0 from the
  register it wrote, as ``gen_set_Rc0`` does. The carry is the host's: its
  ``adds``/``adcs`` set C as PowerPC sets CA, and ``subs``/``sbcs`` compute
  rB + ~rA + C, ``subf``'s definition.
* Where the architecture leaves a result undefined, the gadgets give QEMU's:
  ``divw`` and ``divwu`` by zero, and ``0x80000000 / -1``, leave rA in rD;
  ``sraw`` writes CA32 as QEMU's helper does, ``srawi`` does not.
* Left to TCG, where its TB ends or an exception is due: the OE forms,
  floating point, AltiVec, ``lwarx`` and ``stwcx.``, ``mftb``, ``sc``,
  ``rfi``, ``isync``, ``mtmsr`` and ``mfmsr``, ``sync`` in supervisor mode,
  the cache-block insns that touch memory (``dcbz``, ``dcbf``, ``dcbst``,
  ``icbi``), traps, the forms QEMU takes for illegal (an update load whose
  rA is 0 or rD, an update store whose rA is 0, ``lwbrx.``), ``mfocrf`` and
  ``mtocrf``, ``bc`` on a CR bit and CTR at once, and the conditional
  ``bclr`` and ``bcctr``.

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
CoreMark             13.50 G      5.03 G     2.69
n-body (doubles)     98.80 G      118.41 G   0.83
xz -3                16.98 G      8.72 G     1.95
sha256sum            6.32 G       3.88 G     1.63
awk                  10.56 G      6.42 G     1.64
==================== ============ ========== =======

n-body is floating point, which TCG still translates: its loops go from a
stream to a TCG TB and back through the main loop at every FP insn, since
the two cannot jump into each other. That is what FP gadgets are for.

Tests
=====

The kit's ``check``, ``fptest`` and ``memtest`` transcripts (see the
general page) are identical with ``QEMU_AOK=0`` and with the gadgets, 143
lines, the guest's clock at boot aside.
