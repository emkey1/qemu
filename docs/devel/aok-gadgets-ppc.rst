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
``fneg``, ``fabs``, ``fnabs``, ``fsel``, the arithmetic and the fused
multiply-adds in double and in single precision, ``fsqrt``, ``frsp``,
``fctiw``, ``fctiwz``, ``fcmpu``, ``fcmpo``, ``mffs``, and as calls to C
``fsqrts``, the estimates and the FPSCR's other insns. Since 2026-11-28
also what sent Mac OS X's and Mac OS 9's streams to TCG most (below): the
OE forms, ``bcctr`` on a CR bit, ``mfocrf`` and ``mtocrf``, AltiVec's
``lvx`` and ``stvx`` and its hints, ``lswi`` and ``stswi``, the cache insns,
and for a supervisor ``mfmsr``, ``mtmsr``, the segment register moves,
``isync``, ``sync`` and ``rfi``.

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
* Left to TCG, where its TB ends or an exception is due: AltiVec but for
  ``lvx``, ``stvx`` and the hints, ``sc``, traps that test something, the
  forms QEMU takes for illegal (an update load whose rA is 0 or rD, an
  update store whose rA is 0, ``lwbrx.``), ``mcrfs``, ``bclrl`` on a CR
  bit, a ``bcctr`` that counts, ``lswx``, ``tlbie``, the decrementer, and
  every FP insn while MSR[FP] is clear and every AltiVec one while MSR[VR]
  is.

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

The single-precision ops (``fadds`` and the rest) are QEMU's ``float64r32``
helpers: the exact result rounded once, to a single. Where the operands are
singles (a round trip through a single gives each back) the host's single
arithmetic is that, the same transformations hold in it in the same ranges
scaled to 24 bits, and the result is widened again, which is exact. An
operand that is no single goes to C.

Some results outside those ranges are settled by the values alone, and the
gadgets finish them too, since programs meet them in loops (Xbench's FP
tests under Mac OS X did 43 million insns in C until these were added, and
87 thousand after, nearly all of them ``fctiw`` with FPSCR's RN set):

* A product with a zero operand is an exact zero, and a fused op with one is
  its addend, or a zero. A zero quotient of a zero dividend or of an infinite
  divisor is exact. (A zero that is an underflow stays C's.)
* A fused op whose product is not zero but under 2^-969 (2^-102 for a
  single), and whose addend is 2^-913 or more (2^-75), gives the addend,
  inexact.
* A fused op whose result is a zero while its product is in range cancelled
  exactly: the product is then a multiple of the smallest denormal.
* A quiet NaN operand is passed on, PowerPC's choice of them: frA, then frB,
  then frC, and a single op clears the 29 bits a single has no room for, as
  ``float64r32`` does. A signalling NaN, or infinity times zero beside a
  quiet one, is invalid and stays C's.
* An infinite result of an infinite operand is exact; any other infinity is
  an overflow or a zero divide.

Segment registers and the TLB
=============================

Not a gadget, but found beside them. A 32-bit PowerPC's TLB is tagged with
VSIDs, so writing a segment register invalidates nothing in it, and an OS
writes them as it likes. Mac OS X gives its kernel an address space of its
own: it loads other segment registers on every way into the kernel and out
again. QEMU's TLB has no tags, so ``target/ppc`` flushed all of it at the
context-synchronizing event after such a write, and with it the jump cache:
1.17 million times over a boot of Mac OS X 10.4 and one run of Xbench, some
four thousand a second, against 41 thousand flushes that a ``tlbie`` asked
for. A sample of the vCPU thread in a system-heavy stretch had 15% in
``tcg_flush_jmp_cache()`` and 21% finding translations and TBs again.

``tlb_context_switch()`` (``accel/tcg/cputlb.c``) sets the TLB and the jump
cache aside under a key and takes up the pair last set aside under another
key, or an empty pair; eight are kept. ``check_tlb_flush()`` calls it, with
the sixteen segment registers as the key, where it flushed for a segment
register (``TLB_NEED_SR_SWITCH``; the 32-bit hash MMU only). What makes it
sound:

* A context is as valid as the hardware's entries of those VSIDs would be:
  a guest that changes a PTE must ``tlbie``. Every flush that is not a
  switch (a ``tlbie``, a BAT or SDR1 write, a reset, a change to the memory
  map, a watchpoint) discards all that is set aside. So does ``tb_flush()``,
  for the jump caches.
* Between an ``mtsr`` and the event, QEMU goes on using what is in the TLB
  and translates what is not with the new value. Such an entry is not of
  the set the TLB is kept under (``sr_tlb[]``), so ``ppc_cpu_tlb_fill()``
  asks for the flush after all. The same check catches any other way the
  registers and ``sr_tlb[]`` could come apart, a loaded snapshot for one.
* ``tlb_reset_dirty()`` reaches the contexts set aside: an entry there must
  learn that its page now holds code.

A TLB's tables are resized when they are flushed, by how full they were, and
a context is flushed far less often than the one TLB was. Left at that, a
context's tables stayed small while they filled over a long time: Xbench's
copy of one large buffer to another, whose pages then shared entries of a
direct-mapped table, lost 16%. So a context taken up again whose table is
more than 70% full is flushed there and then, to grow (its entries are lost
once per doubling; the jump cache stays), and a CPU with contexts stops at
8192 entries a table, since it has several of each.

A stream keeps the jump cache's address in a register (``_jc``) from the
time the main loop enters it, and a switch gives the CPU another jump cache.
So a gadget that calls ``check_tlb_flush()`` returns to the main loop if it
did anything (``call_sync``: ``isync`` and ``sync``; ``call_exit``:
``rfi``). ``ctxtest`` fails if one goes on instead.

``QEMU_AOK_NO_TLB_CONTEXTS`` in the environment gives the flushes back.
``QEMU_AOK_STATS`` prints how many switches found their contents.

Over that boot and run, 1.07 million switches found their contents and 72
thousand did not; 25 thousand flushes discarded contexts; tables flushed
fell from 2.33 million to 0.46 million. Xbench 1.3 under Mac OS X 10.4.11,
one binary with the contexts and with ``QEMU_AOK_NO_TLB_CONTEXTS``, each
machine alone, two runs with and three without: Memory test 38.3 against
30.8 (Allocate 33.2 against 15.2, Copy 47.9 against 45.9), Thread test 62.6
against 60.7; and side by side, Quartz Graphics 23.6 against 18.0. The CPU
test's lines are within what identical runs differ by, but for one: its GCD
loop read 362 to 411 with the contexts over four runs and 413 to 443 without
over three, and no cause was found. The kit's Linux uses the contexts too
(its kernel changes segment registers around every access to user memory):
213 thousand switches found over the PowerPC gates.

``ctxtest`` (aok-vm's ``aok/bench-pm/ctx``) is a firmware for ``-M mac99
-bios`` that builds a page table in which one address means different pages
under different VSIDs and walks a segment register through them: data and
code after switching there and back, a ``tlbie`` while a context is set
aside, an access between an ``mtsr`` and its ``isync``, a store to code
through an entry that was set aside when the code was first run, and more
sets than there are contexts. It gives the same results on QEMU 11.1 as
released, and here with and without the contexts and the gadgets. Six
faults put into the code one at a time (a flush that spares the contexts,
the entry made before the ``isync`` kept, the jump cache not exchanged,
``tlb_reset_dirty()`` stopping at the TLB in use, a context reused
unflushed, a key compared in part) each fail the test written for it.

Streams that hand over to TCG
=============================

A TB is a stream as far as its insns are gadgets; from the first that is
not, TCG's TB runs to the end of the block. The two are not linked: each
change goes through the main loop, twice for a block that is entered from
a stream and left for one. Counted with ``QEMU_AOK_STATS=2``, which lists
TCG's TBs by how often the main loop entered them: over a boot of Mac OS X
10.4 and an Xbench run the main loop entered streams 115 million times and
TCG's code 122 million, and nine kinds of insn began 88% of those TBs:
``dst`` 17% (a hint: nothing to do), ``mtocrf`` 14%, ``isync`` 11%,
``stvx`` and ``lvx`` 17% (the copy and fill loops), ``mfmsr`` 8%,
``mtsrin`` 7%, ``mtmsr`` 7%, ``icbi`` and ``dcbf`` 8%. Mac OS 9 was three
kinds for 96% of 203 million in ninety seconds, all in its 68k emulator:
``addco``, ``subfco`` and ``bcctr`` on a CR bit.

They are gadgets now:

* The OE forms set XER[OV] from the host's V flag, which after ``adds``,
  ``adcs``, ``subs`` and ``sbcs`` is the overflow QEMU computes from the
  signs, and add it to SO; ``mullwo`` compares the product with its low
  word sign-extended; ``divwo`` and ``divwuo`` overflow where QEMU leaves
  rA in rD.
* ``mfocrf`` and ``mtocrf`` move the one field of a mask of one bit, and
  with any other mask do nothing, as QEMU's do.
* ``lvx``, ``lvxl``, ``stvx`` and ``stvxl`` are a sixteen-byte load or
  store at the address less its low four bits (so within a page), the bytes
  reversed: a vector register is one 128-bit number of the host's. ``dst``,
  ``dstst``, ``dss`` and ``dcba`` are nothing; ``dcbf``, ``dcbst`` and
  ``icbi`` a load in C for the fault it may raise; ``lswi`` and ``stswi``
  QEMU's helpers.
* ``mfmsr`` is a move, and the segment register insns QEMU's helpers.
  ``isync`` and a supervisor's ``sync`` call ``check_tlb_flush()`` where a
  flush is due, and then leave for the main loop, since the CPU may have
  another jump cache than the stream holds (above); with nothing due, which
  is ten times in eleven, the stream goes on. ``mtmsr`` and ``rfi`` always
  leave: flags have changed.

A stream that would stop at an insn inside a loop, with the loop's branch
back in TCG's part, would trade a loop that TCG links to itself for two
passes of the main loop at every turn (a loop of AltiVec arithmetic
between an ``lvx`` and a ``stvx``). ``tail_loops_back()`` looks ahead to
the block's branch, and such a TB is left whole to TCG.

After: the main loop entered streams 24 million times and TCG's code 6.7
million over the Mac OS X run (99.7% of TBs are streams), and 12 and 7.7
million in Mac OS 9's ninety seconds, which now reaches its desktop in
about 30 s where it took about 50 (two machines side by side, a picture
every ten seconds). Xbench under Mac OS X, alone, before and
after: Memory test 38.3 to 128.6 (Fill 23.9 to 254, Copy 47.9 to 284, the
AltiVec stream tests 46.9 to 202); the CPU and thread tests as they were.
What still begins TCG's TBs: ``sc``, the decrementer's ``mfspr``, ``lvsl``,
``mfvscr`` and ``mtvscr``, and in Mac OS 9 the trap ``twi 31`` and ``lswx``.

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
with few mantissa bits so that many results are exact, and for one op in
eight an addend that is the product or its negative, in random rounding
modes and with random sticky bits in FPSCR, and hashes the result and
FPSCR after each; then two million of the single-precision ops, on operands
that are mostly singles. Its twenty hashes are identical with
``QEMU_AOK=0`` and with the gadgets. Eighteen faults put into the gadgets
one at a time (aok-vm's ``aok/bench-pm/fp``: a result called exact that is
not, operands swapped, a NaN taken from the wrong operand or with its low
bits kept, a signalling NaN let through, an overflow taken for an infinite
operand's, a zero's sign) each change ten or all twenty. The cancelled sums
needed the addends above: before the test had them, a wrong sign there
changed no hash.

``vectest`` (aok-vm's ``aok/bench-pm/i3``) does the same for the insns of
2026-11-28 that a user program has: the vector loads and stores at every
alignment, by a page's end and into a page that is not there, ``mfocrf``
and ``mtocrf`` with every kind of mask, the OE forms from every state of
XER, ``bcctr`` on a CR bit, ``lswi`` and ``stswi`` of every length, the
hints and cache insns; forty-two lines, the same with and without the
gadgets. ``ctxtest`` covers the supervisor's. Seventeen faults put into
these gadgets one at a time are each seen by one or the other.
