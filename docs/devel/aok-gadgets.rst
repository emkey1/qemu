.. SPDX-License-Identifier: GPL-2.0-or-later

===========
AOK gadgets
===========

AOK gadgets are a second translator for TCG on hosts that are not allowed to
generate code at run time. A front end that has one turns guest instructions
straight into a stream of pointers to precompiled gadgets, one gadget per
guest instruction, without going through TCGOps and a TCG backend. The
gadgets come from iSH-AOK's user-mode engine.

It is built with ``--enable-aok-gadgets``, needs an AArch64 host, and applies
to system emulation. RISC-V (RV64) is the only front end so far.

Why
===

TCTI, the threaded interpreter this tree uses where it cannot JIT, executes
one gadget per TCG op. A guest instruction is several TCG ops, and a TB
loads the guest registers it uses into host registers and stores them back
when it ends, each of those a gadget too. An AOK gadget is one guest
instruction, working on the CPU state in memory.

On the same guest programs, in host CPU cycles on an Apple M5 (RV64 guest,
``-M virt -cpu rv64``, one CPU; the stock Alpine 6.18 kernel and userland):

==================== ========= ============ ===========
Workload             TCTI      AOK gadgets  TCTI / AOK
==================== ========= ============ ===========
CoreMark             11.7 G    6.8 G        1.7
n-body (doubles)     10.1 G    3.4 G        2.9
Python               34.1 G    13.0 G       2.6
xz -3                9.7 G     5.8 G        1.7
sha256sum            5.2 G     3.4 G        1.5
awk                  12.2 G    5.1 G        2.4
==================== ========= ============ ===========

A guest boot and shutdown, the whole process: 11.6 G cycles with TCTI, 6.0 G
with the gadgets.

What it is, and is not
======================

It is not an accelerator and not a CPU. The gadgets do the instructions a
program spends its time in; everything else is still QEMU's:

* A TB made of gadgets is an ordinary ``TranslationBlock``. It lives in the
  code buffer, is found by ``tb_lookup``, linked by ``tb_add_jump`` and
  invalidated by ``tb_phys_invalidate`` like any other.
* Guest memory is reached through the softmmu TLB, with ``cputlb.c``'s
  helpers on a miss. Page-table walks, faults, MMIO, watchpoints and the
  protection of translated code are theirs.
* Kernel mode, CSRs, exceptions, interrupts and devices are untouched.
* The translator translates what it is sure of and **stops in front of
  anything else**. The next TB starts there and TCG translates it, raising
  whatever exception is due. A TB whose first instruction is one of those is
  declined outright.

So a guest runs correctly with a front end that translates nothing, and each
instruction class added afterwards only makes it faster.

The parts
=========

``include/accel/tcg/aok.h``, ``accel/tcg/aok.c``
  The interface for front ends and stream emission.

``accel/tcg/aok-entry.S``
  ``aok_tb_exec``, which enters a stream, and the gadgets every front end
  shares: enter, exit, jump to another TB, look the next TB up.

``target/riscv/tcg/aok/``
  RISC-V's translator and gadgets.

``target/riscv/tcg/aok/shared/``, ``scripts/aok-gadgets-sync.sh``
  The gadgets RISC-V shares with iSH-AOK, as copies of its sources, and the
  script that brings the copies up to date (`Gadgets shared with iSH-AOK`_).

Outside those, the changes to TCG are small:

* ``setjmp_gen_code`` offers each TB to ``TCGCPUOps.aok_translate_code``
  before ``translate_code``, and a TB records which translator made it
  (``TranslationBlock.aok``).
* ``cpu_tb_exec`` enters a stream through ``aok_tb_exec`` rather than
  ``tcg_qemu_tb_exec``.
* A stream's linked jump is a word that a gadget reads
  (``jmp_target_addr``), so ``tb_set_jmp_target`` stores it and leaves the
  backend's patcher alone.
* TCG's code and a stream cannot jump into each other. The main loop links
  two TBs only when the same translator made both, and
  ``helper_lookup_tb_ptr`` sends TCG back to the main loop for a stream.

A stream
========

A stream is a sequence of 64-bit words in the code buffer: the address of a
gadget, then that gadget's operands, then the next gadget. A gadget ends by
loading the next word and branching to it.

For RISC-V most operands are byte offsets into ``CPURISCVState``, so one
gadget serves every register::

    [aok_gadget_rv_add_rr][offset of gpr[rd]][offset of gpr[rs1]][offset of gpr[rs2]]

The host registers a gadget may rely on are listed in ``aok.h``. Everything
that must survive a call to C is in a callee-saved register, so a helper is a
plain ``bl``.

Fused pairs
===========

Two gadgets that follow one another in a stream can be one gadget that does
both and dispatches once: the indirect branch between them, the one thing a
gadget cannot do without, is gone. ``aok_gen_pair``, called by a translator
after each instruction, looks the last two gadgets up in the front end's
table of pairs and, where there is one, puts the fused gadget in the first's
place and takes the second's word out::

    [add_rr][rd][rs1][rs2] [slli][rd][rs1][imm]
    [f2_add_rr__slli][rd][rs1][rs2][rd][rs1][imm]

Where the second reads the register the first has just written, a variant of
the pair hands the value over in a host register and the second does not load
it (forwarding). The first still stores it: guest registers are always in
``env``.

Only gadgets that cannot fault, call C or end a TB are paired, so nothing
about exceptions, interrupts or the instruction count changes: a pair is two
instructions of one TB that nothing could have come between.

This is iSH-AOK's scheme (``jit_pair_fuse`` in its ``jit/gen.c``). Which
pairs exist is a list too, measured there from what programs execute.

Gadgets shared with iSH-AOK
===========================

RISC-V's integer gadgets that touch nothing but guest registers, and the
pairs made of them, are not written in this tree. ``shared/alu.S``,
``shared/frag.h`` and ``shared/pairs.h`` are iSH-AOK's
``jit/guest-riscv64`` files of those names, unchanged, and
``gadgets-shared.S`` assembles them with this tree's definitions of what they
ask of a host: the registers for the CPU state and the stream, how a gadget
begins and ends, and which of the gadgets the pair list names exist here.
``frag.h`` states that contract under "A second host".

``scripts/aok-gadgets-sync.sh [CHECKOUT]`` copies the three files from a
checkout of iSH-AOK and writes ``shared/host-gadgets.h`` (which gadgets exist
here, read off the assembled object) and ``shared/SOURCE`` (the commit).
``--check`` says whether the copies are current. **Do not edit the copies**:
change iSH-AOK and copy again, so that a gadget improved or a pair added
there arrives here with nothing ported by hand.

``translate.c`` reads ``pairs.h`` as iSH-AOK's translator does, less the
pairs with a half this front end lacks. Today that is the pairs of two
integer gadgets, 118 of the 332. The rest have a load, a store or a branch in
them, which here go through the softmmu TLB and QEMU's TB linking and are
this tree's own (``gadgets.S``); written as bodies under the same contract,
they would bring their pairs with them.

In host CPU cycles on an Apple M5, same guest and programs as above, with the
pairs and with ``QEMU_AOK_NO_PAIRS=1`` (three interleaved runs of each):

==================== ============ ========== =======
Workload             Without      With pairs Ratio
==================== ============ ========== =======
CoreMark             6.60 G       6.37 G     1.036
n-body (doubles)     3.40 G       3.39 G     1.000
Python               13.18 G      12.20 G    1.080
xz -3                5.52 G       5.28 G     1.046
sha256sum            3.35 G       3.22 G     1.039
awk                  5.26 G       4.96 G     1.062
==================== ============ ========== =======

Rules a front end must keep
===========================

**Nothing is unwound.** TCG recovers the guest state at a fault from the
host pc. A stream has none to give. Guest registers are always in ``env``,
and a gadget that calls something that can raise an exception gives it the
instruction's pc (and whatever else ``restore_state_to_opc`` would have
recovered), which is stored first. The helper is called with a zero return
address.

**GETPC() is not yours.** A helper that uses ``GETPC()`` takes it for a
position in a TCG TB. Under TCI and TCTI it is a variable that still holds
the position of the last helper call some TCG TB made; a helper that raises
would unwind the CPU state to that unrelated TB. Call ``aok_no_retaddr()``
before any such helper.

**TBs are pc-relative** where the target uses ``CF_PCREL``. The enter gadget
takes the pc the TB was entered at, and everything is measured from it.

**A lookup must see breakpoints.** A direct jump to another page, and every
indirect jump, looks its target up rather than being linked, and a lookup is
where QEMU notices a breakpoint. A gadget that does ``tb_lookup``'s first
step itself must go to ``aok_lookup_tb_ptr`` whenever the CPU has one.

**Only the same flags.** Such a gadget may take a TB only if it has the
current TB's ``cs_base``, ``flags`` and ``cflags``. That is sound because
nothing a stream executes can change them: an instruction that could is left
to TCG, or ends its TB in the main loop.

**The host's FP status is the guest's only where you say so.** A front end
whose gadgets compute on the host's FP unit clears the host's FPSR at its
first FP gadget, and before any call to C or leaving the stream moves the
flags it holds to ``cpu->aok_host_fpsr`` (``aok_fp_end``), to be folded into
the guest's FP status by ``TCGCPUOps.aok_fold_fpsr``. A gadget may run on the
host only in the cases where the host gives softfloat's answer, flags
included; ``target/riscv/tcg/aok/gadgets.S`` lists RISC-V's.

Run-time switches
=================

``QEMU_AOK=0``
  Leave every TB to TCG. The same binary then runs as it would without the
  option, which makes it the reference for comparisons.

``QEMU_AOK_STATS=1``
  At exit, print how many TBs each translator made, how often the main loop
  entered each kind, what lookups done in C found, and the first opcodes of
  the TBs left to TCG.

``QEMU_AOK_NO_CSR``, ``QEMU_AOK_NO_ATOMIC``, ``QEMU_AOK_NO_FP``, ``QEMU_AOK_NO_FPNATIVE``
  Leave that instruction class to TCG (or, for the last, to softfloat), for
  bisecting.

``QEMU_AOK_NO_PAIRS``, ``QEMU_AOK_NO_FWD``
  Fuse no pairs; fuse them, but forward no register.

RISC-V
======

Translated: the integer base, M, A, Zba, Zbb, Zbs and Zicond, C, loads and
stores, branches, ``jal`` and ``jalr``, CSR accesses, and F and D.

* Atomics and CSR accesses are one call to C, which does what
  ``trans_rva.c.inc`` and the ``trans_csr*`` functions generate with the same
  helpers. A CSR access ends its TB in the main loop, as with TCG.
* Double-precision arithmetic, comparisons and integer conversions run on
  the host's FP unit when the rounding mode is to nearest. Single precision,
  other rounding modes and the rarer operations are softfloat's, called from
  the stream.
* Left to TCG: ``ecall``, ``ebreak``, ``sret``, ``mret``, ``wfi``, the
  fences other than ``fence``, vectors, and every extension not listed.

A TB is translated only for RV64 with a little-endian guest, not
virtualized, with no pointer masking, CFI or instruction-count trigger, and
with the C extension. It stays within its page.

Testing
=======

The reference for a stream is TCG in the same binary (``QEMU_AOK=0``). Two
guest-side transcripts have been used, each compared between the two:

* a set of programs whose output must be identical: CoreMark's checksums,
  Python big-integer and floating-point arithmetic, xz and gzip, four
  hashes, sort, awk, shell loops, and a hash of every binary in the image;
* an FP test that runs each double-precision operation over a grid of
  awkward operands in all four rounding modes and hashes every result's bits
  together with the exception flags it raised.

Both are identical with one guest CPU and with four.
