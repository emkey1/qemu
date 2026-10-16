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
to system emulation. A guest architecture takes part by having a front end;
each has a page of its own (`Front ends`_).

Why
===

TCTI, the threaded interpreter this tree uses where it cannot JIT, executes
one gadget per TCG op. A guest instruction is several TCG ops, and a TB
loads the guest registers it uses into host registers and stores them back
when it ends, each of those a gadget too. An AOK gadget is one guest
instruction, working on the CPU state in memory. The front ends' pages have
what that is worth on each guest; in short, the same programs take 1.7 to
3.7 times fewer host cycles than under TCTI on an Apple M5 Max, 1.5 to 3.7 on
an iPad's M4 and 1.4 to 4.4 on an A10X.

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
* Kernel mode, system registers, exceptions, interrupts and devices are
  untouched.
* The translator translates what it is sure of and **stops in front of
  anything else**. The next TB starts there and TCG translates it, raising
  whatever exception is due. A TB whose first instruction is one of those is
  declined outright.

So a guest runs correctly with a front end that translates nothing, and each
instruction class added afterwards only makes it faster. Without a front end
for its architecture a guest runs exactly as it would without the option.

The parts
=========

``include/accel/tcg/aok.h``, ``accel/tcg/aok.c``
  The interface for front ends and stream emission.

``accel/tcg/aok-entry.S``
  ``aok_tb_exec``, which enters a stream, and the gadgets every front end
  shares: enter, exit, jump to another TB, look the next TB up.

``include/accel/tcg/aok-asm.h``
  What a front end's gadgets are written with: the host registers, the
  dispatch, the TB lookup (``aok_lookup_jc``), the end of a stream's use of
  the FP unit (``aok_fp_end``).

``accel/tcg/aok-system.c``, ``accel/tcg/aok-fdt.c``
  The machine's note of which engine runs it (`Which engine is running`_);
  the second only in targets that have device trees.

``scripts/aok-host-gadgets.sh``
  For a front end that took gadgets and a table of pairs from iSH-AOK: which
  of the gadgets the table names it has (`Fused pairs`_).

``target/ARCH/tcg/aok/``
  A guest architecture's front end: its translator and its gadgets, and
  ``TCGCPUOps.aok_translate_code`` pointing at the translator.

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
* A store to a page that has translated code invalidates the TBs it
  overlaps a second time, once it has been made (``notdirty_write`` and the
  main loop). This one is for TCG's own TBs as much as for streams: see
  `Stores into code`_.

A stream
========

A stream is a sequence of 64-bit words in the code buffer: the address of a
gadget, then that gadget's operands, then the next gadget. A gadget ends by
loading the next word and branching to it.

Most operands are byte offsets into the target's CPU state, so one gadget
serves every register. A RISC-V ``add``::

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
pairs exist is a list too, measured there from what programs execute; a
front end that has one keeps it in its ``shared/pairs.h``, and
``scripts/aok-host-gadgets.sh`` writes ``shared/host-gadgets.h``, which of
the gadgets the list names the front end has, read off the assembled object
so that it cannot disagree with the code.

Gadgets taken from iSH-AOK
==========================

Some of each front end's gadgets are iSH-AOK's own sources, in the front
end's ``shared/`` directory with a ``SOURCE`` file that names their origin
and their licence: GPL-2.0-only or GPL-3.0-only, iSH-AOK granting GPLv2 as
well for everything contributed to it after its commit 0e3a4144, which all
of these were. They were taken on 2026-10-14 and are this tree's own since:
the two engines differ in their CPU state, in how a block is left, in their
flags and in how they reach guest memory, and keeping one source for both
cost more than it saved. Something iSH-AOK improves is brought over by hand
when it is worth it.

What such a source asks of its host is a contract stated in it (``frag.h``,
"A second host", for RISC-V and AArch64): the registers for the CPU state and
the stream and how a gadget begins and ends; how a load or store turns the
guest address into a host one (here the softmmu fast path, and on a miss
cputlb does the whole access in C and the body's own access is made of a
scratch word instead); how a TB is left; which of the gadgets a pair list
names exist. The front end's ``gadgets-shared.S`` gives it this tree's.

Which engine is running
=======================

A guest cannot tell which engine runs it, and neither can whoever sits at
it, so a machine whose CPUs have a front end says so, as long as the gadgets
are on (``accel/tcg/aok-system.c``, ``aok-fdt.c``):

* in its device tree, where the machine makes one and calls
  ``aok_fdt_announce()``: the property ``aok,engine`` of ``/chosen``, which a
  Linux guest has as ``/proc/device-tree/chosen/aok,engine`` with no driver;
* in the fw_cfg file ``opt/aok/engine``, which in Linux is root's to read
  and needs the ``qemu_fw_cfg`` module.

Both hold one line, ``AOK gadgets (ARCH)``, and neither exists with
``QEMU_AOK=0`` or for a guest architecture that has no front end. A front
end may say it another way where a machine has no device tree (x86: the
CPUID brand string).

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
to TCG, or ends its TB in the main loop. The body of the gadget is one macro
for every front end (``aok_lookup_jc``, ``include/accel/tcg/aok-asm.h``). It
reads both ways of the jump cache, and the second also when the first holds
the pc under other flags: a kernel's code can run under two sets of them, and
then two TBs of one pc sit side by side.

**A TB of two pages is never linked to.** QEMU does not link a direct jump
to one, since its second page may be mapped elsewhere later. A stream whose
jump leads to one would come back to the main loop every time, so the main
loop points that jump at the stream's own lookup stub instead
(``aok_slot_to_lookup``), which every stream with a linkable jump has.

**The host's FP status is the guest's only where you say so.** A front end
whose gadgets compute on the host's FP unit clears the host's FPSR at its
first FP gadget, and before any call to C or leaving the stream moves the
flags it holds to ``cpu->aok_host_fpsr`` (``aok_fp_end``), to be folded into
the guest's FP status by ``TCGCPUOps.aok_fold_fpsr``. A gadget may run on the
host only in the cases where the host gives the guest's answer, flags
included; each front end's sources list them.

Run-time switches
=================

``QEMU_AOK=0``
  Leave every TB to TCG. The same binary then runs as it would without the
  option, which makes it the reference for comparisons.

``QEMU_AOK_STATS=1``
  At exit, print how many TBs each translator made, how often the main loop
  entered each kind, what lookups done in C found, and the first opcodes of
  the TBs left to TCG.
  With the value 2, also which of TCG's TBs the main loop entered most,
  by pc and first instruction: every one is a stream that could not go on.

``QEMU_AOK_NO_PAIRS``, ``QEMU_AOK_NO_FWD``
  Fuse no pairs; fuse them, but forward no register (in a front end that
  has pairs).

Each front end has switches of its own, on its page, that leave an
instruction class to TCG for bisecting.

Stores into code
================

With one thread per guest CPU, a store to a page that has TBs goes through
``notdirty_write``, which invalidates the TBs the store overlaps and returns;
the store is made after that, and the page's lock is not held in between.
Another CPU that translates there in the gap reads the old bytes, and its TB
is valid from then on: the store that should have invalidated it has already
looked.

Linux on x86 walks into this. To patch an instruction that other CPUs may be
executing it writes a breakpoint over the first byte, then the rest, then
the first byte, with an interrupt to every CPU after each step; a CPU that
meets the breakpoint meanwhile is helped over it, and after the last
interrupt none may meet it, so the handler stops knowing the address. A TB
translated in the gap of that last store has the breakpoint in it for good,
and the next CPU to run it is ``Oops: int3``.

TCG has the gap too and seldom loses in it: its TB there begins some
instructions earlier, and by the time its translator reaches the patched
byte the store is in memory. A front end that ends its TB before a
breakpoint, as the x86 one does, makes the TB that is translated again after
the store's invalidation begin at the very byte, and that byte is the first
thing read. On an Apple M5 Max with four guest CPUs, a 32-bit Alpine guest died
at boot in 9 of 180 runs beside other load, and in none of 72 with
``QEMU_AOK=0``; under ``poke`` (a guest that flips one of its scheduler's
static keys three thousand times while three CPUs run the scheduler) in 16 of
16 against none of 8. With the gap made a few microseconds wider by a loop in
``notdirty_write``, ``QEMU_AOK=0`` died in 5 of 6.

So ``notdirty_write`` notes such a store, when CPUs have threads of their
own, and asks its CPU to leave the TB at the TB's end, as ``cpu_exit`` does.
The main loop then invalidates the noted ranges once more before it looks up
another TB, and before ``cpu_exec`` returns. By then the store is in memory,
and the page's lock orders that invalidation against every translation: a
TB is either invalidated by it or made of the new bytes. With that, ``poke``
ran 16 of 16 on the gadgets (and 8 of 8 in a 64-bit guest), 6 of 6 with
``QEMU_AOK=0`` and the widened gap, and the guest that died at boot came up
100 times of 100. What it costs is a turn of the main loop and a second look
at the page for each store into a page with code, a path that already takes
the page's lock and walks its TBs.

One gap of the same kind is left as it was, because nothing sees it: a store
to a page with no TBs takes the fast path, and a first TB can be made on
that page between the fast path's look at the TLB and its store.

Testing
=======

The reference for a stream is TCG in the same binary (``QEMU_AOK=0``), or,
where TCG is not the hardware's equal, the hardware. Three guest-side
transcripts are compared between the two for every front end:

* a set of programs whose output must be identical: CoreMark's checksums,
  Python big-integer and floating-point arithmetic, xz and gzip, four
  hashes, sort, awk, shell loops, and a hash of every binary in the image;
* an FP test that runs each double-precision operation over a grid of
  awkward operands in all four rounding modes and hashes every result's bits
  together with the exception flags it raised;
* a memory test: every access size at every alignment and across a page
  boundary, and pointer walks over pages that fault on first touch and are
  restarted by a signal handler that hashes each fault's address and pc. A
  pair that repeated its first instruction after a fault in its second, or
  reported the wrong one, changes it.

They are identical with one guest CPU and with four (under multi-threaded
TCG too), with pairs, without them, and with forwarding off. Each front
end's page has the tests of its own, and what each was checked against.

Front ends
==========

Each front end has a page of its own beside this one,
``docs/devel/aok-gadgets-ARCH.rst``: what it translates and leaves to TCG,
the gadgets it took from iSH-AOK, its results, its own tests and its
switches.
