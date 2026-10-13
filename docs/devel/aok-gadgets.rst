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
to system emulation. There are front ends for RISC-V (RV64), AArch64 and
x86, both 64-bit and 32-bit code.

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

RISC-V's integer gadgets, its loads and stores, its branches and direct
jumps, and the pairs made of them are not written in this tree.
``shared/alu.S``, ``shared/frag.h`` and ``shared/pairs.h`` are iSH-AOK's
``jit/guest-riscv64`` files of those names, unchanged, and
``gadgets-shared.S`` assembles them with this tree's definitions of what they
ask of a host. ``frag.h`` states that contract under "A second host":

* the registers for the CPU state and the stream, and how a gadget begins
  and ends;
* guest memory: a load or store body computes the address and makes the
  access, and between the two the host turns the guest address into a host
  one (``read_prep``, ``write_prep``). Here that is the softmmu fast path,
  and on a miss cputlb does the whole access in C and the body's own access
  is made of a scratch word instead;
* how a TB is left (``branch_leave``): here ``aok_gadget_goto``'s code, a
  copy for each way out, so that each ends in an indirect branch of its own;
* which of the gadgets the pair list names exist here.

``jalr`` is this tree's own, since it ends in a TB lookup, but it is written
as a body under the name of iSH-AOK's ``jalr_cached``, and so takes the pairs
that end in that.

``scripts/aok-gadgets-sync.sh [CHECKOUT]`` copies the three files from a
checkout of iSH-AOK and writes ``shared/host-gadgets.h`` (which gadgets exist
here, read off the assembled object) and ``shared/SOURCE`` (the commit). It
does the same for AArch64's two files (see below).
``--check`` says whether the copies are current. **Do not edit the copies**:
change iSH-AOK and copy again, so that a gadget improved or a pair added
there arrives here with nothing ported by hand.

``translate.c`` reads ``pairs.h`` as iSH-AOK's translator does. All 332 pairs
are built. Not all can occur yet: iSH-AOK's translator also folds a few
two-instruction idioms into one gadget (a shift pair, a shift and an add, a
constant or a bit test and the branch on it), which this one does not, and
the pairs that name those gadgets wait for that.

In host CPU cycles on an Apple M5, same guest and programs as above, without
pairs (``QEMU_AOK_NO_PAIRS=1``) and with them, five interleaved runs of each:

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

Which engine is running
=======================

A guest cannot tell which engine runs it, and neither can whoever sits at
it, so a machine whose CPUs have a front end says so, as long as the gadgets
are on (``accel/tcg/aok-system.c``):

* in its device tree, where the machine makes one (the ``virt`` machines of
  Arm and RISC-V call ``aok_fdt_announce()``): the property ``aok,engine`` of
  ``/chosen``, which a Linux guest has as
  ``/proc/device-tree/chosen/aok,engine`` with no driver;
* in the fw_cfg file ``opt/aok/engine``, which in Linux is root's to read
  and needs the ``qemu_fw_cfg`` module.

Both hold one line, ``AOK gadgets (ARCH)``, and neither exists with
``QEMU_AOK=0`` or for a guest architecture that has no front end.

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
  With the value 2, also which of TCG's TBs the main loop entered most,
  by pc and first instruction: every one is a stream that could not go on.

``QEMU_AOK_NO_CSR``, ``QEMU_AOK_NO_ATOMIC``, ``QEMU_AOK_NO_FP``, ``QEMU_AOK_NO_FPNATIVE``
  Leave that instruction class to TCG (or, for the last, to softfloat), for
  bisecting.

``QEMU_AOK_NO_SYS``, ``QEMU_AOK_NO_EXC``, ``QEMU_AOK_NO_ATOMIC``, ``QEMU_AOK_NO_FP``
  The same for AArch64: system register accesses; ``svc``, ``eret`` and the
  DAIF immediates; exclusives and ordered accesses; floating point and SIMD.

``QEMU_AOK_NO_PAIRS``, ``QEMU_AOK_NO_FWD``
  Fuse no pairs; fuse them, but forward no register.

``QEMU_AOK_X86_SKIP=88,89,1af``
  For x86: leave these opcodes to TCG (hexadecimal; ``1xx`` is ``0f xx``).

``QEMU_AOK_X86_NO32``, ``QEMU_AOK_X86_NO64``
  For x86: leave 32-bit code, or 64-bit code, to TCG.

``QEMU_AOK_X86_NOLIVE``, ``QEMU_AOK_X86_NOFP``, ``QEMU_AOK_X86_NOHF=mask``
  For x86: compute every flag; leave floating point to softfloat; compute in
  C the conditions of the classes in the mask (bits as ``HF_`` in
  ``translate-x86.c``, bit 8 for "restore none", from bit 16 a mask of the
  sixteen conditions).

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

AArch64
=======

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

* **Shared with iSH-AOK:** ``shared/alu_spec.S`` and ``shared/frag.h`` are its
  ``jit/guest-arm64`` files, unchanged: the operand-specialised integer
  gadgets, and the bodies of loads, stores and pairs. ``gadgets-shared.S``
  gives them this tree's host (``frag.h``, "A second host"): registers, the
  split flags, and guest memory through the softmmu fast path.
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
indirect branches are TCG's, since they set ``PSTATE.BTYPE``.

x86
===

``target/i386/tcg/aok``, in the x86-64 target. Two kinds of code are
translated: long mode's 64-bit code, and 32-bit protected-mode code with a
32-bit stack and flat segments (every one but ``fs`` and ``gs`` at zero),
which is what a 32-bit operating system and its programs run in, and a
64-bit system's 32-bit programs. Real mode, 16-bit segments and virtual-8086
mode are TCG's: they are a firmware's and a boot loader's. Nothing here is
iSH-AOK's: its x86 gadgets are built around its own register cache and
flags, and these are written against ``CPUX86State``.

The i386 target has no front end: its ``CPUX86State`` has registers of four
bytes, and the gadgets' operands are offsets into the other. A 32-bit guest
is run by ``qemu-system-x86_64``, where it finds a CPU that could do more
than it asks of it.

On the same guest programs, in host CPU cycles on an Apple M5 (``-M q35``,
one CPU, the stock Alpine 6.18 kernel and userland; the cycles between a
program's first line of output and its last):

==================== ========= ============ ===========
Workload             TCTI      AOK gadgets  TCTI / AOK
==================== ========= ============ ===========
CoreMark             11.3 G    4.8 G        2.3
n-body (doubles)     9.2 G     5.2 G        1.8
Python               31.0 G    9.3 G        3.3
xz -3                9.2 G     4.5 G        2.0
sha256sum            4.0 G     2.4 G        1.7
awk                  33.0 G    13.2 G       2.5
==================== ========= ============ ===========

A guest boot and shutdown, the whole process: 18.8 G cycles with TCTI, 8.5 G
with the gadgets.

* **Operands** are byte offsets into ``CPUX86State``, so one gadget serves
  every register, and ``ah`` is ``al``'s offset plus one. A 32-bit result is
  stored as eight bytes. An absent base or index is ``aok_zero``, eight
  bytes that nothing writes; ``aok_tmp`` is where the memory operand of a
  rarer form is loaded first, so that the register form's gadget serves it.
* **32-bit code** has the same gadgets: a 32-bit form does not read a
  register's upper half and stores its result zero-extended, as TCG's code
  does. What it has of its own is addresses that wrap at 32 bits (a third
  form of every memory gadget, and ``ea32``), a stack of four-byte slots and
  an ``eip`` that wraps (the gadgets named ``32``), and the opcodes that mean
  something else there. A segment register is loaded in C by the helper TCG
  calls; after ``es`` or ``ds`` the TB ends in the main loop, since a TB's
  flags say whether those are at zero.
* **A memory operand** is a base and a displacement in the gadget's own
  operands, or whatever an ``ea`` gadget before it computed (an index, a
  segment's base, ``rip``). Guest memory is reached through the softmmu
  fast path; an access that is only unaligned, which x86 code is free to
  make, is tried again on the entry's addend before ``cputlb``.
* **A read-modify-write** probes the page for writing before it changes
  anything, so a fault leaves the instruction to be started again. The rarer
  ones are three gadgets: a load that does that probe, the register form on
  the temporary, a store.
* **The flags are QEMU's lazy ones.** A gadget that sets them stores
  ``cc_dst``, ``cc_src`` and ``cc_op`` as the code TCG generates would, so an
  exception, an interrupt or a TB of TCG's finds them right with nothing to
  convert. The gadget computes with the host's flag-setting instruction, and
  the translator tracks what the host's NZCV then says of the guest's flags
  (``Ctx.hf``): a ``jcc``, ``setcc`` or ``cmov`` after a ``cmp`` tests the
  host's and reads nothing. Where they are gone (a load in between), one
  gadget makes them again from the stored state; a condition that cannot be
  had that way is computed in C. A gadget that calls C after it has set the
  host's flags saves them around the call.
* **Liveness.** A rotate changes two flags and keeps the rest, ``inc`` and
  ``dec`` keep the carry, and the lazy state can say either only by
  computing every flag first. TCG drops that as dead code when nothing reads
  it. Here the translator looks ahead: if the instructions after one neither
  read the flags nor can fault or leave the TB before one that sets them
  all, it is translated with no flags at all. The instructions looked at
  must then be in this TB; if one is not, the TB is translated again with
  every flag computed.
* **In C**, one call each: ``mul`` and ``div`` with one operand, the double
  shifts, rotates whose flags are wanted, the string instructions (a ``rep``
  goes page by page on the host's memory where the pages are RAM, and comes
  back to the main loop if it is long), ``cmpxchg``, ``cmpxchg8b``, ``xadd``
  and ``xchg`` with memory, ``pushf`` and ``popf``, ``rdtsc``, ``pause``,
  and ``in`` and ``out`` where the CPL may use any port.
* **Other CPUs.** Under multi-threaded TCG a guest's stores must stay in
  order and its loads before what follows them. Every memory gadget exists
  a second time with the barriers that give that, used in a ``CF_PARALLEL``
  TB. There an instruction with a ``lock`` prefix is ``cputlb``'s atomic
  helper; elsewhere the prefix is nothing, as for TCG.
* **sti** takes effect after the instruction that follows it. The two are
  kept in one TB, with no flag for the shadow, and after the second a gadget
  goes to the main loop if an interrupt has been waiting for the flag.
* **SSE.** The moves, and the integer operations that are one instruction of
  the host's: a gadget loads the two XMM registers, calls a two-instruction
  thunk, and stores the result. Shuffles and the shifts by bytes are a table
  lookup with the indices computed at translation. Without VEX an
  operation's memory operand must be aligned: the fast path sees that, and
  anything else is ``cputlb``'s to raise.
* **Floating point.** An arithmetic instruction is a call of the helper
  TCG's code would call, which is softfloat. For doubles (``addsd`` to
  ``divsd``, ``sqrtsd``, the packed four, ``comisd`` and ``ucomisd``,
  ``cvtsi2sd``, ``cvttsd2si``) the gadget first tries the host's FP unit, in
  the cases where it gives softfloat's answer with softfloat's flags:
  ``gadgets.S`` lists what differs between SSE and AArch64 (denormal
  operands, which NaN, tininess) and what that leaves, which is normal
  numbers and zeros under a plain MXCSR, raising at most inexact.
* **A TB stays in its page.** One whose first instruction runs into the next
  page is that one instruction, as TCG makes it.
* Left to TCG: everything outside those two kinds of code, x87 and MMX,
  single-precision arithmetic on the host (it is softfloat's, called from
  the stream), the system calls, interrupts and the returns from them, the
  control and debug registers, loads of ``ss`` and ``cs``, string I/O,
  ``cmpxchg16b``, the rotates through carry, 16-bit ``adc``/``sbb`` and stack
  operations, 16-bit addressing, a bit string addressed by a register, and
  anything with VEX or EVEX.

A TB is translated only with no single-step or resume flag pending, outside
the shadow of a ``mov`` to ``ss``, system management mode and SVM guests,
with MPX off. Self-modifying code is found as TCG finds it,
with one difference: a store into the page of the TB that is running does
not stop that TB at the store, so an instruction that rewrites one further
on in its own TB still runs the old one once.

Testing
=======

The reference for a stream is TCG in the same binary (``QEMU_AOK=0``). Three
guest-side transcripts have been used, each compared between the two:

* a set of programs whose output must be identical: CoreMark's checksums,
  Python big-integer and floating-point arithmetic, xz and gzip, four
  hashes, sort, awk, shell loops, and a hash of every binary in the image;
* an FP test that runs each double-precision operation over a grid of
  awkward operands in all four rounding modes and hashes every result's bits
  together with the exception flags it raised.

* a memory test: every access size at every alignment and across a page
  boundary, and pointer walks over pages that fault on first touch and are
  restarted by a signal handler that hashes each fault's address and pc. A
  pair that repeated its first instruction after a fault in its second, or
  reported the wrong one, changes it.

All three are identical with one guest CPU and with four, with pairs, without
them, and with forwarding off. For x86-64 they are also identical with four
CPUs under multi-threaded TCG, and so is the FP test printing every result
(370,000 lines).

For x86 there is a fourth, ``x86test``: the integer instructions on awkward
and random operands with the flags hashed in, among them what Linux's
compilers seldom emit and other systems' code is full of: ``rep`` with the
direction flag set, ``repne scas`` and ``repe cmps``, ``loop``,
``cmpxchg8b``, rotates whose flags are read, segment registers pushed and
loaded, and every condition after every kind of instruction that sets flags,
with a load or a store in between. The first three and this one are
identical for a 64-bit guest and for a 32-bit one.

An x86 guest needs a source of entropy to be measured at all: without one a
Linux guest spends a quarter of a minute in its scheduler making some before
the first program that asks for random numbers can run. The x86 runs here
use ``-cpu qemu64,+rdrand`` and ``random.trust_cpu=on``.

For AArch64 there is a fourth, ``simdtest``: every encoding of the scalar FP
and Advanced SIMD data-processing space (560,640 of them, with fixed
registers), each run on four sets of inputs, one under another rounding mode
with flush-to-zero and default NaN, and the result, flags and FPSR hashed. An
encoding that does not exist is a SIGILL and hashed as that, so the
transcript checks both which instructions a guest CPU has and what each
computes. The reference for this one is TCG with a JIT backend: against
QEMU 11.0.3 on a ``cortex-a72`` the transcripts are identical. The threaded
interpreter in this tree is not a reference here. It differs from the JIT,
from the gadgets and from hardware (the same guest under HVF) in ``cmlt #0``
and ``cmle #0`` on 8-, 16- and 32-bit lanes, and in ``sshl`` on 16- and
32-bit lanes.
