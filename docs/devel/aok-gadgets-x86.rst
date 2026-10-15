.. SPDX-License-Identifier: GPL-2.0-or-later

=================
AOK gadgets: x86
=================

``target/i386/tcg/aok``, in the x86-64 target. Two kinds of code are
translated: long mode's 64-bit code, and 32-bit protected-mode code with a
32-bit stack and flat segments (every one but ``fs`` and ``gs`` at zero),
which is what a 32-bit operating system and its programs run in, and a
64-bit system's 32-bit programs. Real mode, 16-bit segments and virtual-8086
mode are TCG's: they are a firmware's and a boot loader's. The integer core
is this tree's own, written against ``CPUX86State`` (iSH-AOK's integer
gadgets are built around its own register cache and flags); the x87 and the
vector frames are iSH-AOK's sources (``shared/``, ``vec/``, each with its
origin and licence).

The i386 target has no front end: its ``CPUX86State`` has registers of four
bytes, and the gadgets' operands are offsets into the other. A 32-bit guest
is run by ``qemu-system-x86_64``, where it finds a CPU that could do more
than it asks of it.

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
  back to the main loop if it is long), ``cmpxchg``, ``cmpxchg8b``,
  ``cmpxchg16b``, ``xadd`` and ``xchg`` with memory, ``pushf`` and ``popf``,
  ``lahf`` and ``sahf``, ``clc``, ``stc`` and ``cmc``, ``rdtsc``, ``rdtscp``,
  ``cpuid``, ``pause``, ``verr`` and ``verw``, ``rdfsbase`` and its kind, and
  ``in`` and ``out`` where the CPL may use any port.
* **The kernel's** fast paths, each a call of the helper TCG's code for the
  instruction calls, and where TCG ends its TB the main loop after it:
  ``iret``, ``syscall`` and ``sysret``, ``mov`` to and from ``cr0``, ``cr2``,
  ``cr3`` and ``cr4``, ``invlpg``, ``clac`` and ``stac``, ``xsave``,
  ``xsaveopt`` and ``xrstor``; ``swapgs`` is a gadget. The instruction after
  ``sti`` may be a ``jmp``, which looks for an interrupt waiting where it
  goes. A bit string addressed by a register (``bt`` and its kind on memory)
  is its operand's address moved by the bit number first.
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
* **Floating point** is VEX's frames (below), which are x86's where QEMU's
  softfloat helpers are not: which NaN an operation returns (SSE's is the
  first source, softfloat's the x87's), MINPS and MAXPS under DAZ, RCPPS's
  table, the flags. A legacy SSE instruction is its VEX form with the
  destination as the first source, its word saying that bits 511:128 stay
  (and a 16-byte operand in memory must be aligned): the arithmetic, square
  roots, compares and the conversions of SSE and SSE2, SSE3's, and the
  SSSE3 and SSE4.1 instructions that have a VEX form (legacy BLENDV's
  implicit xmm0 is the VEX form's mask register), each where the CPU offers
  it. For doubles (``addsd`` to ``divsd``, ``sqrtsd``, the packed four) a
  gadget first tries the host's FP unit, where it is exact: ``gadgets.S``
  lists what differs between SSE and AArch64 (denormal operands, which NaN,
  tininess) and what that leaves, which is normal numbers and zeros under a
  plain MXCSR, raising at most inexact; anything else falls into the frame
  behind it. What the host raises accumulates in FPSR until the stream
  ends and is MXCSR's then. ``QEMU_AOK_X86_SSEHELPERS=1`` gives the old
  way back: QEMU's helpers, with the host first for doubles.
* **The x87** is not softfloat's here. The 80-bit arithmetic, the register
  stack with its tags and faults, every D8-DF instruction's register form, the
  transcendentals and what a memory form does once it has its operand are
  iSH-AOK's x87 sources, in integer registers (``shared/``, this tree's own
  since 2026-10-14; ``x87-host.S`` is this host's side: QEMU keeps TOP beside
  the status word and a tag byte a register, and the shared code is told so in
  four macros). Their answers are the hardware's, which softfloat's are not:
  of iSH-AOK's 167,517 recorded on an AMD Ryzen (``x87kat`` below) the gadgets
  give every one, and TCG's x87 misses 59,159, most of them where a real x87
  raises a stack fault, reports a denormal operand or sets C1, and half of the
  transcendentals (``fsin``, ``fcos`` and ``fptan`` are a double's there). A
  load reads its operand through the softmmu path first; a store converts,
  writes, and only then pops and updates the status word, so a fault leaves
  the instruction to be run again. ``fldcw`` goes through QEMU's helper as
  well, which sets softfloat's modes for the instructions that are still
  TCG's, and ``ldmxcsr`` and ``stmxcsr`` are a call each.
* **VEX and EVEX** (``gadgets-vec.S``, ``vec/``) are iSH-AOK's frames, which
  compute an operation 128 bits at a time exactly as x86 does (its NaNs,
  DAZ and FTZ, denormal flags, tininess after rounding), taken on
  2026-10-14 and this tree's own since: AVX, AVX2, FMA3, F16C, BMI1/2, the
  opmask instructions, and AVX-512 (F, DQ, CD, BW, VL, IFMA, VBMI, VBMI2,
  VNNI, BITALG, VPOPCNTDQ, BF16) with GFNI, VAES, VPCLMULQDQ and AVX-VNNI in
  every form, the legacy SSE ones of GFNI, AES and PCLMULQDQ included. TCG
  has no AVX-512, so the CPU offers it (CPUID, XCR0's opmask and ZMM state)
  only where these gadgets run (not with ``QEMU_AOK=0``,
  ``QEMU_AOK_X86_NOVEC`` or ``QEMU_AOK_X86_NOAVX512``), a TB flag says
  whether XCR0 enables it, TCG's XSAVE and XRSTOR carry its state, and a
  VEX write of TCG's zeroes the register to bit 511 as the hardware's does.
  A memory operand is staged before the frame and stored after it (a store
  that follows a frame that changes MXCSR is probed first); with an opmask,
  or VEX's VMASKMOV's mask register, only the enabled elements are
  touched, so that a masked-off one may be on a page that is not there,
  and a gather or scatter goes element by element, restartable as x86's.
* **A TB stays in its page.** One whose first instruction runs into the next
  page is that one instruction, as TCG makes it.
* Left to TCG: everything outside those two kinds of code, MMX, the x87's
  environment (``fldenv``, ``fnstenv``, ``frstor``, ``fnsave``, ``fxsave``,
  ``fxrstor``, ``fninit``), ``int`` and ``sysenter``/``sysexit``, the debug
  registers, ``cr8``, loads of ``ss`` and ``cs``, the far-pointer loads
  (``lds``, ``lss`` and their kind), string I/O, the rotates through carry,
  16-bit stack operations, 16-bit addressing, SSE4.2's string compares and
  CRC32, SHA, SSE4.1's PEXTR*, EXTRACTPS and MOVNTDQA, VEX's gathers and
  string compares, and 32-bit code's VEX. Not yet anywhere: EVEX in 32-bit
  code, and a memory operand of an EVEX instruction with a 0x67 prefix (both
  raise #UD).

A TB is translated only with no single-step flag pending, outside the shadow
of a ``mov`` to ``ss``, system management mode and SVM guests, with MPX off,
and when the main loop does not want one instruction alone. The exception
is an instruction TCG does not have (EVEX's, an opmask one, GFNI's or
AVX-VNNI's): stepped with EFLAGS.TF, or wanted alone, it is a TB of its own
here, ending in the step's ``#DB`` or the main loop. The resume flag is no
bar: a TB entered with it (the instruction a fault was
returned to) clears it in its first gadget. Before that such TBs were TCG's,
and whatever followed a page fault in its block was run by another engine
than the time before, which for the x87 means other answers. Self-modifying
code is found as TCG finds it (see *Stores into code* on the main page), with
one difference: a store into the page of the TB that is running does
not stop that TB at the store, so an instruction that rewrites one further
on in its own TB still runs the old one once.

The machine says which engine runs it in the processor's name, since a PC
has no device tree (``target/i386/tcg/system/tcg-cpu.c``): the CPUID brand
string ends in ``(AOK gadgets)``, which is ``model name`` in
``/proc/cpuinfo`` and the processor line of a Windows system's properties.

Results
=======

Host CPU cycles a guest program takes under TCTI (``QEMU_AOK=0``, the same
binary) and under the gadgets, with ``-M q35``, one guest CPU and Alpine 3.24
(its 6.18 kernel and userland; *Testing* says why ``+rdrand``): what the QEMU
process spends between a program's first line of output and its last, the
median of two runs. On an Apple M5 Max (macOS); the last column is the same
ratio on an iPad Pro with an M4, in an iOS app, where nothing may be
generated at run time and TCTI is what the gadgets replace.

The 64-bit guest, ``-cpu qemu64,+rdrand``:

==================== ========= ============ =========== =======
Workload             TCTI      AOK gadgets  TCTI / AOK  M4
==================== ========= ============ =========== =======
CoreMark              11.7 G     4.9 G      2.36        2.30
n-body (doubles)       9.5 G     5.7 G      1.66        1.49
Python                31.2 G     9.9 G      3.17        3.15
xz -3                  9.7 G     4.7 G      2.04        2.44
sha256sum              4.2 G     2.5 G      1.69        1.77
awk                   33.6 G    14.0 G      2.41        2.35
==================== ========= ============ =========== =======

The 32-bit guest (Alpine's x86), ``-cpu qemu32,+rdrand``:

==================== ========= ============ =========== =======
Workload             TCTI      AOK gadgets  TCTI / AOK  M4
==================== ========= ============ =========== =======
CoreMark              13.8 G     5.2 G      2.66        2.52
n-body (doubles)      11.2 G     5.9 G      1.90        1.67
Python                51.1 G    14.0 G      3.65        3.41
xz -3                 18.4 G     7.8 G      2.35        2.58
sha256sum              7.9 G     3.3 G      2.37        2.34
awk                   17.0 G     5.5 G      3.09        3.30
==================== ========= ============ =========== =======

Testing
=======

The three transcripts every front end has are identical for a 64-bit guest
and for a 32-bit one, with one CPU and with four. The FP test's reference is
the hardware rather than TCG: TCG's SSE gives two NaN operands the x87's
answer, not SSE's first source, so its transcript differs from an x86
processor's; the gadgets' is the same binary's on an AMD Ryzen, line for
line, the 370,000 lines of every result included.

``x86test``: the integer instructions on awkward and random operands with the
flags hashed in, among them what Linux's compilers seldom emit and other
systems' code is full of: ``rep`` with the direction flag set, ``repne
scas`` and ``repe cmps``, ``loop``, ``cmpxchg8b``, rotates whose flags are
read, segment registers pushed and loaded, and every condition after every
kind of instruction that sets flags, with a load or a store in between.
Identical to TCG's for both guests.

For the x87 the reference is the hardware: ``x87kat`` is iSH-AOK's three
known-answer programs (every D8-DF form under the four rounding and four
precision settings from stacks that overflow and underflow, the same with
exceptions unmasked, and the transcendentals), 167,517 answers recorded on an
AMD Ryzen. Both PC guests pass all of them, three times over in one boot. The
same n-body program compiled for the x87 (``nbody87``, in the 32-bit guest)
takes 107 G host cycles under TCG and 39 G under the gadgets.

For the vectors, iSH-AOK's 35 test programs (SSE to SSE4.2, VEX, EVEX,
MXCSR and the undefined encodings), each carrying its answers from an AMD
Ryzen or, for AVX-512 and the #UD tests, Intel's emulator (SDE): every one
passes, 20,000 AVX-512 forms and 61,440 EVEX encodings among them. A
debugger's single step through AVX-512 code is tested too.

``poke``, a guest that must stay up: three CPUs busy in the scheduler while
the fourth flips one of the scheduler's static keys three thousand times.
*Stores into code* on the main page has what it found.

An x86 guest needs a source of entropy to be measured at all: without one a
Linux guest spends a quarter of a minute in its scheduler making some before
the first program that asks for random numbers can run. The x86 runs here
use ``-cpu qemu64,+rdrand`` and ``random.trust_cpu=on``.

Run-time switches
=================

``QEMU_AOK_X86_SKIP=88,89,1af``
  Leave these opcodes to TCG (hexadecimal; ``1xx`` is ``0f xx``).

``QEMU_AOK_X86_NO32``, ``QEMU_AOK_X86_NO64``
  Leave 32-bit code, or 64-bit code, to TCG.

``QEMU_AOK_X86_NOLIVE``, ``QEMU_AOK_X86_NOFP``, ``QEMU_AOK_X86_NOHF=mask``
  Compute every flag; leave doubles to the frames or QEMU's helpers rather
  than the host's FP unit; compute in C the conditions of the classes in the
  mask (bits as ``HF_`` in ``translate-x86.c``, bit 8 for "restore none",
  from bit 16 a mask of the sixteen conditions).

``QEMU_AOK_X86_NOX87``, ``QEMU_AOK_X86_NOVEC``, ``QEMU_AOK_X86_NOAVX512``
  Leave the x87, or VEX and EVEX, to TCG; offer no AVX-512.

``QEMU_AOK_X86_SSEHELPERS``
  Legacy SSE's floating point with QEMU's helpers, as before the frames.

``QEMU_AOK_X86_NOONE``
  Leave a stepped AVX-512 instruction to TCG (which raises #UD).
