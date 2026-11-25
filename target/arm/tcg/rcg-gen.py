#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
""" RCG's gadget generator for AArch64 guests.

RCG, the rich code generator, runs a guest instruction under TCTI as one
gadget that does the whole instruction, where TCG would run a gadget for
each of its TCG ops. What each A64 instruction does is written here once:
the tables below list every form there is a gadget for, and the body of
each gadget loads its registers from env, computes, then writes the result
and NZCV. The translator is target/arm/tcg/rcg.c.inc.

The harnesses a body runs in, and the part of a body that no guest
changes, are in tcg/aarch64-tcti/rcg_core.py, as for x86.

The translator decodes with a decoder of its own, a64-rcg.decode, which
this writes from a64.decode: the lines of every pattern named in PATTERNS,
with what they refer to, the pattern renamed rcg_<name>. So an instruction
is offered to trans_rcg_<name>() exactly when a64.decode gives it to
trans_<name>(), with the same arguments.

The same tables give the system test that checks RCG against TCG, which
runs every encoding class over awkward values (tests/tcg/aarch64/system).
--check renders every gadget's body and checks what it names, and that the
patterns can be copied. --gadgets writes TCTI's gadgets, a64-rcg-table.c.inc
and a64-rcg.decode to a directory. --coverage checks that the tests took
every gadget (see rcg_core.check_coverage()):

    rcg-gen.py --insn-tests FILE
    rcg-gen.py --branch-tests FILE
    rcg-gen.py --check
    rcg-gen.py --gadgets DIR
    rcg-gen.py --coverage ordered|plain NM TRACE...

There are gadgets for the integer data processing instructions between
registers: the adds and subtracts, the logical operations, the moves of
constants, the bitfield moves and EXTR, the shifts, the multiplies and
divides, and the bit and byte reversals and counts; for the conditional
selects and compares; and for the conditional branches, B.cond, CBZ and
TBZ. Everything else is left to TCG.
"""

import argparse
import os
import re
import sys

# The source tree's root, three levels above this file.
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")

# rcg_core is what RCG's generators share. It is imported without leaving
# bytecode in the source tree.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(SRC, "tcg", "aarch64-tcti"))
import rcg_core  # noqa: E402
from rcg_core import ADDR, A, B, R, T, CheckHarness, TctiHarness  # noqa: E402
from rcg_core import ARM_INVERT, w  # noqa: E402


#
# The guest's side: registers, widths and words.
#

# A register is an operand word: the env offset of its xregs[] slot. Slot 31
# is SP, which only the forms that take SP name. Where register 31 is XZR
# there is no word: a form that often reads it has a variant that reads
# zero, one that often writes it under S has a variant that writes only
# NZCV, and the rest are left to TCG.
WIDTHS = (32, 64)

# The operand words, in the translator's order: the destination register,
# the first, second and third source registers, an immediate, a mask, and
# two shift amounts.
WORD_NAMES = ("d", "n", "m", "a", "imm", "mask", "sa", "sa2")

# The operand words that always fit in 32 bits, signed: env offsets and
# shift amounts. imm and mask may not.
NARROW_WORDS = ("d", "n", "m", "a", "sa", "sa2")

# What an instruction does with NZCV and its result: neither S nor a
# compare ("none"), an S form ("set"), or an S form with XZR as its
# destination, which writes only NZCV ("only": CMP, CMN and TST).
FLAGS = ("none", "set", "only")

# How a shifted-register form shifts its second source: not at all, which
# is any shift by 0, or by the "sa" word. Add and subtract have no ROR.
SHIFTS = ("none", "lsl", "lsr", "asr", "ror")

# Which source of a shifted-register form is XZR: neither, the first
# ("n": NEG, NEGS, MOV and MVN) or the second ("m"), which no shift
# changes.
ZEROS = ("none", "n", "m")

# How an extended-register add or subtract extends its second source: not
# at all (UXTX and SXTX, and at 32 bits UXTW and SXTW too), or from 8, 16
# or 32 bits, without or with sign.
EXTENDS = ("none", "ub", "uh", "uw", "sb", "sh", "sw")

# The logical operations; each also has a form that inverts its second
# source (BIC, ORN and EON).
LOGICS = ("and", "orr", "eor")

# Which of a bitfield move's two shifts it needs (see bitfield_body()).
BITFIELDS = ("both", "first", "second")

# The multiply-adds, by what they multiply: 64-bit registers, 32-bit
# registers, or 32-bit registers extended to 64, with sign or without.
MULS = ("x", "w", "sl", "ul")

# The operations on one register.
UNARIES = ("rbit", "rev16", "rev32", "rev64", "clz", "cls")

# The conditions, by their encoding. 14 and 15 are always, which TCG has.
CONDS = ("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge",
         "lt", "gt", "le")

# The conditional selects: CSEL, CSINC, CSINV and CSNEG.
SELECTS = ("sel", "inc", "inv", "neg")


def select_name(op):
    return "csel" if op == "sel" else "cs" + op

# The gadgets a B.cond right after them can join (see fused_specs()), by
# name without the width: CMP and CMN of an immediate, CMP of a register,
# TST of an immediate and of a register, and SUBS of an immediate.
FUSED_SETTERS = ("cmp_i", "cmn_i", "cmp_r", "ands_i_only", "ands_r_only",
                 "subs_i")

# The patterns of a64.decode that a64-rcg.decode copies, each with the
# translator's trans_rcg_<name>().
PATTERNS = ("ADD_i", "ADDS_i", "SUB_i", "SUBS_i",
            "ADD_r", "ADDS_r", "SUB_r", "SUBS_r",
            "ADD_ext", "ADDS_ext", "SUB_ext", "SUBS_ext",
            "ADC", "ADCS", "SBC", "SBCS",
            "AND_i", "ORR_i", "EOR_i", "ANDS_i",
            "AND_r", "ORR_r", "EOR_r", "ANDS_r",
            "MOVN", "MOVZ", "MOVK", "ADR", "ADRP",
            "SBFM", "BFM", "UBFM", "EXTR",
            "LSLV", "LSRV", "ASRV", "RORV", "UDIV", "SDIV",
            "MADD_w", "MSUB_w", "MADD_x", "MSUB_x",
            "SMADDL", "SMSUBL", "UMADDL", "UMSUBL", "SMULH", "UMULH",
            "RBIT", "REV16", "REV32", "REV64", "CLZ", "CLS",
            "CSEL", "CCMP", "B_cond", "CBZ", "TBZ")

# The translator's tables of gadgets, by kind: each index's name and the
# values it takes, a number of them or the tuple that names them. A kind
# with no index has one gadget.
TABLES = {
    "addsub_i": (("sub", 2), ("sf", 2), ("flags", FLAGS)),
    "addsub_r": (("sub", 2), ("sf", 2), ("flags", FLAGS),
                 ("shift", SHIFTS), ("zero", ZEROS)),
    "addsub_x": (("sub", 2), ("sf", 2), ("flags", FLAGS),
                 ("extend", EXTENDS)),
    "adc": (("sub", 2), ("sf", 2), ("set", 2)),
    "logic_i": (("op", LOGICS), ("sf", 2), ("flags", FLAGS)),
    "logic_r": (("op", LOGICS), ("inv", 2), ("sf", 2), ("flags", FLAGS),
                ("shift", SHIFTS), ("zn", 2)),
    "mov_i": (),
    "movk": (),
    "adr": (),
    "bitfield": (("signed", 2), ("sf", 2), ("shifts", BITFIELDS)),
    "bfm": (("sf", 2),),
    "extr": (("sf", 2), ("ror", 2)),
    "shiftv": (("shift", SHIFTS), ("sf", 2)),
    "div": (("signed", 2), ("sf", 2)),
    "muladd": (("mul", MULS), ("sub", 2), ("za", 2)),
    "mulh": (("signed", 2),),
    "unary": (("op", UNARIES), ("sf", 2)),
    "csel": (("op", SELECTS), ("sf", 2), ("cond", 16), ("zz", 2)),
    "ccmp": (("sub", 2), ("sf", 2), ("imm", 2), ("cond", 16)),
    "bcond": (("cond", 16), ("jumps", 2)),
    "cbz": (("sf", 2), ("nz", 2), ("jumps", 2)),
    "tbz": (("nz", 2), ("jumps", 2)),
    "fused": (("setter", len(FUSED_SETTERS) * 2), ("cond", 16),
              ("jumps", 2)),
}

# The tuples that become enums in the table, with their prefixes.
ENUMS = (("FLAGS", FLAGS), ("SHIFT", SHIFTS), ("ZERO", ZEROS),
         ("EXTEND", EXTENDS), ("LOGIC", LOGICS), ("BITFIELD", BITFIELDS),
         ("MUL", MULS), ("UNARY", UNARIES), ("SELECT", SELECTS))

# The gadget source files, by kind, split so they compile in parallel.
# Must match target/arm/tcg/meson.build.
KIND_FILES = {
    "addsub_i": "addsub", "addsub_r": "addsub", "addsub_x": "addsub",
    "adc": "addsub",
    "logic_i": "logic", "logic_r": "logic",
    "mov_i": "move", "movk": "move", "adr": "move", "bitfield": "move",
    "bfm": "move", "extr": "move", "shiftv": "move", "unary": "move",
    "div": "mul", "muladd": "mul", "mulh": "mul",
    "csel": "cond", "ccmp": "cond",
    "bcond": "branch", "cbz": "branch", "tbz": "branch", "fused": "fused",
}
GADGET_FILES = ("addsub", "logic", "move", "mul", "cond", "branch", "fused")


class Spec:
    """ One gadget: its kind, which picks its body and its table, its
    name, its operand words in the translator's order, its place in the
    kind's table, a value for each index of TABLES, and whatever else its
    body needs to know, as attributes. """

    ordered = False
    accesses_memory = False
    has_table = False

    def __init__(self, kind, name, words, index, **attrs):
        self.kind = kind
        self.name = name
        self.words = list(words)
        self.index = list(index)
        self.__dict__.update(attrs)

    @property
    def stream(self):
        """ The stream words, from rcg_core.stream_words(). """
        return rcg_core.stream_words(self.words, NARROW_WORDS)


def addsub_name(sub, flags):
    """ The mnemonic of an add or subtract, with CMN and CMP for the forms
    that write only NZCV. """
    if flags == "only":
        return "cmp" if sub else "cmn"
    return ("sub" if sub else "add") + ("s" if flags == "set" else "")


def addsub_specs():
    """ ADD, ADDS, SUB and SUBS of an immediate, a shifted register and an
    extended register, and ADC, ADCS, SBC and SBCS. A shifted XZR is still
    zero, so the second source is XZR only without a shift, and a form
    with both sources XZR is left to TCG. """
    for sub in (False, True):
        for width in WIDTHS:
            sf = WIDTHS.index(width)
            for flags in FLAGS:
                f = FLAGS.index(flags)
                d = [] if flags == "only" else ["d"]
                name = addsub_name(sub, flags)
                yield Spec("addsub_i", f"{name}_i_{width}", d + ["n", "imm"],
                           (sub, sf, f), sub=sub, width=width, flags=flags)
                for shift in SHIFTS[:4]:
                    for zero in ZEROS:
                        if zero == "m" and shift != "none":
                            continue
                        form = "r" if shift == "none" else shift
                        if zero != "none":
                            form += "_z" + zero
                        words = d + [r for r in "nm" if r != zero] + \
                            (["sa"] if shift != "none" else [])
                        yield Spec("addsub_r", f"{name}_{form}_{width}", words,
                                   (sub, sf, f, SHIFTS.index(shift),
                                    ZEROS.index(zero)),
                                   sub=sub, width=width, flags=flags,
                                   shift=shift, zero=zero)
                for extend in EXTENDS:
                    if width == 32 and extend in ("uw", "sw"):
                        continue
                    yield Spec("addsub_x", f"{name}_x{extend}_{width}",
                               d + ["n", "m", "sa"],
                               (sub, sf, f, EXTENDS.index(extend)),
                               sub=sub, width=width, flags=flags,
                               extend=extend)
            for setflags in (False, True):
                name = ("sbc" if sub else "adc") + ("s" if setflags else "")
                yield Spec("adc", f"{name}_{width}", ("d", "n", "m"),
                           (sub, sf, setflags), sub=sub, width=width,
                           flags="set" if setflags else "none")


def logic_name(op, inv, flags):
    """ The mnemonic of a logical operation: BIC, ORN and EON invert the
    second source, ANDS and BICS set NZCV. """
    name = {"and": "bic", "orr": "orn", "eor": "eon"}[op] if inv else op
    return name + ("s" if flags != "none" else "")


def logic_specs():
    """ AND, ORR, EOR and ANDS of an immediate, and those and BIC, ORN, EON
    and BICS of a shifted register. Only AND has S forms. ORR and ORN of
    XZR and an unshifted register are MOV and MVN ("zn"). """
    for op in LOGICS:
        o = LOGICS.index(op)
        for width in WIDTHS:
            sf = WIDTHS.index(width)
            for flags in FLAGS if op == "and" else FLAGS[:1]:
                f = FLAGS.index(flags)
                d = [] if flags == "only" else ["d"]
                only = "_only" if flags == "only" else ""
                yield Spec("logic_i",
                           f"{logic_name(op, False, flags)}_i{only}_{width}",
                           d + ["n", "imm"], (o, sf, f),
                           op=op, inv=False, width=width, flags=flags)
                for inv in (False, True):
                    name = logic_name(op, inv, flags)
                    for shift in SHIFTS:
                        form = "r" if shift == "none" else shift
                        yield Spec("logic_r", f"{name}_{form}{only}_{width}",
                                   d + ["n", "m"] +
                                   (["sa"] if shift != "none" else []),
                                   (o, inv, sf, f, SHIFTS.index(shift), 0),
                                   op=op, inv=inv, width=width, flags=flags,
                                   shift=shift, zn=False)
                    if op == "orr":
                        yield Spec("logic_r", f"{name}_r_zn_{width}",
                                   ("d", "m"), (o, inv, sf, f, 0, 1),
                                   op=op, inv=inv, width=width, flags=flags,
                                   shift="none", zn=True)


def move_specs():
    """ The moves: a constant to a register (MOVZ, MOVN, and ORR of XZR and
    an immediate), MOVK, ADR and ADRP, the bitfield moves SBFM, UBFM and
    BFM with every alias they have, EXTR with ROR, the shifts by a
    register, and the operations on one register. """
    yield Spec("mov_i", "mov_i", ("d", "imm"), ())
    yield Spec("movk", "movk", ("d", "imm", "mask"), ())
    yield Spec("adr", "adr", ("d", "imm"), ())
    for width in WIDTHS:
        sf = WIDTHS.index(width)
        for signed in (False, True):
            for shifts in BITFIELDS:
                words = ["d", "n"] + (["sa"] if shifts != "second" else []) + \
                    (["sa2"] if shifts != "first" else [])
                yield Spec("bitfield",
                           f"{'sbfm' if signed else 'ubfm'}_{shifts}_{width}",
                           words, (signed, sf, BITFIELDS.index(shifts)),
                           signed=signed, width=width, shifts=shifts)
        yield Spec("bfm", f"bfm_{width}", ("d", "n", "sa", "mask"), (sf,),
                   width=width)
        yield Spec("extr", f"extr_{width}", ("d", "n", "m", "sa", "sa2"),
                   (sf, 0), width=width, ror=False)
        yield Spec("extr", f"ror_i_{width}", ("d", "m", "sa"), (sf, 1),
                   width=width, ror=True)
        for shift in SHIFTS[1:]:
            yield Spec("shiftv", f"{shift}v_{width}", ("d", "n", "m"),
                       (SHIFTS.index(shift), sf), width=width, shift=shift)
        for op in UNARIES:
            if op == "rev64" and width == 32:
                continue
            yield Spec("unary", f"{op}_{width}", ("d", "n"),
                       (UNARIES.index(op), sf), width=width, op=op)


def mul_specs():
    """ UDIV and SDIV; MADD and MSUB of X and of W registers, and SMADDL,
    SMSUBL, UMADDL and UMSUBL, each also with XZR as the register added to
    or subtracted from ("za": MUL, MNEG, SMULL, SMNEGL, UMULL and UMNEGL);
    and SMULH and UMULH. """
    for signed in (False, True):
        for width in WIDTHS:
            yield Spec("div", f"{'sdiv' if signed else 'udiv'}_{width}",
                       ("d", "n", "m"), (signed, WIDTHS.index(width)),
                       signed=signed, width=width)
    for mul in MULS:
        for sub in (False, True):
            for za in (False, True):
                name = {"x": "m", "w": "m", "sl": "sm", "ul": "um"}[mul] + \
                    ("sub" if sub else "add") + ("l" if "l" in mul else "") + \
                    ("_za" if za else "") + ("_32" if mul == "w" else "")
                yield Spec("muladd", name,
                           ["d", "n", "m"] + ([] if za else ["a"]),
                           (MULS.index(mul), sub, za), mul=mul, sub=sub, za=za)
    for signed in (False, True):
        yield Spec("mulh", "smulh" if signed else "umulh", ("d", "n", "m"),
                   (signed,), signed=signed, width=64)


def cond_specs():
    """ CSEL, CSINC, CSINV and CSNEG for each condition, and CSINC and
    CSINV of XZR and XZR ("zz": CSET and CSETM); and CCMP and CCMN of a
    register and of an immediate for each condition. """
    for op in SELECTS:
        for width in WIDTHS:
            for cond, name in enumerate(CONDS):
                index = (SELECTS.index(op), WIDTHS.index(width), cond)
                yield Spec("csel", f"{select_name(op)}_{name}_{width}",
                           ("d", "n", "m"), (*index, 0), op=op, width=width,
                           cond=cond, zz=False)
                if op in ("inc", "inv"):
                    yield Spec("csel", f"cs{op}_zz_{name}_{width}", ("d",),
                               (*index, 1), op=op, width=width, cond=cond,
                               zz=True)
    for sub in (False, True):
        for width in WIDTHS:
            for imm in (False, True):
                for cond, name in enumerate(CONDS):
                    yield Spec("ccmp",
                               f"{'ccmp' if sub else 'ccmn'}_"
                               f"{'i' if imm else 'r'}_{name}_{width}",
                               ("n", "imm" if imm else "m", "mask"),
                               (sub, WIDTHS.index(width), imm, cond),
                               sub=sub, width=width, imm=imm, cond=cond)


def branch_specs():
    """ B.cond for each condition, CBZ and CBNZ at each width, and TBZ and
    TBNZ, each as a gadget that branches and as one that also makes the
    jump to the next TB each way ("jumps": see rcg_core's Harness). """
    for jumps in (False, True):
        suffix = "_jumps" if jumps else ""
        for cond, name in enumerate(CONDS):
            yield Spec("bcond", f"b_{name}{suffix}", (), (cond, jumps),
                       cond=cond, jumps=jumps)
        for width in WIDTHS:
            for nz in (False, True):
                yield Spec("cbz", f"cb{'n' if nz else ''}z_{width}{suffix}",
                           ("n",), (WIDTHS.index(width), nz, jumps),
                           width=width, nz=nz, jumps=jumps)
        for nz in (False, True):
            yield Spec("tbz", f"tb{'n' if nz else ''}z{suffix}",
                       ("n", "mask"), (nz, jumps), nz=nz, jumps=jumps)


def fused_setters():
    """ The specs of the gadgets a B.cond right after them can join:
    FUSED_SETTERS at each width, in the order of the translator's
    rcg_fused_setter. """
    by_name = {spec.name: spec for spec in (*addsub_specs(), *logic_specs())}
    return [by_name[f"{name}_{width}"]
            for name in FUSED_SETTERS for width in WIDTHS]


def fused_specs():
    """ A setter of fused_setters() and the B.cond right after it, in one
    gadget, which does the setter's work and then branches on the host's
    flags as the setter left them, rather than on NZCV reloaded from env.
    Its words are the setter's. """
    for i, setter in enumerate(fused_setters()):
        for cond, name in enumerate(CONDS):
            for jumps in (False, True):
                yield Spec("fused",
                           f"{setter.name}_b_{name}"
                           f"{'_jumps' if jumps else ''}",
                           setter.words, (i, cond, jumps), setter=setter,
                           cond=cond, jumps=jumps)


def specs():
    """ Every gadget. """
    yield from addsub_specs()
    yield from logic_specs()
    yield from move_specs()
    yield from mul_specs()
    yield from cond_specs()
    yield from branch_specs()
    yield from fused_specs()


#
# The host's side: the gadget bodies.
#

class Body(rcg_core.Body):
    """ An A64 gadget's body: rcg_core's, with the guest's registers and
    NZCV. """

    def read_reg(self, dest, word):
        """ dest = the whole register whose env offset is in word. A body
        at 32 bits uses the low half, as TCG's read_cpu_reg() gives. """
        self.emit(f"ldr {dest}, [{self.env}, {self.word(word)}]")
        self.define(dest)

    def write_reg(self, value, word):
        """ value to the whole register whose env offset is in word. At 32
        bits the body has left the upper half zero, as TCG's ext32u does.
        """
        self.emit(f"str {value}, [{self.env}, {self.word(word)}]")

    def write_nzcv(self):
        """ The guest's NZCV from the host's, as the instruction before
        this left them. env holds each flag in a 32-bit field of which only
        this much means anything: bit 31 of NF and VF, whether ZF is 0,
        which says that Z is set, and CF, 0 or 1. So NF is the host's NZCV
        itself, whose bit 31 is N, VF is that shifted to put V there, and
        ZF and CF are CSETs. The fields are together in env, CF first. It
        uses ADDR, A, B, R and T. """
        self.emit(f"mrs {T}, nzcv",
                  f"cset {w(A)}, cs",
                  f"lsl {w(B)}, {w(T)}, #3",
                  f"cset {w(ADDR)}, ne",
                  f"add {R}, {self.env}, %[cf]",
                  f"stp {w(A)}, {w(B)}, [{R}]",
                  f"stp {w(T)}, {w(ADDR)}, [{R}, #8]")

    def read_carry(self):
        """ The host's C from the guest's: CF is 0 or 1, and comparing it
        with 1 sets C exactly when it is 1. It uses T. """
        self.emit(f"ldr {w(T)}, [{self.env}, %[cf]]",
                  f"cmp {w(T)}, #1")

    def test_cond(self, cond):
        """ Sets the host's flags from the guest's NZCV in env, and returns
        the host's condition under which the guest's condition cond holds.
        It reads only the fields the condition needs, and of them only
        what they mean: N and V are bit 31 of NF and VF, Z is set where ZF
        is 0, and C where CF is not. It uses ADDR and T. """
        env, t, u = self.env, w(T), w(ADDR)
        base = cond >> 1
        if base == 0:
            self.emit(f"ldr {t}, [{env}, %[zf]]", f"cmp {t}, #0")
            arm = "eq"
        elif base == 1:
            self.emit(f"ldr {t}, [{env}, %[cf]]", f"cmp {t}, #0")
            arm = "ne"
        elif base in (2, 3):
            self.emit(f"ldr {t}, [{env}, %[{'nf' if base == 2 else 'vf'}]]",
                      f"cmp {t}, #0")
            arm = "mi"
        elif base == 4:
            # HI: C and not Z. If CF is not 0, the test of ZF; else Z.
            self.emit(f"ldr {t}, [{env}, %[cf]]",
                      f"ldr {u}, [{env}, %[zf]]",
                      f"cmp {t}, #0",
                      f"ccmp {u}, #0, #4, ne")
            arm = "ne"
        else:
            # GE: N is V. GT: that, and not Z: if ZF is not 0, the test of
            # NF ^ VF; else N.
            self.emit(f"ldr {t}, [{env}, %[nf]]",
                      f"ldr {u}, [{env}, %[vf]]",
                      f"eor {t}, {t}, {u}")
            if base == 5:
                self.emit(f"cmp {t}, #0")
            else:
                self.emit(f"ldr {u}, [{env}, %[zf]]",
                          f"cmp {u}, #0",
                          f"ccmp {t}, #0, #8, ne")
            arm = "pl"
        return ARM_INVERT[arm] if cond & 1 else arm


def reg(x, width):
    """ The view of x register x that a body at width computes in. """
    return x if width == 64 else w(x)


def finish(g, spec):
    """ The end of a body that has its result in R and, for an S form, the
    host's NZCV set from it. """
    if spec.flags != "only":
        g.write_reg(R, "d")
    if spec.flags != "none":
        g.write_nzcv()


def addsub_body(g, spec):
    """ ADD, ADDS, SUB and SUBS, CMN and CMP among them: the host's own
    instruction on the two sources, at the guest's width. At 32 bits the
    host's W form leaves the upper half of its result zero and sets NZCV
    from the low half, both as the guest's does. A shift is the host's
    variable one, which takes its amount modulo the width, as the
    translator requires it to be below the width already. An extended
    register is extended from its low 8, 16 or 32 bits, then shifted left
    by 0 to 4, as TCG's ext_and_shift_reg() does. """
    width = spec.width
    a, b, r = reg(A, width), reg(B, width), reg(R, width)
    if spec.kind == "addsub_i":
        g.read_reg(A, "n")
        b = reg(g.word("imm"), width)
    elif spec.kind == "addsub_x":
        g.read_reg(A, "n")
        g.read_reg(B, "m")
        if spec.extend != "none":
            signed, size = spec.extend[0] == "s", spec.extend[1]
            if signed:
                g.emit(f"sxt{size} {b}, {w(B)}")
            elif size == "w":
                g.emit(f"mov {w(B)}, {w(B)}")
            else:
                g.emit(f"uxt{size} {w(B)}, {w(B)}")
        g.emit(f"lsl {b}, {b}, {reg(g.word('sa'), width)}")
    else:
        if spec.zero == "n":
            a = reg("xzr", width)
        else:
            g.read_reg(A, "n")
        if spec.zero == "m":
            b = reg("xzr", width)
        else:
            g.read_reg(B, "m")
        if spec.shift != "none":
            g.emit(f"{spec.shift} {b}, {b}, {reg(g.word('sa'), width)}")
    op = ("sub" if spec.sub else "add") + ("" if spec.flags == "none" else "s")
    g.emit(f"{op} {r}, {a}, {b}")
    finish(g, spec)


def adc_body(g, spec):
    """ ADC, ADCS, SBC and SBCS: the host's own, after its C is set from
    the guest's CF. """
    width = spec.width
    g.read_reg(A, "n")
    g.read_reg(B, "m")
    g.read_carry()
    op = ("sbc" if spec.sub else "adc") + ("" if spec.flags == "none" else "s")
    g.emit(f"{op} {reg(R, width)}, {reg(A, width)}, {reg(B, width)}")
    finish(g, spec)


def logic_body(g, spec):
    """ The logical operations: the host's own. ANDS and BICS leave the
    host's C and V clear, as the guest's are after them. MOV and MVN,
    which are ORR and ORN of XZR, are the host's too. """
    width = spec.width
    a, b, r = reg(A, width), reg(B, width), reg(R, width)
    if spec.kind == "logic_i":
        g.read_reg(A, "n")
        b = reg(g.word("imm"), width)
    else:
        if spec.zn:
            a = reg("xzr", width)
        else:
            g.read_reg(A, "n")
        g.read_reg(B, "m")
        if spec.shift != "none":
            g.emit(f"{spec.shift} {b}, {b}, {reg(g.word('sa'), width)}")
    g.emit(f"{logic_name(spec.op, spec.inv, spec.flags)} {r}, {a}, {b}")
    finish(g, spec)


def mov_i_body(g, spec):
    """ A constant, which the translator works out, to a register. """
    g.write_reg(g.word("imm"), "d")


def movk_body(g, spec):
    """ MOVK: the register with the bits of mask cleared, then those of imm
    set. At 32 bits the mask has the upper half too. """
    g.read_reg(A, "d")
    g.emit(f"bic {A}, {A}, {g.word('mask')}",
           f"orr {A}, {A}, {g.word('imm')}")
    g.write_reg(A, "d")


def adr_body(g, spec):
    """ ADR and ADRP under CF_PCREL: env's pc plus what the translator
    works out, as gen_pc_plus_diff() adds. """
    g.emit(f"ldr {A}, [{g.env}, %[pc]]",
           f"add {A}, {A}, {g.word('imm')}")
    g.write_reg(A, "d")


def bitfield_body(g, spec):
    """ SBFM and UBFM, whatever alias they are: a shift left by sa, then a
    shift right by sa2, arithmetic for SBFM, both at the guest's width.
    With the width less one less imms as the first amount, and that plus
    immr, modulo the width, as the second, the two shifts are an extract
    (imms >= immr) or an insert into zeros, and the host takes each amount
    modulo the width itself. A bitfield move with one amount zero has a
    gadget without that shift: LSL, and LSR and ASR. """
    width = spec.width
    a = reg(A, width)
    g.read_reg(A, "n")
    if spec.shifts != "second":
        g.emit(f"lsl {a}, {a}, {reg(g.word('sa'), width)}")
    if spec.shifts != "first":
        g.emit(f"{'asr' if spec.signed else 'lsr'} {a}, {a}, "
               f"{reg(g.word('sa2'), width)}")
    g.write_reg(A, "d")


def bfm_body(g, spec):
    """ BFM: the source rotated right by immr at the guest's width, which
    puts the field where it goes for both of BFM's cases, then those bits
    of the destination replaced. The translator works out the mask of the
    bits that change. """
    width = spec.width
    a, b, mask = reg(A, width), reg(B, width), reg(g.word("mask"), width)
    g.read_reg(A, "n")
    g.read_reg(B, "d")
    g.emit(f"ror {a}, {a}, {reg(g.word('sa'), width)}",
           f"and {a}, {a}, {mask}",
           f"bic {b}, {b}, {mask}",
           f"orr {b}, {b}, {a}")
    g.write_reg(B, "d")


def extr_body(g, spec):
    """ EXTR: the second source shifted right by sa, with the first
    shifted left by sa2, the width less sa, above it. With both sources
    the same register it is ROR. An EXTR by 0 is left to TCG. """
    width = spec.width
    a, b, r = reg(A, width), reg(B, width), reg(R, width)
    g.read_reg(B, "m")
    if spec.ror:
        g.emit(f"ror {r}, {b}, {reg(g.word('sa'), width)}")
    else:
        g.read_reg(A, "n")
        g.emit(f"lsr {b}, {b}, {reg(g.word('sa'), width)}",
               f"lsl {a}, {a}, {reg(g.word('sa2'), width)}",
               f"orr {r}, {a}, {b}")
    g.write_reg(R, "d")


def binary_body(g, spec, insn):
    """ The host's insn on two registers at the guest's width. """
    width = spec.width
    g.read_reg(A, "n")
    g.read_reg(B, "m")
    g.emit(f"{insn} {reg(R, width)}, {reg(A, width)}, {reg(B, width)}")
    g.write_reg(R, "d")


def shiftv_body(g, spec):
    """ LSLV, LSRV, ASRV and RORV: the host's, which also takes the amount
    modulo the width. """
    binary_body(g, spec, spec.shift)


def div_body(g, spec):
    """ UDIV and SDIV: the host's, which also gives 0 for a division by 0
    and the dividend for the one signed division that overflows. """
    binary_body(g, spec, "sdiv" if spec.signed else "udiv")


def muladd_body(g, spec):
    """ The multiply-adds: the host's own. """
    wide = spec.mul != "w"
    r = R if wide else w(R)
    a, b = (A, B) if spec.mul == "x" else (w(A), w(B))
    prefix = {"x": "", "w": "", "sl": "s", "ul": "u"}[spec.mul]
    suffix = "l" if "l" in spec.mul else ""
    g.read_reg(A, "n")
    g.read_reg(B, "m")
    if spec.za:
        insn = prefix + ("mneg" if spec.sub else "mul") + suffix
        g.emit(f"{insn} {r}, {a}, {b}")
    else:
        g.read_reg(T, "a")
        insn = prefix + ("msub" if spec.sub else "madd") + suffix
        g.emit(f"{insn} {r}, {a}, {b}, {T if wide else w(T)}")
    g.write_reg(R, "d")


def mulh_body(g, spec):
    """ SMULH and UMULH: the host's. """
    binary_body(g, spec, "smulh" if spec.signed else "umulh")


def unary_body(g, spec):
    """ RBIT, REV16, REV32, REV64, CLZ and CLS: the host's. REV32 at 32
    bits is REV of a W register, and REV64 is REV of an X register. """
    width = spec.width
    insn = "rev" if spec.op == "rev64" or (spec.op, width) == ("rev32", 32) \
        else spec.op
    g.read_reg(A, "n")
    g.emit(f"{insn} {reg(R, width)}, {reg(A, width)}")
    g.write_reg(R, "d")


def csel_body(g, spec):
    """ CSEL, CSINC, CSINV and CSNEG: the host's own, on the condition
    that test_cond() makes of the guest's. """
    width = spec.width
    a = b = reg("xzr", width)
    if not spec.zz:
        g.read_reg(A, "n")
        g.read_reg(B, "m")
        a, b = reg(A, width), reg(B, width)
    arm = g.test_cond(spec.cond)
    g.emit(f"{select_name(spec.op)} {reg(R, width)}, {a}, {b}, {arm}")
    g.write_reg(R, "d")


def ccmp_body(g, spec):
    """ CCMP and CCMN: the compare, whose NZCV is kept if the condition
    holds, and else replaced by the instruction's, which the translator
    has shifted into place in the mask word. The condition is tested after
    the compare, from env, which the compare has not changed yet. """
    width = spec.width
    g.read_reg(A, "n")
    if spec.imm:
        b = reg(g.word("imm"), width)
    else:
        g.read_reg(B, "m")
        b = reg(B, width)
    g.emit(f"{'cmp' if spec.sub else 'cmn'} {reg(A, width)}, {b}",
           f"mrs {R}, nzcv")
    arm = g.test_cond(spec.cond)
    g.emit(f"csel {R}, {R}, {g.word('mask')}, {arm}",
           f"msr nzcv, {R}")
    g.write_nzcv()


def branch_end(g, spec, arm):
    """ The end of a branch gadget that branches if the host's condition
    arm holds: the harness's branch, or its branch and jumps. """
    if spec.jumps:
        g.jumps(arm)
    else:
        g.branch(arm)


def bcond_body(g, spec):
    """ B.cond, on NZCV from env. """
    branch_end(g, spec, g.test_cond(spec.cond))


def cbz_body(g, spec):
    """ CBZ and CBNZ. """
    g.read_reg(A, "n")
    g.emit(f"cmp {reg(A, spec.width)}, #0")
    branch_end(g, spec, "ne" if spec.nz else "eq")


def tbz_body(g, spec):
    """ TBZ and TBNZ: the translator gives the bit as a mask. """
    g.read_reg(A, "n")
    g.emit(f"tst {A}, {g.word('mask')}")
    branch_end(g, spec, "ne" if spec.nz else "eq")


def fused_body(g, spec):
    """ The setter's body, then the branch on the host's flags, which are
    the guest's: write_nzcv() has stored them without changing them. """
    BODIES[spec.setter.kind](g, spec.setter)
    branch_end(g, spec, CONDS[spec.cond])


BODIES = {
    "addsub_i": addsub_body,
    "addsub_r": addsub_body,
    "addsub_x": addsub_body,
    "adc": adc_body,
    "logic_i": logic_body,
    "logic_r": logic_body,
    "mov_i": mov_i_body,
    "movk": movk_body,
    "adr": adr_body,
    "bitfield": bitfield_body,
    "bfm": bfm_body,
    "extr": extr_body,
    "shiftv": shiftv_body,
    "div": div_body,
    "muladd": muladd_body,
    "mulh": mulh_body,
    "unary": unary_body,
    "csel": csel_body,
    "ccmp": ccmp_body,
    "bcond": bcond_body,
    "cbz": cbz_body,
    "tbz": tbz_body,
    "fused": fused_body,
}

# The "i" asm operands the bodies use, which the C compiler works out from
# QEMU's definitions: rcg_core's, though no body here reaches guest memory
# yet, then those the bodies use directly.
BODY_OPERANDS = {
    **rcg_core.MEMORY_OPERANDS,
    **rcg_core.HARNESS_OPERANDS,
    "cf": "offsetof(CPUARMState, CF)",
    "vf": "offsetof(CPUARMState, VF)",
    "nf": "offsetof(CPUARMState, NF)",
    "zf": "offsetof(CPUARMState, ZF)",
    "pc": "offsetof(CPUARMState, pc)",
}

# What the bodies take for granted of QEMU's definitions, beyond what their
# operands say, for code that builds the gadgets to check with
# QEMU_BUILD_BUG_ON.
BODY_ASSUMPTIONS = (
    # write_nzcv() stores CF and VF with one STP, and NF and ZF with another.
    "offsetof(CPUARMState, VF) != offsetof(CPUARMState, CF) + 4",
    "offsetof(CPUARMState, NF) != offsetof(CPUARMState, CF) + 8",
    "offsetof(CPUARMState, ZF) != offsetof(CPUARMState, CF) + 12",
    # and reaches them with an ADD immediate.
    "offsetof(CPUARMState, CF) > 4095",
    # read_carry() and adr_body() load from env with an immediate offset.
    "offsetof(CPUARMState, CF) % 4 || offsetof(CPUARMState, pc) % 8",
    "offsetof(CPUARMState, pc) > 32760",
)


def body(spec, harness):
    """ The lines of the gadget for spec, in harness. """
    g = Body(spec, harness)
    BODIES[spec.kind](g, spec)
    return g.lines()


#
# The translator's decoder: the patterns of a64.decode it has gadgets for.
#

A64_DECODE = os.path.join(SRC, "target", "arm", "tcg", "a64.decode")


def decode_lines():
    """ a64.decode's lines, each as its text, with continuation lines
    joined, and its depth in { } and [ ] groups. """
    depth = 0
    pending = ""
    with open(A64_DECODE) as f:
        for line in f:
            line = pending + line.rstrip("\n")
            if line.endswith("\\"):
                pending = line[:-1]
                continue
            pending = ""
            text = line.split("#")[0].strip()
            if text in ("}", "]"):
                depth -= 1
            yield line, text, depth
            if text in ("{", "["):
                depth += 1
    assert not pending and depth == 0


def rcg_decode():
    """ The lines of a64-rcg.decode: for every pattern of PATTERNS, every
    line of a64.decode with that name, renamed rcg_<name>, with the formats
    and fields the lines refer to, copied as they are, in a64.decode's
    order. Every argument set of a64.decode is declared, !extern, in the
    same order, so that decodetree gives a format or pattern that names
    none the set it gives it in a64.decode: the structs are those of
    a64.decode's decoder, and a trans_rcg_<name>() takes the arguments of
    trans_<name>().

    A pattern inside a { } or [ ] group cannot be copied alone: in a64.decode
    an earlier pattern of the group may take some of what it matches. """
    lines = list(decode_lines())
    wanted = set()
    found = set()
    for line, text, depth in lines:
        toks = text.split()
        if toks and toks[0] in PATTERNS:
            assert depth == 0, f"{toks[0]} is in a group in a64.decode"
            found.add(toks[0])
            wanted.update(tok.split("=")[-1] for tok in toks[1:])
    assert found == set(PATTERNS), set(PATTERNS) - found
    # What the patterns' formats refer to, and so on.
    grew = True
    while grew:
        grew = False
        for line, text, depth in lines:
            toks = text.split()
            if toks and toks[0][0] in "@%" and toks[0] in wanted:
                for tok in toks[1:]:
                    ref = tok.split("=")[-1]
                    if ref[0] in "@%&" and ref not in wanted:
                        wanted.add(ref)
                        grew = True
    out = ["# Automatically generated by rcg-gen.py from a64.decode. "
           "Do not edit.", ""]
    for line, text, depth in lines:
        toks = text.split()
        if not toks:
            continue
        if toks[0][0] == "&":
            assert "!extern" not in toks, text
            out.append(text + " !extern")
        elif toks[0] in PATTERNS:
            out.append("rcg_" + text)
        elif toks[0][0] in "@%" and toks[0] in wanted:
            out.append(text)
    return out


def check():
    """ Renders every gadget's body and checks its lines as
    rcg_core.check_lines() does, against BODY_OPERANDS, that each gadget
    has a place of its own in its kind's table, and that a64-rcg.decode
    can be written. Returns how many gadgets were checked. """
    h = CheckHarness()
    names = set()
    places = set()
    for spec in specs():
        assert spec.name not in names, spec.name
        names.add(spec.name)
        place = (spec.kind, *map(int, spec.index))
        assert place not in places, spec.name
        places.add(place)
        sizes = [n if isinstance(n, int) else len(n)
                 for _, n in TABLES[spec.kind]]
        assert len(sizes) == len(spec.index) and \
            all(i < n for i, n in zip(spec.index, sizes)), spec.name
        rcg_core.check_lines(spec.name, body(spec, h), h, BODY_OPERANDS)
    rcg_decode()
    return len(names)


#
# TCTI's gadgets, and the translator's table of them.
#

def write_table(all_specs, out):
    """ The translator's gadget tables: for each kind of TABLES, an array
    of gadgets indexed as it says, with each gadget's words. A form with no
    gadget has a null entry. """
    p = lambda *a: print(*a, file=out)
    rcg_core.write_table_head(out, BODY_ASSUMPTIONS, WORD_NAMES, NARROW_WORDS)
    for prefix, names in ENUMS:
        p("enum {")
        for name in names:
            p(f"    RCG_{prefix}_{name.upper()},")
        p(f"    RCG_NB_{prefix},\n}};\n")
    rcg_core.write_gadget_type(out)
    for spec in all_specs:
        p(f"void rcg_gadget_{spec.name}(void);")
    p("")
    setters = fused_setters()
    p("/* The gadgets a B.cond right after them can join: fused_setters(). */")
    p(f"#define RCG_NB_FUSED {len(setters)}\n")
    p("static const void *const rcg_fused_setter[RCG_NB_FUSED] = {")
    for spec in setters:
        p(f"    rcg_gadget_{spec.name},")
    p("};\n")
    for kind, indices in TABLES.items():
        if indices:
            p(f"/* Indexed by {', '.join(name for name, _ in indices)}. */")
        dims = "".join(f"[{n}]" if isinstance(n, int)
                       else f"[{len(n)}]" for _, n in indices)
        p(f"static const RCGGadget rcg_{kind}{dims} = {{")
        for spec in all_specs:
            if spec.kind == kind:
                place = "".join(f"[{int(i)}]" for i in spec.index)
                words = ", ".join(f"RCG_W_{w.upper()}" for w in spec.words)
                entry = f"rcg_gadget_{spec.name}, {{ {words} }}"
                p(f"    {place} = {{ {entry} }}," if place else
                  f"    {entry}")
        p("};\n")


def write_gadgets(outdir):
    """ Writes the gadgets, in TCTI's harness, as naked functions, their
    table and the translator's decoder to outdir. """
    harness = TctiHarness()
    all_specs = list(specs())
    instructions = rcg_core.write_gadgets(
        outdir, GADGET_FILES, ("cpu.h",), BODY_OPERANDS,
        ((KIND_FILES[spec.kind], spec.name, body(spec, harness))
         for spec in all_specs))
    with open(os.path.join(outdir, "a64-rcg-table.c.inc"), "w") as out:
        write_table(all_specs, out)
    with open(os.path.join(outdir, "a64-rcg.decode"), "w") as out:
        print("\n".join(rcg_decode()), file=out)

    sys.stderr.write(f"RCG: {len(all_specs)} gadgets with {instructions} "
                     f"instructions (~{instructions * 4 // 1024} KiB).\n")


#
# The tests: every encoding class, run over awkward values.
#

# The instructions of a case, as rcg-test.h's RCG_SLOT has it: those the
# case does not give are NOPs.
SLOT = 3
NOP = 0xd503201f

# MOVZ X16, #0xbad, which a case that branches puts after the branch, where
# the branch goes over it: X16 then says which way it went.
MARK = 0xd2800000 | 0xbad << 5 | 16


class Case:
    """ One test case: an instruction, as its encoding (word) and what to
    call it (name), and the registers that take the values tested, a and
    b, of which 31 is SP; -1 for none. more are the instructions after it,
    if any. adr is the register an ADR or ADRP writes, from whose value the
    test takes the instruction's address, or for ADRP (page) its page's, so
    that the result does not depend on where the test was linked. flags
    says that it reads NZCV, so that the test starts it from each value of
    NZCV; and branch that it branches. """

    def __init__(self, name, word, a=-1, b=-1, adr=-1, page=False, more=(),
                 flags=False, branch=False):
        self.name = name
        self.words = (word, *more, *(NOP,) * (SLOT - 1 - len(more)))
        assert len(self.words) == SLOT
        self.a = a
        self.b = b
        self.adr = adr
        self.page = page
        self.flags = flags
        self.branch = branch


def reg_name(n, width, sp=False):
    """ Register n at width as an instruction names it, with 31 as SP if sp
    and else as XZR. """
    if n == 31:
        return {(64, True): "sp", (32, True): "wsp",
                (64, False): "xzr", (32, False): "wzr"}[width, sp]
    return ("x" if width == 64 else "w") + str(n)


def roles(rn, rm):
    """ The registers that take the two values, for an instruction that
    reads rn and rm as registers, where 31 is XZR: each once. """
    return (rn if rn != 31 else -1, rm if rm not in (31, rn) else -1)


# The destination and source of an immediate form, with 31 and the same
# register twice among them.
IMM_REGS = ((0, 1), (2, 2), (0, 31), (31, 1), (31, 31), (30, 29))

# The immediate field's values, by whether it is shifted left by 12.
IMMS = {0: (0, 1, 0x800, 0xfff), 1: (1, 0xfff)}


def addsub_imm_cases():
    """ ADD, ADDS, SUB and SUBS of an immediate: every value of sf, op, S
    and the shift, over IMM_REGS and IMMS. Register 31 is SP, except as the
    destination of an S form, where it is XZR and the instruction is CMN or
    CMP. """
    for sf in (0, 1):
        for op in (0, 1):
            for s in (0, 1):
                for sh, imms in IMMS.items():
                    for rd, rn in IMM_REGS:
                        for imm in imms:
                            width = 64 if sf else 32
                            name = (f"{'sub' if op else 'add'}"
                                    f"{'s' if s else ''} "
                                    f"{reg_name(rd, width, not s)}, "
                                    f"{reg_name(rn, width, True)}, "
                                    f"#{imm:#x}{', lsl #12' if sh else ''}")
                            word = (sf << 31 | op << 30 | s << 29 |
                                    0b100010 << 23 | sh << 22 | imm << 10 |
                                    rn << 5 | rd)
                            yield Case(name, word, a=rn)


# The destination and sources of a form between registers, with 31, which
# is XZR, in each place, and registers repeated.
REGS3 = ((0, 1, 2), (0, 0, 0), (1, 1, 2), (2, 1, 2), (0, 1, 31),
         (0, 31, 2), (31, 1, 2), (31, 31, 2), (31, 1, 31), (0, 31, 31),
         (30, 29, 28))
SHIFT_NAMES = ("lsl", "lsr", "asr", "ror")


def names3(regs, width):
    return ", ".join(reg_name(r, width) for r in regs)


def addsub_shift_cases():
    """ ADD, ADDS, SUB and SUBS of a shifted register: every value of sf,
    op, S and the shift type that is allocated (ROR is not), by amounts
    from 0 to the most the width allows, over REGS3. Those that write
    XZR without S, and those with both sources XZR, are TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for op in (0, 1):
            for s in (0, 1):
                for st in range(3):
                    for sa in ((0, 1, width - 1) if st == 0 else
                               (0, 3, width - 1)):
                        for rd, rn, rm in REGS3:
                            name = (f"{'sub' if op else 'add'}"
                                    f"{'s' if s else ''} "
                                    f"{names3((rd, rn, rm), width)}, "
                                    f"{SHIFT_NAMES[st]} #{sa}")
                            word = (sf << 31 | op << 30 | s << 29 |
                                    0b01011 << 24 | st << 22 | rm << 16 |
                                    sa << 10 | rn << 5 | rd)
                            a, b = roles(rn, rm)
                            yield Case(name, word, a=a, b=b)


EXTEND_NAMES = ("uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx")

# The destination and sources of an extended-register form: 31 is SP as
# the first source, and as the destination without S, and XZR as the
# second source.
EXTEND_REGS = ((0, 1, 2), (1, 1, 2), (0, 31, 2), (31, 1, 2), (31, 31, 2),
               (0, 1, 31), (30, 29, 28))


def addsub_extend_cases():
    """ ADD, ADDS, SUB and SUBS of an extended register: every value of sf,
    op, S and the extension, shifted by 0 over EXTEND_REGS and by 1 and 4
    over two of them. Those with XZR as the second source are TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for op in (0, 1):
            for s in (0, 1):
                for option in range(8):
                    for sa in (0, 1, 4):
                        for rd, rn, rm in (EXTEND_REGS if sa == 0 else
                                           EXTEND_REGS[:1] + EXTEND_REGS[2:3]):
                            name = (f"{'sub' if op else 'add'}"
                                    f"{'s' if s else ''} "
                                    f"{reg_name(rd, width, not s)}, "
                                    f"{reg_name(rn, width, True)}, "
                                    f"{reg_name(rm, width)}, "
                                    f"{EXTEND_NAMES[option]} #{sa}")
                            word = (sf << 31 | op << 30 | s << 29 |
                                    0b01011001 << 21 | rm << 16 |
                                    option << 13 | sa << 10 | rn << 5 | rd)
                            yield Case(name, word, a=rn,
                                       b=rm if rm not in (31, rn) else -1)


def carry_cases():
    """ ADC, ADCS, SBC and SBCS: every value of sf, op and S over REGS3.
    The starts give them each value of C. Those with XZR in any place are
    TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for op in (0, 1):
            for s in (0, 1):
                for rd, rn, rm in REGS3:
                    name = (f"{'sbc' if op else 'adc'}{'s' if s else ''} "
                            f"{names3((rd, rn, rm), width)}")
                    word = (sf << 31 | op << 30 | s << 29 |
                            0b11010000 << 21 | rm << 16 | rn << 5 | rd)
                    a, b = roles(rn, rm)
                    yield Case(name, word, a=a, b=b)


def logic_imm(n, immr, imms):
    """ The value of a logical immediate, as logic_imm_decode_wmask()
    works it out: a run of imms + 1 ones in an element whose size n and
    imms give, rotated right by immr, in every element of 64 bits. """
    length = ((n << 6) | (~imms & 0x3f)).bit_length() - 1
    assert length >= 1
    e = 1 << length
    s, r = imms & (e - 1), immr & (e - 1)
    assert s != e - 1
    mask = (1 << (s + 1)) - 1
    mask = ((mask >> r) | (mask << (e - r))) & ((1 << e) - 1)
    return sum(mask << i for i in range(0, 64, e))


LOGIC_NAMES = ("and", "orr", "eor", "ands")

# Logical immediates, as N, immr and imms: one bit, a byte, all but the top
# bit, the top bit, a run across the top, and repeating patterns with
# elements of 2, 8 and 16 bits. Those of N = 1 need 64 bits.
LOGIC_IMMS = ((0, 0, 0), (0, 0, 7), (0, 0, 30), (0, 1, 0), (0, 28, 3),
              (0, 0, 0b111100), (0, 4, 0b110011), (0, 8, 0b100111),
              (1, 0, 0), (1, 0, 7), (1, 0, 62), (1, 1, 0), (1, 60, 3))

# The destination and source of a logical immediate form. 31 is XZR as
# the source and as ANDS's destination, and SP as the others'.
LOGIC_IMM_REGS = ((0, 1), (2, 2), (31, 1), (0, 31), (30, 29))


def logic_imm_cases():
    """ AND, ORR, EOR and ANDS of an immediate: every value of sf and opc,
    over LOGIC_IMMS and LOGIC_IMM_REGS. ORR and EOR of XZR are moves of the
    immediate, which have the constant's gadget, and AND and ANDS of XZR
    are TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for opc in range(4):
            for n, immr, imms in LOGIC_IMMS:
                if n > sf:
                    continue
                imm = logic_imm(n, immr, imms) & ((1 << width) - 1)
                for rd, rn in LOGIC_IMM_REGS:
                    name = (f"{LOGIC_NAMES[opc]} "
                            f"{reg_name(rd, width, opc != 3)}, "
                            f"{reg_name(rn, width)}, #{imm:#x}")
                    word = (sf << 31 | opc << 29 | 0b100100 << 23 | n << 22 |
                            immr << 16 | imms << 10 | rn << 5 | rd)
                    yield Case(name, word, a=rn if rn != 31 else -1)


# The destination and sources of a logical shifted-register form.
LOGIC_REGS = ((0, 1, 2), (0, 0, 0), (1, 1, 2), (0, 31, 2), (31, 1, 2),
              (0, 1, 31), (30, 29, 28), (30, 31, 28))


def logic_shift_cases():
    """ AND, ORR, EOR and ANDS of a shifted register, and BIC, ORN, EON and
    BICS: every value of sf, opc, N and the shift type, by amounts from 0
    to the most the width allows, over LOGIC_REGS. MOV and MVN, which are
    ORR and ORN of XZR and a register that is not shifted, have gadgets;
    the other forms that read XZR, and those that write it without S, are
    TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for opc in range(4):
            for n in (0, 1):
                mnemonic = (("bic", "orn", "eon", "bics")[opc] if n
                            else LOGIC_NAMES[opc])
                for st in range(4):
                    for sa in ((0, 3, width - 1) if st == 0 else
                               (3, width - 1)):
                        for regs in LOGIC_REGS:
                            rd, rn, rm = regs
                            name = (f"{mnemonic} {names3(regs, width)}, "
                                    f"{SHIFT_NAMES[st]} #{sa}")
                            word = (sf << 31 | opc << 29 | 0b01010 << 24 |
                                    st << 22 | n << 21 | rm << 16 |
                                    sa << 10 | rn << 5 | rd)
                            a, b = roles(rn, rm)
                            yield Case(name, word, a=a, b=b)


def move_wide_cases():
    """ MOVN, MOVZ and MOVK: every value of sf, opc and hw that is
    allocated, with three immediates, to two registers and XZR. MOVK
    keeps the rest of its register, which takes the values. Those to XZR
    are TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for opc, mnemonic in ((0, "movn"), (2, "movz"), (3, "movk")):
            for hw in range(4 if sf else 2):
                for imm in (0, 0xffff, 0x1234):
                    for rd in (0, 30, 31):
                        name = (f"{mnemonic} {reg_name(rd, width)}, "
                                f"#{imm:#x}, lsl #{hw * 16}")
                        word = (sf << 31 | opc << 29 | 0b100101 << 23 |
                                hw << 21 | imm << 5 | rd)
                        yield Case(name, word,
                                   a=rd if opc == 3 and rd != 31 else -1)


def pc_relative_cases():
    """ ADR and ADRP, with offsets of 0, a word each way and the furthest
    each way, to two registers and XZR, which is TCG's. """
    for op, mnemonic in ((0, "adr"), (1, "adrp")):
        for imm in (0, 4, -4, 0xfffff, -0x100000):
            for rd in (0, 30, 31):
                name = f"{mnemonic} {reg_name(rd, 64)}, {imm:+#x}"
                word = (op << 31 | (imm & 3) << 29 | 0b10000 << 24 |
                        ((imm >> 2) & 0x7ffff) << 5 | rd)
                yield Case(name, word, adr=rd if rd != 31 else -1,
                           page=bool(op))


# The destination and source of a form with one source.
REGS2 = ((0, 1), (2, 2), (0, 31), (31, 1), (30, 29))


def bitfield_pairs(width):
    """ immr and imms for a bitfield move at width: the extracts and the
    inserts, with each of their edges, and every alias: the extensions,
    and the shifts by 1, by 4 and by all but one bit. """
    top = width - 1
    pairs = [(0, 0), (0, 7), (0, 15), (0, top), (1, top), (top, top),
             (4, 11), (11, 4), (top, 0), (1, 0), (width - 4, top - 4),
             (0, top - 1), (top, top - 1), (4, top)]
    if width == 64:
        pairs += [(0, 31), (32, 63), (32, 31), (33, 0)]
    return pairs


def bitfield_cases():
    """ SBFM, BFM and UBFM: every value of sf and opc over
    bitfield_pairs() and REGS2. BFM keeps the rest of its destination,
    which takes the second value. Those that read or write XZR are TCG's.
    """
    for sf in (0, 1):
        width = 64 if sf else 32
        for opc, mnemonic in enumerate(("sbfm", "bfm", "ubfm")):
            for immr, imms in bitfield_pairs(width):
                for rd, rn in REGS2:
                    name = (f"{mnemonic} {reg_name(rd, width)}, "
                            f"{reg_name(rn, width)}, #{immr}, #{imms}")
                    word = (sf << 31 | opc << 29 | 0b100110 << 23 | sf << 22 |
                            immr << 16 | imms << 10 | rn << 5 | rd)
                    b = rd if opc == 1 and rd not in (31, rn) else -1
                    yield Case(name, word, a=rn if rn != 31 else -1, b=b)


# The destination and sources of EXTR, with the sources the same register,
# which makes it ROR, among them.
EXTR_REGS = ((0, 1, 2), (0, 1, 1), (0, 0, 0), (1, 1, 2), (2, 1, 2),
             (0, 31, 2), (0, 1, 31), (31, 1, 2), (30, 29, 28))


def extract_cases():
    """ EXTR: both values of sf, from bit 0, which is TCG's, bit 1, bit 13
    and the top bit, over EXTR_REGS. Those that read or write XZR are
    TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for imm in (0, 1, 13, width - 1):
            for regs in EXTR_REGS:
                rd, rn, rm = regs
                name = f"extr {names3(regs, width)}, #{imm}"
                word = (sf << 31 | 0b100111 << 23 | sf << 22 | rm << 16 |
                        imm << 10 | rn << 5 | rd)
                a, b = roles(rn, rm)
                yield Case(name, word, a=a, b=b)


def two_source_cases():
    """ UDIV, SDIV, LSLV, LSRV, ASRV and RORV: both values of sf over
    REGS3. The values divide by 0 and overflow the signed division. Those
    that read or write XZR are TCG's. """
    for opcode, mnemonic in ((0b000010, "udiv"), (0b000011, "sdiv"),
                             (0b001000, "lslv"), (0b001001, "lsrv"),
                             (0b001010, "asrv"), (0b001011, "rorv")):
        for sf in (0, 1):
            width = 64 if sf else 32
            for regs in REGS3:
                rd, rn, rm = regs
                name = f"{mnemonic} {names3(regs, width)}"
                word = (sf << 31 | 0b11010110 << 21 | rm << 16 |
                        opcode << 10 | rn << 5 | rd)
                a, b = roles(rn, rm)
                yield Case(name, word, a=a, b=b)


def one_source_cases():
    """ RBIT, REV16, REV32, REV64, CLZ and CLS: each value of sf that is
    allocated, over REGS2. Those that read or write XZR are TCG's. """
    for opcode, mnemonic in enumerate(("rbit", "rev16", "rev32", "rev64",
                                       "clz", "cls")):
        for sf in (0, 1):
            if mnemonic == "rev64" and not sf:
                continue
            width = 64 if sf else 32
            for rd, rn in REGS2:
                name = (f"{mnemonic} {reg_name(rd, width)}, "
                        f"{reg_name(rn, width)}")
                word = (sf << 31 | 1 << 30 | 0b11010110 << 21 |
                        opcode << 10 | rn << 5 | rd)
                yield Case(name, word, a=rn if rn != 31 else -1)


# The destination, the two registers multiplied and the one added to, with
# XZR as the last, which makes MUL and its like, among them.
REGS4 = ((0, 1, 2, 3), (0, 1, 2, 31), (0, 0, 0, 0), (1, 1, 2, 1),
         (0, 1, 1, 31), (0, 31, 2, 3), (0, 1, 31, 3), (31, 1, 2, 3),
         (30, 29, 28, 27))


def multiply_cases():
    """ MADD and MSUB at both widths, SMADDL, SMSUBL, UMADDL and UMSUBL,
    over REGS4, with the values in the registers multiplied and, once
    more, in the one added to; and SMULH and UMULH over REGS3. Those that
    read XZR to multiply, or write it, are TCG's. """
    for sf, op31, prefix, suffix in ((0, 0, "m", ""), (1, 0, "m", ""),
                                     (1, 1, "sm", "l"), (1, 5, "um", "l")):
        width = 64 if sf else 32
        for o0 in (0, 1):
            mnemonic = prefix + ("sub" if o0 else "add") + suffix
            for regs in REGS4:
                rd, rn, rm, ra = regs
                srcs = 32 if suffix else width
                name = (f"{mnemonic} {reg_name(rd, width)}, "
                        f"{reg_name(rn, srcs)}, {reg_name(rm, srcs)}, "
                        f"{reg_name(ra, width)}")
                word = (sf << 31 | 0b11011 << 24 | op31 << 21 | rm << 16 |
                        o0 << 15 | ra << 10 | rn << 5 | rd)
                a, b = roles(rn, rm)
                yield Case(name, word, a=a, b=b)
                if regs == REGS4[0]:
                    yield Case(name + " (addend)", word, a=ra, b=rn)
    for op31, mnemonic in ((2, "smulh"), (6, "umulh")):
        for regs in REGS3:
            rd, rn, rm = regs
            name = f"{mnemonic} {names3(regs, 64)}"
            word = (1 << 31 | 0b11011 << 24 | op31 << 21 | rm << 16 |
                    31 << 10 | rn << 5 | rd)
            a, b = roles(rn, rm)
            yield Case(name, word, a=a, b=b)


COND_NAMES = (*CONDS, "al", "nv")


def select_cases():
    """ CSEL, CSINC, CSINV and CSNEG: both values of sf, each condition,
    those that always hold among them, over registers with XZR in each
    place and as both sources, which makes CSET and CSETM. Those that
    always hold, and those with XZR in one place, are TCG's. """
    for inv, inc, mnemonic in ((0, 0, "csel"), (0, 1, "csinc"),
                               (1, 0, "csinv"), (1, 1, "csneg")):
        for sf in (0, 1):
            width = 64 if sf else 32
            for cond in range(16):
                for regs in ((0, 1, 2), (0, 31, 31), (0, 1, 31), (0, 31, 2),
                             (31, 1, 2), (0, 1, 1)):
                    rd, rn, rm = regs
                    name = (f"{mnemonic} {names3(regs, width)}, "
                            f"{COND_NAMES[cond]}")
                    word = (sf << 31 | inv << 30 | 0b011010100 << 21 |
                            rm << 16 | cond << 12 | inc << 10 | rn << 5 | rd)
                    a, b = roles(rn, rm)
                    yield Case(name, word, a=a, b=b, flags=True)


def compare_cases():
    """ CCMP and CCMN of an immediate and of a register: both values of sf,
    each condition, with NZCV for a condition that fails that differs from
    what the compare gives. Those that always hold, and those with XZR,
    are TCG's. """
    for op, mnemonic in ((0, "ccmn"), (1, "ccmp")):
        for sf in (0, 1):
            width = 64 if sf else 32
            for cond in range(16):
                for imm, rn, y, nzcv in ((1, 1, 31, 0x6), (1, 1, 0, 0x9),
                                         (1, 31, 1, 0x0), (0, 1, 2, 0x6),
                                         (0, 1, 2, 0x9), (0, 1, 1, 0xf),
                                         (0, 1, 31, 0x0), (0, 31, 2, 0x0)):
                    second = f"#{y}" if imm else reg_name(y, width)
                    name = (f"{mnemonic} {reg_name(rn, width)}, {second}, "
                            f"#{nzcv:#x}, {COND_NAMES[cond]}")
                    word = (sf << 31 | op << 30 | 1 << 29 | 0b11010010 << 21 |
                            y << 16 | cond << 12 | imm << 11 | rn << 5 | nzcv)
                    a, b = (rn if rn != 31 else -1, -1) if imm else \
                        roles(rn, y)
                    yield Case(name, word, a=a, b=b, flags=True)


def b_cond(cond):
    """ B.cond over the next instruction. """
    return 0x54000000 | 2 << 5 | cond


def setter_cases():
    """ An instruction for each kind of FUSED_SETTERS at each width, as its
    name, its encoding and the registers that take the values. """
    for kind in FUSED_SETTERS:
        for sf in (0, 1):
            width = 64 if sf else 32
            r0, r1, r2 = (reg_name(n, width) for n in range(3))
            if kind in ("cmp_i", "cmn_i", "subs_i"):
                op = kind != "cmn_i"
                rd, imm = (0, 1) if kind == "subs_i" else (31, 0x80)
                name = (f"subs {r0}, {r1}, #{imm:#x}" if kind == "subs_i"
                        else f"{kind[:3]} {r1}, #{imm:#x}")
                yield name, (sf << 31 | op << 30 | 1 << 29 | 0b100010 << 23 |
                             imm << 10 | 1 << 5 | rd), 1, -1
            elif kind == "cmp_r":
                yield f"cmp {r1}, {r2}", (sf << 31 | 3 << 29 | 0b01011 << 24 |
                                          2 << 16 | 1 << 5 | 31), 1, 2
            elif kind == "ands_i_only":
                # The top bit: N is sf, immr 1 and imms 0.
                yield (f"tst {r1}, #{1 << (width - 1):#x}",
                       sf << 31 | 3 << 29 | 0b100100 << 23 | sf << 22 |
                       1 << 16 | 1 << 5 | 31, 1, -1)
            else:
                assert kind == "ands_r_only"
                yield f"tst {r1}, {r2}", (sf << 31 | 3 << 29 | 0b01010 << 24 |
                                          2 << 16 | 1 << 5 | 31), 1, 2


def branch_cases():
    """ The cases that branch, each over an instruction that marks the way
    it was not taken: B.cond for each condition from each value of NZCV,
    those that always hold among them, which are TCG's; CBZ and CBNZ at
    each width, and TBZ and TBNZ of the edge bits of each half, with XZR,
    which is TCG's; B.cond right after each kind of setter it can join,
    for each condition; and B.cond after instructions it cannot join: a
    compare that is no setter of FUSED_SETTERS, and one with an
    instruction between. """
    for cond in range(16):
        yield Case(f"b.{COND_NAMES[cond]} +8", b_cond(cond), more=(MARK,),
                   flags=True, branch=True)
    for sf in (0, 1):
        for nz in (0, 1):
            for rt in (1, 30, 31):
                yield Case(f"cb{'n' if nz else ''}z "
                           f"{reg_name(rt, 64 if sf else 32)}, +8",
                           sf << 31 | 0b011010 << 25 | nz << 24 | 2 << 5 | rt,
                           a=rt if rt != 31 else -1, more=(MARK,),
                           branch=True)
    for nz in (0, 1):
        for bit in (0, 1, 31, 32, 63):
            for rt in (1, 31):
                yield Case(f"tb{'n' if nz else ''}z "
                           f"{reg_name(rt, 64 if bit > 31 else 32)}, "
                           f"#{bit}, +8",
                           (bit >> 5) << 31 | 0b011011 << 25 | nz << 24 |
                           (bit & 31) << 19 | 2 << 5 | rt,
                           a=rt if rt != 31 else -1, more=(MARK,),
                           branch=True)
    for name, word, a, b in setter_cases():
        for cond in range(16):
            yield Case(f"{name}; b.{COND_NAMES[cond]} +8", word, a=a, b=b,
                       more=(b_cond(cond), MARK), branch=True)
    # CMP of a shifted register, ADDS of an immediate and ANDS that writes
    # a register have gadgets that B.cond does not join.
    for name, word in (("cmp x1, x2, lsl #1", 0xeb02043f),
                       ("adds x0, x1, #0x1", 0xb1000420),
                       ("ands x0, x1, x2", 0xea020020)):
        for cond in (0, 3, 8, 11):
            yield Case(f"{name}; b.{COND_NAMES[cond]} +8", word, a=1, b=2,
                       more=(b_cond(cond), MARK), branch=True)
    # CMP, then an instruction that leaves NZCV alone, then B.cond.
    for cond in (1, 2, 12):
        yield Case(f"cmp x1, x2; b.{COND_NAMES[cond]} +8 (after mov x3, x4)",
                   0xeb02003f, a=1, b=2, more=(0xaa0403e3, b_cond(cond)),
                   branch=True)


def insn_cases():
    """ The cases of rcg-insns. """
    yield from addsub_imm_cases()
    yield from addsub_shift_cases()
    yield from addsub_extend_cases()
    yield from carry_cases()
    yield from logic_imm_cases()
    yield from logic_shift_cases()
    yield from move_wide_cases()
    yield from pc_relative_cases()
    yield from bitfield_cases()
    yield from extract_cases()
    yield from two_source_cases()
    yield from one_source_cases()
    yield from multiply_cases()
    yield from select_cases()
    yield from compare_cases()
    yield from branch_cases()


def write_cases(cases, out, prefix):
    """ A table of the cases, of rcg-test.h's struct rcg_case (see
    rcg_core.write_cases()). A case needs no function of its own: the test
    patches its instruction into the one that runs them all. """
    def define(name, c):
        return ()

    def row(name, c):
        words = ", ".join(f"{word:#010x}" for word in c.words)
        return (f'"{c.name}", {{ {words} }}, {c.a}, {c.b}, {c.adr}, '
                f'{int(c.page)}, {int(c.flags)}')

    rcg_core.write_cases(cases, out, prefix, define, row)


def check_coverage(order, nm, traces):
    """ Checks that the tests' traces, from runs of QEMU's aarch64 system
    emulator, took every gadget, and that a B.cond right after a setter it
    can join took a fused gadget: see rcg_core.check_coverage(). No gadget
    reaches guest memory yet, so every one is wanted under either order.
    """
    # What a setter's B.cond would be called.
    setters = {spec.name: "b_" for spec in fused_setters()}
    return rcg_core.check_coverage(order, nm, traces, list(specs()), setters)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--insn-tests", metavar="FILE",
                        help="write rcg-insns.c's cases to FILE")
    parser.add_argument("--branch-tests", metavar="FILE",
                        help="write rcg-branch.c's cases to FILE")
    parser.add_argument("--check", action="store_true",
                        help="render every gadget's body and check it")
    parser.add_argument("--gadgets", metavar="DIR",
                        help="write the gadgets for TCTI, their table and "
                             "a64-rcg.decode to DIR")
    parser.add_argument("--coverage", nargs="+", metavar="ARG",
                        help="ORDER NM TRACE...: check that the traces "
                             "took every gadget for ORDER (ordered or "
                             "plain)")
    args = parser.parse_args()
    if not (args.insn_tests or args.branch_tests or args.check or
            args.gadgets or args.coverage):
        parser.error("nothing to do")
    if args.coverage and (len(args.coverage) < 3 or
                          args.coverage[0] not in ("ordered", "plain")):
        parser.error("--coverage takes ordered|plain NM TRACE...")

    if args.check:
        check()
    if args.gadgets:
        write_gadgets(args.gadgets)
    if args.insn_tests:
        with open(args.insn_tests, "w") as out:
            write_cases(insn_cases(), out, "rcg_insn_")
    if args.branch_tests:
        with open(args.branch_tests, "w") as out:
            write_cases((c for c in insn_cases() if c.branch), out,
                        "rcg_insn_")
    if args.coverage:
        order, nm, *traces = args.coverage
        if not check_coverage(order, nm, traces):
            sys.exit(1)


if __name__ == "__main__":
    main()
