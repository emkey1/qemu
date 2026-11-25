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
    rcg-gen.py --check
    rcg-gen.py --gadgets DIR
    rcg-gen.py --coverage ordered|plain NM TRACE...

There are gadgets for ADD, ADDS, SUB and SUBS of an immediate and of a
shifted register. Everything else is left to TCG.
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
from rcg_core import w  # noqa: E402


#
# The guest's side: registers, widths and words.
#

# A register is an operand word: the env offset of its xregs[] slot. Slot 31
# is SP, which only the forms that take SP name. Where register 31 is XZR
# there is no word: a form that reads it has a variant that reads zero, and
# one that writes it has a variant that writes nothing (FLAGS, ZEROS).
WIDTHS = (32, 64)

# The operand words, in the translator's order: the destination register,
# the first and second source registers, an immediate, and a shift amount.
WORD_NAMES = ("d", "n", "m", "imm", "sa")

# The operand words that always fit in 32 bits, signed: env offsets and
# shift amounts. imm may not.
NARROW_WORDS = ("d", "n", "m", "sa")

# What an instruction does with NZCV and its result: neither S nor a
# compare ("none"), an S form ("set"), or an S form with XZR as its
# destination, which writes only NZCV ("only": CMP and CMN).
FLAGS = ("none", "set", "only")

# How a shifted-register form shifts its second source: not at all, which
# is any shift by 0, or by the "sa" word.
SHIFTS = ("none", "lsl", "lsr", "asr")

# Which source of a shifted-register form is XZR: neither, the first
# ("n": NEG and NEGS) or the second ("m"), which no shift changes.
ZEROS = ("none", "n", "m")

# The patterns of a64.decode that a64-rcg.decode copies, each with the
# translator's trans_rcg_<name>().
PATTERNS = ("ADD_i", "ADDS_i", "SUB_i", "SUBS_i",
            "ADD_r", "ADDS_r", "SUB_r", "SUBS_r")

# The translator's tables of gadgets, by kind: each index's name and the
# values it takes, a number of them or the tuple that names them.
TABLES = {
    "addsub_i": (("sub", 2), ("sf", 2), ("flags", FLAGS)),
    "addsub_r": (("sub", 2), ("sf", 2), ("flags", FLAGS),
                 ("shift", SHIFTS), ("zero", ZEROS)),
}

# The tuples that become enums in the table, with their prefixes.
ENUMS = (("FLAGS", FLAGS), ("SHIFT", SHIFTS), ("ZERO", ZEROS))


class Spec:
    """ One gadget: ADD or SUB (sub) of an immediate (kind addsub_i) or of
    a shifted register (addsub_r), at 32 or 64 bits (width), with what it
    does with NZCV and its result (flags), and for a register form its
    shift and which source is XZR (zero). """

    ordered = False
    accesses_memory = False
    has_table = False

    def __init__(self, kind, sub, width, flags, shift="none", zero="none"):
        self.kind = kind
        self.sub = sub
        self.width = width
        self.flags = flags
        self.shift = shift
        self.zero = zero

    @property
    def mnemonic(self):
        """ The A64 mnemonic, with CMP and CMN for the forms that write
        only NZCV. """
        if self.flags == "only":
            return "cmp" if self.sub else "cmn"
        return ("sub" if self.sub else "add") + \
            ("s" if self.flags == "set" else "")

    @property
    def name(self):
        if self.kind == "addsub_i":
            form = "i"
        else:
            form = "r" if self.shift == "none" else self.shift
            if self.zero != "none":
                form += "_z" + self.zero
        return f"{self.mnemonic}_{form}_{self.width}"

    @property
    def words(self):
        """ The gadget's operand words, in the translator's order. """
        words = [] if self.flags == "only" else ["d"]
        if self.kind == "addsub_i":
            return words + ["n", "imm"]
        if self.zero != "n":
            words.append("n")
        if self.zero != "m":
            words.append("m")
        if self.shift != "none":
            words.append("sa")
        return words

    @property
    def stream(self):
        """ The stream words, from rcg_core.stream_words(). """
        return rcg_core.stream_words(self.words, NARROW_WORDS)

    @property
    def index(self):
        """ Where the gadget is in its kind's table: a value for each index
        of TABLES. """
        index = [int(self.sub), WIDTHS.index(self.width),
                 FLAGS.index(self.flags)]
        if self.kind == "addsub_r":
            index += [SHIFTS.index(self.shift), ZEROS.index(self.zero)]
        return index


def specs():
    """ Every gadget. A shifted XZR is still zero, so the second source is
    XZR only without a shift, and a form with both sources XZR is left to
    TCG. """
    for sub in (False, True):
        for width in WIDTHS:
            for flags in FLAGS:
                yield Spec("addsub_i", sub, width, flags)
                for shift in SHIFTS:
                    for zero in ZEROS:
                        if zero == "m" and shift != "none":
                            continue
                        yield Spec("addsub_r", sub, width, flags, shift, zero)


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
        """ The guest's NZCV from the host's, as the ADDS or SUBS before
        this left them. env holds each flag in a 32-bit field of which only
        this much means anything: bit 31 of NF and VF, whether ZF is 0,
        which says that Z is set, and CF, 0 or 1. So NF is the host's NZCV
        itself, whose bit 31 is N, VF is that shifted to put V there, and
        ZF and CF are CSETs. The fields are together in env, CF first. It
        uses ADDR, A, B and T. """
        self.emit(f"mrs {T}, nzcv",
                  f"cset {w(A)}, cs",
                  f"lsl {w(B)}, {w(T)}, #3",
                  f"cset {w(ADDR)}, ne",
                  f"add {R}, {self.env}, %[cf]",
                  f"stp {w(A)}, {w(B)}, [{R}]",
                  f"stp {w(T)}, {w(ADDR)}, [{R}, #8]")


def reg(x, width):
    """ The view of x register x that a body at width computes in. """
    return x if width == 64 else w(x)


def addsub_body(g, spec):
    """ ADD, ADDS, SUB and SUBS, CMN and CMP among them: the host's own
    instruction on the two sources, at the guest's width. At 32 bits the
    host's W form leaves the upper half of its result zero and sets NZCV
    from the low half, both as the guest's does. A shift is the host's
    variable one, which takes its amount modulo the width, as the
    translator requires it to be below the width already. """
    width = spec.width
    a, b, r = reg(A, width), reg(B, width), reg(R, width)
    if spec.kind == "addsub_i":
        g.read_reg(A, "n")
        b = reg(g.word("imm"), width)
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
    if spec.flags != "only":
        g.write_reg(R, "d")
    if spec.flags != "none":
        g.write_nzcv()


BODIES = {
    "addsub_i": addsub_body,
    "addsub_r": addsub_body,
}

# The "i" asm operands the bodies use, which the C compiler works out from
# QEMU's definitions: rcg_core's, though no body here reaches guest memory
# yet, then those the bodies use directly.
BODY_OPERANDS = {
    **rcg_core.MEMORY_OPERANDS,
    **rcg_core.HARNESS_OPERANDS,
    "cf": "offsetof(CPUARMState, CF)",
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
            wanted.update(toks[1:])
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
        place = (spec.kind, *spec.index)
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

# The gadget source files, split so they compile in parallel.
# Must match target/arm/tcg/meson.build.
GADGET_FILES = ("add", "sub")


def gadget_file(spec):
    return "sub" if spec.sub else "add"


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
    for kind, indices in TABLES.items():
        p(f"/* Indexed by {', '.join(name for name, _ in indices)}. */")
        dims = "".join(f"[{n}]" if isinstance(n, int)
                       else f"[{len(n)}]" for _, n in indices)
        p(f"static const RCGGadget rcg_{kind}{dims} = {{")
        for spec in all_specs:
            if spec.kind == kind:
                place = "".join(f"[{i}]" for i in spec.index)
                words = ", ".join(f"RCG_W_{w.upper()}" for w in spec.words)
                p(f"    {place} = {{ rcg_gadget_{spec.name}, {{ {words} }} }},")
        p("};\n")


def write_gadgets(outdir):
    """ Writes the gadgets, in TCTI's harness, as naked functions, their
    table and the translator's decoder to outdir. """
    harness = TctiHarness()
    all_specs = list(specs())
    instructions = rcg_core.write_gadgets(
        outdir, GADGET_FILES, ("cpu.h",), BODY_OPERANDS,
        ((gadget_file(spec), spec.name, body(spec, harness))
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

class Case:
    """ One test case: an instruction, as its encoding (word) and what to
    call it (name), and the registers that take the values tested, a and
    b, of which 31 is SP; -1 for none. """

    def __init__(self, name, word, a=-1, b=-1):
        self.name = name
        self.word = word
        self.a = a
        self.b = b


def reg_name(n, width, sp):
    """ Register n at width as an instruction names it, with 31 as SP if sp
    and else as XZR. """
    if n == 31:
        return {(64, True): "sp", (32, True): "wsp",
                (64, False): "xzr", (32, False): "wzr"}[width, sp]
    return ("x" if width == 64 else "w") + str(n)


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


# The destination and sources of a shifted-register form, with 31, which is
# XZR, in each place, and registers repeated.
SHIFT_REGS = ((0, 1, 2), (0, 0, 0), (1, 1, 2), (2, 1, 2), (0, 1, 31),
              (0, 31, 2), (31, 1, 2), (31, 31, 2), (31, 1, 31), (0, 31, 31),
              (30, 29, 28))


def addsub_shift_cases():
    """ ADD, ADDS, SUB and SUBS of a shifted register: every value of sf,
    op, S and the shift type that is allocated (ROR is not), by amounts
    from 0 to the most the width allows, over SHIFT_REGS. Those that write
    XZR without S, and those with both sources XZR, are TCG's. """
    for sf in (0, 1):
        width = 64 if sf else 32
        for op in (0, 1):
            for s in (0, 1):
                for st, shift in enumerate(("lsl", "lsr", "asr")):
                    for sa in ((0, 1, width - 1) if st == 0 else
                               (0, 3, width - 1)):
                        for rd, rn, rm in SHIFT_REGS:
                            name = (f"{'sub' if op else 'add'}"
                                    f"{'s' if s else ''} "
                                    f"{reg_name(rd, width, False)}, "
                                    f"{reg_name(rn, width, False)}, "
                                    f"{reg_name(rm, width, False)}, "
                                    f"{shift} #{sa}")
                            word = (sf << 31 | op << 30 | s << 29 |
                                    0b01011 << 24 | st << 22 | rm << 16 |
                                    sa << 10 | rn << 5 | rd)
                            a = rn if rn != 31 else -1
                            b = rm if rm not in (31, rn) else -1
                            yield Case(name, word, a=a, b=b)


def insn_cases():
    """ The cases of rcg-insns. """
    yield from addsub_imm_cases()
    yield from addsub_shift_cases()


def write_cases(cases, out, prefix):
    """ A table of the cases, of rcg-test.h's struct rcg_case (see
    rcg_core.write_cases()). A case needs no function of its own: the test
    patches its instruction into the one that runs them all. """
    def define(name, c):
        return ()

    def row(name, c):
        return f'"{c.name}", {c.word:#010x}, {c.a}, {c.b}'

    rcg_core.write_cases(cases, out, prefix, define, row)


def check_coverage(order, nm, traces):
    """ Checks that the tests' traces, from runs of QEMU's aarch64 system
    emulator, took every gadget: see rcg_core.check_coverage(). No gadget
    reaches guest memory yet, so every one is wanted under either order,
    and none is joined to a branch. """
    return rcg_core.check_coverage(order, nm, traces, list(specs()), {})


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--insn-tests", metavar="FILE",
                        help="write rcg-insns.c's cases to FILE")
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
    if not (args.insn_tests or args.check or args.gadgets or args.coverage):
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
    if args.coverage:
        order, nm, *traces = args.coverage
        if not check_coverage(order, nm, traces):
            sys.exit(1)


if __name__ == "__main__":
    main()
