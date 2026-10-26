# SPDX-License-Identifier: MIT
# Copyright (c) 2021 Kate Temkin
""" Guest-memory templates for gadgets on AArch64.

A gadget that accesses guest memory looks the address up in the softmmu TLB
itself (the fast path) and calls cputlb's helpers when that fails (the slow
path). TCTI's qemu_ld and qemu_st gadgets, but for its 128-bit ones, and
RCG's gadgets are built from the templates here, so that the lookup, the
helper calls and the ordering are the same in all of them. A load or store
and its ordered twin come from the same template, so their barriers cannot
drift apart.

Registers are parameters. The defaults are TCTI's convention: env in x14,
the call stack in x15, the stream pointer in x28, and x24, x26 and x27 free
for the templates to use (TMP).
"""

import re

# The MMU indices TCTI makes TLB fast-path gadgets for. Each such gadget
# loads its CPUTLBDescFast from a fixed offset from env, and that offset
# depends on the MMU index and on the layout of CPUNegativeOffsetState, so the
# offset is computed by the C compiler (TCTI_TLB_FAST_OFS, in
# tcti-gadget-defs.h) rather than written down here. An access to any other
# index takes the slow path.
#
# 0-5 are x86's kernel, user and no-SMAP modes, in 64- and 32-bit flavors:
# everything generated code uses. This must match TCTI_TLB_FAST_MMU_INDICES in
# tcti-gadget-defs.h.
QEMU_TLB_FAST_MMU_INDICES = range(6)

# The registers the templates clobber, in the order the tmp parameters take
# them. A fast path leaves the TLB addend in the second; a load's slow path
# leaves the value loaded there.
TMP = ("x26", "x27", "x24")

# The registers a slow path passes a helper's arguments in.
ARG_REGS = ("x0", "x1", "x2", "x3", "x4")


# Assembly code for saving our machine state before entering the C runtime.
C_CALL_PROLOGUE = [
    "stp x14, x15, [sp, #-16]!",
    "stp x28, lr,  [sp, #-16]!",
]

# Assembly code for restoring our machine state after leaving the C runtime.
C_CALL_EPILOGUE = [
    "ldp x28, lr,  [sp], #16",
    "ldp x14, x15, [sp], #16",
]


def _x(reg):
    """ The x name of a register given as xN or wN. """
    return "x" + reg[1:] if reg[0] in "wW" else reg


def _reads(line):
    """ The x names of the registers a line of assembly names. """
    return {"x" + n for n in re.findall(r"\b[xw](\d+)\b", line)}


def create_tlb_fastpath(is_write, miss_label="0", size=None, align=None,
                        addr="Xn", env="x14", tmp=TMP, tlb=None,
                        cmp_operand="tlb_cmp"):
    """ The lines of a softmmu TLB lookup of addr, for a gadget's fast path,
    which skips the call into the C runtime when the guest page is in the
    TLB.

    On a hit, the second register of tmp holds the TLB entry's addend, which
    added to the guest address gives the host address. On a miss, it
    branches to miss_label, where the slow path is.

    align, if given, is the alignment in bytes the access must have. An
    address without it also misses, and the helper raises the fault. An
    access no larger than align cannot cross a page, so size must then be no
    more than align. Without align, a hit needs all size bytes from addr to
    be on the page; size defaults to 8, which covers every access up to 8
    bytes.

    QEMU's constants, the TLB's layout among them, are the gadget's asm
    operands, which tlb_operands() gives for the same is_write and align.
    The comparator's operand is named cmp_operand. tlb, if given, is a
    register that holds the offset from env of the CPUTLBDescFast to use, in
    place of the tlb_ofs operand.

    Clobbers the three registers of tmp. addr and env must be none of them.
    """

    t, out, page = tmp
    assert align is None or size is None or size <= align, (size, align)
    assert _x(addr) not in tmp and env not in tmp, (addr, env, tmp)
    size = size or 8

    if tlb:
        lookup = [f"add {out}, {env}, {tlb}", f"ldp {t}, {out}, [{out}]"]
    else:
        lookup = [f"ldp {t}, {out}, [{env}, %[tlb_ofs]]"]

    fast_path = [
        # Load env_tlb(env)->f[mmu_idx].{mask,table} into {t,out}, from
        # tlb_ofs or from the register tlb.
        *lookup,

        # Extract the TLB index from the address into t.
        f"and {t}, {t}, {addr}, lsr %[tlb_shift]",

        # Add the tlb_table pointer, creating the CPUTLBEntry address into out.
        f"add {out}, {out}, {t}",

        # Load the tlb comparator into t, and the fast path addend into out.
        f"ldr {t}, [{out}, %[{cmp_operand}]]",
        f"ldr {out}, [{out}, %[tlb_addend]]",

    ]

    if align:
        fast_path.extend([
            # Keep the page part of the address, and the bits below the
            # alignment, which must be clear for a hit.
            f"and {page}, {addr}, %[tlb_page_mask]",

            # Compare the masked address with the TLB value.
            f"cmp {t}, {page}",

            # If they differ, this is a miss: go to the slow path.
            f"b.ne {miss_label}f",
        ])
    else:
        fast_path.extend([
            # Take the page of the access's last byte, so that an access
            # that crosses into the next page misses.
            f"add {page}, {addr}, #{size - 1}",
            f"and {page}, {page}, %[tlb_page_mask]",

            # Compare the masked address with the TLB value.
            f"cmp {t}, {page}",

            # If they differ, this is a miss: go to the slow path.
            f"b.ne {miss_label}f",
        ])

    return fast_path


def tlb_operands(mmu_idx, is_write, align=None, cmp_operand="tlb_cmp"):
    """ The asm operand list for a fast-path gadget serving mmu_idx, with the
    is_write, align and cmp_operand its create_tlb_fastpath() was given. The
    C compiler works each value out from QEMU's definitions. """
    comparator = "addr_write" if is_write else "addr_read"
    page_mask = "TCTI_TLB_PAGE_MASK"
    if (align or 1) > 1:
        page_mask += f" | {align - 1}"
    return ", ".join([
        f'[tlb_ofs] "i" (TCTI_TLB_FAST_OFS({mmu_idx}))',
        '[tlb_shift] "i" (TCTI_TLB_INDEX_SHIFT)',
        f'[{cmp_operand}] "i" (offsetof(CPUTLBEntry, {comparator}))',
        '[tlb_addend] "i" (offsetof(CPUTLBEntry, addend))',
        f'[tlb_page_mask] "i" ({page_mask})',
    ])


def granule_check(size, align=None, addr="Xn", tmp="x26", miss_label="0"):
    """ For an ordered access of size bytes, with the alignment align
    already checked if given: branches to the slow path if it crosses a
    16-byte boundary, where an LDAPR or STLR faults even with LSE2. That is,
    if (addr & 15) > 16 - size. """
    if size == 1 or (align or 1) >= size:
        return []
    return [
        f"and {tmp}, {addr}, #15",
        f"cmp {tmp}, #{16 - size}",
        f"b.hi {miss_label}f",
    ]


def load_fast_path(access, addr="Xn", align=None, ordered=None,
                   miss_label="0", env="x14", tmp=TMP, tlb=None,
                   cmp_operand="tlb_cmp", size=None):
    """ The fast path of a guest load: looks addr up in the TLB, as
    create_tlb_fastpath() does with align, branching to miss_label on a
    miss, then runs access, the load itself, which finds the host address as
    [addr, out] (out being the second of tmp, which holds the addend).

    ordered, if given, is the access size in bytes, for the twin that keeps
    the guest's memory order: access then loads from [out] (the host address)
    with LDAPR, after a check that the access does not cross a 16-byte
    boundary unless align says it cannot. tlb, cmp_operand and size are as
    for create_tlb_fastpath(). Clobbers tmp.
    """

    t, out, _ = tmp
    return [
        # Look the address up: a miss goes to miss_label, and a hit leaves
        # the TLB addend in out.
        *create_tlb_fastpath(is_write=False, size=size, align=align, addr=addr,
                             miss_label=miss_label, env=env, tmp=tmp,
                             tlb=tlb, cmp_operand=cmp_operand),
        # LDAPR is FEAT_LRCPC (ARMv8.3), past what we may be built for.
        *(granule_check(ordered, align, addr=addr, tmp=t, miss_label=miss_label)
          + [f"add {out}, {out}, {addr}", ".arch_extension rcpc"]
          if ordered else []),

        # On a hit, the load itself.
        *access,
    ]


def _check_slow_path(oi, addr, env, retaddr, tmp, restore, nb_args,
                     value=None):
    """ Asserts that a slow path's registers do not overwrite each other:
    tmp must not be a helper argument register, addr must not be out, env
    must not be in tmp, and oi must read neither an argument register nor
    one of tmp, which the fast path and the slow path's first moves set
    before it is read; retaddr must be neither. A store's value must not be
    in tmp either, and a load's value must survive restore. Placeholders
    such as TCTI's Xn name no register, so they are not checked. """
    args = set(ARG_REGS[:nb_args])
    oi_reads = _reads(oi.format(""))
    assert not args & set(tmp), tmp
    assert _x(addr) != tmp[1], (addr, tmp)
    assert env not in tmp, (env, tmp)
    assert not oi_reads & args and not oi_reads & set(tmp), oi
    assert retaddr not in args and retaddr not in tmp, retaddr
    assert value is None or _x(value) not in tmp, (value, tmp)
    assert not any(tmp[1] in _reads(line) for line in restore), restore


def load_slow_path(helper, oi, addr="Xn", ordered=None, miss_label="0",
                   env="x14", retaddr="x28", tmp=TMP,
                   save=C_CALL_PROLOGUE, restore=C_CALL_EPILOGUE):
    """ The slow path of a guest load, from miss_label: calls helper, a
    cputlb load helper, and leaves the value in out (the second of tmp).
    When ordered, it orders the helper's plain load before what follows, as
    an LDAPR would.

    oi is the line that puts the MemOpIdx in a register, with {} for it.
    retaddr is the return address the helper unwinds from. save and restore
    keep what the gadget needs across the helper's call, which clobbers
    every register a C call may; restore must not reload out.
    """

    _, out, _ = tmp
    _check_slow_path(oi, addr, env, retaddr, tmp, restore, 3)
    return [
        f"{miss_label}:",
            f"mov {out}, {addr}",

            # Save our registers in preparation for entering a C call.
            *save,

            # The helper's arguments: env, the guest address (copied to out
            # above), the MemOpIdx and the return address.
            f"mov   x0, {env}",
            f"mov   x1, {out}",
            oi.format("x2"),
            f"mov   x3, {retaddr}",

            f"bl _{helper}",

            # Move the value out of x0, which restore may reload.
            f"mov {out}, x0",

            # Restore our registers after our C call.
            *restore,
            *(["dmb ishld"] if ordered else []),
    ]


def load(access, helper, oi, addr="Xn", align=None, ordered=None, fast=True,
         on_hit=(), env="x14", retaddr="x28", tmp=TMP,
         save=C_CALL_PROLOGUE, restore=C_CALL_EPILOGUE, size=None):
    """ A guest load: the fast path (if fast), then on_hit, which must leave
    the gadget, then the slow path at label 0. The other arguments are as
    for load_fast_path() and load_slow_path(); the rest of theirs take their
    defaults. """

    fast_path = (load_fast_path(access, addr, align, ordered, env=env, tmp=tmp,
                                size=size)
                 if fast else [])
    return [
        *fast_path,
        *(on_hit if fast else []),
        *load_slow_path(helper, oi, addr, ordered, env=env, retaddr=retaddr,
                        tmp=tmp, save=save, restore=restore),
    ]


def store_fast_path(access, addr="Xn", align=None, ordered=None,
                    miss_label="0", env="x14", tmp=TMP, tlb=None,
                    cmp_operand="tlb_cmp", size=None):
    """ The fast path of a guest store: as load_fast_path(), with STLR when
    ordered. """

    t, out, _ = tmp
    return [

        # Look the address up: a miss goes to miss_label, and a hit leaves
        # the TLB addend in out.
        *create_tlb_fastpath(is_write=True, size=size, align=align, addr=addr,
                             miss_label=miss_label, env=env, tmp=tmp,
                             tlb=tlb, cmp_operand=cmp_operand),
        *(granule_check(ordered, align, addr=addr, tmp=t, miss_label=miss_label)
          + [f"add {out}, {out}, {addr}"] if ordered else []),

        # On a hit, the store itself.
        *access,
    ]


def store_slow_path(helper, oi, value, addr="Xn", ordered=None,
                    miss_label="0", env="x14", retaddr="x28", tmp=TMP,
                    save=C_CALL_PROLOGUE, restore=C_CALL_EPILOGUE):
    """ The slow path of a guest store of the register value, from
    miss_label: as load_slow_path(), with a cputlb store helper. It produces
    no value.

    When ordered, a DMB ISHST orders the helper's plain store after earlier
    stores, as an STLR would be. The helper orders it after earlier loads as
    well: cputlb puts a full barrier before each store it makes for a guest
    whose memory order needs one (cpu_req_mo()).
    """

    t, out, _ = tmp
    out_value = ("w" if value[0] in "Ww" else "x") + out[1:]
    _check_slow_path(oi, addr, env, retaddr, tmp, [], 5, value)
    return [
        f"{miss_label}:",
            # Move the value and the address out of the way of the helper's
            # arguments, as either may be in x0-x4.
            f"mov {out_value}, {value}",
            f"mov {t}, {addr}",

            # Save our registers in preparation for entering a C call.
            *save,

            # The helper's arguments: env, the guest address (in t), the
            # value (in out), the MemOpIdx and the return address.
            f"mov   x0, {env}",
            f"mov   x1, {t}",
            f"mov   x2, {out}",
            oi.format("x3"),
            f"mov   x4, {retaddr}",
            *(["dmb ishst"] if ordered else []),

            f"bl _{helper}",

            # Restore our registers after our C call.
            *restore,
    ]


def store(access, helper, oi, value, addr="Xn", align=None, ordered=None,
          fast=True, on_hit=(), env="x14", retaddr="x28", tmp=TMP,
          save=C_CALL_PROLOGUE, restore=C_CALL_EPILOGUE, size=None):
    """ A guest store of the register value; otherwise as load(). """

    fast_path = (store_fast_path(access, addr, align, ordered, env=env,
                                 tmp=tmp, size=size)
                 if fast else [])
    return [
        *fast_path,
        *(on_hit if fast else []),
        *store_slow_path(helper, oi, value, addr, ordered, env=env,
                         retaddr=retaddr, tmp=tmp, save=save, restore=restore),
    ]
