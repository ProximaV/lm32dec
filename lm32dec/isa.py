"""
LatticeMico32 (LM32) instruction-set description.

Fixed 32-bit instructions (4-byte aligned).
Dual-endian (big-endian native, little-endian in PS Vita coprocessor firmware).

32 General-Purpose Registers (r0..r31), with r0 hardwired to 0.
32 Control and Status Registers (CSRs).
"""

# General Purpose Registers (GPRs), index 0..31
REG = (
    "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
    "r24", "r25", "gp",  "fp",  "sp",  "ra",  "ea",  "ba",
)

# Control and Status Registers (CSRs), index 0..31
CSR = (
    "IE",     "IM",     "IP",     "ICC",    "DCC",    "CC",     "CFG",    "EBA",
    "DC",     "DEBA",   "CFG2",   "CSR_B",  "CSR_C",  "CSR_D",  "JTX",    "JRX",
    "BP0",    "BP1",    "BP2",    "BP3",    "CSR_14", "CSR_15", "CSR_16", "CSR_17",
    "WP0",    "WP1",    "WP2",    "WP3",    "CSR_1C", "PSW",    "TLBVAD", "TLBPAD",
)

# ABI registers
GP = "gp"  # r26
FP = "fp"  # r27
SP = "sp"  # r28
RA = "ra"  # r29
EA = "ea"  # r30
BA = "ba"  # r31

# Function arguments and return registers
ARG_REGS = tuple(f"r{i}" for i in range(1, 9))      # r1..r8 (up to 8 argument registers)
RET_REGS = ("r1", "r2")                              # r1 (32-bit), r1:r2 (64-bit)

CALLER_SAVED = frozenset(
    tuple(f"r{i}" for i in range(1, 11)) + (RA, EA, BA)
)  # r1..r10, ra, ea, ba

CALLEE_SAVED = frozenset(
    tuple(f"r{i}" for i in range(11, 26)) + (GP, FP, SP)
)  # r11..r25, gp, fp, sp


def reg(i):
    """Return register name for index 0..31."""
    return REG[i & 0x1F]


def csr(i):
    """Return control/status register name for index 0..31."""
    return CSR[i & 0x1F]


# --- control-flow classification -------------------------------------------

COND_BRANCH = frozenset(("be", "bne", "bg", "bge", "bgu", "bgeu"))
CALL = frozenset(("call", "calli"))
RET = frozenset(("ret", "eret", "bret"))
UNCOND = frozenset(("bi", "b"))
STOP = frozenset(("ret", "eret", "bret", "bi", "b", "scall", "break", "raise"))
