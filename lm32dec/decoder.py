"""
Standalone LatticeMico32 (LM32) decoder.

Fixed 32-bit instructions (4 bytes).
Dual-endian support: supports both Big-Endian (native LM32) and Little-Endian (PS Vita LM32).

Operand ``mode`` values:
    reg     register (``reg`` = 0..31 GPR, or CSR index 0..31)
    imm     immediate (``value``)
    near    code target (``addr``)
    displ   disp(reg) (``base_reg``, ``disp``, ``width``)
    phrase  (reg)     (``base_reg``, ``disp=0``, ``width``)
"""

from . import isa


def _sx(x, b):
    m = 1 << (b - 1)
    x &= (1 << b) - 1
    return (x ^ m) - m


class Operand:
    __slots__ = ("mode", "reg", "value", "addr", "base_reg", "disp", "width", "name")

    def __init__(self, mode, reg=0, value=0, addr=0, base_reg=0, disp=0, width=4, name=None):
        self.mode = mode
        self.reg = reg
        self.value = value
        self.addr = addr
        self.base_reg = base_reg
        self.disp = disp
        self.width = width
        self.name = name

    def __repr__(self):
        if self.mode == "reg":
            return f"reg({isa.reg(self.reg) if isinstance(self.reg, int) else self.reg})"
        if self.mode == "imm":
            return f"imm(0x{self.value:X})"
        if self.mode == "near":
            return f"near(0x{self.addr:X})"
        if self.mode in ("displ", "phrase"):
            return f"{self.mode}({isa.reg(self.base_reg)}+{self.disp}, w={self.width})"
        return f"Op({self.mode})"


class SwitchInfo:
    __slots__ = ("jmp_ea", "table_ea", "ncases", "lowcase", "default_ea",
                 "bounds_ea", "idx_reg", "cases", "targets", "setup_eas")

    def __init__(self, jmp_ea, table_ea, ncases, lowcase, default_ea,
                 bounds_ea, idx_reg, cases, targets, setup_eas):
        self.jmp_ea = jmp_ea
        self.table_ea = table_ea
        self.ncases = ncases
        self.lowcase = lowcase
        self.default_ea = default_ea
        self.bounds_ea = bounds_ea
        self.idx_reg = idx_reg
        self.cases = cases
        self.targets = targets
        self.setup_eas = setup_eas


class Insn:
    __slots__ = ("ea", "size", "mnem", "ops", "switch_info")

    def __init__(self, ea):
        self.ea = ea
        self.size = 4
        self.mnem = None
        self.ops = []
        self.switch_info = None

    def __repr__(self):
        op_strs = [str(o) for o in self.ops]
        return f"<Insn 0x{self.ea:08X} {self.mnem:<7} {', '.join(op_strs)}>"


def in_bounds(image, ea, base=0, size=4):
    if hasattr(image, "contains"):
        return image.contains(ea, size)
    off = ea - base
    return 0 <= off and off + size <= len(image)


def read_u32(image, ea, base=0, is_be=False):
    """Read a 32-bit unsigned integer with specified endianness."""
    if hasattr(image, "get_u32"):
        return image.get_u32(ea)
    off = ea - base
    if off < 0 or off + 4 > len(image):
        return None
    b0, b1, b2, b3 = image[off], image[off + 1], image[off + 2], image[off + 3]
    if is_be:
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    else:
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)


# Bitfield extraction
def f_opcode(w): return (w >> 26) & 0x3F
def f_r0(w): return (w >> 21) & 0x1F
def f_r1(w): return (w >> 16) & 0x1F
def f_r2(w): return (w >> 11) & 0x1F
def f_shift(w): return w & 0x1F
def f_imm16(w): return _sx(w & 0xFFFF, 16)
def f_uimm16(w): return w & 0xFFFF
def f_call26(w): return _sx(w & 0x03FFFFFF, 26)


def decode_one(image, ea, base=0, is_be=False):
    """Decode a single 32-bit LM32 instruction at ea."""
    word = read_u32(image, ea, base=base, is_be=is_be)
    if word is None:
        return None

    ins = Insn(ea)
    ins.size = 4
    opc = f_opcode(word)
    r0 = f_r0(word)
    r1 = f_r1(word)
    r2 = f_r2(word)
    imm16 = f_imm16(word)
    uimm16 = f_uimm16(word)
    shift = f_shift(word)
    call26 = f_call26(word)

    # Register operand constructors
    def reg_op(idx):
        return Operand("reg", reg=idx)

    def imm_op(val):
        return Operand("imm", value=val)

    def near_op(target):
        return Operand("near", addr=target & 0xFFFFFFFF)

    def displ_op(base_r, disp, width):
        mode = "phrase" if disp == 0 else "displ"
        return Operand(mode, base_reg=base_r, disp=disp, width=width)

    # 0x00 - 0x0F
    if opc == 0x00:
        ins.mnem = "srui"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(shift)]
    elif opc == 0x01:
        ins.mnem = "nori"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x02:
        ins.mnem = "muli"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(imm16)]
    elif opc == 0x03:
        ins.mnem = "sh"
        ins.ops = [displ_op(r0, imm16, width=2), reg_op(r1)]
    elif opc == 0x04:
        ins.mnem = "lb"
        ins.ops = [reg_op(r1), displ_op(r0, imm16, width=1)]
    elif opc == 0x05:
        ins.mnem = "sri"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(shift)]
    elif opc == 0x06:
        ins.mnem = "xori"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x07:
        ins.mnem = "lh"
        ins.ops = [reg_op(r1), displ_op(r0, imm16, width=2)]
    elif opc == 0x08:
        ins.mnem = "andi"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x09:
        ins.mnem = "xnori"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x0A:
        ins.mnem = "lw"
        ins.ops = [reg_op(r1), displ_op(r0, imm16, width=4)]
    elif opc == 0x0B:
        ins.mnem = "lhu"
        ins.ops = [reg_op(r1), displ_op(r0, imm16, width=2)]
    elif opc == 0x0C:
        ins.mnem = "sb"
        ins.ops = [displ_op(r0, imm16, width=1), reg_op(r1)]
    elif opc == 0x0D:
        if word == 0x34000000:
            ins.mnem = "nop"
            ins.ops = []
        elif r0 == 0:
            ins.mnem = "mvi"
            ins.ops = [reg_op(r1), imm_op(imm16)]
        else:
            ins.mnem = "addi"
            ins.ops = [reg_op(r1), reg_op(r0), imm_op(imm16)]
    elif opc == 0x0E:
        if r0 == 0:
            ins.mnem = "mvui"
            ins.ops = [reg_op(r1), imm_op(uimm16)]
        else:
            ins.mnem = "ori"
            ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x0F:
        ins.mnem = "sli"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(shift)]

    # 0x10 - 0x1F
    elif opc == 0x10:
        ins.mnem = "lbu"
        ins.ops = [reg_op(r1), displ_op(r0, imm16, width=1)]
    elif opc == 0x11:
        ins.mnem = "be"
        ins.ops = [reg_op(r0), reg_op(r1), near_op(ea + (imm16 << 2))]
    elif opc == 0x12:
        ins.mnem = "bg"
        ins.ops = [reg_op(r0), reg_op(r1), near_op(ea + (imm16 << 2))]
    elif opc == 0x13:
        ins.mnem = "bge"
        ins.ops = [reg_op(r0), reg_op(r1), near_op(ea + (imm16 << 2))]
    elif opc == 0x14:
        ins.mnem = "bgeu"
        ins.ops = [reg_op(r0), reg_op(r1), near_op(ea + (imm16 << 2))]
    elif opc == 0x15:
        ins.mnem = "bgu"
        ins.ops = [reg_op(r0), reg_op(r1), near_op(ea + (imm16 << 2))]
    elif opc == 0x16:
        ins.mnem = "sw"
        ins.ops = [displ_op(r0, imm16, width=4), reg_op(r1)]
    elif opc == 0x17:
        ins.mnem = "bne"
        ins.ops = [reg_op(r0), reg_op(r1), near_op(ea + (imm16 << 2))]
    elif opc == 0x18:
        ins.mnem = "andhi"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x19:
        ins.mnem = "cmpei"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(imm16)]
    elif opc == 0x1A:
        ins.mnem = "cmpgi"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(imm16)]
    elif opc == 0x1B:
        ins.mnem = "cmpgei"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(imm16)]
    elif opc == 0x1C:
        ins.mnem = "cmpgeui"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x1D:
        ins.mnem = "cmpgui"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x1E:
        if r0 == 0:
            ins.mnem = "mvhi"
            ins.ops = [reg_op(r1), imm_op(uimm16)]
        else:
            ins.mnem = "orhi"
            ins.ops = [reg_op(r1), reg_op(r0), imm_op(uimm16)]
    elif opc == 0x1F:
        ins.mnem = "cmpnei"
        ins.ops = [reg_op(r1), reg_op(r0), imm_op(imm16)]

    # 0x20 - 0x2F
    elif opc == 0x20:
        ins.mnem = "sru"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x21:
        ins.mnem = "nor"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x22:
        ins.mnem = "mul"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x23:
        ins.mnem = "divu"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x24:
        ins.mnem = "rcsr"
        # rcsr r1, csr(r0)
        ins.ops = [reg_op(r1), Operand("reg", reg=isa.csr(r0))]
    elif opc == 0x25:
        ins.mnem = "sr"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x26:
        ins.mnem = "xor"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x27:
        ins.mnem = "div"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x28:
        ins.mnem = "and"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x29:
        if r1 == 0:
            ins.mnem = "not"
            ins.ops = [reg_op(r2), reg_op(r0)]
        else:
            ins.mnem = "xnor"
            ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x2A:
        ins.mnem = "x_invalid"
        ins.ops = []
    elif opc == 0x2B:
        imm = word & 0x1F
        if imm == 2:
            ins.mnem = "break"
            ins.ops = []
        elif imm == 7:
            ins.mnem = "scall"
            ins.ops = []
        else:
            ins.mnem = "raise"
            ins.ops = [imm_op(imm)]
    elif opc == 0x2C:
        ins.mnem = "sextb"
        ins.ops = [reg_op(r2), reg_op(r0)]
    elif opc == 0x2D:
        ins.mnem = "add"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x2E:
        if r1 == 0:
            ins.mnem = "mv"
            ins.ops = [reg_op(r2), reg_op(r0)]
        else:
            ins.mnem = "or"
            ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x2F:
        ins.mnem = "sl"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]

    # 0x30 - 0x3F
    elif opc == 0x30:
        if r0 == 29:  # ra
            ins.mnem = "ret"
            ins.ops = []
        elif r0 == 30:  # ea
            ins.mnem = "eret"
            ins.ops = []
        elif r0 == 31:  # ba
            ins.mnem = "bret"
            ins.ops = []
        else:
            ins.mnem = "b"
            ins.ops = [reg_op(r0)]
    elif opc == 0x31:
        ins.mnem = "modu"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x32:
        ins.mnem = "sub"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x33:
        ins.mnem = "user"
        ins.ops = [imm_op(word & 0x7FF)]
    elif opc == 0x34:
        ins.mnem = "wcsr"
        # wcsr csr(r0), r1
        ins.ops = [Operand("reg", reg=isa.csr(r0)), reg_op(r1)]
    elif opc == 0x35:
        ins.mnem = "mod"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x36:
        ins.mnem = "call"
        ins.ops = [reg_op(r0)]
    elif opc == 0x37:
        ins.mnem = "sexth"
        ins.ops = [reg_op(r2), reg_op(r0)]
    elif opc == 0x38:
        ins.mnem = "bi"
        ins.ops = [near_op(ea + (call26 << 2))]
    elif opc == 0x39:
        ins.mnem = "cmpe"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x3A:
        ins.mnem = "cmpg"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x3B:
        ins.mnem = "cmpge"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x3C:
        ins.mnem = "cmpgeu"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x3D:
        ins.mnem = "cmpgu"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    elif opc == 0x3E:
        ins.mnem = "calli"
        ins.ops = [near_op(ea + (call26 << 2))]
    elif opc == 0x3F:
        ins.mnem = "cmpne"
        ins.ops = [reg_op(r2), reg_op(r0), reg_op(r1)]
    else:
        ins.mnem = "x_invalid"
        ins.ops = []

    return ins


def target_of(ins):
    """Return branch/call near target address if present, else None."""
    for op in ins.ops:
        if op.mode == "near":
            return op.addr
    return None


def decode(image, entries=(), base=0, is_be=False, stop_at=None):
    """Worklist-driven recursive decoder covering reachable code blocks."""
    insns = {}
    calls = set()
    work = list(entries)
    seen = set()

    stop_set = set(stop_at) if stop_at else set()

    while work:
        ea = work.pop()
        while ea not in insns:
            if stop_set and ea in stop_set:
                break
            if not in_bounds(image, ea, base=base, size=4):
                break
            ins = decode_one(image, ea, base=base, is_be=is_be)
            if ins is None:
                break
            insns[ea] = ins

            m = ins.mnem
            if m in isa.CALL:
                tgt = target_of(ins)
                if tgt is not None:
                    calls.add(tgt)
                ea += 4
            elif m in isa.COND_BRANCH:
                tgt = target_of(ins)
                if tgt is not None and tgt not in seen:
                    work.append(tgt)
                    seen.add(tgt)
                ea += 4
            elif m in ("bi",):
                tgt = target_of(ins)
                if tgt is not None and tgt not in seen:
                    work.append(tgt)
                    seen.add(tgt)
                break
            elif m in isa.STOP:
                break
            else:
                ea += 4

    return insns, calls
