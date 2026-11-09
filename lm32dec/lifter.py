"""
Lift decoded LM32 :class:`~lm32dec.decoder.Insn` objects into 3-address IR statements.

Translates LM32 machine instructions into high-level IR:
- Register r0 reads evaluate to ir.Const(0). Writes to r0 are dead assignments.
- Direct 2-register relational compares in conditional branches (be, bne, bg, bge, bgu, bgeu).
- Condition setting instructions (cmpe, cmpg, cmpge, cmpgu, cmpgeu, cmpne, and immediate variants).
- CSR reads/writes lifted to __rcsr / __wcsr intrinsics.
- Fixed 32-bit width and standard arithmetic/logical operators.
"""

from . import ir, isa


def _reg(i):
    if isinstance(i, str):
        if i == "r0":
            return ir.Const(0)
        return ir.Reg(i)
    if i == 0:
        return ir.Const(0)
    return ir.Reg(isa.reg(i))


def op_expr(op):
    m = op.mode
    name = getattr(op, "name", None)
    if m == "reg":
        return _reg(op.reg)
    if m == "imm":
        return ir.Const(op.value, name=name)
    if m == "near":
        return ir.Const(op.addr, name=name)
    if m in ("displ", "phrase"):
        base = _reg(op.base_reg)
        if isinstance(base, ir.Const) and base.value == 0:
            addr = ir.Const(op.disp & 0xFFFFFFFF, name=name)
        elif op.disp == 0:
            addr = base
        else:
            addr = ir.Bin("+", base, ir.Const(op.disp & 0xFFFFFFFF))
        return ir.Mem(addr, width=op.width, name=name)
    return ir.Const(0, name=name)


def lift_insn(ins):
    ea = ins.ea
    m = ins.mnem
    ops = ins.ops

    def e(i):
        return op_expr(ops[i])

    # --- moves / nops ------------------------------------------------------
    if m == "nop":
        return [ir.Nop(ea)]
    if m in ("mv", "mvi", "mvui"):
        # dst = src
        return [ir.Assign(ea, e(0), e(1))]
    if m == "mvhi":
        val = (ops[1].value << 16) & 0xFFFFFFFF
        return [ir.Assign(ea, e(0), ir.Const(val))]

    # --- arithmetic / logic ------------------------------------------------
    if m in ("add", "addi"):
        return [ir.Assign(ea, e(0), ir.Bin("+", e(1), e(2)))]
    if m == "sub":
        return [ir.Assign(ea, e(0), ir.Bin("-", e(1), e(2)))]
    if m in ("mul", "muli"):
        return [ir.Assign(ea, e(0), ir.Bin("*", e(1), e(2)))]
    if m == "div":
        return [ir.Assign(ea, e(0), ir.Bin("/", e(1), e(2)))]
    if m == "divu":
        return [ir.Assign(ea, e(0), ir.IntrExpr("divu", [e(1), e(2)]))]
    if m == "mod":
        return [ir.Assign(ea, e(0), ir.Bin("%", e(1), e(2)))]
    if m == "modu":
        return [ir.Assign(ea, e(0), ir.IntrExpr("modu", [e(1), e(2)]))]

    if m in ("and", "andi"):
        return [ir.Assign(ea, e(0), ir.Bin("&", e(1), e(2)))]
    if m == "andhi":
        val = (ops[2].value << 16) & 0xFFFFFFFF
        return [ir.Assign(ea, e(0), ir.Bin("&", e(1), ir.Const(val)))]
    if m in ("or", "ori"):
        return [ir.Assign(ea, e(0), ir.Bin("|", e(1), e(2)))]
    if m == "orhi":
        val = (ops[2].value << 16) & 0xFFFFFFFF
        return [ir.Assign(ea, e(0), ir.Bin("|", e(1), ir.Const(val)))]
    if m in ("xor", "xori"):
        return [ir.Assign(ea, e(0), ir.Bin("^", e(1), e(2)))]
    if m in ("nor", "nori"):
        return [ir.Assign(ea, e(0), ir.Un("~", ir.Bin("|", e(1), e(2))))]
    if m in ("xnor", "xnori"):
        return [ir.Assign(ea, e(0), ir.Un("~", ir.Bin("^", e(1), e(2))))]
    if m == "not":
        return [ir.Assign(ea, e(0), ir.Un("~", e(1)))]

    if m == "sextb":
        return [ir.Assign(ea, e(0), ir.IntrExpr("sextb", [e(1)]))]
    if m == "sexth":
        return [ir.Assign(ea, e(0), ir.IntrExpr("sexth", [e(1)]))]

    # --- shifts ------------------------------------------------------------
    if m in ("sl", "sli"):
        return [ir.Assign(ea, e(0), ir.Bin("<<", e(1), e(2)))]
    if m in ("sr", "sri"):
        return [ir.Assign(ea, e(0), ir.IntrExpr("sra", [e(1), e(2)]))]
    if m in ("sru", "srui"):
        return [ir.Assign(ea, e(0), ir.Bin(">>", e(1), e(2)))]

    # --- memory loads / stores ---------------------------------------------
    if m == "lw":
        return [ir.Assign(ea, e(0), e(1))]
    if m == "lhu":
        mem = e(1)
        mem.signed = False
        return [ir.Assign(ea, e(0), mem)]
    if m == "lh":
        mem = e(1)
        mem.signed = True
        return [ir.Assign(ea, e(0), mem)]
    if m == "lbu":
        mem = e(1)
        mem.signed = False
        return [ir.Assign(ea, e(0), mem)]
    if m == "lb":
        mem = e(1)
        mem.signed = True
        return [ir.Assign(ea, e(0), mem)]
    if m in ("sw", "sh", "sb"):
        return [ir.Assign(ea, e(0), e(1))]

    # --- comparisons -------------------------------------------------------
    if m in ("cmpe", "cmpei"):
        return [ir.Assign(ea, e(0), ir.Bin("==", e(1), e(2)))]
    if m in ("cmpne", "cmpnei"):
        return [ir.Assign(ea, e(0), ir.Bin("!=", e(1), e(2)))]
    if m in ("cmpg", "cmpgi"):
        return [ir.Assign(ea, e(0), ir.Bin(">", e(1), e(2)))]
    if m in ("cmpge", "cmpgei"):
        return [ir.Assign(ea, e(0), ir.Bin(">=", e(1), e(2)))]
    if m in ("cmpgu", "cmpgui"):
        return [ir.Assign(ea, e(0), ir.Bin("u>", e(1), e(2)))]
    if m in ("cmpgeu", "cmpgeui"):
        return [ir.Assign(ea, e(0), ir.Bin("u>=", e(1), e(2)))]

    # --- conditional branches ----------------------------------------------
    if m in isa.COND_BRANCH:
        op_map = {
            "be": "==",
            "bne": "!=",
            "bg": ">",
            "bge": ">=",
            "bgu": "u>",
            "bgeu": "u>",
        }
        relop = op_map[m]
        cexpr = ir.Bin(relop, e(0), e(1))
        target = ops[2].addr
        return [ir.Branch(ea, cexpr, target, ea + 4)]

    # --- unconditional jumps & returns -------------------------------------
    if m == "bi":
        return [ir.Goto(ea, ops[0].addr)]
    if m in ("ret", "eret", "bret"):
        return [ir.Ret(ea, kind=m)]
    if m == "b":
        if ins.switch_info is not None:
            sw = ins.switch_info
            return [ir.Switch(ea, _reg(sw.idx_reg), sw.cases, default_ea=sw.default_ea)]
        # Indirect jump
        return [ir.Goto(ea, None)]

    # --- calls -------------------------------------------------------------
    if m == "calli":
        return [ir.Call(ea, target=ops[0].addr)]
    if m == "call":
        return [ir.Call(ea, expr=e(0))]

    # --- CSR & system ------------------------------------------------------
    if m == "rcsr":
        return [ir.Assign(ea, e(0), ir.IntrExpr("__rcsr", [e(1)]))]
    if m == "wcsr":
        return [ir.Intrinsic(ea, "__wcsr", [e(0), e(1)])]
    if m in ("scall", "break"):
        return [ir.Intrinsic(ea, f"__{m}", [])]
    if m in ("raise", "user"):
        return [ir.Intrinsic(ea, f"__{m}", [e(0)])]

    return [ir.Intrinsic(ea, m, [e(i) for i in range(len(ops))])]
