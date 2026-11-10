"""
Calling convention analysis and function signature recovery for LatticeMico32 (LM32).

LM32 calling conventions:
1. First 8 arguments passed in 32-bit general registers:
   r1 (first), r2 (second), r3 (third), r4 (fourth),
   r5 (fifth), r6 (sixth), r7 (seventh), r8 (eighth).
2. Additional arguments (9th+) passed on the stack at entry SP (sp0 + 0, sp0 + 4, ...).
3. Return values:
   - 32-bit scalar or pointer returned in r1.
   - 64-bit scalar returned in r1:r2.
   - Structs > 8 bytes return via caller-allocated pointer passed in r1.
4. Volatile (caller-saved) registers:
   r1..r10, ra (r29), ea (r30), ba (r31) - clobbered across calls.
5. Callee-saved registers:
   r11..r25, gp (r26), fp (r27), sp (r28) - preserved across calls.
"""

from . import ir, isa

ARG_REGS = ("r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8")
CALLER_SAVED = frozenset(
    [f"r{i}" for i in range(1, 11)] + ["ra", "ea", "ba"]
)
CALLEE_SAVED = frozenset(
    [f"r{i}" for i in range(11, 26)] + ["gp", "fp", "sp"]
)


class Param:
    __slots__ = ("name", "type_str", "location")

    def __init__(self, name, type_str="int", location="r1"):
        self.name = name
        self.type_str = type_str
        self.location = location

    def __repr__(self):
        return f"{self.type_str} {self.name}"


class FunctionSig:
    def __init__(self, name=None, ret_type="void", ret_expr=None, params=None):
        self.name = name
        self.ret_type = ret_type
        self.ret_expr = ret_expr
        self.params = list(params) if params else []

    def format_signature(self, func_name=None):
        name = func_name or self.name or "sub_unknown"
        if self.params:
            pstr = ", ".join(f"{p.type_str} {p.name}" for p in self.params)
        else:
            pstr = "void"
        return f"{self.ret_type} {name}({pstr})"


def _collect_expr_regs(e, out_regs):
    if isinstance(e, ir.Reg):
        out_regs.add(e.name)
    elif isinstance(e, ir.Bin):
        _collect_expr_regs(e.l, out_regs)
        _collect_expr_regs(e.r, out_regs)
    elif isinstance(e, ir.Un):
        _collect_expr_regs(e.e, out_regs)
    elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        _collect_expr_regs(e.addr, out_regs)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _collect_expr_regs(a, out_regs)


def compute_liveness(func, hidden_stmts=frozenset()):
    """Compute entry live-in registers via standard backwards dataflow analysis."""
    block_gen = {}
    block_kill = {}

    for b in func.blocks.values():
        gen = set()
        kill = set()

        for s in b.stmts:
            if id(s) in hidden_stmts:
                continue

            used = set()
            if isinstance(s, ir.Assign):
                _collect_expr_regs(s.src, used)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    _collect_expr_regs(s.dst.addr, used)
            elif isinstance(s, ir.Call):
                if s.args:
                    for a in s.args:
                        _collect_expr_regs(a, used)
                if s.expr:
                    _collect_expr_regs(s.expr, used)
            elif isinstance(s, ir.Branch):
                if isinstance(s.cexpr, ir.Expr):
                    _collect_expr_regs(s.cexpr, used)
            elif isinstance(s, ir.Switch) and isinstance(s.expr, ir.Expr):
                _collect_expr_regs(s.expr, used)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    _collect_expr_regs(a, used)

            # Upward exposed uses in this block
            gen |= (used - kill)

            # Definitions kill earlier uses
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                kill.add(s.dst.name)
            elif isinstance(s, ir.Call):
                kill |= CALLER_SAVED

        block_gen[b.start] = gen
        block_kill[b.start] = kill

    live_in = {ea: set() for ea in func.blocks}
    changed = True
    while changed:
        changed = False
        for ea, b in func.blocks.items():
            live_out = set()
            for _, tgt in b.succ:
                if tgt in live_in:
                    live_out |= live_in[tgt]
            new_in = block_gen[ea] | (live_out - block_kill[ea])
            if new_in != live_in[ea]:
                live_in[ea] = new_in
                changed = True

    return live_in.get(func.entry, set())


def _infer_return(func):
    """Infer return type: void, int, uint64_t, or pointer."""
    ret_blocks = [b for b in func.blocks.values() if b.term == "ret"]
    if not ret_blocks:
        return "void", None

    r1_defined = False
    r2_defined = False
    cand_expr = None

    for b in ret_blocks:
        for s in reversed(b.stmts):
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                if s.dst.name == "r1" and not r1_defined:
                    r1_defined = True
                    cand_expr = s.src
                elif s.dst.name == "r2" and not r2_defined:
                    r2_defined = True
            elif isinstance(s, ir.Call):
                break

    # If both r1 and r2 defined at exit, 64-bit return
    if r1_defined and r2_defined:
        return "uint64_t", ir.Reg("r1")

    if r1_defined:
        if isinstance(cand_expr, ir.Const) and cand_expr.value >= 0x800000:
            return "int *", cand_expr
        if isinstance(cand_expr, ir.Mem):
            return "int", cand_expr
        return "int", cand_expr or ir.Reg("r1")

    # If no explicit assignment in return block, check if entry block defined r1
    entry_block = func.blocks.get(func.entry)
    if entry_block:
        for s in entry_block.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == "r1":
                return "int", ir.Reg("r1")

    return "void", None


def analyze_calling_convention(func, frame_info=None, user_proto=None, func_name=None, ret_types=None, caller_consensus=None):
    """Reconstruct function signature (parameters, return type) for LM32."""
    fn_name = func_name or getattr(func, "name", None) or ("sub_%X" % func.entry)
    if user_proto:
        sig = parse_cdecl_prototype(user_proto)
        if sig:
            sig.name = fn_name
            return sig

    hidden = frame_info.hidden_stmts if frame_info else frozenset()
    live_in = set(compute_liveness(func, hidden))

    if caller_consensus:
        for rname, has_arg in caller_consensus.items():
            if has_arg:
                live_in.add(rname)

    # Determine highest live-in argument register
    hi_arg = -1
    for idx, r in enumerate(ARG_REGS):
        if r in live_in:
            hi_arg = idx

    # If function accesses incoming stack arguments, all 8 argument registers are active
    stack_args = getattr(func, "stack_args", {}) or {}
    if frame_info and frame_info.stack_args:
        stack_args = frame_info.stack_args

    if stack_args:
        hi_arg = 7

    params = []
    # Register parameters a0..a7
    for i in range(hi_arg + 1):
        r_name = ARG_REGS[i]
        params.append(Param(name=f"a{i}", type_str="int", location=r_name))

    # Stack parameters arg_0, arg_4, ...
    if stack_args:
        seen_names = {p.name for p in params}
        for off in sorted(stack_args):
            name, width = stack_args[off]
            if name in seen_names:
                continue
            seen_names.add(name)
            t_str = "int" if width == 4 else ("short" if width == 2 else "char")
            params.append(Param(name=name, type_str=t_str, location=f"[sp+{off}]"))

    ret_type, ret_expr = _infer_return(func)
    return FunctionSig(name=fn_name, ret_type=ret_type, ret_expr=ret_expr, params=params)


def parse_cdecl_prototype(proto_str):
    """Parse a C prototype string like 'int foo(int a, void *b)', using IDA's parse_decl when available."""
    try:
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
        decl = proto_str.strip().rstrip(";") + ";"
        fn_name = ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL)
        if fn_name and tif.is_func():
            fi = ida_typeinf.func_type_data_t()
            if tif.get_func_details(fi):
                ret_type = fi.rettype.dstr()
                params = []
                for idx, p in enumerate(fi):
                    p_name = p.name or f"a{idx}"
                    t_str = p.type.dstr()
                    loc = ARG_REGS[idx] if idx < len(ARG_REGS) else f"stack_{idx}"
                    params.append(Param(p_name, t_str, location=loc))
                return FunctionSig(name=fn_name, ret_type=ret_type, params=params)
    except Exception:
        pass

    import re
    proto_str = proto_str.strip().rstrip(";")
    m = re.match(r"^([\w\s\*]+?)\s+(\w+)\s*\((.*?)\)$", proto_str)
    if not m:
        return None
    ret_type = m.group(1).strip()
    func_name = m.group(2).strip()
    param_str = m.group(3).strip()

    params = []
    if param_str and param_str != "void":
        for idx, p in enumerate(param_str.split(",")):
            p = p.strip()
            parts = p.rsplit(None, 1)
            if len(parts) == 2:
                t_str, p_name = parts[0].strip(), parts[1].strip()
            else:
                t_str, p_name = p, f"a{idx}"
            loc = ARG_REGS[idx] if idx < len(ARG_REGS) else f"stack_{idx}"
            params.append(Param(p_name, t_str, location=loc))

    return FunctionSig(name=func_name, ret_type=ret_type, params=params)
