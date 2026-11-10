"""
Stack-frame recovery and cleanup for LatticeMico32 (LM32).

LM32 stack convention:
- sp = r28 (stack pointer, grows down toward lower addresses)
- fp = r27 (frame pointer, optional / general-purpose register under -fomit-frame-pointer)
- ra = r29 (return address link register)
- Callee-saved registers: r11..r25, gp (r26), fp (r27), sp (r28), and ra (r29)

LM32 GCC stack frame layout:
- Function prologue allocates stack frame: `addi sp, sp, -frame_size`.
- Callee-saved registers are stored into `[sp+4 .. sp+frame_size]`.
- Local variables occupy slots `[sp+K .. sp+frame_size]`.
- Stack variable naming:
    for canon_off <= frame_size:
        var_offset = frame_size - canon_off + 4 -> `var_{var_offset:X}` (matches IDA Pro)
    for canon_off > frame_size:
        arg_offset = canon_off - frame_size - 4 -> `arg_{arg_offset:X}`
"""

from . import ir

FP = "fp"
SP = "sp"
RA = "ra"

CALLEE_SAVED = frozenset(
    [f"r{i}" for i in range(11, 26)] + ["gp", "fp", "sp", "ra"]
)


def _sign_extend_imm(v):
    if v is None:
        return None
    if v >= (1 << 63):
        v -= (1 << 64)
    elif v >= 0x80000000:
        v -= 0x100000000
    elif v >= 0x8000:
        v -= 0x10000
    return v


def _sp_off(addr):
    """Return displacement if addr is sp/fp / sp+const, else None."""
    if isinstance(addr, ir.Reg) and addr.name in (SP, FP):
        return 0
    if (isinstance(addr, ir.Bin) and addr.op == "+"
            and isinstance(addr.l, ir.Reg) and addr.l.name in (SP, FP)
            and isinstance(addr.r, ir.Const)):
        return addr.r.value
    return None


def _sp_adjust_delta(stmt):
    """If stmt is `sp = sp + K` or `sp = sp - K`, return signed delta, else None."""
    if not (isinstance(stmt, ir.Assign) and isinstance(stmt.dst, ir.Reg) and stmt.dst.name == SP):
        return None
    if isinstance(stmt.src, ir.Bin) and isinstance(stmt.src.l, ir.Reg) and stmt.src.l.name == SP:
        if isinstance(stmt.src.r, ir.Const):
            signed_v = _sign_extend_imm(stmt.src.r.value)
            if stmt.src.op == "+":
                return signed_v
            if stmt.src.op == "-":
                return -signed_v
    return None


def _compute_sp_profile(func):
    """Compute `(frame_size, entry_delta)` across func."""
    entry_delta = {func.entry: 0}
    min_delta = 0
    for b in func.ordered():
        cur = entry_delta.get(b.start, min_delta)
        for s in b.stmts:
            d = _sp_adjust_delta(s)
            if d is not None:
                cur += d
                if cur < min_delta:
                    min_delta = cur
        for _, tgt in b.succ:
            if tgt in func.blocks and tgt not in entry_delta:
                entry_delta[tgt] = cur
    frame_size = -min_delta
    return frame_size, entry_delta


def _canon_off(raw_off, cur_delta, frame_size):
    if raw_off is None:
        return None
    signed_raw = _sign_extend_imm(raw_off)
    return (cur_delta + frame_size) + signed_raw


def _saved_slots(func, frame_size, entry_delta):
    """Find canonical offsets holding callee-saved registers or ra."""
    stores, loads = {}, {}
    for b in func.ordered():
        cur_delta = entry_delta.get(b.start, -frame_size)
        for s in b.stmts:
            d = _sp_adjust_delta(s)
            if d is not None:
                cur_delta += d
                continue
            if not isinstance(s, ir.Assign):
                continue
            if isinstance(s.dst, ir.Mem) and isinstance(s.src, ir.Reg) and s.src.name in CALLEE_SAVED:
                off = _canon_off(_sp_off(s.dst.addr), cur_delta, frame_size)
                if off is not None and 0 <= off <= frame_size:
                    stores.setdefault(off, set()).add(s.src.name)
            elif isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Mem) and s.dst.name in CALLEE_SAVED:
                off = _canon_off(_sp_off(s.src.addr), cur_delta, frame_size)
                if off is not None and 0 <= off <= frame_size:
                    loads.setdefault(off, set()).add(s.dst.name)

    common = {}
    for off in set(stores) & set(loads):
        shared = stores[off] & loads[off]
        if shared:
            common[off] = shared
    # In LM32 non-leaf functions, ra is saved in prologue. If stored, treat as saved even if unlinked return.
    for off, s_regs in stores.items():
        if "ra" in s_regs and off not in common:
            common[off] = {"ra"}
    return common


def rewrite(func, ida_frame_info=None):
    """Rewrite stack slots to named locals/arguments and strip prologue/epilogue boilerplate."""
    frame_size, entry_delta = _compute_sp_profile(func)
    saved = _saved_slots(func, frame_size, entry_delta) if frame_size > 0 else {}

    func.locals = getattr(func, "locals", {}) or {}
    func.stack_args = getattr(func, "stack_args", {}) or {}

    def slot_name(canon_off, width=4, ea=None):
        if frame_size > 0:
            if canon_off > frame_size:
                arg_off = canon_off - frame_size - 4
                if arg_off < 0:
                    arg_off = 0
                if ida_frame_info and getattr(ida_frame_info, "stkvars_by_ea", None) and ea in ida_frame_info.stkvars_by_ea:
                    for op_info in ida_frame_info.stkvars_by_ea[ea].values():
                        soff, sname, ssz, is_arg = op_info
                        if is_arg:
                            func.stack_args[arg_off] = (sname, width)
                            return sname
                name = f"arg_{arg_off:X}"
                func.stack_args[arg_off] = (name, width)
                return name
            else:
                var_off = frame_size - canon_off + 4
                if ida_frame_info and getattr(ida_frame_info, "stkvars_by_ea", None) and ea in ida_frame_info.stkvars_by_ea:
                    for op_info in ida_frame_info.stkvars_by_ea[ea].values():
                        soff, sname, ssz, is_arg = op_info
                        if not is_arg:
                            func.locals[sname] = max(func.locals.get(sname, 1), width)
                            return sname
                name = f"var_{var_off:X}"
                func.locals[name] = max(func.locals.get(name, 1), width)
                return name
        else:
            if canon_off >= 4:
                arg_off = canon_off - 4
                name = f"arg_{arg_off:X}"
                func.stack_args[arg_off] = (name, width)
                return name
            else:
                name = f"var_{canon_off:X}"
                func.locals[name] = max(func.locals.get(name, 1), width)
                return name

    def make_xf(cur_delta, ea=None):
        def xf(e):
            if isinstance(e, ir.Mem):
                off = _canon_off(_sp_off(e.addr), cur_delta, frame_size)
                if off is not None and off not in saved:
                    return ir.Reg(slot_name(off, e.width, ea=ea))
                addr = xf(e.addr) if isinstance(e.addr, ir.Expr) else e.addr
                return ir.Mem(addr, e.width, e.signed, getattr(e, 'name', None))
            if isinstance(e, ir.Bin):
                off = _canon_off(_sp_off(e), cur_delta, frame_size)
                if off is not None and off not in saved:
                    return ir.Un("&", ir.Reg(slot_name(off, 4, ea=ea)))
                return ir.Bin(e.op, xf(e.l), xf(e.r))
            if isinstance(e, ir.Un):
                return ir.Un(e.op, xf(e.e))
            if isinstance(e, ir.IntrExpr):
                return ir.IntrExpr(e.name, [xf(a) for a in e.args])
            return e
        return xf

    def drop(s, cur_delta, is_ret_block):
        # sp adjust: sp = sp + K or sp = fp
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == SP:
            if isinstance(s.src, ir.Bin) and isinstance(s.src.l, ir.Reg) and s.src.l.name == SP:
                return True
            if isinstance(s.src, ir.Reg) and s.src.name in (SP, FP):
                return True
        # frame pointer setup: fp = sp or fp = sp + K
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == FP:
            if isinstance(s.src, ir.Reg) and s.src.name == SP:
                return True
            if isinstance(s.src, ir.Bin) and isinstance(s.src.l, ir.Reg) and s.src.l.name == SP:
                return True
        # callee-saved register save/restore
        if isinstance(s, ir.Assign):
            if isinstance(s.dst, ir.Mem) and isinstance(s.src, ir.Reg):
                off = _canon_off(_sp_off(s.dst.addr), cur_delta, frame_size)
                if off in saved and s.src.name in saved[off]:
                    return True
            if isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Mem):
                off = _canon_off(_sp_off(s.src.addr), cur_delta, frame_size)
                if off in saved and s.dst.name in saved[off]:
                    return True
        return False

    for b in func.ordered():
        cur_delta = entry_delta.get(b.start, -frame_size)
        is_ret_block = (b.term == "ret")
        out = []
        for s in b.stmts:
            d = _sp_adjust_delta(s)
            if d is not None:
                cur_delta += d
            if drop(s, cur_delta, is_ret_block):
                continue

            ea = getattr(s, "ea", None)
            xf = make_xf(cur_delta, ea=ea)
            if isinstance(s, ir.Assign):
                s.src = xf(s.src)
                if isinstance(s.dst, ir.Mem):
                    off = _canon_off(_sp_off(s.dst.addr), cur_delta, frame_size)
                    if off is not None and off not in saved:
                        s.dst = ir.Reg(slot_name(off, s.dst.width, ea=ea))
                    else:
                        s.dst = ir.Mem(xf(s.dst.addr) if isinstance(s.dst.addr, ir.Expr) else s.dst.addr,
                                       s.dst.width, s.dst.signed, getattr(s.dst, 'name', None))
            elif isinstance(s, ir.Branch):
                s.cexpr = xf(s.cexpr)
            elif isinstance(s, ir.Switch):
                s.expr = xf(s.expr)
            elif isinstance(s, ir.Intrinsic):
                s.args = [xf(a) for a in s.args]
            elif isinstance(s, ir.Call) and s.expr is not None:
                s.expr = xf(s.expr)
            out.append(s)
        b.stmts = out

    return func


class FrameInfo:
    def __init__(self, locals=None, stack_args=None, hidden_stmts=None, virtual_vars=None, user_renames=None, user_types=None, ida_stkvars=None):
        self.locals = locals or {}
        self.stack_args = stack_args or {}
        self.hidden_stmts = hidden_stmts or set()
        self.virtual_vars = virtual_vars or {}
        self.user_renames = user_renames or {}
        self.user_types = user_types or {}
        self.ida_stkvars = ida_stkvars or {}


def analyze_frame(func, ida_frame_info=None):
    """Analyze stack frame, rewrite stack accesses, and return FrameInfo."""
    rewrite(func, ida_frame_info=ida_frame_info)
    locals_dict = dict(getattr(func, "locals", {}) or {})
    stack_args = dict(getattr(func, "stack_args", {}) or {})
    return FrameInfo(locals=locals_dict, stack_args=stack_args, ida_stkvars=getattr(ida_frame_info, "stkvars_by_ea", None))
