"""
Call-argument folding for LatticeMico32 (LM32).

LM32 passes up to 8 integer/pointer arguments in r1..r8.
Tracks values assigned to r1..r8 within a basic block immediately preceding Call statements.
Folds the setup assignments into the call's `args` list and eliminates redundant setup statements.
"""

from . import ir

ARGS = ("r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8")
_ARGSET = frozenset(ARGS)


def _expr_regs(e, out):
    if isinstance(e, ir.Reg):
        out.add(e.name)
    elif isinstance(e, ir.Bin):
        _expr_regs(e.l, out); _expr_regs(e.r, out)
    elif isinstance(e, ir.Un):
        _expr_regs(e.e, out)
    elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        _expr_regs(e.addr, out)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _expr_regs(a, out)
    return out


def _has_mem(e):
    if isinstance(e, ir.Mem):
        return True
    if isinstance(e, ir.Bin):
        return _has_mem(e.l) or _has_mem(e.r)
    if isinstance(e, ir.Un):
        return _has_mem(e.e)
    if isinstance(e, ir.IntrExpr):
        return any(_has_mem(a) for a in e.args)
    return False


def rewrite(func, arity=None):
    arity = arity or {}
    for b in func.blocks.values():
        argexpr = {}        # reg name -> current value expr
        argstmt = {}        # reg name -> the Assign that set it
        used_since = set()  # arg regs read since their Assign
        out = []

        for s in b.stmts:
            if isinstance(s, ir.Assign):
                src_regs = _expr_regs(s.src, set())
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    src_regs |= _expr_regs(s.dst.addr, set())
                used_since |= (src_regs & _ARGSET)

                if isinstance(s.dst, ir.Reg):
                    dname = s.dst.name
                    # Invalidate pending arg exprs that depend on dname
                    for a, ex in list(argexpr.items()):
                        if a != dname and dname in _expr_regs(ex, set()):
                            argexpr[a] = ir.Reg(a)
                            argstmt.pop(a, None)
                    if dname in _ARGSET:
                        if dname in src_regs and dname in argstmt:
                            argstmt.pop(dname, None)
                        argexpr[dname] = s.src
                        argstmt[dname] = s
                        used_since.discard(dname)
                        out.append(s)
                        continue
                elif isinstance(s.dst, ir.Mem):
                    for a, ex in list(argexpr.items()):
                        if _has_mem(ex):
                            argexpr[a] = ir.Reg(a)
                            argstmt.pop(a, None)
                out.append(s)
                continue

            if isinstance(s, ir.Call):
                call_ptr_regs = _expr_regs(s.expr, set()) if s.expr is not None else set()
                n = arity.get(s.target)
                if n is not None:
                    k = n
                else:
                    set_indices = [idx for idx, a in enumerate(ARGS) if a in argexpr and a not in call_ptr_regs]
                    if getattr(s, "is_tail", False) and set_indices:
                        k = max(set_indices) + 1
                    else:
                        run = []
                        for idx, a in enumerate(ARGS):
                            if a in argexpr and a not in call_ptr_regs:
                                run.append(a)
                            else:
                                break
                        k = len(run)

                k_regs = min(k, len(ARGS))
                call_args = [argexpr.get(ARGS[i], ir.Reg(ARGS[i])) for i in range(k_regs)]
                s.args = call_args

                # Drop folded setup statements if they were not read otherwise
                for i in range(k_regs):
                    a = ARGS[i]
                    if a in argstmt and a not in used_since:
                        st = argstmt[a]
                        if st in out:
                            out.remove(st)
                            s.inlined_eas.append(st.ea)

                argexpr.clear()
                argstmt.clear()
                used_since.clear()
                out.append(s)
                continue

            out.append(s)

        b.stmts = out

    return func
