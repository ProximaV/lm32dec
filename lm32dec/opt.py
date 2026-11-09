"""
Block-local optimization and SSA-style simplification for LM32.

Performs:
1. Constant folding (arithmetic, shifts, bitwise, comparisons).
2. Constant and copy propagation within basic blocks.
3. 32-bit immediate folding (mvhi + ori / addi -> single 32-bit Const).
4. Cmp-to-Branch folding:
   Folds boolean compare statements (cmpe, cmpg, cmpge, cmpgu, cmpgeu, cmpne, etc.)
   immediately preceding conditional branches against zero (bne/be reg, r0)
   into direct relational branch conditions, eliminating intermediate flag variables.
5. Dead assignment elimination (including discarding writes to r0).
"""

from . import ir

_OPS = {
    "+": lambda a, b: (a + b) & 0xFFFFFFFF,
    "-": lambda a, b: (a - b) & 0xFFFFFFFF,
    "*": lambda a, b: (a * b) & 0xFFFFFFFF,
    "/": lambda a, b: (a // b) & 0xFFFFFFFF if b != 0 else 0,
    "%": lambda a, b: (a % b) & 0xFFFFFFFF if b != 0 else 0,
    "|": lambda a, b: a | b,
    "&": lambda a, b: a & b,
    "^": lambda a, b: a ^ b,
    "<<": lambda a, b: (a << (b & 31)) & 0xFFFFFFFF,
    ">>": lambda a, b: (a & 0xFFFFFFFF) >> (b & 31),
    "==": lambda a, b: 1 if a == b else 0,
    "!=": lambda a, b: 1 if a != b else 0,
    "<": lambda a, b: 1 if _signed32(a) < _signed32(b) else 0,
    "<=": lambda a, b: 1 if _signed32(a) <= _signed32(b) else 0,
    ">": lambda a, b: 1 if _signed32(a) > _signed32(b) else 0,
    ">=": lambda a, b: 1 if _signed32(a) >= _signed32(b) else 0,
    "u<": lambda a, b: 1 if (a & 0xFFFFFFFF) < (b & 0xFFFFFFFF) else 0,
    "u<=": lambda a, b: 1 if (a & 0xFFFFFFFF) <= (b & 0xFFFFFFFF) else 0,
    "u>": lambda a, b: 1 if (a & 0xFFFFFFFF) > (b & 0xFFFFFFFF) else 0,
    "u>=": lambda a, b: 1 if (a & 0xFFFFFFFF) >= (b & 0xFFFFFFFF) else 0,
}


def _signed32(v):
    v &= 0xFFFFFFFF
    return (v - 0x100000000) if v >= 0x80000000 else v


_INVERT_RELOP = {
    "==": "!=",
    "!=": "==",
    "<": ">=",
    ">=": "<",
    ">": "<=",
    "<=": ">",
    "u<": "u>=",
    "u>=": "u<",
    "u>": "u<=",
    "u<=": "u>",
}


def _fold(e):
    if isinstance(e, ir.Bin):
        l, r = _fold(e.l), _fold(e.r)
        if isinstance(l, ir.Const) and isinstance(r, ir.Const) and e.op in _OPS:
            return ir.Const(_OPS[e.op](l.value, r.value))
        # Algebraic identities with 0
        if isinstance(r, ir.Const) and r.value == 0:
            if e.op in ("+", "-", "|", "^", "<<", ">>"):
                return l
            if e.op in ("*", "&"):
                return ir.Const(0)
        if isinstance(l, ir.Const) and l.value == 0:
            if e.op in ("+", "|", "^"):
                return r
            if e.op in ("*", "&", "/", "%", "<<", ">>"):
                return ir.Const(0)
        # Identity with 1
        if isinstance(r, ir.Const) and r.value == 1 and e.op in ("*", "/"):
            return l
        # Identity with 0xFFFFFFFF
        if isinstance(r, ir.Const) and r.value == 0xFFFFFFFF and e.op == "&":
            return l

        # Boolean relational compare against 0:
        # (cmp != 0) -> cmp
        # (cmp == 0) -> !cmp
        if isinstance(l, ir.Bin) and l.op in _INVERT_RELOP and isinstance(r, ir.Const) and r.value == 0:
            if e.op == "!=":
                return l
            if e.op == "==":
                inv_op = _INVERT_RELOP.get(l.op)
                if inv_op:
                    return ir.Bin(inv_op, l.l, l.r)
        if isinstance(r, ir.Bin) and r.op in _INVERT_RELOP and isinstance(l, ir.Const) and l.value == 0:
            if e.op == "!=":
                return r
            if e.op == "==":
                inv_op = _INVERT_RELOP.get(r.op)
                if inv_op:
                    return ir.Bin(inv_op, r.l, r.r)

        return ir.Bin(e.op, l, r)

    if isinstance(e, ir.Un):
        sub = _fold(e.e)
        if isinstance(sub, ir.Const):
            if e.op == "~":
                return ir.Const((~sub.value) & 0xFFFFFFFF)
            if e.op == "-":
                return ir.Const((-sub.value) & 0xFFFFFFFF)
            if e.op == "!":
                return ir.Const(0 if sub.value else 1)
        return ir.Un(e.op, sub)

    if isinstance(e, ir.Mem):
        return ir.Mem(_fold(e.addr) if isinstance(e.addr, ir.Expr) else e.addr, e.width, e.signed, getattr(e, 'name', None))

    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_fold(a) for a in e.args])

    return e


def _mentions(e, name):
    if isinstance(e, ir.Reg):
        return e.name == name
    if isinstance(e, ir.Bin):
        return _mentions(e.l, name) or _mentions(e.r, name)
    if isinstance(e, ir.Un):
        return _mentions(e.e, name)
    if isinstance(e, ir.Mem):
        return isinstance(e.addr, ir.Expr) and _mentions(e.addr, name)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions(a, name) for a in e.args)
    return False


def _stmt_reads(s, name):
    if isinstance(s, ir.Assign):
        if _mentions(s.src, name):
            return True
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
            return _mentions(s.dst.addr, name)
        return False
    if isinstance(s, ir.Branch):
        return _mentions(s.cexpr, name)
    if isinstance(s, ir.Switch):
        return _mentions(s.expr, name)
    if isinstance(s, ir.Call):
        return (s.expr is not None and _mentions(s.expr, name)) or any(
            _mentions(a, name) for a in (s.args or ())
        )
    if isinstance(s, ir.Intrinsic):
        return any(_mentions(a, name) for a in s.args)
    return False


def _subst(e, env):
    if isinstance(e, ir.Reg):
        return env.get(e.name, e)
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst(e.l, env), _subst(e.r, env))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst(e.e, env))
    if isinstance(e, ir.Mem):
        return ir.Mem(_subst(e.addr, env) if isinstance(e.addr, ir.Expr) else e.addr, e.width, e.signed, getattr(e, 'name', None))
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst(a, env) for a in e.args])
    return e


def _kill(env, name):
    for k in [k for k, v in env.items() if k == name or _mentions(v, name)]:
        del env[k]


_KEEP_INTRINSICS = frozenset(("__scall", "__break", "__raise", "__wcsr"))


def _opt_block(block):
    env = {}
    mem_env = {}
    cmp_def_stmts = {}  # reg_name -> Assign statement that defined it as a compare

    for s in block.stmts:
        if isinstance(s, ir.Assign):
            s.src = _fold(_subst(s.src, env))
            if isinstance(s.dst, ir.Reg):
                # Discard writes to r0 (hardwired 0)
                if s.dst.name == "r0":
                    continue

                _kill(env, s.dst.name)
                _kill(mem_env, s.dst.name)
                cmp_def_stmts.pop(s.dst.name, None)

                if isinstance(s.src, (ir.Const, ir.Reg)) and not _mentions(s.src, s.dst.name):
                    env[s.dst.name] = s.src
                elif isinstance(s.src, ir.Bin) and s.src.op in _INVERT_RELOP and not _mentions(s.src, s.dst.name):
                    env[s.dst.name] = s.src
                    cmp_def_stmts[s.dst.name] = s
                elif isinstance(s.src, ir.Mem) and not _mentions(s.src, s.dst.name):
                    mem_env[s.dst.name] = s.src
            else:
                s.dst = _fold(_subst(s.dst, env))
                mem_env.clear()

        elif isinstance(s, ir.Branch):
            orig = s.cexpr
            s.cexpr = _fold(_subst(s.cexpr, env))
            if isinstance(orig, ir.Bin) and isinstance(orig.l, ir.Reg) and orig.l.name in cmp_def_stmts:
                s.inlined_eas.append(cmp_def_stmts[orig.l.name].ea)
            elif isinstance(orig, ir.Bin) and isinstance(orig.r, ir.Reg) and orig.r.name in cmp_def_stmts:
                s.inlined_eas.append(cmp_def_stmts[orig.r.name].ea)

        elif isinstance(s, ir.Switch):
            s.expr = _fold(_subst(s.expr, env))

        elif isinstance(s, ir.Intrinsic):
            s.args = [_fold(_subst(a, env)) for a in s.args]
            if s.name not in _KEEP_INTRINSICS:
                env.clear()
            mem_env.clear()

        elif isinstance(s, ir.Call):
            if s.expr is not None:
                s.expr = _fold(_subst(s.expr, env))
            env.clear()
            mem_env.clear()

    # Intra-block dead assignment elimination:
    # 1. Drop writes to r0.
    # 2. Drop self-copies `rX = rX`.
    # 3. Drop `rX = ...` if rX is overwritten later in the same block before any read.
    # 4. Drop inlined cmp definitions.
    stmts = block.stmts
    keep = []
    n = len(stmts)

    for i, s in enumerate(stmts):
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
            rname = s.dst.name
            if rname == "r0":
                continue
            if isinstance(s.src, ir.Reg) and s.src.name == rname:
                continue

            dead = False
            for j in range(i + 1, n):
                sj = stmts[j]
                if _stmt_reads(sj, rname):
                    break
                if isinstance(sj, ir.Assign) and isinstance(sj.dst, ir.Reg) and sj.dst.name == rname:
                    dead = True
                    break
            if dead:
                continue

            # If s was an inlined cmp statement folded into the terminating branch and not read elsewhere:
            if rname in cmp_def_stmts and cmp_def_stmts[rname] is s:
                read_elsewhere = any(_stmt_reads(stmts[k], rname) for k in range(i + 1, n))
                if not read_elsewhere:
                    continue

        keep.append(s)

    block.stmts = keep


def optimize(func):
    for b in func.blocks.values():
        _opt_block(b)
    return func
