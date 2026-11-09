"""
Virtual Variable Recovery and SSA Def-Use Web Layer for LatticeMico32 (LM32).

Transforms machine registers (r1..r25) into clean C virtual variables:
1. Reaching definitions analysis across CFG basic blocks.
2. Def-use live range construction via Union-Find.
3. Function argument binding (r1..r8 -> a0..a7).
4. Register reuse splitting into disjoint virtual variables (v0, v1, ...).
5. Copy propagation and dead temporary elimination.
6. Single-use inlining for natural C expressions.
7. Variable declarations and type deduction.
"""

from . import ir, isa

LM32_GPRS = {f"r{i}" for i in range(1, 26)} | {"ra", "ea", "ba"}
ARG_REGS = ("r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8")
CALLER_SAVED = frozenset([f"r{i}" for i in range(1, 11)] + ["ra", "ea", "ba"])


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        if x not in self.parent:
            self.parent[x] = x
            return x
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[rx] = ry


def _collect_expr_regs(e, out_regs):
    if isinstance(e, ir.Reg) and e.name in LM32_GPRS:
        out_regs.append(e.name)
    elif isinstance(e, ir.Var):
        out_regs.append(e.name)
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


def _get_stmt_uses(s):
    uses = []
    if isinstance(s, ir.Assign):
        _collect_expr_regs(s.src, uses)
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
            _collect_expr_regs(s.dst.addr, uses)
    elif isinstance(s, ir.Call):
        if s.args:
            for a in s.args:
                _collect_expr_regs(a, uses)
        if s.expr:
            _collect_expr_regs(s.expr, uses)
    elif isinstance(s, ir.Branch):
        if isinstance(s.cexpr, ir.Expr):
            _collect_expr_regs(s.cexpr, uses)
    elif isinstance(s, ir.Switch) and isinstance(s.expr, ir.Expr):
        _collect_expr_regs(s.expr, uses)
    elif isinstance(s, ir.Intrinsic):
        for a in s.args:
            _collect_expr_regs(a, uses)
    return uses


def _get_stmt_defs(s):
    defs = []
    clobbers = []
    if isinstance(s, ir.Assign):
        if isinstance(s.dst, ir.Reg) and s.dst.name in LM32_GPRS:
            defs.append(s.dst.name)
        elif isinstance(s.dst, ir.Var):
            defs.append(s.dst.name)
    elif isinstance(s, ir.Call):
        if not getattr(s, "is_tail", False):
            for r in CALLER_SAVED:
                if r in LM32_GPRS:
                    clobbers.append(r)
    return defs, clobbers


def _expr_uses_var(e, var_name):
    if isinstance(e, (ir.Var, ir.Reg)) and e.name == var_name:
        return True
    if isinstance(e, ir.Bin):
        return _expr_uses_var(e.l, var_name) or _expr_uses_var(e.r, var_name)
    if isinstance(e, ir.Un):
        return _expr_uses_var(e.e, var_name)
    if isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        return _expr_uses_var(e.addr, var_name)
    if isinstance(e, ir.IntrExpr):
        return any(_expr_uses_var(a, var_name) for a in e.args)
    return False


def _stmt_uses_var(s, var_name):
    if isinstance(s, ir.Assign):
        if _expr_uses_var(s.src, var_name):
            return True
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
            return _expr_uses_var(s.dst.addr, var_name)
        return False
    if isinstance(s, ir.Call):
        if s.args and any(_expr_uses_var(a, var_name) for a in s.args):
            return True
        if s.expr and _expr_uses_var(s.expr, var_name):
            return True
        return False
    if isinstance(s, ir.Branch):
        return isinstance(s.cexpr, ir.Expr) and _expr_uses_var(s.cexpr, var_name)
    if isinstance(s, ir.Switch):
        return isinstance(s.expr, ir.Expr) and _expr_uses_var(s.expr, var_name)
    if isinstance(s, ir.Intrinsic):
        return any(_expr_uses_var(a, var_name) for a in s.args)
    return False


def _subst_ast(e, repl):
    if isinstance(e, ir.Reg) and e.name in repl:
        return repl[e.name]
    if isinstance(e, ir.Var) and e.name in repl:
        return repl[e.name]
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst_ast(e.l, repl), _subst_ast(e.r, repl))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst_ast(e.e, repl))
    if isinstance(e, ir.Mem):
        addr = _subst_ast(e.addr, repl) if isinstance(e.addr, ir.Expr) else e.addr
        return ir.Mem(addr, e.width, e.signed, getattr(e, 'name', None))
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst_ast(a, repl) for a in e.args])
    return e


def _subst_stmt_var(s, var_name, new_expr):
    repl = {var_name: new_expr}
    changed = False
    if isinstance(s, ir.Assign):
        if _expr_uses_var(s.src, var_name):
            s.src = _subst_ast(s.src, repl)
            changed = True
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
            if _expr_uses_var(s.dst.addr, var_name):
                s.dst.addr = _subst_ast(s.dst.addr, repl)
                changed = True
    elif isinstance(s, ir.Call):
        if s.args:
            new_args = []
            for a in s.args:
                if _expr_uses_var(a, var_name):
                    new_args.append(_subst_ast(a, repl))
                    changed = True
                else:
                    new_args.append(a)
            if changed:
                s.args = new_args
        if s.expr and _expr_uses_var(s.expr, var_name):
            s.expr = _subst_ast(s.expr, repl)
            changed = True
    elif isinstance(s, ir.Branch):
        if isinstance(s.cexpr, ir.Expr) and _expr_uses_var(s.cexpr, var_name):
            s.cexpr = _subst_ast(s.cexpr, repl)
            changed = True
    elif isinstance(s, ir.Switch) and isinstance(s.expr, ir.Expr):
        if _expr_uses_var(s.expr, var_name):
            s.expr = _subst_ast(s.expr, repl)
            changed = True
    elif isinstance(s, ir.Intrinsic):
        new_args = []
        for a in s.args:
            if _expr_uses_var(a, var_name):
                new_args.append(_subst_ast(a, repl))
                changed = True
            else:
                new_args.append(a)
        if changed:
            s.args = new_args
    return changed


def _is_pure_expr(e):
    if isinstance(e, (ir.Const, ir.Reg, ir.Var)):
        return True
    if isinstance(e, ir.Bin):
        return _is_pure_expr(e.l) and _is_pure_expr(e.r)
    if isinstance(e, ir.Un):
        return _is_pure_expr(e.e)
    if isinstance(e, ir.IntrExpr):
        return all(_is_pure_expr(a) for a in e.args)
    return False


def _compute_var_counts(func, hidden):
    use_count = {}
    def_count = {}

    def count_in_expr(e):
        if isinstance(e, (ir.Var, ir.Reg)):
            use_count[e.name] = use_count.get(e.name, 0) + 1
        elif isinstance(e, ir.Bin):
            count_in_expr(e.l)
            count_in_expr(e.r)
        elif isinstance(e, ir.Un):
            count_in_expr(e.e)
        elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
            count_in_expr(e.addr)
        elif isinstance(e, ir.IntrExpr):
            for a in e.args:
                count_in_expr(a)

    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            if isinstance(s, ir.Assign):
                count_in_expr(s.src)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    count_in_expr(s.dst.addr)
                elif isinstance(s.dst, (ir.Var, ir.Reg)):
                    def_count[s.dst.name] = def_count.get(s.dst.name, 0) + 1
            elif isinstance(s, ir.Call):
                if s.args:
                    for a in s.args:
                        count_in_expr(a)
                if s.expr:
                    count_in_expr(s.expr)
            elif isinstance(s, ir.Branch):
                if isinstance(s.cexpr, ir.Expr):
                    count_in_expr(s.cexpr)
            elif isinstance(s, ir.Switch) and isinstance(s.expr, ir.Expr):
                count_in_expr(s.expr)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    count_in_expr(a)

    return use_count, def_count


def _fold_temp_copies(func, hidden):
    changed = False
    for b in func.blocks.values():
        new_stmts = []
        i = 0
        stmts = b.stmts
        while i < len(stmts):
            s = stmts[i]
            if id(s) in hidden:
                new_stmts.append(s)
                i += 1
                continue

            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Var) and isinstance(s.src, ir.Var):
                dst_name = s.dst.name
                src_var = s.src

                subst_count = 0
                for j in range(i + 1, len(stmts)):
                    nxt = stmts[j]
                    if id(nxt) in hidden:
                        continue
                    nxt_defs, _ = _get_stmt_defs(nxt)
                    if src_var.name in nxt_defs:
                        break
                    if _subst_stmt_var(nxt, dst_name, src_var):
                        subst_count += 1
                        changed = True
                    if dst_name in nxt_defs:
                        break

            new_stmts.append(s)
            i += 1
        b.stmts = new_stmts
    return changed


def _inline_single_use(func, hidden):
    use_count, def_count = _compute_var_counts(func, hidden)
    changed = False

    for b in func.blocks.values():
        new_stmts = []
        i = 0
        stmts = b.stmts
        while i < len(stmts):
            s = stmts[i]
            if id(s) in hidden:
                new_stmts.append(s)
                i += 1
                continue

            if (isinstance(s, ir.Assign)
                and isinstance(s.dst, ir.Var)
                and s.dst.name.startswith("v")
                and def_count.get(s.dst.name, 0) == 1
                and use_count.get(s.dst.name, 0) == 1
                and _is_pure_expr(s.src)):

                v_name = s.dst.name
                can_inline = False
                target_stmt_idx = None
                for j in range(i + 1, len(stmts)):
                    nxt = stmts[j]
                    if id(nxt) in hidden:
                        continue
                    if _stmt_uses_var(nxt, v_name):
                        can_inline = True
                        target_stmt_idx = j
                        break
                    nxt_defs, _ = _get_stmt_defs(nxt)
                    if any(_expr_uses_var(s.src, d) for d in nxt_defs):
                        break

                if can_inline and target_stmt_idx is not None:
                    nxt = stmts[target_stmt_idx]
                    if _subst_stmt_var(nxt, v_name, s.src):
                        if getattr(nxt, "inlined_eas", None) is None:
                            nxt.inlined_eas = []
                        if getattr(s, "ea", None) is not None:
                            nxt.inlined_eas.append(s.ea)
                        if getattr(s, "inlined_eas", None):
                            nxt.inlined_eas.extend(s.inlined_eas)
                        changed = True
                        i += 1
                        continue

            new_stmts.append(s)
            i += 1
        b.stmts = new_stmts
    return changed


def _eliminate_dead_assignments(func, hidden, sig=None):
    protected_names = set()
    if sig and sig.ret_type != "void":
        protected_names.add("r1")
        if sig.ret_type == "uint64_t":
            protected_names.add("r2")

    changed = True
    any_changed = False
    iterations = 0
    while changed and iterations < 10:
        changed = False
        iterations += 1
        use_count, _ = _compute_var_counts(func, hidden)

        for b in func.blocks.values():
            new_stmts = []
            for s in b.stmts:
                if id(s) in hidden:
                    new_stmts.append(s)
                    continue

                if isinstance(s, ir.Assign) and _is_pure_expr(s.src):
                    # Check virtual variables
                    if isinstance(s.dst, ir.Var) and s.dst.name.startswith("v") and s.dst.name[1:].isdigit():
                        if use_count.get(s.dst.name, 0) == 0:
                            changed = True
                            any_changed = True
                            continue
                    # Check GPRs
                    elif isinstance(s.dst, ir.Reg) and s.dst.name in LM32_GPRS:
                        if use_count.get(s.dst.name, 0) == 0 and s.dst.name not in protected_names:
                            changed = True
                            any_changed = True
                            continue

                new_stmts.append(s)
            b.stmts = new_stmts

    return any_changed


def recover_variables(func, sig=None, frame_info=None):
    """Recover SSA-style virtual variables across func."""
    hidden = frame_info.hidden_stmts if frame_info else frozenset()

    # 1. Label def sites and entry parameters
    entry_defs = {}
    param_map = {}
    if sig and sig.params:
        for idx, p in enumerate(sig.params):
            if idx < len(ARG_REGS):
                rloc = ARG_REGS[idx]
                entry_defs[rloc] = ("entry", rloc)
                param_map[p.name] = rloc

    def_map = {}
    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            defs, _ = _get_stmt_defs(s)
            for d in defs:
                def_map[id(s), d] = (id(s), d)

    # 2. Reaching definitions analysis
    block_in_defs = {b.start: {} for b in func.ordered()}
    block_out_defs = {b.start: {} for b in func.ordered()}
    block_in_defs[func.entry] = {r: {("entry", r)} for r in entry_defs}

    changed = True
    while changed:
        changed = False
        for b in func.ordered():
            in_defs = {}
            for pred_ea, b_pred in func.blocks.items():
                for _, tgt in b_pred.succ:
                    if tgt == b.start and pred_ea in block_out_defs:
                        for r, s_set in block_out_defs[pred_ea].items():
                            in_defs.setdefault(r, set()).update(s_set)

            if b.start == func.entry:
                for r in entry_defs:
                    in_defs.setdefault(r, set()).add(("entry", r))

            if in_defs != block_in_defs[b.start]:
                block_in_defs[b.start] = in_defs
                changed = True

            cur_defs = {r: set(s_set) for r, s_set in in_defs.items()}
            for s in b.stmts:
                if id(s) in hidden:
                    continue
                defs, clobbers = _get_stmt_defs(s)
                for d in defs:
                    cur_defs[d] = {(id(s), d)}
                for c in clobbers:
                    cur_defs[c] = {(id(s), f"clobber_{c}")}

            if cur_defs != block_out_defs[b.start]:
                block_out_defs[b.start] = cur_defs
                changed = True

    # 3. Union-Find Def-Use Webs
    uf = _UnionFind()
    for b in func.ordered():
        cur_defs = {r: set(s_set) for r, s_set in block_in_defs[b.start].items()}
        for s in b.stmts:
            if id(s) in hidden:
                continue
            for u in _get_stmt_uses(s):
                use_key = (id(s), u, "use")
                for r_site in cur_defs.get(u, ()):
                    uf.union(use_key, r_site)

            defs, clobbers = _get_stmt_defs(s)
            for d in defs:
                cur_defs[d] = {(id(s), d)}
            for c in clobbers:
                cur_defs[c] = {(id(s), f"clobber_{c}")}

    # Group components
    groups = {}
    for node in list(uf.parent.keys()):
        root = uf.find(node)
        groups.setdefault(root, set()).add(node)

    # 4. Map Roots to Names
    web_var = {}
    var_counter = 0

    for root, members in groups.items():
        name = None
        for p_name, rloc in param_map.items():
            if ("entry", rloc) in members:
                name = p_name
                break

        if name is None and frame_info and getattr(frame_info, "stack_args", None):
            for sname in frame_info.stack_args:
                if any(m[0] == "entry" and m[1] == sname for m in members):
                    name = sname
                    break

        if name is None:
            name = f"v{var_counter}"
            var_counter += 1

        web_var[root] = ir.Var(name, width="w")

    # 5. Rewrite Statements
    for b in func.blocks.values():
        new_stmts = []
        for s in b.stmts:
            if id(s) in hidden:
                new_stmts.append(s)
                continue

            uses_repl = {}
            for reg in _get_stmt_uses(s):
                use_key = (id(s), reg, "use")
                root = uf.find(use_key)
                if root in web_var:
                    uses_repl[reg] = web_var[root]

            dst_var = None
            defs, _ = _get_stmt_defs(s)
            if defs:
                reg = defs[0]
                def_key = (id(s), reg)
                root = uf.find(def_key)
                if root in web_var:
                    dst_var = web_var[root]

            if isinstance(s, ir.Assign):
                s.src = _subst_ast(s.src, uses_repl)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    s.dst.addr = _subst_ast(s.dst.addr, uses_repl)
                elif dst_var is not None:
                    s.dst = dst_var

                if isinstance(s.dst, ir.Var) and isinstance(s.src, ir.Var) and s.dst.name == s.src.name:
                    continue

            elif isinstance(s, ir.Branch):
                if isinstance(s.cexpr, ir.Expr):
                    s.cexpr = _subst_ast(s.cexpr, uses_repl)
            elif isinstance(s, ir.Switch) and isinstance(s.expr, ir.Expr):
                s.expr = _subst_ast(s.expr, uses_repl)
            elif isinstance(s, ir.Call):
                if s.args:
                    s.args = [_subst_ast(a, uses_repl) for a in s.args]
                if s.expr:
                    s.expr = _subst_ast(s.expr, uses_repl)
            elif isinstance(s, ir.Intrinsic):
                s.args = [_subst_ast(a, uses_repl) for a in s.args]

            new_stmts.append(s)
        b.stmts = new_stmts

    # 6. Optimization Loop
    for _ in range(8):
        c1 = _eliminate_dead_assignments(func, hidden, sig=sig)
        c2 = _fold_temp_copies(func, hidden)
        c3 = _inline_single_use(func, hidden)
        if not (c1 or c2 or c3):
            break
    _eliminate_dead_assignments(func, hidden, sig=sig)

    # 7. Collect virtual variable declarations
    virtual_vars = {}

    def _collect_vvar(e):
        if isinstance(e, ir.Var) and not isinstance(e, ir.StackVar) and e.name.startswith("v") and e.name[1:].isdigit():
            virtual_vars[e.name] = (e, "w")
        elif isinstance(e, ir.Bin):
            _collect_vvar(e.l)
            _collect_vvar(e.r)
        elif isinstance(e, ir.Un):
            _collect_vvar(e.e)
        elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
            _collect_vvar(e.addr)
        elif isinstance(e, ir.IntrExpr):
            for a in e.args:
                _collect_vvar(a)

    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            if isinstance(s, ir.Assign):
                _collect_vvar(s.dst)
                _collect_vvar(s.src)
            elif isinstance(s, ir.Call):
                if s.args:
                    for a in s.args:
                        _collect_vvar(a)
                if s.expr:
                    _collect_vvar(s.expr)
            elif isinstance(s, ir.Branch):
                if isinstance(s.cexpr, ir.Expr):
                    _collect_vvar(s.cexpr)
            elif isinstance(s, ir.Switch) and isinstance(s.expr, ir.Expr):
                _collect_vvar(s.expr)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    _collect_vvar(a)

    if frame_info:
        frame_info.virtual_vars = virtual_vars
    func.virtual_vars = virtual_vars
    return func
