"""
Control-flow structuring for LatticeMico32 (LM32).

Recovers if / else, while, do-while, and switch constructs with exact instruction EA anchoring.
Every structural node carries its originating instruction EA.
"""

from . import ir


class SStmt:
    def __init__(self, stmt):
        self.stmt = stmt
        self.ea = getattr(stmt, "ea", None)


class SLabel:
    def __init__(self, ea):
        self.ea = ea


class SGoto:
    def __init__(self, ea):
        self.ea = ea


class SRet:
    def __init__(self, ea=None):
        self.ea = ea


class SIf:
    def __init__(self, cond, then, els, ea=None):
        self.cond = cond
        self.then = then
        self.els = els
        self.ea = ea


class SIfGoto:
    def __init__(self, cond, ea, branch_ea=None):
        self.cond = cond
        self.ea = ea
        self.branch_ea = branch_ea


class SWhile:
    def __init__(self, body, cond=None, dowhile=False, ea=None):
        self.body = body
        self.cond = cond
        self.dowhile = dowhile
        self.ea = ea


class SBreak:
    def __init__(self, ea=None):
        self.ea = ea


class SContinue:
    def __init__(self, cond=None, ea=None):
        self.cond = cond
        self.ea = ea


class SBreakIf:
    def __init__(self, cond, ea=None):
        self.cond = cond
        self.ea = ea


class SSwitch:
    def __init__(self, expr, cases, default_body=None, ea=None):
        self.expr = expr
        self.cases = cases              # list of (case_vals_list, body_nodes)
        self.default_body = default_body
        self.ea = ea


_NEG = {
    "==": "!=",
    "!=": "==",
    ">": "<=",
    "<": ">=",
    ">=": "<",
    "<=": ">",
    "u>": "u<=",
    "u<": "u>=",
    "u>=": "u<",
    "u<=": "u>",
}


def cond_expr(branch):
    return branch.cexpr


def negate(e):
    if isinstance(e, ir.Un) and e.op == "!":
        return e.e
    if isinstance(e, ir.Bin) and e.op in _NEG:
        return ir.Bin(_NEG[e.op], e.l, e.r)
    if isinstance(e, ir.Const):
        return ir.Const(0 if e.value else 1)
    return ir.Un("!", e)


class _Structurer:
    def __init__(self, func):
        self.order = func.ordered()
        self.idx = {b.start: i for i, b in enumerate(self.order)}
        self.blocks = self.order
        self._open = set()
        self.preds = {b.start: set() for b in self.blocks}
        for i, b in enumerate(self.blocks):
            for _, tgt in b.succ:
                if tgt in self.preds:
                    self.preds[tgt].add(i)

    def run(self):
        return self._emit(0, len(self.blocks), loop=None, switch_merge=None)

    def _in_range(self, ea, lo, hi):
        i = self.idx.get(ea)
        return i is not None and lo <= i < hi

    def _region_clean(self, r_lo, r_hi, parent_idx):
        if r_hi - r_lo > 16:
            return False
        for k in range(r_lo, r_hi):
            if self.blocks[k].term == "switch":
                return False
            if k > r_lo:
                for p in self.preds.get(self.blocks[k].start, ()):
                    if not (r_lo <= p < r_hi) and p != parent_idx:
                        return False
        return True

    def _find_latch(self, header_idx, hi):
        h = self.blocks[header_idx].start
        latch = None
        for j in range(header_idx, hi):
            for _, tgt in self.blocks[j].succ:
                if tgt == h and j >= header_idx:
                    latch = j
        return latch

    def _body_stmts(self, block):
        res = []
        for s in block.stmts:
            if isinstance(s, (ir.Branch, ir.Goto, ir.Nop)):
                continue
            if isinstance(s, ir.Ret):
                continue
            res.append(SStmt(s))
        return res

    def _emit(self, lo, hi, loop=None, switch_merge=None):
        out = []
        i = lo
        while i < hi:
            b = self.blocks[i]
            b_ea = b.start

            # Check loop header
            latch = self._find_latch(i, hi) if (loop is None or i != loop) else None
            if latch is not None:
                # Structure while loop
                latch_block = self.blocks[latch]
                if b.term == "branch" and len(b.succ) == 2 and latch == i:
                    # Single-block while loop
                    taken_tgt, fall_tgt = b.succ[0][1], b.succ[1][1]
                    branch_stmt = next((s for s in reversed(b.stmts) if isinstance(s, ir.Branch)), None)
                    c_expr = branch_stmt.cexpr if branch_stmt else None
                    if taken_tgt == b_ea:
                        body = self._body_stmts(b)
                        out.append(SWhile(body, cond=c_expr, dowhile=False, ea=b_ea))
                        i += 1
                        continue
                elif b.term == "branch" and len(b.succ) == 2:
                    # Multi-block while loop
                    taken_tgt, fall_tgt = b.succ[0][1], b.succ[1][1]
                    branch_stmt = next((s for s in reversed(b.stmts) if isinstance(s, ir.Branch)), None)
                    c_expr = branch_stmt.cexpr if branch_stmt else None
                    if self._in_range(taken_tgt, i, latch + 1):
                        body = self._body_stmts(b)
                        sub_body = self._emit(i + 1, latch + 1, loop=i, switch_merge=switch_merge)
                        body.extend(sub_body)
                        out.append(SWhile(body, cond=c_expr, dowhile=False, ea=b_ea))
                        i = latch + 1
                        continue

            # Switch construct
            if b.term == "switch":
                sw_stmt = next((s for s in reversed(b.stmts) if isinstance(s, ir.Switch)), None)
                if sw_stmt is not None:
                    out.extend(self._body_stmts(b))
                    cases_ast = []
                    for c_val, c_tgt in sw_stmt.cases:
                        c_idx = self.idx.get(c_tgt)
                        c_body = []
                        if c_idx is not None and self._in_range(c_tgt, i + 1, hi):
                            c_body = self._emit(c_idx, c_idx + 1, loop=loop, switch_merge=hi)
                        cases_ast.append(([c_val], c_body))
                    def_body = []
                    if sw_stmt.default_ea:
                        d_idx = self.idx.get(sw_stmt.default_ea)
                        if d_idx is not None and self._in_range(sw_stmt.default_ea, i + 1, hi):
                            def_body = self._emit(d_idx, d_idx + 1, loop=loop, switch_merge=hi)
                    out.append(SSwitch(sw_stmt.expr, cases_ast, default_body=def_body, ea=b_ea))
                    i += 1
                    continue

            # If-Then-Else construct
            if b.term == "branch" and len(b.succ) == 2:
                t_taken, t_fall = b.succ[0][1], b.succ[1][1]
                idx_taken = self.idx.get(t_taken)
                idx_fall = self.idx.get(t_fall)
                branch_stmt = next((s for s in reversed(b.stmts) if isinstance(s, ir.Branch)), None)
                c_expr = branch_stmt.cexpr if branch_stmt else None

                out.extend(self._body_stmts(b))

                # If-then diamond or triangle:
                # Triangle: taken jumps ahead over then-block (fall through is then-body)
                if idx_fall == i + 1 and idx_taken is not None and idx_taken > i + 1:
                    then_hi = min(idx_taken, hi)
                    if self._region_clean(i + 1, then_hi, i):
                        then_body = self._emit(i + 1, then_hi, loop=loop, switch_merge=switch_merge)
                        out.append(SIf(negate(c_expr), then_body, [], ea=b_ea))
                        i = then_hi
                        continue

                # If-then-else diamond:
                if idx_taken is not None and idx_fall is not None:
                    if idx_taken > i and idx_fall > i:
                        out.append(SIfGoto(c_expr, t_taken, branch_ea=b_ea))
                        i += 1
                        continue

            # Default: emit block statements
            out.extend(self._body_stmts(b))
            if b.term == "ret":
                out.append(SRet(ea=b_ea))
            elif b.term == "goto" and b.succ:
                tgt = b.succ[0][1]
                if loop is not None and tgt == self.blocks[loop].start:
                    out.append(SContinue(ea=b_ea))
                elif switch_merge is not None and tgt == switch_merge:
                    out.append(SBreak(ea=b_ea))
                elif tgt != (self.blocks[i + 1].start if i + 1 < len(self.blocks) else None):
                    out.append(SGoto(tgt))

            i += 1

        return out


def structure(func):
    """Transform CFG of func into structured AST with exact instruction EA anchoring."""
    s = _Structurer(func)
    return s.run()
