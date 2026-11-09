"""
Control-flow graph for LatticeMico32 (LM32).
Carves decoded instructions into basic blocks and functions, and lifts each block into IR.

LM32 instructions are fixed 32-bit (4-byte aligned).
Flow termination:
- ret / eret / bret ends a block with term='ret'
- bi(target) ends a block with term='goto' (or tail call if target is outside body)
- b(rX) ends a block (return if rX is ra, switch if switch_info attached, else indirect jump)
- be / bne / bg / bge / bgu / bgeu end a block with term='branch'
- calli / call fall through to ea + 4
"""

from . import ir, isa
from .lifter import lift_insn
from .decoder import target_of, SwitchInfo


class Block:
    __slots__ = ("start", "insns", "stmts", "succ", "term")

    def __init__(self, start):
        self.start = start
        self.insns = []
        self.stmts = []
        self.succ = []
        self.term = None


class Func:
    __slots__ = ("entry", "blocks", "calls", "name", "locals", "stack_args", "virtual_vars")

    def __init__(self, entry):
        self.entry = entry
        self.blocks = {}
        self.calls = set()
        self.name = None
        self.locals = {}
        self.stack_args = {}
        self.virtual_vars = {}

    def ordered(self):
        return [self.blocks[k] for k in sorted(self.blocks)]


def _succ(ins, bounds_to_sw=None):
    bounds_to_sw = bounds_to_sw or {}
    m = ins.mnem
    if ins.ea in bounds_to_sw:
        sw = bounds_to_sw[ins.ea]
        # When bounds check is bypassed for the switch, jump to default if out of bounds
        return [("default", sw.default_ea), ("fall", ins.ea + 4)]

    if m in isa.RET:
        return []

    if m in isa.COND_BRANCH:
        tgt = target_of(ins)
        return [("cond", tgt), ("fall", ins.ea + 4)]

    if m == "bi":
        tgt = target_of(ins)
        return [("jump", tgt)] if tgt is not None else []

    if m == "b":
        if ins.switch_info is not None:
            sw = ins.switch_info
            res = [("case", t) for _, t in sw.cases]
            if sw.default_ea is not None:
                res.append(("default", sw.default_ea))
            return res
        tgt = target_of(ins)
        return [("jump", tgt)] if tgt is not None else []

    if m in ("raise", "break", "scall"):
        return []

    # Sequential instructions and calls fall through to next 4-byte instruction
    return [("fall", ins.ea + 4)]


def _collect_body(insns, entry, entry_set):
    """Reachability traversal collecting instruction addresses for one function."""
    body = set()
    work = [entry]
    while work:
        ea = work.pop()
        if ea in body or ea not in insns:
            continue
        body.add(ea)
        ins = insns[ea]
        for how, tgt in _succ(ins):
            if tgt in insns and (tgt == entry or tgt not in entry_set):
                work.append(tgt)
    return body


def _discover_switches(insns, body, image=None, base=0, is_be=False):
    """Detect jump table patterns leading up to an indirect jump `b rX`."""
    bounds_to_sw = {}
    setup_skip = set()

    for ea in sorted(body):
        ins = insns[ea]
        if ins.mnem != "b" or not ins.ops or ins.ops[0].mode != "reg":
            continue
        dest_reg = ins.ops[0].reg
        if dest_reg == 29:  # ret
            continue

        # Look backwards up to 16 instructions within body
        prev_eas = [e for e in sorted(body) if ea - 64 <= e < ea]
        if not prev_eas:
            continue

        # Pattern:
        #   cmpgui r_cmp, r_idx, max_case
        #   bne r_cmp, r0, default_ea
        #   ...
        #   sli r_off, r_idx, 2
        #   mvhi r_tbl, hi16
        #   ori r_tbl, r_tbl, lo16
        #   add r_ptr, r_off, r_tbl
        #   lw r_dest, (r_ptr+0)
        #   b r_dest
        lw_ins = insns.get(prev_eas[-1]) if prev_eas else None
        if not lw_ins or lw_ins.mnem != "lw":
            continue

        ptr_reg = lw_ins.ops[1].base_reg if (lw_ins.ops and len(lw_ins.ops) >= 2 and lw_ins.ops[1].mode in ("displ", "phrase")) else None
        if ptr_reg is None:
            continue

        add_ins = None
        table_ea = None
        idx_reg = None
        max_cases = None
        default_ea = None
        bounds_ea = None

        # Search for add and sli
        for pe in reversed(prev_eas[:-1]):
            pi = insns[pe]
            if pi.mnem == "add" and len(pi.ops) == 3 and pi.ops[0].reg == ptr_reg:
                add_ins = pi
            elif pi.mnem == "sli" and len(pi.ops) == 3 and pi.ops[2].value == 2:
                idx_reg = pi.ops[1].reg
            elif pi.mnem in ("bne", "be") and len(pi.ops) == 3 and default_ea is None:
                default_ea = pi.ops[2].addr
                bounds_ea = pe
            elif pi.mnem == "cmpgui" and len(pi.ops) == 3 and max_cases is None:
                max_cases = pi.ops[2].value + 1

        # Check for mvhi + ori address composition for table_ea
        hi16, lo16 = None, None
        for pe in prev_eas:
            pi = insns[pe]
            if pi.mnem == "mvhi" and len(pi.ops) == 2:
                hi16 = pi.ops[1].value
            elif pi.mnem == "ori" and len(pi.ops) == 3 and hi16 is not None:
                lo16 = pi.ops[2].value
                table_ea = (hi16 << 16) | lo16

        if table_ea is not None and max_cases is not None and 1 < max_cases <= 256:
            # Read cases from table
            cases = []
            targets = set()
            if image is not None:
                from .decoder import read_u32
                for c in range(max_cases):
                    t = read_u32(image, table_ea + c * 4, base=base, is_be=is_be)
                    if t is not None:
                        cases.append((c, t))
                        targets.add(t)
            sw = SwitchInfo(
                jmp_ea=ea,
                table_ea=table_ea,
                ncases=max_cases,
                lowcase=0,
                default_ea=default_ea,
                bounds_ea=bounds_ea,
                idx_reg=idx_reg if idx_reg is not None else 1,
                cases=cases,
                targets=list(targets),
                setup_eas=prev_eas
            )
            ins.switch_info = sw
            if bounds_ea is not None:
                bounds_to_sw[bounds_ea] = sw
            for pe in prev_eas:
                setup_skip.add(pe)

    return bounds_to_sw, setup_skip


def _leaders(insns, body, bounds_to_sw):
    leaders = set()
    for ea in body:
        ins = insns[ea]
        for how, tgt in _succ(ins, bounds_to_sw):
            if how in ("cond", "jump", "case", "default") and tgt in body:
                leaders.add(tgt)
        if ea in bounds_to_sw:
            continue
        if ins.mnem in isa.COND_BRANCH or ins.mnem in isa.CALL or ins.mnem in isa.STOP:
            nxt = ea + 4
            if nxt in body:
                leaders.add(nxt)
    return leaders


def build_func(insns, entry, entry_set, image=None, base=0, is_be=False):
    body = _collect_body(insns, entry, entry_set)
    if not body:
        return None

    bounds_to_sw, setup_skip = _discover_switches(insns, body, image=image, base=base, is_be=is_be)
    leaders = _leaders(insns, body, bounds_to_sw)
    leaders.add(entry)

    f = Func(entry)
    cur = None
    for ea in sorted(body):
        ins = insns[ea]
        if ea in leaders or cur is None:
            cur = Block(ea)
            f.blocks[ea] = cur
        cur.insns.append(ins)
        succ = _succ(ins, bounds_to_sw)
        nxt = ea + 4
        term = None

        if ea in bounds_to_sw:
            if nxt in leaders or nxt not in body:
                term = ("fall", [("fall", nxt)] if nxt in body else [])
        elif ins.mnem == "b" and ins.switch_info is not None:
            term = ("switch", succ)
        elif ins.mnem == "bi" and target_of(ins) is not None and target_of(ins) not in body:
            # Tail call
            term = ("ret", [])
        elif ins.mnem == "bi":
            term = ("goto", succ)
        elif ins.mnem in isa.RET:
            term = ("ret", [])
        elif ins.mnem == "b" and ins.ops and ins.ops[0].reg == 29:
            term = ("ret", [])
        elif ins.mnem == "b":
            term = ("goto", succ)
        elif ins.mnem in isa.COND_BRANCH:
            term = ("branch", succ)
        elif ins.mnem in ("raise", "break", "scall"):
            term = ("stop", [])
        elif nxt in leaders or nxt not in body:
            term = ("fall", [("fall", nxt)] if nxt in body else [])

        if term is not None:
            cur.term, cur.succ = term
            cur = None

    for b in f.blocks.values():
        for ins in b.insns:
            if ins.mnem in isa.CALL and target_of(ins) is not None:
                f.calls.add(target_of(ins))
            if ins.ea in setup_skip:
                continue
            if ins.mnem == "bi" and target_of(ins) is not None and target_of(ins) not in body:
                tgt = target_of(ins)
                f.calls.add(tgt)
                b.stmts.append(ir.Call(ins.ea, target=tgt, is_tail=True))
                b.stmts.append(ir.Ret(ins.ea, "ret"))
                continue
            lifted = lift_insn(ins)
            b.stmts.extend(lifted)

    return f


def build_functions(insns, calls, extra_entries=(), image=None, base=0, is_be=False):
    entry_set = {e for e in (set(calls) | set(extra_entries)) if e in insns}
    funcs = {}
    for entry in sorted(entry_set):
        fn = build_func(insns, entry, entry_set, image=image, base=base, is_be=is_be)
        if fn is not None:
            funcs[entry] = fn
    return funcs
