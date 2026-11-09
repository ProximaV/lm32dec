"""
IDA integration for lm32dec. Runs inside IDA Pro on a database opened with an LM32
processor module.
Supports both Big-Endian and Little-Endian firmware dynamically querying inf_is_be().
Reads bytes from the database, uses IDA's function boundaries as entry points,
and reuses IDA's names. IDA modules are imported lazily.
"""

from . import decoder, cfg, opt, frame, callargs, structure, cgen, db, abi, vars
from .names import Namer
from . import Program, Function, BANNER  # noqa: F401


class IdaNamer(Namer):
    def __init__(self):
        super().__init__()
        import ida_name, ida_bytes, ida_nalt, ida_segment
        self._n = ida_name
        self._b = ida_bytes
        self._nalt = ida_nalt
        self._seg = ida_segment
        self._str_cache = {}

    def code(self, ea):
        if ea is None:
            return "?"
        return self._n.get_name(ea) or super().code(ea)

    def label(self, ea):
        return self._n.get_name(ea) or super().label(ea)

    def data(self, ea):
        return self._n.get_name(ea) or super().data(ea)

    def string(self, key):
        if key is None:
            return None
        if key in self._str_cache:
            return self._str_cache[key]
        ea = key
        if isinstance(key, str):
            try:
                ea = self._n.get_name_ea(0, key)
                if ea == 0xFFFFFFFF or ea == 0xFFFFFFFFFFFFFFFF:
                    return None
            except Exception:
                return None
        val = self._lookup_string(ea)
        self._str_cache[key] = val
        return val

    def _lookup_string(self, ea):
        try:
            if not isinstance(ea, int) or ea < 0x1000:
                return None
            flags = self._b.get_flags(ea)
            is_str = self._b.is_strlit(flags)
            name = self._n.get_name(ea) or ""
            seg = self._seg.getseg(ea)
            if not seg:
                return None
            if seg.type == self._seg.SEG_CODE and not is_str:
                return None

            if is_str or name.startswith(("a", "asc_")):
                raw = self._b.get_strlit_contents(ea, -1, self._nalt.STRTYPE_C)
                if raw and all(32 <= b <= 126 or b in (9, 10, 13) for b in raw):
                    return raw.decode("latin-1")
            elif seg.type != self._seg.SEG_CODE and not name.startswith(("sub_", "loc_")):
                raw = self._b.get_strlit_contents(ea, 256, self._nalt.STRTYPE_C)
                if raw and len(raw) >= 2 and all(32 <= b <= 126 or b in (9, 10, 13) for b in raw):
                    return raw.decode("latin-1")
        except Exception:
            pass
        return None


class SegmentedImage:
    """Sparse segment-backed memory image that avoids reading unmapped address gaps."""
    def __init__(self, segments, is_be=True):
        # segments: list of (start_ea, end_ea, bytearray) sorted by start_ea
        self.segments = sorted(segments, key=lambda s: s[0])
        self.base = self.segments[0][0] if self.segments else 0
        self._total = sum(len(b) for _, _, b in self.segments)
        self.is_be = is_be

    def __len__(self):
        return self._total

    def contains(self, ea, size=1):
        for start, end, _ in self.segments:
            if start <= ea:
                if ea + size <= end:
                    return True
            else:
                break
        return False

    def get_u16(self, ea):
        for start, end, buf in self.segments:
            if start <= ea:
                if ea + 2 <= end:
                    off = ea - start
                    if self.is_be:
                        return (buf[off] << 8) | buf[off + 1]
                    else:
                        return buf[off] | (buf[off + 1] << 8)
            else:
                break
        return None

    def get_u32(self, ea):
        for start, end, buf in self.segments:
            if start <= ea:
                if ea + 4 <= end:
                    off = ea - start
                    if self.is_be:
                        return ((buf[off] << 24) | (buf[off + 1] << 16)
                                | (buf[off + 2] << 8) | buf[off + 3])
                    else:
                        return (buf[off] | (buf[off + 1] << 8)
                                | (buf[off + 2] << 16) | (buf[off + 3] << 24))
            else:
                break
        return None


_ARITY_CACHE = {}
_RET_CACHE = {}


def _is_be():
    try:
        import ida_ida
        return ida_ida.inf_is_be()
    except Exception:
        return True


def _image():
    import ida_bytes, ida_segment
    is_be = _is_be()
    segments = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        start, end = seg.start_ea, seg.end_ea
        size = end - start
        if 0 < size <= 0x4000000 and ida_bytes.is_loaded(start):
            data = ida_bytes.get_bytes(start, size)
            if data:
                segments.append((start, end, bytearray(data)))
        seg = ida_segment.get_next_seg(start)
    if not segments:
        return None, 0, is_be
    img = SegmentedImage(segments, is_be=is_be)
    return img, img.base, is_be


def _entries():
    import idautils
    return sorted(idautils.Functions())


def _resolve_op_name(ea, n, op=None):
    """Resolve an instruction operand to a named symbol in IDA using structured instruction decoding and flags."""
    try:
        import ida_ua, ida_name, ida_bytes, idautils
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) > 0 and n < len(insn.ops):
            ida_op = insn.ops[n]
            if ida_op.type != ida_ua.o_void:
                # 1. Direct memory or code target
                if ida_op.type in (ida_ua.o_mem, ida_ua.o_near):
                    target_ea = ida_op.addr
                    sym = ida_name.get_ea_name(target_ea, ida_name.GN_NOT_DUMMY)
                    if sym:
                        return sym
                    tflags = ida_bytes.get_flags(target_ea)
                    if ida_bytes.has_user_name(tflags):
                        return ida_name.get_name(target_ea)
                # 2. Immediate operand marked as offset or referencing mapped address
                elif ida_op.type == ida_ua.o_imm:
                    flags = ida_bytes.get_flags(ea)
                    val = ida_op.value & 0xFFFFFFFF
                    if ida_bytes.is_off(flags, n) or (0x1000 <= val < 0xFFFFFFFF):
                        sym = ida_name.get_ea_name(val, ida_name.GN_NOT_DUMMY)
                        if sym:
                            return sym
                        vflags = ida_bytes.get_flags(val)
                        if ida_bytes.has_user_name(vflags):
                            return ida_name.get_name(val)

        # 3. Data cross references from this instruction
        for x in idautils.XrefsFrom(ea):
            if not x.iscode:
                sym = ida_name.get_ea_name(x.to, ida_name.GN_NOT_DUMMY)
                if sym:
                    return sym
                xflags = ida_bytes.get_flags(x.to)
                if ida_bytes.has_user_name(xflags):
                    return ida_name.get_name(x.to)

        # 4. Fallback to decoder op value if provided
        if op is not None:
            val = getattr(op, "value", None) or getattr(op, "addr", None)
            if val is not None and isinstance(val, int) and (val >= 0x1000):
                sym = ida_name.get_ea_name(val, ida_name.GN_NOT_DUMMY)
                if sym:
                    return sym
                val_flags = ida_bytes.get_flags(val)
                if ida_bytes.has_user_name(val_flags):
                    return ida_name.get_name(val)
    except Exception:
        pass
    return None


def _annotate_operand_names(insns):
    """Annotate operands of instructions with resolved symbol names from IDA."""
    for ins in insns.values():
        for n, op in enumerate(ins.ops):
            if getattr(op, "mode", None) in ("imm", "near", "mem"):
                sym = _resolve_op_name(ins.ea, n, op)
                if sym:
                    op.name = sym


class _IdaFrameInfo:
    def __init__(self, members=None, stkvars_by_ea=None):
        self.members = members or {}
        self.stkvars_by_ea = stkvars_by_ea or {}


def _ida_frame_info(ea):
    """Read stack frame structure details and stack variable operands from IDA Pro using native API."""
    try:
        import ida_funcs, ida_frame, ida_typeinf, ida_ua
        from ida_idaapi import BADADDR
        pfn = ida_funcs.get_func(ea)
        if not pfn:
            return None
        tif = ida_typeinf.tinfo_t()
        members = {}
        if ida_frame.get_func_frame(tif, pfn):
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                frsize = getattr(pfn, "frsize", 0)
                for m in udt:
                    actual_off = (m.offset // 8) - frsize
                    members[actual_off] = (m.name, m.size // 8, m.type.dstr())

        off_args = ida_frame.frame_off_args(pfn)
        stkvars_by_ea = {}
        cur = pfn.start_ea
        insn = ida_ua.insn_t()
        while cur < pfn.end_ea:
            if ida_ua.decode_insn(insn, cur) > 0:
                for n in range(6):
                    op = insn.ops[n]
                    if op.type == ida_ua.o_void:
                        break
                    soff = ida_frame.calc_stkvar_struc_offset(pfn, insn, n)
                    if soff != BADADDR and soff is not None:
                        if soff >= (1 << 63):
                            soff -= (1 << 64)
                        m = members.get(soff)
                        name = m[0] if m else ida_frame.build_stkvar_name(pfn, soff)
                        size = m[1] if m else 4
                        if soff < 0:
                            is_arg = False
                            if name.startswith("arg_"):
                                name = "var_%X" % abs(soff)
                        else:
                            is_arg = (soff >= off_args) if off_args != BADADDR else name.startswith("arg_")
                        stkvars_by_ea.setdefault(cur, {})[n] = (soff, name, size, is_arg)
            cur += insn.size if insn.size > 0 else 4
        return _IdaFrameInfo(members=members, stkvars_by_ea=stkvars_by_ea)
    except Exception:
        return None


def _get_ida_func_proto(ea):
    """Retrieve function prototype from IDA type system if set."""
    try:
        import ida_typeinf, ida_name
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.get_tinfo(tif, ea):
            name = ida_name.get_name(ea) or ("sub_%X" % ea)
            return tif.dstr() + " " + name
    except Exception:
        pass
    return None


def decode_insn_via_ida(ea):
    """Decode a single instruction at ea using IDA's native instruction decoding API (ida_ua.decode_insn)."""
    try:
        import ida_ua
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return None
        res = decoder.Insn(ea)
        res.size = insn.size
        res.mnem = insn.get_canon_mnem().lower()
        if res.mnem == "mvu":
            res.mnem = "mvui"
        for n in range(6):
            op = insn.ops[n]
            if op.type == ida_ua.o_void:
                break
            if op.type == ida_ua.o_reg:
                res.ops.append(decoder.Operand("reg", reg=op.reg))
            elif op.type == ida_ua.o_imm:
                res.ops.append(decoder.Operand("imm", value=op.value & 0xFFFFFFFF))
            elif op.type == ida_ua.o_near:
                res.ops.append(decoder.Operand("near", addr=op.addr & 0xFFFFFFFF))
            elif op.type == ida_ua.o_displ:
                disp = op.addr
                if disp >= (1 << 31):
                    disp -= (1 << 64) if disp >= (1 << 63) else (1 << 32)
                w = ida_ua.get_dtype_size(op.dtype) or 4
                mode = "phrase" if disp == 0 else "displ"
                res.ops.append(decoder.Operand(mode, base_reg=op.reg, disp=disp, width=w))
            elif op.type == ida_ua.o_phrase:
                w = ida_ua.get_dtype_size(op.dtype) or 4
                res.ops.append(decoder.Operand("phrase", base_reg=op.reg, disp=0, width=w))
            elif op.type == ida_ua.o_mem:
                res.ops.append(decoder.Operand("near", addr=op.addr & 0xFFFFFFFF))
        return res
    except Exception:
        return None


def decode_func_via_ida(pfn):
    """Decode all instructions in an IDA function pfn using the native IDA API."""
    try:
        import ida_ua, ida_idp, ida_funcs
        insns = {}
        calls = set()
        insn_t = ida_ua.insn_t()
        for item_ea in ida_funcs.Addresses(pfn):
            ins = decode_insn_via_ida(item_ea)
            if ins is not None:
                insns[item_ea] = ins
                if ida_ua.decode_insn(insn_t, item_ea) > 0:
                    feat = insn_t.get_canon_feature()
                    if feat & ida_idp.CF_CALL:
                        tgt = decoder.target_of(ins)
                        if tgt is not None:
                            calls.add(tgt)
        return insns, calls
    except Exception:
        return None, None


def _get_caller_consensus(entry):
    """Infer whether callers set parameter registers (r1..r8) before calling entry using native instruction flags."""
    try:
        import idautils, ida_ua, ida_idp, ida_bytes, ida_idaapi
        caller_eas = list(idautils.CodeRefsTo(entry, 0))
        if not caller_eas:
            return None
        counts = {i: 0 for i in range(1, 9)}
        valid = 0
        insn = ida_ua.insn_t()
        for c in caller_eas:
            cur = c
            found = set()
            count = 0
            while cur != ida_idaapi.BADADDR and cur >= c - 48 and count < 12:
                cur = ida_bytes.prev_head(cur, 0)
                if cur == ida_idaapi.BADADDR:
                    break
                if ida_ua.decode_insn(insn, cur) == 0:
                    break
                count += 1
                feat = insn.get_canon_feature()
                if (feat & ida_idp.CF_STOP) and cur != c:
                    break
                # Check destination operand if it modifies r1..r8
                if (feat & ida_idp.CF_CHG1) and len(insn.ops) > 0 and insn.ops[0].type == ida_ua.o_reg:
                    reg_idx = insn.ops[0].reg
                    if 1 <= reg_idx <= 8 and reg_idx not in found:
                        found.add(reg_idx)
                if (feat & ida_idp.CF_CALL):
                    break
            valid += 1
            for regnum in found:
                counts[regnum] += 1
        if valid == 0:
            return None
        res = {}
        for r in range(1, 9):
            if (counts[r] / valid) >= 0.75:
                res[f"r{r}"] = True
        return res if res else None
    except Exception:
        return None


def _find_entry(image, base, ea, entset, is_be=True):
    """If ea is inside an un-functioned routine in IDA, locate its entry using instruction boundaries."""
    if ea in entset:
        return ea
    try:
        import ida_bytes, ida_ua, ida_idp, ida_idaapi
        cur = ea
        insn = ida_ua.insn_t()
        limit = max(base, cur - 0x400)
        while cur > limit:
            prev = ida_bytes.prev_head(cur, base)
            if prev == ida_idaapi.BADADDR:
                break
            if prev in entset:
                return prev
            if ida_ua.decode_insn(insn, prev) > 0:
                feat = insn.get_canon_feature()
                # Unconditional returns/stops in LM32 have CF_STOP
                if (feat & ida_idp.CF_STOP):
                    return cur
                if insn.itype == getattr(ida_idp, "LM32_INSN_NOP", -1) or insn.get_canon_mnem().lower() == "nop":
                    prev2 = ida_bytes.prev_head(prev, base)
                    if prev2 != ida_idaapi.BADADDR and ida_ua.decode_insn(insn, prev2) > 0:
                        if (insn.get_canon_feature() & ida_idp.CF_STOP):
                            return cur
            cur = prev
        if cur != ea:
            return cur
    except Exception:
        pass

    cur = ea & ~3
    limit = max(base, cur - 0x400)
    best = cur
    while cur > limit:
        prev4 = cur - 4
        ins4 = decoder.decode_one(image, prev4, base, is_be=is_be) if decoder.in_bounds(image, prev4, base, 4) else None
        if ins4 is not None:
            if ins4.mnem in ("eret", "bret", "bi"):
                return cur
            if ins4.mnem == "b" and getattr(ins4.ops[0], "reg", None) == 29:
                return cur
            if ins4.mnem == "nop":
                ins_before = decoder.decode_one(image, prev4 - 4, base, is_be=is_be)
                if ins_before is not None:
                    if ins_before.mnem in ("eret", "bret", "bi") or (ins_before.mnem == "b" and getattr(ins_before.ops[0], "reg", None) == 29):
                        return cur
        if prev4 in entset:
            return prev4
        cur -= 4
    return best


def _callee_arity(image, base, callee_ea, entset, is_be=True):
    if callee_ea in _ARITY_CACHE:
        return _ARITY_CACHE[callee_ea]
    stop = entset - {callee_ea}
    c_insns, _ = decoder.decode(image, entries=[callee_ea], base=base, stop_at=stop, is_be=is_be)
    c_func = cfg.build_func(c_insns, callee_ea, entset)
    if c_func is None:
        return None
    frame_info = frame.analyze_frame(c_func)
    opt.optimize(c_func)
    cons = _get_caller_consensus(callee_ea)
    sig = abi.analyze_calling_convention(c_func, frame_info=frame_info, caller_consensus=cons)
    n = len(sig.params)
    _ARITY_CACHE[callee_ea] = n
    _RET_CACHE[callee_ea] = sig.ret_type
    return n


def decompile_program():
    image, base, is_be = _image()
    if image is None:
        raise RuntimeError("lm32dec: no segments loaded")
    entries = _entries() or [base]

    insns = None
    calls = None
    try:
        import idautils, ida_funcs
        all_funcs = list(idautils.Functions())
        if all_funcs:
            insns = {}
            calls = set()
            for fn_ea in all_funcs:
                pfn = ida_funcs.get_func(fn_ea)
                if pfn:
                    fn_insns, fn_calls = decode_func_via_ida(pfn)
                    if fn_insns:
                        insns.update(fn_insns)
                        if fn_calls:
                            calls.update(fn_calls)
    except Exception:
        insns = None
        calls = None

    if not insns:
        insns, calls = decoder.decode(image, entries=entries, base=base, is_be=is_be)

    _annotate_operand_names(insns)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = IdaNamer()

    # Pre-populate arity cache
    for entry, f in funcs.items():
        frame_info = frame.analyze_frame(f)
        opt.optimize(f)
        cons = _get_caller_consensus(entry)
        sig = abi.analyze_calling_convention(f, frame_info=frame_info, caller_consensus=cons)
        _ARITY_CACHE[entry] = len(sig.params)
        _RET_CACHE[entry] = sig.ret_type

    out = {}
    for entry, f in funcs.items():
        db_data = db.get_func_data(entry)
        u_renames = db_data.get("renames", {})
        u_types = db_data.get("types", {})
        u_proto = db_data.get("proto") or _get_ida_func_proto(entry)

        ida_info = _ida_frame_info(entry)
        frame_info = frame.analyze_frame(f, ida_frame_info=ida_info)
        frame_info.user_renames = u_renames
        frame_info.user_types = u_types

        callargs.rewrite(f, _ARITY_CACHE)
        opt.optimize(f)
        consensus = _get_caller_consensus(entry)
        sig = abi.analyze_calling_convention(f, frame_info=frame_info, user_proto=u_proto,
                                             ret_types=_RET_CACHE, caller_consensus=consensus)
        vars.recover_variables(f, sig=sig, frame_info=frame_info)
        tree = structure.structure(f)
        u_comments = db_data.get("cmts", {})
        u_numforms = db_data.get("numforms", {})
        u_iflags = db_data.get("iflags", [])
        lines = cgen.generate(f, tree, namer, frame_info=frame_info, sig=sig,
                              user_renames=u_renames, user_types=u_types,
                              user_comments=u_comments, user_numforms=u_numforms,
                              user_iflags=u_iflags)
        out[entry] = Function(entry, namer.code(entry), f, tree, lines)
    return Program(image, base, insns, out, namer, is_be=is_be)


def decompile_one(ea, show_casts=True):
    import ida_funcs
    image, base, is_be = _image()
    if image is None:
        raise RuntimeError("lm32dec: no segments loaded")
    entset = set(_entries())
    f = ida_funcs.get_func(ea)
    entry = f.start_ea if f is not None else _find_entry(image, base, ea, entset, is_be=is_be)
    entset.add(entry)
    stop = entset - {entry}

    # If f is an IDA function, decode natively using IDA's instruction decoding API
    if f is not None:
        insns, calls = decode_func_via_ida(f)
    else:
        insns, calls = None, None

    if not insns:
        insns, calls = decoder.decode(image, entries=[entry], base=base, stop_at=stop, is_be=is_be)
    _annotate_operand_names(insns)

    # Check if entry is a switch case fragment belonging to a parent function
    for ins in insns.values():
        if getattr(ins, "switch", None) is not None and entry in ins.switch.targets:
            parent_f = ida_funcs.get_func(ins.ea)
            if parent_f and parent_f.start_ea != entry:
                entry = parent_f.start_ea
                break

    all_entries = entset | calls
    func = cfg.build_func(insns, entry, all_entries)
    if func is None:
        raise RuntimeError("lm32dec: nothing decoded at 0x%X" % entry)
    namer = IdaNamer()

    db_data = db.get_func_data(entry)
    u_renames = db_data.get("renames", {})
    u_types = db_data.get("types", {})
    u_proto = db_data.get("proto") or _get_ida_func_proto(entry)
    u_comments = db_data.get("cmts", {})
    u_numforms = db_data.get("numforms", {})
    u_iflags = db_data.get("iflags", [])

    ida_info = _ida_frame_info(entry)
    frame_info = frame.analyze_frame(func, ida_frame_info=ida_info)
    frame_info.user_renames = u_renames
    frame_info.user_types = u_types

    # Resolve direct callee arities
    arity = {}
    for callee in func.calls:
        ca = _callee_arity(image, base, callee, all_entries, is_be=is_be)
        if ca is not None:
            arity[callee] = ca
    callargs.rewrite(func, arity)

    opt.optimize(func)
    consensus = _get_caller_consensus(entry)
    sig = abi.analyze_calling_convention(func, frame_info=frame_info, user_proto=u_proto,
                                         ret_types=_RET_CACHE, caller_consensus=consensus)
    vars.recover_variables(func, sig=sig, frame_info=frame_info)
    tree = structure.structure(func)
    lines = cgen.generate(func, tree, namer, frame_info=frame_info, sig=sig, banner=None,
                          user_renames=u_renames, user_types=u_types,
                          user_comments=u_comments, user_numforms=u_numforms,
                          user_iflags=u_iflags, show_casts=show_casts)
    return Function(entry, namer.code(entry), func, tree, lines)
