"""
Pseudo-C back-end for the LatticeMico32 (LM32) decompiler.

Generates Hex-Rays parity C code:
- Register and virtual variable names (r1..r31, v0, v1, a0..a7).
- Memory reads and writes using Hex-Rays style pointer dereferences:
  *(_DWORD *), *(_WORD *), *(_BYTE *), *(short *), *(char *).
- Typed pointer array indexing (ptr[i]) and dereferences (*ptr).
- Relational conditional branches without flags layer.
- Structured if/else, while, do-while, switch/case.
- Dense instruction EA anchoring (100% instruction coverage for bidirectional sync).
- User overrides: renames, types, number formats, comments, if-inversions.
"""

from . import ir
from . import structure as S


_PRECEDENCE = {
    "*": 10, "/": 10, "%": 10,
    "+": 9, "-": 9,
    "<<": 8, ">>": 8,
    "<": 7, "<=": 7, ">": 7, ">=": 7,
    "==": 6, "!=": 6,
    "&": 5,
    "^": 4,
    "|": 3,
    "&&": 2,
    "||": 1,
}


class CodeLines(list):
    """List of generated C lines carrying parallel line_eas, line_to_eas, and ea_to_line mappings."""
    pass


def format_c_string(s):
    """Format string content as a standard C escaped double-quoted string literal."""
    if isinstance(s, bytes):
        try:
            s = s.decode("latin-1")
        except Exception:
            s = str(s)
    res = []
    for ch in s:
        if ch == '"':
            res.append(r'\"')
        elif ch == '\\':
            res.append(r'\\')
        elif ch == '\n':
            res.append(r'\n')
        elif ch == '\r':
            res.append(r'\r')
        elif ch == '\t':
            res.append(r'\t')
        elif ch == '\a':
            res.append(r'\a')
        elif ch == '\b':
            res.append(r'\b')
        elif ch == '\f':
            res.append(r'\f')
        elif ch == '\v':
            res.append(r'\v')
        elif 32 <= ord(ch) <= 126:
            res.append(ch)
        else:
            res.append(r'\x%02X' % ord(ch))
    return '"' + ''.join(res) + '"'


def format_c_char(v):
    """Format an integer as a standard C character literal."""
    if 0 <= v <= 255:
        ch = chr(v)
        if ch == "'":
            return r"'\''"
        elif ch == '\\':
            return r"'\\'"
        elif ch == '\n':
            return r"'\n'"
        elif ch == '\t':
            return r"'\t'"
        elif ch == '\r':
            return r"'\r'"
        elif ch == '\a':
            return r"'\a'"
        elif ch == '\b':
            return r"'\b'"
        elif 32 <= v <= 126:
            return f"'{ch}'"
        else:
            return r"'\x%02X'" % v
    chars = []
    temp = v
    while temp > 0:
        b = temp & 0xFF
        if 32 <= b <= 126 and chr(b) not in ("'", "\\"):
            chars.append(chr(b))
        else:
            return "0x%X" % v
        temp >>= 8
    return "'" + "".join(chars) + "'"


class _Emit:
    def __init__(self, namer, block_starts=frozenset(), returns_value=False, sig=None, hidden=frozenset(),
                 user_renames=None, user_types=None, user_numforms=None, user_iflags=None, show_casts=True):
        self.namer = namer
        self.block_starts = block_starts
        self.returns_value = returns_value
        self.sig = sig
        self.hidden = hidden
        self.user_renames = user_renames or {}
        self.user_types = user_types or {}
        self.user_numforms = user_numforms or {}
        self.user_iflags = set(user_iflags or [])
        self.show_casts = show_casts
        self.cur_ea = None
        self.used_labels = set()
        self._pending = []

    def _resolve_sym_name(self, v):
        if hasattr(self.namer, "code"):
            name = self.namer.code(v)
            if name and not name.startswith("?"):
                return name
        if hasattr(self.namer, "data"):
            name = self.namer.data(v)
            if name:
                return name
        return None

    def _invert_cond(self, cond):
        if isinstance(cond, ir.Bin):
            inv_map = {
                "==": "!=", "!=": "==",
                "<": ">=", ">=": "<",
                ">": "<=", "<=": ">",
                "u<": "u>=", "u>=": "u<",
                "u>": "u<=", "u<=": "u>",
            }
            if cond.op in inv_map:
                return ir.Bin(inv_map[cond.op], cond.l, cond.r)
        if isinstance(cond, ir.Un) and cond.op == "!":
            return cond.e
        return ir.Un("!", cond)

    def expr(self, e, top=True):
        if isinstance(e, ir.Const):
            v = e.value & 0xFFFFFFFF
            # Check custom number format override
            form = None
            if self.user_numforms:
                v_hex = hex(v)
                v_hex_lower = v_hex.lower()
                if self.cur_ea is not None:
                    ea_hex = hex(self.cur_ea)
                    ea_hex_lower = ea_hex.lower()
                    form = (self.user_numforms.get(f"{ea_hex}:{v_hex}")
                            or self.user_numforms.get(f"{ea_hex_lower}:{v_hex_lower}")
                            or self.user_numforms.get(f"{ea_hex}:{v}")
                            or self.user_numforms.get(f"{self.cur_ea}:{v_hex}")
                            or self.user_numforms.get(f"{self.cur_ea}:{v_hex_lower}")
                            or self.user_numforms.get(f"{self.cur_ea}:{v}")
                            or self.user_numforms.get((self.cur_ea, v_hex))
                            or self.user_numforms.get((self.cur_ea, v_hex_lower))
                            or self.user_numforms.get((self.cur_ea, v))
                            or self.user_numforms.get((ea_hex, v_hex))
                            or self.user_numforms.get((ea_hex_lower, v_hex_lower)))
                if not form:
                    form = (self.user_numforms.get(v_hex)
                            or self.user_numforms.get(v_hex_lower)
                            or self.user_numforms.get(str(v))
                            or self.user_numforms.get(v))

            if form:
                if form == "hex":
                    return "0x%X" % v
                elif form == "dec":
                    signed = (v - 0x100000000) if v >= 0x80000000 else v
                    return str(signed)
                elif form == "char":
                    return format_c_char(v)
                elif form in ("offset", "sym"):
                    sym = self._resolve_sym_name(v)
                    if sym:
                        return sym
                elif form == "invsign":
                    signed = (v - 0x100000000) if v >= 0x80000000 else v
                    return str(signed)
                elif form == "bnot":
                    inv = (~v) & 0xFFFFFFFF
                    return ("~0x%X" % inv) if inv >= 10 else f"~{inv}"

            if getattr(e, "name", None) and e.name in self.user_renames:
                return self.user_renames[e.name]
            if hasattr(self.namer, "string"):
                s = self.namer.string(e.value)
                if s is None and getattr(e, "name", None):
                    s = self.namer.string(e.name)
                if s is not None:
                    return format_c_string(s)
            if getattr(e, "name", None):
                return self.user_renames.get(e.name, e.name)
            return str(v) if v < 10 else "0x%X" % v

        if isinstance(e, (ir.Reg, ir.Var)):
            return self.user_renames.get(e.name, e.name)
        if isinstance(e, ir.Mem):
            return self._mem(e)
        if isinstance(e, ir.Bin):
            op, r = e.op, e.r
            # Render "+ 0xFFFFFFFF" (add #-1) etc. as a subtraction
            if op == "+" and isinstance(r, ir.Const) and r.value >= 0x80000000:
                op, r = "-", ir.Const((0x100000000 - r.value))
            rs = self.expr(r, False)
            s = "%s %s %s" % (self.expr(e.l, False), op, rs)
            return s if top else "(%s)" % s
        if isinstance(e, ir.Un):
            return "%s%s" % (e.op, self.expr(e.e, False))
        if isinstance(e, ir.IntrExpr):
            return "%s(%s)" % (e.name, ", ".join(self.expr(a) for a in e.args)) if e.args else e.name
        return "?"

    def _mem(self, e):
        # 1. Direct symbolic name on the Mem object
        if getattr(e, "name", None):
            return self.user_renames.get(e.name, e.name)

        # 2. Check if address is a constant with a known symbolic name in IDA / namer
        addr_val = None
        if isinstance(e.addr, ir.Const):
            if getattr(e.addr, "name", None):
                return self.user_renames.get(e.addr.name, e.addr.name)
            addr_val = e.addr.value
        elif isinstance(e.addr, int):
            addr_val = e.addr

        if addr_val is not None:
            sym = None
            if hasattr(self.namer, "data"):
                sym = self.namer.data(addr_val)
            elif hasattr(self.namer, "code_names"):
                sym = self.namer.code_names.get(addr_val)
            if sym and not sym.startswith(("sub_", "loc_")):
                return self.user_renames.get(sym, sym)

        # 3. Check if address is a base named symbol + offset or index
        if isinstance(e.addr, ir.Bin) and e.addr.op == "+":
            if isinstance(e.addr.l, ir.Const) and getattr(e.addr.l, "name", None):
                base_name = self.user_renames.get(e.addr.l.name, e.addr.l.name)
                return "%s[%s]" % (base_name, self.expr(e.addr.r))
            elif isinstance(e.addr.r, ir.Const) and getattr(e.addr.r, "name", None):
                base_name = self.user_renames.get(e.addr.r.name, e.addr.r.name)
                return "%s[%s]" % (base_name, self.expr(e.addr.l))

        # 4. Check if address is a typed pointer variable (*ptr)
        if isinstance(e.addr, (ir.Reg, ir.Var)):
            vname = e.addr.name
            vtype = self.user_types.get(vname, "")
            if vtype.endswith("*"):
                base_t = vtype[:-1].strip()
                t_size = 4 if base_t in ("int", "_DWORD", "uint32_t", "int32_t", "unsigned int") else (
                         2 if base_t in ("short", "_WORD", "uint16_t", "int16_t", "unsigned short") else (
                         1 if base_t in ("char", "_BYTE", "uint8_t", "int8_t", "unsigned char") else None))
                if t_size is None or t_size == e.width:
                    eff_name = self.user_renames.get(vname, vname)
                    return "*%s" % eff_name

        # 5. Check if address is ptr + offset for a typed pointer (ptr[idx])
        if isinstance(e.addr, ir.Bin) and e.addr.op == "+":
            if isinstance(e.addr.l, (ir.Reg, ir.Var)) and isinstance(e.addr.r, (ir.Const, int)):
                vname = e.addr.l.name
                offset_val = e.addr.r.value if isinstance(e.addr.r, ir.Const) else e.addr.r
                vtype = self.user_types.get(vname, "")
                if vtype.endswith("*"):
                    base_t = vtype[:-1].strip()
                    t_size = 4 if base_t in ("int", "_DWORD", "uint32_t", "int32_t", "unsigned int") else (
                             2 if base_t in ("short", "_WORD", "uint16_t", "int16_t", "unsigned short") else (
                             1 if base_t in ("char", "_BYTE", "uint8_t", "int8_t", "unsigned char") else None))
                    if t_size and e.width == t_size and offset_val % t_size == 0:
                        eff_name = self.user_renames.get(vname, vname)
                        idx = offset_val // t_size
                        return "%s[%d]" % (eff_name, idx)

        # 6. Default Hex-Rays cast dereference
        if not self.show_casts:
            cast = ""
        elif e.width == 4:
            cast = "_DWORD *"
        elif e.width == 2:
            cast = "short *" if e.signed else "_WORD *"
        elif e.width == 1:
            cast = "char *" if e.signed else "_BYTE *"
        else:
            cast = "_DWORD *"

        if isinstance(e.addr, ir.Expr):
            addr_str = self.expr(e.addr, top=False)
            if not self.show_casts:
                return "*%s" % (("(%s)" % addr_str) if " " in addr_str else addr_str)
            if addr_str.startswith("(") and addr_str.endswith(")"):
                return "*(%s)%s" % (cast, addr_str)
            elif " " in addr_str:
                return "*(%s)(%s)" % (cast, addr_str)
            else:
                return "*(%s)%s" % (cast, addr_str)
        else:
            if not self.show_casts:
                return "*0x%X" % e.addr
            return "*(%s)0x%X" % (cast, e.addr)

    def stmt(self, s):
        self.cur_ea = getattr(s, "ea", None)
        if isinstance(s, ir.Assign):
            if isinstance(s.dst, ir.Const) and s.dst.value == 0:
                return "%s;" % self.expr(s.src)
            return "%s = %s;" % (self.expr(s.dst), self.expr(s.src))
        if isinstance(s, ir.Call):
            args = ", ".join(self.expr(a) for a in (s.args or []))
            if s.target is not None:
                tgt_name = self.namer.code(s.target)
                tgt_name = self.user_renames.get(tgt_name, tgt_name)
                call_str = "%s(%s)" % (tgt_name, args)
            else:
                call_str = "(*%s)(%s)" % (self.expr(s.expr), args)
            if getattr(s, "is_tail", False):
                if self.returns_value:
                    return "return %s;" % call_str
                else:
                    return "%s;" % call_str
            return "%s;" % call_str
        if isinstance(s, ir.Intrinsic):
            call = "%s(%s);" % (s.name, ", ".join(self.expr(a) for a in s.args))
            return call + ("   /* %s */" % s.note if s.note else "")
        return "/* %s */" % type(s).__name__

    def _ext(self, ea):
        return self.namer.code(ea) if ea is not None else "?"

    def emit(self, nodes, ind):
        pad = "    " * ind
        for n in nodes:
            if isinstance(n, S.SLabel):
                self._pending.append((ind, None, n.ea, n.ea, [n.ea]))
            elif isinstance(n, S.SStmt):
                ea = getattr(n.stmt, "ea", None)
                inlined = list(getattr(n.stmt, "inlined_eas", []))
                all_eas = ([ea] if ea is not None else []) + inlined
                self._pending.append((ind, pad + self.stmt(n.stmt), None, ea, all_eas))
            elif isinstance(n, S.SRet):
                if self._pending and self._pending[-1][1] and self._pending[-1][1].strip().startswith("return "):
                    continue
                ea = getattr(n, "ea", None)
                if self.returns_value:
                    if self.sig and getattr(self.sig, "ret_type", None) == "uint64_t":
                        ret_expr = "return ((uint64_t)r2 << 32) | r1;"
                    else:
                        ret_expr = "return r1;"
                else:
                    ret_expr = "return;"
                self._pending.append((ind, pad + ret_expr, None, ea, [ea] if ea else []))
            elif isinstance(n, S.SGoto):
                ea = getattr(n, "ea", None)
                all_eas = [ea] if ea is not None else []
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    self._pending.append((ind, pad + "goto %s;" % self.namer.label(n.ea), None, ea, all_eas))
                else:
                    self._pending.append((ind, pad + "JUMPOUT(%s);" % self._ext(n.ea), None, ea, all_eas))
            elif isinstance(n, S.SIfGoto):
                br_ea = getattr(n, "branch_ea", None) or getattr(n, "ea", None)
                all_eas = [e for e in (br_ea, getattr(n, "ea", None)) if e is not None]
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    tail = "goto %s;" % self.namer.label(n.ea)
                else:
                    tail = "JUMPOUT(%s);" % self._ext(n.ea)
                self._pending.append((ind, pad + "if (%s) %s" % (self.expr(n.cond), tail), None, br_ea, all_eas))
            elif isinstance(n, S.SBreak):
                ea = getattr(n, "ea", None)
                self._pending.append((ind, pad + "break;", None, ea, [ea] if ea is not None else []))
            elif isinstance(n, S.SBreakIf):
                ea = getattr(n, "ea", None)
                self._pending.append((ind, pad + "if (%s) break;" % self.expr(n.cond), None, ea, [ea] if ea is not None else []))
            elif isinstance(n, S.SContinue):
                ea = getattr(n, "ea", None)
                all_eas = [ea] if ea is not None else []
                if n.cond is None:
                    self._pending.append((ind, pad + "continue;", None, ea, all_eas))
                else:
                    self._pending.append((ind, pad + "if (%s) continue;" % self.expr(n.cond), None, ea, all_eas))
            elif isinstance(n, S.SIf):
                ea = getattr(n, "ea", None)
                inverted = False
                if ea is not None and (ea in self.user_iflags or hex(ea) in self.user_iflags or str(ea) in self.user_iflags):
                    inverted = True

                cond_expr = n.cond
                then_body = n.then
                els_body = n.els

                if inverted:
                    cond_expr = self._invert_cond(cond_expr)
                    if els_body:
                        then_body, els_body = els_body, then_body

                self.cur_ea = ea
                self._pending.append((ind, pad + "if (%s) {" % self.expr(cond_expr), None, ea, [ea] if ea is not None else []))
                self.emit(then_body, ind + 1)
                if els_body:
                    self._pending.append((ind, pad + "} else {", None, None, []))
                    self.emit(els_body, ind + 1)
                self._pending.append((ind, pad + "}", None, None, []))
            elif isinstance(n, S.SWhile):
                self._emit_while(n, ind)
            elif isinstance(n, S.SSwitch):
                self._emit_switch(n, ind)

    def _emit_switch(self, n, ind):
        pad = "    " * ind
        ea = getattr(n, "ea", None)
        self._pending.append((ind, pad + "switch (%s) {" % self.expr(n.expr), None, ea, [ea] if ea is not None else []))
        for vals, arm in n.cases:
            for v in vals:
                v_str = str(v) if v < 10 else "0x%X" % v
                self._pending.append((ind, pad + "case %s:" % v_str, None, None, []))
            self.emit(arm, ind + 1)
        if n.default_body:
            self._pending.append((ind, pad + "default:", None, None, []))
            self.emit(n.default_body, ind + 1)
        self._pending.append((ind, pad + "}", None, None, []))

    def _emit_while(self, n, ind):
        pad = "    " * ind
        body = list(n.body)
        tail = None
        tail_ea = None
        ea = getattr(n, "ea", None)
        all_eas = [ea] if ea is not None else []
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is not None:
            tail = body[-1].cond
            tail_ea = getattr(body[-1], "ea", None)
            body = body[:-1]
        if tail is not None:
            self._pending.append((ind, pad + "do {", None, ea, all_eas))
            self.emit(body, ind + 1)
            t_eas = [tail_ea] if tail_ea is not None else []
            self._pending.append((ind, pad + "} while (%s);" % self.expr(tail), None, tail_ea, t_eas))
            return
        # Drop redundant unconditional `continue;` at the end of a while loop
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is None:
            body = body[:-1]
        # Check if the first statement after loop header label is `if (cond) break;`
        first_idx = None
        for idx, item in enumerate(body):
            if not isinstance(item, S.SLabel):
                first_idx = idx
                break
        if first_idx is not None and isinstance(body[first_idx], S.SBreakIf):
            wcond = S.negate(body[first_idx].cond)
            body = body[:first_idx] + body[first_idx + 1:]
            self._pending.append((ind, pad + "while (%s) {" % self.expr(wcond), None, ea, all_eas))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None, None, []))
        else:
            self._pending.append((ind, pad + "while (1) {", None, ea, all_eas))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None, None, []))

    def flush(self):
        out = []
        line_eas = []
        line_to_eas = {}
        for ind, text, label_ea, primary_ea, all_eas in self._pending:
            if label_ea is not None:
                if label_ea in self.used_labels:
                    lineno = len(out)
                    out.append("%s:" % self.namer.label(label_ea))
                    line_eas.append(label_ea)
                    line_to_eas[lineno] = [label_ea]
                continue
            lineno = len(out)
            out.append(text)
            line_eas.append(primary_ea)
            unique_eas = list(dict.fromkeys(e for e in all_eas if e is not None))
            line_to_eas[lineno] = unique_eas
        return out, line_eas, line_to_eas


def generate(func, tree, namer, frame_info=None, sig=None, banner=None,
             user_renames=None, user_types=None, user_comments=None,
             user_numforms=None, user_iflags=None, show_casts=True):
    hidden = getattr(frame_info, "hidden_stmts", frozenset()) if frame_info else frozenset()
    u_renames = dict(getattr(frame_info, "user_renames", {}) or {})
    if user_renames:
        u_renames.update(user_renames)
    u_types = dict(getattr(frame_info, "user_types", {}) or {})
    if user_types:
        u_types.update(user_types)

    returns_value = (sig.ret_type != "void") if sig else False
    em = _Emit(namer, block_starts=frozenset(func.blocks), returns_value=returns_value, sig=sig,
               hidden=hidden, user_renames=u_renames, user_types=u_types,
               user_numforms=user_numforms, user_iflags=user_iflags, show_casts=show_casts)
    em.emit(tree, 1)
    body, body_eas, body_line_to_eas = em.flush()

    if user_comments:
        for idx in range(len(body)):
            line_eas = body_line_to_eas.get(idx, [])
            for lea in line_eas:
                ea_key = hex(lea) if isinstance(lea, int) else str(lea)
                cmt = (user_comments.get(ea_key)
                       or user_comments.get(str(lea))
                       or (user_comments.get(lea) if isinstance(lea, int) else None))
                if cmt:
                    body[idx] = f"{body[idx]}  // {cmt}"
                    break

    out = CodeLines()
    if banner:
        out.extend(banner)

    fn_name = namer.code(func.entry)
    fn_name = u_renames.get(fn_name, fn_name)

    if sig is not None:
        ret_t = u_types.get("__return__", sig.ret_type)
        if sig.params:
            param_parts = []
            for p in sig.params:
                p_name = u_renames.get(p.name, p.name)
                p_type = u_types.get(p.name, u_types.get(p_name, p.type_str))
                sep = "" if p_type.endswith("*") else " "
                param_parts.append(f"{p_type}{sep}{p_name}")
            pstr = ", ".join(param_parts)
        else:
            pstr = "void"
        ret_sep = "" if ret_t.endswith("*") else " "
        out.append(f"{ret_t}{ret_sep}{fn_name}({pstr})")
    else:
        out.append(f"void {fn_name}(void)")

    out.append("{")
    decls = []

    # Stack variable declarations
    if frame_info and frame_info.locals:
        def sort_loc(kv):
            name = kv[0]
            if isinstance(name, str) and "_" in name and name.split("_")[1].isalnum():
                try:
                    return (0, int(name.split("_")[1], 16))
                except ValueError:
                    pass
            return (1, str(name))

        for name, size in sorted(frame_info.locals.items(), key=sort_loc):
            eff_name = u_renames.get(name, name)
            default_t = {1: "char", 2: "short", 4: "int"}.get(size, "int")
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            sep = "" if tstr.endswith("*") else " "
            decls.append(f"    {tstr}{sep}{eff_name};")

    # Virtual variable declarations
    vvars = getattr(frame_info, "virtual_vars", None) or getattr(func, "virtual_vars", None)
    if vvars:
        def sort_vvar(kv):
            name = kv[0]
            if name.startswith("v") and name[1:].isdigit():
                return (0, int(name[1:]))
            return (1, name)

        for name, entry in sorted(vvars.items(), key=sort_vvar):
            if frame_info and frame_info.locals and name in frame_info.locals:
                continue
            eff_name = u_renames.get(name, name)
            default_t = "int"
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            sep = "" if tstr.endswith("*") else " "
            decls.append(f"    {tstr}{sep}{eff_name};")

    if decls:
        out.extend(decls)
        if body:
            out.append("")

    header_count = len(out)
    out.header_count = header_count
    out.extend(body)
    out.append("}")
    out.line_eas = [None] * header_count + body_eas + [None]

    # Map line numbers to associated instruction EAs
    out.line_to_eas = {header_count + k: v for k, v in body_line_to_eas.items()}
    out.ea_to_line = {}
    for lineno, eas in out.line_to_eas.items():
        for ea in eas:
            if ea not in out.ea_to_line:
                out.ea_to_line[ea] = lineno

    # Map function prototype and header lines to func.entry
    proto_lineno = len(banner) if banner else 0
    if proto_lineno < header_count:
        if func.entry not in out.ea_to_line:
            out.ea_to_line[func.entry] = proto_lineno
        for h_line in range(proto_lineno, header_count):
            if func.entry not in out.line_to_eas.setdefault(h_line, []):
                out.line_to_eas[h_line].append(func.entry)
            out.line_eas[h_line] = func.entry

    # Dense instruction completion across all basic blocks in func
    if getattr(func, "blocks", None):
        sorted_blocks = sorted(func.blocks.values(), key=lambda b: b.start)
        for b in sorted_blocks:
            b_lines = []
            for s in b.stmts:
                s_ea = getattr(s, "ea", None)
                if s_ea in out.ea_to_line:
                    b_lines.append((s_ea, out.ea_to_line[s_ea]))
            for ins in getattr(b, "insns", []):
                if ins.ea in out.ea_to_line:
                    continue
                chosen_line = None
                if b_lines:
                    _, chosen_line = min(b_lines, key=lambda pair: abs(pair[0] - ins.ea))
                elif b.start in out.ea_to_line:
                    chosen_line = out.ea_to_line[b.start]
                else:
                    chosen_line = proto_lineno if proto_lineno >= 0 else 0
                if chosen_line is not None:
                    out.ea_to_line[ins.ea] = chosen_line
                    if ins.ea not in out.line_to_eas.setdefault(chosen_line, []):
                        out.line_to_eas[chosen_line].append(ins.ea)

    return out
