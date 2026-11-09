"""
C syntax highlighting for the lm32dec viewer (theme-aware; IDA-only import).
Falls back to raw strings in headless mode.
"""

import re

try:
    import ida_lines
except ImportError:
    ida_lines = None

C_KEYWORDS = frozenset(("if", "else", "while", "do", "for", "return", "break",
                        "continue", "goto", "switch", "case", "default", "sizeof", "typedef"))
C_TYPES = frozenset(("void", "char", "short", "int", "long", "unsigned", "signed", "const",
                     "u8", "u16", "u32", "uint8_t", "uint16_t", "uint32_t",
                     "int8_t", "int16_t", "int32_t", "bool", "size_t",
                     "_BYTE", "_WORD", "_DWORD", "_QWORD", "__int8", "__int16", "__int32", "__int64"))
INTRINSICS = frozenset(("__rcsr", "__wcsr", "__scall", "__break", "JUMPOUT"))

_TOK = re.compile(r"""
      (?P<comment>/\*.*?\*/|//.*)
    | (?P<string>"(?:[^"\\]|\\.)*")
    | (?P<hex>-?\b0[xX][0-9A-Fa-f]+)
    | (?P<num>-?\b\d+\b)
    | (?P<ident>[A-Za-z_$][A-Za-z_0-9$]*)
    | (?P<ws>\s+)
    | (?P<op>.)
""", re.VERBOSE)
_CALL = re.compile(r"\s*[\(\[]")
_LABEL = re.compile(r"^[A-Za-z_]\w*:\s*$")


def _tag(t, c):
    if ida_lines is not None:
        return ida_lines.COLSTR(t, c)
    return t


def colorize(line, highlight_ident=None):
    if not line:
        return line
    if ida_lines is None:
        return line
    st = line.lstrip()
    if st.startswith(("//", "/*", "*", "*/")) and not highlight_ident:
        return _tag(line, ida_lines.SCOLOR_AUTOCMT)
    if _LABEL.match(st) and not highlight_ident:
        return _tag(line, ida_lines.SCOLOR_CREFTAIL)
    out, pos, n = [], 0, len(line)
    extra_col = getattr(ida_lines, "SCOLOR_EXTRA", getattr(ida_lines, "SCOLOR_ERROR", "\x01\x32"))
    while pos < n:
        m = _TOK.match(line, pos)
        if not m:
            out.append(line[pos])
            pos += 1
            continue
        k, t = m.lastgroup, m.group()
        pos = m.end()
        if k == "ws":
            out.append(t)
        elif k == "comment":
            out.append(_tag(t, ida_lines.SCOLOR_AUTOCMT))
        elif k == "string":
            out.append(_tag(t, getattr(ida_lines, "SCOLOR_STRING", ida_lines.SCOLOR_SYMBOL)))
        elif k in ("hex", "num"):
            out.append(_tag(t, ida_lines.SCOLOR_NUMBER))
        elif k == "ident":
            if highlight_ident and t == highlight_ident:
                out.append(_tag(t, extra_col))
            else:
                out.append(_tag(t, _ic(t, line, pos)))
        else:
            out.append(_tag(t, ida_lines.SCOLOR_SYMBOL))
    return "".join(out)


def _ic(t, line, after):
    if ida_lines is None:
        return ""
    if t in C_KEYWORDS:
        return ida_lines.SCOLOR_KEYWORD
    if t in C_TYPES:
        return ida_lines.SCOLOR_TYPE
    if t.startswith(("loc_", "sub_")):
        return ida_lines.SCOLOR_CREFTAIL
    if t in INTRINSICS or _CALL.match(line, after):
        return ida_lines.SCOLOR_CNAME
    return ida_lines.SCOLOR_REG


def colorize_all(lines):
    return [colorize(x) for x in lines]
