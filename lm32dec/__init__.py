"""
lm32dec -- an interactive and headless decompiler for the LatticeMico32 (LM32) processor.

Supports both Big-Endian (standard LM32) and Little-Endian (PS Vita LM32 coprocessors).
Runs headless with zero IDA dependencies, and integrates seamlessly as a Hex-Rays parity
interactive plugin inside IDA Pro.

Pipeline:
    decoder -> lifter -> cfg -> frame -> callargs -> opt -> abi -> vars -> structure -> cgen
"""

from . import decoder, cfg, opt, frame, callargs, structure, cgen, loader, abi, vars
from .names import Namer

__version__ = "1.0.0"

BANNER = [
    "/*",
    " * Decompiled by lm32dec -- LatticeMico32 (LM32) Decompiler.",
    " * r0..r31 / gp / fp / sp / ra / ea / ba are machine registers.",
    " * *(_DWORD *), *(_WORD *), *(_BYTE *) dereference memory.",
    " * CSR registers accessed via __rcsr / __wcsr intrinsics.",
    " * Cross-function tail jumps render as JUMPOUT().",
    " */",
    "",
]


class Function:
    def __init__(self, entry, name, func, tree, lines, line_eas=None, line_to_eas=None, ea_to_line=None, header_count=None):
        self.entry = entry
        self.name = name
        self.cfg = func
        self.tree = tree
        self.lines = lines
        self.line_eas = line_eas if line_eas is not None else getattr(lines, "line_eas", None)
        self.line_to_eas = line_to_eas if line_to_eas is not None else getattr(lines, "line_to_eas", {})
        self.ea_to_line = ea_to_line if ea_to_line is not None else getattr(lines, "ea_to_line", {})
        self.header_count = header_count if header_count is not None else getattr(lines, "header_count", 0)


class Program:
    def __init__(self, image, base, insns, funcs, namer, is_be=True):
        self.image = image
        self.base = base
        self.insns = insns
        self.funcs = funcs
        self.namer = namer
        self.is_be = is_be

    def listing(self, banner=True):
        out = list(BANNER) if banner else []
        for entry in sorted(self.funcs):
            out.extend(self.funcs[entry].lines)
            out.append("")
        return "\n".join(out)


def decompile_image(image, entries, base=0, is_be=True, code_names=None):
    insns, calls = decoder.decode(image, entries=entries, base=base, is_be=is_be)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = Namer(code_names=code_names)

    # 1. Pre-compute calling conventions and arities
    arity = {}
    for entry, f in funcs.items():
        frame_info = frame.analyze_frame(f)
        opt.optimize(f)
        sig = abi.analyze_calling_convention(f, frame_info=frame_info)
        arity[entry] = len(sig.params)

    # 2. Decompile each function with virtual variable recovery
    out = {}
    for entry, f in funcs.items():
        frame_info = frame.analyze_frame(f)
        callargs.rewrite(f, arity)
        opt.optimize(f)
        sig = abi.analyze_calling_convention(f, frame_info=frame_info)
        vars.recover_variables(f, sig=sig, frame_info=frame_info)
        tree = structure.structure(f)
        lines = cgen.generate(f, tree, namer, frame_info=frame_info, sig=sig)
        out[entry] = Function(entry, namer.code(entry), f, tree, lines)

    return Program(image, base, insns, out, namer, is_be=is_be)


def decompile_file(path, base=None, extra_entries=(), is_be=True, **kw):
    image = loader.load(path)
    det_base, reset = loader.detect_base(image, is_be=is_be)
    if base is None:
        base = det_base
    entries = list(loader.vector_entries(image, base=base, is_be=is_be))
    if reset and reset not in entries:
        entries.append(reset)
    entries += list(extra_entries)
    return decompile_image(image, entries=entries, base=base, is_be=is_be, **kw)


def decompile_one(ea):
    from . import ida_bridge
    return ida_bridge.decompile_one(ea)
