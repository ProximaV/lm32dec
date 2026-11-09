"""
Headless CLI for the LatticeMico32 (LM32) decompiler:

    python -m lm32dec firmware.bin
    python -m lm32dec firmware.bin -o decompiled.c
    python -m lm32dec firmware.bin --endian little --base 0x800000 --entry 0x800100
    python -m lm32dec firmware.bin --func 0x800340

No IDA installation required.
"""

import argparse
import sys

from . import decompile_file


def _int(s):
    return int(s, 0)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(prog="lm32dec",
                                 description="Decompile LatticeMico32 (LM32) firmware to pseudo-C.")
    ap.add_argument("rom", help="raw LM32 flash dump or binary image")
    ap.add_argument("-o", "--out", help="write C source listing to this file (default: stdout)")
    ap.add_argument("--base", type=_int, default=None, help="link base address (default: auto from reset vector)")
    ap.add_argument("--entry", type=_int, action="append", default=None, help="extra entry point address (repeatable)")
    ap.add_argument("--func", type=_int, default=None, help="only decompile and emit the function at this address")
    ap.add_argument("--endian", choices=["big", "little"], default="big", help="target endianness (default: big)")
    ap.add_argument("--no-banner", action="store_true", help="omit banner header comments")
    args = ap.parse_args(argv)

    is_be = (args.endian == "big")
    prog = decompile_file(args.rom, base=args.base,
                          extra_entries=tuple(args.entry) if args.entry else (),
                          is_be=is_be)

    if args.func is not None:
        f = prog.funcs.get(args.func)
        if f is None:
            ap.error("no function decoded at 0x%X (try --entry 0x%X)" % (args.func, args.func))
        text = "\n".join(f.lines)
    else:
        text = prog.listing(banner=not args.no_banner)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(text + "\n")
        print("lm32dec: base 0x%X, %d functions -> %s" % (prog.base, len(prog.funcs), args.out), file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
