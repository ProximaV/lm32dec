"""
Headless tests for disassembly <-> pseudocode line selection syncing and
instruction mapping in lm32dec.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lm32dec import cfg, ir, cgen, callargs, structure, names, decoder


def _make_insn(ea, mnem):
    ins = decoder.Insn(ea)
    ins.mnem = mnem
    ins.size = 4
    return ins


def test_inlined_call_args_sync():
    # Block at 0x100:
    # 0x100: addi r1, r0, 10
    # 0x104: addi r2, r0, 20
    # 0x108: calli 0x500
    # 0x10C: b r29
    f = cfg.Func(0x100)
    b = cfg.Block(0x100)
    for ea, mnem in [(0x100, "addi"), (0x104, "addi"), (0x108, "calli"), (0x10C, "b")]:
        b.insns.append(_make_insn(ea, mnem))
    b.stmts = [
        ir.Assign(0x100, ir.Reg("r1"), ir.Const(10)),
        ir.Assign(0x104, ir.Reg("r2"), ir.Const(20)),
        ir.Call(0x108, target=0x500),
        ir.Ret(0x10C),
    ]
    b.term = "ret"
    f.blocks[0x100] = b

    callargs.rewrite(f, {0x500: 2})
    tree = structure.structure(f)
    namer = names.Namer()
    lines = cgen.generate(f, tree, namer)

    assert hasattr(lines, "line_to_eas")
    assert hasattr(lines, "ea_to_line")

    # Find the line containing "sub_500(10, 20);"
    call_line = None
    for idx, text in enumerate(lines):
        if "sub_500" in text:
            call_line = idx
            break

    assert call_line is not None, lines

    # Both argument setups (0x100, 0x104) and the call (0x108) must map to call_line!
    assert lines.ea_to_line[0x100] == call_line, (lines.ea_to_line[0x100], call_line)
    assert lines.ea_to_line[0x104] == call_line, (lines.ea_to_line[0x104], call_line)
    assert lines.ea_to_line[0x108] == call_line, (lines.ea_to_line[0x108], call_line)

    # In reverse: selecting call_line must highlight all 3 instructions!
    eas = lines.line_to_eas[call_line]
    assert 0x100 in eas, eas
    assert 0x104 in eas, eas
    assert 0x108 in eas, eas
    print("ok  test_inlined_call_args_sync")


def test_tail_call_sync():
    # 0x200: addi r1, r0, 5
    # 0x204: bi 0x400 (tail call)
    f = cfg.Func(0x200)
    b = cfg.Block(0x200)
    for ea, mnem in [(0x200, "addi"), (0x204, "bi")]:
        b.insns.append(_make_insn(ea, mnem))
    b.stmts = [
        ir.Assign(0x200, ir.Reg("r1"), ir.Const(5)),
        ir.Call(0x204, target=0x400, is_tail=True),
        ir.Ret(0x204),
    ]
    b.term = "ret"
    f.blocks[0x200] = b

    callargs.rewrite(f, {0x400: 1})
    tree = structure.structure(f)
    namer = names.Namer()
    lines = cgen.generate(f, tree, namer)

    tail_line = None
    for idx, text in enumerate(lines):
        if "sub_400" in text:
            tail_line = idx
            break

    assert tail_line is not None, lines
    assert lines.ea_to_line[0x200] == tail_line
    assert lines.ea_to_line[0x204] == tail_line
    print("ok  test_tail_call_sync")


def test_dense_instruction_coverage():
    # Ensure all instructions in basic blocks are anchored to lines
    f = cfg.Func(0x300)
    b = cfg.Block(0x300)
    for off in range(0, 16, 4):
        b.insns.append(_make_insn(0x300 + off, "nop"))
    b.stmts = [ir.Ret(0x30C)]
    b.term = "ret"
    f.blocks[0x300] = b

    tree = structure.structure(f)
    namer = names.Namer()
    lines = cgen.generate(f, tree, namer)

    for off in range(0, 16, 4):
        ea = 0x300 + off
        assert ea in lines.ea_to_line, f"Missing EA {hex(ea)}"
        line = lines.ea_to_line[ea]
        assert ea in lines.line_to_eas[line]
    print("ok  test_dense_instruction_coverage")


if __name__ == "__main__":
    test_inlined_call_args_sync()
    test_tail_call_sync()
    test_dense_instruction_coverage()
    print("\nALL SYNC TESTS PASSED!")
