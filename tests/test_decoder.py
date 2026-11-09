"""
Unit tests for the LM32 standalone decoder and IR lifter.
Tests both Little-Endian and Big-Endian modes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lm32dec import decoder, lifter, ir, isa


def _img_at(ea, val, is_be=False):
    buf = bytearray(ea + 4)
    if is_be:
        packed = [(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]
    else:
        packed = [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF]
    buf[ea:ea+4] = packed
    return buf


def test_decode_addi_and_nop():
    # nop: 0x34000000
    b_nop = _img_at(0x1000, 0x34000000, is_be=False)
    ins = decoder.decode_one(b_nop, 0x1000, is_be=False)
    assert ins.mnem == "nop"
    stmts = lifter.lift_insn(ins)
    assert len(stmts) == 1 and isinstance(stmts[0], ir.Nop)

    # mvi r1, 0x150: addi r1, r0, 0x150 -> opcode=0x0D, r0=0, r1=1, imm=0x150
    # (0x0D << 26) | (0 << 21) | (1 << 16) | 0x150 = 0x34010150
    b_mvi = _img_at(0x1004, 0x34010150, is_be=False)
    ins = decoder.decode_one(b_mvi, 0x1004, is_be=False)
    assert ins.mnem == "mvi"
    assert ins.ops[0].reg == 1 and ins.ops[1].value == 0x150
    stmts = lifter.lift_insn(ins)
    assert len(stmts) == 1 and isinstance(stmts[0], ir.Assign)
    assert isinstance(stmts[0].dst, ir.Reg) and stmts[0].dst.name == "r1"
    assert isinstance(stmts[0].src, ir.Const) and stmts[0].src.value == 0x150

    # addi sp, sp, -0x88 -> opcode=0x0D, r0=28(sp), r1=28(sp), imm=-0x88 (0xFF78)
    # (0x0D << 26) | (28 << 21) | (28 << 16) | 0xFF78 = 0x379CFF78
    b_addi = _img_at(0x1008, 0x379CFF78, is_be=False)
    ins = decoder.decode_one(b_addi, 0x1008, is_be=False)
    assert ins.mnem == "addi"
    assert ins.ops[0].reg == 28 and ins.ops[1].reg == 28 and ins.ops[2].value == -0x88
    stmts = lifter.lift_insn(ins)
    assert isinstance(stmts[0], ir.Assign)
    assert stmts[0].dst.name == "sp"
    assert stmts[0].src.op == "+"


def test_decode_big_endian():
    # Test big-endian decoding of addi sp, sp, -0x88
    b_be = _img_at(0x2000, 0x379CFF78, is_be=True)
    ins = decoder.decode_one(b_be, 0x2000, is_be=True)
    assert ins.mnem == "addi"
    assert ins.ops[0].reg == 28 and ins.ops[2].value == -0x88


def test_decode_loads_and_stores():
    # sw (sp+0x14), r11: opcode=0x16, r0=28(sp), r1=11, imm=0x14
    # (0x16 << 26) | (28 << 21) | (11 << 16) | 0x14 = 0x5B8B0014
    b_sw = _img_at(0x1010, 0x5B8B0014, is_be=False)
    ins = decoder.decode_one(b_sw, 0x1010, is_be=False)
    assert ins.mnem == "sw"
    assert ins.ops[0].mode == "displ" and ins.ops[0].base_reg == 28 and ins.ops[0].disp == 0x14
    assert ins.ops[1].mode == "reg" and ins.ops[1].reg == 11
    stmts = lifter.lift_insn(ins)
    assert isinstance(stmts[0], ir.Assign)
    assert isinstance(stmts[0].dst, ir.Mem)
    assert stmts[0].src.name == "r11"

    # lw r2, (r3+0): opcode=0x0A, r0=3, r1=2, imm=0
    # (0x0A << 26) | (3 << 21) | (2 << 16) | 0 = 0x28620000
    b_lw = _img_at(0x1014, 0x28620000, is_be=False)
    ins = decoder.decode_one(b_lw, 0x1014, is_be=False)
    assert ins.mnem == "lw"
    assert ins.ops[0].reg == 2 and ins.ops[1].base_reg == 3 and ins.ops[1].disp == 0
    stmts = lifter.lift_insn(ins)
    assert isinstance(stmts[0], ir.Assign)
    assert stmts[0].dst.name == "r2"
    assert isinstance(stmts[0].src, ir.Mem) and stmts[0].src.width == 4


def test_decode_branches_and_calls():
    # calli 0x60DC: opcode=0x3E, pc=0x8CD0, disp=(0x60DC - 0x8CD0) // 4 = -0xAFD
    disp26 = (-0xAFD) & 0x03FFFFFF
    word = (0x3E << 26) | disp26
    b_call = _img_at(0x8CD0, word, is_be=False)
    ins = decoder.decode_one(b_call, 0x8CD0, is_be=False)
    assert ins.mnem == "calli"
    assert ins.ops[0].addr == 0x60DC
    stmts = lifter.lift_insn(ins)
    assert isinstance(stmts[0], ir.Call) and stmts[0].target == 0x60DC

    # be r1, r0, 0x8CF0: opcode=0x11, r0=1, r1=0, disp=(0x8CF0 - 0x8CF8) / 4 = -2
    disp16 = (-2) & 0xFFFF
    word = (0x11 << 26) | (1 << 21) | (0 << 16) | disp16
    b_be = _img_at(0x8CF8, word, is_be=False)
    ins = decoder.decode_one(b_be, 0x8CF8, is_be=False)
    assert ins.mnem == "be"
    assert ins.ops[2].addr == 0x8CF0
    stmts = lifter.lift_insn(ins)
    assert isinstance(stmts[0], ir.Branch)
    assert stmts[0].target == 0x8CF0
    assert stmts[0].fallthrough == 0x8CFC
    # Notice that r0 in r1 operand evaluates to Const(0)!
    assert isinstance(stmts[0].cexpr.r, ir.Const) and stmts[0].cexpr.r.value == 0

    # ret: b ra -> opcode=0x30, r0=29 (ra)
    # (0x30 << 26) | (29 << 21) = 0xC3A00000
    b_ret = _img_at(0x1020, 0xC3A00000, is_be=False)
    ins = decoder.decode_one(b_ret, 0x1020, is_be=False)
    assert ins.mnem == "ret"
    stmts = lifter.lift_insn(ins)
    assert isinstance(stmts[0], ir.Ret) and stmts[0].kind == "ret"


def test_csr_instructions():
    # rcsr r0, IM: opcode=0x24, r0=1(IM), r1=0
    # (0x24 << 26) | (1 << 21) | (0 << 16) = 0x90200000
    b_rcsr = _img_at(0x8CF0, 0x90200000, is_be=False)
    ins = decoder.decode_one(b_rcsr, 0x8CF0, is_be=False)
    assert ins.mnem == "rcsr"
    assert ins.ops[0].reg == 0 and ins.ops[1].reg == "IM"
    stmts = lifter.lift_insn(ins)
    assert isinstance(stmts[0], ir.Assign)
    assert isinstance(stmts[0].src, ir.IntrExpr) and stmts[0].src.name == "__rcsr"


if __name__ == "__main__":
    test_decode_addi_and_nop()
    test_decode_big_endian()
    test_decode_loads_and_stores()
    test_decode_branches_and_calls()
    test_csr_instructions()
    print("ALL DECODER & LIFTER TESTS PASSED!")
