"""
Unit tests for LM32 ABI, calling conventions, stack frame, and callargs.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lm32dec import ir, cfg, frame, abi, callargs


def test_abi_param_recovery():
    # Construct a function reading r1, r2, r3, r4, r5, r6, r7, r8
    f = cfg.Func(0x1000)
    b0 = cfg.Block(0x1000)
    b0.term = "ret"
    # Read r1..r5
    for i in range(1, 6):
        b0.stmts.append(ir.Assign(0x1000 + i * 4, ir.Reg(f"r{i+10}"), ir.Reg(f"r{i}")))
    # Return r1
    b0.stmts.append(ir.Assign(0x1020, ir.Reg("r1"), ir.Const(42)))
    b0.stmts.append(ir.Ret(0x1024, "ret"))
    f.blocks[0x1000] = b0

    sig = abi.analyze_calling_convention(f)
    assert len(sig.params) == 5
    assert [p.location for p in sig.params] == ["r1", "r2", "r3", "r4", "r5"]
    assert sig.ret_type == "int"


def test_abi_64bit_return():
    # Function returning both r1 and r2
    f = cfg.Func(0x2000)
    b0 = cfg.Block(0x2000)
    b0.term = "ret"
    b0.stmts.append(ir.Assign(0x2000, ir.Reg("r1"), ir.Const(0x12345678)))
    b0.stmts.append(ir.Assign(0x2004, ir.Reg("r2"), ir.Const(0x9ABCDEF0)))
    b0.stmts.append(ir.Ret(0x2008, "ret"))
    f.blocks[0x2000] = b0

    sig = abi.analyze_calling_convention(f)
    assert sig.ret_type == "uint64_t"


def test_frame_spill_cleanup():
    # Prologue:
    #   addi sp, sp, -16
    #   sw (sp+4), ra
    #   sw (sp+8), r11
    # Epilogue:
    #   lw r11, (sp+8)
    #   lw ra, (sp+4)
    #   addi sp, sp, 16
    #   ret
    f = cfg.Func(0x3000)
    b0 = cfg.Block(0x3000)
    b0.term = "ret"
    b0.stmts = [
        ir.Assign(0x3000, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(-16))),
        ir.Assign(0x3004, ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(4))), ir.Reg("ra")),
        ir.Assign(0x3008, ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(8))), ir.Reg("r11")),
        # Some actual work using stack slot sp+12 (local var_8 in 16-byte frame: 16 - 12 + 4 = 8)
        ir.Assign(0x300C, ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(12))), ir.Const(0xCAFE)),
        ir.Assign(0x3010, ir.Reg("r1"), ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(12)))),
        ir.Assign(0x3014, ir.Reg("r11"), ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(8)))),
        ir.Assign(0x3018, ir.Reg("ra"), ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(4)))),
        ir.Assign(0x301C, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(16))),
        ir.Ret(0x3020, "ret"),
    ]
    f.blocks[0x3000] = b0

    frame_info = frame.analyze_frame(f)
    # Callee saves for ra and r11 and sp adjusts should be stripped
    # Only the local var slot and return should remain
    remaining = b0.stmts
    assert len(remaining) == 3
    assert isinstance(remaining[0].dst, ir.Reg) and remaining[0].dst.name == "var_8"
    assert isinstance(remaining[1].src, ir.Reg) and remaining[1].src.name == "var_8"
    assert isinstance(remaining[2], ir.Ret)


def test_frame_saved_slot_at_frame_size():
    # Frame size 8: saving ra at sp+4 and r11 at sp+8 (at frame_size boundary)
    f = cfg.Func(0x3100)
    b0 = cfg.Block(0x3100)
    b0.term = "ret"
    b0.stmts = [
        ir.Assign(0x3100, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(-8))),
        ir.Assign(0x3104, ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(4))), ir.Reg("ra")),
        ir.Assign(0x3108, ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(8))), ir.Reg("r11")),
        ir.Assign(0x310C, ir.Reg("r1"), ir.Const(100)),
        ir.Assign(0x3110, ir.Reg("r11"), ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(8)))),
        ir.Assign(0x3114, ir.Reg("ra"), ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(4)))),
        ir.Assign(0x3118, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(8))),
        ir.Ret(0x311C, "ret"),
    ]
    f.blocks[0x3100] = b0

    frame_info = frame.analyze_frame(f)
    # Callee saves at sp+8 must be stripped, NOT converted into fake arg_0
    assert not frame_info.stack_args
    assert not frame_info.locals
    remaining = b0.stmts
    assert len(remaining) == 2  # r1 = 100, ret
    assert isinstance(remaining[0], ir.Assign) and remaining[0].dst.name == "r1"
    sig = abi.analyze_calling_convention(f, frame_info=frame_info)
    assert len(sig.params) == 0  # No fake a0..a7 or arg_0!


def test_frame_incoming_stack_argument():
    # Frame size 16: reads caller stack argument at sp + 16 + 4 = sp + 20
    f = cfg.Func(0x3200)
    b0 = cfg.Block(0x3200)
    b0.term = "ret"
    b0.stmts = [
        ir.Assign(0x3200, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(-16))),
        ir.Assign(0x3204, ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(4))), ir.Reg("ra")),
        ir.Assign(0x3208, ir.Reg("r1"), ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(20)))),
        ir.Assign(0x320C, ir.Reg("ra"), ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(4)))),
        ir.Assign(0x3210, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(16))),
        ir.Ret(0x3214, "ret"),
    ]
    f.blocks[0x3200] = b0

    frame_info = frame.analyze_frame(f)
    assert 0 in frame_info.stack_args
    assert frame_info.stack_args[0][0] == "arg_0"
    sig = abi.analyze_calling_convention(f, frame_info=frame_info)
    assert any(p.name == "arg_0" for p in sig.params)
    assert len(sig.params) == 9  # a0..a7 + arg_0


def test_callargs_folding():
    # Setup r1..r3 and call foo()
    f = cfg.Func(0x4000)
    b0 = cfg.Block(0x4000)
    b0.term = "ret"
    b0.stmts = [
        ir.Assign(0x4000, ir.Reg("r1"), ir.Const(10)),
        ir.Assign(0x4004, ir.Reg("r2"), ir.Const(20)),
        ir.Assign(0x4008, ir.Reg("r3"), ir.Const(30)),
        ir.Call(0x400C, target=0x5000),
        ir.Ret(0x4010, "ret"),
    ]
    f.blocks[0x4000] = b0

    callargs.rewrite(f, arity={0x5000: 3})
    assert len(b0.stmts) == 2  # Call and Ret
    call_stmt = b0.stmts[0]
    assert isinstance(call_stmt, ir.Call)
    assert len(call_stmt.args) == 3
    assert [a.value for a in call_stmt.args] == [10, 20, 30]
    assert call_stmt.inlined_eas == [0x4000, 0x4004, 0x4008]


if __name__ == "__main__":
    test_abi_param_recovery()
    test_abi_64bit_return()
    test_frame_spill_cleanup()
    test_callargs_folding()
    print("ALL ABI & FRAME TESTS PASSED!")
