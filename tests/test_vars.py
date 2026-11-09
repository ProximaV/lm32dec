"""
Unit tests for LM32 SSA def-use variable recovery, optimization, and structuring.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lm32dec import ir, cfg, opt, vars, structure, abi


def test_cmp_to_branch_folding():
    # cmpe r1, r2, r3 -> r1 = (r2 == r3)
    # bne r1, r0, 0x1010 -> if (r1 != 0) goto 0x1010
    # Should fold into: if (r2 == r3) goto 0x1010
    f = cfg.Func(0x1000)
    b0 = cfg.Block(0x1000)
    b0.term = "branch"
    b0.succ = [(True, 0x1010), (False, 0x1008)]
    b0.stmts = [
        ir.Assign(0x1000, ir.Reg("r1"), ir.Bin("==", ir.Reg("r2"), ir.Reg("r3"))),
        ir.Branch(0x1004, ir.Bin("!=", ir.Reg("r1"), ir.Const(0)), 0x1010, 0x1008),
    ]
    f.blocks[0x1000] = b0

    opt.optimize(f)
    assert len(b0.stmts) == 1
    branch = b0.stmts[0]
    assert isinstance(branch, ir.Branch)
    assert branch.cexpr.op == "=="
    assert branch.cexpr.l.name == "r2"
    assert branch.cexpr.r.name == "r3"
    assert branch.inlined_eas == [0x1000]


def test_vars_recovery_and_splitting():
    # Block 0:
    #   r1 is input arg (a0)
    #   r2 = r1 + 1 (v0)
    #   r10 = r2 * 2 (v1)
    # Block 1 (separate disjoint use of r2):
    #   r2 = 100 (v2)
    #   r1 = r2 + r10 (return value)
    f = cfg.Func(0x2000)
    b0 = cfg.Block(0x2000)
    b0.term = "fall"
    b0.succ = [("fall", 0x2010)]
    b0.stmts = [
        ir.Assign(0x2000, ir.Reg("r2"), ir.Bin("+", ir.Reg("r1"), ir.Const(1))),
        ir.Assign(0x2004, ir.Reg("r10"), ir.Bin("*", ir.Reg("r2"), ir.Const(2))),
    ]

    b1 = cfg.Block(0x2010)
    b1.term = "ret"
    b1.stmts = [
        ir.Assign(0x2010, ir.Reg("r2"), ir.Const(100)),
        ir.Assign(0x2014, ir.Reg("r1"), ir.Bin("+", ir.Reg("r2"), ir.Reg("r10"))),
        ir.Ret(0x2018, "ret"),
    ]
    f.blocks[0x2000] = b0
    f.blocks[0x2010] = b1

    sig = abi.analyze_calling_convention(f)
    assert len(sig.params) == 1 and sig.params[0].name == "a0"

    vars.recover_variables(f, sig=sig)

    # In b0: r2 was inlined into r10 because it was single-use: r10 = (a0 + 1) * 2
    assert len(b0.stmts) == 1
    assert b0.stmts[0].src.l.l.name == "a0"
    v_r10_name = b0.stmts[0].dst.name
    assert v_r10_name.startswith("v")

    # In b1: r2 is reassigned, and used in return expression: r1 = v_r2 + v_r10
    assert len(b1.stmts) >= 1
    # Check that virtual variables are distinct
    assert v_r10_name in [s.src.r.name for s in b1.stmts if isinstance(s, ir.Assign) and isinstance(s.src, ir.Bin)]


def test_structure_if_then():
    # CFG with if-then triangle:
    # 0x3000: if (r1 == 0) goto 0x3010
    # 0x3004: r2 = 5
    # 0x3010: return
    f = cfg.Func(0x3000)
    b0 = cfg.Block(0x3000)
    b0.term = "branch"
    b0.succ = [(True, 0x3010), (False, 0x3004)]
    b0.stmts = [ir.Branch(0x3000, ir.Bin("==", ir.Reg("r1"), ir.Const(0)), 0x3010, 0x3004)]

    b1 = cfg.Block(0x3004)
    b1.term = "fall"
    b1.succ = [("fall", 0x3010)]
    b1.stmts = [ir.Assign(0x3004, ir.Reg("r2"), ir.Const(5))]

    b2 = cfg.Block(0x3010)
    b2.term = "ret"
    b2.stmts = [ir.Ret(0x3010, "ret")]

    f.blocks[0x3000] = b0
    f.blocks[0x3004] = b1
    f.blocks[0x3010] = b2

    tree = structure.structure(f)
    assert len(tree) >= 1
    # Check that SIf was recovered with exact instruction EA anchoring
    sif = next((node for node in tree if isinstance(node, structure.SIf)), None)
    assert sif is not None
    assert sif.ea == 0x3000


if __name__ == "__main__":
    test_cmp_to_branch_folding()
    test_vars_recovery_and_splitting()
    test_structure_if_then()
    print("ALL VARS & STRUCTURER TESTS PASSED!")
