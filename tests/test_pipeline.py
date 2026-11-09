"""
Headless pipeline tests for the LM32 decompiler.
Verifies end-to-end decompilation, EA anchoring, and Hex-Rays C generation.
Zero IDA dependencies.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lm32dec import decompile_image, decoder


def _pack_be(words):
    b = bytearray()
    for w in words:
        b.extend(w.to_bytes(4, "big"))
    return b


def _pack_le(words):
    b = bytearray()
    for w in words:
        b.extend(w.to_bytes(4, "little"))
    return b


def test_simple_function_pipeline_be():
    # addi r1, r1, 10
    # b r29 (ret)
    words = [
        0x3421000A,  # addi r1, r1, 10
        0xC3A00000,  # b r29
    ]
    img = _pack_be(words)
    prog = decompile_image(img, entries=[0], base=0, is_be=True)
    assert 0 in prog.funcs
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "int sub_0(int a0)" in text
    assert "+ 0xA" in text or "0xA" in text
    assert "return" in text

    # Verify 100% instruction EA anchoring
    assert 0 in fn.ea_to_line
    assert 4 in fn.ea_to_line
    assert fn.ea_to_line[0] in fn.line_to_eas
    assert fn.ea_to_line[4] in fn.line_to_eas
    print("ok  test_simple_function_pipeline_be")


def test_simple_function_pipeline_le():
    # addi r1, r1, 10
    # b r29 (ret)
    words = [
        0x3421000A,
        0xC3A00000,
    ]
    img = _pack_le(words)
    prog = decompile_image(img, entries=[0], base=0, is_be=False)
    assert 0 in prog.funcs
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "sub_0" in text
    assert "return" in text
    assert 0 in fn.ea_to_line
    assert 4 in fn.ea_to_line
    print("ok  test_simple_function_pipeline_le")


def test_loop_structuring():
    # 0x00: addi r1, r0, 5      # r1 = 5
    # 0x04: addi r1, r1, -1     # loop: r1 = r1 - 1
    # 0x08: bne r1, r0, -1      # if r1 != 0 goto 0x04 (disp = -1 word)
    # 0x0C: b r29               # ret
    words = [
        0x34010005,  # addi r1, r0, 5
        0x3421FFFF,  # addi r1, r1, -1
        0x5C20FFFF,  # bne r1, r0, disp=-1 (to 0x04)
        0xC3A00000,  # b r29
    ]
    img = _pack_be(words)
    prog = decompile_image(img, entries=[0], base=0, is_be=True)
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "do {" in text or "while (" in text, text
    assert text.count("{") == text.count("}"), text

    for ea in (0, 4, 8, 12):
        assert ea in fn.ea_to_line, f"EA {hex(ea)} missing from ea_to_line"
    print("ok  test_loop_structuring")


def test_memory_load_store():
    # lw r2, (r1+4)
    # addi r2, r2, 1
    # sw (r1+4), r2
    # b r29
    words = [
        0x28220004,  # lw r2, (r1+4)
        0x34420001,  # addi r2, r2, 1
        0x58220004,  # sw (r1+4), r2
        0xC3A00000,  # b r29
    ]
    img = _pack_be(words)
    prog = decompile_image(img, entries=[0], base=0, is_be=True)
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "*(_DWORD *)" in text, text
    print("ok  test_memory_load_store")


def test_csr_intrinsics():
    # rcsr r1, IE
    # wcsr IE, r1
    # b r29
    words = [
        0x90010000,  # rcsr r1, IE (csr 0)
        0xD0010000,  # wcsr IE, r1 (csr 0)
        0xC3A00000,  # b r29
    ]
    img = _pack_be(words)
    prog = decompile_image(img, entries=[0], base=0, is_be=True)
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "__rcsr" in text, text
    assert "__wcsr" in text, text
    print("ok  test_csr_intrinsics")


if __name__ == "__main__":
    test_simple_function_pipeline_be()
    test_simple_function_pipeline_le()
    test_loop_structuring()
    test_memory_load_store()
    test_csr_intrinsics()
    print("\nALL PIPELINE TESTS PASSED!")
