"""
Headless test for the lm32dec syntax highlighter (stubs ida_lines).
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _stub():
    il = types.ModuleType("ida_lines")
    il.COLSTR = lambda t, c: "<%s>%s</%s>" % (c, t, c)
    for n in ("AUTOCMT", "NUMBER", "KEYWORD", "TYPE", "CREFTAIL", "CNAME", "REG", "SYMBOL", "EXTRA", "STRING", "ERROR"):
        setattr(il, "SCOLOR_" + n, n.lower())
    sys.modules["ida_lines"] = il


def test_highlight():
    _stub()
    from lm32dec import highlight as H
    assert "<keyword>do</keyword>" in H.colorize("    do {")
    assert "<keyword>while</keyword>" in H.colorize("    } while (r1 != 0);")
    assert "<creftail>sub_80030A</creftail>" in H.colorize("    sub_80030A();")
    assert "<creftail>loc_10</creftail>" in H.colorize("    goto loc_10;")
    assert "<number>0xE005003C</number>" in H.colorize("x = 0xE005003C;")
    assert "<cname>__rcsr</cname>" in H.colorize("    r1 = __rcsr(IE);")
    assert "<cname>__wcsr</cname>" in H.colorize("    __wcsr(IE, r1);")
    assert "<reg>r5</reg>" in H.colorize("    r5 = r0;")
    assert H.colorize("loc_10:").startswith("<creftail>")
    assert len(H.colorize_all(["void f(void)", "{", "}"])) == 3

    # Token occurrence highlighting
    hl = H.colorize("    r5 = r5 + 1;", highlight_ident="r5")
    assert "<extra>r5</extra>" in hl
    print("ok  test_highlight")


if __name__ == "__main__":
    test_highlight()
    print("\nALL HIGHLIGHT TESTS PASSED!")
