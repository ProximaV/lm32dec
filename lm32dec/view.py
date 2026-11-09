"""
Interactive IDA custom viewer for lm32dec pseudocode.

Provides:
- Right-click context menu and hotkeys for:
  - Renaming variables and functions ('N') with IDB netnode persistence.
  - Setting variable and function types ('Y') with IDA type system integration.
  - Linking / synchronizing with IDA's disassembly view (follows cursor across functions).
  - Jumping to disassembly and clicking through to callee functions ('Enter' / 'Space' / double-click).
  - Refreshing decompilation ('F5').
- Caret token occurrence highlighting using SCOLOR_EXTRA.
- Navigation history stack (forward navigation on symbol click, back with 'Esc').
- Decompiler window state persistence across IDA sessions via netnodes.
- Automatic docking beside IDA View-A.
"""

import re
import ida_kernwin
import ida_funcs
import ida_lines
import ida_typeinf
import idaapi

from . import highlight, ida_bridge, db

_VIEW_TITLE = "lm32dec - Pseudocode"

ACTION_DECOMPILE = "lm32dec:decompile"
ACTION_RENAME = "lm32dec:rename_var"
ACTION_SET_TYPE = "lm32dec:set_type"
ACTION_TOGGLE_SYNC = "lm32dec:toggle_sync"
ACTION_JUMP_DISASM = "lm32dec:jump_disasm"
ACTION_REFRESH = "lm32dec:refresh"
ACTION_TOGGLE_HEX_DEC = "lm32dec:toggle_hex_dec"
ACTION_CVT_OFFSET = "lm32dec:cvt_offset"
ACTION_CVT_CHAR = "lm32dec:cvt_char"
ACTION_INVERT_SIGN = "lm32dec:invert_sign"
ACTION_BITWISE_NEGATE = "lm32dec:bitwise_negate"
ACTION_EDIT_COMMENT = "lm32dec:edit_comment"
ACTION_INVERT_IF = "lm32dec:invert_if"
ACTION_TOGGLE_CASTS = "lm32dec:toggle_casts"
ACTION_JUMP_XREF = "lm32dec:jump_xref"
ACTION_JUMP_BRACE = "lm32dec:jump_brace"
ACTION_RESET_ITEM = "lm32dec:reset_item"

_active_viewer = None
_ui_hooks = None
_view_hooks = None


def _is_dark_theme():
    """Detect if IDA is currently using a dark theme."""
    try:
        from PySide6 import QtWidgets, QtGui
        app = QtWidgets.QApplication.instance()
        if app:
            pal = app.palette()
            role = QtGui.QPalette.ColorRole.Base if hasattr(QtGui.QPalette, "ColorRole") else QtGui.QPalette.Base
            return pal.color(role).lightness() < 128
    except Exception:
        pass
    try:
        from PyQt5 import QtWidgets, QtGui
        app = QtWidgets.QApplication.instance()
        if app:
            pal = app.palette()
            role = QtGui.QPalette.ColorRole.Base if hasattr(QtGui.QPalette, "ColorRole") else QtGui.QPalette.Base
            return pal.color(role).lightness() < 128
    except Exception:
        pass
    return False


def _get_highlight_colors():
    """Return (asm_highlight_color, decomp_highlight_bg) based on active IDA theme."""
    if _is_dark_theme():
        return 0x304855, 0x283848
    else:
        return 0xC0E0FF, 0xD0E8FF


def _jumpto_disasm(ea):
    """Jump to ea in IDA disassembly view (IDA View-A)."""
    if ea is None:
        return False
    try:
        flags = getattr(ida_kernwin, "UIJMP_IDAVIEW", 0x0001)
        return ida_kernwin.jumpto(ea, -1, flags)
    except Exception:
        try:
            return idaapi.jumpto(ea)
        except Exception:
            return False


class _ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, view, callback):
        super().__init__()
        self.view = view
        self.callback = callback

    def activate(self, ctx):
        if self.callback:
            self.callback()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class _DecompilerView(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super().__init__()
        self.current_func_ea = None
        self.current_func_name = None
        self.line_ea = []
        self.line_to_eas = {}
        self.ea_to_line = {}
        self.raw_lines = []
        self.header_count = 0
        self._selected_line = None
        self._highlighted_asm_eas = set()
        self._sync_lock = False
        self.sync_with_disasm = db.get_sync_enabled()
        self.show_casts = True
        self._nav_history = []
        self._last_token = None
        self._highlighted_token_lines = set()

    def save_state(self, is_open=True):
        """Save active window state into the persistent database netnode."""
        if getattr(self, "_saving_state_lock", False):
            return
        self._saving_state_lock = True
        try:
            if self.current_func_ea is None:
                return
            pos = self.GetPos()
            lineno = max(0, pos[0]) if (pos and pos[0] >= 0) else 0
            col = max(0, pos[1]) if (pos and pos[1] >= 0) else 0
            mode = "c"
            db.save_window_state(is_open=is_open, func_ea=self.current_func_ea, lineno=lineno, col=col, mode=mode)
        finally:
            self._saving_state_lock = False

    def build_or_refresh(self, fn):
        """Populate or update lines with decompiled Function fn."""
        self.header_count = getattr(fn, "header_count", 0) or getattr(fn.lines, "header_count", 0)
        self.clear_asm_highlights()
        self.current_func_ea = fn.entry
        self.current_func_name = fn.name
        self.line_ea = []
        self.line_to_eas = getattr(fn, "line_to_eas", {}) or {}
        self.ea_to_line = getattr(fn, "ea_to_line", {}) or {}
        self.raw_lines = list(fn.lines)
        self._selected_line = None
        self._last_token = None
        self._highlighted_token_lines.clear()

        self.ClearLines()
        fn_line_eas = getattr(fn, "line_eas", None) or getattr(fn.lines, "line_eas", None)
        for i, ln in enumerate(fn.lines):
            self.AddLine(highlight.colorize(ln))
            ea = fn_line_eas[i] if (fn_line_eas and i < len(fn_line_eas)) else None
            self.line_ea.append(ea)
        self.Refresh()

        # If IDA's screen cursor is already at a specific executable body statement,
        # scroll to and highlight that statement.
        initial_stmt_line = None
        try:
            screen_ea = ida_kernwin.get_screen_ea()
            if screen_ea is not None and screen_ea in self.ea_to_line:
                cand = self.ea_to_line[screen_ea]
                if cand >= self.header_count:
                    initial_stmt_line = cand
        except Exception:
            pass

        if initial_stmt_line is not None and initial_stmt_line < len(self.raw_lines):
            self.select_line(initial_stmt_line, jump=True, update_asm=True, jump_asm=False)
        else:
            self._selected_line = None
            try:
                self.Jump(0, 0)
            except Exception:
                pass

    def clear_asm_highlights(self):
        """Restore default background color for all previously highlighted asm instructions."""
        if not self._highlighted_asm_eas:
            return
        import ida_nalt
        for ea in list(self._highlighted_asm_eas):
            try:
                ida_nalt.del_item_color(ea)
            except Exception:
                pass
        self._highlighted_asm_eas.clear()
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

    def select_line(self, lineno, jump=False, update_asm=True, jump_asm=True):
        """Move selection to lineno, visually highlight row, and sync asm highlight."""
        if lineno < 0 or lineno >= len(self.raw_lines):
            return
        prev_line = self._selected_line
        self._selected_line = lineno

        asm_color, decomp_bg = _get_highlight_colors()

        # Unhighlight previous decompiled line
        if prev_line is not None and prev_line != lineno and 0 <= prev_line < len(self.raw_lines):
            try:
                colored = highlight.colorize(self.raw_lines[prev_line], highlight_ident=self._last_token)
                self.EditLine(prev_line, colored, bgcolor=0xFFFFFFFF)
            except Exception:
                pass

        # Highlight current decompiled line if it has content
        if self.raw_lines[lineno].strip():
            try:
                colored = highlight.colorize(self.raw_lines[lineno], highlight_ident=self._last_token)
                self.EditLine(lineno, colored, bgcolor=decomp_bg)
                self.RefreshCurrent()
            except Exception:
                pass
        else:
            self._selected_line = None

        if jump:
            try:
                self.Jump(lineno, 0)
            except Exception:
                pass

        if update_asm:
            self._update_asm_highlight_for_line(lineno, jump_asm=jump_asm)

    def _update_asm_highlight_for_line(self, lineno, jump_asm=True):
        """Highlight assembly instructions in IDA disassembly corresponding to decompiled line."""
        import ida_nalt

        # Clear previous asm highlights
        for ea in list(self._highlighted_asm_eas):
            try:
                ida_nalt.del_item_color(ea)
            except Exception:
                pass
        self._highlighted_asm_eas.clear()

        eas = self.line_to_eas.get(lineno, [])
        if not eas and lineno < len(self.line_ea) and self.line_ea[lineno] is not None:
            eas = [self.line_ea[lineno]]

        if not eas:
            if self.line_to_eas:
                nearest_line = min(self.line_to_eas.keys(), key=lambda l: abs(l - lineno))
                eas = self.line_to_eas[nearest_line]
            elif self.current_func_ea is not None:
                eas = [self.current_func_ea]

        if eas:
            asm_color, _ = _get_highlight_colors()
            for ea in eas:
                try:
                    ida_nalt.set_item_color(ea, asm_color)
                    self._highlighted_asm_eas.add(ea)
                except Exception:
                    pass
            try:
                ida_kernwin.refresh_idaview_anyway()
            except Exception:
                pass

            if self.sync_with_disasm and jump_asm:
                try:
                    self._sync_lock = True
                    _jumpto_disasm(eas[0])
                except Exception:
                    pass
                finally:
                    self._sync_lock = False
        else:
            try:
                ida_kernwin.refresh_idaview_anyway()
            except Exception:
                pass

    def _update_token_highlight(self):
        """Highlight all occurrences of the identifier under caret across the view."""
        if not self.raw_lines:
            return
        word, lineno = self.get_word_under_cursor()
        active_token = None
        if word and (word[0].isalpha() or word[0] == "_"):
            if word not in highlight.C_KEYWORDS and word not in highlight.C_TYPES:
                active_token = word

        if active_token == self._last_token:
            return

        self._last_token = active_token
        _, decomp_bg = _get_highlight_colors()

        to_restore = set(self._highlighted_token_lines)
        self._highlighted_token_lines.clear()

        new_matching = set()
        if active_token:
            pat = re.compile(r"\b" + re.escape(active_token) + r"\b")
            for idx, raw in enumerate(self.raw_lines):
                if idx >= self.header_count and pat.search(raw):
                    new_matching.add(idx)

        affected = to_restore.union(new_matching)
        for idx in affected:
            if 0 <= idx < len(self.raw_lines):
                try:
                    colored = highlight.colorize(self.raw_lines[idx], highlight_ident=active_token)
                    bg = decomp_bg if idx == self._selected_line else 0xFFFFFFFF
                    self.EditLine(idx, colored, bgcolor=bg)
                    if idx in new_matching:
                        self._highlighted_token_lines.add(idx)
                except Exception:
                    pass
        if affected:
            try:
                self.RefreshCurrent()
            except Exception:
                pass

    def sync_from_disasm_ea(self, ea):
        """Called when cursor moves in disassembly; syncs selection in decompiled view."""
        if self._sync_lock:
            return
        lineno = self.ea_to_line.get(ea)
        if lineno is None:
            lineno = self._find_closest_line(ea)

        if lineno is None or lineno < self.header_count:
            if self._selected_line is not None:
                if 0 <= self._selected_line < len(self.raw_lines):
                    try:
                        self.EditLine(self._selected_line, highlight.colorize(self.raw_lines[self._selected_line], highlight_ident=self._last_token), bgcolor=0xFFFFFFFF)
                    except Exception:
                        pass
                self._selected_line = None
            self.clear_asm_highlights()
            return

        if lineno == self._selected_line:
            return

        self._sync_lock = True
        try:
            self.select_line(lineno, jump=True, update_asm=True, jump_asm=False)
        finally:
            self._sync_lock = False

    def _find_closest_line(self, ea):
        """Find the decompiled line whose instruction EA is closest to ea."""
        if not self.ea_to_line:
            return None
        closest_ea = min(self.ea_to_line.keys(), key=lambda e: abs(e - ea))
        return self.ea_to_line[closest_ea]

    def on_cursor_changed(self):
        """Called when user clicks or navigates in decompiler window."""
        self._update_token_highlight()
        if self._sync_lock:
            return
        pos = self.GetPos()
        if not pos:
            return
        lineno = pos[0]
        if lineno < 0 or lineno >= len(self.raw_lines):
            return
        if lineno == self._selected_line:
            return

        self._sync_lock = True
        try:
            self.select_line(lineno, jump=False, update_asm=True, jump_asm=True)
        finally:
            self._sync_lock = False

    def OnCursorPosChanged(self):
        self.on_cursor_changed()

    def OnClick(self, shift):
        self.on_cursor_changed()

    def Close(self):
        self.clear_asm_highlights()
        return super().Close()

    def show_func(self, ea):
        """Decompile function at ea and refresh view."""
        pfn = ida_funcs.get_func(ea)
        entry = pfn.start_ea if pfn else ea
        try:
            fn = ida_bridge.decompile_one(entry, show_casts=getattr(self, "show_casts", True))
            self.build_or_refresh(fn)
            self.save_state(is_open=True)
            return True
        except Exception as exc:
            print("lm32dec: decompilation failed for 0x%X: %s" % (entry, exc))
            return False

    def get_literal_under_cursor(self):
        """Return (literal_str, num_val, lineno, col, stmt_ea)."""
        pos = self.GetPos()
        if not pos:
            return None, None, 0, 0, None
        lineno, col = pos[0], pos[1]
        if lineno < 0 or lineno >= len(self.raw_lines):
            return None, None, lineno, col, None
        line = self.raw_lines[lineno]
        if not line:
            return None, None, lineno, col, None
        stmt_eas = self.line_to_eas.get(lineno, [])
        stmt_ea = stmt_eas[0] if stmt_eas else (self.line_ea[lineno] if lineno < len(self.line_ea) else None)

        num_pat = re.compile(r"0x[0-9a-fA-F]+|-?\b\d+\b|'[^']*'")
        for m in num_pat.finditer(line):
            start, end = m.span()
            if start <= col <= end:
                text = m.group(0)
                val = None
                try:
                    if text.startswith(("0x", "0X")):
                        val = int(text, 16)
                    elif text.startswith("'") and text.endswith("'"):
                        inner = text[1:-1]
                        if len(inner) == 1:
                            val = ord(inner)
                        elif inner.startswith("\\x"):
                            val = int(inner[2:], 16)
                    else:
                        val = int(text, 10)
                except Exception:
                    pass
                return text, val, lineno, col, stmt_ea
        return None, None, lineno, col, stmt_ea

    def on_toggle_hex_dec(self):
        """Toggle numeric constant between hex and decimal format (H)."""
        if self.current_func_ea is None:
            return
        text, val, lineno, col, stmt_ea = self.get_literal_under_cursor()
        if text is None or val is None:
            return
        pos = self.GetPos()
        curr_form = db.get_numform(self.current_func_ea, stmt_ea or 0, hex(val))
        if curr_form:
            target_form = "dec" if curr_form == "hex" else "hex"
        else:
            target_form = "dec" if text.startswith(("0x", "0X")) else "hex"
        db.set_numform(self.current_func_ea, stmt_ea or 0, hex(val), target_form)
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_convert_offset(self):
        """Convert numeric constant to offset / symbol reference (O)."""
        if self.current_func_ea is None:
            return
        text, val, lineno, col, stmt_ea = self.get_literal_under_cursor()
        if text is None or val is None:
            word, lineno = self.get_word_under_cursor()
            if word:
                pos = self.GetPos()
                stmt_eas = self.line_to_eas.get(lineno, [])
                stmt_ea = stmt_eas[0] if stmt_eas else None
                db.set_numform(self.current_func_ea, stmt_ea or 0, word, "hex")
                self.show_func(self.current_func_ea)
                if pos:
                    try:
                        self.Jump(pos[0], pos[1])
                    except Exception:
                        pass
            return
        pos = self.GetPos()
        db.set_numform(self.current_func_ea, stmt_ea or 0, hex(val), "offset")
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_convert_char(self):
        """Convert numeric constant to character literal (R)."""
        if self.current_func_ea is None:
            return
        text, val, lineno, col, stmt_ea = self.get_literal_under_cursor()
        if text is None or val is None:
            return
        pos = self.GetPos()
        db.set_numform(self.current_func_ea, stmt_ea or 0, hex(val), "char")
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_invert_sign(self):
        """Invert sign of numeric constant (_)."""
        if self.current_func_ea is None:
            return
        text, val, lineno, col, stmt_ea = self.get_literal_under_cursor()
        if text is None or val is None:
            return
        pos = self.GetPos()
        curr_form = db.get_numform(self.current_func_ea, stmt_ea or 0, hex(val))
        target_form = "default" if curr_form == "invsign" else "invsign"
        db.set_numform(self.current_func_ea, stmt_ea or 0, hex(val), target_form)
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_bitwise_negate(self):
        """Bitwise negate numeric constant (~)."""
        if self.current_func_ea is None:
            return
        text, val, lineno, col, stmt_ea = self.get_literal_under_cursor()
        if text is None or val is None:
            return
        pos = self.GetPos()
        curr_form = db.get_numform(self.current_func_ea, stmt_ea or 0, hex(val))
        target_form = "default" if curr_form == "bnot" else "bnot"
        db.set_numform(self.current_func_ea, stmt_ea or 0, hex(val), target_form)
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_edit_comment(self):
        """Add or edit statement comment for current line (/ or ;)."""
        if self.current_func_ea is None:
            return
        pos = self.GetPos()
        lineno = pos[0] if pos else 0
        stmt_eas = self.line_to_eas.get(lineno, [])
        stmt_ea = stmt_eas[0] if stmt_eas else (self.line_ea[lineno] if lineno < len(self.line_ea) else None)
        if stmt_ea is None:
            stmt_ea = self.current_func_ea

        curr_cmt = db.get_statement_cmt(self.current_func_ea, stmt_ea) or ""
        new_cmt = ida_kernwin.ask_str(curr_cmt, 0, f"Statement Comment (0x{stmt_ea:X}):")
        if new_cmt is None:
            return
        new_cmt = new_cmt.strip()
        db.set_statement_cmt(self.current_func_ea, stmt_ea, new_cmt)
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_invert_if(self):
        """Invert if-condition and swap branches (I)."""
        if self.current_func_ea is None:
            return
        pos = self.GetPos()
        lineno = pos[0] if pos else 0
        stmt_eas = self.line_to_eas.get(lineno, [])
        stmt_ea = stmt_eas[0] if stmt_eas else None
        if stmt_ea is None:
            return
        db.toggle_iflag(self.current_func_ea, stmt_ea)
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_toggle_casts(self):
        """Toggle displaying type casts (\\)."""
        self.show_casts = not getattr(self, "show_casts", True)
        pos = self.GetPos()
        self.show_func(self.current_func_ea)
        if pos:
            try:
                self.Jump(pos[0], pos[1])
            except Exception:
                pass

    def on_jump_xref(self):
        """Open cross-references dialog for symbol or address under cursor (X)."""
        word, lineno = self.get_word_under_cursor()
        target_ea = None
        if word:
            try:
                import ida_name, ida_idaapi
                target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
                if target_ea == ida_idaapi.BADADDR:
                    target_ea = None
            except Exception:
                pass
            if target_ea is None and word.startswith(("0x", "0X")):
                try:
                    target_ea = int(word, 16)
                except ValueError:
                    pass
        if target_ea is None:
            stmt_eas = self.line_to_eas.get(lineno, [])
            target_ea = stmt_eas[0] if stmt_eas else self.current_func_ea

        if target_ea is not None:
            try:
                ida_kernwin.open_xrefs_window(target_ea)
                return True
            except Exception:
                pass
        return False

    def on_jump_matching_brace(self):
        """Jump between matching '{' and '}' braces (B)."""
        pos = self.GetPos()
        if not pos:
            return False
        cur_line, cur_col = pos[0], pos[1]
        if cur_line < 0 or cur_line >= len(self.raw_lines):
            return False
        line = self.raw_lines[cur_line]

        target_line = None
        if "{" in line and "}" not in line:
            depth = 1
            for l in range(cur_line + 1, len(self.raw_lines)):
                ln = self.raw_lines[l]
                depth += ln.count("{") - ln.count("}")
                if depth == 0:
                    target_line = l
                    break
        elif "}" in line and "{" not in line:
            depth = 1
            for l in range(cur_line - 1, -1, -1):
                ln = self.raw_lines[l]
                depth += ln.count("}") - ln.count("{")
                if depth == 0:
                    target_line = l
                    break

        if target_line is not None:
            t_line = self.raw_lines[target_line]
            col = t_line.find("}") if "}" in t_line else (t_line.find("{") if "{" in t_line else 0)
            self.select_line(target_line, jump=True, update_asm=True, jump_asm=True)
            self.Jump(target_line, max(0, col))
            return True
        return False

    def on_reset_item(self):
        """Reset custom format, rename, comment, or inversion on item under cursor (Del)."""
        if self.current_func_ea is None:
            return
        pos = self.GetPos()
        lineno = pos[0] if pos else 0
        stmt_eas = self.line_to_eas.get(lineno, [])
        stmt_ea = stmt_eas[0] if stmt_eas else None

        # 1. Statement comment
        if stmt_ea is not None and db.get_statement_cmt(self.current_func_ea, stmt_ea):
            db.set_statement_cmt(self.current_func_ea, stmt_ea, None)
            self.show_func(self.current_func_ea)
            if pos:
                try:
                    self.Jump(pos[0], pos[1])
                except Exception:
                    pass
            return

        # 2. Number format
        text, val, _, _, _ = self.get_literal_under_cursor()
        if val is not None:
            db.set_numform(self.current_func_ea, stmt_ea or 0, hex(val), "default")
            self.show_func(self.current_func_ea)
            if pos:
                try:
                    self.Jump(pos[0], pos[1])
                except Exception:
                    pass
            return

        # 3. Variable rename
        word, _ = self.get_word_under_cursor()
        if word:
            data = db.get_func_data(self.current_func_ea)
            renames = data.get("renames", {})
            for orig, user_name in list(renames.items()):
                if user_name == word or orig == word:
                    db.set_var_rename(self.current_func_ea, orig, None)
                    self.show_func(self.current_func_ea)
                    if pos:
                        try:
                            self.Jump(pos[0], pos[1])
                        except Exception:
                            pass
                    return

        # 4. Inverted if
        if stmt_ea is not None and db.is_iflag_inverted(self.current_func_ea, stmt_ea):
            db.toggle_iflag(self.current_func_ea, stmt_ea)
            self.show_func(self.current_func_ea)
            if pos:
                try:
                    self.Jump(pos[0], pos[1])
                except Exception:
                    pass
            return

    def get_word_under_cursor(self):
        """Return the identifier under cursor and the line number."""
        pos = self.GetPos()
        if not pos:
            word = self.GetCurrentWord()
            return word or "", 0
        lineno, col = pos[0], pos[1]
        if lineno < 0 or lineno >= len(self.raw_lines):
            return "", lineno
        line = self.raw_lines[lineno]
        if not line:
            return "", lineno
        if col < 0:
            col = 0
        elif col >= len(line):
            col = len(line) - 1

        # Check identifier character boundary
        if not (line[col].isalnum() or line[col] == "_"):
            if col > 0 and (line[col - 1].isalnum() or line[col - 1] == "_"):
                col -= 1
            elif col + 1 < len(line) and (line[col + 1].isalnum() or line[col + 1] == "_"):
                col += 1
            else:
                return "", lineno

        start = col
        while start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
            start -= 1
        end = col
        while end < len(line) and (line[end].isalnum() or line[end] == "_"):
            end += 1
        return line[start:end], lineno

    def on_rename(self):
        """Rename variable or function under cursor and persist in IDB netnode."""
        if self.current_func_ea is None:
            return
        word, lineno = self.get_word_under_cursor()
        if not word:
            word = ida_kernwin.ask_str("", 0, "Enter variable name to rename")
            if not word:
                return

        new_name = ida_kernwin.ask_str(word, 0, f"Rename '{word}' in {self.current_func_name or 'function'}")
        if new_name is None:
            return
        new_name = new_name.strip()

        # If renaming the function itself
        if word == self.current_func_name or (lineno == 0 and ("(" in self.raw_lines[0])):
            import ida_name
            if new_name:
                ida_name.set_name(self.current_func_ea, new_name)
                self.current_func_name = new_name
            self.show_func(self.current_func_ea)
            return

        # Save variable rename to persistent IDB netnode
        db.set_var_rename(self.current_func_ea, word, new_name)

        # If word is a global symbol in IDA, also rename in IDA's name table
        try:
            import ida_name, ida_idaapi
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
            if ea != ida_idaapi.BADADDR and new_name:
                ida_name.set_name(ea, new_name)
        except Exception:
            pass

        # If it's a stack frame variable, also rename in IDA's frame struct
        self._rename_frame_member(word, new_name)

        # Refresh decompile
        self.show_func(self.current_func_ea)

    def _rename_frame_member(self, old_name, new_name):
        """Rename stack variable member in IDA's frame structure if present."""
        try:
            import ida_frame
            pfn = ida_funcs.get_func(self.current_func_ea)
            if not pfn:
                return
            tif = ida_typeinf.tinfo_t()
            if ida_frame.get_func_frame(tif, pfn):
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    for m in udt:
                        if m.name == old_name:
                            m.name = new_name
                            tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
                            break
        except Exception:
            pass

    def on_set_type(self):
        """Set variable type or function prototype and persist in IDB netnode."""
        if self.current_func_ea is None:
            return
        word, lineno = self.get_word_under_cursor()
        is_sig_line = (lineno == 0) or ("(" in self.raw_lines[lineno] and ")" in self.raw_lines[lineno] and not self.raw_lines[lineno].strip().endswith(";"))

        if is_sig_line or word == self.current_func_name:
            # Edit function prototype
            data = db.get_func_data(self.current_func_ea)
            curr_proto = data.get("proto") or (self.raw_lines[0] if self.raw_lines else "")
            new_proto = ida_kernwin.ask_str(curr_proto, 0, f"Set Function Prototype for {self.current_func_name}")
            if new_proto is None:
                return
            new_proto = new_proto.strip()
            db.set_func_proto(self.current_func_ea, new_proto)

            # Apply to IDA type system
            if new_proto:
                try:
                    ida_typeinf.apply_cdecl(None, self.current_func_ea, new_proto)
                except Exception:
                    pass

            self.show_func(self.current_func_ea)
            return

        if not word:
            return

        # Edit variable type
        data = db.get_func_data(self.current_func_ea)
        curr_type = data.get("types", {}).get(word, "int")
        new_type = ida_kernwin.ask_str(curr_type, 0, f"Set Type for variable '{word}'")
        if new_type is None:
            return
        new_type = new_type.strip()
        db.set_var_type(self.current_func_ea, word, new_type)

        self.show_func(self.current_func_ea)

    def toggle_sync(self):
        """Toggle synchronization with IDA disassembly view."""
        self.sync_with_disasm = not self.sync_with_disasm
        db.set_sync_enabled(self.sync_with_disasm)
        state_str = "ENABLED" if self.sync_with_disasm else "DISABLED"
        print(f"lm32dec: Sync with Disassembly {state_str}")
        if self.sync_with_disasm:
            ea = ida_kernwin.get_screen_ea()
            pfn = ida_funcs.get_func(ea)
            if pfn and pfn.start_ea != self.current_func_ea:
                self.show_func(pfn.start_ea)

    def jump_disasm(self):
        """Jump to the linear address or switch decompiler view to callee function."""
        word, lineno = self.get_word_under_cursor()
        if word:
            # 1. Check if word is a function in IDA -> click-through to that function!
            try:
                import ida_name, ida_idaapi
                target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
                if target_ea != ida_idaapi.BADADDR:
                    pfn = ida_funcs.get_func(target_ea)
                    if pfn and pfn.start_ea == target_ea:
                        _jumpto_disasm(target_ea)
                        if target_ea != self.current_func_ea:
                            pos = self.GetPos()
                            self._nav_history.append((self.current_func_ea, pos[0] if pos else 0, pos[1] if pos else 0))
                            self.show_func(target_ea)
                        return True
                    else:
                        _jumpto_disasm(target_ea)
                        return True
            except Exception:
                pass

            # 2. Check if word is a hex address literal (e.g. 0x10040)
            if word.startswith(("0x", "0X")):
                try:
                    target_ea = int(word, 16)
                    _jumpto_disasm(target_ea)
                    return True
                except ValueError:
                    pass

        # Fallback: jump to line_ea or line_to_eas of current line
        target_ea = None
        if lineno is not None:
            if lineno in self.line_to_eas and self.line_to_eas[lineno]:
                target_ea = self.line_to_eas[lineno][0]
            elif lineno < len(self.line_ea) and self.line_ea[lineno] is not None:
                target_ea = self.line_ea[lineno]
            elif self.line_to_eas:
                nearest_line = min(self.line_to_eas.keys(), key=lambda l: abs(l - lineno))
                target_ea = self.line_to_eas[nearest_line][0]
            elif self.current_func_ea is not None:
                target_ea = self.current_func_ea

        if target_ea is not None:
            _jumpto_disasm(target_ea)
            return True
        return False

    def OnDblClick(self, shift):
        return self.jump_disasm()

    def OnKeydown(self, vkey, shift):
        if vkey in (ord('N'), ord('n')):
            self.on_rename()
            return True
        if vkey in (ord('Y'), ord('y')):
            self.on_set_type()
            return True
        if vkey in (ord('H'), ord('h')):
            self.on_toggle_hex_dec()
            return True
        if vkey in (ord('O'), ord('o')):
            self.on_convert_offset()
            return True
        if vkey in (ord('R'), ord('r')):
            self.on_convert_char()
            return True
        if vkey in (ord('_'), ord('-'), 189):
            self.on_invert_sign()
            return True
        if vkey in (ord('~'), 192):
            self.on_bitwise_negate()
            return True
        if vkey in (ord('/'), ord(';'), 191, 186):
            self.on_edit_comment()
            return True
        if vkey in (ord('I'), ord('i')):
            self.on_invert_if()
            return True
        if vkey in (ord('\\'), 220):
            self.on_toggle_casts()
            return True
        if vkey in (ord('X'), ord('x')):
            return self.on_jump_xref()
        if vkey in (ord('B'), ord('b')):
            return self.on_jump_matching_brace()
        if vkey == 46:  # VK_DELETE
            self.on_reset_item()
            return True
        if vkey == 116:  # F5
            if self.current_func_ea is not None:
                self.show_func(self.current_func_ea)
            return True
        if vkey in (13, 32):  # Enter or Space
            return self.jump_disasm()
        if vkey == 9:  # Tab
            self.toggle_sync()
            return True
        if vkey == 27:  # Esc
            if self._nav_history:
                prev_ea, prev_line, prev_col = self._nav_history.pop()
                self.show_func(prev_ea)
                try:
                    self.select_line(prev_line, jump=True, update_asm=True, jump_asm=True)
                    self.Jump(prev_line, prev_col)
                except Exception:
                    pass
                return True
            global _active_viewer
            self.clear_asm_highlights()
            _active_viewer = None
            if self.current_func_ea is not None:
                self.save_state(is_open=False)
            self.Close()
            return True
        # Navigation keys: Up(38), Down(40), PageUp(33), PageDown(34), Home(36), End(35)
        if vkey in (38, 40, 33, 34, 36, 35):
            try:
                ida_kernwin.execute_ui_requests([self.on_cursor_changed])
            except Exception:
                pass
        return False


class _UiHooks(ida_kernwin.UI_Hooks):
    def __init__(self, view):
        super().__init__()
        self.view = view
        self._is_closing_database = False

    def get_widget_config(self, widget, cfg):
        """Called by IDA when saving desktop configuration."""
        if self.view and widget == self.view.GetWidget():
            pos = self.view.GetPos() or (0, 0)
            return {
                "ea": self.view.current_func_ea,
                "lineno": pos[0],
                "col": pos[1],
                "mode": "c",
                "sync": getattr(self.view, "sync_with_disasm", True),
            }
        return None

    def set_widget_config(self, widget, cfg):
        """Called by IDA when restoring desktop configuration."""
        if self.view and widget == self.view.GetWidget():
            config = {}
            if cfg and hasattr(cfg, "get_dict"):
                try:
                    config = cfg.get_dict() or {}
                except Exception:
                    pass
            lineno = max(0, config.get("lineno", 0))
            col = max(0, config.get("col", 0))
            if lineno > 0:
                try:
                    self.view.Jump(lineno, col)
                except Exception:
                    pass

    def create_desktop_widget(self, title, cfg):
        """Called by IDA desktop manager to reconstruct docked widgets."""
        if title != _VIEW_TITLE:
            return None
        config = {}
        if cfg and hasattr(cfg, "get_dict"):
            try:
                config = cfg.get_dict() or {}
            except Exception:
                pass
        ea = config.get("ea")
        if ea is None:
            st = db.load_window_state()
            if st.get("is_open"):
                ea = st.get("func_ea")
                config.update(st)
        if ea is None:
            return None

        v = restore_view(ea, config=config, display=False)
        return v.GetWidget() if v else None

    def ready_to_run(self):
        """Called when IDA UI elements are fully initialized on database reopen."""
        check_and_restore_saved_view()

    def desktop_applied(self, name, from_idb, type):
        """Called when a desktop layout is applied."""
        check_and_restore_saved_view()

    def database_inited(self, is_new_database, idc_script=None):
        """Called after database initialization."""
        check_and_restore_saved_view()

    def saving(self):
        if getattr(self, "_in_saving", False):
            return
        self._in_saving = True
        try:
            self._is_closing_database = True
            self._record_current_state()
        finally:
            self._in_saving = False

    def saved(self):
        if getattr(self, "_in_saved", False):
            return
        self._in_saved = True
        try:
            self._record_current_state()
        finally:
            self._is_closing_database = False
            self._in_saved = False

    def database_closed(self):
        global _active_viewer
        _active_viewer = None
        self._is_closing_database = False

    def _record_current_state(self):
        global _active_viewer
        if _active_viewer is not None and _active_viewer.GetWidget() is not None:
            try:
                _active_viewer.save_state(is_open=True)
            except Exception:
                pass

    def screen_ea_changed(self, ea, prev_ea):
        """Automatically follow current function in disassembly and sync line selection."""
        if not self.view or self.view._sync_lock:
            return
        if _active_viewer is not self.view:
            return
        pfn = ida_funcs.get_func(ea)
        if pfn is None:
            return
        if pfn.start_ea != self.view.current_func_ea:
            if self.view.sync_with_disasm:
                self.view.show_func(pfn.start_ea)
            else:
                return
        self.view.sync_from_disasm_ea(ea)

    def widget_closing(self, widget):
        """Called when a widget is closing."""
        global _active_viewer
        if self.view and widget == self.view.GetWidget():
            self.view.clear_asm_highlights()
            if not self._is_closing_database and self.view.current_func_ea is not None:
                self.view.save_state(is_open=False)
            _active_viewer = None

    def widget_invisible(self, widget):
        """Called when widget becomes invisible (e.g. switching tabs). DO NOT mark is_open=False!"""
        if self.view and widget == self.view.GetWidget():
            self.view.clear_asm_highlights()

    def finish_populating_widget_popup(self, widget, popup_handle):
        """Attach decompiler context actions to the right-click popup menu."""
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_DECOMPILE)
            return

        if not self.view:
            return
        view_widget = self.view.GetWidget()
        if widget != view_widget:
            return

        # Contextual modifications
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RENAME)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_SET_TYPE)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_EDIT_COMMENT)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RESET_ITEM)

        # Number format conversions
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_TOGGLE_HEX_DEC)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_CVT_CHAR)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_CVT_OFFSET)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_INVERT_SIGN)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_BITWISE_NEGATE)

        # Structure / flow
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_INVERT_IF)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_TOGGLE_CASTS)

        # Navigation & refresh
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_JUMP_XREF)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_JUMP_BRACE)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_JUMP_DISASM)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_TOGGLE_SYNC)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_REFRESH)


class _CustViewHooks(ida_kernwin.View_Hooks):
    def __init__(self, view):
        super().__init__()
        self.view = view

    def view_curpos(self, view):
        """Called whenever cursor position changes in any view."""
        if self.view and view == self.view.GetWidget():
            self.view.on_cursor_changed()

    def view_click(self, view, event):
        """Called on mouse click in view."""
        if self.view and view == self.view.GetWidget():
            self.view.on_cursor_changed()

    def view_close(self, view):
        """Called when view is closed."""
        if self.view and view == self.view.GetWidget():
            self.view.clear_asm_highlights()


ALL_DECOMPILER_ACTIONS = [
    ACTION_DECOMPILE,
    ACTION_RENAME,
    ACTION_SET_TYPE,
    ACTION_EDIT_COMMENT,
    ACTION_RESET_ITEM,
    ACTION_TOGGLE_HEX_DEC,
    ACTION_CVT_CHAR,
    ACTION_CVT_OFFSET,
    ACTION_INVERT_SIGN,
    ACTION_BITWISE_NEGATE,
    ACTION_INVERT_IF,
    ACTION_TOGGLE_CASTS,
    ACTION_JUMP_XREF,
    ACTION_JUMP_BRACE,
    ACTION_TOGGLE_SYNC,
    ACTION_JUMP_DISASM,
    ACTION_REFRESH,
]


def _register_actions(view):
    """Register IDA actions for popup menu."""
    actions = [
        (ACTION_RENAME, "Rename variable/symbol... (N)", view.on_rename),
        (ACTION_SET_TYPE, "Set variable/function type... (Y)", view.on_set_type),
        (ACTION_EDIT_COMMENT, "Edit statement comment... (/)", view.on_edit_comment),
        (ACTION_RESET_ITEM, "Reset item to default (Del)", view.on_reset_item),
        (ACTION_TOGGLE_HEX_DEC, "Toggle Hex/Decimal (H)", view.on_toggle_hex_dec),
        (ACTION_CVT_CHAR, "Convert to character constant (R)", view.on_convert_char),
        (ACTION_CVT_OFFSET, "Convert to offset/symbol (O)", view.on_convert_offset),
        (ACTION_INVERT_SIGN, "Invert sign (_)", view.on_invert_sign),
        (ACTION_BITWISE_NEGATE, "Bitwise negate (~)", view.on_bitwise_negate),
        (ACTION_INVERT_IF, "Invert if-condition (I)", view.on_invert_if),
        (ACTION_TOGGLE_CASTS, "Toggle type casts (\\)", view.on_toggle_casts),
        (ACTION_JUMP_XREF, "Jump to xref (X)", view.on_jump_xref),
        (ACTION_JUMP_BRACE, "Jump to matching brace (B)", view.on_jump_matching_brace),
        (ACTION_TOGGLE_SYNC, "Sync with Disassembly (Tab)", view.toggle_sync),
        (ACTION_JUMP_DISASM, "Jump to Disassembly / Callee (Enter)", view.jump_disasm),
        (ACTION_REFRESH, "Refresh Decompilation (F5)", lambda: view.show_func(view.current_func_ea)),
    ]
    for action_id, label, callback in actions:
        ida_kernwin.unregister_action(action_id)
        desc = ida_kernwin.action_desc_t(
            action_id,
            label,
            _ActionHandler(view, callback),
            None,
            label
        )
        ida_kernwin.register_action(desc)


def show(function, dock=True):
    """Open or refresh the dockable decompiler view for the specified function."""
    global _active_viewer, _ui_hooks, _view_hooks
    if _active_viewer is None or _active_viewer.GetWidget() is None:
        v = _DecompilerView()
        if not v.Create(_VIEW_TITLE):
            return None
        _active_viewer = v
        _register_actions(_active_viewer)

        if _ui_hooks is None and ida_kernwin:
            _ui_hooks = _UiHooks(_active_viewer)
            _ui_hooks.hook()
        elif _ui_hooks is not None:
            _ui_hooks.view = _active_viewer

        if _view_hooks is None and ida_kernwin:
            _view_hooks = _CustViewHooks(_active_viewer)
            _view_hooks.hook()
        elif _view_hooks is not None:
            _view_hooks.view = _active_viewer
    else:
        if _ui_hooks is not None:
            _ui_hooks.view = _active_viewer
        if _view_hooks is not None:
            _view_hooks.view = _active_viewer

    if isinstance(function, int):
        _active_viewer.show_func(function)
    else:
        _active_viewer.build_or_refresh(function)
    _active_viewer.Show()

    # Dock beside IDA View-A if in GUI mode
    if dock and ida_kernwin and hasattr(ida_kernwin, "is_idaq") and ida_kernwin.is_idaq():
        try:
            disasm_w = ida_kernwin.find_widget("IDA View-A")
            my_w = _active_viewer.GetWidget()
            if disasm_w and my_w:
                ida_kernwin.display_widget(
                    my_w,
                    ida_kernwin.WOPN_DP_TAB | ida_kernwin.WOPN_RESTORE,
                    disasm_w
                )
        except Exception:
            pass

    _active_viewer.save_state(is_open=True)
    return _active_viewer


def restore_view(ea, config=None, display=True):
    """Restore decompiler view for function at ea with persistent settings."""
    global _active_viewer, _ui_hooks, _view_hooks
    try:
        pfn = ida_funcs.get_func(ea)
        entry = pfn.start_ea if pfn else ea
        fn = ida_bridge.decompile_one(entry)
    except Exception as exc:
        print("lm32dec: restore failed for 0x%X: %s" % (ea, exc))
        return None

    if _active_viewer is None or _active_viewer.GetWidget() is None:
        v = _DecompilerView()
        if not v.Create(_VIEW_TITLE):
            return None
        _active_viewer = v
        _register_actions(_active_viewer)

        if _ui_hooks is None and ida_kernwin:
            _ui_hooks = _UiHooks(_active_viewer)
            _ui_hooks.hook()
        elif _ui_hooks is not None:
            _ui_hooks.view = _active_viewer

        if _view_hooks is None and ida_kernwin:
            _view_hooks = _CustViewHooks(_active_viewer)
            _view_hooks.hook()
        elif _view_hooks is not None:
            _view_hooks.view = _active_viewer
    else:
        v = _active_viewer
        if _ui_hooks is not None:
            _ui_hooks.view = v
        if _view_hooks is not None:
            _view_hooks.view = v

    cfg = config or {}
    v.sync_with_disasm = cfg.get("sync", db.get_sync_enabled())
    v.build_or_refresh(fn)

    lineno = max(0, cfg.get("lineno", 0))
    col = max(0, cfg.get("col", 0))
    if lineno > 0:
        try:
            v.Jump(lineno, col)
        except Exception:
            pass

    if display:
        v.Show()
        if ida_kernwin and hasattr(ida_kernwin, "is_idaq") and ida_kernwin.is_idaq():
            try:
                disasm_w = ida_kernwin.find_widget("IDA View-A")
                my_w = v.GetWidget()
                if disasm_w and my_w:
                    ida_kernwin.display_widget(
                        my_w,
                        ida_kernwin.WOPN_DP_TAB | ida_kernwin.WOPN_RESTORE,
                        disasm_w
                    )
            except Exception:
                pass

    v.save_state(is_open=True)
    return v


def check_and_restore_saved_view():
    """Restore decompiler view from database netnode if it was open when saved."""
    if not ida_kernwin or (hasattr(ida_kernwin, "is_idaq") and not ida_kernwin.is_idaq()):
        return None
    existing = ida_kernwin.find_widget(_VIEW_TITLE)
    if existing is not None:
        return None
    st = db.load_window_state()
    if st and st.get("is_open") and st.get("func_ea") is not None:
        return restore_view(st["func_ea"], config=st, display=True)
    return None


def init_hooks():
    """Initialize UI hooks early (at plugin load) to support desktop/docking persistence."""
    global _ui_hooks, _view_hooks
    if _ui_hooks is None and ida_kernwin:
        _ui_hooks = _UiHooks(None)
        _ui_hooks.hook()
    if _view_hooks is None and ida_kernwin:
        _view_hooks = _CustViewHooks(None)
        _view_hooks.hook()


def show_listing(title, lines):
    """Fallback simple viewer for whole-program export listing."""
    v = ida_kernwin.simplecustviewer_t()
    if v.Create(title):
        for ln in lines:
            v.AddLine(highlight.colorize(ln))
        v.Show()
        return v
    return None


def cleanup():
    """Unregister hooks and actions on plugin unload."""
    global _active_viewer, _ui_hooks, _view_hooks
    if _active_viewer is not None:
        try:
            _active_viewer.clear_asm_highlights()
        except Exception:
            pass
    if _ui_hooks is not None:
        try:
            _ui_hooks.unhook()
        except Exception:
            pass
        _ui_hooks = None
    if _view_hooks is not None:
        try:
            _view_hooks.unhook()
        except Exception:
            pass
        _view_hooks = None
    for action_id in ALL_DECOMPILER_ACTIONS:
        try:
            ida_kernwin.unregister_action(action_id)
        except Exception:
            pass
    _active_viewer = None
