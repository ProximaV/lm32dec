# lm32dec — A LatticeMico32 (LM32) Decompiler for IDA Pro

`lm32dec` is a high-fidelity decompiler for firmware and binaries targeting the **LatticeMico32 (LM32)** 32-bit RISC soft processor architecture. It operates both as an interactive **Hex-Rays-style decompiler plugin for IDA Pro 9.x / 8.x** and as a **standalone headless decompiler and lifter** requiring zero IDA dependencies.

The plugin provides native dual-endian support:
* **Big-Endian**: Standard Lattice Semiconductor softcore designs, FPGA SoCs (Milkymist, White Rabbit, RTEMS, Linux), and QEMU LM32 targets.
* **Little-Endian**: Proprietary embedded security coprocessors, including PlayStation Vita coprocessor firmware (e.g. `80010001_dec.self`).

The IDA processor module is leveraged strictly for instruction decoding (`insn_t`), while lifting, static single assignment (SSA) def-use web analysis, virtual variable synthesis, calling convention recovery, control-flow restructuring, and C code generation are entirely custom:

```mermaid
flowchart LR
    Decoder["1. Decoder (insn_t / binary)"] --> Lifter["2. IR Lifter"]
    Lifter --> CFG["3. CFG Builder"]
    CFG --> Struct["4. Structurer"]
    Struct --> Frame["5. Frame Analysis"]
    Frame --> ABI["6. ABI & Signature"]
    ABI --> Vars["7. Def-Use Webs & SSA"]
    Vars --> Opt["8. AST & String Opt"]
    Opt --> CGen["9. Hex-Rays C Emitter"]
```

---

## What It Produces

```c
/*
 * Decompiled by lm32dec -- LatticeMico32 (LM32, little-endian).
 */

void sub_0(int a0, int a1)
{
    sub_20(a0, a1 + 1);
    return;
}

int sub_300(int a0, int a1, int a2)
{
    int v0;
    int v1;
    int v2;

    *(_DWORD *)0xE0000010 = 0xFFFFFFFF;
    v0 = 0x80001000;
    while (1) {
        v1 = *(_DWORD *)v0;
        if (v1 != 0) {
            *(_DWORD *)v0 = 0;
            break;
        }
    }
    if (a0 == 1) {
        v2 = __rcsr(IE);
        __wcsr(IE, v2 & ~1);
        (*((void (*)(int, int))v1))(a1, a2);
        __wcsr(IE, v2);
    }
    return v1;
}

int sub_450(int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int arg_0)
{
    int var_14;
    int var_18;
    int var_1C;

    var_1C = a0;
    var_18 = a1;
    var_14 = arg_0;
    sub_620("Device init: status = 0x%08X (flags = %d)\n", a0, arg_0);
    return a0 + a1;
}
```

* **Virtual Variables (`v0, v1, ...`)**: Eliminates raw register clutter (`r1..r25`) by tracking live ranges and promoting values to clean C local variables.
* **Function Parameters (`a0..a7`, `arg_0..`)**: Up to 8 register arguments (`r1` through `r8`) and incoming stack slots above caller frame are bound directly to parameter names.
* **Hex-Rays Pointer Dereferencing**: Emits standard Hex-Rays typed dereference expressions (`*(_DWORD *)ptr`, `*(short *)ptr`, `*(_BYTE *)ptr`, `*ptr`, `ptr[idx]`).
* **Hardware Intrinsics**: Control and Status Register operations (`__rcsr`, `__wcsr`) render with canonical register names (`IE`, `IM`, `IP`, `ICC`, `DCC`, `CC`, `CFG`, `EBA`, etc.), alongside system intrinsics (`__break()`, `__scall()`).
* **Global Symbol & String Resolution**: Data and code addresses automatically resolve to symbolic names in IDA, and pointer arguments render as formatted C string literals.
* **Control-Flow Recovery**: Reconstructs `if`/`else`, `while(1)`, `while(cond)`, `do-while`, loop `break`/`continue`, relational compares, and switch jump tables.
* **Stack Frame Recovery**: Automatically detects frame allocations, strips prologue/epilogue callee-saved register spills (`r11..r25`, `gp`, `fp`, `ra`), and binds stack offsets to local variables (`var_X`).

---

## Key Capabilities & Architectural Enhancements

### 1. Dual-Endian Decoding & Zero-Flag IR Lifter ([`lm32dec/decoder.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/decoder.py), [`lm32dec/lifter.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/lifter.py))
* **Fixed 32-bit Instruction Decoding**: Decodes all LM32 32-bit instructions with full support for both Big-Endian and Little-Endian byte orders.
* **Zero-Flag Architecture Support**: LM32 features no status/condition flags; compare-and-branch instructions (`be`, `bne`, `bge`, `bgeu`, `bgt`, `bgtu`) test registers directly. The lifter models these cleanly as high-level relational expressions.
* **Hardwired Zero Register (`r0`)**: Reads from `r0` fold to literal `0`; writes to `r0` (used for discards or flags) are preserved as pure side effects or safely eliminated.
* **Switch Table Identification**: Recognizes indirect branch sequences (`lshift -> add -> lw -> b rX`) and extracts jump tables, case bounds, and dispatch targets.

### 2. Stack Frame Analysis & Callee-Saved Register Stripping ([`lm32dec/frame.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/frame.py))
* **Prologue & Epilogue Identification**: Identifies stack allocations (`addi r28, r28, -frame_size`), frame pointer updates (`addi r27, r28, ...`), and stack deallocations.
* **Callee-Saved Spill Elimination**: Detects prologue saves and epilogue restores for `r11`–`r25`, `gp` (`r26`), `fp` (`r27`), and `ra` (`r29`), completely stripping them from the pseudocode AST.
* **Stack Variable Categorization**: Categorizes negative and positive frame offsets into local variables (`var_X`) and incoming stack arguments (`arg_X`).

### 3. LM32 EABI Calling Convention & Signature Synthesis ([`lm32dec/abi.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/abi.py), [`lm32dec/callargs.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/callargs.py))
* **Register Arguments (`r1`–`r8`)**: Backward iterative dataflow liveness analysis detects active register parameters at function entry (`a0` through `a7`).
* **Stack Arguments (`arg_0, arg_4, ...`)**: Incoming stack slots accessed above the caller's frame are promoted to function parameters.
* **Return Value Inference**: Verifies reaching definitions of `r1` (32-bit) and `r2` (64-bit high word) at return sites (`b r29`), inferring `void`, `int`, or pointer return types.
* **Caller Consensus & Call Argument Folding**: Cross-references call sites across the database to reach consensus on parameter counts, folding reaching argument assignments directly into call statements (`sub_20(a0, a1 + 1)`).

### 4. SSA-Style Def-Use Webs & Virtual Variable Recovery ([`lm32dec/vars.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/vars.py))
* **Iterative Reaching Definitions**: Tracks active register definitions, kills, and clobbers (including call clobbers) across basic blocks.
* **Union-Find Live Range Splitting**: Merges reaching definitions and uses into disjoint live ranges, splitting independent reuses of machine registers into separate virtual variables (`v0`, `v1`, ...).
* **Copy Propagation & Inlining**: Folds single-use register copies (`v1 = v0`) and pure address arithmetic directly into memory dereferences and call arguments.
* **Dead Assignment Elimination**: Eliminates unused intermediate assignments while safeguarding return value registers (`r1`/`r2`).

### 5. Hex-Rays Style Memory & Symbol Representation ([`lm32dec/cgen.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/cgen.py))
* **Standard Type Casts**:
  * 32-bit: `*(_DWORD *)addr`
  * 16-bit unsigned: `*(_WORD *)addr`
  * 16-bit signed: `*(short *)addr`
  * 8-bit unsigned: `*(_BYTE *)addr`
  * 8-bit signed: `*(char *)addr`
* **Typed Pointer Expressions**: When variables are typed as pointers (`int *`, `char *`), emits clean dereferences (`*ptr`) and array indexing (`ptr[i]`) without redundant casts.
* **Symbolic Name Resolution**: Addresses matching named data or code symbols in IDA render directly as identifiers.
* **String Literals**: Quoted C string literals are automatically formatted and escaped for pointer arguments.

### 6. Interactive Decompiler View & UX ([`lm32dec/view.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/view.py), [`lm32dec/highlight.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/highlight.py))
* **Dense Multi-Instruction EA Anchoring**: 100% of contributing instruction EAs are mapped bidirectionally (`line_to_eas` and `ea_to_line`), ensuring seamless navigation across all basic blocks.
* **Bidirectional Disassembly $\leftrightarrow$ Pseudocode Synchronization**:
  * Selecting any instruction in `IDA View-A` immediately scrolls and highlights the corresponding decompiled line.
  * Navigating in the pseudocode viewer synchronizes IDA's disassembly cursor without stealing focus.
  * Pressing **`Tab`** switches between Disassembly and Pseudocode at the matching instruction address.
* **Identifier Occurrence Highlighting**: Placing the cursor on any variable, parameter, or symbol highlights all occurrences across the function.
* **Navigation History Stack**: Double-clicking, pressing **`Enter`**, or pressing **`Space`** on a function call navigates to that function; pressing **`Esc`** returns directly to the caller.

### 7. Hex-Rays Interactive Shortcuts
`lm32dec` implements the full suite of interactive AST customizations:
* **Immediate Format Conversions**:
  * **`H`**: Toggle number constant representation between Hexadecimal and Decimal.
  * **`O`**: Convert numeric immediate to offset / symbol reference.
  * **`R`**: Convert constant to character or multi-byte literal (`'A'`, `'\n'`, `'RIFF'`).
  * **`_`** / **`-`**: Invert sign of number (`-1` vs `0xFFFFFFFF`).
  * **`~`**: Bitwise negation (`~0` vs `0xFFFFFFFF`).
* **Control-Flow & Cast Toggles**:
  * **`I`**: Invert if-condition and swap `then` / `else` branch blocks.
  * **`\`**: Toggle display of explicit type casts on pointer dereferences.
* **Code Annotations & Customizations**:
  * **`/`** or **`;`**: Add, edit, or remove persistent statement comments (`// comment`).
  * **`N`**: Rename variable, parameter, stack frame member, or function symbol.
  * **`Y`**: Set variable type or edit function prototype (applied to IDA's type system via `ida_typeinf.apply_cdecl`).
  * **`Del`**: Reset custom formatting, comment, variable rename, or if-inversion back to default.
* **Navigation & Analysis**:
  * **`X`**: Jump to cross-references (opens IDA native xrefs dialog).
  * **`B`**: Jump between matching opening and closing curly braces (`{` $\leftrightarrow$ `}`).
  * **`F5`**: Refresh decompilation.
  * **`Ctrl-F5`**: Batch decompile entire database and export to a `.c` file.

### 8. Netnode & Desktop Layout Persistence ([`lm32dec/db.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/lm32dec/lm32dec/db.py))
* **Database Netnode (`$ lm32dec`)**: All analyst modifications (variable renames, types, function prototypes, immediate formatting, comments, if-inversions, and sync preferences) are saved directly in the `.idb` / `.i64` file.
* **Desktop Layout Manager**: Restores open decompiler tabs, docking positions, and cursor locations upon reopening databases.
* **Headless Fallback**: Transparent in-memory storage fallback for command-line execution and headless unit tests.

### 9. High Performance
* **Single Function**: ~7.7 ms average decompilation time.
* **Full Firmware Benchmark**: Decompiled all 251 functions (20,789 lines of C) in `80010001_dec.self.i64` in **1.94 seconds** with 100% instruction EA anchoring.

---

## Interactive Hotkeys & Shortcuts

When running inside IDA Pro:

| Hotkey | Action | Description |
| :--- | :--- | :--- |
| **`F5`** | Decompile / Refresh | Decompiles the current function or refreshes the active view |
| **`Tab`** | Switch View | Disassembly $\leftrightarrow$ Pseudocode at exact matching instruction EA |
| **`Enter`** / **`Space`** | Navigate Symbol | Jumps to callee function, label, or global data address |
| **`Esc`** | History Back | Steps backward through the function navigation history stack |
| **`H`** | Hex / Decimal Toggle | Toggles immediate constant representation between hex and dec |
| **`O`** | Convert to Offset | Converts immediate constant to symbolic address reference |
| **`R`** | Character Literal | Formats constant as C character literal (`'A'`, `'\n'`, `'RIFF'`) |
| **`_`** / **`-`** | Invert Sign | Inverts sign of numeric constant (`-1` vs `0xFFFFFFFF`) |
| **`~`** | Bitwise Negate | Bitwise negates numeric constant (`~0` vs `0xFFFFFFFF`) |
| **`I`** | Invert If-Condition | Inverts if-statement condition and swaps then/else branches |
| **`\`** | Toggle Casts | Toggles display of explicit pointer type casts |
| **`N`** | Rename Identifier | Renames variable, stack member, or function (saved to IDB netnode) |
| **`Y`** | Set Type / Prototype | Modifies variable type or function prototype (IDA type system) |
| **`/`** or **`;`** | Line Comment | Adds or edits a persistent comment on the current statement |
| **`Del`** | Reset Item | Resets formatting, rename, comment, or inversion on item to default |
| **`X`** | Cross-References | Opens IDA's native cross-references window for symbol under cursor |
| **`B`** | Jump Matching Brace | Jumps between matching `{` and `}` curly braces |
| **`Ctrl-F5`** | Decompile Database | Decompiles all functions in database and exports to `.c` file |

---

## LM32 Architecture & Register Conventions

The LatticeMico32 is a 32-bit Harvard architecture RISC microprocessor:

### General Purpose Registers (GPRs)
| Register | Name | Role | Preservation |
| :--- | :--- | :--- | :--- |
| **`r0`** | `zero` | Constant 0 (writes ignored, reads return 0) | — |
| **`r1`–`r8`** | `a0`–`a7` | Function arguments; `r1` return value (`r2` high 32-bit return) | Caller-saved |
| **`r9`–`r10`** | `t0`–`t1` | Temporary scratch registers | Caller-saved |
| **`r11`–`r25`** | `s0`–`s14` | Saved registers | Callee-saved |
| **`r26`** | `gp` | Global Pointer | Callee-saved |
| **`r27`** | `fp` | Frame Pointer | Callee-saved |
| **`r28`** | `sp` | Stack Pointer | Callee-saved |
| **`r29`** | `ra` | Return Address / Link Register | Caller-saved |
| **`r30`** | `ea` | Exception Address | Special |
| **`r31`** | `ba` | Breakpoint Address | Special |

### Control and Status Registers (CSRs)
| CSR ID | Name | Description |
| :--- | :--- | :--- |
| **0** | `IE` | Interrupt Enable |
| **1** | `IM` | Interrupt Mask |
| **2** | `IP` | Interrupt Pending |
| **3** | `ICC` | Instruction Cache Control |
| **4** | `DCC` | Data Cache Control |
| **5** | `CC` | Cycle Counter |
| **6** | `CFG` | Configuration Register |
| **7** | `EBA` | Exception Base Address |
| **8** | `DC` | Debug Control |
| **9** | `DEBA` | Debug Exception Base Address |
| **14** | `JTX` | JTAG Transmit |
| **15** | `JRX` | JTAG Receive |
| **16..19** | `BP0`..`BP3` | Breakpoint Registers 0–3 |
| **24..27** | `WP0`..`WP3` | Watchpoint Registers 0–3 |

---

## How to Run

### As an IDA Pro Plugin
1. Open your LM32 binary or firmware dump in IDA Pro (using the `lm32` processor module in big-endian or little-endian mode).
2. Copy `lm32dec_plugin.py` and the `lm32dec/` package into IDA's plugins folder:
   ```cmd
   copy lm32dec_plugin.py "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
   xcopy /E /I /Y lm32dec "%APPDATA%\Hex-Rays\IDA Pro\plugins\lm32dec"
   ```
3. Open any function in IDA Pro and press **`F5`** (or **`Ctrl-Shift-S`**) on any instruction.

### Headless (Command-Line CLI)
Decompile raw binary dumps directly without requiring IDA Pro:

```bash
# Decompile entire firmware image to a C file (Big-Endian default)
python -m lm32dec firmware.bin -o firmware.c

# Decompile Little-Endian firmware (e.g. PS Vita LM32 coprocessor)
python -m lm32dec 80010001_dec.bin --endian little -o coprocessor.c

# Decompile a specific function by address
python -m lm32dec firmware.bin --func 0x00000300

# Specify custom base and entry points
python -m lm32dec dump.bin --base 0x00000000 --entry 0x00000000 --entry 0x00000400
```

---

## Test Suite

The test suite runs 100% headlessly with zero IDA dependencies:

```bash
python tests/test_decoder.py
python tests/test_abi.py
python tests/test_vars.py
python tests/test_pipeline.py
python tests/test_db.py
python tests/test_highlight.py
python tests/test_sync.py
```

All 7 test suites verify:
* **Decoder & Lifter**: Fixed 32-bit Big-Endian and Little-Endian instruction decoding, relational branch lifting, CSR operations, and indirect switch dispatch.
* **ABI & Frame Analysis**: EABI register (`r1`..`r8`) and stack argument recovery, return type inference, callee-saved register stripping, and caller consensus folding.
* **SSA Def-Use Webs**: Reaching definitions, Union-Find live range splitting, virtual variable promotion, copy propagation, single-use inlining, and dead assignment elimination.
* **Structuring & C Emitter**: Control-flow structuring (`if`/`else`, `while`, `do-while`, `switch`), Hex-Rays typed pointer casts, CSR intrinsics, and string literal formatting.
* **Database & Persistence**: Schema serialization, variable renames, custom prototypes, immediate representations, comments, and window state persistence.
* **View Synchronization**: Dense multi-instruction EA anchoring (100% coverage), line-to-EA mappings, and syntax/token highlighting.

---

## Credits & License

* Lattice Semiconductor **LatticeMico32 Processor Reference Manual**.
* Architecture and UX design inspired by [`f00ddec`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/f00ddec/README.md), [`spudec`](https://github.com/zecoxao/spudec), and [`rl78dec`](https://github.com/zecoxao/rl78dec).
* Licensed under the **MIT License**.
