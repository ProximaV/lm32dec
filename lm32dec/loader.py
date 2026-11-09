"""
Image loading and entry point discovery for LatticeMico32 (LM32) firmware.

LM32 exception vectors are located at the Exception Base Address (EBA),
spaced 32 bytes (0x20) apart:
    0x00: Reset
    0x20: Breakpoint
    0x40: Instruction Bus Error
    0x60: Watchpoint
    0x80: Data Bus Error
    0xA0: Divide by Zero
    0xC0: Interrupt
    0xE0: System Call
"""

from . import decoder

LM32_VECTOR_OFFSETS = (0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0)


def load(path):
    with open(path, "rb") as fp:
        return bytearray(fp.read())


def detect_base(image, is_be=True):
    """Infer the link base from the reset vector or default to 0."""
    if len(image) >= 4:
        ins = decoder.decode_one(image, 0, base=0, is_be=is_be)
        if ins is not None and ins.mnem in ("bi", "calli"):
            t = decoder.target_of(ins)
            if t is not None:
                # If target is above 4 KiB, it may indicate a link base
                if t >= 0x1000:
                    return t & ~0xFFF, t
                return 0, t
    return 0, 0


def vector_entries(image, base=0, is_be=True):
    """Return discovered exception vector entries and reset targets."""
    entries = []
    seen = set()

    # Check the standard vector table slots
    for off in LM32_VECTOR_OFFSETS:
        if off + 4 <= len(image):
            ea = base + off
            ins = decoder.decode_one(image, ea, base=base, is_be=is_be)
            if ins is not None:
                t = decoder.target_of(ins)
                if t is not None and base <= t < base + len(image):
                    if t not in seen:
                        seen.add(t)
                        entries.append(t)
                else:
                    if ea not in seen:
                        seen.add(ea)
                        entries.append(ea)

    # Scan the first 0x200 bytes for additional calls or branches
    for off in range(0, min(0x200, len(image) - 3), 4):
        ea = base + off
        ins = decoder.decode_one(image, ea, base=base, is_be=is_be)
        if ins is not None and ins.mnem in ("calli", "bi"):
            t = decoder.target_of(ins)
            if t is not None and base <= t < base + len(image) and t not in seen:
                seen.add(t)
                entries.append(t)

    return entries
