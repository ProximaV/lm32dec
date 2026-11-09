"""
Code, label, and string naming for LatticeMico32 (LM32).
Inside IDA, the Namer is fed IDA's own names. Headless, it defaults to sub_X / loc_X.
"""


class Namer:
    def __init__(self, code_names=None, strings=None):
        self.code_names = dict(code_names or {})
        self.strings = dict(strings or {})

    def code(self, ea):
        if ea is None:
            return "?"
        return self.code_names.get(ea) or ("sub_%X" % ea)

    def label(self, ea):
        return self.code_names.get(ea) or ("loc_%X" % ea)

    def data(self, ea):
        return self.code_names.get(ea)

    def string(self, key):
        if key in self.strings:
            return self.strings[key]
        return None
