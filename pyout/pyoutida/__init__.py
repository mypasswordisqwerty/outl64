import idaapi
import sys
from .hexrays import HexraysPlugin


class _Mods:

    def __init__(self):
        self.loaded = {}

    def reload(self):
        for x in self.loaded:
            nm = "pyout.pyoutida." + x
            idaapi.require(nm)
            self.loaded[x] = sys.modules[nm]

    def __getattr__(self, attr):
        if attr not in self.loaded:
            nm = "pyout.pyoutida." + attr
            idaapi.require(nm)
            self.loaded[attr] = sys.modules[nm]
        return self.loaded[attr]


MODS = _Mods()


__all__ = (MODS, HexraysPlugin)
