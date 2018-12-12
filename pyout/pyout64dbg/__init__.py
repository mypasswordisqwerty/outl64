import sys
import importlib


class _Mods:

    def __init__(self):
        self.loaded = {}

    def reload(self):
        for x in self.loaded:
            nm = "pyout.pyout64dbg." + x
            sys.modules[nm] = reload(sys.modules[nm])
            self.loaded[x] = sys.modules[nm]

    def __getattr__(self, attr):
        if attr not in self.loaded:
            nm = "pyout.pyout64dbg." + attr
            m = importlib.import_module(nm)
            sys.modules[nm] = m
            self.loaded[attr] = sys.modules[nm]
        return self.loaded[attr]


MODS = _Mods()


__all__ = (MODS)
