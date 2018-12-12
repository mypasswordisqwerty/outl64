from x64dbgpy import pluginsdk, Breakpoint
from pyout.classes.logger import Logger


class Breaks:
    callbacks = {}
    x64 = None

    def __init__(self, x64):
        Breaks.x64 = x64

    @staticmethod
    def run():
        x = Breaks.x64
        Logger.info("break at %08X", x.rip)
        proc = Breaks.callbacks.get(x.rip)
        if proc:
            proc(x)

    def set(self, addr, callback, **kwargs):
        Breaks.callbacks[addr] = callback
        Breakpoint.add(addr, Breaks.run)

    def remove(self, addr):
        Breakpoint.remove(addr)
        if addr in Breaks.callbacks:
            del Breaks.callbacks[addr]
