from classes.singleton import Singleton
from classes.logger import Logger
try:
    from x64dbgpy import pluginsdk
    from pyout64dbg import MODS
except Exception as e:
    pluginsdk = None


class X64Dbg:
    """ pyout x64dbg helper """

    class NoX64DbgError(Exception):

        def __init__(self): Exception.__init__(self, "x64dbg context required")

    def __init__(self, verbose=False):
        if pluginsdk is None:
            raise X64Dbg.NoX64DbgError()
        Logger.setVerbose(verbose)

    @staticmethod
    def hasX64Dbg():
        return pluginsdk is not None

    def reload(self):
        MODS.reload()

    def __getattr__(self, name):
        meth = "Get" + name.upper()
        meth = getattr(pluginsdk, "Get" + name.upper())
        return meth() if meth else None

    def guid(self, addr):
        MODS.guid.Guid().info(addr)

    def bp(self, addr, callback, **kwargs):
        self.bpd(addr)
        MODS.breaks.Breaks(self).set(addr, callback, **kwargs)

    def bpd(self, addr):
        MODS.breaks.Breaks(self).remove(addr)
