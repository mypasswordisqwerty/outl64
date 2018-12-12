from x64dbgpy import pluginsdk
from pyout.util.guid import GuidHelper
from pyout.classes.logger import Logger


class Guid:

    def __init__(self):
        pass

    def info(self, addr):
        v = [pluginsdk.ReadDword(addr), pluginsdk.ReadWord(addr + 4), pluginsdk.ReadWord(addr + 6), []]
        addr += 8
        for i in range(8):
            v[3] += [pluginsdk.ReadByte(addr)]
            addr += 1
        h = GuidHelper()
        g = h.guidOfVals(v)
        info = h.findGuid(g)
        if not info:
            Logger.info("Guid %s not found", str(g))
        else:
            Logger.info(str(info))
