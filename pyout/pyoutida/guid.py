import _winreg
import idc
import idaapi
import json
from pyout.classes.logger import Logger
from pyout.util.guid import GuidHelper
from pyout.pyoutida import MODS
struct = MODS.struct


class Guid:
    """ IDA guid handler """

    def __init__(self, obj=None):
        try:
            self.struct = struct.Struct("IID")
            self.struct2 = struct.Struct("GUID")
        except:
            pass
        self.obj = obj

    def updateIIDs(self, **kwargs):
        h = GuidHelper()
        inst = self.struct.instances()
        inst.update(self.struct2.instances())
        busy = []
        for x in inst:
            n = h.guidOfVals((inst[x]['Data1'], inst[x]['Data2'], inst[x]['Data3'], inst[x]['Data4']))
            found = h.findGuid(n)
            if found:
                nm = found['name']
                for c in " ,.:;-+<>/*":
                    nm = nm.replace(c, '_')
                for c in nm:
                    if ord(c) > 0x7F:
                        nm = nm.replace(c, '_')
                if found['prefix'] and not nm.startswith(found['prefix']):
                    nm = found['prefix'] + "_" + nm
            else:
                nm = "iid_" + str(n).replace('-', '_')

            rnm = nm
            if nm:
                if idc.Name(x).startswith(nm):
                    busy += [nm]
                    continue
                i = 2
                while nm in busy and i < 10:
                    nm = rnm + "__" + str(i)
                    i += 1
                while (idaapi.get_name_ea(idc.BADADDR, nm) != idc.BADADDR or not idc.MakeName(x, nm)) and i < 10:
                    nm = rnm + "__" + str(i)
                    i += 1
                busy += [nm]

    def guidAtAddr(self, addr):
        val = [idc.Dword(addr), idc.Word(addr + 4), idc.Word(addr + 6), []]
        addr += 8
        val[3] = [idc.Byte(addr + i) for i in range(8)]
        h = GuidHelper()
        guid = h.guidOfVals(val)
        val = h.findGuid(guid)
        return (val or guid)

    def printGuid(self, addr=None, **kwargs):
        addr = addr or idaapi.get_screen_ea()
        Logger.info(self.guidAtAddr(addr))

    def explore(self, **kwargs):
        if not "IID" in self.obj['type'] and not "GUID" in self.obj['type'] and not "CLSID" in self.obj['type']:
            return ""
        addr = int(self.obj['val'])  # MODS.util.derefType(self.obj['val'], self.obj['type'])
        return "GUID:" + self.guidAtAddr(addr)
