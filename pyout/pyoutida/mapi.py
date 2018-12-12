from pyout.enums.mapi import MapiEnum
import idc
from pyout.pyoutida import MODS


class MapiExplorer:

    def __init__(self, var):
        self.var = var

    def explore(self, **kwargs):
        res = ""
        x = self.var
        addr = MODS.util.derefType(x['val'], x['type'])
        if not addr:
            return res
        if x['type'].startswith("LPSPropValue"):
            cnt = kwargs.get('cValues')
            if not cnt:
                c = MODS.explore.Explore('cValues').run({"quiet": True, "nothrow": True})
                if c:
                    cnt = c[0].get('val')
            res += self.getPropVal(addr, cnt)
        if x['type'].startswith("SPropTagArray"):
            res += self.getPropTagArray(addr)
        return res

    def bin2str(self, data):
        res = ''
        for i in range(len(data)):
            if data[i] != 0:
                res += data[i] if data[i] >= ' ' else '.'
        return res

    def arrFormat(self, arr, fmt='08X', delim=', '):
        return delim.join([('{0:' + fmt + '}').format(x) for x in arr])

    def hexFormat(self, arr):
        return self.arrFormat([ord(b) for b in arr], '02X', '')

    def getPropValue(self, tp, v1, v2):
        if tp == MapiEnum.PT_BINARY:
            data = idc.GetManyBytes(v2, int(v1 & 0xFFFFFFFF))
            data = self.hexFormat(data) + ' (' + self.bin2str(data) + ')'
        elif tp == MapiEnum.PT_STRING:
            data = idc.GetString(v1)
        elif tp == MapiEnum.PT_UNICODE_STRING:
            data = idc.GetString(v1, -1, idc.ASCSTR_UNICODE)
        elif tp == MapiEnum.PT_INT:
            data = hex(v1 & 0xFFFFFFFF)
        elif tp == MapiEnum.PT_SHORT or tp == MapiEnum.PT_BOOLEAN:
            data = hex(v1 & 0xFFFF)
        elif tp == MapiEnum.PT_APPTIME or tp == MapiEnum.PT_SYSTIME:
            data = hex(v1)
        else:
            data = ''
        return data

    def getPropVal(self, addr, cnt=1):
        cnt = cnt or 1
        res = ""
        mp = MapiEnum()
        for x in range(cnt):
            tp = idc.Dword(addr)
            v1 = idc.Qword(addr + 8)
            v2 = idc.Qword(addr + 0x10)
            data = self.getPropValue(tp & 0xFFFF, v1, v2)
            res += str(x) + ": type " + hex(tp) + " " + mp.name(tp) + " = " + str(data) + "\n"
            addr += 0x18
        return res

    def getPropTagArray(self, addr):
        cnt = idc.Dword(addr)
        if cnt == idc.BADADDR:
            return ''
        arr = []
        for i in range(cnt):
            addr += 4
            arr += [idc.Dword(addr)]
        return 'count:{0}\n[{1}]\n'.format(cnt, self.arrFormat(arr, '04X', ', '))
