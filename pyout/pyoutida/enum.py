import json
import idc
import os
import pyout
from pyout.classes.logger import Logger


class Enum:
    """ IDA enum handler """

    class EnumNotFoundError(Exception):

        def __init__(self, name):
            Exception.__init__(self, "Enum not found: " + name)

    def __init__(self, name, canCreate=False):
        if isinstance(name, (int, long)):
            name = str(name)
        self.name = name
        self.id = idc.GetEnum(name)
        self._vals = None
        self._names = None
        if self.id == idc.BADADDR:
            try:
                self.id = int(name)
                self.name = idc.GetEnumName(self.id)
            except Exception:
                self.name = None
                self.id = None
        if not self.name:
            if not canCreate:
                raise Enum.EnumNotFoundError(name)
            self.id = idc.AddEnum(idc.GetEnumQty(), name, 0)

    def getConsts(self, reload=False):
        if self._vals and not reload:
            return self._vals
        res = {}
        bm = idc.GetFirstBmask(self.id)
        while True:
            if bm not in res:
                res[bm] = {}
            c = idc.GetFirstConst(self.id, bm)
            while c != idc.BADADDR:
                cid = idc.GetConstEx(self.id, c, 0, bm)
                res[bm][c] = cid
                c = idc.GetNextConst(self.id, c, bm)
            if bm == idc.BADADDR:
                self._vals = res
                return res
            bm = idc.GetNextBmask(self.id, bm)

    def getName(self, val, reload=False):
        if not self._names or reload:
            self._names = {}
            cns = self.getConsts(reload)
            for x in cns:
                for y in cns[x]:
                    self._names[y] = idc.GetConstName(cns[x][y])
        return self._names.get(val)

    def deleteConst(self, cid):
        idc.DelConstEx(self.id, idc.GetConstValue(cid), 0, idc.GetConstBmask(cid))

    def clear(self):
        cs = self.getConsts()
        for bm in cs:
            for c, cid in cs[bm].iteritems():
                self.deleteConst(cid)

    def setBitfield(self, isBF=True):
        if isBF and idc.IsBitfield(self.id):
            return
        if not isBF and not idc.IsBitfield(self.id):
            return
        if isBF:
            self.clear()
        idc.SetEnumBf(self.id, 1 if isBF else 0)

    def setBMask(self, mask, name):
        idc.SetBmaskName(self.id, mask, name)

    def setMember(self, name, val, maskVal=None):
        const = idc.GetConstByName(name)
        if const and const != idc.BADADDR:
            # remove constant
            self.deleteConst(const)
        idc.AddConstEx(self.id, name, val, maskVal if maskVal else idc.BADADDR)

    @staticmethod
    def syncEnums(jsonFile, **kwargs):
        if not jsonFile:
            jsonFile = os.path.join(pyout.mypath("doc"), "mapienums.json")
        with open(jsonFile, "r") as f:
            enums = json.load(f)
        for ename in enums:
            Logger.debug("Sync enum %s", ename)
            e = Enum(ename.encode('ascii'), True)
            e.clear()
            masks = {}
            for nm, val in enums[ename].iteritems():
                nm = nm.encode('ascii')
                if isinstance(val, (str, unicode)):
                    val = eval(val)
                if nm.endswith('_MASK_'):
                    masks[val] = nm
                    e.setBitfield()
            for nm, val in enums[ename].iteritems():
                nm = nm.encode('ascii')
                if isinstance(val, (str, unicode)):
                    val = eval(val)
                if not nm.endswith('_MASK_'):
                    msk = [m for m in masks.keys() if val & m == val]
                    msk = msk[0] if len(msk) > 0 else None
                    if len(masks) > 0 and not msk:
                        msk = val
                    e.setMember(nm, val, msk)
            for x in masks:
                e.setBMask(x, masks[x])
