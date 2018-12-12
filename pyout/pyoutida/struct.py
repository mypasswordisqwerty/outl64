import idautils
import idc
import idaapi
from pyout.pyoutida import MODS
util = MODS.util
fusage = MODS.fusage
dictchooser = MODS.dictchooser


class Struct:
    """ IDA structure handler """
    MAX_FIELDS = 10

    class StructNotFoundError(Exception):

        def __init__(self, name):
            Exception.__init__(self, "Structure not found: " + name)

    def __init__(self, name):
        if isinstance(name, (int, long)):
            name = str(name)
        self.align = 8
        self.name = name
        self.id = idc.GetStrucIdByName(name)
        if self.id == idc.BADADDR:
            try:
                self.id = int(name)
                self.name = idc.GetStrucName(self.id)
                if not self.name:
                    raise ""
            except Exception:
                raise Struct.StructNotFoundError(name)
        self._xrefs = None
        self._fields = None
        self._inst = None
        self._showFields = None

    def xrefs(self, reload=False):
        if reload or not self._xrefs:
            self._xrefs = idautils.XrefsTo(self.id)
        return self._xrefs

    def fields(self, reload=False):
        if reload or not self._fields:
            self._fields = {}
            m = 0
            while True:
                if m >= idc.GetStrucSize(self.id):
                    break
                n = idc.GetMemberName(self.id, m)
                if n == idc.BADADDR:
                    break
                sz = idc.GetMemberSize(self.id, m)
                mid = idc.GetMemberId(self.id, m)
                tp = idc.GetType(mid)
                fld = {'offset': m, 'id': mid, 'name': n,
                       'size': sz, 'type': [tp, None]}
                if n != '':
                    fld['type'][1] = idc.GetMemberFlag(self.id, m)
                self._fields[m] = fld
                m = idc.GetStrucNextOff(self.id, m)
                if m == idc.BADADDR:
                    break
        return self._fields

    def fieldOfs(self, fieldname):
        flds = self.fields()
        for x in flds:
            if flds[x]['name'] == fieldname:
                return x
        raise Exception("Struct field {0}->{1} not found".format(self.name, fieldname))

    def info(self, reload=False):
        cols = [['offset', 10 | idaapi.Choose2.CHCOL_HEX], 'name', 'type',
                'size', 'id']
        dictchooser.DictChooser(
            "Struct Fields " + self.name, self.fields(reload), cols).Show()

    def readInst(self, addr):
        flds = self.fields()
        ret = {'address': addr}
        for y in sorted(flds.keys()):
            if not flds[y]['name']:
                continue
            ea = addr + flds[y]['offset']
            ret[flds[y]['name']] = util.readData(ea, flds[y]['type'], flds[y]['size'])
        return ret

    def subInst(self, inst, field):
        o = self.fieldOfs(field)
        fd = self.fields()[o]
        tp = fd['type'][0]
        st = Struct(tp.split(' ')[0])
        return st.readInst(inst[field] if '*' in tp else inst['address'] + o)

    def instances(self, reload=False):
        if reload or not self._inst:
            xr = self.xrefs(reload)
            self._inst = {}
            for x in xr:
                if not idc.isLoaded(x.frm):
                    continue
                ins = self.readInst(x.frm)
                self._inst[ins['address']] = ins
        return self._inst

    def setFields(self, fields=None):
        self._showFields = []
        for x in self.fields().values():
            if not fields or x['name'] in fields:
                self._showFields += [x['name']]
                if not fields and len(self._showFields) > Struct.MAX_FIELDS:
                    return

    def showInstances(self, inst):
        if not self._showFields:
            self.setFields()
        cols = [['address', 10 | idaapi.Choose2.CHCOL_HEX]]
        flds = self.fields(reload)
        for x in sorted(flds.keys()):
            if flds[x]['name'] in self._showFields:
                it = [flds[x]['name']]
                if util.isNumeric(flds[x]['type']):
                    it += [7 | idaapi.Choose2.CHCOL_HEX]
                cols += [it]
        dictchooser.DictChooser(self.name, inst, cols).Show()

    def show(self, fields=None, reload=False):
        if fields:
            self.setFields(fields)
        self.showInstances(self.instances(reload))

    def filter(self, predicate, reload=False):
        inst = self.instances(reload)
        inst = filter(predicate, inst.values())
        self.showInstances(inst)

    def mkfld(self, ofs, sz, cnt=1, name=None):
        flgs = idc.FF_DATA | util.DATA['sizeType'][sz]
        if name is None:
            name = "field_%X" % ofs
        idc.AddStrucMember(self.id, name, ofs, flgs, -1, sz * cnt)

    def mkarr(self, ofs, size):
        align = self.align
        if ofs % align != 0:
            sz = align - (ofs % align)
            if size < sz:
                sz = size
            self.mkfld(ofs, sz)
            ofs += sz
            size -= sz
        cnt = size // align
        if cnt > 0:
            nm = "__unk_%X" % ofs
            self.mkfld(ofs, align, cnt, nm)
            size -= cnt * align
            ofs += cnt * align
        while size > 0:
            while size < align:
                align //= 2
            self.mkfld(ofs, align)
            size -= align
            ofs += align

    def fixFields(self, size=None):
        flds = self.fields()
        umap = {}
        prev = -2
        lst = -2
        for y in flds:
            if not flds[y]['name']:
                if prev == y - 1:
                    umap[lst] += 1
                else:
                    lst = y
                    umap[lst] = 1
                prev = y
        print "nfields", umap
        if len(umap) > 0:
            for x in umap:
                self.mkarr(x, umap[x])
            flds = self.fields(True)
        for y in flds:
            x = flds[y]
            if not x['name'].startswith('field_'):
                continue
            nm = 'field_{:X}'.format(x['offset'])
            if x['name'] == nm:
                continue
            idc.SetMemberName(self.id, x['offset'], nm)
            x['name'] = nm
            self._fields[y] = x

    def extractField(self, ofsOrName, idxOrNone=None, size=None):
        size = size or self.align
        flds = self.fields()
        ofs = ofsOrName
        fld = None
        for x in flds:
            if idxOrNone is None:
                if x <= ofs and x + flds[x]['size'] > ofs and idxOrNone is None:
                    fld = x
                    break
            else:
                if x == ofsOrName or flds[x]['name'] == ofsOrName:
                    fld = x
                    ofs = x + idxOrNone * util.getTypeSize(flds[x]['type'])
                    break
        if fld is None:
            raise Exception("Field not found: " + str(ofs))
        idc.DelStrucMember(self.id, fld)
        cnt = 1
        if size > self.align:
            cnt = size / self.align
            size = self.align
        self.mkfld(ofs, size, cnt)
        flds = self.fields(True)
        self.fixFields()

    def assigns(self, field, **kwargs):
        return fusage.FUsage(self.name + "." + field, **kwargs).find(**kwargs)

    def usage(self, field, **kwargs):
        return self.assigns(field, usage=True, **kwargs)
