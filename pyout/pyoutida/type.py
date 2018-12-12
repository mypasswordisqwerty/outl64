import idc
import idaapi
import idautils
from pyout.classes.logger import Logger
from pyout.pyoutida import MODS
import os
import shutil


class FuncDescr:

    class NotFunctionError(Exception):

        def __init__(self, ea):
            ea = "{0:08X}".format(ea) if isinstance(ea, (int, long)) else str(ea)
            Exception.__init__(self, "Not a function at: " + ea)

    class BadParameterError(Exception):

        def __init__(self, str):
            Exception.__init__(self, "Bad parameter: " + str)

    def __init__(self, guess=None):
        self.name = None
        self.ea = None
        self.params = []
        self.type = None
        self.defines = None
        if not guess:
            return
        if isinstance(guess, (int, long)):
            self.readEA(guess)
        elif isinstance(guess, (str, unicode)):
            self.readEA(idc.LocByName(guess))
        else:
            raise self.NotFunctionError(guess)

    @staticmethod
    def fromEA(ea):
        return FuncDescr().readEA(ea)

    @staticmethod
    def fromName(name):
        return FuncDescr().readEA(idc.LocByName(name))

    @staticmethod
    def fromType(typestr):
        return FuncDescr().parseType(typestr)

    def readEA(self, ea):
        self.name = idc.GetFunctionName(ea)
        if not self.name:
            raise self.NotFunctionError(ea)
        self.ea = ea
        tp = idc.GetType(ea) or idc.GuessType(ea)
        if tp:
            self.parseType(tp, skipName=True)
        return self

    def parseParam(self, param):
        p = param.split(' ')
        if len(p) < 2:
            if not p[0]:
                raise self.BadParameterError(param)
            p += ['a' + str(len(self.params))]
        nm = p[-1]
        tp = ' '.join(p[:-1])
        while nm.startswith('*'):
            tp += '*'
            nm = nm[1:]
        return [tp, nm]

    def clearType(self):
        self.params = []
        self.type = None
        self.defines = None

    def parseType(self, tp, skipName=False):
        if not tp:
            raise self.NotFunctionError(tp)
        p = tp.split('(')
        if len(p) not in (2, 3):
            raise self.NotFunctionError(tp)
        if len(p) == 3:
            p[0] = p[0] + ' ' + p[1].split(')')[0]
            p[1] = p[2]
        for x in p[1].split(')')[0].split(','):
            if not x:
                break
            self.params += [self.parseParam(x)]
        func = p[0].split(' ')
        self.type = func[0]
        self.defines = ''
        if len(func) == 1:
            return
        nm = func[-1]
        self.defines = ' '.join(func[1:-1])
        if nm.endswith('call'):
            self.defines += ' ' + nm
            nm = None
        if nm and not skipName:
            nm.replace('*', '')
            self.name = nm

    def changeParam(self, pid, name, typename):
        if len(self.params) <= pid:
            raise self.BadParameterError(str(pid))
        self.params[pid] = [typename, name]

    def checkThis(self, typename):
        if len(self.params) > 0:
            pnm = self.params[0][1]
            if pnm.lower() == 'this':
                return
        else:
            self.params += [typename, 'this']
            return
        self.changeParam(0, 'this', typename)
        self.update()

    def update(self, withName=False):
        if not self.ea:
            raise self.NotFunctionError(self.name)
        idc.SetType(self.ea, self.buildType())
        if self.name and withName:
            idc.MakeName(self.ea, self.name)

    def buildType(self, struct=False):
        if not self.type:
            return None
        res = self.type + ' '
        if struct:
            res += '('
        res += self.defines + ' '
        if struct:
            res += '*'
        res += (self.name or '')
        if struct:
            res += ')'
        res += '(' + ','.join([p[0] + ' ' + p[1] for p in self.params]) + ');'
        return res

    def __str__(self):
        return self.buildType() or str(self.name)


class Type:
    CHECK_NONE = 0
    CHECK_VTBL = 1

    class TypeNotExistsError(Exception):

        def __init__(self, what, tname=None):
            if tname:
                what = tname + ": " + what
            Exception.__init__(self, what)

    class WrongTypeError(Exception):

        def __init__(self, what, tname=None):
            if tname:
                what = tname + ": " + what
            Exception.__init__(self, what)

    def __init__(self, typeid=None):
        self.typeid = typeid

    def getTypeVtbl(self, descr):
        if not descr.get('id'):
            return descr
        mid = idc.GetMemberId(descr['id'], 0)
        if not mid or mid == idc.BADADDR:
            return descr
        t = idc.GetType(mid) or ''
        t = t.replace('*', '').replace(' ', '')
        if 'VTABLE' not in t:
            return descr
        svid = idc.GetStrucIdByName(t)
        if not svid or svid == idc.BADADDR:
            return descr
        idc.SetStrucName(svid, descr['name'] + 'Vtbl')
        descr['vtblid'] = svid
        descr['vtblnm'] = descr['name'] + 'Vtbl'
        return descr

    def currentType(self, check=CHECK_NONE, **kwargs):
        tnm = None
        if self.typeid:
            tnm = self.typeid
        else:
            nm = idc.Name(idaapi.get_screen_ea())
            if nm and nm.startswith('vtbl_'):
                tnm = nm[5:]
        if not tnm:
            obj = MODS.explore.Explore(self.typeid).getVar()
            if obj:
                tnm = obj[-1].get('type')
        if not tnm:
            raise self.TypeNotExistsError("Type not found")
        tnm = tnm.replace('*', '').strip()
        tpdescr = {'name': tnm}
        sid = idc.GetStrucIdByName(tnm)
        if sid != idc.BADADDR:
            tpdescr['id'] = sid
        svid = idc.GetStrucIdByName(tnm + 'Vtbl')
        if svid != idc.BADADDR:
            tpdescr['vtblid'] = svid
            tpdescr['vtblnm'] = tnm + 'Vtbl'
        else:
            tpdescr = self.getTypeVtbl(tpdescr)
        ea = idc.LocByName('vtbl_' + tnm)
        if ea != idc.BADADDR:
            tpdescr['vtblea'] = ea
        if check == self.CHECK_VTBL and not tpdescr.get('vtblea'):
            raise self.TypeNotExistsError("vtbl not found", tnm)
        return tpdescr

    def setStrucPntr(self, sid, ofs, name, tp=None):
        vnm = idc.GetMemberName(sid, ofs)
        if not vnm or vnm in (idc.BADADDR, -1):
            idc.AddStrucMember(sid, name, ofs, idc.FF_QWRD, -1, 8)
            vnm = name
        if vnm != name:
            idc.SetMemberName(sid, ofs, name)
        sz = idc.GetMemberSize(sid, ofs)
        if sz != 8:
            idc.SetMemberType(sid, ofs, idc.FF_QWRD, -1, 1)
        mid = idc.GetMemberId(sid, ofs)
        t = idc.GetType(mid) or ''
        if tp and t.replace(' ', '') != tp.replace(' ', ''):
            idc.SetType(mid, tp + ';')

    def checkVtblStruct(self, descr):
        if not descr.get('vtblid'):
            descr['vtblnm'] = descr['name'] + 'Vtbl'
            descr['vtblid'] = idc.AddStrucEx(-1, descr['vtblnm'], 0)
            idc.AddStrucMember(descr['vtblid'], "queryi", 0, idc.FF_QWRD, -1, 8)
        if not descr.get('id'):
            descr['id'] = idc.AddStrucEx(-1, descr['name'], 0)
        self.setStrucPntr(descr['id'], 0, 'vtbl', descr['vtblnm'] + '*')
        return descr

    def untouchedFunc(self, name):
        return '::' in name or name.startswith('sub_')

    def update(self, **kwargs):
        tp = self.currentType(self.CHECK_VTBL, **kwargs)
        tp = self.checkVtblStruct(tp)
        Logger.debug("Updating class %s", str(tp))
        ea = tp['vtblea']
        nm = None
        funcs = []
        while(not nm):
            ofs = idc.Qword(ea)
            if not ofs or ofs == idc.BADADDR:
                break
            func = FuncDescr.fromEA(ofs)
            if self.untouchedFunc(func.name):
                func.checkThis(tp['name'] + '*')
            Logger.debug("found vtbl function: %s", str(func))
            name = func.name
            i = 2
            while name in funcs:
                name = func.name + "_" + str(i)
                i += 1
            self.setStrucPntr(tp['vtblid'], ea - tp['vtblea'], name, func.buildType(True))
            funcs += [name]
            ea += 8
            nm = idc.Name(ea)

    def rename(self, nuname=None, **kwargs):
        tp = self.currentType(**kwargs)
        cnm = tp['name']
        if not nuname:
            nuname = idc.AskStr(cnm, "Set new type name for " + cnm + ":")
        if not nuname or nuname == cnm:
            Logger.debug("Rename cancelled")
            return
        sid = idc.GetStrucIdByName(nuname)
        if sid and sid != idc.BADADDR:
            raise self.WrongTypeError("Type already exists", nuname)
        Logger.debug("Renaming class %s to %s", str(tp), nuname)
        if tp.get('vtblea'):
            idc.MakeName(tp['vtblea'], 'vtbl_' + nuname)
        if tp.get('id'):
            idc.SetStrucName(tp['id'], nuname)
        if tp.get('vtblid'):
            tp['vtblnm'] = nuname + 'Vtbl'
            idc.SetStrucName(tp['vtblid'], tp['vtblnm'])
        for nm in idautils.Names():
            if nm[1].startswith(cnm):
                fn = nm[1].replace(cnm, nuname)
                Logger.debug("Renaming function " + nm[1] + " to " + fn)
                idc.MakeName(nm[0], fn)
        self.typeid = nuname
        self.update()

    def subclass(self, sup=None, **kwargs):
        tp = self.currentType(self.CHECK_VTBL, **kwargs)
        tp = self.checkVtblStruct(tp)
        cnm = tp['name']
        if not sup:
            sup = idc.AskStr('', "Subclass " + cnm + " from:")
        if not sup or sup == cnm:
            Logger.debug("Subclasssing cancelled")
            return
        idc.Til2Idb(-1, sup + 'Vtbl')
        s = MODS.struct.Struct(sup + 'Vtbl')
        Logger.debug("Subclassing class %s from %s", str(tp), sup)
        ea = tp['vtblea']
        nm = None
        funcs = []
        while(not nm):
            ofs = idc.Qword(ea)
            if not ofs or ofs == idc.BADADDR:
                break
            try:
                func = FuncDescr.fromEA(ofs)
            except FuncDescr.NotFunctionError as e:
                func = None
                if not kwargs.get('force'):
                    raise
            funcs += [func]
            ea += 8
            nm = idc.Name(ea)
        flds = s.fields()
        if len(funcs) != len(flds) and (not kwargs.get('force')):
            raise self.WrongTypeError("Functions count doesn't match", s.name)
        for i, fofs in enumerate(sorted(flds.keys())):
            fld = flds[fofs]
            f = funcs[i]
            if f is None:
                continue
            refcnt = len(MODS.util.refsFromSeg(f.ea, ".rdata"))
            if self.untouchedFunc(f.name):
                nm = cnm if refcnt == 1 else sup
                was = str(f)
                f.clearType()
                f.parseType(fld['type'][0])
                f.name = nm + "::" + fld['name']
                ni = 1
                while idaapi.get_name_ea(idc.BADADDR, f.name) != idc.BADADDR:
                    ni += 1
                    f.name = nm + "::" + fld['name'] + "_" + str(ni)
                f.changeParam(0, 'this', nm + '*')
                f.update(True)
                Logger.debug("Converted func %s to type %s", was, str(f))
        self.update()

    def exportLib(self, **kwargs):
        file = os.path.splitext(idc.GetInputFile())[0]
        path = os.path.split(idc.GetIdbPath())[0]
        idapath = idc.GetIdaDirectory()
        tilname = os.path.join(path, file + ".til")
        outfile = os.path.join(idapath, 'til', 'pc', file + ".til")
        shutil.copy(tilname, outfile)
        os.system(os.path.join(idapath, "tilib64.exe") + " -#- " + outfile)
