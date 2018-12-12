import idautils
import idc
import idaapi
from pyout.classes.logger import Logger
from pyout.pyoutida import MODS
util = MODS.util
dictchooser = MODS.dictchooser
struct = MODS.struct


class FUsage:

    def __init__(self, fname, **kwargs):
        self.name = fname.split('.')
        self.stname = self.name[0]
        self.fname = '.'.join(self.name[1:])

    def checkFunc(self, ea, **kwargs):
        usage = kwargs.get('usage') or False
        fn = idc.GetFunctionName(ea)
        try:
            func = idaapi.decompile(ea)
            if not func:
                return None
        except Exception as e:
            Logger.error("Error decompiling " + fn + ": " + str(e))
            return None
        vrs = []
        for v in func.lvars:
            t = v.type().dstr()
            if self.stname in t:
                vrs += [v.name + ("->" if '*' in t else '.') + self.fname]
        #Logger.debug("Checking function %s %s", fn, str(vrs))
        ret = []
        for i, x in enumerate(str(func).split("\n")):
            for y in vrs:
                if y not in x:
                    continue
                x = x.strip()
                if not usage:
                    p = x.find(y)
                    if p != 0 or '=' not in x:
                        continue
                ret += [{'address': fn + " : " + str(i), 'code': x, }]
        return ret

    def jump(self, data):
        j = data['address'].split(" : ")
        ea = idaapi.get_name_ea(idc.BADADDR, j[0])
        ln = int(j[1])
        print "JUMPTO", j, ea, ln
        ui = idaapi.open_pseudocode(ea, False)
        (pl, x, y) = idaapi.get_custom_viewer_place(ui.ct, False)
        pl2 = idaapi.place_t_as_simpleline_place_t(pl.clone())
        pl2.n = ln
        idaapi.jumpto(ui.ct, pl2, 0, y)

    def find(self, **kwargs):
        res = []
        if kwargs.get('func'):
            f = kwargs.get('func')
            if isinstance(f, basestring):
                f = idaapi.get_name_ea(idc.BADADDR, f)
            res = self.checkFunc(f, **kwargs) or []
        else:
            for funcea in idautils.Functions():
                tp = idc.GetType(funcea)
                if tp is None or self.stname not in tp:
                    continue
                r = self.checkFunc(funcea, **kwargs)
                if r:
                    res += r
        if kwargs.get("silent"):
            return res
        if len(res):
            dictchooser.DictChooser('.'.join(self.name) + " usage", res, jumpProc=self.jump).Show()
        else:
            Logger.info("Nothing found")
