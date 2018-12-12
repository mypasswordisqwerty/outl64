import idaapi
import idc
from pyout.classes.logger import Logger
from pyout.pyoutida import HexraysPlugin, MODS
util = MODS.util
struct = MODS.struct
mapi = MODS.mapi
guid = MODS.guid


class Explore:
    MEMS = ['memptr', 'memref']
    REGS = ['rip', 'rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rbp', 'rdi',
            'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

    def __init__(self, what=None):
        self.what = what
        self.func = idaapi.decompile(idaapi.get_screen_ea())
        self.structs = {}

    def parseVar(self, obj, hs):
        vr = self.func.lvars[obj.v.idx]
        hs['name'] = vr.name
        hs['var'] = vr
        if obj.ea != idc.BADADDR:
            hs['val'] = obj.ea
        try:
            if vr.is_reg_var():
                regid = vr.get_regnum() / 8
                regname = self.REGS[regid]
                hs['reg'] = [vr.get_regnum(), regname]
                hs['val'] = idc.GetRegValue(regname)
            if vr.is_stk_var():
                ofs = vr.location.calc_offset()
                hs['ofs'] = ofs
                val = idc.Qword(idc.GetRegValue('rsp') + ofs)
                if val != idc.BADADDR:
                    hs['val'] = val
        except Exception:
            pass
        return hs

    def getStruct(self, tp, ):
        if tp.endswith('*'):
            tp = tp[:-2].strip()
        if tp not in self.structs:
            self.structs[tp] = struct.Struct(tp)
        return self.structs[tp]

    def getStructMember(self, tp, m, hs, v):
        s = self.getStruct(tp)
        hs['sname'] = s.name
        hs['name'] = s.fields()[m]['name']
        if v.get('val'):
            inst = s.readInst(v.get('val'))
            hs['val'] = inst[hs['name']]
        return hs

    def getVar(self, obj=None, **kwargs):
        if not obj:
            obj = HexraysPlugin().expr()
        if not obj:
            return None
        hs = {'expr': obj, 'type': obj.type.dstr()}
        print hs, str(obj), str(obj.v), str(obj.n), str(obj.m), str(obj.x), str(obj.string)
        if obj.opname == 'var':
            return [self.parseVar(obj, hs)]
        if obj.opname in self.MEMS:
            v = self.getVar(obj.x, **kwargs)
            if not v:
                return None
            return v + [self.getStructMember(obj.x.type.dstr(), obj.m, hs, v[-1])]
        return hs

    def findStructMember(self, parents, names):
        if len(parents) == 0:
            return None
        s = self.getStruct(parents[0].type.dstr())
        fld = s.fieldOfs(names[0])
        vexp = []
        for x in self.func.treeitems:
            if not x.is_expr():
                continue
            if x.cexpr.opname in self.MEMS and x.cexpr.m == fld and x.cexpr.x in parents:
                if len(names) == 1:
                    return x.cexpr
                vexp += [x.cexpr]
        return self.findStructMember(vexp, names[1:])

    def findNamedVar(self, names, **kwargs):
        varid = None
        for i, x in enumerate(self.func.lvars):
            if x.name == names[0]:
                varid = i
                break
        if varid is None:
            if kwargs.get('nothrow'):
                return None
            raise Exception("Variable not found: " + names[0])
        vexp = []
        for x in self.func.treeitems:
            if x.is_expr() and x.cexpr.opname == "var" and x.cexpr.v.idx == varid:
                if len(names) == 1:
                    return x.cexpr
                vexp += [x.cexpr]
        return self.findStructMember(vexp, names[1:])

    def exploreVarMem(self, mem, **kwargs):
        m = idc.Qword(mem)
        if m == idc.BADADDR:
            return "Not addr\n"
        ad = idc.Name(m)
        return "addr: 0x{0:08X} {1}\n".format(m, ad) + self.exploreVarMem(m)

    def report(self, text, title):
        return util.showText(text, title)

    def exploreTypes(self, obj, **kwargs):
        if kwargs.get('quiet'):
            return
        nm = ''
        o = None
        for x in obj:
            nm += '->' if len(nm) > 0 else ''
            nm += x['name']
            o = x
        val = o.get('val')
        title = "{0}: {1} = {2}".format(nm, o['type'], hex(val) if val is not None else 'None')
        res = ''
        if val:
            res = mapi.MapiExplorer(o).explore(**kwargs)
        if len(res) == 0 and val:
            res = guid.Guid(o).explore(**kwargs)
        if res == 0 and val:
            res = self.exploreVarMem(val, **kwargs)
        obj += [res]
        if kwargs.get('show') == False:
            return None
        return self.report(title + "\n" + str(res), title)

    def run(self, **kwargs):
        obj = None
        if self.what in self.REGS:
            obj = [{'name': self.what, 'res': self.what, 'val': idc.GetRegValue(self.what), 'type': kwargs.get('type')}]
        else:
            if (self.what):
                obj = self.findNamedVar(self.what.split('->'), **kwargs)
                if not obj:
                    return None
            obj = self.getVar(obj, **kwargs)
        Logger.debug("explorering object %s", str(obj))
        if obj:
            self.exploreTypes(obj, **kwargs)
        else:
            Logger.error("Object not found")
        return obj

    def stval(self, addr, ofs, sz=8):
        if addr < 20:
            """ argument """
            if addr < 4:
                regs = ["rcx", "rdx", "r8", "r9"]
                addr = idc.GetRegValue(regs[addr])
            else:
                rsp = idc.GetRegValue('rsp')
                addr = idc.Qword(rsp + addr * 8 + 8)
        if isinstance(ofs, basestring):
            sf = ofs.split('.')
            st = struct.Struct(sf[0])
            res = st.readInst(addr)
            while len(sf) > 2:
                res = st.subInst(res, sf[1])
                sf = sf[1:]
            if len(sf) > 1:
                res = res[sf[1]]
            return str(res)
        if sz == 8:
            return idc.Qword(addr + ofs)
        if sz == 4:
            return idc.Dword(addr + ofs)
        if sz == 2:
            return idc.Word(addr + ofs)
        return idc.Byte(addr + ofs)

    def bplog(self, regs, cont, **kwargs):
        rg = {}
        for x in self.REGS:
            try:
                rg[x] = idc.GetRegValue(x)
            except Exception:
                print "BP: REGISTERS UNAVAILABLE"
                return
        ea = rg['rip']
        nm = "BP:" + idc.Name(ea)
        if not regs or len(regs) == 0:
            regs = ["rcx", "rdx", "r8", "r9"]
        if not isinstance(regs, (list, tuple)):
            regs = [regs]
        for x in regs:
            nm += " " + x + "=" + hex(rg[x])
        proc = kwargs.get('proc')
        if proc:
            rg['E'] = self
            nm += " " + proc(rg)
        print nm
        return not cont
