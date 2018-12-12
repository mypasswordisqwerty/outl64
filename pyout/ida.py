from classes.singleton import Singleton
from classes.logger import Logger
try:
    import idaapi
    from pyout.pyoutida import plugin, MODS, HexraysPlugin
except Exception as e:
    idaapi = None


class IDA:
    """ pyout ida helper """
    __metaclass__ = Singleton

    class NoIdaError(Exception):

        def __init__(self): Exception.__init__(self, "IDA context required.")

    def __init__(self, verbose=False):
        if idaapi is None:
            raise IDA.NoIdaError()
        self.structs = {}
        self.enums = {}
        Logger.setVerbose(verbose)

    @staticmethod
    def hasIDA():
        return idaapi is not None

    def reload(self):
        MODS.reload()

    def isDebugMode(self):
        return idaapi.is_debugger_on()

    def isDebugBusy(self):
        return idaapi.is_debugger_busy()

    def test(self, **kwargs):
        return MODS.test.Test().run(**kwargs)

    def getStruct(self, name, reload=False):
        name = str(name)
        if reload or name not in self.structs:
            s = MODS.struct.Struct(name)
            self.structs[s.name] = s
            self.structs[str(s.id)] = s
        return self.structs[name]

    def getEnum(self, name, reload=False):
        name = str(name)
        if reload or name not in self.enums:
            s = MODS.enum.Enum(name)
            self.enums[s.name] = s
            self.enums[str(s.id)] = s
        return self.enums[name]

    def plugin(self):
        return plugin.PyoutPlugin()

    def mapInterfaces(self, **kwargs):
        MODS.guid.Guid().updateIIDs(**kwargs)

    def mapOids(self, **kwargs):
        MODS.oid.Oid().update(**kwargs)

    def renameType(self, typeid=None, nuname=None, **kwargs):
        return MODS.type.Type(typeid).rename(nuname, **kwargs)

    def updateType(self, typeid=None, **kwargs):
        return MODS.type.Type(typeid).update(**kwargs)

    def subclassType(self, typeid=None, superc=None, **kwargs):
        return MODS.type.Type(typeid).subclass(superc, **kwargs)

    def explore(self, obj=None, **kwargs):
        return MODS.explore.Explore(obj).run(**kwargs)

    def curvar(self, **kwargs):
        return HexraysPlugin().obj(**kwargs)

    def exportTypes(self, **kwargs):
        return MODS.type.Type().exportLib(**kwargs)

    def syncEnums(self, fname=None, **kwargs):
        return MODS.enum.Enum.syncEnums(fname, **kwargs)

    def bplog(self, regs=None, cont=False, **kwargs):
        return MODS.explore.Explore().bplog(regs, cont, **kwargs)

    def bpcond(self, group=None, cond="", **kwargs):
        return MODS.util.bpcond(group, cond, **kwargs)

    def fieldUsage(self, name, **kwargs):
        return MODS.fusage.FUsage(name, **kwargs).find(**kwargs)

    def guid(self, addr=None, **kwargs):
        return MODS.guid.Guid().printGuid(addr, **kwargs)
