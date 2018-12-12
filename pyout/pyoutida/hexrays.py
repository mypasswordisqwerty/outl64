from pyout.classes.singleton import Singleton
from pyout.classes.logger import Logger
import idaapi


class HexraysPlugin(object):
    """ hexrays plugin """
    __metaclass__ = Singleton

    def __init__(self):
        Logger.debug("Creating")
        self.lastObj = None
        self.lastExpr = None
        self.installed = False
        self.safe = False
        if idaapi.init_hexrays_plugin():
            if idaapi.install_hexrays_callback(self.callback):
                self.installed = True

    def unload(self):
        if self.installed:
            idaapi.remove_hexrays_callback(self.callback)
            self.installed = False

    def getVar(self, name, **kwargs):
        if not name:
            obj = self.obj()
            if obj and obj.op == idaapi.cot_var:
                name = obj.v.idx
        if not name:
            return None
        f = idaapi.decompile(idaapi.get_screen_ea())
        if not f:
            return None
        var = None
        for idx, x in enumerate(f.lvars):
            if x.name == name or idx == name:
                var = x
                break
        return var

    def expr(self, **kwargs):
        return self.lastExpr

    def obj(self, **kwargs):
        return self.lastObj

    def getItem(self, vu):
        if not vu:
            return None
        if not vu.item.is_citem():
            return None
        return vu.item.e

    def callback(self, event, *args):
        try:
            if event <= idaapi.hxe_print_func:
                self.safe = False
            if event == idaapi.hxe_switch_pseudocode:
                self.safe = False
            if event == idaapi.hxe_func_printed:
                self.safe = True
            if event == idaapi.hxe_text_ready:
                self.safe = True
            if event == idaapi.hxe_curpos:
                self.lastObj = None
                self.lastExpr = None
                if not self.safe:
                    return 0
                it = self.getItem(args[0])
                if not it:
                    return 0
                self.lastObj = it
                self.lastExpr = self.lastObj if self.lastObj.is_expr() else None
        except Exception as e:
            Logger.error("HexraysPlugin Error: " + str(e))
        return 0
