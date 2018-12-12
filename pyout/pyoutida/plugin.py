import idaapi
import idc
import os
import sys
from pyout.classes.logger import Logger
import pyoutconf as Config
import pyout
from pyout.pyoutida import MODS, HexraysPlugin

_G = {
    'inited': False,
    'menu': "Edit/Pyout/",
}


class IDAAction(idaapi.action_handler_t):

    def __init__(self, name, key=None):
        idaapi.action_handler_t.__init__(self)
        self.name = name
        self.id = "pyout:" + name.lower().replace(' ', '_')
        self.key = key
        self.proc = None

    def activate(self, ctx):
        if self.proc:
            self.proc()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def setProc(self, proc):
        self.proc = proc
        return self

    def register(self):
        idaapi.register_action(idaapi.action_desc_t(self.id, self.name, self, self.key, None, -1))
        return self

    def addMenu(self):
        idaapi.attach_action_to_menu(_G['menu'], self.id, idaapi.SETMENU_APP)
        return self

    def toolbar(self, tbname):
        idaapi.attach_action_to_toolbar(tbname, self.id)
        return self


class UpdateTypeAction(IDAAction):

    def __init__(self, key=None):
        IDAAction.__init__(self, "Update type", key)

    def activate(self, ctx):
        Logger.debug("Update type called")
        MODS.type.Type().update()


class RenameTypeAction(IDAAction):

    def __init__(self, key=None):
        IDAAction.__init__(self, "Rename type", key)

    def activate(self, ctx):
        Logger.debug("Rename type called")
        MODS.type.Type().rename()


class SubclassTypeAction(IDAAction):

    def __init__(self, key=None):
        IDAAction.__init__(self, "Subclass type", key)

    def activate(self, ctx):
        Logger.debug("subclass type called")
        MODS.type.Type().subclass()


class MapInterfacesAction(IDAAction):

    def __init__(self, key=None):
        IDAAction.__init__(self, "Map Interfaces", key)

    def activate(self, ctx):
        Logger.debug("map interfaces called")
        MODS.guid.Guid().updateIIDs()


class TestAction(IDAAction):

    def __init__(self, key=None):
        IDAAction.__init__(self, "Run test", key)

    def activate(self, ctx):
        MODS.test.Test().run()


class ExploreAction(IDAAction):

    def __init__(self, key=None):
        IDAAction.__init__(self, "Explore", key)

    def activate(self, ctx):
        Logger.debug("Explore called")
        MODS.explore.Explore().run()


class ExportTypesAction(IDAAction):

    def __init__(self, key=None):
        IDAAction.__init__(self, "Export types", key)

    def activate(self, ctx):
        Logger.debug("Export types called")
        MODS.type.Type().exportLib()


class PyoutPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Pyout IDA package"
    help = "Pyout IDA package"
    wanted_name = "Pyout"
    wanted_hotkey = ""

    def version(self):
        Logger.info("Pyout package v%s.", pyout.__version__)

    def verbose(self):
        Logger.setVerbose(not Logger.isVerbose())
        Logger.info("Verbose mode is %s.", "ON" if Logger.isVerbose() else "OFF")

    def reload(self):
        Logger.info("Reloading pyout")
        MODS.reload()

    def test(self):
        Logger.debug("Rename type called")
        MODS.test.Test().run()

    def init(self):
        if not _G['inited']:
            if hasattr(Config, "debug") and Config.debug:
                Logger.setVerbose(True)
            HexraysPlugin()
            UpdateTypeAction("Ctrl-Shift-U").register().addMenu()
            RenameTypeAction().register().addMenu()
            SubclassTypeAction().register().addMenu()
            MapInterfacesAction("Ctrl-Shift-I").register().addMenu()
            ExploreAction("Ctrl-Shift-E").register().addMenu()
            ExportTypesAction().register().addMenu()
            TestAction("Ctrl-Shift-]").register().addMenu()
            IDAAction('Reload', "Ctrl-Shift-R").setProc(self.reload).register().addMenu()
            IDAAction('Verbose').setProc(self.verbose).register().addMenu()
            IDAAction('About').setProc(self.version).register().addMenu()
            _G['inited'] = True
            doc = os.path.split(idc.GetIdbPath())[1].split('.')[0]
            inits = ["ida_init", "ida_init_" + doc.lower()]
            for y in inits:
                if not hasattr(Config, y):
                    continue
                for x in getattr(Config, y).split(';'):
                    x = x.strip()
                    Logger.debug("initcmd: %s", x)
                    try:
                        exec(x, globals())
                    except Exception as e:
                        print "Error running init cmd", x, ":", str(e)
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        return

    def term(self):
        HexraysPlugin().unload()
