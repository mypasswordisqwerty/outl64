#!/usr/bin/env python
import sys
import os
import site
import hashlib
import base64
from pyout.util import IDAPath, mypath
try:
    import pip
except Exception as e:
    print "pip required"


PYOUT_PATH_FILE = "pyout.pth"
CFG_EXAMPLE = """
smtp = {"host": "192.168.56.13",
        "user": "user1@192.168.56.13",
        "password": "123",
        "from": "user1 <user1@192.168.56.13>",
        "to": "user2 <user2@192.168.56.13>"
        }
debug = False
hipchatApiUrl = ""
hipchatRoom = 168
"""

PYOUT_PLUGIN = """
import idaapi
idaapi.require("pyout")
idaapi.require("pyout.ida")


def PLUGIN_ENTRY():
    return pyout.ida.IDA().plugin()
"""


def getSPFile():
    global PYOUT_PATH_FILE
    rpath = None
    for x in site.getsitepackages():
        fname = os.path.join(x, PYOUT_PATH_FILE)
        if os.path.exists(fname):
            return fname
        if x.endswith("site-packages"):
            rpath = x
    if rpath is not None:
        return os.path.join(rpath, PYOUT_PATH_FILE)


def regsvr(install=True):
    fuz = os.path.join(mypath(), "fuzzer", "Outl64FuzzLib", "bin")
    cmd = "C:\\windows\\system32\\regsvr32.exe /s "
    cmd += "" if install else "/u "
    cmd += '\"' + os.path.join(fuz, "Outl64FuzzLib.dll") + '\"'
    cmd += " && C:\\windows\\SysWOW64\\regsvr32.exe /s "
    cmd += "" if install else "/u "
    cmd += '\"' + os.path.join(fuz, "Outl64FuzzLibPS.dll") + '\"'
    cmd += ' || pause'
    ps = "Start-Process cmd.exe @('/c','" + cmd + "') -verb runas -wait"
    enc = base64.b64encode(ps.decode('ascii').encode("utf-16le"))
    return os.system('powershell.exe -EncodedCommand ' + enc)


def install():
    global CFG_EXAMPLE, PYOUT_PLUGIN
    isWin = sys.platform == "win32"
    mods = ["install", "hexdump", "netifaces"]
    if isWin:
        mods += ["pypiwin32"]
    pip.main(mods)
    mpath = mypath()
    # install pyout package(.pth to current dir) to site-packages
    file = getSPFile()
    if os.path.exists(file):
        data = None
        with open(file, "r") as f:
            data = f.read()
        data = data.split("\r")[0].split("\r")[0]
        if data == mpath:
            print "Path already installed at", file
        else:
            os.unlink(file)
    if not os.path.exists(file):
        print "Installing", mpath, "to", file
        with open(file, "w") as f:
            f.write(mpath)
    # install ida plugin
    ida = IDAPath("plugins")
    if ida is not None:
        plug = os.path.join(ida, "PyoutPlugin.py")
        h1 = None
        if os.path.exists(plug):
            h1 = hashlib.md5(open(plug, 'r').read()).hexdigest()
        h2 = hashlib.md5(PYOUT_PLUGIN).hexdigest()
        if h1 == h2:
            print "IDA plugin already installed at:", ida
        else:
            print "Installing IDA plugin to:", plug
            with open(plug, "w") as f:
                f.write(PYOUT_PLUGIN)
    else:
        print "IDA installation not found."
    # install fuzzer com objects
    if isWin:
        stat = regsvr()
        if stat == 0:
            print "COM objects registered."
        else:
            print "Error registering COM objects:", stat
    # make config
    cfg = os.path.join(mpath, "pyoutconf.py")
    if not os.path.exists(cfg):
        with open(cfg, "w") as f:
            f.write(CFG_EXAMPLE)
        print "Config file installed. Edit pyoutconf.py after install."
    print "Installed."
    return 0


def uninstall():
    file = getSPFile()
    # uninstall package
    if not os.path.exists(file):
        print "Not installed"
        return 1
    while os.path.exists(file):
        print "Uninstalling from ", file
        os.unlink(file)
        file = getSPFile()
    # uninstall ida plugin
    ida = IDAPath("plugins")
    if ida:
        plug = os.path.join(ida, "PyoutPlugin.py")
        if os.path.exists(plug):
            print "Uninstalling IDAPlugin", plug
            os.unlink(plug)
    else:
        print "IDAPlugin not uninstalled: IDA installation not found"
    if sys.platform == "win32":
        regsvr(False)
    print "Uninstalled."
    return 0


def usage():
    print """
    install.py creates pyout.pth file in your site-packages.

    Usage:
    install.py [install]
    install.py uninstall
    """


def main():
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "install"
    if cmd == "install":
        return install()
    elif cmd == "uninstall":
        return uninstall()
    elif cmd in ("help", "-h", "--help", "/?"):
        usage()
    else:
        print "Unknown command:", cmd
        usage()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
