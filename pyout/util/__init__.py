from pyout.classes.logger import Logger
from oids import Oids
import pyout
import os
import pyout.mailer
from pyout.outlook import Outlook
from guid import GuidHelper
try:
    import _winreg
except ImportError:
    print "You need pywin32 lib.\nRun: pip install pypiwin32\n"


def version():
    Logger.info("Pyout package v%s.", pyout.__version__)


def verbose(verb=True):
    Logger.setVerbose(verb)


def mail(mailname=0, **kwargs):
    """ send mail to smtp server and receive w outl """
    pyout.mailer.Mailer().mail(mailname, **kwargs)
    if kwargs.get("nosend") != True:
        Outlook().receive()


def mypath(subdir=None):
    pth = os.path.dirname(os.path.realpath(__file__))
    pth = os.path.realpath(os.path.join(pth, '..', '..'))
    if subdir:
        pth = os.path.join(pth, subdir)
    return pth


def IDAPath(subdir=None):
    try:
        path = "IDAPro.Database64\\shell\\open\\command"
        k = _winreg.OpenKey(_winreg.HKEY_CLASSES_ROOT, path)
        pth = _winreg.QueryValue(k, None)
        pth = pth.split(' ')[0].strip()
        if pth.startswith('"'):
            pth = pth[1:-1]
        if not os.path.exists(pth):
            raise "Not found"
        dr = os.path.realpath(os.path.split(pth)[0])
        if subdir:
            dr = os.path.join(dr, subdir)
            if not os.path.exists(dr):
                raise "Not found"
        return dr
    except Exception:
        return None


def exportMapiEnums():
    tilib = os.path.join(IDAPath(), "tilib64.exe")
    til = os.path.join(IDAPath("til"), "MAPIENUMS.til")
    hdr = os.path.join(mypath("doc"), "mapienums.mac")
    os.system("{0} -c -m{1} {2}".format(tilib, hdr, til))


def updateOIDS():
    Oids().updateNames()


def guid(guid):
    return GuidHelper().findGuid(guid)
