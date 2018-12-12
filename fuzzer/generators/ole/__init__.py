
import olefile
import doc
import ppt
import utils
import sys

MASK_MODE = 0xFFF
MASK_X = 0x1000
MASK_DETECT = 0x2000

MODE_OLE = 0

MODE_DOC = 1
MODE_DOC_X = MODE_DOC | MASK_X
MODE_DOC_DETECT = MODE_DOC | MASK_DETECT

MODE_PPT = 2
MODE_PPTX = MODE_PPT | MASK_X
MODE_PPT_DETECT = MODE_PPT | MASK_DETECT

MODE_PPS = 3
MODE_PPSX = MODE_PPS | MASK_X
MODE_PPS_DETECT = MODE_PPS | MASK_DETECT

PIGS = {
    MODE_OLE: None,
    MODE_DOC: "pig.doc",
    MODE_DOC_X: "pig.docx",
    MODE_PPTX: "pig.pptx",
    MODE_PPSX: "pig.pptx",
}


def gendata(size=None, val="AA"):
    if not size:
        size = 0x100
    i = 0
    ret = ""
    while len(ret) < size:
        ret += val + "{:02d}".format(i)
        i += 1
    return ret[:size]


def createOleFile(mode, pig, **kwargs):
    if not pig:
        pig = PIGS.get(mode)

    detect = (mode & MASK_DETECT) != 0
    modex = (mode & MASK_X) != 0
    isBin = None if detect else False if modex else True
    mode &= MASK_MODE

    if mode == MODE_OLE:
        return olefile.OleFile(pig, **kwargs)
    elif mode == MODE_DOC:
        return doc.DocFile(pig, isBin=isBin)
    elif mode in [MODE_PPT, MODE_PPS]:
        return ppt.PptFile(mode == MODE_PPS, pig, isBin=isBin)
    else:
        raise OleError("Unknown mode for ole file: " + str(mode))


def getOleObject(name):
    Cls = None
    mods = ["moniker", "oleobject", "equation", "objref", "persiststm", "persiststminit"]
    for x in mods:
        cls = name.split('.')
        if len(cls) == 1:
            cls = [x] + cls
        if cls[0] != 'ole':
            cls = ["ole"] + cls
        pack = '.'.join(cls[:-1])
        __import__(pack, globals(), locals())
        try:
            Cls = getattr(sys.modules[pack], cls[-1])
            if Cls is not None:
                return Cls
        except AttributeError:
            Cls = None
    raise utils.OleError("Unknown object class: " + name)
