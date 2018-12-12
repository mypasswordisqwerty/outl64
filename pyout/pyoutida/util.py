import idaapi
import idc
import idautils

DATA = {
    'types': {
        idc.FF_BYTE: "Byte",
        idc.FF_WORD: "Word",
        idc.FF_DWRD: "DWord",
        idc.FF_QWRD: "QWord",
        idc.FF_TBYT: "Ten bytes",
        idc.FF_ASCI: "ASCII string",
        idc.FF_STRU: "Structure",
        idc.FF_FLOAT: "Float",
        idc.FF_DOUBLE: "Double",
        idc.FF_PACKREAL: "PackedReal"
    },
    'typeSize': {
        idc.FF_BYTE: 1,
        idc.FF_WORD: 2,
        idc.FF_DWRD: 4,
        idc.FF_QWRD: 8,
        idc.FF_TBYT: 10,
        idc.FF_ASCI: 8,
        idc.FF_STRU: 8,
        idc.FF_FLOAT: 4,
        idc.FF_DOUBLE: 8,
        idc.FF_PACKREAL: 4
    },
    'sizeType': {
        1: idc.FF_BYTE,
        2: idc.FF_WORD,
        4: idc.FF_DWRD,
        8: idc.FF_QWRD
    },
    'itypes': [idc.FF_BYTE, idc.FF_WORD, idc.FF_DWRD, idc.FF_QWRD],
    'strtypes': {"char *": idc.ASCSTR_C, "wchar_t *": idc.ASCSTR_UNICODE}
}


def showText(text, title="text"):
    idaapi.asktext(len(text) + 1024, text, title)


def customView(text, title="text"):
    v = idaapi.simplecustviewer_t()
    if v.Create(title):
        for line in text.split('\n'):
            v.AddLine(line)
        v.Show()
    else:
        print "Failed to create viewer"


def getTypeSize(type):
    x = type[1] & idc.DT_TYPE
    return DATA['typeSize'][x]


def getTypeStr(type):
    x = type[1] & idc.DT_TYPE
    if x not in DATA['types']:
        return "Unknown {:x}h".format(x)
    return DATA['types'][x]


def flagToTypeStr(type):
    flag = type[1]
    if not flag:
        return "Undefined"
    tp = getTypeStr(type)
    add = ''
    if idc.isOff0(flag):
        add = " Offset"
    if idc.isChar0(flag):
        add += " Character"
    if idc.isSeg0(flag):
        add += " Segment"
    if idc.isDec0(flag):
        add += " Decimal"
    if idc.isHex0(flag):
        add += " Hex"
    if idc.isOct0(flag):
        add += " Octal"
    if idc.isBin0(flag):
        add += " Binary"
    return tp + add


def isNumeric(type):
    return (type[1] & idc.DT_TYPE) in DATA['itypes'] and type[0] not in DATA['strtypes']


def readData(ea, type, size):
    flag = type[1]
    if not flag:
        return ''
    t = flag & idc.DT_TYPE
    tsz = DATA['typeSize'][t]
    val = []
    for i in range(size / tsz):
        if t == idc.FF_BYTE:
            val += [idc.Byte(ea)]
        elif t == idc.FF_WORD:
            val += [idc.Word(ea)]
        elif t == idc.FF_DWRD:
            val += [idc.Dword(ea)]
        elif t == idc.FF_QWRD:
            val += [idc.Qword(ea)]
        elif t == idc.FF_FLOAT:
            val += [idc.GetFloat(ea)]
        ea += tsz
    if len(val) == 1:
        val = idc.GetString(val[0], -1, DATA['strtypes'][type[0]]) if type[0] in DATA['strtypes'] else val[0]
    return val


def derefType(addr, atype, totypes=None):
    res = addr
    if not res:
        return None
    t = atype.replace(' ', '').strip()
    if not totypes:
        if t.lower().startswith('lp'):
            totypes = [t.strip('*')]
        else:
            totypes = [t.strip('*') + '*']
    for i, x in enumerate(totypes):
        totypes[i] = x.replace(' ', '').strip()
    while t not in totypes:
        res = idc.Qword(res)
        t = t[0:-1]
        if res == idc.BADADDR:
            return None
    return res


def refsFromSeg(ea, segname):
    refs = idautils.XrefsTo(ea)
    res = []
    for x in refs:
        if idc.SegName(x.frm) == segname:
            res += [x]
    return res


def bpcond(group=None, cond="", **kwargs):
    bp = idaapi.bpt_t()
    cond = cond or ''
    i = 0
    lng = kwargs.get("lang") or "Python"
    while idaapi.getn_bpt(i, bp):
        idaapi.getn_bpt(i, bp)
        i += 1
        if group and group != idaapi.get_bpt_group(bp.loc):
            continue
        idc.SetBptCnd(bp.ea, cond)
