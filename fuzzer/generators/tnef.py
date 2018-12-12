#!/usr/bin/env python
# -*- coding: utf-8 -*-
import struct
import sys
from datetime import datetime
from pyout.enums.tnef import TnefEnum
from mapiprop import MapiProps


class TNEF:
    """ TNEF Generator """

    SIGNATURE = 0x223e9f78

    LVL_MESSAGE = 0x01
    LVL_ATTACHMENT = 0x02

    DATA_VERSION = 0x00010000
    DATA_CODEPAGE = 0x00000000000004e4

    ATTACH_LEVEL_IDS = [TnefEnum.ID_ATTACHDATA, TnefEnum.ID_ATTACHTITLE, TnefEnum.ID_ATTACHMETAFILE,
                        TnefEnum.ID_ATTACHCREATEDATE, TnefEnum.ID_ATTACHMODIFYDATE, TnefEnum.ID_ATTACHTRANSPORTFILENAME,
                        TnefEnum.ID_ATTACHRENDDATA, TnefEnum.ID_ATTACHMENT]

    STATUS_READ = 0x20
    STATUS_MODIFIED = 0x01
    STATUS_SUBMITTED = 0x04
    STATUS_LOCAL = 0x02
    STATUS_HASATTACH = 0x80

    CLASS_NOTE = "IPM.Microsoft Mail.Note"
    CLASS_IPNRN = "IPM.Microsoft Mail.Read Receipt"
    CLASS_NDR = "IPM.Microsoft Mail.Non-Delivery"
    CLASS_MRESPP = "IPM.Microsoft Schedule.MtgRespP"
    CLASS_MRESPN = "IPM.Microsoft Schedule.MtgRespN"
    CLASS_MRESPA = "IPM.Microsoft Schedule.MtgRespA"
    CLASS_MREQ = "IPM.Microsoft Schedule.MtgReq"
    CLASS_MCNCL = "IPM.Microsoft Schedule.MtgCncl"

    PRIORITY_LOW = 3
    PRIORITY_NORMAL = 2
    PRIORITY_HIGH = 1

    class Address:
        """ TNEF Address type.
            Dumps to triple or owner structs.
        """

        def __init__(self, email=None, name=None):
            self.name = name or ""
            self.email = email or "SMTP:sample@example.com"
            if ':' not in self.email:
                self.email = "SMTP:" + self.email

        def dumpTriple(self):
            ret = struct.pack('H', 4)
            ret += struct.pack('H', 18 + len(self.name) + len(self.email))
            ret += struct.pack('H', len(self.name) + 1)
            ret += struct.pack('H', len(self.email) + 1)
            ret += self.name + "\x00"
            ret += self.email + "\x00"
            ret += "\x00" * 8
            return ret

        def dump(self):
            ret = struct.pack('H', len(self.name) + 1)
            ret += self.name + "\x00"
            ret += struct.pack('H', len(self.email) + 1)
            ret += self.email + "\x00"
            return ret

    class AttachRendData:
        """ TNEF RENDDATA struct. """
        TYPE_FILE = 1
        TYPE_OLE = 2
        FLAG_DEFAULT = 0
        FLAG_MACBIN = 1

        def __init__(self, atype=TYPE_FILE, pos=0, width=0, height=0, flags=FLAG_DEFAULT):
            self.atype = atype
            self.pos = pos
            self.width = width
            self.height = height
            self.flags = flags

        def dump(self):
            ret = struct.pack('H', self.atype)
            ret += struct.pack('i', self.pos)
            ret += struct.pack('h', self.width)
            ret += struct.pack('h', self.height)
            ret += struct.pack('I', self.flags)
            return ret

    def __init__(self, key=0x01):
        self.clear(key)

    def checksum(self, data):
        return sum([ord(x) for x in data]) & 0xFFFF

    def CheckSum(data):
        return sum([ord(x) for x in data]) & 0xFFFF

    def clear(self, key=0x01):
        self.TNEFStream = struct.pack('I', TNEF.SIGNATURE)
        self.TNEFStream += struct.pack('H', key)
        return self

    def dump(self):
        return self.TNEFStream

    @staticmethod
    def parse(fp, dump=None, dfile=None):
        te = TnefEnum()
        print >> sys.stderr, "signature: {s[0]:08X} key:{s[1]:04X}".format(s=struct.unpack("IH", fp.read(6)))
        while True:
            buf = fp.read(9)
            if buf is None or len(buf) < 9:
                break
            lvl = struct.unpack("B", buf[0])[0]
            aid, sz = struct.unpack("Ii", buf[1:])
            aidfmt = "{:08X}".format(aid)
            nm = te.getName(aid)
            val = ''
            if aid not in [te.ID_MAPIPROPS, te.ID_ATTACHMENT]:
                data = fp.read(sz)
                if dump and dump in [aidfmt, nm]:
                    with open(dfile, "wb") as f:
                        f.write(data)
                if aid == te.ID_TNEFVERSION:
                    val = struct.unpack("I", data)[0]
                if aid == te.ID_OEMCODEPAGE:
                    val = struct.unpack("Q", data)[0]
                if aid == te.ID_MESSAGECLASS:
                    val = data[:-1]
            print >> sys.stderr, "{}:{} {} {} {}".format(aidfmt, nm, lvl, sz, val)
            if aid == te.ID_MAPIPROPS or aid == te.ID_ATTACHMENT:
                MapiProps.parse(fp, sz, dump, dfile)
                print >> sys.stderr, "------"
            fp.read(2)

    def replaceRtf(buf, rtfdata):
        pos = 0
        te = TnefEnum()
        aid, sz = struct.unpack("Ii", buf[pos + 1:pos + 9])
        if aid == te.ID_MAPIPROPS:
            pos += 9
            epos = pos + sz
            data = buf[pos:epos]
            ndata = MapiProps.replaceRtf(data, rtfdata)
            crc = TNEF.CheckSum(ndata)
            buf = buf[:pos - 4] + struct.pack('i', len(ndata)) + ndata + struct.pack('H', crc) + buf[epos + 2:]
            pos += len(ndata) + 2
        else:
            pos += 9 + sz + 2

    def add(self, attrId, data, **kwargs):
        """ Add custon attribute.
            kwargs:
            type = TNEF.TYPE_ - set attribute type bits
            level = TNEF.LVL_ - change attribute level
        """
        lvl = TNEF.LVL_ATTACHMENT if attrId in TNEF.ATTACH_LEVEL_IDS else TNEF.LVL_MESSAGE
        if kwargs.get('level') is not None:
            lvl = kwargs['level']
        if kwargs.get('type') is not None:
            attrId = (attrId & 0xFFFF) | kwargs['type']
        self.TNEFStream += struct.pack('B', lvl)
        self.TNEFStream += struct.pack('I', attrId)
        self.TNEFStream += struct.pack('i', len(data))
        self.TNEFStream += data
        self.TNEFStream += struct.pack('H', self.checksum(data))
        return self

    def addDate(self, attrId, dtm=None, **kwargs):
        """ Add date attribute.
            dtm - datetime. default: now().
        """
        dtm = dtm or datetime.now()
        if isinstance(dtm, datetime):
            data = struct.pack('H', dtm.year)
            data += struct.pack('H', dtm.month)
            data += struct.pack('H', dtm.day)
            data += struct.pack('H', dtm.hour)
            data += struct.pack('H', dtm.minute)
            data += struct.pack('H', dtm.second)
            wday = dtm.weekday()
            wday = 0 if wday == 6 else wday + 1
            data += struct.pack('H', wday)
        else:
            data = dtm
        return self.add(attrId, data, **kwargs)

    def addTriple(self, attrId, address=None, **kwargs):
        """ Add triple attribute.
            address - TNEF.Address. default: sample@example.com
        """
        if not address:
            address = TNEF.Address()
        if isinstance(address, TNEF.Address):
            address = address.dumpTriple()
        return self.add(attrId, address, **kwargs)

    def addAddress(self, attrId, address=None, **kwargs):
        """ Add triple attribute.
            triple - TNEF.Address. default: sample@example.com
        """
        if address is None:
            address = TNEF.Address()
        if isinstance(address, TNEF.Address):
            address = address.dump()
        return self.add(attrId, address, **kwargs)

    def addRendData(self, attrId, rend=None, **kwargs):
        if rend is None:
            rend = TNEF.AttachRendData()
        if isinstance(rend, TNEF.AttachRendData):
            rend = rend.dump()
        return self.add(attrId, rend, **kwargs)

    def addZString(self, attrId, data, **kwargs):
        return self.add(attrId, data + "\x00", **kwargs)

    def addMapiProps(self, attrId, mapiProps=None, **kwargs):
        if mapiProps is None:
            mapiProps = MapiProps()
        return self.add(attrId, mapiProps.dumpTnef(), **kwargs)

    def addMapiPropsArr(self, attrId, mapiPropsArr=None, **kwargs):
        if mapiPropsArr is None:
            mapiPropsArr = [MapiProps()]
        val = struct.pack('I', len(mapiPropsArr))
        for x in mapiPropsArr:
            val += x.dumpTnef()
        return self.add(attrId, val, **kwargs)

    def addFmt(self, attrId, data, fmt, **kwargs):
        """ Add struct.format()'ed attribute. """
        if not isinstance(data, basestring):
            data = struct.pack(fmt, data)
        return self.add(attrId, data, **kwargs)

    def addDword(self, attrId, data, **kwargs):
        return self.addFmt(attrId, data, 'I', **kwargs)

    def addQword(self, attrId, data, **kwargs):
        return self.addFmt(attrId, data, 'Q', **kwargs)

    def addLong(self, attrId, data, **kwargs):
        return self.addFmt(attrId, data, 'i', **kwargs)

    def addWord(self, attrId, data, **kwargs):
        return self.addFmt(attrId, data, 'H', **kwargs)

    def addShort(self, attrId, data, **kwargs):
        return self.addFmt(attrId, data, 'h', **kwargs)

    def addByte(self, attrId, data, **kwargs):
        return self.addFmt(attrId, data, 'B', **kwargs)

    def std(self):
        """ Standard tnef initialization: version & codepage. """
        return self.version().codePage()

    def version(self, data=DATA_VERSION, **kwargs):
        return self.addDword(TnefEnum.ID_TNEFVERSION, data, **kwargs)

    def codePage(self, data=DATA_CODEPAGE, **kwargs):
        return self.addQword(TnefEnum.ID_OEMCODEPAGE, data, **kwargs)

    def owner(self, address=None, **kwargs):
        return self.addAddress(TnefEnum.ID_OWNER, address, **kwargs)

    def sentFor(self, address=None, **kwargs):
        return self.addAddress(TnefEnum.ID_SENTFOR, address, **kwargs)

    def delegate(self, data="", **kwargs):
        return self.add(TnefEnum.ID_DELEGATE, data, **kwargs)

    def dateStart(self, dtm=None, **kwargs):
        return self.addDate(TnefEnum.ID_DATESTART, dtm, **kwargs)

    def dateEnd(self, dtm=None, **kwargs):
        return self.addDate(TnefEnum.ID_DATEEND, dtm, **kwargs)

    def aidOwner(self, data=0, **kwargs):
        return self.addLong(TnefEnum.ID_AIDOWNER, data, **kwargs)

    def requestRes(self, data=0, **kwargs):
        return self.addShort(TnefEnum.ID_REQUESTRES, data, **kwargs)

    def fromAddress(self, address=None, **kwargs):
        return self.addTriple(TnefEnum.ID_FROM, address, **kwargs)

    def subject(self, data="", **kwargs):
        return self.addZString(TnefEnum.ID_SUBJECT, data, **kwargs)

    def dateSent(self, dtm=None, **kwargs):
        return self.addDate(TnefEnum.ID_DATESENT, dtm, **kwargs)

    def dateRecd(self, dtm=None, **kwargs):
        return self.addDate(TnefEnum.ID_DATERECD, dtm, **kwargs)

    def messageStatus(self, data=0, **kwargs):
        return self.addByte(TnefEnum.ID_MESSAGESTATUS, data, **kwargs)

    def messageClass(self, data=CLASS_NOTE, **kwargs):
        return self.addZString(TnefEnum.ID_MESSAGECLASS, data, **kwargs)

    def originalMessageClass(self, data=CLASS_NOTE, **kwargs):
        return self.addZString(TnefEnum.ID_ORIGINALMESSAGECLASS, data, **kwargs)

    def messageId(self, data="", **kwargs):
        return self.add(TnefEnum.ID_MESSAGEID, data, **kwargs)

    def parentId(self, data="", **kwargs):
        return self.addZString(TnefEnum.ID_PARENTID, data, **kwargs)

    def conversationId(self, data="", **kwargs):
        return self.addZString(TnefEnum.ID_CONVERSATIONID, data, **kwargs)

    def body(self, data="", **kwargs):
        return self.addZString(TnefEnum.ID_BODY, data, **kwargs)

    def priority(self, data=PRIORITY_NORMAL, **kwargs):
        return self.addShort(TnefEnum.ID_PRIORITY, data, **kwargs)

    def attachData(self, data, **kwargs):
        return self.add(TnefEnum.ID_ATTACHDATA, data, **kwargs)

    def attachTitle(self, data="", **kwargs):
        return self.addZString(TnefEnum.ID_ATTACHTITLE, data, **kwargs)

    def attachMetaFile(self, data, **kwargs):
        return self.add(TnefEnum.ID_ATTACHMETAFILE, data, **kwargs)

    def attachCreateDate(self, dtm=None, **kwargs):
        return self.addDate(TnefEnum.ID_ATTACHCREATEDATE, dtm, **kwargs)

    def attachModifyDate(self, dtm=None, **kwargs):
        return self.addDate(TnefEnum.ID_ATTACHMODIFYDATE, dtm, **kwargs)

    def dateModified(self, dtm=None, **kwargs):
        return self.addDate(TnefEnum.ID_DATEMODIFIED, dtm, **kwargs)

    def attachTransportFilename(self, data="", **kwargs):
        return self.addZString(TnefEnum.ID_ATTACHTRANSPORTFILENAME, data, **kwargs)

    def attachRendData(self, rend=None, **kwargs):
        return self.addRendData(TnefEnum.ID_ATTACHRENDDATA, rend, **kwargs)

    def mapiProps(self, mapiProps=None, **kwargs):
        return self.addMapiProps(TnefEnum.ID_MAPIPROPS, mapiProps, **kwargs)

    def msgProps(self, mapiProps=None, **kwargs):
        return self.addMapiProps(TnefEnum.ID_MAPIPROPS, mapiProps, **kwargs)

    def attachment(self, mapiProps=None, **kwargs):
        return self.addMapiProps(TnefEnum.ID_ATTACHMENT, mapiProps, **kwargs)

    def recipTable(self, mapiPropsArr=None, **kwargs):
        return self.addMapiPropsArr(TnefEnum.ID_RECIPTABLE, mapiPropsArr, **kwargs)


if __name__ == "__main__":
    from pyout.enums.mapi import MapiEnum
    import rtf
    import uuid
    import sys
    from officefile import OfficeFile
    import ole
    import os
    import base64
    if len(sys.argv) < 3:
        print "Usage: tnef.py command [params]\nCommands:"
        print "parse tneffile - parse tnef file"
        print "dump tneffile prop dumpfile - parse tnef file and dump property to stdout"
        print "rtf rtffile outfile - build tnef with rtf"
        print "folderwv url outfile - build tnef with FOLDER_WEB_VIEW property"
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "parse" or cmd == "dump":
        dump = sys.argv[3] if cmd == "dump" else None
        dfile = sys.argv[4] if cmd == "dump" else None
        TNEF.parse(open(sys.argv[2], "rb"), dump, dfile)
        sys.exit(0)
    mp = MapiProps()
    t = TNEF().std().messageClass()
    fnm = 3
    if cmd == "folderwv":
        mp.addBinStream(MapiEnum.PR_FOLDER_WEBVIEW_INFO, sys.argv[2].encode("utf-16le"))
        t.mapiProps(mp)
        t.msgProps(mp)
        t.attachment(mp)
        t.recipTable([mp])
    elif cmd == "repack":
        data = ''.join([x.rstrip() for x in open(sys.argv[2])])
        tnef = base64.b64decode()
        rtf = open(sys.argv[3]).read()
        rtdata = rtf.RTFCompressor.compress(rtdata)
        nu = TNEF.replaceRtf(tnef, rtfdata)
        nub = base64.b64encode(nu)

    elif cmd == "rtf":
        if os.path.isfile(sys.argv[2]):
            rtdata = open(sys.argv[2]).read()
        else:
            fnm = 4
            Cls = ole.getOleObject(sys.argv[2])
            obj = Cls(sys.argv[3])
            data = OfficeFile.OLEObject(obj)
            doc = rtf.RTF()
            doc.addObject(
                "OfficeDOC",
                data,
                objType=rtf.RTF.RtfObject.OBJ_AUTOLINK,
                embedType=rtf.RTF.RtfObject.EMBED)
            rtdata = doc.dump()
        rtdata = rtf.RTFCompressor.compress(rtdata)
        # MS-EMAIL fields
        # mp.add(MapiEnum.PR_ALTERNATE_RECIPIENT_ALLOWED, 1)
        # mp.add(MapiEnum.PR_PRIORITY, 0)
        # mp.add(MapiEnum.PR_READ_RECEIPT_REQUESTED, 0)
        # mp.add(MapiEnum.PR_CONVERSATION_TOPIC, 'rtfmail')
        # mp.add(MapiEnum.PR_CONVERSATION_INDEX,
        #        "\x01\xd3\x46\x5c\x32\xb5\xe5\xab\x9f\x99\xda\x3f\x4d\xcc\xb8\xdc\x7a\x1e\x5b\x39\xcb\x38")
        # mp.add(MapiEnum.PR_DELETE_AFTER_SUBMIT, 0)
        # mp.add(MapiEnum.PR_SENTMAIL_ENTRYID,
        #        "\x00\x00\x00\x00\xd5\xe1\xaf\x72\x38\x17\x68\x47\xbd\xac\xbb\x79\xf4\x73\xa7\x80\xc2\x80\x00\x00")
        # mp.add(MapiEnum.PR_SUBMIT_FLAGS, 1)
        # mp.add(0x0E28001E, '00000002\x01user1@192.168.56.13\x01user1@192.168.56.13')
        # mp.add(0x0E29001E, '00000002\x01user1@192.168.56.13\x01user1@192.168.56.13')
        mp.rtf(rtdata)
        # mp.add(0x3FDE0003, 20127)
        # mp.add(0x3FF10003, 1049)
        # mp.add(0x59090003, 3)
        # mp.add(0x8010000B, 0, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34051)
        # mp.add(0x80110003, 0, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34064)
        # mp.add(0x80A6000B, 0, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34054)
        # mp.add(0x80A70003, 0, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34049)
        # mp.add(0x80AF000B, 0, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34062)
        # mp.add(0x80B20003, 0, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34072)
        # mp.add(0x80C8000B, 0, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34178)
        # mp.add(0x80FD0003, 1033, guid=uuid.UUID("{00062008-0000-0000-c000-000000000046}"), map=34283)
        # mp.add(MapiEnum.PR_RTF_IN_SYNC, 1)
        # mp.add(MapiEnum.PR_MAPPING_SIGNATURE, "\xd5\xe1\xaf\x72\x38\x17\x68\x47\xbd\xac\xbb\x79\xf4\x73\xa7\x80")
        # mp.add(MapiEnum.PR_STORE_RECORD_KEY, "\xd5\xe1\xaf\x72\x38\x17\x68\x47\xbd\xac\xbb\x79\xf4\x73\xa7\x80")
        # mp.add(MapiEnum.PR_OBJECT_TYPE, 5)
        # mp.add(MapiEnum.PR_STORE_SUPPORT_MASK, 245710845)
        # mp.add(0x340F0003, 245710845)
        # mp.add(MapiEnum.PR_MDB_PROVIDER, "NITA\xf9\xbf\xb8\x01\x00\xaa\x00\x37\xd9\x6e\x00\x00")
        # mp.add(MapiEnum.PR_TNEF_CORRELATION_KEY, "00000000D5E1AF7238176847BDACBB79F473A78084885E19\x00")
        mp.add(MapiEnum.PR_RTF_SYNC_BODY_CRC, 0)
        # mp.add(MapiEnum.PR_RTF_SYNC_BODY_COUNT, 5)
        # mp.add(MapiEnum.PR_RTF_SYNC_PREFIX_COUNT, 0)
        # mp.add(MapiEnum.PR_RTF_SYNC_TRAILING_COUNT, 0)
        # mp.add(MapiEnum.PR_RTF_SYNC_BODY_TAG, 'MYRTF')
        t.mapiProps(mp)

    elif cmd == "ole":
        if os.path.isfile(sys.argv[2]):
            data = open(sys.argv[2]).read()
        else:
            fnm = 4
            Cls = ole.getOleObject(sys.argv[2])
            obj = Cls(sys.argv[3])
            data = OfficeFile.OLEObject(obj)
        mp.add(MapiEnum.PR_OBJECT_TYPE, 5)
        mp.add(MapiEnum.PR_HASATTACH, True)
        mp.add(MapiEnum.PR_MESSAGE_CLASS, "IPM.Note")
        mp.add(MapiEnum.PR_MESSAGE_FLAGS, 12)
        mp.add(MapiEnum.PR_BODY, "Test mail")
        t.mapiProps(mp)

        ard = TNEF.AttachRendData(TNEF.AttachRendData.TYPE_OLE, pos=0, width=100, height=100)
        t.attachRendData(ard)
        t.attachData(data)

        mp = MapiProps()
        mp.add(MapiEnum.PR_OBJECT_TYPE, 7)
        mp.add(MapiEnum.PR_ATTACH_NUM, 0)
        mp.add(MapiEnum.PR_RENDERING_POSITION, 5)
        mp.add(MapiEnum.PR_ATTACH_METHOD, 6)
        #mp.add(MapiEnum.PR_ATTACH_LONG_PATHNAME, "http://www.local:8080/index.html")
        #pg = uuid.UUID("{96357F7F-59E1-47D0-99A7-46515C183B54}")
        #mp.addString(0x8000001F, "GoogleDrive", guid=pg, map="AttachmentProviderType")
        g = uuid.UUID("{0000000B-0000-0000-C000-000000000046}")
        mp.add(MapiEnum.PR_ATTACH_DATA_OBJ, g.bytes_le + data)
        t.attachment(mp)
    else:
        raise Exception("Unsupported command:" + cmd)
    with open(sys.argv[fnm], "wb") as f:
        f.write(t.dump())
