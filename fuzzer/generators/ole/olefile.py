#!/usr/bin/env python
import os
import uuid
import struct
import copy
from datetime import datetime, timedelta
from StringIO import StringIO
from utils import Utils, OleError
import olestream


class OleFile:
    """ Binary CFB office file """

    MAXREGSECT = 0xFFFFFFFA  # : (-6) maximum SECT
    DIFSECT = 0xFFFFFFFC  # : (-4) denotes a DIFAT sector in a FAT
    FATSECT = 0xFFFFFFFD  # : (-3) denotes a FAT sector in a FAT
    ENDOFCHAIN = 0xFFFFFFFE  # : (-2) end of a virtual stream chain
    FREESECT = 0xFFFFFFFF  # : (-1) unallocated sector

    DIR_SIZE = 128

    class Header(object):
        MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

        def __init__(self):
            self.clsid = Utils.GUID_NULL
            self.minor = 0x3E
            self.major = 3
            self.order = 0xFFFE
            self.sshift = 9
            self.minishift = 6
            self.reserved1 = 0
            self.reserved2 = 0
            self.dirnum = 0
            self.fatnum = 1
            self.dirloc = 0
            self.transnum = 0
            self.minicutoff = 0x1000
            self.miniloc = 0
            self.mininum = 0
            self.difatloc = 0xFFFFFFFE
            self.difatnum = 0
            self.difattbl = []

        def setVersion(self, ver):
            self.major = ver
            self.sshift = 0x0C if ver == 4 else 9

        def secsize(self, mini=False):
            if mini:
                return 1 << self.minishift
            return 1 << self.sshift

        def read(self, fp):
            mag = fp.read(8)
            if mag != self.MAGIC:
                raise OleError("Wrong magic")
            self.clsid = uuid.UUID(bytes_le=fp.read(16))
            (self.minor, self.major, self.order, self.sshift, self.minishift, self.reserved1, self.reserved2,
                self.dirnum, self.fatnum, self.dirloc, self.transnum, self.minicutoff, self.miniloc, self.mininum,
                self.difatloc, self.difatnum) = struct.unpack("<HHHHHHLLLLLLLLLL", fp.read(52))
            self.difattbl = []
            for x in struct.unpack("<109L", fp.read(436)):
                if x != OleFile.FREESECT:
                    self.difattbl += [x]
            return self

        def write(self, fp):
            fp.write(self.MAGIC)
            fp.write(self.clsid.bytes_le)
            fp.write(struct.pack("<HHHHHHLLLLLLLLLL", self.minor, self.major, self.order, self.sshift, self.minishift,
                                 self.reserved1, self.reserved2, self.dirnum, self.fatnum,
                                 self.dirloc, self. transnum, self.minicutoff, self.miniloc,
                                 self.mininum, self.difatloc, self.difatnum))
            fmt = "<{}L".format(len(self.difattbl))
            fp.write(struct.pack(fmt, *self.difattbl))
            fp.write("\xFF" * 4 * (109 - len(self.difattbl)))
            if self.secsize() > 512:
                fp.write("\x00" * (self.secsize() - 512))

        def pprint(self):
            print "OLEFILE clsid:", self.clsid, " ver: {}.{}".format(self.major, self.minor)
            print "secsize:", self.secsize(), self.secsize(True)
            print "fat sector count:", self.fatnum, self.mininum
            fat = [hex(x) for x in self.difattbl]
            print "directory:", hex(self.dirloc), " fat:", fat, " minifat:", hex(self.miniloc)

    class Node:
            # [PL]: added constants for Directory Entry IDs (from AAF specifications)
        MAXREGSID = 0xFFFFFFFA  # : (-6) maximum directory entry ID
        NOSTREAM = 0xFFFFFFFF  # : (-1) unallocated directory entry

        # [PL] object types in storage (from AAF specifications)
        STGTY_EMPTY = 0  # : empty directory entry
        STGTY_STORAGE = 1  # : element is a storage object
        STGTY_STREAM = 2  # : element is a stream object
        STGTY_LOCKBYTES = 3  # : element is an ILockBytes object
        STGTY_PROPERTY = 4  # : element is an IPropertyStorage object
        STGTY_ROOT = 5  # : element is a root storage

        # Unknown size for a stream (used by OleStream):
        UNKNOWN_SIZE = 0x7FFFFFFF

        def __init__(self, name=None, clsid=None, etype=STGTY_STREAM):
            if name and len(name) > 31:
                raise OleError("Name too long: " + name)
            self.name = unicode(name) if name else None
            self.clsid = clsid or Utils.GUID_NULL
            self.etype = etype
            self.flags = 0
            self.ctime = None
            self.mtime = None
            self.sector = None
            self.data = None
            self.parent = None
            self.subnodes = {}

        def read(self, buf):
            nm = buf[:64]
            (ln, self.etype, col, left, right, child) = struct.unpack("<HBBLLL", buf[64:80])
            if ln == 0:
                return (None,) * 4
            self.name = ''
            for x in nm.decode('UTF-16LE')[:ln - 1]:
                if x == '\x00':
                    break
                if (x > '\x00' and x < ' ') or x > '\x7F':
                    self.name += u"\\x{:02X}".format(ord(x))
                else:
                    self.name += x
            self.clsid = uuid.UUID(bytes_le=buf[80:96])
            (self.flags, ctime, mtime, self.sector, size) = struct.unpack("<LQQLQ", buf[96:])
            self.ctime = Utils.fromFiletime(ctime)
            self.mtime = Utils.fromFiletime(mtime)
            return (left, right, child, size)

        def __repr__(self):
            return "<Node " + self.name + ">"

        def rname(self):
            nm = self.name
            if not nm:
                return None
            while u"\\x" in nm:
                pos = nm.find(u"\\x")
                hx = int(nm[pos + 2:pos + 4], 16)
                nm = nm.replace(u"\\x{:02X}".format(hx), chr(hx))
            return nm

        def findNode(self, path, canCreate=False):
            p = path.split("/")
            if (len(p) == 1):
                if canCreate and not path in self.subnodes:
                    nd = OleFile.Node(path)
                    nd.parent = self
                    self.subnodes[nd.name] = nd
                return None if not path in self.subnodes else self.subnodes[path]
            if not p[0] in self.subnodes or self.subnodes[p[0]].etype != self.STGTY_STORAGE:
                return None
            return self.subnodes[p[0]].findNode('/'.join(p[1:]), canCreate)

        @staticmethod
        def writeEmpty(fp):
            fp.write("\x00" * 68)
            fp.write("\xFF" * 12)
            fp.write("\x00" * 48)

        def write(self, fp, left, right, child):
            nm = self.rname() or ''
            left = left or self.NOSTREAM
            right = right or self.NOSTREAM
            child = child or self.NOSTREAM
            fp.write(nm.encode('UTF-16LE'))
            ln = len(nm)
            fp.write("\x00" * (64 - ln * 2))
            fp.write(struct.pack("<HBBLLL", ln * 2 + 2, self.etype, 1, left, right, child))
            fp.write(self.clsid.bytes_le)
            mtime = Utils.toFiletime(self.mtime)
            ctime = Utils.toFiletime(self.ctime)
            if isinstance(self.data, (int, long)):
                size = self.data
                self.data = None
            else:
                size = len(self.data) if self.data else 0
            fp.write(struct.pack("<LQQLQ", self.flags, ctime, mtime, self.sector or 0, size))

        def pprint(self, tab=0):
            print "\t" * tab,
            print "{} ({}) - {} {}".format(self.name, self.clsid, self.etype, len(self.data) if self.data else u"DIR")
            o = olestream.StreamFactory(self.name, None)
            objs = [o.parse(self.data)] if o else []
            for x in self.subnodes:
                objs += self.subnodes[x].pprint(tab + 1)
            return objs

    class Reader:

        def __init__(self, fp):
            self.fp = fp
            self.header = None
            self.secsize = 0
            self.fat = []
            self.minifat = []
            self.ministream = None

        def readHeader(self):
            self.header = OleFile.Header().read(self.fp)
            self.secsize = self.header.secsize()
            for x in self.header.difattbl:
                self.seek(x)
                fmt = "<{}L".format(self.secsize / 4)
                self.fat += struct.unpack(fmt, self.fp.read(self.secsize))
            if self.header.miniloc < OleFile.MAXREGSECT:
                stream = self.readFatStream(self.header.miniloc)
                fmt = "<{}L".format(len(stream) / 4)
                self.minifat = struct.unpack(fmt, stream)
            return self.header

        def seek(self, sector):
            self.fp.seek((sector + 1) * self.secsize)

        def readFatStream(self, secnum, size=None):
            ret = ''
            while True:
                self.seek(secnum)
                ret += self.fp.read(self.secsize)
                if size and len(ret) >= size:
                    return ret[:size]
                if self.fat[secnum] > OleFile.MAXREGSECT:
                    return ret
                secnum = self.fat[secnum]

        def readMinifatStream(self, secnum, size=None):
            if not self.ministream:
                raise OleError("Ministream not loaded")
            ret = ''
            sz = self.header.secsize(True)
            while True:
                pos = sz * secnum
                ret += self.ministream[pos:pos + sz]
                if size and len(ret) >= size:
                    return ret[:size]
                if self.minifat[secnum] > OleFile.MAXREGSECT:
                    return ret
                secnum = self.minifat[secnum]

        def readDir(self, data, idx, parent=None):
            nd = OleFile.Node()
            nd.parent = parent
            isRoot = parent is None
            pos = idx * OleFile.DIR_SIZE
            (left, right, child, size) = nd.read(data[pos:pos + OleFile.DIR_SIZE])
            if isRoot != (nd.etype == OleFile.Node.STGTY_ROOT):
                raise OleError("Wrong root node.")
            if nd.sector is not None and size:
                if isRoot:
                    self.ministream = self.readFatStream(nd.sector, size)
                elif nd.etype == OleFile.Node.STGTY_STREAM:
                    if size < self.header.minicutoff:
                        nd.data = self.readMinifatStream(nd.sector, size)
                    else:
                        nd.data = self.readFatStream(nd.sector, size)
                else:
                    raise OleError("Dont know how to read sectors of " + str(nd.etype))
            if left and left != OleFile.Node.NOSTREAM:
                node = self.readDir(data, left, nd.parent)
                nd.parent.subnodes[node.name] = node
            if right and right != OleFile.Node.NOSTREAM:
                node = self.readDir(data, right, nd.parent)
                nd.parent.subnodes[node.name] = node
            if child and child != OleFile.Node.NOSTREAM:
                ch = self.readDir(data, child, nd)
                nd.subnodes[ch.name] = ch
            return nd

        def readRoot(self):
            if not self.header:
                raise OleError("Header not read.")
            data = self.readFatStream(self.header.dirloc)
            return self.readDir(data, 0)

        def read(self):
            return (self.readHeader(), self.readRoot())

    class Writer:

        def __init__(self, fp, header):
            self.fp = fp
            self.header = copy.copy(header)
            self.header.difattbl = []
            self.files = [[], []]
            self.fats = [[], []]

        def secCount(self, size, mini=False):
            ssz = self.header.secsize(mini)
            return size // ssz + (0 if size % ssz == 0 else 1)

        def addFat(self, num, fatid=0):
            for x in range(num - 1):
                self.fats[fatid] += [len(self.fats[fatid]) + 1]
            self.fats[fatid] += [OleFile.ENDOFCHAIN]

        def calcFats(self, node):
            if node.etype == OleFile.Node.STGTY_STREAM and node.data and len(node.data) > 0:
                sz = len(node.data)
                fatid = 1 if sz < self.header.minicutoff else 0
                node.sector = len(self.fats[fatid])
                self.files[fatid] += [node]
                self.addFat(self.secCount(sz, fatid == 1), fatid)
                return 1
            else:
                ret = 1
                for x in node.subnodes:
                    ret += self.calcFats(node.subnodes[x])
                return ret

        def writeFiles(self, fp, mini=False):
            fatid = 1 if mini else 0
            ssz = self.header.secsize(mini)
            for x in self.files[fatid]:
                fp.write(x.data)
                sz = len(x.data)
                if sz % ssz != 0:
                    fp.write("\x00" * (ssz - sz % ssz))
            self.files[fatid] = None

        def writeFat(self, mini=False):
            fatid = 1 if mini else 0
            fmt = "<{}L".format(len(self.fats[fatid]))
            self.fp.write(struct.pack(fmt, *self.fats[fatid]))
            fill = (len(self.fats[fatid]) * 4) % self.header.secsize()
            if fill > 0:
                self.fp.write("\xFF" * (self.header.secsize() - fill))

        def writeNode(self, node=None, left=None, right=None, child=None):
            if not node:
                OleFile.Node.writeEmpty(self.fp)
                return
            node.write(self.fp, left, right, child)

        def writeDir(self, root, cid=1, left=None, right=None):
            if len(root.subnodes) == 0:
                self.writeNode(root, left, right)
                root.sector = cid
                return cid
            chld = cid + len(root.subnodes) // 2  # +1 (cid is +1 already)
            self.writeNode(root, left, right, chld)
            root.sector = cid
            return cid + len(root.subnodes)

        def writeNodes(self, root, cid):

            def sorter(x, y):
                nx = x.rname()
                ny = y.rname()
                if len(nx) != len(ny):
                    return cmp(len(nx), len(ny))
                return cmp(nx.upper(), ny.upper())

            def btree(cnt, hlp=[0]):
                add = hlp[0]
                if cnt < 4:
                    SMALL = [[], [(None, None)], [(None, None), (add, None)],
                             [(None, None), (add, add + 2), (None, None)]]
                    SMALL_V = [add, add, add + 1, add + 1]
                    hlp[0] = SMALL_V[cnt]
                    return SMALL[cnt]
                hlp[0] = cnt // 2 + 1
                ops = [[add], [hlp[0]]]
                lft = btree(hlp[0] - 1, ops[0])
                rgt = btree(cnt - hlp[0], ops[1])
                return lft + [(ops[0][0], ops[1][0])] + rgt

            subs = sorted(root.subnodes.values(), cmp=sorter)
            lnk = btree(len(subs))
            lnk = [(None if x[0] is None else x[0] + root.sector,
                    None if x[1] is None else x[1] + root.sector) for x in lnk]
            for i, x in enumerate(subs):
                if x.etype == OleFile.Node.STGTY_STORAGE:
                    cid = self.writeDir(x, cid, lnk[i][0], lnk[i][1])
                else:
                    self.writeNode(x, lnk[i][0], lnk[i][1])
            for x in subs:
                if x.etype == OleFile.Node.STGTY_STORAGE:
                    self.writeNodes(x, cid)

        def write(self, root):
            objs = self.calcFats(root)
            ssz = self.header.secsize()
            dirsz = self.secCount(objs * OleFile.DIR_SIZE)  # directory sectors
            self.header.mininum = self.secCount(len(self.fats[1]) * 4)  # minifat sectors
            minisz = self.secCount(len(self.fats[1]) * 64)    # ministream sectors
            sec = len(self.fats[0])
            fatsz = sec + minisz + self.header.mininum + dirsz
            self.header.fatnum = self.secCount(fatsz * 4)  # fat sectors
            for x in range(self.header.fatnum):
                self.header.difattbl += [sec]
                self.fats[0] += [OleFile.FATSECT]
                sec += 1
            self.header.dirloc = sec
            self.addFat(dirsz)
            self.header.miniloc = len(self.fats[0])
            self.addFat(self.header.mininum)
            root.sector = len(self.fats[0])
            root.data = len(self.fats[1]) * 64
            self.addFat(minisz)
            # write
            self.header.write(self.fp)
            self.writeFiles(self.fp)
            self.writeFat()
            self.writeNodes(root, self.writeDir(root))
            secobj = ssz // OleFile.DIR_SIZE
            fill = objs % secobj
            if fill:                    # fill with empty direntries
                for x in range(secobj - fill):
                    self.writeNode()
            self.writeFat(True)
            mini = StringIO()
            self.writeFiles(mini, True)
            data = mini.getvalue()
            del mini
            self.fp.write(data)
            fill = len(data) % ssz
            if fill > 0:
                self.fp.write("\x00" * (ssz - fill))

    class IOProxy(StringIO):

        def __init__(self, node):
            StringIO.__init__(self, node.data)
            self.node = node

        def __enter__(self): return self

        def __exit__(self, exc_type, exc_val, exc_tb): self.close()

        def close(self):
            self.node.data = self.getvalue()
            StringIO.close(self)

    def __init__(self, fp=None, **kwargs):
        if fp:
            rd = OleFile.Reader(Utils.openFP(fp))
            self.header, self.root = rd.read()
        else:
            self.header = OleFile.Header()
            self.root = OleFile.Node(u"Root Entry", clsid=kwargs.get("clsid"), etype=OleFile.Node.STGTY_ROOT)

    def save(self, fname):
        with open(fname, "wb") as f:
            OleFile.Writer(f, self.header).write(self.root)

    def dump(self):
        fp = StringIO()
        OleFile.Writer(fp, self.header).write(self.root)
        return fp.getvalue()

    def pprint(self):
        self.header.pprint()
        objs = self.root.pprint()
        print
        for x in objs:
            x.pprint()

    def node(self, path, canCreate=False):
        if path.startswith('/'):
            path = path[1:]
        return self.root.findNode(path, canCreate)

    def isFile(self, path):
        nd = self.node(path)
        return nd and nd.etype == OleFile.Node.STGTY_STREAM

    def isDir(self, path):
        nd = self.node(path, OleFile.Node.STGTY_STORAGE)
        return nd and nd.etype == OleFile.Node.STGTY_STREAM

    def mkdir(self, path, clsid=None):
        nd = self.node(path, True)
        if not nd:
            raise OleError("Path not found: " + path)
        nd.etype = OleFile.Node.STGTY_STORAGE
        if clsid:
            nd.clsid = clsid
        nd.data = None
        return nd

    def open(self, path, mode="r"):
        nd = self.node(path, 'w' in mode)
        if not nd or nd.etype != OleFile.Node.STGTY_STREAM:
            raise OleError("File not exists: " + path)
        if not nd.data:
            nd.data = ''
        return OleFile.IOProxy(nd)

    def getFile(self, path):
        nd = self.node(path)
        if not nd or nd.etype != OleFile.Node.STGTY_STREAM:
            raise OleError("File not exists: " + path)
        return nd.data

    def setFile(self, path, data):
        nd = self.node(path, True)
        if not nd or nd.etype != OleFile.Node.STGTY_STREAM:
            raise OleError("Cant create file: " + path)
        nd.data = data
        return nd

    def rm(self, path):
        nd = self.node(path)
        del nd.parent.subnodes[nd.name]

    @staticmethod
    def detect(fp):
        return Utils.readFP(fp, 8) == OleFile.Header.MAGIC

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        ole = OleFile()
        ole.mkdir("FOLDER")
        ole.root.clsid = uuid.uuid4()
        with ole.open("/FOLDER/\\x02TestDoc", "w") as f:
            f.write("Some String")
    else:
        ole = OleFile(sys.argv[1])
        if len(sys.argv) > 3:
            buf = ole.getFile(sys.argv[2])
            open(sys.argv[3], "wb").write(buf)
    ole.pprint()
    ole.save("tmp.doc")
