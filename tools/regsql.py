#!/usr/bin/env python

import sys
import argparse
import logging
import json
from pyout.classes.registry import Registry

logger = logging.getLogger("Fuzzer")


class RegSQL:
    MODE_SQLITE = 0

    class SQL:

        def __init__(self, mode):
            self.mode = mode

        def null(self):
            return "null"

        def str(self, val):
            if val is None:
                return self.null()
            repl = {"\\": "\\\\", "\"": "\\\"", "\'": "\'\'"}
            for x in repl:
                val = val.replace(x, repl[x])
            return "'" + val + "'"

        def guid(self, val):
            return self.str(val)

        def asciiEncode(self, val):
            if not val:
                return val
            return ''.join([i if ord(i) < 128 else ' ' for i in val])

        def ascii(self, val):
            return self.str(self.asciiEncode(val))

        def strArr(self, arr, ifempty=None):
            if not arr or len(arr) == 0:
                return ifempty or self.null()
            return self.str(", ".join(arr))

    class EmptyRegKey:

        def open(self, k):
            return None

        def value(self, k=None):
            return None

        def subkeyValue(self, nm):
            return None

    def __init__(self):
        self.cmds = {"combIntf": self.combIntf, "create": self.createSQL}
        self.mode = RegSQL.MODE_SQLITE
        self.AUTO_INCREMENT = "AUTO_INCREMENT"
        self.reg = None
        self.sql = RegSQL.SQL(self.mode)

    def initDB(self):
        print """
        BEGIN;
        -- helper tables
        CREATE TABLE obj_types(id INTEGER NOT NULL PRIMARY KEY, name VARCHAR NOT NULL);
        INSERT INTO obj_types(id, name) VALUES (1,'AppID'),(2,'Typelib'),(3,'CLSID'),(4,'Interface');
        CREATE TABLE flags_descr(obj_type INTEGER NOT NULL, value INTEGER NOT NULL, descr VARCHAR NOT NULL);
        """

    def finDB(self):
        print """
        COMMIT;
        BEGIN;

        --integrity restore
        INSERT INTO appid(id, name) SELECT DISTINCT appid, null FROM clsid
            WHERE appid IS NOT NULL AND appid NOT IN (SELECT id FROM appid);
        INSERT INTO typelib(id, version, name) SELECT DISTINCT typelib, null, null FROM clsid
            WHERE typelib IS NOT NULL AND typelib NOT IN (SELECT id FROM typelib);
        INSERT INTO clsid(id, name) SELECT DISTINCT pstub_clsid, null FROM interface
            WHERE pstub_clsid IS NOT NULL AND pstub_clsid NOT IN (SELECT id FROM clsid);
        INSERT INTO clsid(id, name) SELECT DISTINCT pstub_clsid2, null FROM interface
            WHERE pstub_clsid2 IS NOT NULL AND pstub_clsid2 NOT IN (SELECT id FROM clsid);
        INSERT INTO interface(id, name) SELECT DISTINCT async_intf, null FROM interface
            WHERE async_intf IS NOT NULL AND async_intf NOT IN (SELECT id FROM interface);
        INSERT INTO clsid(id, name) SELECT DISTINCT clsid, null FROM clsid_interfaces
            WHERE clsid NOT IN (SELECT id FROM clsid);
        INSERT INTO interface(id, name) SELECT DISTINCT interface, null FROM clsid_interfaces
            WHERE interface NOT IN (SELECT id FROM interface);

        --views
        CREATE VIEW guids(id, obj_type) AS
            SELECT id,1 FROM appid UNION
            SELECT id,2 FROM typelib UNION
            SELECT id,3 FROM clsid UNION
            SELECT id,4 FROM interface;

        CREATE VIEW persist(id, name, flags, appid, typelib, progid, class, libs, interfaces, status, descr) AS
SELECT c.id, c.name, c.flags, (a.id || '
' || a.name), (t.id || '
' || t.name || '
w64tlb: ' || t.win64 || '
w32tlb: ' || t.win32), c.progid, c.class, c.libs,
(SELECT GROUP_CONCAT(name, '
') FROM interface _i LEFT JOIN clsid_interfaces _ci ON _ci.interface=_i.id WHERE _ci.clsid = c.id),
c.status, c.descr
FROM interface i LEFT JOIN clsid_interfaces ci ON ci.interface = i.id
LEFT JOIN clsid c ON c.id = ci.clsid LEFT JOIN appid a ON a.id = c.appid LEFT JOIN typelib t ON t.id = c.typelib
WHERE i.name='IPersist';

        CREATE VIEW todo(id, name, flags, appid, typelib, progid, class, libs, interfaces, status, descr) AS
            SELECT * FROM persist WHERE descr IS NULL;
        COMMIT;
        """

# ------------------------------APPS--------------------------------
    def getAppNames(self, reg, names, flag):
        for x in reg.subkeys():
            if x[0] == '{':
                continue
            r = reg.open(x)
            appid = r.value('AppID')
            n2 = r.value()
            if appid not in names:
                names[appid] = {'name': x, 'other': [], 'flags': flag}
            else:
                names[appid]['flags'] |= flag
                if x not in names[appid]['other'] and x != names[appid]['name']:
                    names[appid]['other'] += [x]
            if n2 and n2 not in names[appid]['other'] and n2 != names[appid]['name'] and n2 != appid:
                names[appid]['other'] += [n2]

    def printApp(self, reg, aid, names, flags):
        if aid[0] != '{':
            return
        if not self.firstPrint:
            print ","
        else:
            self.firstPrint = False
        name = None
        onames = []
        appf = 0
        serv = None
        runas = None
        if reg:
            r = reg.open(aid)
            name = self.sql.asciiEncode(r.value())
            serv = r.value('LocalService')
            runas = r.value('RunAs')
            if r.hasValue('DllSurrogate'):
                flags |= 4
            appf = r.value("AppIDFlags") or 0
        if aid in names:
            onames = [name] if name and name != names[aid][
                'name'] and name not in names[aid]['other'] and name != aid else []
            name = names[aid]['name']
            onames += names[aid]['other']
        # print aid, name, onames
        print "({},{},{},{},{},{},{})".format(self.sql.guid(aid), self.sql.str(name),
                                              self.sql.strArr(onames), flags, self.sql.str(serv),
                                              self.sql.str(runas), appf),

    def addApps(self):
        logger.info('Processing Apps')
        print """-- appid
        INSERT INTO flags_descr (obj_type, value, descr) VALUES
            (1,1,'64bit app'),
            (1,2,'32bit app'),
            (1,4,'DllSurrogate');
        CREATE TABLE appid(
            id GUID NOT NULL PRIMARY KEY,
            name VARCHAR,
            other_names VARCHAR DEFAULT NULL,
            flags INTEGER NOT NULL DEFAULT 0,
            local_service VARCHAR DEFAULT NULL,
            run_as VARCHAR DEFAULT NULL,
            appid_flags INTEGER DEFAULT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            descr VARCHAR DEFAULT NULL
            );
        CREATE INDEX idx_appid_name ON appid(name);
        CREATE INDEX idx_appid_status ON appid(status);
        INSERT INTO appid(id, name, other_names, flags, local_service, run_as, appid_flags) VALUES
        """
        reg64 = self.reg.open("AppID", Registry.MODE_64)
        reg32 = self.reg.open("AppID", Registry.MODE_32)
        # fill names
        names = {}
        self.getAppNames(reg64, names, 1)
        self.getAppNames(reg32, names, 2)
        apps = set()
        self.firstPrint = True
        for x in reg64.subkeys():
            apps.add(x)
            self.printApp(reg64, x, names, 3 if reg32.hasSubkey(x) else 1)
        for x in reg32.subkeys():
            if x in apps:
                continue
            apps.add(x)
            print "32BIT ", x
            self.printApp(reg32, x, names, 2)
        for x in names:
            if x not in apps:
                self.printApp(None, x, names, names[x]['flags'])
        print ";"

# ------------------------------TYPELIBS--------------------------------

    def verAbove(self, ver1, ver2):
        v1 = ver1.split('.')
        v2 = ver2.split('.')
        for i in range(len(v1)):
            if (len(v2) <= i):
                return False
            if int(v1[i], 16) < int(v2[i], 16):
                return False
        return True

    def loadTypelib(self, reg, tid, flag, tl):
        if tid not in tl:
            tl[tid] = {'max': None}
        r = reg.open(tid)
        for x in r.subkeys():
            ver = r.open(x)
            if not ver.hasSubkey('0'):
                continue
            if x in tl[tid]:
                tl[tid][x]['flags'] |= flag
                continue
            zero = ver.open('0')
            tl[tid][x] = {
                'name': ver.value(),
                'flags': flag,
                'win64': zero.subkeyValue('win64'),
                'win32': zero.subkeyValue('win32')}
            if not tl[tid]['max'] or self.verAbove(x, tl[tid]['max']):
                tl[tid]['max'] = x

    def printTypelib(self, tid, ver, lib):
        if not lib:
            return
        if not self.firstPrint:
            print ","
        else:
            self.firstPrint = False
        print "({},{},{},{},{},{})".format(self.sql.guid(tid), self.sql.str(ver), self.sql.str(lib['name']),
                                           lib['flags'], self.sql.str(lib['win64']), self.sql.str(lib['win32'])),

    def addTypelib(self):
        logger.info('Processing Typelibs')
        print """-- Typelib
        INSERT INTO flags_descr (obj_type, value, descr) VALUES
            (2,1,'64bit app'),
            (2,2,'32bit app');

        CREATE TABLE typelib(
            id GUID NOT NULL PRIMARY KEY,
            version VARCHAR,
            name VARCHAR,
            flags INTEGER NOT NULL DEFAULT 0,
            win64 VARCHAR DEFAULT NULL,
            win32 VARCHAR DEFAULT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            descr VARCHAR DEFAULT NULL
            );
        CREATE INDEX idx_typelib_name ON typelib(name);
        CREATE INDEX idx_typelib_status ON typelib(status);

        CREATE TABLE typelib_version(
            id GUID NOT NULL,
            version VARCHAR,
            name VARCHAR,
            flags INTEGER NOT NULL DEFAULT 0,
            win64 VARCHAR DEFAULT NULL,
            win32 VARCHAR DEFAULT NULL,
            FOREIGN KEY(id) REFERENCES typelib(id) ON DELETE CASCADE
            );
        CREATE INDEX idx_typelib_version_id ON typelib_version(id);
        CREATE INDEX idx_typelib_version_name ON typelib_version(name);
        INSERT INTO typelib(id, version, name, flags, win64, win32) VALUES
        """
        reg64 = self.reg.open("TypeLib", Registry.MODE_64)
        reg32 = self.reg.open("TypeLib", Registry.MODE_32)
        tl = {}
        for x in reg64.subkeys():
            self.loadTypelib(reg64, x, 1, tl)
        for x in reg32.subkeys():
            self.loadTypelib(reg32, x, 2, tl)
        self.firstPrint = True
        for x in tl:
            mx = tl[x].get('max')
            if mx:
                self.printTypelib(x, mx, tl[x].get(mx))
        print ";"
        print "INSERT INTO typelib_version(id, version, name, flags, win64, win32) VALUES"
        self.firstPrint = True
        for x in tl:
            mx = tl[x].get('max')
            for y in tl[x]:
                if y != 'max' and y != mx:
                    self.printTypelib(x, y, tl[x].get(y))
        print ";"

# ------------------------------CLSID--------------------------------

    def printCLSID(self, reg64, reg32, cid):
        r64 = reg64.open(cid) if reg64 else None
        r32 = reg32.open(cid)
        flags = 3 if r64 and r32 else 2 if r32 else 1
        regs = (r64 or RegSQL.EmptyRegKey(), r32 or RegSQL.EmptyRegKey())

        def _anyopen(x):
            return (regs[0].open(x) or RegSQL.EmptyRegKey(), regs[1].open(x) or RegSQL.EmptyRegKey())

        def _anyval(r, x=''):
            return r[0].value(x) or r[1].value(x)

        def _anysub(r, x=''):
            return r[0].subkeyValue(x) or r[1].subkeyValue(x)
        svr = _anyopen('InprocServer32')
        tm = _anyval(svr, 'ThreadingModel')
        if tm:
            flags |= 4 if tm == 'Apartment' or tm == 'Both' else 0
            flags |= 8 if tm != 'Apartment' else 0

        if not self.firstPrint:
            print ","
        else:
            self.firstPrint = False
        print '(', self.sql.guid(cid), ",", self.sql.ascii(_anyval(regs)), ",", flags, ",",
        print self.sql.guid(_anyval(regs, 'AppID')), ",",
        tl = _anyopen('Typelib')
        print self.sql.guid(_anyval(tl)), ",", self.sql.str(_anyval(tl, 'Version')), ",",
        print self.sql.str(_anysub(regs, "ProgID")), ",",
        libs = {"is64": svr[0].value(), 'is32': svr[1].value(),
                'ih64': regs[0].subkeyValue('InprocHandler32'), 'ih32': regs[1].subkeyValue('InprocHandler32'),
                'ls64': regs[0].subkeyValue('LocalServer32') or regs[0].subkeyValue('LocalServer'),
                'ls32': regs[1].subkeyValue('LocalServer32') or regs[1].subkeyValue('LocalServer')
                }
        libs = [x + ": " + y for x, y in libs.iteritems() if y]
        print self.sql.str("\n".join(libs) if len(libs) else None), ",", self.sql.str(_anyval(svr, 'Class')), ")",

    def addCLSID(self):
        logger.info('Processing CLSID')
        print """-- clsid
        INSERT INTO flags_descr (obj_type, value, descr) VALUES
            (3,1,'64bit app'),
            (3,2,'32bit app'),
            (3,4,'Apartment Threading'),
            (3,8,'Multithreading'),
            (3,16,'Exception 64bit Apartment'),
            (3,32,'Exception 64bit Multithreaded'),
            (3,64,'Exception 32bit Apartment'),
            (3,128,'Exception 32bit Multithreaded');

        CREATE TABLE clsid(
            id GUID NOT NULL PRIMARY KEY,
            name VARCHAR,
            flags INTEGER NOT NULL DEFAULT 0,
            appid GUID DEFAULT NULL,
            typelib GUID DEFAULT NULL,
            typelib_ver VARCHAR DEFAULT NULL,
            progid VARCHAR DEFAULT NULL,
            libs VARCHAR DEFAULT NULL,
            class VARCHAR DEFAULT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            descr VARCHAR DEFAULT NULL,
            FOREIGN KEY(appid) REFERENCES appid(id) ON DELETE SET NULL,
            FOREIGN KEY(typelib) REFERENCES typelib(id) ON DELETE SET NULL
            );
        CREATE INDEX idx_clsid_name ON clsid(name);
        CREATE INDEX idx_clsid_flags ON clsid(flags);
        CREATE INDEX idx_clsid_status ON clsid(status);
        CREATE INDEX idx_clsid_appid ON clsid(appid);
        CREATE INDEX idx_clsid_typelib ON clsid(typelib);
        CREATE INDEX idx_clsid_class ON clsid(class);
        INSERT INTO clsid(id, name, flags, appid, typelib, typelib_ver, progid, libs, class) VALUES
        """
        reg64 = self.reg.open("CLSID", Registry.MODE_64)
        reg32 = self.reg.open("CLSID", Registry.MODE_32)
        done = set()
        self.firstPrint = True
        for x in reg64.subkeys():
            self.printCLSID(reg64, reg32, x)
            done.add(x)
        for x in reg32.subkeys():
            if x not in done:
                self.printCLSID(None, reg32, x)
        print ";"


# ------------------------------INTERFACE--------------------------------

    def printInterface(self, reg64, reg32, iid):
        r64 = reg64.open(iid) if reg64 else None
        r32 = reg32.open(iid)
        flags = 3 if r64 and r32 else 2 if r32 else 1
        r64 = r64 or RegSQL.EmptyRegKey()
        r32 = r32 or RegSQL.EmptyRegKey()

        nm = r64.value() or r32.value()
        async = r64.subkeyValue('AsynchronousInterface') or r32.subkeyValue('AsynchronousInterface')
        num = r64.subkeyValue('NumMethods') or r32.subkeyValue('NumMethods') or 0
        pstubs = {r64.subkeyValue('ProxyStubClsid32'), r64.subkeyValue('ProxyStubClsid'),
                  r32.subkeyValue('ProxyStubClsid'), r32.subkeyValue('ProxyStubClsid')}
        pstubs -= {None, ''}
        pstubs = list(pstubs)
        while len(pstubs) < 2:
            pstubs += [None]
        tlib = None
        tver = None
        for i in range(2):
            tl = r64.open('TypeLib') if i == 0 else r32.open('TypeLib')
            if tl:
                tlib = tlib or tl.value()
                tver = tver or tl.value('Version')
        if tver and tver.startswith('14.0'):
            tver = '14.0'

        if not self.firstPrint:
            print ","
        else:
            self.firstPrint = False
        if not nm:
            nm = iid
        print "({},{},{},{},{},{},{},{},{})".format(self.sql.guid(iid), self.sql.str(nm), flags, self.sql.str(async),
                                                    self.sql.str(pstubs[0]), self.sql.str(pstubs[1]),
                                                    self.sql.str(tlib), self.sql.str(tver), num),

    def addInterface(self):
        logger.info('Processing Interfaces')
        print """-- Interface
        INSERT INTO flags_descr (obj_type, value, descr) VALUES
            (4,1,'64bit app'),
            (4,2,'32bit app');

        CREATE TABLE interface(
            id GUID NOT NULL PRIMARY KEY,
            name VARCHAR,
            flags INTEGER NOT NULL DEFAULT 0,
            async_intf GUID DEFAULT NULL,
            pstub_clsid GUID DEFAULT NULL,
            pstub_clsid2 GUID DEFAULT NULL,
            typelib GUID DEFAULT NULL,
            typelib_ver VARCHAR DEFAULT NULL,
            methods INTEGER DEFAULT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            descr VARCHAR DEFAULT NULL,
            FOREIGN KEY(async_intf) REFERENCES interface(id) ON DELETE SET NULL,
            FOREIGN KEY(pstub_clsid) REFERENCES clsid(id) ON DELETE SET NULL,
            FOREIGN KEY(pstub_clsid2) REFERENCES clsid(id) ON DELETE SET NULL,
            FOREIGN KEY(typelib) REFERENCES typelib(id) ON DELETE SET NULL
            );
        CREATE INDEX idx_interface_name ON interface(name);
        CREATE INDEX idx_interface_status ON interface(status);
        CREATE INDEX idx_interface_async_intf ON interface(async_intf);
        CREATE INDEX idx_interface_pstub_clsid ON interface(pstub_clsid);
        CREATE INDEX idx_interface_pstub_clsid2 ON interface(pstub_clsid2);
        CREATE INDEX idx_interface_typelib ON interface(typelib);
    INSERT INTO interface(id, name, flags, async_intf, pstub_clsid, pstub_clsid2, typelib, typelib_ver, methods) VALUES
        """
        reg64 = self.reg.open("Interface", Registry.MODE_64)
        reg32 = self.reg.open("Interface", Registry.MODE_32)
        done = set()

        self.firstPrint = True
        for x in reg64.subkeys():
            self.printInterface(reg64, reg32, x)
            done.add(x)
        for x in reg32.subkeys():
            if x not in done:
                self.printInterface(None, reg32, x)
        print ";"


# ------------------------------CLSID INTERFACES--------------------------------

    def addCLSIDInterfaces(self):
        logger.info('Processing CLSID Interfaces')
        print """-- CLSID - Interfaces
        CREATE TABLE clsid_interfaces(
            clsid GUID NOT NULL,
            interface GUILD NOT NULL,
            PRIMARY KEY (clsid, interface),
            FOREIGN KEY(clsid) REFERENCES clsid(id) ON DELETE CASCADE,
            FOREIGN KEY(interface) REFERENCES interface(id) ON DELETE CASCADE
        );
        INSERT INTO clsid_interfaces(clsid, interface) VALUES
        """
        exc_descr = {'64A': 16, '64M': 32, '64': 16 | 32, '32A': 64, '32M': 128, '32': 64 | 128}
        exc = {}
        with open(self.args.files[0]) as f:
            dst = json.load(f)
        self.firstPrint = True
        for x in dst:
            for y in dst[x]:
                if y.startswith('EXCEPTION_'):
                    v = exc_descr[y[10:]]
                    exc[x] = (exc[x] | v) if x in exc else v
                else:
                    if self.firstPrint:
                        self.firstPrint = False
                    else:
                        print ","
                    print "({},{})".format(self.sql.guid(x), self.sql.guid(y)),
        print ";"
        print "-- clsid exceptions"
        rexc = {}
        for x, y in exc.iteritems():
            if y not in rexc:
                rexc[y] = []
            rexc[y] += [x]
        for x, y in rexc.iteritems():
            print "UPDATE clsid SET flags = flags | {} WHERE id IN ({});".format(x, "'" + "','".join(y) + "'")


# ------------------------------OTHER--------------------------------

    def createSQL(self, args):
        self.args = args
        orig_out = sys.stdout
        if args.output:
            f = open(args.output, "w")
            sys.stdout = f
        try:
            self.reg = Registry()
            self.initDB()
            self.addApps()
            self.addTypelib()
            self.addCLSID()
            self.addInterface()
            self.addCLSIDInterfaces()
            self.finDB()
        finally:
            if args.output:
                sys.stdout.close()
            sys.stdout = orig_out

    def combIntf(self, args):
        if len(args.files) < 2:
            logger.error("Need 2 or more files")
            return 1
        logger.info("Combining interfaces from files %s", str(args.files))
        with open(args.files[0]) as f:
            dst = json.load(f)
        for x in args.files[1:]:
            logger.debug("adding file %s", x)
            with open(x) as f:
                src = json.load(f)
            for i in src:
                if i not in dst:
                    dst[i] = src[i]
                    continue
                if dst[i] == src[i]:
                    continue
                st = set(dst[i]).union(src[i])
                dst[i] = list(st)
        print json.dumps(dst, indent=2)
        return 0

    def run(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--verbose', '-v', action='count')
        parser.add_argument('--output', '-o')
        parser.add_argument('command', choices=self.cmds.keys())
        parser.add_argument('files', nargs="*")
        args = parser.parse_args(sys.argv[1:])

        fmt = logging.Formatter("%(levelname)s: %(message)s")
        hndl = logging.StreamHandler()
        hndl.formatter = fmt
        logger.addHandler(hndl)
        logger.setLevel(logging.DEBUG if args.verbose > 0 else logging.INFO)

        if args.command in self.cmds:
            return self.cmds[args.command](args)
        else:
            logger.error("Unknown command: " + args.command)
            return 1


if __name__ == "__main__":
    sys.exit(RegSQL().run())
