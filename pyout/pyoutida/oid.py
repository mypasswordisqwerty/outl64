from pyout.util.oids import Oids
import idautils
import idc
import re


class Oid:

    def update(self, **kwargs):
        oids = Oids()
        sc = idautils.Strings()
        r = re.compile(r"^[012]\.\d+(\.\d+)+$")
        for s in sc:
            if r.match(str(s)):
                val = oids.getOid(str(s), False)
                if val != str(s):
                    val = val.replace('/', '').replace(' ', '_').replace('-', '_').replace('.', '_')
                    nm = 'oid_' + val.encode('ascii')
                    if not idc.Name(s.ea).startswith(nm):
                        idc.MakeName(s.ea, nm)
        oids.save()
