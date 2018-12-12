import os
import json
import pyout
import urllib2
import re
from pyout.classes.logger import Logger


class Oids:
    """ OIDs updater """
    URL = "http://www.oid-info.com/get/"

    def __init__(self):
        self.path = os.path.join(pyout.mypath('doc'), "oids.json")
        self.oids = None
        self.names = None
        self.changed = False

    def getOids(self):
        if self.oids is None:
            self.oids = {}
            if not os.path.isfile(self.path):
                return {}
            with open(self.path, "r") as f:
                self.oids = json.load(f)
        return self.oids

    def save(self):
        if not self.changed:
            return
        with open(self.path, "w") as f:
            json.dump(self.oids, f, indent=4, sort_keys=True)
        self.changed = False

    def getOid(self, oid, saveNow=True):
        if oid not in self.getOids():
            self.oids[oid] = oid
            self.changed = True
            self.names = None
            if saveNow:
                self.save()
        return self.oids[oid]

    def oidByName(self, name):
        if not self.names:
            self.names = {name: oid for oid, name in self.getOids().iteritems()}
        return self.names[name]

    def getName(self, value):
        url = self.URL + value
        try:
            html = urllib2.urlopen(url).read()
        except Exception:
            return None
        title = re.search(r"<title>(.*) - " + value + r" = {(.*)}</title>", html)
        if not title:
            return None
        descr = title.groups()
        if len(descr) != 2 or descr[0] != "OID repository":
            return None
        name = descr[1].split(' ')[-1]
        return name.split('(')[0]

    def updateNames(self):
        upd = []
        print "updating names"
        for n, v in self.getOids().iteritems():
            if v != n:
                continue
            upd += [n]
        Logger.debug("Updating oids %s", str(upd))
        for x in upd:
            nm = self.getName(x)
            if nm:
                Logger.debug("%s = %s", x, nm)
                self.oids[x] = nm
                self.changed = True
        self.save()
