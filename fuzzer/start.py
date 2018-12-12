#!/usr/bin/env python

import sys
import pyoutconf as Config
import platform
import reporter
import argparse
from net.db import DB
from net import *
import os
from datetime import datetime


class App:
    UPDATE_SCRIPT = "update.cmd"
    REPORT_TIME_MIN = 60 * 24

    def __init__(self):
        self.client = None
        self.dir = None
        self.reportDate = None
        self.reportTime = App.REPORT_TIME_MIN

    def serverCallback(self):
        delta = (datetime.now() - self.reportDate).total_seconds() * 1.0 / 60
        if delta < self.reportTime or self.reportTime == 0:
            return
        self.reportDate = datetime.now()
        reporter.Reporter().report("FuzzerServer", DB().onlineReport())

    def serverLoop(self, opts):
        # server loop
        from net.server import Server
        server = Server(opts.port)

        try:
            reporter.Reporter().report("FuzzerServer", "started v" + __version__ + "\n" + DB().onlineReport())
            self.reportDate = datetime.now()
            return server.run(self.serverCallback)
        except (Exception, KeyboardInterrupt) as e:
            server.stop()
            reporter.Reporter().reportExc("FuzzerServer", e)
            raise

    def importClass(self, className):
        mods = className.split('.')
        mod = __import__(mods[0])
        for m in mods[1:]:
            mod = getattr(mod, m)
        return mod

    def clientCallback(self, progress):
        res = self.client.heartbeat(progress)
        if res is None:
            print "Server off"
            return
        flags = res.get('flags')
        if flags & DB.CLIENT_RELOAD:
            print "Reloading client"
            args = sys.argv[:]
            args.insert(0, sys.executable)
            if sys.platform == 'win32':
                args = ['"%s"' % arg for arg in args]
            os.chdir(self.dir)
            os.execv(sys.executable, args)
        if flags & DB.CLIENT_UPDATE:
            os.chdir(self.dir)
            os.execv(App.UPDATE_SCRIPT, [App.UPDATE_SCRIPT])

    def clientLoop(self, opts):
        # client job
        from net.client import Client
        try:
            self.dir = os.getcwd()
            self.client = Client(opts.port)
            print "discovering server..."
            res = self.client.discover(opts.hostId, opts.hostName)
            print "Server discovered at:", self.client.server
            hostId = res['hostId']
            self.client.hostId = hostId
            task = res['task']
            print "Host id:", hostId
            print "Task:", task
            if not task:
                raise Exception("Task is None")
            args = task.split()
            klass = self.importClass(args[0])
            return klass().run(args[1:], self.clientCallback)
        except (Exception, KeyboardInterrupt) as e:
            reporter.Reporter().reportExc("FuzzerClient", e)
            raise

    def run(self):
        port = 43210
        hostId = -1
        hostName = platform.node()
        if hasattr(Config, "port"):
            port = Config.port
        if hasattr(Config, "hostId"):
            hostId = Config.hostId
            hostName = "VM_" + str(hostId)
        if hasattr(Config, "hostName"):
            hostName = Config.hostName
        if hasattr(Config, "reportTime"):
            self.reportTime = Config.reportTime

        parser = argparse.ArgumentParser()
        parser.add_argument('--hostId', '-i', type=int, default=hostId)
        parser.add_argument('--hostName', '-n', default=hostName)
        parser.add_argument('--port', '-p', type=int, default=port)
        opts = parser.parse_args(sys.argv[1:])

        if opts.hostId == 0:
            return self.serverLoop(opts)
        else:
            return self.clientLoop(opts)


if __name__ == "__main__":
    sys.exit(App().run())
