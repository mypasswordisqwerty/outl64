#!/usr/bin/env python
import win32com.client as com
from win32com.client import gencache
from pywintypes import IID
import pythoncom
import pywintypes
import winerror
import sys
import logging
import hexdump
import argparse
import random
import os
import reporter
import time

logger = logging.getLogger("Fuzzer")


class Fuzzer:
    MAX_RANDOM_DATA = 1024
    MAX_RANDOM_STRING = 300
    PROB_SMALLDATA = 0.5

    class FuzzEvents():
        LOGL = {0: "DEBUG", 1: "INFO", 2: "WARNING", 3: "ERROR"}

        def Onlog(self, level, msg):
            logger.debug("FUZZLIB %s: %s", Fuzzer.FuzzEvents.LOGL[level], msg)

    class ComError(Exception):

        def __init__(self, err):
            self.eid = err[0]
            self.code = 0xFFFFFFFF + self.eid + 1
            descr = u"Error 0x{:08X}: {}".format(self.code, err[1].decode('cp1251'))
            descr = descr.encode(sys.stdout.encoding)
            Exception.__init__(self, descr)

    class RpcServerError(ComError):
        """ 0x80010105 RPC_E_SERVERFAULT """

    LIBID = IID('{E8FBB04D-8A6F-4517-B6EB-6FC7033DF2B5}')
    CLSID = IID('{2FD04774-5788-4BBA-B925-71AFBC0A38C7}')
    CLSNAME = 'Outl64FuzzLib.MapiFuzz'
    IID_IMapiFuzz = IID('{7CEECFDA-32C6-4592-BE27-A881E1967FC4}')

    def __init__(self, func=None):
        gencache.EnsureModule(Fuzzer.LIBID, 1, 0, 0)
        self.intf = com.DispatchWithEvents(Fuzzer.CLSNAME, Fuzzer.FuzzEvents)
        self.testFunc = func
        self.step = 0
        self.maxStep = 0
        self.data = None
        self.logfile = self.__class__.__name__ + ".log"
        self.printStep = 1000
        self.mode = 0
        self.dumpCrashData = True
        self.sleep = 0.01
        self.callback = None
        random.seed()

    def randByte(self):
        return random.randint(0, 255)

    def randData(self, minlen=0, maxlen=MAX_RANDOM_DATA):
        if self.prob(self.__class__.PROB_SMALLDATA):
            maxlen = 4
        ln = random.randint(minlen, maxlen)
        if not ln:
            return ''
        ret = ''
        for x in range(ln):
            ret += chr(self.randByte())
        return ret

    def randString(self, minlen=0, maxlen=MAX_RANDOM_STRING):
        ret = ''
        for x in range(random.randint(minlen, maxlen)):
            ret += chr(random.randint(0x1, 0x7F))
        return ret

    def prob(self, prob):
        return True if random.random() < prob else False

    def debug(self, *args):
        logger.debug(*args)

    def info(self, *args):
        logger.info(*args)

    def error(self, *args):
        logger.error(*args)

    def config(self, logLevel):
        self.intf.config(logLevel)

    def variant(self, data):
        if isinstance(data, str):
            data = [ord(x) & 0xFF for x in data]
        return com.VARIANT(pythoncom.VT_ARRAY | pythoncom.VT_UI1, data)

    def var2str(self, var):
        ret = ''
        for x in var.value:
            ret += chr(x)
        return ret

    def version(self):
        print self.intf.version()

    def parseTnef(self, bufOrFname, mock=False):
        return self.intf.parseTnef(bufOrFname, 1 if mock else 0)

    def createMessage(self, bufOrFname):
        return self.intf.createMessage(bufOrFname)

    def parseCert(self, bufOrFname):
        return self.intf.parseCert(bufOrFname)

    def crash(self, param=0):
        return self.intf.crash(param)

    def test(self):
        print "testing\n"
        self.config(0)
        self.version()
        self.parseTnef("C:\\projects\\revers\\outl64\\mails\\exp.tnef")
        self.crash()

    def generate(self, step):
        raise NotImplementedError()

    def saveCrash(self, data):
        if not self.dumpCrashData:
            return
        i = 0
        while os.path.exists("crashdata{}.log".format(i)):
            i += 1
        with open("crashdata{}.log".format(i), "wb") as f:
            f.write(data)

    def next(self):
        self.step += 1
        if self.step % self.printStep == 0:
            logger.info("Step %d", self.step)
            if self.callback:
                self.callback(self.step)
        else:
            logger.debug("Step %d", self.step)
        try:
            self.data = self.generate(self.step)
            if not isinstance(self.data, (tuple, list)):
                self.data = [self.data]
            try:
                return self.testFunc(*self.data)
            except pywintypes.com_error as e:
                if e[0] == winerror.RPC_E_SERVERFAULT:
                    raise Fuzzer.RpcServerError(e)
                else:
                    raise Fuzzer.ComError(e)
        except Exception as e:
            args = "\n"
            if isinstance(self.data, (list, tuple)):
                for x in self.data:
                    x = self.var2str(x) if isinstance(x, com.VARIANT) else x
                    if isinstance(x, (str, unicode)):
                        self.saveCrash(x)
                        x = hexdump.hexdump(x, 'return')
                    else:
                        x = str(x)
                    args += x + "\n\n"
            else:
                args = str(self.data)
            logger.exception("Exception on args:\n%s", args)
            reporter.Reporter(logger).reportExc(self.__class__.__name__, e)
            raise

    def parseArgs(self, parser, args):
        fmt = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        hndl = logging.StreamHandler()
        hndl.formatter = fmt
        logger.addHandler(hndl)
        if parser is None:
            logger.setLevel(logging.DEBUG if '-v' in args else logging.INFO)
            return
        opts = parser.parse_args(args)
        logger.setLevel(logging.DEBUG if opts.verbose > 0 else logging.INFO)
        if opts.logfile:
            hndl = logging.FileHandler(opts.logfile)
            hndl.formatter = fmt
            logger.addHandler(hndl)
        self.maxStep = opts.count
        self.printStep = opts.printstep
        self.mode = opts.mode
        self.dumpCrashData = opts.nodumpcrash
        self.sleep = opts.sleep
        return 0

    def run(self, args=None, callback=None):
        self.callback = callback
        parser = argparse.ArgumentParser()
        parser.add_argument('--verbose', '-v', action='count')
        parser.add_argument('--logfile', '-l', default=self.__class__.__name__ + ".log")
        parser.add_argument('--count', '-c', type=int)
        parser.add_argument('--printstep', '-p', type=int, default=10000)
        parser.add_argument('--mode', '-m', type=int, default=0)
        parser.add_argument('--nodumpcrash', '-n', action='store_false')
        parser.add_argument('--sleep', '-s', type=float, default=0.01)
        if args is None:
            args = sys.argv[1:]
        res = self.parseArgs(parser, args)
        if res != 0:
            return res
        self.step = 0
        logger.info("Fuzzing started")
        while True:
            self.next()
            if self.maxStep > 0 and self.step >= self.maxStep:
                logger.info("Max steps reached: %d", self.step)
                return 0
            time.sleep(self.sleep)


if __name__ == '__main__':
    Fuzzer().test()
