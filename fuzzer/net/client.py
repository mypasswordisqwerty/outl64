import socket
import netifaces
import json
import httplib
import time
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from . import *


class FakeSocket():

    def __init__(self, response_str):
        self._file = StringIO(response_str)

    def makefile(self, *args, **kwargs):
        return self._file


class Client:

    def __init__(self, port):
        self.port = port
        self.server = None
        self.hostId = -1

    def makeHTTP(self, path="", data=None, meth=None, headers={}):
        if data and not isinstance(data, basestring):
            data = json.dumps(data)
        if len(path) == 0 or path[0] != '/':
            path = '/' + path
        if meth is None:
            meth = 'GET' if data is None else 'POST'
        ret = meth + ' ' + path + ' HTTP/1.1\r\n'
        if data:
            headers['Content-Length'] = len(data)
        for x in headers:
            ret += x + ": " + str(headers[x]) + "\r\n"
        ret += "\r\n"
        if data:
            ret += data
        return ret

    def httpCall(self, path, data):
        if data and not isinstance(data, basestring):
            data = json.dumps(data)
        raise NotImplementedError()

    def udpCall(self, path, data=None, server=None):
        if server is None:
            server = self.server
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = self.makeHTTP(path, data)
            sock.settimeout(1)
            sock.sendto(data, (server, self.port))
            time.sleep(0.3)
            data, addr = sock.recvfrom(4096)
            ret = httplib.HTTPResponse(FakeSocket(data))
            ret.begin()
            if not self.server:
                self.server = addr[0]
            if ret.status != 200:
                return None
            return json.loads(ret.read())
        except Exception as e:
            print "UDP Error: ", str(e)
            return None

    def discover(self, hostId, hostName):
        self.hostId = hostId
        for x in netifaces.interfaces():
            lst = netifaces.ifaddresses(x)
            for y in lst:
                for i in lst[y]:
                    if 'addr' not in i or 'broadcast' not in i:
                        continue
                    if i['addr'] == '127.0.0.1' or ':' in i['addr']:
                        continue
                    res = self.udpCall("/register",
                                       {"hostId": hostId,
                                        "hostName": hostName,
                                        "version": __version__},
                                       i['broadcast'])
                    if res is None:
                        continue
                    return res
        raise Exception("Server not discovered")

    def heartbeat(self, progress):
        return self.udpCall("/heartbeat", {"hostId": self.hostId, "progress": str(progress)})
