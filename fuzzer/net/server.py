import SocketServer
import BaseHTTPServer
import time
import json
import urllib
import os
from string import Template
from db import DB
from . import *


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    FILES = {}
    _CT = "Content-type"
    _CL = "Content-length"
    _CC = "Cache-control"

    def setup(self):
        if isinstance(self.server, SocketServer.UDPServer):
            try:
                from cStringIO import StringIO
            except ImportError:
                from StringIO import StringIO
            self.packet, self.socket = self.request
            self.rfile = StringIO(self.packet)
            self.wfile = StringIO()
        else:
            BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def finish(self):
        if isinstance(self.server, SocketServer.UDPServer):
            self.socket.sendto(self.wfile.getvalue(), self.client_address)
        else:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)

    def _headers(self, headers={}, status=200):
        self.send_response(status)
        if self._CT not in headers:
            headers[self._CT] = "text/html"
        if "charset=" not in headers[self._CT]:
            headers[self._CT] += "; charset=utf-8"
        for x in headers:
            self.send_header(x, str(headers[x]))
        self.end_headers()

    def _error(self, status, descr="Internal error", headers={}, body=None):
        if not body:
            body = "<html><body><h1>{} {}</h1></body></html>".format(status, descr)
        headers[self._CL] = len(body)
        self._headers(headers, status)
        self.wfile.write(body)

    def do_HEAD(self):
        self._headers()

    def extractData(self):
        length = self.headers.get(self._CL)
        data = {}
        prms = ""
        if length:
            prms = self.rfile.read(int(length))
            if prms[0] in ('[', '{'):
                data = json.loads(prms)
                prms = ""
        arg = self.path.split('?')
        if len(arg) > 1:
            prms = arg[1] + '&' + prms
        for x in prms.split('&'):
            par = x.split('=')
            if len(par) != 2:
                continue
            data[urllib.unquote(par[0])] = urllib.unquote(par[1]).replace('+', ' ')
        return arg[0], data

    def process(self, meth):
        path, data = self.extractData()
        path = path.split('/')
        if len(path) > 1:
            path = path[1:]
        if not path[0]:
            path[0] = "index"
        proc = None
        hdrs = {}
        if hasattr(self.__class__, path[0]):
            proc = getattr(self.__class__, path[0])
        if proc and callable(proc):
            self.page = path[0]
            body = proc(self, path=path[1:], data=data, headers=hdrs, method=meth)
        else:
            self._error(404, "Not Found")
            return
        if body:
            if not isinstance(body, basestring):
                body = json.dumps(body)
                if self._CT not in hdrs:
                    hdrs[self._CT] = "application/json"
            hdrs[self._CL] = len(body)
        self._headers(hdrs)
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self.process(DB.GET)

    def do_POST(self):
        self.process(DB.POST)

    def do_PUT(self):
        self.process(DB.PUT)

    def do_DELETE(self):
        self.process(DB.DELETE)

    def fileContent(self, name):
        if name not in self.FILES:
            path = os.path.realpath(__file__)
            path = os.path.join(os.path.dirname(path), "static", name)
            with open(path) as f:
                return f.read()
                self.FILES[name] = f.read()
        return self.FILES[name]

    def template(self, pid, title, params={}):
        if not params:
            params = {}
        params['menu_class_' + pid] = 'class="selected"'
        params['id'] = pid
        params['title'] = title
        params['version'] = __version__
        body = Template(self.fileContent("page.html")).safe_substitute(params)
        return body

    def css(self, **kwargs):
        kwargs['headers'][self._CT] = "text/css"
        kwargs['headers'][self._CC] = "max-age=3600"
        return self.fileContent("all.css")

    def js(self, **kwargs):
        kwargs['headers'][self._CT] = "application/javascript"
        kwargs['headers'][self._CC] = "max-age=3600"
        return self.fileContent("fuzz.js")

    def register(self, **kwargs):
        return DB().registerClient(kwargs['data'], self.client_address[0])

    def heartbeat(self, **kwargs):
        return DB().heartbeat(kwargs['data'])

    def index(self, **kwargs):
        return self.template("clients", "Clients")

    def jobs(self, **kwargs):
        return self.template("jobs", "Jobs")

    def job(self, **kwargs):
        return DB().restJob(kwargs['method'], kwargs['data'])

    def client(self, **kwargs):
        return DB().restClient(kwargs['method'], kwargs['data'])


class Server:

    def __init__(self, port):
        self.port = port
        self.udp = None
        self.web = None
        self._stop = True
        self.running = False

    def run(self, callback=None):
        self._stop = False
        self.running = True
        self.udp = SocketServer.UDPServer(('', self.port), Handler)
        self.udp.timeout = 0.3
        try:
            self.web = SocketServer.TCPServer(('', self.port), Handler)
            self.web.timeout = 0.3
        except Exception:
            self.udp.server_close()
            self.udp = None
            raise
        while not self._stop:
            self.udp.handle_request()
            self.web.handle_request()
            if callback is not None:
                callback()
            time.sleep(0.3)
        self.udp.server_close()
        self.web.server_close()
        self.udp = None
        self.web = None
        self.running = False
        return 0

    def stop(self):
        self._stop = True
