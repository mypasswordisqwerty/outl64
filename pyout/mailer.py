from classes.singleton import Singleton
from classes.logger import Logger
import smtplib
from datetime import datetime
import email
import os
import uuid
import base64
from pyout.util import mypath
try:
    import pyoutconf as Config
except Exception:
    Config = {}


class TimeGenerator:
    FORMATS = {
        'ISO': "%Y-%m-%d %H:%M:%S",
        'ISOT': "%Y%m%dT%H%M%S",
        'ISOTZ': "%Y%m%dT%H%M%SZ",
        'ISOD': '%Y-%m-%d',
        'ISODT': '%Y%m%d',
    }

    def __init__(self):
        self.now = datetime.now()

    def __repr__(self):
        return "<TimeGenerator>"

    def changeDate(self, params):
        dt = self.now
        if len(params) == 0 or params[0] in ('', 'now'):
            return dt
        if params[0].startswith('dadd'):
            return dt + datetime.timedelta(days=int(params[0][5:]))

    def __getattr__(self, attr):
        params = attr.split('_')
        fmt = params[-1]
        dt = self.changeDate(params[:-1])
        # change format
        if (fmt == ''):
            fmt = 'ISO'
        if fmt not in self.FORMATS:
            raise AttributeError("Unsupported format: " + fmt)
        return dt.strftime(self.FORMATS[fmt])


class Mailer:
    """ smtp mailer """

    __metaclass__ = Singleton
    mid = 0

    class MailNotFoundError(Exception):

        def __init__(self, name):
            Exception.__init__(self, "Mail not found: " + name)

    def splitAddr(self, addr):
        s = addr.split('<')
        s[0] = s[0].strip()
        if len(s) > 1:
            s[1] = s[1].split('>')[0].strip()
        return s

    def buildParams(self, name, params):
        p = {}
        p['subject'] = "Mail {} {}".format(name, params.get('subj') or Mailer.mid)
        Mailer.mid += 1
        cfg = Config.smtp
        p['from'] = cfg['from']
        p['to'] = cfg['to']
        p['date'] = email.utils.formatdate()
        p['id'] = str(uuid.uuid4())
        adr = self.splitAddr(cfg['from'])
        p['from_name'] = adr[0]
        p['from_adr'] = adr[1] if len(adr) > 1 else adr[0]
        adr = self.splitAddr(cfg['to'])
        p['to_name'] = adr[0]
        p['to_adr'] = adr[1] if len(adr) > 1 else adr[0]
        p['times'] = TimeGenerator()
        if params:
            p.update(params)
        return p

    def readFile(self, fname, enc):
        Logger.debug("Adding file %s %s", fname, enc)
        data = None
        with open(fname, 'rb') as f:
            data = f.read()
        if enc is None:
            return data
        if enc == 'base64':
            data = base64.encodestring(data)
        elif enc == 'base64l':
            data = base64.encodestring(data).replace("\r", "").replace("\n", "")
        else:
            raise Exception("Unknown file encoding: " + enc)
        return data

    def buildFiles(self, body, params, path):
        for x in body.split("{m[file"):
            if not x.startswith("__"):
                continue
            f = x.split("]}")
            if len(f) != 2:
                continue
            f = f[0]
            fl = f.split('__')
            if len(fl) < 2:
                raise Exception("Wrong file descriptor: " + f)
            rname = params.get(fl[1]) or fl[1]
            enc = None if len(fl) < 3 else fl[2]
            fname = rname
            if not os.path.exists(fname):
                fname = os.path.realpath(os.path.join(path, rname))
            if not os.path.exists(fname):
                fname = os.path.realpath(os.path.join(path, "files", rname))
            if not os.path.exists(fname) or not os.path.isfile(fname):
                raise Exception("File not found: " + fname)
            params['file' + f] = self.readFile(fname, enc)
        return params

    def buildMsg(self, name, params):
        pth = mypath("mails")
        fname = os.path.join(pth, "mail_" + name + ".txt")
        params = self.buildParams(name, params)
        Logger.debug("preparing mail %s w params %s", fname, str(params))
        if not os.path.exists(fname):
            raise Mailer.MailNotFoundError(name)
        body = None
        with open(fname, "r") as f:
            body = f.read()
        params = self.buildFiles(body, params, pth)
        return body.format(m=params)

    def mail(self, name=0, **kwargs):
        name = str(name)
        cfg = Config.smtp
        Logger.debug("sending mail %s%s from %s to %s",
                     name, str(kwargs), cfg['from'], cfg['to'])
        usr = cfg.get('user')
        pswd = cfg.get('password')
        msg = self.buildMsg(name, kwargs)
        dump = kwargs.get("dump")
        if dump:
            with open(dump, "w") as f:
                f.write(msg)
            Logger.info("Message %s saved to %s", name, dump)
            return
        cli = smtplib.SMTP(cfg['host'])
        if cfg.get('ssl') == True:
            cli.starttls()
        if usr and pswd:
            cli.ehlo()
            cli.login(usr, pswd)
        else:
            cli.helo()
        cli.sendmail(cfg['from'], kwargs.get('to') or cfg['to'], msg)
        cli.quit()
        Logger.info("Message %s sent", name)
