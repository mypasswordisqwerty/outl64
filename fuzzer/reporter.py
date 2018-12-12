#!/usr/bin/env python
import urllib2
import urllib
import platform
import pyoutconf as Config
import json
import logging
import ssl


class Reporter:
    _logger = None
    HDR_JSON = {"Content-Type": "application/json"}

    def __init__(self, logger=None):
        if not logger:
            if not Reporter._logger:
                Reporter._logger = logging.getLogger("Reporter")
                Reporter._logger.setLevel(logging.INFO)
                Reporter._logger.addHandler(logging.StreamHandler())
            logger = Reporter._logger
        self.logger = logger

    def httpPost(self, url, postData, headers={}):
        try:
            req = urllib2.Request(url, postData, headers=headers)
            try:
                urllib2.urlopen(req, context=ssl._create_unverified_context())
            except AttributeError:
                urllib2.urlopen(req)
        except urllib2.URLError as e:
            self.logger.error("Error sending report to %s: %s", url, str(e))

    def reportHipChatAPI(self, msg, loud):
        if not hasattr(Config, 'hipchatApiUrl') or not hasattr(Config, 'hipchatRoom'):
            return
        self.logger.debug("reporting hipchat at %s", Config.hipchatApiUrl)
        data = urllib.urlencode({"room_id": Config.hipchatRoom, "from": "Fuzzer",
                                 "message_format": "text", "message": msg, "notify": 1 if loud else 0})
        self.httpPost(Config.hipchatApiUrl, data)

    def reportHipChatBYO(self, msg, loud):
        if not hasattr(Config, 'hipchatByoUrl'):
            return
        self.logger.debug("reporting hipchat at %s", Config.hipchatURL)
        data = json.dumps({"message": msg, "notify": loud, "message_format": "text"})
        self.httpPost(Config.hipchatURL, data, Reporter.HDR_JSON)

    def report(self, who, what, loud=False):
        if hasattr(Config, "hostName"):
            who = Config.hostName + "." + who
        elif hasattr(Config, "hostId"):
            who = "VM_" + str(Config.hostId) + "." + who
        else:
            who = platform.node() + "." + who
        msg = who + ": " + what
        self.logger.info(msg)
        self.reportHipChatBYO(msg, loud)
        self.reportHipChatAPI(msg, loud)

    def reportExc(self, who, exc, loud=True):
        self.report(who, str(exc.__class__.__name__) + " " + str(exc), loud)


if __name__ == "__main__":
    Reporter().report("TEST", "test report")
