from classes.singleton import Singleton
from classes.logger import Logger
try:
    import win32com.client
except Exception:
    print "You need pywin32 lib.\nRun: pip install pypiwin32\n"


class Outlook:
    """ oulook mapi """
    __metaclass__ = Singleton

    def __init__(self):
        self.mapi = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")

    def receive(self):
        Logger.debug("Sending and receiveing outlook mail")
        self.mapi.SendAndReceive(False)
