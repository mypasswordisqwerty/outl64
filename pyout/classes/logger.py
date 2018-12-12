from singleton import Singleton
import logging


class Logger:
    __metaclass__ = Singleton

    def __init__(self):
        self.logger = logging.getLogger("pyout")
        self.logger.setLevel(logging.INFO)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter(
            "%(name)s %(levelname)s: %(message)s"))
        self.logger.addHandler(sh)

    @staticmethod
    def debug(msg, *args, **kwargs):
        Logger().logger.debug(msg, *args, **kwargs)

    @staticmethod
    def info(msg, *args, **kwargs):
        Logger().logger.info(msg, *args, **kwargs)

    @staticmethod
    def warning(msg, *args, **kwargs):
        Logger().logger.warning(msg, *args, **kwargs)

    @staticmethod
    def error(msg, *args, **kwargs):
        Logger().logger.error(msg, *args, **kwargs)

    @staticmethod
    def setVerbose(verb):
        Logger().logger.setLevel(logging.DEBUG if verb else logging.INFO)

    @staticmethod
    def isVerbose():
        return Logger().logger.level == logging.DEBUG
