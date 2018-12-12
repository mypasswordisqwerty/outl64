import struct
import uuid
from moniker import ObjRefMoniker
from . import gendata
import os
from persiststm import PersistStream
from pyout.util.variant import *


class PersistStreamInit(PersistStream):
    BDACOLLECTION_CLSID = uuid.UUID("{809b6661-94c4-49e6-b6ec-3f0f862215aa}")
    CLSID = None

    def dump(self, filename, **kwargs):
        ret = self.OBJREF_CLSID.bytes_le
        data = struct.pack("<QL", 0, 0x10)
        data += self.BDACOLLECTION_CLSID.bytes_le
        data2 = struct.pack("<L", 1)
        data2 += self.clsid.bytes_le
        data2 += self.build()
        data += struct.pack("<L", len(data2)) + data2
        ret += self._dumpInternal(data, self.INTERCEPTOR_CLSID)
        return ret

    def build(self):
        data = gendata()
        return struct.pack("<L", len(data)) + data


class HTA(PersistStreamInit):
    CLSID = uuid.UUID("{3050f5c8-98b5-11cf-bb82-00aa00bdce0b}")

    def build(self):
        return self.data


class WMZ(PersistStreamInit):
    CLSID = uuid.UUID("{22d6f312-b0f6-11d0-94ab-0080c74c7e95}")

    def build(self):
        ret = struct.pack("<LQ", 1, 0x6699)
        ret += VariantArray.dumpHashAndData([
            ["Audiostream", 0x99, 3],
            ["Autosize", True],
            ["Autostart", True],
            ["Animationatsta", True],
            ["Allowscan", True],
            ["Allowchangedis", True],
            ["Allowchanged", True],
            ["Autorewind", True],
            ["Balance", 0x99, 3],
            ["Baseurl", "BaseurlValue"],
            ["Bufferingtime", 0x66, 5],
            ["Captioningid", "CaptioningidValue"],
            ["Clicktoplay", True],
            ["Cursortype", 0x99, 3],
            ["Currentposit", 0x66, 5],
            ["Currentmarke", 0x99, 3],
            ["Defaultframe", "DefaultframeValue"],
            ["Displaybackcol", 0, 0x13],
            ["Displayforecol", 0, 0x13],
            ["Displaymode", 0x99, 3],
            ["Displaysize", 0x99, 3],
            ["Enabled", True],
            ["Enablecontextm", True],
            ["Enableposition", True],
            ["Enablefullscre", True],
            ["Enabletracker", True],
            ["Filename", "FilenameValue"],
            ["Invokeurls", True],
            ["Language", 0x99, 3],
            ["Mute", True],
            ["Playcount", 0x99, 3],
            ["Previewmode", True],
            ["Rate", 0x66, 5],
            ["Samilang", "SamilangValue"],
            ["Samistyle", "SamistyleValue"],
            ["Samifilename", "SamifilenameValue"],
        ], self.data)
        return ret


class HTMLElem(PersistStreamInit):
    CLSID = uuid.UUID("{8bd21d50-ec42-11ce-9e0d-00aa006002f3}")

    def build(self):
        return self.data.encode('utf-16le')


class ShellListView(PersistStreamInit):
    CLSID = uuid.UUID("{ace52d03-e5cd-4b20-82ff-e71b11beae1d}")

    def build(self):
        ret = struct.pack("<L", 4)
        ret += VariantArray.dumpHashAndData([
            ["cx", 0x66, 0x13],
            ["cy", 0x99, 0x13],
            ["root", "SomeRoot", 0x0C],
        ], self.data, Variant.POL_COMPLEX)
        return ret


class OutlookView(PersistStreamInit):
    CLSID = uuid.UUID("{0006f063-0000-0000-c000-000000000046}")

    def build(self):
        ret = struct.pack("<L", 0x96)
        ret += VariantArray.dumpHashAndData([
            ["cx", 0x66, 0x13],
            ["cy", 0x99, 0x13],
            ["View", "ViewValue"],
            ["Folder", "FolderValue"],
            ["Namespace", "NamespaceValue"],
            ["ActiveFolder", VariantIntf("", "{0006F063-0000-0000-C000-000000000046}"), 0x09],
            ["OutlookApplication", VariantIntf("", "{0006F063-0000-0000-C000-000000000046}"), 0x09],
            ["Restriction", "RestrictionValue"],
            ["DeferUpdate", True],
            ["Dirty", True],
            ["Filter", "FilterValue"],
            ["FilterAppend", "FilterAppendValue"],
            ["EnableRowPersistance", True],
            ["ViewXML", "<view>some xml</view>"],
        ], self.data, Variant.POL_COMPLEX)
        return ret


class IPSecMon(PersistStreamInit):
    CLSID = uuid.UUID("{57c596d0-9370-40c0-ba0d-ab491b63255d}")

    def __init__(self, data, clsid=None):
        PersistStreamInit.__init__(self, data, clsid)
        self.strs = ["FirstString"]
        self.ints = [[0x61],
                     [0x62],
                     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
                     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
                     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]]

    def build(self):
        ret = struct.pack("<LLLL", 1, 1, 1, 0)
        ret += struct.pack("<LL", 0x8002, len(self.strs))
        for x in self.strs:
            ret += struct.pack("<L", len(x))
            ret += x
        for y in self.ints:
            ret += struct.pack("<LL", 0x8001, len(y))
            for x in y:
                ret += struct.pack("<L", x)
        ret += gendata()
        return ret


class HHCtrl(PersistStreamInit):
    CLSID = uuid.UUID("{52a2aaae-085d-4187-97ea-8c30db990436}")

    def build(self):
        ret = struct.pack("<QQQLQ", 0x12344321, 8, 0x66, 0x3186, 0x99)
        ret += struct.pack("<L", len(self.data))
        ret += self.data
        return ret


class RDPShell(PersistStreamInit):
    CLSID = uuid.UUID("{ace575fd-1fcf-4074-9401-ebab990fa9de}")

    def build(self):
        ret = struct.pack("<L", 0x66)
        ret += VariantArray.dumpHashAndData([
            ["Server", "http://www.local:8080/"],
            ["FullScreen", True],
            ["StartConnected", True],
        ], self.data)
        return ret


class Scriptlet(PersistStreamInit):
    CLSID = uuid.UUID("{ae24fdae-03c6-11d1-8b76-0080c744f389}")

    def build(self):
        ret = struct.pack("<H", 0)
        ret += struct.pack("<L", len(self.data))
        ret += self.data.encode("utf-16le")
        return ret


class Flash(PersistStreamInit):
    CLSID = uuid.UUID("{d27cdb6e-ae6d-11cf-96b8-444553540000}")

    def build(self):
        ret = struct.pack("<L", 0x55665567)  # load thru IDispatch
        ret += VariantArray.dumpHashAndData([
            ["_cx", 0, 0x13],
            ["_cy", 0, 0x13],
            ["FlashVars", "FlashVarsValue"],
            ["Movie", "MovieValue"],
            ["Src", "SrcValue"],
            ["WMode", "WModeValue"],
            ["Play", "PlayValue"],
            ["Loop", "LoopValue"],
            ["Quality", "QualityValue"],
            ["SAlign", "SAlignValue"],
            ["Menu", "MenuValue"],
            ["Base", "BaseValue"],
            ["AllowScriptAccess", "AllowScriptAccessValue"],
            ["Scale", "ScaleValue"],
            ["DeviceFont", "DeviceFontValue"],
            ["EmbedMovie", "EmbedMovieValue"],
            ["BGColor", "BGColorValue"],
            ["SWRemote", "SWRemoteValue"],
            ["MovieData", "MovieDataValue"],
            ["inine-data", VariantIntf("", "{0006F063-0000-0000-C000-000000000046}"), 0x0D],
            ["SeamlessTabbing", "SeamlessTabbingValue"],
            ["Profile", "ProfileValue"],
            ["ProfileAddress", "ProfileAddressValue"],
            ["ProfilePort", "ProfilePortValue"],
            ["AllowNetworking", "AllowNetworkingValue"],
            ["AllowFullScreen", "AllowFullScreenValue"],
            ["AllowFullScreenInteractive", "AllowFullScreenInteractiveValue"],
            ["IsDependent", "IsDependentValue"],
            ["BrowserZoom", "BrowserZoomValue"],
        ], self.data)
        return ret
