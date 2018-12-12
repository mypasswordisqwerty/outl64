#!/usr/bin/env python
import sys
import base64


def main(argv):
    inp = sys.stdin
    if len(argv) > 0:
        inp = open(argv[0])
    data = inp.read()
    print base64.b64encode(data.encode("utf-16le"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
