#!/usr/bin/python

import sys
import json

if sys.version_info.major != 3:
    sys.stderr.write(sys.argv[0] + " requires Python 3\n")
    exit(1)

cvedata = json.load(sys.stdin)

cvemap={}
for version in cvedata:
    rec = cvedata[version]
    for cveid in rec:
        if cveid not in cvemap:
            cvemap[cveid] = (rec[cveid]['score'], rec[cveid]['severity'])
        print(f"+{version},{cveid}")

for cveid in cvemap:
    score,severity = cvemap[cveid]
    print(f"{cveid},{severity.lower()},{score}")


