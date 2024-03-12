#!/usr/bin/python

import sys
import os
import gzip as GZ
import sqlite3
import json

if sys.version_info.major != 3:
    sys.stderr.write(sys.argv[0] + " requires Python 3\n")
    exit(1)

dbname=None
hashdb=None
ndxfile=None
split_fingerprints=True
split_hashes=True

archive_prefix = None
archivedir=None

ndx = 1
while ndx < len(sys.argv):
    arg = sys.argv[ndx]
    ndx += 1
    
    if arg == '-d':
        dbname=sys.argv[ndx]
        ndx += 1
    elif arg == '-h':
        hashdb=sys.argv[ndx]
        ndx += 1
    elif arg == '-a':
        archivedir=sys.argv[ndx]
        ndx += 1
    elif arg == '-p':
        archive_prefix=sys.argv[ndx]
        ndx += 1
    elif arg == '-i':
        ndxfile=sys.argv[ndx]
        ndx += 1
    elif arg == '--no-fingerprints':
        split_fingerprints=False
    elif arg == '--no-hashes':
        split_hashes=False

error=False
if archivedir is None:
    sys.stderr.write("ERROR: Must specify the folder where archive data should be stored with -a option.\n")
    error=True

if archive_prefix is None:
    sys.stderr.write("ERROR: Must specify the folder prefix to use in location of archive data in JSON config file with -p option.\n")
    error=True

if ndxfile is None:
    sys.stderr.write("ERROR: Must specify the folder where the index file 'archives.json' should be stored with -a option.\n")
    error=True

if hashdb is None and split_hashes:
    sys.stderr.write("ERROR: Must specify the location of the master list of SHA256 hashes with -h option.\n")
    error=True
    
if split_fingerprints and  dbname is None:
    sys.stderr.write("ERROR: Must specify the name of the SQLite3 fingerprint database with -d option.\n")
    error=True



if error:
    exit(1)

fpdir = os.path.join(archivedir, 'fingerprints')
if not os.path.exists(fpdir):
    os.mkdir(fpdir)
hashdir = os.path.join(archivedir, 'hashes')
if not os.path.exists(hashdir):
    os.mkdir(hashdir)
        
pkgs={
    "log4j-core": {
        'group': 'log4j',
	"description": "Apache Log4J v1 & v2, plus Apache Chainsaw"
    },
        
    "log4j": {
        'group': 'log4j',
	"description": "Apache Log4J v1 & v2, plus Apache Chainsaw"
    },
    "apache-chainsaw": {
        'group': 'log4j',
	"description": "Apache Log4J v1 & v2, plus Apache Chainsaw"
    },
    "apache-log4j-extras": {
        'group': 'log4j',
	"description": "Apache Log4J v1 & v2, plus Apache Chainsaw"
    },
    "elasticsearch": {
        'description': "Elastic Search"
    },
    "jackson-databind": {
	"description": "FasterXML jackson-databind",
    },
        
    "gt-main": {
        'group': 'geotools',
	"description": "Geotools"
    },
    
    "commons-compress": {
	"description": "Apache Commons Compress",
    },
    
    "gson": {
	"description": "Google GSON",
    },
    "guava": {
	"description": "Google Guava",
    }
}

archive={}
for p in pkgs.keys():
    if 'group' not in pkgs[p]:
        pkgs[p]['group'] = p
    if p in archive:
        continue
    r = {
        'description': pkgs[p]['description'],
        'fingerprints': [],
        'hashes': [],
        'count': 0
    }
    archive[pkgs[p]['group']] = r


notfound=set()

if split_fingerprints:
    counters={}
    data = {}
    fnv = {}
    db = sqlite3.connect(dbname)

    active = []

    for cname,sig,version in db.execute("select * from signatures"):
        for p in pkgs:
            n = len(p)
            found=False

            if version[0:n] == p:
                group = pkgs[p]['group']
                archive[group]['count'] += 1
                if version not in data:
                    if len(active) > 200:
                        oldest = active[0]
                        active = active[1:]
                        data[oldest].close()
                        del data[oldest]
                        del counters[oldest]

                    if version in fnv:
                        fn = f"{version}-{fnv[version]}.fp.psv.gz"
                    else:
                        fn = f"{version}.fp.psv"
                    if fn not in archive[group]['fingerprints']:
                        archive[group]['fingerprints'].append(fn)
                    fn = os.path.join(fpdir, fn)
                    
                    data[version] = open(fn, 'at', encoding='utf8')
                    active.append(version)
                    counters[version] = 0
                        
                data[version].write(f"{cname}|{sig}|{version}\n")
                counters[version] += 1
                if counters[version] == 10000000:
                    data[version].close()
                    if version not in fnv:
                        fnv[version] = 0
                    fnv[version] += 1
                    fn = f"{version}-{fnv[version]}.fp.psv"
                    if fn not in archive[group]['fingerprints']:
                        archive[group]['fingerprints'].append(fn)
                    fn = os.path.join(fpdir, fn)
                    data[version] = open(fn, 'at', encoding='utf8')
                    counters[version] = 0
                found=True
                break

        if not found:
            for ndx in range(0,len(version)-1):
                if version[ndx] == '-' and version[ndx+1].isdigit():
                    v = version[:ndx]
                    notfound.add(v)
                    break


    for name in data:
        data[name].close()

cfpdir = os.path.join(archive_prefix, 'fingerprints')
for group in archive:
    new_names=[]
    for fn in archive[group]['fingerprints']:
        ifn = os.path.join(fpdir, fn)
        with open(ifn, 'rt', encoding='utf8') as f:
            records=[]
            for line in f:
                records.append(line)
            records = sorted(records)
        nfn = os.path.join(fpdir, fn + ".gz")
        with GZ.open(nfn, 'wt', encoding='utf8') as f:
            f.write("".join(records) + "\n")
        cfn = os.path.join(cfpdir, fn+'.gz')
        new_names.append(os.path.join(cfpdir, cfn))
        os.unlink(ifn)
    archive[group]['fingerprints'] = new_names

if split_hashes:
    data = {}
    for n in pkgs:
        data[n] = None

    with open(hashdb, 'r') as f:
        for line in f:
            line = line.rstrip()
            h,version = line.split(',')
            for p in pkgs:
                n = len(p)
                found=False

                if version[0:n] == p:
                    group = pkgs[p]['group']
                    if data[p] is None:
                        data[p] = []
                    data[p].append(line)
                    found=True
                    break

            if not found:
                for ndx in range(0,len(version)-1):
                    if version[ndx] == '-' and version[ndx+1].isdigit():
                        v = version[:ndx]
                        notfound.add(v)
                        break

    hpdir = os.path.join(archive_prefix, "hashes")
    for p in data:
        group = pkgs[p]['group']
        fn = f"{p}.sha256"
        data[p] = sorted(data[p])
        cfn = os.path.join(hpdir, fn)
        ofn = os.path.join(hashdir, fn)
        with open(ofn, 'wt', encoding='utf8') as f:
            f.write("\n".join(data[p]) + "\n")
        archive[group]['hashes'].append(cfn)


if len(notfound) != 0:
    s = ",".join(sorted(list(notfound)))
    sys.stderr.write(f"WARNING: These names not handled:\n\t{s}\n")

with open(ndxfile, 'wt', encoding='utf8') as out:
    out.write(json.dumps(archive, indent=4, sort_keys=True))
    out.write("\n")
