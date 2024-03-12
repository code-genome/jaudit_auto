#!/usr/bin/python

#
# This code is part of the Jaudit utilty.
#
# (C) Copyright IBM 2023.
#
# This code is licensed under the Apache License, Version 2.0. You may
# obtain a copy of this license in the LICENSE.txt file in the root directory
# of this source tree or at http://www.apache.org/licenses/LICENSE-2.0.
#
# Any modifications or derivative works of this code must retain this
# copyright notice, and modified files need to carry a notice indicating
# that they have been altered from the originals.
#

import sys
import os
from hashlib import sha256

if sys.version_info.major != 3:
    sys.stderr.write(sys.argv[0] + " requires Python 3\n")
    exit(1)

myname = sys.argv[0]
mydir = os.path.realpath(os.path.dirname(myname))
basedir = os.path.realpath(os.path.join(mydir, ".."))
topdir = os.path.realpath(os.path.join(basedir, ".."))

runcmd = os.path.join(topdir, "bin/run")

jaudit_data = os.path.join(topdir, "jaudit.data")

config_file=os.path.join(basedir, "cf/auto.cf")

ndx = 1
while ndx < len(sys.argv):
    arg = sys.argv[ndx]
    ndx += 1

    if ndx == '--config':
        config_file=sys.argv[ndx]
        ndx += 1
    else:
        pass

def load_config(CF, config, parent=None):
    if CF[0] != '/' and parent is not None:
        dir = os.path.dirname(parent)
        CF=os.path.join(dir, CF)
        
    with open(CF, "r") as cfFile:
        currentID = None
        for line in cfFile:
            if line[0] == '#':
                continue
            line = line.rstrip()
            if line == '':
                continue
            if line.startswith("include "):
                fn = line[7:].strip()
                load_config(fn, config, parent=CF)
                continue
            var,value = line.split('=', 1)
            if var == 'ident':
                currentID = value
                if currentID not in config:
                    config[currentID] = {}
            elif currentID is None:
                sys.stderr.write(f"Missing ident record in {CF}\n")
            else:
                config[currentID][var] = value

def is_enabled(s):
    s = s.lower()
    return s in ['true', 'yes', '1']

config={}
load_config(config_file, config)

data_dir=config['*'].get('data_dir', None)

error = False

if data_dir is None:
    sys.stderr.write(f"data_dir is not set in {config_file}\n")
    error = True

for id in config:
    if id == '*':
        continue
    enabled = config[id].get('enable', 'false')

    if not is_enabled(enabled):
        continue
	
    repo=config[id].get('repo',None)

    archive=config[id].get('archive', None)
    if archive is None:
        sys.stderr.write("No archive specified for {id}, skipping.\n")
        continue

    if archive[0] != '/':
        archive = os.path.join(jaudit_data, archive)

    if repo[0] != '/':
        repo = os.path.join(data_dir, repo)
    if not os.path.exists(archive):
        os.mkdir(archive)

    jardir = os.path.join(repo, "jars")
    for jarname in os.listdir(jardir):
        if not jarname.endswith('.jar'):
            continue
        filename = os.path.join(jardir, jarname)
        os.system(f"{runcmd} add-jars -a '{archive}' '{filename}'")
