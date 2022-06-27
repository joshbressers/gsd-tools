#!/usr/bin/env python

import sqlite3
import datetime
import sys
import json

d = datetime.datetime.utcnow()
now = d.isoformat("T") + "Z"

def gen_osv(metadata):
    # Generate the initial OSV data

    osv = {
        "schema_version" : "1.3.0",
        "id" : metadata[0][0],
        "modified": now,
        "published": now, # XXX Fix this one
        "aliases" : [],
        "details": "",
        "severity": [],
        "affected": [],
        "references": []
    }

    # 0 id
    # 1 namespace
    # 2 data_source
    # 3 record_source
    # 4 severity
    # 5 urls (JSON)
    # 6 description
    # 7 cvss


    # Sometimes we get more than one metadata entry, find a nicer way
    # to do this someday

    for m in metadata:

        # This is json
        urls = json.dumps(m[5])

#        for u in urls:
#            osv["references"].append({
#                "type": "WEB",
#                "url": u
#            })

    osv["details"] = metadata[0][6]

    # We don't have a very nice way to tie severity to package, we need to
    # fix this in the OSV format
    # https://github.com/ossf/osv-schema/issues/40
    # We will just pick one for now
    osv["severity"].append({
        "type": "Grype",
        "score": metadata[0][4]
    })

    # XXX Add aliases

    # Let's ignore CVSS, we can get that from the upstream identifier
    # database and the severity field is already pretty squishy

    return osv

def main():

    con = sqlite3.connect("vulnerability.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM vulnerability")

    # The data we get back is
    # 0 pk - primary key
    # 1 id - vuln ID
    # 2 package_name
    # 3 namespace
    # 4 version_constraint
    # 5 version_format
    # 6 cpes (JSON)
    # 7 related_vulnerabilities (JSON)
    # 8 fixed_in_versions (JSON)
    # 9 fix_state
    # 10 advisories

    # We are going to try to put these in the OSV format as best as we can
    # https://ossf.github.io/osv-schema/

    # This will hold all the data
    vulns = {}

    ops = {}

    for vuln in cur.fetchall():

        vuln_id = vuln[1]

        # We need to figure out if this has a higher level ID
        # Top level IDs are CVE and GHSA, everything should have another ID
        # type

        #if vuln_id.split('0')[0]

        #print(vuln_id.split('-')[0])

        if vuln_id.split('-')[0] == '0':
            print(vuln)
        continue

        if vuln_id not in vulns:
            # First time we see this, we need to fill out the OSV data

            meta_cur = con.cursor()
            # I don't think this library has prepared statements (bleh)
            meta_cur.execute("SELECT * FROM vulnerability_metadata WHERE id='%s'" % vuln_id)
            metadata = meta_cur.fetchall()

            new_osv = gen_osv(metadata)
            vulns[vuln_id] = new_osv

            meta_cur.close()

        # Add affected
        # This code will be the most buggy out of the gate and will need
        # constant refinement. Let's just do something easy and dumb to
        # start
        #
        # the package name is straightforward
        # We will use the "namespace" as our ecosystem
        # Version constraints looks like
        # < 3.0.000.115 || >= 3.1.000.000, < 3.1.000.044 || >= 3.2.000.000, < 3.2.000.009
        # We may or may not have a fixed_in_versions
        # Those look like ["2.15.0-1~deb10u1"]

        package_name = vuln[2]
        package_namespace = vuln[3]
        version_format = vuln[5]
        versions = vuln[4]

        vulns[vuln_id]['affected'].append({
            "package": {
                "ecosystem": package_namespace,
                "name": package_name
            },
            "ranges": [{
                "type": version_format,
                "events": []
            }]
        })

        for verop in versions.split("||"):
            verop = verop.lstrip().rstrip()

            # Now we have to split on ','
            vers = verop.split(',')

            # We have 3 possible states now
            # an introduced and fixed state
            # an introduced only
            # a fixed only

            for ver in vers:

                ver = ver.lstrip().rstrip()
                one_ver = '-1'

                # every operation is one of "> < <= >= ="
                if len(ver) == 0:
                    continue
                if ver[1] in "<>=":
                    op = ver[0:2]
                    one_ver = ver[2:]
                    one_ver = one_ver.lstrip().rstrip()
                elif ver[0] in '<>=':
                    op = ver[0]
                    one_ver = ver[1:]
                    one_ver = one_ver.lstrip().rstrip()
                else:
                    # If there is no op, the previous op will apply to this
                    # version
                    one_ver = ver
                    one_ver = one_ver.lstrip().rstrip()

                # Specifying the introduced field using a > doens't really
                # make sense, anytime NVD specifies this it's almost
                # certainly a bug. We're going to cheat and use >= for now
                if op == '>':
                    op = ">="

                condition = ''
                if op == "<":
                    condition = "last_affected"
                elif op == "<=":
                    condition = "fixed"
                # A singular = only ever appearsin the affected column
                elif op == ">="or op == "=":
                    condition = "introduced"
                else:
                    print("Something terrible has happened, no condition")
                    print(vuln)
                    sys.exit(1)

                vulns[vuln_id]['affected'][-1]["ranges"][-1]["events"].append(
                    {
                        condition: one_ver
                    }
                )



    con.close()

if __name__ == '__main__':
    main()
