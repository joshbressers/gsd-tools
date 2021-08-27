#!/usr/bin/env node

var jsonld = require('jsonld');
var jsonld_request = require('jsonld-request');

var ld_file = "../UVI-2021-38208.jsonld";

function NVDtoOSV(nvd_data) {

    // Map NVD to OSV
    var osv = {};

    uvi_id = nvd_data["cve"]["CVE_data_meta"]["ID"].replace("CVE", "UVI");

    osv["id"] = uvi_id;
    osv["published"] = nvd_data["publishedDate"];
    osv["modified"] = nvd_data["lastModifiedDate"];
    osv["aliases"] = [ nvd_data["cve"]["CVE_data_meta"]["ID"] ];
    osv["summary"] = "MISSING";
    osv["description"] = nvd_data["cve"]["description"]["description_data"][0]["value"];
    osv["affected"] = [ {
        "package": {
            "ecosystem": "MISSING",
            "name": "MISSING"
        },
        "ranges": [ {
            "type": "MISSING",
            "repo": "MISSING",
            "events": [ {
                "introduced": "MISSING",
                "fixed": "MISSING",
                "limit": "MISSING"
            } ]
        } ],
        "versions": "MISSING"
    } ];

    osv["references"] = [];
    nvd_data["cve"]["references"]["reference_data"].forEach(function(ref) {
        one_ref = {
            "type": "WEB",
            "url" : ref["url"]
        };
        osv["references"].push(one_ref);
    });

    return osv;
}

jsonld_request(ld_file, function(err, res, the_data) {
    console.log("Loading " + ld_file);
    var cve_url = the_data['cve'];

    console.log("Loading " + cve_url);
    jsonld_request(cve_url, function(err, res, cve_data) {
        var cve_id = cve_data['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID'];
        console.log("Found " + cve_id);
        console.log("-----");

        the_json = JSON.stringify(NVDtoOSV(cve_data['result']['CVE_Items'][0]), null, 2);
        console.log(the_json);
    });

});
